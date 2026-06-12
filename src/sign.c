/* sign.c - Authenticode + catalog signature verification with caching.
 *
 * sign_verify() is the hot path: WinVerifyTrust is expensive (tens of ms,
 * sometimes more with revocation). Scanners call it concurrently across many
 * files, often the same files repeatedly. We therefore:
 *   - disable revocation network I/O (WTD_REVOKE_NONE, cache-only state),
 *   - cache results keyed by lowercased path + last-write-time,
 *   - guard the cache with a CRITICAL_SECTION.
 *
 * Embedded verification is tried first; on TRUST_E_NOSIGNATURE we fall back to
 * catalog verification (CryptCATAdmin*). The signer subject is extracted via
 * CryptQueryObject + CMSG_SIGNER_INFO + CertGetNameStringA.
 */
#include "sentinelc.h"

#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ cache */

typedef struct {
    char        path[SC_MAX_PATH];   /* lowercased */
    FILETIME    mtime;
    SignVerdict verdict;
    char        signer[SC_NAME_LEN];
    bool        used;
} SignCacheEntry;

static SignCacheEntry  *g_cache = NULL;
static size_t           g_cache_count = 0;
static size_t           g_cache_cap   = 0;
static CRITICAL_SECTION g_cache_lock;
static INIT_ONCE        g_cache_once = INIT_ONCE_STATIC_INIT;
static bool             g_cache_ready = false;

static BOOL CALLBACK sign_cache_init_once(PINIT_ONCE once, PVOID param,
                                          PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&g_cache_lock);
    g_cache       = NULL;
    g_cache_count = 0;
    g_cache_cap   = 0;
    g_cache_ready = true;
    return TRUE;
}

void sign_cache_init(void)
{
    /* Idempotent and safe under concurrent first-callers: multiple scanner
     * threads racing on the lazy init path in sign_verify() must not each
     * InitializeCriticalSection the same object (double-init corrupts it and
     * leaks). InitOnceExecuteOnce runs the initializer exactly once. */
    InitOnceExecuteOnce(&g_cache_once, sign_cache_init_once, NULL, NULL);
}

void sign_cache_free(void)
{
    if (!g_cache_ready) return;
    EnterCriticalSection(&g_cache_lock);
    free(g_cache);
    g_cache       = NULL;
    g_cache_count = 0;
    g_cache_cap   = 0;
    LeaveCriticalSection(&g_cache_lock);
    DeleteCriticalSection(&g_cache_lock);
    g_cache_ready = false;
    /* Reset the one-time guard so a later sign_cache_init() re-initializes
     * cleanly (e.g. a second scan pass within the same process). */
    {
        INIT_ONCE fresh = INIT_ONCE_STATIC_INIT;
        g_cache_once = fresh;
    }
}

static bool ft_equal(const FILETIME *a, const FILETIME *b)
{
    return a->dwLowDateTime == b->dwLowDateTime &&
           a->dwHighDateTime == b->dwHighDateTime;
}

/* Look up a cached verdict. Returns true on hit and fills *out / signer. */
static bool cache_get(const char *lpath, const FILETIME *mtime,
                      SignVerdict *out, char *signer_out, size_t signer_cap)
{
    bool hit = false;
    EnterCriticalSection(&g_cache_lock);
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_cache[i].used && ft_equal(&g_cache[i].mtime, mtime) &&
            strcmp(g_cache[i].path, lpath) == 0) {
            *out = g_cache[i].verdict;
            if (signer_out && signer_cap > 0) {
                strncpy(signer_out, g_cache[i].signer, signer_cap - 1);
                signer_out[signer_cap - 1] = '\0';
            }
            hit = true;
            break;
        }
    }
    LeaveCriticalSection(&g_cache_lock);
    return hit;
}

static void cache_put(const char *lpath, const FILETIME *mtime,
                      SignVerdict v, const char *signer)
{
    EnterCriticalSection(&g_cache_lock);

    /* If an entry for this path exists (stale mtime), update it in place. */
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].path, lpath) == 0) {
            g_cache[i].mtime   = *mtime;
            g_cache[i].verdict = v;
            g_cache[i].signer[0] = '\0';
            if (signer) {
                strncpy(g_cache[i].signer, signer, sizeof g_cache[i].signer - 1);
                g_cache[i].signer[sizeof g_cache[i].signer - 1] = '\0';
            }
            LeaveCriticalSection(&g_cache_lock);
            return;
        }
    }

    if (g_cache_count == g_cache_cap) {
        size_t ncap = g_cache_cap ? g_cache_cap * 2 : 128;
        SignCacheEntry *n = realloc(g_cache, ncap * sizeof *n);
        if (!n) { LeaveCriticalSection(&g_cache_lock); return; } /* skip cache */
        g_cache = n;
        g_cache_cap = ncap;
    }

    SignCacheEntry *e = &g_cache[g_cache_count++];
    memset(e, 0, sizeof *e);
    {
        size_t n = strlen(lpath);
        if (n >= sizeof e->path) n = sizeof e->path - 1;
        memcpy(e->path, lpath, n);
        e->path[n] = '\0';
    }
    e->mtime   = *mtime;
    e->verdict = v;
    if (signer) {
        size_t n = strlen(signer);
        if (n >= sizeof e->signer) n = sizeof e->signer - 1;
        memcpy(e->signer, signer, n);
        e->signer[n] = '\0';
    }
    e->used = true;

    LeaveCriticalSection(&g_cache_lock);
}

/* --------------------------------------------------------------- signer name */

/* Extract the signer subject of an embedded-signed file into signer_out.
 * Best-effort: on any failure signer_out is left as an empty string and the
 * function returns false. Used to classify SIGN_SIGNED vs SIGN_SIGNED_MS. */
static bool extract_signer(const wchar_t *wpath, char *signer_out,
                           size_t signer_cap)
{
    bool ok = false;
    HCERTSTORE       hStore = NULL;
    HCRYPTMSG        hMsg   = NULL;
    PCMSG_SIGNER_INFO pSigner = NULL;
    PCCERT_CONTEXT   pCert  = NULL;
    DWORD            dwSigner = 0;

    if (signer_out && signer_cap > 0) signer_out[0] = '\0';

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL,
                          &hStore, &hMsg, NULL))
        return false;

    /* Pull signer info from the message. */
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSigner) ||
        dwSigner == 0)
        goto cleanup;

    pSigner = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSigner);
    if (!pSigner) goto cleanup;

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSigner, &dwSigner))
        goto cleanup;

    /* Find the signer's certificate by issuer + serial. */
    {
        CERT_INFO ci;
        ci.Issuer       = pSigner->Issuer;
        ci.SerialNumber = pSigner->SerialNumber;
        pCert = CertFindCertificateInStore(
            hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_CERT, &ci, NULL);
    }
    if (!pCert) goto cleanup;

    if (signer_out && signer_cap > 0) {
        DWORD n = CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                     NULL, signer_out, (DWORD)signer_cap);
        if (n > 1) ok = true;   /* n counts the NUL; 1 means empty */
        signer_out[signer_cap - 1] = '\0';
    } else {
        ok = true;
    }

cleanup:
    if (pCert)   CertFreeCertificateContext(pCert);
    if (pSigner) LocalFree(pSigner);
    if (hMsg)    CryptMsgClose(hMsg);
    if (hStore)  CertCloseStore(hStore, 0);
    return ok;
}

/* ------------------------------------------------------------ WinVerifyTrust */

/* Run WinVerifyTrust over an embedded signature. Returns the raw LONG result. */
static LONG verify_embedded(const wchar_t *wpath)
{
    WINTRUST_FILE_INFO fi;
    memset(&fi, 0, sizeof fi);
    fi.cbStruct       = sizeof fi;
    fi.pcwszFilePath  = wpath;
    fi.hFile          = NULL;
    fi.pgKnownSubject = NULL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd;
    memset(&wd, 0, sizeof wd);
    wd.cbStruct            = sizeof wd;
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;     /* speed: no network CRL */
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    wd.hWVTStateData       = NULL;

    LONG status = WinVerifyTrust(NULL, &action, &wd);

    /* Always release provider state. */
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &wd);

    return status;
}

/* Verify a file against the system catalog store. On success, extracts the
 * catalog's signer subject. Returns a SignVerdict; SIGN_UNSIGNED if the file is
 * in no catalog. */
static SignVerdict verify_catalog(const wchar_t *wpath, char *signer_out,
                                  size_t signer_cap)
{
    SignVerdict verdict = SIGN_UNSIGNED;
    HANDLE      hFile   = INVALID_HANDLE_VALUE;
    HCATADMIN   hCatAdmin = NULL;
    HCATINFO    hCatInfo  = NULL;
    BYTE       *hash    = NULL;
    DWORD       hashLen = 0;

    hFile = CreateFileW(wpath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return SIGN_UNSIGNED;

    GUID drvAction = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, &drvAction, 0)) {
        CloseHandle(hFile);
        return SIGN_UNKNOWN;
    }

    /* Two-pass hash size query. */
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, NULL, 0) ||
        hashLen == 0) {
        goto cleanup;
    }
    hash = (BYTE *)malloc(hashLen);
    if (!hash) { verdict = SIGN_UNKNOWN; goto cleanup; }
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash, 0))
        goto cleanup;

    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashLen, 0,
                                                NULL);
    if (!hCatInfo) {
        verdict = SIGN_UNSIGNED;       /* not in any catalog */
        goto cleanup;
    }

    /* Found a catalog; verify it with WinVerifyTrust (WINTRUST_CATALOG_INFO). */
    {
        CATALOG_INFO ci;
        memset(&ci, 0, sizeof ci);
        ci.cbStruct = sizeof ci;
        if (!CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0)) {
            verdict = SIGN_UNKNOWN;
            goto cleanup;
        }

        /* Build a wide hex member tag from the hash. */
        wchar_t memberTag[256];
        size_t  cap = sizeof memberTag / sizeof memberTag[0];
        size_t  pos = 0;
        for (DWORD i = 0; i < hashLen && pos + 2 < cap; i++) {
            static const wchar_t hexd[] = L"0123456789ABCDEF";
            memberTag[pos++] = hexd[(hash[i] >> 4) & 0xF];
            memberTag[pos++] = hexd[hash[i] & 0xF];
        }
        memberTag[pos] = L'\0';

        WINTRUST_CATALOG_INFO wci;
        memset(&wci, 0, sizeof wci);
        wci.cbStruct          = sizeof wci;
        wci.pcwszCatalogFilePath = ci.wszCatalogFile;
        wci.pcwszMemberTag    = memberTag;
        wci.pcwszMemberFilePath = wpath;
        wci.hMemberFile       = hFile;
        wci.pbCalculatedFileHash = hash;
        wci.cbCalculatedFileHash = hashLen;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA wd;
        memset(&wd, 0, sizeof wd);
        wd.cbStruct            = sizeof wd;
        wd.dwUIChoice          = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice       = WTD_CHOICE_CATALOG;
        wd.pCatalog            = &wci;
        wd.dwStateAction       = WTD_STATEACTION_VERIFY;
        wd.dwProvFlags         = WTD_REVOCATION_CHECK_NONE |
                                 WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG status = WinVerifyTrust(NULL, &action, &wd);

        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wd);

        if (status == ERROR_SUCCESS) {
            verdict = SIGN_SIGNED;
            /* Signer of the catalog file itself. */
            if (extract_signer(ci.wszCatalogFile, signer_out, signer_cap) &&
                signer_out && str_icontains(signer_out, "Microsoft"))
                verdict = SIGN_SIGNED_MS;
        } else {
            verdict = SIGN_INVALID;
        }
    }

cleanup:
    free(hash);
    if (hCatInfo)  CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    if (hCatAdmin) CryptCATAdminReleaseContext(hCatAdmin, 0);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return verdict;
}

/* --------------------------------------------------------------- public API */

SignVerdict sign_verify(const char *path, char *signer_out, size_t signer_cap)
{
    if (signer_out && signer_cap > 0) signer_out[0] = '\0';
    if (!path || path[0] == '\0') return SIGN_UNKNOWN;
    if (!g_cache_ready) sign_cache_init();   /* tolerate missing init */

    /* mtime + lowercased key. */
    WIN32_FILE_ATTRIBUTE_DATA fad;
    FILETIME mtime = {0, 0};
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
        mtime = fad.ftLastWriteTime;

    char lpath[SC_MAX_PATH];
    strncpy(lpath, path, sizeof lpath - 1);
    lpath[sizeof lpath - 1] = '\0';
    str_lower(lpath);

    SignVerdict cached;
    if (cache_get(lpath, &mtime, &cached, signer_out, signer_cap))
        return cached;

    wchar_t wpath[SC_MAX_PATH * 2];
    if (utf8_to_wide(path, wpath, sizeof wpath / sizeof wpath[0]) == 0)
        return SIGN_UNKNOWN;

    char signer[SC_NAME_LEN] = {0};
    SignVerdict verdict;

    LONG status = verify_embedded(wpath);
    if (status == ERROR_SUCCESS) {
        verdict = SIGN_SIGNED;
        if (extract_signer(wpath, signer, sizeof signer) &&
            str_icontains(signer, "Microsoft"))
            verdict = SIGN_SIGNED_MS;
    } else if ((DWORD)status == (DWORD)TRUST_E_NOSIGNATURE) {
        /* No embedded signature -> try catalog. */
        verdict = verify_catalog(wpath, signer, sizeof signer);
    } else if ((DWORD)status == (DWORD)TRUST_E_BAD_DIGEST ||
               (DWORD)status == (DWORD)TRUST_E_SUBJECT_NOT_TRUSTED ||
               (DWORD)status == (DWORD)CERT_E_UNTRUSTEDROOT ||
               (DWORD)status == (DWORD)CERT_E_CHAINING ||
               (DWORD)status == (DWORD)CERT_E_EXPIRED) {
        /* Signature present but verification failed. CERT_E_* with an embedded
         * sig means a real (if untrusted) signature exists. Treat untrusted
         * root as SIGNED-but-untrusted; treat digest/explicit-distrust as
         * INVALID. */
        if ((DWORD)status == (DWORD)CERT_E_UNTRUSTEDROOT ||
            (DWORD)status == (DWORD)CERT_E_CHAINING) {
            /* A real signature is present but its chain does NOT validate to a
             * trusted root. It may name itself "Microsoft", but the signer is
             * unverified, so it must NOT be promoted to SIGN_SIGNED_MS — that
             * would let any self-signed cert with "Microsoft" in its CN spoof a
             * trusted Microsoft binary. Record it as SIGNED-but-untrusted only.
             * We still extract the signer for reporting, but never upgrade the
             * verdict. */
            verdict = SIGN_SIGNED;
            extract_signer(wpath, signer, sizeof signer);
        } else {
            verdict = SIGN_INVALID;
        }
    } else {
        /* Other errors: try catalog as a last resort, else mark invalid. */
        verdict = verify_catalog(wpath, signer, sizeof signer);
        if (verdict == SIGN_UNSIGNED)
            verdict = SIGN_INVALID;
    }

    cache_put(lpath, &mtime, verdict, signer);

    if (signer_out && signer_cap > 0) {
        strncpy(signer_out, signer, signer_cap - 1);
        signer_out[signer_cap - 1] = '\0';
    }
    return verdict;
}
