/* sign.c - Authenticode + catalog signature verification with caching.
 *
 * sign_verify() is the hot path: WinVerifyTrust is expensive (tens of ms,
 * sometimes more with revocation). Scanners call it concurrently across many
 * files, often the same files repeatedly. We therefore:
 *   - disable revocation network I/O (WTD_REVOKE_NONE, cache-only state),
 *   - cache results in-process keyed by lowercased path + size + mtime,
 *   - persist verified results with an additional SHA-256 content key,
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
#include <bcrypt.h>
#include <sddl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ cache */

#define SIGN_PERSIST_MAX_BYTES ((uint64_t)512u * 1024u * 1024u)
#define SIGN_HASH_BLOCK        (1024u * 1024u)

typedef struct {
    char        path[SC_MAX_PATH];   /* lowercased */
    FILETIME    mtime;
    uint64_t    fsize;
    char        sha256[65];          /* lowercase hex; optional */
    SignVerdict verdict;
    char        signer[SC_NAME_LEN];
    bool        used;
    bool        has_sha256;
    bool        persisted;           /* loaded from disk; require sha match */
} SignCacheEntry;

static SignCacheEntry  *g_cache = NULL;
static size_t           g_cache_count = 0;
static size_t           g_cache_cap   = 0;
static CRITICAL_SECTION g_cache_lock;
static INIT_ONCE        g_cache_once = INIT_ONCE_STATIC_INIT;
static bool             g_cache_ready = false;
static bool             g_persist_ready = false;
static char             g_persist_path[SC_MAX_PATH];
static volatile LONG64  g_sign_calls = 0;
static volatile LONG64  g_sign_memory_hits = 0;
static volatile LONG64  g_sign_persistent_hits = 0;
static volatile LONG64  g_sign_verifications = 0;
static volatile LONG64  g_sign_persistent_hash_checks = 0;
static volatile LONG64  g_sign_persistent_loaded = 0;
static volatile LONG64  g_sign_persistent_saved = 0;

static uint64_t atomic_read64(volatile LONG64 *p)
{
    return (uint64_t)InterlockedCompareExchange64(p, 0, 0);
}

static uint64_t ft_to_u64(const FILETIME *ft)
{
    return ((uint64_t)ft->dwHighDateTime << 32) | (uint64_t)ft->dwLowDateTime;
}

static void u64_to_ft(uint64_t v, FILETIME *ft)
{
    ft->dwLowDateTime  = (DWORD)(v & 0xffffffffu);
    ft->dwHighDateTime = (DWORD)(v >> 32);
}

static bool setup_persistent_cache_path(void);
static void persistent_cache_load(void);
static void persistent_cache_save(void);

static BOOL CALLBACK sign_cache_init_once(PINIT_ONCE once, PVOID param,
                                          PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&g_cache_lock);
    g_cache       = NULL;
    g_cache_count = 0;
    g_cache_cap   = 0;
    g_cache_ready = true;
    g_persist_ready = false;
    g_persist_path[0] = '\0';
    if (setup_persistent_cache_path())
        persistent_cache_load();
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
    persistent_cache_save();
    EnterCriticalSection(&g_cache_lock);
    free(g_cache);
    g_cache       = NULL;
    g_cache_count = 0;
    g_cache_cap   = 0;
    LeaveCriticalSection(&g_cache_lock);
    DeleteCriticalSection(&g_cache_lock);
    g_cache_ready = false;
    g_persist_ready = false;
    g_persist_path[0] = '\0';
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

static bool apply_admin_system_dacl(const char *path)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    bool ok = false;
    const char *sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl, SDDL_REVISION_1, &sd, NULL))
        return false;
    ok = SetFileSecurityA(path,
                          DACL_SECURITY_INFORMATION |
                          PROTECTED_DACL_SECURITY_INFORMATION,
                          sd) != 0;
    LocalFree(sd);
    return ok;
}

static bool ensure_dir_secure(const char *path)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES sa;
    bool have_sd = ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        SDDL_REVISION_1, &sd, NULL) != 0;

    memset(&sa, 0, sizeof sa);
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = have_sd ? sd : NULL;
    sa.bInheritHandle = FALSE;

    if (!CreateDirectoryA(path, have_sd ? &sa : NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            if (sd) LocalFree(sd);
            return false;
        }
    }
    if (sd) LocalFree(sd);
    return apply_admin_system_dacl(path);
}

static bool setup_persistent_cache_path(void)
{
    char program_data[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", program_data,
                                      sizeof program_data);
    if (n == 0 || n >= sizeof program_data) {
        strncpy(program_data, "C:\\ProgramData", sizeof program_data - 1);
        program_data[sizeof program_data - 1] = '\0';
    }

    char base[SC_MAX_PATH];
    char cache_dir[SC_MAX_PATH];
    snprintf(base, sizeof base, "%s\\SentinelC", program_data);
    snprintf(cache_dir, sizeof cache_dir, "%s\\cache", base);
    if (!ensure_dir_secure(base) || !ensure_dir_secure(cache_dir))
        return false;

    snprintf(g_persist_path, sizeof g_persist_path,
             "%s\\sign_cache.tsv", cache_dir);
    g_persist_path[sizeof g_persist_path - 1] = '\0';
    g_persist_ready = true;
    return true;
}

static bool sha256_file_hex_w(const wchar_t *wpath, uint64_t fsize,
                              char hex_out[65])
{
    static const char hexd[] = "0123456789abcdef";
    bool ok = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObj = 0, cb = 0;
    PUCHAR hashObj = NULL;
    BYTE digest[32];
    BYTE *buf = NULL;

    if (!hex_out) return false;
    hex_out[0] = '\0';
    if (!wpath || !wpath[0] || fsize > SIGN_PERSIST_MAX_BYTES)
        return false;

    hFile = CreateFileW(wpath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(
            hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObj, sizeof cbHashObj,
            &cb, 0)))
        goto cleanup;
    hashObj = (PUCHAR)malloc(cbHashObj);
    buf = (BYTE *)malloc(SIGN_HASH_BLOCK);
    if (!hashObj || !buf)
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(
            hAlg, &hHash, hashObj, cbHashObj, NULL, 0, 0)))
        goto cleanup;

    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hFile, buf, SIGN_HASH_BLOCK, &rd, NULL))
            goto cleanup;
        if (rd == 0)
            break;
        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, buf, rd, 0)))
            goto cleanup;
    }
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, digest, sizeof digest, 0)))
        goto cleanup;

    for (size_t i = 0; i < sizeof digest; i++) {
        hex_out[i * 2]     = hexd[digest[i] >> 4];
        hex_out[i * 2 + 1] = hexd[digest[i] & 0x0f];
    }
    hex_out[64] = '\0';
    ok = true;

cleanup:
    free(buf);
    free(hashObj);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return ok;
}

static bool clean_cache_text(char *s)
{
    if (!s) return false;
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '\t' || ch == '\r' || ch == '\n')
            *s = ' ';
        else if (ch < 0x20)
            *s = ' ';
    }
    return true;
}

/* Look up a cached verdict. Returns true on hit and fills *out / signer. */
static bool cache_get_fast(const char *lpath, const FILETIME *mtime,
                           uint64_t fsize, SignVerdict *out,
                           char *signer_out, size_t signer_cap)
{
    bool hit = false;
    EnterCriticalSection(&g_cache_lock);
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_cache[i].used && ft_equal(&g_cache[i].mtime, mtime) &&
            g_cache[i].fsize == fsize && !g_cache[i].persisted &&
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

static bool cache_has_persistent_candidate(const char *lpath,
                                           const FILETIME *mtime,
                                           uint64_t fsize)
{
    bool found = false;
    EnterCriticalSection(&g_cache_lock);
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_cache[i].used && g_cache[i].persisted &&
            g_cache[i].has_sha256 && g_cache[i].fsize == fsize &&
            ft_equal(&g_cache[i].mtime, mtime) &&
            strcmp(g_cache[i].path, lpath) == 0) {
            found = true;
            break;
        }
    }
    LeaveCriticalSection(&g_cache_lock);
    return found;
}

static bool cache_get_persistent(const char *lpath, const FILETIME *mtime,
                                 uint64_t fsize, const char sha256[65],
                                 SignVerdict *out,
                                 char *signer_out, size_t signer_cap)
{
    bool hit = false;
    EnterCriticalSection(&g_cache_lock);
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_cache[i].used && g_cache[i].persisted &&
            g_cache[i].has_sha256 && g_cache[i].fsize == fsize &&
            ft_equal(&g_cache[i].mtime, mtime) &&
            strcmp(g_cache[i].path, lpath) == 0 &&
            strcmp(g_cache[i].sha256, sha256) == 0) {
            *out = g_cache[i].verdict;
            if (signer_out && signer_cap > 0) {
                strncpy(signer_out, g_cache[i].signer, signer_cap - 1);
                signer_out[signer_cap - 1] = '\0';
            }
            g_cache[i].persisted = false; /* next hit this run is fast */
            hit = true;
            break;
        }
    }
    LeaveCriticalSection(&g_cache_lock);
    return hit;
}

static void cache_put_ex(const char *lpath, const FILETIME *mtime,
                         uint64_t fsize, const char sha256[65],
                         SignVerdict v, const char *signer, bool persisted)
{
    EnterCriticalSection(&g_cache_lock);

    /* If an entry for this path exists (stale metadata), update it in place. */
    for (size_t i = 0; i < g_cache_count; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].path, lpath) == 0) {
            g_cache[i].mtime   = *mtime;
            g_cache[i].fsize   = fsize;
            g_cache[i].verdict = v;
            g_cache[i].has_sha256 = false;
            g_cache[i].sha256[0] = '\0';
            if (sha256 && sha256[0]) {
                strncpy(g_cache[i].sha256, sha256,
                        sizeof g_cache[i].sha256 - 1);
                g_cache[i].sha256[sizeof g_cache[i].sha256 - 1] = '\0';
                g_cache[i].has_sha256 = true;
            }
            g_cache[i].persisted = persisted;
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
    e->fsize   = fsize;
    if (sha256 && sha256[0]) {
        strncpy(e->sha256, sha256, sizeof e->sha256 - 1);
        e->sha256[sizeof e->sha256 - 1] = '\0';
        e->has_sha256 = true;
    }
    e->verdict = v;
    if (signer) {
        size_t n = strlen(signer);
        if (n >= sizeof e->signer) n = sizeof e->signer - 1;
        memcpy(e->signer, signer, n);
        e->signer[n] = '\0';
    }
    e->used = true;
    e->persisted = persisted;

    LeaveCriticalSection(&g_cache_lock);
}

static bool valid_sha256_hex(const char *s)
{
    if (!s || strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        char ch = s[i];
        if (!((ch >= '0' && ch <= '9') ||
              (ch >= 'a' && ch <= 'f') ||
              (ch >= 'A' && ch <= 'F')))
            return false;
    }
    return true;
}

static void lower_hex(char *s)
{
    for (; s && *s; s++) {
        if (*s >= 'A' && *s <= 'F')
            *s = (char)(*s - 'A' + 'a');
    }
}

static char *split_tab(char **cursor)
{
    char *s = *cursor;
    if (!s) return NULL;
    char *tab = strchr(s, '\t');
    if (tab) {
        *tab = '\0';
        *cursor = tab + 1;
    } else {
        *cursor = s + strlen(s);
    }
    return s;
}

static void persistent_cache_load(void)
{
    if (!g_persist_ready || !g_persist_path[0])
        return;

    FILE *f = fopen(g_persist_path, "rb");
    if (!f)
        return;

    char line[SC_MAX_PATH + SC_NAME_LEN + 256];
    if (!fgets(line, sizeof line, f)) {
        fclose(f);
        return;
    }
    if (strncmp(line, "sentinelc-sign-cache-v2", 23) != 0) {
        fclose(f);
        return;
    }

    while (fgets(line, sizeof line, f)) {
        line[sizeof line - 1] = '\0';
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;

        char *p = line;
        char *sha = split_tab(&p);
        char *size_s = split_tab(&p);
        char *mtime_s = split_tab(&p);
        char *verdict_s = split_tab(&p);
        char *signer = split_tab(&p);
        char *path = p;
        if (!sha || !size_s || !mtime_s || !verdict_s || !signer ||
            !path || !path[0])
            continue;
        if (!valid_sha256_hex(sha))
            continue;
        lower_hex(sha);

        char *end = NULL;
        unsigned long long fsize = strtoull(size_s, &end, 10);
        if (!end || *end) continue;
        end = NULL;
        unsigned long long mtime64 = strtoull(mtime_s, &end, 10);
        if (!end || *end) continue;
        long v = strtol(verdict_s, &end, 10);
        if (!end || *end) continue;
        if (v <= SIGN_UNKNOWN || v > SIGN_SIGNED_MS)
            continue;

        str_lower(path);
        FILETIME ft;
        u64_to_ft((uint64_t)mtime64, &ft);
        cache_put_ex(path, &ft, (uint64_t)fsize, sha, (SignVerdict)v,
                     signer, true);
        InterlockedIncrement64(&g_sign_persistent_loaded);
    }

    fclose(f);
}

static void persistent_cache_save(void)
{
    if (!g_persist_ready || !g_persist_path[0] || !g_cache_ready)
        return;

    char tmp[SC_MAX_PATH];
    snprintf(tmp, sizeof tmp, "%s.%lu.tmp", g_persist_path,
             (unsigned long)GetCurrentProcessId());
    tmp[sizeof tmp - 1] = '\0';

    FILE *f = fopen(tmp, "wb");
    if (!f)
        return;

    fprintf(f, "sentinelc-sign-cache-v2\n");

    EnterCriticalSection(&g_cache_lock);
    for (size_t i = 0; i < g_cache_count; i++) {
        SignCacheEntry *e = &g_cache[i];
        if (!e->used || !e->has_sha256 || e->verdict == SIGN_UNKNOWN)
            continue;
        if (!valid_sha256_hex(e->sha256))
            continue;

        char signer[SC_NAME_LEN];
        char path[SC_MAX_PATH];
        strncpy(signer, e->signer, sizeof signer - 1);
        signer[sizeof signer - 1] = '\0';
        strncpy(path, e->path, sizeof path - 1);
        path[sizeof path - 1] = '\0';
        clean_cache_text(signer);
        clean_cache_text(path);

        fprintf(f, "%s\t%llu\t%llu\t%d\t%s\t%s\n",
                e->sha256,
                (unsigned long long)e->fsize,
                (unsigned long long)ft_to_u64(&e->mtime),
                (int)e->verdict,
                signer,
                path);
        InterlockedIncrement64(&g_sign_persistent_saved);
    }
    LeaveCriticalSection(&g_cache_lock);

    if (fclose(f) != 0) {
        DeleteFileA(tmp);
        return;
    }

    apply_admin_system_dacl(tmp);
    if (!MoveFileExA(tmp, g_persist_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(tmp);
        return;
    }
    apply_admin_system_dacl(g_persist_path);
}

void sign_cache_stats(SignCacheStats *out)
{
    if (!out) return;
    memset(out, 0, sizeof *out);
    out->calls = atomic_read64(&g_sign_calls);
    out->memory_hits = atomic_read64(&g_sign_memory_hits);
    out->persistent_hits = atomic_read64(&g_sign_persistent_hits);
    out->verifications = atomic_read64(&g_sign_verifications);
    out->persistent_hash_checks =
        atomic_read64(&g_sign_persistent_hash_checks);
    out->persistent_entries_loaded =
        atomic_read64(&g_sign_persistent_loaded);
    out->persistent_entries_saved =
        atomic_read64(&g_sign_persistent_saved);
    out->persistent_enabled = g_persist_ready;

    if (g_cache_ready) {
        EnterCriticalSection(&g_cache_lock);
        out->entries = (uint64_t)g_cache_count;
        LeaveCriticalSection(&g_cache_lock);
    }
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
    InterlockedIncrement64(&g_sign_calls);
    if (!g_cache_ready) sign_cache_init();   /* tolerate missing init */

    wchar_t wpath[SC_MAX_PATH * 2];
    if (utf8_to_wide(path, wpath, sizeof wpath / sizeof wpath[0]) == 0)
        return SIGN_UNKNOWN;

    /* Metadata + lowercased key. Persistent cache hits also require SHA-256. */
    WIN32_FILE_ATTRIBUTE_DATA fad;
    FILETIME mtime = {0, 0};
    uint64_t fsize = 0;
    bool have_meta = false;
    if (GetFileAttributesExW(wpath, GetFileExInfoStandard, &fad) &&
        !(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        mtime = fad.ftLastWriteTime;
        fsize = ((uint64_t)fad.nFileSizeHigh << 32) |
                (uint64_t)fad.nFileSizeLow;
        have_meta = true;
    }

    char lpath[SC_MAX_PATH];
    strncpy(lpath, path, sizeof lpath - 1);
    lpath[sizeof lpath - 1] = '\0';
    str_lower(lpath);

    SignVerdict cached;
    if (cache_get_fast(lpath, &mtime, fsize, &cached, signer_out, signer_cap)) {
        InterlockedIncrement64(&g_sign_memory_hits);
        return cached;
    }

    char sha256[65] = "";
    if (have_meta && g_persist_ready &&
        cache_has_persistent_candidate(lpath, &mtime, fsize) &&
        sha256_file_hex_w(wpath, fsize, sha256)) {
        InterlockedIncrement64(&g_sign_persistent_hash_checks);
        if (cache_get_persistent(lpath, &mtime, fsize, sha256, &cached,
                                 signer_out, signer_cap)) {
            InterlockedIncrement64(&g_sign_persistent_hits);
            return cached;
        }
    }

    char signer[SC_NAME_LEN] = {0};
    SignVerdict verdict;
    InterlockedIncrement64(&g_sign_verifications);

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

    if (have_meta && g_persist_ready && verdict != SIGN_UNKNOWN &&
        sha256[0] == '\0')
        sha256_file_hex_w(wpath, fsize, sha256);

    cache_put_ex(lpath, &mtime, fsize, sha256, verdict, signer, false);

    if (signer_out && signer_cap > 0) {
        strncpy(signer_out, signer, signer_cap - 1);
        signer_out[signer_cap - 1] = '\0';
    }
    return verdict;
}
