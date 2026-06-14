/* scan_path.c - targeted file / directory scanner.
 *
 * Walks ctx->cfg->scan_path. For a single file: analyze it. For a directory:
 * recurse with FindFirstFile/FindNextFile, skipping reparse points (symlinks /
 * junctions) to avoid loops, and capping recursion depth.
 *
 * For each file we run pe_analyze + sign_verify and emit findings:
 *   FILE.PACKED          (SEV_MED)  looks_packed
 *   FILE.UNSIGNED_PE     (SEV_LOW/MED by location) unsigned PE in system/pf dir
 *   FILE.HIGH_ENTROPY    (SEV_LOW)  entropy > 7.2, non-PE
 *   FILE.SUSPICIOUS_CAPS (SEV_MED)  PE in user-writable/temp with dangerous
 *                                   import combos (hook+net / inject+net /
 *                                   keystate+net)
 *   FILE.IOC_HASH        (severity by match) sha256 matches a loaded IOC
 *   FILE.IOC_STRING      (SEV_HIGH) file content contains a loaded string IOC
 *                                   (e.g. a C2 domain from yara_subset.txt)
 *
 * Hashing is gated on ctx->cfg->deep OR the presence of an IOC set.
 */
#include "sentinelc.h"

#include <bcrypt.h>
#include <string.h>
#include <stdio.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#define SCAN_MAX_DEPTH 32

/* Cumulative count of files analyzed in this scan (drives the progress bar).
 * Single-threaded scanner, so a plain file-local counter is sufficient. */
static uint64_t g_scanned_files;
static ProgressBar *g_scan_bar;

/* Compute the SHA-256 of a file, writing a lowercase 64-char hex string + NUL
 * into hex_out (must be >= 65 bytes). Returns false on any error. */
static bool sha256_file(const wchar_t *wpath, char *hex_out)
{
    bool ok = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE  hashObj = NULL, hashVal = NULL;
    DWORD  cbHashObj = 0, cbHashVal = 0, cbData = 0;
    BYTE   buf[64 * 1024];

    hFile = CreateFileW(wpath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                                NULL, 0)))
        goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                      (PBYTE)&cbHashObj, sizeof cbHashObj,
                                      &cbData, 0)))
        goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                                      (PBYTE)&cbHashVal, sizeof cbHashVal,
                                      &cbData, 0)) ||
        cbHashVal != 32)
        goto cleanup;

    hashObj = (PBYTE)malloc(cbHashObj);
    hashVal = (PBYTE)malloc(cbHashVal);
    if (!hashObj || !hashVal) goto cleanup;

    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj, cbHashObj,
                                     NULL, 0, 0)))
        goto cleanup;

    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hFile, buf, sizeof buf, &rd, NULL)) goto cleanup;
        if (rd == 0) break;
        if (!NT_SUCCESS(BCryptHashData(hHash, buf, rd, 0))) goto cleanup;
    }

    if (!NT_SUCCESS(BCryptFinishHash(hHash, hashVal, cbHashVal, 0)))
        goto cleanup;

    {
        static const char hexd[] = "0123456789abcdef";
        for (DWORD i = 0; i < cbHashVal; i++) {
            hex_out[i * 2]     = hexd[(hashVal[i] >> 4) & 0xF];
            hex_out[i * 2 + 1] = hexd[hashVal[i] & 0xF];
        }
        hex_out[cbHashVal * 2] = '\0';
        ok = true;
    }

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    free(hashObj);
    free(hashVal);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return ok;
}

/* Count the files that scan_dir/scan_one_file would analyze, so the progress
 * bar gets an accurate total + ETA. Mirrors scan_dir's traversal rules
 * (reparse points skipped, same depth cap) but does no analysis. */
static uint64_t count_files(const char *dir, int depth)
{
    if (depth > SCAN_MAX_DEPTH) return 0;

    char pattern[SC_MAX_PATH];
    int n = snprintf(pattern, sizeof pattern, "%s\\*", dir);
    if (n < 0 || (size_t)n >= sizeof pattern) return 0;

    wchar_t wpattern[SC_MAX_PATH * 2];
    if (utf8_to_wide(pattern, wpattern, sizeof wpattern / sizeof wpattern[0]) == 0)
        return 0;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    uint64_t total = 0;
    do {
        char name[SC_MAX_PATH];
        if (wide_to_utf8(fd.cFileName, name, sizeof name) == 0)
            continue;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        bool is_dir     = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        bool is_reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        if (is_reparse)
            continue;

        if (is_dir) {
            char full[SC_MAX_PATH];
            int m = snprintf(full, sizeof full, "%s\\%s", dir, name);
            if (m < 0 || (size_t)m >= sizeof full)
                continue;
            total += count_files(full, depth + 1);
        } else {
            total++;
        }
    } while (FindNextFileW(h, &fd));

    FindClose(h);
    return total;
}

/* Read up to cap-1 bytes of a file into buf and NUL-terminate. Embedded NUL
 * bytes are replaced with spaces so ASCII markers inside binaries still match a
 * substring search. Returns bytes read (0 on error). */
static size_t read_file_text(const char *path, char *buf, size_t cap, bool strip)
{
    if (cap == 0) return 0;
    wchar_t wpath[SC_MAX_PATH * 2];
    if (utf8_to_wide(path, wpath, sizeof wpath / sizeof wpath[0]) == 0)
        return 0;
    HANDLE h = CreateFileW(wpath, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)(cap - 1), &rd, NULL);
    CloseHandle(h);
    if (!ok) return 0;
    /* strip=true: NUL -> space for the NUL-terminated substring IOC matcher.
     * strip=false: keep raw bytes (YARA wide/hex patterns rely on the NULs). */
    if (strip)
        for (DWORD i = 0; i < rd; i++)
            if (buf[i] == '\0') buf[i] = ' ';
    buf[rd] = '\0';
    return rd;
}

/* Examine a single file and emit findings. */
static void scan_one_file(ScanCtx *c, const char *path)
{
    /* advance the progress bar (no-op when not a TTY) */
    g_scanned_files++;
    progress_step(g_scan_bar, g_scanned_files, path);

    PeInfo pe;
    bool is_pe = pe_analyze(path, &pe);

    PathLoc loc = path_classify(path);
    bool user_writable = path_is_user_writable(path);

    /* ---- signature (PE only; non-PE files aren't Authenticode targets) ---- */
    SignVerdict sv = SIGN_UNKNOWN;
    char signer[SC_NAME_LEN] = {0};
    if (is_pe)
        sv = sign_verify(path, signer, sizeof signer);

    /* ---- FILE.PACKED ---- */
    if (is_pe && pe.looks_packed) {
        char hint[80];
        if (pe.packer_hint[0])
            snprintf(hint, sizeof hint, " (%s)", pe.packer_hint);
        else
            hint[0] = '\0';
        bus_emit(c->bus, "FILE.PACKED", SEV_MED, 70, ACT_REVIEW, 0, path,
                 "Packed / high-entropy executable",
                 "max section entropy %.2f, %d imports%s",
                 pe.max_section_entropy, pe.import_count, hint);
    }

    /* ---- FILE.UNSIGNED_PE ---- (system / programfiles dirs) ---- */
    if (is_pe && (sv == SIGN_UNSIGNED || sv == SIGN_INVALID) &&
        (loc == PATHLOC_SYSTEM || loc == PATHLOC_PROGRAMFILES ||
         loc == PATHLOC_WINDOWS)) {
        Severity sev = (loc == PATHLOC_SYSTEM) ? SEV_MED : SEV_LOW;
        bus_emit(c->bus, "FILE.UNSIGNED_PE", sev, 65, ACT_REVIEW, 0, path,
                 (sv == SIGN_INVALID) ? "PE with invalid signature in system path"
                                      : "Unsigned PE in system path",
                 "signature=%s, location=%s",
                 sign_name(sv),
                 (loc == PATHLOC_SYSTEM)       ? "System32/WinSxS" :
                 (loc == PATHLOC_PROGRAMFILES) ? "Program Files" : "Windows");
    }

    /* ---- FILE.HIGH_ENTROPY ---- (non-PE only) ---- */
    if (!is_pe && pe.overall_entropy > 7.2) {
        bus_emit(c->bus, "FILE.HIGH_ENTROPY", SEV_LOW, 50, ACT_REVIEW, 0, path,
                 "High-entropy non-PE file",
                 "overall entropy %.2f (possible encrypted/compressed payload)",
                 pe.overall_entropy);
    }

    /* ---- FILE.SUSPICIOUS_CAPS ---- (PE in user-writable/temp) ---- */
    if (is_pe && (user_writable || loc == PATHLOC_TEMP ||
                  loc == PATHLOC_USER_WRITABLE)) {
        bool hook_net    = pe.imp_hook_api    && pe.imp_net_api;
        bool inject_net  = pe.imp_proc_inject_api && pe.imp_net_api;
        bool keystate_net = pe.imp_keystate_api && pe.imp_net_api;
        if (hook_net || inject_net || keystate_net) {
            const char *combo = inject_net  ? "process-injection + network" :
                                hook_net     ? "windows-hook + network" :
                                               "keystate-capture + network";
            bus_emit(c->bus, "FILE.SUSPICIOUS_CAPS", SEV_MED, 75, ACT_REVIEW,
                     0, path,
                     "Executable in user-writable path with dangerous imports",
                     "imports: %s%s%s%s%s",
                     combo,
                     pe.imp_crypt_api      ? " +crypt"   : "",
                     pe.imp_rawinput_api   ? " +rawinput": "",
                     pe.imp_hook_api       ? " +hook"    : "",
                     pe.looks_packed       ? " +packed"  : "");
        }
    }

    /* ---- FILE.IOC_HASH ---- (compute sha256 when deep or IOC present) ---- */
    if (c->ioc && (c->cfg->deep || c->ioc)) {
        wchar_t wpath[SC_MAX_PATH * 2];
        if (utf8_to_wide(path, wpath, sizeof wpath / sizeof wpath[0]) != 0) {
            char hex[65];
            if (sha256_file(wpath, hex) &&
                ioc_match_hash_sha256(c->ioc, hex)) {
                bus_emit(c->bus, "FILE.IOC_HASH", SEV_HIGH, 95, ACT_QUARANTINE,
                         0, path, "File matches known-bad IOC hash",
                         "sha256=%s", hex);
            }
        }
    }

    /* ---- content checks: YARA-subset rules (raw bytes) + string IOC ---- */
    if (c->yara || c->ioc) {
        /* 1 MiB scan window; single-threaded scanner so a static is safe and
         * avoids a per-file allocation. Read RAW (no NUL strip) for YARA. */
        static char content[1u << 20];
        size_t got = read_file_text(path, content, sizeof content, false);
        if (got > 0) {
            char rulename[80];
            if (c->yara &&
                yara_scan(c->yara, (const unsigned char *)content, got,
                          rulename, sizeof rulename)) {
                bus_emit(c->bus, "FILE.YARA_MATCH", SEV_HIGH, 85, ACT_QUARANTINE,
                         0, path, "File content matches a YARA rule",
                         "matched YARA rule '%s'", rulename);
            }
            /* the string IOC matcher is NUL-terminated; strip embedded NULs. */
            if (c->ioc) {
                for (size_t i = 0; i < got; i++)
                    if (content[i] == '\0') content[i] = ' ';
                content[got] = '\0';
                if (ioc_match_string(c->ioc, content)) {
                    bus_emit(c->bus, "FILE.IOC_STRING", SEV_HIGH, 90, ACT_QUARANTINE,
                             0, path, "File content matches a known-bad string IOC",
                             "matched a loaded indicator (string/C2 domain)");
                }
            }
        }
    }
}

/* Recurse into a directory. depth bounds the descent; reparse points are
 * skipped to avoid symlink/junction loops. */
static void scan_dir(ScanCtx *c, const char *dir, int depth)
{
    if (depth > SCAN_MAX_DEPTH) return;

    char pattern[SC_MAX_PATH];
    int n = snprintf(pattern, sizeof pattern, "%s\\*", dir);
    if (n < 0 || (size_t)n >= sizeof pattern) return;

    wchar_t wpattern[SC_MAX_PATH * 2];
    if (utf8_to_wide(pattern, wpattern, sizeof wpattern / sizeof wpattern[0]) == 0)
        return;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "access denied listing directory: %s", dir);
        return;
    }

    do {
        char name[SC_MAX_PATH];
        if (wide_to_utf8(fd.cFileName, name, sizeof name) == 0)
            continue;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        char full[SC_MAX_PATH];
        int m = snprintf(full, sizeof full, "%s\\%s", dir, name);
        if (m < 0 || (size_t)m >= sizeof full)
            continue;   /* path too long; skip */

        bool is_dir     = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        bool is_reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

        if (is_reparse)
            continue;   /* don't follow symlinks/junctions */

        if (is_dir)
            scan_dir(c, full, depth + 1);
        else
            scan_one_file(c, full);

    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

void scan_path(ScanCtx *c)
{
    if (!c || !c->cfg) return;
    const char *target = c->cfg->scan_path;
    if (!target || target[0] == '\0')
        return;   /* not a path scan */

    wchar_t wtarget[SC_MAX_PATH * 2];
    if (utf8_to_wide(target, wtarget, sizeof wtarget / sizeof wtarget[0]) == 0) {
        ctx_note_limit(c, "could not convert scan path: %s", target);
        return;
    }

    DWORD attr = GetFileAttributesW(wtarget);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "access denied: %s", target);
        else
            ctx_note_limit(c, "scan path not found: %s", target);
        return;
    }

    /* Progress: count the relevant files first, then scan with a bar over
     * file count. The bar is TTY-gated, so it stays silent (and stdout JSON
     * stays clean) when output is redirected. A single file => total 1. */
    g_scanned_files = 0;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        uint64_t total = count_files(target, 0);
        g_scan_bar = progress_begin("Scanning", total, false /* files */);
        scan_dir(c, target, 0);
    } else {
        g_scan_bar = progress_begin("Scanning", 1, false /* files */);
        scan_one_file(c, target);
    }
    progress_end(g_scan_bar);
    g_scan_bar = NULL;
}
