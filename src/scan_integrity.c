/* scan_integrity.c - Merkle-tree file integrity monitoring (FIM).
 *
 * Two standalone modes, dispatched from main.c:
 *
 *   --baseline   Walk a set of roots, hash every execution-relevant file
 *                (PE/binary, script, code, doc/config by extension), build a
 *                binary Merkle tree over the per-file leaves, and write a TSV
 *                manifest (the "baseline") to disk along with the Merkle root.
 *
 *   --integrity  Re-walk the same roots, rebuild the current manifest + root,
 *                and diff against the stored baseline keyed by lowercased
 *                absolute path: ADDED / REMOVED / MODIFIED. Prints the full
 *                absolute paths of each change (console or --json), emits bus
 *                findings for execution-relevant changes, and audit-logs the
 *                summary.
 *
 * Leaf:   SHA256( lowercased_utf8_abspath || 0x00 || raw32(content_sha256) )
 * Parent: SHA256( left || right )  (odd tail duplicated)
 * Leaves are sorted case-insensitively by absolute path before tree build.
 *
 * Everything streams: file content is hashed in 1 MiB blocks, so large files
 * never sit whole in RAM. Files > 512 MiB skip content hashing and record a
 * sentinel hash (still tracked by size + mtime). Reparse points are skipped to
 * avoid symlink/junction loops; recursion is depth-capped. Wide (W) APIs are
 * used throughout for Unicode paths; paths are stored/compared as UTF-8.
 */
#include "sentinelc.h"

#include <bcrypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <io.h>      /* _isatty, _fileno (enumerating banner gating) */

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#define FIM_MAX_DEPTH        64
#define FIM_HASH_BLOCK       (1u * 1024u * 1024u)   /* 1 MiB stream block */
#define FIM_BIG_FILE_BYTES   (512ull * 1024ull * 1024ull)
#define FIM_EMPTY_ROOT \
    "0000000000000000000000000000000000000000000000000000000000000000"
/* sentinel content hash for files too large to hash (still tracked) */
#define FIM_BIG_SENTINEL \
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

/* ---- one tracked file ---- */
typedef struct {
    char     *path;        /* UTF-8 absolute path (original case) */
    char     *key;         /* lowercased path for sort/compare */
    char      sha[65];     /* content sha256 hex, lowercase */
    uint64_t  size;
    uint64_t  mtime;       /* last-write FILETIME as u64 */
    uint8_t   leaf[32];    /* leaf hash (binding path+content) */
} FimEntry;

typedef struct {
    FimEntry *items;
    size_t    count;
    size_t    cap;
} FimList;

/* ================================================================== */
/* hex / small helpers                                                 */
/* ================================================================== */

static void hex_encode(const uint8_t *in, size_t n, char *out /* >=2n+1 */)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = hexd[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexd[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}

/* parse 64 lowercase/upper hex chars into 32 bytes; false on bad input */
static bool hex_decode32(const char *hex, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        int hi = hex[i * 2], lo = hex[i * 2 + 1];
        int hv, lv;
        if      (hi >= '0' && hi <= '9') hv = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hv = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hv = hi - 'A' + 10;
        else return false;
        if      (lo >= '0' && lo <= '9') lv = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lv = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lv = lo - 'A' + 10;
        else return false;
        out[i] = (uint8_t)((hv << 4) | lv);
    }
    return true;
}

/* duplicate s; NULL-safe-ish (returns NULL on OOM) */
static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

/* lowercase ASCII copy (paths are case-insensitive on Windows) */
static char *dup_lower(const char *s)
{
    char *p = dup_str(s);
    if (p) str_lower(p);
    return p;
}

/* ================================================================== */
/* SHA-256 primitives (BCrypt)                                         */
/* ================================================================== */

/* One-shot SHA-256 over a memory buffer -> 32 raw bytes. false on error. */
static bool sha256_buf(const uint8_t *data, size_t len, uint8_t out[32])
{
    bool ok = false;
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE  hashObj = NULL;
    DWORD  cbHashObj = 0, cbData = 0;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        return false;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                      (PBYTE)&cbHashObj, sizeof cbHashObj, &cbData, 0)))
        goto cleanup;
    hashObj = (PBYTE)malloc(cbHashObj);
    if (!hashObj) goto cleanup;
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj, cbHashObj, NULL, 0, 0)))
        goto cleanup;
    if (len && !NT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0)))
        goto cleanup;
    if (!NT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0)))
        goto cleanup;
    ok = true;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    free(hashObj);
    return ok;
}

/* Stream the file contents -> 32 raw bytes, 1 MiB at a time. false on error. */
static bool sha256_file_raw(const wchar_t *wpath, uint8_t out[32])
{
    bool ok = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE  hashObj = NULL, buf = NULL;
    DWORD  cbHashObj = 0, cbData = 0;

    hFile = CreateFileW(wpath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                                      (PBYTE)&cbHashObj, sizeof cbHashObj, &cbData, 0)))
        goto cleanup;
    hashObj = (PBYTE)malloc(cbHashObj);
    buf     = (PBYTE)malloc(FIM_HASH_BLOCK);
    if (!hashObj || !buf) goto cleanup;
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, hashObj, cbHashObj, NULL, 0, 0)))
        goto cleanup;

    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hFile, buf, FIM_HASH_BLOCK, &rd, NULL)) goto cleanup;
        if (rd == 0) break;
        if (!NT_SUCCESS(BCryptHashData(hHash, buf, rd, 0))) goto cleanup;
    }
    if (!NT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0))) goto cleanup;
    ok = true;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    free(hashObj);
    free(buf);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return ok;
}

/* ================================================================== */
/* extension filter -- "impacts execution"                            */
/* ================================================================== */

static bool ext_is_relevant(const char *name)
{
    static const char *exts[] = {
        /* PE / binary */
        ".exe",".dll",".sys",".scr",".com",".cpl",".ocx",".drv",".efi",".mui",".mun",
        /* scripts */
        ".ps1",".psm1",".psd1",".bat",".cmd",".vbs",".vbe",".js",".jse",".wsf",".wsh",
        ".hta",".py",".pl",".rb",".lua",".sh",
        /* code */
        ".c",".h",".cpp",".cc",".cxx",".hpp",".hh",".cs",".java",".go",".rs",".ts",
        ".tsx",".jsx",".php",
        /* docs / cfg */
        ".md",".json",".yml",".yaml",".xml",".ini",".conf",".cfg",".toml",".reg",
        ".inf",".lnk",".manifest",
        NULL
    };
    for (int i = 0; exts[i]; i++)
        if (str_iendswith(name, exts[i]))
            return true;
    return false;
}

/* True for a PE/binary extension (for severity decisions on findings). */
static bool ext_is_pe(const char *name)
{
    static const char *exts[] = {
        ".exe",".dll",".sys",".scr",".com",".cpl",".ocx",".drv",".efi",NULL
    };
    for (int i = 0; exts[i]; i++)
        if (str_iendswith(name, exts[i]))
            return true;
    return false;
}

static bool path_in_system_dir(const char *path)
{
    PathLoc loc = path_classify(path);
    return loc == PATHLOC_SYSTEM || loc == PATHLOC_PROGRAMFILES ||
           loc == PATHLOC_WINDOWS;
}

/* ================================================================== */
/* FimList management                                                  */
/* ================================================================== */

static void list_init(FimList *l) { l->items = NULL; l->count = 0; l->cap = 0; }

static void list_free(FimList *l)
{
    for (size_t i = 0; i < l->count; i++) {
        free(l->items[i].path);
        free(l->items[i].key);
    }
    free(l->items);
    l->items = NULL; l->count = 0; l->cap = 0;
}

/* append a copy of an entry (takes ownership of nothing; dups strings).
 * Returns the new slot or NULL on OOM. */
static FimEntry *list_add(FimList *l, const char *path, const char *sha,
                          uint64_t size, uint64_t mtime)
{
    if (l->count == l->cap) {
        size_t nc = l->cap ? l->cap * 2 : 1024;
        if (nc < l->cap || nc > SIZE_MAX / sizeof(FimEntry))
            return NULL;
        FimEntry *ni = (FimEntry *)realloc(l->items, nc * sizeof(FimEntry));
        if (!ni) return NULL;
        l->items = ni;
        l->cap = nc;
    }
    FimEntry *e = &l->items[l->count];
    memset(e, 0, sizeof(*e));
    e->path = dup_str(path);
    e->key  = dup_lower(path);
    if (!e->path || !e->key) { free(e->path); free(e->key); return NULL; }
    snprintf(e->sha, sizeof e->sha, "%s", sha);
    e->size  = size;
    e->mtime = mtime;
    l->count++;
    return e;
}

static int entry_cmp(const void *a, const void *b)
{
    const FimEntry *ea = (const FimEntry *)a;
    const FimEntry *eb = (const FimEntry *)b;
    return strcmp(ea->key, eb->key);
}

/* Compute each entry's leaf hash from its (lowercased path, content sha). */
static void list_compute_leaves(FimList *l)
{
    for (size_t i = 0; i < l->count; i++) {
        FimEntry *e = &l->items[i];
        uint8_t content[32];
        if (!hex_decode32(e->sha, content))
            memset(content, 0, sizeof content);

        size_t klen = strlen(e->key);
        /* buffer = key || 0x00 || raw32 */
        size_t blen = klen + 1 + 32;
        uint8_t *buf = (uint8_t *)malloc(blen);
        if (!buf) { memset(e->leaf, 0, 32); continue; }
        memcpy(buf, e->key, klen);
        buf[klen] = 0x00;
        memcpy(buf + klen + 1, content, 32);
        if (!sha256_buf(buf, blen, e->leaf))
            memset(e->leaf, 0, 32);
        free(buf);
    }
}

/* ================================================================== */
/* Merkle root over sorted leaves                                      */
/* ================================================================== */

/* Build the Merkle root (hex64) from the list's leaf hashes (must be sorted).
 * Empty set => FIM_EMPTY_ROOT. */
static void merkle_root(const FimList *l, char root_hex[65])
{
    if (l->count == 0) {
        snprintf(root_hex, 65, "%s", FIM_EMPTY_ROOT);
        return;
    }

    size_t n = l->count;
    if (n > SIZE_MAX / 32) { snprintf(root_hex, 65, "%s", FIM_EMPTY_ROOT); return; }
    uint8_t (*level)[32] = (uint8_t (*)[32])malloc(n * 32);
    if (!level) { snprintf(root_hex, 65, "%s", FIM_EMPTY_ROOT); return; }
    for (size_t i = 0; i < n; i++)
        memcpy(level[i], l->items[i].leaf, 32);

    while (n > 1) {
        size_t parents = (n + 1) / 2;
        uint8_t (*next)[32] = (uint8_t (*)[32])malloc(parents * 32);
        if (!next) { free(level); snprintf(root_hex, 65, "%s", FIM_EMPTY_ROOT); return; }
        for (size_t i = 0; i < parents; i++) {
            uint8_t pair[64];
            memcpy(pair, level[i * 2], 32);
            /* odd tail: duplicate the last node */
            if (i * 2 + 1 < n) memcpy(pair + 32, level[i * 2 + 1], 32);
            else               memcpy(pair + 32, level[i * 2], 32);
            if (!sha256_buf(pair, 64, next[i]))
                memset(next[i], 0, 32);
        }
        free(level);
        level = next;
        n = parents;
    }

    hex_encode(level[0], 32, root_hex);
    free(level);
}

/* ================================================================== */
/* directory walk                                                      */
/* ================================================================== */

typedef struct {
    ScanCtx  *ctx;
    FimList  *list;
    bool      noted_denied;   /* note access-denied at most once */

    /* progress / two-pass state */
    bool         count_only;  /* pass 1: tally only, no hash/list/qualify */
    uint64_t     files_total; /* pass 1 result: relevant file count */
    uint64_t     bytes_total; /* pass 1 result: bytes that WILL be hashed */
    uint64_t     files_done;  /* pass 2: files processed so far */
    uint64_t     bytes_done;  /* pass 2: bytes hashed so far */
    ProgressBar *bar;         /* pass 2 progress bar (may be NULL) */
} WalkState;

/* Recurse a directory (wide path), collecting relevant files into st->list. */
static void walk_dir(WalkState *st, const wchar_t *wdir, int depth)
{
    if (depth > FIM_MAX_DEPTH) return;

    size_t dl = wcslen(wdir);
    /* pattern = wdir + "\\*" */
    wchar_t *pat = (wchar_t *)malloc((dl + 3) * sizeof(wchar_t));
    if (!pat) return;
    memcpy(pat, wdir, dl * sizeof(wchar_t));
    pat[dl] = L'\\'; pat[dl + 1] = L'*'; pat[dl + 2] = L'\0';

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    free(pat);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_ACCESS_DENIED && !st->noted_denied) {
            ctx_note_limit(st->ctx, "FIM: access denied during integrity walk");
            st->noted_denied = true;
        }
        return;
    }

    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == L'\0' ||
             (fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0')))
            continue;

        bool is_dir     = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        bool is_reparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        if (is_reparse) continue;   /* don't follow symlinks/junctions */

        /* full = wdir + "\\" + name */
        size_t nl = wcslen(fd.cFileName);
        wchar_t *full = (wchar_t *)malloc((dl + 1 + nl + 1) * sizeof(wchar_t));
        if (!full) continue;
        memcpy(full, wdir, dl * sizeof(wchar_t));
        full[dl] = L'\\';
        memcpy(full + dl + 1, fd.cFileName, (nl + 1) * sizeof(wchar_t));

        if (is_dir) {
            walk_dir(st, full, depth + 1);
            free(full);
            continue;
        }

        /* file: filter by extension first (cheap) */
        char u8name[SC_MAX_PATH];
        if (wide_to_utf8(fd.cFileName, u8name, sizeof u8name) == 0 ||
            !ext_is_relevant(u8name)) {
            free(full);
            continue;
        }

        /* size from the find record (needed by both passes) */
        uint64_t fsize = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

        /* PASS 1 (count_only): tally and move on. Big files are sentinel'd
         * (~0 hash time), so exclude their bytes to keep the ETA honest. Do
         * NOT hash, list_add, or GetFullPathName here -- keep pass 1 cheap. */
        if (st->count_only) {
            st->files_total++;
            if (fsize <= FIM_BIG_FILE_BYTES)
                st->bytes_total += fsize;
            free(full);
            continue;
        }

        /* fully-qualify */
        wchar_t wabs[SC_MAX_PATH * 2];
        DWORD glen = GetFullPathNameW(full, SC_MAX_PATH * 2, wabs, NULL);
        const wchar_t *use = (glen > 0 && glen < SC_MAX_PATH * 2) ? wabs : full;

        char u8abs[SC_MAX_PATH * 2];
        if (wide_to_utf8(use, u8abs, sizeof u8abs) == 0) {
            free(full);
            continue;
        }

        /* size + mtime from the find record */
        uint64_t size  = fsize;
        uint64_t mtime = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) |
                          fd.ftLastWriteTime.dwLowDateTime;

        /* advance the progress bar for every file we touch (even skipped /
         * denied below) so it keeps moving and matches the pass-1 tally. */
        st->files_done++;
        st->bytes_done += (size <= FIM_BIG_FILE_BYTES) ? size : 0;
        progress_step(st->bar, st->bytes_done, u8abs);

        /* content hash (stream), unless the file is huge */
        char hex[65];
        if (size > FIM_BIG_FILE_BYTES) {
            snprintf(hex, sizeof hex, "%s", FIM_BIG_SENTINEL);
        } else {
            uint8_t raw[32];
            if (!sha256_file_raw(use, raw)) {
                if (!st->noted_denied) {
                    ctx_note_limit(st->ctx, "FIM: could not open a file for hashing");
                    st->noted_denied = true;
                }
                free(full);
                continue;
            }
            hex_encode(raw, 32, hex);
        }

        if (!list_add(st->list, u8abs, hex, size, mtime)) {
            /* OOM: stop adding but don't crash */
            free(full);
            FindClose(h);
            return;
        }
        free(full);
    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

/* ================================================================== */
/* roots parsing                                                       */
/* ================================================================== */

#define FIM_MAX_ROOTS 64

typedef struct {
    char  *items[FIM_MAX_ROOTS];   /* UTF-8 root paths (heap) */
    size_t count;
} RootSet;

static void roots_free(RootSet *r)
{
    for (size_t i = 0; i < r->count; i++)
        free(r->items[i]);
    r->count = 0;
}

static void roots_add(RootSet *r, const char *p)
{
    if (r->count >= FIM_MAX_ROOTS || !p || !p[0]) return;
    /* trim leading/trailing spaces */
    while (*p == ' ') p++;
    char *d = dup_str(p);
    if (!d) return;
    size_t n = strlen(d);
    while (n > 0 && (d[n - 1] == ' ' || d[n - 1] == '\\')) d[--n] = '\0';
    if (n == 0) { free(d); return; }
    r->items[r->count++] = d;
}

/* Split a semicolon list into roots. */
static void roots_parse_list(RootSet *r, const char *list)
{
    const char *s = list;
    char buf[SC_MAX_PATH];
    size_t bi = 0;
    for (;; s++) {
        if (*s == ';' || *s == '\0') {
            buf[bi] = '\0';
            if (bi > 0) roots_add(r, buf);
            bi = 0;
            if (*s == '\0') break;
        } else if (bi + 1 < sizeof buf) {
            buf[bi++] = *s;
        }
    }
}

/* Default roots, expanding %USERPROFILE%. Existing-dir check happens later. */
static void roots_defaults(RootSet *r)
{
    roots_add(r, "C:\\Windows\\System32");
    roots_add(r, "C:\\Windows\\SysWOW64");
    roots_add(r, "C:\\Program Files");
    roots_add(r, "C:\\Program Files (x86)");

    wchar_t wprof[SC_MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"USERPROFILE", wprof, SC_MAX_PATH);
    if (n > 0 && n < SC_MAX_PATH) {
        char prof[SC_MAX_PATH];
        if (wide_to_utf8(wprof, prof, sizeof prof) > 0) {
            char appl[SC_MAX_PATH + 64];
            snprintf(appl, sizeof appl, "%s\\AppData\\Local\\Programs", prof);
            roots_add(r, appl);
        }
    }
}

static bool dir_exists_u8(const char *path)
{
    wchar_t w[SC_MAX_PATH * 2];
    if (utf8_to_wide(path, w, SC_MAX_PATH * 2) == 0) return false;
    DWORD a = GetFileAttributesW(w);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

/* Join roots with ';' into out (for the baseline header). */
static void roots_join(const RootSet *r, char *out, size_t cap)
{
    out[0] = '\0';
    size_t used = 0;
    for (size_t i = 0; i < r->count; i++) {
        int w = snprintf(out + used, cap - used, "%s%s",
                         i ? ";" : "", r->items[i]);
        if (w < 0 || (size_t)w >= cap - used) break;
        used += (size_t)w;
    }
}

/* ================================================================== */
/* baseline file path + I/O                                            */
/* ================================================================== */

/* Resolve the baseline file path into out (UTF-8). Uses cfg override or the
 * default %ProgramData%\SentinelC\integrity\baseline.tsv (dirs created). */
static void resolve_baseline_path(const Config *cfg, char *out, size_t cap)
{
    if (cfg->baseline_file[0]) {
        snprintf(out, cap, "%s", cfg->baseline_file);
        return;
    }
    wchar_t wpd[SC_MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ProgramData", wpd, SC_MAX_PATH);
    char pd[SC_MAX_PATH] = "C:\\ProgramData";
    if (n > 0 && n < SC_MAX_PATH)
        wide_to_utf8(wpd, pd, sizeof pd);
    snprintf(out, cap, "%s\\SentinelC\\integrity\\baseline.tsv", pd);
}

/* Create parent directories of a file path (best effort). */
static void ensure_parent_dirs(const char *file_path)
{
    wchar_t w[SC_MAX_PATH * 2];
    if (utf8_to_wide(file_path, w, SC_MAX_PATH * 2) == 0) return;
    /* strip filename */
    size_t len = wcslen(w);
    while (len > 0 && w[len - 1] != L'\\' && w[len - 1] != L'/') len--;
    if (len == 0) return;
    w[len - 1] = L'\0';
    /* walk and create each component */
    for (size_t i = 3; i <= wcslen(w); i++) {   /* skip "C:\" drive root */
        if (w[i] == L'\\' || w[i] == L'\0') {
            wchar_t save = w[i];
            w[i] = L'\0';
            CreateDirectoryW(w, NULL);   /* ignore "already exists" */
            w[i] = save;
            if (save == L'\0') break;
        }
    }
    CreateDirectoryW(w, NULL);
}

/* Replace any literal tab in a path with "%09" (TSV safety). Returns a heap
 * copy the caller must free, or NULL on OOM. */
static char *path_tab_escape(const char *p, bool *escaped)
{
    *escaped = false;
    size_t tabs = 0;
    for (const char *q = p; *q; q++) if (*q == '\t') tabs++;
    if (tabs == 0) return dup_str(p);
    *escaped = true;
    size_t n = strlen(p) + tabs * 2 + 1;
    char *out = (char *)malloc(n);
    if (!out) return NULL;
    char *d = out;
    for (const char *q = p; *q; q++) {
        if (*q == '\t') { *d++ = '%'; *d++ = '0'; *d++ = '9'; }
        else            { *d++ = *q; }
    }
    *d = '\0';
    return out;
}

/* Write the manifest to disk (sorted by path). Returns false on I/O error. */
static bool baseline_write(const char *file_path, const FimList *l,
                           const char *root_hex, const char *roots_joined)
{
    ensure_parent_dirs(file_path);

    wchar_t w[SC_MAX_PATH * 2];
    if (utf8_to_wide(file_path, w, SC_MAX_PATH * 2) == 0) return false;
    FILE *f = _wfopen(w, L"wb");
    if (!f) return false;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "#SENTINELC-FIM v1\troot=%s\tcount=%zu\tcreated=%04d-%02d-%02d %02d:%02d:%02d\troots=%s\n",
            root_hex, l->count,
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            roots_joined);

    for (size_t i = 0; i < l->count; i++) {
        const FimEntry *e = &l->items[i];
        bool esc = false;
        char *safe = path_tab_escape(e->path, &esc);
        if (!safe) continue;
        fprintf(f, "%s\t%llu\t%llu\t%s\n",
                e->sha, (unsigned long long)e->size,
                (unsigned long long)e->mtime, safe);
        free(safe);
    }
    fclose(f);
    return true;
}

/* Loaded baseline header info. */
typedef struct {
    char root[65];
    char created[32];
    char roots[4096];
    bool ok;
} BaselineHdr;

/* Load a baseline file into list + header. Returns false if file missing. */
static bool baseline_load(const char *file_path, FimList *out, BaselineHdr *hdr)
{
    memset(hdr, 0, sizeof *hdr);
    wchar_t w[SC_MAX_PATH * 2];
    if (utf8_to_wide(file_path, w, SC_MAX_PATH * 2) == 0) return false;
    FILE *f = _wfopen(w, L"rb");
    if (!f) return false;

    char *line = NULL;
    size_t cap = 0;
    /* read line by line with a growable buffer */
    int c;
    bool first = true;
    for (;;) {
        size_t len = 0;
        for (;;) {
            c = fgetc(f);
            if (c == EOF || c == '\n') break;
            if (len + 1 >= cap) {
                size_t nc = cap ? cap * 2 : 256;
                char *nl = (char *)realloc(line, nc);
                if (!nl) { free(line); fclose(f); return hdr->ok; }
                line = nl; cap = nc;
            }
            if (c != '\r') line[len++] = (char)c;
        }
        if (len == 0 && c == EOF) break;
        if (len + 1 >= cap) {
            size_t nc = cap ? cap * 2 : 256;
            char *nl = (char *)realloc(line, nc);
            if (!nl) break;
            line = nl; cap = nc;
        }
        line[len] = '\0';

        if (first) {
            first = false;
            if (strncmp(line, "#SENTINELC-FIM", 14) == 0) {
                hdr->ok = true;
                /* parse tab fields */
                char *save = NULL;
                for (char *tok = strtok_s(line, "\t", &save); tok;
                     tok = strtok_s(NULL, "\t", &save)) {
                    if (strncmp(tok, "root=", 5) == 0)
                        snprintf(hdr->root, sizeof hdr->root, "%s", tok + 5);
                    else if (strncmp(tok, "created=", 8) == 0)
                        snprintf(hdr->created, sizeof hdr->created, "%s", tok + 8);
                    else if (strncmp(tok, "roots=", 6) == 0)
                        snprintf(hdr->roots, sizeof hdr->roots, "%s", tok + 6);
                }
            }
            if (c == EOF) break;
            continue;
        }

        /* data line: sha \t size \t mtime \t path (path = last field) */
        char *p = line;
        char *t1 = strchr(p, '\t');           if (!t1) { if (c == EOF) break; continue; }
        *t1 = '\0';
        char *t2 = strchr(t1 + 1, '\t');       if (!t2) { if (c == EOF) break; continue; }
        *t2 = '\0';
        char *t3 = strchr(t2 + 1, '\t');       if (!t3) { if (c == EOF) break; continue; }
        *t3 = '\0';
        const char *sha   = p;
        uint64_t size     = _strtoui64(t1 + 1, NULL, 10);
        uint64_t mtime    = _strtoui64(t2 + 1, NULL, 10);
        const char *path  = t3 + 1;   /* embedded spaces fine; last field */
        if (strlen(sha) == 64)
            list_add(out, path, sha, size, mtime);

        if (c == EOF) break;
    }
    free(line);
    fclose(f);
    return hdr->ok;
}

/* ================================================================== */
/* JSON output helpers                                                 */
/* ================================================================== */

static void json_print_escaped(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '\\': fputs("\\\\", f); break;
        case '"':  fputs("\\\"", f); break;
        case '\n': fputs("\\n", f);  break;
        case '\r': fputs("\\r", f);  break;
        case '\t': fputs("\\t", f);  break;
        default:
            if (*p < 0x20) fprintf(f, "\\u%04x", *p);
            else           fputc(*p, f);
        }
    }
    fputc('"', f);
}

/* ================================================================== */
/* walking all roots into a list                                       */
/* ================================================================== */

/* Walk every existing root once. count_only controls pass 1 (tally) vs pass 2
 * (hash + collect). skipped (pass 1 only) records missing roots for the report;
 * pass 2 passes NULL since the set is identical. */
static void walk_all_roots(WalkState *st, const RootSet *roots, char *skipped)
{
    if (skipped) skipped[0] = '\0';
    for (size_t i = 0; i < roots->count; i++) {
        if (!dir_exists_u8(roots->items[i])) {
            if (skipped) {
                size_t used = strlen(skipped);
                snprintf(skipped + used, 1024 - used, "%s%s",
                         used ? ", " : "", roots->items[i]);
            }
            continue;
        }
        wchar_t wroot[SC_MAX_PATH * 2];
        if (utf8_to_wide(roots->items[i], wroot, SC_MAX_PATH * 2) == 0)
            continue;
        /* fully-qualify the root itself */
        wchar_t wabs[SC_MAX_PATH * 2];
        DWORD glen = GetFullPathNameW(wroot, SC_MAX_PATH * 2, wabs, NULL);
        walk_dir(st, (glen > 0 && glen < SC_MAX_PATH * 2) ? wabs : wroot, 0);
    }
}

static void build_manifest(ScanCtx *c, const RootSet *roots, FimList *out,
                           char skipped[1024])
{
    skipped[0] = '\0';

    WalkState st;
    memset(&st, 0, sizeof st);
    st.ctx  = c;
    st.list = out;

    /* PASS 1: count relevant files and the bytes that will actually be hashed,
     * so the bar in pass 2 can show an accurate %/ETA. Cheap: enumeration +
     * extension filter only, no hashing. */
    if (_isatty(_fileno(stderr)))
        fprintf(stderr, "Enumerating files...\r");
    st.count_only = true;
    walk_all_roots(&st, roots, skipped);
    st.count_only = false;

    /* PASS 2: hash + collect, driving a progress bar over hashed bytes. The bar
     * is TTY-gated inside progress_begin, so this is silent under redirection
     * (--json) and leaves stdout untouched. */
    st.bar = progress_begin("Hashing files", st.bytes_total, true /* bytes */);
    walk_all_roots(&st, roots, NULL);
    progress_end(st.bar);

    qsort(out->items, out->count, sizeof(FimEntry), entry_cmp);
    list_compute_leaves(out);
}

/* find an entry by lowercased key via binary search (list is sorted by key) */
static FimEntry *list_find(FimList *l, const char *key)
{
    size_t lo = 0, hi = l->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int cmp = strcmp(l->items[mid].key, key);
        if (cmp == 0) return &l->items[mid];
        if (cmp < 0)  lo = mid + 1;
        else          hi = mid;
    }
    return NULL;
}

/* ================================================================== */
/* MODE A: --baseline                                                  */
/* ================================================================== */

static void run_baseline(ScanCtx *c, RootSet *roots)
{
    char bpath[SC_MAX_PATH];
    resolve_baseline_path(c->cfg, bpath, sizeof bpath);

    char roots_joined[4096];
    roots_join(roots, roots_joined, sizeof roots_joined);

    printf("SentinelC FIM: building baseline...\n");
    printf("Roots: %s\n", roots_joined[0] ? roots_joined : "(none)");
    printf("Note: scanning large system roots is slow on the first baseline.\n"
           "      Pass --integrity-roots \"DIR\" to scope it (e.g. a single\n"
           "      project directory for code + markdown).\n");

    DWORD t0 = GetTickCount();
    FimList list; list_init(&list);
    char skipped[1024];
    build_manifest(c, roots, &list, skipped);

    char root_hex[65];
    merkle_root(&list, root_hex);

    bool wrote = baseline_write(bpath, &list, root_hex, roots_joined);
    double secs = (GetTickCount() - t0) / 1000.0;

    if (c->cfg->json) {
        printf("{\"mode\":\"baseline\",\"files\":%zu,\"merkle_root\":\"%s\",",
               list.count, root_hex);
        printf("\"baseline_file\":");
        json_print_escaped(stdout, bpath);
        printf(",\"elapsed_seconds\":%.2f,\"written\":%s",
               secs, wrote ? "true" : "false");
        if (skipped[0]) { printf(",\"skipped_roots\":"); json_print_escaped(stdout, skipped); }
        printf("}\n");
    } else {
        printf("\nBaseline complete.\n");
        printf("  Files indexed : %zu\n", list.count);
        printf("  Merkle root   : %s\n", root_hex);
        printf("  Baseline file : %s%s\n", bpath, wrote ? "" : "  (WRITE FAILED)");
        printf("  Elapsed       : %.2f s\n", secs);
        if (skipped[0])
            printf("  Skipped roots : %s\n", skipped);
    }

    audit_logf("FIM baseline: root=%s count=%zu file=%s%s",
               root_hex, list.count, bpath, wrote ? "" : " (WRITE FAILED)");

    list_free(&list);
}

/* ================================================================== */
/* MODE B: --integrity                                                 */
/* ================================================================== */

static void run_check(ScanCtx *c, RootSet *roots, bool roots_from_cli)
{
    char bpath[SC_MAX_PATH];
    resolve_baseline_path(c->cfg, bpath, sizeof bpath);

    FimList base; list_init(&base);
    BaselineHdr hdr;
    if (!baseline_load(bpath, &base, &hdr) || !hdr.ok) {
        printf("No baseline found at: %s\n", bpath);
        printf("Run with --baseline first (optionally with --integrity-roots) "
               "to create one.\n");
        list_free(&base);
        return;
    }

    /* If the caller didn't pass roots, re-use the baseline's recorded scope so
     * the check matches the baseline exactly. */
    if (!roots_from_cli && hdr.roots[0]) {
        roots_free(roots);
        roots_parse_list(roots, hdr.roots);
    }

    char skipped[1024];
    FimList cur; list_init(&cur);
    build_manifest(c, roots, &cur, skipped);

    char cur_root[65];
    merkle_root(&cur, cur_root);

    bool match = (strcmp(cur_root, hdr.root) == 0);

    /* diff: mark baseline entries seen; collect modified/added/removed indices */
    /* MODIFIED + ADDED come from iterating current; REMOVED from baseline. */
    size_t *mod = (size_t *)malloc(cur.count * sizeof(size_t));
    size_t *add = (size_t *)malloc(cur.count * sizeof(size_t));
    size_t *rem = (size_t *)malloc(base.count * sizeof(size_t));
    char   *seen = (char *)calloc(base.count ? base.count : 1, 1);
    size_t nmod = 0, nadd = 0, nrem = 0;
    if ((cur.count && (!mod || !add)) || (base.count && (!rem || !seen))) {
        free(mod); free(add); free(rem); free(seen);
        list_free(&base); list_free(&cur);
        printf("FIM: out of memory during diff.\n");
        return;
    }

    for (size_t i = 0; i < cur.count; i++) {
        FimEntry *b = list_find(&base, cur.items[i].key);
        if (!b) {
            add[nadd++] = i;
        } else {
            /* mark this baseline entry as seen */
            seen[(size_t)(b - base.items)] = 1;
            if (strcmp(b->sha, cur.items[i].sha) != 0)
                mod[nmod++] = i;
        }
    }
    for (size_t i = 0; i < base.count; i++)
        if (!seen[i]) rem[nrem++] = i;

    /* ---- output ---- */
    if (c->cfg->json) {
        printf("{");
        printf("\"baseline_root\":\"%s\",\"current_root\":\"%s\",", hdr.root, cur_root);
        printf("\"match\":%s,", match ? "true" : "false");
        printf("\"baseline_created\":"); json_print_escaped(stdout, hdr.created);
        printf(",\"modified\":[");
        for (size_t i = 0; i < nmod; i++) {
            if (i) fputc(',', stdout);
            json_print_escaped(stdout, cur.items[mod[i]].path);
        }
        printf("],\"added\":[");
        for (size_t i = 0; i < nadd; i++) {
            if (i) fputc(',', stdout);
            json_print_escaped(stdout, cur.items[add[i]].path);
        }
        printf("],\"removed\":[");
        for (size_t i = 0; i < nrem; i++) {
            if (i) fputc(',', stdout);
            json_print_escaped(stdout, base.items[rem[i]].path);
        }
        printf("],\"summary\":{\"modified\":%zu,\"added\":%zu,\"removed\":%zu}}\n",
               nmod, nadd, nrem);
    } else {
        printf("Baseline root: %s  Current root: %s  [%s]\n",
               hdr.root, cur_root, match ? "MATCH" : "CHANGED");
        if (skipped[0])
            printf("Skipped (missing) roots: %s\n", skipped);

        if (nmod == 0 && nadd == 0 && nrem == 0) {
            printf("No integrity changes; Merkle root matches baseline.\n");
        } else {
            printf("\n=== MODIFIED (%zu) ===\n", nmod);
            for (size_t i = 0; i < nmod; i++) {
                FimEntry *cc = &cur.items[mod[i]];
                FimEntry *bb = list_find(&base, cc->key);
                const char *meta = "";
                if (bb && bb->sha[0] && cc->sha[0] &&
                    strcmp(bb->sha, cc->sha) == 0)
                    meta = "  (mtime/size only)";
                else if (bb && (bb->size != cc->size || bb->mtime != cc->mtime))
                    meta = "  (content + mtime/size)";
                printf("%s%s\n", cc->path, meta);
            }
            printf("\n=== ADDED (%zu) ===\n", nadd);
            for (size_t i = 0; i < nadd; i++)
                printf("%s\n", cur.items[add[i]].path);
            printf("\n=== REMOVED (%zu) ===\n", nrem);
            for (size_t i = 0; i < nrem; i++)
                printf("%s\n", base.items[rem[i]].path);
            printf("\nSummary: %zu modified, %zu added, %zu removed.\n",
                   nmod, nadd, nrem);
        }
    }

    /* ---- bus findings (for report integration if ever combined) ---- */
    for (size_t i = 0; i < nmod; i++) {
        const char *path = cur.items[mod[i]].path;
        if (ext_is_pe(path))
            bus_emit(c->bus, "FIM.MODIFIED", SEV_MED, 70, ACT_REVIEW, 0, path,
                     "Execution-relevant file modified since baseline",
                     "content sha changed (was %.12s..., now %.12s...)",
                     "baseline", cur.items[mod[i]].sha);
    }
    for (size_t i = 0; i < nadd; i++) {
        const char *path = cur.items[add[i]].path;
        if (ext_is_pe(path) && path_in_system_dir(path))
            bus_emit(c->bus, "FIM.ADDED", SEV_LOW, 55, ACT_REVIEW, 0, path,
                     "New PE appeared in a system directory since baseline",
                     "sha256=%s", cur.items[add[i]].sha);
    }
    for (size_t i = 0; i < nrem; i++) {
        const char *path = base.items[rem[i]].path;
        if (ext_is_pe(path) && path_in_system_dir(path))
            bus_emit(c->bus, "FIM.REMOVED", SEV_LOW, 55, ACT_REVIEW, 0, path,
                     "System binary removed since baseline",
                     "was present in baseline (sha256=%s)", base.items[rem[i]].sha);
    }

    audit_logf("FIM check: baseline_root=%s current_root=%s match=%s "
               "modified=%zu added=%zu removed=%zu",
               hdr.root, cur_root, match ? "true" : "false",
               nmod, nadd, nrem);

    free(mod); free(add); free(rem); free(seen);
    list_free(&base);
    list_free(&cur);
}

/* ================================================================== */
/* entry point                                                         */
/* ================================================================== */

void scan_integrity(ScanCtx *c)
{
    if (!c || !c->cfg) return;

    RootSet roots; roots.count = 0;
    bool roots_from_cli = (c->cfg->integrity_roots[0] != '\0');
    if (roots_from_cli)
        roots_parse_list(&roots, c->cfg->integrity_roots);
    else
        roots_defaults(&roots);

    if (c->cfg->integrity_baseline)
        run_baseline(c, &roots);
    else if (c->cfg->integrity_check)
        run_check(c, &roots, roots_from_cli);

    roots_free(&roots);
}
