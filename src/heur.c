/* heur.c - heuristics, path classification, masquerade & allowlist.
 * C11, Win32 user-mode. Libs: kernel32.
 */
#include "sentinelc.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

/* ===================================================================
 *  Shannon entropy (0..8 bits/byte)
 * =================================================================== */
double shannon_entropy(const unsigned char *buf, size_t len)
{
    if (!buf || len == 0)
        return 0.0;

    size_t counts[256];
    memset(counts, 0, sizeof(counts));
    for (size_t i = 0; i < len; ++i)
        counts[buf[i]]++;

    double entropy = 0.0;
    double dlen = (double)len;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0)
            continue;
        double p = (double)counts[i] / dlen;
        entropy -= p * (log(p) / log(2.0));
    }
    if (entropy < 0.0)
        entropy = 0.0;
    if (entropy > 8.0)
        entropy = 8.0;
    return entropy;
}

/* ===================================================================
 *  internal helpers
 * =================================================================== */

/* Case-insensitive substring test (local; util.c's str_icontains is the
 * public one but heur.c keeps a private copy to avoid coupling). */
static bool ci_contains(const char *hay, const char *needle)
{
    if (!hay || !needle)
        return false;
    if (needle[0] == '\0')
        return true;
    size_t lh = strlen(hay), ln = strlen(needle);
    if (ln > lh)
        return false;
    for (size_t i = 0; i + ln <= lh; ++i) {
        size_t j = 0;
        for (; j < ln; ++j) {
            if (tolower((unsigned char)hay[i + j]) !=
                tolower((unsigned char)needle[j]))
                break;
        }
        if (j == ln)
            return true;
    }
    return false;
}

static bool ci_eq(const char *a, const char *b)
{
    if (!a || !b)
        return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

/* Get %SystemRoot% (e.g. "C:\\Windows"), no trailing slash. */
static void get_windir(char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    UINT n = GetWindowsDirectoryA(out, (UINT)cap);
    if (n == 0 || n >= cap) {
        /* Fallback */
        strncpy(out, "C:\\Windows", cap - 1);
        out[cap - 1] = '\0';
    }
    /* Trim trailing slash. */
    size_t len = strlen(out);
    while (len > 0 && (out[len - 1] == '\\' || out[len - 1] == '/')) {
        out[len - 1] = '\0';
        --len;
    }
}

/* ===================================================================
 *  Path canonicalization
 *
 *  Turn an arbitrary (possibly relative, 8.3-short, prefixed, or
 *  trailing-dot/space) UTF-8 path into a single normalized, lowercased
 *  UTF-8 form so that downstream comparisons can be done on path-segment
 *  boundaries instead of raw substrings:
 *    1. UTF-8 -> wide.
 *    2. GetFullPathNameW   -> resolves "..", ".", relative paths, and
 *       normalizes forward slashes to '\' and strips trailing dots/spaces.
 *    3. GetLongPathNameW   -> expands 8.3 short names (DOCUME~1 -> ...).
 *       This fails when the file does not exist; on any failure we keep
 *       the GetFullPathNameW result.
 *    4. Strip a leading "\\?\" or "\\?\UNC\" extended-length prefix.
 *    5. Lowercase (invariant ASCII-ish; tolower on wide units).
 *    6. wide -> UTF-8.
 *  On ANY failure we fall back to copying the original string verbatim,
 *  so we never crash or drop the path.
 * =================================================================== */

/* Buffers are sized generously: paths can exceed MAX_PATH once "\\?\" /
 * long-name expansion is in play. */
#define SC_CANON_WIDE (2 * SC_MAX_PATH)

static void canonicalize_path(const char *in, char *out, size_t out_cap)
{
    if (!out || out_cap == 0)
        return;
    out[0] = '\0';
    if (!in)
        return;

    /* Fallback copy helper (truncate-safe, NUL-terminated). */
    /* We populate `out` with the original up-front; every early return
     * below therefore yields a usable value. */
    {
        size_t i = 0;
        for (; in[i] && i + 1 < out_cap; ++i)
            out[i] = in[i];
        out[i] = '\0';
    }
    if (in[0] == '\0')
        return;

    wchar_t win[SC_CANON_WIDE];
    win[0] = L'\0';
    if (utf8_to_wide(in, win, SC_CANON_WIDE) == 0)
        return; /* keep original */
    win[SC_CANON_WIDE - 1] = L'\0';

    /* Step 2: GetFullPathNameW. */
    wchar_t wfull[SC_CANON_WIDE];
    wfull[0] = L'\0';
    DWORD nf = GetFullPathNameW(win, SC_CANON_WIDE, wfull, NULL);
    if (nf == 0 || nf >= SC_CANON_WIDE) {
        /* Too long or failed: keep what we already have (original). */
        return;
    }
    wfull[SC_CANON_WIDE - 1] = L'\0';

    /* Step 3: GetLongPathNameW (expands 8.3). Fails if path doesn't exist
     * -> fall back to the full-path result. */
    wchar_t wlong[SC_CANON_WIDE];
    wlong[0] = L'\0';
    DWORD nl = GetLongPathNameW(wfull, wlong, SC_CANON_WIDE);
    const wchar_t *chosen;
    if (nl == 0 || nl >= SC_CANON_WIDE)
        chosen = wfull;          /* nonexistent / too long -> full path */
    else {
        wlong[SC_CANON_WIDE - 1] = L'\0';
        chosen = wlong;
    }

    /* Step 4: strip extended-length prefix "\\?\" and "\\?\UNC\".
     * `wunc` is stack-local (thread-safe). */
    wchar_t wunc[SC_CANON_WIDE];
    if (chosen[0] == L'\\' && chosen[1] == L'\\' &&
        chosen[2] == L'?'  && chosen[3] == L'\\') {
        const wchar_t *p = chosen + 4;
        /* "\\?\UNC\server\share" -> "\\server\share" */
        if ((p[0] == L'U' || p[0] == L'u') &&
            (p[1] == L'N' || p[1] == L'n') &&
            (p[2] == L'C' || p[2] == L'c') &&
            p[3] == L'\\') {
            /* Re-form a normal UNC path: keep one leading backslash, the
             * "UNC\" becomes "\". */
            wunc[0] = L'\\';
            size_t w = 1;
            const wchar_t *q = p + 3; /* points at the '\' before server */
            for (; *q && w + 1 < SC_CANON_WIDE; ++q)
                wunc[w++] = *q;
            wunc[w] = L'\0';
            chosen = wunc;
        } else {
            chosen = p;
        }
    }

    /* Step 5: lowercase into a writable buffer.
     * NOTE: heur functions may run on a thread pool, so every working
     * buffer here is on the stack -- no shared static state. */
    wchar_t wlow[SC_CANON_WIDE];
    {
        size_t w = 0;
        for (; chosen[w] && w + 1 < SC_CANON_WIDE; ++w) {
            wchar_t c = chosen[w];
            if (c >= L'A' && c <= L'Z')
                c = (wchar_t)(c - L'A' + L'a');
            wlow[w] = c;
        }
        wlow[w] = L'\0';
    }

    /* Step 6: wide -> UTF-8 back into out. On failure keep original. */
    char tmp[SC_CANON_WIDE];
    size_t got = wide_to_utf8(wlow, tmp, sizeof(tmp));
    if (got == 0)
        return; /* keep original copy already in out */
    tmp[sizeof(tmp) - 1] = '\0';

    size_t i = 0;
    for (; tmp[i] && i + 1 < out_cap; ++i)
        out[i] = tmp[i];
    out[i] = '\0';
}

/* Lowercase a UTF-8 (ASCII path) string in place. Used to canonicalize
 * the env-expanded anchors so both sides of the prefix test are lower. */
static void ascii_lower(char *s)
{
    if (!s)
        return;
    for (; *s; ++s) {
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
    }
}

/* Segment-boundary prefix test: returns true iff `path` starts with
 * `prefix` AND the boundary in `path` immediately after the prefix is a
 * path separator or end-of-string. Both inputs are assumed lowercased.
 * Trailing separators on `prefix` are ignored so "C:\\windows\\" and
 * "C:\\windows" behave identically.
 *
 *   prefix="c:\\windows\\system32"
 *     "c:\\windows\\system32"        -> true  (exact, EOS boundary)
 *     "c:\\windows\\system32\\a.dll" -> true  ('\\' boundary)
 *     "c:\\windows\\system32evil"    -> false (no boundary)
 *     "c:\\x\\windows\\system32"     -> false (not a prefix)
 */
static bool seg_prefix(const char *path, const char *prefix)
{
    if (!path || !prefix)
        return false;
    size_t lp = strlen(prefix);
    /* Ignore trailing separators on the prefix. */
    while (lp > 0 && (prefix[lp - 1] == '\\' || prefix[lp - 1] == '/'))
        --lp;
    if (lp == 0)
        return false;
    if (strncmp(path, prefix, lp) != 0)
        return false;
    char nxt = path[lp];
    return nxt == '\0' || nxt == '\\' || nxt == '/';
}

/* Does any path SEGMENT of `path` exactly equal `seg` (e.g. "$recycle.bin",
 * "temp")?  Matches a directory/file component bounded by separators or the
 * string ends. `path` and `seg` are lowercased. */
static bool has_segment(const char *path, const char *seg)
{
    if (!path || !seg || seg[0] == '\0')
        return false;
    size_t ls = strlen(seg);
    const char *p = path;
    while (*p) {
        /* p sits at the start of a segment. */
        if (strncmp(p, seg, ls) == 0) {
            char nxt = p[ls];
            if (nxt == '\0' || nxt == '\\' || nxt == '/')
                return true;
        }
        /* advance to the char after the next separator */
        while (*p && *p != '\\' && *p != '/')
            ++p;
        while (*p == '\\' || *p == '/')
            ++p;
    }
    return false;
}

/* Expand+lowercase an environment variable's value into `out`. Returns
 * true if the variable was present and non-empty. */
static bool get_env_lower(const char *name, char *out, size_t cap)
{
    if (!out || cap == 0)
        return false;
    out[0] = '\0';
    DWORD r = GetEnvironmentVariableA(name, out, (DWORD)cap);
    if (r == 0 || r >= cap) {
        out[0] = '\0';
        return false;
    }
    ascii_lower(out);
    return out[0] != '\0';
}

/* Local base-name extraction (avoids cross-module dependency). */
static void local_base_name(const char *path, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!path)
        return;
    const char *base = path;
    for (const char *p = path; *p; ++p) {
        if (*p == '\\' || *p == '/')
            base = p + 1;
    }
    size_t i = 0;
    for (; base[i] && i + 1 < cap; ++i)
        out[i] = base[i];
    out[i] = '\0';
}

/* ===================================================================
 *  Path classification
 * =================================================================== */
PathLoc path_classify(const char *path)
{
    if (!path || path[0] == '\0')
        return PATHLOC_OTHER;

    /* Canonicalize once; everything below compares on the normalized,
     * lowercased form using segment-boundary matching. */
    char c[SC_CANON_WIDE];
    canonicalize_path(path, c, sizeof(c));
    if (c[0] == '\0')
        return PATHLOC_OTHER;

    /* Windows dir (lowercased), and its well-known subdirs. */
    char windir[MAX_PATH];
    get_windir(windir, sizeof(windir));
    ascii_lower(windir);

    char sys32[MAX_PATH + 32], syswow[MAX_PATH + 32], winsxs[MAX_PATH + 32];
    snprintf(sys32,  sizeof(sys32),  "%s\\system32", windir);
    snprintf(syswow, sizeof(syswow), "%s\\syswow64", windir);
    snprintf(winsxs, sizeof(winsxs), "%s\\winsxs",   windir);

    /* TEMP / RECYCLE take priority for the "user-writable" intent,
     * regardless of root. Match real path segments, not substrings. */
    if (has_segment(c, "$recycle.bin"))
        return PATHLOC_RECYCLE;
    if (has_segment(c, "temp"))
        return PATHLOC_TEMP;

    /* SYSTEM dirs (System32 / SysWOW64 / WinSxS). */
    if (seg_prefix(c, sys32) || seg_prefix(c, syswow) || seg_prefix(c, winsxs))
        return PATHLOC_SYSTEM;

    /* Program Files (env-anchored; check both 64- and 32-bit roots). */
    {
        char pf[MAX_PATH], pfx86[MAX_PATH];
        if (get_env_lower("ProgramFiles", pf, sizeof(pf)) && seg_prefix(c, pf))
            return PATHLOC_PROGRAMFILES;
        if (get_env_lower("ProgramFiles(x86)", pfx86, sizeof(pfx86)) &&
            seg_prefix(c, pfx86))
            return PATHLOC_PROGRAMFILES;
        /* No "by name anywhere" fallback: that was the evasion primitive.
         * A "Program Files" directory under a user-writable root must NOT
         * be treated as the protected Program Files. */
    }

    /* Anything else under %SystemRoot% is WINDOWS. */
    if (seg_prefix(c, windir))
        return PATHLOC_WINDOWS;

    /* User-writable locations: any path containing one of these as a real
     * segment. \Temp already handled above (returns TEMP). */
    if (has_segment(c, "users") ||
        has_segment(c, "appdata") ||
        has_segment(c, "programdata") ||
        has_segment(c, "public"))
        return PATHLOC_USER_WRITABLE;

    return PATHLOC_OTHER;
}

bool path_is_user_writable(const char *path)
{
    switch (path_classify(path)) {
    case PATHLOC_TEMP:
    case PATHLOC_RECYCLE:
    case PATHLOC_USER_WRITABLE:
        return true;
    default:
        return false;
    }
}

/* ===================================================================
 *  Masquerade detection
 * =================================================================== */

/* Known critical system images and their legitimate location.
 * loc: 0 = System32 (under %SystemRoot%\System32), 1 = %SystemRoot% root. */
struct sys_image {
    const char *name;
    int         loc;
};

static const struct sys_image kSysImages[] = {
    { "svchost.exe",   0 },
    { "lsass.exe",     0 },
    { "services.exe",  0 },
    { "csrss.exe",     0 },
    { "winlogon.exe",  0 },
    { "smss.exe",      0 },
    { "wininit.exe",   0 },
    { "taskhostw.exe", 0 },
    { "rundll32.exe",  0 },
    { "conhost.exe",   0 },
    { "dllhost.exe",   0 },
    { "spoolsv.exe",   0 },
    { "explorer.exe",  1 },   /* legit dir is %SystemRoot% itself */
};

static const size_t kSysImagesN = sizeof(kSysImages) / sizeof(kSysImages[0]);

/* Levenshtein distance, capped (small inputs -> simple DP). */
static int edit_distance(const char *a, const char *b)
{
    size_t la = strlen(a), lb = strlen(b);
    if (la == 0)
        return (int)lb;
    if (lb == 0)
        return (int)la;
    if (la > 64 || lb > 64)
        return 99; /* too long to be a typo of a short image name */

    int prev[66], cur[66];
    for (size_t j = 0; j <= lb; ++j)
        prev[j] = (int)j;

    for (size_t i = 1; i <= la; ++i) {
        cur[0] = (int)i;
        for (size_t j = 1; j <= lb; ++j) {
            int cost = (tolower((unsigned char)a[i - 1]) ==
                        tolower((unsigned char)b[j - 1])) ? 0 : 1;
            int del = prev[j] + 1;
            int ins = cur[j - 1] + 1;
            int sub = prev[j - 1] + cost;
            int m = del < ins ? del : ins;
            if (sub < m)
                m = sub;
            cur[j] = m;
        }
        memcpy(prev, cur, (lb + 1) * sizeof(int));
    }
    return prev[lb];
}

/* Does `name` look like a homoglyph/typo of `legit`?
 * We treat it as a masquerade if edit distance is small (1) AND the names
 * differ (i.e. not an exact match). This catches digit substitution
 * (svch0st.exe) and single transposition-ish edits. We also require the
 * length to be similar to avoid matching very different names. */
static bool is_typo_of(const char *name, const char *legit)
{
    if (ci_eq(name, legit))
        return false; /* exact -> not a typo */
    size_t ln = strlen(name), ll = strlen(legit);
    /* length must be within 1 of legit */
    size_t diff = (ln > ll) ? (ln - ll) : (ll - ln);
    if (diff > 1)
        return false;
    int d = edit_distance(name, legit);
    /* distance 1 (substitution/insert/delete). Transposition like
     * scvhost vs svchost is distance 2 under plain Levenshtein, handle
     * it explicitly below for equal-length adjacent swaps. */
    if (d == 1)
        return true;
    if (d == 2 && ln == ll) {
        /* check for a single adjacent transposition */
        size_t k = 0;
        while (k < ln &&
               tolower((unsigned char)name[k]) ==
               tolower((unsigned char)legit[k]))
            ++k;
        if (k + 1 < ln &&
            tolower((unsigned char)name[k]) ==
                tolower((unsigned char)legit[k + 1]) &&
            tolower((unsigned char)name[k + 1]) ==
                tolower((unsigned char)legit[k])) {
            /* rest must match */
            size_t r = k + 2;
            while (r < ln &&
                   tolower((unsigned char)name[r]) ==
                       tolower((unsigned char)legit[r]))
                ++r;
            if (r == ln)
                return true;
        }
    }
    return false;
}

bool name_is_masquerade(const char *image_path)
{
    if (!image_path || image_path[0] == '\0')
        return false;

    /* Canonicalize first so short names ("PROGRA~1"), forward slashes,
     * "\\?\" prefixes, and trailing dots/spaces are normalized away before
     * we compare the directory against the legit homes. */
    char canon[SC_CANON_WIDE];
    canonicalize_path(image_path, canon, sizeof(canon));
    if (canon[0] == '\0')
        return false;

    char name[SC_NAME_LEN];
    local_base_name(canon, name, sizeof(name));
    if (name[0] == '\0')
        return false;

    char windir[MAX_PATH];
    get_windir(windir, sizeof(windir));
    ascii_lower(windir);

    char sys32[MAX_PATH + 32], syswow[MAX_PATH + 32];
    snprintf(sys32,  sizeof(sys32),  "%s\\system32", windir);
    snprintf(syswow, sizeof(syswow), "%s\\syswow64", windir);

    /* Directory portion of the canonical path (lowercased already). */
    char dir[SC_CANON_WIDE];
    {
        size_t len = strlen(canon);
        size_t cut = (size_t)-1;
        for (size_t i = len; i > 0; --i) {
            if (canon[i - 1] == '\\' || canon[i - 1] == '/') {
                cut = i - 1;
                break;
            }
        }
        if (cut == (size_t)-1) {
            dir[0] = '\0'; /* bare name, no directory */
        } else {
            size_t n = cut < sizeof(dir) - 1 ? cut : sizeof(dir) - 1;
            memcpy(dir, canon, n);
            dir[n] = '\0';
        }
    }

    for (size_t i = 0; i < kSysImagesN; ++i) {
        const struct sys_image *si = &kSysImages[i];

        if (ci_eq(name, si->name)) {
            /* Exact critical-name match: verify it lives in its legit dir.
             * Use seg_prefix so an exact dir match (or a trailing
             * separator) is accepted; both sides are lowercase. */
            if (si->loc == 0) {
                /* System32 or SysWOW64 are both acceptable legit homes.
                 * The binary must sit *directly* in that dir, so compare
                 * the (canonical, lowercased) directory for equality. */
                if (ci_eq(dir, sys32) || ci_eq(dir, syswow))
                    return false;     /* legit */
                return true;          /* right name, wrong place */
            } else {
                /* explorer.exe legit dir is %SystemRoot% root. */
                if (ci_eq(dir, windir))
                    return false;
                return true;
            }
        }

        /* Homoglyph / typo of a critical name => always masquerade. */
        if (is_typo_of(name, si->name))
            return true;
    }

    return false;
}

/* ===================================================================
 *  Allowlist
 * =================================================================== */

typedef struct {
    char **entries;   /* each NUL-terminated line: path or base name */
    size_t count;
    size_t cap;
    bool   loaded;
} Allowlist;

static Allowlist g_allow = { NULL, 0, 0, false };

static bool allow_push(const char *line)
{
    if (g_allow.count == g_allow.cap) {
        size_t ncap = g_allow.cap ? g_allow.cap * 2 : 16;
        char **n = (char **)realloc(g_allow.entries, ncap * sizeof(char *));
        if (!n)
            return false;
        g_allow.entries = n;
        g_allow.cap = ncap;
    }
    size_t len = strlen(line);
    char *dup = (char *)malloc(len + 1);
    if (!dup)
        return false;
    memcpy(dup, line, len + 1);
    g_allow.entries[g_allow.count++] = dup;
    return true;
}

/* Trim leading/trailing whitespace (in place). */
static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        ++s;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                       s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[len - 1] = '\0';
        --len;
    }
    return s;
}

void allowlist_load(const char *path)
{
    /* Reset any prior load. */
    allowlist_free();
    g_allow.loaded = true; /* mark as attempted even if file missing */

    if (!path || path[0] == '\0')
        return;

    FILE *f = NULL;
#if defined(_MSC_VER)
    if (fopen_s(&f, path, "rb") != 0)
        f = NULL;
#else
    f = fopen(path, "rb");
#endif
    if (!f)
        return; /* missing file => no-op, safe */

    char buf[SC_MAX_PATH + 64];
    while (fgets(buf, sizeof(buf), f)) {
        char *line = trim(buf);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        if (!allow_push(line))
            break; /* OOM: stop loading, keep what we have */
    }
    fclose(f);
}

bool allowlist_match(const char *path_or_name)
{
    if (!path_or_name || path_or_name[0] == '\0')
        return false;
    if (g_allow.count == 0)
        return false;

    char base[SC_NAME_LEN];
    local_base_name(path_or_name, base, sizeof(base));

    for (size_t i = 0; i < g_allow.count; ++i) {
        const char *e = g_allow.entries[i];
        if (!e || e[0] == '\0')
            continue;

        /* Exact base-name match (case-insensitive). */
        if (base[0] && ci_eq(base, e))
            return true;

        /* Also: if the allowlist entry itself has a base name equal to ours. */
        char ebase[SC_NAME_LEN];
        local_base_name(e, ebase, sizeof(ebase));
        if (base[0] && ebase[0] && ci_eq(base, ebase))
            return true;

        /* Substring path match (entry contained in the queried path). */
        if (ci_contains(path_or_name, e))
            return true;
    }
    return false;
}

void allowlist_free(void)
{
    if (g_allow.entries) {
        for (size_t i = 0; i < g_allow.count; ++i)
            free(g_allow.entries[i]);
        free(g_allow.entries);
    }
    g_allow.entries = NULL;
    g_allow.count = 0;
    g_allow.cap = 0;
    g_allow.loaded = false;
}
