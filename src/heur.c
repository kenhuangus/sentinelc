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

/* Does `s` begin with prefix `p` (case-insensitive)? */
static bool ci_startswith(const char *s, const char *p)
{
    if (!s || !p)
        return false;
    while (*p) {
        if (tolower((unsigned char)*s) != tolower((unsigned char)*p))
            return false;
        ++s;
        ++p;
    }
    return true;
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

    char windir[MAX_PATH];
    get_windir(windir, sizeof(windir));

    /* Build the well-known system subdirs from windir. */
    char sys32[MAX_PATH + 32], syswow[MAX_PATH + 32], winsxs[MAX_PATH + 32];
    snprintf(sys32,  sizeof(sys32),  "%s\\System32", windir);
    snprintf(syswow, sizeof(syswow), "%s\\SysWOW64", windir);
    snprintf(winsxs, sizeof(winsxs), "%s\\WinSxS", windir);

    /* TEMP / RECYCLE checks are substring-based and take priority for the
     * "user-writable" intent regardless of root. */
    if (ci_contains(path, "$Recycle.Bin"))
        return PATHLOC_RECYCLE;
    if (ci_contains(path, "\\AppData\\Local\\Temp") ||
        ci_contains(path, "\\Temp\\"))
        return PATHLOC_TEMP;

    /* SYSTEM dirs. */
    if (ci_startswith(path, sys32) || ci_startswith(path, syswow) ||
        ci_startswith(path, winsxs))
        return PATHLOC_SYSTEM;

    /* Program Files (check (x86) first since it shares the prefix). */
    {
        char pf[MAX_PATH] = {0}, pfx86[MAX_PATH] = {0};
        DWORD r1 = GetEnvironmentVariableA("ProgramFiles", pf, sizeof(pf));
        DWORD r2 = GetEnvironmentVariableA("ProgramFiles(x86)", pfx86, sizeof(pfx86));
        if (r1 > 0 && r1 < sizeof(pf) && ci_startswith(path, pf))
            return PATHLOC_PROGRAMFILES;
        if (r2 > 0 && r2 < sizeof(pfx86) && ci_startswith(path, pfx86))
            return PATHLOC_PROGRAMFILES;
        /* Generic fallback by name. */
        if (ci_contains(path, "\\Program Files (x86)\\") ||
            ci_contains(path, "\\Program Files\\"))
            return PATHLOC_PROGRAMFILES;
    }

    /* Anything else under %SystemRoot% is WINDOWS. */
    if (ci_startswith(path, windir))
        return PATHLOC_WINDOWS;

    /* User-writable locations. */
    if (ci_contains(path, "\\Users\\") ||
        ci_contains(path, "\\AppData\\") ||
        ci_contains(path, "\\ProgramData\\") ||
        ci_contains(path, "\\Public\\"))
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

    char name[SC_NAME_LEN];
    local_base_name(image_path, name, sizeof(name));
    if (name[0] == '\0')
        return false;

    char windir[MAX_PATH];
    get_windir(windir, sizeof(windir));

    char sys32[MAX_PATH + 32], syswow[MAX_PATH + 32];
    snprintf(sys32,  sizeof(sys32),  "%s\\System32", windir);
    snprintf(syswow, sizeof(syswow), "%s\\SysWOW64", windir);

    /* Build the directory portion of the image path. */
    char dir[SC_MAX_PATH];
    {
        size_t len = strlen(image_path);
        size_t cut = (size_t)-1;
        for (size_t i = len; i > 0; --i) {
            if (image_path[i - 1] == '\\' || image_path[i - 1] == '/') {
                cut = i - 1;
                break;
            }
        }
        if (cut == (size_t)-1) {
            dir[0] = '\0'; /* bare name, no directory */
        } else {
            size_t n = cut < sizeof(dir) - 1 ? cut : sizeof(dir) - 1;
            memcpy(dir, image_path, n);
            dir[n] = '\0';
        }
    }

    for (size_t i = 0; i < kSysImagesN; ++i) {
        const struct sys_image *si = &kSysImages[i];

        if (ci_eq(name, si->name)) {
            /* Exact critical-name match: verify it lives in its legit dir. */
            if (si->loc == 0) {
                /* System32 or SysWOW64 are both acceptable legit homes. */
                if (ci_eq(dir, sys32) || ci_eq(dir, syswow))
                    return false; /* legit */
                return true;      /* right name, wrong place */
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
