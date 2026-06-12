/* ioc.c - SentinelC indicator-of-compromise sets.
 * Loads bad IPv4, sha256 hashes, and yara-subset substrings from a directory.
 * C11, Win32 user-mode. Libs: kernel32.
 */
#include "sentinelc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct IocSet {
    uint32_t *ips;        /* big-endian ipv4 */
    size_t    ip_count;
    size_t    ip_cap;

    char    **hashes;     /* lowercased sha256 hex strings */
    size_t    hash_count;
    size_t    hash_cap;

    char    **strings;    /* lowercased substrings */
    size_t    str_count;
    size_t    str_cap;
};

/* ---- small helpers ---- */

static char *dup_str(const char *s)
{
    size_t n = strlen(s);
    char *p = (char *)malloc(n + 1);
    if (p) memcpy(p, s, n + 1);
    return p;
}

static void lower_inplace(char *s)
{
    for (; *s; ++s)
        *s = (char)tolower((unsigned char)*s);
}

/* case-insensitive substring; local to avoid hard dependency on util. */
static bool local_icontains(const char *hay, const char *needle)
{
    if (!hay || !needle) return false;
    if (!*needle) return true;
    for (; *hay; ++hay) {
        const char *h = hay;
        const char *n = needle;
        while (*h && *n &&
               tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
            ++h; ++n;
        }
        if (!*n) return true;
    }
    return false;
}

/* strip leading/trailing whitespace; returns pointer into buf (NUL-terminated) */
static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) ++s;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return s;
}

/* parse dotted-quad into big-endian uint32. returns false on malformed. */
static bool parse_ipv4_be(const char *s, uint32_t *out)
{
    unsigned a, b, c, d;
    char extra;
    /* %c catches trailing junk like "1.2.3.4.5" */
    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
        return false;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return false;
    *out = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8)  | (uint32_t)d;
    return true;
}

static bool is_hex64(const char *s)
{
    if (strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!isxdigit((unsigned char)s[i]))
            return false;
    return true;
}

/* generic dynamic-array push for char* lists */
static bool push_strlist(char ***arr, size_t *count, size_t *cap, char *val)
{
    if (*count == *cap) {
        size_t ncap = *cap ? *cap * 2 : 16;
        char **np = (char **)realloc(*arr, ncap * sizeof(char *));
        if (!np) return false;
        *arr = np;
        *cap = ncap;
    }
    (*arr)[(*count)++] = val;
    return true;
}

static bool push_ip(struct IocSet *s, uint32_t ip)
{
    if (s->ip_count == s->ip_cap) {
        size_t ncap = s->ip_cap ? s->ip_cap * 2 : 16;
        uint32_t *np = (uint32_t *)realloc(s->ips, ncap * sizeof(uint32_t));
        if (!np) return false;
        s->ips = np;
        s->ip_cap = ncap;
    }
    s->ips[s->ip_count++] = ip;
    return true;
}

/* Open <dir>/<name>; for each non-blank, non-# line call cb(line, ud). */
static void for_each_line(const char *dir, const char *name,
                          void (*cb)(char *line, void *ud), void *ud)
{
    char path[SC_MAX_PATH];
    if (_snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", dir, name) < 0)
        return;

    FILE *fp = fopen(path, "rb");
    if (!fp) return;

    char buf[2048];
    while (fgets(buf, sizeof(buf), fp)) {
        char *line = trim(buf);
        if (line[0] == '\0' || line[0] == '#')
            continue;
        cb(line, ud);
    }
    fclose(fp);
}

/* ---- line callbacks ---- */

static void cb_ip(char *line, void *ud)
{
    struct IocSet *s = (struct IocSet *)ud;
    uint32_t ip;
    if (parse_ipv4_be(line, &ip))
        push_ip(s, ip);
}

static void cb_hash(char *line, void *ud)
{
    struct IocSet *s = (struct IocSet *)ud;
    lower_inplace(line);
    if (!is_hex64(line))
        return;
    char *d = dup_str(line);
    if (d && !push_strlist(&s->hashes, &s->hash_count, &s->hash_cap, d))
        free(d);
}

static void cb_string(char *line, void *ud)
{
    struct IocSet *s = (struct IocSet *)ud;
    lower_inplace(line);
    if (line[0] == '\0')
        return;
    char *d = dup_str(line);
    if (d && !push_strlist(&s->strings, &s->str_count, &s->str_cap, d))
        free(d);
}

/* ---- public API ---- */

IocSet *ioc_load(const char *dir)
{
    if (!dir || !dir[0])
        return NULL;

    DWORD attr = GetFileAttributesA(dir);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
        return NULL;

    struct IocSet *s = (struct IocSet *)calloc(1, sizeof(*s));
    if (!s)
        return NULL;

    for_each_line(dir, "ioc_ips.txt",     cb_ip,     s);
    for_each_line(dir, "ioc_hashes.txt",  cb_hash,   s);
    for_each_line(dir, "yara_subset.txt", cb_string, s);

    if (s->ip_count == 0 && s->hash_count == 0 && s->str_count == 0) {
        ioc_free(s);
        return NULL;
    }
    return s;
}

void ioc_free(IocSet *s)
{
    if (!s)
        return;
    free(s->ips);
    for (size_t i = 0; i < s->hash_count; ++i)
        free(s->hashes[i]);
    free(s->hashes);
    for (size_t i = 0; i < s->str_count; ++i)
        free(s->strings[i]);
    free(s->strings);
    free(s);
}

bool ioc_match_ip(IocSet *s, uint32_t ipv4_be)
{
    if (!s)
        return false;
    for (size_t i = 0; i < s->ip_count; ++i)
        if (s->ips[i] == ipv4_be)
            return true;
    return false;
}

bool ioc_match_hash_sha256(IocSet *s, const char *hex64)
{
    if (!s || !hex64)
        return false;
    if (strlen(hex64) != 64)
        return false;
    for (size_t i = 0; i < s->hash_count; ++i) {
        /* both stored lowercase; compare case-insensitively for safety */
        if (_stricmp(s->hashes[i], hex64) == 0)
            return true;
    }
    return false;
}

bool ioc_match_string(IocSet *s, const char *haystack)
{
    if (!s || !haystack)
        return false;
    for (size_t i = 0; i < s->str_count; ++i)
        if (local_icontains(haystack, s->strings[i]))
            return true;
    return false;
}
