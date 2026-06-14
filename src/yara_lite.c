/* yara_lite.c -- a focused YARA-subset rule engine for SentinelC.
 *
 * Pure C11, libc only (no windows.h, no external deps). Parses a small,
 * well-defined subset of YARA rule syntax, matches byte/text patterns against
 * an in-memory buffer, and reports the first rule whose condition is satisfied.
 *
 * --------------------------------------------------------------------------
 * GRAMMAR ACCEPTED (everything outside this is ignored/skipped gracefully)
 * --------------------------------------------------------------------------
 *   file        := { rule }
 *   rule        := "rule" NAME "{" [meta-section] [strings-section]
 *                   condition-section "}"
 *   meta:       :=  "meta:" ... (skipped entirely)
 *   strings:    :=  "strings:" { string-def }
 *   string-def  :=  "$" ID "=" ( "\"" TEXT "\"" [mods] | "{" HEXBYTES "}" )
 *   mods        :=  any space-separated combo of: ascii wide nocase
 *   condition:  :=  "condition:" cond
 *   cond        :=  "any of them"
 *                |  "all of them"
 *                |  INT "of them"
 *                |  string-id { ("and"|"or") string-id }     (flat, no parens)
 *                |  string-id                                  (single)
 *
 * Comments: // line and / * ... * / block comments are stripped before parse.
 * Lines beginning with "import" are ignored. Keywords are case-insensitive.
 * An unrecognized condition defaults to "any of them".
 *
 * --------------------------------------------------------------------------
 * MATCHING SEMANTICS
 * --------------------------------------------------------------------------
 *  text strings : default = ascii, case-sensitive. Modifiers (any combo):
 *      ascii  -> match the raw bytes as written.
 *      wide   -> match the UTF-16LE form: each ASCII byte followed by 0x00.
 *      nocase -> case-insensitive (applied to whichever of ascii/wide forms
 *                are active; folding is done per-byte on A-Z/a-z).
 *      If both ascii and wide are given, a hit on EITHER form counts.
 *      If neither is given, ascii is assumed.
 *  hex strings  : "{ 68 ?? ?? ?? ?? c3 }". Whitespace-separated byte pairs.
 *      "??" is a full-byte wildcard (matches any single byte). Single-nibble
 *      wildcards like "4?" are NOT supported and are treated as a full-byte
 *      wildcard "??" (documented widening; never rejects the rule).
 *
 * --------------------------------------------------------------------------
 * HARD CAPS (everything is bounded; malformed input is skipped, never crashes)
 * --------------------------------------------------------------------------
 *   rules per file        <= 1024
 *   strings per rule      <= 64
 *   pattern bytes         <= 256   (per encoded form)
 *   rule name length      <= 64
 */

#include "sentinelc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ---- caps ---- */
#define YL_MAX_RULES        1024
#define YL_MAX_STR_PER_RULE 64
#define YL_MAX_PATTERN      256
#define YL_MAX_NAME         64
#define YL_MAX_STRID        64

/* condition kinds */
typedef enum {
    COND_ANY = 0,   /* any of them (also the default fallback) */
    COND_ALL,       /* all of them */
    COND_N,         /* <N> of them  (n_threshold holds N) */
    COND_BOOL       /* flat boolean over ids; bool_or distinguishes and/or */
} CondKind;

typedef struct {
    char          id[YL_MAX_STRID];     /* without the leading '$' */
    int           is_hex;               /* 1 => hex pattern, 0 => text */
    /* text form: */
    int           m_ascii;              /* match ascii form */
    int           m_wide;               /* match wide (UTF-16LE) form */
    int           m_nocase;             /* case-insensitive */
    unsigned char text[YL_MAX_PATTERN]; /* raw literal bytes (ascii form) */
    size_t        text_len;
    /* hex form: */
    unsigned char hbytes[YL_MAX_PATTERN];  /* byte values (wildcards = 0) */
    unsigned char hwild[YL_MAX_PATTERN];   /* 1 => wildcard at this position */
    size_t        hlen;
} YlString;

typedef struct {
    char      name[YL_MAX_NAME];
    YlString  strs[YL_MAX_STR_PER_RULE];
    size_t    nstr;

    CondKind  cond;
    int       n_threshold;              /* for COND_N */
    int       bool_or;                  /* for COND_BOOL: 1 => OR, 0 => AND */
    /* for COND_BOOL: which string indices are referenced */
    int       bool_idx[YL_MAX_STR_PER_RULE];
    size_t    bool_count;
} YlRule;

struct YaraRules {
    YlRule *rules;
    size_t  count;
};

/* ===================================================================== */
/* small helpers                                                          */
/* ===================================================================== */

static unsigned char fold(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (unsigned char)(c - 'A' + 'a');
    return c;
}

/* case-insensitive byte compare of two buffers */
static int mem_ieq(const unsigned char *a, const unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (fold(a[i]) != fold(b[i])) return 0;
    return 1;
}

/* naive substring search of needle in hay; nocase optional. */
static int find_bytes(const unsigned char *hay, size_t hlen,
                      const unsigned char *needle, size_t nlen, int nocase)
{
    if (nlen == 0 || nlen > hlen) return 0;
    size_t last = hlen - nlen;
    for (size_t i = 0; i <= last; i++) {
        if (nocase) {
            if (mem_ieq(hay + i, needle, nlen)) return 1;
        } else {
            if (memcmp(hay + i, needle, nlen) == 0) return 1;
        }
    }
    return 0;
}

/* hex pattern search honoring per-position wildcards. */
static int find_hex(const unsigned char *hay, size_t hlen,
                    const YlString *s)
{
    if (s->hlen == 0 || s->hlen > hlen) return 0;
    size_t last = hlen - s->hlen;
    for (size_t i = 0; i <= last; i++) {
        size_t j = 0;
        for (; j < s->hlen; j++) {
            if (s->hwild[j]) continue;
            if (hay[i + j] != s->hbytes[j]) break;
        }
        if (j == s->hlen) return 1;
    }
    return 0;
}

/* does this single string match the buffer? */
static int string_matches(const YlString *s,
                          const unsigned char *buf, size_t len)
{
    if (s->is_hex)
        return find_hex(buf, len, s);

    /* text: try ascii and/or wide forms */
    if (s->m_ascii && s->text_len > 0) {
        if (find_bytes(buf, len, s->text, s->text_len, s->m_nocase))
            return 1;
    }
    if (s->m_wide && s->text_len > 0) {
        /* build UTF-16LE form on the stack (bounded by 2*YL_MAX_PATTERN) */
        unsigned char w[YL_MAX_PATTERN * 2];
        size_t wn = 0;
        for (size_t i = 0; i < s->text_len && wn + 2 <= sizeof(w); i++) {
            w[wn++] = s->text[i];
            w[wn++] = 0x00;
        }
        if (find_bytes(buf, len, w, wn, s->m_nocase))
            return 1;
    }
    return 0;
}

/* ===================================================================== */
/* preprocessing: strip comments into a freshly malloc'd buffer           */
/* ===================================================================== */

/* Returns a NUL-terminated copy of `src` with // and block comments
 * replaced by spaces (newlines preserved). Caller frees. NULL on OOM. */
static char *strip_comments(const char *src, size_t n)
{
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    size_t o = 0;
    int in_str = 0;     /* inside a "..." literal */
    for (size_t i = 0; i < n; i++) {
        char c = src[i];
        if (in_str) {
            out[o++] = c;
            if (c == '\\' && i + 1 < n) {   /* keep escaped char verbatim */
                out[o++] = src[++i];
            } else if (c == '"') {
                in_str = 0;
            }
            continue;
        }
        if (c == '"') {
            in_str = 1;
            out[o++] = c;
            continue;
        }
        if (c == '/' && i + 1 < n && src[i + 1] == '/') {
            /* line comment: skip to EOL */
            i += 2;
            while (i < n && src[i] != '\n') i++;
            if (i < n) out[o++] = '\n';
            continue;
        }
        if (c == '/' && i + 1 < n && src[i + 1] == '*') {
            /* block comment: skip to closing, preserve newlines */
            i += 2;
            while (i + 1 < n && !(src[i] == '*' && src[i + 1] == '/')) {
                if (src[i] == '\n') out[o++] = '\n';
                i++;
            }
            i += 1;  /* points at '/'; for-loop ++ consumes it */
            out[o++] = ' ';
            continue;
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return out;
}

/* ===================================================================== */
/* tokenizing helpers over the stripped text                              */
/* ===================================================================== */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* parse a quoted literal beginning at *p (which points just after the
 * opening quote). Decodes \\, \", \t, \n, \r, \xHH. Writes into dst (bounded).
 * Advances *p past the closing quote. Returns bytes written. */
static size_t parse_quoted(const char **p, unsigned char *dst, size_t cap)
{
    const char *s = *p;
    size_t len = 0;
    while (*s && *s != '"') {
        unsigned char ch;
        if (*s == '\\' && s[1]) {
            s++;
            switch (*s) {
                case 'n':  ch = '\n'; break;
                case 't':  ch = '\t'; break;
                case 'r':  ch = '\r'; break;
                case '\\': ch = '\\'; break;
                case '"':  ch = '"';  break;
                case 'x': {
                    int hi = s[1] ? hexval(s[1]) : -1;
                    int lo = (s[1] && s[2]) ? hexval(s[2]) : -1;
                    if (hi >= 0 && lo >= 0) {
                        ch = (unsigned char)((hi << 4) | lo);
                        s += 2;
                    } else {
                        ch = 'x';
                    }
                    break;
                }
                default:   ch = (unsigned char)*s; break;
            }
            s++;
        } else {
            ch = (unsigned char)*s++;
        }
        if (len < cap) dst[len] = ch;
        len++;   /* count even past cap so we can clamp */
    }
    if (*s == '"') s++;          /* consume closing quote */
    *p = s;
    return len > cap ? cap : len;
}

/* ===================================================================== */
/* parse one string-def line: text after the '=' for id `id`.            */
/* `body` points at the first non-space char after '='. returns 1 ok.    */
/* ===================================================================== */

static int parse_string_def(const char *id, const char *body, YlString *out)
{
    memset(out, 0, sizeof(*out));
    /* bounded id copy */
    size_t k = 0;
    while (id[k] && k < YL_MAX_STRID - 1) { out->id[k] = id[k]; k++; }
    out->id[k] = '\0';

    while (*body == ' ' || *body == '\t') body++;

    if (*body == '"') {
        body++;
        out->is_hex   = 0;
        out->text_len = parse_quoted(&body, out->text, YL_MAX_PATTERN);
        /* modifiers follow */
        out->m_ascii = out->m_wide = out->m_nocase = 0;
        /* scan trailing words on the (already comment-stripped) tail */
        char word[16];
        while (*body) {
            while (*body == ' ' || *body == '\t') body++;
            if (!*body || *body == '\n' || *body == '\r') break;
            size_t w = 0;
            while (*body && *body != ' ' && *body != '\t' &&
                   *body != '\n' && *body != '\r' && w < sizeof(word) - 1) {
                word[w++] = (char)tolower((unsigned char)*body);
                body++;
            }
            word[w] = '\0';
            /* skip any leftover non-space chars of an overlong word */
            while (*body && *body != ' ' && *body != '\t' &&
                   *body != '\n' && *body != '\r') body++;
            if (strcmp(word, "ascii") == 0)       out->m_ascii  = 1;
            else if (strcmp(word, "wide") == 0)   out->m_wide   = 1;
            else if (strcmp(word, "nocase") == 0) out->m_nocase = 1;
            /* unknown modifiers ignored gracefully */
        }
        if (!out->m_ascii && !out->m_wide) out->m_ascii = 1;  /* default */
        return out->text_len > 0;
    }

    if (*body == '{') {
        body++;
        out->is_hex = 1;
        out->hlen   = 0;
        while (*body && *body != '}') {
            while (*body == ' ' || *body == '\t' ||
                   *body == '\n' || *body == '\r') body++;
            if (!*body || *body == '}') break;
            if (out->hlen >= YL_MAX_PATTERN) {
                /* pattern too long: skip remaining tokens, keep what we have */
                while (*body && *body != '}') body++;
                break;
            }
            if (body[0] == '?' && body[1] == '?') {
                out->hbytes[out->hlen] = 0;
                out->hwild[out->hlen]  = 1;
                out->hlen++;
                body += 2;
            } else {
                int hi = hexval(body[0]);
                int lo = body[0] ? hexval(body[1]) : -1;
                if (hi < 0) {           /* garbage token */
                    if (body[0] == '?') {  /* single-nibble wildcard -> full */
                        out->hbytes[out->hlen] = 0;
                        out->hwild[out->hlen]  = 1;
                        out->hlen++;
                        body++;
                        if (*body && *body != ' ' && *body != '\t' &&
                            *body != '\n' && *body != '\r' && *body != '}')
                            body++;  /* consume the partner nibble char */
                        continue;
                    }
                    body++;   /* skip and continue */
                    continue;
                }
                if (lo < 0) {           /* "4?" style: treat as wildcard */
                    out->hbytes[out->hlen] = 0;
                    out->hwild[out->hlen]  = 1;
                    out->hlen++;
                    body += (body[1] ? 2 : 1);
                } else {
                    out->hbytes[out->hlen] = (unsigned char)((hi << 4) | lo);
                    out->hwild[out->hlen]  = 0;
                    out->hlen++;
                    body += 2;
                }
            }
        }
        return out->hlen > 0;
    }

    return 0;  /* unrecognized form */
}

/* find string index by id within a rule; -1 if absent */
static int rule_find_str(const YlRule *r, const char *id)
{
    for (size_t i = 0; i < r->nstr; i++)
        if (strcmp(r->strs[i].id, id) == 0) return (int)i;
    return -1;
}

/* ===================================================================== */
/* parse the condition expression for a rule                             */
/* ===================================================================== */

static void parse_condition(YlRule *r, const char *expr)
{
    /* default fallback */
    r->cond = COND_ANY;

    /* lowercase a working copy for keyword detection */
    char low[512];
    size_t i = 0;
    for (const char *p = expr; *p && i < sizeof(low) - 1; p++)
        low[i++] = (char)tolower((unsigned char)*p);
    low[i] = '\0';

    /* trim leading space */
    const char *L = low;
    while (*L == ' ' || *L == '\t' || *L == '\n' || *L == '\r') L++;

    if (strstr(L, "of them")) {
        if (strncmp(L, "any", 3) == 0) { r->cond = COND_ANY; return; }
        if (strncmp(L, "all", 3) == 0) { r->cond = COND_ALL; return; }
        /* "<N> of them" */
        char *end = NULL;
        long n = strtol(L, &end, 10);
        if (end != L && n > 0) {
            r->cond        = COND_N;
            r->n_threshold = (int)n;
            return;
        }
        r->cond = COND_ANY;
        return;
    }

    /* boolean over ids: tokenize the ORIGINAL expr for '$ids' and and/or.
     * We forbid mixing and/or (no precedence); first connective seen wins. */
    r->cond       = COND_BOOL;
    r->bool_or    = -1;          /* unknown yet */
    r->bool_count = 0;

    const char *p = expr;
    int saw_and = 0, saw_or = 0;
    while (*p) {
        if (*p == '$') {
            char idbuf[YL_MAX_STRID];
            size_t k = 0;
            p++;
            while (*p && (isalnum((unsigned char)*p) || *p == '_') &&
                   k < YL_MAX_STRID - 1) {
                idbuf[k++] = *p++;
            }
            idbuf[k] = '\0';
            int idx = rule_find_str(r, idbuf);
            if (idx >= 0 && r->bool_count < YL_MAX_STR_PER_RULE)
                r->bool_idx[r->bool_count++] = idx;
            continue;
        }
        /* detect connective keywords (word-boundary-ish) */
        if ((p[0] == 'a' || p[0] == 'A') &&
            (p[1] == 'n' || p[1] == 'N') &&
            (p[2] == 'd' || p[2] == 'D')) {
            saw_and = 1; p += 3; continue;
        }
        if ((p[0] == 'o' || p[0] == 'O') &&
            (p[1] == 'r' || p[1] == 'R')) {
            saw_or = 1; p += 2; continue;
        }
        p++;
    }

    if (r->bool_count == 0) { r->cond = COND_ANY; return; }  /* nothing usable */
    /* OR wins only if no AND present; default AND. A single id => AND of one. */
    r->bool_or = (saw_or && !saw_and) ? 1 : 0;
}

/* ===================================================================== */
/* parse a single rule body (text between the rule's outer braces)        */
/* into *r. Returns 1 on success.                                         */
/* ===================================================================== */

/* Returns pointer to start of `section:` content within body, or NULL.
 * Matches a lowercase keyword followed by ':' as a token. */
static const char *find_section(const char *body, const char *kw)
{
    size_t klen = strlen(kw);
    for (const char *p = body; *p; p++) {
        if (tolower((unsigned char)*p) != kw[0]) continue;
        size_t j = 0;
        while (j < klen &&
               tolower((unsigned char)p[j]) == kw[j]) j++;
        if (j == klen) {
            const char *q = p + klen;
            while (*q == ' ' || *q == '\t') q++;
            if (*q == ':') return q + 1;
        }
    }
    return NULL;
}

static int parse_rule_body(YlRule *r, const char *body)
{
    r->nstr = 0;

    const char *strings_at   = find_section(body, "strings");
    const char *condition_at = find_section(body, "condition");

    /* parse strings up to condition (or end) */
    if (strings_at) {
        const char *end = condition_at ? condition_at : body + strlen(body);
        const char *p   = strings_at;
        while (p < end && *p) {
            /* find next '$' that begins a string-def */
            while (p < end && *p && *p != '$') p++;
            if (p >= end || !*p) break;
            p++;  /* past '$' */
            char idbuf[YL_MAX_STRID];
            size_t k = 0;
            while (p < end && *p &&
                   (isalnum((unsigned char)*p) || *p == '_') &&
                   k < YL_MAX_STRID - 1) {
                idbuf[k++] = *p++;
            }
            idbuf[k] = '\0';
            /* expect '=' */
            while (p < end && (*p == ' ' || *p == '\t')) p++;
            if (p >= end || *p != '=') continue;
            p++;  /* past '=' */
            if (r->nstr >= YL_MAX_STR_PER_RULE) {
                /* cap reached: stop adding, but keep scanning to condition */
                break;
            }
            if (parse_string_def(idbuf, p, &r->strs[r->nstr]))
                r->nstr++;
            /* advance p to end of this def's value to avoid re-reading the
             * same '$' on the next loop: skip the literal/hex chunk. */
            if (*( (p += strspn(p, " \t")) ) == '"') {
                p++;
                while (p < end && *p && *p != '"') {
                    if (*p == '\\' && p[1]) p++;
                    p++;
                }
                if (p < end && *p == '"') p++;
            } else if (*p == '{') {
                while (p < end && *p && *p != '}') p++;
                if (p < end && *p == '}') p++;
            }
        }
    }

    /* condition */
    if (condition_at) {
        /* condition text runs to end of body */
        parse_condition(r, condition_at);
    } else {
        r->cond = COND_ANY;
    }
    return 1;
}

/* ===================================================================== */
/* evaluate a rule's condition against per-string match flags            */
/* ===================================================================== */

static int eval_rule(const YlRule *r, const unsigned char *buf, size_t len)
{
    if (r->nstr == 0) return 0;   /* no strings => never matches */

    int hits[YL_MAX_STR_PER_RULE];
    int nhit = 0;
    for (size_t i = 0; i < r->nstr; i++) {
        hits[i] = string_matches(&r->strs[i], buf, len) ? 1 : 0;
        nhit += hits[i];
    }

    switch (r->cond) {
        case COND_ANY: return nhit > 0;
        case COND_ALL: return nhit == (int)r->nstr;
        case COND_N:   return nhit >= r->n_threshold;
        case COND_BOOL: {
            if (r->bool_count == 0) return nhit > 0;
            if (r->bool_or) {
                for (size_t i = 0; i < r->bool_count; i++)
                    if (hits[r->bool_idx[i]]) return 1;
                return 0;
            } else {
                for (size_t i = 0; i < r->bool_count; i++)
                    if (!hits[r->bool_idx[i]]) return 0;
                return 1;
            }
        }
    }
    return nhit > 0;  /* unreachable; safe default */
}

/* ===================================================================== */
/* public API                                                            */
/* ===================================================================== */

YaraRules *yara_load(const char *path)
{
    if (!path) return NULL;

    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

    /* sane upper bound on file size: 8 MiB */
    if (sz > 8 * 1024 * 1024) { fclose(f); return NULL; }

    char *raw = (char *)malloc((size_t)sz + 1);
    if (!raw) { fclose(f); return NULL; }
    size_t got = fread(raw, 1, (size_t)sz, f);
    fclose(f);
    raw[got] = '\0';

    char *src = strip_comments(raw, got);
    free(raw);
    if (!src) return NULL;

    YaraRules *y = (YaraRules *)calloc(1, sizeof(*y));
    if (!y) { free(src); return NULL; }
    y->rules = (YlRule *)calloc(YL_MAX_RULES, sizeof(YlRule));
    if (!y->rules) { free(src); free(y); return NULL; }
    y->count = 0;

    /* scan for "rule" tokens */
    const char *p = src;
    while (*p && y->count < YL_MAX_RULES) {
        /* find "rule" keyword as a token start */
        const char *r = strstr(p, "rule");
        if (!r) break;
        /* require a word boundary before and after "rule" */
        int pre_ok  = (r == src) || !(isalnum((unsigned char)r[-1]) ||
                                       r[-1] == '_');
        char after  = r[4];
        int post_ok = (after == ' ' || after == '\t' ||
                       after == '\n' || after == '\r' || after == '{');
        if (!(pre_ok && post_ok)) { p = r + 4; continue; }

        const char *q = r + 4;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;

        /* rule name */
        char namebuf[YL_MAX_NAME];
        size_t k = 0;
        while (*q && (isalnum((unsigned char)*q) || *q == '_') &&
               k < YL_MAX_NAME - 1) {
            namebuf[k++] = *q++;
        }
        namebuf[k] = '\0';
        /* skip overlong name remainder */
        while (*q && (isalnum((unsigned char)*q) || *q == '_')) q++;

        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (*q != '{' || k == 0) { p = r + 4; continue; }  /* malformed */

        /* find matching closing brace (no nesting inside our subset, but be
         * defensive: balance braces, ignoring those inside quotes). */
        const char *bstart = q + 1;
        const char *b = bstart;
        int depth = 1;
        int in_str = 0;
        while (*b && depth > 0) {
            if (in_str) {
                if (*b == '\\' && b[1]) b++;
                else if (*b == '"') in_str = 0;
            } else if (*b == '"') {
                in_str = 1;
            } else if (*b == '{') {
                depth++;
            } else if (*b == '}') {
                depth--;
                if (depth == 0) break;
            }
            b++;
        }
        if (depth != 0) break;   /* unterminated rule; stop parsing */

        /* extract body into a bounded temp buffer */
        size_t blen = (size_t)(b - bstart);
        char *body = (char *)malloc(blen + 1);
        if (!body) break;
        memcpy(body, bstart, blen);
        body[blen] = '\0';

        YlRule *rr = &y->rules[y->count];
        memset(rr, 0, sizeof(*rr));
        size_t nn = 0;
        while (namebuf[nn] && nn < YL_MAX_NAME - 1) {
            rr->name[nn] = namebuf[nn]; nn++;
        }
        rr->name[nn] = '\0';

        if (parse_rule_body(rr, body))
            y->count++;
        free(body);

        p = b + 1;   /* continue after this rule */
    }

    free(src);

    if (y->count == 0) { yara_free(y); return NULL; }
    return y;
}

void yara_free(YaraRules *y)
{
    if (!y) return;
    free(y->rules);
    free(y);
}

bool yara_scan(YaraRules *y, const unsigned char *buf, size_t len,
               char *out, size_t cap)
{
    if (out && cap > 0) out[0] = '\0';
    if (!y || !buf || len == 0) return false;

    for (size_t i = 0; i < y->count; i++) {
        if (eval_rule(&y->rules[i], buf, len)) {
            if (out && cap > 0) {
                size_t n = strlen(y->rules[i].name);
                if (n >= cap) n = cap - 1;
                memcpy(out, y->rules[i].name, n);
                out[n] = '\0';
            }
            return true;
        }
    }
    return false;
}
