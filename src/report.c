/* report.c - SentinelC reporter. Human console (ANSI) or JSON.
 * Read-only: never mutates the bus. C11, Win32 user-mode. Libs: kernel32.
 */
#include "sentinelc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* ---- ANSI ---- */
#define A_RESET "\x1b[0m"
#define A_RED   "\x1b[31m"
#define A_YEL   "\x1b[33m"
#define A_CYAN  "\x1b[36m"
#define A_DIM   "\x1b[2m"
#define A_BOLD  "\x1b[1m"

/* ---- sort: severity desc, then confidence desc, over an index array ---- */
static const Finding *g_sort_items;

static int cmp_idx(const void *a, const void *b)
{
    size_t ia = *(const size_t *)a;
    size_t ib = *(const size_t *)b;
    const Finding *fa = &g_sort_items[ia];
    const Finding *fb = &g_sort_items[ib];
    if (fa->severity != fb->severity)
        return (fa->severity < fb->severity) ? 1 : -1; /* desc */
    if (fa->confidence != fb->confidence)
        return (fa->confidence < fb->confidence) ? 1 : -1; /* desc */
    return 0;
}

/* Build a sorted index array (caller frees). NULL if count==0 or OOM. */
static size_t *sorted_index(const FindingBus *b)
{
    if (b->count == 0)
        return NULL;
    size_t *idx = (size_t *)malloc(b->count * sizeof(size_t));
    if (!idx)
        return NULL;
    for (size_t i = 0; i < b->count; ++i)
        idx[i] = i;
    g_sort_items = b->items;
    qsort(idx, b->count, sizeof(size_t), cmp_idx);
    g_sort_items = NULL;
    return idx;
}

/* ---- JSON escaping ---- */
static void json_escape(const char *s, char *out, size_t cap)
{
    size_t o = 0;
    if (cap == 0) return;
    for (; *s && o + 7 < cap; ++s) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '\\': out[o++] = '\\'; out[o++] = '\\'; break;
        case '"':  out[o++] = '\\'; out[o++] = '"';  break;
        case '\n': out[o++] = '\\'; out[o++] = 'n';  break;
        case '\r': out[o++] = '\\'; out[o++] = 'r';  break;
        case '\t': out[o++] = '\\'; out[o++] = 't';  break;
        case '\b': out[o++] = '\\'; out[o++] = 'b';  break;
        case '\f': out[o++] = '\\'; out[o++] = 'f';  break;
        default:
            if (c < 0x20) {
                int n = _snprintf_s(out + o, cap - o, _TRUNCATE,
                                    "\\u%04x", c);
                if (n > 0) o += (size_t)n;
            } else {
                out[o++] = (char)c;
            }
        }
    }
    out[o] = '\0';
}

static const char *action_name(ActionKind a)
{
    switch (a) {
    case ACT_KILL:        return "kill";
    case ACT_SUSPEND:     return "suspend";
    case ACT_DISABLE_SVC: return "disable_service";
    case ACT_QUARANTINE:  return "quarantine";
    case ACT_REVIEW:
    default:              return "review";
    }
}

/* ---- JSON renderer ---- */
static void render_json(const FindingBus *b, const ScanCtx *c, size_t *idx)
{
    char esc[SC_EVID_LEN * 2 + 16];

    size_t counts[5] = {0,0,0,0,0};
    for (size_t i = 0; i < b->count; ++i) {
        Severity s = b->items[i].severity;
        if (s >= SEV_INFO && s <= SEV_CRIT)
            counts[s]++;
    }

    printf("{\n");
    printf("  \"findings\": [");

    for (size_t i = 0; i < b->count; ++i) {
        const Finding *f = &b->items[idx ? idx[i] : i];
        printf("%s\n    {\n", (i == 0) ? "" : ",");

        json_escape(f->rule_id, esc, sizeof(esc));
        printf("      \"rule\": \"%s\",\n", esc);
        printf("      \"severity\": \"%s\",\n", sev_name(f->severity));
        printf("      \"confidence\": %d,\n", f->confidence);
        printf("      \"pid\": %lu,\n", (unsigned long)f->pid);

        json_escape(f->target, esc, sizeof(esc));
        printf("      \"target\": \"%s\",\n", esc);

        json_escape(f->title, esc, sizeof(esc));
        printf("      \"title\": \"%s\",\n", esc);

        json_escape(f->evidence, esc, sizeof(esc));
        printf("      \"evidence\": \"%s\",\n", esc);

        printf("      \"recommended\": \"%s\"\n", action_name(f->recommended));
        printf("    }");
    }

    printf("%s  ],\n", b->count ? "\n" : "");

    json_escape((c && c->limitations[0]) ? c->limitations : "", esc, sizeof(esc));
    printf("  \"limitations\": \"%s\",\n", esc);

    printf("  \"summary\": {\n");
    printf("    \"total\": %lu,\n", (unsigned long)b->count);
    printf("    \"crit\": %lu,\n", (unsigned long)counts[SEV_CRIT]);
    printf("    \"high\": %lu,\n", (unsigned long)counts[SEV_HIGH]);
    printf("    \"med\": %lu,\n",  (unsigned long)counts[SEV_MED]);
    printf("    \"low\": %lu,\n",  (unsigned long)counts[SEV_LOW]);
    printf("    \"info\": %lu\n",  (unsigned long)counts[SEV_INFO]);
    printf("  }\n");
    printf("}\n");
}

/* ---- console helpers ---- */

/* Enable VT processing on stdout. Returns true if color may be used. */
static bool enable_vt(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE || h == NULL)
        return false;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode))
        return false; /* redirected to a file/pipe: skip color */
    if (!SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        return false;
    return true;
}

static const char *sev_color(Severity s)
{
    switch (s) {
    case SEV_CRIT:
    case SEV_HIGH: return A_RED;
    case SEV_MED:  return A_YEL;
    case SEV_LOW:  return A_CYAN;
    case SEV_INFO:
    default:       return A_DIM;
    }
}

/* Copy src into dst (cap incl. NUL), truncating with a trailing "..." if
 * longer than cap-1. Returns dst. */
static char *trunc_field(const char *src, char *dst, size_t cap)
{
    if (cap == 0) return dst;
    size_t len = strlen(src);
    if (len < cap) {
        memcpy(dst, src, len + 1);
        return dst;
    }
    /* need room for "..." (3) + NUL */
    if (cap < 5) {
        size_t n = cap - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
        return dst;
    }
    size_t keep = cap - 4;
    memcpy(dst, src, keep);
    dst[keep] = '.'; dst[keep+1] = '.'; dst[keep+2] = '.';
    dst[keep+3] = '\0';
    return dst;
}

/* ---- console renderer ---- */
static void render_console(const FindingBus *b, const ScanCtx *c, size_t *idx,
                           bool color)
{
    const char *reset = color ? A_RESET : "";

    if (b->count == 0) {
        if (color) printf(A_BOLD "No suspicious artifacts found." A_RESET "\n");
        else       printf("No suspicious artifacts found.\n");
    } else {
        if (color) printf(A_BOLD);
        printf("SEV   CONF  RULE                       PID    TARGET\n");
        printf("----  ----  -------------------------  -----  ------------------------------\n");
        if (color) printf("%s", reset);

        char rule[26], tgt[31], title[200], evid[400];

        for (size_t i = 0; i < b->count; ++i) {
            const Finding *f = &b->items[idx ? idx[i] : i];
            const char *col = color ? sev_color(f->severity) : "";

            trunc_field(f->rule_id, rule, sizeof(rule));
            trunc_field(f->target,  tgt,  sizeof(tgt));

            printf("%s%-4s%s  %4d  %-25s  %5lu  %-30s\n",
                   col, sev_name(f->severity), reset,
                   f->confidence, rule,
                   (unsigned long)f->pid, tgt);

            trunc_field(f->title, title, sizeof(title));
            printf("      %s%s%s\n", color ? A_BOLD : "", title, reset);

            if (f->evidence[0]) {
                trunc_field(f->evidence, evid, sizeof(evid));
                printf("      %s%s%s\n", color ? A_DIM : "", evid, reset);
            }
            printf("\n");
        }
    }

    /* summary line: counts per severity */
    size_t counts[5] = {0,0,0,0,0};
    for (size_t i = 0; i < b->count; ++i) {
        Severity s = b->items[i].severity;
        if (s >= SEV_INFO && s <= SEV_CRIT)
            counts[s]++;
    }
    printf("Summary: %lu finding%s  (CRIT %lu, HIGH %lu, MED %lu, LOW %lu, INFO %lu)\n",
           (unsigned long)b->count, b->count == 1 ? "" : "s",
           (unsigned long)counts[SEV_CRIT], (unsigned long)counts[SEV_HIGH],
           (unsigned long)counts[SEV_MED], (unsigned long)counts[SEV_LOW],
           (unsigned long)counts[SEV_INFO]);

    printf("\nLimitations:\n");
    if (c && c->limitations[0]) {
        /* limitations is a single accumulated string; print as-is, indented. */
        printf("  %s\n", c->limitations);
    } else {
        printf("  (none recorded; scan ran with available privileges)\n");
    }
}

/* ---- entry point ---- */
void report_render(const FindingBus *b, const ScanCtx *c)
{
    if (!b)
        return;

    size_t *idx = sorted_index(b);
    /* idx may be NULL when count==0 or OOM; renderers handle NULL by
     * falling back to natural order. */

    if (c && c->cfg && c->cfg->json) {
        render_json(b, c, idx);
    } else {
        bool color = false;
        if (!(c && c->cfg && c->cfg->no_color))
            color = enable_vt();
        render_console(b, c, idx, color);
    }

    free(idx);
}
