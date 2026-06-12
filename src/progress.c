/* progress.c - live console progress display for SentinelC.
 *
 * A single self-rewriting status line written to STDERR (never stdout, which
 * carries JSON). The bar is TTY-gated: in progress_begin we check whether
 * stderr is a console with _isatty(). If it isn't (redirected to a file/pipe),
 * every function becomes a no-op so redirected logs and --json output stay
 * clean. We still allocate/track the handle so callers never special-case.
 *
 * Redraws are throttled to at most ~10 Hz (100 ms) via GetTickCount64, but the
 * final step (progress_end) always draws. The line is padded to a fixed width
 * so leftovers from a longer previous line are erased, then '\r' returns the
 * cursor for the next overwrite.
 *
 * Two render modes:
 *   total > 0  : "<label>  62% | 3.4/5.6 GB | 12345/143737 | ETA 03:21 | <item>"
 *   total == 0 : "<label>  | 12345 files | 00:42 | <item>"   (indeterminate)
 *
 * is_bytes controls whether the numerator/denominator are humanized as bytes
 * (B/KB/MB/GB) or printed as plain counts.
 *
 * Not thread-safe (FIM / scan_path are single-threaded). No global state, so
 * two bars may be used sequentially without interference.
 */
#include "sentinelc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>        /* _isatty, _fileno */

#define PROG_LINE_WIDTH   100   /* fixed pad width to clear prior longer lines */
#define PROG_LABEL_MAX     32
#define PROG_ITEM_MAX      40   /* basename truncation for the current item */
#define PROG_THROTTLE_MS  100   /* min interval between redraws */

struct ProgressBar {
    bool      enabled;        /* false => all ops are no-ops (not a TTY) */
    bool      is_bytes;       /* humanize numerator/denominator as bytes */
    uint64_t  total;          /* 0 => indeterminate */
    uint64_t  done;           /* last reported cumulative units */
    uint64_t  start_tick;     /* GetTickCount64 at begin */
    uint64_t  last_draw_tick; /* GetTickCount64 at last redraw */
    bool      drawn;          /* have we drawn at least once? */
    char      label[PROG_LABEL_MAX];
    int       spin;           /* spinner phase for indeterminate mode */
};

/* Extract the trailing path component (after the last '\\' or '/'). */
static const char *prog_basename(const char *path)
{
    if (!path) return "";
    const char *base = path;
    for (const char *p = path; *p; p++)
        if (*p == '\\' || *p == '/')
            base = p + 1;
    return base;
}

/* Format a byte count as "<num><unit>" with one decimal for KB+ (e.g. "3.4 GB",
 * "512 B"). out must hold >= 16 bytes. */
static void prog_fmt_bytes(uint64_t v, char *out, size_t cap)
{
    const char *unit = "B";
    double d = (double)v;
    if      (d >= 1024.0 * 1024.0 * 1024.0) { d /= 1024.0 * 1024.0 * 1024.0; unit = "GB"; }
    else if (d >= 1024.0 * 1024.0)          { d /= 1024.0 * 1024.0;          unit = "MB"; }
    else if (d >= 1024.0)                   { d /= 1024.0;                   unit = "KB"; }

    if (unit[0] == 'B')
        snprintf(out, cap, "%llu %s", (unsigned long long)v, unit);
    else
        snprintf(out, cap, "%.1f %s", d, unit);
}

/* Format a second count as "M:SS" or "MM:SS". out must hold >= 8 bytes. */
static void prog_fmt_time(uint64_t secs, char *out, size_t cap)
{
    uint64_t m = secs / 60;
    uint64_t s = secs % 60;
    if (m > 99) m = 99;   /* clamp so the field stays narrow */
    snprintf(out, cap, "%02llu:%02llu", (unsigned long long)m, (unsigned long long)s);
}

ProgressBar *progress_begin(const char *label, uint64_t total_units, bool is_bytes)
{
    ProgressBar *p = (ProgressBar *)calloc(1, sizeof(*p));
    if (!p) return NULL;

    /* TTY gating: only draw when stderr is an interactive console. */
    p->enabled    = (_isatty(_fileno(stderr)) != 0);
    p->is_bytes   = is_bytes;
    p->total      = total_units;
    p->done       = 0;
    p->start_tick = GetTickCount64();
    p->last_draw_tick = 0;
    p->drawn      = false;
    p->spin       = 0;
    snprintf(p->label, sizeof p->label, "%s", label ? label : "Working");
    return p;
}

/* Render the current state to stderr. force=true bypasses the throttle and
 * always redraws (used for the final line). */
static void prog_draw(ProgressBar *p, const char *current_item, bool force)
{
    if (!p || !p->enabled) return;

    uint64_t now = GetTickCount64();
    if (!force) {
        if (p->drawn && (now - p->last_draw_tick) < PROG_THROTTLE_MS)
            return;
    }
    p->last_draw_tick = now;
    p->drawn = true;

    uint64_t elapsed_ms  = now - p->start_tick;
    uint64_t elapsed_sec = elapsed_ms / 1000;

    char item[PROG_ITEM_MAX + 4];
    const char *base = prog_basename(current_item);
    snprintf(item, sizeof item, "%.*s", PROG_ITEM_MAX, base);

    char line[PROG_LINE_WIDTH + 8];
    int n;

    if (p->total > 0) {
        /* determinate: percent | bytes/count | done/total | ETA | item */
        uint64_t pct = (p->done * 100) / p->total;
        if (pct > 100) pct = 100;

        char nbuf[24], dbuf[24];
        if (p->is_bytes) {
            prog_fmt_bytes(p->done, nbuf, sizeof nbuf);
            prog_fmt_bytes(p->total, dbuf, sizeof dbuf);
        } else {
            snprintf(nbuf, sizeof nbuf, "%llu", (unsigned long long)p->done);
            snprintf(dbuf, sizeof dbuf, "%llu", (unsigned long long)p->total);
        }

        char eta[8];
        if (elapsed_sec > 0 && p->done > 0 && p->done <= p->total) {
            /* rate = done/elapsed; eta = (total-done)/rate */
            double rate = (double)p->done / (double)elapsed_sec;
            if (rate > 0.0) {
                double eta_sec = (double)(p->total - p->done) / rate;
                if (eta_sec < 0) eta_sec = 0;
                if (eta_sec > 99 * 60 + 59) eta_sec = 99 * 60 + 59;
                prog_fmt_time((uint64_t)(eta_sec + 0.5), eta, sizeof eta);
            } else {
                snprintf(eta, sizeof eta, "--:--");
            }
        } else {
            snprintf(eta, sizeof eta, "--:--");
        }

        n = snprintf(line, sizeof line,
                     "%s %3llu%% | %s/%s | ETA %s | %s",
                     p->label, (unsigned long long)pct, nbuf, dbuf, eta, item);
    } else {
        /* indeterminate: spinner | count | elapsed | item */
        static const char spinch[4] = { '|', '/', '-', '\\' };
        char et[8];
        prog_fmt_time(elapsed_sec, et, sizeof et);
        const char *unit = p->is_bytes ? "" : " files";
        n = snprintf(line, sizeof line,
                     "%c %s | %llu%s | %s | %s",
                     spinch[p->spin & 3], p->label,
                     (unsigned long long)p->done, unit, et, item);
        p->spin++;
    }

    if (n < 0) return;

    /* pad to fixed width so a previous longer line is fully erased */
    int len = n;
    if (len > PROG_LINE_WIDTH) len = PROG_LINE_WIDTH;  /* truncate overruns */
    fputc('\r', stderr);
    fwrite(line, 1, (size_t)len, stderr);
    for (int i = len; i < PROG_LINE_WIDTH; i++)
        fputc(' ', stderr);
    fputc('\r', stderr);
    fflush(stderr);
}

void progress_step(ProgressBar *p, uint64_t units_done, const char *current_item)
{
    if (!p || !p->enabled) return;
    p->done = units_done;
    prog_draw(p, current_item, false);
}

void progress_end(ProgressBar *p)
{
    if (!p) return;
    if (p->enabled) {
        /* snap to 100% for determinate bars, then finish the line */
        if (p->total > 0 && p->done < p->total)
            p->done = p->total;
        prog_draw(p, NULL, true);
        fputc('\n', stderr);
        fflush(stderr);
    }
    free(p);
}
