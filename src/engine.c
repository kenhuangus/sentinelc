/* engine.c - finding bus, limitation accumulator, and the correlation pass.
 *
 * The FindingBus is the thread-safe sink every scanner writes to. correlate()
 * is a post-scan pass that promotes multi-signal artifacts (a single pid lit up
 * across several finding families) into a high-confidence CORR.IMPLANT finding.
 */
#include "sentinelc.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define BUS_INIT_CAP 128

/* ------------------------------------------------------------------ */
/* small bounded-string helpers                                        */
/* ------------------------------------------------------------------ */

static void copy_bounded(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* FindingBus                                                          */
/* ------------------------------------------------------------------ */

void bus_init(FindingBus *b)
{
    if (!b)
        return;
    b->items = NULL;
    b->count = 0;
    b->cap   = 0;
    InitializeCriticalSection(&b->lock);
}

void bus_free(FindingBus *b)
{
    if (!b)
        return;
    EnterCriticalSection(&b->lock);
    free(b->items);
    b->items = NULL;
    b->count = 0;
    b->cap   = 0;
    LeaveCriticalSection(&b->lock);
    DeleteCriticalSection(&b->lock);
}

/* Copies *f into the bus. Thread-safe. Returns false only on OOM. */
bool bus_push(FindingBus *b, const Finding *f)
{
    if (!b || !f)
        return false;

    bool ok = true;
    EnterCriticalSection(&b->lock);

    if (b->count >= b->cap) {
        size_t new_cap = (b->cap == 0) ? BUS_INIT_CAP : b->cap * 2;
        if (new_cap < b->cap || new_cap > (SIZE_MAX / sizeof(Finding))) {
            ok = false;
        } else {
            Finding *grown = (Finding *)realloc(b->items, new_cap * sizeof(Finding));
            if (!grown) {
                ok = false;
            } else {
                b->items = grown;
                b->cap   = new_cap;
            }
        }
    }

    if (ok) {
        b->items[b->count] = *f;   /* struct copy */
        b->count++;
    }

    LeaveCriticalSection(&b->lock);
    return ok;
}

/* Build + push a finding in one call. Thread-safe. */
void bus_emit(FindingBus *b, const char *rule_id, Severity sev, int confidence,
              ActionKind rec, DWORD pid, const char *target,
              const char *title, const char *evidence_fmt, ...)
{
    if (!b)
        return;

    Finding f;
    memset(&f, 0, sizeof(f));

    f.severity    = sev;
    f.confidence  = (confidence < 0) ? 0 : (confidence > 100 ? 100 : confidence);
    f.recommended = rec;
    f.pid         = pid;

    copy_bounded(f.rule_id, sizeof(f.rule_id), rule_id);
    copy_bounded(f.title,   sizeof(f.title),   title);
    copy_bounded(f.target,  sizeof(f.target),  target);

    if (evidence_fmt) {
        va_list ap;
        va_start(ap, evidence_fmt);
        int n = vsnprintf(f.evidence, sizeof(f.evidence), evidence_fmt, ap);
        va_end(ap);
        /* vsnprintf always null-terminates within cap on C99+; guard anyway */
        if (n < 0)
            f.evidence[0] = '\0';
        f.evidence[sizeof(f.evidence) - 1] = '\0';
    } else {
        f.evidence[0] = '\0';
    }

    (void)bus_push(b, &f);
}

/* ------------------------------------------------------------------ */
/* limitation accumulator                                              */
/* ------------------------------------------------------------------ */

void ctx_note_limit(ScanCtx *c, const char *fmt, ...)
{
    if (!c || !fmt)
        return;

    char line[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    line[sizeof(line) - 1] = '\0';

    EnterCriticalSection(&c->limit_lock);

    size_t used = strlen(c->limitations);
    size_t cap  = sizeof(c->limitations);
    if (used + 1 < cap) {
        size_t avail = cap - used - 1;        /* room left for chars + NUL */
        size_t want  = strlen(line);
        size_t need_nl = (used > 0) ? 1 : 0;  /* separator newline */

        if (avail > need_nl) {
            if (need_nl) {
                c->limitations[used] = '\n';
                used++;
                avail--;
            }
            size_t take = (want < avail) ? want : avail;
            memcpy(c->limitations + used, line, take);
            used += take;
            c->limitations[used] = '\0';
        }
    }

    LeaveCriticalSection(&c->limit_lock);
}

/* ------------------------------------------------------------------ */
/* correlation pass                                                    */
/* ------------------------------------------------------------------ */

/* finding-family classification by rule_id prefix */
typedef enum {
    FAM_PROC = 0,
    FAM_NET,
    FAM_PERSIST,
    FAM_SVC,
    FAM_OTHER,
    FAM__COUNT
} Family;

static Family family_of(const char *rule_id)
{
    if (!rule_id)
        return FAM_OTHER;
    if (strncmp(rule_id, "PROC.", 5) == 0)
        return FAM_PROC;
    if (strncmp(rule_id, "NET.", 4) == 0)
        return FAM_NET;
    if (strncmp(rule_id, "PERSIST.", 8) == 0)
        return FAM_PERSIST;
    if (strncmp(rule_id, "SVC.", 4) == 0)
        return FAM_SVC;
    return FAM_OTHER;
}

/* per-pid accumulator used while grouping */
typedef struct {
    DWORD    pid;
    unsigned fam_mask;          /* bit per Family */
    int      fam_count;         /* distinct families seen */
    int      total;             /* findings referencing this pid */
    Severity max_sev;
    /* short evidence breadcrumb per family, first one wins */
    char     proc_rule[SC_RULEID_LEN];
    char     net_rule[SC_RULEID_LEN];
    char     persist_rule[SC_RULEID_LEN];
} PidAgg;

static PidAgg *agg_find(PidAgg *aggs, size_t n, DWORD pid)
{
    for (size_t i = 0; i < n; i++)
        if (aggs[i].pid == pid)
            return &aggs[i];
    return NULL;
}

void correlate(ScanCtx *c)
{
    if (!c || !c->bus)
        return;

    FindingBus *b = c->bus;

    EnterCriticalSection(&b->lock);
    size_t snap_count = b->count;
    /* Take a private snapshot so we can iterate without holding the lock while
     * we bus_emit (which re-enters the lock). The bus only grows; snapshot is
     * a consistent prefix. */
    Finding *snap = NULL;
    if (snap_count > 0) {
        snap = (Finding *)malloc(snap_count * sizeof(Finding));
        if (snap)
            memcpy(snap, b->items, snap_count * sizeof(Finding));
        else
            snap_count = 0;
    }
    LeaveCriticalSection(&b->lock);

    if (snap_count == 0) {
        free(snap);
        return;
    }

    /* ---- group by pid ---- */
    PidAgg *aggs = (PidAgg *)calloc(snap_count, sizeof(PidAgg));
    if (!aggs) {
        free(snap);
        return;
    }
    size_t nagg = 0;

    for (size_t i = 0; i < snap_count; i++) {
        const Finding *f = &snap[i];
        if (f->pid == 0)
            continue;
        Family fam = family_of(f->rule_id);

        PidAgg *a = agg_find(aggs, nagg, f->pid);
        if (!a) {
            a = &aggs[nagg++];
            a->pid     = f->pid;
            a->max_sev = SEV_INFO;
        }
        a->total++;
        if (f->severity > a->max_sev)
            a->max_sev = f->severity;

        unsigned bit = 1u << (unsigned)fam;
        if (!(a->fam_mask & bit)) {
            a->fam_mask |= bit;
            if (fam != FAM_OTHER)
                a->fam_count++;
            switch (fam) {
            case FAM_PROC:    copy_bounded(a->proc_rule,    sizeof(a->proc_rule),    f->rule_id); break;
            case FAM_NET:     copy_bounded(a->net_rule,     sizeof(a->net_rule),     f->rule_id); break;
            case FAM_PERSIST: copy_bounded(a->persist_rule, sizeof(a->persist_rule), f->rule_id); break;
            default: break;
            }
        }
    }

    /* ---- promote implants: pid lit across >=2 distinct families ---- */
    for (size_t i = 0; i < nagg; i++) {
        PidAgg *a = &aggs[i];
        if (a->fam_count < 2)
            continue;

        /* Build an evidence summary from the families that fired. */
        char ev[SC_EVID_LEN];
        char target[SC_MAX_PATH];
        const char *pname = NULL;
        bool signed_ok = false;
        if (c->procs) {
            ProcRec *pr = proctable_find(c->procs, a->pid);
            if (pr) {
                if (pr->name[0])
                    pname = pr->name;
                signed_ok = (pr->sign_state == SIGN_SIGNED ||
                             pr->sign_state == SIGN_SIGNED_MS);
            }
        }

        snprintf(target, sizeof(target), "pid %lu", (unsigned long)a->pid);

        snprintf(ev, sizeof(ev),
                 "pid %lu%s%s%s shows %d correlated signals across %d families: %s %s %s",
                 (unsigned long)a->pid,
                 pname ? " (" : "", pname ? pname : "", pname ? ")" : "",
                 a->total, a->fam_count,
                 a->proc_rule[0]    ? a->proc_rule    : "",
                 a->net_rule[0]     ? a->net_rule     : "",
                 a->persist_rule[0] ? a->persist_rule : "");
        ev[sizeof(ev) - 1] = '\0';

        /* A real implant is almost never a validly-signed binary. If the
         * process carries a valid signature, the multi-signal pattern is more
         * likely a benign app that simply lives in AppData and listens on a
         * port (LM Studio, WPS, etc.) -- report it for review, but do NOT
         * escalate to a CRITICAL implant. Unsigned/invalid -> CRITICAL. */
        if (signed_ok) {
            bus_emit(b, "CORR.MULTI_SIGNAL", SEV_MED, 45, ACT_REVIEW, a->pid,
                     target,
                     "Multi-signal process (validly signed) -- review",
                     "%s [signed; likely benign multi-signal app]", ev);
        } else {
            bus_emit(b, "CORR.IMPLANT", SEV_CRIT, 90, ACT_REVIEW, a->pid, target,
                     "Multi-signal implant: process correlated across families",
                     "%s", ev);
        }
    }

    /* ---- merge: SVC target binary path == PROC image path ---- */
    /* For each SVC.* finding whose target is a file path, see if any process's
     * image_path matches; if so, note the correlation. */
    if (c->procs && c->procs->count > 0) {
        for (size_t i = 0; i < snap_count; i++) {
            const Finding *sf = &snap[i];
            if (family_of(sf->rule_id) != FAM_SVC)
                continue;
            if (sf->target[0] == '\0')
                continue;

            for (size_t p = 0; p < c->procs->count; p++) {
                ProcRec *pr = &c->procs->items[p];
                if (pr->image_path[0] == '\0')
                    continue;
                if (_stricmp(pr->image_path, sf->target) == 0) {
                    char target[SC_MAX_PATH];
                    copy_bounded(target, sizeof(target), sf->target);
                    bus_emit(b, "CORR.SVC_PROC", SEV_HIGH, 80, ACT_REVIEW,
                             pr->pid, target,
                             "Service binary matches a running process image",
                             "service finding %s targets %s, which is the image "
                             "of running pid %lu (%s)",
                             sf->rule_id, sf->target,
                             (unsigned long)pr->pid,
                             pr->name[0] ? pr->name : "?");
                    break; /* one note per service finding */
                }
            }
        }
    }

    free(aggs);
    free(snap);
}
