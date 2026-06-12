/* proc_cache.c - process table cache.
 * Populated by scan_process(), read by the other scanners.
 * Single-writer model: scan_process runs to completion and fills the table
 * before any concurrent scanner reads it, so reads need no lock.
 */
#include "sentinelc.h"

#include <stdlib.h>
#include <string.h>

#define PROCTABLE_INIT_CAP 64

void proctable_init(ProcTable *t)
{
    if (!t)
        return;
    t->items = NULL;
    t->count = 0;
    t->cap   = 0;
}

void proctable_free(ProcTable *t)
{
    if (!t)
        return;
    free(t->items);
    t->items = NULL;
    t->count = 0;
    t->cap   = 0;
}

/* Returns a zeroed slot, or NULL on OOM. Pointers returned by previous calls
 * may be invalidated by realloc, so callers must use the slot before the next
 * add (scan_process fills each slot immediately). */
ProcRec *proctable_add(ProcTable *t)
{
    if (!t)
        return NULL;

    if (t->count >= t->cap) {
        size_t new_cap = (t->cap == 0) ? PROCTABLE_INIT_CAP : t->cap * 2;
        /* guard against overflow of the multiply */
        if (new_cap < t->cap || new_cap > (SIZE_MAX / sizeof(ProcRec)))
            return NULL;
        ProcRec *grown = (ProcRec *)realloc(t->items, new_cap * sizeof(ProcRec));
        if (!grown)
            return NULL;
        t->items = grown;
        t->cap   = new_cap;
    }

    ProcRec *slot = &t->items[t->count++];
    memset(slot, 0, sizeof(*slot));
    slot->integrity  = -1;            /* unknown */
    slot->sign_state = SIGN_UNKNOWN;
    return slot;
}

ProcRec *proctable_find(ProcTable *t, DWORD pid)
{
    if (!t || !t->items)
        return NULL;
    for (size_t i = 0; i < t->count; i++) {
        if (t->items[i].pid == pid)
            return &t->items[i];
    }
    return NULL;
}
