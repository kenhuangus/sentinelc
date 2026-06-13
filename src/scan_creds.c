/* scan_creds.c - credential-access detection (read-only, blue-team).
 *
 * Detects OTHER processes that are positioned to steal credentials by
 * inspecting the system handle table for suspicious processes holding handles
 * to credential-bearing OS objects. This module NEVER opens, reads, or dumps
 * any credential store itself -- it only OBSERVES which processes hold such
 * handles and flags the suspicious owners so the user can investigate.
 *
 * Two checks, both driven off a single read-only walk of the global handle
 * table (NtQuerySystemInformation/SystemHandleInformation):
 *
 *   CHECK 1  CRED.LSASS_HANDLE  (T1003.001)
 *            A non-system process holding a read/dump handle TO lsass.exe is
 *            the classic credential-dumping precursor.
 *
 *   CHECK 2  CRED.SENSITIVE_FILE  (T1003.002 / T1555.003)
 *            A suspicious process holding an open FILE handle to a credential
 *            store (SAM/SECURITY/SYSTEM hive, browser login DB, etc.).
 *
 * Gating (what keeps a clean machine quiet): the OWNER of every flagged handle
 * must be "suspicious" -- unsigned/invalid signature, OR running from a
 * user-writable path, OR not Microsoft-signed. A Microsoft-signed process
 * living in System32 (the OS legitimately holds these handles) is suppressed,
 * as are allowlisted images. lsass/system pseudo-PIDs are never flagged as
 * owners.
 *
 * Robustness: every loop and buffer is bounded with a hard ceiling; offsets
 * are validated; every duplicated handle and allocation is freed/closed on all
 * paths. We resolve a foreign handle's NAME only for FILE-type handles owned by
 * an already-suspicious process (to bound cost and to dodge the well-known
 * NtQueryObject hang on certain synchronous pipe handles). If not elevated,
 * most of the table is inaccessible -> we note the limit once and return
 * gracefully (no crash, no false-negative claims).
 */
#include "sentinelc.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* ntdll types (MinGW lacks SYSTEM_HANDLE_INFORMATION / OBJECT_*)      */
/* ------------------------------------------------------------------ */

typedef LONG NTSTATUS_;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS_)(s)) >= 0)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS_)0xC0000004L)
#endif

#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif
#ifndef ObjectNameInformation
#define ObjectNameInformation 1
#endif

/* PROCESS_* access rights relevant to a read/dump of lsass memory. */
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ           0x0010
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif
#ifndef PROCESS_ALL_ACCESS
/* value varies by SDK; we only test the access-relevant low bits below, but
 * keep a definition for clarity of intent. */
#define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#endif

/* SYSTEM_HANDLE_TABLE_ENTRY_INFO: the legacy (class 16) per-handle record. */
typedef struct {
    USHORT UniqueProcessId;       /* PID that OWNS (holds) the handle */
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;           /* the handle value within the owner */
    PVOID  Object;                /* kernel object pointer */
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_;

typedef struct {
    ULONG                           NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_ Handles[1];   /* variable length */
} SYSTEM_HANDLE_INFORMATION_;

/* OBJECT_NAME_INFORMATION: a UNICODE_STRING whose buffer follows inline. */
typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_;

typedef struct {
    UNICODE_STRING_ Name;
    /* name buffer follows inline */
} OBJECT_NAME_INFORMATION_;

typedef NTSTATUS_ (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

typedef NTSTATUS_ (NTAPI *PFN_NtQueryObject)(
    HANDLE Handle, ULONG ObjectInformationClass, PVOID ObjectInformation,
    ULONG ObjectInformationLength, PULONG ReturnLength);

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static int conf_clamp(int v)
{
    if (v < 0)   return 0;
    if (v > 100) return 100;
    return v;
}

/* The owner pseudo-PIDs that legitimately hold credential-bearing handles and
 * must never be flagged: System Idle (0), System (4). lsass itself is handled
 * separately (a handle whose owner IS lsass is not a "foreign" handle). */
static bool is_system_owner_pid(DWORD pid)
{
    return pid == 0 || pid == 4;
}

/* Decide whether the OWNER process of a handle is suspicious enough to flag.
 * This is the gate that keeps a clean machine quiet: a Microsoft-signed image
 * in System32 (or any validly Microsoft-signed image) is exonerated, as is an
 * allowlisted image; everything unsigned / user-writable / non-MS is suspect.
 *
 * Returns true if suspicious. *why (optional) gets a short reason for evidence.
 * If the owner process is not in our cache or has no resolvable image, we treat
 * it conservatively as suspicious (an owner we could not vet sitting on a
 * credential handle is exactly what we want surfaced). */
static bool owner_is_suspicious(const ProcRec *r, const char **why)
{
    if (why) *why = "owner not inspectable";
    if (!r)
        return true;  /* unknown owner holding a cred handle -> surface it */

    /* allowlisted image: explicitly trusted -> quiet. */
    if (r->image_path[0] && allowlist_match(r->image_path)) {
        if (why) *why = "allowlisted";
        return false;
    }

    bool have_img = r->image_path[0] != '\0';
    SignVerdict sv = (SignVerdict)r->sign_state;

    /* A validly signed image -- Microsoft OR a trusted third party (Chrome,
     * Slack, an EDR agent, ...) -- is the clean state and is the ONLY broad
     * exoneration. This is also what keeps the cost bounded: validly-signed
     * processes (the vast majority) never trigger the expensive handle-name
     * resolution below. */
    if (have_img && (sv == SIGN_SIGNED || sv == SIGN_SIGNED_MS)) {
        if (why) *why = "validly signed";
        return false;
    }

    /* The genuine risk shapes: unsigned/invalid, or running from a path the
     * user (hence malware) can write. */
    if (have_img && (sv == SIGN_UNSIGNED || sv == SIGN_INVALID)) {
        if (why) *why = "unsigned/invalid signature";
        return true;
    }
    if (have_img && path_is_user_writable(r->image_path)) {
        if (why) *why = "user-writable path";
        return true;
    }
    /* Could-not-verify (signature unknown, or no image because we could not
     * open it). Elevated -- where this module runs -- this is uncommon (mostly
     * PPL/protected processes), so surfacing such an owner sitting on a cred
     * handle is worth it without flooding cost. */
    if (why) *why = have_img ? "signature unverifiable" : "image path unknown";
    return true;
}

/* Find lsass.exe in the process cache. Returns its pid, or 0 if not found. */
static DWORD find_lsass_pid(const ProcTable *t)
{
    if (!t)
        return 0;
    for (size_t i = 0; i < t->count; i++) {
        const ProcRec *r = &t->items[i];
        if (_stricmp(r->name, "lsass.exe") == 0)
            return r->pid;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* handle-table acquisition                                            */
/* ------------------------------------------------------------------ */

/* Query the global handle table with a bounded grow loop. On success returns a
 * malloc'd buffer (caller frees) and sets *out_count to NumberOfHandles. On
 * failure returns NULL. *denied is set true when the call was refused in a way
 * that suggests insufficient privilege. */
static SYSTEM_HANDLE_INFORMATION_ *
query_handle_table(PFN_NtQuerySystemInformation NtQSI, ULONG *out_count,
                   bool *denied)
{
    const ULONG  CEIL    = 0x10000000u;   /* 256 MiB hard ceiling */
    ULONG        cap     = 0x100000;      /* 1 MiB seed */
    BYTE        *buf     = NULL;
    NTSTATUS_    st      = STATUS_INFO_LENGTH_MISMATCH;
    ULONG        ret     = 0;

    *out_count = 0;
    if (denied) *denied = false;

    for (int tries = 0; tries < 16; tries++) {
        BYTE *grown = (BYTE *)realloc(buf, cap);
        if (!grown) {
            free(buf);
            return NULL;
        }
        buf = grown;

        ret = 0;
        st = NtQSI(SystemHandleInformation, buf, cap, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            ULONG want = (ret > cap) ? ret : cap;
            if (want >= CEIL - 0x100000) {
                free(buf);
                return NULL;
            }
            /* grow generously: the table can change between calls. */
            cap = want + want / 2 + 0x100000;
            if (cap >= CEIL || cap < want) {  /* overflow / ceiling guard */
                free(buf);
                return NULL;
            }
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(st)) {
        if (denied) *denied = true;
        free(buf);
        return NULL;
    }

    SYSTEM_HANDLE_INFORMATION_ *shi = (SYSTEM_HANDLE_INFORMATION_ *)buf;

    /* Validate that NumberOfHandles actually fits in the returned buffer so a
     * bogus count cannot march us off the end. */
    if (cap < sizeof(ULONG)) {
        free(buf);
        return NULL;
    }
    ULONG n = shi->NumberOfHandles;
    size_t header = sizeof(ULONG);  /* NumberOfHandles, then array */
    size_t maxfit = (cap - header) / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_);
    if ((size_t)n > maxfit)
        n = (ULONG)maxfit;

    *out_count = n;
    return shi;
}

/* ------------------------------------------------------------------ */
/* CHECK 2: sensitive-file name matching + foreign-handle name resolve */
/* ------------------------------------------------------------------ */

/* Does an object name (case-insensitive) point at a credential-bearing file?
 * On match, *is_hive is set true for the SAM/SECURITY/SYSTEM registry hives
 * (which warrant CRIT rather than HIGH). The match is conservative: registry
 * hives require their full "\config\<HIVE>" tail; browser stores match by a
 * distinctive file name. */
static bool name_is_sensitive(const char *name, bool *is_hive)
{
    if (is_hive) *is_hive = false;
    if (!name || !name[0])
        return false;

    /* Registry hives (T1003.002): SAM and SECURITY are the credential hives;
     * SYSTEM is needed alongside them to decrypt -> all three are CRIT. */
    static const char *hives[] = {
        "\\config\\sam", "\\config\\security", "\\config\\system"
    };
    for (size_t i = 0; i < sizeof(hives) / sizeof(hives[0]); i++) {
        if (str_iendswith(name, hives[i])) {
            if (is_hive) *is_hive = true;
            return true;
        }
    }

    /* Browser / app credential stores (T1555.003). "Login Data" / "Local State"
     * are Chromium; key4.db / logins.json / cookies.sqlite / places.sqlite are
     * Firefox; "\Network\Cookies" is Chromium's network cookie DB. */
    static const char *files[] = {
        "\\login data", "key4.db", "logins.json", "cookies.sqlite",
        "\\network\\cookies", "places.sqlite", "\\local state"
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if (str_icontains(name, files[i]))
            return true;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* same-app suppression for CHECK 2 (browser/app store false positives)*/
/* ------------------------------------------------------------------ */

/* Lower-case copy into a bounded buffer. Always NUL-terminates. */
static void sc_to_lower_copy(const char *src, char *dst, size_t cap)
{
    if (!dst || cap == 0)
        return;
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < cap; i++) {
            char ch = src[i];
            if (ch >= 'A' && ch <= 'Z')
                ch = (char)(ch - 'A' + 'a');
            dst[i] = ch;
        }
    }
    dst[i] = '\0';
}

/* Is the credential file under a KNOWN REAL-BROWSER profile path? These are the
 * genuine infostealer targets: a non-browser process touching Chrome/Edge/Brave/
 * Firefox/Chromium "User Data" / "Profiles" is the signal we must NEVER suppress.
 * `lname` must already be lower-cased. */
static bool cred_is_real_browser_profile(const char *lname)
{
    static const char *browser_profiles[] = {
        "\\google\\chrome\\user data\\",
        "\\microsoft\\edge\\user data\\",
        "\\bravesoftware\\brave-browser\\",
        "\\mozilla\\firefox\\profiles\\",
        "\\chromium\\user data\\",
    };
    for (size_t i = 0; i < sizeof(browser_profiles) / sizeof(browser_profiles[0]);
         i++) {
        if (strstr(lname, browser_profiles[i]))
            return true;
    }
    return false;
}

/* Extract, from a lower-cased path, the MSIX/Store package moniker segment that
 * follows "\windowsapps\" or "\packages\" -- i.e. the directory component right
 * after that anchor. Writes the segment (lower-cased, up to the next '\') into
 * `seg` and returns true if found. Examples of a segment:
 *   "openai.codex_26.609.3341.0_x64__2p2nqsd0c76g0"
 *   "openai.codex_2p2nqsd0c76g0"  */
static bool extract_pkg_segment(const char *lname, const char *anchor,
                                char *seg, size_t cap)
{
    if (!lname || !anchor || !seg || cap == 0)
        return false;
    const char *p = strstr(lname, anchor);
    if (!p)
        return false;
    p += strlen(anchor);          /* now at the start of the segment */
    size_t i = 0;
    for (; p[i] && p[i] != '\\' && i + 1 < cap; i++)
        seg[i] = p[i];
    seg[i] = '\0';
    return i > 0;
}

/* From a package moniker segment (lower-cased), derive:
 *   - name prefix  = everything before the FIRST '_'
 *   - publisher id = the token after the LAST "__" if present (WindowsApps form),
 *                    else the token after the LAST '_' (Packages\<Name>_<pubid>).
 * Both outputs are NUL-terminated. Returns true if BOTH could be derived. */
static bool pkg_name_and_pubid(const char *seg, char *name, size_t name_cap,
                               char *pubid, size_t pubid_cap)
{
    if (!seg || !seg[0] || !name || name_cap == 0 || !pubid || pubid_cap == 0)
        return false;

    /* name prefix: up to first '_' */
    size_t i = 0;
    for (; seg[i] && seg[i] != '_' && i + 1 < name_cap; i++)
        name[i] = seg[i];
    name[i] = '\0';
    if (i == 0)
        return false;

    /* publisher id: prefer the token after the LAST "__", else after last '_'. */
    const char *dd = NULL;
    for (const char *q = seg; (q = strstr(q, "__")) != NULL; q += 2)
        dd = q;
    const char *pub = NULL;
    if (dd) {
        pub = dd + 2;
    } else {
        const char *us = strrchr(seg, '_');
        if (!us)
            return false;
        pub = us + 1;
    }
    size_t j = 0;
    for (; pub[j] && pub[j] != '\\' && j + 1 < pubid_cap; j++)
        pubid[j] = pub[j];
    pubid[j] = '\0';
    return j > 0;
}

/* Try one anchor: extract the package segment from the OWNER path, derive its
 * Name + PublisherId, and confirm BOTH the name prefix AND the publisher-id hash
 * also appear in the credential-file path. Returns true on a same-package match.
 * All inputs are lower-cased. */
static bool same_pkg_via_anchor(const char *owner_l, const char *cred_l,
                                const char *anchor)
{
    char seg[SC_MAX_PATH];
    if (!extract_pkg_segment(owner_l, anchor, seg, sizeof(seg)))
        return false;

    char name[SC_NAME_LEN], pubid[SC_NAME_LEN];
    if (!pkg_name_and_pubid(seg, name, sizeof(name), pubid, sizeof(pubid)))
        return false;

    /* Require a reasonably distinctive publisher id so a 1-2 char token can't
     * accidentally match. Store PublisherIds are 13-char hashes. */
    if (strlen(pubid) < 4 || strlen(name) < 2)
        return false;

    if (strstr(cred_l, name) && strstr(cred_l, pubid))
        return true;
    return false;
}

/* Compute the owner's app-root directory (lower-cased) from its image path:
 * the directory portion, walked up past a trailing "\app", "\bin", or a
 * version-looking last segment. Writes a lower-cased result into `root`. */
static void owner_app_root(const char *owner_l, char *root, size_t cap)
{
    if (!root || cap == 0)
        return;
    root[0] = '\0';
    if (!owner_l)
        return;

    /* directory portion = strip the final "\<file>" component. */
    const char *slash = strrchr(owner_l, '\\');
    size_t dirlen = slash ? (size_t)(slash - owner_l) : strlen(owner_l);
    if (dirlen + 1 > cap)
        dirlen = cap - 1;
    memcpy(root, owner_l, dirlen);
    root[dirlen] = '\0';

    /* Walk up at most a couple of obviously-non-root trailing segments. */
    for (int pass = 0; pass < 2; pass++) {
        char *s = strrchr(root, '\\');
        if (!s)
            break;
        const char *last = s + 1;
        bool stripit = false;
        if (strcmp(last, "app") == 0 || strcmp(last, "bin") == 0) {
            stripit = true;
        } else {
            /* version-looking segment: starts with a digit and contains only
             * digits / dots. e.g. "26.609.3341.0". */
            if (last[0] >= '0' && last[0] <= '9') {
                bool only_ver = true;
                for (const char *q = last; *q; q++) {
                    if (!((*q >= '0' && *q <= '9') || *q == '.')) {
                        only_ver = false;
                        break;
                    }
                }
                stripit = only_ver;
            }
        }
        if (!stripit)
            break;
        *s = '\0';
    }
}

/* Decide whether a CHECK-2 credential-file hit should be SUPPRESSED because the
 * file belongs to the SAME application as the owner process (legit embedded
 * Chromium/CEF/Electron reading its OWN login store).
 *
 * Ordering is critical for safety:
 *   (0) If the credential file lives under a KNOWN REAL-BROWSER profile path,
 *       NEVER suppress -- a non-browser process on a real browser's Login Data
 *       is the genuine infostealer signal. This check is FIRST so nothing below
 *       can hide it.
 *   Then suppress if ANY same-app rule fires:
 *     (1) MSIX/Store package identity match (Name prefix + PublisherId hash both
 *         present in owner path AND cred-file path).
 *     (2) Own-install-dir containment: cred file under the owner's app root.
 *     (3) Generic own-store name-stem: the package segment's name-stem (or the
 *         owner image base-name stem) appears in the cred-file path.
 *
 * `owner_path` is the owner image path (may be empty); `cred_name` is the
 * resolved credential-file object name. Returns true => SUPPRESS (do not emit).
 * Conservative toward NOT suppressing: returns false whenever inputs are thin. */
static bool cred_same_app_suppress(const char *owner_path, const char *cred_name)
{
    if (!owner_path || !owner_path[0] || !cred_name || !cred_name[0])
        return false;   /* not enough to prove same-app -> fire (don't suppress) */

    char owner_l[SC_MAX_PATH];
    char cred_l[SC_MAX_PATH];
    sc_to_lower_copy(owner_path, owner_l, sizeof(owner_l));
    sc_to_lower_copy(cred_name, cred_l, sizeof(cred_l));

    /* (0) Real-browser profile -> ALWAYS fire (never suppress). FIRST. */
    if (cred_is_real_browser_profile(cred_l))
        return false;

    /* (1) MSIX/Store package identity match via either anchor. */
    if (same_pkg_via_anchor(owner_l, cred_l, "\\windowsapps\\"))
        return true;
    if (same_pkg_via_anchor(owner_l, cred_l, "\\packages\\"))
        return true;

    /* (2) Own-install-dir containment. */
    char root[SC_MAX_PATH];
    owner_app_root(owner_l, root, sizeof(root));
    if (root[0] && strstr(cred_l, root))
        return true;

    /* (3) Generic own-store name-stem: derive a distinctive stem from the
     * owner's package segment (preferred) or its image base name, and require
     * that stem to also appear in the credential-file path. */
    {
        char seg[SC_MAX_PATH];
        char stem[SC_NAME_LEN] = {0};
        if (extract_pkg_segment(owner_l, "\\windowsapps\\", seg, sizeof(seg)) ||
            extract_pkg_segment(owner_l, "\\packages\\", seg, sizeof(seg))) {
            /* name prefix before first '_' */
            size_t i = 0;
            for (; seg[i] && seg[i] != '_' && i + 1 < sizeof(stem); i++)
                stem[i] = seg[i];
            stem[i] = '\0';
        } else {
            /* image base name without extension, e.g. "codex" from "codex.exe" */
            const char *slash = strrchr(owner_l, '\\');
            const char *base = slash ? slash + 1 : owner_l;
            size_t i = 0;
            for (; base[i] && base[i] != '.' && i + 1 < sizeof(stem); i++)
                stem[i] = base[i];
            stem[i] = '\0';
        }
        /* Require a distinctive stem so common short tokens can't over-suppress.
         * Generic Electron/runtime names are not distinctive enough. */
        if (strlen(stem) >= 5 &&
            strcmp(stem, "electron") != 0 &&
            strcmp(stem, "chrome") != 0 &&
            strcmp(stem, "msedge") != 0 &&
            strstr(cred_l, stem))
            return true;
    }

    return false;
}

/* --------- timeout-bounded NtQueryObject(ObjectNameInformation) ----------
 *
 * NtQueryObject(ObjectNameInformation) can BLOCK FOREVER on certain handle
 * types (synchronous named pipes, handles to dead/hung network shares, some
 * device handles). The "only resolve file-ish handles owned by suspicious
 * processes" gating reduces how OFTEN we call it, but a single bad handle still
 * hangs the whole scan. The canonical mitigation: run the actual NtQueryObject
 * call on a dedicated worker thread and have the main thread wait on it with a
 * short timeout. If it does not complete in time, ABANDON it (never
 * TerminateThread -- that can corrupt process state / leak locks); the abandoned
 * thread keeps its own context + duplicated handle and frees them itself if it
 * ever returns, so there is no use-after-free with the main thread.
 */

/* Per-call worker timeout. Small: a healthy NtQueryObject returns in well under
 * a millisecond; anything past this is treated as hung. */
#define NQO_TIMEOUT_MS 100u

/* Heap context shared between the main thread and the worker. Ownership rules:
 *   - SUCCESS path (worker finished in time): the MAIN thread reads the result,
 *     closes the worker thread handle, closes ctx->dup, and frees ctx.
 *   - TIMEOUT path (worker still running): ownership of *ctx AND ctx->dup
 *     transfers to the abandoned worker; the main thread closes ONLY the thread
 *     handle (detaching it) and touches neither ctx nor dup again. The worker
 *     closes ctx->dup and frees ctx itself when (if) it ever completes. This is
 *     what prevents a use-after-free across the abandoned-thread boundary. */
typedef struct {
    PFN_NtQueryObject NtQO;
    HANDLE            dup;       /* duplicated handle (worker owns on timeout) */
    BYTE             *nbuf;      /* output buffer */
    ULONG             nbuf_cap;
    NTSTATUS_         status;    /* result of the query */
    bool             completed; /* worker set this just before returning */
} NqoWorkerCtx;

/* Worker entry: performs the one potentially-hanging call. It NEVER frees the
 * context inline on the normal/success path -- the main thread does that after
 * reading the result while still synchronized via the thread handle. Only when
 * the call returns AFTER the main thread has already abandoned it would the
 * resource still be alive; to cover that we cannot know here whether we were
 * abandoned, so the main thread guarantees it will not free a ctx whose worker
 * may still run (it only frees on the WAIT_OBJECT_0 path). On the timeout path
 * the worker's own cleanup (below) is what releases everything. */
static DWORD WINAPI nqo_worker(LPVOID param)
{
    NqoWorkerCtx *w = (NqoWorkerCtx *)param;
    ULONG ret = 0;
    /* The (possibly forever-)blocking call, isolated on this thread. */
    w->status = w->NtQO(w->dup, ObjectNameInformation, w->nbuf, w->nbuf_cap,
                        &ret);
    /* Publish completion last, with a release-ish full barrier so the main
     * thread (which only reads this after WaitForSingleObject signals) sees the
     * status store too. WaitForSingleObject already provides the ordering on
     * the success path; this is belt-and-suspenders. */
    MemoryBarrier();
    w->completed = true;
    return 0;
}

/* Parse a successfully-filled OBJECT_NAME_INFORMATION buffer into UTF-8 out. */
static bool parse_object_name(const BYTE *nbuf, ULONG need, char *out,
                              size_t cap)
{
    const OBJECT_NAME_INFORMATION_ *oni =
        (const OBJECT_NAME_INFORMATION_ *)nbuf;
    if (!oni->Name.Buffer || oni->Name.Length == 0)
        return false;
    /* The name buffer must lie within our allocation. */
    const BYTE *nb = (const BYTE *)oni->Name.Buffer;
    const BYTE *ne = nbuf + need;
    if (!(nb >= nbuf && nb < ne && (size_t)(ne - nb) >= oni->Name.Length))
        return false;

    USHORT wn = oni->Name.Length / (USHORT)sizeof(wchar_t);
    size_t maxw = (need / sizeof(wchar_t));
    if (wn > maxw - 1) wn = (USHORT)(maxw - 1);
    wchar_t *wtmp = (wchar_t *)calloc((size_t)wn + 1, sizeof(wchar_t));
    if (!wtmp)
        return false;
    memcpy(wtmp, oni->Name.Buffer, (size_t)wn * sizeof(wchar_t));
    wtmp[wn] = L'\0';
    bool ok = (wide_to_utf8(wtmp, out, cap) > 0);
    free(wtmp);
    return ok;
}

/* Resolve the object name of a FILE handle held by another process. We
 * DuplicateHandle it into our own process (read-only intent), then call
 * NtQueryObject(ObjectNameInformation) ON A WORKER THREAD bounded by
 * NQO_TIMEOUT_MS, then close the duplicate.
 *
 * Caller guarantees this is a FILE-type handle, but that gating alone is NOT
 * sufficient to avoid the documented NtQueryObject hang, so the worker-thread
 * timeout is the real safety net.
 *
 * *timed_out (required) is set true when the call hung and we abandoned the
 * worker (so the caller can count it against the abandon cap). On the timeout
 * path the duplicated handle is intentionally NOT closed here -- the abandoned
 * worker owns it.
 *
 * Returns true and fills out (UTF-8) on success; false on any failure/timeout. */
static bool resolve_file_handle_name(PFN_NtQueryObject NtQO, HANDLE owner_proc,
                                     HANDLE remote_handle, char *out, size_t cap,
                                     bool *timed_out)
{
    if (timed_out) *timed_out = false;
    if (out && cap) out[0] = '\0';
    if (!owner_proc || !NtQO || !out || cap == 0 || !timed_out)
        return false;

    HANDLE dup = NULL;
    if (!DuplicateHandle(owner_proc, remote_handle, GetCurrentProcess(), &dup,
                         0, FALSE, DUPLICATE_SAME_ACCESS))
        return false;
    if (!dup || dup == INVALID_HANDLE_VALUE)
        return false;

    /* Bounded output buffer. We deliberately do NOT do a sizing call first --
     * the sizing call is itself an NtQueryObject(ObjectNameInformation) and can
     * hang exactly like the real one, so we'd need a second worker for it.
     * Instead use a fixed generous cap (64 KiB); object names never approach
     * this. */
    const ULONG need = 0x10000;  /* 64 KiB */
    BYTE *nbuf = (BYTE *)malloc(need);
    if (!nbuf) {
        CloseHandle(dup);
        return false;
    }

    NqoWorkerCtx *w = (NqoWorkerCtx *)calloc(1, sizeof(*w));
    if (!w) {
        free(nbuf);
        CloseHandle(dup);
        return false;
    }
    w->NtQO     = NtQO;
    w->dup      = dup;
    w->nbuf     = nbuf;
    w->nbuf_cap = need;
    w->status   = STATUS_INFO_LENGTH_MISMATCH;
    w->completed = false;

    HANDLE th = CreateThread(NULL, 0, nqo_worker, w, 0, NULL);
    if (!th) {
        /* Could not spawn a worker -- do not risk a synchronous hang. Treat as
         * unresolved; we still own everything here. */
        free(nbuf);
        free(w);
        CloseHandle(dup);
        return false;
    }

    DWORD wr = WaitForSingleObject(th, NQO_TIMEOUT_MS);
    if (wr == WAIT_OBJECT_0) {
        /* Worker finished in time: we are synchronized with it, so reading w
         * and freeing everything here is safe. */
        bool ok = false;
        if (NT_SUCCESS(w->status))
            ok = parse_object_name(nbuf, need, out, cap);
        CloseHandle(th);
        CloseHandle(dup);
        free(nbuf);
        free(w);
        return ok;
    }

    /* TIMEOUT (or wait failure): the call is hung. ABANDON the worker. Ownership
     * of w, nbuf, and dup now belongs to the still-running thread, which will
     * release them in nqo_cleanup_abandoned-equivalent logic below if it ever
     * returns. We must NOT free/close any of them here, and we close ONLY the
     * thread handle to detach it. */
    *timed_out = true;
    CloseHandle(th);
    return false;
}

/* NOTE on the abandoned-thread cleanup: nqo_worker itself does not free its
 * context, because on the SUCCESS path the main thread owns the free (it is
 * still synchronized via the thread handle and reads w->status). On the TIMEOUT
 * path the worker is abandoned and the main thread has relinquished ownership;
 * to free the resources exactly once in that case we cannot have BOTH sides
 * free. We resolve this by making the worker the sole owner on the timeout path
 * and the main thread the sole owner on the success path. Since the worker does
 * not know which case it is in, the abandoned resources (one small ctx + one
 * 64 KiB buffer + one duplicated handle per abandoned thread) are intentionally
 * left for the OS to reclaim at process exit. This is a bounded, deliberate
 * leak: the abandon cap (see run_walk) limits it to at most a handful of
 * threads per run, which is the documented trade-off for never calling
 * TerminateThread. */

/* ------------------------------------------------------------------ */
/* the walk                                                            */
/* ------------------------------------------------------------------ */

/* The ntdll FILE object type is named "File"; the per-build numeric
 * ObjectTypeIndex is not stable across Windows versions, so we cannot hardcode
 * it. We therefore identify file-type handles by attempting name resolution
 * only after the owner is already suspicious, and we additionally guard the
 * duplicate so a non-file object simply fails to match a sensitive name. To
 * still avoid the NtQueryObject pipe hang, we only resolve handles whose
 * GrantedAccess looks file-like (has FILE_READ_DATA-ish bits) and never touch
 * objects we cannot duplicate. */

/* Heuristic: a granted-access mask that plausibly belongs to a file we would
 * care about (read/query). We keep this permissive but it lets us skip clearly
 * unrelated masks cheaply. */
static bool access_looks_filey(ULONG acc)
{
    /* FILE_READ_DATA(0x1) | FILE_READ_ATTRIBUTES(0x80) | GENERIC_READ
     * | SYNCHRONIZE(0x100000). Any read-ish bit qualifies. */
    const ULONG READISH = 0x0001 | 0x0080 | 0x0089 | 0x00120089u | 0x80000000u;
    return (acc & READISH) != 0;
}

static void run_walk(ScanCtx *c, PFN_NtQuerySystemInformation NtQSI,
                     PFN_NtQueryObject NtQO, DWORD lsass_pid)
{
    bool denied = false;
    ULONG count = 0;
    SYSTEM_HANDLE_INFORMATION_ *shi = query_handle_table(NtQSI, &count, &denied);
    if (!shi) {
        if (denied)
            ctx_note_limit(c,
                "scan_creds: could not read the system handle table "
                "(NtQuerySystemInformation denied); run elevated for credential-"
                "access detection.");
        return;
    }

    /* Cache of opened owner-process handles, keyed by pid, so we don't reopen
     * the same owner for every one of its handles. Bounded small table. */
    enum { OWNER_CACHE = 64 };
    struct { DWORD pid; HANDLE h; bool tried; } cache[OWNER_CACHE];
    memset(cache, 0, sizeof(cache));

    size_t resolved_attempts = 0;
    const size_t RESOLVE_CEIL = 20000;  /* bound total name resolutions */

    /* Cap how many name resolutions may TIME OUT (and thus abandon a stuck
     * worker thread) in a single run. A machine with many hang-prone handles
     * must not spawn hundreds of stuck threads, so after this many timeouts we
     * stop attempting any further name resolution (CHECK 1 still runs). */
    size_t timed_out_count = 0;
    const size_t TIMEOUT_ABANDON_CAP = 8;
    bool noted_skip = false;

    /* Global wall-clock guard for the whole handle-table loop. Even with the
     * per-call timeout, guarantee the module can never dominate scan time: if
     * the loop runs longer than this, stop and return what we found. */
    const ULONGLONG WALL_CAP_MS = 20000;  /* ~20 s */
    ULONGLONG walk_start = GetTickCount64();
    bool noted_timecap = false;

    for (ULONG i = 0; i < count; i++) {
        /* Wall-clock guard: check periodically (cheap) to bound total time. */
        if ((i & 0x3FF) == 0 &&
            (GetTickCount64() - walk_start) > WALL_CAP_MS) {
            if (!noted_timecap) {
                ctx_note_limit(c, "scan_creds: handle scan time-capped");
                noted_timecap = true;
            }
            break;
        }

        SYSTEM_HANDLE_TABLE_ENTRY_INFO_ *e = &shi->Handles[i];
        DWORD owner = (DWORD)e->UniqueProcessId;

        /* Skip handles owned by system pseudo-PIDs or by lsass itself. */
        if (is_system_owner_pid(owner))
            continue;
        if (lsass_pid && owner == lsass_pid)
            continue;

        ProcRec *or_ = proctable_find(c->procs, owner);

        /* -------- CHECK 1: a handle TO lsass held by a foreign process -----
         * The legacy handle table does not record a process handle's TARGET
         * pid, only the object pointer. So we pre-filter on the access mask
         * (a read/dump-relevant grant) and an already-suspicious owner, then
         * duplicate the handle and compare GetProcessId(dup) == lsass to
         * confirm the target. */
        if (lsass_pid &&
            (e->GrantedAccess & (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION |
                                 (PROCESS_ALL_ACCESS & 0xFFFF)))) {

            const char *why = NULL;
            if (owner_is_suspicious(or_, &why)) {
                /* Confirm the handle actually targets lsass: duplicate it and
                 * query the target pid. Only do this for already-suspicious
                 * owners (bounds cost) and only when we can open the owner. */
                HANDLE owner_proc = NULL;
                for (int k = 0; k < OWNER_CACHE; k++) {
                    if (cache[k].tried && cache[k].pid == owner) {
                        owner_proc = cache[k].h;
                        break;
                    }
                }
                if (!owner_proc) {
                    for (int k = 0; k < OWNER_CACHE; k++) {
                        if (!cache[k].tried) {
                            cache[k].tried = true;
                            cache[k].pid = owner;
                            cache[k].h = OpenProcess(
                                PROCESS_DUP_HANDLE, FALSE, owner);
                            owner_proc = cache[k].h;
                            break;
                        }
                    }
                }

                bool targets_lsass = false;
                if (owner_proc) {
                    HANDLE dup = NULL;
                    if (DuplicateHandle(owner_proc, (HANDLE)(ULONG_PTR)e->HandleValue,
                                        GetCurrentProcess(), &dup,
                                        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0) &&
                        dup && dup != INVALID_HANDLE_VALUE) {
                        DWORD tpid = GetProcessId(dup);
                        if (tpid == lsass_pid)
                            targets_lsass = true;
                        CloseHandle(dup);
                    }
                }

                if (targets_lsass) {
                    const char *img = (or_ && or_->image_path[0])
                                      ? or_->image_path
                                      : (or_ && or_->name[0] ? or_->name
                                                             : "<unknown>");
                    char target[SC_MAX_PATH];
                    snprintf(target, sizeof(target), "pid %lu",
                             (unsigned long)owner);
                    bus_emit(c->bus, "CRED.LSASS_HANDLE", SEV_CRIT,
                             conf_clamp(90), ACT_SUSPEND, owner, target,
                             "Suspicious process holds a read handle to LSASS",
                             "owner %s (pid %lu, %s) holds a handle to lsass.exe "
                             "(pid %lu) with access 0x%08lX "
                             "(VM_READ/QUERY) -- credential-dumping precursor "
                             "(T1003.001)",
                             img, (unsigned long)owner, why,
                             (unsigned long)lsass_pid,
                             (unsigned long)e->GrantedAccess);
                }
            }
        }

        /* -------- CHECK 2: a FILE handle to a credential store ------------- */
        if (resolved_attempts < RESOLVE_CEIL &&
            timed_out_count < TIMEOUT_ABANDON_CAP &&
            access_looks_filey(e->GrantedAccess)) {
            const char *why = NULL;
            if (owner_is_suspicious(or_, &why)) {
                /* Open (cached) the owner with DUP_HANDLE rights. */
                HANDLE owner_proc = NULL;
                for (int k = 0; k < OWNER_CACHE; k++) {
                    if (cache[k].tried && cache[k].pid == owner) {
                        owner_proc = cache[k].h;
                        break;
                    }
                }
                if (!owner_proc) {
                    for (int k = 0; k < OWNER_CACHE; k++) {
                        if (!cache[k].tried) {
                            cache[k].tried = true;
                            cache[k].pid = owner;
                            cache[k].h = OpenProcess(
                                PROCESS_DUP_HANDLE, FALSE, owner);
                            owner_proc = cache[k].h;
                            break;
                        }
                    }
                }

                if (owner_proc) {
                    char oname[SC_MAX_PATH];
                    bool timed_out = false;
                    resolved_attempts++;
                    bool got = resolve_file_handle_name(
                            NtQO, owner_proc,
                            (HANDLE)(ULONG_PTR)e->HandleValue,
                            oname, sizeof(oname), &timed_out);
                    if (timed_out) {
                        timed_out_count++;
                        if (timed_out_count >= TIMEOUT_ABANDON_CAP &&
                            !noted_skip) {
                            ctx_note_limit(c,
                                "scan_creds: name resolution partially skipped "
                                "after %zu hung NtQueryObject calls "
                                "(abandoned to avoid blocking the scan)",
                                timed_out_count);
                            noted_skip = true;
                        }
                    }
                    if (got) {
                        bool is_hive = false;
                        if (name_is_sensitive(oname, &is_hive)) {
                            const char *img = (or_ && or_->image_path[0])
                                ? or_->image_path
                                : (or_ && or_->name[0] ? or_->name
                                                       : "<unknown>");

                            /* Same-app suppression: a process reading ITS OWN
                             * app's embedded-browser credential store is normal
                             * and must not be flagged. Applies ONLY to the
                             * browser/app-store cases -- NEVER to SAM/SECURITY/
                             * SYSTEM hives (those are never "an app's own
                             * store"). The real-browser guard inside the helper
                             * is ordered first so a non-browser process touching
                             * a genuine browser's Login Data still fires. */
                            if (!is_hive && or_ &&
                                or_->image_path[0] &&
                                cred_same_app_suppress(or_->image_path, oname))
                                continue;

                            Severity sev = is_hive ? SEV_CRIT : SEV_HIGH;
                            char target[SC_MAX_PATH];
                            snprintf(target, sizeof(target), "pid %lu",
                                     (unsigned long)owner);
                            bus_emit(c->bus, "CRED.SENSITIVE_FILE", sev,
                                     conf_clamp(85), ACT_REVIEW, owner, target,
                                     "Suspicious process holds a credential-file "
                                     "handle",
                                     "owner %s (pid %lu, %s) holds an open file "
                                     "handle to credential store '%s' "
                                     "(%s) -- T1003.002/T1555.003",
                                     img, (unsigned long)owner, why, oname,
                                     is_hive ? "registry hive" : "browser/app "
                                                                 "store");
                        }
                    }
                }
            }
        }
    }

    /* Close every cached owner handle. */
    for (int k = 0; k < OWNER_CACHE; k++) {
        if (cache[k].h && cache[k].h != INVALID_HANDLE_VALUE)
            CloseHandle(cache[k].h);
    }

    free(shi);
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

void scan_creds(ScanCtx *c)
{
    if (!c || !c->procs || !c->bus)
        return;

    /* Credential-access detection reads the global handle table and duplicates
     * other processes' handles -- both need administrator / SeDebugPrivilege.
     * Without elevation the table is mostly invisible (so this finds nothing
     * useful) AND nearly every owner becomes "un-inspectable" -> the file-name
     * resolution path would fire on a huge number of handles and dominate scan
     * time. So require elevation; otherwise note the gap and skip cheaply. */
    if (!c->is_admin) {
        ctx_note_limit(c,
            "scan_creds: not elevated -- credential-access handle inspection "
            "(LSASS/SAM/browser-cred handles) needs admin; skipped.");
        return;
    }

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) {
        ctx_note_limit(c, "scan_creds: ntdll.dll unavailable; skipped.");
        return;
    }
    PFN_NtQuerySystemInformation NtQSI =
        (PFN_NtQuerySystemInformation)(void *)
        GetProcAddress(nt, "NtQuerySystemInformation");
    PFN_NtQueryObject NtQO =
        (PFN_NtQueryObject)(void *)GetProcAddress(nt, "NtQueryObject");
    if (!NtQSI || !NtQO) {
        ctx_note_limit(c, "scan_creds: required ntdll entry points missing; "
                          "skipped.");
        return;
    }

    /* lsass pid for CHECK 1. If lsass is not in the cache (we could not see
     * it, e.g. not elevated), CHECK 1 is skipped but CHECK 2 still runs on
     * whatever owners we can inspect. */
    DWORD lsass_pid = find_lsass_pid(c->procs);

    run_walk(c, NtQSI, NtQO, lsass_pid);
}
