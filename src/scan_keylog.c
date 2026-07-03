/* scan_keylog.c - heuristic keylogger / input-hook detector.
 *
 * There is no clean user-mode API to enumerate the owners of global
 * WH_KEYBOARD_LL hooks, so detection rests on two pillars:
 *
 *   1. IAT capability analysis (pe_analyze) of each process image: a binary
 *      that imports hook / async-key-state / raw-input APIs alongside network,
 *      crypto, or while living in a user-writable path is a keylogger shape.
 *
 *   2. Injected-DLL fan-out: a non-system DLL that is loaded into MANY
 *      processes AND itself imports hook/keystate APIs is the classic shape of
 *      an injected global keylogger. We enumerate per-process module lists and
 *      count fan-out, capping work for speed.
 *
 * Signed/Microsoft images are scored down (many legit apps hook); unsigned +
 * user-writable + net images are scored up.
 *
 * Libs: psapi, kernel32, advapi32.
 */
#include "sentinelc.h"

#include <tlhelp32.h>
#include <psapi.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* bounded string copy (file-local) */
static void copy_target(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0)
        return;
    if (!src) { dst[0] = '\0'; return; }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* IAT capability heuristics over the process table                    */
/* ------------------------------------------------------------------ */

/* A short allowlist of well-known input apps that legitimately use raw input
 * (games / IME / accessibility). base name, case-insensitive. */
static bool is_known_input_app(const char *name)
{
    static const char *known[] = {
        "explorer.exe", "TextInputHost.exe", "ctfmon.exe", "dwm.exe",
        "ApplicationFrameHost.exe", "SearchApp.exe", "StartMenuExperienceHost.exe",
        NULL
    };
    if (!name || !name[0])
        return false;
    for (int i = 0; known[i]; i++)
        if (_stricmp(name, known[i]) == 0)
            return true;
    return false;
}

static bool sign_is_ms(int sstate)
{
    return sstate == SIGN_SIGNED_MS;
}

static bool sign_is_trusted(int sstate)
{
    return sstate == SIGN_SIGNED_MS || sstate == SIGN_SIGNED;
}

static int conf_clamp(int v)
{
    if (v < 0)   return 0;
    if (v > 100) return 100;
    return v;
}

static void append_tag(char *dst, size_t cap, const char *tag)
{
    if (!dst || cap == 0 || !tag || !tag[0])
        return;
    size_t used = strlen(dst);
    if (used + 1 >= cap)
        return;
    if (used) {
        dst[used++] = ' ';
        dst[used] = '\0';
    }
    strncat(dst, tag, cap - strlen(dst) - 1);
}

static bool pe_keyboard_capture(const PeInfo *pe)
{
    return pe && (pe->imp_hook_api || pe->imp_keystate_api ||
                  pe->imp_rawinput_api);
}

static int capture_family_count(const PeInfo *pe)
{
    if (!pe)
        return 0;
    int n = 0;
    if (pe_keyboard_capture(pe)) n++;
    if (pe->imp_clipboard_api) n++;
    if (pe->imp_screen_api) n++;
    if (pe->imp_media_capture_api) n++;
    if (pe->imp_cred_api) n++;
    return n;
}

static void capture_tags(const PeInfo *pe, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!pe)
        return;
    if (pe->imp_hook_api) append_tag(out, cap, "hook");
    if (pe->imp_keystate_api) append_tag(out, cap, "keystate");
    if (pe->imp_rawinput_api) append_tag(out, cap, "rawinput");
    if (pe->imp_clipboard_api) append_tag(out, cap, "clipboard");
    if (pe->imp_screen_api) append_tag(out, cap, "screen");
    if (pe->imp_media_capture_api) append_tag(out, cap, "media");
    if (pe->imp_cred_api) append_tag(out, cap, "cred-api");
    if (out[0] == '\0')
        append_tag(out, cap, "none");
}

static void eval_proc_caps(ScanCtx *c, ProcRec *pr)
{
    if (!pr || !pr->image_path[0])
        return;
    if (allowlist_match(pr->image_path) ||
        (pr->name[0] && allowlist_match(pr->name)))
        return;

    PeInfo pe;
    if (!pe_analyze(pr->image_path, &pe))
        return;     /* not a readable PE; nothing to say */

    const char *img  = pr->image_path;
    const char *name = pr->name[0] ? pr->name : "?";
    int  sstate = pr->sign_state;
    bool user_writable = path_is_user_writable(img);
    bool unsigned_img  = (sstate == SIGN_UNSIGNED || sstate == SIGN_INVALID);
    bool ms_signed     = sign_is_ms(sstate);
    bool trusted_img   = sign_is_trusted(sstate);
    bool masquerade    = name_is_masquerade(img);
    bool high_risk_owner = unsigned_img || masquerade ||
                           (pe.looks_packed && !trusted_img) ||
                           (user_writable && !trusted_img);
    bool egress        = pe.imp_net_api || pe.imp_crypt_api;
    int  families      = capture_family_count(&pe);

    char target[SC_MAX_PATH];
    copy_target(target, sizeof(target), img);

    /* ---- KEY.LL_HOOK : hooking + (exfil OR hide) ---- */
    if (pe.imp_hook_api &&
        (pe.imp_net_api || pe.imp_crypt_api || user_writable)) {
        int conf = 70;
        if (unsigned_img)    conf += 12;
        if (user_writable)   conf += 8;
        if (pe.imp_net_api)  conf += 5;
        if (sign_is_trusted(sstate)) conf -= 25;
        if (ms_signed)       conf -= 15;     /* extra discount for MS */
        if (conf < 20) conf = 20;
        if (conf > 99) conf = 99;

        bus_emit(c->bus, "KEY.LL_HOOK", SEV_HIGH, conf, ACT_REVIEW,
                 pr->pid, target,
                 "Process installs input hooks and can exfiltrate/hide",
                 "pid %lu (%s) imports hook API + %s%s%s; sign=%s; image=%s",
                 (unsigned long)pr->pid, name,
                 pe.imp_net_api ? "net " : "",
                 pe.imp_crypt_api ? "crypt " : "",
                 user_writable ? "user-writable-path" : "",
                 sign_name((SignVerdict)sstate), img);
    }

    /* ---- KEY.RAW_INPUT : raw-input + user-writable/unsigned, not a known app ---- */
    if (pe.imp_rawinput_api &&
        (user_writable || unsigned_img) &&
        !is_known_input_app(name)) {
        int conf = 55;
        if (unsigned_img)  conf += 12;
        if (user_writable) conf += 8;
        if (sign_is_trusted(sstate)) conf -= 20;
        if (conf < 15) conf = 15;
        if (conf > 95) conf = 95;

        bus_emit(c->bus, "KEY.RAW_INPUT", SEV_MED, conf, ACT_REVIEW,
                 pr->pid, target,
                 "Raw-input capture by user-writable/unsigned process",
                 "pid %lu (%s) imports RawInput API; %s%s; sign=%s; image=%s",
                 (unsigned long)pr->pid, name,
                 user_writable ? "user-writable " : "",
                 unsigned_img ? "unsigned" : "",
                 sign_name((SignVerdict)sstate), img);
    }

    /* ---- KEY.POLL_HEURISTIC : GetAsyncKeyState poller + net, not MS-signed ---- */
    if (pe.imp_keystate_api && pe.imp_net_api && !ms_signed) {
        int conf = 60;
        if (unsigned_img)  conf += 15;
        if (user_writable) conf += 10;
        if (sstate == SIGN_SIGNED) conf -= 12;   /* signed non-MS: mild discount */
        if (conf < 20) conf = 20;
        if (conf > 97) conf = 97;

        bus_emit(c->bus, "KEY.POLL_HEURISTIC", SEV_MED, conf, ACT_REVIEW,
                 pr->pid, target,
                 "Keystate-polling process with network egress",
                 "pid %lu (%s) imports GetAsyncKeyState/GetKeyState + net; "
                 "sign=%s; image=%s",
                 (unsigned long)pr->pid, name,
                 sign_name((SignVerdict)sstate), img);
    }

    /* ---- SPY.MULTI_CAPTURE: more than one capture family + egress ---- */
    if (families >= 2 && egress && !ms_signed && !is_known_input_app(name) &&
        (high_risk_owner || !trusted_img || families >= 3)) {
        char caps[160];
        capture_tags(&pe, caps, sizeof(caps));

        int conf = 68;
        if (families >= 3) conf += 10;
        if (unsigned_img)  conf += 12;
        if (user_writable) conf += 8;
        if (masquerade)    conf += 8;
        if (pe.looks_packed) conf += 6;
        if (trusted_img)   conf -= 20;
        conf = conf_clamp(conf);

        if (conf >= 50) {
            Severity sev = (conf >= 85 && high_risk_owner) ? SEV_CRIT : SEV_HIGH;
            bus_emit(c->bus, "SPY.MULTI_CAPTURE", sev, conf, ACT_REVIEW,
                     pr->pid, target,
                     "Process combines multiple spyware capture capabilities",
                     "pid %lu (%s) imports capture APIs [%s] plus %s%s; "
                     "families=%d; sign=%s; image=%s",
                     (unsigned long)pr->pid, name, caps,
                     pe.imp_net_api ? "net " : "",
                     pe.imp_crypt_api ? "crypt " : "",
                     families, sign_name((SignVerdict)sstate), img);
        }
    }

    /* ---- SPY.CLIPBOARD: clipboard theft shape ---- */
    if (pe.imp_clipboard_api && !ms_signed &&
        (high_risk_owner || (egress && !trusted_img))) {
        int conf = 58;
        if (egress)        conf += 8;
        if (unsigned_img)  conf += 12;
        if (user_writable) conf += 8;
        if (masquerade)    conf += 8;
        if (pe.looks_packed) conf += 6;
        if (trusted_img)   conf -= 18;
        conf = conf_clamp(conf);

        if (conf >= 50) {
            bus_emit(c->bus, "SPY.CLIPBOARD", SEV_MED, conf, ACT_REVIEW,
                     pr->pid, target,
                     "Process can read clipboard contents with other risk signals",
                     "pid %lu (%s) imports clipboard APIs and has %s%s%s%s; "
                     "sign=%s; image=%s",
                     (unsigned long)pr->pid, name,
                     pe.imp_net_api ? "net " : "",
                     pe.imp_crypt_api ? "crypt " : "",
                     user_writable ? "user-writable-path " : "",
                     unsigned_img ? "unsigned/invalid-signature" : "",
                     sign_name((SignVerdict)sstate), img);
        }
    }

    /* ---- SPY.SCREEN_CAPTURE: screenshot / desktop capture shape ---- */
    if (pe.imp_screen_api && (high_risk_owner || (egress && !trusted_img)) &&
        !ms_signed && !is_known_input_app(name)) {
        int conf = 56;
        if (egress)        conf += 8;
        if (unsigned_img)  conf += 12;
        if (user_writable) conf += 8;
        if (masquerade)    conf += 8;
        if (pe.looks_packed) conf += 6;
        if (trusted_img)   conf -= 20;
        conf = conf_clamp(conf);

        if (conf >= 50) {
            bus_emit(c->bus, "SPY.SCREEN_CAPTURE", SEV_MED, conf, ACT_REVIEW,
                     pr->pid, target,
                     "Process can capture the screen with other risk signals",
                     "pid %lu (%s) imports screenshot/desktop-capture APIs and "
                     "has %s%s%s%s; sign=%s; image=%s",
                     (unsigned long)pr->pid, name,
                     pe.imp_net_api ? "net " : "",
                     pe.imp_crypt_api ? "crypt " : "",
                     user_writable ? "user-writable-path " : "",
                     unsigned_img ? "unsigned/invalid-signature" : "",
                     sign_name((SignVerdict)sstate), img);
        }
    }

    /* ---- SPY.MEDIA_CAPTURE: microphone/camera capture shape ---- */
    if (pe.imp_media_capture_api && !ms_signed &&
        (high_risk_owner || (egress && !trusted_img))) {
        int conf = 56;
        if (egress)        conf += 8;
        if (unsigned_img)  conf += 12;
        if (user_writable) conf += 8;
        if (masquerade)    conf += 8;
        if (pe.looks_packed) conf += 6;
        if (trusted_img)   conf -= 20;
        conf = conf_clamp(conf);

        if (conf >= 50) {
            bus_emit(c->bus, "SPY.MEDIA_CAPTURE", SEV_MED, conf, ACT_REVIEW,
                     pr->pid, target,
                     "Process can capture microphone/camera input with risk signals",
                     "pid %lu (%s) imports media capture APIs and has %s%s%s%s; "
                     "sign=%s; image=%s",
                     (unsigned long)pr->pid, name,
                     pe.imp_net_api ? "net " : "",
                     pe.imp_crypt_api ? "crypt " : "",
                     user_writable ? "user-writable-path " : "",
                     unsigned_img ? "unsigned/invalid-signature" : "",
                     sign_name((SignVerdict)sstate), img);
        }
    }

    /* ---- SPY.CRED_API: Vault/Cred/DPAPI secret-access capability ---- */
    if (pe.imp_cred_api && !ms_signed &&
        (high_risk_owner || (egress && !trusted_img))) {
        int conf = 62;
        if (egress)        conf += 8;
        if (unsigned_img)  conf += 12;
        if (user_writable) conf += 8;
        if (masquerade)    conf += 8;
        if (pe.looks_packed) conf += 6;
        if (trusted_img)   conf -= 18;
        conf = conf_clamp(conf);

        if (conf >= 55) {
            bus_emit(c->bus, "SPY.CRED_API", SEV_HIGH, conf, ACT_REVIEW,
                     pr->pid, target,
                     "Process imports Windows credential/secret APIs with risk signals",
                     "pid %lu (%s) imports Cred/Vault/DPAPI APIs with %s%s%s%s; "
                     "sign=%s; image=%s",
                     (unsigned long)pr->pid, name,
                     pe.imp_net_api ? "net " : "",
                     pe.imp_crypt_api ? "crypt " : "",
                     user_writable ? "user-writable-path " : "",
                     unsigned_img ? "unsigned/invalid-signature" : "",
                     sign_name((SignVerdict)sstate), img);
        }
    }
}

/* ------------------------------------------------------------------ */
/* injected-DLL fan-out detection                                      */
/* ------------------------------------------------------------------ */

#define DLL_MAX_TRACK     1024
#define DLL_FANOUT_MIN    5      /* loaded into >= this many procs => suspicious */
#define DLL_PROC_CAP      400    /* cap processes inspected for speed */
#define DLL_MOD_CAP       512    /* cap modules per process */

typedef struct {
    char  path[SC_MAX_PATH];     /* lowercased full path, dedup key */
    int   count;                 /* distinct processes it is loaded into */
    bool  analyzed;
    bool  is_hooklike;           /* pe_analyze said hook/keystate */
} DllTrack;

static DllTrack *dll_find(DllTrack *a, size_t n, const char *lpath)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(a[i].path, lpath) == 0)
            return &a[i];
    return NULL;
}

/* Is this module path under a system directory (legit shared DLL)? */
static bool module_is_system(const char *path)
{
    PathLoc loc = path_classify(path);
    return loc == PATHLOC_SYSTEM || loc == PATHLOC_WINDOWS ||
           loc == PATHLOC_PROGRAMFILES;
}

/* Record one module sighting for a process, deduped per-process by caller. */
static void dll_record(DllTrack *tracks, size_t *ntracks, const char *path)
{
    if (!path || !path[0])
        return;
    if (module_is_system(path))
        return;     /* only care about non-system DLLs */

    char lpath[SC_MAX_PATH];
    size_t n = strlen(path);
    if (n >= sizeof(lpath)) n = sizeof(lpath) - 1;
    memcpy(lpath, path, n);
    lpath[n] = '\0';
    str_lower(lpath);

    DllTrack *t = dll_find(tracks, *ntracks, lpath);
    if (!t) {
        if (*ntracks >= DLL_MAX_TRACK)
            return;
        t = &tracks[(*ntracks)++];
        copy_target(t->path, sizeof(t->path), lpath);
        t->count = 0;
        t->analyzed = false;
        t->is_hooklike = false;
    }
    t->count++;
}

/* Enumerate modules of one pid via EnumProcessModulesEx, recording non-system
 * DLLs. Dedups within the process so each DLL counts once per process.
 * Returns false if the process could not be opened/inspected. */
static bool enum_proc_modules(DWORD pid, DllTrack *tracks, size_t *ntracks)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) {
        /* fall back to a limited-info handle (works for some procs) */
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h)
            return false;
    }

    HMODULE mods[DLL_MOD_CAP];
    DWORD needed = 0;
    BOOL ok = EnumProcessModulesEx(h, mods, sizeof(mods), &needed,
                                   LIST_MODULES_ALL);
    if (!ok) {
        CloseHandle(h);
        return false;
    }

    DWORD count = needed / sizeof(HMODULE);
    if (count > DLL_MOD_CAP)
        count = DLL_MOD_CAP;

    /* Resolve each module path at most ONCE per handle (N syscalls, not N^2),
     * caching the kept .dll paths into a bounded local array, then dedup by
     * string-comparing against the already-cached paths. The array is sized to
     * the module cap (DLL_MOD_CAP), so it can never overflow. Heap-allocated to
     * keep the stack frame small and avoid shared mutable state. */
    char (*seen)[SC_MAX_PATH] = malloc((size_t)DLL_MOD_CAP * SC_MAX_PATH);
    if (!seen) {
        CloseHandle(h);
        return false;
    }
    size_t nseen = 0;

    for (DWORD i = 0; i < count; i++) {
        char path[SC_MAX_PATH];
        if (GetModuleFileNameExA(h, mods[i], path, sizeof(path)) == 0)
            continue;
        path[sizeof(path) - 1] = '\0';

        /* skip the main image (module 0 is the EXE itself) */
        if (i == 0 && !str_iendswith(path, ".dll"))
            continue;
        if (!str_iendswith(path, ".dll"))
            continue;

        /* check for duplicate within this process against cached paths */
        bool dup = false;
        for (size_t j = 0; j < nseen && !dup; j++) {
            if (_stricmp(seen[j], path) == 0)
                dup = true;
        }
        if (dup)
            continue;

        /* cache this unique path (bounded by DLL_MOD_CAP, can't overflow) */
        if (nseen < DLL_MOD_CAP) {
            copy_target(seen[nseen], SC_MAX_PATH, path);
            nseen++;
        }

        dll_record(tracks, ntracks, path);
    }

    free(seen);
    CloseHandle(h);
    return true;
}

static void detect_injected_dlls(ScanCtx *c)
{
    if (!c->procs || c->procs->count == 0)
        return;

    DllTrack *tracks = (DllTrack *)calloc(DLL_MAX_TRACK, sizeof(DllTrack));
    if (!tracks) {
        ctx_note_limit(c, "keylog: OOM allocating DLL fan-out tracker");
        return;
    }
    size_t ntracks = 0;

    size_t inspected = 0;
    size_t failed = 0;
    size_t limit = c->procs->count;
    if (limit > DLL_PROC_CAP)
        limit = DLL_PROC_CAP;

    for (size_t i = 0; i < c->procs->count && inspected < limit; i++) {
        ProcRec *pr = &c->procs->items[i];
        if (pr->pid == 0)
            continue;
        if (enum_proc_modules(pr->pid, tracks, &ntracks))
            inspected++;
        else
            failed++;
    }

    if (inspected == 0) {
        ctx_note_limit(c, "keylog: could not enumerate modules of any process "
                          "(need elevation / SeDebugPrivilege)");
        free(tracks);
        return;
    }
    if (failed > 0)
        ctx_note_limit(c, "keylog: module enumeration failed for %zu of %zu "
                          "processes (access denied)", failed, inspected + failed);

    /* analyze high-fan-out non-system DLLs */
    for (size_t i = 0; i < ntracks; i++) {
        DllTrack *t = &tracks[i];
        if (t->count < DLL_FANOUT_MIN)
            continue;
        if (allowlist_match(t->path))
            continue;

        PeInfo pe;
        if (!pe_analyze(t->path, &pe))
            continue;
        bool keyboardlike = pe_keyboard_capture(&pe);
        bool capturelike = keyboardlike || pe.imp_clipboard_api ||
                           pe.imp_screen_api || pe.imp_media_capture_api;
        if (!capturelike)
            continue;

        SignVerdict sv = sign_verify(t->path, NULL, 0);
        if (sv == SIGN_SIGNED_MS)
            continue;       /* MS-signed shared DLL: legit fan-out (e.g. shims) */
        if (sv == SIGN_SIGNED && !pe.imp_net_api && !pe.imp_crypt_api) {
            bool strong_capture = pe.imp_keystate_api || pe.imp_rawinput_api ||
                                  pe.imp_clipboard_api ||
                                  pe.imp_media_capture_api;
            if (!strong_capture)
                continue;   /* signed GUI/render DLL fan-out is common */
        }

        char base[SC_NAME_LEN];
        base_name(t->path, base, sizeof(base));

        int conf = 72;
        if (sv == SIGN_UNSIGNED || sv == SIGN_INVALID) conf += 15;
        if (pe.imp_net_api) conf += 5;
        if (pe.imp_clipboard_api || pe.imp_screen_api ||
            pe.imp_media_capture_api) conf += 6;
        if (t->count >= DLL_FANOUT_MIN * 3) conf += 5;
        if (conf > 97) conf = 97;

        char caps[160];
        capture_tags(&pe, caps, sizeof(caps));
        const char *rule = keyboardlike ? "KEY.INJECTED_DLL"
                                        : "SPY.INJECTED_CAPTURE_DLL";
        const char *title = keyboardlike
            ? "Non-system hook/keystate DLL injected across many processes"
            : "Non-system capture-capable DLL injected across many processes";

        bus_emit(c->bus, rule, SEV_HIGH, conf, ACT_REVIEW,
                 0, t->path,
                 title,
                 "%s loaded into %d processes; imports [%s]; sign=%s; path=%s",
                 base, t->count, caps,
                 sign_name(sv), t->path);
    }

    free(tracks);
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

void scan_keylog(ScanCtx *c)
{
    if (!c || !c->bus || !c->procs)
        return;

    /* pillar 1: per-process IAT capability heuristics */
    for (size_t i = 0; i < c->procs->count; i++)
        eval_proc_caps(c, &c->procs->items[i]);

    /* pillar 2: injected-DLL fan-out (best-effort, capped) */
    detect_injected_dlls(c);
}
