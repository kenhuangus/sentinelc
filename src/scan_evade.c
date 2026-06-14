/* scan_evade.c - AMSI / ETW in-memory tamper detection (read-only, blue-team).
 *
 * Before running malicious script or .NET, attackers commonly "blind the
 * defender" by patching two functions in their own process memory:
 *   amsi.dll!AmsiScanBuffer  -> so AMSI never sees the payload   (T1562.001)
 *   ntdll!EtwEventWrite      -> so ETW telemetry is suppressed   (T1562.006)
 * The patch lives in memory, not on disk, so it survives packing and never
 * touches a file a signature scanner could catch.
 *
 * We read each candidate process's copy of those function prologues and compare
 * them to a clean reference taken from our own freshly-loaded copy. A mismatch
 * is classified, which is what controls false positives:
 *   - "bypass": the prologue is rewritten to RETURN IMMEDIATELY (ret / xor
 *     eax,eax;ret / mov eax,imm;ret). This neuters the function. CRITICAL.
 *   - "hook": the prologue is a jump/trampoline (jmp rel32, jmp [rip], mov
 *     rax,imm;jmp). Legitimate security products also hook this way, so this is
 *     HIGH and the evidence says "AV product or malware -- investigate".
 *
 * Scope: candidate = a process worth a deep look (unsigned / suspicious / user-
 * writable) OR a script host (powershell/wscript/cscript/mshta), since those
 * are the AMSI-bypass targets. Per-process module bases are resolved so the
 * comparison is correct under ASLR. Wall-clock guarded; degrades without admin.
 *
 * Build: C11, MinGW-w64 / MSVC, -Wall -Wextra. Libs: psapi advapi32 kernel32.
 */
#include "sentinelc.h"

#include <psapi.h>
#include <stdio.h>
#include <string.h>

#define EV_PROLOGUE   16            /* bytes of prologue compared              */
#define EV_MAX_MODS   2048          /* module-handle cap per process           */
#define EV_WALLCLOCK  20000         /* whole-module time budget (ms)           */

/* clean reference prologues + their RVAs, captured once from our own process */
typedef struct {
    bool          have;
    unsigned char bytes[EV_PROLOGUE];
    SIZE_T        rva;              /* func addr - module base                 */
} CleanRef;

static bool is_script_host(const char *name)
{
    return _stricmp(name, "powershell.exe") == 0 || _stricmp(name, "pwsh.exe") == 0 ||
           _stricmp(name, "wscript.exe") == 0 || _stricmp(name, "cscript.exe") == 0 ||
           _stricmp(name, "mshta.exe") == 0;
}

/* Capture a clean prologue + RVA from a module loaded in our own process. */
static void capture_ref(HMODULE mod, const char *fn, CleanRef *out)
{
    out->have = false;
    if (!mod) return;
    FARPROC p = GetProcAddress(mod, fn);
    if (!p) return;
    memcpy(out->bytes, (const void *)p, EV_PROLOGUE);
    out->rva = (SIZE_T)((const unsigned char *)p - (const unsigned char *)mod);
    out->have = true;
}

/* Classify a modified prologue. Returns 1 = bypass (neutered), 2 = hook, 0 = no
 * recognizable patch shape (still a mismatch, report as generic tamper). */
static int classify_patch(const unsigned char *b)
{
    /* return-early shapes => bypass */
    if (b[0] == 0xC3) return 1;                                   /* ret      */
    if ((b[0] == 0x31 || b[0] == 0x33) && b[1] == 0xC0 && b[2] == 0xC3)
        return 1;                                                 /* xor eax,eax;ret */
    if (b[0] == 0xB8 && b[5] == 0xC3) return 1;                   /* mov eax,imm32;ret */
    if (b[0] == 0xC2) return 1;                                   /* ret imm16 */
    /* jump/trampoline shapes => hook */
    if (b[0] == 0xE9) return 2;                                   /* jmp rel32 */
    if (b[0] == 0xFF && b[1] == 0x25) return 2;                   /* jmp [rip+x] */
    if (b[0] == 0x48 && b[1] == 0xB8) return 2;                   /* mov rax,imm64 (->jmp) */
    if (b[0] == 0x68) return 2;                                   /* push imm; ret */
    return 0;
}

/* Resolve a named module's base in a remote process (ASLR-correct). */
static BYTE *remote_module_base(HANDLE proc, const wchar_t *want)
{
    HMODULE mods[EV_MAX_MODS];
    DWORD need = 0;
    if (!EnumProcessModulesEx(proc, mods, sizeof mods, &need, LIST_MODULES_ALL))
        return NULL;
    size_t n = need / sizeof(HMODULE);
    if (n > EV_MAX_MODS) n = EV_MAX_MODS;
    for (size_t i = 0; i < n; i++) {
        wchar_t base[64];
        if (GetModuleBaseNameW(proc, mods[i], base, 64) &&
            _wcsicmp(base, want) == 0)
            return (BYTE *)mods[i];
    }
    return NULL;
}

static void check_func(ScanCtx *c, HANDLE proc, const ProcRec *r, BYTE *modbase,
                       const CleanRef *ref, const char *label, const char *rule)
{
    if (!modbase || !ref->have)
        return;
    unsigned char cur[EV_PROLOGUE];
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, modbase + ref->rva, cur, EV_PROLOGUE, &got) ||
        got < EV_PROLOGUE)
        return;
    if (memcmp(cur, ref->bytes, EV_PROLOGUE) == 0)
        return;   /* clean */

    int kind = classify_patch(cur);
    char target[SC_MAX_PATH];
    snprintf(target, sizeof target, "%s", r->image_path[0] ? r->image_path : r->name);
    if (kind == 1) {
        bus_emit(c->bus, rule, SEV_CRIT, 90, ACT_SUSPEND, r->pid, target,
                 "AMSI/ETW neutered in memory (defense-evasion bypass)",
                 "%s (pid %lu): %s prologue rewritten to return immediately "
                 "[%02x %02x %02x %02x %02x %02x] -- scanning/telemetry disabled",
                 r->name, (unsigned long)r->pid, label,
                 cur[0], cur[1], cur[2], cur[3], cur[4], cur[5]);
    } else {
        bus_emit(c->bus, rule, SEV_HIGH, 65, ACT_REVIEW, r->pid, target,
                 "AMSI/ETW function hooked in memory",
                 "%s (pid %lu): %s prologue modified [%02x %02x %02x %02x %02x %02x] "
                 "-- a hook/trampoline (a security product or malware); investigate",
                 r->name, (unsigned long)r->pid, label,
                 cur[0], cur[1], cur[2], cur[3], cur[4], cur[5]);
    }
}

void scan_evade(ScanCtx *c)
{
    if (!c || !c->procs || !c->bus)
        return;

    /* clean references from our own (fresh, untampered) process */
    CleanRef etw = {0}, amsi = {0};
    capture_ref(GetModuleHandleW(L"ntdll.dll"), "EtwEventWrite", &etw);
    HMODULE amsimod = LoadLibraryW(L"amsi.dll");
    capture_ref(amsimod, "AmsiScanBuffer", &amsi);
    if (!etw.have && !amsi.have) {
        ctx_note_limit(c, "scan_evade: could not load reference functions; skipped.");
        if (amsimod) FreeLibrary(amsimod);
        return;
    }

    ULONGLONG t0 = GetTickCount64();
    size_t denied = 0, skipped_wow64 = 0;
    DWORD self = GetCurrentProcessId();

    for (size_t i = 0; i < c->procs->count; i++) {
        if (GetTickCount64() - t0 > EV_WALLCLOCK) {
            ctx_note_limit(c, "scan_evade: time-capped; some processes not checked.");
            break;
        }
        ProcRec *r = &c->procs->items[i];
        if (r->pid == 0 || r->pid == 4 || r->pid == self)
            continue;
        bool validly_signed = (r->sign_state == SIGN_SIGNED || r->sign_state == SIGN_SIGNED_MS);
        bool candidate = is_script_host(r->name) || !validly_signed ||
                         r->suspicious_mem ||
                         (r->image_path[0] && path_is_user_writable(r->image_path));
        if (!candidate)
            continue;
        if (r->image_path[0] && allowlist_match(r->image_path))
            continue;

        HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  FALSE, r->pid);
        if (!proc) { denied++; continue; }

        /* Our reference prologues come from this 64-bit process's ntdll/amsi.
         * A WOW64 (32-bit) target has a different 32-bit ntdll/amsi with a
         * different layout, so our 64-bit RVA does not apply -- comparing would
         * be a guaranteed false positive. Skip 32-bit processes (a 64-bit
         * scanner cannot validly check them). */
        BOOL wow = FALSE;
        if (IsWow64Process(proc, &wow) && wow) {
            CloseHandle(proc); skipped_wow64++; continue;
        }

        if (etw.have)
            check_func(c, proc, r, remote_module_base(proc, L"ntdll.dll"),
                       &etw, "ntdll!EtwEventWrite", "EVADE.ETW_PATCH");
        if (amsi.have) {
            BYTE *ab = remote_module_base(proc, L"amsi.dll");
            if (ab)   /* amsi only loaded in AMSI-using processes */
                check_func(c, proc, r, ab, &amsi, "amsi!AmsiScanBuffer",
                           "EVADE.AMSI_PATCH");
        }
        CloseHandle(proc);
    }

    if (denied)
        ctx_note_limit(c, "scan_evade: could not open %zu process(es) "
                          "(run elevated for full coverage).", denied);
    if (skipped_wow64)
        ctx_note_limit(c, "scan_evade: %zu 32-bit (WOW64) process(es) not "
                          "checked (a 64-bit scanner cannot compare them).",
                       skipped_wow64);
    if (amsimod) FreeLibrary(amsimod);
}
