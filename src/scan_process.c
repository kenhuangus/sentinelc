/* scan_process.c - process enumeration + per-process triage.
 *
 * Runs FIRST and populates ctx->procs (the shared cache) so that every other
 * scanner can cross-reference processes by pid. Two phases:
 *
 *   Phase 1  Enumerate every process and fill a ProcRec slot:
 *            pid, ppid, name, image_path, cmdline, user, integrity,
 *            sign_state, suspicious_mem (RWX/unbacked-exec walk), accessible.
 *            We DO NOT emit findings here because proctable_add() may realloc
 *            and invalidate slot pointers, and because parent lookups must see
 *            the whole table.
 *
 *   Phase 2  After the table is fully built, walk it by index and emit
 *            findings, including SUSPICIOUS_PARENT which needs proctable_find()
 *            on the ppid.
 *
 * Enumeration is via ntdll!NtQuerySystemInformation(SystemProcessInformation)
 * with a grow-the-buffer loop, falling back to Toolhelp if that fails.
 */
#include "sentinelc.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tlhelp32.h>

/* ------------------------------------------------------------------ */
/* ntdll types (MinGW lacks SYSTEM_PROCESS_INFORMATION)                */
/* ------------------------------------------------------------------ */

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

typedef LONG NTSTATUS_;
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS_)(s)) >= 0)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS_)0xC0000004L)
#endif

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_;

/* Only the fields we touch are named accurately; the rest are padding that
 * matches the documented layout on x64/x86 Windows 10. */
typedef struct _SYSTEM_PROCESS_INFORMATION_ {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING_ ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
    /* threads follow */
} SYSTEM_PROCESS_INFORMATION_;

typedef NTSTATUS_ (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

/* NtQueryInformationProcess + PEB walk for cmdline (best effort) */
#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

typedef struct {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
} PROCESS_BASIC_INFORMATION_;

typedef NTSTATUS_ (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength);

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
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

/* parent-of-interest set for the spawn heuristic */
static bool is_office_parent(const char *name)
{
    static const char *names[] = {
        "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
        "wscript.exe", "cscript.exe", "mshta.exe"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (_stricmp(name, names[i]) == 0)
            return true;
    return false;
}

static bool is_lolbin_child(const char *name)
{
    return _stricmp(name, "cmd.exe") == 0 ||
           _stricmp(name, "powershell.exe") == 0 ||
           _stricmp(name, "rundll32.exe") == 0;
}

/* ------------------------------------------------------------------ */
/* per-process detail collection                                       */
/* ------------------------------------------------------------------ */

/* Full image path via QueryFullProcessImageNameW. Returns true on success. */
static bool get_image_path(HANDLE h, char *out, size_t cap)
{
    wchar_t wbuf[SC_MAX_PATH];
    DWORD wlen = (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]));
    if (!QueryFullProcessImageNameW(h, 0, wbuf, &wlen))
        return false;
    wbuf[(sizeof(wbuf) / sizeof(wbuf[0])) - 1] = L'\0';
    return wide_to_utf8(wbuf, out, cap) > 0;
}

/* DOMAIN\user from the process token. Best effort. */
static void get_token_user(HANDLE proc, char *out, size_t cap)
{
    out[0] = '\0';
    HANDLE tok = NULL;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok))
        return;

    DWORD need = 0;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    if (need == 0) {
        CloseHandle(tok);
        return;
    }
    TOKEN_USER *tu = (TOKEN_USER *)malloc(need);
    if (!tu) {
        CloseHandle(tok);
        return;
    }
    if (GetTokenInformation(tok, TokenUser, tu, need, &need)) {
        wchar_t name[SC_NAME_LEN], dom[SC_NAME_LEN];
        DWORD nlen = SC_NAME_LEN, dlen = SC_NAME_LEN;
        SID_NAME_USE use;
        if (LookupAccountSidW(NULL, tu->User.Sid, name, &nlen, dom, &dlen, &use)) {
            wchar_t full[SC_NAME_LEN * 2 + 2];
            if (dom[0])
                _snwprintf(full, sizeof(full) / sizeof(full[0]), L"%s\\%s", dom, name);
            else
                _snwprintf(full, sizeof(full) / sizeof(full[0]), L"%s", name);
            full[(sizeof(full) / sizeof(full[0])) - 1] = L'\0';
            wide_to_utf8(full, out, cap);
        }
    }
    free(tu);
    CloseHandle(tok);
}

/* Integrity level RID from the token, or -1 if unknown. */
static int get_token_integrity(HANDLE proc)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok))
        return -1;

    int rid = -1;
    DWORD need = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &need);
    if (need > 0) {
        TOKEN_MANDATORY_LABEL *til = (TOKEN_MANDATORY_LABEL *)malloc(need);
        if (til) {
            if (GetTokenInformation(tok, TokenIntegrityLevel, til, need, &need)) {
                DWORD cnt = *GetSidSubAuthorityCount(til->Label.Sid);
                if (cnt > 0)
                    rid = (int)*GetSidSubAuthority(til->Label.Sid, cnt - 1);
            }
            free(til);
        }
    }
    CloseHandle(tok);
    return rid;
}

/* Best-effort command line via PEB->ProcessParameters->CommandLine. */
static void get_cmdline(HANDLE proc, char *out, size_t cap)
{
    out[0] = '\0';

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt)
        return;
    PFN_NtQueryInformationProcess NtQIP =
        (PFN_NtQueryInformationProcess)(void *)GetProcAddress(nt, "NtQueryInformationProcess");
    if (!NtQIP)
        return;

    PROCESS_BASIC_INFORMATION_ pbi;
    memset(&pbi, 0, sizeof(pbi));
    if (!NT_SUCCESS(NtQIP(proc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
        return;
    if (!pbi.PebBaseAddress)
        return;

    /* PEB layout: ProcessParameters pointer sits at offset 0x20 (x64) /
     * 0x10 (x86). RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) sits
     * at offset 0x70 (x64) / 0x40 (x86). We read pointer-sized fields so the
     * same code works for both bitnesses of *this* build. */
#ifdef _WIN64
    const SIZE_T OFF_PP   = 0x20;
    const SIZE_T OFF_CMD  = 0x70;
#else
    const SIZE_T OFF_PP   = 0x10;
    const SIZE_T OFF_CMD  = 0x40;
#endif

    BYTE *peb = (BYTE *)pbi.PebBaseAddress;
    PVOID pp = NULL;
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, peb + OFF_PP, &pp, sizeof(pp), &got) ||
        got != sizeof(pp) || !pp)
        return;

    UNICODE_STRING_ us;
    memset(&us, 0, sizeof(us));
    if (!ReadProcessMemory(proc, (BYTE *)pp + OFF_CMD, &us, sizeof(us), &got) ||
        got != sizeof(us) || !us.Buffer || us.Length == 0)
        return;

    USHORT len = us.Length;
    if (len > (SC_MAX_CMDLINE - 1) * (USHORT)sizeof(wchar_t))
        len = (SC_MAX_CMDLINE - 1) * (USHORT)sizeof(wchar_t);

    wchar_t *wbuf = (wchar_t *)calloc((size_t)len / sizeof(wchar_t) + 1, sizeof(wchar_t));
    if (!wbuf)
        return;
    if (ReadProcessMemory(proc, us.Buffer, wbuf, len, &got) && got > 0) {
        wbuf[got / sizeof(wchar_t)] = L'\0';
        wide_to_utf8(wbuf, out, cap);
    }
    free(wbuf);
}

/* VirtualQueryEx walk: flag the first private RWX / unbacked-exec region.
 * Bounded by region count for speed. */
static bool walk_memory_suspicious(HANDLE proc)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;
    const unsigned MAX_REGIONS = 4096;

    for (unsigned i = 0; i < MAX_REGIONS; i++) {
        SIZE_T r = VirtualQueryEx(proc, addr, &mbi, sizeof(mbi));
        if (r == 0)
            break;

        if (mbi.State == MEM_COMMIT) {
            DWORD prot = mbi.Protect & 0xFF;  /* mask PAGE_GUARD/NOCACHE bits */
            bool rwx  = (prot == PAGE_EXECUTE_READWRITE);
            bool exec = (prot == PAGE_EXECUTE ||
                         prot == PAGE_EXECUTE_READ ||
                         prot == PAGE_EXECUTE_WRITECOPY ||
                         prot == PAGE_EXECUTE_READWRITE);

            if (mbi.Type == MEM_PRIVATE && rwx)
                return true;
            if (exec && mbi.Type != MEM_IMAGE)
                return true;
        }

        BYTE *next = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr)   /* overflow / no progress guard */
            break;
        addr = next;
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* enumeration: NtQuerySystemInformation, Toolhelp fallback            */
/* ------------------------------------------------------------------ */

/* Fill one ProcRec slot for the given pid/ppid/name. Opens the process for
 * deep inspection where allowed. Returns true if it could open it. */
static bool fill_proc(ScanCtx *c, DWORD pid, DWORD ppid, const char *name)
{
    ProcRec *r = proctable_add(c->procs);
    if (!r)
        return false;

    r->pid  = pid;
    r->ppid = ppid;
    copy_bounded(r->name, sizeof(r->name), name);
    r->accessible = false;

    /* PID 0 (System Idle) and 4 (System) cannot be meaningfully opened. */
    if (pid == 0 || pid == 4)
        return false;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                           FALSE, pid);
    if (!h) {
        /* Retry without VM_READ: still lets us get image path/token. */
        h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h)
            return false;
    }

    r->accessible = true;

    if (get_image_path(h, r->image_path, sizeof(r->image_path))) {
        /* If name was empty (Toolhelp gave nothing), derive from path. */
        if (r->name[0] == '\0')
            base_name(r->image_path, r->name, sizeof(r->name));
        r->sign_state = (int)sign_verify(r->image_path, NULL, 0);
    }

    get_token_user(h, r->user, sizeof(r->user));
    r->integrity = get_token_integrity(h);
    get_cmdline(h, r->cmdline, sizeof(r->cmdline));
    r->suspicious_mem = walk_memory_suspicious(h);

    CloseHandle(h);
    return true;
}

/* Returns true if at least one process was enumerated. */
static bool enum_via_ntdll(ScanCtx *c, size_t *inaccessible, size_t *total)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt)
        return false;
    PFN_NtQuerySystemInformation NtQSI =
        (PFN_NtQuerySystemInformation)(void *)GetProcAddress(nt, "NtQuerySystemInformation");
    if (!NtQSI)
        return false;

    ULONG cap = 0x10000;   /* 64 KiB seed */
    BYTE *buf = NULL;
    NTSTATUS_ st = STATUS_INFO_LENGTH_MISMATCH;
    ULONG ret = 0;

    for (int tries = 0; tries < 12; tries++) {
        BYTE *grown = (BYTE *)realloc(buf, cap);
        if (!grown) {
            free(buf);
            return false;
        }
        buf = grown;

        ret = 0;
        st = NtQSI(SystemProcessInformation, buf, cap, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            /* grow generously; ret is a hint that can lag a changing table.
             * Cap at 256 MiB to bound a runaway loop, and guard overflow. */
            const ULONG CEIL = 0x10000000u;   /* 256 MiB */
            ULONG want = (ret > cap) ? ret : cap;
            ULONG headroom = (want < CEIL - 0x10000) ? 0x10000 : 0;
            if (want >= CEIL) {
                free(buf);
                return false;
            }
            cap = want + headroom;
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(st)) {
        free(buf);
        return false;
    }

    /* Bound the walk by the number of bytes the call actually returned, so a
     * bogus NextEntryOffset can't march us off the end of the buffer. */
    size_t valid = (ret > 0 && ret <= cap) ? (size_t)ret : (size_t)cap;
    const BYTE *end = buf + valid;

    size_t count = 0, denied = 0;
    BYTE *p = buf;
    for (;;) {
        /* need at least the fixed header to read the offset fields */
        if (p < buf || (size_t)(end - p) < sizeof(SYSTEM_PROCESS_INFORMATION_))
            break;

        SYSTEM_PROCESS_INFORMATION_ *spi = (SYSTEM_PROCESS_INFORMATION_ *)p;
        DWORD pid  = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
        DWORD ppid = (DWORD)(ULONG_PTR)spi->InheritedFromUniqueProcessId;

        char name[SC_NAME_LEN];
        name[0] = '\0';
        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            /* ImageName.Buffer points into our buffer; it is not NUL-terminated,
             * so copy exactly Length/2 wchars into a temp and terminate. Only
             * trust the pointer if it lies within the returned buffer span. */
            const BYTE *nb = (const BYTE *)spi->ImageName.Buffer;
            if (nb >= buf && nb < end &&
                (size_t)(end - nb) >= spi->ImageName.Length) {
                USHORT wn = spi->ImageName.Length / (USHORT)sizeof(wchar_t);
                wchar_t wtmp[SC_NAME_LEN];
                if (wn > SC_NAME_LEN - 1)
                    wn = SC_NAME_LEN - 1;
                memcpy(wtmp, spi->ImageName.Buffer, (size_t)wn * sizeof(wchar_t));
                wtmp[wn] = L'\0';
                wide_to_utf8(wtmp, name, sizeof(name));
            }
        } else if (pid == 0) {
            copy_bounded(name, sizeof(name), "System Idle Process");
        }

        bool opened = fill_proc(c, pid, ppid, name);
        count++;
        if (!opened && pid != 0 && pid != 4)
            denied++;

        if (spi->NextEntryOffset == 0)
            break;
        /* advance, guarding against a zero/backwards/overflowing offset */
        BYTE *next = p + spi->NextEntryOffset;
        if (next <= p || next > end)
            break;
        p = next;
    }

    free(buf);
    *inaccessible = denied;
    *total = count;
    return count > 0;
}

static bool enum_via_toolhelp(ScanCtx *c, size_t *inaccessible, size_t *total)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    size_t count = 0, denied = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[SC_NAME_LEN];
            name[0] = '\0';
            wide_to_utf8(pe.szExeFile, name, sizeof(name));

            DWORD pid  = pe.th32ProcessID;
            DWORD ppid = pe.th32ParentProcessID;
            bool opened = fill_proc(c, pid, ppid, name);
            count++;
            if (!opened && pid != 0 && pid != 4)
                denied++;
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    *inaccessible = denied;
    *total = count;
    return count > 0;
}

/* ------------------------------------------------------------------ */
/* finding emission (phase 2)                                          */
/* ------------------------------------------------------------------ */

static int conf_clamp(int v)
{
    if (v < 0)  return 0;
    if (v > 100) return 100;
    return v;
}

static void emit_for_proc(ScanCtx *c, ProcRec *r)
{
    if (r->pid == 0 || r->pid == 4)
        return;
    if (r->image_path[0] && allowlist_match(r->image_path))
        return;

    const char *img = r->image_path[0] ? r->image_path : r->name;
    char target[SC_MAX_PATH];
    copy_bounded(target, sizeof(target), img);

    bool unsigned_bad = (r->sign_state == SIGN_UNSIGNED ||
                         r->sign_state == SIGN_INVALID);
    bool user_writable = r->image_path[0] && path_is_user_writable(r->image_path);

    PeInfo pe;
    bool have_pe = false;
    if (r->image_path[0])
        have_pe = pe_analyze(r->image_path, &pe);
    bool packed = have_pe && pe.looks_packed;

    /* PROC.MASQUERADE -- system name living outside its real home */
    if (r->image_path[0] && name_is_masquerade(r->image_path)) {
        bus_emit(c->bus, "PROC.MASQUERADE", SEV_HIGH, conf_clamp(85),
                 ACT_SUSPEND, r->pid, target,
                 "Process masquerades as a system image",
                 "%s (pid %lu) uses a known system image name but lives at %s",
                 r->name, (unsigned long)r->pid, r->image_path);
    }

    /* PROC.TEMP_PATH -- running from a user-writable location.
     *
     * Temp/AppData execution is worth noting, but many legitimate apps live in
     * AppData (VS Code, Slack, Teams, Discord). A valid signature is strong
     * evidence of legitimacy, so signed images get a markedly lower confidence
     * baseline; unsigned/invalid images keep the higher baseline. */
    if (user_writable) {
        bool signed_ok = (r->sign_state == SIGN_SIGNED ||
                          r->sign_state == SIGN_SIGNED_MS);
        int conf = signed_ok ? 30 : 60;
        if (unsigned_bad) conf += 15;
        if (packed)       conf += 10;
        bus_emit(c->bus, "PROC.TEMP_PATH", SEV_MED, conf_clamp(conf),
                 ACT_SUSPEND, r->pid, target,
                 "Process image in a user-writable path",
                 "%s (pid %lu) runs from user-writable path %s [sign=%s%s]",
                 r->name, (unsigned long)r->pid, r->image_path,
                 sign_name((SignVerdict)r->sign_state),
                 packed ? ", packed" : "");
    }

    /* PROC.UNSIGNED_SYS32 -- unsigned/invalid image that claims a system dir */
    if (unsigned_bad && r->image_path[0] &&
        path_classify(r->image_path) == PATHLOC_SYSTEM) {
        bus_emit(c->bus, "PROC.UNSIGNED_SYS32", SEV_MED, conf_clamp(70),
                 ACT_REVIEW, r->pid, target,
                 "Unsigned image in a system directory",
                 "%s (pid %lu) at %s is %s but resides in a system directory",
                 r->name, (unsigned long)r->pid, r->image_path,
                 sign_name((SignVerdict)r->sign_state));
    }

    /* PROC.RWX_MEM -- private RWX / unbacked executable memory.
     *
     * Private RWX / unbacked-exec memory is ubiquitous in legitimate software
     * (.NET JIT, browsers, Electron, AV, games), so on its own it is pure
     * noise. The suspicious_mem flag is still recorded in the ProcRec for the
     * correlation pass; here we only EMIT when there is a corroborating signal:
     * the image is unsigned/invalid, OR runs from a user-writable/temp path, OR
     * the name masquerades as a system image. A signed, system-path process
     * with RWX memory is normal -> suppressed (logged at INFO, not a threat). */
    if (r->suspicious_mem) {
        bool masquerade = r->image_path[0] && name_is_masquerade(r->image_path);
        bool signed_ok  = (r->sign_state == SIGN_SIGNED ||
                           r->sign_state == SIGN_SIGNED_MS);
        /* A valid signature is a strong exoneration: a signed app living in
         * AppData (PowerToys, VS Code, Slack, Teams) with RWX memory is normal.
         * Treat user-writable path as corroborating ONLY when the image is not
         * validly signed. Unsigned/invalid or masquerade always corroborate. */
        bool corroborated = unsigned_bad || masquerade ||
                            (user_writable && !signed_ok);

        if (corroborated) {
            /* SEV_MED by default; raise to HIGH only when unsigned AND
             * user-writable (the strongest staged-code combination). */
            Severity sev = (unsigned_bad && user_writable) ? SEV_HIGH : SEV_MED;
            int conf = 60;
            if (unsigned_bad)  conf += 15;
            if (user_writable) conf += 10;
            if (masquerade)    conf += 10;
            bus_emit(c->bus, "PROC.RWX_MEM", sev, conf_clamp(conf),
                     ACT_SUSPEND, r->pid, target,
                     "Private executable (RWX/unbacked) memory",
                     "%s (pid %lu) has private RWX or unbacked-executable memory "
                     "(possible injected/staged code) [sign=%s%s%s]",
                     r->name, (unsigned long)r->pid,
                     sign_name((SignVerdict)r->sign_state),
                     user_writable ? ", user-writable path" : "",
                     masquerade ? ", masquerade" : "");
        }
        /* Else: signed/system-path process with RWX memory is normal (JIT,
         * browsers, AV, games). We do NOT emit a finding for it -- the
         * suspicious_mem flag remains on the ProcRec for the correlation pass,
         * but on its own it is not worth a line in the report. */
    }

    /* PROC.PACKED -- entropy/section/import packer heuristic.
     *
     * Many legitimate binaries (bash.exe, git tools, compressed installers)
     * sit around entropy ~6.9 and trip the packer heuristic. A signed binary
     * in Program Files that merely looks high-entropy is not worth flagging,
     * so only emit when it looks packed AND there is a corroborating signal
     * (unsigned/invalid signature OR a user-writable path). */
    if (packed && (unsigned_bad || user_writable)) {
        char hint[80];
        if (pe.packer_hint[0])
            _snprintf(hint, sizeof(hint), " hint=%s", pe.packer_hint);
        else
            hint[0] = '\0';
        hint[sizeof(hint) - 1] = '\0';
        int conf = 45;
        if (unsigned_bad)   conf += 15;
        if (user_writable)  conf += 10;
        bus_emit(c->bus, "PROC.PACKED", SEV_LOW, conf_clamp(conf),
                 ACT_REVIEW, r->pid, target,
                 "Process image appears packed",
                 "%s (pid %lu) at %s looks packed (entropy=%.2f)%s",
                 r->name, (unsigned long)r->pid,
                 r->image_path[0] ? r->image_path : "?",
                 pe.overall_entropy, hint);
    }

    /* PROC.SUSPICIOUS_PARENT -- office/script app spawning a shell/lolbin */
    if (is_lolbin_child(r->name)) {
        ProcRec *parent = proctable_find(c->procs, r->ppid);
        if (parent && parent->name[0] && is_office_parent(parent->name)) {
            bus_emit(c->bus, "PROC.SUSPICIOUS_PARENT", SEV_MED, conf_clamp(70),
                     ACT_REVIEW, r->pid, target,
                     "Suspicious parent/child spawn chain",
                     "%s (pid %lu) was spawned by %s (pid %lu) -- "
                     "classic macro/script-to-shell chain",
                     r->name, (unsigned long)r->pid,
                     parent->name, (unsigned long)r->ppid);
        }
    }
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

void scan_process(ScanCtx *c)
{
    if (!c || !c->procs || !c->bus)
        return;

    size_t denied = 0, total = 0;

    /* Phase 1: enumerate + fill the table. */
    if (!enum_via_ntdll(c, &denied, &total))
        (void)enum_via_toolhelp(c, &denied, &total);

    /* If we couldn't open a large share of processes, we're probably not
     * elevated; note it once so the report can caveat its coverage. */
    if (total > 0 && denied * 2 >= total) {
        ctx_note_limit(c,
            "scan_process: could not open %zu of %zu processes for deep "
            "inspection (memory/signature/token); run elevated for full coverage.",
            denied, total);
    }

    /* Phase 2: emit findings now that the table is complete and stable
     * (no more proctable_add, so pointers/indices are valid for parent
     * lookups). Iterate by index, not by cached pointer. */
    for (size_t i = 0; i < c->procs->count; i++)
        emit_for_proc(c, &c->procs->items[i]);
}
