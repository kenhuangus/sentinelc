/* scan_rootkit.c -- SentinelC user-mode cross-view rootkit detection.
 *
 * Principle: collect the same information through DIFFERENT APIs and diff
 * them. Discrepancies (a PID, file, or driver visible via one API but hidden
 * from another) suggest user-mode hooking / hiding.
 *
 * HONESTY: this is user-mode cross-view only. A kernel DKOM rootkit that
 * unlinks an EPROCESS from every list, or hooks at the kernel level so all
 * user APIs return the same lie, will defeat this check entirely. We say so
 * in the evidence text. This catches user-mode hooking and naive hiders.
 *
 * Build: C11, MinGW-w64 / MSVC, -Wall -Wextra. ntdll resolved at runtime via
 * GetProcAddress. Libs: psapi wtsapi32 advapi32 kernel32.
 */
#include "sentinelc.h"

#include <psapi.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

/* ---- tuning ---- */
#define RK_MAX_PIDS          4096
#define RK_MAX_HIDDEN_PROC   16
#define RK_MAX_HIDDEN_FILE   24
#define RK_MAX_DRIVERS       1024
#define RK_NT_BUF_START      (64 * 1024)
#define RK_NT_BUF_MAX        (32 * 1024 * 1024)
#define RK_DIR_BUF           (64 * 1024)

/* ============================================================
 *  Minimal ntdll types -- declared here, not in a public SDK.
 * ============================================================ */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((RK_NTSTATUS)(s)) >= 0)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((RK_NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((RK_NTSTATUS)0x80000005L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((RK_NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_NO_MORE_FILES
#define STATUS_NO_MORE_FILES ((RK_NTSTATUS)0x80000006L)
#endif

/* We deliberately do NOT typedef NTSTATUS (some toolchains already do via
 * winternl.h, and a duplicate can warn). Use a private alias instead. */
typedef LONG RK_NTSTATUS;

/* Uniquely-named (_RK suffix) so they never collide with a toolchain's own
 * ntdef/winternl declarations. */
typedef struct _UNICODE_STRING_RK {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_RK;

typedef struct _IO_STATUS_BLOCK_RK {
    union {
        RK_NTSTATUS Status;
        PVOID    Pointer;
    } u;
    ULONG_PTR Information;
} IO_STATUS_BLOCK_RK;

/* SYSTEM_PROCESS_INFORMATION (SystemProcessInformation = 5). We only need the
 * fields up to ImageName + the link offset; layout matches the documented
 * structure for x64/x86. */
typedef struct _SYSTEM_PROCESS_INFORMATION_RK {
    ULONG            NextEntryOffset;
    ULONG            NumberOfThreads;
    LARGE_INTEGER    WorkingSetPrivateSize;
    ULONG            HardFaultCount;
    ULONG            NumberOfThreadsHighWatermark;
    ULONGLONG        CycleTime;
    LARGE_INTEGER    CreateTime;
    LARGE_INTEGER    UserTime;
    LARGE_INTEGER    KernelTime;
    UNICODE_STRING_RK ImageName;
    LONG             BasePriority;
    HANDLE           UniqueProcessId;
    HANDLE           InheritedFromUniqueProcessId;
    /* ... more fields follow; we do not touch them ... */
} SYSTEM_PROCESS_INFORMATION_RK;

#define SystemProcessInformation_RK 5

/* FILE_DIRECTORY_INFORMATION for NtQueryDirectoryFile (info class 1). */
typedef struct _FILE_DIRECTORY_INFORMATION_RK {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;   /* bytes */
    WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION_RK;

#define FileDirectoryInformation_RK 1

/* ---- ntdll function pointer types ---- */
typedef RK_NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

typedef RK_NTSTATUS (NTAPI *NtQueryDirectoryFile_t)(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    IO_STATUS_BLOCK_RK *IoStatusBlock, PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass, BOOLEAN ReturnSingleEntry,
    UNICODE_STRING_RK *FileName, BOOLEAN RestartScan);

typedef struct {
    HMODULE                    ntdll;
    NtQuerySystemInformation_t NtQuerySystemInformation;
    NtQueryDirectoryFile_t     NtQueryDirectoryFile;
} NtApi;

static void ntapi_load(NtApi *n)
{
    memset(n, 0, sizeof(*n));
    n->ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!n->ntdll)
        return;
    n->NtQuerySystemInformation = (NtQuerySystemInformation_t)
        (void *)GetProcAddress(n->ntdll, "NtQuerySystemInformation");
    n->NtQueryDirectoryFile = (NtQueryDirectoryFile_t)
        (void *)GetProcAddress(n->ntdll, "NtQueryDirectoryFile");
}

/* ============================================================
 *  PID set helpers
 * ============================================================ */
typedef struct {
    DWORD pids[RK_MAX_PIDS];
    size_t count;
    bool   ok;       /* the source produced data at all */
    bool   truncated;
} PidSet;

static void pidset_init(PidSet *s)
{
    s->count = 0;
    s->ok = false;
    s->truncated = false;
}

static bool pidset_has(const PidSet *s, DWORD pid)
{
    for (size_t i = 0; i < s->count; i++)
        if (s->pids[i] == pid)
            return true;
    return false;
}

static void pidset_add(PidSet *s, DWORD pid)
{
    if (pid == 0)
        return; /* System Idle -- not a real, consistently-listed process */
    if (pidset_has(s, pid))
        return;
    if (s->count >= RK_MAX_PIDS) {
        s->truncated = true;
        return;
    }
    s->pids[s->count++] = pid;
}

/* ---- source a: Toolhelp ---- */
static void collect_toolhelp(PidSet *s)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            pidset_add(s, pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
        s->ok = true;
    }
    CloseHandle(snap);
}

/* ---- source b: EnumProcesses (psapi) ---- */
static void collect_enumprocesses(PidSet *s)
{
    DWORD *buf = NULL;
    DWORD cap = 1024;
    DWORD needed = 0;
    for (;;) {
        DWORD *nb = (DWORD *)realloc(buf, cap * sizeof(DWORD));
        if (!nb) {
            free(buf);
            return;
        }
        buf = nb;
        if (!EnumProcesses(buf, cap * (DWORD)sizeof(DWORD), &needed)) {
            free(buf);
            return;
        }
        if (needed < cap * sizeof(DWORD))
            break;             /* fit */
        if (cap >= (DWORD)RK_MAX_PIDS * 4u) /* sane upper bound */
            break;
        cap *= 2;
    }
    DWORD n = needed / (DWORD)sizeof(DWORD);
    for (DWORD i = 0; i < n; i++)
        pidset_add(s, buf[i]);
    s->ok = true;
    free(buf);
}

/* ---- source c: NtQuerySystemInformation ---- */
static void collect_ntquery(PidSet *s, const NtApi *n)
{
    if (!n->NtQuerySystemInformation)
        return;
    ULONG cap = RK_NT_BUF_START;
    BYTE *buf = NULL;
    RK_NTSTATUS st;
    for (;;) {
        BYTE *nb = (BYTE *)realloc(buf, cap);
        if (!nb) {
            free(buf);
            return;
        }
        buf = nb;
        ULONG ret = 0;
        st = n->NtQuerySystemInformation(SystemProcessInformation_RK,
                                         buf, cap, &ret);
        if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL ||
            st == STATUS_BUFFER_OVERFLOW) {
            ULONG want = (ret > cap) ? ret : cap * 2;
            if (want > RK_NT_BUF_MAX) {
                free(buf);
                return;
            }
            cap = want;
            continue;
        }
        break;
    }
    if (!NT_SUCCESS(st)) {
        free(buf);
        return;
    }
    BYTE *p = buf;
    for (;;) {
        /* Validate the fixed header fits before dereferencing any field. */
        if ((size_t)(p - buf) > cap ||
            (size_t)(cap - (size_t)(p - buf)) < sizeof(SYSTEM_PROCESS_INFORMATION_RK))
            break;
        SYSTEM_PROCESS_INFORMATION_RK *spi =
            (SYSTEM_PROCESS_INFORMATION_RK *)p;
        DWORD pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
        pidset_add(s, pid);
        ULONG next = spi->NextEntryOffset;
        if (next == 0)
            break;
        /* Reject a non-advancing or backward offset, or one smaller than the
         * header (would cause overlap / stuck loop / OOB on next iteration). */
        if (next < sizeof(SYSTEM_PROCESS_INFORMATION_RK))
            break;
        p += next;
        if ((size_t)(p - buf) >= cap) /* guard malformed chain */
            break;
    }
    s->ok = true;
    free(buf);
}

/* ---- source d: WTSEnumerateProcesses ---- */
static void collect_wts(PidSet *s)
{
    PWTS_PROCESS_INFOW info = NULL;
    DWORD count = 0;
    if (!WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                                &info, &count))
        return;
    for (DWORD i = 0; i < count; i++)
        pidset_add(s, info[i].ProcessId);
    s->ok = true;
    WTSFreeMemory(info);
}

/* Re-verify a suspected hidden PID actually exists right now. A PID missing
 * from a list-API but openable with STILL_ACTIVE is the rootkit signal; a PID
 * that has truly exited is just an enumeration race and we drop it. */
static bool pid_truly_alive(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) {
        /* ERROR_ACCESS_DENIED means it exists but we can't open it -> alive.
         * ERROR_INVALID_PARAMETER means no such pid -> gone (race). */
        return GetLastError() == ERROR_ACCESS_DENIED;
    }
    DWORD code = 0;
    bool alive = false;
    if (GetExitCodeProcess(h, &code))
        alive = (code == STILL_ACTIVE);
    else
        alive = true; /* exists, couldn't read code */
    CloseHandle(h);
    return alive;
}

static const char *src_name(int i)
{
    switch (i) {
    case 0: return "Toolhelp32";
    case 1: return "EnumProcesses";
    case 2: return "NtQuerySystemInformation";
    case 3: return "WTSEnumerateProcesses";
    default: return "?";
    }
}

/* ============================================================
 *  1. PROCESS CROSS-VIEW
 * ============================================================ */
static void cross_view_processes(ScanCtx *c, const NtApi *n)
{
    PidSet src[4];
    for (int i = 0; i < 4; i++)
        pidset_init(&src[i]);

    collect_toolhelp(&src[0]);
    collect_enumprocesses(&src[1]);
    collect_ntquery(&src[2], n);
    collect_wts(&src[3]);

    int ok_sources = 0;
    for (int i = 0; i < 4; i++) {
        if (src[i].ok)
            ok_sources++;
        else
            ctx_note_limit(c, "rootkit: process source %s unavailable",
                           src_name(i));
        if (src[i].truncated)
            ctx_note_limit(c, "rootkit: process source %s truncated at %d pids",
                           src_name(i), RK_MAX_PIDS);
    }
    if (ok_sources < 2) {
        ctx_note_limit(c, "rootkit: <2 process sources available, "
                          "cross-view skipped");
        return;
    }

    /* Build the union of all PIDs any source saw. */
    PidSet uni;
    pidset_init(&uni);
    for (int i = 0; i < 4; i++)
        for (size_t j = 0; j < src[i].count; j++)
            pidset_add(&uni, src[i].pids[j]);

    int emitted = 0;
    for (size_t j = 0; j < uni.count && emitted < RK_MAX_HIDDEN_PROC; j++) {
        DWORD pid = uni.pids[j];

        /* Count how many *available* sources saw / missed this pid. */
        int saw = 0, missed = 0;
        char saw_str[160] = {0};
        char miss_str[160] = {0};
        for (int i = 0; i < 4; i++) {
            if (!src[i].ok)
                continue;
            if (pidset_has(&src[i], pid)) {
                saw++;
                if (saw_str[0])
                    strncat(saw_str, ",", sizeof(saw_str) - strlen(saw_str) - 1);
                strncat(saw_str, src_name(i),
                        sizeof(saw_str) - strlen(saw_str) - 1);
            } else {
                missed++;
                if (miss_str[0])
                    strncat(miss_str, ",",
                            sizeof(miss_str) - strlen(miss_str) - 1);
                strncat(miss_str, src_name(i),
                        sizeof(miss_str) - strlen(miss_str) - 1);
            }
        }

        /* Only interesting if at least one source saw it AND at least one
         * available source missed it. A pid every source missed isn't in the
         * union; a pid every source saw is consistent. */
        if (saw == 0 || missed == 0)
            continue;

        /* Filter the unavoidable enumeration race: re-confirm the process
         * truly exists right now before crying rootkit. */
        if (!pid_truly_alive(pid))
            continue;

        bus_emit(c->bus, "RK.HIDDEN_PROC", SEV_CRIT, 70, ACT_REVIEW, pid,
                 "pid hidden from a list API",
                 "PID hidden in process cross-view",
                 "pid %lu seen by [%s] but missing from [%s]; "
                 "OpenProcess/GetExitCodeProcess confirms it is STILL_ACTIVE. "
                 "A list API is hiding a live process -- user-mode hooking. "
                 "(NOTE: a kernel DKOM rootkit can hide a process from ALL "
                 "user-mode APIs and would NOT be caught here.)",
                 (unsigned long)pid, saw_str, miss_str);
        emitted++;
    }
    if (emitted >= RK_MAX_HIDDEN_PROC)
        ctx_note_limit(c, "rootkit: hidden-process findings capped at %d",
                       RK_MAX_HIDDEN_PROC);
}

/* ============================================================
 *  2. FILE CROSS-VIEW
 * ============================================================ */
typedef struct {
    char  names[512][SC_NAME_LEN];
    size_t count;
    bool   ok;
    bool   truncated;
} NameSet;

static void nameset_init(NameSet *s)
{
    s->count = 0;
    s->ok = false;
    s->truncated = false;
}

static bool nameset_has(const NameSet *s, const char *name)
{
    for (size_t i = 0; i < s->count; i++)
        if (_stricmp(s->names[i], name) == 0)
            return true;
    return false;
}

static void nameset_add(NameSet *s, const char *name)
{
    if (!name[0] || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return;
    if (nameset_has(s, name))
        return;
    if (s->count >= 512) {
        s->truncated = true;
        return;
    }
    strncpy(s->names[s->count], name, SC_NAME_LEN - 1);
    s->names[s->count][SC_NAME_LEN - 1] = '\0';
    s->count++;
}

/* ---- view 1: FindFirstFile/FindNextFile ---- */
static void list_findfirst(const char *dir, NameSet *s)
{
    char pat[SC_MAX_PATH];
    int wn = snprintf(pat, sizeof(pat), "%s\\*", dir);
    if (wn <= 0 || wn >= (int)sizeof(pat))
        return;
    wchar_t wpat[SC_MAX_PATH];
    if (utf8_to_wide(pat, wpat, SC_MAX_PATH) == 0)
        return;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        char nm[SC_NAME_LEN];
        if (wide_to_utf8(fd.cFileName, nm, sizeof(nm)) > 0)
            nameset_add(s, nm);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    s->ok = true;
}

/* ---- view 2: NtQueryDirectoryFile ---- */
static void list_ntquerydir(const char *dir, NameSet *s, const NtApi *n)
{
    if (!n->NtQueryDirectoryFile)
        return;

    /* Open the directory with backslash-prefixed Win32 path; CreateFileW with
     * FILE_FLAG_BACKUP_SEMANTICS gives us a dir handle usable by Nt APIs. */
    wchar_t wdir[SC_MAX_PATH];
    if (utf8_to_wide(dir, wdir, SC_MAX_PATH) == 0)
        return;
    HANDLE h = CreateFileW(wdir, FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;

    BYTE *buf = (BYTE *)malloc(RK_DIR_BUF);
    if (!buf) {
        CloseHandle(h);
        return;
    }

    BOOLEAN restart = TRUE;
    for (;;) {
        IO_STATUS_BLOCK_RK iosb;
        memset(&iosb, 0, sizeof(iosb));
        RK_NTSTATUS st = n->NtQueryDirectoryFile(
            h, NULL, NULL, NULL, &iosb, buf, RK_DIR_BUF,
            FileDirectoryInformation_RK, FALSE, NULL, restart);
        restart = FALSE;
        if (st == STATUS_NO_MORE_FILES)
            break;
        if (!NT_SUCCESS(st))
            break;
        if (iosb.Information == 0)
            break;

        /* Only iterate over the bytes the kernel actually wrote. */
        size_t valid = (iosb.Information < RK_DIR_BUF)
                           ? (size_t)iosb.Information : (size_t)RK_DIR_BUF;
        BYTE *p = buf;
        for (;;) {
            /* The fixed header (offset of FileName) must fit in valid bytes
             * before we may read FileNameLength / NextEntryOffset. */
            size_t used = (size_t)(p - buf);
            size_t hdr = offsetof(FILE_DIRECTORY_INFORMATION_RK, FileName);
            if (used > valid || valid - used < hdr)
                break;
            FILE_DIRECTORY_INFORMATION_RK *di =
                (FILE_DIRECTORY_INFORMATION_RK *)p;
            ULONG fnl = di->FileNameLength;          /* bytes */
            /* FileName payload must also lie entirely within valid bytes. */
            if (fnl <= (valid - used - hdr)) {
                ULONG nl = fnl / (ULONG)sizeof(WCHAR);
                if (nl > 0 && nl < (ULONG)SC_NAME_LEN) {
                    wchar_t wnm[SC_NAME_LEN];
                    memcpy(wnm, di->FileName, (size_t)nl * sizeof(WCHAR));
                    wnm[nl] = L'\0';
                    char nm[SC_NAME_LEN];
                    if (wide_to_utf8(wnm, nm, sizeof(nm)) > 0)
                        nameset_add(s, nm);
                }
            }
            ULONG next = di->NextEntryOffset;
            if (next == 0)
                break;
            /* Reject backward / non-advancing offsets (stuck loop / OOB). */
            if (next < hdr)
                break;
            p += next;
            if ((size_t)(p - buf) >= valid)
                break;
        }
    }
    free(buf);
    CloseHandle(h);
    s->ok = true;
}

static void cross_view_one_dir(ScanCtx *c, const char *dir, const NtApi *n,
                               int *emitted)
{
    NameSet a, b;
    nameset_init(&a);
    nameset_init(&b);
    list_findfirst(dir, &a);
    list_ntquerydir(dir, &b, n);

    if (!a.ok || !b.ok) {
        ctx_note_limit(c, "rootkit: file cross-view incomplete for %s "
                          "(FindFirst=%d NtQueryDir=%d)",
                       dir, a.ok, b.ok);
        return;
    }

    /* Names present via Nt (lower level) but hidden from FindFirst -> classic
     * filter-driver / hook hiding. Also flag the reverse. */
    for (size_t i = 0; i < b.count && *emitted < RK_MAX_HIDDEN_FILE; i++) {
        if (!nameset_has(&a, b.names[i])) {
            char full[SC_MAX_PATH];
            snprintf(full, sizeof(full), "%s\\%s", dir, b.names[i]);
            bus_emit(c->bus, "RK.HIDDEN_FILE", SEV_HIGH, 65, ACT_REVIEW, 0,
                     full, "file hidden from FindFirstFile",
                     "'%s' is returned by NtQueryDirectoryFile but hidden from "
                     "FindFirstFile in %s -- user-mode directory-listing hook. "
                     "(A kernel filter/DKOM rootkit could hide it from both.)",
                     b.names[i], dir);
            (*emitted)++;
        }
    }
    for (size_t i = 0; i < a.count && *emitted < RK_MAX_HIDDEN_FILE; i++) {
        if (!nameset_has(&b, a.names[i])) {
            char full[SC_MAX_PATH];
            snprintf(full, sizeof(full), "%s\\%s", dir, a.names[i]);
            bus_emit(c->bus, "RK.HIDDEN_FILE", SEV_HIGH, 55, ACT_REVIEW, 0,
                     full, "file inconsistent across listing APIs",
                     "'%s' is returned by FindFirstFile but missing from "
                     "NtQueryDirectoryFile in %s -- listing inconsistency.",
                     a.names[i], dir);
            (*emitted)++;
        }
    }
}

static void cross_view_files(ScanCtx *c, const NtApi *n)
{
    char sysdir[SC_MAX_PATH];
    char windir[SC_MAX_PATH];
    char tmpdir[SC_MAX_PATH];
    char drvdir[SC_MAX_PATH];

    UINT sl = GetSystemDirectoryA(sysdir, sizeof(sysdir));
    UINT wl = GetWindowsDirectoryA(windir, sizeof(windir));
    DWORD tl = GetTempPathA(sizeof(tmpdir), tmpdir);

    const char *dirs[4];
    int ndirs = 0;

    if (sl > 0 && sl < sizeof(sysdir)) {
        dirs[ndirs++] = sysdir;
        if (snprintf(drvdir, sizeof(drvdir), "%s\\drivers", sysdir) <
            (int)sizeof(drvdir))
            dirs[ndirs++] = drvdir;
    }
    if (wl > 0 && wl < sizeof(windir))
        dirs[ndirs++] = windir;
    if (tl > 0 && tl < sizeof(tmpdir)) {
        /* GetTempPath leaves a trailing backslash; trim it for consistency. */
        size_t len = strlen(tmpdir);
        if (len > 3 && tmpdir[len - 1] == '\\')
            tmpdir[len - 1] = '\0';
        dirs[ndirs++] = tmpdir;
    }

    int emitted = 0;
    for (int i = 0; i < ndirs && emitted < RK_MAX_HIDDEN_FILE; i++)
        cross_view_one_dir(c, dirs[i], n, &emitted);

    if (emitted >= RK_MAX_HIDDEN_FILE)
        ctx_note_limit(c, "rootkit: hidden-file findings capped at %d",
                       RK_MAX_HIDDEN_FILE);
}

/* ============================================================
 *  3. DRIVER INVENTORY
 * ============================================================ */
/* Normalize \SystemRoot\..., \??\C:\..., \\?\C:\... device prefixes into a
 * plain drive path that sign_verify / path_classify can use. */
static void normalize_driver_path(const char *in, char *out, size_t cap)
{
    out[0] = '\0';
    if (!in || !in[0])
        return;

    char win[SC_MAX_PATH];
    UINT wl = GetWindowsDirectoryA(win, sizeof(win));
    if (wl == 0 || wl >= sizeof(win))
        win[0] = '\0';

    if (_strnicmp(in, "\\SystemRoot\\", 12) == 0) {
        snprintf(out, cap, "%s\\%s", win, in + 12);
    } else if (_strnicmp(in, "\\??\\", 4) == 0) {
        snprintf(out, cap, "%s", in + 4);
    } else if (_strnicmp(in, "\\\\?\\", 4) == 0) {
        snprintf(out, cap, "%s", in + 4);
    } else if (_strnicmp(in, "\\Windows\\", 9) == 0) {
        /* relative to system drive; derive drive from windir */
        char drive = (win[0] && win[1] == ':') ? win[0] : 'C';
        if (cap >= 3) {
            out[0] = drive;
            out[1] = ':';
            size_t room = cap - 3;            /* bytes for `in`, minus NUL */
            size_t n = strlen(in);
            if (n > room) n = room;
            memcpy(out + 2, in, n);
            out[2 + n] = '\0';
        } else {
            size_t n = strlen(in);
            if (n >= cap) n = cap - 1;
            memcpy(out, in, n);
            out[n] = '\0';
        }
    } else {
        snprintf(out, cap, "%s", in);
    }
}

static void driver_inventory(ScanCtx *c)
{
    if (!c->is_admin) {
        ctx_note_limit(c, "rootkit: not elevated -- driver inventory may be "
                          "incomplete; kernel SSDT/inline hooks are NOT "
                          "inspectable from user mode regardless.");
    }

    LPVOID *bases = (LPVOID *)malloc(RK_MAX_DRIVERS * sizeof(LPVOID));
    if (!bases) {
        ctx_note_limit(c, "rootkit: OOM allocating driver list");
        return;
    }
    DWORD needed = 0;
    if (!EnumDeviceDrivers(bases, RK_MAX_DRIVERS * (DWORD)sizeof(LPVOID),
                           &needed)) {
        ctx_note_limit(c, "rootkit: EnumDeviceDrivers failed (err %lu)",
                       (unsigned long)GetLastError());
        free(bases);
        return;
    }
    DWORD count = needed / (DWORD)sizeof(LPVOID);
    if (count > (DWORD)RK_MAX_DRIVERS) {
        ctx_note_limit(c, "rootkit: driver list truncated to %d",
                       RK_MAX_DRIVERS);
        count = RK_MAX_DRIVERS;
    }

    int emitted = 0;
    for (DWORD i = 0; i < count; i++) {
        wchar_t wpath[SC_MAX_PATH];
        if (GetDeviceDriverFileNameW(bases[i], wpath, SC_MAX_PATH) == 0)
            continue;

        char raw[SC_MAX_PATH];
        if (wide_to_utf8(wpath, raw, sizeof(raw)) == 0)
            continue;

        char path[SC_MAX_PATH];
        normalize_driver_path(raw, path, sizeof(path));
        if (!path[0])
            continue;

        char signer[SC_NAME_LEN] = {0};
        SignVerdict v = sign_verify(path, signer, sizeof(signer));

        PathLoc loc = path_classify(path);
        bool in_driver_dir =
            (loc == PATHLOC_SYSTEM) || str_icontains(path, "\\system32\\drivers\\");
        bool user_writable = path_is_user_writable(path);

        bool bad_sign = (v == SIGN_UNSIGNED || v == SIGN_INVALID ||
                         v == SIGN_SIGNED); /* SIGNED but not MS = non-MS */

        /* Flag drivers that are unsigned/non-MS AND located outside the
         * legitimate driver dir, or in a user-writable path. */
        if (bad_sign && (!in_driver_dir || user_writable)) {
            const char *why =
                user_writable ? "in a user-writable path"
                              : "outside System32\\drivers";
            bus_emit(c->bus, "RK.SUSPICIOUS_DRIVER", SEV_MED, 55, ACT_REVIEW, 0,
                     path, "suspicious loaded kernel driver",
                     "loaded driver '%s' is %s and %s (signer: %s). "
                     "Unsigned/non-Microsoft drivers in unusual locations are a "
                     "common rootkit loader. NOTE: user mode cannot inspect "
                     "SSDT/IRP/inline kernel hooks -- a signed-but-malicious or "
                     "DKOM driver may not show here.",
                     path,
                     (v == SIGN_UNSIGNED) ? "UNSIGNED"
                       : (v == SIGN_INVALID) ? "INVALID-signature"
                       : "non-Microsoft-signed",
                     why, signer[0] ? signer : "(none)");
            if (++emitted >= RK_MAX_HIDDEN_FILE)
                break;
        }
    }

    free(bases);
}

/* ============================================================
 *  Entry point
 * ============================================================ */
void scan_rootkit(ScanCtx *c)
{
    if (!c || !c->bus)
        return;

    NtApi n;
    ntapi_load(&n);
    if (!n.NtQuerySystemInformation)
        ctx_note_limit(c, "rootkit: ntdll!NtQuerySystemInformation "
                          "unavailable -- process cross-view degraded");
    if (!n.NtQueryDirectoryFile)
        ctx_note_limit(c, "rootkit: ntdll!NtQueryDirectoryFile "
                          "unavailable -- file cross-view skipped");

    cross_view_processes(c, &n);
    cross_view_files(c, &n);
    driver_inventory(c);
}
