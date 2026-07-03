/* scan_memscan.c - in-memory injected-code detection (read-only, blue-team).
 *
 * The structural answer to packing: a packed loader hides its imports on disk,
 * but it cannot hide the code it unpacks into memory. This module READS the
 * memory of suspicious processes (it never writes) and classifies anomalous
 * executable regions:
 *
 *   MEM.REFLECTIVE_PE  A private (non-image-backed) executable region whose
 *                      bytes are a mapped PE -> reflective/manual DLL loading
 *                      (Cobalt Strike beacons, reflective loaders). T1620.
 *   MEM.SHELLCODE      A private RWX (writable+executable) region holding raw
 *                      code (no PE header) -> staged shellcode. T1055.
 *   PROC.HOLLOWED      The main image's in-memory PE headers disagree with the
 *                      on-disk file in fields load never changes (entry point,
 *                      section count, image size) -> process hollowing. T1055.012.
 *
 * Cost + false-positive control: we only deep-scan a process that is NOT
 * validly signed, OR already flagged with suspicious memory, OR runs from a
 * user-writable path. Validly-signed system processes (whose JITs legitimately
 * use RWX) are skipped -- that is what keeps this fast and quiet. A global
 * wall-clock guard ensures the module can never dominate scan time. Needs
 * PROCESS_VM_READ (SeDebugPrivilege/admin for other users' processes); it
 * degrades gracefully and notes what it could not read.
 *
 * Build: C11, MinGW-w64 / MSVC, -Wall -Wextra. Libs: psapi advapi32 kernel32.
 */
#include "sentinelc.h"

#include <psapi.h>
#include <stdio.h>
#include <string.h>

/* ---- tuning / hard caps ---- */
#define MS_MAX_REGIONS    8192          /* VirtualQueryEx iterations per proc  */
#define MS_READ_HDR       4096          /* bytes read to classify a region     */
#define MS_MIN_REGION     0x1000        /* ignore sub-page noise               */
#define MS_WALLCLOCK_MS   30000         /* whole-module time budget            */
#define MS_MAX_FINDINGS   256           /* stop emitting past this (sanity)    */

static bool is_lolbin_host(const ProcRec *r)
{
    if (!r)
        return false;
    char name[SC_NAME_LEN] = {0};
    if (r->name[0]) {
        snprintf(name, sizeof(name), "%s", r->name);
    } else if (r->image_path[0]) {
        base_name(r->image_path, name, sizeof(name));
    }
    if (!name[0])
        return false;

    static const char *hosts[] = {
        "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe",
        "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
        "certutil.exe", "bitsadmin.exe", "msiexec.exe", NULL
    };
    for (int i = 0; hosts[i]; i++)
        if (_stricmp(name, hosts[i]) == 0)
            return true;
    return false;
}

/* Is this process worth the cost of a memory deep-scan? Validly-signed images
 * are exonerated (their RWX is often JIT or normal runtime behavior) UNLESS
 * already flagged with suspicious memory or they are signed Windows scripting /
 * LOLBin hosts commonly abused for in-memory payloads. Everything unsigned,
 * unknown, or user-writable remains in scope. */
static bool worth_scanning(const ProcRec *r)
{
    if (!r || r->pid == 0 || r->pid == 4)
        return false;
    if (r->image_path[0] && allowlist_match(r->image_path))
        return false;
    bool validly_signed = (r->sign_state == SIGN_SIGNED ||
                           r->sign_state == SIGN_SIGNED_MS);
    if (validly_signed && !r->suspicious_mem && !is_lolbin_host(r))
        return false;
    return true;
}

static bool prot_is_exec(DWORD p)
{
    DWORD m = p & 0xFF;
    return m == PAGE_EXECUTE || m == PAGE_EXECUTE_READ ||
           m == PAGE_EXECUTE_READWRITE || m == PAGE_EXECUTE_WRITECOPY;
}
static bool prot_is_rwx(DWORD p)
{
    DWORD m = p & 0xFF;
    return m == PAGE_EXECUTE_READWRITE || m == PAGE_EXECUTE_WRITECOPY;
}

/* True if buf looks like a mapped PE: 'MZ', a sane e_lfanew, 'PE\0\0' there. */
static bool looks_like_pe(const unsigned char *buf, size_t n)
{
    if (n < 0x40 || buf[0] != 'M' || buf[1] != 'Z')
        return false;
    uint32_t e_lfanew;
    memcpy(&e_lfanew, buf + 0x3C, 4);
    if (e_lfanew < 0x40 || (size_t)e_lfanew + 4 > n)
        return false;
    return buf[e_lfanew] == 'P' && buf[e_lfanew + 1] == 'E' &&
           buf[e_lfanew + 2] == 0 && buf[e_lfanew + 3] == 0;
}

/* Read the on-disk PE's load-invariant fields. Returns false if not a PE. */
typedef struct { uint32_t entry; uint32_t size_of_image; uint16_t sections; } PeKey;
static bool ondisk_pekey(const char *path, PeKey *out)
{
    wchar_t wp[SC_MAX_PATH * 2];
    if (utf8_to_wide(path, wp, sizeof wp / sizeof wp[0]) == 0)
        return false;
    HANDLE h = CreateFileW(wp, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    unsigned char buf[0x400];
    DWORD rd = 0;
    bool ok = false;
    if (ReadFile(h, buf, sizeof buf, &rd, NULL) && rd >= 0x40 &&
        buf[0] == 'M' && buf[1] == 'Z') {
        uint32_t e; memcpy(&e, buf + 0x3C, 4);
        /* NT headers: Signature(4) + FileHeader(20) + OptionalHeader.
         * NumberOfSections @ FileHeader+2; AddressOfEntryPoint @ Opt+16;
         * SizeOfImage @ Opt+56 (same offset for PE32/PE32+). */
        if (e >= 0x40 && (size_t)e + 0x60 <= rd && buf[e] == 'P' && buf[e+1] == 'E') {
            memcpy(&out->sections, buf + e + 6, 2);
            memcpy(&out->entry,    buf + e + 24 + 16, 4);
            memcpy(&out->size_of_image, buf + e + 24 + 56, 4);
            ok = true;
        }
    }
    CloseHandle(h);
    return ok;
}

/* Read the same fields from the image mapped at base in the remote process. */
static bool inmem_pekey(HANDLE proc, BYTE *base, PeKey *out)
{
    unsigned char buf[0x400];
    SIZE_T got = 0;
    if (!ReadProcessMemory(proc, base, buf, sizeof buf, &got) || got < 0x40)
        return false;
    if (buf[0] != 'M' || buf[1] != 'Z')
        return false;
    uint32_t e; memcpy(&e, buf + 0x3C, 4);
    if (e < 0x40 || (size_t)e + 0x60 > got || buf[e] != 'P' || buf[e+1] != 'E')
        return false;
    memcpy(&out->sections, buf + e + 6, 2);
    memcpy(&out->entry,    buf + e + 24 + 16, 4);
    memcpy(&out->size_of_image, buf + e + 24 + 56, 4);
    return true;
}

/* Walk one process's address space. Returns number of findings emitted. */
static int scan_one(ScanCtx *c, ProcRec *r, ULONGLONG t0, int *budget)
{
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              FALSE, r->pid);
    if (!proc)
        return -1;   /* could not open -> caller notes the limitation */

    int emitted = 0;
    bool bad_owner = !(r->sign_state == SIGN_SIGNED || r->sign_state == SIGN_SIGNED_MS) ||
                     (r->image_path[0] && path_is_user_writable(r->image_path)) ||
                     (r->image_path[0] && name_is_masquerade(r->image_path));
    /* Raw RWX memory is ubiquitous in JIT runtimes (node, .NET, browsers,
     * game engines), so "RWX in an unsigned process" is NOT shellcode. Only
     * call raw RWX suspicious when the host is already highly suspect by
     * LOCATION or NAME -- a temp/recycle path or a masquerading image. */
    bool highly_suspicious = r->image_path[0] &&
        (path_classify(r->image_path) == PATHLOC_TEMP ||
         path_classify(r->image_path) == PATHLOC_RECYCLE ||
         name_is_masquerade(r->image_path));
    int rwx_count = 0, reflective_seen = 0;
    void *rwx_first = NULL;
    unsigned char rwx_bytes[6] = {0};

    char target[SC_MAX_PATH];
    snprintf(target, sizeof target, "%s", r->image_path[0] ? r->image_path : r->name);

    /* --- PROC.HOLLOWED: main image headers vs on-disk --- */
    if (r->image_path[0]) {
        HMODULE mods[1];
        DWORD need = 0;
        if (EnumProcessModules(proc, mods, sizeof mods, &need) && need >= sizeof(HMODULE)) {
            PeKey disk, mem;
            if (ondisk_pekey(r->image_path, &disk) &&
                inmem_pekey(proc, (BYTE *)mods[0], &mem)) {
                if (disk.entry != mem.entry || disk.sections != mem.sections ||
                    disk.size_of_image != mem.size_of_image) {
                    bus_emit(c->bus, "PROC.HOLLOWED", bad_owner ? SEV_CRIT : SEV_HIGH,
                             bad_owner ? 90 : 80, ACT_SUSPEND, r->pid, target,
                             "Process image in memory differs from the file on disk",
                             "%s (pid %lu) hollowed/replaced: disk(entry=0x%lx sects=%u "
                             "size=0x%lx) != mem(entry=0x%lx sects=%u size=0x%lx)",
                             r->name, (unsigned long)r->pid,
                             (unsigned long)disk.entry, disk.sections,
                             (unsigned long)disk.size_of_image,
                             (unsigned long)mem.entry, mem.sections,
                             (unsigned long)mem.size_of_image);
                    emitted++; (*budget)--;
                }
            }
        }
    }

    /* --- region walk: private executable memory --- */
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *addr = NULL;
    unsigned char sample[MS_READ_HDR];
    for (int i = 0; i < MS_MAX_REGIONS && *budget > 0; i++) {
        if ((i & 0x3F) == 0 && GetTickCount64() - t0 > MS_WALLCLOCK_MS)
            break;
        if (VirtualQueryEx(proc, addr, &mbi, sizeof mbi) != sizeof mbi)
            break;
        unsigned char *next = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;   /* overflow / no progress */
        addr = next;

        if (mbi.State != MEM_COMMIT || mbi.RegionSize < MS_MIN_REGION)
            continue;
        if (mbi.Type == MEM_IMAGE)          /* image-backed code is normal     */
            continue;
        if (!prot_is_exec(mbi.Protect))     /* only executable regions matter  */
            continue;

        SIZE_T got = 0;
        size_t want = mbi.RegionSize < MS_READ_HDR ? mbi.RegionSize : MS_READ_HDR;
        if (!ReadProcessMemory(proc, mbi.BaseAddress, sample, want, &got) || got < 64)
            continue;

        if (looks_like_pe(sample, got)) {
            /* A mapped PE in private memory is a strong signal; cap per-process
             * emissions but keep counting. */
            if (reflective_seen < 4) {
                bus_emit(c->bus, "MEM.REFLECTIVE_PE", bad_owner ? SEV_CRIT : SEV_HIGH,
                         bad_owner ? 90 : 85, ACT_SUSPEND, r->pid, target,
                         "Manually-mapped PE in private memory (reflective loading)",
                         "%s (pid %lu): PE image mapped in private %s memory at %p "
                         "(size 0x%llx) -- not backed by any file",
                         r->name, (unsigned long)r->pid,
                         prot_is_rwx(mbi.Protect) ? "RWX" : "exec",
                         mbi.BaseAddress, (unsigned long long)mbi.RegionSize);
                emitted++; (*budget)--;
            }
            reflective_seen++;
        } else if (prot_is_rwx(mbi.Protect)) {
            if (rwx_count == 0) {
                rwx_first = mbi.BaseAddress;
                memcpy(rwx_bytes, sample, 6);
            }
            rwx_count++;
        }
    }

    /* MEM.SHELLCODE: one summarized finding per process, and only when the host
     * is highly suspicious by location/name (raw RWX alone is just JIT). */
    if (highly_suspicious && rwx_count > 0 && *budget > 0) {
        bus_emit(c->bus, "MEM.SHELLCODE", SEV_HIGH, 75, ACT_SUSPEND, r->pid, target,
                 "Private RWX executable memory in a suspicious process",
                 "%s (pid %lu): %d private RWX region(s); first at %p bytes "
                 "%02x %02x %02x %02x %02x %02x",
                 r->name, (unsigned long)r->pid, rwx_count, rwx_first,
                 rwx_bytes[0], rwx_bytes[1], rwx_bytes[2],
                 rwx_bytes[3], rwx_bytes[4], rwx_bytes[5]);
        emitted++; (*budget)--;
    }

    CloseHandle(proc);
    return emitted;
}

void scan_memscan(ScanCtx *c)
{
    if (!c || !c->procs || !c->bus)
        return;

    ULONGLONG t0 = GetTickCount64();
    int budget = MS_MAX_FINDINGS;
    size_t denied = 0, scanned = 0;

    for (size_t i = 0; i < c->procs->count && budget > 0; i++) {
        if (GetTickCount64() - t0 > MS_WALLCLOCK_MS) {
            ctx_note_limit(c, "scan_memscan: time-capped after %u ms; "
                              "some processes not memory-scanned.", MS_WALLCLOCK_MS);
            break;
        }
        ProcRec *r = &c->procs->items[i];
        if (!worth_scanning(r))
            continue;
        scanned++;
        if (scan_one(c, r, t0, &budget) < 0)
            denied++;
    }

    if (denied)
        ctx_note_limit(c, "scan_memscan: could not open %zu process(es) for "
                          "memory inspection (run elevated for full coverage).",
                       denied);
    (void)scanned;
}
