/* pe.c - PE / image analysis for SentinelC.
 *
 * Maps a file read-only, parses DOS + NT headers with full bounds checking,
 * computes entropy (overall + per-section), walks the import directory, and
 * derives capability flags from imported function names.
 *
 * Every offset taken from the file is validated against the mapped size before
 * dereference: a malformed PE must never crash the scanner.
 */
#include "sentinelc.h"

#include <string.h>
#include <ctype.h>

/* ---- result cache (OPT 1) -------------------------------------------------
 * pe_analyze() is called ~10x redundantly per scan (once per process in
 * scan_process, again per process in scan_keylog) over a small set of unique
 * images. Memoize the (PeInfo, result) by (lowercased path, last-write-time,
 * file size) so a repeat call on an unchanged file skips the whole map+entropy
 * pass. The key is obtained cheaply via GetFileAttributesExW -- we never open
 * or map the file just to compute it.
 *
 * Thread-safety: pe_analyze runs on the main thread (scan_process) and the
 * thread pool (scan_keylog) concurrently. A single CRITICAL_SECTION, lazily
 * created exactly once via InitOnceExecuteOnce (mirrors sign.c), guards the
 * table. The lock is held ONLY around the lookup and the insert -- never during
 * the file mapping / entropy work -- so concurrent misses on different files
 * still run in parallel. PeInfo is copied out by value under the lock, so we
 * never hand back a pointer into the (fixed, non-realloc) array.
 */
#define PE_CACHE_CAP 4096

typedef struct {
    char    path[SC_MAX_PATH];   /* lowercased UTF-8 path */
    uint64_t mtime;              /* LastWriteTime FILETIME as u64 */
    uint64_t fsize;              /* file size in bytes */
    PeInfo  info;
    bool    result;             /* pe_analyze() return value */
    bool    used;
} PeCacheEntry;

static PeCacheEntry    *g_pe_cache = NULL;     /* fixed array, never realloc'd */
static size_t           g_pe_cache_count = 0;
static CRITICAL_SECTION g_pe_cache_lock;
static INIT_ONCE        g_pe_cache_once = INIT_ONCE_STATIC_INIT;
static bool             g_pe_cache_ready = false;
static volatile LONG64  g_pe_calls = 0;
static volatile LONG64  g_pe_hits = 0;
static volatile LONG64  g_pe_misses = 0;
static volatile LONG64  g_pe_stores = 0;

static uint64_t atomic_read64(volatile LONG64 *p)
{
    return (uint64_t)InterlockedCompareExchange64(p, 0, 0);
}

static BOOL CALLBACK pe_cache_init_once(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once; (void)param; (void)ctx;
    InitializeCriticalSection(&g_pe_cache_lock);
    /* One up-front allocation: a fixed array so entries never move (pointers
     * into it would otherwise dangle across a realloc). If it fails, caching is
     * simply disabled -- analysis still runs, just without memoization. */
    g_pe_cache       = (PeCacheEntry *)calloc(PE_CACHE_CAP, sizeof(PeCacheEntry));
    g_pe_cache_count = 0;
    g_pe_cache_ready = (g_pe_cache != NULL);
    return TRUE;
}

/* Build the cache key for `path` without opening the file. Returns false if the
 * attributes can't be read (caller then proceeds without caching). On success,
 * `lower_out` (cap SC_MAX_PATH) gets the lowercased path, and *mtime / *fsize
 * are filled. */
static bool pe_cache_key(const char *path, char *lower_out,
                         uint64_t *mtime, uint64_t *fsize)
{
    wchar_t wpath[SC_MAX_PATH * 2];
    if (utf8_to_wide(path, wpath, sizeof wpath / sizeof wpath[0]) == 0)
        return false;

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(wpath, GetFileExInfoStandard, &fad))
        return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return false;

    /* Lowercased copy of the path (bounded to SC_MAX_PATH). */
    size_t n = strlen(path);
    if (n >= SC_MAX_PATH) n = SC_MAX_PATH - 1;
    memcpy(lower_out, path, n);
    lower_out[n] = '\0';
    str_lower(lower_out);

    *mtime = ((uint64_t)fad.ftLastWriteTime.dwHighDateTime << 32) |
             (uint64_t)fad.ftLastWriteTime.dwLowDateTime;
    *fsize = ((uint64_t)fad.nFileSizeHigh << 32) | (uint64_t)fad.nFileSizeLow;
    return true;
}

/* Lookup under the lock. On hit, copies PeInfo by value into *out and the
 * cached return value into *result, then returns true. */
static bool pe_cache_get(const char *lpath, uint64_t mtime, uint64_t fsize,
                         PeInfo *out, bool *result)
{
    bool hit = false;
    if (!g_pe_cache_ready) return false;
    EnterCriticalSection(&g_pe_cache_lock);
    for (size_t i = 0; i < g_pe_cache_count; i++) {
        if (g_pe_cache[i].used &&
            g_pe_cache[i].mtime == mtime &&
            g_pe_cache[i].fsize == fsize &&
            strcmp(g_pe_cache[i].path, lpath) == 0) {
            *out    = g_pe_cache[i].info;     /* copy out by value */
            *result = g_pe_cache[i].result;
            hit = true;
            break;
        }
    }
    LeaveCriticalSection(&g_pe_cache_lock);
    return hit;
}

/* Insert under the lock. Caps at PE_CACHE_CAP entries; once full, new entries
 * are silently dropped (no eviction, no realloc thrash). */
static void pe_cache_put(const char *lpath, uint64_t mtime, uint64_t fsize,
                         const PeInfo *info, bool result)
{
    if (!g_pe_cache_ready) return;
    EnterCriticalSection(&g_pe_cache_lock);
    if (g_pe_cache_count < PE_CACHE_CAP) {
        PeCacheEntry *e = &g_pe_cache[g_pe_cache_count];
        /* lpath is already bounded to < SC_MAX_PATH by pe_cache_key. */
        strncpy(e->path, lpath, sizeof e->path - 1);
        e->path[sizeof e->path - 1] = '\0';
        e->mtime  = mtime;
        e->fsize  = fsize;
        e->info   = *info;
        e->result = result;
        e->used   = true;
        g_pe_cache_count++;
        InterlockedIncrement64(&g_pe_stores);
    }
    LeaveCriticalSection(&g_pe_cache_lock);
}

void pe_cache_stats(PeCacheStats *out)
{
    if (!out) return;
    memset(out, 0, sizeof *out);
    out->calls  = atomic_read64(&g_pe_calls);
    out->hits   = atomic_read64(&g_pe_hits);
    out->misses = atomic_read64(&g_pe_misses);
    out->stores = atomic_read64(&g_pe_stores);
    out->enabled = g_pe_cache_ready;

    if (g_pe_cache_ready) {
        EnterCriticalSection(&g_pe_cache_lock);
        out->entries = (uint64_t)g_pe_cache_count;
        LeaveCriticalSection(&g_pe_cache_lock);
    }
}

/* ---- local bounds helpers -------------------------------------------------
 * All take the mapped base + size and a candidate (offset, length). Return
 * true only when [off, off+len) lies fully inside [0, size).
 */
static bool range_ok(size_t size, size_t off, size_t len)
{
    if (off > size) return false;
    if (len > size - off) return false;
    return true;
}

/* Read a NUL-terminated ASCII string starting at file offset `off`, copying at
 * most cap-1 bytes into out. Returns false if off is out of range or no NUL is
 * found before the end of the mapping. */
static bool read_cstr(const unsigned char *base, size_t size, size_t off,
                      char *out, size_t cap)
{
    if (off >= size || cap == 0) return false;
    size_t i = 0;
    for (; off + i < size && i < cap - 1; i++) {
        char c = (char)base[off + i];
        if (c == '\0') { out[i] = '\0'; return true; }
        out[i] = c;
    }
    /* No terminator within cap or within mapping. */
    out[cap - 1] = '\0';
    /* Accept truncated names (still useful for matching) only if we hit cap,
     * not the end of the file mid-string. */
    return (off + i < size);
}

/* RVA -> file offset using the section table. Returns false if the RVA does not
 * fall inside any section's raw data. */
static bool rva_to_off(const IMAGE_SECTION_HEADER *sects, unsigned nsect,
                       size_t size, DWORD rva, size_t *out_off)
{
    for (unsigned i = 0; i < nsect; i++) {
        DWORD va   = sects[i].VirtualAddress;
        DWORD vsz  = sects[i].Misc.VirtualSize;
        DWORD rawsz = sects[i].SizeOfRawData;
        DWORD span = (vsz > rawsz) ? vsz : rawsz;
        if (span == 0) span = rawsz;
        /* Compare the span end in 64-bit space: va + span can overflow DWORD
         * for a crafted section, which would wrap and admit out-of-range RVAs. */
        if (rva >= va && (uint64_t)rva < (uint64_t)va + span) {
            DWORD delta = rva - va;
            if (delta >= rawsz) return false;            /* in uninit tail */
            /* PointerToRawData + delta in 64-bit, then bound to the mapping. */
            uint64_t off = (uint64_t)sects[i].PointerToRawData + delta;
            if (off >= (uint64_t)size) return false;
            *out_off = (size_t)off;
            return true;
        }
    }
    return false;
}

/* Case-insensitive equality of an imported function name against a literal. */
static bool ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return false;
    }
    return *a == *b;
}

/* Does `name` start with `prefix` (case-insensitive)? Used for A/W pairs. */
static bool istartswith(const char *name, const char *prefix)
{
    for (; *prefix; name++, prefix++) {
        if (*name == '\0') return false;
        if (tolower((unsigned char)*name) != tolower((unsigned char)*prefix))
            return false;
    }
    return true;
}

/* Match an imported function name against the capability tables and set flags. */
static void classify_import(const char *fn, PeInfo *out)
{
    /* Hooking */
    if (istartswith(fn, "SetWindowsHookEx") || ieq(fn, "SetWinEventHook") ||
        ieq(fn, "CallNextHookEx"))
        out->imp_hook_api = true;

    /* Keystate sampling */
    if (ieq(fn, "GetAsyncKeyState") || ieq(fn, "GetKeyState") ||
        ieq(fn, "GetKeyboardState"))
        out->imp_keystate_api = true;

    /* Raw input */
    if (ieq(fn, "RegisterRawInputDevices") || ieq(fn, "GetRawInputData"))
        out->imp_rawinput_api = true;

    /* Clipboard/input theft. Clipboard polling/listening plus egress is a
     * common infostealer shape and is part of MITRE ATT&CK Input Capture. */
    if (ieq(fn, "OpenClipboard") || ieq(fn, "GetClipboardData") ||
        ieq(fn, "EnumClipboardFormats") ||
        ieq(fn, "GetPriorityClipboardFormat") ||
        ieq(fn, "IsClipboardFormatAvailable") ||
        ieq(fn, "AddClipboardFormatListener") ||
        ieq(fn, "RemoveClipboardFormatListener") ||
        ieq(fn, "SetClipboardViewer") || ieq(fn, "ChangeClipboardChain") ||
        istartswith(fn, "RegisterClipboardFormat"))
        out->imp_clipboard_api = true;

    /* Screen capture. Avoid ultra-broad GetDC-only signals; these APIs are
     * stronger indicators of screenshot/desktop capture capability. */
    if (ieq(fn, "BitBlt") || ieq(fn, "StretchBlt") ||
        ieq(fn, "PrintWindow") || ieq(fn, "CreateCompatibleBitmap") ||
        ieq(fn, "CreateDIBSection") || ieq(fn, "GetWindowDC") ||
        ieq(fn, "GetDesktopWindow"))
        out->imp_screen_api = true;

    /* Microphone/camera capture capability. */
    if (istartswith(fn, "waveIn") || istartswith(fn, "capCreateCaptureWindow") ||
        ieq(fn, "MFEnumDeviceSources") || ieq(fn, "MFCreateDeviceSource") ||
        ieq(fn, "MFCreateSourceReaderFromMediaSource"))
        out->imp_media_capture_api = true;

    /* Secret-read APIs used by credential grabbers. CryptUnprotectData is
     * broad by itself, so downstream rules require other risk signals too. */
    if (istartswith(fn, "CredRead") || istartswith(fn, "CredEnumerate") ||
        ieq(fn, "CryptUnprotectData") || ieq(fn, "VaultEnumerateVaults") ||
        ieq(fn, "VaultOpenVault") || ieq(fn, "VaultGetItem") ||
        ieq(fn, "PStoreCreateInstance"))
        out->imp_cred_api = true;

    /* Networking (function-name signal; DLL-name signal handled separately) */
    if (ieq(fn, "connect") || ieq(fn, "send") || ieq(fn, "WSASocketW") ||
        ieq(fn, "WSASocketA") || ieq(fn, "WSAConnect") ||
        ieq(fn, "InternetOpenA") || ieq(fn, "InternetOpenW") ||
        ieq(fn, "InternetConnectA") || ieq(fn, "InternetConnectW") ||
        ieq(fn, "HttpOpenRequestA") || ieq(fn, "HttpOpenRequestW") ||
        ieq(fn, "WinHttpOpen") || ieq(fn, "WinHttpConnect") ||
        ieq(fn, "WinHttpSendRequest"))
        out->imp_net_api = true;

    /* Process injection */
    if (ieq(fn, "WriteProcessMemory") || ieq(fn, "CreateRemoteThread") ||
        ieq(fn, "CreateRemoteThreadEx") || ieq(fn, "VirtualAllocEx") ||
        ieq(fn, "QueueUserAPC") || ieq(fn, "NtMapViewOfSection") ||
        ieq(fn, "ZwMapViewOfSection"))
        out->imp_proc_inject_api = true;

    /* Crypto */
    if (ieq(fn, "CryptEncrypt") || ieq(fn, "BCryptEncrypt") ||
        ieq(fn, "CryptAcquireContextA") || ieq(fn, "CryptAcquireContextW") ||
        ieq(fn, "CryptAcquireContext"))
        out->imp_crypt_api = true;
}

/* DLL-name level networking signal: ws2_32 / wininet / winhttp. */
static bool dll_is_net(const char *dll)
{
    return str_icontains(dll, "ws2_32") || str_icontains(dll, "wsock32") ||
           str_icontains(dll, "wininet") || str_icontains(dll, "winhttp");
}

/* Packer / known-section signatures. Sets packer_hint and returns true if a
 * packer section name was recognized. */
static bool section_is_packer(const char *sname, PeInfo *out)
{
    /* Names are at most 8 bytes, possibly not NUL-terminated; caller passes a
     * NUL-terminated copy. */
    if (strncmp(sname, "UPX", 3) == 0) {
        if (out->packer_hint[0] == '\0')
            strncpy(out->packer_hint, "UPX", sizeof out->packer_hint - 1);
        return true;
    }
    if (str_icontains(sname, "aspack")) {
        if (out->packer_hint[0] == '\0')
            strncpy(out->packer_hint, "ASPack", sizeof out->packer_hint - 1);
        return true;
    }
    if (str_icontains(sname, "themida") || str_icontains(sname, ".vmp")) {
        if (out->packer_hint[0] == '\0')
            strncpy(out->packer_hint, "Themida/VMProtect",
                    sizeof out->packer_hint - 1);
        return true;
    }
    if (str_icontains(sname, "petite") || str_icontains(sname, "nsp") ||
        str_icontains(sname, "mpress")) {
        if (out->packer_hint[0] == '\0')
            strncpy(out->packer_hint, "Packer", sizeof out->packer_hint - 1);
        return true;
    }
    return false;
}

/* Walk the import directory. base/size = mapping. sects/nsect = section table.
 * import_dir = the IMAGE_DATA_DIRECTORY for imports. is64 selects thunk width.
 * Defensive throughout: any malformed offset stops the walk cleanly. */
static void walk_imports(const unsigned char *base, size_t size,
                         const IMAGE_SECTION_HEADER *sects, unsigned nsect,
                         IMAGE_DATA_DIRECTORY import_dir, bool is64,
                         PeInfo *out)
{
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
        return;

    size_t desc_off;
    if (!rva_to_off(sects, nsect, size, import_dir.VirtualAddress, &desc_off))
        return;

    const size_t DESC_SZ = sizeof(IMAGE_IMPORT_DESCRIPTOR);
    /* Cap descriptor iterations defensively. */
    for (unsigned d = 0; d < 4096; d++) {
        size_t this_off = desc_off + (size_t)d * DESC_SZ;
        if (!range_ok(size, this_off, DESC_SZ)) break;

        IMAGE_IMPORT_DESCRIPTOR desc;
        memcpy(&desc, base + this_off, DESC_SZ);

        /* Terminator: all-zero descriptor. */
        if (desc.Name == 0 && desc.FirstThunk == 0 &&
            desc.OriginalFirstThunk == 0)
            break;

        /* DLL name */
        char dll[64] = {0};
        bool dll_net = false;
        size_t name_off;
        if (desc.Name != 0 &&
            rva_to_off(sects, nsect, size, desc.Name, &name_off)) {
            if (read_cstr(base, size, name_off, dll, sizeof dll))
                dll_net = dll_is_net(dll);
        }
        if (dll_net) out->imp_net_api = true;

        /* Thunk array: prefer OriginalFirstThunk (INT), fall back to IAT. */
        DWORD thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk
                                                  : desc.FirstThunk;
        if (thunk_rva == 0) continue;

        size_t thunk_off;
        if (!rva_to_off(sects, nsect, size, thunk_rva, &thunk_off))
            continue;

        const size_t TW = is64 ? 8u : 4u;
        const uint64_t ORD_FLAG = is64 ? 0x8000000000000000ULL
                                       : 0x80000000ULL;

        for (unsigned t = 0; t < 65535; t++) {
            size_t toff = thunk_off + (size_t)t * TW;
            if (!range_ok(size, toff, TW)) break;

            uint64_t val = 0;
            if (is64) {
                memcpy(&val, base + toff, 8);
            } else {
                uint32_t v32 = 0;
                memcpy(&v32, base + toff, 4);
                val = v32;
            }
            if (val == 0) break;                 /* end of this DLL's thunks */

            out->import_count++;

            if (val & ORD_FLAG)
                continue;                        /* import by ordinal, no name */

            /* val is an RVA to IMAGE_IMPORT_BY_NAME: WORD Hint; char Name[]. */
            DWORD ibn_rva = (DWORD)(val & 0x7FFFFFFFULL);
            size_t ibn_off;
            if (!rva_to_off(sects, nsect, size, ibn_rva, &ibn_off))
                continue;
            if (!range_ok(size, ibn_off, sizeof(WORD)))
                continue;

            char fn[128];
            if (read_cstr(base, size, ibn_off + sizeof(WORD), fn, sizeof fn))
                classify_import(fn, out);
        }
    }
}

bool pe_analyze(const char *path, PeInfo *out)
{
    if (!out) return false;
    memset(out, 0, sizeof *out);
    if (!path || path[0] == '\0') return false;
    InterlockedIncrement64(&g_pe_calls);

    bool result = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMap  = NULL;
    const unsigned char *base = NULL;
    LARGE_INTEGER li = {0};

    /* ---- OPT 1: result cache lookup ---- */
    InitOnceExecuteOnce(&g_pe_cache_once, pe_cache_init_once, NULL, NULL);
    char     ckey[SC_MAX_PATH];
    uint64_t cmtime = 0, csize = 0;
    bool     have_key = pe_cache_key(path, ckey, &cmtime, &csize);
    if (have_key) {
        PeInfo cached;
        bool   cached_result;
        if (pe_cache_get(ckey, cmtime, csize, &cached, &cached_result)) {
            *out = cached;            /* copy by value, no dangling pointer */
            InterlockedIncrement64(&g_pe_hits);
            return cached_result;
        }
    }
    InterlockedIncrement64(&g_pe_misses);

    wchar_t wpath[SC_MAX_PATH * 2];
    if (utf8_to_wide(path, wpath, sizeof wpath / sizeof wpath[0]) == 0)
        return false;

    hFile = CreateFileW(wpath, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    if (!GetFileSizeEx(hFile, &li) || li.QuadPart <= 0) {
        CloseHandle(hFile);
        return false;
    }
    /* Sanity cap: refuse to map absurdly large files (> 512 MiB). */
    if (li.QuadPart > (LONGLONG)512 * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }
    size_t size = (size_t)li.QuadPart;

    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return false;
    }
    base = (const unsigned char *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    /* OPT 2: do NOT scan the whole file for entropy here. For a valid PE,
     * overall_entropy is unused by any rule (looks_packed derives from the
     * per-section entropy + import/packer heuristics computed below), so the
     * whole-file pass is pure waste. For NON-PE inputs scan_path.c still reads
     * overall_entropy (FILE.HIGH_ENTROPY: !is_pe && overall_entropy > 7.2), so
     * we compute it lazily at the `not_pe` exit -- only when is_pe is false. */

    /* ---- DOS header ---- */
    if (!range_ok(size, 0, sizeof(IMAGE_DOS_HEADER)))
        goto done;
    IMAGE_DOS_HEADER dos;
    memcpy(&dos, base, sizeof dos);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)            /* 'MZ' */
        goto done;

    LONG elf = dos.e_lfanew;
    if (elf < 0 || (size_t)elf > size)
        goto done;

    /* ---- NT signature + file header ---- */
    if (!range_ok(size, (size_t)elf, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)))
        goto done;
    DWORD ntsig;
    memcpy(&ntsig, base + elf, sizeof ntsig);
    if (ntsig != IMAGE_NT_SIGNATURE)                   /* 'PE\0\0' */
        goto done;

    size_t fh_off = (size_t)elf + sizeof(DWORD);
    IMAGE_FILE_HEADER fh;
    memcpy(&fh, base + fh_off, sizeof fh);

    out->is_pe  = true;
    out->is_dll = (fh.Characteristics & IMAGE_FILE_DLL) != 0;
    result = true;   /* it IS a valid PE from here on */

    size_t opt_off = fh_off + sizeof(IMAGE_FILE_HEADER);
    WORD opt_size  = fh.SizeOfOptionalHeader;

    /* Need at least the magic word to determine bitness. */
    if (!range_ok(size, opt_off, sizeof(WORD)) || opt_size < sizeof(WORD))
        goto sections_unknown;

    WORD magic;
    memcpy(&magic, base + opt_off, sizeof magic);

    IMAGE_DATA_DIRECTORY import_dir = {0, 0};
    bool have_import_dir = false;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        out->is_64bit = true;
        if (range_ok(size, opt_off, sizeof(IMAGE_OPTIONAL_HEADER64)) &&
            opt_size >= sizeof(IMAGE_OPTIONAL_HEADER64)) {
            IMAGE_OPTIONAL_HEADER64 oh;
            memcpy(&oh, base + opt_off, sizeof oh);
            if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                import_dir = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                have_import_dir = true;
            }
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        out->is_64bit = false;
        if (range_ok(size, opt_off, sizeof(IMAGE_OPTIONAL_HEADER32)) &&
            opt_size >= sizeof(IMAGE_OPTIONAL_HEADER32)) {
            IMAGE_OPTIONAL_HEADER32 oh;
            memcpy(&oh, base + opt_off, sizeof oh);
            if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
                import_dir = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                have_import_dir = true;
            }
        }
    }

    /* ---- Section table ---- */
    size_t sect_off = opt_off + opt_size;
    unsigned nsect = fh.NumberOfSections;
    if (nsect == 0 || nsect > 96)        /* PE spec caps sections at 96 */
        goto done;
    if (!range_ok(size, sect_off,
                  (size_t)nsect * sizeof(IMAGE_SECTION_HEADER)))
        goto done;

    const IMAGE_SECTION_HEADER *sects =
        (const IMAGE_SECTION_HEADER *)(base + sect_off);

    double max_ent = 0.0;
    for (unsigned i = 0; i < nsect; i++) {
        /* NUL-terminated copy of the 8-byte section name. */
        char sname[9];
        memcpy(sname, sects[i].Name, 8);
        sname[8] = '\0';
        section_is_packer(sname, out);

        DWORD raw = sects[i].PointerToRawData;
        DWORD rsz = sects[i].SizeOfRawData;
        if (rsz == 0) continue;
        if (!range_ok(size, raw, rsz)) continue;   /* skip malformed section */

        double e = shannon_entropy(base + raw, rsz);
        if (e > max_ent) max_ent = e;
    }
    out->max_section_entropy = max_ent;
    /* OPT 2: for a PE, overall_entropy is section-derived (no rule reads it for
     * PE images). Use the highest section entropy as a cheap stand-in. */
    out->overall_entropy = max_ent;

    /* ---- Imports ---- */
    if (have_import_dir)
        walk_imports(base, size, sects, nsect, import_dir, out->is_64bit, out);

    /* ---- Packing heuristic ---- */
    if (out->max_section_entropy > 7.0 ||
        out->import_count < 5 ||
        out->packer_hint[0] != '\0')
        out->looks_packed = true;

    goto done;

sections_unknown:
    /* Valid PE but optional header too small to trust; leave defaults. */
    if (out->max_section_entropy == 0.0 && out->import_count == 0)
        out->looks_packed = (out->packer_hint[0] != '\0');

done:
    /* OPT 2: non-PE inputs still need a whole-file overall_entropy, since
     * scan_path.c's FILE.HIGH_ENTROPY rule reads it for !is_pe files. We skip
     * this scan only for valid PEs (where overall_entropy was set from section
     * data above and no rule consults it). */
    if (!out->is_pe && base)
        out->overall_entropy = shannon_entropy(base, size);

    if (base) UnmapViewOfFile(base);
    if (hMap) CloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    /* ---- OPT 1: store the result before returning. ---- */
    if (have_key)
        pe_cache_put(ckey, cmtime, csize, out, result);

    return result;
}
