/* scan_service.c - Windows service triage.
 *
 * Enumerates every service & driver (all types, all states) via
 * EnumServicesStatusEx with a grow-the-buffer loop, then for each:
 *   - QueryServiceConfig  -> binary path (dequoted, args stripped), start type,
 *                            lpServiceStartName (account)
 *   - QueryServiceStatusEx -> running pid, cross-referenced into ctx->procs
 *   - signature + path classification of the resolved binary
 *   - for svchost services, the ServiceDll under HKLM\...\Parameters
 *
 * Findings: SVC.USERWRITABLE_PATH, SVC.UNSIGNED, SVC.UNQUOTED_PATH,
 *           SVC.SUSPICIOUS_DLL. Recommended action ACT_DISABLE_SVC,
 *           target = service name.
 */
#include "sentinelc.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* helpers                                                             */
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

/* True if a (resolved) path is a Microsoft inbox location -- System32,
 * WinSxS, or Program Files. Used to suppress UNSIGNED noise on inbox bins
 * that are catalog-signed (sign_verify may still resolve them, but be lenient
 * for inbox paths). */
static bool is_inbox_path(const char *path)
{
    if (!path || !path[0])
        return false;
    PathLoc loc = path_classify(path);
    return loc == PATHLOC_SYSTEM ||
           loc == PATHLOC_WINDOWS ||
           loc == PATHLOC_PROGRAMFILES;
}

/* Expand %VAR% references in a path. Falls back to a copy on failure. */
static void expand_env(const char *in, char *out, size_t cap)
{
    out[0] = '\0';
    if (!in)
        return;

    wchar_t win[SC_MAX_PATH * 2];
    if (utf8_to_wide(in, win, sizeof(win) / sizeof(win[0])) == 0) {
        copy_bounded(out, cap, in);
        return;
    }
    wchar_t wout[SC_MAX_PATH * 2];
    DWORD n = ExpandEnvironmentStringsW(win, wout, (DWORD)(sizeof(wout) / sizeof(wout[0])));
    if (n == 0 || n > sizeof(wout) / sizeof(wout[0])) {
        copy_bounded(out, cap, in);
        return;
    }
    if (wide_to_utf8(wout, out, cap) == 0)
        copy_bounded(out, cap, in);
}

/* From a raw service ImagePath, extract the executable image:
 *   - if it starts with a quote, the image is the quoted span
 *   - otherwise the image is up to the first space that yields an existing
 *     file, falling back to the first whitespace-delimited token
 * Writes the dequoted/stripped image to out. Also reports (via had_quote /
 * had_space) the facts the unquoted-path heuristic needs about the RAW path. */
static void extract_image(const char *raw, char *out, size_t cap,
                          bool *had_quote, bool *had_space_unquoted)
{
    out[0] = '\0';
    if (had_quote)          *had_quote = false;
    if (had_space_unquoted) *had_space_unquoted = false;
    if (!raw)
        return;

    /* skip leading whitespace */
    const char *p = raw;
    while (*p == ' ' || *p == '\t')
        p++;

    if (*p == '"') {
        if (had_quote)
            *had_quote = true;
        p++;
        const char *end = strchr(p, '"');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len >= cap)
            len = cap - 1;
        memcpy(out, p, len);
        out[len] = '\0';
        return;
    }

    /* Unquoted. Determine whether the path (before any arguments) contains a
     * space -- the classic unquoted-service-path condition. We pick the image
     * as the longest leading prefix ending in ".exe"/".sys", else first token. */
    bool has_space_in_path = false;
    size_t best = 0;     /* length of chosen image */
    size_t i = 0;
    for (; p[i]; i++) {
        char ch = p[i];
        if (ch == '.' &&
            (_strnicmp(p + i, ".exe", 4) == 0 || _strnicmp(p + i, ".sys", 4) == 0)) {
            best = i + 4;
            /* note whether a space appeared before this extension */
            for (size_t j = 0; j < best; j++)
                if (p[j] == ' ')
                    has_space_in_path = true;
            break;
        }
    }

    if (best == 0) {
        /* no recognizable extension: take the first whitespace-delimited token */
        while (p[best] && p[best] != ' ' && p[best] != '\t')
            best++;
        /* a space later means the (multi-token) path was unquoted with spaces */
        for (size_t j = 0; p[j]; j++) {
            if (p[j] == ' ' || p[j] == '\t') {
                has_space_in_path = (p[j + 1] != '\0');
                break;
            }
        }
    }

    if (had_space_unquoted)
        *had_space_unquoted = has_space_in_path;

    if (best >= cap)
        best = cap - 1;
    memcpy(out, p, best);
    out[best] = '\0';
}

/* Normalize a service/driver binary path to a real Win32 path so sign_verify
 * and path_classify can actually open the file.
 *
 * Handles the NT-style and relative forms the SCM hands back for drivers:
 *   \SystemRoot\System32\drivers\foo.sys   -> C:\Windows\System32\drivers\foo.sys
 *   \??\C:\Windows\...                      -> C:\Windows\...
 *   \\?\C:\Windows\...                      -> C:\Windows\...
 *   System32\DRIVERS\foo.sys  (relative)    -> C:\Windows\System32\DRIVERS\foo.sys
 *   bare relative containing drivers\/System32 -> resolved under %WINDIR%
 * Case-insensitive throughout. Leaves already-absolute X:\ and UNC paths alone.
 * On any failure, copies the input through unchanged. */
static void normalize_service_path(const char *in, char *out, size_t cap)
{
    out[0] = '\0';
    if (!in || !in[0] || cap == 0)
        return;

    /* Resolve %WINDIR% once (UTF-8). */
    char windir[SC_MAX_PATH];
    windir[0] = '\0';
    {
        wchar_t wwin[SC_MAX_PATH];
        UINT n = GetWindowsDirectoryW(wwin, (UINT)(sizeof(wwin) / sizeof(wwin[0])));
        if (n > 0 && n < sizeof(wwin) / sizeof(wwin[0]))
            wide_to_utf8(wwin, windir, sizeof(windir));
    }
    /* strip any trailing backslash on windir for clean joins */
    {
        size_t wl = strlen(windir);
        while (wl > 0 && (windir[wl - 1] == '\\' || windir[wl - 1] == '/'))
            windir[--wl] = '\0';
    }

    const char *p = in;

    /* "\??\" or "\\?\" prefixes: strip them, remainder is a normal path. */
    if (_strnicmp(p, "\\??\\", 4) == 0) {
        p += 4;
        copy_bounded(out, cap, p);
        return;
    }
    if (_strnicmp(p, "\\\\?\\", 4) == 0) {
        p += 4;
        copy_bounded(out, cap, p);
        return;
    }

    /* "\SystemRoot\..." -> windir + "\" + remainder */
    if (_strnicmp(p, "\\SystemRoot\\", 12) == 0) {
        if (windir[0]) {
            const char *rest = p + 12; /* after "\SystemRoot\" */
            _snprintf(out, cap, "%s\\%s", windir, rest);
            out[cap - 1] = '\0';
        } else {
            copy_bounded(out, cap, p);
        }
        return;
    }

    /* "SystemRoot\..." (no leading backslash) -> windir + "\" + remainder */
    if (_strnicmp(p, "SystemRoot\\", 11) == 0) {
        if (windir[0]) {
            const char *rest = p + 11;
            _snprintf(out, cap, "%s\\%s", windir, rest);
            out[cap - 1] = '\0';
        } else {
            copy_bounded(out, cap, p);
        }
        return;
    }

    /* Already absolute drive path ("X:\..." or "X:/...") -> leave as-is. */
    if (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) &&
        p[1] == ':' && (p[2] == '\\' || p[2] == '/')) {
        copy_bounded(out, cap, p);
        return;
    }

    /* UNC path "\\server\..." -> leave as-is (but not the \??\ / \\?\ handled above). */
    if (p[0] == '\\' && p[1] == '\\') {
        copy_bounded(out, cap, p);
        return;
    }

    /* "System32\..." (no leading backslash, no drive) -> under %WINDIR% */
    if (_strnicmp(p, "System32\\", 9) == 0) {
        if (windir[0]) {
            _snprintf(out, cap, "%s\\%s", windir, p);
            out[cap - 1] = '\0';
        } else {
            copy_bounded(out, cap, p);
        }
        return;
    }

    /* Leading single backslash, e.g. "\System32\..." or "\Windows\..." :
     * treat as relative to the drive of %WINDIR%. */
    if (p[0] == '\\') {
        if (windir[0] && windir[1] == ':') {
            /* windir like "C:\Windows" -> take "C:" drive prefix */
            _snprintf(out, cap, "%c:%s", windir[0], p);
            out[cap - 1] = '\0';
        } else {
            copy_bounded(out, cap, p);
        }
        return;
    }

    /* Bare relative path with no drive: drivers are System-relative. If it
     * references drivers\ or System32 anywhere, resolve under %WINDIR%. */
    if (windir[0] &&
        (str_icontains(p, "drivers\\") || str_icontains(p, "system32"))) {
        _snprintf(out, cap, "%s\\%s", windir, p);
        out[cap - 1] = '\0';
        return;
    }

    /* Otherwise leave as-is. */
    copy_bounded(out, cap, p);
}

/* Read HKLM\System\CurrentControlSet\Services\<svc>\Parameters\ServiceDll,
 * expand env vars, into out. Returns true if present. */
static bool read_service_dll(const char *svc_name, char *out, size_t cap)
{
    out[0] = '\0';
    if (!svc_name || !svc_name[0])
        return false;

    wchar_t wkey[512];
    _snwprintf(wkey, sizeof(wkey) / sizeof(wkey[0]),
               L"System\\CurrentControlSet\\Services\\%hs\\Parameters",
               svc_name);
    wkey[(sizeof(wkey) / sizeof(wkey[0])) - 1] = L'\0';

    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wkey, 0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS)
        return false;

    wchar_t wval[SC_MAX_PATH];
    DWORD type = 0;
    DWORD sz = sizeof(wval);
    LONG rc = RegQueryValueExW(hk, L"ServiceDll", NULL, &type,
                               (LPBYTE)wval, &sz);
    RegCloseKey(hk);

    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
        return false;

    /* ensure NUL termination within bounds */
    wval[(sizeof(wval) / sizeof(wval[0])) - 1] = L'\0';

    char raw[SC_MAX_PATH];
    if (wide_to_utf8(wval, raw, sizeof(raw)) == 0)
        return false;
    expand_env(raw, out, cap);
    return out[0] != '\0';
}

static const char *start_type_name(DWORD st)
{
    switch (st) {
    case SERVICE_BOOT_START:   return "boot";
    case SERVICE_SYSTEM_START: return "system";
    case SERVICE_AUTO_START:   return "auto";
    case SERVICE_DEMAND_START: return "demand";
    case SERVICE_DISABLED:     return "disabled";
    default:                   return "?";
    }
}

/* ------------------------------------------------------------------ */
/* per-service inspection                                              */
/* ------------------------------------------------------------------ */

static void inspect_service(ScanCtx *c, SC_HANDLE scm, const char *name,
                            const char *display)
{
    SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!svc) {
        /* Some services deny config read without admin; note once via caller. */
        return;
    }

    /* ---- QueryServiceConfig (grow buffer) ---- */
    DWORD need = 0;
    QueryServiceConfigA(svc, NULL, 0, &need);
    if (need == 0) {
        CloseServiceHandle(svc);
        return;
    }
    QUERY_SERVICE_CONFIGA *cfg = (QUERY_SERVICE_CONFIGA *)malloc(need);
    if (!cfg) {
        CloseServiceHandle(svc);
        return;
    }
    DWORD got = 0;
    if (!QueryServiceConfigA(svc, cfg, need, &got)) {
        free(cfg);
        CloseServiceHandle(svc);
        return;
    }

    const char *raw_path = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "";
    const char *account  = cfg->lpServiceStartName ? cfg->lpServiceStartName : "";
    DWORD start_type     = cfg->dwStartType;
    DWORD svc_type       = cfg->dwServiceType;

    /* ---- extract + resolve the binary image ---- */
    bool had_quote = false, unquoted_space = false;
    char image_raw[SC_MAX_PATH];
    extract_image(raw_path, image_raw, sizeof(image_raw), &had_quote, &unquoted_space);

    /* expand %ENV% first, then normalize NT-style / relative paths to a real
     * Win32 path so sign_verify / path_classify can open the file. */
    char binary_expanded[SC_MAX_PATH];
    expand_env(image_raw, binary_expanded, sizeof(binary_expanded));

    char binary[SC_MAX_PATH];
    normalize_service_path(binary_expanded, binary, sizeof(binary));

    /* Does the resolved binary actually exist on disk? */
    bool binary_exists = false;
    if (binary[0]) {
        wchar_t wbin[SC_MAX_PATH];
        if (utf8_to_wide(binary, wbin, sizeof(wbin) / sizeof(wbin[0])) != 0)
            binary_exists = (GetFileAttributesW(wbin) != INVALID_FILE_ATTRIBUTES);
    }

    /* ---- running pid cross-ref ---- */
    DWORD pid = 0;
    SERVICE_STATUS_PROCESS ssp;
    DWORD sneed = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                             sizeof(ssp), &sneed)) {
        pid = ssp.dwProcessId;
    }
    /* NOTE: we deliberately do NOT back-fill the shared ProcRec's image_path
     * here. scan_service runs concurrently with the other scanners (network,
     * rootkit, persist) on the thread pool, and the proc cache is a
     * single-writer/read-only structure once scan_process has filled it
     * (see proc_cache.c). Writing pr->image_path now would be a data race:
     * another scanner may be reading that same buffer concurrently, yielding
     * a torn read. The local `binary` is sufficient for every check below.
     * pid is still used below as the finding target. */

    /* ---- signature + classification of resolved binary ---- */
    /* Only verify the signature of a file that actually exists. If we could not
     * resolve the path to a real file, we must not claim it is unsigned. */
    SignVerdict sv = SIGN_UNKNOWN;
    if (binary[0] && binary_exists)
        sv = sign_verify(binary, NULL, 0);
    bool unsigned_bad = (sv == SIGN_UNSIGNED || sv == SIGN_INVALID);

    char target[SC_MAX_PATH];
    copy_bounded(target, sizeof(target), name);

    const char *disp = (display && display[0]) ? display : name;

    bool skip = false;
    if (binary[0] && allowlist_match(binary))
        skip = true;
    if (!skip && allowlist_match(name))
        skip = true;

    /* If we extracted an image but couldn't resolve it to an existing file,
     * note the limitation once rather than flagging it as unsigned. */
    if (binary[0] && !binary_exists) {
        static bool noted_unresolved = false;
        if (!noted_unresolved) {
            noted_unresolved = true;
            ctx_note_limit(c,
                "scan_service: one or more service binaries could not be "
                "resolved to an existing file (e.g. '%s'); signature checks "
                "skipped for those.",
                binary);
        }
    }

    if (!skip) {
        /* SVC.USERWRITABLE_PATH -- binary in a user-writable location.
         * Microsoft signs Defender et al. out of a versioned %ProgramData%
         * path, which is technically user-writable; a valid MS signature
         * exonerates it. A valid third-party signature downgrades to MED;
         * only unsigned/invalid binaries in a writable path are HIGH. */
        if (binary[0] && path_is_user_writable(binary) && sv != SIGN_SIGNED_MS) {
            Severity uw_sev = (sv == SIGN_SIGNED) ? SEV_MED : SEV_HIGH;
            int      uw_conf = (sv == SIGN_SIGNED) ? 50 : 85;
            bus_emit(c->bus, "SVC.USERWRITABLE_PATH", uw_sev, uw_conf,
                     ACT_DISABLE_SVC, pid, target,
                     "Service binary in a user-writable path",
                     "service '%s' (%s) runs %s from a user-writable path "
                     "[start=%s account=%s sign=%s]",
                     name, disp, binary, start_type_name(start_type),
                     account[0] ? account : "?", sign_name(sv));
        }

        /* SVC.UNSIGNED -- unsigned/invalid and not a Microsoft inbox path.
         * Only fires for a binary we actually resolved to an existing file. */
        if (unsigned_bad && binary[0] && binary_exists && !is_inbox_path(binary)) {
            int conf = 60;
            if (start_type == SERVICE_AUTO_START ||
                start_type == SERVICE_BOOT_START ||
                start_type == SERVICE_SYSTEM_START)
                conf += 10;
            bus_emit(c->bus, "SVC.UNSIGNED", SEV_MED, conf,
                     ACT_DISABLE_SVC, pid, target,
                     "Unsigned service binary",
                     "service '%s' (%s) binary %s is %s [start=%s]",
                     name, disp, binary, sign_name(sv),
                     start_type_name(start_type));
        }

        /* SVC.UNQUOTED_PATH -- raw image path has a space and isn't quoted */
        if (!had_quote && unquoted_space) {
            bus_emit(c->bus, "SVC.UNQUOTED_PATH", SEV_LOW, 55,
                     ACT_DISABLE_SVC, pid, target,
                     "Unquoted service path with spaces",
                     "service '%s' (%s) has an unquoted ImagePath containing "
                     "spaces: %s (privilege-escalation hijack risk)",
                     name, disp, raw_path);
        }

        /* SVC.SUSPICIOUS_DLL -- svchost ServiceDll unsigned or user-writable */
        if ((svc_type & SERVICE_WIN32_SHARE_PROCESS) ||
            (binary[0] && str_icontains(binary, "svchost.exe"))) {
            char dll_raw[SC_MAX_PATH];
            if (read_service_dll(name, dll_raw, sizeof(dll_raw))) {
                char dll[SC_MAX_PATH];
                normalize_service_path(dll_raw, dll, sizeof(dll));
                bool dll_exists = false;
                {
                    wchar_t wdll[SC_MAX_PATH];
                    if (dll[0] &&
                        utf8_to_wide(dll, wdll, sizeof(wdll) / sizeof(wdll[0])) != 0)
                        dll_exists =
                            (GetFileAttributesW(wdll) != INVALID_FILE_ATTRIBUTES);
                }
                SignVerdict dsv = dll_exists ? sign_verify(dll, NULL, 0)
                                             : SIGN_UNKNOWN;
                bool dll_unsigned = (dsv == SIGN_UNSIGNED || dsv == SIGN_INVALID);
                bool dll_writable = dll_exists && path_is_user_writable(dll);
                if (dll_exists &&
                    ((dll_unsigned && !is_inbox_path(dll)) || dll_writable)) {
                    bus_emit(c->bus, "SVC.SUSPICIOUS_DLL", SEV_MED, 70,
                             ACT_DISABLE_SVC, pid, target,
                             "Suspicious svchost ServiceDll",
                             "service '%s' (%s) ServiceDll %s is %s%s",
                             name, disp, dll, sign_name(dsv),
                             dll_writable ? " and user-writable" : "");
                }
            }
        }
    }

    free(cfg);
    CloseServiceHandle(svc);
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

void scan_service(ScanCtx *c)
{
    if (!c || !c->bus)
        return;

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL,
                                   SC_MANAGER_ENUMERATE_SERVICE | GENERIC_READ);
    if (!scm) {
        ctx_note_limit(c,
            "scan_service: OpenSCManager failed (err=%lu); service scan skipped "
            "-- some queries need administrator rights.",
            (unsigned long)GetLastError());
        return;
    }

    /* ---- EnumServicesStatusEx with grow-the-buffer ---- */
    DWORD bytes_needed = 0, services = 0, resume = 0;
    BYTE *buf = NULL;
    DWORD cap = 0;
    bool ok = false;
    bool denied = false;

    for (int tries = 0; tries < 16; tries++) {
        if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO,
                                  SERVICE_WIN32 | SERVICE_DRIVER,
                                  SERVICE_STATE_ALL,
                                  buf, cap, &bytes_needed, &services,
                                  &resume, NULL)) {
            ok = true;
            break;
        }

        DWORD err = GetLastError();
        if (err == ERROR_MORE_DATA) {
            DWORD want = cap + bytes_needed + 4096;
            if (want < cap) {       /* overflow guard */
                break;
            }
            BYTE *grown = (BYTE *)realloc(buf, want);
            if (!grown)
                break;
            buf = grown;
            cap = want;
            continue;
        }
        if (err == ERROR_ACCESS_DENIED)
            denied = true;
        break;
    }

    if (ok && buf && services > 0) {
        ENUM_SERVICE_STATUS_PROCESSW *list = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
        for (DWORD i = 0; i < services; i++) {
            char name[SC_NAME_LEN];
            char disp[SC_NAME_LEN];
            name[0] = disp[0] = '\0';
            if (list[i].lpServiceName)
                wide_to_utf8(list[i].lpServiceName, name, sizeof(name));
            if (list[i].lpDisplayName)
                wide_to_utf8(list[i].lpDisplayName, disp, sizeof(disp));
            if (name[0])
                inspect_service(c, scm, name, disp);
        }
    } else if (denied) {
        ctx_note_limit(c,
            "scan_service: EnumServicesStatusEx denied; run elevated for the "
            "full service inventory.");
    }

    free(buf);
    CloseServiceHandle(scm);
}
