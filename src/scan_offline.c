/* scan_offline.c -- online "offline-like" hunting.
 *
 * This does not pretend to be Defender Offline: the current OS is still
 * running, so a kernel rootkit can still interfere with some user-mode APIs.
 * It narrows that gap without rebooting by:
 *   - creating a VSS snapshot of the system volume
 *   - scanning high-value paths through the snapshot namespace
 *   - loading registry hives from the snapshot with RegLoadAppKey
 *   - checking boot/system drivers and offline autoruns from those hives
 *   - probing the raw NTFS volume path when elevated
 *
 * Read-only except for the short-lived VSS shadow copy created and removed by
 * this module. Findings are evidence only; deletion/disable/quarantine remains
 * under the responder flags.
 */

#include "sentinelc.h"

#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <bcrypt.h>
#include <sddl.h>

#ifndef REG_PROCESS_APPKEY
#define REG_PROCESS_APPKEY 0x00000001
#endif

typedef LONG (WINAPI *RegLoadAppKeyA_Fn)(LPCSTR, PHKEY, REGSAM, DWORD, DWORD);

typedef struct {
    char id[128];
    char device[SC_MAX_PATH];
} ShadowCopy;

typedef struct {
    HKEY key;
    char scratch_dir[SC_MAX_PATH];
    char scratch_path[SC_MAX_PATH];
    char mount_name[128];
} LoadedHive;

static bool ieq(const char *a, const char *b)
{
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return false;
        a++;
        b++;
    }
    return *a == *b;
}

static bool istarts(const char *s, const char *prefix)
{
    if (!s || !prefix) return false;
    while (*prefix) {
        if (*s == '\0') return false;
        if (tolower((unsigned char)*s) != tolower((unsigned char)*prefix))
            return false;
        s++;
        prefix++;
    }
    return true;
}

static void copy_bounded(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void trim_ws(char *s)
{
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                 s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
    size_t i = 0;
    while (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')
        i++;
    if (i)
        memmove(s, s + i, strlen(s + i) + 1);
}

static void strip_quotes(char *s)
{
    if (!s) return;
    trim_ws(s);
    size_t n = strlen(s);
    if (n >= 2 && s[0] == '"') {
        char *q = strchr(s + 1, '"');
        if (q) {
            size_t inner = (size_t)(q - (s + 1));
            memmove(s, s + 1, inner);
            s[inner] = '\0';
            return;
        }
        memmove(s, s + 1, n);
    }
}

static void expand_env(const char *in, char *out, size_t cap)
{
    if (!out || cap == 0) return;
    out[0] = '\0';
    if (!in) return;
    DWORD r = ExpandEnvironmentStringsA(in, out, (DWORD)cap);
    if (r == 0 || r > cap)
        copy_bounded(out, cap, in);
}

static char windows_drive_char(void)
{
    char win[SC_MAX_PATH];
    DWORD n = GetWindowsDirectoryA(win, sizeof(win));
    if (n > 1 && n < sizeof(win) && win[1] == ':')
        return (char)toupper((unsigned char)win[0]);
    return 'C';
}

static bool enable_named_privilege(const char *name)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid;
    bool ok = false;
    if (LookupPrivilegeValueA(NULL, name, &luid)) {
        TOKEN_PRIVILEGES tp;
        memset(&tp, 0, sizeof(tp));
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL) &&
            GetLastError() == ERROR_SUCCESS)
            ok = true;
    }
    CloseHandle(token);
    return ok;
}

static bool system_tool_path(const char *relative, char *out, size_t cap)
{
    if (!relative || !out || cap == 0) return false;
    out[0] = '\0';
    char sys[SC_MAX_PATH];
    UINT n = GetSystemDirectoryA(sys, sizeof(sys));
    if (n == 0 || n >= sizeof(sys))
        return false;
    int m = snprintf(out, cap, "%s\\%s", sys, relative);
    if (m < 0 || (size_t)m >= cap)
        return false;
    DWORD attrs = GetFileAttributesA(out);
    return attrs != INVALID_FILE_ATTRIBUTES &&
           (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 &&
           (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

static bool create_admin_only_dir(const char *path)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
            SDDL_REVISION_1, &sd, NULL))
        return false;

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;

    BOOL ok = CreateDirectoryA(path, &sa);
    LocalFree(sd);
    if (!ok)
        return false;

    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        RemoveDirectoryA(path);
        return false;
    }
    return true;
}

static bool random_hex(char *out, size_t cap)
{
    if (!out || cap < 17) return false;
    unsigned char bytes[8];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, bytes, sizeof(bytes),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return false;
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); i++) {
        out[i * 2] = hexd[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = hexd[bytes[i] & 0xF];
    }
    out[16] = '\0';
    return true;
}

static bool make_secure_scratch_dir(const char *tmpdir, const char *safe_tag,
                                    char *out, size_t cap)
{
    if (!tmpdir || !safe_tag || !out || cap == 0) return false;
    out[0] = '\0';
    for (int i = 0; i < 16; i++) {
        char nonce[17];
        if (!random_hex(nonce, sizeof(nonce)))
            return false;
        int n = snprintf(out, cap, "%ssentinelc-hive-%lu-%s-%s",
                         tmpdir, (unsigned long)GetCurrentProcessId(),
                         safe_tag, nonce);
        if (n < 0 || (size_t)n >= cap)
            return false;
        if (create_admin_only_dir(out))
            return true;
    }
    out[0] = '\0';
    return false;
}

static bool run_capture(const char *application, char *cmdline, char *out,
                        size_t cap, DWORD *exit_code)
{
    if (!application || !cmdline || !out || cap == 0) return false;
    out[0] = '\0';
    if (exit_code) *exit_code = 0;

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return false;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    BOOL ok = CreateProcessA(application, cmdline, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(wr);
    if (!ok) {
        CloseHandle(rd);
        return false;
    }

    size_t used = 0;
    for (;;) {
        char buf[512];
        DWORD got = 0;
        BOOL rr = ReadFile(rd, buf, sizeof(buf), &got, NULL);
        if (!rr || got == 0)
            break;
        if (used + got >= cap)
            got = (DWORD)(cap - used - 1);
        if (got > 0) {
            memcpy(out + used, buf, got);
            used += got;
            out[used] = '\0';
        }
        if (used + 1 >= cap)
            break;
    }
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    if (exit_code) *exit_code = code;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

static bool parse_prefixed_line(const char *text, const char *prefix,
                                char *out, size_t cap)
{
    if (!text || !prefix || !out || cap == 0) return false;
    out[0] = '\0';
    size_t plen = strlen(prefix);
    const char *p = text;
    while (*p) {
        const char *line = p;
        const char *end = strpbrk(line, "\r\n");
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len >= plen && _strnicmp(line, prefix, plen) == 0) {
            size_t vlen = len - plen;
            if (vlen >= cap) vlen = cap - 1;
            memcpy(out, line + plen, vlen);
            out[vlen] = '\0';
            trim_ws(out);
            return out[0] != '\0';
        }
        if (!end) break;
        p = end;
        while (*p == '\r' || *p == '\n') p++;
    }
    return false;
}

static bool system_volume(char *volume, size_t cap, char *drive, size_t dcap)
{
    char win[SC_MAX_PATH];
    DWORD n = GetWindowsDirectoryA(win, sizeof(win));
    if (n == 0 || n >= sizeof(win) || win[1] != ':') {
        copy_bounded(volume, cap, "C:\\");
        copy_bounded(drive, dcap, "C:");
        return false;
    }
    snprintf(volume, cap, "%c:\\", (char)toupper((unsigned char)win[0]));
    snprintf(drive, dcap, "%c:", (char)toupper((unsigned char)win[0]));
    return true;
}

static bool create_shadow_copy(ScanCtx *c, const char *volume, ShadowCopy *sc)
{
    if (!sc) return false;
    sc->id[0] = '\0';
    sc->device[0] = '\0';

    char powershell[SC_MAX_PATH];
    if (!system_tool_path("WindowsPowerShell\\v1.0\\powershell.exe",
                          powershell, sizeof(powershell))) {
        ctx_note_limit(c, "offline-like: could not resolve system PowerShell path.");
        return false;
    }

    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "\"%s\" -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$ErrorActionPreference='Stop'; "
        "$r=Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create "
        "-Arguments @{Volume='%s';Context='ClientAccessible'}; "
        "if($r.ReturnValue -ne 0){ Write-Output ('ERR=' + $r.ReturnValue); exit 2 }; "
        "$s=Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $r.ShadowID }; "
        "Write-Output ('ID=' + $r.ShadowID); "
        "Write-Output ('DEVICE=' + $s.DeviceObject)\"",
        powershell, volume);

    char out[4096];
    DWORD code = 0;
    if (!run_capture(powershell, cmd, out, sizeof(out), &code)) {
        ctx_note_limit(c, "offline-like: could not start PowerShell to create a VSS snapshot.");
        return false;
    }
    if (code != 0 ||
        !parse_prefixed_line(out, "ID=", sc->id, sizeof(sc->id)) ||
        !parse_prefixed_line(out, "DEVICE=", sc->device, sizeof(sc->device))) {
        char err[256] = {0};
        parse_prefixed_line(out, "ERR=", err, sizeof(err));
        if (err[0])
            ctx_note_limit(c, "offline-like: VSS snapshot creation failed for %s (ReturnValue=%s).",
                           volume, err);
        else
            ctx_note_limit(c, "offline-like: VSS snapshot creation failed for %s.", volume);
        return false;
    }
    trim_ws(sc->device);
    trim_ws(sc->id);
    return sc->device[0] != '\0';
}

static void delete_shadow_copy(ScanCtx *c, const ShadowCopy *sc)
{
    if (!sc || !sc->id[0]) return;
    char powershell[SC_MAX_PATH];
    if (!system_tool_path("WindowsPowerShell\\v1.0\\powershell.exe",
                          powershell, sizeof(powershell))) {
        ctx_note_limit(c, "offline-like: could not resolve system PowerShell for VSS cleanup.");
        return;
    }
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "\"%s\" -NoProfile -ExecutionPolicy Bypass -Command "
        "\"$ErrorActionPreference='Stop'; "
        "$s=Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq '%s' }; "
        "if($s){ $s | Remove-CimInstance; Write-Output 'DELETED' }\"",
        powershell, sc->id);
    char out[1024];
    DWORD code = 0;
    if (!run_capture(powershell, cmd, out, sizeof(out), &code) || code != 0)
        ctx_note_limit(c, "offline-like: VSS snapshot cleanup failed for %s.", sc->id);
}

static void append_shadow_path(const char *device, const char *rel,
                               char *out, size_t cap)
{
    if (!device || !rel || !out || cap == 0) return;
    while (*rel == '\\' || *rel == '/')
        rel++;
    size_t n = strlen(device);
    if (n && (device[n - 1] == '\\' || device[n - 1] == '/'))
        snprintf(out, cap, "%s%s", device, rel);
    else
        snprintf(out, cap, "%s\\%s", device, rel);
}

static void map_live_root_to_shadow(const char *device, const char *live,
                                    char *out, size_t cap)
{
    char expanded[SC_MAX_PATH];
    expand_env(live, expanded, sizeof(expanded));
    trim_ws(expanded);
    strip_quotes(expanded);
    if (expanded[1] == ':' && (expanded[2] == '\\' || expanded[2] == '/')) {
        append_shadow_path(device, expanded + 3, out, cap);
        return;
    }
    if (istarts(expanded, "\\SystemRoot\\"))
        append_shadow_path(device, expanded + 12, out, cap);
    else if (istarts(expanded, "SystemRoot\\"))
        append_shadow_path(device, expanded + 11, out, cap);
    else if (istarts(expanded, "\\Windows\\"))
        append_shadow_path(device, expanded + 1, out, cap);
    else
        append_shadow_path(device, expanded, out, cap);
}

static void resolve_image_path(const char *device, const char *svc_name,
                               const char *raw, char *live, size_t live_cap,
                               char *shadow, size_t shadow_cap)
{
    char expanded[SC_MAX_CMDLINE];
    if (raw && raw[0]) {
        expand_env(raw, expanded, sizeof(expanded));
    } else {
        char fallback[SC_MAX_PATH];
        snprintf(fallback, sizeof(fallback),
                 "%%SystemRoot%%\\System32\\drivers\\%s.sys",
                 svc_name ? svc_name : "unknown");
        expand_env(fallback, expanded, sizeof(expanded));
    }
    trim_ws(expanded);

    char target[SC_MAX_CMDLINE];
    copy_bounded(target, sizeof(target), expanded);
    strip_quotes(target);

    if (istarts(target, "\\??\\"))
        memmove(target, target + 4, strlen(target + 4) + 1);
    if (istarts(target, "\\SystemRoot\\")) {
        char tmp[SC_MAX_PATH];
        snprintf(tmp, sizeof(tmp), "%c:\\Windows\\%s", windows_drive_char(),
                 target + 12);
        copy_bounded(target, sizeof(target), tmp);
    } else if (istarts(target, "SystemRoot\\")) {
        char tmp[SC_MAX_PATH];
        snprintf(tmp, sizeof(tmp), "%c:\\Windows\\%s", windows_drive_char(),
                 target + 11);
        copy_bounded(target, sizeof(target), tmp);
    } else if (istarts(target, "System32\\") || istarts(target, "SysWOW64\\")) {
        char tmp[SC_MAX_PATH];
        snprintf(tmp, sizeof(tmp), "%c:\\Windows\\%s", windows_drive_char(), target);
        copy_bounded(target, sizeof(target), tmp);
    } else if (istarts(target, "\\Windows\\")) {
        char tmp[SC_MAX_PATH];
        snprintf(tmp, sizeof(tmp), "%c:%s", windows_drive_char(), target);
        copy_bounded(target, sizeof(target), tmp);
    }

    /* If a service image has arguments, keep the executable/driver token. */
    if (target[0] == '"') {
        strip_quotes(target);
    } else {
        char low[SC_MAX_CMDLINE];
        copy_bounded(low, sizeof(low), target);
        str_lower(low);
        const char *exts[] = { ".sys", ".exe", ".dll", NULL };
        size_t best = (size_t)-1;
        for (int i = 0; exts[i]; i++) {
            const char *p = strstr(low, exts[i]);
            if (p) {
                size_t end = (size_t)(p - low) + strlen(exts[i]);
                if (best == (size_t)-1 || end < best)
                    best = end;
            }
        }
        if (best != (size_t)-1 && best < strlen(target))
            target[best] = '\0';
    }
    trim_ws(target);

    copy_bounded(live, live_cap, target);
    if (target[1] == ':' && (target[2] == '\\' || target[2] == '/'))
        append_shadow_path(device, target + 3, shadow, shadow_cap);
    else
        append_shadow_path(device, target, shadow, shadow_cap);
}

static bool load_app_hive(const char *path, HKEY *out)
{
    if (!out) return false;
    *out = NULL;
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    if (!adv)
        adv = LoadLibraryA("advapi32.dll");
    if (!adv)
        return false;
    FARPROC proc = GetProcAddress(adv, "RegLoadAppKeyA");
    if (!proc)
        return false;
    RegLoadAppKeyA_Fn fn = NULL;
    memcpy(&fn, &proc, sizeof(fn));
    LONG rc = fn(path, out, KEY_READ, REG_PROCESS_APPKEY, 0);
    return rc == ERROR_SUCCESS && *out != NULL;
}

static void delete_scratch_dir_files(const char *dir);

static bool load_hive_with_copy_fallback(ScanCtx *c, const char *path,
                                         const char *tag, LoadedHive *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (load_app_hive(path, &out->key))
        return true;

    char tmpdir[SC_MAX_PATH];
    DWORD n = GetTempPathA((DWORD)sizeof(tmpdir), tmpdir);
    if (n == 0 || n >= sizeof(tmpdir)) {
        ctx_note_limit(c, "offline-like: could not resolve temp path for hive fallback.");
        return false;
    }

    char safe_tag[64];
    copy_bounded(safe_tag, sizeof(safe_tag), tag ? tag : "hive");
    for (char *p = safe_tag; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-')
            *p = '_';

    if (!make_secure_scratch_dir(tmpdir, safe_tag,
                                 out->scratch_dir, sizeof(out->scratch_dir))) {
        ctx_note_limit(c, "offline-like: could not create a secure hive scratch directory.");
        return false;
    }

    char hive_base[SC_NAME_LEN];
    base_name(path, hive_base, sizeof(hive_base));
    if (!hive_base[0])
        copy_bounded(hive_base, sizeof(hive_base), safe_tag);

    snprintf(out->scratch_path, sizeof(out->scratch_path),
             "%s\\%s", out->scratch_dir, hive_base);

    if (!CopyFileA(path, out->scratch_path, FALSE)) {
        DWORD err = GetLastError();
        RemoveDirectoryA(out->scratch_dir);
        out->scratch_dir[0] = '\0';
        out->scratch_path[0] = '\0';
        ctx_note_limit(c, "offline-like: could not copy snapshot %s hive for fallback (error %lu).",
                       tag ? tag : "registry", (unsigned long)err);
        return false;
    }

    {
        char src_log[SC_MAX_PATH], dst_log[SC_MAX_PATH];
        snprintf(src_log, sizeof(src_log), "%s.LOG1", path);
        snprintf(dst_log, sizeof(dst_log), "%s.LOG1", out->scratch_path);
        CopyFileA(src_log, dst_log, FALSE);
        snprintf(src_log, sizeof(src_log), "%s.LOG2", path);
        snprintf(dst_log, sizeof(dst_log), "%s.LOG2", out->scratch_path);
        CopyFileA(src_log, dst_log, FALSE);
    }

    if (load_app_hive(out->scratch_path, &out->key))
        return true;

    snprintf(out->mount_name, sizeof(out->mount_name),
             "SentinelC_%lu_%lu_%s",
             (unsigned long)GetCurrentProcessId(),
             (unsigned long)GetTickCount(), safe_tag);

    char reg_exe[SC_MAX_PATH];
    if (!system_tool_path("reg.exe", reg_exe, sizeof(reg_exe))) {
        ctx_note_limit(c, "offline-like: could not resolve system reg.exe path.");
        DeleteFileA(out->scratch_path);
        delete_scratch_dir_files(out->scratch_dir);
        RemoveDirectoryA(out->scratch_dir);
        out->scratch_dir[0] = '\0';
        out->scratch_path[0] = '\0';
        out->mount_name[0] = '\0';
        return false;
    }

    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "\"%s\" load HKU\\%s \"%s\"",
             reg_exe,
             out->mount_name, out->scratch_path);
    char capout[2048];
    DWORD code = 1;
    if (run_capture(reg_exe, cmd, capout, sizeof(capout), &code) && code == 0) {
        if (RegOpenKeyExA(HKEY_USERS, out->mount_name, 0, KEY_READ, &out->key) == ERROR_SUCCESS)
            return true;

        snprintf(cmd, sizeof(cmd), "\"%s\" unload HKU\\%s",
                 reg_exe, out->mount_name);
        run_capture(reg_exe, cmd, capout, sizeof(capout), &code);
    } else {
        trim_ws(capout);
        ctx_note_limit(c, "offline-like: reg load fallback failed for %s hive (exit %lu): %.180s",
                       tag ? tag : "registry", (unsigned long)code,
                       capout[0] ? capout : "no output");
    }

    DeleteFileA(out->scratch_path);
    delete_scratch_dir_files(out->scratch_dir);
    RemoveDirectoryA(out->scratch_dir);
    out->scratch_dir[0] = '\0';
    out->scratch_path[0] = '\0';
    out->mount_name[0] = '\0';
    return false;
}

static void delete_scratch_dir_files(const char *dir)
{
    if (!dir || !dir[0])
        return;
    char pat[SC_MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        if (ieq(fd.cFileName, ".") || ieq(fd.cFileName, ".."))
            continue;
        char child[SC_MAX_PATH];
        snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            DeleteFileA(child);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void close_loaded_hive(LoadedHive *h)
{
    if (!h) return;
    if (h->key) {
        RegCloseKey(h->key);
        h->key = NULL;
    }
    if (h->mount_name[0]) {
        char cmd[512];
        char out[512];
        DWORD code = 0;
        char reg_exe[SC_MAX_PATH];
        if (system_tool_path("reg.exe", reg_exe, sizeof(reg_exe))) {
            snprintf(cmd, sizeof(cmd), "\"%s\" unload HKU\\%s",
                     reg_exe, h->mount_name);
            run_capture(reg_exe, cmd, out, sizeof(out), &code);
        }
        Sleep(150);
        h->mount_name[0] = '\0';
    }
    if (h->scratch_path[0]) {
        char logp[SC_MAX_PATH];
        DeleteFileA(h->scratch_path);
        snprintf(logp, sizeof(logp), "%s.LOG1", h->scratch_path);
        DeleteFileA(logp);
        snprintf(logp, sizeof(logp), "%s.LOG2", h->scratch_path);
        DeleteFileA(logp);
        h->scratch_path[0] = '\0';
    }
    if (h->scratch_dir[0]) {
        delete_scratch_dir_files(h->scratch_dir);
        RemoveDirectoryA(h->scratch_dir);
        h->scratch_dir[0] = '\0';
    }
}

static bool reg_read_dword(HKEY key, const char *name, DWORD *out)
{
    DWORD type = 0, value = 0, cb = sizeof(value);
    LONG rc = RegQueryValueExA(key, name, NULL, &type, (LPBYTE)&value, &cb);
    if (rc == ERROR_SUCCESS && type == REG_DWORD && cb == sizeof(value)) {
        if (out) *out = value;
        return true;
    }
    return false;
}

static bool reg_read_string(HKEY key, const char *name, char *out, size_t cap)
{
    if (!out || cap == 0) return false;
    out[0] = '\0';
    DWORD type = 0;
    char buf[SC_MAX_CMDLINE];
    DWORD cb = sizeof(buf) - 1;
    LONG rc = RegQueryValueExA(key, name, NULL, &type, (LPBYTE)buf, &cb);
    if (rc != ERROR_SUCCESS ||
        !(type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ))
        return false;
    buf[sizeof(buf) - 1] = '\0';
    if (type == REG_EXPAND_SZ)
        expand_env(buf, out, cap);
    else
        copy_bounded(out, cap, buf);
    trim_ws(out);
    return out[0] != '\0';
}

static bool path_exists_file(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void inspect_boot_drivers(ScanCtx *c, const char *device, HKEY sys_hive,
                                 int pass)
{
    HKEY select = NULL;
    DWORD current = 1;
    if (RegOpenKeyExA(sys_hive, "Select", 0, KEY_READ, &select) == ERROR_SUCCESS) {
        reg_read_dword(select, "Current", &current);
        RegCloseKey(select);
    }
    if (current == 0 || current > 999)
        current = 1;

    char services_path[128];
    snprintf(services_path, sizeof(services_path),
             "ControlSet%03lu\\Services", (unsigned long)current);

    HKEY services = NULL;
    if (RegOpenKeyExA(sys_hive, services_path, 0, KEY_READ, &services) != ERROR_SUCCESS) {
        ctx_note_limit(c, "offline-like: could not open offline SYSTEM\\%s.", services_path);
        return;
    }

    for (DWORD idx = 0;; idx++) {
        char name[SC_NAME_LEN];
        DWORD name_len = sizeof(name);
        LONG er = RegEnumKeyExA(services, idx, name, &name_len, NULL, NULL, NULL, NULL);
        if (er == ERROR_NO_MORE_ITEMS)
            break;
        if (er != ERROR_SUCCESS)
            continue;

        HKEY svc = NULL;
        if (RegOpenKeyExA(services, name, 0, KEY_READ, &svc) != ERROR_SUCCESS)
            continue;

        DWORD type = 0, start = 99;
        reg_read_dword(svc, "Type", &type);
        reg_read_dword(svc, "Start", &start);
        bool kernel_driver = (type & 0x1) || (type & 0x2);
        bool early = (start == 0 || start == 1);
        if (!kernel_driver || !early) {
            RegCloseKey(svc);
            continue;
        }

        char raw[SC_MAX_CMDLINE] = {0};
        reg_read_string(svc, "ImagePath", raw, sizeof(raw));

        char live[SC_MAX_PATH], shadow[SC_MAX_PATH];
        resolve_image_path(device, name, raw, live, sizeof(live), shadow, sizeof(shadow));

        bool exists = path_exists_file(shadow);
        bool normal_driver_dir = str_icontains(live, "\\windows\\system32\\drivers\\") ||
                                 str_icontains(live, "\\windows\\system32\\driverstore\\filerepository\\");
        bool outside_driver_dir = !normal_driver_dir;
        bool writable = path_is_user_writable(live);
        SignVerdict sv = SIGN_UNKNOWN;
        char signer[SC_NAME_LEN] = {0};
        if (exists)
            sv = sign_verify(shadow, signer, sizeof(signer));

        if (!exists || writable || outside_driver_dir ||
            sv == SIGN_UNSIGNED || sv == SIGN_INVALID) {
            Severity sev = (!exists || writable || sv == SIGN_INVALID) ? SEV_HIGH : SEV_MED;
            int conf = (!exists || sv == SIGN_INVALID) ? 86 : 74;
            if (writable) {
                sev = SEV_CRIT;
                conf = 92;
            }
            bus_emit(c->bus, "OFFLINE.BOOT_DRIVER", sev, conf,
                     ACT_DISABLE_SVC, 0, name,
                     "Offline boot/system driver needs review",
                     "pass=%d service=%s start=%lu type=0x%lx live=%s snapshot=%s exists=%s sign=%s signer=%s",
                     pass, name, (unsigned long)start, (unsigned long)type,
                     live, shadow, exists ? "yes" : "no", sign_name(sv),
                     signer[0] ? signer : "-");
        }
        RegCloseKey(svc);
    }
    RegCloseKey(services);
}

static void extract_autorun_target(const char *raw, char *out, size_t cap)
{
    char expanded[SC_MAX_CMDLINE];
    expand_env(raw, expanded, sizeof(expanded));
    trim_ws(expanded);
    out[0] = '\0';
    if (!expanded[0]) return;

    if (expanded[0] == '"') {
        const char *q = strchr(expanded + 1, '"');
        if (q) {
            size_t len = (size_t)(q - (expanded + 1));
            if (len >= cap) len = cap - 1;
            memcpy(out, expanded + 1, len);
            out[len] = '\0';
            return;
        }
    }

    char low[SC_MAX_CMDLINE];
    copy_bounded(low, sizeof(low), expanded);
    str_lower(low);
    const char *exts[] = { ".exe", ".dll", ".scr", ".bat", ".cmd",
                           ".com", ".cpl", ".vbs", ".js", ".ps1", NULL };
    size_t best = (size_t)-1;
    for (int e = 0; exts[e]; e++) {
        const char *hit = strstr(low, exts[e]);
        if (hit) {
            size_t end = (size_t)(hit - low) + strlen(exts[e]);
            if (best == (size_t)-1 || end < best) best = end;
        }
    }
    if (best != (size_t)-1) {
        if (best >= cap) best = cap - 1;
        memcpy(out, expanded, best);
        out[best] = '\0';
    } else {
        size_t j = 0;
        const char *p = expanded;
        while (*p && *p != ' ' && *p != '\t' && j < cap - 1)
            out[j++] = *p++;
        out[j] = '\0';
    }
    strip_quotes(out);
    trim_ws(out);
}

static void inspect_run_key(ScanCtx *c, const char *device, HKEY hive,
                            const char *subkey, const char *rule,
                            const char *scope, int pass)
{
    HKEY key = NULL;
    if (RegOpenKeyExA(hive, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return;

    for (DWORD i = 0;; i++) {
        char name[SC_NAME_LEN];
        BYTE data[SC_MAX_CMDLINE];
        DWORD name_len = sizeof(name);
        DWORD type = 0, cb = sizeof(data) - 2;
        LONG rc = RegEnumValueA(key, i, name, &name_len, NULL, &type, data, &cb);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc != ERROR_SUCCESS ||
            !(type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ))
            continue;
        data[cb] = 0;
        data[cb + 1] = 0;

        char target[SC_MAX_PATH];
        extract_autorun_target((const char *)data, target, sizeof(target));
        if (!target[0])
            continue;

        char shadow[SC_MAX_PATH];
        if (target[1] == ':' && (target[2] == '\\' || target[2] == '/'))
            append_shadow_path(device, target + 3, shadow, sizeof(shadow));
        else
            append_shadow_path(device, target, shadow, sizeof(shadow));

        bool exists = path_exists_file(shadow);
        bool writable = path_is_user_writable(target);
        bool tempish = str_icontains(target, "\\temp\\") ||
                       str_icontains(target, "\\appdata\\local\\temp\\") ||
                       str_icontains(target, "\\$recycle.bin\\");
        SignVerdict sv = exists ? sign_verify(shadow, NULL, 0) : SIGN_UNKNOWN;

        if (writable || tempish || sv == SIGN_UNSIGNED || sv == SIGN_INVALID) {
            Severity sev = SEV_LOW;
            int conf = 48;
            if (sv == SIGN_INVALID || tempish) {
                sev = SEV_HIGH;
                conf = 86;
            } else if (sv == SIGN_UNSIGNED) {
                sev = writable ? SEV_HIGH : SEV_MED;
                conf = writable ? 84 : 74;
            } else if (sv == SIGN_SIGNED || sv == SIGN_SIGNED_MS) {
                sev = SEV_LOW;
                conf = (sv == SIGN_SIGNED_MS) ? 38 : 48;
            } else if (writable) {
                sev = SEV_MED;
                conf = 66;
            }
            bus_emit(c->bus, rule, sev, conf, ACT_QUARANTINE,
                     0, target, "Offline autorun target is suspicious",
                     "pass=%d scope=%s key=%s value=%s command=%s target=%s snapshot=%s exists=%s sign=%s",
                     pass, scope, subkey, name, (const char *)data, target,
                     shadow, exists ? "yes" : "no", sign_name(sv));
        }
    }
    RegCloseKey(key);
}

static void inspect_defender_exclusions(ScanCtx *c, HKEY software_hive, int pass)
{
    static const char *subs[] = {
        "Microsoft\\Windows Defender\\Exclusions\\Paths",
        "Microsoft\\Windows Defender\\Exclusions\\Extensions",
        "Microsoft\\Windows Defender\\Exclusions\\Processes",
        NULL
    };
    for (int s = 0; subs[s]; s++) {
        HKEY key = NULL;
        if (RegOpenKeyExA(software_hive, subs[s], 0, KEY_READ, &key) != ERROR_SUCCESS)
            continue;
        for (DWORD i = 0;; i++) {
            char name[SC_MAX_PATH];
            DWORD name_len = sizeof(name);
            LONG rc = RegEnumValueA(key, i, name, &name_len, NULL, NULL, NULL, NULL);
            if (rc == ERROR_NO_MORE_ITEMS)
                break;
            if (rc != ERROR_SUCCESS)
                continue;
            bus_emit(c->bus, "OFFLINE.DEFENDER_EXCLUSION", SEV_HIGH, 88,
                     ACT_REVIEW, 0, name,
                     "Offline Defender exclusion present",
                     "pass=%d hive=SOFTWARE key=%s value=%s",
                     pass, subs[s], name);
        }
        RegCloseKey(key);
    }
}

static void inspect_offline_hives(ScanCtx *c, const ShadowCopy *sc, int pass)
{
    char system_hive[SC_MAX_PATH];
    char software_hive[SC_MAX_PATH];
    append_shadow_path(sc->device, "Windows\\System32\\config\\SYSTEM",
                       system_hive, sizeof(system_hive));
    append_shadow_path(sc->device, "Windows\\System32\\config\\SOFTWARE",
                       software_hive, sizeof(software_hive));

    LoadedHive h;
    if (load_hive_with_copy_fallback(c, system_hive, "SYSTEM", &h)) {
        inspect_boot_drivers(c, sc->device, h.key, pass);
        close_loaded_hive(&h);
    } else {
        ctx_note_limit(c, "offline-like: could not load snapshot SYSTEM hive.");
    }

    if (load_hive_with_copy_fallback(c, software_hive, "SOFTWARE", &h)) {
        inspect_defender_exclusions(c, h.key, pass);
        inspect_run_key(c, sc->device, h.key,
                        "Microsoft\\Windows\\CurrentVersion\\Run",
                        "OFFLINE.RUNKEY", "HKLM", pass);
        inspect_run_key(c, sc->device, h.key,
                        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                        "OFFLINE.RUNKEY", "HKLM", pass);
        inspect_run_key(c, sc->device, h.key,
                        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "OFFLINE.RUNKEY", "HKLM32", pass);
        close_loaded_hive(&h);
    } else {
        ctx_note_limit(c, "offline-like: could not load snapshot SOFTWARE hive.");
    }

    char user_profile[SC_MAX_PATH];
    DWORD r = ExpandEnvironmentStringsA("%USERPROFILE%", user_profile,
                                        (DWORD)sizeof(user_profile));
    if (r > 0 && r < sizeof(user_profile) && user_profile[1] == ':') {
        char ntuser[SC_MAX_PATH];
        append_shadow_path(sc->device, user_profile + 3, ntuser, sizeof(ntuser));
        size_t used = strlen(ntuser);
        snprintf(ntuser + used, sizeof(ntuser) - used, "\\NTUSER.DAT");
        if (load_hive_with_copy_fallback(c, ntuser, "NTUSER", &h)) {
            inspect_run_key(c, sc->device, h.key,
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "OFFLINE.USER_RUNKEY", "HKCU", pass);
            inspect_run_key(c, sc->device, h.key,
                            "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                            "OFFLINE.USER_RUNKEY", "HKCU", pass);
            close_loaded_hive(&h);
        }
    }
}

static void add_root(char roots[][SC_MAX_PATH], size_t *count, size_t cap,
                     const char *device, const char *live)
{
    if (!roots || !count || *count >= cap || !live || !live[0])
        return;
    char mapped[SC_MAX_PATH];
    map_live_root_to_shadow(device, live, mapped, sizeof(mapped));
    if (!mapped[0])
        return;
    for (size_t i = 0; i < *count; i++)
        if (ieq(roots[i], mapped))
            return;
    copy_bounded(roots[*count], SC_MAX_PATH, mapped);
    (*count)++;
}

static void add_default_roots(char roots[][SC_MAX_PATH], size_t *count,
                              size_t cap, const char *device)
{
    add_root(roots, count, cap, device, "%SystemRoot%\\System32\\drivers");
    add_root(roots, count, cap, device, "%SystemRoot%\\System32\\Tasks");
    add_root(roots, count, cap, device, "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    add_root(roots, count, cap, device, "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
}

static void add_user_roots(char roots[][SC_MAX_PATH], size_t *count, size_t cap,
                           const char *device, const char *list)
{
    if (!list || !list[0]) return;
    char tmp[4096];
    copy_bounded(tmp, sizeof(tmp), list);
    char *ctx = NULL;
    for (char *tok = strtok_s(tmp, ";", &ctx); tok; tok = strtok_s(NULL, ";", &ctx)) {
        trim_ws(tok);
        if (tok[0])
            add_root(roots, count, cap, device, tok);
    }
}

static void scan_snapshot_paths(ScanCtx *c, const ShadowCopy *sc)
{
    char roots[32][SC_MAX_PATH];
    size_t count = 0;
    memset(roots, 0, sizeof(roots));
    add_default_roots(roots, &count, 32, sc->device);
    add_user_roots(roots, &count, 32, sc->device, c->cfg->offline_roots);

    char saved[SC_MAX_PATH];
    copy_bounded(saved, sizeof(saved), c->cfg->scan_path);
    for (size_t i = 0; i < count; i++) {
        DWORD attr = GetFileAttributesA(roots[i]);
        if (attr == INVALID_FILE_ATTRIBUTES)
            continue;
        copy_bounded(c->cfg->scan_path, sizeof(c->cfg->scan_path), roots[i]);
        scan_path(c);
    }
    copy_bounded(c->cfg->scan_path, sizeof(c->cfg->scan_path), saved);
}

static void raw_volume_probe(ScanCtx *c, const char *drive)
{
    char vol[16];
    snprintf(vol, sizeof(vol), "\\\\.\\%c:", drive && drive[0] ? drive[0] : 'C');
    HANDLE h = CreateFileA(vol, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        ctx_note_limit(c, "offline-like: could not open raw volume %s for metadata.", vol);
        return;
    }
    NTFS_VOLUME_DATA_BUFFER nb;
    DWORD got = 0;
    memset(&nb, 0, sizeof(nb));
    if (DeviceIoControl(h, FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0,
                        &nb, sizeof(nb), &got, NULL)) {
        bus_emit(c->bus, "OFFLINE.RAW_VOLUME", SEV_INFO, 60, ACT_REVIEW,
                 0, vol, "Raw NTFS volume metadata readable",
                 "bytesPerCluster=%lu bytesPerFileRecord=%lu mftStartLcn=%lld",
                 (unsigned long)nb.BytesPerCluster,
                 (unsigned long)nb.BytesPerFileRecordSegment,
                 (long long)nb.MftStartLcn.QuadPart);
    } else {
        ctx_note_limit(c, "offline-like: raw volume metadata query failed for %s.", vol);
    }
    CloseHandle(h);
}

void scan_offline_like(ScanCtx *c)
{
    if (!c || !c->cfg || !c->bus)
        return;

    ctx_note_limit(c, "offline-like: this narrows the Defender Offline gap without rebooting, but it cannot fully replace a rebooted trusted scanner.");

    if (!c->is_admin)
        ctx_note_limit(c, "offline-like: not elevated; VSS, raw volume, and offline hive checks may be incomplete.");

    enable_named_privilege(SE_BACKUP_NAME);
    enable_named_privilege(SE_RESTORE_NAME);

    char volume[16], drive[8];
    system_volume(volume, sizeof(volume), drive, sizeof(drive));
    raw_volume_probe(c, drive);

    int passes = c->cfg->offline_passes > 0 ? c->cfg->offline_passes : 2;
    if (passes > 10)
        passes = 10;

    for (int pass = 1; pass <= passes; pass++) {
        ShadowCopy sc;
        memset(&sc, 0, sizeof(sc));
        if (!create_shadow_copy(c, volume, &sc))
            return;

        bus_emit(c->bus, "OFFLINE.SNAPSHOT", SEV_INFO, 70, ACT_REVIEW,
                 0, sc.device, "VSS snapshot pass started",
                 "pass=%d/%d id=%s device=%s", pass, passes, sc.id, sc.device);

        inspect_offline_hives(c, &sc, pass);
        scan_snapshot_paths(c, &sc);

        delete_shadow_copy(c, &sc);
        if (pass < passes)
            Sleep(1200);
    }
}
