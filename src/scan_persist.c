/* scan_persist.c -- SentinelC persistence / autostart scanner.
 *
 * Enumerates classic Windows autostart and persistence locations, resolves
 * each entry to a target binary, and weights severity higher when that
 * target is unsigned and/or sits in a user-writable directory.
 *
 * Covered:
 *   - Run / RunOnce          (HKLM, HKCU, Wow6432Node)   -> PERSIST.RUNKEY
 *   - Winlogon Shell/Userinit (HKLM)                     -> PERSIST.WINLOGON
 *   - AppInit_DLLs           (HKLM)                       -> PERSIST.APPINIT
 *   - Image File Execution Options Debugger              -> PERSIST.IFEO
 *   - Startup folders (per-user + all-users)             -> PERSIST.STARTUP_FOLDER
 *   - Scheduled tasks (System32\Tasks XML)               -> PERSIST.TASK
 *   - WMI event subscription (root\subscription)         -> PERSIST.WMI_SUB
 *   - COM hijack (HKCU CLSID shadowing HKLM)             -> PERSIST.COM_HIJACK
 *
 * Read-only. No process state mutated. Safe to run on a thread pool.
 *
 * Build: -Iinclude  -Wall -Wextra
 * Libs : advapi32 ole32 oleaut32 wbemuuid kernel32
 *        (WMI GUIDs are also defined locally so wbemuuid is optional under
 *         MinGW -- see WMI section below.)
 */

#include "sentinelc.h"

#include <objbase.h>
#include <shlobj.h>     /* SHGetFolderPathW, CSIDL_* */
#include <wchar.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* WMI / COM for the event-subscription check. wbemidl.h ships with both
 * MinGW-w64 and the Windows SDK. We define the GUIDs we need locally so the
 * module links even if wbemuuid.lib is unavailable under MinGW. */
#define COBJMACROS
#include <wbemidl.h>

/* ------------------------------------------------------------------ *
 *  small local helpers
 * ------------------------------------------------------------------ */

/* Strip a single layer of surrounding double quotes, in place. */
static void strip_quotes(char *s)
{
    size_t n = strlen(s);
    if (n >= 2 && s[0] == '"') {
        char *q = strchr(s + 1, '"');
        if (q) {
            size_t inner = (size_t)(q - (s + 1));
            memmove(s, s + 1, inner);
            s[inner] = '\0';
            return;
        }
        /* unterminated leading quote: just drop it */
        memmove(s, s + 1, n);   /* includes NUL */
    }
}

static void trim_ws(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                 s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = '\0';
    size_t i = 0;
    while (s[i] == ' ' || s[i] == '\t') i++;
    if (i) memmove(s, s + i, strlen(s + i) + 1);
}

/* Expand %VARS% using the process environment into a bounded buffer. */
static void expand_env(const char *in, char *out, size_t cap)
{
    if (cap == 0) return;
    DWORD r = ExpandEnvironmentStringsA(in, out, (DWORD)cap);
    if (r == 0 || r > cap) {
        /* fall back to the raw value, bounded */
        size_t n = strlen(in);
        if (n >= cap) n = cap - 1;
        memcpy(out, in, n);
        out[n] = '\0';
    }
}

/* Given a raw autostart command line, extract the launched binary path.
 *
 *  - expands environment variables
 *  - handles  "C:\path with spaces\x.exe" args
 *  - handles  rundll32.exe shell32.dll,Control_RunDLL "C:\bad.cpl"  -> the
 *    rundll target DLL/binary after the comma-or-space argument
 *  - otherwise takes the token up to the first space following a known
 *    extension, else the whole first token
 *
 * Writes a bounded result to out[cap].
 */
static void extract_target(const char *raw, char *out, size_t cap)
{
    char expanded[SC_MAX_CMDLINE];
    expand_env(raw, expanded, sizeof expanded);
    trim_ws(expanded);

    out[0] = '\0';
    if (expanded[0] == '\0') return;

    /* rundll32 / regsvr32 style: the real payload is the module argument. */
    {
        char low[SC_MAX_CMDLINE];
        strncpy(low, expanded, sizeof low - 1);
        low[sizeof low - 1] = '\0';
        str_lower(low);
        const char *rd = strstr(low, "rundll32");
        if (!rd) rd = strstr(low, "regsvr32");
        if (rd) {
            /* find the module: first non-flag token after the host exe.
             * e.g.  rundll32.exe  "C:\evil.dll",Entry
             *       rundll32.exe  C:\evil.dll,Entry            */
            const char *p = expanded;
            /* skip the host exe token (may be quoted) */
            if (*p == '"') { p++; const char *q = strchr(p, '"'); p = q ? q + 1 : p + strlen(p); }
            else { while (*p && *p != ' ' && *p != '\t') p++; }
            while (*p == ' ' || *p == '\t') p++;
            if (*p) {
                char mod[SC_MAX_PATH];
                size_t j = 0;
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"' && j < sizeof mod - 1) mod[j++] = *p++;
                } else {
                    /* up to first comma or whitespace */
                    while (*p && *p != ',' && *p != ' ' && *p != '\t' &&
                           j < sizeof mod - 1)
                        mod[j++] = *p++;
                }
                mod[j] = '\0';
                trim_ws(mod);
                if (mod[0]) {
                    strncpy(out, mod, cap - 1);
                    out[cap - 1] = '\0';
                    return;
                }
            }
            /* fall through if we couldn't isolate a module */
        }
    }

    /* Quoted leading path: take exactly what is inside the quotes. */
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

    /* Unquoted: many real entries contain spaces in the path
     * (e.g. C:\Program Files\...). Take the substring up to and including a
     * known executable extension if present; otherwise the first token. */
    {
        const char *exts[] = { ".exe", ".dll", ".scr", ".bat", ".cmd",
                               ".com", ".cpl", ".vbs", ".js", ".ps1", NULL };
        char low[SC_MAX_CMDLINE];
        strncpy(low, expanded, sizeof low - 1);
        low[sizeof low - 1] = '\0';
        str_lower(low);

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
            strip_quotes(out);
            trim_ws(out);
            return;
        }
    }

    /* Last resort: first whitespace-delimited token. */
    {
        size_t j = 0;
        const char *p = expanded;
        while (*p && *p != ' ' && *p != '\t' && j < cap - 1) out[j++] = *p++;
        out[j] = '\0';
        strip_quotes(out);
        trim_ws(out);
    }
}

/* Classify a resolved target and decide whether it should bump severity.
 * Returns true when the target is unsigned/invalid or user-writable. Also
 * fills a short reason and the signer verdict for evidence. */
static bool target_is_risky(const char *target, char *reason, size_t rcap,
                            SignVerdict *verdict_out)
{
    SignVerdict v = SIGN_UNKNOWN;
    bool risky = false;
    reason[0] = '\0';

    /* Only verify when it actually points at a file on disk. */
    DWORD attr = GetFileAttributesA(target);
    bool exists = (attr != INVALID_FILE_ATTRIBUTES);

    if (exists) {
        v = sign_verify(target, NULL, 0);
        if (v == SIGN_UNSIGNED || v == SIGN_INVALID) {
            risky = true;
            snprintf(reason, rcap, "%s", sign_name(v));
        }
    }
    if (verdict_out) *verdict_out = v;

    if (path_is_user_writable(target)) {
        risky = true;
        if (reason[0])
            snprintf(reason + strlen(reason), rcap - strlen(reason),
                     ", user-writable");
        else
            snprintf(reason, rcap, "user-writable");
    }
    return risky;
}

/* ------------------------------------------------------------------ *
 *  Run / RunOnce keys
 * ------------------------------------------------------------------ */

static void scan_run_key(ScanCtx *c, HKEY root, const char *rootname,
                         const char *subkey, REGSAM extra)
{
    HKEY hk;
    LONG rc = RegOpenKeyExA(root, subkey, 0,
                            KEY_READ | KEY_QUERY_VALUE | extra, &hk);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied reading %s\\%s",
                           rootname, subkey);
        /* ERROR_FILE_NOT_FOUND is normal */
        return;
    }

    DWORD idx = 0;
    for (;;) {
        char  name[SC_NAME_LEN];
        DWORD nlen = sizeof name;
        BYTE  data[SC_MAX_CMDLINE];
        DWORD dlen = sizeof data;
        DWORD type = 0;

        LONG e = RegEnumValueA(hk, idx, name, &nlen, NULL, &type, data, &dlen);
        if (e == ERROR_NO_MORE_ITEMS) break;
        idx++;
        if (e != ERROR_SUCCESS) continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        if (dlen == 0) continue;

        /* Ensure NUL termination within bounds. */
        data[(dlen < sizeof data) ? dlen : sizeof data - 1] = '\0';
        data[sizeof data - 1] = '\0';

        char raw[SC_MAX_CMDLINE];
        if (type == REG_EXPAND_SZ) {
            expand_env((const char *)data, raw, sizeof raw);
        } else {
            strncpy(raw, (const char *)data, sizeof raw - 1);
            raw[sizeof raw - 1] = '\0';
        }

        char target[SC_MAX_PATH];
        extract_target(raw, target, sizeof target);
        if (target[0] == '\0') continue;
        if (allowlist_match(target) || allowlist_match(name)) continue;

        char reason[128];
        bool risky = target_is_risky(target, reason, sizeof reason, NULL);

        bus_emit(c->bus, "PERSIST.RUNKEY",
                 risky ? SEV_MED : SEV_LOW,
                 risky ? 70 : 45,
                 ACT_REVIEW, 0, target,
                 "Autostart Run key entry",
                 "%s\\%s value \"%s\" -> %s%s%s%s",
                 rootname, subkey, name, target,
                 risky ? " [" : "", risky ? reason : "",
                 risky ? "]" : "");
    }
    RegCloseKey(hk);
}

static void scan_run_keys(ScanCtx *c)
{
    static const char *RUN      = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    static const char *RUNONCE  = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    static const char *RUN64    = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
    static const char *RUNONCE64= "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

    scan_run_key(c, HKEY_LOCAL_MACHINE, "HKLM", RUN,       0);
    scan_run_key(c, HKEY_LOCAL_MACHINE, "HKLM", RUNONCE,   0);
    scan_run_key(c, HKEY_CURRENT_USER,  "HKCU", RUN,       0);
    scan_run_key(c, HKEY_CURRENT_USER,  "HKCU", RUNONCE,   0);

    /* WOW6432Node (32-bit view). On 32-bit Windows the Wow6432Node path is
     * absent; RegOpenKeyEx just returns FILE_NOT_FOUND, which we ignore. */
    scan_run_key(c, HKEY_LOCAL_MACHINE, "HKLM", RUN64,     0);
    scan_run_key(c, HKEY_LOCAL_MACHINE, "HKLM", RUNONCE64, 0);
    scan_run_key(c, HKEY_CURRENT_USER,  "HKCU", RUN64,     0);
    scan_run_key(c, HKEY_CURRENT_USER,  "HKCU", RUNONCE64, 0);
}

/* ------------------------------------------------------------------ *
 *  Winlogon  (Shell / Userinit)
 * ------------------------------------------------------------------ */

static bool read_reg_sz(HKEY root, const char *subkey, const char *value,
                        char *out, size_t cap)
{
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return false;
    BYTE  data[SC_MAX_CMDLINE];
    DWORD dlen = sizeof data;
    DWORD type = 0;
    LONG e = RegQueryValueExA(hk, value, NULL, &type, data, &dlen);
    RegCloseKey(hk);
    if (e != ERROR_SUCCESS) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ) return false;
    data[(dlen < sizeof data) ? dlen : sizeof data - 1] = '\0';
    data[sizeof data - 1] = '\0';
    if (type == REG_EXPAND_SZ) expand_env((const char *)data, out, cap);
    else { strncpy(out, (const char *)data, cap - 1); out[cap - 1] = '\0'; }
    return true;
}

static void scan_winlogon(ScanCtx *c)
{
    static const char *WL =
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

    /* Shell -- expected exactly "explorer.exe". */
    char shell[SC_MAX_CMDLINE];
    if (read_reg_sz(HKEY_LOCAL_MACHINE, WL, "Shell", shell, sizeof shell)) {
        trim_ws(shell);
        char low[SC_MAX_CMDLINE];
        strncpy(low, shell, sizeof low - 1); low[sizeof low - 1] = '\0';
        str_lower(low);
        if (strcmp(low, "explorer.exe") != 0 && shell[0]) {
            char target[SC_MAX_PATH];
            extract_target(shell, target, sizeof target);
            bus_emit(c->bus, "PERSIST.WINLOGON", SEV_HIGH, 85,
                     ACT_REVIEW, 0, target[0] ? target : shell,
                     "Winlogon Shell altered",
                     "HKLM\\%s Shell = \"%s\" (expected explorer.exe)",
                     WL, shell);
        }
    }

    /* Userinit -- expected userinit.exe in System32, single entry. */
    char userinit[SC_MAX_CMDLINE];
    if (read_reg_sz(HKEY_LOCAL_MACHINE, WL, "Userinit", userinit,
                    sizeof userinit)) {
        trim_ws(userinit);
        char low[SC_MAX_CMDLINE];
        strncpy(low, userinit, sizeof low - 1); low[sizeof low - 1] = '\0';
        str_lower(low);

        /* Userinit is a comma-separated list; the canonical value is
         * "C:\Windows\system32\userinit.exe,". Anything beyond that one
         * entry (an extra binary) is the persistence signal. */
        bool deviates = false;
        if (!strstr(low, "system32\\userinit.exe") &&
            !strstr(low, "userinit.exe"))
            deviates = true;

        /* Count comma-separated non-empty tokens; >1 means an extra binary. */
        int tokens = 0;
        char tmp[SC_MAX_CMDLINE];
        strncpy(tmp, userinit, sizeof tmp - 1); tmp[sizeof tmp - 1] = '\0';
        for (char *p = strtok(tmp, ","); p; p = strtok(NULL, ",")) {
            trim_ws(p);
            if (*p) tokens++;
        }
        if (tokens > 1) deviates = true;

        if (deviates) {
            char target[SC_MAX_PATH];
            extract_target(userinit, target, sizeof target);
            bus_emit(c->bus, "PERSIST.WINLOGON", SEV_HIGH, 85,
                     ACT_REVIEW, 0, target[0] ? target : userinit,
                     "Winlogon Userinit altered",
                     "HKLM\\%s Userinit = \"%s\" "
                     "(expected single system32\\userinit.exe)",
                     WL, userinit);
        }
    }
}

/* ------------------------------------------------------------------ *
 *  AppInit_DLLs
 * ------------------------------------------------------------------ */

static void scan_appinit(ScanCtx *c)
{
    static const char *paths[] = {
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        char val[SC_MAX_CMDLINE];
        if (!read_reg_sz(HKEY_LOCAL_MACHINE, paths[i], "AppInit_DLLs",
                         val, sizeof val))
            continue;
        trim_ws(val);
        if (val[0] == '\0') continue;     /* empty is the clean state */

        /* AppInit_DLLs may list multiple DLLs (space/comma separated). */
        char tmp[SC_MAX_CMDLINE];
        strncpy(tmp, val, sizeof tmp - 1); tmp[sizeof tmp - 1] = '\0';
        bool emitted_any = false;
        for (char *p = strtok(tmp, " ,;\t"); p; p = strtok(NULL, " ,;\t")) {
            char target[SC_MAX_PATH];
            extract_target(p, target, sizeof target);
            if (target[0] == '\0') continue;
            if (allowlist_match(target)) continue;
            emitted_any = true;
            char reason[128];
            target_is_risky(target, reason, sizeof reason, NULL);
            bus_emit(c->bus, "PERSIST.APPINIT", SEV_HIGH, 88,
                     ACT_REVIEW, 0, target,
                     "AppInit_DLLs injection DLL configured",
                     "HKLM\\%s AppInit_DLLs = \"%s\" -> %s%s%s%s",
                     paths[i], val, target,
                     reason[0] ? " [" : "", reason[0] ? reason : "",
                     reason[0] ? "]" : "");
        }
        if (!emitted_any) {
            /* Non-empty but unparsable -- still report the raw value. */
            bus_emit(c->bus, "PERSIST.APPINIT", SEV_HIGH, 80,
                     ACT_REVIEW, 0, val,
                     "AppInit_DLLs non-empty",
                     "HKLM\\%s AppInit_DLLs = \"%s\"", paths[i], val);
        }
    }
}

/* ------------------------------------------------------------------ *
 *  Image File Execution Options -- Debugger hijack
 * ------------------------------------------------------------------ */

static void scan_ifeo(ScanCtx *c)
{
    static const char *IFEO =
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Image File Execution Options";

    HKEY hk;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, IFEO, 0,
                            KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hk);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied reading IFEO");
        return;
    }

    DWORD idx = 0;
    for (;;) {
        char  sub[SC_NAME_LEN];
        DWORD slen = sizeof sub;
        LONG e = RegEnumKeyExA(hk, idx, sub, &slen, NULL, NULL, NULL, NULL);
        if (e == ERROR_NO_MORE_ITEMS) break;
        idx++;
        if (e != ERROR_SUCCESS) continue;

        char full[SC_MAX_PATH];
        snprintf(full, sizeof full, "%s\\%s", IFEO, sub);

        char dbg[SC_MAX_CMDLINE];
        if (!read_reg_sz(HKEY_LOCAL_MACHINE, full, "Debugger", dbg, sizeof dbg))
            continue;
        trim_ws(dbg);
        if (dbg[0] == '\0') continue;

        char target[SC_MAX_PATH];
        extract_target(dbg, target, sizeof target);
        if (allowlist_match(target)) continue;

        char reason[128];
        target_is_risky(target, reason, sizeof reason, NULL);
        bus_emit(c->bus, "PERSIST.IFEO", SEV_HIGH, 90,
                 ACT_REVIEW, 0, target[0] ? target : dbg,
                 "Image File Execution Options Debugger hijack",
                 "HKLM\\%s Debugger = \"%s\" (launches on %s)%s%s%s",
                 full, dbg, sub,
                 reason[0] ? " [" : "", reason[0] ? reason : "",
                 reason[0] ? "]" : "");
    }
    RegCloseKey(hk);
}

/* ------------------------------------------------------------------ *
 *  Startup folders  (.lnk resolution via IShellLink, best effort)
 * ------------------------------------------------------------------ */

/* Resolve a .lnk to its target path. Returns true on success.
 * Assumes COM is already initialized on this thread. */
static bool resolve_lnk(const wchar_t *lnk_w, char *out, size_t cap)
{
    bool ok = false;
    IShellLinkW *psl = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                                  &IID_IShellLinkW, (void **)&psl);
    if (FAILED(hr) || !psl) return false;

    IPersistFile *ppf = NULL;
    hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void **)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        hr = ppf->lpVtbl->Load(ppf, lnk_w, STGM_READ);
        if (SUCCEEDED(hr)) {
            wchar_t pathw[SC_MAX_PATH];
            pathw[0] = L'\0';
            hr = psl->lpVtbl->GetPath(psl, pathw, SC_MAX_PATH, NULL,
                                      SLGP_RAWPATH);
            if (SUCCEEDED(hr) && pathw[0]) {
                if (wide_to_utf8(pathw, out, cap) > 0)
                    ok = true;
            }
        }
        ppf->lpVtbl->Release(ppf);
    }
    psl->lpVtbl->Release(psl);
    return ok;
}

static void scan_startup_dir(ScanCtx *c, const wchar_t *dirw,
                             const char *label, bool com_ok)
{
    char diru[SC_MAX_PATH];
    if (wide_to_utf8(dirw, diru, sizeof diru) == 0) return;

    wchar_t pattern[SC_MAX_PATH];
    _snwprintf(pattern, SC_MAX_PATH, L"%s\\*", dirw);
    pattern[SC_MAX_PATH - 1] = L'\0';

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;   /* missing dir is normal */

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (fd.cFileName[0] == L'.') continue;
        /* Ignore the usual desktop.ini noise. */
        if (_wcsicmp(fd.cFileName, L"desktop.ini") == 0) continue;

        wchar_t fullw[SC_MAX_PATH];
        _snwprintf(fullw, SC_MAX_PATH, L"%s\\%s", dirw, fd.cFileName);
        fullw[SC_MAX_PATH - 1] = L'\0';

        char fileu[SC_MAX_PATH];
        if (wide_to_utf8(fullw, fileu, sizeof fileu) == 0) continue;

        if (allowlist_match(fileu)) continue;

        char target[SC_MAX_PATH];
        target[0] = '\0';
        bool resolved = false;
        if (com_ok && str_iendswith(fileu, ".lnk")) {
            resolved = resolve_lnk(fullw, target, sizeof target);
        }
        if (!resolved) {
            /* Either not a shortcut, or COM resolution failed: flag the
             * startup file itself as the target. */
            strncpy(target, fileu, sizeof target - 1);
            target[sizeof target - 1] = '\0';
        }
        if (allowlist_match(target)) continue;

        char reason[128];
        bool risky = false;
        /* Only sign-check things that look like real binaries on disk. */
        if (GetFileAttributesA(target) != INVALID_FILE_ATTRIBUTES)
            risky = target_is_risky(target, reason, sizeof reason, NULL);
        else
            reason[0] = '\0';

        bus_emit(c->bus, "PERSIST.STARTUP_FOLDER",
                 risky ? SEV_MED : SEV_LOW,
                 risky ? 65 : 40,
                 ACT_REVIEW, 0, target,
                 "Startup folder autostart item",
                 "%s: %s -> %s%s%s%s%s", label, fileu,
                 target,
                 resolved ? "" : (str_iendswith(fileu, ".lnk")
                                  ? " (unresolved .lnk)" : ""),
                 risky ? " [" : "", risky ? reason : "",
                 risky ? "]" : "");
    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

static void scan_startup_folders(ScanCtx *c, bool com_ok)
{
    wchar_t pathw[SC_MAX_PATH];

    /* Per-user Startup */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL,
                                   SHGFP_TYPE_CURRENT, pathw)))
        scan_startup_dir(c, pathw, "User Startup", com_ok);

    /* All-users Startup */
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL,
                                   SHGFP_TYPE_CURRENT, pathw)))
        scan_startup_dir(c, pathw, "Common Startup", com_ok);
}

/* ------------------------------------------------------------------ *
 *  Scheduled tasks  (System32\Tasks XML walk)
 * ------------------------------------------------------------------ */

/* Pull the text between <tag> and </tag> from a UTF-8 XML buffer.
 * Returns true if found (non-empty trimmed value written to out). */
static bool xml_extract(const char *xml, const char *tag,
                        char *out, size_t cap)
{
    char open[64], close[64];
    snprintf(open, sizeof open, "<%s>", tag);
    snprintf(close, sizeof close, "</%s>", tag);
    const char *s = strstr(xml, open);
    if (!s) return false;
    s += strlen(open);
    const char *e = strstr(s, close);
    if (!e) return false;
    size_t len = (size_t)(e - s);
    if (len >= cap) len = cap - 1;
    memcpy(out, s, len);
    out[len] = '\0';
    trim_ws(out);
    return out[0] != '\0';
}

static void scan_task_file(ScanCtx *c, const wchar_t *fullw,
                           const char *rel)
{
    HANDLE h = CreateFileW(fullw, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    DWORD size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > (1u << 20)) {
        CloseHandle(h);
        return;
    }

    /* Task XML is UTF-16LE (sometimes BOM). Read raw then convert. */
    char *raw = (char *)malloc(size + 2);
    if (!raw) { CloseHandle(h); return; }
    DWORD got = 0;
    BOOL  ok  = ReadFile(h, raw, size, &got, NULL);
    CloseHandle(h);
    if (!ok) { free(raw); return; }
    raw[got] = '\0';
    raw[got + 1] = '\0';

    char  utf8[1 << 16];
    const char *xml;
    /* Detect UTF-16LE BOM (FF FE) or heuristic (NUL in low bytes). */
    bool is_utf16 = (got >= 2 && (unsigned char)raw[0] == 0xFF &&
                                  (unsigned char)raw[1] == 0xFE);
    if (!is_utf16 && got >= 2 && raw[1] == '\0') is_utf16 = true;

    if (is_utf16) {
        const wchar_t *w = (const wchar_t *)raw;
        if (raw[0] == (char)0xFF) w = (const wchar_t *)(raw + 2); /* skip BOM */
        size_t n = wide_to_utf8(w, utf8, sizeof utf8);
        if (n == 0) { free(raw); return; }
        xml = utf8;
    } else {
        /* already UTF-8/ASCII; skip a UTF-8 BOM if present */
        xml = raw;
        if (got >= 3 && (unsigned char)raw[0] == 0xEF &&
            (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF)
            xml = raw + 3;
    }

    char command[SC_MAX_PATH];
    char args[SC_MAX_CMDLINE];
    bool have_cmd = xml_extract(xml, "Command", command, sizeof command);
    bool have_arg = xml_extract(xml, "Arguments", args, sizeof args);
    free(raw);

    if (!have_cmd) return;     /* nothing actionable to resolve */

    char target[SC_MAX_PATH];
    extract_target(command, target, sizeof target);
    if (target[0] == '\0') {
        strncpy(target, command, sizeof target - 1);
        target[sizeof target - 1] = '\0';
    }
    if (allowlist_match(target) || allowlist_match(rel)) return;

    /* Severity bump conditions:
     *  - command resolves into a user-writable path, OR
     *  - command is powershell/mshta with encoded/obfuscated args. */
    bool risky = false;
    char reason[160]; reason[0] = '\0';

    if (path_is_user_writable(target)) {
        risky = true;
        snprintf(reason, sizeof reason, "user-writable target");
    }

    char tlow[SC_MAX_PATH];
    strncpy(tlow, target, sizeof tlow - 1); tlow[sizeof tlow - 1] = '\0';
    str_lower(tlow);
    bool is_ps   = strstr(tlow, "powershell") != NULL;
    bool is_mshta= strstr(tlow, "mshta")      != NULL;
    if ((is_ps || is_mshta) && have_arg) {
        char alow[SC_MAX_CMDLINE];
        strncpy(alow, args, sizeof alow - 1); alow[sizeof alow - 1] = '\0';
        str_lower(alow);
        if (strstr(alow, "-enc") || strstr(alow, "encodedcommand") ||
            strstr(alow, "-e ")  || strstr(alow, "frombase64") ||
            strstr(alow, "iex")  || strstr(alow, "downloadstring") ||
            strstr(alow, "javascript:") || strstr(alow, "vbscript:")) {
            risky = true;
            if (reason[0])
                snprintf(reason + strlen(reason),
                         sizeof reason - strlen(reason),
                         ", encoded %s", is_ps ? "powershell" : "mshta");
            else
                snprintf(reason, sizeof reason, "encoded %s",
                         is_ps ? "powershell" : "mshta");
        }
    }

    bus_emit(c->bus, "PERSIST.TASK",
             risky ? SEV_MED : SEV_LOW,
             risky ? 65 : 40,
             ACT_REVIEW, 0, target,
             "Scheduled task autostart",
             "Task %s: Command=\"%s\"%s%s%s%s", rel, command,
             have_arg ? " Arguments=\"" : "",
             have_arg ? args : "",
             have_arg ? "\"" : "",
             reason[0] ? reason : "");
}

static void walk_tasks(ScanCtx *c, const wchar_t *dirw, const char *relbase,
                       int depth)
{
    if (depth > 12) return;   /* defensive recursion bound */

    wchar_t pattern[SC_MAX_PATH];
    _snwprintf(pattern, SC_MAX_PATH, L"%s\\*", dirw);
    pattern[SC_MAX_PATH - 1] = L'\0';

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied enumerating Tasks");
        return;
    }

    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == L'\0' ||
             (fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0')))
            continue;

        wchar_t childw[SC_MAX_PATH];
        _snwprintf(childw, SC_MAX_PATH, L"%s\\%s", dirw, fd.cFileName);
        childw[SC_MAX_PATH - 1] = L'\0';

        char childname[SC_NAME_LEN];
        wide_to_utf8(fd.cFileName, childname, sizeof childname);

        char rel[SC_MAX_PATH];
        snprintf(rel, sizeof rel, "%s\\%s", relbase, childname);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk_tasks(c, childw, rel, depth + 1);
        } else {
            scan_task_file(c, childw, rel);
        }
    } while (FindNextFileW(h, &fd));

    FindClose(h);
}

static void scan_scheduled_tasks(ScanCtx *c)
{
    wchar_t windir[SC_MAX_PATH];
    UINT n = GetWindowsDirectoryW(windir, SC_MAX_PATH);
    if (n == 0 || n >= SC_MAX_PATH) return;

    wchar_t tasksw[SC_MAX_PATH];
    _snwprintf(tasksw, SC_MAX_PATH, L"%s\\System32\\Tasks", windir);
    tasksw[SC_MAX_PATH - 1] = L'\0';

    walk_tasks(c, tasksw, "\\", 0);
}

/* ------------------------------------------------------------------ *
 *  WMI event subscription persistence
 * ------------------------------------------------------------------ *
 *
 * GUIDs defined locally so the module does not require wbemuuid.lib under
 * MinGW. If you DO link wbemuuid, these definitions are still safe (one
 * definition; the linker resolves to ours). */

/* Define real storage (not just an extern decl) so the module links without
 * wbemuuid.lib. These values are the stable, documented WMI class IDs. */
static const GUID SC_CLSID_WbemLocator = {
    0x4590f811, 0x1d3a, 0x11d0,
    { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
static const GUID SC_IID_IWbemLocator = {
    0xdc12a687, 0x737f, 0x11cf,
    { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
#define WBEM_CLSID SC_CLSID_WbemLocator
#define WBEM_IID   SC_IID_IWbemLocator

/* Run one WQL query against an already-connected namespace and, for each
 * row, emit a PERSIST.WMI_SUB finding. Returns the number of rows seen. */
static int wmi_query_emit(ScanCtx *c, IWbemServices *svc, const wchar_t *wql,
                          const char *kind)
{
    int rows = 0;
    IEnumWbemClassObject *en = NULL;
    BSTR lang = SysAllocString(L"WQL");
    BSTR q    = SysAllocString(wql);
    if (!lang || !q) {
        if (lang) SysFreeString(lang);
        if (q) SysFreeString(q);
        return 0;
    }

    HRESULT hr = svc->lpVtbl->ExecQuery(
        svc, lang, q,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &en);
    SysFreeString(lang);
    SysFreeString(q);
    if (FAILED(hr) || !en) return 0;

    for (;;) {
        IWbemClassObject *obj = NULL;
        ULONG ret = 0;
        hr = en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &ret);
        if (hr != WBEM_S_NO_ERROR || ret == 0 || !obj) break;
        rows++;

        /* Best-effort: pull Name + a command-ish property for evidence. */
        char namebuf[SC_NAME_LEN]   = "";
        char cmdbuf[SC_MAX_CMDLINE] = "";
        const wchar_t *props[] = { L"Name", NULL };
        const wchar_t *cmds[]  = { L"CommandLineTemplate", L"ExecutablePath",
                                   L"ScriptText", L"ScriptFileName",
                                   L"Query", NULL };

        for (int i = 0; props[i]; i++) {
            VARIANT v; VariantInit(&v);
            if (SUCCEEDED(obj->lpVtbl->Get(obj, props[i], 0, &v, NULL, NULL))
                && v.vt == VT_BSTR && v.bstrVal) {
                wide_to_utf8(v.bstrVal, namebuf, sizeof namebuf);
            }
            VariantClear(&v);
            if (namebuf[0]) break;
        }
        for (int i = 0; cmds[i]; i++) {
            VARIANT v; VariantInit(&v);
            if (SUCCEEDED(obj->lpVtbl->Get(obj, cmds[i], 0, &v, NULL, NULL))
                && v.vt == VT_BSTR && v.bstrVal) {
                wide_to_utf8(v.bstrVal, cmdbuf, sizeof cmdbuf);
            }
            VariantClear(&v);
            if (cmdbuf[0]) break;
        }

        char target[SC_MAX_PATH];
        if (cmdbuf[0]) extract_target(cmdbuf, target, sizeof target);
        else { strncpy(target, namebuf, sizeof target - 1);
               target[sizeof target - 1] = '\0'; }

        if (!allowlist_match(target)) {
            bus_emit(c->bus, "PERSIST.WMI_SUB", SEV_HIGH, 85,
                     ACT_REVIEW, 0, target[0] ? target : namebuf,
                     "WMI event subscription persistence",
                     "root\\subscription %s Name=\"%s\"%s%s", kind,
                     namebuf[0] ? namebuf : "(unnamed)",
                     cmdbuf[0] ? " -> " : "",
                     cmdbuf[0] ? cmdbuf : "");
        }
        obj->lpVtbl->Release(obj);
    }
    en->lpVtbl->Release(en);
    return rows;
}

/* Returns true if it actually connected and queried; false (with a
 * ctx_note_limit already recorded) on COM/WMI failure. */
static void scan_wmi_subscriptions(ScanCtx *c, bool com_ok)
{
    if (!com_ok) {
        ctx_note_limit(c, "persist: WMI check skipped (COM init failed)");
        return;
    }

    IWbemLocator *loc = NULL;
    HRESULT hr = CoCreateInstance(&WBEM_CLSID, NULL, CLSCTX_INPROC_SERVER,
                                  &WBEM_IID, (void **)&loc);
    if (FAILED(hr) || !loc) {
        ctx_note_limit(c, "persist: WMI locator unavailable (0x%08lx)",
                       (unsigned long)hr);
        return;
    }

    IWbemServices *svc = NULL;
    BSTR ns = SysAllocString(L"ROOT\\Subscription");
    if (!ns) { loc->lpVtbl->Release(loc); return; }

    hr = loc->lpVtbl->ConnectServer(loc, ns, NULL, NULL, NULL, 0, NULL, NULL,
                                    &svc);
    SysFreeString(ns);
    if (FAILED(hr) || !svc) {
        if (hr == E_ACCESSDENIED || (unsigned long)hr == 0x80041003ul)
            ctx_note_limit(c, "persist: WMI ROOT\\Subscription needs admin");
        else
            ctx_note_limit(c, "persist: WMI ConnectServer failed (0x%08lx)",
                           (unsigned long)hr);
        loc->lpVtbl->Release(loc);
        return;
    }

    /* Best-effort proxy security blanket; ignore failure. */
    CoSetProxyBlanket((IUnknown *)svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                      NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                      NULL, EOAC_NONE);

    /* Consumers are the actionable signal (a filter alone does nothing). */
    wmi_query_emit(c, svc,
        L"SELECT * FROM CommandLineEventConsumer", "CommandLineEventConsumer");
    wmi_query_emit(c, svc,
        L"SELECT * FROM ActiveScriptEventConsumer", "ActiveScriptEventConsumer");
    /* Bindings tie a filter to a consumer -- presence corroborates. */
    wmi_query_emit(c, svc,
        L"SELECT * FROM __FilterToConsumerBinding", "__FilterToConsumerBinding");

    svc->lpVtbl->Release(svc);
    loc->lpVtbl->Release(loc);
}

/* ------------------------------------------------------------------ *
 *  COM hijack -- HKCU CLSID InprocServer32 shadowing HKLM
 * ------------------------------------------------------------------ */

static void scan_com_hijack(ScanCtx *c)
{
    /* A small set of frequently-abused / commonly-loaded CLSIDs. If HKCU
     * defines an InprocServer32 for one of these (HKCU wins over HKLM in the
     * search order), that's a classic per-user COM hijack. */
    static const char *clsids[] = {
        "{0358b920-0ac7-461f-98f4-58e32cd89148}", /* ShellWindows-ish */
        "{42aedc87-2188-41fd-b9a3-0c966feabec1}", /* MruPidlList */
        "{fbeb8a05-beee-4442-804e-409d6c4515e9}", /* CLSID often abused */
        "{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}", /* DragDropHelper-ish */
        "{F82B4EF1-93A9-4DDE-8015-F7950A1A6E31}", /* shell namespace */
        NULL
    };

    for (int i = 0; clsids[i]; i++) {
        char sub[SC_MAX_PATH];
        snprintf(sub, sizeof sub,
                 "Software\\Classes\\CLSID\\%s\\InprocServer32", clsids[i]);

        char dll[SC_MAX_CMDLINE];
        if (!read_reg_sz(HKEY_CURRENT_USER, sub, NULL, dll, sizeof dll) ||
            dll[0] == '\0')
            continue;     /* no per-user override -> not hijacked */

        char target[SC_MAX_PATH];
        extract_target(dll, target, sizeof target);
        if (target[0] == '\0') {
            strncpy(target, dll, sizeof target - 1);
            target[sizeof target - 1] = '\0';
        }
        if (allowlist_match(target)) continue;

        char reason[128];
        target_is_risky(target, reason, sizeof reason, NULL);
        bus_emit(c->bus, "PERSIST.COM_HIJACK", SEV_MED, 70,
                 ACT_REVIEW, 0, target,
                 "Per-user COM server hijack (HKCU shadows HKLM)",
                 "HKCU\\%s = \"%s\"%s%s%s", sub, dll,
                 reason[0] ? " [" : "", reason[0] ? reason : "",
                 reason[0] ? "]" : "");
    }
}

/* ------------------------------------------------------------------ *
 *  entry point
 * ------------------------------------------------------------------ */

void scan_persist(ScanCtx *c)
{
    if (!c || !c->bus) return;

    /* COM is needed for .lnk resolution and WMI. Initialize once for the
     * whole scan; tolerate "already initialized" from another component. */
    bool com_inited_here = false;
    bool com_ok = false;
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr == S_OK) {
        com_inited_here = true;
        com_ok = true;
    } else if (hr == S_FALSE) {
        /* already initialized on this thread by us -- still balance it */
        com_inited_here = true;
        com_ok = true;
    } else if (hr == RPC_E_CHANGED_MODE) {
        /* COM already up in a different apartment model -- usable, but we
         * must NOT call CoUninitialize for an init we didn't perform. */
        com_ok = true;
        com_inited_here = false;
    } else {
        com_ok = false;
        ctx_note_limit(c, "persist: CoInitializeEx failed (0x%08lx)",
                       (unsigned long)hr);
    }

    /* Registry-based checks (no COM needed). */
    scan_run_keys(c);
    scan_winlogon(c);
    scan_appinit(c);
    scan_ifeo(c);
    scan_com_hijack(c);

    /* Filesystem-based checks. */
    scan_startup_folders(c, com_ok);
    scan_scheduled_tasks(c);

    /* WMI (COM). Never fatal: notes a limit and continues on failure. */
    scan_wmi_subscriptions(c, com_ok);

    if (com_inited_here)
        CoUninitialize();
}
