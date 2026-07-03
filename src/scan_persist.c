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

static const char *root_label(HKEY root)
{
    if (root == HKEY_LOCAL_MACHINE) return "HKLM";
    if (root == HKEY_CURRENT_USER)  return "HKCU";
    return "HK?";
}

static bool read_reg_dword(HKEY root, const char *subkey, const char *value,
                           DWORD *out)
{
    if (out) *out = 0;
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_QUERY_VALUE, &hk)
        != ERROR_SUCCESS)
        return false;
    DWORD data = 0, dlen = sizeof data, type = 0;
    LONG e = RegQueryValueExA(hk, value, NULL, &type, (BYTE *)&data, &dlen);
    RegCloseKey(hk);
    if (e != ERROR_SUCCESS || type != REG_DWORD || dlen != sizeof data)
        return false;
    if (out) *out = data;
    return true;
}

static bool reg_key_exists(HKEY root, const char *subkey)
{
    HKEY hk;
    LONG e = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk);
    if (e == ERROR_SUCCESS) {
        RegCloseKey(hk);
        return true;
    }
    return false;
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
 *  AppCertDlls  (loaded into every process that calls a Win32 process-
 *  creation API via the Application Certification callback)  T1546.009
 * ------------------------------------------------------------------ */

static void scan_appcert(ScanCtx *c)
{
    static const char *APPCERT =
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls";

    HKEY hk;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, APPCERT, 0,
                            KEY_READ | KEY_QUERY_VALUE, &hk);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied reading AppCertDlls");
        return;   /* key absent on a clean system -> normal */
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
        data[(dlen < sizeof data) ? dlen : sizeof data - 1] = '\0';
        data[sizeof data - 1] = '\0';

        char raw[SC_MAX_CMDLINE];
        if (type == REG_EXPAND_SZ)
            expand_env((const char *)data, raw, sizeof raw);
        else { strncpy(raw, (const char *)data, sizeof raw - 1);
               raw[sizeof raw - 1] = '\0'; }
        trim_ws(raw);
        if (raw[0] == '\0') continue;

        char target[SC_MAX_PATH];
        extract_target(raw, target, sizeof target);
        if (target[0] == '\0') {
            strncpy(target, raw, sizeof target - 1);
            target[sizeof target - 1] = '\0';
        }
        if (allowlist_match(target) || allowlist_match(name)) continue;

        char reason[128];
        bool risky = target_is_risky(target, reason, sizeof reason, NULL);
        int conf = risky ? 90 : 80;

        bus_emit(c->bus, "PERSIST.APPCERT", SEV_HIGH, conf,
                 ACT_REVIEW, 0, target,
                 "AppCertDlls injection DLL configured",
                 "HKLM\\%s value \"%s\" = \"%s\" -> %s%s%s%s",
                 APPCERT, name, raw, target,
                 reason[0] ? " [" : "", reason[0] ? reason : "",
                 reason[0] ? "]" : "");
    }
    RegCloseKey(hk);
}

/* ------------------------------------------------------------------ *
 *  LSA security/authentication/notification providers (SSP/AP DLLs
 *  loaded by LSASS)  T1547.005 -- credential-theft persistence.
 * ------------------------------------------------------------------ */

/* Known-good inbox LSA provider base names (lower-case, no extension). When
 * one of these is signed and lives under System32 we suppress it as noise. */
static bool is_inbox_lsa_provider(const char *base_lower)
{
    static const char *good[] = {
        "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u",
        "cloudap", "negoexts", "ctxauth", "livessp", NULL
    };
    for (int i = 0; good[i]; i++)
        if (strcmp(base_lower, good[i]) == 0) return true;
    return false;
}

static void lsa_check_provider(ScanCtx *c, const char *valuename,
                               const char *entry)
{
    /* entry is a base name (no path/extension), e.g. "msv1_0". Resolve to
     * %WINDIR%\System32\<name>.dll for sign/path checking. */
    char base[SC_NAME_LEN];
    strncpy(base, entry, sizeof base - 1);
    base[sizeof base - 1] = '\0';
    trim_ws(base);
    /* strip surrounding double-quotes some entries carry, then re-trim */
    if (base[0] == '"') memmove(base, base + 1, strlen(base));
    { size_t bq = strlen(base); if (bq && base[bq - 1] == '"') base[bq - 1] = '\0'; }
    trim_ws(base);
    if (base[0] == '\0') return;
    /* require a plausible module name: at least one alphanumeric char, else
     * it is a stray separator/quote in the REG_MULTI_SZ, not a provider. */
    {
        bool alnum = false;
        for (const char *q = base; *q; q++)
            if ((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
                (*q >= '0' && *q <= '9')) { alnum = true; break; }
        if (!alnum) return;
    }

    /* Some entries carry a path or extension; reduce to the leaf for the
     * inbox comparison, but build the resolved path from the bare name. */
    char baselow[SC_NAME_LEN];
    strncpy(baselow, base, sizeof baselow - 1);
    baselow[sizeof baselow - 1] = '\0';
    str_lower(baselow);
    /* strip a trailing .dll if present for the known-good comparison */
    size_t bl = strlen(baselow);
    if (bl > 4 && strcmp(baselow + bl - 4, ".dll") == 0)
        baselow[bl - 4] = '\0';

    char windir[MAX_PATH];
    UINT wn = GetWindowsDirectoryA(windir, sizeof windir);
    if (wn == 0 || wn >= sizeof windir) return;

    char target[SC_MAX_PATH];
    /* If entry already looks like a path, use it as-is; else resolve. */
    if (strchr(base, '\\') || strchr(base, '/')) {
        expand_env(base, target, sizeof target);
    } else {
        snprintf(target, sizeof target, "%s\\System32\\%s.dll",
                 windir, base);
    }

    if (allowlist_match(target) || allowlist_match(base)) return;

    SignVerdict v = SIGN_UNKNOWN;
    char reason[128];
    bool risky = target_is_risky(target, reason, sizeof reason, &v);

    bool signed_ms = (v == SIGN_SIGNED_MS);
    bool in_system32 = (path_classify(target) == PATHLOC_SYSTEM);

    /* A validly MS-signed provider under System32 is the clean state. Windows
     * ships many beyond any fixed name list (scecli, rassfm, ...), so suppress
     * on signature+location, not on a hardcoded set -- that set only refines
     * the note. This is what keeps a clean LSASS quiet. */
    if (signed_ms && in_system32) {
        const char *note = is_inbox_lsa_provider(baselow) ? "inbox/signed"
                                                          : "signed/system32";
        bus_emit(c->bus, "PERSIST.LSA_PROVIDER", SEV_LOW, 30,
                 ACT_REVIEW, 0, target,
                 "LSA provider (signed, System32)",
                 "HKLM\\...\\Lsa %s entry \"%s\" -> %s [%s]",
                 valuename, base, target, note);
        return;
    }

    /* Unexpected / unsigned / user-writable LSA provider: credential-theft
     * persistence. CRIT when unsigned or user-writable. */
    bool unsigned_or_writable = risky || v == SIGN_UNSIGNED ||
                                v == SIGN_INVALID;
    Severity sev = unsigned_or_writable ? SEV_CRIT : SEV_HIGH;

    bus_emit(c->bus, "PERSIST.LSA_PROVIDER", sev, 80,
             ACT_REVIEW, 0, target,
             "Unexpected LSA security provider (LSASS DLL)",
             "HKLM\\...\\Lsa %s entry \"%s\" -> %s%s%s%s",
             valuename, base, target,
             reason[0] ? " [" : "", reason[0] ? reason : "",
             reason[0] ? "]" : "");
}

static void scan_lsa_providers(ScanCtx *c)
{
    static const char *LSA = "SYSTEM\\CurrentControlSet\\Control\\Lsa";
    static const char *values[] = {
        "Security Packages", "Authentication Packages",
        "Notification Packages", NULL
    };

    HKEY hk;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, LSA, 0,
                            KEY_READ | KEY_QUERY_VALUE, &hk);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied reading Lsa");
        return;
    }

    for (int vi = 0; values[vi]; vi++) {
        BYTE  data[SC_MAX_CMDLINE];
        DWORD dlen = sizeof data;
        DWORD type = 0;
        LONG e = RegQueryValueExA(hk, values[vi], NULL, &type, data, &dlen);
        if (e != ERROR_SUCCESS) continue;
        if (type != REG_MULTI_SZ) continue;
        if (dlen == 0) continue;
        /* Guarantee double-NUL termination within bounds. */
        if (dlen > sizeof data - 2) dlen = sizeof data - 2;
        data[dlen]     = '\0';
        data[dlen + 1] = '\0';

        /* Walk the REG_MULTI_SZ: consecutive NUL-terminated strings, ends
         * with an empty string. */
        const char *p = (const char *)data;
        const char *end = (const char *)data + dlen + 1;
        while (p < end && *p) {
            lsa_check_provider(c, values[vi], p);
            size_t n = strnlen(p, (size_t)(end - p));
            p += n + 1;
        }
    }
    RegCloseKey(hk);
}

/* ------------------------------------------------------------------ *
 *  Image File Execution Options -- Debugger hijack
 * ------------------------------------------------------------------ */

static bool is_accessibility_image(const char *base);

/* SilentProcessExit persistence: under
 * HKLM\...\SilentProcessExit\<image>, a MonitorProcess value (paired with
 * GlobalFlag/ReportingMode) runs a binary when <image> exits (T1546.012-ish
 * execution-on-exit). Enumerate the key and flag any MonitorProcess. */
static void scan_silent_exit(ScanCtx *c)
{
    static const char *SPE =
        "Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit";

    HKEY hk;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SPE, 0,
                            KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hk);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied reading SilentProcessExit");
        return;   /* ERROR_FILE_NOT_FOUND is normal (key absent on clean) */
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
        snprintf(full, sizeof full, "%s\\%s", SPE, sub);

        char mon[SC_MAX_CMDLINE];
        if (!read_reg_sz(HKEY_LOCAL_MACHINE, full, "MonitorProcess",
                         mon, sizeof mon))
            continue;
        trim_ws(mon);
        if (mon[0] == '\0') continue;

        char target[SC_MAX_PATH];
        extract_target(mon, target, sizeof target);
        if (target[0] == '\0') {
            strncpy(target, mon, sizeof target - 1);
            target[sizeof target - 1] = '\0';
        }
        if (allowlist_match(target) || allowlist_match(sub)) continue;

        char reason[128];
        bool risky = target_is_risky(target, reason, sizeof reason, NULL);

        /* Monitoring an accessibility image on exit is as bad as the IFEO
         * variant -- treat as CRIT. */
        bool is_acc = is_accessibility_image(sub);
        Severity sev = is_acc ? SEV_CRIT : SEV_HIGH;
        int conf = 80;
        if (risky && conf < 90) conf = 90;
        if (is_acc && conf < 90) conf = 90;

        bus_emit(c->bus, "PERSIST.SILENT_EXIT", sev, conf,
                 ACT_REVIEW, 0, target,
                 "SilentProcessExit MonitorProcess persistence",
                 "HKLM\\%s MonitorProcess = \"%s\" (runs when %s exits)%s%s%s",
                 full, mon, sub,
                 (risky || is_acc) ? " [" : "",
                 reason[0] ? reason : (is_acc ? "accessibility image" : ""),
                 (risky || is_acc) ? "]" : "");
    }
    RegCloseKey(hk);
}

/* True (case-insensitive) when base is a Windows accessibility binary that is
 * a classic sticky-keys / utilman backdoor target. base may be a bare image
 * name (IFEO subkey) -- compared against the leaf name. */
static bool is_accessibility_image(const char *base)
{
    static const char *acc[] = {
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe",
        "narrator.exe", "displayswitch.exe", "atbroker.exe", NULL
    };
    /* reduce to leaf name in case a path slipped in */
    char leaf[SC_NAME_LEN];
    base_name(base, leaf, sizeof leaf);
    if (leaf[0] == '\0') {
        strncpy(leaf, base, sizeof leaf - 1);
        leaf[sizeof leaf - 1] = '\0';
    }
    str_lower(leaf);
    for (int i = 0; acc[i]; i++)
        if (strcmp(leaf, acc[i]) == 0) return true;
    return false;
}

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

        /* A Debugger on an accessibility binary is the classic
         * sticky-keys / utilman backdoor (T1546.008) -- near-zero FP. */
        if (is_accessibility_image(sub)) {
            bus_emit(c->bus, "PERSIST.IFEO_ACCESSIBILITY", SEV_CRIT, 90,
                     ACT_REVIEW, 0, target[0] ? target : dbg,
                     "Accessibility binary IFEO Debugger backdoor",
                     "HKLM\\%s Debugger = \"%s\" (hijacks accessibility "
                     "binary %s)%s%s%s",
                     full, dbg, sub,
                     reason[0] ? " [" : "", reason[0] ? reason : "",
                     reason[0] ? "]" : "");
            continue;
        }

        bus_emit(c->bus, "PERSIST.IFEO", SEV_HIGH, 90,
                 ACT_REVIEW, 0, target[0] ? target : dbg,
                 "Image File Execution Options Debugger hijack",
                 "HKLM\\%s Debugger = \"%s\" (launches on %s)%s%s%s",
                 full, dbg, sub,
                 reason[0] ? " [" : "", reason[0] ? reason : "",
                 reason[0] ? "]" : "");
    }
    RegCloseKey(hk);

    scan_silent_exit(c);
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

/* Produce a sanitized copy of an XML buffer into out[cap]:
 *   - XML comments  <!-- ... -->        are dropped entirely (so a fake
 *     <Command> hidden in a comment never reaches the tag scan).
 *   - CDATA sections <![CDATA[ ... ]]>  are UNWRAPPED -- the literal payload
 *     is kept (so a real command stored in CDATA IS extracted), with any
 *     '<','>','&' inside neutralized to spaces so they can't forge tags.
 * Bounded and crash-safe on truncated/malformed input (unterminated comment
 * or CDATA just consumes to end-of-buffer). Returns the sanitized buffer
 * (always NUL-terminated). */
static void xml_sanitize(const char *xml, char *out, size_t cap)
{
    size_t o = 0;
    if (cap == 0) return;
    const char *p = xml;
    while (*p && o < cap - 1) {
        if (p[0] == '<' && p[1] == '!' && p[2] == '-' && p[3] == '-') {
            /* skip comment up to the closing "-->" (or EOF) */
            p += 4;
            while (*p && !(p[0] == '-' && p[1] == '-' && p[2] == '>')) p++;
            if (*p) p += 3;            /* consume "-->" */
            continue;
        }
        if (strncmp(p, "<![CDATA[", 9) == 0) {
            /* unwrap: copy the inner literal, neutralizing markup chars */
            p += 9;
            while (*p && !(p[0] == ']' && p[1] == ']' && p[2] == '>') &&
                   o < cap - 1) {
                char ch = *p++;
                if (ch == '<' || ch == '>' || ch == '&') ch = ' ';
                out[o++] = ch;
            }
            if (*p) p += 3;            /* consume "]]>" */
            continue;
        }
        out[o++] = *p++;
    }
    out[o] = '\0';
}

static int xml_hexval(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
}

static void xml_unescape_inplace(char *s)
{
    char *r = s;
    char *w = s;
    while (*r) {
        if (*r == '&') {
            if (strncmp(r, "&amp;", 5) == 0)   { *w++ = '&';  r += 5; continue; }
            if (strncmp(r, "&lt;", 4) == 0)    { *w++ = '<';  r += 4; continue; }
            if (strncmp(r, "&gt;", 4) == 0)    { *w++ = '>';  r += 4; continue; }
            if (strncmp(r, "&quot;", 6) == 0)  { *w++ = '"';  r += 6; continue; }
            if (strncmp(r, "&apos;", 6) == 0)  { *w++ = '\''; r += 6; continue; }
            if (r[1] == '#') {
                const char *p = r + 2;
                bool hex = false;
                unsigned long val = 0;
                int digits = 0;
                if (*p == 'x' || *p == 'X') { hex = true; p++; }
                while (*p && *p != ';') {
                    int d = hex ? xml_hexval(*p) :
                                  ((*p >= '0' && *p <= '9') ? *p - '0' : -1);
                    if (d < 0) break;
                    val = hex ? (val * 16u + (unsigned)d)
                              : (val * 10u + (unsigned)d);
                    digits++;
                    p++;
                }
                if (*p == ';' && digits > 0 && val > 0 && val < 0x80) {
                    *w++ = (char)val;
                    r = (char *)(p + 1);
                    continue;
                }
            }
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static bool xml_is_name_end(char ch)
{
    return ch == '>' || ch == '/' || ch == ' ' || ch == '\t' ||
           ch == '\r' || ch == '\n';
}

static bool xml_open_is_self_closing(const char *lt, const char *gt)
{
    const char *p = gt;
    while (p > lt) {
        p--;
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            continue;
        return *p == '/';
    }
    return false;
}

static bool xml_tag_matches_at(const char *name, const char *limit,
                               const char *tag, size_t tlen)
{
    const char *colon = NULL;
    for (const char *r = name; r < limit && *r && !xml_is_name_end(*r); r++) {
        if (*r == ':') colon = r;
    }
    const char *nm = colon ? colon + 1 : name;
    if ((size_t)(limit - nm) < tlen)
        return false;
    return strncmp(nm, tag, tlen) == 0 && xml_is_name_end(nm[tlen]);
}

static bool xml_find_open_limited(const char *start, const char *limit,
                                  const char *tag, const char **body,
                                  const char **after_open, bool *self_closing)
{
    size_t tlen = strlen(tag);
    const char *p = start;
    if (!limit) limit = start + strlen(start);

    while (p && p < limit) {
        p = strchr(p, '<');
        if (!p || p >= limit) break;
        const char *q = p + 1;
        if (q >= limit) break;
        if (*q == '/' || *q == '?' || *q == '!') {
            p = q + 1;
            continue;
        }
        if (xml_tag_matches_at(q, limit, tag, tlen)) {
            const char *gt = strchr(q, '>');
            if (!gt || gt >= limit)
                return false;
            bool closed = xml_open_is_self_closing(p, gt);
            if (body) *body = closed ? gt : gt + 1;
            if (after_open) *after_open = gt + 1;
            if (self_closing) *self_closing = closed;
            return true;
        }
        p = q + 1;
    }
    return false;
}

static const char *xml_find_close_limited(const char *start, const char *limit,
                                          const char *tag)
{
    size_t tlen = strlen(tag);
    const char *p = start;
    if (!limit) limit = start + strlen(start);

    while (p && p < limit) {
        p = strstr(p, "</");
        if (!p || p >= limit) break;
        const char *name = p + 2;
        if (name >= limit) break;
        if (xml_tag_matches_at(name, limit, tag, tlen))
            return p;
        p = name + 1;
    }
    return NULL;
}

static bool xml_find_element_limited(const char *start, const char *limit,
                                     const char *tag, const char **body,
                                     const char **end, const char **next)
{
    const char *b = NULL, *after_open = NULL;
    bool self = false;
    if (!limit) limit = start + strlen(start);
    if (!xml_find_open_limited(start, limit, tag, &b, &after_open, &self))
        return false;
    if (self) {
        if (body) *body = b;
        if (end) *end = b;
        if (next) *next = after_open;
        return true;
    }
    const char *e = xml_find_close_limited(b, limit, tag);
    if (!e)
        return false;
    const char *gt = strchr(e, '>');
    if (!gt || gt >= limit) gt = limit - 1;
    if (body) *body = b;
    if (end) *end = e;
    if (next) *next = gt + 1;
    return true;
}

static bool xml_extract_limited(const char *start, const char *limit,
                                const char *tag, char *out, size_t cap)
{
    const char *s = NULL, *e = NULL, *next = NULL;
    if (cap == 0) return false;
    out[0] = '\0';
    if (!xml_find_element_limited(start, limit, tag, &s, &e, &next))
        return false;
    size_t len = (size_t)(e - s);
    if (len >= cap) len = cap - 1;
    memcpy(out, s, len);
    out[len] = '\0';
    xml_unescape_inplace(out);
    trim_ws(out);
    return out[0] != '\0';
}

static void emit_task_exec(ScanCtx *c, const char *rel,
                           const char *command, const char *args,
                           bool have_arg)
{
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
    bool is_ps    = strstr(tlow, "powershell") != NULL ||
                    strstr(tlow, "pwsh")       != NULL;
    bool is_mshta = strstr(tlow, "mshta")      != NULL;
    if ((is_ps || is_mshta) && have_arg) {
        char alow[SC_MAX_CMDLINE];
        strncpy(alow, args, sizeof alow - 1); alow[sizeof alow - 1] = '\0';
        str_lower(alow);
        if (strstr(alow, "-enc") || strstr(alow, "encodedcommand") ||
            strstr(alow, "-e ")  || strstr(alow, "frombase64") ||
            strstr(alow, "frombase64string") ||
            strstr(alow, "invoke-expression") ||
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

static bool read_com_server(HKEY root, const char *clsid,
                            char *server, size_t scp,
                            char *where, size_t wcap)
{
    static const char *leaves[] = { "InprocServer32", "LocalServer32", NULL };
    static const char *bases[] = {
        "Software\\Classes\\CLSID\\%s\\%s",
        "Software\\Classes\\Wow6432Node\\CLSID\\%s\\%s",
        NULL
    };

    for (int b = 0; bases[b]; b++) {
        for (int l = 0; leaves[l]; l++) {
            char sub[SC_MAX_PATH];
            snprintf(sub, sizeof sub, bases[b], clsid, leaves[l]);
            if (read_reg_sz(root, sub, NULL, server, scp) && server[0]) {
                snprintf(where, wcap, "%s\\%s", root_label(root), sub);
                return true;
            }
        }
    }
    return false;
}

static void emit_task_comhandler(ScanCtx *c, const char *rel,
                                 const char *clsid, const char *data)
{
    if (!clsid || clsid[0] == '\0') return;
    if (allowlist_match(clsid) || allowlist_match(rel)) return;

    char server[SC_MAX_CMDLINE] = "";
    char regwhere[SC_MAX_PATH] = "";
    HKEY server_root = NULL;
    if (read_com_server(HKEY_CURRENT_USER, clsid, server, sizeof server,
                        regwhere, sizeof regwhere)) {
        server_root = HKEY_CURRENT_USER;
    } else if (read_com_server(HKEY_LOCAL_MACHINE, clsid, server, sizeof server,
                               regwhere, sizeof regwhere)) {
        server_root = HKEY_LOCAL_MACHINE;
    }

    char target[SC_MAX_PATH];
    target[0] = '\0';
    if (server[0])
        extract_target(server, target, sizeof target);
    if (target[0] == '\0') {
        strncpy(target, clsid, sizeof target - 1);
        target[sizeof target - 1] = '\0';
    }
    if (allowlist_match(target)) return;

    char reason[160];
    reason[0] = '\0';
    bool risky = false;
    if (server_root == HKEY_CURRENT_USER) {
        risky = true;
        snprintf(reason, sizeof reason, "per-user COM registration");
    }
    if (server[0]) {
        char why[128];
        if (target_is_risky(target, why, sizeof why, NULL) && why[0]) {
            risky = true;
            if (reason[0])
                snprintf(reason + strlen(reason),
                         sizeof reason - strlen(reason),
                         ", %s", why);
            else
                snprintf(reason, sizeof reason, "%s", why);
        }
    }

    bus_emit(c->bus, "PERSIST.TASK_COMHANDLER",
             risky ? SEV_MED : SEV_LOW,
             risky ? 70 : 45,
             ACT_REVIEW, 0, target,
             "Scheduled task COM handler autostart",
             "Task %s: ComHandler ClassId=\"%s\"%s%s%s%s%s%s%s%s%s",
             rel, clsid,
             server[0] ? " Server=\"" : "",
             server[0] ? server : "",
             server[0] ? "\"" : "",
             data && data[0] ? " Data=\"" : "",
             data && data[0] ? data : "",
             data && data[0] ? "\"" : "",
             reason[0] ? " [" : "",
             reason[0] ? reason : "",
             reason[0] ? "]" : "");
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

    char *clean = (char *)malloc(1 << 16);
    if (!clean) { free(raw); return; }
    xml_sanitize(xml, clean, 1 << 16);
    free(raw);

    int emitted_exec = 0;
    const char *cursor = clean;
    for (int guard = 0; guard < 128; guard++) {
        const char *body = NULL, *end = NULL, *next = NULL;
        if (!xml_find_element_limited(cursor, NULL, "Exec", &body, &end, &next))
            break;

        char command[SC_MAX_PATH];
        char args[SC_MAX_CMDLINE];
        bool have_cmd = xml_extract_limited(body, end, "Command",
                                            command, sizeof command);
        bool have_arg = xml_extract_limited(body, end, "Arguments",
                                            args, sizeof args);
        if (have_cmd) {
            emit_task_exec(c, rel, command, args, have_arg);
            emitted_exec++;
        }
        if (!next || next <= cursor)
            break;
        cursor = next;
    }

    /* Compatibility fallback for unusual task XML that has Command directly
     * under Actions instead of an Exec wrapper. */
    if (emitted_exec == 0) {
        char command[SC_MAX_PATH];
        char args[SC_MAX_CMDLINE];
        bool have_cmd = xml_extract_limited(clean, NULL, "Command",
                                            command, sizeof command);
        bool have_arg = xml_extract_limited(clean, NULL, "Arguments",
                                            args, sizeof args);
        if (have_cmd)
            emit_task_exec(c, rel, command, args, have_arg);
    }

    cursor = clean;
    for (int guard = 0; guard < 128; guard++) {
        const char *body = NULL, *end = NULL, *next = NULL;
        if (!xml_find_element_limited(cursor, NULL, "ComHandler",
                                      &body, &end, &next))
            break;
        char clsid[SC_NAME_LEN];
        char data[SC_MAX_CMDLINE];
        bool have_clsid = xml_extract_limited(body, end, "ClassId",
                                              clsid, sizeof clsid);
        bool have_data = xml_extract_limited(body, end, "Data",
                                             data, sizeof data);
        if (have_clsid)
            emit_task_comhandler(c, rel, clsid, have_data ? data : "");
        if (!next || next <= cursor)
            break;
        cursor = next;
    }

    free(clean);
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
                                   L"Consumer", L"Filter", L"Query", NULL };

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

        if (_stricmp(kind, "__FilterToConsumerBinding") == 0) {
            if (!namebuf[0] && !cmdbuf[0]) {
                obj->lpVtbl->Release(obj);
                continue;
            }
            if (str_icontains(cmdbuf, "NTEventLogEventConsumer") &&
                str_icontains(cmdbuf, "SCM Event Log Consumer")) {
                obj->lpVtbl->Release(obj);
                continue;
            }
        }

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
 *  Services written directly in the registry  (T1543.003)
 * ------------------------------------------------------------------ *
 *
 * scan_service.c only sees what the SCM enumerates (EnumServicesStatusEx).
 * Malware can drop a service straight under
 *   HKLM\SYSTEM\CurrentControlSet\Services\<name>
 * with a malicious ImagePath + Start type. A boot/system-start driver or a
 * service that has not yet been started can be missed or under-inspected by
 * the SCM view. Here we walk the registry side directly. Only genuinely
 * off-profile binaries are emitted, so the thousands of legitimate inbox
 * drivers/services stay quiet.
 */

/* Map a Start REG_DWORD to its canonical name. */
static const char *svc_start_name(DWORD start)
{
    switch (start) {
        case 0:  return "boot";      /* SERVICE_BOOT_START   */
        case 1:  return "system";    /* SERVICE_SYSTEM_START */
        case 2:  return "auto";      /* SERVICE_AUTO_START   */
        case 3:  return "demand";    /* SERVICE_DEMAND_START */
        case 4:  return "disabled";  /* SERVICE_DISABLED     */
        default: return "unknown";
    }
}

/* Resolve a service ImagePath (which uses NT-native conventions) to a real
 * Win32 path for sign/path classification. Handles:
 *   \SystemRoot\System32\drivers\x.sys      -> %WINDIR%\System32\drivers\x.sys
 *   \??\C:\path\x.exe                        -> C:\path\x.exe
 *   system32\drivers\x.sys  (relative)       -> %WINDIR%\System32\drivers\x.sys
 *   "C:\path\x.exe" -args                    -> C:\path\x.exe (via extract_target)
 * Env vars are expanded first.  Writes a bounded result to out[cap]. */
static void resolve_svc_imagepath(const char *raw, char *out, size_t cap)
{
    out[0] = '\0';
    if (cap == 0) return;

    char expanded[SC_MAX_CMDLINE];
    expand_env(raw, expanded, sizeof expanded);
    trim_ws(expanded);
    strip_quotes(expanded);
    trim_ws(expanded);
    if (expanded[0] == '\0') return;

    char base[MAX_PATH];
    UINT wn = GetWindowsDirectoryA(base, sizeof base);
    if (wn == 0 || wn >= sizeof base) {
        strncpy(base, "C:\\Windows", sizeof base - 1);
        base[sizeof base - 1] = '\0';
    }

    /* Build a normalized leading-path form, then hand it to extract_target()
     * to peel off arguments and isolate the binary. A real Win32 path fits in
     * SC_MAX_PATH; the tail we splice in is bounded to keep the result well
     * inside that and avoid any format-truncation. */
    char norm[SC_MAX_CMDLINE];   /* roomy: base(MAX_PATH) + tail(SC_MAX_PATH) */

    /* case-insensitive prefix tests on a lowercased copy */
    char low[SC_MAX_CMDLINE];
    strncpy(low, expanded, sizeof low - 1);
    low[sizeof low - 1] = '\0';
    str_lower(low);

    /* bounded tail buffer: whatever we append after a base dir */
    char tail[SC_MAX_PATH];

    if (strncmp(low, "\\systemroot\\", 12) == 0) {
        /* \SystemRoot\<rest> -> %WINDIR%\<rest> */
        strncpy(tail, expanded + 12, sizeof tail - 1);
        tail[sizeof tail - 1] = '\0';
        snprintf(norm, sizeof norm, "%s\\%s", base, tail);
    } else if (strncmp(low, "\\??\\", 4) == 0) {
        /* \??\C:\... -> C:\... */
        strncpy(norm, expanded + 4, sizeof norm - 1);
        norm[sizeof norm - 1] = '\0';
    } else if (strncmp(low, "system32\\", 9) == 0 ||
               strncmp(low, "\\system32\\", 10) == 0) {
        /* relative to %WINDIR% (driver convention) */
        strncpy(tail, (expanded[0] == '\\') ? expanded + 1 : expanded,
                sizeof tail - 1);
        tail[sizeof tail - 1] = '\0';
        snprintf(norm, sizeof norm, "%s\\%s", base, tail);
    } else if (expanded[1] == ':' && (expanded[2] == '\\' || expanded[2] == '/')) {
        /* already a drive-absolute path */
        strncpy(norm, expanded, sizeof norm - 1);
        norm[sizeof norm - 1] = '\0';
    } else if (expanded[0] == '\\') {
        /* some other NT path (\Driver\..., \Device\...); leave as-is, it
         * won't resolve to a file and will be treated as non-existent */
        strncpy(norm, expanded, sizeof norm - 1);
        norm[sizeof norm - 1] = '\0';
    } else {
        /* bare relative name: assume a driver under System32\drivers */
        strncpy(tail, expanded, sizeof tail - 1);
        tail[sizeof tail - 1] = '\0';
        snprintf(norm, sizeof norm, "%s\\System32\\drivers\\%s", base, tail);
    }

    /* Peel arguments / isolate the binary token. */
    extract_target(norm, out, cap);
    if (out[0] == '\0') {
        size_t nn = strlen(norm);
        if (nn >= cap) nn = cap - 1;
        memcpy(out, norm, nn);
        out[nn] = '\0';
    }
}

static void scan_svc_registry(ScanCtx *c)
{
    static const char *SERVICES = "SYSTEM\\CurrentControlSet\\Services";

    HKEY hk;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SERVICES, 0,
                            KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hk);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied reading Services");
        return;
    }

    DWORD idx = 0;
    for (; idx < 8192; ) {     /* defensive cap */
        char  sub[SC_NAME_LEN];
        DWORD slen = sizeof sub;
        LONG e = RegEnumKeyExA(hk, idx, sub, &slen, NULL, NULL, NULL, NULL);
        if (e == ERROR_NO_MORE_ITEMS) break;
        idx++;
        if (e != ERROR_SUCCESS) continue;

        /* Open the per-service subkey for its values. */
        char subpath[SC_MAX_PATH];
        snprintf(subpath, sizeof subpath, "%s\\%s", SERVICES, sub);

        HKEY shk;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subpath, 0, KEY_READ, &shk)
            != ERROR_SUCCESS)
            continue;

        /* ImagePath (REG_SZ / REG_EXPAND_SZ). Absent for many group/no-binary
         * keys -- skip those silently. */
        BYTE  data[SC_MAX_CMDLINE];
        DWORD dlen = sizeof data;
        DWORD type = 0;
        LONG  ie = RegQueryValueExA(shk, "ImagePath", NULL, &type, data, &dlen);
        if (ie != ERROR_SUCCESS ||
            (type != REG_SZ && type != REG_EXPAND_SZ) || dlen == 0) {
            RegCloseKey(shk);
            continue;
        }
        data[(dlen < sizeof data) ? dlen : sizeof data - 1] = '\0';
        data[sizeof data - 1] = '\0';

        char raw[SC_MAX_CMDLINE];
        if (type == REG_EXPAND_SZ)
            expand_env((const char *)data, raw, sizeof raw);
        else { strncpy(raw, (const char *)data, sizeof raw - 1);
               raw[sizeof raw - 1] = '\0'; }
        trim_ws(raw);
        if (raw[0] == '\0') { RegCloseKey(shk); continue; }

        /* Start + Type (REG_DWORD, may be absent). */
        DWORD start = (DWORD)-1, vlen = sizeof(DWORD), vt = 0;
        if (RegQueryValueExA(shk, "Start", NULL, &vt, (BYTE *)&start, &vlen)
                != ERROR_SUCCESS || vt != REG_DWORD)
            start = (DWORD)-1;

        DWORD svctype = (DWORD)-1; vlen = sizeof(DWORD); vt = 0;
        if (RegQueryValueExA(shk, "Type", NULL, &vt, (BYTE *)&svctype, &vlen)
                != ERROR_SUCCESS || vt != REG_DWORD)
            svctype = (DWORD)-1;

        RegCloseKey(shk);

        /* Resolve to a real binary on disk. */
        char target[SC_MAX_PATH];
        resolve_svc_imagepath(raw, target, sizeof target);
        if (target[0] == '\0') continue;

        /* Classify signer + path. */
        SignVerdict v = SIGN_UNKNOWN;
        bool exists = (GetFileAttributesA(target) != INVALID_FILE_ATTRIBUTES);
        if (exists) v = sign_verify(target, NULL, 0);

        PathLoc loc = path_classify(target);
        bool user_writable = path_is_user_writable(target);
        bool signed_ms     = (v == SIGN_SIGNED_MS);
        bool unsigned_bad  = (v == SIGN_UNSIGNED || v == SIGN_INVALID);
        bool in_inbox_dir  = (loc == PATHLOC_SYSTEM || loc == PATHLOC_WINDOWS);

        /* SUPPRESS the legitimate inbox population: an MS-signed binary under
         * System32 / System32\drivers / WinSxS (all PATHLOC_SYSTEM, with
         * WINDOWS as a near-inbox sibling) is the clean state. Do not emit. */
        if (signed_ms && in_inbox_dir)
            continue;

        /* Decide whether this service binary is genuinely suspicious:
         *   - sits in a user-writable / temp / AppData / ProgramData path, OR
         *   - is unsigned/invalid AND lives outside the MS inbox dirs.
         * Everything else (e.g. validly third-party-signed under Program
         * Files) is left to scan_service / other vantage points -- not flagged
         * here, to keep registry-view volume low. */
        /* A validly signed binary (MS or trusted third party) is exonerated
         * even from a user-writable path: Microsoft Defender runs from a
         * versioned %ProgramData% dir, Store apps from WindowsApps, etc. Only
         * an UNSIGNED binary sitting in a user-writable path is the malware
         * shape. (Same lesson as scan_service.c's Defender false positive.) */
        bool validly_signed = (v == SIGN_SIGNED || v == SIGN_SIGNED_MS);
        const char *why = NULL;
        if (user_writable && !validly_signed) {
            why = (loc == PATHLOC_TEMP)  ? "ImagePath in temp" :
                  (loc == PATHLOC_USER_WRITABLE) ?
                      "ImagePath in user-writable (AppData/ProgramData/Public)" :
                  "ImagePath in user-writable location";
        } else if (unsigned_bad && !in_inbox_dir) {
            why = (v == SIGN_INVALID) ? "invalid signature outside inbox dirs"
                                      : "unsigned outside inbox dirs";
        } else if (!exists) {
            /* Binary referenced by the service does not exist on disk: either
             * a stale entry or a dropper that has not yet staged the payload.
             * Only call it out when it ALSO claims an early Start type, which
             * is what a not-yet-started boot/system driver would look like. */
            if (start == 0 || start == 1)
                why = "ImagePath missing on disk (early-start service)";
        }

        if (!why) continue;     /* off-profile only -- keep it quiet otherwise */

        /* Severity: HIGH, escalate to CRIT when unsigned AND user-writable
         * (the strongest direct-write malware signal). */
        Severity sev = SEV_HIGH;
        if (unsigned_bad && user_writable) sev = SEV_CRIT;

        bus_emit(c->bus, "PERSIST.SVC_REGISTRY", sev, 80,
                 ACT_REVIEW, 0, target,
                 "Service defined directly in registry (off-profile binary)",
                 "HKLM\\%s\\%s ImagePath=\"%s\" Start=%s Type=0x%lx -> %s "
                 "[%s; %s] (registry view; SCM may not enumerate this)",
                 SERVICES, sub, raw, svc_start_name(start),
                 (svctype == (DWORD)-1) ? 0ul : (unsigned long)svctype,
                 target, sign_name(v), why);
    }
    RegCloseKey(hk);
}

/* ------------------------------------------------------------------ *
 *  Security-control tamper and high-value policy persistence
 * ------------------------------------------------------------------ *
 *
 * Modern intrusions frequently try to make the host easier to reinfect or
 * harder to investigate: disable Defender/Firewall, create broad Defender
 * exclusions, force browser extensions, or steer traffic through a proxy/PAC.
 * These are not always malware by themselves, so every finding is ACT_REVIEW.
 */

static void emit_dword_when(ScanCtx *c, const char *rule, Severity sev,
                            int conf, HKEY root, const char *subkey,
                            const char *value, DWORD bad_value,
                            const char *title, const char *why)
{
    DWORD got = 0;
    if (!read_reg_dword(root, subkey, value, &got))
        return;
    if (got != bad_value)
        return;

    char target[SC_MAX_PATH];
    snprintf(target, sizeof target, "%s\\%s\\%s",
             root_label(root), subkey, value);
    bus_emit(c->bus, rule, sev, conf, ACT_REVIEW, 0, target,
             title, "%s %s\\%s %s=%lu", why, root_label(root), subkey,
             value, (unsigned long)got);
}

static void scan_defender_policy_tamper(ScanCtx *c)
{
    static const char *WD =
        "Software\\Policies\\Microsoft\\Windows Defender";
    static const char *RTP =
        "Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";
    static const char *SPYNET =
        "Software\\Policies\\Microsoft\\Windows Defender\\Spynet";
    static const char *FEATURES =
        "Software\\Microsoft\\Windows Defender\\Features";

    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_CRIT, 92,
        HKEY_LOCAL_MACHINE, WD, "DisableAntiSpyware", 1,
        "Microsoft Defender disabled by policy",
        "Defender anti-spyware protection is explicitly disabled:");
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_CRIT, 92,
        HKEY_LOCAL_MACHINE, WD, "DisableAntiVirus", 1,
        "Microsoft Defender disabled by policy",
        "Defender antivirus protection is explicitly disabled:");
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_HIGH, 86,
        HKEY_LOCAL_MACHINE, RTP, "DisableRealtimeMonitoring", 1,
        "Defender real-time monitoring disabled",
        "Real-time monitoring is explicitly disabled:");
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_HIGH, 84,
        HKEY_LOCAL_MACHINE, RTP, "DisableBehaviorMonitoring", 1,
        "Defender behavior monitoring disabled",
        "Behavior monitoring is explicitly disabled:");
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_HIGH, 84,
        HKEY_LOCAL_MACHINE, RTP, "DisableOnAccessProtection", 1,
        "Defender on-access protection disabled",
        "On-access protection is explicitly disabled:");
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_HIGH, 84,
        HKEY_LOCAL_MACHINE, RTP, "DisableIOAVProtection", 1,
        "Defender downloaded-file scanning disabled",
        "IOAV/downloaded-file scanning is explicitly disabled:");
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_HIGH, 82,
        HKEY_LOCAL_MACHINE, RTP, "DisableScriptScanning", 1,
        "Defender script scanning disabled",
        "Script scanning is explicitly disabled:");
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_HIGH, 82,
        HKEY_LOCAL_MACHINE, SPYNET, "DisableBlockAtFirstSeen", 1,
        "Defender cloud block-at-first-sight disabled",
        "Block-at-first-sight protection is explicitly disabled:");

    /* TamperProtection is noisy across Windows builds, so only report a
     * confidently bad explicit zero. Normal enabled values are non-zero. */
    emit_dword_when(c, "TAMPER.DEFENDER_DISABLED", SEV_HIGH, 80,
        HKEY_LOCAL_MACHINE, FEATURES, "TamperProtection", 0,
        "Defender Tamper Protection disabled",
        "Tamper Protection is explicitly disabled:");
}

static bool exclusion_value_suspicious(const char *name)
{
    if (!name || !name[0])
        return false;
    if (strcmp(name, "*") == 0 || strcmp(name, ".") == 0)
        return true;
    if (str_icontains(name, "\\users\\") ||
        str_icontains(name, "\\appdata\\") ||
        str_icontains(name, "\\programdata\\") ||
        str_icontains(name, "\\temp\\") ||
        str_icontains(name, "\\downloads\\") ||
        str_icontains(name, "\\desktop\\") ||
        str_icontains(name, "powershell.exe") ||
        str_icontains(name, "pwsh.exe") ||
        str_icontains(name, "cmd.exe") ||
        str_icontains(name, "wscript.exe") ||
        str_icontains(name, "cscript.exe") ||
        str_icontains(name, "mshta.exe") ||
        str_icontains(name, "rundll32.exe") ||
        str_icontains(name, "regsvr32.exe"))
        return true;
    return false;
}

static void scan_defender_exclusion_key(ScanCtx *c, const char *leaf,
                                        Severity base_sev)
{
    char subkey[SC_MAX_PATH];
    snprintf(subkey, sizeof subkey,
             "Software\\Microsoft\\Windows Defender\\Exclusions\\%s", leaf);

    HKEY hk;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0,
                            KEY_READ | KEY_QUERY_VALUE, &hk);
    if (rc != ERROR_SUCCESS) {
        if (rc == ERROR_ACCESS_DENIED)
            ctx_note_limit(c, "persist: access denied reading Defender exclusions");
        return;
    }

    DWORD idx = 0;
    for (;;) {
        char  name[SC_MAX_PATH];
        DWORD nlen = sizeof name;
        BYTE  data[SC_MAX_CMDLINE];
        DWORD dlen = sizeof data;
        DWORD type = 0;
        LONG e = RegEnumValueA(hk, idx, name, &nlen, NULL, &type, data, &dlen);
        if (e == ERROR_NO_MORE_ITEMS) break;
        idx++;
        if (e != ERROR_SUCCESS) continue;
        name[sizeof name - 1] = '\0';

        bool broad = exclusion_value_suspicious(name);
        if (!broad && (type == REG_SZ || type == REG_EXPAND_SZ) && dlen > 0) {
            data[(dlen < sizeof data) ? dlen : sizeof data - 1] = '\0';
            broad = exclusion_value_suspicious((const char *)data);
        }
        if (!broad && allowlist_match(name))
            continue;

        char target[SC_MAX_PATH];
        snprintf(target, sizeof target, "%s:%s", leaf, name);
        bus_emit(c->bus, "TAMPER.DEFENDER_EXCLUSION",
                 broad ? SEV_HIGH : base_sev, broad ? 82 : 55,
                 ACT_REVIEW, 0, target,
                 broad ? "Suspicious Microsoft Defender exclusion"
                       : "Microsoft Defender exclusion present",
                 "HKLM\\%s value \"%s\"%s", subkey, name,
                 broad ? " covers a broad/user-writable/tooling location" : "");
    }
    RegCloseKey(hk);
}

static void scan_defender_exclusions(ScanCtx *c)
{
    scan_defender_exclusion_key(c, "Paths", SEV_MED);
    scan_defender_exclusion_key(c, "Processes", SEV_MED);
    scan_defender_exclusion_key(c, "Extensions", SEV_LOW);
}

static void scan_firewall_tamper(ScanCtx *c)
{
    static const char *BASE =
        "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy";
    static const char *profiles[] = {
        "DomainProfile", "StandardProfile", "PublicProfile", NULL
    };
    for (int i = 0; profiles[i]; i++) {
        char sub[SC_MAX_PATH];
        snprintf(sub, sizeof sub, "%s\\%s", BASE, profiles[i]);
        emit_dword_when(c, "TAMPER.FIREWALL_DISABLED", SEV_HIGH, 78,
            HKEY_LOCAL_MACHINE, sub, "EnableFirewall", 0,
            "Windows Firewall profile disabled",
            "Firewall profile is explicitly disabled:");
    }
}

static void scan_security_service_tamper(ScanCtx *c)
{
    static const struct {
        const char *svc;
        const char *title;
        Severity sev;
    } svcs[] = {
        { "WinDefend", "Microsoft Defender Antivirus service disabled", SEV_CRIT },
        { "WdNisSvc",  "Defender Network Inspection service disabled", SEV_HIGH },
        { "Sense",     "Microsoft Defender for Endpoint sensor disabled", SEV_HIGH },
        { "SecurityHealthService", "Windows Security Health service disabled", SEV_MED },
        { NULL, NULL, SEV_INFO }
    };

    for (int i = 0; svcs[i].svc; i++) {
        char sub[SC_MAX_PATH];
        snprintf(sub, sizeof sub, "SYSTEM\\CurrentControlSet\\Services\\%s",
                 svcs[i].svc);
        DWORD start = 0;
        if (!read_reg_dword(HKEY_LOCAL_MACHINE, sub, "Start", &start))
            continue;
        if (start != 4)
            continue;
        char target[SC_MAX_PATH];
        snprintf(target, sizeof target, "HKLM\\%s", sub);
        bus_emit(c->bus, "TAMPER.SECURITY_SERVICE", svcs[i].sev, 84,
                 ACT_REVIEW, 0, target, svcs[i].title,
                 "HKLM\\%s Start=disabled (4); malware/BYOVD commonly "
                 "disables security services before staging payloads",
                 sub);
    }
}

static void scan_security_tamper(ScanCtx *c)
{
    scan_defender_policy_tamper(c);
    scan_defender_exclusions(c);
    scan_firewall_tamper(c);
    scan_security_service_tamper(c);
}

static bool proxy_value_suspicious(const char *v)
{
    if (!v || !v[0])
        return false;
    if (str_icontains(v, "127.0.0.1") ||
        str_icontains(v, "localhost") ||
        str_icontains(v, "pac") ||
        str_icontains(v, "http://") ||
        str_icontains(v, "https://") ||
        str_icontains(v, ".onion") ||
        str_icontains(v, "\\appdata\\") ||
        str_icontains(v, "\\temp\\"))
        return true;
    return false;
}

static void scan_proxy_policy_one(ScanCtx *c, HKEY root)
{
    static const char *INET =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    DWORD enabled = 0;
    char proxy[SC_MAX_CMDLINE] = "";
    char pac[SC_MAX_CMDLINE] = "";
    bool have_proxy = read_reg_sz(root, INET, "ProxyServer", proxy, sizeof proxy);
    bool have_pac = read_reg_sz(root, INET, "AutoConfigURL", pac, sizeof pac);

    if (read_reg_dword(root, INET, "ProxyEnable", &enabled) &&
        enabled == 1 && have_proxy && proxy[0] &&
        !allowlist_match(proxy)) {
        bool sus = proxy_value_suspicious(proxy);
        bus_emit(c->bus, "PERSIST.PROXY", sus ? SEV_HIGH : SEV_MED,
                 sus ? 78 : 55, ACT_REVIEW, 0, proxy,
                 sus ? "Suspicious system proxy configured"
                     : "System proxy configured",
                 "%s\\%s ProxyEnable=1 ProxyServer=\"%s\"",
                 root_label(root), INET, proxy);
    }
    if (have_pac && pac[0] && !allowlist_match(pac)) {
        bool sus = proxy_value_suspicious(pac);
        bus_emit(c->bus, "PERSIST.PROXY", sus ? SEV_HIGH : SEV_MED,
                 sus ? 80 : 60, ACT_REVIEW, 0, pac,
                 sus ? "Suspicious PAC/AutoConfig proxy configured"
                     : "PAC/AutoConfig proxy configured",
                 "%s\\%s AutoConfigURL=\"%s\"",
                 root_label(root), INET, pac);
    }
}

static void scan_proxy_policy(ScanCtx *c)
{
    scan_proxy_policy_one(c, HKEY_CURRENT_USER);
    scan_proxy_policy_one(c, HKEY_LOCAL_MACHINE);
}

static void scan_browser_forced_extensions_one(ScanCtx *c, HKEY root,
                                               const char *vendor,
                                               const char *browser)
{
    char subkey[SC_MAX_PATH];
    snprintf(subkey, sizeof subkey,
             "Software\\Policies\\%s\\%s\\ExtensionInstallForcelist",
             vendor, browser);

    HKEY hk;
    LONG rc = RegOpenKeyExA(root, subkey, 0,
                            KEY_READ | KEY_QUERY_VALUE, &hk);
    if (rc != ERROR_SUCCESS)
        return;

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
        if (e != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
            continue;
        if (dlen == 0) continue;
        data[(dlen < sizeof data) ? dlen : sizeof data - 1] = '\0';
        data[sizeof data - 1] = '\0';
        char raw[SC_MAX_CMDLINE];
        if (type == REG_EXPAND_SZ) expand_env((const char *)data, raw, sizeof raw);
        else { strncpy(raw, (const char *)data, sizeof raw - 1);
               raw[sizeof raw - 1] = '\0'; }
        trim_ws(raw);
        if (!raw[0] || allowlist_match(raw))
            continue;

        bool external = str_icontains(raw, "http://") ||
                        str_icontains(raw, "https://") ||
                        str_icontains(raw, ";");
        bus_emit(c->bus, "PERSIST.BROWSER_EXTENSION",
                 external ? SEV_HIGH : SEV_MED, external ? 78 : 65,
                 ACT_REVIEW, 0, raw,
                 "Browser extension force-installed by policy",
                 "%s\\%s value \"%s\" = \"%s\"",
                 root_label(root), subkey, name, raw);
    }
    RegCloseKey(hk);
}

static void scan_browser_forced_extensions(ScanCtx *c)
{
    scan_browser_forced_extensions_one(c, HKEY_LOCAL_MACHINE, "Google", "Chrome");
    scan_browser_forced_extensions_one(c, HKEY_CURRENT_USER,  "Google", "Chrome");
    scan_browser_forced_extensions_one(c, HKEY_LOCAL_MACHINE, "Microsoft", "Edge");
    scan_browser_forced_extensions_one(c, HKEY_CURRENT_USER,  "Microsoft", "Edge");
}

static bool app_path_name_sensitive(const char *sub)
{
    static const char *names[] = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "regedit.exe", "taskmgr.exe", "mmc.exe", "control.exe",
        "msiexec.exe", "schtasks.exe", "sc.exe", "net.exe", NULL
    };
    char leaf[SC_NAME_LEN];
    base_name(sub, leaf, sizeof leaf);
    if (!leaf[0]) {
        strncpy(leaf, sub ? sub : "", sizeof leaf - 1);
        leaf[sizeof leaf - 1] = '\0';
    }
    str_lower(leaf);
    for (int i = 0; names[i]; i++)
        if (strcmp(leaf, names[i]) == 0)
            return true;
    return false;
}

static void scan_app_paths_hijack_one(ScanCtx *c, HKEY root)
{
    static const char *APP_PATHS =
        "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths";
    HKEY hk;
    LONG rc = RegOpenKeyExA(root, APP_PATHS, 0,
                            KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hk);
    if (rc != ERROR_SUCCESS)
        return;

    DWORD idx = 0;
    for (; idx < 4096; ) {
        char  sub[SC_NAME_LEN];
        DWORD slen = sizeof sub;
        LONG e = RegEnumKeyExA(hk, idx, sub, &slen, NULL, NULL, NULL, NULL);
        if (e == ERROR_NO_MORE_ITEMS) break;
        idx++;
        if (e != ERROR_SUCCESS) continue;

        char full[SC_MAX_PATH];
        snprintf(full, sizeof full, "%s\\%s", APP_PATHS, sub);
        char val[SC_MAX_CMDLINE];
        if (!read_reg_sz(root, full, NULL, val, sizeof val))
            continue;
        trim_ws(val);
        if (!val[0]) continue;

        char target[SC_MAX_PATH];
        extract_target(val, target, sizeof target);
        if (!target[0]) {
            strncpy(target, val, sizeof target - 1);
            target[sizeof target - 1] = '\0';
        }
        if (allowlist_match(target) || allowlist_match(sub))
            continue;

        if (str_icontains(target, "\\windowsapps\\"))
            continue; /* normal Store/App Execution Alias population */

        SignVerdict v = SIGN_UNKNOWN;
        if (GetFileAttributesA(target) != INVALID_FILE_ATTRIBUTES)
            v = sign_verify(target, NULL, 0);

        PathLoc loc = path_classify(target);
        bool user_writable = path_is_user_writable(target);
        bool unsigned_bad = (v == SIGN_UNSIGNED || v == SIGN_INVALID);
        bool tempish = (loc == PATHLOC_TEMP || loc == PATHLOC_RECYCLE);
        bool sensitive = app_path_name_sensitive(sub);

        if (sensitive && v == SIGN_SIGNED_MS &&
            (loc == PATHLOC_SYSTEM || loc == PATHLOC_WINDOWS))
            continue;

        if (!sensitive && !(unsigned_bad && user_writable) && !tempish)
            continue;

        const char *why = sensitive ? "sensitive command name" :
                          tempish ? "temp/recycle target" :
                          (v == SIGN_INVALID ? "invalid signature in user-writable path" :
                                               "unsigned in user-writable path");

        bus_emit(c->bus, "PERSIST.APP_PATHS",
                 (sensitive || tempish) ? SEV_HIGH : SEV_MED,
                 (sensitive || tempish) ? 78 : 65,
                 ACT_REVIEW, 0, target,
                 root == HKEY_CURRENT_USER ?
                    "Per-user App Paths execution hijack" :
                    "Suspicious App Paths target",
                 "%s\\%s default=\"%s\" -> %s [%s; %s%s%s]",
                 root_label(root), full, val, target, why, sign_name(v),
                 user_writable ? "; user-writable" : "",
                 tempish ? "; temp-like" : "");
    }
    RegCloseKey(hk);
}

static void scan_app_paths_hijack(ScanCtx *c)
{
    if (reg_key_exists(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"))
        scan_app_paths_hijack_one(c, HKEY_CURRENT_USER);
    scan_app_paths_hijack_one(c, HKEY_LOCAL_MACHINE);
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
    scan_appcert(c);
    scan_lsa_providers(c);
    scan_ifeo(c);
    scan_com_hijack(c);
    scan_svc_registry(c);
    scan_security_tamper(c);
    scan_proxy_policy(c);
    scan_browser_forced_extensions(c);
    scan_app_paths_hijack(c);

    /* Filesystem-based checks. */
    scan_startup_folders(c, com_ok);
    scan_scheduled_tasks(c);

    /* WMI (COM). Never fatal: notes a limit and continues on failure. */
    scan_wmi_subscriptions(c, com_ok);

    if (com_inited_here)
        CoUninitialize();
}
