/* respond.c - SentinelC responder. DESTRUCTIVE actions, heavily guarded.
 * Default is dry-run. Every attempt and result is audited.
 * C11, Win32 user-mode. Libs: advapi32, kernel32 (ntdll via GetProcAddress).
 */
#include "sentinelc.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <aclapi.h>
#include <sddl.h>

/* ---- critical process names (never-kill) ---- */
static const char *k_critical_names[] = {
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe",
};

/* Resolve a pid's base image name into out (lowercased). false if unknown. */
static bool pid_base_name(DWORD pid, char *out, size_t cap)
{
    if (cap == 0) return false;
    out[0] = '\0';

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;

    wchar_t wpath[SC_MAX_PATH];
    DWORD wlen = (DWORD)(sizeof(wpath) / sizeof(wpath[0]));
    bool ok = false;
    if (QueryFullProcessImageNameW(h, 0, wpath, &wlen)) {
        char path[SC_MAX_PATH];
        if (wide_to_utf8(wpath, path, sizeof(path)) > 0) {
            base_name(path, out, cap);
            str_lower(out);
            ok = (out[0] != '\0');
        }
    }
    CloseHandle(h);
    return ok;
}

bool is_critical_pid(DWORD pid)
{
    /* System Idle (0) and System (4) are always off-limits. */
    if (pid == 0 || pid == 4)
        return true;

    char name[SC_NAME_LEN];
    if (pid_base_name(pid, name, sizeof(name))) {
        for (size_t i = 0; i < sizeof(k_critical_names)/sizeof(k_critical_names[0]); ++i)
            if (_stricmp(name, k_critical_names[i]) == 0)
                return true;
        return false;
    }

    /* Name unobtainable: be cautious for low system PIDs we couldn't open. */
    if (pid <= 8)
        return true;
    return false;
}

/* ---- console confirmation ---- */
/* Returns true if the user typed y/Y. assume_yes short-circuits to true. */
static bool confirm(bool assume_yes, const char *fmt, ...)
{
    if (assume_yes)
        return true;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);

    char buf[64];
    if (!fgets(buf, sizeof(buf), stdin))
        return false;
    /* first non-space char must be y/Y */
    for (char *p = buf; *p; ++p) {
        if (isspace((unsigned char)*p))
            continue;
        return (*p == 'y' || *p == 'Y');
    }
    return false;
}

/* Emit a JSON string body (no surrounding quotes) to fp, escaping the
 * characters that would otherwise break the JSON or inject structure:
 * backslash, double-quote, and all control chars (<0x20) via \uXXXX. */
static void json_write_escaped(FILE *fp, const char *s)
{
    for (const char *p = s; *p; ++p) {
        unsigned char ch = (unsigned char)*p;
        switch (ch) {
        case '\\': fputs("\\\\", fp); break;
        case '"':  fputs("\\\"", fp); break;
        case '\n': fputs("\\n", fp);  break;
        case '\r': fputs("\\r", fp);  break;
        case '\t': fputs("\\t", fp);  break;
        case '\b': fputs("\\b", fp);  break;
        case '\f': fputs("\\f", fp);  break;
        default:
            if (ch < 0x20)
                fprintf(fp, "\\u%04x", ch);
            else
                fputc((int)ch, fp);
        }
    }
}

/* Best-effort path lookup for messaging/audit. "" if unknown. */
static void pid_path(DWORD pid, char *out, size_t cap)
{
    if (cap) out[0] = '\0';
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    wchar_t wpath[SC_MAX_PATH];
    DWORD wlen = (DWORD)(sizeof(wpath) / sizeof(wpath[0]));
    if (QueryFullProcessImageNameW(h, 0, wpath, &wlen))
        wide_to_utf8(wpath, out, cap);
    CloseHandle(h);
}

/* ---- kill ---- */
static bool do_kill(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        audit_logf("KILL pid %lu FAILED: OpenProcess err=%lu",
                   (unsigned long)pid, (unsigned long)GetLastError());
        return false;
    }
    BOOL ok = TerminateProcess(h, 1);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (ok)
        audit_logf("KILL pid %lu OK", (unsigned long)pid);
    else
        audit_logf("KILL pid %lu FAILED: TerminateProcess err=%lu",
                   (unsigned long)pid, (unsigned long)err);
    return ok != 0;
}

/* ---- suspend (NtSuspendProcess) ---- */
typedef LONG (NTAPI *PFN_NtSuspendProcess)(HANDLE);

static bool do_suspend(DWORD pid)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) nt = LoadLibraryW(L"ntdll.dll");
    if (!nt) {
        audit_logf("SUSPEND pid %lu FAILED: ntdll unavailable", (unsigned long)pid);
        return false;
    }
    PFN_NtSuspendProcess pNtSuspend =
        (PFN_NtSuspendProcess)(void *)GetProcAddress(nt, "NtSuspendProcess");
    if (!pNtSuspend) {
        audit_logf("SUSPEND pid %lu FAILED: NtSuspendProcess not found",
                   (unsigned long)pid);
        return false;
    }

    HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!h) {
        audit_logf("SUSPEND pid %lu FAILED: OpenProcess err=%lu",
                   (unsigned long)pid, (unsigned long)GetLastError());
        return false;
    }
    LONG st = pNtSuspend(h);
    CloseHandle(h);
    bool ok = (st >= 0);
    audit_logf("SUSPEND pid %lu %s (status=0x%lx)", (unsigned long)pid,
               ok ? "OK" : "FAILED", (unsigned long)st);
    return ok;
}

/* ---- disable service ---- */
static bool do_disable_svc(const char *name)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL,
                                   SC_MANAGER_CONNECT);
    if (!scm) {
        audit_logf("DISABLE_SVC '%s' FAILED: OpenSCManager err=%lu",
                   name, (unsigned long)GetLastError());
        return false;
    }
    SC_HANDLE svc = OpenServiceA(scm, name,
                                 SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS);
    if (!svc) {
        audit_logf("DISABLE_SVC '%s' FAILED: OpenService err=%lu",
                   name, (unsigned long)GetLastError());
        CloseServiceHandle(scm);
        return false;
    }

    /* Best-effort stop (ignore "not running" failures). */
    SERVICE_STATUS ss;
    if (ControlService(svc, SERVICE_CONTROL_STOP, &ss))
        audit_logf("DISABLE_SVC '%s' stop signalled", name);
    else
        audit_logf("DISABLE_SVC '%s' stop not applied err=%lu",
                   name, (unsigned long)GetLastError());

    BOOL cfg_ok = ChangeServiceConfigA(svc, SERVICE_NO_CHANGE,
                                       SERVICE_DISABLED, SERVICE_NO_CHANGE,
                                       NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    DWORD err = cfg_ok ? 0 : GetLastError();

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (cfg_ok)
        audit_logf("DISABLE_SVC '%s' OK", name);
    else
        audit_logf("DISABLE_SVC '%s' FAILED: ChangeServiceConfig err=%lu",
                   name, (unsigned long)err);
    return cfg_ok != 0;
}

/* ---- quarantine ---- */

/* Apply a deny-everyone DACL to a path. Best-effort. */
static bool lock_down_acl(const char *path)
{
    /* Empty DACL = no access for anyone (owner can still change ACL). */
    PSECURITY_DESCRIPTOR sd = NULL;
    /* "D:P" = protected DACL, no ACEs => deny-all. */
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P", SDDL_REVISION_1, &sd, NULL))
        return false;

    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = NULL;
    bool ok = false;
    if (GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) {
        (void)present; (void)defaulted;
        DWORD rc = SetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                                         DACL_SECURITY_INFORMATION |
                                         PROTECTED_DACL_SECURITY_INFORMATION,
                                         NULL, NULL, dacl, NULL);
        ok = (rc == ERROR_SUCCESS);
    }
    LocalFree(sd);
    return ok;
}

static bool do_quarantine(const char *path)
{
    char base[SC_MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", base, (DWORD)sizeof(base));
    if (n == 0 || n >= sizeof(base)) {
        strncpy(base, "C:\\ProgramData", sizeof(base) - 1);
        base[sizeof(base) - 1] = '\0';
    }

    char qdir[SC_MAX_PATH];
    if (_snprintf_s(qdir, sizeof(qdir), _TRUNCATE,
                    "%s\\SentinelC\\quarantine", base) < 0) {
        audit_logf("QUARANTINE '%s' FAILED: path too long", path);
        return false;
    }
    /* ensure parent + quarantine dir */
    char scdir[SC_MAX_PATH];
    _snprintf_s(scdir, sizeof(scdir), _TRUNCATE, "%s\\SentinelC", base);
    CreateDirectoryA(scdir, NULL);
    CreateDirectoryA(qdir, NULL);

    char nm[SC_NAME_LEN];
    base_name(path, nm, sizeof(nm));
    if (nm[0] == '\0') {
        strncpy(nm, "file", sizeof(nm) - 1);
        nm[sizeof(nm) - 1] = '\0';
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    char dest[SC_MAX_PATH];
    if (_snprintf_s(dest, sizeof(dest), _TRUNCATE,
                    "%s\\%04u%02u%02u_%02u%02u%02u_%s",
                    qdir, st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond, nm) < 0) {
        audit_logf("QUARANTINE '%s' FAILED: dest path too long", path);
        return false;
    }

    if (MoveFileExA(path, dest, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
        /* sidecar recording original path */
        char side[SC_MAX_PATH];
        if (_snprintf_s(side, sizeof(side), _TRUNCATE, "%s.json", dest) >= 0) {
            FILE *fp = fopen(side, "wb");
            if (fp) {
                /* minimal JSON; every string value must be fully escaped --
                 * paths contain backslashes and may contain quotes/controls. */
                fprintf(fp, "{\n  \"original_path\": \"");
                json_write_escaped(fp, path);
                fprintf(fp, "\",\n  \"quarantined\": \"");
                json_write_escaped(fp, dest);
                fprintf(fp, "\",\n  \"time\": \"%04u-%02u-%02u %02u:%02u:%02u\"\n}\n",
                        st.wYear, st.wMonth, st.wDay,
                        st.wHour, st.wMinute, st.wSecond);
                fclose(fp);
            }
        }
        bool acl = lock_down_acl(dest);
        audit_logf("QUARANTINE '%s' -> '%s' OK (acl_locked=%d)",
                   path, dest, acl ? 1 : 0);
        return true;
    }

    DWORD err = GetLastError();
    /* In use / sharing violation: schedule delayed move at reboot. */
    if (MoveFileExA(path, dest, MOVEFILE_DELAY_UNTIL_REBOOT)) {
        audit_logf("QUARANTINE '%s' -> '%s' DEFERRED until reboot "
                   "(immediate move err=%lu)",
                   path, dest, (unsigned long)err);
        return true;
    }

    audit_logf("QUARANTINE '%s' FAILED: move err=%lu, deferred err=%lu",
               path, (unsigned long)err, (unsigned long)GetLastError());
    return false;
}

/* ---- guarded wrappers for pid actions ---- */

/* Returns 1 if performed, 0 otherwise. kind: "KILL" or "SUSPEND". */
static int act_on_pid(DWORD pid, bool is_kill, const Config *cfg)
{
    char path[SC_MAX_PATH];
    pid_path(pid, path, sizeof(path));
    const char *verb = is_kill ? "KILL" : "SUSPEND";

    if (is_critical_pid(pid) && !cfg->force_critical) {
        printf("REFUSED: %s on critical pid %lu (%s) - use --force-critical to override.\n",
               verb, (unsigned long)pid, path[0] ? path : "?");
        audit_logf("%s pid %lu REFUSED: critical process (%s)",
                   verb, (unsigned long)pid, path[0] ? path : "?");
        return 0;
    }

    if (!confirm(cfg->assume_yes,
                 "About to %s pid %lu (%s) [y/N]: ",
                 verb, (unsigned long)pid, path[0] ? path : "?")) {
        audit_logf("%s pid %lu DECLINED by operator", verb, (unsigned long)pid);
        return 0;
    }

    audit_logf("%s pid %lu ATTEMPT (%s)", verb, (unsigned long)pid,
               path[0] ? path : "?");
    bool ok = is_kill ? do_kill(pid) : do_suspend(pid);
    return ok ? 1 : 0;
}

static int act_disable_svc(const char *name, const Config *cfg)
{
    if (!confirm(cfg->assume_yes,
                 "About to DISABLE service '%s' [y/N]: ", name)) {
        audit_logf("DISABLE_SVC '%s' DECLINED by operator", name);
        return 0;
    }
    audit_logf("DISABLE_SVC '%s' ATTEMPT", name);
    return do_disable_svc(name) ? 1 : 0;
}

static int act_quarantine(const char *path, const Config *cfg)
{
    if (!confirm(cfg->assume_yes,
                 "About to QUARANTINE '%s' [y/N]: ", path)) {
        audit_logf("QUARANTINE '%s' DECLINED by operator", path);
        return 0;
    }
    audit_logf("QUARANTINE '%s' ATTEMPT", path);
    return do_quarantine(path) ? 1 : 0;
}

/* ---- interactive: walk actionable findings ---- */
static int respond_interactive(ScanCtx *c)
{
    int performed = 0;
    FindingBus *b = c->bus;
    if (!b)
        return 0;

    EnterCriticalSection(&b->lock);
    size_t count = b->count;
    /* Snapshot findings so we don't hold the lock across console prompts. */
    Finding *snap = NULL;
    if (count) {
        snap = (Finding *)malloc(count * sizeof(Finding));
        if (snap)
            memcpy(snap, b->items, count * sizeof(Finding));
        else
            count = 0;
    }
    LeaveCriticalSection(&b->lock);

    for (size_t i = 0; i < count; ++i) {
        const Finding *f = &snap[i];
        if (f->recommended == ACT_REVIEW)
            continue;

        printf("\n[%s] %s (sev=%s conf=%d)\n      %s\n",
               f->rule_id, f->title, sev_name(f->severity),
               f->confidence, f->target);

        switch (f->recommended) {
        case ACT_KILL:
            performed += act_on_pid(f->pid, true, c->cfg);
            break;
        case ACT_SUSPEND:
            performed += act_on_pid(f->pid, false, c->cfg);
            break;
        case ACT_DISABLE_SVC:
            performed += act_disable_svc(f->target, c->cfg);
            break;
        case ACT_QUARANTINE:
            performed += act_quarantine(f->target, c->cfg);
            break;
        case ACT_REVIEW:
        default:
            break;
        }
    }

    free(snap);
    return performed;
}

/* ---- entry point ---- */
int respond_apply(ScanCtx *c)
{
    if (!c || !c->cfg)
        return 0;
    const Config *cfg = c->cfg;

    bool any_explicit = cfg->kill_pid || cfg->suspend_pid ||
                        cfg->disable_svc[0] || cfg->quarantine_path[0];

    if (!any_explicit && !cfg->interactive) {
        /* pure dry-run: nothing requested */
        audit_logf("RESPOND dry-run: no actions requested");
        return 0;
    }

    int performed = 0;

    if (cfg->kill_pid)
        performed += act_on_pid(cfg->kill_pid, true, cfg);

    if (cfg->suspend_pid)
        performed += act_on_pid(cfg->suspend_pid, false, cfg);

    if (cfg->disable_svc[0])
        performed += act_disable_svc(cfg->disable_svc, cfg);

    if (cfg->quarantine_path[0])
        performed += act_quarantine(cfg->quarantine_path, cfg);

    if (cfg->interactive)
        performed += respond_interactive(c);

    audit_logf("RESPOND complete: %d action(s) performed", performed);
    return performed;
}
