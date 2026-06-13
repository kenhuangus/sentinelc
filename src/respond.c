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

/* ---- critical process names (never-kill) ----
 * Expanded per audit M1: include kernel/PPL-adjacent names that often
 * resolve oddly or not at all, plus the desktop/composition stack whose
 * death wrecks the session. Names matched case-insensitively on the base
 * image name. Some (MemCompression, Registry, System) are kernel-managed
 * and have no ".exe" extension. */
static const char *k_critical_names[] = {
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe",
    "memcompression", "registry", "system",
    "fontdrvhost.exe", "dwm.exe",
};

/* A small set of well-known System32 images that Windows ships and that
 * should be treated as protected when found running from System32. This is
 * a cheap approximation of "System32 + Microsoft-signed" that avoids a
 * signature call on the hot path (audit M1). Matched case-insensitively. */
static const char *k_system32_protected[] = {
    "svchost.exe", "lsaiso.exe", "wininit.exe", "services.exe",
    "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe",
    "spoolsv.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
    "fontdrvhost.exe", "dwm.exe", "conhost.exe",
};

/* True if path (full image path) lives directly under %SystemRoot%\System32.
 * Case-insensitive substring check; cheap and good enough for the guard. */
static bool path_in_system32(const char *full_path)
{
    if (!full_path || !full_path[0])
        return false;
    return str_icontains(full_path, "\\windows\\system32\\");
}

/* Resolve a pid's full image path (utf8) and lowercased base name.
 * Either out pointer may be NULL. Returns false if the image could not be
 * resolved at all (OpenProcess / QueryFullProcessImageName failed). */
static bool pid_resolve(DWORD pid, char *full_out, size_t full_cap,
                        char *name_out, size_t name_cap)
{
    if (full_out && full_cap) full_out[0] = '\0';
    if (name_out && name_cap) name_out[0] = '\0';

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;

    wchar_t wpath[SC_MAX_PATH];
    DWORD wlen = (DWORD)(sizeof(wpath) / sizeof(wpath[0]));
    bool ok = false;
    if (QueryFullProcessImageNameW(h, 0, wpath, &wlen)) {
        char path[SC_MAX_PATH];
        if (wide_to_utf8(wpath, path, sizeof(path)) > 0) {
            char nm[SC_NAME_LEN];
            base_name(path, nm, sizeof(nm));
            str_lower(nm);
            ok = (nm[0] != '\0');
            if (ok) {
                if (full_out && full_cap) {
                    size_t len = strlen(path);
                    if (len >= full_cap) len = full_cap - 1;
                    memcpy(full_out, path, len);
                    full_out[len] = '\0';
                }
                if (name_out && name_cap) {
                    size_t len = strlen(nm);
                    if (len >= name_cap) len = name_cap - 1;
                    memcpy(name_out, nm, len);
                    name_out[len] = '\0';
                }
            }
        }
    }
    CloseHandle(h);
    return ok;
}

/* Classify a (lowercased) base name + optional full path as critical. */
static bool name_is_critical(const char *name, const char *full_path)
{
    for (size_t i = 0; i < sizeof(k_critical_names)/sizeof(k_critical_names[0]); ++i)
        if (_stricmp(name, k_critical_names[i]) == 0)
            return true;

    /* System32-resident system images: treat as protected (audit M1). */
    if (full_path && path_in_system32(full_path)) {
        for (size_t i = 0; i < sizeof(k_system32_protected)/sizeof(k_system32_protected[0]); ++i)
            if (_stricmp(name, k_system32_protected[i]) == 0)
                return true;
    }
    return false;
}

bool is_critical_pid(DWORD pid)
{
    /* System Idle (0) and System (4) are always off-limits. */
    if (pid == 0 || pid == 4)
        return true;

    char full[SC_MAX_PATH];
    char name[SC_NAME_LEN];
    if (pid_resolve(pid, full, sizeof(full), name, sizeof(name)))
        return name_is_critical(name, full);

    /* Name unobtainable. Low system PIDs are always off-limits. */
    if (pid <= 8)
        return true;

    /* FAIL CLOSED (audit M1): a pid > 8 whose image we cannot resolve is
     * almost always a protected / PPL / kernel process that denied us
     * PROCESS_QUERY_LIMITED_INFORMATION. Treat it as critical so it is
     * refused unless --force-critical. */
    return true;
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

/* ---- kill ---- */
/* Terminate via an already-open, already-validated handle (audit M2).
 * The caller is responsible for opening + revalidating the handle so the
 * pid cannot be recycled between the confirmation prompt and the kill. */
static bool do_kill_h(HANDLE h, DWORD pid)
{
    BOOL ok = TerminateProcess(h, 1);
    DWORD err = ok ? 0 : GetLastError();
    if (ok)
        audit_logf("KILL pid %lu OK", (unsigned long)pid);
    else
        audit_logf("KILL pid %lu FAILED: TerminateProcess err=%lu",
                   (unsigned long)pid, (unsigned long)err);
    return ok != 0;
}

/* ---- suspend (NtSuspendProcess) ---- */
typedef LONG (NTAPI *PFN_NtSuspendProcess)(HANDLE);

/* Suspend via an already-open, already-validated handle (audit M2). */
static bool do_suspend_h(HANDLE h, DWORD pid)
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

    LONG st = pNtSuspend(h);
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

/* ---- quarantine ----
 *
 * Hardened against TOCTOU / reparse-point abuse (audit H1/H2/L1/L4):
 *   - The source is opened ONCE by handle with FILE_FLAG_OPEN_REPARSE_POINT
 *     and rejected if it is a reparse point or a directory. All operations
 *     run against that handle.
 *   - The quarantine directory is created with an explicit SYSTEM+Admins
 *     DACL, and verified to NOT be a reparse point if it already exists.
 *   - The move is done by handle (FileRenameInfoEx); cross-volume falls back
 *     to copy-by-handle into a CREATE_NEW file + delete-by-handle.
 *   - The lock-down ACL is applied by HANDLE (SetSecurityInfo), never by path.
 */

/* SDDL: protected DACL, FullAccess to SYSTEM (SY) and BUILTIN\Admins (BA). */
#define SC_Q_SDDL  L"D:P(A;;FA;;;SY)(A;;FA;;;BA)"
/* Same plus owner=Administrators, group=SYSTEM for the quarantined file. */
#define SC_Q_FILE_SDDL  L"O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"

/* Build a SECURITY_ATTRIBUTES from an SDDL string. Caller LocalFree()s
 * sa->lpSecurityDescriptor on success. Returns false on failure. */
static bool sd_from_sddl(const wchar_t *sddl, SECURITY_ATTRIBUTES *sa)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, NULL))
        return false;
    sa->nLength = sizeof(*sa);
    sa->lpSecurityDescriptor = sd;
    sa->bInheritHandle = FALSE;
    return true;
}

/* Create dir (wide) with the SYSTEM+Admins DACL. If it already exists,
 * verify it is a real directory and NOT a reparse point. Returns false and
 * logs on a reparse point or other hard failure. */
static bool ensure_locked_dir(const wchar_t *wdir)
{
    SECURITY_ATTRIBUTES sa;
    bool have_sa = sd_from_sddl(SC_Q_SDDL, &sa);

    BOOL created = CreateDirectoryW(wdir, have_sa ? &sa : NULL);
    DWORD err = created ? 0 : GetLastError();
    if (have_sa)
        LocalFree(sa.lpSecurityDescriptor);

    if (created)
        return true;
    if (err != ERROR_ALREADY_EXISTS) {
        audit_logf("QUARANTINE dir create FAILED: err=%lu", (unsigned long)err);
        return false;
    }

    /* Already exists: it must be a directory and must not be a reparse point. */
    DWORD attr = GetFileAttributesW(wdir);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        audit_logf("QUARANTINE dir verify FAILED: GetFileAttributes err=%lu",
                   (unsigned long)GetLastError());
        return false;
    }
    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        audit_logf("QUARANTINE ABORT: quarantine dir is a reparse point "
                   "(possible junction attack)");
        return false;
    }
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        audit_logf("QUARANTINE ABORT: quarantine path exists but is not a directory");
        return false;
    }
    return true;
}

/* Apply the lock-down ACL to an OPEN handle (audit H2/L4).
 *
 * We set ONLY a protected DACL (FullAccess to SYSTEM + BUILTIN\Admins, deny to
 * everyone else). We deliberately do NOT set owner/group: changing a file's
 * owner needs SeRestorePrivilege/SeTakeOwnership, which is not reliably held
 * even when elevated, so attempting it made SetSecurityInfo fail outright and
 * left the file with no lock-down at all. The protected deny-all DACL is the
 * isolation guarantee; the original owner retaining WRITE_DAC is an accepted
 * "neutralize" tradeoff (the sample is moved into an admin-only directory
 * regardless). Returns true on success. */
static bool lock_down_handle(HANDLE h)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            SC_Q_SDDL, SDDL_REVISION_1, &sd, NULL))
        return false;

    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    PACL dacl = NULL;
    bool ok = false;

    if (GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted) &&
        daclPresent) {
        (void)daclDefaulted;
        DWORD rc = SetSecurityInfo(
            h, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, dacl, NULL);
        ok = (rc == ERROR_SUCCESS);
    }
    LocalFree(sd);
    return ok;
}

/* Rename the OPEN source handle to wdest via FileRenameInfoEx.
 * ReplaceIfExists=FALSE (Flags=0). Returns true on success; on cross-volume
 * (ERROR_NOT_SAME_DEVICE) sets *cross_volume. */
static bool rename_handle_to(HANDLE h, const wchar_t *wdest, bool *cross_volume)
{
    *cross_volume = false;
    size_t name_bytes = (wcslen(wdest)) * sizeof(wchar_t);
    size_t total = sizeof(FILE_RENAME_INFO) + name_bytes; /* struct has [1] slot */
    FILE_RENAME_INFO *fri = (FILE_RENAME_INFO *)calloc(1, total);
    if (!fri)
        return false;

    fri->Flags = 0;            /* do NOT replace if exists */
    fri->RootDirectory = NULL;
    fri->FileNameLength = (DWORD)name_bytes;
    memcpy(fri->FileName, wdest, name_bytes);

    BOOL ok = SetFileInformationByHandle(h, FileRenameInfoEx, fri, (DWORD)total);
    DWORD err = ok ? 0 : GetLastError();
    free(fri);

    if (ok)
        return true;
    if (err == ERROR_NOT_SAME_DEVICE)
        *cross_volume = true;
    SetLastError(err);
    return false;
}

/* Copy the source handle's contents into a freshly CREATE_NEW dest file,
 * then delete the original via FileDispositionInfo on srch. Used only for the
 * cross-volume fallback. Returns true on success; *out_h receives the open
 * dest handle (caller closes) on success. */
static bool copy_then_delete(HANDLE srch, const wchar_t *wdest,
                             SECURITY_ATTRIBUTES *file_sa, HANDLE *out_h)
{
    *out_h = INVALID_HANDLE_VALUE;

    /* CREATE_NEW: fail closed if a file is already squatting the dest name. */
    HANDLE dh = CreateFileW(wdest, GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER,
                            0 /* no sharing */, file_sa, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (dh == INVALID_HANDLE_VALUE) {
        audit_logf("QUARANTINE copy FAILED: dest CreateFile(CREATE_NEW) err=%lu",
                   (unsigned long)GetLastError());
        return false;
    }

    /* Rewind source and stream it across. */
    LARGE_INTEGER zero = {0};
    SetFilePointerEx(srch, zero, NULL, FILE_BEGIN);

    char buf[64 * 1024];
    DWORD rd;
    bool ok = true;
    for (;;) {
        if (!ReadFile(srch, buf, sizeof(buf), &rd, NULL)) {
            audit_logf("QUARANTINE copy FAILED: ReadFile err=%lu",
                       (unsigned long)GetLastError());
            ok = false;
            break;
        }
        if (rd == 0)
            break;
        DWORD off = 0;
        while (off < rd) {
            DWORD wr = 0;
            if (!WriteFile(dh, buf + off, rd - off, &wr, NULL) || wr == 0) {
                audit_logf("QUARANTINE copy FAILED: WriteFile err=%lu",
                           (unsigned long)GetLastError());
                ok = false;
                break;
            }
            off += wr;
        }
        if (!ok)
            break;
    }

    if (!ok) {
        /* Roll back the partial dest. */
        FILE_DISPOSITION_INFO fdi; fdi.DeleteFile = TRUE;
        SetFileInformationByHandle(dh, FileDispositionInfo, &fdi, sizeof(fdi));
        CloseHandle(dh);
        return false;
    }

    /* Delete the original via the source handle. */
    FILE_DISPOSITION_INFO sdi; sdi.DeleteFile = TRUE;
    if (!SetFileInformationByHandle(srch, FileDispositionInfo, &sdi, sizeof(sdi))) {
        DWORD err = GetLastError();
        audit_logf("QUARANTINE copy: original delete FAILED err=%lu "
                   "(copy succeeded, original remains)", (unsigned long)err);
        /* Copy is in place but original survives -- roll back the copy so we
         * don't leave a duplicate, and report failure. */
        FILE_DISPOSITION_INFO fdi; fdi.DeleteFile = TRUE;
        SetFileInformationByHandle(dh, FileDispositionInfo, &fdi, sizeof(fdi));
        CloseHandle(dh);
        return false;
    }

    *out_h = dh;
    return true;
}

/* Write the sidecar JSON next to the quarantined file. Best-effort. */
static void write_sidecar(const char *dest, const char *orig, const SYSTEMTIME *st)
{
    char side[SC_MAX_PATH];
    if (_snprintf_s(side, sizeof(side), _TRUNCATE, "%s.json", dest) < 0)
        return;
    FILE *fp = fopen(side, "wb");
    if (!fp)
        return;
    fprintf(fp, "{\n  \"original_path\": \"");
    json_write_escaped(fp, orig);
    fprintf(fp, "\",\n  \"quarantined\": \"");
    json_write_escaped(fp, dest);
    fprintf(fp, "\",\n  \"time\": \"%04u-%02u-%02u %02u:%02u:%02u\"\n}\n",
            st->wYear, st->wMonth, st->wDay,
            st->wHour, st->wMinute, st->wSecond);
    fclose(fp);
}

/* Process-lifetime counter feeding the random dest-name component. */
static unsigned long g_qcounter = 0;

static bool do_quarantine(const char *path)
{
    /* ---- 1. open the source by handle, reject reparse points / dirs ---- */
    wchar_t wpath[SC_MAX_PATH];
    if (utf8_to_wide(path, wpath, sizeof(wpath) / sizeof(wpath[0])) == 0) {
        printf("QUARANTINE '%s' FAILED: cannot widen source path.\n", path);
        audit_logf("QUARANTINE '%s' FAILED: utf8_to_wide", path);
        return false;
    }

    /* DELETE for the rename, GENERIC_READ for the cross-volume copy fallback,
     * WRITE_DAC so the post-move lock-down ACL can be set on this same handle. */
    HANDLE srch = CreateFileW(
        wpath, DELETE | GENERIC_READ | WRITE_DAC, FILE_SHARE_READ, NULL,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (srch == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("QUARANTINE '%s' FAILED: cannot open source (err=%lu).\n",
               path, (unsigned long)err);
        audit_logf("QUARANTINE '%s' FAILED: CreateFile err=%lu",
                   path, (unsigned long)err);
        return false;
    }

    BY_HANDLE_FILE_INFORMATION fi;
    if (!GetFileInformationByHandle(srch, &fi)) {
        DWORD err = GetLastError();
        printf("QUARANTINE '%s' FAILED: GetFileInformationByHandle (err=%lu).\n",
               path, (unsigned long)err);
        audit_logf("QUARANTINE '%s' FAILED: GetFileInformationByHandle err=%lu",
                   path, (unsigned long)err);
        CloseHandle(srch);
        return false;
    }
    if (fi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        printf("QUARANTINE '%s' REFUSED: source is a reparse point "
               "(symlink/junction) - possible redirection attack.\n", path);
        audit_logf("QUARANTINE '%s' REFUSED: source is a reparse point", path);
        CloseHandle(srch);
        return false;
    }
    if (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        printf("QUARANTINE '%s' REFUSED: source is a directory.\n", path);
        audit_logf("QUARANTINE '%s' REFUSED: source is a directory", path);
        CloseHandle(srch);
        return false;
    }

    /* ---- 2. compute %ProgramData%\SentinelC[\quarantine], lock them down ---- */
    char base[SC_MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", base, (DWORD)sizeof(base));
    if (n == 0 || n >= sizeof(base)) {
        strncpy(base, "C:\\ProgramData", sizeof(base) - 1);
        base[sizeof(base) - 1] = '\0';
    }

    char scdir[SC_MAX_PATH], qdir[SC_MAX_PATH];
    if (_snprintf_s(scdir, sizeof(scdir), _TRUNCATE, "%s\\SentinelC", base) < 0 ||
        _snprintf_s(qdir, sizeof(qdir), _TRUNCATE, "%s\\SentinelC\\quarantine", base) < 0) {
        printf("QUARANTINE '%s' FAILED: path too long.\n", path);
        audit_logf("QUARANTINE '%s' FAILED: path too long", path);
        CloseHandle(srch);
        return false;
    }

    wchar_t wscdir[SC_MAX_PATH], wqdir[SC_MAX_PATH];
    if (utf8_to_wide(scdir, wscdir, sizeof(wscdir)/sizeof(wscdir[0])) == 0 ||
        utf8_to_wide(qdir, wqdir, sizeof(wqdir)/sizeof(wqdir[0])) == 0) {
        printf("QUARANTINE '%s' FAILED: cannot widen quarantine dir.\n", path);
        audit_logf("QUARANTINE '%s' FAILED: widen qdir", path);
        CloseHandle(srch);
        return false;
    }

    if (!ensure_locked_dir(wscdir) || !ensure_locked_dir(wqdir)) {
        printf("QUARANTINE '%s' ABORTED: quarantine directory is unsafe "
               "(see audit log).\n", path);
        CloseHandle(srch);
        return false;
    }

    /* ---- 3. build an unpredictable destination name ---- */
    char nm[SC_NAME_LEN];
    base_name(path, nm, sizeof(nm));
    if (nm[0] == '\0') {
        strncpy(nm, "file", sizeof(nm) - 1);
        nm[sizeof(nm) - 1] = '\0';
    }

    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    unsigned long long rnd =
        ((unsigned long long)ft.dwHighDateTime << 32 | ft.dwLowDateTime) ^
        ((unsigned long long)GetCurrentProcessId() << 16) ^
        ((unsigned long long)(++g_qcounter) * 0x9E3779B97F4A7C15ULL);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char dest[SC_MAX_PATH];
    if (_snprintf_s(dest, sizeof(dest), _TRUNCATE,
                    "%s\\%04u%02u%02u_%02u%02u%02u_%016llx_%s",
                    qdir, st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond,
                    (unsigned long long)rnd, nm) < 0) {
        printf("QUARANTINE '%s' FAILED: dest path too long.\n", path);
        audit_logf("QUARANTINE '%s' FAILED: dest path too long", path);
        CloseHandle(srch);
        return false;
    }
    wchar_t wdest[SC_MAX_PATH];
    if (utf8_to_wide(dest, wdest, sizeof(wdest)/sizeof(wdest[0])) == 0) {
        printf("QUARANTINE '%s' FAILED: cannot widen dest.\n", path);
        audit_logf("QUARANTINE '%s' FAILED: widen dest", path);
        CloseHandle(srch);
        return false;
    }

    /* ---- 4. move by handle; cross-volume => copy+delete fallback ---- */
    HANDLE desth = INVALID_HANDLE_VALUE;  /* handle to the file in quarantine */
    bool moved = false;
    bool cross = false;

    if (rename_handle_to(srch, wdest, &cross)) {
        /* Same-volume rename succeeded; srch now refers to the dest file. */
        desth = srch;
        srch = INVALID_HANDLE_VALUE;
        moved = true;
    } else if (cross) {
        SECURITY_ATTRIBUTES fsa;
        bool have_fsa = sd_from_sddl(SC_Q_SDDL, &fsa);
        bool cd = copy_then_delete(srch, wdest, have_fsa ? &fsa : NULL, &desth);
        if (have_fsa)
            LocalFree(fsa.lpSecurityDescriptor);
        if (cd) {
            audit_logf("QUARANTINE '%s' -> '%s' cross-volume copy+delete OK",
                       path, dest);
            moved = true;
        }
    }

    if (!moved) {
        DWORD err = GetLastError();
        /* In use / sharing violation: schedule a delayed move at reboot.
         * MoveFileEx by path is the only mechanism for this; the source is
         * not a reparse point (verified above), so this is acceptable. */
        if (MoveFileExA(path, dest, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            if (srch != INVALID_HANDLE_VALUE) CloseHandle(srch);
            printf("QUARANTINE '%s': DEFERRED until reboot (target still "
                   "running/locked, err=%lu). NOT yet neutralized.\n",
                   path, (unsigned long)err);
            audit_logf("QUARANTINE '%s' -> '%s' DEFERRED until reboot "
                       "(still running, move err=%lu)",
                       path, dest, (unsigned long)err);
            return false;  /* do not claim success (audit L1) */
        }
        if (srch != INVALID_HANDLE_VALUE) CloseHandle(srch);
        printf("QUARANTINE '%s' FAILED: move err=%lu, deferred err=%lu.\n",
               path, (unsigned long)err, (unsigned long)GetLastError());
        audit_logf("QUARANTINE '%s' FAILED: move err=%lu, deferred err=%lu",
                   path, (unsigned long)err, (unsigned long)GetLastError());
        return false;
    }

    /* ---- 5. sidecar + lock-down ACL by handle ---- */
    write_sidecar(dest, path, &st);

    bool acl = lock_down_handle(desth);
    if (desth != INVALID_HANDLE_VALUE)
        CloseHandle(desth);

    if (acl) {
        printf("QUARANTINE '%s' -> '%s' OK (locked down).\n", path, dest);
        audit_logf("QUARANTINE '%s' -> '%s' OK (acl_locked=1)", path, dest);
    } else {
        /* PARTIAL FAILURE: the file is moved/isolated but not ACL-locked.
         * Surface this to the operator, not just the log (audit L4). */
        printf("QUARANTINE '%s' -> '%s' PARTIAL: file isolated but lock-down "
               "ACL FAILED -- the quarantined copy may be world-accessible. "
               "Review permissions manually.\n", path, dest);
        audit_logf("QUARANTINE '%s' -> '%s' PARTIAL: ACL lock-down FAILED",
                   path, dest);
    }
    return true;
}

/* ---- guarded wrappers for pid actions ---- */

/* Resolve full image path + lowercased base name from an OPEN handle.
 * Avoids the OpenProcess-by-pid race (audit M2). false if unresolved. */
static bool handle_resolve(HANDLE h, char *full_out, size_t full_cap,
                           char *name_out, size_t name_cap)
{
    if (full_out && full_cap) full_out[0] = '\0';
    if (name_out && name_cap) name_out[0] = '\0';

    wchar_t wpath[SC_MAX_PATH];
    DWORD wlen = (DWORD)(sizeof(wpath) / sizeof(wpath[0]));
    if (!QueryFullProcessImageNameW(h, 0, wpath, &wlen))
        return false;

    char path[SC_MAX_PATH];
    if (wide_to_utf8(wpath, path, sizeof(path)) == 0)
        return false;

    char nm[SC_NAME_LEN];
    base_name(path, nm, sizeof(nm));
    str_lower(nm);
    if (nm[0] == '\0')
        return false;

    if (full_out && full_cap) {
        size_t len = strlen(path);
        if (len >= full_cap) len = full_cap - 1;
        memcpy(full_out, path, len);
        full_out[len] = '\0';
    }
    if (name_out && name_cap) {
        size_t len = strlen(nm);
        if (len >= name_cap) len = name_cap - 1;
        memcpy(name_out, nm, len);
        name_out[len] = '\0';
    }
    return true;
}

/* Returns 1 if performed, 0 otherwise.
 *
 * audit M2: open the process handle ONCE (with the rights needed to act),
 * validate criticality on the image resolved FROM THAT HANDLE, prompt, then
 * re-validate on the same handle immediately before terminating/suspending.
 * The same handle is passed to the destructive call, so the pid cannot be
 * recycled while the confirmation prompt blocks. */
static int act_on_pid(DWORD pid, bool is_kill, const Config *cfg)
{
    const char *verb = is_kill ? "KILL" : "SUSPEND";

    /* Open once with the action right plus query rights for revalidation. */
    DWORD access = (is_kill ? PROCESS_TERMINATE : PROCESS_SUSPEND_RESUME)
                 | PROCESS_QUERY_LIMITED_INFORMATION;
    HANDLE h = OpenProcess(access, FALSE, pid);
    if (!h) {
        DWORD err = GetLastError();
        /* Could not open. is_critical_pid will fail closed for pid>8. */
        bool crit = is_critical_pid(pid);
        if (crit && !cfg->force_critical) {
            printf("REFUSED: %s on pid %lu - cannot open handle "
                   "(err=%lu), treating as critical; use --force-critical.\n",
                   verb, (unsigned long)pid, (unsigned long)err);
            audit_logf("%s pid %lu REFUSED: OpenProcess err=%lu (fail-closed critical)",
                       verb, (unsigned long)pid, (unsigned long)err);
        } else {
            printf("%s on pid %lu FAILED: OpenProcess err=%lu\n",
                   verb, (unsigned long)pid, (unsigned long)err);
            audit_logf("%s pid %lu FAILED: OpenProcess err=%lu",
                       verb, (unsigned long)pid, (unsigned long)err);
        }
        return 0;
    }

    /* Resolve the image FROM THE HANDLE (not a fresh OpenProcess by pid). */
    char path[SC_MAX_PATH], name[SC_NAME_LEN];
    bool resolved = handle_resolve(h, path, sizeof(path), name, sizeof(name));

    /* Criticality from the handle-resolved name; unresolved => fail closed. */
    bool crit = resolved ? name_is_critical(name, path) : true;
    if (crit && !cfg->force_critical) {
        printf("REFUSED: %s on critical pid %lu (%s) - use --force-critical to override.\n",
               verb, (unsigned long)pid, path[0] ? path : "?");
        audit_logf("%s pid %lu REFUSED: critical process (%s)",
                   verb, (unsigned long)pid, path[0] ? path : "?");
        CloseHandle(h);
        return 0;
    }

    if (!confirm(cfg->assume_yes,
                 "About to %s pid %lu (%s) [y/N]: ",
                 verb, (unsigned long)pid, path[0] ? path : "?")) {
        audit_logf("%s pid %lu DECLINED by operator", verb, (unsigned long)pid);
        CloseHandle(h);
        return 0;
    }

    /* Re-validate on the SAME handle immediately before acting: the image
     * path must still resolve and still match what we confirmed (audit M2).
     * A handle keeps the kernel object alive, so the pid behind it cannot be
     * reused; a mismatch here means something is badly wrong -- abort. */
    char path2[SC_MAX_PATH], name2[SC_NAME_LEN];
    bool resolved2 = handle_resolve(h, path2, sizeof(path2), name2, sizeof(name2));
    if (resolved != resolved2 ||
        (resolved2 && _stricmp(path, path2) != 0) ||
        (resolved2 && !cfg->force_critical && name_is_critical(name2, path2))) {
        printf("ABORTED: %s on pid %lu - image changed/became critical after "
               "prompt (was '%s', now '%s').\n",
               verb, (unsigned long)pid,
               path[0] ? path : "?", path2[0] ? path2 : "?");
        audit_logf("%s pid %lu ABORTED: revalidation mismatch (was '%s' now '%s')",
                   verb, (unsigned long)pid,
                   path[0] ? path : "?", path2[0] ? path2 : "?");
        CloseHandle(h);
        return 0;
    }

    audit_logf("%s pid %lu ATTEMPT (%s)", verb, (unsigned long)pid,
               path[0] ? path : "?");
    bool ok = is_kill ? do_kill_h(h, pid) : do_suspend_h(h, pid);
    CloseHandle(h);
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
