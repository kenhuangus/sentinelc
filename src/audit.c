/* audit.c - SentinelC append-only audit log.
 * Thread-safe via CRITICAL_SECTION. Degrades to stderr if file unavailable.
 * C11, Win32 user-mode. Libs: kernel32.
 */
#include "sentinelc.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static struct {
    FILE            *fp;        /* NULL => log to stderr */
    bool             open;
    CRITICAL_SECTION lock;
    bool             lock_init;
} g_audit = { NULL, false, {0}, false };

/* Race-free one-time creation of g_audit.lock. Multiple threads may call
 * audit_logf() before audit_open(); without this guard two threads could each
 * InitializeCriticalSection() the same object, corrupting it. */
static INIT_ONCE g_audit_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK audit_init_lock_cb(PINIT_ONCE o, PVOID p, PVOID *ctx)
{
    (void)o; (void)p; (void)ctx;
    InitializeCriticalSection(&g_audit.lock);
    g_audit.lock_init = true;
    return TRUE;
}

static void audit_ensure_lock(void)
{
    InitOnceExecuteOnce(&g_audit_once, audit_init_lock_cb, NULL, NULL);
}

/* Build the default audit path: %ProgramData%\SentinelC\audit.log
 * Returns true on success. Also ensures the directory exists. */
static bool default_audit_path(char *out, size_t cap)
{
    char base[SC_MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", base, (DWORD)sizeof(base));
    if (n == 0 || n >= sizeof(base)) {
        /* fall back to a sane default */
        strncpy(base, "C:\\ProgramData", sizeof(base) - 1);
        base[sizeof(base) - 1] = '\0';
    }

    char dir[SC_MAX_PATH];
    if (_snprintf_s(dir, sizeof(dir), _TRUNCATE, "%s\\SentinelC", base) < 0)
        return false;

    /* CreateDirectory is fine if it already exists. */
    CreateDirectoryA(dir, NULL);

    if (_snprintf_s(out, cap, _TRUNCATE, "%s\\audit.log", dir) < 0)
        return false;
    return true;
}

void audit_open(const char *path)
{
    audit_ensure_lock();

    EnterCriticalSection(&g_audit.lock);

    if (g_audit.open) {
        /* already open; idempotent */
        LeaveCriticalSection(&g_audit.lock);
        return;
    }

    char resolved[SC_MAX_PATH];
    const char *target = NULL;

    if (path && path[0]) {
        target = path;
    } else if (default_audit_path(resolved, sizeof(resolved))) {
        target = resolved;
    }

    if (target) {
        /* append mode; created if absent */
        g_audit.fp = fopen(target, "ab");
    }

    /* If file open failed, fp stays NULL and we degrade to stderr. */
    g_audit.open = true;

    LeaveCriticalSection(&g_audit.lock);

    audit_logf("=== SentinelC audit session start (v%s) ===", SC_VERSION);
}

void audit_logf(const char *fmt, ...)
{
    /* audit_open may not have been called; ensure the lock exists (race-free)
     * so we never crash and degrade to stderr. */
    audit_ensure_lock();

    SYSTEMTIME st;
    GetLocalTime(&st);

    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(msg, sizeof(msg), fmt ? fmt : "", ap);
    va_end(ap);
    if (m < 0) msg[0] = '\0';

    /* Sanitize the assembled message so attacker-controlled fields (paths,
     * service names, process images) cannot forge log entries by embedding
     * CR/LF, and cannot smuggle terminal control sequences. Each log call is
     * exactly one line; the only newline is the one we append below. */
    for (char *p = msg; *p; ++p) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '\n' || ch == '\r' || ch == '\t')
            *p = ' ';
        else if (ch < 0x20 || ch == 0x7f)
            *p = '?';
    }

    char line[2400];
    int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
                        "%04u-%02u-%02u %02u:%02u:%02u.%03u  %s\n",
                        st.wYear, st.wMonth, st.wDay,
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                        msg);
    if (n < 0) {
        line[sizeof(line) - 1] = '\0';
    }

    EnterCriticalSection(&g_audit.lock);
    FILE *out = g_audit.fp ? g_audit.fp : stderr;
    fputs(line, out);
    fflush(out);
    LeaveCriticalSection(&g_audit.lock);
}

void audit_close(void)
{
    if (!g_audit.lock_init)
        return;

    EnterCriticalSection(&g_audit.lock);
    if (g_audit.fp) {
        fflush(g_audit.fp);
        fclose(g_audit.fp);
        g_audit.fp = NULL;
    }
    g_audit.open = false;
    LeaveCriticalSection(&g_audit.lock);

    DeleteCriticalSection(&g_audit.lock);
    g_audit.lock_init = false;
    /* Reset the one-time guard so a subsequent audit_open()/audit_logf() after
     * a close re-creates the lock instead of reusing the deleted one. */
    InitOnceInitialize(&g_audit_once);
}
