/* main.c - SentinelC entry point.
 *
 * Parses the CLI into a Config, builds a ScanCtx, runs scan_process to
 * completion (it fills ctx->procs which every other scanner reads), then fans
 * the remaining scanners out across a Win32 thread pool. Afterward it
 * correlates, renders the report, opens the audit log, applies any responder
 * actions, and tears everything down.
 */
#include "sentinelc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>      /* _isatty / _fileno for the progress heartbeat */

/* ------------------------------------------------------------------ */
/* CLI helpers                                                         */
/* ------------------------------------------------------------------ */

static void copy_arg(char *dst, size_t cap, const char *src)
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

static void print_version(void)
{
    printf("SentinelC %s\n", SC_VERSION);
}

static void print_help(const char *argv0)
{
    const char *prog = argv0 ? argv0 : "sentinelc";
    printf(
        "SentinelC %s - fast Windows threat triage scanner\n"
        "\n"
        "Usage: %s [scan-mode] [options]\n"
        "\n"
        "Scan modes:\n"
        "  --quick            Fast subset: process, service, persist, network (default)\n"
        "  --full             All scanners (adds keylog, rootkit)\n"
        "  --deep             Hash files / heavier checks\n"
        "  --watch N          Network beacon sampling window of N seconds\n"
        "  --scan-path PATH   Targeted file/directory scan (skips live scanners)\n"
        "\n"
        "Output:\n"
        "  --json             Emit JSON\n"
        "  --no-color         Disable ANSI color\n"
        "\n"
        "Responder (destructive; default is dry-run):\n"
        "  --kill PID         Terminate process PID\n"
        "  --suspend PID      Suspend process PID\n"
        "  --disable-service NAME  Disable a service\n"
        "  --quarantine PATH  Quarantine a file\n"
        "  --interactive      Prompt before each actionable finding\n"
        "  --yes              Skip confirmation prompts\n"
        "  --force-critical   Allow acting on critical system PIDs\n"
        "\n"
        "Integrity (Merkle FIM):\n"
        "  --baseline         Build/update a Merkle baseline of execution-relevant files\n"
        "  --integrity        Diff the current tree against the baseline (what changed)\n"
        "  --integrity-roots \"A;B;C\"  Semicolon-separated roots to scan (default: system dirs)\n"
        "  --baseline-file PATH        Baseline file location (default: %%ProgramData%%\\SentinelC\\integrity\\baseline.tsv)\n"
        "\n"
        "Tuning:\n"
        "  --allowlist PATH   Load an allowlist file\n"
        "  --ioc-dir PATH     Load IOC sets from a directory\n"
        "  --audit PATH       Write an audit log to PATH\n"
        "\n"
        "  --help             Show this help and exit\n"
        "  --version          Show version and exit\n",
        SC_VERSION, prog);
}

/* parse a DWORD pid from a string; returns false on bad input */
static bool parse_pid(const char *s, DWORD *out)
{
    if (!s || !s[0])
        return false;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s || (end && *end != '\0'))
        return false;
    *out = (DWORD)v;
    return true;
}

/* Returns 0 on success, 1 if the caller should exit 0 (help/version),
 * 2 on a parse error (caller exits non-zero). */
static int parse_cli(int argc, char **argv, Config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            print_help(argv[0]);
            return 1;
        }
        if (strcmp(a, "--version") == 0) {
            print_version();
            return 1;
        }
        if (strcmp(a, "--quick") == 0) {
            cfg->quick = true;
            continue;
        }
        if (strcmp(a, "--full") == 0) {
            cfg->full = true;
            continue;
        }
        if (strcmp(a, "--deep") == 0) {
            cfg->deep = true;
            continue;
        }
        if (strcmp(a, "--json") == 0) {
            cfg->json = true;
            continue;
        }
        if (strcmp(a, "--no-color") == 0) {
            cfg->no_color = true;
            continue;
        }
        if (strcmp(a, "--interactive") == 0) {
            cfg->interactive = true;
            continue;
        }
        if (strcmp(a, "--yes") == 0) {
            cfg->assume_yes = true;
            continue;
        }
        if (strcmp(a, "--force-critical") == 0) {
            cfg->force_critical = true;
            continue;
        }
        if (strcmp(a, "--baseline") == 0) {
            cfg->integrity_baseline = true;
            continue;
        }
        if (strcmp(a, "--integrity") == 0) {
            cfg->integrity_check = true;
            continue;
        }
        if (strcmp(a, "--integrity-roots") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--integrity-roots requires a semicolon list\n"); return 2; }
            copy_arg(cfg->integrity_roots, sizeof(cfg->integrity_roots), argv[++i]);
            continue;
        }
        if (strcmp(a, "--baseline-file") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--baseline-file requires a path\n"); return 2; }
            copy_arg(cfg->baseline_file, sizeof(cfg->baseline_file), argv[++i]);
            continue;
        }

        /* options that consume the next argv */
        if (strcmp(a, "--watch") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--watch requires N seconds\n"); return 2; }
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || v < 0) {
                fprintf(stderr, "--watch: invalid seconds '%s'\n", argv[i]);
                return 2;
            }
            cfg->watch_secs = (int)v;
            continue;
        }
        if (strcmp(a, "--scan-path") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--scan-path requires a path\n"); return 2; }
            copy_arg(cfg->scan_path, sizeof(cfg->scan_path), argv[++i]);
            continue;
        }
        if (strcmp(a, "--kill") == 0) {
            if (i + 1 >= argc || !parse_pid(argv[++i], &cfg->kill_pid)) {
                fprintf(stderr, "--kill requires a numeric PID\n");
                return 2;
            }
            continue;
        }
        if (strcmp(a, "--suspend") == 0) {
            if (i + 1 >= argc || !parse_pid(argv[++i], &cfg->suspend_pid)) {
                fprintf(stderr, "--suspend requires a numeric PID\n");
                return 2;
            }
            continue;
        }
        if (strcmp(a, "--disable-service") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--disable-service requires a name\n"); return 2; }
            copy_arg(cfg->disable_svc, sizeof(cfg->disable_svc), argv[++i]);
            continue;
        }
        if (strcmp(a, "--quarantine") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--quarantine requires a path\n"); return 2; }
            copy_arg(cfg->quarantine_path, sizeof(cfg->quarantine_path), argv[++i]);
            continue;
        }
        if (strcmp(a, "--allowlist") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--allowlist requires a path\n"); return 2; }
            copy_arg(cfg->allowlist_path, sizeof(cfg->allowlist_path), argv[++i]);
            continue;
        }
        if (strcmp(a, "--ioc-dir") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--ioc-dir requires a path\n"); return 2; }
            copy_arg(cfg->ioc_dir, sizeof(cfg->ioc_dir), argv[++i]);
            continue;
        }
        if (strcmp(a, "--audit") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--audit requires a path\n"); return 2; }
            copy_arg(cfg->audit_path, sizeof(cfg->audit_path), argv[++i]);
            continue;
        }

        fprintf(stderr, "Unknown argument: %s (try --help)\n", a);
        return 2;
    }

    /* default scan mode: quick (unless full was requested) */
    if (!cfg->quick && !cfg->full)
        cfg->quick = true;

    return 0;
}

/* ------------------------------------------------------------------ */
/* scanner dispatch on a Win32 thread pool                             */
/* ------------------------------------------------------------------ */

typedef void (*ScanFn)(ScanCtx *);

typedef struct {
    ScanFn       fn;
    ScanCtx     *ctx;
    const char  *name;     /* scanner label for the progress heartbeat */
    ULONGLONG    start;    /* GetTickCount64 at submit */
    volatile LONG done;    /* set to 1 by the worker when finished */
} ScanJob;

static VOID CALLBACK scan_work_cb(PTP_CALLBACK_INSTANCE inst,
                                  PVOID context,
                                  PTP_WORK work)
{
    (void)inst;
    (void)work;
    ScanJob *job = (ScanJob *)context;
    if (job && job->fn && job->ctx)
        job->fn(job->ctx);
    if (job)
        InterlockedExchange(&job->done, 1);
}

/* True if stderr is an interactive console. Phase/progress output is written to
 * stderr and gated on this, so it never pollutes --json (stdout) or a redirected
 * log, but shows live when you run a scan in a real terminal. */
static bool phase_tty(void)
{
    return _isatty(_fileno(stderr)) != 0;
}

/* One stderr status line, rewritable via carriage-return, only on a TTY.
 * We pad with trailing spaces to overwrite any longer previous line, which
 * works on every console without needing VT escape support. */
#define PHASE_WIDTH 100
static void phase_emit(const char *s, bool newline)
{
    if (!phase_tty()) return;
    char buf[PHASE_WIDTH + 8];
    int n = snprintf(buf, sizeof buf, "%-*.*s", PHASE_WIDTH, PHASE_WIDTH, s);
    (void)n;
    fprintf(stderr, "\r%s%s", buf, newline ? "\n" : "");
    fflush(stderr);
}

static void phase_line(const char *s)      { phase_emit(s, false); }
static void phase_done_line(const char *s) { phase_emit(s, true); }

/* Run a set of scanners concurrently. Falls back to sequential if the pool
 * cannot be created. scan_process must already have completed. names[i] labels
 * fns[i] for the progress heartbeat (may be NULL). */
static void run_scanners_parallel(ScanCtx *ctx, ScanFn *fns,
                                  const char **names, size_t n)
{
    if (n == 0)
        return;

    ScanJob *jobs = (ScanJob *)calloc(n, sizeof(ScanJob));
    PTP_WORK *works = (PTP_WORK *)calloc(n, sizeof(PTP_WORK));
    if (!jobs || !works) {
        /* OOM: run sequentially */
        for (size_t i = 0; i < n; i++)
            if (fns[i]) fns[i](ctx);
        free(jobs);
        free(works);
        return;
    }

    size_t submitted = 0;
    for (size_t i = 0; i < n; i++) {
        if (!fns[i])
            continue;
        jobs[submitted].fn    = fns[i];
        jobs[submitted].ctx   = ctx;
        jobs[submitted].name  = (names && names[i]) ? names[i] : "scanner";
        jobs[submitted].start = GetTickCount64();
        jobs[submitted].done  = 0;
        works[submitted] = CreateThreadpoolWork(scan_work_cb, &jobs[submitted], NULL);
        if (!works[submitted]) {
            /* pool work creation failed: run this one inline now */
            fns[i](ctx);
            jobs[submitted].done = 1;
            continue;
        }
        SubmitThreadpoolWork(works[submitted]);
        submitted++;
    }

    /* Heartbeat: poll the done flags and show which scanners are still running,
     * with elapsed time, so a slow or hung scanner is obvious. TTY-gated. */
    ULONGLONG last = 0;
    for (;;) {
        size_t remaining = 0;
        for (size_t i = 0; i < submitted; i++)
            if (!jobs[i].done) remaining++;
        if (remaining == 0)
            break;
        ULONGLONG now = GetTickCount64();
        if (phase_tty() && now - last >= 1000) {   /* refresh ~1/s */
            char line[512];
            int off = snprintf(line, sizeof line, "  scanning (%zu running):",
                               remaining);
            for (size_t i = 0; i < submitted && off > 0 && off < (int)sizeof line; i++) {
                if (jobs[i].done) continue;
                unsigned secs = (unsigned)((now - jobs[i].start) / 1000);
                off += snprintf(line + off, sizeof line - (size_t)off,
                                " %s(%us%s)", jobs[i].name, secs,
                                secs >= 20 ? " SLOW" : "");
            }
            phase_line(line);
            last = now;
        }
        Sleep(120);
    }

    for (size_t i = 0; i < submitted; i++) {
        if (works[i]) {
            WaitForThreadpoolWorkCallbacks(works[i], FALSE);
            CloseThreadpoolWork(works[i]);
        }
    }
    phase_done_line("  scanners complete.");

    free(jobs);
    free(works);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    Config cfg;
    int pr = parse_cli(argc, argv, &cfg);
    if (pr == 1)
        return 0;        /* help / version */
    if (pr == 2)
        return 2;        /* parse error */

    /* ---- build context ---- */
    FindingBus bus;
    ProcTable  procs;
    bus_init(&bus);
    proctable_init(&procs);

    ScanCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cfg   = &cfg;
    ctx.bus   = &bus;
    ctx.procs = &procs;
    ctx.ioc   = NULL;
    InitializeCriticalSection(&ctx.limit_lock);
    ctx.limitations[0] = '\0';

    /* privilege / elevation detection */
    ctx.is_admin        = process_is_elevated();
    ctx.have_debug_priv = enable_debug_privilege();

    /* signature verification cache lifetime spans the whole scan */
    sign_cache_init();

    /* optional tuning inputs (both safe if missing). If the user did not pass
     * explicit paths, auto-load rules\ next to the executable so the shipped
     * defaults (vendor allowlist, IOC lists) apply without extra flags. */
    {
        char exedir[SC_MAX_PATH] = {0};
        DWORD n = GetModuleFileNameA(NULL, exedir, sizeof(exedir));
        if (n > 0 && n < sizeof(exedir)) {
            char *slash = strrchr(exedir, '\\');
            if (slash) *slash = '\0';
        } else {
            exedir[0] = '\0';
        }
        if (cfg.allowlist_path[0]) {
            allowlist_load(cfg.allowlist_path);
        } else if (exedir[0]) {
            char def[SC_MAX_PATH];
            snprintf(def, sizeof(def), "%s\\rules\\allowlist.txt", exedir);
            allowlist_load(def);                 /* no-op if absent */
        }
        if (cfg.ioc_dir[0]) {
            ctx.ioc = ioc_load(cfg.ioc_dir);
        } else if (exedir[0]) {
            char def[SC_MAX_PATH];
            snprintf(def, sizeof(def), "%s\\rules", exedir);
            ctx.ioc = ioc_load(def);             /* NULL if absent/empty */
        }
    }

    /* ---- dispatch ---- */
    if (cfg.integrity_baseline || cfg.integrity_check) {
        /* standalone Merkle FIM mode: builds/diffs its own output and prints
         * it directly. Skips the live scanners, correlation, report, and
         * responder below. */
        audit_open(cfg.audit_path[0] ? cfg.audit_path : NULL);
        scan_integrity(&ctx);
        audit_close();

        if (ctx.ioc)
            ioc_free(ctx.ioc);
        allowlist_free();
        sign_cache_free();
        DeleteCriticalSection(&ctx.limit_lock);
        proctable_free(&procs);
        bus_free(&bus);
        return 0;
    }
    if (cfg.scan_path[0]) {
        /* targeted file/dir scan only */
        scan_path(&ctx);
    } else {
        /* scan_process FIRST and to completion: it fills ctx->procs. */
        phase_line("  scanning processes...");
        ULONGLONG p0 = GetTickCount64();
        scan_process(&ctx);
        {
            char d[64];
            snprintf(d, sizeof d, "  processes done (%us).",
                     (unsigned)((GetTickCount64() - p0) / 1000));
            phase_done_line(d);
        }

        /* remaining scanners run concurrently */
        ScanFn fns[8];
        const char *names[8];
        size_t n = 0;
        fns[n] = scan_service;  names[n] = "service";    n++;
        fns[n] = scan_persist;  names[n] = "persistence"; n++;
        fns[n] = scan_network;  names[n] = "network";     n++;
        if (cfg.full) {
            fns[n] = scan_keylog;  names[n] = "keylogger"; n++;
            fns[n] = scan_rootkit; names[n] = "rootkit";   n++;
            fns[n] = scan_creds;   names[n] = "cred-access"; n++;
            fns[n] = scan_memscan; names[n] = "memory";    n++;
        }
        run_scanners_parallel(&ctx, fns, names, n);
    }

    /* ---- correlate, report, respond ---- */
    correlate(&ctx);
    report_render(&bus, &ctx);

    audit_open(cfg.audit_path[0] ? cfg.audit_path : NULL);
    int actions = respond_apply(&ctx);
    audit_logf("respond_apply performed %d action(s)", actions);
    audit_close();

    /* ---- teardown ---- */
    if (ctx.ioc)
        ioc_free(ctx.ioc);
    allowlist_free();
    sign_cache_free();

    DeleteCriticalSection(&ctx.limit_lock);
    proctable_free(&procs);
    bus_free(&bus);

    return 0;
}
