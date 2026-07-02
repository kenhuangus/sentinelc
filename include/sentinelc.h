/* SentinelC - fast Windows threat triage scanner.
 * Shared contracts. Every module compiles against this header.
 * C11, Win32 user-mode. Build: MinGW-w64 (x86_64-w64-mingw32) or MSVC.
 */
#ifndef SENTINELC_H
#define SENTINELC_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00 /* Windows 10 */
#endif

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SC_VERSION "1.0.0"

/* ---- limits ---- */
#define SC_MAX_PATH     1024
#define SC_MAX_CMDLINE  4096
#define SC_RULEID_LEN   40
#define SC_TITLE_LEN    160
#define SC_EVID_LEN     1024
#define SC_NAME_LEN     256

/* ---- severity / confidence ---- */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW  = 1,
    SEV_MED  = 2,
    SEV_HIGH = 3,
    SEV_CRIT = 4
} Severity;

const char *sev_name(Severity s);   /* util.c */

/* recommended action codes (responder maps these) */
typedef enum {
    ACT_REVIEW = 0,
    ACT_KILL,
    ACT_SUSPEND,
    ACT_DISABLE_SVC,
    ACT_QUARANTINE
} ActionKind;

/* ---- a single finding ---- */
typedef struct {
    char       rule_id[SC_RULEID_LEN];   /* e.g. "PROC.UNSIGNED_SYS32" */
    Severity   severity;
    int        confidence;               /* 0..100 */
    char       title[SC_TITLE_LEN];
    char       evidence[SC_EVID_LEN];    /* human-readable proof */
    char       target[SC_MAX_PATH];      /* path / service name / "pid 1234" */
    DWORD      pid;                      /* 0 if N/A */
    ActionKind recommended;
} Finding;

/* ---- thread-safe finding bus ---- */
typedef struct {
    Finding         *items;
    size_t           count;
    size_t           cap;
    CRITICAL_SECTION lock;
} FindingBus;

void bus_init(FindingBus *b);
void bus_free(FindingBus *b);
/* Copies *f. Thread-safe. Returns false only on OOM. */
bool bus_push(FindingBus *b, const Finding *f);
/* Convenience: build+push in one call. Thread-safe. */
void bus_emit(FindingBus *b, const char *rule_id, Severity sev, int confidence,
              ActionKind rec, DWORD pid, const char *target,
              const char *title, const char *evidence_fmt, ...);

/* ---- configuration (parsed from CLI) ---- */
typedef struct {
    bool quick;          /* fast subset (default if neither quick/full set) */
    bool full;           /* all scanners */
    bool deep;           /* hash files, heavier checks */
    int  watch_secs;     /* >0 => network beacon sampling window */
    bool json;           /* JSON output */
    bool no_color;

    /* targeted file/dir scan */
    char scan_path[SC_MAX_PATH];  /* empty => not a path scan */

    /* responder (destructive) -- all default off => dry-run */
    DWORD kill_pid;          /* 0 => none */
    DWORD suspend_pid;       /* 0 => none */
    char  disable_svc[SC_NAME_LEN]; /* empty => none */
    char  quarantine_path[SC_MAX_PATH]; /* empty => none */
    bool  interactive;       /* prompt per actionable finding */
    bool  assume_yes;        /* --yes : skip confirmation */
    bool  force_critical;    /* allow acting on critical PIDs */

    /* tuning */
    char allowlist_path[SC_MAX_PATH];
    char ioc_dir[SC_MAX_PATH];
    char audit_path[SC_MAX_PATH];

    /* false-positive suppression (suppress.c) */
    bool no_auto_fp;                  /* --no-auto-fp : disable layer-1 auto */
    char suppress_path[SC_MAX_PATH];  /* --suppress PATH; empty => default */
    char mark_fp_rule[SC_RULEID_LEN]; /* --mark-fp RULE FILE : append + exit */
    char mark_fp_file[SC_MAX_PATH];

    /* integrity / Merkle FIM (appended; zero-init safe) */
    bool integrity_baseline;   /* --baseline : build/update baseline */
    bool integrity_check;      /* --integrity : diff vs baseline */
    char integrity_roots[4096];/* --integrity-roots "A;B;C" (semicolon list); empty => defaults */
    char baseline_file[SC_MAX_PATH]; /* --baseline-file PATH; empty => default location */
} Config;

/* ---- cached process record (populated by scan_process, read by others) ---- */
typedef struct {
    DWORD  pid;
    DWORD  ppid;
    char   image_path[SC_MAX_PATH];   /* full path, "" if unknown */
    char   name[SC_NAME_LEN];         /* base name */
    char   cmdline[SC_MAX_CMDLINE];   /* "" if unobtainable */
    char   user[SC_NAME_LEN];         /* DOMAIN\user, "" if unknown */
    int    integrity;                 /* SECURITY_MANDATORY_* RID, -1 unknown */
    int    sign_state;                /* SignVerdict (see sign.h values) cached */
    bool   suspicious_mem;            /* private RWX / unbacked exec found */
    bool   accessible;                /* could we open it for full inspection */
    uint64_t create_time;            /* process CreateTime (FILETIME u64), 0 unknown */
} ProcRec;

typedef struct {
    ProcRec *items;
    size_t   count;
    size_t   cap;
} ProcTable;

/* ---- IOC sets (loaded once, read by scanners) ---- */
typedef struct IocSet IocSet;        /* opaque, defined in ioc.c */
typedef struct YaraRules YaraRules;  /* opaque, defined in yara_lite.c */

/* ---- shared scan context handed to every scanner ---- */
typedef struct {
    Config     *cfg;
    FindingBus *bus;
    ProcTable  *procs;     /* shared cache; scan_process fills it first */
    IocSet     *ioc;       /* may be NULL */
    YaraRules  *yara;      /* compiled YARA-subset rules; may be NULL */
    bool        is_admin;
    bool        have_debug_priv;
    /* limitations accumulator (thread-safe append) */
    CRITICAL_SECTION limit_lock;
    char        limitations[4096];
} ScanCtx;

/* record a "could not inspect X" note for the report footer. thread-safe. */
void ctx_note_limit(ScanCtx *c, const char *fmt, ...);

/* =====================================================================
 *  Scanner module entry points. Each reads ctx, pushes Findings.
 *  Read-only. Safe to run on a thread pool.
 * ===================================================================== */
void scan_process(ScanCtx *c);   /* scan_process.c -- also fills c->procs */
void scan_service(ScanCtx *c);   /* scan_service.c */
void scan_rootkit(ScanCtx *c);   /* scan_rootkit.c */
void scan_network(ScanCtx *c);   /* scan_network.c */
void scan_persist(ScanCtx *c);   /* scan_persist.c */
void scan_keylog(ScanCtx *c);    /* scan_keylog.c */
void scan_path(ScanCtx *c);      /* pe.c/heur -- targeted file/dir scan */
void scan_integrity(ScanCtx *c); /* scan_integrity.c -- Merkle FIM baseline/check */
void scan_creds(ScanCtx *c);     /* scan_creds.c -- credential-access detection */
void scan_memscan(ScanCtx *c);   /* scan_memscan.c -- in-memory injected-code scan */
void scan_evade(ScanCtx *c);     /* scan_evade.c -- AMSI/ETW tamper detection */

/* correlation pass: promotes multi-signal artifacts. engine.c */
void correlate(ScanCtx *c);

/* =====================================================================
 *  Process table helpers (proc_cache.c)
 * ===================================================================== */
void   proctable_init(ProcTable *t);
void   proctable_free(ProcTable *t);
ProcRec *proctable_add(ProcTable *t);            /* returns zeroed slot */
ProcRec *proctable_find(ProcTable *t, DWORD pid);

/* =====================================================================
 *  PE / image analysis (pe.c)
 * ===================================================================== */
typedef struct {
    bool   is_pe;
    bool   is_dll;
    bool   is_64bit;
    double overall_entropy;     /* 0..8 */
    double max_section_entropy;
    bool   looks_packed;        /* entropy/section/import heuristic */
    int    import_count;
    /* capability flags derived from IAT */
    bool   imp_hook_api;        /* SetWindowsHookEx etc */
    bool   imp_keystate_api;    /* GetAsyncKeyState/GetKeyState */
    bool   imp_rawinput_api;    /* Register/GetRawInputData */
    bool   imp_clipboard_api;   /* clipboard read/listen APIs */
    bool   imp_screen_api;      /* screenshot / desktop capture APIs */
    bool   imp_media_capture_api; /* mic/camera capture APIs */
    bool   imp_cred_api;        /* Cred/Vault/DPAPI secret-read APIs */
    bool   imp_net_api;         /* ws2_32 connect/send/WSASocket */
    bool   imp_proc_inject_api; /* WriteProcessMemory/CreateRemoteThread */
    bool   imp_crypt_api;       /* crypt/ransomware-ish */
    char   packer_hint[64];     /* e.g. "UPX", "" if none */
} PeInfo;

/* Analyze a file on disk. Returns false if not a readable PE. */
bool pe_analyze(const char *path, PeInfo *out);

/* Shannon entropy of a buffer, 0..8. (heur.c) */
double shannon_entropy(const unsigned char *buf, size_t len);

/* =====================================================================
 *  Authenticode / catalog signing (sign.c)
 * ===================================================================== */
typedef enum {
    SIGN_UNKNOWN = 0,    /* not checked / error */
    SIGN_UNSIGNED,       /* no signature */
    SIGN_INVALID,        /* signature present but failed verification */
    SIGN_SIGNED,         /* valid signature, untrusted/unknown signer */
    SIGN_SIGNED_MS       /* valid & signer is Microsoft */
} SignVerdict;

const char *sign_name(SignVerdict v);            /* util.c */
/* Verify a file's signature (embedded + catalog). Result cached by path+mtime.
 * signer_out (may be NULL) receives the signer subject (<= SC_NAME_LEN). */
SignVerdict sign_verify(const char *path, char *signer_out, size_t signer_cap);
void        sign_cache_init(void);
void        sign_cache_free(void);

/* =====================================================================
 *  Heuristics / path classification / allowlist (heur.c)
 * ===================================================================== */
typedef enum {
    PATHLOC_SYSTEM = 0,   /* System32 / WinSxS */
    PATHLOC_PROGRAMFILES,
    PATHLOC_WINDOWS,
    PATHLOC_USER_WRITABLE,/* AppData, ProgramData (user-writable), Users\Public */
    PATHLOC_TEMP,
    PATHLOC_RECYCLE,
    PATHLOC_OTHER
} PathLoc;

PathLoc path_classify(const char *path);
bool    path_is_user_writable(const char *path); /* temp/appdata/recycle/etc */
/* True if path's base name matches a known system image name but lives
 * outside its legitimate directory (masquerade). */
bool    name_is_masquerade(const char *image_path);

void    allowlist_load(const char *path);        /* optional; safe if missing */
bool    allowlist_match(const char *path_or_name);
void    allowlist_free(void);

/* =====================================================================
 *  False-positive suppression (suppress.c)
 * ===================================================================== */
/* Load rules\suppress.txt (typed: sha256:/signer:/path:). Safe if missing. */
void suppress_load(const char *path);
/* Filter the bus in place: drop known-good findings. Call after correlate(),
 * before report_render(). Layer 1 (signed-noise auto) honors cfg->no_auto_fp. */
void suppress_apply(ScanCtx *c);
void suppress_free(void);
/* --mark-fp: hash `file`, append "<rule> sha256:<hash>" to suppress_path.
 * Returns 0 on success. */
int  suppress_mark_fp(const char *suppress_path, const char *rule_id,
                      const char *file);

/* =====================================================================
 *  IOC sets (ioc.c)
 * ===================================================================== */
IocSet *ioc_load(const char *dir);   /* NULL if dir missing/empty */
void    ioc_free(IocSet *s);
bool    ioc_match_ip(IocSet *s, uint32_t ipv4_be);   /* big-endian ipv4 */
bool    ioc_match_hash_sha256(IocSet *s, const char *hex64);
bool    ioc_match_string(IocSet *s, const char *haystack); /* yara-subset */

/* =====================================================================
 *  Reporter (report.c)
 * ===================================================================== */
void report_render(const FindingBus *b, const ScanCtx *c);

/* =====================================================================
 *  Responder + audit (respond.c, audit.c)  -- DESTRUCTIVE
 * ===================================================================== */
/* Apply any responder actions requested in cfg. Honors dry-run/guards.
 * Returns number of actions actually performed. */
int  respond_apply(ScanCtx *c);
/* True if pid is a never-kill critical system process. */
bool is_critical_pid(DWORD pid);

void audit_open(const char *path);
void audit_logf(const char *fmt, ...);
void audit_close(void);

/* =====================================================================
 *  util.c -- small helpers shared everywhere
 * ===================================================================== */
/* UTF-16 -> UTF-8 into out (returns bytes written, 0 on error). */
size_t wide_to_utf8(const wchar_t *w, char *out, size_t cap);
size_t utf8_to_wide(const char *s, wchar_t *out, size_t cap_wchars);
void   str_lower(char *s);
bool   str_iendswith(const char *s, const char *suffix);
bool   str_icontains(const char *hay, const char *needle);
void   base_name(const char *path, char *out, size_t cap);
/* Enable SeDebugPrivilege on current process. Returns true on success. */
bool   enable_debug_privilege(void);
bool   process_is_elevated(void);

/* =====================================================================
 *  Live console progress (progress.c)  -- STDERR, TTY-gated, self-rewriting
 * =====================================================================
 * A single self-rewriting status line on stderr. All functions are no-ops
 * when stderr is not a TTY (output redirected), so stdout JSON and piped
 * logs stay clean. Not thread-safe (callers are single-threaded). Safe to
 * pass NULL to step/end.
 */
typedef struct ProgressBar ProgressBar;   /* opaque */

/* Begin a progress bar. label is a short prefix (e.g. "Hashing files").
 * total_units == 0 => indeterminate mode (spinner + count + elapsed, no %/ETA).
 * is_bytes: when total_units counts bytes, numerator/denominator are humanized
 * (B/KB/MB/GB); otherwise rendered as plain counts (e.g. files). */
ProgressBar *progress_begin(const char *label, uint64_t total_units, bool is_bytes);

/* Update progress. units_done is cumulative; current_item is the path/name
 * currently being processed (may be NULL). Throttled to ~10 Hz; the call is
 * cheap when throttled. */
void progress_step(ProgressBar *p, uint64_t units_done, const char *current_item);

/* Finish: draw the final line at 100%, emit a newline, flush, free. NULL-safe. */
void progress_end(ProgressBar *p);

/* =====================================================================
 *  YARA-subset rule engine (yara_lite.c)
 * =====================================================================
 * Generic byte/text pattern matcher over a focused subset of YARA syntax.
 * Pure C, libc only. Parses `rule <Name> { strings: ... condition: ... }`
 * rule files; text strings support ascii/wide/nocase modifiers; hex strings
 * support full-byte `??` wildcards; conditions support
 *   any of them | all of them | <N> of them | flat $a and/or $b
 * (unrecognized conditions fall back to "any of them"). Caps: <=1024 rules,
 * <=64 strings/rule, <=256 pattern bytes, <=64-char rule names. Malformed
 * input is skipped, never fatal.
 */
typedef struct YaraRules YaraRules;            /* opaque */
YaraRules *yara_load(const char *path);        /* parse a .yar file; NULL if missing/empty/none */
void       yara_free(YaraRules *y);
/* Scan buf; on the first rule whose condition is satisfied, copy its name to
 * out (bounded) and return true. false if nothing matched. */
bool       yara_scan(YaraRules *y, const unsigned char *buf, size_t len,
                     char *out, size_t cap);

#endif /* SENTINELC_H */
