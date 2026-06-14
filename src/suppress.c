/* suppress.c - false-positive suppression engine.
 *
 * A security scanner that cries wolf gets ignored. This module removes
 * known-good findings WITHOUT blindly muting a whole rule (which would let
 * real malware hide behind a reused name). Three layers, applied as a single
 * post-scan filter pass over the FindingBus (after correlate(), before report):
 *
 *   1. Built-in, research-based auto-suppression. The noisy heuristic rules
 *      ("looks odd: unsigned / user-writable / RWX / installs a hook") are
 *      suppressed when the offending binary is VALIDLY Authenticode-signed by
 *      Microsoft or a curated trusted publisher. That is the JIT-engine and
 *      signed-service false-positive class. High-signal rules (encoded
 *      PowerShell, LOLBIN abuse, credential access, reflective PE) are NEVER
 *      auto-suppressed -- a validly signed powershell.exe running an encoded
 *      command IS the attack.
 *
 *   2. A persistent whitelist (rules/suppress.txt) matched by:
 *        <RULE_GLOB> sha256:<hex64>     exact content hash (code signature)
 *        <RULE_GLOB> signer:<subject>   validly signed by this publisher
 *        <RULE_GLOB> path:<substring>   path/name substring, scoped to the rule
 *      RULE_GLOB is an exact rule id (PROC.RWX_MEM), a family (NET.*), or *.
 *      Hash pins are exact: a trojaned replacement with the same name does not
 *      inherit the pass.
 *
 *   3. --mark-fp <RULE> <file>: hash a file and append a sha256 pin to
 *      suppress.txt. For unsigned-but-known tools (dev runtimes, etc.).
 *
 * Auto-suppression (layer 1) can be disabled with --no-auto-fp.
 */

#include "sentinelc.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

/* ------------------------------------------------------------------ */
/* suppress.txt parsed entries                                         */
/* ------------------------------------------------------------------ */

typedef enum { M_SHA256 = 0, M_SIGNER, M_PATH } MatchKind;

typedef struct {
    char      rule[SC_RULEID_LEN]; /* "PROC.RWX_MEM", "NET.*", or "*"   */
    MatchKind kind;
    char      val[SC_MAX_PATH];    /* hash hex / signer substr / path  */
} SuppRule;

static struct {
    SuppRule *items;
    size_t    count;
    size_t    cap;
    bool      loaded;
} g_supp;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void str_lower_local(char *s)
{
    for (; *s; ++s)
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
}

static bool ci_contains_local(const char *hay, const char *needle)
{
    if (!hay || !needle || !needle[0])
        return false;
    size_t nl = strlen(needle);
    for (const char *p = hay; *p; ++p) {
        if (_strnicmp(p, needle, nl) == 0)
            return true;
    }
    return false;
}

/* rule-glob match: exact, "FAMILY.*" prefix, or "*". case-insensitive. */
static bool rule_glob_match(const char *glob, const char *rule_id)
{
    if (!glob || !rule_id)
        return false;
    if (strcmp(glob, "*") == 0)
        return true;
    size_t gl = strlen(glob);
    if (gl >= 2 && glob[gl - 1] == '*') {
        /* "NET.*" -> prefix "NET." */
        return _strnicmp(glob, rule_id, gl - 1) == 0;
    }
    return _stricmp(glob, rule_id) == 0;
}

/* SHA-256 of a file, lowercase hex (65 bytes incl NUL). false on error. */
static bool sha256_file_hex(const char *path, char hex_out[65])
{
    wchar_t wpath[SC_MAX_PATH];
    if (utf8_to_wide(path, wpath, SC_MAX_PATH) == 0)
        return false;

    HANDLE h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hh = NULL;
    bool ok = false;
    DWORD objlen = 0, cb = 0;
    unsigned char *obj = NULL;
    unsigned char digest[32];

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        goto done;
    if (!NT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objlen,
                                      sizeof(objlen), &cb, 0)))
        goto done;
    obj = (unsigned char *)malloc(objlen);
    if (!obj)
        goto done;
    if (!NT_SUCCESS(BCryptCreateHash(alg, &hh, obj, objlen, NULL, 0, 0)))
        goto done;

    {
        unsigned char buf[65536];
        DWORD rd = 0;
        for (;;) {
            if (!ReadFile(h, buf, sizeof(buf), &rd, NULL))
                goto done;
            if (rd == 0)
                break;
            if (!NT_SUCCESS(BCryptHashData(hh, buf, rd, 0)))
                goto done;
        }
    }
    if (!NT_SUCCESS(BCryptFinishHash(hh, digest, sizeof(digest), 0)))
        goto done;

    static const char *hexd = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        hex_out[i * 2]     = hexd[(digest[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hexd[digest[i] & 0xF];
    }
    hex_out[64] = '\0';
    ok = true;

done:
    if (hh) BCryptDestroyHash(hh);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    free(obj);
    CloseHandle(h);
    return ok;
}

/* ------------------------------------------------------------------ */
/* layer 1: built-in research-based auto-suppression                   */
/* ------------------------------------------------------------------ */

/* Heuristic rules whose dominant false-positive cause is "validly signed
 * code that legitimately does something that looks odd" (JIT RWX memory,
 * a signed service listening, an input app installing a keyboard hook,
 * a signed app shipped under AppData). These are safe to auto-suppress
 * when the binary carries a valid signature. Deliberately excludes
 * PROC.ENCODED_CMD, PROC.LOLBIN_ARGS, MEM.REFLECTIVE_PE, PROC.HOLLOWED,
 * EVADE.*, CRED.*, PERSIST.* and RK.* -- those are dangerous precisely
 * BECAUSE attackers run them through signed binaries. */
static bool rule_is_signed_noise(const char *rule_id)
{
    static const char *noisy[] = {
        "PROC.RWX_MEM",
        "PROC.TEMP_PATH",
        "MEM.SHELLCODE",
        "NET.LISTEN_SUSPICIOUS_PROC",
        "KEY.LL_HOOK",
        "KEY.RAWINPUT",
        NULL
    };
    for (int i = 0; noisy[i]; ++i)
        if (_stricmp(noisy[i], rule_id) == 0)
            return true;
    return false;
}

/* Publishers we treat as trusted for layer-1 auto-suppression of the noisy
 * rules. Microsoft is handled separately via SIGN_SIGNED_MS. Substring,
 * case-insensitive against the Authenticode subject. */
static bool signer_is_trusted(const char *signer)
{
    if (!signer || !signer[0])
        return false;
    static const char *pubs[] = {
        "Microsoft", "Google", "Mozilla", "Oracle", "Adobe",
        "Dell", "Intel", "NVIDIA", "Realtek", "Logitech", "Lenovo",
        "Apple", "Zoom", "Valve", "Discord", "Brave Software",
        "Kingsoft", "Hewlett", "ASUSTeK", "Synaptics",
        NULL
    };
    for (int i = 0; pubs[i]; ++i)
        if (ci_contains_local(signer, pubs[i]))
            return true;
    return false;
}

/* ------------------------------------------------------------------ */
/* resolve the binary a finding is about                               */
/* ------------------------------------------------------------------ */

/* Returns true and fills out[] with a binary path for finding f, using the
 * cached process table first (most reliable) then the target field if it
 * looks like a real file. */
static bool finding_binary(const ScanCtx *c, const Finding *f, char *out, size_t cap)
{
    if (f->pid && c && c->procs) {
        ProcRec *pr = proctable_find(c->procs, f->pid);
        if (pr && pr->image_path[0]) {
            strncpy(out, pr->image_path, cap - 1);
            out[cap - 1] = '\0';
            return true;
        }
    }
    /* target may itself be a path ("C:\...\foo.exe") rather than "pid N". */
    if (f->target[0] && (f->target[1] == ':' || f->target[0] == '\\')) {
        DWORD attr = GetFileAttributesA(f->target);
        if (attr != INVALID_FILE_ATTRIBUTES &&
            !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            strncpy(out, f->target, cap - 1);
            out[cap - 1] = '\0';
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* decision: should this finding be suppressed?                        */
/* ------------------------------------------------------------------ */

/* Returns a static reason string if the finding should be dropped, else NULL.
 * Hash/signer are computed lazily and only when an applicable rule exists. */
static const char *should_suppress(const ScanCtx *c, const Finding *f)
{
    char bin[SC_MAX_PATH];
    bool have_bin = finding_binary(c, f, bin, sizeof bin);

    /* lazy-computed, cached within this call */
    bool       sig_done = false; SignVerdict sig = SIGN_UNKNOWN;
    char       signer[SC_NAME_LEN] = {0};
    bool       hash_done = false; bool hash_ok = false; char hash[65] = {0};

    /* ---- layer 2: explicit suppress.txt entries ---- */
    for (size_t i = 0; i < g_supp.count; ++i) {
        const SuppRule *r = &g_supp.items[i];
        if (!rule_glob_match(r->rule, f->rule_id))
            continue;

        if (r->kind == M_PATH) {
            if ((f->target[0] && ci_contains_local(f->target, r->val)) ||
                (have_bin && ci_contains_local(bin, r->val)))
                return "suppress.txt:path";
        } else if (r->kind == M_SHA256) {
            if (!have_bin)
                continue;
            if (!hash_done) { hash_ok = sha256_file_hex(bin, hash); hash_done = true; }
            if (hash_ok && _stricmp(hash, r->val) == 0)
                return "suppress.txt:sha256";
        } else if (r->kind == M_SIGNER) {
            if (!have_bin)
                continue;
            if (!sig_done) { sig = sign_verify(bin, signer, sizeof signer); sig_done = true; }
            if ((sig == SIGN_SIGNED || sig == SIGN_SIGNED_MS) &&
                ci_contains_local(signer, r->val))
                return "suppress.txt:signer";
        }
    }

    /* ---- layer 1: built-in signed-noise auto-suppression ---- */
    if (c && c->cfg && !c->cfg->no_auto_fp && have_bin &&
        rule_is_signed_noise(f->rule_id)) {
        if (!sig_done) { sig = sign_verify(bin, signer, sizeof signer); sig_done = true; }
        if (sig == SIGN_SIGNED_MS)
            return "auto:signed-microsoft";
        if (sig == SIGN_SIGNED && signer_is_trusted(signer))
            return "auto:signed-trusted";
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* public: load / apply / free                                         */
/* ------------------------------------------------------------------ */

static void supp_push(const char *rule, MatchKind kind, const char *val)
{
    if (g_supp.count == g_supp.cap) {
        size_t ncap = g_supp.cap ? g_supp.cap * 2 : 16;
        SuppRule *n = (SuppRule *)realloc(g_supp.items, ncap * sizeof(SuppRule));
        if (!n) return;
        g_supp.items = n;
        g_supp.cap = ncap;
    }
    SuppRule *r = &g_supp.items[g_supp.count++];
    memset(r, 0, sizeof *r);
    strncpy(r->rule, rule, sizeof(r->rule) - 1);
    r->kind = kind;
    strncpy(r->val, val, sizeof(r->val) - 1);
}

static char *trim_local(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') ++s;
    size_t len = strlen(s);
    while (len > 0 && (s[len-1]==' '||s[len-1]=='\t'||s[len-1]=='\r'||s[len-1]=='\n'))
        s[--len] = '\0';
    return s;
}

void suppress_load(const char *path)
{
    suppress_free();
    g_supp.loaded = true;
    if (!path || !path[0])
        return;
    FILE *f = fopen(path, "rb");
    if (!f)
        return; /* missing => no-op */

    char buf[SC_MAX_PATH + 128];
    while (fgets(buf, sizeof buf, f)) {
        /* strip trailing comment introduced by " #" */
        char *hash = strstr(buf, " #");
        if (hash) *hash = '\0';
        char *line = trim_local(buf);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        /* split into <rule> <matcher> */
        char *sp = line;
        while (*sp && *sp != ' ' && *sp != '\t') ++sp;
        if (!*sp)
            continue; /* no matcher -> ignore (don't blanket-mute) */
        *sp = '\0';
        char *rule = line;
        char *matcher = trim_local(sp + 1);

        if (_strnicmp(matcher, "sha256:", 7) == 0) {
            char *v = trim_local(matcher + 7);
            str_lower_local(v);
            supp_push(rule, M_SHA256, v);
        } else if (_strnicmp(matcher, "signer:", 7) == 0) {
            supp_push(rule, M_SIGNER, trim_local(matcher + 7));
        } else if (_strnicmp(matcher, "path:", 5) == 0) {
            supp_push(rule, M_PATH, trim_local(matcher + 5));
        }
        /* unknown matcher kinds are ignored on purpose */
    }
    fclose(f);
}

void suppress_apply(ScanCtx *c)
{
    if (!c || !c->bus)
        return;
    FindingBus *b = c->bus;

    /* If auto-fp is off and no suppress.txt entries, nothing to do. */
    if ((!c->cfg || c->cfg->no_auto_fp) && g_supp.count == 0)
        return;

    EnterCriticalSection(&b->lock);

    size_t kept = 0;
    int n_auto = 0, n_rule = 0;
    for (size_t i = 0; i < b->count; ++i) {
        const char *why = should_suppress(c, &b->items[i]);
        if (why) {
            if (strncmp(why, "auto:", 5) == 0) n_auto++;
            else n_rule++;
            continue; /* drop */
        }
        if (kept != i)
            b->items[kept] = b->items[i];
        kept++;
    }
    int dropped = (int)(b->count - kept);
    b->count = kept;

    LeaveCriticalSection(&b->lock);

    if (dropped > 0)
        ctx_note_limit(c,
            "suppressed %d known false positive(s): %d auto (validly signed), "
            "%d by suppress.txt", dropped, n_auto, n_rule);
}

void suppress_free(void)
{
    free(g_supp.items);
    g_supp.items = NULL;
    g_supp.count = g_supp.cap = 0;
    g_supp.loaded = false;
}

/* ------------------------------------------------------------------ */
/* public: --mark-fp <rule> <file> -> append sha256 pin to suppress.txt */
/* ------------------------------------------------------------------ */

int suppress_mark_fp(const char *suppress_path, const char *rule_id, const char *file)
{
    if (!suppress_path || !rule_id || !file) {
        fprintf(stderr, "mark-fp: missing argument\n");
        return 2;
    }
    char hex[65];
    if (!sha256_file_hex(file, hex)) {
        fprintf(stderr, "mark-fp: cannot read/hash file: %s\n", file);
        return 1;
    }

    /* base name for the comment */
    const char *base = file;
    for (const char *p = file; *p; ++p)
        if (*p == '\\' || *p == '/')
            base = p + 1;

    SYSTEMTIME st;
    GetLocalTime(&st);

    FILE *f = fopen(suppress_path, "ab");
    if (!f) {
        fprintf(stderr, "mark-fp: cannot open suppress file: %s\n", suppress_path);
        return 1;
    }
    fprintf(f, "%s sha256:%s  # %s marked FP %04d-%02d-%02d\r\n",
            rule_id, hex, base, st.wYear, st.wMonth, st.wDay);
    fclose(f);

    printf("Marked false positive:\n");
    printf("  rule   : %s\n", rule_id);
    printf("  file   : %s\n", file);
    printf("  sha256 : %s\n", hex);
    printf("  -> appended to %s\n", suppress_path);
    printf("Future scans will suppress %s for this exact binary.\n", rule_id);
    return 0;
}
