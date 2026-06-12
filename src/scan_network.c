/* scan_network.c - TCP/UDP connection triage via iphlpapi.
 *
 * Enumerates owner-pid TCP/UDP tables (IPv4 + IPv6), classifies each endpoint
 * against the cached process table, and emits findings for living-off-the-land
 * beacon shapes, reverse-shell sockets, suspicious listeners, and IOC hits.
 * With --watch it samples the TCP table on a cadence and flags regular-interval
 * connections (beaconing) by interval-stddev analysis.
 *
 * Libs: iphlpapi, ws2_32, kernel32.
 */
#include <winsock2.h>
#include <ws2tcpip.h>

#include "sentinelc.h"

#include <iphlpapi.h>
#include <ws2ipdef.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* ------------------------------------------------------------------ */
/* small helpers                                                        */
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

/* Format an IPv4 address held as a big-endian DWORD (network byte order,
 * as iphlpapi stores dwLocalAddr/dwRemoteAddr) into dotted-quad. */
static void fmt_ipv4_be(uint32_t be, char *out, size_t cap)
{
    const unsigned char *o = (const unsigned char *)&be;
    snprintf(out, cap, "%u.%u.%u.%u",
             (unsigned)o[0], (unsigned)o[1], (unsigned)o[2], (unsigned)o[3]);
}

/* iphlpapi stores ports in network byte order in the low 16 bits. */
static unsigned port_from_be(DWORD be_port)
{
    return (unsigned)ntohs((unsigned short)(be_port & 0xFFFF));
}

/* True if a big-endian IPv4 address is private/loopback/link-local/etc.
 * i.e. NOT a routable public address. */
static bool ipv4_is_private_be(uint32_t be)
{
    uint32_t h = ntohl(be);            /* host order */
    unsigned a = (h >> 24) & 0xFF;
    unsigned b = (h >> 16) & 0xFF;

    if (a == 10) return true;                       /* 10.0.0.0/8 */
    if (a == 127) return true;                      /* loopback */
    if (a == 172 && b >= 16 && b <= 31) return true;/* 172.16/12 */
    if (a == 192 && b == 168) return true;          /* 192.168/16 */
    if (a == 169 && b == 254) return true;          /* link-local */
    if (a == 0) return true;                        /* "this" / unspecified */
    if (a >= 224) return true;                      /* multicast / reserved */
    if (a == 100 && b >= 64 && b <= 127) return true;/* CGNAT 100.64/10 */
    return false;
}

/* True if an IPv6 address is loopback/link-local/unspecified/unique-local. */
static bool ipv6_is_private(const UCHAR addr[16])
{
    /* unspecified :: */
    bool all_zero = true;
    for (int i = 0; i < 16; i++)
        if (addr[i]) { all_zero = false; break; }
    if (all_zero)
        return true;
    /* loopback ::1 */
    bool loop = (addr[15] == 1);
    for (int i = 0; i < 15 && loop; i++)
        if (addr[i]) loop = false;
    if (loop)
        return true;
    /* link-local fe80::/10 */
    if (addr[0] == 0xfe && (addr[1] & 0xc0) == 0x80)
        return true;
    /* unique-local fc00::/7 */
    if ((addr[0] & 0xfe) == 0xfc)
        return true;
    /* multicast ff00::/8 */
    if (addr[0] == 0xff)
        return true;
    /* IPv4-mapped ::ffff:a.b.c.d -> defer to v4 rules */
    {
        bool mapped = true;
        for (int i = 0; i < 10 && mapped; i++)
            if (addr[i]) mapped = false;
        if (mapped && addr[10] == 0xff && addr[11] == 0xff) {
            uint32_t be;
            memcpy(&be, &addr[12], 4);
            return ipv4_is_private_be(be);
        }
    }
    return false;
}

static void fmt_ipv6(const UCHAR addr[16], char *out, size_t cap)
{
    struct in6_addr a;
    memcpy(&a, addr, 16);
    if (!InetNtopA(AF_INET6, &a, out, cap))
        copy_bounded(out, cap, "[ipv6?]");
}

/* Is this image name a script/office/LOLBin host? base name, case-insensitive. */
static bool is_lolbin_name(const char *name)
{
    static const char *names[] = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", NULL
    };
    if (!name || !name[0])
        return false;
    for (int i = 0; names[i]; i++)
        if (_stricmp(name, names[i]) == 0)
            return true;
    return false;
}

static bool is_shell_name(const char *name)
{
    if (!name || !name[0])
        return false;
    return _stricmp(name, "cmd.exe") == 0 ||
           _stricmp(name, "powershell.exe") == 0 ||
           _stricmp(name, "pwsh.exe") == 0;
}

/* A "console-ish" parent (a legit interactive shell ancestry). */
static bool parent_is_console(const char *pname)
{
    if (!pname || !pname[0])
        return false;
    return _stricmp(pname, "explorer.exe") == 0 ||
           _stricmp(pname, "cmd.exe") == 0 ||
           _stricmp(pname, "powershell.exe") == 0 ||
           _stricmp(pname, "pwsh.exe") == 0 ||
           _stricmp(pname, "WindowsTerminal.exe") == 0 ||
           _stricmp(pname, "conhost.exe") == 0 ||
           _stricmp(pname, "code.exe") == 0;
}

/* ------------------------------------------------------------------ */
/* per-row finding logic (shared by v4/v6)                             */
/* ------------------------------------------------------------------ */

static void eval_tcp_row(ScanCtx *c, DWORD pid, DWORD state,
                         const char *remote_ip, unsigned remote_port,
                         bool remote_public, bool have_ioc_hit)
{
    if (!c || !c->bus)
        return;

    ProcRec *pr = c->procs ? proctable_find(c->procs, pid) : NULL;
    const char *img  = (pr && pr->image_path[0]) ? pr->image_path : NULL;
    const char *name = (pr && pr->name[0]) ? pr->name : NULL;
    int  sstate = pr ? pr->sign_state : SIGN_UNKNOWN;

    /* skip allowlisted images entirely (except IOC, which is authoritative) */
    bool allowlisted = false;
    if (img && allowlist_match(img))
        allowlisted = true;
    else if (name && allowlist_match(name))
        allowlisted = true;

    char target[SC_MAX_PATH];
    snprintf(target, sizeof(target), "pid %lu", (unsigned long)pid);

    /* ---- NET.IOC_MATCH (authoritative, always fires) ---- */
    if (have_ioc_hit) {
        bus_emit(c->bus, "NET.IOC_MATCH", SEV_HIGH, 95, ACT_KILL, pid, target,
                 "Connection to known-bad IOC address",
                 "pid %lu (%s) -> %s:%u matches IOC indicator [image=%s]",
                 (unsigned long)pid, name ? name : "?",
                 remote_ip, remote_port, img ? img : "?");
    }

    if (allowlisted)
        return;

    bool established = (state == MIB_TCP_STATE_ESTAB);
    bool listening   = (state == MIB_TCP_STATE_LISTEN);

    /* ---- NET.LISTEN_SUSPICIOUS_PROC ---- */
    if (listening && img) {
        bool user_writable = path_is_user_writable(img);
        bool unsigned_img = (sstate == SIGN_UNSIGNED || sstate == SIGN_INVALID);
        if (user_writable || unsigned_img) {
            bus_emit(c->bus, "NET.LISTEN_SUSPICIOUS_PROC", SEV_HIGH, 80,
                     ACT_REVIEW, pid, target,
                     "Listening socket owned by user-writable/unsigned process",
                     "pid %lu (%s) LISTEN; image=%s [%s%s%s]",
                     (unsigned long)pid, name ? name : "?", img,
                     user_writable ? "user-writable" : "",
                     (user_writable && unsigned_img) ? "," : "",
                     unsigned_img ? sign_name((SignVerdict)sstate) : "");
        }
    }

    /* The remaining rules require an established outbound to a public IP. */
    if (!established || !remote_public)
        return;

    /* ---- NET.SHELL_SOCKET (reverse-shell shape) ---- */
    /* Genuinely conservative. ALL of the following must hold to emit CRITICAL:
     *   1. ESTABLISHED outbound TCP (already gated above).
     *   2. Remote is a PUBLIC, routable IP (already gated above via remote_public;
     *      excludes RFC1918/loopback/link-local/CGNAT and the v6 equivalents).
     *   3. The OWNING image is itself a shell/LOLBin (cmd/powershell/pwsh) -- NOT
     *      merely a process that happens to have a shell child. The "has a shell
     *      child" arm is dropped entirely: every terminal/git/IDE trips it.
     *   4. A corroborating signal that this shell is not an ordinary interactive
     *      session: the image is UNSIGNED/INVALID, OR runs from a user-writable/
     *      temp path, OR its parent is not a known console/shell host (a shell
     *      with a public socket and an unusual non-interactive parent).
     * A normal machine with powershell windows open to the internet (signed,
     * in System32, parented by explorer/conhost/terminal) produces ZERO hits. */
    if (name && is_shell_name(name)) {
        bool unsigned_img   = (sstate == SIGN_UNSIGNED || sstate == SIGN_INVALID);
        bool user_writable  = img ? path_is_user_writable(img) : false;

        bool noncon_parent = false;
        const char *pname = NULL;
        if (pr && c->procs) {
            ProcRec *par = proctable_find(c->procs, pr->ppid);
            pname = (par && par->name[0]) ? par->name : NULL;
            /* Only treat a *known* parent that isn't a console/shell host as
             * corroborating. If we couldn't resolve the parent, do NOT use it
             * as a signal (avoid FPs from un-inspectable ancestry). */
            noncon_parent = (pname != NULL) && !parent_is_console(pname);
        }

        /* #4 corroboration. We require at least one strong signal. */
        bool corroborated = unsigned_img || user_writable || noncon_parent;

        if (corroborated) {
            const char *why =
                unsigned_img  ? "shell image is unsigned/invalid" :
                user_writable ? "shell image runs from user-writable/temp path" :
                                "shell has non-console/non-shell parent";
            bus_emit(c->bus, "NET.SHELL_SOCKET", SEV_CRIT, 88, ACT_KILL,
                     pid, target,
                     "Established socket tied to a shell process (reverse-shell shape)",
                     "pid %lu (%s) ESTAB -> %s:%u; %s [image=%s parent=%s sign=%s]",
                     (unsigned long)pid, name, remote_ip, remote_port, why,
                     img ? img : "?", pname ? pname : "?",
                     sign_name((SignVerdict)sstate));
            return; /* CRIT subsumes the beacon-shape note below */
        }
    }

    /* ---- NET.RAW_IP_OUTBOUND (LOLBin beacon shape) ---- */
    if (name && is_lolbin_name(name)) {
        bus_emit(c->bus, "NET.RAW_IP_OUTBOUND", SEV_MED, 65, ACT_REVIEW,
                 pid, target,
                 "Script/LOLBin host making outbound connection to public IP",
                 "pid %lu (%s) ESTAB -> %s:%u [image=%s]",
                 (unsigned long)pid, name, remote_ip, remote_port,
                 img ? img : "?");
    }
}

/* ------------------------------------------------------------------ */
/* TCP table fetch with grow-on-insufficient-buffer                    */
/* ------------------------------------------------------------------ */

/* Generic fetcher: returns malloc'd buffer (caller frees) or NULL.
 * which selects v4/v6 via ulAf; tableClass passed through. */
static void *fetch_tcp_table(ScanCtx *c, ULONG family, const char *label)
{
    ULONG  size = 0;
    void  *buf  = NULL;
    DWORD  rc;

    /* first call to size */
    rc = GetExtendedTcpTable(NULL, &size, TRUE, family,
                             TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) {
        ctx_note_limit(c, "network: GetExtendedTcpTable(%s) sizing failed (rc=%lu)",
                       label, (unsigned long)rc);
        return NULL;
    }

    for (int attempt = 0; attempt < 6; attempt++) {
        free(buf);
        buf = malloc(size ? size : 4096);
        if (!buf) {
            ctx_note_limit(c, "network: OOM allocating TCP(%s) table", label);
            return NULL;
        }
        rc = GetExtendedTcpTable(buf, &size, TRUE, family,
                                 TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR)
            return buf;
        if (rc != ERROR_INSUFFICIENT_BUFFER) {
            ctx_note_limit(c, "network: GetExtendedTcpTable(%s) failed (rc=%lu)",
                           label, (unsigned long)rc);
            free(buf);
            return NULL;
        }
        /* loop: size was updated, retry with grown buffer */
    }
    free(buf);
    ctx_note_limit(c, "network: TCP(%s) table kept growing; gave up", label);
    return NULL;
}

static void *fetch_udp_table(ScanCtx *c, ULONG family, const char *label)
{
    ULONG  size = 0;
    void  *buf  = NULL;
    DWORD  rc;

    rc = GetExtendedUdpTable(NULL, &size, TRUE, family,
                             UDP_TABLE_OWNER_PID, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) {
        ctx_note_limit(c, "network: GetExtendedUdpTable(%s) sizing failed (rc=%lu)",
                       label, (unsigned long)rc);
        return NULL;
    }

    for (int attempt = 0; attempt < 6; attempt++) {
        free(buf);
        buf = malloc(size ? size : 4096);
        if (!buf) {
            ctx_note_limit(c, "network: OOM allocating UDP(%s) table", label);
            return NULL;
        }
        rc = GetExtendedUdpTable(buf, &size, TRUE, family,
                                 UDP_TABLE_OWNER_PID, 0);
        if (rc == NO_ERROR)
            return buf;
        if (rc != ERROR_INSUFFICIENT_BUFFER) {
            ctx_note_limit(c, "network: GetExtendedUdpTable(%s) failed (rc=%lu)",
                           label, (unsigned long)rc);
            free(buf);
            return NULL;
        }
    }
    free(buf);
    ctx_note_limit(c, "network: UDP(%s) table kept growing; gave up", label);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* snapshot pass                                                       */
/* ------------------------------------------------------------------ */

static void scan_tcp_v4(ScanCtx *c)
{
    MIB_TCPTABLE_OWNER_PID *tbl =
        (MIB_TCPTABLE_OWNER_PID *)fetch_tcp_table(c, AF_INET, "v4");
    if (!tbl)
        return;

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *r = &tbl->table[i];
        char ip[INET6_ADDRSTRLEN];
        fmt_ipv4_be((uint32_t)r->dwRemoteAddr, ip, sizeof(ip));
        unsigned rport = port_from_be(r->dwRemotePort);

        bool pub = !ipv4_is_private_be((uint32_t)r->dwRemoteAddr);
        bool ioc = (c->ioc && ioc_match_ip(c->ioc, (uint32_t)r->dwRemoteAddr));

        eval_tcp_row(c, r->dwOwningPid, r->dwState, ip, rport, pub, ioc);
    }
    free(tbl);
}

static void scan_tcp_v6(ScanCtx *c)
{
    MIB_TCP6TABLE_OWNER_PID *tbl =
        (MIB_TCP6TABLE_OWNER_PID *)fetch_tcp_table(c, AF_INET6, "v6");
    if (!tbl)
        return;

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        MIB_TCP6ROW_OWNER_PID *r = &tbl->table[i];
        char ip[INET6_ADDRSTRLEN];
        fmt_ipv6(r->ucRemoteAddr, ip, sizeof(ip));
        unsigned rport = port_from_be(r->dwRemotePort);

        bool pub = !ipv6_is_private(r->ucRemoteAddr);
        /* IOC IP set is ipv4-only per the contract; check mapped addrs. */
        bool ioc = false;
        if (c->ioc) {
            bool mapped = true;
            for (int k = 0; k < 10 && mapped; k++)
                if (r->ucRemoteAddr[k]) mapped = false;
            if (mapped && r->ucRemoteAddr[10] == 0xff && r->ucRemoteAddr[11] == 0xff) {
                uint32_t be;
                memcpy(&be, &r->ucRemoteAddr[12], 4);
                ioc = ioc_match_ip(c->ioc, be);
            }
        }

        eval_tcp_row(c, r->dwOwningPid, r->dwState, ip, rport, pub, ioc);
    }
    free(tbl);
}

/* UDP has no connection state; we only check listeners' owners and IOC hits
 * against the (local) bound address is not meaningful for remote IOC, so we
 * use UDP only for suspicious-owner listener notes mirroring LISTEN. */
static void scan_udp_v4(ScanCtx *c)
{
    MIB_UDPTABLE_OWNER_PID *tbl =
        (MIB_UDPTABLE_OWNER_PID *)fetch_udp_table(c, AF_INET, "v4");
    if (!tbl)
        return;

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        MIB_UDPROW_OWNER_PID *r = &tbl->table[i];
        /* Treat a bound UDP endpoint owned by a user-writable/unsigned image as
         * a suspicious listener (reuse the LISTEN rule path). */
        eval_tcp_row(c, r->dwOwningPid, MIB_TCP_STATE_LISTEN,
                     "0.0.0.0", port_from_be(r->dwLocalPort), false, false);
    }
    free(tbl);
}

static void scan_udp_v6(ScanCtx *c)
{
    MIB_UDP6TABLE_OWNER_PID *tbl =
        (MIB_UDP6TABLE_OWNER_PID *)fetch_udp_table(c, AF_INET6, "v6");
    if (!tbl)
        return;

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        MIB_UDP6ROW_OWNER_PID *r = &tbl->table[i];
        eval_tcp_row(c, r->dwOwningPid, MIB_TCP_STATE_LISTEN,
                     "[::]", port_from_be(r->dwLocalPort), false, false);
    }
    free(tbl);
}

/* ------------------------------------------------------------------ */
/* --watch beacon sampling                                             */
/* ------------------------------------------------------------------ */

#define BEACON_MAX_TRACK   512
#define BEACON_MAX_TS      64

typedef struct {
    DWORD    pid;
    uint32_t remote_be;        /* v4 remote addr, big-endian */
    unsigned port;
    int      nts;
    ULONGLONG ts[BEACON_MAX_TS];
} BeaconTrack;

static BeaconTrack *btrack_find(BeaconTrack *a, size_t n,
                                DWORD pid, uint32_t be, unsigned port)
{
    for (size_t i = 0; i < n; i++)
        if (a[i].pid == pid && a[i].remote_be == be && a[i].port == port)
            return &a[i];
    return NULL;
}

/* Sample established v4 TCP connections to public IPs, record timestamps. */
static void beacon_sample(ScanCtx *c, BeaconTrack *tracks, size_t *ntracks,
                          ULONGLONG now)
{
    MIB_TCPTABLE_OWNER_PID *tbl =
        (MIB_TCPTABLE_OWNER_PID *)fetch_tcp_table(c, AF_INET, "v4-watch");
    if (!tbl)
        return;

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *r = &tbl->table[i];
        if (r->dwState != MIB_TCP_STATE_ESTAB)
            continue;
        uint32_t be = (uint32_t)r->dwRemoteAddr;
        if (ipv4_is_private_be(be))
            continue;
        unsigned port = port_from_be(r->dwRemotePort);

        BeaconTrack *t = btrack_find(tracks, *ntracks, r->dwOwningPid, be, port);
        if (!t) {
            if (*ntracks >= BEACON_MAX_TRACK)
                continue;
            t = &tracks[(*ntracks)++];
            t->pid = r->dwOwningPid;
            t->remote_be = be;
            t->port = port;
            t->nts = 0;
        }
        if (t->nts < BEACON_MAX_TS)
            t->ts[t->nts++] = now;
    }
    free(tbl);
}

static void beacon_analyze(ScanCtx *c, BeaconTrack *tracks, size_t ntracks)
{
    for (size_t i = 0; i < ntracks; i++) {
        BeaconTrack *t = &tracks[i];
        if (t->nts < 4)
            continue;

        /* intervals between consecutive sightings */
        double sum = 0.0;
        int nint = t->nts - 1;
        double *iv = (double *)malloc((size_t)nint * sizeof(double));
        if (!iv)
            continue;
        for (int k = 1; k < t->nts; k++) {
            double d = (double)(t->ts[k] - t->ts[k - 1]);
            iv[k - 1] = d;
            sum += d;
        }
        double mean = sum / (double)nint;
        if (mean <= 0.0) { free(iv); continue; }

        double var = 0.0;
        for (int k = 0; k < nint; k++) {
            double dd = iv[k] - mean;
            var += dd * dd;
        }
        var /= (double)nint;
        double sd = sqrt(var);
        free(iv);

        double cv = sd / mean;          /* coefficient of variation */
        if (cv < 0.25) {
            ProcRec *pr = c->procs ? proctable_find(c->procs, t->pid) : NULL;
            const char *name = (pr && pr->name[0]) ? pr->name : "?";
            const char *img  = (pr && pr->image_path[0]) ? pr->image_path : "?";
            if ((pr && allowlist_match(img)) || allowlist_match(name))
                continue;

            char ip[INET6_ADDRSTRLEN];
            fmt_ipv4_be(t->remote_be, ip, sizeof(ip));
            char target[SC_MAX_PATH];
            snprintf(target, sizeof(target), "pid %lu", (unsigned long)t->pid);

            bus_emit(c->bus, "NET.BEACON", SEV_HIGH, 78, ACT_REVIEW,
                     t->pid, target,
                     "Regular-cadence outbound connection (beaconing)",
                     "pid %lu (%s) -> %s:%u seen %d times, mean interval %.0fms, "
                     "stddev %.0fms (cv=%.2f) [image=%s]",
                     (unsigned long)t->pid, name, ip, t->port,
                     t->nts, mean, sd, cv, img);
        }
    }
}

static void watch_beacons(ScanCtx *c, int watch_secs)
{
    BeaconTrack *tracks = (BeaconTrack *)calloc(BEACON_MAX_TRACK,
                                                sizeof(BeaconTrack));
    if (!tracks) {
        ctx_note_limit(c, "network: OOM allocating beacon tracker");
        return;
    }
    size_t ntracks = 0;

    ULONGLONG start = GetTickCount64();
    ULONGLONG deadline = start + (ULONGLONG)watch_secs * 1000ULL;

    for (;;) {
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
            break;
        beacon_sample(c, tracks, &ntracks, now);
        Sleep(1000);
    }
    /* one final sample at the end */
    beacon_sample(c, tracks, &ntracks, GetTickCount64());

    beacon_analyze(c, tracks, ntracks);
    free(tracks);
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

void scan_network(ScanCtx *c)
{
    if (!c || !c->bus)
        return;

    /* single snapshot of every table */
    scan_tcp_v4(c);
    scan_tcp_v6(c);
    scan_udp_v4(c);
    scan_udp_v6(c);

    /* beacon sampling only when requested */
    if (c->cfg && c->cfg->watch_secs > 0)
        watch_beacons(c, c->cfg->watch_secs);
}
