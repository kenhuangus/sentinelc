# Architecture — SentinelC

## 1. Overview

SentinelC is a single user-mode Win32 C executable. It is organized as a small
core (CLI, scheduler, finding bus, reporter) plus independent **scanner
modules** that each emit `Finding` records, and a **responder** that acts on
findings. Everything is read-only until the responder is explicitly invoked.

```
                         +------------------------+
                         |        main()          |
                         |  CLI parse / config    |
                         +-----------+------------+
                                     |
                         +-----------v------------+
                         |     Scan Engine        |
                         |  (orchestrator, thread |
                         |   pool, finding bus)    |
                         +--+----+----+----+----+--+
                            |    |    |    |    |
        +-------------------+    |    |    |    +--------------------+
        |          +-------------+    |    +----------+             |
        v          v                  v               v             v
  +----------+ +---------+      +-----------+   +-----------+  +-----------+
  | Process  | | Service |      |  Rootkit  |   |  Network  |  |Persistence|
  | Scanner  | | Scanner |      | Cross-View|   |  Scanner  |  |  Scanner  |
  +----+-----+ +----+----+      +-----+-----+   +-----+-----+  +-----+-----+
       |            |                 |               |              |
       +------+-----+--------+--------+-------+-------+------+-------+
              |              |                 |              |
         +----v----+   +-----v-----+    +------v-----+   +----v-----+
         |  PE /    |   |  Signing  |    |  Entropy / |   | Keylogger|
         | Image    |   | (WinTrust)|    |  Heuristic |   |  /Hook   |
         | Utils    |   |           |    |  Engine    |   | Scanner  |
         +----+-----+   +-----+-----+    +------+-----+   +----+-----+
              |               |                 |              |
              +-------+-------+--------+--------+------+-------+
                      |                |               |
                      v                v               v
              +---------------------------------------------+
              |            Finding Bus (in-memory)          |
              |   dedup, correlate, score (sev x conf)      |
              +----------------------+----------------------+
                                     |
                  +------------------+------------------+
                  v                                     v
          +---------------+                     +----------------+
          |   Reporter    |                     |   Responder    |
          | console/JSON  |                     | kill/suspend/  |
          |               |                     | disable/quarant|
          +---------------+                     +-------+--------+
                                                        |
                                                +-------v--------+
                                                |  Audit Log     |
                                                | (append-only)  |
                                                +----------------+
```

## 2. Core data structures

```c
typedef enum { SEV_INFO, SEV_LOW, SEV_MED, SEV_HIGH, SEV_CRIT } Severity;

typedef struct {
    char        rule_id[32];      // e.g. "PROC.UNSIGNED_SYS32"
    Severity    severity;
    int         confidence;       // 0-100
    char        title[128];
    char        evidence[512];    // human-readable proof
    char        target[260];      // path / pid / service name
    DWORD       pid;              // 0 if N/A
    char        recommended[64];  // "kill" | "disable" | "quarantine" | "review"
} Finding;

typedef struct {
    Finding*    items;
    size_t      count, cap;
    CRITICAL_SECTION lock;        // scanners push concurrently
} FindingBus;
```

Scanners never print. They only `bus_push(&bus, finding)`. This keeps modules
testable and the output centralized and rankable.

## 3. Modules

### 3.1 Scan Engine (orchestrator)
- Parses config, requests privileges (`SeDebugPrivilege`, checks Admin).
- Dispatches scanners on a small Win32 thread pool (`QueueUserWorkItem` /
  `CreateThreadpoolWork`). Modules are independent → embarrassingly parallel.
- Joins, then runs the **correlation** pass on the finding bus.

### 3.2 Process Scanner (`scan_process.c`)
- Primary enumeration: `NtQuerySystemInformation(SystemProcessInformation)` for
  full data in one syscall (fast); fallback `CreateToolhelp32Snapshot`.
- For each process: open with least privilege, get image path
  (`QueryFullProcessImageName`), command line (PEB read or `NtQuery...`),
  token user + integrity level, parent PID.
- Calls Signing + PE utils + Entropy engine on the image.
- Memory anomaly check: `VirtualQueryEx` scan for private RWX regions / executable
  regions not backed by an image (injection heuristic).
- Emits findings: `PROC.UNSIGNED_SYS32`, `PROC.MASQUERADE`, `PROC.TEMP_PATH`,
  `PROC.RWX_MEM`, `PROC.SUSPICIOUS_PARENT`, `PROC.PACKED`.

### 3.3 Service Scanner (`scan_service.c`)
- `OpenSCManager` + `EnumServicesStatusEx` (all services, all states).
- Per service: `QueryServiceConfig` → binary path, start type, account.
- Resolve binary, run Signing + path checks. Cross-reference PID if running.
- Findings: `SVC.UNSIGNED`, `SVC.USERWRITABLE_PATH`, `SVC.UNQUOTED_PATH`,
  `SVC.SUSPICIOUS_DLL` (svchost groups), `SVC.RECENT` (creation time heuristic).

### 3.4 Rootkit Cross-View Scanner (`scan_rootkit.c`)
- **Process cross-view**: build PID sets from 4 sources — Toolhelp,
  `EnumProcesses`, `NtQuerySystemInformation`, `WTSEnumerateProcesses`. Any PID
  present in one but hidden from another → `RK.HIDDEN_PROC`.
- **File cross-view**: for sensitive dirs, diff `FindFirstFile/FindNextFile`
  against `NtQueryDirectoryFile` → `RK.HIDDEN_FILE`.
- **Driver inventory**: `EnumDeviceDrivers` + `GetDeviceDriverFileName`; verify
  signature; flag non-Microsoft unsigned drivers → `RK.SUSPICIOUS_DRIVER`.
- Documented limit: cannot see a driver that unlinks itself from the loaded-
  module list (DKOM). v1 catches naive hooks and user-mode hiding.

### 3.5 Network Scanner (`scan_network.c`)
- `GetExtendedTcpTable` / `GetExtendedUdpTable` (with owning PID).
- Join endpoints to processes from the Process Scanner cache.
- Findings: `NET.LISTEN_SUSPICIOUS_PROC`, `NET.RAW_IP_OUTBOUND`,
  `NET.SHELL_SOCKET` (process owns socket + child cmd/powershell),
  `NET.IOC_MATCH` (local IOC IP list). Optional `--watch N` samples N seconds to
  detect periodic beaconing (jitter/interval scoring).

### 3.6 Persistence Scanner (`scan_persist.c`)
- Registry: Run/RunOnce (HKLM+HKCU+Wow64), Winlogon (Shell/Userinit),
  AppInit_DLLs, IFEO debuggers, common COM-hijack CLSIDs.
- Filesystem: Startup folders (all users + current).
- Scheduled Tasks: parse `%WINDIR%\System32\Tasks` XML (or COM ITaskService).
- WMI: query `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`.
- Each entry's target binary runs through Signing/PE checks.
- Findings: `PERSIST.RUNKEY`, `PERSIST.IFEO`, `PERSIST.WMI_SUB`,
  `PERSIST.TASK`, `PERSIST.STARTUP_FOLDER`, `PERSIST.COM_HIJACK`.

### 3.7 Keylogger / Hook Scanner (`scan_keylog.c`)
- Enumerate top-level windows / threads; where determinable, detect global
  `WH_KEYBOARD_LL`/`WH_MOUSE_LL` hook owners.
- `GetRegisteredRawInputDevices` per process where accessible; flag keyboard
  raw-input registrants that aren't expected apps.
- Static heuristic: for each process image, check IAT for the hook/poll APIs
  (`SetWindowsHookEx`, `GetAsyncKeyState`, `RegisterRawInputDevices`,
  `GetRawInputData`) combined with file-write or network capability → score.
- Findings: `KEY.LL_HOOK`, `KEY.RAW_INPUT`, `KEY.POLL_HEURISTIC`.

### 3.8 Shared utilities
- **PE/Image utils** (`pe.c`): map file, parse headers, section entropy,
  imports (IAT) enumeration, detect packers (entropy + section names like
  `UPX0`, missing imports).
- **Signing** (`sign.c`): `WinVerifyTrust` Authenticode + catalog signature;
  extract signer subject; cache results by path+mtime to avoid recomputation.
- **Entropy/Heuristic engine** (`heur.c`): Shannon entropy, scoring helpers,
  allowlist matching, path classification (system vs user-writable vs temp).
- **IOC** (`ioc.c`): optional local lists — SHA-256 hashes, bad IPs/domains,
  tiny built-in YARA-subset string rules.

### 3.9 Reporter (`report.c`)
- Sorts findings by `severity` then `confidence`.
- Console: ANSI-colored table; summary counts; explicit "limitations" footer
  (e.g. "not elevated → driver scan skipped").
- `--json`: array of Finding objects for SIEM.

### 3.10 Responder (`respond.c`)
- Actions: `TerminateProcess`, `NtSuspendProcess`/thread suspend,
  `ChangeServiceConfig` → Disabled + `ControlService` stop, quarantine = move to
  `%PROGRAMDATA%\SentinelC\quarantine\` + deny-all ACL + record original path.
- **Guards**: never-kill list (PID 0/4, csrss, wininit, services, lsass unless
  `--force-critical`); confirmation prompt unless `--yes`; dry-run unless an
  action flag is present.
- Writes every attempted/actual action to the append-only audit log.

## 4. Privilege model
- Detect Admin (`CheckTokenMembership` for Administrators).
- Enable `SeDebugPrivilege` when present (process memory/handles).
- Each scanner degrades gracefully: on `ACCESS_DENIED`, emit an `INFO` finding
  that the check was partial, never crash. Reporter aggregates skipped checks.

## 5. Concurrency & performance
- Scanners run in parallel on a thread pool.
- Single process enumeration pass is cached and shared (network/keylog/service
  reuse it — no re-enumeration).
- Signing results cached by `path+mtime` (the expensive call).
- Target: quick scan < 10s by avoiding per-file hashing unless `--deep`.

## 6. Build & layout
```
sentinelc/
  src/
    main.c            CLI, config, orchestration entry
    engine.c/.h       thread pool, finding bus, correlation
    scan_process.c
    scan_service.c
    scan_rootkit.c
    scan_network.c
    scan_persist.c
    scan_keylog.c
    pe.c  sign.c  heur.c  ioc.c
    report.c  respond.c  audit.c
    util.c  (string, path, registry helpers)
  include/sentinelc.h
  rules/   ioc_hashes.txt  ioc_ips.txt  yara_subset.txt  allowlist.txt
  tests/   (VM test fixtures, planted-threat scripts)
  CMakeLists.txt   Makefile (MinGW)   build.ps1
```
- Toolchains: MSVC (`cl` / CMake) and MinGW-w64 (`gcc`). Static-link CRT.
- Libs: `ntdll`, `advapi32`, `psapi`, `wintrust`, `crypt32`, `iphlpapi`,
  `wtsapi32`, `wevtapi`, `ole32`, `oleaut32` (WMI/tasks via COM).

## 7. Correlation pass (why a flat scanner isn't enough)
After all scanners push, the engine runs cross-module correlation to *raise
confidence and reduce noise*:
- A process that is (unsigned in temp) **and** (listening) **and** (has a Run
  key) **and** (spawns powershell) → single high-confidence `CORR.IMPLANT`
  finding instead of 4 medium ones.
- A service whose binary equals a flagged process image → merge.
- Correlation is what makes the output actionable rather than a wall of
  medium-severity noise.

## 8. Testing strategy (summary; detail in plan.md)
- Unit tests for `pe.c`, `heur.c`, `sign.c` (golden files).
- Integration: a Windows test VM with planted artifacts (EICAR, nc reverse
  shell, SetWindowsHookEx keylogger, Run-key persistence, userland hider) —
  assert each is flagged with the right rule id, and that dry-run mutates
  nothing (audit log diff).
