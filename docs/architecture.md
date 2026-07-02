# SentinelC Architecture

## Overview

SentinelC is a single user-mode Win32 C executable. The engine parses CLI
configuration, builds a shared process table, runs scanner modules, correlates
findings, renders console or JSON output, and only then invokes responder actions
when the operator explicitly requested them.

The tool is read-only by default. Destructive actions are gated by explicit
flags or interactive prompts and are written to the audit log.

## Core Flow

1. `main.c` parses the CLI into `Config`.
2. `scan_process.c` runs first and fills the shared `ProcTable`.
3. Remaining live scanners run on a Win32 thread pool:
   service, persistence, network, keylogger/spyware, rootkit, credential access,
   memory scan, and AMSI/ETW evasion checks.
4. Optional special modes run separately:
   `--scan-path`, `--baseline`, `--integrity`, and `--offline-like`.
5. `correlate()` adds multi-signal findings.
6. `suppress_apply()` removes known false positives.
7. `report.c` writes human or JSON output.
8. `respond.c` performs only the requested response actions.

## Shared Types

The authoritative definitions are in `include/sentinelc.h`.

```c
typedef struct {
    char       rule_id[SC_RULEID_LEN];   /* 40 bytes */
    Severity   severity;
    int        confidence;               /* 0..100 */
    char       title[SC_TITLE_LEN];      /* 160 bytes */
    char       evidence[SC_EVID_LEN];    /* 1024 bytes */
    char       target[SC_MAX_PATH];      /* 1024 bytes */
    DWORD      pid;                      /* 0 if N/A */
    ActionKind recommended;
} Finding;

typedef struct {
    Finding         *items;
    size_t           count;
    size_t           cap;
    CRITICAL_SECTION lock;
} FindingBus;
```

Scanners do not print directly. They emit findings through `bus_emit()` and let
the reporter handle presentation.

## Scanner Modules

- `scan_process.c`: process inventory, image path, command line, signer state,
  packed-image checks, RWX/unbacked executable memory, parent-chain heuristics,
  PPID spoofing, LOLBin arguments, and encoded PowerShell.
- `scan_service.c`: service and driver inventory, service binary normalization,
  signature/path checks, unquoted paths, and suspicious `svchost` service DLLs.
- `scan_persist.c`: Run keys, Winlogon, AppInit, AppCertDLLs, IFEO,
  SilentProcessExit, startup folders, scheduled tasks, WMI subscriptions, COM
  hijacks, service registry view, Defender/security-service tamper, proxy
  settings, browser extensions, and App Paths.
- `scan_network.c`: TCP/UDP endpoints, suspicious listeners, shell-socket shape,
  raw-IP outbound connections, IOC IP matches, and optional beacon sampling.
- `scan_keylog.c`: low-level hooks, raw input, key-state polling, clipboard,
  screen, media-capture, and credential-API capability combinations.
- `scan_rootkit.c`: process and file cross-view checks plus loaded driver
  inventory. It documents the user-mode limitation against advanced DKOM.
- `scan_creds.c`: LSASS handle access and sensitive file/browser credential
  handle access.
- `scan_memscan.c`: private executable memory, reflective PE markers, shellcode
  markers, and process hollowing checks.
- `scan_evade.c`: AMSI and ETW prologue integrity checks in live processes.
- `scan_path.c`: targeted file/directory scan, PE/signing/entropy checks, hash
  IOC checks, YARA-lite rules, and full-file string IOC streaming.
- `scan_integrity.c`: Merkle file-integrity baseline/check. Both baseline and
  integrity modes stream-hash file contents; baselines are HMAC-authenticated
  with a DPAPI-wrapped key.
- `scan_offline.c`: no-reboot offline-like hunting through VSS snapshots,
  offline hive inspection, boot-driver checks, Defender exclusion checks, and
  raw-volume probes where accessible.

## Response Model

`respond.c` supports process kill, process suspend, service disable, and file
quarantine. Important safety properties:

- Dry-run by default.
- Confirmation required unless `--yes`.
- Critical processes are refused unless `--force-critical`.
- Process actions open one handle, validate the image from that handle, prompt,
  then revalidate before acting to avoid PID-reuse races.
- Quarantine opens the source with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects
  reparse points/directories, creates a SYSTEM/Admin-only quarantine directory,
  moves by handle, and uses copy/delete fallback for cross-volume moves.

## Fleet Console And Endpoint Agent

`fleet-console/server.js` is a zero-dependency Node.js dashboard. Read APIs use a
console bearer token. Ingest uses per-host bearer tokens, so a host token can
only submit for its configured hostname. Helper upload scripts reject
non-loopback plaintext HTTP.

`installer/install.ps1` installs `sentinelc.exe`, rules, and agent scripts into
an ACL-locked directory, stores the host ingest token protected with DPAPI
LocalMachine scope, and registers a SYSTEM scheduled task for daily/startup/on
demand scans.

## Build And Layout

```text
sentinelc/
  include/sentinelc.h
  src/*.c
  rules/
  fleet-console/
  installer/
  codex/
  tests/
  Makefile
  build.ps1
  build.sh
```

Supported build paths are MinGW-w64 through `build.ps1`, `build.sh`, or
`Makefile`. The current build scripts add stack-protector, FORTIFY,
format-string checks, ASLR, DEP, and high-entropy ASLR flags. CFG/CET remain an
MSVC release-build concern.

Current Windows build output is about 1.1 MB.

## Important Limits

- No kernel driver ships in this repo. Advanced kernel rootkits can hide from
  user-mode cross-view checks.
- `--offline-like` narrows the Defender Offline gap without rebooting, but the
  live Windows kernel is still active.
- The YARA implementation is intentionally a lightweight subset, not libyara.
- Defender/SmartScreen may flag unsigned development builds; production release
  needs code signing.
