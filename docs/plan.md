# Implementation Plan — SentinelC

Phased, milestone-based plan. Each milestone is independently buildable and
testable. Estimates assume a single focused developer. Order is chosen so that
shared infrastructure exists before the modules that depend on it, and so that
the **read-only scanners are fully working and trusted before any
kill/quarantine code exists**.

## Guiding principles
- Read-only first. The responder (destructive code) is the **last** milestone.
- Every scanner ships with a planted-threat test in the VM before it's "done".
- Dry-run is the default at every stage; destructive paths gated behind flags.
- Honest output: each milestone adds its "limitations" reporting too.

---

## Milestone 0 — Project skeleton & build (0.5 day)
- Repo layout per architecture.md.
- `CMakeLists.txt` (MSVC) + `Makefile` (MinGW) + `build.ps1`; static CRT.
- `include/sentinelc.h`: `Finding`, `Severity`, `FindingBus`, config struct.
- `main.c`: CLI parsing (`--quick`, `--full`, `--json`, `--deep`, `--watch`,
  action flags, `--yes`, `--scan-path`), help text, version.
- Stub engine that pushes one dummy finding → reporter prints it.
- **Exit criteria**: builds clean on MSVC + MinGW; `sentinelc --help` works;
  dummy finding prints in console and `--json`.

## Milestone 1 — Core engine + shared utils (1 day)
- `engine.c`: thread pool, `FindingBus` (locked push), scanner registration,
  correlation-pass stub.
- `util.c`: path classification (system / program-files / user-writable / temp /
  recycle), registry read helpers, UTF-16↔UTF-8.
- `heur.c`: Shannon entropy, scoring helpers, allowlist loader.
- `report.c`: sort by severity×confidence, colored console table, JSON output,
  limitations footer.
- Privilege bootstrap: Admin check, enable `SeDebugPrivilege`.
- **Exit criteria**: engine runs N stub scanners in parallel; report sorts and
  renders; `rules/allowlist.txt` honored.

## Milestone 2 — PE + Signing utilities (1 day)
- `pe.c`: map PE, parse headers/sections, per-section entropy, IAT enumeration,
  packer heuristics (entropy, `UPX*`/odd section names, tiny import table).
- `sign.c`: `WinVerifyTrust` Authenticode + catalog verification; signer subject
  extraction; result cache keyed by path+mtime.
- Unit tests with golden files: a signed MS binary, an unsigned binary, a
  packed sample, EICAR.
- **Exit criteria**: correct signed/unsigned/packed verdicts on the golden set;
  signing cache demonstrably avoids recompute.

## Milestone 3 — Process Scanner (1.5 days)
- `scan_process.c`: `NtQuerySystemInformation` enumeration (Toolhelp fallback);
  image path, command line, token user, integrity level, parent chain.
- Memory anomaly scan (`VirtualQueryEx` for private RWX / non-image exec).
- Rules: `PROC.UNSIGNED_SYS32`, `PROC.MASQUERADE`, `PROC.TEMP_PATH`,
  `PROC.RWX_MEM`, `PROC.SUSPICIOUS_PARENT`, `PROC.PACKED`.
- Cache the process table for later modules to reuse.
- **Exit criteria (VM)**: a binary copied to `%TEMP%` and run is flagged
  `PROC.TEMP_PATH`; a renamed `svchost.exe` outside System32 is flagged
  `PROC.MASQUERADE`; no flags on a clean process set beyond known allowlist.

## Milestone 4 — Persistence Scanner (1.5 days)
- `scan_persist.c`: Run/RunOnce (HKLM/HKCU/Wow64), Winlogon, AppInit_DLLs, IFEO,
  COM-hijack CLSILs; Startup folders; Scheduled Tasks (XML/COM); WMI event subs.
- Each target binary → PE/Signing checks.
- Rules: `PERSIST.RUNKEY`, `PERSIST.IFEO`, `PERSIST.WMI_SUB`, `PERSIST.TASK`,
  `PERSIST.STARTUP_FOLDER`, `PERSIST.COM_HIJACK`.
- **Exit criteria (VM)**: a planted HKCU Run key, a planted scheduled task, and
  a planted WMI subscription are each flagged with the right rule id.

## Milestone 5 — Service Scanner (1 day)
- `scan_service.c`: enumerate all services; config; signing; path checks;
  cross-ref running PID with the process cache.
- Rules: `SVC.UNSIGNED`, `SVC.USERWRITABLE_PATH`, `SVC.UNQUOTED_PATH`,
  `SVC.SUSPICIOUS_DLL`, `SVC.RECENT`.
- **Exit criteria (VM)**: a planted service with a binary in `%TEMP%` is flagged
  unsigned + user-writable-path; unquoted-path service is flagged.

## Milestone 6 — Network Scanner (1 day)
- `scan_network.c`: `GetExtendedTcpTable/UdpTable` with PID join to process
  cache; remote IP classification; optional `--watch` beacon sampling.
- Rules: `NET.LISTEN_SUSPICIOUS_PROC`, `NET.RAW_IP_OUTBOUND`,
  `NET.SHELL_SOCKET`, `NET.IOC_MATCH`.
- `ioc.c`: load local IP/hash/string lists.
- **Exit criteria (VM)**: a netcat/`powershell` reverse shell to a listener is
  flagged `NET.SHELL_SOCKET` and/or `NET.RAW_IP_OUTBOUND`.

## Milestone 7 — Keylogger / Hook Scanner (1 day)
- `scan_keylog.c`: global LL-hook owner detection where determinable; raw-input
  keyboard registrants; IAT heuristic (`SetWindowsHookEx`, `GetAsyncKeyState`,
  `RegisterRawInputDevices`, `GetRawInputData`) + capability scoring.
- Rules: `KEY.LL_HOOK`, `KEY.RAW_INPUT`, `KEY.POLL_HEURISTIC`.
- **Exit criteria (VM)**: a sample `SetWindowsHookEx(WH_KEYBOARD_LL)` keylogger
  is flagged `KEY.LL_HOOK`; a `GetAsyncKeyState` poller is flagged by heuristic.

## Milestone 8 — Rootkit Cross-View Scanner (1.5 days)
- `scan_rootkit.c`: 4-source process cross-view diff; file cross-view
  (`FindFirstFile` vs `NtQueryDirectoryFile`); driver inventory + signing.
- Rules: `RK.HIDDEN_PROC`, `RK.HIDDEN_FILE`, `RK.SUSPICIOUS_DRIVER`.
- Document limitations prominently in output.
- **Exit criteria (VM)**: a userland API-hooking process hider (hooks
  `NtQuerySystemInformation` in a target) produces a cross-view discrepancy →
  `RK.HIDDEN_PROC`; an unsigned non-MS driver is flagged.

## Milestone 9 — Correlation pass (0.5 day)
- Promote correlated multi-signal artifacts to `CORR.IMPLANT` high-confidence
  findings; merge service↔process duplicates; collapse noise.
- **Exit criteria (VM)**: the planted reverse-shell-with-persistence box yields
  one ranked `CORR.IMPLANT` at top instead of 4 scattered mediums.

## Milestone 10 — Responder + Audit (1 day) — DESTRUCTIVE, LAST
- `respond.c`: kill, suspend, disable+stop service, quarantine (move + ACL).
- Guards: never-kill list, dry-run default, `--yes` confirmation bypass,
  `--force-critical`, interactive per-finding prompt mode.
- `audit.c`: append-only timestamped log of every attempted/actual action.
- **Exit criteria (VM)**: dry-run mutates nothing (verified by audit + state
  diff); with `--kill` the planted implant is terminated and logged; critical
  PIDs are refused without `--force-critical`.

## Milestone 11 — Hardening, docs, packaging (1 day)
- False-positive pass on a clean reference image; tune allowlist + scores.
- Graceful degradation review (no Admin → clear limitations output, no crash).
- README (usage, authorized-use scope, Defender-exclusion note for testing),
  rule catalog doc.
- Release build, optional code-signing step documented.
- **Exit criteria**: clean-image FP count at/under target; all VM planted
  threats still detected; docs complete.

---

## Test fixtures (built alongside, kept in `tests/`)
- `plant_eicar.ps1`, `plant_runkey.ps1`, `plant_task.ps1`, `plant_wmi.ps1`,
  `plant_service.ps1`, `revshell_listener.ps1` + `revshell_client`,
  `keylogger_hook.c` (SetWindowsHookEx sample), `poller.c` (GetAsyncKeyState),
  `proc_hider.c` (userland NtQuerySystemInformation hook), `cleanup_all.ps1`.
- A `run_vm_suite.ps1` that plants everything, runs `sentinelc --full --json`,
  and asserts each expected rule id is present and that dry-run changed nothing.

## Sequencing rationale
1. Build/engine/utils (M0-M1) — nothing works without the bus + reporter.
2. PE+Signing (M2) — every scanner depends on these verdicts.
3. Process (M3) — produces the cache reused by service/network/keylog.
4. Persistence (M4) before service (M5) — overlapping registry/scan logic.
5. Network (M6), keylog (M7), rootkit (M8) — independent, could parallelize.
6. Correlation (M9) — needs all signals present.
7. Responder (M10) — destructive, only after detection is trusted.
8. Hardening (M11) — tune against false positives last.

## Rough total
~13 developer-days for v1 (single dev). Modules M6-M8 are parallelizable if more
hands are available, cutting wall-clock to ~9-10 days.

## Definition of done (v1)
- All 11 milestones' exit criteria met in the test VM.
- Quick scan < 10s, full scan < 60s on the reference workstation.
- Zero destructive action in dry-run (audit-verified).
- Every planted threat detected with the correct rule id.
- Honest limitations are printed every run.

---

## Next step
On approval of these three docs (PRD / architecture / plan), implementation
starts at **Milestone 0**. Recommend confirming: (a) the realistic positioning
in PRD §4 is acceptable, (b) target Windows versions (10/11 x64 assumed),
(c) whether a signed kernel driver (v2) is desired later for true kernel-level
rootkit visibility.
