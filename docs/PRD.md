# PRD — SentinelC: Fast Windows Threat Triage Scanner

## 1. Summary

SentinelC is a fast, native C command-line tool for Windows that scans a live
system for signs of malware, rootkits, keyloggers, RCE backdoors, and
command-and-control (C2) implants, surfaces suspicious services and processes,
and can terminate/disable them on operator confirmation.

It is a **host triage and detection** tool, not a replacement for a full EDR.
It is designed to run in seconds, be fully transparent (every detection rule is
explainable), and require zero cloud dependency.

## 2. Problem statement

Commercial AV/EDR products are opaque black boxes, often heavy, and can miss
fileless or living-off-the-land threats. Incident responders and power users
need a fast, scriptable, locally-controlled tool that:

- Enumerates everything that runs, persists, listens, or hooks input.
- Flags anomalies using explainable heuristics (not a hidden ML model).
- Detects rootkit-style hiding via cross-view comparison.
- Lets the operator kill/disable confirmed threats immediately.

## 3. Goals & non-goals

### Goals
- **Speed**: full quick scan (processes, services, persistence, network) in
  under ~10 seconds on a typical workstation.
- **Transparency**: every finding cites the exact rule and evidence that
  triggered it, with a severity and confidence score.
- **Coverage of the named threat classes**:
  - Generic malware (suspicious PEs, packed/high-entropy, unsigned in system
    paths, masquerading binaries).
  - Rootkits (hidden processes/files/registry via cross-view diff; SSDT/driver
    anomalies where accessible).
  - Keyloggers (low-level keyboard/mouse hooks, raw input device registration,
    suspicious GetAsyncKeyState pollers).
  - RCE / reverse shells / C2 (anomalous outbound connections, beaconing
    patterns, processes spawning shells, suspicious parent/child chains).
  - Persistence (run keys, services, scheduled tasks, WMI subscriptions,
    startup folders, image hijacks, AppInit/IFEO).
- **Response**: terminate process, suspend process, stop + disable service,
  quarantine file (move + strip ACLs), with confirmation gates.
- **Safety**: dry-run by default; nothing is killed or modified without an
  explicit flag or interactive confirmation; full audit log.

### Non-goals
- Not a real-time always-on AV (no kernel minifilter in v1).
- Not a signature/cloud-reputation race against Defender/CrowdStrike.
- Not a remediation/repair tool (no registry cleaning, no rollback).
- No automatic kernel driver loading in v1 (user-mode only; documented
  limitations on what user-mode rootkit detection can see).

## 4. Honest positioning vs. existing AV

| Dimension | SentinelC | Commercial AV/EDR |
|---|---|---|
| Speed of a triage scan | **Wins** (seconds, no cloud) | Slower, background scans |
| Transparency / tunability | **Wins** (open rules) | Opaque |
| Fileless / LOLBin heuristics | Competitive | Varies |
| Signature breadth | Loses | Wins (huge corpora + cloud) |
| Kernel-level rootkit visibility | Loses in v1 (user-mode) | Wins (kernel driver) |
| Real-time blocking | Loses (on-demand only) | Wins |

**Conclusion:** SentinelC's value is *fast, explainable, locally-controlled
triage and response*, complementing — not replacing — Defender. The "better
than other antivirus" framing is scoped to **speed and transparency on
on-demand host triage**, not total detection rate.

## 5. Users & use cases

- **Incident responder**: lands on a possibly-compromised box, runs a 10s scan,
  gets a ranked list of suspicious artifacts with evidence, kills the obvious
  implant.
- **Power user / sysadmin**: periodic sweep for persistence and rogue services.
- **Blue-team / detection engineer**: tunes rules, exports JSON for a SIEM.

## 6. Functional requirements

### FR-1 Process scan
- Enumerate all processes (PID, PPID, image path, command line, user, signing
  status, integrity level, parent chain).
- Flag: unsigned binary in `System32`/`Program Files`; image path mismatch with
  known system process name (e.g. `svch0st.exe`, `svchost.exe` outside System32);
  process running from temp/`AppData`/recycle bin; high-entropy/packed image;
  injected/RWX memory regions; suspicious parent (e.g. `winword.exe` →
  `cmd.exe` → `powershell.exe`).

### FR-2 Service scan
- Enumerate all services (name, display name, binary path, start type, state,
  account, signing status).
- Flag: unsigned service binary; binary in user-writable path; unquoted service
  path with spaces; recently created service; service whose binary is also
  flagged by the process/file rules; svchost service with a suspicious DLL.
- **Response**: stop + set start type Disabled, with confirmation.

### FR-3 Rootkit detection (user-mode cross-view)
- Compare process lists from multiple APIs (`CreateToolhelp32Snapshot`,
  `EnumProcesses`, `NtQuerySystemInformation`, WTS) → hidden-process diff.
- Compare directory listings (`FindFirstFile` vs `NtQueryDirectoryFile`) for
  hidden files.
- Compare registry enumeration paths for hidden keys.
- Enumerate loaded kernel drivers (`EnumDeviceDrivers`) and flag unsigned /
  non-Microsoft drivers in suspicious paths.
- Document clearly: a kernel rootkit can defeat user-mode cross-view; v1 detects
  the common user-mode and naive kernel hooks, not advanced DKOM.

### FR-4 Keylogger detection
- Detect global low-level hooks where determinable; enumerate windows/hooks.
- Flag processes registered for Raw Input keyboard devices.
- Flag processes with tight `GetAsyncKeyState`/`GetKeyState` polling patterns
  (heuristic, via imported APIs + behavior where observable).
- Flag DLLs loaded into many processes that import keyboard-hook APIs.

### FR-5 Network / C2 / RCE detection
- Enumerate TCP/UDP endpoints with owning PID (`GetExtendedTcpTable`).
- Flag: listening ports bound by unsigned/temp-path processes; outbound
  connections to non-standard ports by office/script processes; beaconing
  (requires short sampling window — optional `--watch` mode);
  process holding a socket *and* a pipe to `cmd.exe`/`powershell.exe`
  (reverse-shell shape).
- Resolve remote IPs; flag connections to raw IPs with no DNS, or to known-bad
  ranges from an optional local IOC list.

### FR-6 Persistence enumeration
- Run/RunOnce keys (HKLM/HKCU, Wow6432Node).
- Services (cross-ref FR-2).
- Scheduled tasks (parse Task Scheduler).
- Startup folders.
- WMI event subscriptions (`__EventFilter`/`CommandLineEventConsumer`).
- Image File Execution Options (debugger hijack), AppInit_DLLs, Winlogon
  Shell/Userinit, COM hijacks (common CLSIDs).

### FR-7 File scan (targeted)
- On-demand scan of a path/directory: entropy, PE anomalies, Authenticode
  verification, optional YARA-style local rule matching, optional hash check
  against a local IOC hash list.

### FR-8 Reporting
- Human-readable colored console output, ranked by severity × confidence.
- `--json` machine-readable output for SIEM ingestion.
- Per-finding: rule id, evidence, severity, confidence, recommended action.

### FR-9 Response actions (gated)
- `--kill <pid>`, `--suspend <pid>`, `--disable-service <name>`,
  `--quarantine <path>`.
- Interactive mode: present findings, prompt per action.
- All actions logged to an append-only audit file with timestamps.

## 7. Non-functional requirements

- **Performance**: quick scan < 10s; full scan < 60s on SSD workstation.
- **Footprint**: single static-linked .exe, < 2 MB, no installer, no .NET.
- **Privilege**: runs with current token; auto-detects when elevation is needed
  and reports what it could not inspect without admin. Many checks require
  Administrator; `SeDebugPrivilege` requested when available.
- **Safety**: read-only by default; no destructive action without explicit flag
  or confirmation; never kill PID 0/4/critical system PIDs without `--force`.
- **Portability**: Windows 10/11 x64; build with MSVC and MinGW-w64.
- **No false sense of security**: output states scan limitations explicitly.

## 8. Success metrics

- Detects a planted EICAR file, a Run-key persistence, a netcat reverse shell,
  a SetWindowsHookEx keylogger, and a userland process-hiding hook in a test
  VM — all flagged with correct evidence.
- Quick scan completes in target time.
- Zero destructive action taken in dry-run mode (verified by audit log).
- False-positive rate on a clean reference image: tracked and minimized;
  tunable via allowlist.

## 9. Risks & mitigations

- **False positives killing legit services** → confirmation gates, allowlist,
  dry-run default, never-kill list of critical PIDs.
- **Kernel rootkit evasion** → documented limitation; v2 optional signed driver.
- **Being flagged by Defender itself** (it enumerates/kills processes) → ship
  unsigned dev build with documented Defender exclusion for testing; plan code
  signing for release.
- **Privilege misuse** → tool is dual-use; document authorized-use scope; audit
  log of all actions.

## 10. Out of scope for v1 (future)
- Kernel minifilter driver for real-time + true kernel cross-view.
- Memory dumping / full memory forensics.
- Automated remediation/repair and rollback.
- Cloud reputation lookups.
- YARA full engine (v1 uses a small built-in rule subset).
