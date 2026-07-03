# PRD - SentinelC: Fast Windows Threat Triage Scanner

## Summary

SentinelC is a fast, native C command-line tool for Windows that scans a live
system for signs of malware, spyware, keyloggers, rootkit-style hiding,
credential access, persistence, RCE backdoors, C2 behavior, memory injection,
and Defender/security tamper. It can also perform gated response actions after
operator confirmation.

It is a host triage and response tool, not a replacement for a full EDR or
Defender. Its value is speed, transparency, local control, and explainable
evidence.

## Goals

- Run on-demand host triage quickly without a cloud dependency.
- Cite rule id, severity, confidence, target, and evidence for every finding.
- Detect process, service, persistence, network, keylogger/spyware, rootkit-style
  cross-view, credential-access, memory-injection, evasion, file IOC, FIM, and
  offline-like VSS signals.
- Stay read-only by default.
- Gate destructive actions with explicit flags, confirmation, critical-process
  guards, and audit logging.

## Non-Goals

- No always-on real-time AV in this repository.
- No cloud reputation or signature-corpus race against Defender/CrowdStrike.
- No automatic kernel driver loading.
- No registry cleaner or generic "remove unused entries" feature.
- No guarantee against advanced kernel DKOM rootkits from user mode.

## Positioning

| Dimension | SentinelC | Commercial AV/EDR |
|---|---|---|
| On-demand triage speed | Strong | Varies |
| Transparency | Strong, source/rules are readable | Usually opaque |
| Local-only operation | Strong | Often cloud-assisted |
| Signature breadth | Limited | Strong |
| Kernel-level visibility | Limited in this repo | Strong when an agent/driver exists |
| Real-time blocking | Not the current product | Strong |

SentinelC complements Defender. It should not be marketed as a total AV/EDR
replacement.

## Functional Requirements

### FR-1 Process Scan

- Enumerate PID, PPID, image path, command line, user, integrity level, signer
  state, parent chain, and create time where accessible.
- Flag masquerading, temp/user-writable execution, unsigned/invalid system-path
  images, unverifiable signatures in sensitive locations, suspicious parent
  chains, private RWX/unbacked executable memory, packed images, PPID spoofing,
  LOLBin arguments, and encoded PowerShell.

### FR-2 Service Scan

- Enumerate services and drivers, normalize service binary paths, inspect signer
  and path state, and cross-reference running PIDs.
- Flag user-writable service paths, unsigned/invalid binaries, unverifiable
  signatures outside inbox paths, unquoted paths, and suspicious `svchost`
  ServiceDll values.
- Response: stop and disable service with confirmation.

### FR-3 Rootkit-Style Cross-View

- Compare process lists from multiple APIs.
- Compare file listings in sensitive paths through Win32 and native directory
  enumeration.
- Enumerate loaded drivers and flag suspicious unsigned/non-Microsoft drivers.
- Clearly report that advanced kernel rootkits can defeat user-mode checks.

### FR-4 Keylogger And Spyware Signals

- Detect low-level hook owners where determinable.
- Flag raw-input keyboard registrations.
- Flag key-state polling/import combinations.
- Flag multi-capture capability combinations: clipboard, screen, media capture,
  credential APIs, and network capability.

### FR-5 Network, C2, And RCE Signals

- Enumerate TCP/UDP endpoints with owning PID.
- Flag suspicious listeners, raw-IP outbound connections, known-bad IOC IPs,
  shell-socket process shapes, and optional beaconing through `--watch N`.

### FR-6 Persistence And Tamper

- Inspect Run/RunOnce, Winlogon, AppInit, AppCertDLLs, IFEO,
  SilentProcessExit, startup folders, scheduled task Exec and ComHandler
  actions, WMI subscriptions, COM hijacks, service registry view,
  Defender/security-service tamper, proxy settings, browser extensions, and App
  Paths.

### FR-7 Targeted File Scan

- On-demand scan of a file or directory for PE/signing/entropy anomalies,
  packed files, suspicious import combinations, hash IOCs, YARA-lite rules, and
  full-file string IOC streaming.

### FR-8 Credential, Memory, And Evasion Scan

- Flag suspicious LSASS and sensitive credential-file handles.
- Inspect private executable memory for shellcode and reflective PE markers.
- Compare loaded module headers with on-disk files for hollowing evidence.
- Compare AMSI/ETW prologues in memory with clean on-disk bytes.

### FR-9 Integrity And Offline-Like Modes

- `--baseline` and `--integrity` build/check a Merkle baseline over
  execution-relevant files, stream-hash file contents, and authenticate baselines
  with HMAC-SHA256 plus a DPAPI-wrapped key.
- `--offline-like` creates a VSS snapshot, scans selected snapshot paths,
  inspects offline registry hives, checks boot drivers and Defender exclusions,
  and probes raw volume metadata where accessible.

### FR-10 Reporting And Response

- Console report sorted by severity/confidence.
- JSON report for automation and fleet ingestion.
- Per-finding rule id, severity, confidence, title, target, PID, evidence, and
  recommended action.
- Gated actions: kill, suspend, disable service, quarantine, or interactive
  review. All actions are audited.

## Non-Functional Requirements

- Windows 10/11 x64.
- Native Windows binary built with MinGW-w64 through `build.ps1`, `build.sh`, or
  `Makefile`.
- Current build output is about 1.1 MB.
- No cloud dependency.
- Graceful degradation when not elevated, with limitations in output.
- Read-only by default.
- No destructive action without explicit operator request.

## Safety Requirements

- Critical PIDs and critical system images are refused unless
  `--force-critical`.
- Process kill/suspend validates and acts through one handle to avoid PID reuse.
- Quarantine rejects reparse points/directories and uses locked SYSTEM/Admin-only
  storage.
- Remote Fleet Console uploads must use HTTPS, except loopback HTTP for local
  testing.
- Built-in false-positive suppression must not trust arbitrary signer subjects;
  only Microsoft-signed noisy rules are auto-suppressed.

## Risks And Mitigations

- False positives: confirmation gates, suppress/allowlist support, conservative
  auto-suppression, and evidence-first reporting.
- Kernel rootkit evasion: documented limitation and future signed-driver
  roadmap.
- Unsigned binary reputation: production release should use code signing.
- Dual-use risk: authorized-use documentation, dry-run defaults, and audit logs.

## Future Work

- Persistent signature/PE caches.
- Parallel FIM hashing.
- Full YARA/libyara or a larger documented subset.
- Signed kernel driver for kernel-vantage visibility and real-time blocking.
