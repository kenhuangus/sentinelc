# SentinelC

A fast, native-C, on-demand threat-triage scanner for Windows 10/11 (x64).
It enumerates everything that runs, persists, listens, or hooks input, flags
anomalies with **explainable** heuristics, detects user-mode rootkit hiding via
cross-view diffing, and can terminate/disable confirmed threats — all in one
small `.exe` with no installer, no cloud, no kernel driver.

> **Honest scope.** This is a *triage and response* tool, not a replacement for
> Defender/EDR. It wins on **speed and transparency** (a full scan in seconds,
> every detection cites its evidence and rule id), not on signature breadth or
> kernel-level visibility. See `../PRD.md` §4. A kernel (DKOM) rootkit can defeat
> user-mode cross-view detection — the tool says so in its own output.

## What it detects

| Family | Rules (examples) |
|---|---|
| Malicious processes | `PROC.MASQUERADE`, `PROC.TEMP_PATH`, `PROC.RWX_MEM`, `PROC.PACKED`, `PROC.SUSPICIOUS_PARENT` |
| Suspicious services | `SVC.UNSIGNED`, `SVC.USERWRITABLE_PATH`, `SVC.UNQUOTED_PATH`, `SVC.SUSPICIOUS_DLL` |
| Persistence | `PERSIST.RUNKEY`, `PERSIST.WINLOGON`, `PERSIST.IFEO`, `PERSIST.APPINIT`, `PERSIST.TASK`, `PERSIST.WMI_SUB`, `PERSIST.STARTUP_FOLDER`, `PERSIST.COM_HIJACK` |
| C2 / RCE / reverse shells | `NET.SHELL_SOCKET`, `NET.LISTEN_SUSPICIOUS_PROC`, `NET.RAW_IP_OUTBOUND`, `NET.BEACON`, `NET.IOC_MATCH` |
| Keyloggers / hooks | `KEY.LL_HOOK`, `KEY.RAW_INPUT`, `KEY.POLL_HEURISTIC`, `KEY.INJECTED_DLL` |
| Rootkits (cross-view) | `RK.HIDDEN_PROC`, `RK.HIDDEN_FILE`, `RK.SUSPICIOUS_DRIVER` |
| Correlation | `CORR.IMPLANT` (unsigned multi-signal), `CORR.MULTI_SIGNAL` |

A post-scan **correlation pass** fuses multiple signals on one PID into a single
ranked finding instead of a wall of mediums.

## Build

### Windows (recommended)
Needs MinGW-w64. If you don't have it:
```
choco install mingw -y        :: run in an ADMIN window
```
(An existing MSYS2 install at `C:\msys64` is auto-detected too.)
Then:
```
powershell -ExecutionPolicy Bypass -File build.ps1
```
→ produces `build\sentinelc.exe`.

### WSL
The scanner is a native Windows binary, so cross-compile it:
```
sudo apt-get install -y gcc-mingw-w64-x86-64
./build.sh
```
WSL's Windows interop lets you then run the produced `.exe` directly from the
Linux shell — it scans the **Windows host**:
```
./build/sentinelc.exe --quick
```
(For full coverage launch it elevated — see below. A non-elevated run still
works and clearly lists what it could not inspect.)

### Make
```
make                                   # MSYS2 ucrt64 shell
make CC=x86_64-w64-mingw32-gcc         # WSL cross-compile
```

## Run

**Many checks require Administrator** (service config, other processes' memory,
drivers, the Tasks folder). Without elevation the tool runs fine and prints a
`Limitations:` section listing exactly what was skipped.

### Elevated, from a DOS window
Open `cmd` / Windows Terminal **as Administrator**, then:
```
cd /d <path-to>\sentinelc
build\sentinelc.exe --full
```

### One-click elevated launcher
Double-click **`sentinelc-admin.cmd`** (or run it from any prompt). It triggers
the UAC prompt, runs `--full`, keeps the window open, and points you at the
audit log. Pass your own args: `sentinelc-admin.cmd --quick --json`.

## Usage

```
sentinelc.exe [scan-mode] [options]

Scan modes:
  --quick            process + service + persistence + network   (default, fast)
  --full             everything (adds keylogger + rootkit cross-view)
  --deep             hash files / heavier checks
  --watch N          sample network for N seconds to catch C2 beaconing
  --scan-path PATH   scan a file or directory only (entropy/signing/IOC)

Integrity (Merkle file-integrity monitoring):
  --baseline                 build/update a Merkle baseline of execution-relevant
                             files (exe/dll/sys/scripts/source code/.md/config)
  --integrity                diff the current tree against the baseline and list
                             exactly what changed (added/modified/removed)
  --integrity-roots "A;B;C"  semicolon-separated roots to cover (default: system
                             dirs; pass a project dir to track code + markdown)
  --baseline-file PATH       baseline location (default:
                             %ProgramData%\SentinelC\integrity\baseline.tsv)

Output:
  --json             machine-readable JSON (for a SIEM)
  --no-color         plain text

Responder (DESTRUCTIVE -- default is dry-run; nothing is touched without these):
  --kill PID                 terminate a process
  --suspend PID              suspend a process
  --disable-service NAME     stop + disable a service
  --quarantine PATH          move a file to quarantine + deny-all ACL
  --interactive              prompt per actionable finding
  --yes                      skip the confirmation prompt
  --force-critical           allow acting on critical system PIDs (dangerous)

Tuning:
  --allowlist PATH   suppress known-good binaries (default: rules\allowlist.txt)
  --ioc-dir DIR      load IOC IP/hash/string lists (default: rules\)
  --audit PATH       audit-log location (default: %ProgramData%\SentinelC\audit.log)
```

`rules\allowlist.txt`, `rules\ioc_*.txt`, and `rules\yara_subset.txt` next to the
exe are auto-loaded; no flags needed.

## Safety model

- **Read-only by default.** No process is killed, no service disabled, no file
  moved unless you pass an explicit `--kill/--suspend/--disable-service/
  --quarantine` flag or use `--interactive`.
- **Confirmation gates.** Destructive actions prompt (default **No**) unless
  `--yes`. Critical system PIDs (smss/csrss/wininit/winlogon/services/lsass and
  PID 0/4) are refused unless `--force-critical`.
- **Full audit trail.** Every attempted and performed action is timestamped in
  the audit log.

## Examples
```
:: fast read-only triage
build\sentinelc.exe --quick

:: deep sweep + 30s beacon watch, JSON to a file
build\sentinelc.exe --full --deep --watch 30 --json > scan.json

:: scan a suspicious download
build\sentinelc.exe --scan-path "C:\Users\me\Downloads\invoice.exe" --deep

:: kill a confirmed implant (will prompt)
build\sentinelc.exe --kill 4242

:: triage interactively, acting on each finding
build\sentinelc.exe --full --interactive

:: file-integrity monitoring (Merkle tree) -- track a project's code + docs
build\sentinelc.exe --baseline  --integrity-roots "C:\path\to\project"
::   ...later, after edits...
build\sentinelc.exe --integrity --integrity-roots "C:\path\to\project"
::   -> lists ADDED / MODIFIED / REMOVED files by absolute path; the Merkle
::      root is an O(1) "did anything change at all?" check.
```

## File integrity monitoring (Merkle tree)

`--baseline` hashes every execution-relevant file (PE binaries, scripts, source
code, `.md`, and execution-affecting config) under the chosen roots, builds a
**Merkle tree** (leaf = `SHA256(lowercased-abspath ‖ content-hash)`, combined
pairwise to a single root), and stores a sorted manifest. `--integrity` re-walks
and diffs against it:

- The **Merkle root** is a single hash that proves the whole set is unchanged
  (`[MATCH]`) or changed (`[CHANGED]`) in one comparison.
- The **manifest diff** lists every `ADDED` / `MODIFIED` / `REMOVED` file by
  full absolute path (human table or `--json`). A rename shows as remove+add
  because the path is bound into each leaf hash.
- A first baseline of large system roots is slow (it hashes every file); scope
  with `--integrity-roots` for fast, targeted monitoring of a project or folder.

## Notes & limitations
- User-mode only: a kernel rootkit that lies to every user API defeats the
  cross-view checks. Drivers are inventoried and signature-checked, which catches
  the common unsigned-driver case.
- First run is slower (it verifies signatures for every process/service);
  results are cached within a run.
- This is a dual-use security tool. Use it on systems you are authorized to
  inspect. Defender may flag it during testing because it enumerates and can
  terminate processes — add a temporary exclusion for `build\sentinelc.exe` if
  needed, and code-sign for production use.

See `../PRD.md`, `../architecture.md`, and `../plan.md` for the full design.
