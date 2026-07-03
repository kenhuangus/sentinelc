# SentinelC Implementation Status

This file replaces the original build-from-zero plan. The scanner, responder,
Fleet Console, installer, and Codex skill/plugin packaging now exist. Keep this
document as a concise current status and use `IMPROVEMENT-PLAN.md` for the
remaining roadmap.

## Current Build Targets

- `build.ps1`: Windows PowerShell build using MinGW-w64.
- `build.sh`: WSL/MSYS2/Git-Bash build using a Windows-targeting gcc.
- `Makefile`: MinGW/MSYS2 build target.

There is no `CMakeLists.txt` in the current repo.

## Current Runtime Modes

- `--quick`: process, service, persistence, and network triage.
- `--full`: adds keylogger/spyware, rootkit, credential-access, memory, and
  AMSI/ETW evasion checks.
- `--deep`: heavier hashing/checks where applicable.
- `--watch N`: network beacon sampling.
- `--scan-path PATH`: targeted file/directory scan.
- `--baseline` / `--integrity`: Merkle FIM baseline/check.
- `--offline-like`: VSS snapshot plus offline hive and boot-driver hunting.

## Current Packaging

- `sentinelc-admin.cmd` launches a default elevated full scan.
- `sentinelc-admin.ps1` supports custom elevated scan arguments through a JSON
  handoff file.
- `installer/install.ps1` installs a SYSTEM scheduled task endpoint agent.
- `fleet-console/server.js` provides the local/fleet dashboard.
- `codex/skills/...` and `codex/plugins/...` package the incident-response skill
  and plugin copies.

## Current Verification Commands

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
.\build\sentinelc.exe --help
.\build\sentinelc.exe --full --json --no-color
node --check fleet-console\server.js
```

PowerShell script syntax can be checked with
`[System.Management.Automation.Language.Parser]::ParseFile(...)` over the
installer, fleet, admin, skill, and plugin scripts.

## Done Criteria For Future Changes

- Build succeeds without compiler warnings introduced by the change.
- Relevant PowerShell scripts parse cleanly.
- Node console code passes `node --check`.
- Behavior changes include a focused regression check.
- README and docs are updated in the same branch when behavior changes.
