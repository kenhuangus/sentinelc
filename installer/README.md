# SentinelC endpoint agent installer

Deploys SentinelC so scans run with **full coverage (admin)** without prompting
for UAC on every run. This is the standard model for security agents: elevate
**once** at install, then do privileged work as `NT AUTHORITY\SYSTEM`.

## Why not "click a button in the browser to elevate"?

A browser tab is sandboxed — it cannot launch processes or trigger UAC, by
design. So the privileged work lives in a scheduled task that already runs as
SYSTEM. The dashboard just *shows results*; an on-demand scan is triggered by
`scan-now.cmd` (which calls the already-elevated task — no prompt).

## Install

From the repo (one UAC prompt when it self-elevates):

```powershell
powershell -ExecutionPolicy Bypass -File installer\install.ps1 `
  -ConsoleUrl https://your-console.example.com -Token <fleet-token>
```

Options:

| Flag | Default | Meaning |
|---|---|---|
| `-ConsoleUrl` | (required) | Fleet Console base URL |
| `-Token` | (required) | Ingest bearer token |
| `-InstallDir` | `C:\Program Files\SentinelC` | Install location |
| `-SourceDir` | `..\build` | Where `sentinelc.exe` + `rules\` live |
| `-DailyAt` | `03:00` | Daily scan time |
| `-NoStartup` | off | Skip the at-startup trigger |
| `-DryRun` | off | Print actions, change nothing (no elevation) |

## What it sets up

1. Copies `sentinelc.exe`, `rules\`, and the agent scripts to `InstallDir`.
2. ACL-locks the dir: **SYSTEM/Admins full, Users read-only** (the exe can't be
   tampered with by a standard user).
3. Writes `config.json` with the console URL and a **DPAPI-encrypted token**
   (`LocalMachine` scope — only this machine can decrypt it). The file is
   readable only by SYSTEM/Admins.
4. Registers scheduled task `\SentinelC\FullScan`, running as **SYSTEM with
   highest privileges**, triggered **daily** + **at startup** + **on demand**.

## Run a scan on demand

```cmd
"C:\Program Files\SentinelC\scan-now.cmd"
```
or
```cmd
schtasks /run /tn "\SentinelC\FullScan"
```
Neither prompts for UAC — the task is already privileged. A tray app or a local
helper can call this to give users a "Scan now" button.

Logs: `C:\Program Files\SentinelC\logs\scan-YYYYMMDD.log`.

## Enterprise deployment (zero UAC)

Push `install.ps1` via **Intune / SCCM / GPO**. Those run as SYSTEM, so the
self-elevation step is a no-op and **no UAC ever appears**.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\SentinelC\uninstall.ps1"
```

## Before you ship to other people

- **Code-sign `sentinelc.exe` and the installer** (OV/EV cert). Then UAC shows
  *"Verified publisher: <you>"* instead of "Unknown publisher", and SmartScreen
  stops blocking downloads. This is the single biggest trust factor.
- Serve the Fleet Console over **HTTPS** and rotate the ingest token per tenant.
