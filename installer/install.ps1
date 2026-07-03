<#
.SYNOPSIS
  Install the SentinelC endpoint agent as a SYSTEM scheduled task.

.DESCRIPTION
  Best-practice deployment: privileged work runs as NT AUTHORITY\SYSTEM under a
  scheduled task with highest privileges, so scans get full coverage
  (LSASS/credential handles, driver inventory) WITHOUT a UAC prompt on every
  run. UAC appears exactly once -- when this installer self-elevates. Pushed via
  Intune/SCCM/GPO (which run as SYSTEM), it prompts zero times.

  What it does (elevated):
    1. Copies sentinelc.exe + rules\ + agent scripts to $InstallDir.
    2. Locks the install dir ACL (SYSTEM/Admins full, Users read-only).
    3. Writes config.json with the console URL and a DPAPI-protected host ingest token.
    4. Registers task "\SentinelC\FullScan" (SYSTEM, highest) on a daily
       schedule, at startup, and runnable on demand.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install.ps1 `
    -ConsoleUrl https://console.example.com -Token <this-host-ingest-token>

.EXAMPLE
  # See what it would do without changing anything:
  powershell -ExecutionPolicy Bypass -File install.ps1 `
    -ConsoleUrl http://127.0.0.1:8787 -Token testtoken123 -DryRun
#>
[CmdletBinding()]
param(
  [string]$ConsoleUrl,
  [string]$Token,
  [string]$InstallDir = (Join-Path $env:ProgramFiles "SentinelC"),
  [string]$SourceDir,
  [string]$DailyAt = "03:00",
  [switch]$NoStartup,
  [switch]$DryRun,
  [string]$ElevatedArgsPath
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $SourceDir) {
  $candidate = Join-Path $here "..\build"
  if (Test-Path $candidate) { $SourceDir = (Resolve-Path $candidate).Path }
  else { $SourceDir = $here }
}

function Get-SystemPowerShellPath {
  $p = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  if (-not (Test-Path -LiteralPath $p)) { throw "system PowerShell not found at $p" }
  return $p
}

function Get-SystemToolPath {
  param([Parameter(Mandatory = $true)][string]$Name)
  $p = Join-Path $env:WINDIR ("System32\" + $Name)
  if (-not (Test-Path -LiteralPath $p)) { throw "system tool not found at $p" }
  return $p
}

function Assert-SafeConsoleUrl {
  param([Parameter(Mandatory = $true)][string]$Url)
  try {
    $uri = [Uri]$Url
  } catch {
    throw "ConsoleUrl is not a valid URI: $Url"
  }
  if ($uri.Scheme -eq 'https') { return }
  if ($uri.Scheme -eq 'http' -and $uri.IsLoopback) { return }
  throw "Refusing to persist a non-loopback plaintext HTTP ConsoleUrl. Use https:// or http://127.0.0.1 for local-only testing."
}

if ($ElevatedArgsPath) {
  $handoff = Get-Content -LiteralPath $ElevatedArgsPath -Raw | ConvertFrom-Json
  $ConsoleUrl = [string]$handoff.ConsoleUrl
  $Token = [string]$handoff.Token
  $InstallDir = [string]$handoff.InstallDir
  $SourceDir = [string]$handoff.SourceDir
  $DailyAt = [string]$handoff.DailyAt
  $NoStartup = [bool]$handoff.NoStartup
  $DryRun = [bool]$handoff.DryRun
  Remove-Item -LiteralPath $ElevatedArgsPath -Force -ErrorAction SilentlyContinue
}

if ([string]::IsNullOrWhiteSpace($ConsoleUrl)) { throw "ConsoleUrl is required." }
if ([string]::IsNullOrWhiteSpace($Token)) { throw "Token is required." }
Assert-SafeConsoleUrl -Url $ConsoleUrl

# --- self-elevate: the single UAC moment -------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) {
  Write-Host "Requesting administrator rights (UAC)..." -ForegroundColor Yellow
  $handoffPath = Join-Path ([IO.Path]::GetTempPath()) ("sentinelc-install-{0}.json" -f ([guid]::NewGuid().ToString("N")))
  [ordered]@{
    ConsoleUrl = $ConsoleUrl
    Token = $Token
    InstallDir = $InstallDir
    SourceDir = $SourceDir
    DailyAt = $DailyAt
    NoStartup = [bool]$NoStartup
    DryRun = [bool]$DryRun
  } | ConvertTo-Json -Compress | Set-Content -LiteralPath $handoffPath -Encoding UTF8 -Force
  $argList = @(
    "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", $MyInvocation.MyCommand.Path,
    "-ElevatedArgsPath", $handoffPath
  )
  try { Start-Process -FilePath (Get-SystemPowerShellPath) -Verb RunAs -ArgumentList $argList }
  catch {
    Remove-Item -LiteralPath $handoffPath -Force -ErrorAction SilentlyContinue
    Write-Error "Elevation was cancelled. Installation aborted."
  }
  return
}

# --- validate source ----------------------------------------------------------
$exeSrc = Join-Path $SourceDir "sentinelc.exe"
if (-not (Test-Path $exeSrc)) { throw "scanner not found at $exeSrc (build it first, or pass -SourceDir)" }

Write-Host "Installing SentinelC agent"
Write-Host "  source : $SourceDir"
Write-Host "  target : $InstallDir"
Write-Host "  console: $ConsoleUrl"
Write-Host ("  daily  : {0}{1}" -f $DailyAt, $(if ($NoStartup) { "" } else { " + at startup" }))
if ($DryRun) { Write-Host "[DryRun] no changes made." -ForegroundColor Cyan; return }

# --- 1. copy files ------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $exeSrc (Join-Path $InstallDir "sentinelc.exe") -Force
$rulesSrc = Join-Path $SourceDir "rules"
if (Test-Path $rulesSrc) { Copy-Item $rulesSrc (Join-Path $InstallDir "rules") -Recurse -Force }
foreach ($f in @("run-scan.ps1", "uninstall.ps1", "scan-now.cmd")) {
  $src = Join-Path $here $f
  if (Test-Path $src) { Copy-Item $src (Join-Path $InstallDir $f) -Force }
}

# --- 2. protected config ------------------------------------------------------
Add-Type -AssemblyName System.Security
$tokenBytes = [Text.Encoding]::UTF8.GetBytes($Token)
$prot = [Security.Cryptography.ProtectedData]::Protect(
          $tokenBytes, $null,
          [Security.Cryptography.DataProtectionScope]::LocalMachine)
$cfg = [ordered]@{ consoleUrl = $ConsoleUrl; tokenProtected = [Convert]::ToBase64String($prot) }
$cfgPath = Join-Path $InstallDir "config.json"
$cfg | ConvertTo-Json | Set-Content -Path $cfgPath -Encoding UTF8

# --- 3. lock down ACLs --------------------------------------------------------
# Install dir: SYSTEM/Admins full, Users read+execute (cannot tamper the exe).
$icacls = Get-SystemToolPath -Name "icacls.exe"
& $icacls "$InstallDir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
# config.json holds the token: SYSTEM + Admins only, no Users at all.
& $icacls "$cfgPath" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null

# --- 4. register the scheduled task as SYSTEM / highest -----------------------
$action = New-ScheduledTaskAction -Execute (Get-SystemPowerShellPath) `
  -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$InstallDir\run-scan.ps1`""
$triggers = @( New-ScheduledTaskTrigger -Daily -At ([datetime]$DailyAt) )
if (-not $NoStartup) { $triggers += New-ScheduledTaskTrigger -AtStartup }
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName "FullScan" -TaskPath "\SentinelC\" `
  -Action $action -Trigger $triggers -Principal $taskPrincipal -Settings $settings -Force | Out-Null

Write-Host ""
Write-Host "Installed. The agent runs as SYSTEM -- no further UAC prompts." -ForegroundColor Green
Write-Host "  Scan now : `"$InstallDir\scan-now.cmd`"   (or: schtasks /run /tn `"\SentinelC\FullScan`")"
Write-Host "  Logs     : $InstallDir\logs"
Write-Host "  Uninstall: powershell -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
