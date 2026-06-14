<#
.SYNOPSIS
  SentinelC scheduled-task action. Runs the scanner and uploads results.

.DESCRIPTION
  Invoked by the "\SentinelC\FullScan" scheduled task, which runs as
  NT AUTHORITY\SYSTEM with highest privileges (no UAC). Reads config.json
  (console URL + DPAPI-protected token) from its own directory, runs
  sentinelc.exe --full --json, wraps it in the ingest envelope, and POSTs it
  to the Fleet Console. Writes a daily log under .\logs.

  Not meant to be run by hand -- use scan-now.cmd or:
    schtasks /run /tn "\SentinelC\FullScan"
#>
[CmdletBinding()]
param([string]$ConfigPath)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ConfigPath) { $ConfigPath = Join-Path $here "config.json" }

$logDir = Join-Path $here "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logFile = Join-Path $logDir ("scan-{0:yyyyMMdd}.log" -f (Get-Date))
function Log($m) { Add-Content -Path $logFile -Value ("{0} {1}" -f (Get-Date).ToString("o"), $m) }

try {
  if (-not (Test-Path $ConfigPath)) { throw "config not found: $ConfigPath" }
  $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
  $consoleUrl = $cfg.consoleUrl
  if ([string]::IsNullOrWhiteSpace($consoleUrl)) { throw "config has no consoleUrl" }

  # Decrypt the bearer token (DPAPI LocalMachine: only this machine can read it).
  Add-Type -AssemblyName System.Security
  $protected  = [Convert]::FromBase64String($cfg.tokenProtected)
  $tokenBytes = [Security.Cryptography.ProtectedData]::Unprotect(
                  $protected, $null,
                  [Security.Cryptography.DataProtectionScope]::LocalMachine)
  $token = [Text.Encoding]::UTF8.GetString($tokenBytes)

  $exe = Join-Path $here "sentinelc.exe"
  if (-not (Test-Path $exe)) { throw "scanner not found: $exe" }

  Log "running $exe --full --json"
  $stdout   = & $exe --full --json
  $scanJson = ($stdout -join "`n")
  $scan     = $scanJson | ConvertFrom-Json   # validate

  $payload = [ordered]@{
    hostname  = $env:COMPUTERNAME
    scannedAt = (Get-Date).ToUniversalTime().ToString("o")
    scan      = $scan
  }
  $body    = $payload | ConvertTo-Json -Depth 20 -Compress
  $headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }
  $ingest  = ($consoleUrl.TrimEnd("/")) + "/api/ingest"

  Log "uploading to $ingest as host '$($env:COMPUTERNAME)'"
  $resp = Invoke-RestMethod -Uri $ingest -Method Post -Headers $headers -Body $body -TimeoutSec 120
  Log ("result: " + ($resp | ConvertTo-Json -Compress))
  if (-not $resp.ok) { throw "console reported failure" }
  Log "done OK"
  exit 0
} catch {
  Log ("ERROR: " + $_.Exception.Message)
  exit 1
}
