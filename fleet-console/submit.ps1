<#
.SYNOPSIS
  SentinelC fleet agent: runs the local scanner and uploads results to the Fleet Console.

.DESCRIPTION
  Runs ..\build\sentinelc.exe --full --json, captures stdout, wraps it in the
  ingest envelope { hostname, scannedAt, scan }, and POSTs it to the console's
  /api/ingest endpoint with a bearer token.

.PARAMETER ConsoleUrl
  Base URL of the Fleet Console. Default http://127.0.0.1:8787

.PARAMETER Token
  Bearer token. Defaults to the SENTINELC_FLEET_TOKEN environment variable.

.EXAMPLE
  .\submit.ps1 -ConsoleUrl http://127.0.0.1:8787 -Token <token>
#>
[CmdletBinding()]
param(
  [string]$ConsoleUrl = "http://127.0.0.1:8787",
  [string]$Token = $env:SENTINELC_FLEET_TOKEN
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Token)) {
  Write-Error "No token supplied. Pass -Token or set SENTINELC_FLEET_TOKEN."
  exit 1
}

# Locate the scanner relative to this script.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $scriptDir "..\build\sentinelc.exe"
if (-not (Test-Path $exe)) {
  Write-Error "Scanner not found at $exe"
  exit 1
}

Write-Host "Running scanner: $exe --full --json"
$stdout = & $exe --full --json
$scanJson = ($stdout -join "`n")

# Parse to validate and to embed as an object (not a double-encoded string).
try {
  $scan = $scanJson | ConvertFrom-Json
} catch {
  Write-Error "Scanner did not emit valid JSON: $($_.Exception.Message)"
  exit 1
}

$payload = [ordered]@{
  hostname  = $env:COMPUTERNAME
  scannedAt = (Get-Date).ToUniversalTime().ToString("o")
  scan      = $scan
}

$body = $payload | ConvertTo-Json -Depth 20 -Compress

$headers = @{
  "Authorization" = "Bearer $Token"
  "Content-Type"  = "application/json"
}

$ingestUrl = ($ConsoleUrl.TrimEnd("/")) + "/api/ingest"
Write-Host "Uploading to $ingestUrl as host '$($env:COMPUTERNAME)'..."

try {
  $resp = Invoke-RestMethod -Uri $ingestUrl -Method Post -Headers $headers -Body $body
  Write-Host "Result:" ($resp | ConvertTo-Json -Compress)
  if ($resp.ok) {
    Write-Host "Submitted successfully." -ForegroundColor Green
    exit 0
  } else {
    Write-Warning "Console reported failure."
    exit 1
  }
} catch {
  Write-Error "Upload failed: $($_.Exception.Message)"
  exit 1
}
