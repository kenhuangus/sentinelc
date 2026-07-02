[CmdletBinding()]
param(
    [string]$ExePath,
    [string]$RepoRoot,
    [string]$OutputDir,
    [int]$OfflinePasses = 1
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $PSCommandPath

function Get-SystemPowerShellPath {
    $path = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "System PowerShell not found at $path"
    }
    return $path
}

if (-not $OutputDir) {
    $OutputDir = Join-Path (Get-Location) ('sentinelc-verify-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$runner = Join-Path $scriptDir 'run-sentinelc-scan.ps1'
$parser = Join-Path $scriptDir 'parse-sentinelc-findings.py'

$args = @(
    '-Mode', 'offline-like',
    '-OfflinePasses', [string]$OfflinePasses,
    '-OutputDir', $OutputDir
)
if ($ExePath) { $args += @('-ExePath', $ExePath) }
if ($RepoRoot) { $args += @('-RepoRoot', $RepoRoot) }

& (Get-SystemPowerShellPath) -NoProfile -ExecutionPolicy Bypass -File $runner @args

$report = Join-Path $OutputDir 'sentinelc.json'
$plan = Join-Path $OutputDir 'action-plan.md'
python $parser $report --out $plan

Write-Output "report=$report"
Write-Output "plan=$plan"
