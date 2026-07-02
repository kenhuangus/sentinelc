[CmdletBinding()]
param(
    [string]$ExePath,
    [string]$RepoRoot,
    [ValidateSet('quick', 'full', 'offline-like')]
    [string]$Mode = 'offline-like',
    [int]$OfflinePasses = 1,
    [int]$WatchSeconds = 0,
    [switch]$Deep,
    [string]$OutputDir,
    [switch]$NoElevate,
    [string]$ElevatedArgsPath
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-SystemPowerShellPath {
    $p = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $p)) { throw "system PowerShell not found at $p" }
    return $p
}

if ($ElevatedArgsPath) {
    $handoff = Get-Content -LiteralPath $ElevatedArgsPath -Raw | ConvertFrom-Json
    $ExePath = [string]$handoff.ExePath
    $RepoRoot = [string]$handoff.RepoRoot
    $Mode = [string]$handoff.Mode
    $OfflinePasses = [int]$handoff.OfflinePasses
    $WatchSeconds = [int]$handoff.WatchSeconds
    $Deep = [bool]$handoff.Deep
    $OutputDir = [string]$handoff.OutputDir
    $NoElevate = $true
    Remove-Item -LiteralPath $ElevatedArgsPath -Force -ErrorAction SilentlyContinue
}

function Resolve-SentinelCExe {
    param([string]$ExePath, [string]$RepoRoot)
    if ($ExePath) {
        return (Resolve-Path -LiteralPath $ExePath).Path
    }
    if ($RepoRoot) {
        $candidate = Join-Path $RepoRoot 'build\sentinelc.exe'
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
        throw 'SentinelC executable not found under RepoRoot\build. Build it before requesting elevation, or pass -ExePath.'
    }
    $local = Join-Path (Get-Location) 'build\sentinelc.exe'
    if (Test-Path -LiteralPath $local) { return (Resolve-Path -LiteralPath $local).Path }
    throw 'SentinelC executable not found. Pass -ExePath or -RepoRoot.'
}

if (-not $OutputDir) {
    $OutputDir = Join-Path (Get-Location) ('sentinelc-scan-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

if (-not $NoElevate -and -not (Test-IsAdmin)) {
    $handoffPath = Join-Path $OutputDir ('elevate-args-' + [guid]::NewGuid().ToString('N') + '.json')
    [ordered]@{
        ExePath = $ExePath
        RepoRoot = $RepoRoot
        Mode = $Mode
        OfflinePasses = $OfflinePasses
        WatchSeconds = $WatchSeconds
        Deep = [bool]$Deep
        OutputDir = $OutputDir
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $handoffPath -Encoding UTF8 -Force
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-NoElevate',
        '-ElevatedArgsPath', $handoffPath
    )
    Start-Process -Verb RunAs -Wait -FilePath (Get-SystemPowerShellPath) -ArgumentList $argList
    Get-Content -LiteralPath (Join-Path $OutputDir 'status.txt') -ErrorAction SilentlyContinue
    return
}

$exe = Resolve-SentinelCExe -ExePath $ExePath -RepoRoot $RepoRoot
$json = Join-Path $OutputDir 'sentinelc.json'
$err = Join-Path $OutputDir 'sentinelc.err'
$status = Join-Path $OutputDir 'status.txt'

$scanArgs = @()
switch ($Mode) {
    'quick' { $scanArgs += '--quick' }
    'full' { $scanArgs += '--full' }
    'offline-like' { $scanArgs += @('--offline-like', '--offline-passes', [string]$OfflinePasses) }
}
if ($Deep) { $scanArgs += '--deep' }
if ($WatchSeconds -gt 0) { $scanArgs += @('--watch', [string]$WatchSeconds) }
$scanArgs += @('--json', '--no-color')

& $exe @scanArgs 1> $json 2> $err
$exit = $LASTEXITCODE

@(
    "exit=$exit",
    "elevated=$(Test-IsAdmin)",
    "mode=$Mode",
    "json=$json",
    "stderr=$err"
) | Out-File -LiteralPath $status -Encoding ascii -Force

exit $exit
