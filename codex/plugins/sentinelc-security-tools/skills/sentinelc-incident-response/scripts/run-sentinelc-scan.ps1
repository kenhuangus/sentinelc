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
    [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Resolve-SentinelCExe {
    param([string]$ExePath, [string]$RepoRoot)
    if ($ExePath) {
        return (Resolve-Path -LiteralPath $ExePath).Path
    }
    if ($RepoRoot) {
        $candidate = Join-Path $RepoRoot 'build\sentinelc.exe'
        if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
        $build = Join-Path $RepoRoot 'build.ps1'
        if (Test-Path -LiteralPath $build) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $build
            if (Test-Path -LiteralPath $candidate) { return (Resolve-Path -LiteralPath $candidate).Path }
        }
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
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"' + $PSCommandPath + '"'),
        '-NoElevate',
        '-Mode', $Mode,
        '-OfflinePasses', $OfflinePasses,
        '-WatchSeconds', $WatchSeconds,
        '-OutputDir', ('"' + $OutputDir + '"')
    )
    if ($ExePath) { $argList += @('-ExePath', ('"' + $ExePath + '"')) }
    if ($RepoRoot) { $argList += @('-RepoRoot', ('"' + $RepoRoot + '"')) }
    if ($Deep) { $argList += '-Deep' }
    Start-Process -Verb RunAs -Wait -FilePath powershell.exe -ArgumentList ($argList -join ' ')
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
