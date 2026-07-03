[CmdletBinding()]
param(
    [string]$ElevatedArgsPath,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$SentinelArgs
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-SystemPowerShellPath {
    $path = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "System PowerShell not found at $path"
    }
    return $path
}

if ($ElevatedArgsPath) {
    $handoff = Get-Content -LiteralPath $ElevatedArgsPath -Raw | ConvertFrom-Json
    $SentinelArgs = @($handoff.SentinelArgs | ForEach-Object { [string]$_ })
    Remove-Item -LiteralPath $ElevatedArgsPath -Force -ErrorAction SilentlyContinue
}

if (-not $SentinelArgs -or $SentinelArgs.Count -eq 0) {
    $SentinelArgs = @('--full')
}

$repoRoot = Split-Path -Parent $PSCommandPath
$exe = Join-Path $repoRoot 'build\sentinelc.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    throw "SentinelC executable not found at $exe. Build it first with build.ps1."
}

if (-not (Test-IsAdmin)) {
    $handoffPath = Join-Path $env:TEMP ('sentinelc-admin-args-' + [guid]::NewGuid().ToString('N') + '.json')
    [ordered]@{
        SentinelArgs = @($SentinelArgs)
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $handoffPath -Encoding UTF8 -Force

    $argList = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-ElevatedArgsPath', $handoffPath
    )
    $child = Start-Process -Verb RunAs -Wait -PassThru -FilePath (Get-SystemPowerShellPath) -ArgumentList $argList
    if ($null -ne $child.ExitCode) {
        exit $child.ExitCode
    }
    exit 1
}

Write-Host "[*] Running: sentinelc.exe $($SentinelArgs -join ' ')"
& $exe @SentinelArgs
exit $LASTEXITCODE
