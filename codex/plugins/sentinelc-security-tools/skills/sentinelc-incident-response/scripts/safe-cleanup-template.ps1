[CmdletBinding()]
param(
    [string]$EvidenceDir,
    [string[]]$RemoveDefenderExclusionPath = @(),
    [string[]]$DisableRunValue = @(),
    [string[]]$StopProcessName = @(),
    [string[]]$DisableServiceName = @(),
    [string[]]$QuarantineTarget = @()
)

$ErrorActionPreference = 'Continue'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not $EvidenceDir) {
    $EvidenceDir = Join-Path (Get-Location) ('sentinelc-cleanup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

$actions = New-Object System.Collections.Generic.List[object]
function Add-Action($Item, $Action, $Result, $Detail) {
    $actions.Add([pscustomobject]@{
        time = (Get-Date).ToString('s')
        item = $Item
        action = $Action
        result = $Result
        detail = $Detail
    }) | Out-Null
}

Get-CimInstance Win32_Process |
    Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
    ConvertTo-Json -Depth 4 |
    Out-File -LiteralPath (Join-Path $EvidenceDir 'processes_before.json') -Encoding utf8 -Force

reg.exe export 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' (Join-Path $EvidenceDir 'hkcu_run_before.reg') /y | Out-Null
reg.exe export 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' (Join-Path $EvidenceDir 'defender_exclusions_before.reg') /y | Out-Null

foreach ($ex in $RemoveDefenderExclusionPath) {
    try {
        Remove-MpPreference -ExclusionPath $ex -Force
        Add-Action 'Defender exclusion' "remove $ex" 'done' 'Removed requested exclusion.'
    } catch {
        Add-Action 'Defender exclusion' "remove $ex" 'failed' $_.Exception.Message
    }
}

$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
foreach ($name in $DisableRunValue) {
    try {
        $props = Get-ItemProperty -Path $runKey -ErrorAction Stop
        if ($null -ne $props.PSObject.Properties[$name]) {
            Remove-ItemProperty -Path $runKey -Name $name -Force
            Add-Action 'HKCU Run' "remove $name" 'done' 'Disabled startup value.'
        } else {
            Add-Action 'HKCU Run' "remove $name" 'not-present' 'Startup value was absent.'
        }
    } catch {
        Add-Action 'HKCU Run' "remove $name" 'failed' $_.Exception.Message
    }
}

foreach ($name in $StopProcessName) {
    $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.Id -Force
            Add-Action 'Process' "stop $name pid $($p.Id)" 'done' 'Stopped requested process.'
        } catch {
            Add-Action 'Process' "stop $name pid $($p.Id)" 'failed' $_.Exception.Message
        }
    }
}

foreach ($svcName in $DisableServiceName) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            Get-CimInstance Win32_Service -Filter "Name='$svcName'" |
                ConvertTo-Json -Depth 4 |
                Out-File -LiteralPath (Join-Path $EvidenceDir ("service_$svcName.before.json")) -Encoding utf8 -Force
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svcName -StartupType Disabled
            Add-Action 'Service' "disable $svcName" 'done' 'Stopped and disabled service.'
        } else {
            Add-Action 'Service' "disable $svcName" 'not-present' 'Service was absent.'
        }
    } catch {
        Add-Action 'Service' "disable $svcName" 'failed' $_.Exception.Message
    }
}

foreach ($spec in $QuarantineTarget) {
    $parts = $spec -split '\|', 2
    $path = $parts[0]
    $expected = if ($parts.Count -gt 1) { $parts[1].ToUpperInvariant() } else { '' }
    try {
        if (-not (Test-Path -LiteralPath $path)) {
            Add-Action 'Quarantine' $path 'not-present' 'Target was absent.'
            continue
        }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
        Get-Item -LiteralPath $path -Force |
            Format-List * |
            Out-File -LiteralPath (Join-Path $EvidenceDir ('file_' + [IO.Path]::GetFileName($path) + '.metadata.txt')) -Encoding utf8 -Force
        if ($expected -and $hash -ne $expected) {
            Copy-Item -LiteralPath $path -Destination (Join-Path $EvidenceDir ([IO.Path]::GetFileName($path) + '.review-copy')) -Force
            Add-Action 'Quarantine' $path 'skipped' "Hash changed. expected=$expected actual=$hash"
            continue
        }
        Move-Item -LiteralPath $path -Destination (Join-Path $EvidenceDir ([IO.Path]::GetFileName($path))) -Force
        Add-Action 'Quarantine' $path 'done' "Moved target with sha256=$hash"
    } catch {
        Add-Action 'Quarantine' $path 'failed' $_.Exception.Message
    }
}

reg.exe export 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' (Join-Path $EvidenceDir 'hkcu_run_after.reg') /y | Out-Null
reg.exe export 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' (Join-Path $EvidenceDir 'defender_exclusions_after.reg') /y | Out-Null

$actions | ConvertTo-Json -Depth 4 | Out-File -LiteralPath (Join-Path $EvidenceDir 'actions.json') -Encoding utf8 -Force
$actions | Format-Table -AutoSize | Out-String -Width 240 | Out-File -LiteralPath (Join-Path $EvidenceDir 'actions.txt') -Encoding utf8 -Force

Write-Output "elevated=$(Test-IsAdmin)"
Write-Output "evidence=$EvidenceDir"
