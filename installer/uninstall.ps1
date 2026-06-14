<#
.SYNOPSIS
  Remove the SentinelC agent: unregister the scheduled task and delete files.
#>
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:ProgramFiles "SentinelC"))

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# self-elevate
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Host "Requesting administrator rights (UAC)..." -ForegroundColor Yellow
  Start-Process powershell.exe -Verb RunAs -ArgumentList @(
    "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", "`"$($MyInvocation.MyCommand.Path)`"",
    "-InstallDir", "`"$InstallDir`"")
  return
}

try { Unregister-ScheduledTask -TaskName "FullScan" -TaskPath "\SentinelC\" -Confirm:$false -ErrorAction Stop; Write-Host "Removed scheduled task \SentinelC\FullScan." }
catch { Write-Host "Task not found (already removed)." }

# Don't delete the dir we're running from.
if ((Test-Path $InstallDir) -and ($here.TrimEnd('\') -ne $InstallDir.TrimEnd('\'))) {
  try { Remove-Item $InstallDir -Recurse -Force -ErrorAction Stop; Write-Host "Removed $InstallDir" }
  catch { Write-Warning "Could not remove $InstallDir : $($_.Exception.Message)" }
} else {
  Write-Host "Delete $InstallDir manually (it contains this script)."
}
