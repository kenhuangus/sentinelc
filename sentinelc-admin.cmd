@echo off
REM sentinelc-admin.cmd - double-click friendly elevated full scan launcher.
REM Custom scan arguments are handled by sentinelc-admin.ps1 to avoid passing
REM raw command text through an elevated cmd.exe boundary.
setlocal
set "HERE=%~dp0"
set "PS=%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%PS%" (
    echo [!] System PowerShell not found at "%PS%".
    pause
    exit /b 1
)

if not "%~1"=="" (
    echo [!] sentinelc-admin.cmd no longer forwards custom arguments.
    echo     Use: "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%HERE%sentinelc-admin.ps1" --quick --json
    pause
    exit /b 2
)

"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%HERE%sentinelc-admin.ps1"
set "RC=%ERRORLEVEL%"
echo.
echo [*] Scan complete (exit %RC%). Audit log: %ProgramData%\SentinelC\audit.log
pause
exit /b %RC%
