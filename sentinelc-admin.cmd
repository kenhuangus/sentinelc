@echo off
REM sentinelc-admin.cmd - launch SentinelC elevated (UAC prompt) and keep the
REM window open. Double-click this, or run it from any cmd window.
REM All arguments are forwarded to sentinelc.exe (default: --full).
setlocal
set "HERE=%~dp0"
set "EXE=%HERE%build\sentinelc.exe"

if not exist "%EXE%" (
    echo [!] %EXE% not found. Build it first: powershell -ExecutionPolicy Bypass -File "%HERE%build.ps1"
    pause
    exit /b 1
)

REM Are we already elevated?
net session >nul 2>&1
if %errorlevel%==0 goto :run

REM Not elevated: relaunch this script as admin via PowerShell.
echo [*] Requesting administrator privileges...
powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
exit /b

:run
set "ARGS=%*"
if "%ARGS%"=="" set "ARGS=--full"
echo [*] Running: sentinelc.exe %ARGS%
echo.
"%EXE%" %ARGS%
echo.
echo [*] Scan complete (exit %errorlevel%). Audit log: %ProgramData%\SentinelC\audit.log
pause
