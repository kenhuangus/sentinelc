# build.ps1 - build SentinelC on Windows with MinGW-w64 (MSYS2 or Chocolatey).
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
# Output: build\sentinelc.exe
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Locate a gcc that can target Windows. Prefer MSYS2 ucrt64, then mingw64,
# then anything named x86_64-w64-mingw32-gcc / gcc on PATH (Chocolatey mingw).
$candidates = @(
    'C:\msys64\ucrt64\bin\gcc.exe',
    'C:\msys64\mingw64\bin\gcc.exe',
    'C:\ProgramData\chocolatey\bin\x86_64-w64-mingw32-gcc.exe',
    'x86_64-w64-mingw32-gcc',
    'gcc'
)
$gcc = $null
foreach ($c in $candidates) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd) { $gcc = $cmd.Source; break }
}
if (-not $gcc) {
    Write-Error "No MinGW gcc found. Install with:  choco install mingw -y   (run as admin)"
    exit 1
}
Write-Host "Using compiler: $gcc"

# MSYS2 gcc needs its bin dir on PATH to load its runtime DLLs.
$gccDir = Split-Path -Parent $gcc
$env:PATH = "$gccDir;$env:PATH"

New-Item -ItemType Directory -Force -Path "$root\build" | Out-Null
$srcs = Get-ChildItem "$root\src\*.c" | ForEach-Object { $_.FullName }
$libs = @('-lwintrust','-lcrypt32','-lbcrypt','-liphlpapi','-lws2_32','-lpsapi',
          '-lwtsapi32','-lole32','-loleaut32','-luuid','-lshell32',
          '-ladvapi32','-lkernel32','-lm')
$out = "$root\build\sentinelc.exe"

$args = @('-std=c11','-Wall','-Wextra','-O2','-I',"$root\include") + $srcs +
        @('-o',$out) + $libs
Write-Host "Compiling $($srcs.Count) modules..."
& $gcc @args
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed."; exit 1 }
Write-Host "OK -> $out"
