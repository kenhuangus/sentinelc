#!/usr/bin/env bash
# build.sh - build SentinelC from WSL or an MSYS2/Git-Bash shell.
#
# From WSL Ubuntu you need the MinGW cross-compiler:
#     sudo apt-get install -y gcc-mingw-w64-x86-64
# From MSYS2 you need the ucrt64 toolchain on PATH.
#
# The produced build/sentinelc.exe is a NATIVE WINDOWS binary. Under WSL,
# Windows interop lets you run it directly:  ./build/sentinelc.exe --quick
# (it scans the Windows host). Run from an elevated context for full coverage.
set -euo pipefail
cd "$(dirname "$0")"

# Pick a Windows-targeting gcc.
GCC=""
for c in x86_64-w64-mingw32-gcc \
         /c/msys64/ucrt64/bin/gcc.exe \
         /mnt/c/msys64/ucrt64/bin/gcc.exe \
         /c/msys64/mingw64/bin/gcc.exe \
         /mnt/c/msys64/mingw64/bin/gcc.exe; do
    if command -v "$c" >/dev/null 2>&1; then GCC="$c"; break; fi
done
if [ -z "$GCC" ]; then
    echo "No MinGW gcc found." >&2
    echo "  WSL:   sudo apt-get install -y gcc-mingw-w64-x86-64" >&2
    echo "  MSYS2: pacman -S mingw-w64-ucrt-x86_64-gcc  (and run from ucrt64 shell)" >&2
    exit 1
fi
echo "Using compiler: $GCC"

# If using the MSYS2 gcc.exe, add its dir to PATH so its DLLs load.
case "$GCC" in
    *msys64*) export PATH="$(dirname "$GCC"):$PATH" ;;
esac

mkdir -p build
# Exploit-mitigation flags: stack canaries + FORTIFY + format checks (compile),
# ASLR / DEP / high-entropy ASLR (link). gcc auto-links the stack-protector
# runtime, so no explicit -lssp (which is absent on some MinGW builds).
HARDEN_C="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fno-strict-aliasing"
HARDEN_L="-Wl,--dynamicbase,--nxcompat,--high-entropy-va"
LIBS="-lwintrust -lcrypt32 -lbcrypt -liphlpapi -lws2_32 -lpsapi -lwtsapi32 \
      -lole32 -loleaut32 -luuid -lshell32 -ladvapi32 -lkernel32 -lm"
echo "Compiling $(ls src/*.c | wc -l) modules..."
# shellcheck disable=SC2086
"$GCC" -std=c11 -Wall -Wextra -O2 $HARDEN_C -I include $(ls src/*.c) \
       -o build/sentinelc.exe $HARDEN_L $LIBS
echo "OK -> build/sentinelc.exe"
