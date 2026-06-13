# SentinelC Makefile (MinGW-w64 / MSYS2).
# Usage:  make            -> build/sentinelc.exe
#         make clean
# On MSYS2 run from a ucrt64 shell; on WSL set CC=x86_64-w64-mingw32-gcc.

CC      ?= gcc
# Exploit-mitigation flags: stack canaries, FORTIFY, format-string checks,
# and (linker) ASLR / DEP / high-entropy ASLR. -lssp provides the stack/fortify
# runtime under MinGW. For Control Flow Guard / CET, build a release with MSVC
# (cl /guard:cf /CETCOMPAT /Qspectre /sdl) -- MinGW cannot emit CFG.
HARDEN_C := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fno-strict-aliasing
HARDEN_L := -Wl,--dynamicbase,--nxcompat,--high-entropy-va
CFLAGS  ?= -std=c11 -Wall -Wextra -O2 -Iinclude $(HARDEN_C)
LDLIBS  := -lwintrust -lcrypt32 -lbcrypt -liphlpapi -lws2_32 -lpsapi \
           -lwtsapi32 -lole32 -loleaut32 -luuid -lshell32 -ladvapi32 \
           -lkernel32 -lm

SRCS    := $(wildcard src/*.c)
OUT     := build/sentinelc.exe

all: $(OUT)

$(OUT): $(SRCS) include/sentinelc.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $(OUT) $(HARDEN_L) $(LDLIBS)
	@echo "OK -> $(OUT)"

clean:
	rm -f $(OUT)

.PHONY: all clean
