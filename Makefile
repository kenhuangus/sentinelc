# SentinelC Makefile (MinGW-w64 / MSYS2).
# Usage:  make            -> build/sentinelc.exe
#         make clean
# On MSYS2 run from a ucrt64 shell; on WSL set CC=x86_64-w64-mingw32-gcc.

CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2 -Iinclude
LDLIBS  := -lwintrust -lcrypt32 -lbcrypt -liphlpapi -lws2_32 -lpsapi \
           -lwtsapi32 -lole32 -loleaut32 -luuid -lshell32 -ladvapi32 \
           -lkernel32 -lm

SRCS    := $(wildcard src/*.c)
OUT     := build/sentinelc.exe

all: $(OUT)

$(OUT): $(SRCS) include/sentinelc.h
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $(OUT) $(LDLIBS)
	@echo "OK -> $(OUT)"

clean:
	rm -f $(OUT)

.PHONY: all clean
