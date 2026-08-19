# Copyright (c) 2026 Christiaan (chris@boreddev.nl)
# kirc IRC Client Standalone Makefile for BoredOS

CC = x86_64-boredos-gcc
AR = x86_64-boredos-ar

DESTDIR ?= $(abspath build/dist)

BEARSSL_DIR = ../bearssl
BEARSSL_SRCS = $(shell find $(BEARSSL_DIR)/src -name "*.c" 2>/dev/null)
BEARSSL_OBJS = $(patsubst $(BEARSSL_DIR)/src/%.c, obj/bearssl/%.o, $(BEARSSL_SRCS))

CFLAGS  = -Wall -Wextra -std=gnu11 -ffreestanding -O2 -fno-stack-protector \
          -fno-stack-check -fno-lto -fno-pie -m64 -march=x86-64 -mno-red-zone \
          -D_GNU_SOURCE -Iinclude -Isrc -I$(BEARSSL_DIR)/inc -I$(BEARSSL_DIR)/src

LDFLAGS = -static -no-pie -Wl,-Ttext=0x40000000 \
          -Wl,--no-dynamic-linker -Wl,-z,text -Wl,-z,max-page-size=0x1000

KIRC_SRCS = $(wildcard src/*.c)
KIRC_OBJS = $(patsubst src/%.c, obj/%.o, $(KIRC_SRCS))

APPS = kirc.elf

all: bootstrap-bearssl $(APPS)

.PHONY: bootstrap-bearssl apps bup install clean

bootstrap-bearssl:
	@if [ ! -d "$(BEARSSL_DIR)" ]; then \
		echo "[STANDALONE] BearSSL not found at $(BEARSSL_DIR). Cloning mirror..."; \
		git clone https://www.bearssl.org/git/BearSSL $(BEARSSL_DIR); \
	fi

obj/bearssl/%.o: $(BEARSSL_DIR)/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

obj/libbearssl.a: $(BEARSSL_OBJS)
	@mkdir -p obj
	$(AR) rcs $@ $(BEARSSL_OBJS)

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -c $< -o $@

kirc.elf: $(KIRC_OBJS) obj/libbearssl.a
	$(CC) $(KIRC_OBJS) obj/libbearssl.a $(LDFLAGS) -o $@

install: all
	mkdir -p $(DESTDIR)/bin
	cp $(APPS) $(DESTDIR)/bin/

bup: all
	rm -rf build/package
	mkdir -p build/package/bin
	cp $(APPS) build/package/bin/
	cp MANIFEST.toml build/package/
	x86_64-boredos-strip --strip-unneeded build/package/bin/*.elf 2>/dev/null || true
	mkdir -p build
	tar -cf build/kirc.tar -C build/package MANIFEST.toml bin
	lz4 -f build/kirc.tar build/kirc.bup
	rm -f build/kirc.tar
	rm -rf build/package

clean:
	rm -rf obj build $(APPS)
