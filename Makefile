# Makefile for eBPF SQL injection detector + shell guard
CLANG := clang
CC := gcc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(shell uname -m)-linux-gnu
USER_CFLAGS := -O2 -g -Wall
USER_LDFLAGS := -lbpf -lelf -lz

.PHONY: all clean

all: vmlinux.h sqli_detect.bpf.o sqli_detect shell_guard.bpf.o shell_guard

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

sqli_detect.bpf.o: sqli_detect.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

sqli_detect: sqli_detect.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS)

shell_guard.bpf.o: shell_guard.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

shell_guard: shell_guard.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS)

clean:
	rm -f sqli_detect.bpf.o sqli_detect shell_guard.bpf.o shell_guard vmlinux.h
