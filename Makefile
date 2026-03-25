# process_metrics — event-driven BPF process metrics collector
#
# Structure:
#   src/               — project source code
#   src/bpftool/       — bpftool source (vendored, built locally)
#   build/             — generated artifacts (.bpf.o, .skel.h, binary)
#
# Usage:
#   make               — show this help
#   make deps          — install build dependencies (auto-detects apt/yum)
#   make all           — full build: vmlinux.h + bpftool + BPF + binary
#   make bpftool       — build only bpftool from src/bpftool/
#   make vmlinux       — regenerate vmlinux.h from running kernel BTF
#   make bpf           — compile BPF object + generate skeleton
#   make binary        — compile userspace binary (requires skeleton)
#   make clean         — remove build artifacts
#
# Requirements:
#   clang >= 10        — for BPF CO-RE and userspace
#   gcc                — for vendored bpftool
#   libbpf-dev, libelf-dev, zlib1g-dev

SRCDIR   := src
BUILDDIR := build

# Source files
BPF_SRC    := $(SRCDIR)/process_metrics.bpf.c
USER_SRCS  := $(SRCDIR)/process_metrics.c $(SRCDIR)/event_file.c $(SRCDIR)/http_server.c
COMMON_H   := $(SRCDIR)/process_metrics_common.h
EF_H       := $(SRCDIR)/event_file.h
HS_H       := $(SRCDIR)/http_server.h
VMLINUX_H  := $(SRCDIR)/vmlinux.h

# Build artifacts
BPF_OBJ    := $(BUILDDIR)/process_metrics.bpf.o
SKEL_H     := $(BUILDDIR)/process_metrics.skel.h
BINARY     := $(BUILDDIR)/process_metrics

# bpftool from vendored sources
BPFTOOL_SRCDIR := $(SRCDIR)/bpftool/src
BPFTOOL_BIN    := $(BUILDDIR)/bpftool

# Tools — auto-detect newest clang with BPF CO-RE support (>= 10)
CLANG   ?= $(shell best=""; best_ver=0; \
            for c in clang clang-10 clang-11 clang-12 clang-13 clang-14 clang-15 clang-16 clang-17 clang-18 clang-19 clang-20; do \
              command -v $$c >/dev/null 2>&1 || continue; \
              ver=$$($$c --version 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1); \
              [ -n "$$ver" ] && [ "$$ver" -ge 10 ] 2>/dev/null && [ "$$ver" -gt "$$best_ver" ] && best=$$c && best_ver=$$ver; \
            done; echo $$best)
BPFTOOL ?= $(BPFTOOL_BIN)
CC      := $(CLANG)

# Flags
BPF_CFLAGS := -O2 -g -target bpf -I$(SRCDIR) -D__TARGET_ARCH_x86
CFLAGS     := -O2 -Wall -I$(BUILDDIR) -I$(SRCDIR)
LDFLAGS    := -static -lbpf -lelf -lz -lconfig -lpthread

# Dependency packages
APT_PKGS := gcc make build-essential libbpf-dev libelf-dev zlib1g-dev libbfd-dev libcap-dev llvm libconfig-dev
YUM_PKGS := gcc make gcc-c++ libbpf-devel elfutils-libelf-devel zlib-devel binutils-devel libcap-devel llvm libconfig-devel

# Minimum clang version for BPF CO-RE
MIN_CLANG_VER := 10

# Test artifacts
TEST_EF_SRC    := tests/test_event_file.c
TEST_EF_BIN    := $(BUILDDIR)/test_event_file

.PHONY: help all clean vmlinux bpf binary deps deps-apt deps-yum bpftool check-clang test test-unit test-http test-clickhouse

help:
	@echo "process_metrics — event-driven BPF process metrics collector"
	@echo ""
	@echo "  make deps       install build dependencies (auto-detects apt/yum)"
	@echo "  make all        full build: vmlinux + bpftool + bpf + binary"
	@echo "  make vmlinux    regenerate vmlinux.h from running kernel BTF"
	@echo "  make bpftool    build bpftool from vendored sources"
	@echo "  make bpf        compile BPF object + generate skeleton"
	@echo "  make binary     compile userspace binary"
	@echo "  make clean      remove build artifacts"
	@echo "  make test       run unit tests"
	@echo ""
	@echo "Detected clang:   $(or $(CLANG),NOT FOUND — install clang >= $(MIN_CLANG_VER))"
	@echo "Kernel version:   $(shell uname -r)"
	@echo ""
	@echo "Quick start:"
	@echo "  make deps && make all"

# --- main targets ---

all: check-clang vmlinux bpftool bpf binary
	@echo ""
	@echo "Build complete: $(BINARY)"
	@echo "  kernel: $(shell uname -r)"
	@file $(BINARY) | sed 's/^/  /'

# --- clang version check ---

check-clang:
	@if [ -z "$(CLANG)" ]; then \
		echo "Error: no clang >= $(MIN_CLANG_VER) found."; \
		echo "Install: apt install clang-11  OR  yum install clang"; \
		echo "Or specify: make all CLANG=/path/to/clang-11"; \
		exit 1; \
	fi; \
	ver=$$($(CLANG) --version 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1); \
	if [ -z "$$ver" ] || [ "$$ver" -lt $(MIN_CLANG_VER) ]; then \
		echo "Error: $(CLANG) version $$ver < $(MIN_CLANG_VER) (need >= $(MIN_CLANG_VER) for BPF CO-RE)"; \
		echo "Install clang >= $(MIN_CLANG_VER) or specify: make all CLANG=clang-11"; \
		exit 1; \
	fi; \
	echo "Using $(CLANG) (version $$ver), kernel $(shell uname -r)"

# --- dependency installation ---

deps:
	@if command -v apt-get >/dev/null 2>&1; then \
		$(MAKE) deps-apt; \
	elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then \
		$(MAKE) deps-yum; \
	else \
		echo "Error: neither apt-get nor yum/dnf found"; exit 1; \
	fi

deps-apt:
	apt-get update
	apt-get install -y $(APT_PKGS)
	@# kernel headers — optional, may not exist in containers
	apt-get install -y linux-headers-$(shell uname -r) 2>/dev/null || \
		echo "Note: linux-headers not found (OK for containers, needed only for vmlinux.h regeneration)"
	@# Install clang >= 10: try clang-10..clang-18, then generic clang
	@found=0; \
	for pkg in clang-10 clang-11 clang-12 clang-13 clang-14 clang-15 clang-16 clang-17 clang-18 clang; do \
		if apt-cache show $$pkg >/dev/null 2>&1; then \
			echo "Installing $$pkg..."; \
			apt-get install -y $$pkg; \
			found=1; \
			break; \
		fi; \
	done; \
	if [ "$$found" = "0" ]; then \
		echo "Warning: no clang package found in apt repos"; \
		echo "Install clang >= $(MIN_CLANG_VER) manually"; \
	fi

deps-yum:
	yum install -y $(YUM_PKGS) clang
	@# kernel headers — optional, may not exist in containers
	yum install -y kernel-devel-$(shell uname -r) 2>/dev/null || \
		echo "Note: kernel-devel not found (OK for containers, needed only for vmlinux.h regeneration)"

# --- vmlinux.h from running kernel BTF ---

vmlinux: $(BPFTOOL_BIN)
	chmod ugo+x $(BPFTOOL)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "vmlinux.h regenerated from $(shell uname -r)"

# --- bpftool from vendored source ---

bpftool: $(BPFTOOL_BIN)

$(BPFTOOL_BIN): | $(BUILDDIR)
	mkdir -p $(CURDIR)/$(BUILDDIR)/bpftool-build
	$(MAKE) -C $(BPFTOOL_SRCDIR) -j$$(nproc) \
		OUTPUT=$(CURDIR)/$(BUILDDIR)/bpftool-build/ \
		CC=gcc \
		EXTRA_CFLAGS="-Wno-error=discarded-qualifiers" \
		LLVM_STRIP="$(shell command -v llvm-strip 2>/dev/null || echo true)"
	cp $(CURDIR)/$(BUILDDIR)/bpftool-build/bpftool $@
	rm -rf $(CURDIR)/$(BUILDDIR)/bpftool-build

# --- BPF compilation ---

bpf: $(SKEL_H)

$(BPF_OBJ): $(BPF_SRC) $(COMMON_H) $(VMLINUX_H) | $(BUILDDIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_H): $(BPF_OBJ) $(BPFTOOL_BIN)
	chmod ugo+x $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

# --- userspace binary ---

binary: $(BINARY)

$(BINARY): $(USER_SRCS) $(COMMON_H) $(EF_H) $(HS_H) $(SKEL_H)
	$(CC) $(CFLAGS) -o $@ $(USER_SRCS) $(LDFLAGS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(BINARY) $(BPFTOOL_BIN) $(TEST_EF_BIN)
	rm -rf $(BUILDDIR)/bpftool-build

# --- tests ---

$(TEST_EF_BIN): $(TEST_EF_SRC) $(SRCDIR)/event_file.c $(EF_H) $(COMMON_H) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(TEST_EF_SRC) $(SRCDIR)/event_file.c -lpthread

test-unit: $(TEST_EF_BIN)
	$(TEST_EF_BIN)

test-http: $(BINARY)
	tests/test_http_server.sh

test-clickhouse: $(BINARY)
	tests/test_clickhouse_integration.sh

test: test-unit
