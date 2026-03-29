# process_metrics — событийный BPF-коллектор метрик процессов
#
# Структура:
#   src/               — исходный код проекта
#   src/bpftool/       — исходники bpftool (вендорная копия, собирается локально)
#   build/             — сгенерированные артефакты (.bpf.o, .skel.h, бинарник)
#
# Использование:
#   make               — показать эту справку
#   make deps          — установить зависимости сборки (автоопределение pacman/apt/yum)
#   make all           — полная сборка: vmlinux.h + bpftool + BPF + бинарник
#   make bpftool       — собрать только bpftool из src/bpftool/
#   make vmlinux       — пересоздать vmlinux.h из BTF текущего ядра
#   make bpf           — скомпилировать BPF-объект + сгенерировать скелетон
#   make binary        — скомпилировать userspace-бинарник (требует скелетон)
#   make clean         — удалить артефакты сборки
#
# Требования:
#   clang >= 10        — для BPF CO-RE и userspace-кода
#   gcc                — для вендорного bpftool
#   libbpf-dev, libelf-dev, zlib1g-dev

SRCDIR   := src
BUILDDIR := build

# Исходные файлы
BPF_SRC    := $(SRCDIR)/process_metrics.bpf.c
USER_SRCS  := $(SRCDIR)/process_metrics.c $(SRCDIR)/event_file.c $(SRCDIR)/http_server.c $(SRCDIR)/csv_format.c
COMMON_H   := $(SRCDIR)/process_metrics_common.h
EF_H       := $(SRCDIR)/event_file.h
HS_H       := $(SRCDIR)/http_server.h
CSV_H      := $(SRCDIR)/csv_format.h
VMLINUX_H  := $(SRCDIR)/vmlinux.h

# Артефакты сборки
BPF_OBJ    := $(BUILDDIR)/process_metrics.bpf.o
SKEL_H     := $(BUILDDIR)/process_metrics.skel.h
BINARY     := $(BUILDDIR)/process_metrics

# bpftool из вендорных исходников
BPFTOOL_SRCDIR := $(SRCDIR)/bpftool/src
BPFTOOL_BIN    := $(BUILDDIR)/bpftool

# Инструменты — автоопределение самого нового clang с поддержкой BPF CO-RE (>= 10)
CLANG   ?= $(shell best=""; best_ver=0; \
            for c in clang clang-10 clang-11 clang-12 clang-13 clang-14 clang-15 clang-16 clang-17 clang-18 clang-19 clang-20; do \
              command -v $$c >/dev/null 2>&1 || continue; \
              ver=$$($$c --version 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1); \
              [ -n "$$ver" ] && [ "$$ver" -ge 10 ] 2>/dev/null && [ "$$ver" -gt "$$best_ver" ] && best=$$c && best_ver=$$ver; \
            done; echo $$best)
BPFTOOL ?= $(BPFTOOL_BIN)
CC      := $(CLANG)

# Версия ядра — для совместимости BPF верификатора (5.15 vs 6.x)
KERN_VER_MAJOR := $(shell uname -r | cut -d. -f1)
KERN_VER_MINOR := $(shell uname -r | cut -d. -f2)

# Флаги компиляции
BPF_CFLAGS := -O2 -g -target bpf -I$(SRCDIR) -D__TARGET_ARCH_x86 \
              -DKERN_VER_MAJOR=$(KERN_VER_MAJOR) -DKERN_VER_MINOR=$(KERN_VER_MINOR)
CFLAGS     := -O2 -Wall -I$(BUILDDIR) -I$(SRCDIR)

# Опциональные флаги сборки:
#   make binary NO_TAGS=1  — отключить подсистему тегов (для бенчмаркинга)
ifdef NO_TAGS
CFLAGS += -DNO_TAGS
endif
LDFLAGS    := -Wl,-Bstatic -lbpf -lelf -lzstd -lz -lconfig -Wl,-Bdynamic -lpthread -lc

# Пакеты зависимостей
APT_PKGS := gcc make build-essential libbpf-dev libelf-dev zlib1g-dev libbfd-dev libcap-dev llvm libconfig-dev
YUM_PKGS := gcc make gcc-c++ libbpf-devel elfutils-libelf-devel zlib-devel binutils-devel libcap-devel llvm libconfig-devel
PAC_PKGS := gcc make libbpf libelf zlib binutils libcap llvm clang libconfig

# Минимальная версия clang для BPF CO-RE
MIN_CLANG_VER := 10

# Артефакты тестов
TEST_EF_SRC    := tests/test_event_file.c
TEST_EF_BIN    := $(BUILDDIR)/test_event_file

.PHONY: help all clean vmlinux bpf binary deps deps-apt deps-yum deps-pacman bpftool check-clang test test-unit test-http test-clickhouse test-net test-identity compat stress-http stress-soak stress-pid stress-ringbuf stress

help:
	@echo "process_metrics — событийный BPF-коллектор метрик процессов"
	@echo ""
	@echo "  make deps       установить зависимости сборки (автоопределение pacman/apt/yum)"
	@echo "  make all        полная сборка: vmlinux + bpftool + bpf + бинарник"
	@echo "  make vmlinux    пересоздать vmlinux.h из BTF текущего ядра"
	@echo "  make bpftool    собрать bpftool из вендорных исходников"
	@echo "  make bpf        скомпилировать BPF-объект + сгенерировать скелетон"
	@echo "  make binary     скомпилировать userspace-бинарник"
	@echo "  make clean      удалить артефакты сборки"
	@echo "  make test       запустить юнит-тесты"
	@echo "  make compat     проверить совместимость BPF с разными ядрами"
	@echo ""
	@echo "Обнаруженный clang: $(or $(CLANG),НЕ НАЙДЕН — установите clang >= $(MIN_CLANG_VER))"
	@echo "Версия ядра:        $(shell uname -r)"
	@echo ""
	@echo "Быстрый старт:"
	@echo "  make deps && make all"

# --- основные цели ---

all: check-clang vmlinux bpftool bpf binary
	@echo ""
	@echo "Сборка завершена: $(BINARY)"
	@echo "  ядро: $(shell uname -r)"
	@file $(BINARY) | sed 's/^/  /'

# --- проверка версии clang ---

check-clang:
	@if [ -z "$(CLANG)" ]; then \
		echo "Ошибка: не найден clang >= $(MIN_CLANG_VER)."; \
		echo "Установите: pacman -S clang  ИЛИ  apt install clang-11  ИЛИ  yum install clang"; \
		echo "Или укажите: make all CLANG=/path/to/clang-11"; \
		exit 1; \
	fi; \
	ver=$$($(CLANG) --version 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1); \
	if [ -z "$$ver" ] || [ "$$ver" -lt $(MIN_CLANG_VER) ]; then \
		echo "Ошибка: $(CLANG) версия $$ver < $(MIN_CLANG_VER) (нужен >= $(MIN_CLANG_VER) для BPF CO-RE)"; \
		echo "Установите clang >= $(MIN_CLANG_VER) или укажите: make all CLANG=clang-11"; \
		exit 1; \
	fi; \
	echo "Используется $(CLANG) (версия $$ver), ядро $(shell uname -r)"

# --- установка зависимостей ---

deps:
	@if command -v pacman >/dev/null 2>&1; then \
		$(MAKE) deps-pacman; \
	elif command -v apt-get >/dev/null 2>&1; then \
		$(MAKE) deps-apt; \
	elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then \
		$(MAKE) deps-yum; \
	else \
		echo "Ошибка: не найден ни pacman, ни apt-get, ни yum/dnf"; exit 1; \
	fi

deps-apt:
	apt-get update
	apt-get install -y $(APT_PKGS)
	@# заголовки ядра — опционально, могут отсутствовать в контейнерах
	apt-get install -y linux-headers-$(shell uname -r) 2>/dev/null || \
		echo "Примечание: linux-headers не найдены (ОК для контейнеров, нужны только для пересоздания vmlinux.h)"
	@# Установка clang >= 10: пробуем clang-10..clang-18, затем обычный clang
	@found=0; \
	for pkg in clang-10 clang-11 clang-12 clang-13 clang-14 clang-15 clang-16 clang-17 clang-18 clang; do \
		if apt-cache show $$pkg >/dev/null 2>&1; then \
			echo "Устанавливается $$pkg..."; \
			apt-get install -y $$pkg; \
			found=1; \
			break; \
		fi; \
	done; \
	if [ "$$found" = "0" ]; then \
		echo "Предупреждение: пакет clang не найден в apt-репозиториях"; \
		echo "Установите clang >= $(MIN_CLANG_VER) вручную"; \
	fi

deps-yum:
	yum install -y $(YUM_PKGS) clang
	@# заголовки ядра — опционально, могут отсутствовать в контейнерах
	yum install -y kernel-devel-$(shell uname -r) 2>/dev/null || \
		echo "Примечание: kernel-devel не найден (ОК для контейнеров, нужен только для пересоздания vmlinux.h)"

deps-pacman:
	sudo pacman -Sy --needed --noconfirm $(PAC_PKGS)
	@# заголовки ядра — опционально
	sudo pacman -S --needed --noconfirm linux-headers 2>/dev/null || \
		echo "Примечание: linux-headers не найдены (ОК для контейнеров, нужны только для пересоздания vmlinux.h)"

# --- vmlinux.h из BTF текущего ядра ---

vmlinux: $(BPFTOOL_BIN)
	chmod ugo+x $(BPFTOOL)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "vmlinux.h пересоздан из $(shell uname -r)"

# --- bpftool из вендорных исходников ---

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

# --- компиляция BPF ---

bpf: $(SKEL_H)

$(BPF_OBJ): $(BPF_SRC) $(COMMON_H) $(VMLINUX_H) | $(BUILDDIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_H): $(BPF_OBJ) $(BPFTOOL_BIN)
	chmod ugo+x $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

# --- userspace-бинарник ---

binary: $(BINARY)

$(BINARY): $(USER_SRCS) $(COMMON_H) $(EF_H) $(HS_H) $(CSV_H) $(SKEL_H)
	$(CC) $(CFLAGS) -o $@ $(USER_SRCS) $(LDFLAGS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(BINARY) $(BPFTOOL_BIN) $(TEST_EF_BIN)
	rm -rf $(BUILDDIR)/bpftool-build

# --- тесты ---

$(TEST_EF_BIN): $(TEST_EF_SRC) $(SRCDIR)/event_file.c $(EF_H) $(COMMON_H) | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $(TEST_EF_SRC) $(SRCDIR)/event_file.c -lpthread

test-unit: $(TEST_EF_BIN)
	$(TEST_EF_BIN)

test-http: $(BINARY)
	tests/test_http_server.sh

test-clickhouse: $(BINARY)
	tests/test_clickhouse_integration.sh

test-net: $(BINARY)
	sudo bash tests/test_net_metrics.sh

test-identity: $(BINARY)
	sudo bash tests/test_identity_all.sh

test: test-unit

# --- стресс-тесты ---
# Требуют запущенный process_metrics:
#   sudo ./build/process_metrics -c tests/stress_test.conf

stress-http:
	bash tests/stress_http.sh

stress-soak:
	bash tests/stress_soak.sh

stress-pid:
	bash tests/stress_pid_recycle.sh

stress-ringbuf:
	bash tests/stress_ringbuf.sh

stress: stress-http stress-pid stress-ringbuf

# --- проверка совместимости с ядрами ---

compat: $(BPFTOOL_BIN)
	tests/compat_kernels.sh
