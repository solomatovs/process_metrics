#!/bin/bash
# tests/compat_kernels.sh — проверка совместимости BPF-кода с разными ядрами
#
# Список ядер определяется папками в tests/vmlinux_cache/:
#   tests/vmlinux_cache/5.14/vmlinux.h
#   tests/vmlinux_cache/6.1/vmlinux.h
#   ...
#
# Использование:
#   ./tests/compat_kernels.sh              — проверить все ядра из vmlinux_cache/
#   ./tests/compat_kernels.sh 5.14 6.1     — проверить конкретные версии
#   ./tests/compat_kernels.sh --list       — показать доступные ядра
#   ./tests/compat_kernels.sh --fetch 5.15 — скачать vmlinux.h для нового ядра
#
# Добавление нового ядра:
#   1. Добавить источник в FETCH_SOURCES ниже
#   2. ./tests/compat_kernels.sh --fetch <версия>
#   3. git add tests/vmlinux_cache/<версия>/vmlinux.h
#
# Требования: clang >= 10, bpftool (из build/)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CACHE_DIR="$SCRIPT_DIR/vmlinux_cache"
BPFTOOL="$PROJECT_DIR/build/bpftool"
BPF_SRC="$PROJECT_DIR/src/process_metrics.bpf.c"
COMMON_H="$PROJECT_DIR/src/process_metrics_common.h"

# ──────────────────────────────────────────────────────────────────────
# Источники для скачивания vmlinux.h (--fetch)
#
# Формат: FETCH_SOURCES["версия"]="тип|url"
#   rpm   — debuginfo RPM (CentOS/RHEL/Fedora), извлекаем vmlinux → BTF → vmlinux.h
#   btf   — готовый .btf или .btf.tar.xz файл
#   local — /sys/kernel/btf/vmlinux текущего хоста
# ──────────────────────────────────────────────────────────────────────
declare -A FETCH_SOURCES

FETCH_SOURCES["5.14"]="rpm|https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/debug/tree/Packages/kernel-debuginfo-5.14.0-687.el9.x86_64.rpm"
FETCH_SOURCES["6.8"]="rpm|https://kojipkgs.fedoraproject.org/packages/kernel/6.8.11/300.fc40/x86_64/kernel-debuginfo-6.8.11-300.fc40.x86_64.rpm"
FETCH_SOURCES["local"]="local|/sys/kernel/btf/vmlinux"

# ──────────────────────────────────────────────────────────────────────
# Цвета
# ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[  OK]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }

# ──────────────────────────────────────────────────────────────────────
# Определение clang (копия логики из Makefile)
# ──────────────────────────────────────────────────────────────────────
find_clang() {
    local best="" best_ver=0
    for c in clang clang-{10..20}; do
        command -v "$c" >/dev/null 2>&1 || continue
        local ver
        ver=$("$c" --version 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1)
        if [[ -n "$ver" && "$ver" -ge 10 && "$ver" -gt "$best_ver" ]]; then
            best="$c"
            best_ver="$ver"
        fi
    done
    echo "$best"
}

CLANG="${CLANG:-$(find_clang)}"
if [[ -z "$CLANG" ]]; then
    fail "clang >= 10 не найден"
    exit 1
fi

# ──────────────────────────────────────────────────────────────────────
# Список доступных ядер (по папкам в vmlinux_cache/)
# ──────────────────────────────────────────────────────────────────────
list_cached_kernels() {
    local versions=()
    for dir in "$CACHE_DIR"/*/; do
        [[ -f "$dir/vmlinux.h" ]] || continue
        local ver
        ver=$(basename "$dir")
        versions+=("$ver")
    done
    printf '%s\n' "${versions[@]}" | sort -V
}

# ──────────────────────────────────────────────────────────────────────
# Скачивание vmlinux.h (--fetch)
# ──────────────────────────────────────────────────────────────────────
fetch_vmlinux_h() {
    local version="$1"
    local spec="${FETCH_SOURCES[$version]:-}"
    if [[ -z "$spec" ]]; then
        fail "Ядро '$version' не зарегистрировано в FETCH_SOURCES"
        echo "  Добавьте строку в tests/compat_kernels.sh:"
        echo "  FETCH_SOURCES[\"$version\"]=\"rpm|https://...\""
        return 1
    fi

    if [[ ! -x "$BPFTOOL" ]]; then
        fail "bpftool не найден: $BPFTOOL (make bpftool)"
        return 1
    fi

    local type="${spec%%|*}"
    local url="${spec#*|}"
    local dest_dir="$CACHE_DIR/$version"
    local dest="$dest_dir/vmlinux.h"

    mkdir -p "$dest_dir"

    case "$type" in
        rpm)
            info "Скачивание debuginfo RPM для ядра $version (может занять несколько минут)..."
            local tmpdir
            tmpdir=$(mktemp -d)

            curl -sL "$url" \
                | rpm2cpio - \
                | (cd "$tmpdir" && cpio -idm --quiet "*/vmlinux" 2>/dev/null)

            local vmlinux
            vmlinux=$(find "$tmpdir" -name "vmlinux" -type f | head -1)
            if [[ -z "$vmlinux" ]]; then
                rm -rf "$tmpdir"
                fail "vmlinux не найден в RPM"
                return 1
            fi

            info "Генерация vmlinux.h из BTF..."
            "$BPFTOOL" btf dump file "$vmlinux" format c > "$dest"
            rm -rf "$tmpdir"
            ;;

        btf)
            info "Скачивание BTF для ядра $version..."
            local tmpbtf="$dest_dir/vmlinux.btf"
            if [[ "$url" == *.tar.xz ]]; then
                curl -sL "$url" | tar -xJ -C "$dest_dir"
                local btf_file
                btf_file=$(find "$dest_dir" -name "*.btf" -type f | head -1)
                [[ -n "$btf_file" ]] && mv "$btf_file" "$tmpbtf"
            else
                curl -sL "$url" -o "$tmpbtf"
            fi
            "$BPFTOOL" btf dump file "$tmpbtf" format c > "$dest"
            rm -f "$tmpbtf"
            ;;

        local)
            if [[ ! -f "$url" ]]; then
                fail "$url не найден (BTF не включён в ядре?)"
                return 1
            fi
            info "Генерация vmlinux.h из BTF текущего ядра..."
            "$BPFTOOL" btf dump file "$url" format c > "$dest"
            ;;

        *)
            fail "Неизвестный тип источника: $type"
            return 1
            ;;
    esac

    local lines
    lines=$(wc -l < "$dest")
    ok "vmlinux.h для ядра $version: $lines строк → $dest"
    echo "  Добавьте в git: git add $dest"
}

# ──────────────────────────────────────────────────────────────────────
# Компиляция BPF-объекта с указанным vmlinux.h
# ──────────────────────────────────────────────────────────────────────
compile_bpf_with() {
    local version="$1"
    local vmlinux_h="$CACHE_DIR/$version/vmlinux.h"

    if [[ ! -f "$vmlinux_h" ]]; then
        fail "vmlinux.h для ядра $version не найден: $vmlinux_h"
        echo "  Скачайте: $0 --fetch $version"
        return 1
    fi

    # Извлекаем major.minor из имени версии
    local kern_major kern_minor
    kern_major=$(echo "$version" | cut -d. -f1)
    kern_minor=$(echo "$version" | cut -d. -f2)

    local tmpdir
    tmpdir=$(mktemp -d)

    # Копируем vmlinux.h и common.h во временную директорию
    cp "$vmlinux_h" "$tmpdir/vmlinux.h"
    cp "$COMMON_H" "$tmpdir/"

    # Компиляция BPF с подменённым vmlinux.h
    local output
    if output=$("$CLANG" -O2 -g -target bpf \
        -I"$tmpdir" -I"$PROJECT_DIR/src" \
        -D__TARGET_ARCH_x86 \
        -DKERN_VER_MAJOR="$kern_major" -DKERN_VER_MINOR="$kern_minor" \
        -c "$BPF_SRC" -o "$tmpdir/test.bpf.o" 2>&1); then
        rm -rf "$tmpdir"
        return 0
    else
        echo "$output"
        rm -rf "$tmpdir"
        return 1
    fi
}

# ──────────────────────────────────────────────────────────────────────
# Команды
# ──────────────────────────────────────────────────────────────────────
cmd_list() {
    echo "Доступные ядра (tests/vmlinux_cache/):"
    echo ""
    while IFS= read -r version; do
        local lines size
        lines=$(wc -l < "$CACHE_DIR/$version/vmlinux.h")
        size=$(du -h "$CACHE_DIR/$version/vmlinux.h" | cut -f1)
        printf "  %-12s  %s  (%s строк)\n" "$version" "$size" "$lines"
    done < <(list_cached_kernels)
    echo ""

    if [[ ${#FETCH_SOURCES[@]} -gt 0 ]]; then
        echo "Доступны для скачивания (--fetch):"
        for v in $(echo "${!FETCH_SOURCES[@]}" | tr ' ' '\n' | sort -V); do
            local cached=" "
            [[ -f "$CACHE_DIR/$v/vmlinux.h" ]] && cached="*"
            printf "  %s %-12s  %s\n" "$cached" "$v" "${FETCH_SOURCES[$v]%%|*}"
        done
        echo "  (* = уже в кеше)"
    fi
}

cmd_check() {
    local versions=("$@")
    local pass=0 total=0 failed_versions=()

    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║     Проверка совместимости BPF с ядрами             ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    info "Компилятор: $CLANG ($($CLANG --version 2>/dev/null | head -1))"
    info "BPF исходник: $BPF_SRC"
    echo ""

    for version in "${versions[@]}"; do
        total=$((total + 1))
        printf "  %-12s  " "$version"

        if compile_bpf_with "$version" > /dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
            pass=$((pass + 1))
        else
            echo -e "${RED}FAIL${NC}"
            failed_versions+=("$version")
            echo ""
            compile_bpf_with "$version" 2>&1 | sed 's/^/    /'
            echo ""
        fi
    done

    echo ""
    echo "────────────────────────────────────────────────────────"
    if [[ $pass -eq $total ]]; then
        ok "Все $total ядер: совместимы"
    else
        fail "$pass/$total ядер совместимы"
        echo "  Несовместимые: ${failed_versions[*]}"
    fi
    echo ""

    [[ $pass -eq $total ]]
}

# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────
case "${1:-}" in
    --list|-l)
        cmd_list
        ;;
    --fetch|-f)
        shift
        for v in "$@"; do
            fetch_vmlinux_h "$v"
        done
        ;;
    --help|-h)
        echo "Проверка совместимости BPF-кода с разными версиями ядра Linux"
        echo ""
        echo "Использование:"
        echo "  $0                    — проверить все ядра из vmlinux_cache/"
        echo "  $0 5.14 6.1           — проверить конкретные версии"
        echo "  $0 --list             — показать доступные ядра"
        echo "  $0 --fetch 5.15       — скачать vmlinux.h для нового ядра"
        echo "  $0 --help             — эта справка"
        echo ""
        echo "Добавление нового ядра:"
        echo "  1. Добавьте источник в FETCH_SOURCES в этом скрипте"
        echo "  2. $0 --fetch <версия>"
        echo "  3. git add tests/vmlinux_cache/<версия>/vmlinux.h"
        ;;
    --*)
        fail "Неизвестная опция: $1"
        exit 1
        ;;
    *)
        if [[ $# -gt 0 ]]; then
            versions=("$@")
        else
            mapfile -t versions < <(list_cached_kernels)
            if [[ ${#versions[@]} -eq 0 ]]; then
                fail "Нет ядер в $CACHE_DIR"
                echo "  Скачайте: $0 --fetch 5.14"
                exit 1
            fi
        fi
        cmd_check "${versions[@]}"
        ;;
esac
