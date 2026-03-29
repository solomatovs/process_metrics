#!/usr/bin/env bash
# stress_net_ringbuf.sh — подбор оптимальных ring buffer'ов
#
# Прогоняет сетевой стресс-тест с разными размерами ring buffer'ов
# и выводит итоговую таблицу: размер → drops/total → % потерь
#
# Запуск: sudo bash tests/stress_net_ringbuf.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/build/process_metrics"
BASE_CONF="${SCRIPT_DIR}/stress_net.conf"
DURATION=15
WORKERS=16
TMPD="/tmp/stress_rb_$$"

log() { echo -e "[$(date +%H:%M:%S)] $*"; }

mkdir -p "$TMPD"

# Размеры для тестирования (net, sec)
# Формат: "net_size sec_size label"
CONFIGS=(
    "4096 4096 4K_4K"
    "16384 16384 16K_16K"
    "65536 32768 64K_32K"
    "131072 65536 128K_64K"
    "262144 131072 256K_128K"
    "524288 262144 512K_256K"
    "1048576 524288 1M_512K"
    "0 0 default_4M_1M"
)

# Генератор нагрузки
run_load() {
    local dur=$1
    for i in $(seq 0 $((WORKERS - 1))); do
        (exec -a "NETSTRESS_tcp_w${i}" python3 -c "
import socket, time
PORT = 20000 + ${i}; end = time.time() + ${dur}
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', PORT)); srv.listen(128); srv.settimeout(0.1)
while time.time() < end:
    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM); cli.settimeout(1.0)
        cli.connect(('127.0.0.1', PORT))
        acc, _ = srv.accept(); cli.sendall(b'X'*1024); cli.close(); acc.close()
    except: pass
srv.close()
") &
    done

    local udp_w=$((WORKERS / 2))
    [ "$udp_w" -lt 1 ] && udp_w=1
    for i in $(seq 0 $((udp_w - 1))); do
        (exec -a "NETSTRESS_udp_w${i}" python3 -c "
import socket, time
PORT = 20500 + ${i}; end = time.time() + ${dur}
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', PORT)); srv.settimeout(0.01)
cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while time.time() < end:
    cli.sendto(b'U'*512, ('127.0.0.1', PORT))
    try: srv.recv(4096)
    except: pass
cli.close(); srv.close()
") &
    done

    (exec -a "NETSTRESS_rst" python3 -c "
import socket, time
end = time.time() + ${dur}
while time.time() < end:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.1)
    try: s.connect(('127.0.0.1', 19999))
    except: pass
    s.close()
") &
}

# Результаты
RESULTS=()

for cfg_line in "${CONFIGS[@]}"; do
    read net_sz sec_sz label <<< "$cfg_line"

    log "═══ Тест: ${label} ═══"

    # Генерируем конфиг
    CONF="${TMPD}/test.conf"
    cp "$BASE_CONF" "$CONF"

    # Убираем существующие ring_buffers
    sed -i '/ring_buffers/,/};/d' "$CONF"

    if [ "$net_sz" -gt 0 ]; then
        # Вставляем ring_buffers перед snapshot_interval
        sed -i "1i ring_buffers = { net = ${net_sz}; sec = ${sec_sz}; };" "$CONF"
    fi

    # Запускаем PM
    LOGFILE="${TMPD}/pm_${label}.log"
    "$BINARY" -c "$CONF" > "$LOGFILE" 2>&1 &
    PM_PID=$!
    sleep 3

    if ! kill -0 "$PM_PID" 2>/dev/null; then
        log "  PM не запустился!"
        RESULTS+=("$label|FAIL|FAIL|FAIL|FAIL")
        continue
    fi

    PM_REAL=$(pgrep -a process_metrics | grep -v sudo | grep "test.conf" | awk '{print $1}' | head -1)
    [ -z "$PM_REAL" ] && PM_REAL=$PM_PID

    # Ждём первый snapshot
    for i in $(seq 1 20); do
        grep -q "snapshot:" "$LOGFILE" 2>/dev/null && break
        sleep 0.5
    done
    curl -s "http://127.0.0.1:19093/metrics?clear=1" > /dev/null

    # Нагрузка
    run_load $DURATION
    sleep $((DURATION + 3))

    # Убиваем нагрузку
    pkill -f "NETSTRESS" 2>/dev/null
    sleep 2

    # Собираем drops
    LAST_DROP=$(grep "ringbuf drops:" "$LOGFILE" | tail -1)
    if [ -n "$LAST_DROP" ]; then
        NET_VALS=$(echo "$LAST_DROP" | grep -oP 'net=\S+' | head -1 | cut -d= -f2)
        SEC_VALS=$(echo "$LAST_DROP" | grep -oP 'sec=\S+' | head -1 | cut -d= -f2)
        NET_DROP=$(echo "$NET_VALS" | cut -d/ -f1)
        NET_TOTAL=$(echo "$NET_VALS" | cut -d/ -f2)
        SEC_DROP=$(echo "$SEC_VALS" | cut -d/ -f1)
        SEC_TOTAL=$(echo "$SEC_VALS" | cut -d/ -f2)
    else
        # Нет drops — берём из DEBUG-строки или ставим 0
        NET_DROP=0; NET_TOTAL="?"; SEC_DROP=0; SEC_TOTAL="?"
        # Попробуем взять total из последних цифр
        LAST_STAT=$(grep "ringbuf" "$LOGFILE" | tail -1)
        if [ -n "$LAST_STAT" ]; then
            NET_TOTAL=$(echo "$LAST_STAT" | grep -oP 'net=\S+' | head -1 | cut -d= -f2 | cut -d/ -f2)
            SEC_TOTAL=$(echo "$LAST_STAT" | grep -oP 'sec=\S+' | head -1 | cut -d= -f2 | cut -d/ -f2)
        fi
    fi

    # RSS
    RSS=$(awk '/^VmRSS/ {print $2}' /proc/$PM_REAL/status 2>/dev/null || echo "?")

    # Форматируем
    if [ "$NET_DROP" = "0" ] && [ "$SEC_DROP" = "0" ]; then
        STATUS="✓ 0 drops"
    else
        NET_PCT="?"
        SEC_PCT="?"
        [ "$NET_TOTAL" != "?" ] && [ "$NET_TOTAL" -gt 0 ] 2>/dev/null && \
            NET_PCT=$(awk "BEGIN {printf \"%.1f\", 100.0 * $NET_DROP / $NET_TOTAL}")
        [ "$SEC_TOTAL" != "?" ] && [ "$SEC_TOTAL" -gt 0 ] 2>/dev/null && \
            SEC_PCT=$(awk "BEGIN {printf \"%.1f\", 100.0 * $SEC_DROP / $SEC_TOTAL}")
        STATUS="net=${NET_PCT}% sec=${SEC_PCT}%"
    fi

    RESULTS+=("${label}|net=${NET_DROP}/${NET_TOTAL}|sec=${SEC_DROP}/${SEC_TOTAL}|RSS=${RSS}kB|${STATUS}")
    log "  ${STATUS}  RSS=${RSS}kB"

    # Убиваем PM
    kill "$PM_PID" 2>/dev/null
    wait "$PM_PID" 2>/dev/null || true
    sleep 1
done

# Итоговая таблица
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  ИТОГОВАЯ ТАБЛИЦА: ring buffer sizing (${DURATION}s, ${WORKERS} TCP + 4 UDP + 1 RST)"
echo "════════════════════════════════════════════════════════════════════"
printf "%-20s %-22s %-22s %-14s %s\n" "Размер" "net drops" "sec drops" "RSS" "Статус"
printf "%-20s %-22s %-22s %-14s %s\n" "----" "---------" "---------" "---" "------"
for r in "${RESULTS[@]}"; do
    IFS='|' read label net sec rss status <<< "$r"
    printf "%-20s %-22s %-22s %-14s %s\n" "$label" "$net" "$sec" "$rss" "$status"
done
echo ""

rm -rf "$TMPD"
