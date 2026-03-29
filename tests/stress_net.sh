#!/usr/bin/env bash
# stress_net.sh — сетевой стресс-тест для проверки ring buffer drops
#
# Генерирует массовый сетевой трафик tracked-процессами:
#   - TCP connect/accept/close шторм
#   - TCP data transfer (большие объёмы)
#   - UDP шторм
#   - Параллельные короткоживущие соединения
#
# Проверяет:
#   - Количество drops по каждому ring buffer
#   - Количество событий net_listen/net_connect/net_accept/net_close
#   - Корректность данных
#
# Запуск: sudo bash tests/stress_net.sh [duration_sec] [workers]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/build/process_metrics"
CONF="${SCRIPT_DIR}/stress_net.conf"
PORT=19093
BASE_URL="http://127.0.0.1:${PORT}"
DURATION=${1:-30}
WORKERS=${2:-8}
TMPD="/tmp/stress_net_$$"
LOGFILE="${TMPD}/pm.log"
TCP_BASE_PORT=20000
UDP_PORT=20500

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "[$(date +%H:%M:%S)] $*"; }
PM_PID=""
PIDS_TO_KILL=()

cleanup() {
    log "cleanup..."
    for p in "${PIDS_TO_KILL[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    if [ -n "$PM_PID" ] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null
        wait "$PM_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    rm -rf "$TMPD" /tmp/stress_net
}
trap cleanup EXIT

mkdir -p "$TMPD" /tmp/stress_net

[ -x "$BINARY" ] || { log "Binary not found: $BINARY"; exit 1; }

if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    log "Port ${PORT} busy"; exit 1
fi

# ═══════════════════════════════════════════════════════════════
#  Запуск process_metrics
# ═══════════════════════════════════════════════════════════════
log "${CYAN}Запуск process_metrics (полный трекинг)...${NC}"
"$BINARY" -c "$CONF" > "$LOGFILE" 2>&1 &
PM_PID=$!
sleep 3

if ! kill -0 "$PM_PID" 2>/dev/null; then
    log "${RED}process_metrics не запустился!${NC}"
    cat "$LOGFILE"
    exit 1
fi
log "PM PID=${PM_PID}"

# Ждём первый snapshot
for i in $(seq 1 30); do
    grep -q "snapshot:" "$LOGFILE" 2>/dev/null && break
    sleep 0.5
done

# Очищаем буфер
curl -s "${BASE_URL}/metrics?clear=1" > /dev/null
log "Буфер очищен"

# ═══════════════════════════════════════════════════════════════
#  Генерация нагрузки
# ═══════════════════════════════════════════════════════════════
log "${CYAN}═══ НАГРУЗКА: ${WORKERS} воркеров × ${DURATION}с ═══${NC}"
log "TCP connect/close шторм + data transfer + UDP шторм"
log ""

# Воркер: массовые TCP connect/send/close
tcp_worker() {
    local id=$1
    local port=$((TCP_BASE_PORT + id))
    exec -a "NETSTRESS_tcp_w${id}" python3 -c "
import socket, time, os

PORT = ${port}
DURATION = ${DURATION}
end = time.time() + DURATION
conns = 0
bytes_sent = 0

# Запускаем listener
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', PORT))
srv.listen(128)
srv.settimeout(0.1)

while time.time() < end:
    # Создаём соединение
    try:
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.settimeout(1.0)
        cli.connect(('127.0.0.1', PORT))

        # Accept
        try:
            acc, _ = srv.accept()
        except socket.timeout:
            cli.close()
            continue

        # Шлём данные
        data = b'X' * 1024
        for _ in range(5):
            cli.sendall(data)
            bytes_sent += 1024

        # Закрываем
        cli.close()
        acc.close()
        conns += 1
    except Exception:
        pass

srv.close()
with open('${TMPD}/tcp_w${id}.stat', 'w') as f:
    f.write(f'{conns} {bytes_sent}')
"
}

# Воркер: массовые UDP send/recv
udp_worker() {
    local id=$1
    exec -a "NETSTRESS_udp_w${id}" python3 -c "
import socket, time

DURATION = ${DURATION}
PORT = ${UDP_PORT} + ${id}
end = time.time() + DURATION
pkts = 0
bs = 0

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', PORT))
srv.settimeout(0.01)

cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while time.time() < end:
    payload = b'U' * 512
    cli.sendto(payload, ('127.0.0.1', PORT))
    pkts += 1
    bs += 512
    try:
        srv.recv(4096)
    except socket.timeout:
        pass

cli.close()
srv.close()
with open('${TMPD}/udp_w${id}.stat', 'w') as f:
    f.write(f'{pkts} {bs}')
"
}

# Воркер: rapid connect к закрытому порту (RST flood)
rst_worker() {
    exec -a "NETSTRESS_rst" python3 -c "
import socket, time

DURATION = ${DURATION}
end = time.time() + DURATION
count = 0

while time.time() < end:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    try:
        s.connect(('127.0.0.1', 19999))
    except:
        pass
    s.close()
    count += 1

with open('${TMPD}/rst.stat', 'w') as f:
    f.write(str(count))
"
}

START_TIME=$(date +%s)
log "Запуск TCP-воркеров..."
for i in $(seq 0 $((WORKERS - 1))); do
    tcp_worker $i &
    PIDS_TO_KILL+=($!)
done

log "Запуск UDP-воркеров..."
UDP_WORKERS=$((WORKERS / 2))
[ "$UDP_WORKERS" -lt 1 ] && UDP_WORKERS=1
for i in $(seq 0 $((UDP_WORKERS - 1))); do
    udp_worker $i &
    PIDS_TO_KILL+=($!)
done

log "Запуск RST-воркера..."
rst_worker &
PIDS_TO_KILL+=($!)

log "Ожидание завершения (${DURATION}с)..."

# Периодический отчёт
ELAPSED=0
while [ $ELAPSED -lt $DURATION ]; do
    sleep 5
    ELAPSED=$(( $(date +%s) - START_TIME ))
    # Проверяем drops в логе
    DROPS=$(grep -c "ringbuf drops:" "$LOGFILE" 2>/dev/null || echo 0)
    ALIVE=$(ps -o pid= -p "$(echo "${PIDS_TO_KILL[@]}" | tr ' ' ',')" 2>/dev/null | wc -l || echo 0)
    log "  ${ELAPSED}/${DURATION}с  воркеров=${ALIVE}  drop_warnings=${DROPS}"
done

# Ждём завершения воркеров
for p in "${PIDS_TO_KILL[@]}"; do
    wait "$p" 2>/dev/null || true
done
PIDS_TO_KILL=()
sleep 2

# ═══════════════════════════════════════════════════════════════
#  Сбор и анализ результатов
# ═══════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ РЕЗУЛЬТАТЫ ═══${NC}"

# Статистика воркеров
TOTAL_CONNS=0
TOTAL_TCP_BYTES=0
for f in "${TMPD}"/tcp_w*.stat; do
    [ -f "$f" ] || continue
    read conns bs < "$f"
    TOTAL_CONNS=$((TOTAL_CONNS + conns))
    TOTAL_TCP_BYTES=$((TOTAL_TCP_BYTES + bs))
done

TOTAL_UDP_PKTS=0
TOTAL_UDP_BYTES=0
for f in "${TMPD}"/udp_w*.stat; do
    [ -f "$f" ] || continue
    read pkts bs < "$f"
    TOTAL_UDP_PKTS=$((TOTAL_UDP_PKTS + pkts))
    TOTAL_UDP_BYTES=$((TOTAL_UDP_BYTES + bs))
done

RST_COUNT=0
[ -f "${TMPD}/rst.stat" ] && RST_COUNT=$(cat "${TMPD}/rst.stat")

log "Генерировано:"
log "  TCP: ${TOTAL_CONNS} соединений, $((TOTAL_TCP_BYTES / 1024 / 1024)) МБ"
log "  UDP: ${TOTAL_UDP_PKTS} пакетов, $((TOTAL_UDP_BYTES / 1024 / 1024)) МБ"
log "  RST: ${RST_COUNT} попыток"
log ""

# Забираем CSV
curl -s "${BASE_URL}/metrics?clear=1" > "${TMPD}/final.csv"
CSV_LINES=$(($(wc -l < "${TMPD}/final.csv") - 1))
log "CSV: ${CSV_LINES} событий"

# Подсчёт по event_type
log ""
log "Распределение событий:"
tail -n +2 "${TMPD}/final.csv" | awk -F',' '{print $3}' | sort | uniq -c | sort -rn | while read cnt evt; do
    printf "  %-20s %s\n" "$evt" "$cnt"
done

# Ring buffer drops из логов
log ""
log "${CYAN}── Ring buffer drops ──${NC}"
DROP_LINES=$(grep "ringbuf drops:" "$LOGFILE" 2>/dev/null || true)
if [ -n "$DROP_LINES" ]; then
    log "${YELLOW}DROPS DETECTED:${NC}"
    echo "$DROP_LINES" | tail -5 | while IFS= read -r line; do
        log "  ${YELLOW}${line}${NC}"
    done
    # Парсим последнюю строку drops
    LAST_DROP=$(echo "$DROP_LINES" | tail -1)
    log ""
    log "Последние значения:"
    echo "$LAST_DROP" | grep -oP 'proc=\S+|file=\S+|net=\S+|sec=\S+|cgroup=\S+|missed_exec_overflow=\S+' | while read kv; do
        KEY=$(echo "$kv" | cut -d= -f1)
        VALS=$(echo "$kv" | cut -d= -f2)
        DROP=$(echo "$VALS" | cut -d/ -f1)
        TOTAL=$(echo "$VALS" | cut -d/ -f2)
        if [ "$DROP" -gt 0 ] 2>/dev/null; then
            PCT=$(awk "BEGIN {printf \"%.2f\", 100.0 * $DROP / ($TOTAL + 0.001)}")
            log "  ${RED}${KEY}: ${DROP}/${TOTAL} (${PCT}% lost)${NC}"
        else
            log "  ${GREEN}${KEY}: ${DROP}/${TOTAL} (0% lost)${NC}"
        fi
    done
else
    log "${GREEN}НЕТ DROPS — все ring buffer'ы справились!${NC}"
fi

# Финальная статистика из лога (последний snapshot)
log ""
log "${CYAN}── Последний snapshot ──${NC}"
grep "snapshot:" "$LOGFILE" | tail -1 | while IFS= read -r line; do
    log "  $line"
done

# RSS процесса
RSS=$(awk '/^VmRSS/ {print $2}' /proc/$PM_PID/status 2>/dev/null || echo "?")
FDS=$(ls /proc/$PM_PID/fd 2>/dev/null | wc -w || echo "?")
log ""
log "PM RSS: ${RSS} kB, FDs: ${FDS}"

log ""
if [ -n "$DROP_LINES" ]; then
    log "${YELLOW}РЕЗУЛЬТАТ: БЫЛИ DROPS — ring buffer'ы перегружены${NC}"
else
    log "${GREEN}РЕЗУЛЬТАТ: 0 DROPS — всё чисто${NC}"
fi
