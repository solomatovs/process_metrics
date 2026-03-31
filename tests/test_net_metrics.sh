#!/usr/bin/env bash
# test_net_metrics.sh — интеграционные тесты корректности ВСЕХ net-показателей
#
# Тесты:
#   1. snapshot: net_tx_bytes / net_rx_bytes > 0 после TCP-трафика
#   2. snapshot: net_tx_bytes / net_rx_bytes > 0 после UDP-трафика
#   3. snapshot: net_tx_bytes растёт между циклами (кумулятивность)
#   4. conn_snapshot: net_conn_tx_bytes / net_conn_rx_bytes > 0
#   5. conn_snapshot: net_conn_tx_calls / net_conn_rx_calls > 0
#   6. conn_snapshot: net_local_addr / net_remote_addr заполнены
#   7. conn_snapshot: net_local_port / net_remote_port корректны
#   8. conn_snapshot: net_duration_ms > 0
#   9. conn_snapshot: state = L для listener, E для established
#  10. conn_snapshot: open_tcp_conns корректен в snapshot
#  11. net_close: все поля заполнены (tx/rx bytes, calls, duration, addr, port)
#  12. net_close: state = I (initiator) или R (responder)
#  13. net_close: net_conn_tx_bytes совпадает с отправленным объёмом
#  14. net_connect / net_accept / net_listen — события генерируются
#  15. UDP: net_tx_bytes / net_rx_bytes в snapshot включают UDP-трафик
#
# Запуск: sudo bash tests/test_net_metrics.sh
#
# Требования:
#   - Собранный бинарник в build/process_metrics
#   - python3

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/build/process_metrics"
CONF="${SCRIPT_DIR}/test_net_metrics.conf"
PORT=19094
BASE_URL="http://127.0.0.1:${PORT}"
SNAP_INTERVAL=5
TMPD="/tmp/test_net_metrics_$$"
LOGFILE="${TMPD}/pm.log"

# Порты для тестов
PORT_TCP=19301
PORT_UDP=19302
PORT_CLOSE=19303

PASS=0
FAIL=0
WARN=0
REPORT=""
PM_PID=""
PIDS_TO_KILL=()

# ── Цвета ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "[$(date +%H:%M:%S)] $*"; }
pass() { ((PASS++)); REPORT+="  ${GREEN}✓${NC} $1\n"; log "${GREEN}PASS${NC}: $1"; }
fail() { ((FAIL++)); REPORT+="  ${RED}✗${NC} $1\n"; log "${RED}FAIL${NC}: $1"; }
warn() { ((WARN++)); REPORT+="  ${YELLOW}⚠${NC} $1\n"; log "${YELLOW}WARN${NC}: $1"; }

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
    if [ "$FAIL" -eq 0 ]; then
        rm -rf "$TMPD"
    else
        log "Логи сохранены в ${TMPD}"
    fi
}
trap cleanup EXIT

mkdir -p "$TMPD"

# ── Проверка зависимостей ─────────────────────────────────────────
if [ ! -x "$BINARY" ]; then
    log "Бинарник не найден: $BINARY"
    log "Запустите: make all"
    exit 1
fi

if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    log "Порт ${PORT} уже занят"
    exit 1
fi

# ── Запуск process_metrics ────────────────────────────────────────
log "запуск process_metrics..."
"$BINARY" -c "$CONF" > "$LOGFILE" 2>&1 &
PM_PID=$!
sleep 3

if ! kill -0 "$PM_PID" 2>/dev/null; then
    log "process_metrics не запустился!"
    cat "$LOGFILE"
    exit 1
fi
log "process_metrics PID=${PM_PID}"

# Ждём первый snapshot
for i in $(seq 1 30); do
    if grep -q "snapshot:" "$LOGFILE" 2>/dev/null; then break; fi
    sleep 0.5
done

# Очистка буфера
curl -s "${BASE_URL}/metrics?clear=1" > /dev/null
log "буфер очищен"

# ── Вспомогательные функции ───────────────────────────────────────

wait_snapshot() {
    local snap_before
    snap_before=$(grep -c "snapshot:" "$LOGFILE" 2>/dev/null || echo 0)
    for i in $(seq 1 $((SNAP_INTERVAL * 4))); do
        local snap_now
        snap_now=$(grep -c "snapshot:" "$LOGFILE" 2>/dev/null || echo 0)
        if [ "$snap_now" -gt "$snap_before" ]; then
            sleep 0.5
            return 0
        fi
        sleep 0.5
    done
    log "timeout: snapshot не произошёл"
    return 1
}

fetch_csv() {
    local outfile=$1
    curl -s "${BASE_URL}/metrics?clear=1" > "$outfile"
}

HEADER=""
col_num() {
    echo "$HEADER" | tr ',' '\n' | grep -n "^${1}$" | cut -d: -f1
}

# Python CSV-парсер для надёжного извлечения полей
# $1 = csv-файл, $2 = event_type, $3 = field_name, $4 = filter (опционально, exec или port)
csv_field() {
    python3 -c "
import csv, sys
fname = sys.argv[1]
evt_type = sys.argv[2]
field = sys.argv[3]
filt = sys.argv[4] if len(sys.argv) > 4 else ''
with open(fname, encoding='utf-8', errors='replace') as f:
    for row in csv.DictReader(f):
        if row.get('event_type') != evt_type:
            continue
        if filt and filt not in row.get('exec','') and filt not in str(row.get('net_local_port','')) and filt not in str(row.get('net_remote_port','')):
            continue
        # Для conn_snapshot пропускаем listener — нужны established
        if evt_type == 'conn_snapshot' and row.get('state') == 'L':
            continue
        print(row.get(field, ''))
" "$@" 2>/dev/null | head -1
}

# Все значения конкретного поля для event_type
csv_field_all() {
    python3 -c "
import csv, sys
fname = sys.argv[1]
evt_type = sys.argv[2]
field = sys.argv[3]
filt = sys.argv[4] if len(sys.argv) > 4 else ''
with open(fname, encoding='utf-8', errors='replace') as f:
    for row in csv.DictReader(f):
        if row.get('event_type') != evt_type:
            continue
        if filt and filt not in row.get('exec','') and filt not in str(row.get('net_local_port','')) and filt not in str(row.get('net_remote_port','')):
            continue
        print(row.get(field, ''))
" "$@" 2>/dev/null
}

# Подсчёт событий
csv_count() {
    python3 -c "
import csv, sys
fname = sys.argv[1]
evt_type = sys.argv[2]
filt = sys.argv[3] if len(sys.argv) > 3 else ''
count = 0
with open(fname, encoding='utf-8', errors='replace') as f:
    for row in csv.DictReader(f):
        if row.get('event_type') != evt_type:
            continue
        if filt and filt not in row.get('exec','') and filt not in str(row.get('net_local_port','')) and filt not in str(row.get('net_remote_port','')):
            continue
        count += 1
print(count)
" "$@" 2>/dev/null
}

# ══════════════════════════════════════════════════════════════════
#  ФАЗА 1: TCP echo-сервер + клиент — генерация трафика
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ФАЗА 1: TCP-трафик (echo сервер/клиент) ═══${NC}"

TCP_SEND_BYTES=5000
TCP_WAVES=2

(exec -a "NETTEST_tcp_echo" python3 -c "
import socket, time, threading, os, signal, sys

PORT = ${PORT_TCP}
TMPD = '${TMPD}'

stop = threading.Event()

def echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', PORT))
    srv.listen(1)
    srv.settimeout(1.0)
    with open(os.path.join(TMPD, 'tcp_ready'), 'w') as f:
        f.write(str(os.getpid()))

    while not stop.is_set():
        try:
            conn, addr = srv.accept()
            conn.settimeout(0.5)
            while not stop.is_set():
                try:
                    data = conn.recv(8192)
                    if not data:
                        break
                    conn.sendall(data)
                except socket.timeout:
                    continue
                except Exception:
                    break
            conn.close()
        except socket.timeout:
            continue
    srv.close()

t = threading.Thread(target=echo_server, daemon=True)
t.start()

# Ждём готовности
for _ in range(50):
    if os.path.exists(os.path.join(TMPD, 'tcp_ready')):
        break
    time.sleep(0.1)

# Клиент: волна 1
cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', PORT))
cli.sendall(b'A' * ${TCP_SEND_BYTES})
time.sleep(0.5)
cli.settimeout(2.0)
try:
    d = cli.recv(65536)
except:
    d = b''
with open(os.path.join(TMPD, 'tcp_wave1'), 'w') as f:
    f.write(f'sent=${TCP_SEND_BYTES},recv={len(d)}')

# Ожидание SIGUSR1 для волны 2
def wave2(signum, frame):
    cli.sendall(b'B' * ${TCP_SEND_BYTES})
    time.sleep(0.5)
    try:
        cli.settimeout(2.0)
        d2 = cli.recv(65536)
    except:
        d2 = b''
    with open(os.path.join(TMPD, 'tcp_wave2'), 'w') as f:
        f.write(f'sent=${TCP_SEND_BYTES},recv={len(d2)}')

# Ожидание SIGUSR2 для закрытия
def do_close(signum, frame):
    cli.close()
    stop.set()
    with open(os.path.join(TMPD, 'tcp_closed'), 'w') as f:
        f.write('ok')

signal.signal(signal.SIGUSR1, wave2)
signal.signal(signal.SIGUSR2, do_close)
time.sleep(120)
") &
TCP_PID=$!
PIDS_TO_KILL+=($TCP_PID)

# Ждём готовности
for i in $(seq 1 30); do
    [ -f "${TMPD}/tcp_wave1" ] && break
    sleep 0.2
done

if [ -f "${TMPD}/tcp_wave1" ]; then
    log "TCP волна 1: $(cat ${TMPD}/tcp_wave1)"
else
    log "ОШИБКА: TCP-процесс не стартовал"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════
#  ФАЗА 2: UDP-трафик
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ФАЗА 2: UDP-трафик ═══${NC}"

UDP_SEND_BYTES=400
UDP_PACKETS=10

(exec -a "NETTEST_udp_pair" python3 -c "
import socket, time, os

PORT = ${PORT_UDP}
TMPD = '${TMPD}'

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', PORT))
srv.settimeout(0.5)

cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

total_sent = 0
total_recv = 0
for i in range(${UDP_PACKETS}):
    payload = b'U' * ${UDP_SEND_BYTES}
    cli.sendto(payload, ('127.0.0.1', PORT))
    total_sent += len(payload)
    try:
        data, addr = srv.recvfrom(4096)
        total_recv += len(data)
        srv.sendto(b'P' * 100, addr)
    except socket.timeout:
        pass
    time.sleep(0.05)

with open(os.path.join(TMPD, 'udp_done'), 'w') as f:
    f.write(f'sent={total_sent},recv={total_recv}')

time.sleep(60)
cli.close()
srv.close()
") &
UDP_PID=$!
PIDS_TO_KILL+=($UDP_PID)

for i in $(seq 1 30); do
    [ -f "${TMPD}/udp_done" ] && break
    sleep 0.2
done
log "UDP: $(cat ${TMPD}/udp_done 2>/dev/null || echo N/A)"

# ══════════════════════════════════════════════════════════════════
#  Snapshot 1
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ Ожидание snapshot 1 ═══${NC}"
wait_snapshot
fetch_csv "${TMPD}/snap1.csv"
SNAP1_LINES=$(($(wc -l < "${TMPD}/snap1.csv") - 1))
log "Snapshot 1: ${SNAP1_LINES} событий"

# Определяем заголовок
HEADER=$(head -1 "${TMPD}/snap1.csv")

# ══════════════════════════════════════════════════════════════════
#  Волна 2 TCP
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ TCP волна 2 ═══${NC}"
kill -USR1 "$TCP_PID" 2>/dev/null
for i in $(seq 1 30); do
    [ -f "${TMPD}/tcp_wave2" ] && break
    sleep 0.2
done
log "TCP волна 2: $(cat ${TMPD}/tcp_wave2 2>/dev/null || echo N/A)"

# Snapshot 2
log "ожидание snapshot 2..."
wait_snapshot
fetch_csv "${TMPD}/snap2.csv"
SNAP2_LINES=$(($(wc -l < "${TMPD}/snap2.csv") - 1))
log "Snapshot 2: ${SNAP2_LINES} событий"

# ══════════════════════════════════════════════════════════════════
#  Закрытие TCP-соединения (для net_close)
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ Закрытие TCP-соединения ═══${NC}"
kill -USR2 "$TCP_PID" 2>/dev/null
for i in $(seq 1 30); do
    [ -f "${TMPD}/tcp_closed" ] && break
    sleep 0.2
done
log "TCP закрыт"

# Snapshot 3 (содержит net_close)
log "ожидание snapshot 3..."
wait_snapshot
fetch_csv "${TMPD}/snap3.csv"
SNAP3_LINES=$(($(wc -l < "${TMPD}/snap3.csv") - 1))
log "Snapshot 3: ${SNAP3_LINES} событий"

# ══════════════════════════════════════════════════════════════════
#  АНАЛИЗ РЕЗУЛЬТАТОВ
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  АНАЛИЗ NET-МЕТРИК"
log "${CYAN}════════════════════════════════════════════════════${NC}"

# ── ТЕСТ 1: snapshot net_tx_bytes > 0 (TCP) ──
log ""
log "${CYAN}═══ ТЕСТ 1: snapshot net_tx_bytes > 0 (TCP) ═══${NC}"
SNAP_TX=$(csv_field "${TMPD}/snap1.csv" "snapshot" "net_tx_bytes" "NETTEST_tcp")
if [ -n "$SNAP_TX" ] && [ "$SNAP_TX" -gt 0 ] 2>/dev/null; then
    pass "snapshot net_tx_bytes=${SNAP_TX} > 0 (TCP)"
else
    fail "snapshot net_tx_bytes=${SNAP_TX:-пусто} (ожидалось > 0)"
fi

# ── ТЕСТ 2: snapshot net_rx_bytes > 0 (TCP echo) ──
log ""
log "${CYAN}═══ ТЕСТ 2: snapshot net_rx_bytes > 0 (TCP echo) ═══${NC}"
SNAP_RX=$(csv_field "${TMPD}/snap1.csv" "snapshot" "net_rx_bytes" "NETTEST_tcp")
if [ -n "$SNAP_RX" ] && [ "$SNAP_RX" -gt 0 ] 2>/dev/null; then
    pass "snapshot net_rx_bytes=${SNAP_RX} > 0 (TCP echo)"
else
    warn "snapshot net_rx_bytes=${SNAP_RX:-пусто} (echo мог не дойти)"
fi

# ── ТЕСТ 3: snapshot net_tx_bytes кумулятивен (растёт между snapshot) ──
log ""
log "${CYAN}═══ ТЕСТ 3: net_tx_bytes кумулятивен ═══${NC}"
SNAP_TX2=$(csv_field "${TMPD}/snap2.csv" "snapshot" "net_tx_bytes" "NETTEST_tcp")
if [ -n "$SNAP_TX" ] && [ -n "$SNAP_TX2" ] && [ "$SNAP_TX2" -gt "$SNAP_TX" ] 2>/dev/null; then
    pass "net_tx_bytes растёт: ${SNAP_TX} → ${SNAP_TX2}"
else
    if [ -n "$SNAP_TX" ] && [ -n "$SNAP_TX2" ]; then
        fail "net_tx_bytes НЕ вырос: ${SNAP_TX} → ${SNAP_TX2}"
    else
        fail "net_tx_bytes недоступен: snap1=${SNAP_TX:-N/A} snap2=${SNAP_TX2:-N/A}"
    fi
fi

# ── ТЕСТ 4: conn_snapshot — net_conn_tx_bytes > 0 ──
log ""
log "${CYAN}═══ ТЕСТ 4: conn_snapshot net_conn_tx_bytes > 0 ═══${NC}"
CS_TX=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_conn_tx_bytes" "${PORT_TCP}")
if [ -n "$CS_TX" ] && [ "$CS_TX" -gt 0 ] 2>/dev/null; then
    pass "conn_snapshot net_conn_tx_bytes=${CS_TX} > 0"
else
    fail "conn_snapshot net_conn_tx_bytes=${CS_TX:-пусто} (ожидалось > 0)"
fi

# ── ТЕСТ 5: conn_snapshot — net_conn_rx_bytes > 0 ──
log ""
log "${CYAN}═══ ТЕСТ 5: conn_snapshot net_conn_rx_bytes > 0 ═══${NC}"
CS_RX=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_conn_rx_bytes" "${PORT_TCP}")
if [ -n "$CS_RX" ] && [ "$CS_RX" -gt 0 ] 2>/dev/null; then
    pass "conn_snapshot net_conn_rx_bytes=${CS_RX} > 0"
else
    warn "conn_snapshot net_conn_rx_bytes=${CS_RX:-пусто} (echo мог не дойти)"
fi

# ── ТЕСТ 6: conn_snapshot — net_conn_tx_calls > 0 ──
log ""
log "${CYAN}═══ ТЕСТ 6: conn_snapshot net_conn_tx_calls > 0 ═══${NC}"
CS_TX_CALLS=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_conn_tx_calls" "${PORT_TCP}")
if [ -n "$CS_TX_CALLS" ] && [ "$CS_TX_CALLS" -gt 0 ] 2>/dev/null; then
    pass "conn_snapshot net_conn_tx_calls=${CS_TX_CALLS} > 0"
else
    fail "conn_snapshot net_conn_tx_calls=${CS_TX_CALLS:-пусто} (ожидалось > 0)"
fi

# ── ТЕСТ 7: conn_snapshot — net_conn_rx_calls > 0 ──
log ""
log "${CYAN}═══ ТЕСТ 7: conn_snapshot net_conn_rx_calls > 0 ═══${NC}"
CS_RX_CALLS=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_conn_rx_calls" "${PORT_TCP}")
if [ -n "$CS_RX_CALLS" ] && [ "$CS_RX_CALLS" -gt 0 ] 2>/dev/null; then
    pass "conn_snapshot net_conn_rx_calls=${CS_RX_CALLS} > 0"
else
    warn "conn_snapshot net_conn_rx_calls=${CS_RX_CALLS:-пусто}"
fi

# ── ТЕСТ 8: conn_snapshot — net_local_addr заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 8: conn_snapshot net_local_addr ═══${NC}"
CS_LADDR=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_local_addr" "${PORT_TCP}")
if [ -n "$CS_LADDR" ] && [ "$CS_LADDR" != "0" ] && [ "$CS_LADDR" != "0.0.0.0" ]; then
    pass "conn_snapshot net_local_addr=${CS_LADDR}"
else
    fail "conn_snapshot net_local_addr=${CS_LADDR:-пусто} (ожидался IP)"
fi

# ── ТЕСТ 9: conn_snapshot — net_remote_addr заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 9: conn_snapshot net_remote_addr ═══${NC}"
CS_RADDR=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_remote_addr" "${PORT_TCP}")
if [ -n "$CS_RADDR" ] && [ "$CS_RADDR" != "0" ] && [ "$CS_RADDR" != "0.0.0.0" ]; then
    pass "conn_snapshot net_remote_addr=${CS_RADDR}"
else
    # listener может иметь 0.0.0.0 для remote
    warn "conn_snapshot net_remote_addr=${CS_RADDR:-пусто}"
fi

# ── ТЕСТ 10: conn_snapshot — net_local_port корректен ──
log ""
log "${CYAN}═══ ТЕСТ 10: conn_snapshot net_local_port ═══${NC}"
CS_LPORT=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_local_port" "${PORT_TCP}")
CS_RPORT=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "net_remote_port" "${PORT_TCP}")
if [ "$CS_LPORT" = "${PORT_TCP}" ] || [ "$CS_RPORT" = "${PORT_TCP}" ]; then
    pass "conn_snapshot порт ${PORT_TCP} найден (lport=${CS_LPORT}, rport=${CS_RPORT})"
else
    fail "conn_snapshot порт ${PORT_TCP} не найден (lport=${CS_LPORT:-?}, rport=${CS_RPORT:-?})"
fi

# ── ТЕСТ 11: conn_snapshot — net_duration_ms > 0 ──
log ""
log "${CYAN}═══ ТЕСТ 11: conn_snapshot net_duration_ms > 0 ═══${NC}"
CS_DUR=$(csv_field "${TMPD}/snap2.csv" "conn_snapshot" "net_duration_ms" "${PORT_TCP}")
if [ -n "$CS_DUR" ] && [ "$CS_DUR" -gt 0 ] 2>/dev/null; then
    pass "conn_snapshot net_duration_ms=${CS_DUR} > 0"
else
    fail "conn_snapshot net_duration_ms=${CS_DUR:-пусто} (ожидалось > 0)"
fi

# ── ТЕСТ 12: conn_snapshot — state: L (listener) и E (established) ──
log ""
log "${CYAN}═══ ТЕСТ 12: conn_snapshot state (L/E) ═══${NC}"
CS_STATES=$(csv_field_all "${TMPD}/snap1.csv" "conn_snapshot" "state" "${PORT_TCP}" | sort -u | tr '\n' ',')
HAS_L=0; HAS_E=0
echo "$CS_STATES" | grep -q "L" && HAS_L=1
echo "$CS_STATES" | grep -q "E" && HAS_E=1

if [ "$HAS_E" -eq 1 ]; then
    pass "conn_snapshot: state=E (established) присутствует"
else
    fail "conn_snapshot: state=E (established) не найден (states: ${CS_STATES})"
fi
if [ "$HAS_L" -eq 1 ]; then
    pass "conn_snapshot: state=L (listener) присутствует"
else
    warn "conn_snapshot: state=L (listener) не найден (states: ${CS_STATES})"
fi

# ── ТЕСТ 13: open_tcp_conns в snapshot ──
log ""
log "${CYAN}═══ ТЕСТ 13: open_tcp_conns в snapshot ═══${NC}"
OPEN_CONNS=$(csv_field "${TMPD}/snap1.csv" "snapshot" "open_tcp_conns" "NETTEST_tcp")
if [ -n "$OPEN_CONNS" ] && [ "$OPEN_CONNS" -gt 0 ] 2>/dev/null; then
    pass "open_tcp_conns=${OPEN_CONNS} > 0"
else
    warn "open_tcp_conns=${OPEN_CONNS:-пусто}"
fi

# ── ТЕСТ 14: conn_snapshot tx_bytes растёт между snapshot ──
log ""
log "${CYAN}═══ ТЕСТ 14: conn_snapshot tx_bytes растёт ═══${NC}"
CS_TX2=$(csv_field "${TMPD}/snap2.csv" "conn_snapshot" "net_conn_tx_bytes" "${PORT_TCP}")
if [ -n "$CS_TX" ] && [ -n "$CS_TX2" ] && [ "$CS_TX2" -gt "$CS_TX" ] 2>/dev/null; then
    pass "conn_snapshot tx_bytes растёт: ${CS_TX} → ${CS_TX2}"
else
    if [ -n "$CS_TX" ] && [ -n "$CS_TX2" ]; then
        warn "conn_snapshot tx_bytes не вырос: ${CS_TX} → ${CS_TX2}"
    else
        warn "conn_snapshot tx_bytes: snap1=${CS_TX:-N/A} snap2=${CS_TX2:-N/A}"
    fi
fi

# ══════════════════════════════════════════════════════════════════
#  ТЕСТЫ net_close
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 15-19: net_close ═══${NC}"

# net_close может быть в snap2 или snap3
NC_FILE=""
for snap in snap2.csv snap3.csv; do
    NC_CNT=$(csv_count "${TMPD}/${snap}" "net_close" "${PORT_TCP}")
    if [ "$NC_CNT" -gt 0 ]; then
        NC_FILE="${TMPD}/${snap}"
        break
    fi
done

if [ -n "$NC_FILE" ]; then
    pass "net_close для порта ${PORT_TCP} найден"

    # ТЕСТ 15: net_close — net_conn_tx_bytes > 0
    NC_TX=$(csv_field "$NC_FILE" "net_close" "net_conn_tx_bytes" "${PORT_TCP}")
    if [ -n "$NC_TX" ] && [ "$NC_TX" -gt 0 ] 2>/dev/null; then
        pass "net_close net_conn_tx_bytes=${NC_TX} > 0"
    else
        fail "net_close net_conn_tx_bytes=${NC_TX:-пусто}"
    fi

    # ТЕСТ 16: net_close — net_conn_rx_bytes > 0
    NC_RX=$(csv_field "$NC_FILE" "net_close" "net_conn_rx_bytes" "${PORT_TCP}")
    if [ -n "$NC_RX" ] && [ "$NC_RX" -gt 0 ] 2>/dev/null; then
        pass "net_close net_conn_rx_bytes=${NC_RX} > 0"
    else
        warn "net_close net_conn_rx_bytes=${NC_RX:-пусто}"
    fi

    # ТЕСТ 17: net_close — net_duration_ms > 0
    NC_DUR=$(csv_field "$NC_FILE" "net_close" "net_duration_ms" "${PORT_TCP}")
    if [ -n "$NC_DUR" ] && [ "$NC_DUR" -gt 0 ] 2>/dev/null; then
        pass "net_close net_duration_ms=${NC_DUR} > 0"
    else
        fail "net_close net_duration_ms=${NC_DUR:-пусто}"
    fi

    # ТЕСТ 18: net_close — tx_bytes >= отправленному (2 волны)
    EXPECTED_TX=$((TCP_SEND_BYTES * TCP_WAVES))
    if [ -n "$NC_TX" ] && [ "$NC_TX" -ge "$EXPECTED_TX" ] 2>/dev/null; then
        pass "net_close tx_bytes=${NC_TX} >= expected=${EXPECTED_TX}"
    elif [ -n "$NC_TX" ] && [ "$NC_TX" -gt 0 ] 2>/dev/null; then
        warn "net_close tx_bytes=${NC_TX} < expected=${EXPECTED_TX} (возможна потеря данных)"
    else
        fail "net_close tx_bytes=${NC_TX:-0}"
    fi

    # ТЕСТ 19: net_close — state: I (initiator) или R (responder)
    NC_STATE=$(csv_field "$NC_FILE" "net_close" "state" "${PORT_TCP}")
    if [ "$NC_STATE" = "I" ] || [ "$NC_STATE" = "R" ]; then
        pass "net_close state=${NC_STATE}"
    elif [ -n "$NC_STATE" ]; then
        warn "net_close state=${NC_STATE} (ожидалось I или R)"
    else
        fail "net_close state пустой"
    fi

    # ТЕСТ 20: net_close — IP-адреса заполнены
    NC_LADDR=$(csv_field "$NC_FILE" "net_close" "net_local_addr" "${PORT_TCP}")
    NC_RADDR=$(csv_field "$NC_FILE" "net_close" "net_remote_addr" "${PORT_TCP}")
    if [ -n "$NC_LADDR" ] && [ "$NC_LADDR" != "0.0.0.0" ]; then
        pass "net_close net_local_addr=${NC_LADDR}"
    else
        fail "net_close net_local_addr=${NC_LADDR:-пусто}"
    fi
    if [ -n "$NC_RADDR" ] && [ "$NC_RADDR" != "0.0.0.0" ]; then
        pass "net_close net_remote_addr=${NC_RADDR}"
    else
        fail "net_close net_remote_addr=${NC_RADDR:-пусто}"
    fi

    # ТЕСТ 21: net_close — tx_calls > 0
    NC_TX_CALLS=$(csv_field "$NC_FILE" "net_close" "net_conn_tx_calls" "${PORT_TCP}")
    if [ -n "$NC_TX_CALLS" ] && [ "$NC_TX_CALLS" -gt 0 ] 2>/dev/null; then
        pass "net_close net_conn_tx_calls=${NC_TX_CALLS} > 0"
    else
        fail "net_close net_conn_tx_calls=${NC_TX_CALLS:-пусто}"
    fi
else
    fail "net_close для порта ${PORT_TCP} НЕ найден"
    # Пропускаем зависимые тесты
    for t in "net_close tx" "net_close rx" "net_close dur" "net_close tx>=expected" "net_close state" "net_close laddr" "net_close raddr" "net_close tx_calls"; do
        fail "$t (net_close отсутствует)"
    done
fi

# ══════════════════════════════════════════════════════════════════
#  ТЕСТЫ net_connect / net_accept / net_listen
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 22-24: net_connect/net_accept/net_listen ═══${NC}"

# Объединяем все CSV
cat "${TMPD}/snap1.csv" > "${TMPD}/all.csv"
tail -n +2 "${TMPD}/snap2.csv" >> "${TMPD}/all.csv"
tail -n +2 "${TMPD}/snap3.csv" >> "${TMPD}/all.csv"

# ТЕСТ 22: net_listen
NL_CNT=$(csv_count "${TMPD}/all.csv" "net_listen" "${PORT_TCP}")
if [ "$NL_CNT" -gt 0 ]; then
    pass "net_listen: ${NL_CNT} событий для порта ${PORT_TCP}"
else
    warn "net_listen не найден (порт ${PORT_TCP})"
fi

# ТЕСТ 23: net_connect
NC_CONN=$(csv_count "${TMPD}/all.csv" "net_connect" "${PORT_TCP}")
if [ "$NC_CONN" -gt 0 ]; then
    pass "net_connect: ${NC_CONN} событий для порта ${PORT_TCP}"
else
    warn "net_connect не найден (порт ${PORT_TCP})"
fi

# ТЕСТ 24: net_accept
NC_ACC=$(csv_count "${TMPD}/all.csv" "net_accept" "${PORT_TCP}")
if [ "$NC_ACC" -gt 0 ]; then
    pass "net_accept: ${NC_ACC} событий для порта ${PORT_TCP}"
else
    warn "net_accept не найден (порт ${PORT_TCP})"
fi

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 25: UDP — net_tx_bytes в snapshot включает UDP
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 25: UDP net_tx_bytes в snapshot ═══${NC}"
UDP_SNAP_TX=$(csv_field "${TMPD}/snap1.csv" "snapshot" "net_tx_bytes" "NETTEST_udp")
if [ -n "$UDP_SNAP_TX" ] && [ "$UDP_SNAP_TX" -gt 0 ] 2>/dev/null; then
    pass "UDP snapshot net_tx_bytes=${UDP_SNAP_TX} > 0"
else
    warn "UDP snapshot net_tx_bytes=${UDP_SNAP_TX:-пусто}"
fi

# ── ТЕСТ 26: UDP — net_rx_bytes в snapshot ──
log ""
log "${CYAN}═══ ТЕСТ 26: UDP net_rx_bytes в snapshot ═══${NC}"
UDP_SNAP_RX=$(csv_field "${TMPD}/snap1.csv" "snapshot" "net_rx_bytes" "NETTEST_udp")
if [ -n "$UDP_SNAP_RX" ] && [ "$UDP_SNAP_RX" -gt 0 ] 2>/dev/null; then
    pass "UDP snapshot net_rx_bytes=${UDP_SNAP_RX} > 0"
else
    warn "UDP snapshot net_rx_bytes=${UDP_SNAP_RX:-пусто}"
fi

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 27: Согласованность snapshot net_tx >= conn_snapshot net_conn_tx
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 27: snapshot tx >= conn_snapshot tx ═══${NC}"
if [ -n "$SNAP_TX" ] && [ "$SNAP_TX" -gt 0 ] 2>/dev/null && \
   [ -n "$CS_TX" ] && [ "$CS_TX" -gt 0 ] 2>/dev/null; then
    if [ "$SNAP_TX" -ge "$CS_TX" ]; then
        pass "snapshot net_tx_bytes(${SNAP_TX}) >= conn_snapshot net_conn_tx_bytes(${CS_TX})"
    else
        warn "snapshot net_tx_bytes(${SNAP_TX}) < conn_snapshot tx(${CS_TX}) — возможно несколько соединений"
    fi
else
    warn "невозможно сравнить: snap_tx=${SNAP_TX:-N/A} cs_tx=${CS_TX:-N/A}"
fi

# ══════════════════════════════════════════════════════════════════
#  ТЕСТЫ UID / IDENTITY для сетевых событий
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  ТЕСТЫ UID / IDENTITY"
log "${CYAN}════════════════════════════════════════════════════${NC}"

# Определяем ожидаемый UID процесса (тест запускается от текущего пользователя через sudo)
# BPF bpf_get_current_uid_gid() вернёт UID вызвавшего python3 (через exec -a)
# Процесс создаётся из sudo bash → python3, uid будет 0 (root)
EXPECTED_UID=$(csv_field "${TMPD}/snap1.csv" "snapshot" "uid" "NETTEST_tcp")
log "Ожидаемый uid=${EXPECTED_UID}"

# ── ТЕСТ 28: snapshot uid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 28: snapshot uid ═══${NC}"
if [ -n "$EXPECTED_UID" ]; then
    pass "snapshot uid=${EXPECTED_UID}"
else
    fail "snapshot uid пустой"
fi

# ── ТЕСТ 29: snapshot loginuid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 29: snapshot loginuid ═══${NC}"
SNAP_LOGINUID=$(csv_field "${TMPD}/snap1.csv" "snapshot" "loginuid" "NETTEST_tcp")
if [ -n "$SNAP_LOGINUID" ]; then
    pass "snapshot loginuid=${SNAP_LOGINUID}"
else
    fail "snapshot loginuid пустой"
fi

# ── ТЕСТ 30: snapshot euid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 30: snapshot euid ═══${NC}"
SNAP_EUID=$(csv_field "${TMPD}/snap1.csv" "snapshot" "euid" "NETTEST_tcp")
if [ -n "$SNAP_EUID" ]; then
    pass "snapshot euid=${SNAP_EUID}"
else
    fail "snapshot euid пустой"
fi

# ── ТЕСТ 31: snapshot sessionid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 31: snapshot sessionid ═══${NC}"
SNAP_SESSIONID=$(csv_field "${TMPD}/snap1.csv" "snapshot" "sessionid" "NETTEST_tcp")
if [ -n "$SNAP_SESSIONID" ]; then
    pass "snapshot sessionid=${SNAP_SESSIONID}"
else
    fail "snapshot sessionid пустой"
fi

# ── ТЕСТ 32: conn_snapshot uid совпадает с snapshot ──
log ""
log "${CYAN}═══ ТЕСТ 32: conn_snapshot uid ═══${NC}"
CS_UID=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "uid" "${PORT_TCP}")
if [ -n "$CS_UID" ] && [ "$CS_UID" = "$EXPECTED_UID" ]; then
    pass "conn_snapshot uid=${CS_UID} == snapshot uid"
elif [ -n "$CS_UID" ]; then
    fail "conn_snapshot uid=${CS_UID} != snapshot uid=${EXPECTED_UID}"
else
    fail "conn_snapshot uid пустой"
fi

# ── ТЕСТ 33: conn_snapshot loginuid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 33: conn_snapshot loginuid ═══${NC}"
CS_LOGINUID=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "loginuid" "${PORT_TCP}")
if [ -n "$CS_LOGINUID" ] && [ "$CS_LOGINUID" = "$SNAP_LOGINUID" ]; then
    pass "conn_snapshot loginuid=${CS_LOGINUID} == snapshot loginuid"
elif [ -n "$CS_LOGINUID" ]; then
    warn "conn_snapshot loginuid=${CS_LOGINUID} != snapshot loginuid=${SNAP_LOGINUID}"
else
    fail "conn_snapshot loginuid пустой"
fi

# ── ТЕСТ 34: conn_snapshot euid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 34: conn_snapshot euid ═══${NC}"
CS_EUID=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "euid" "${PORT_TCP}")
if [ -n "$CS_EUID" ] && [ "$CS_EUID" = "$SNAP_EUID" ]; then
    pass "conn_snapshot euid=${CS_EUID} == snapshot euid"
elif [ -n "$CS_EUID" ]; then
    warn "conn_snapshot euid=${CS_EUID} != snapshot euid=${SNAP_EUID}"
else
    fail "conn_snapshot euid пустой"
fi

# ── ТЕСТ 35: conn_snapshot sessionid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 35: conn_snapshot sessionid ═══${NC}"
CS_SESSIONID=$(csv_field "${TMPD}/snap1.csv" "conn_snapshot" "sessionid" "${PORT_TCP}")
if [ -n "$CS_SESSIONID" ] && [ "$CS_SESSIONID" = "$SNAP_SESSIONID" ]; then
    pass "conn_snapshot sessionid=${CS_SESSIONID} == snapshot sessionid"
elif [ -n "$CS_SESSIONID" ]; then
    warn "conn_snapshot sessionid=${CS_SESSIONID} != snapshot sessionid=${SNAP_SESSIONID}"
else
    fail "conn_snapshot sessionid пустой"
fi

# ── ТЕСТ 36: net_close uid совпадает с snapshot ──
log ""
log "${CYAN}═══ ТЕСТ 36: net_close uid ═══${NC}"
if [ -n "$NC_FILE" ]; then
    NC_UID=$(csv_field "$NC_FILE" "net_close" "uid" "${PORT_TCP}")
    if [ -n "$NC_UID" ] && [ "$NC_UID" = "$EXPECTED_UID" ]; then
        pass "net_close uid=${NC_UID} == snapshot uid"
    elif [ -n "$NC_UID" ]; then
        fail "net_close uid=${NC_UID} != snapshot uid=${EXPECTED_UID}"
    else
        fail "net_close uid пустой"
    fi
else
    fail "net_close uid (net_close отсутствует)"
fi

# ── ТЕСТ 37: net_close loginuid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 37: net_close loginuid ═══${NC}"
if [ -n "$NC_FILE" ]; then
    NC_LOGINUID=$(csv_field "$NC_FILE" "net_close" "loginuid" "${PORT_TCP}")
    if [ -n "$NC_LOGINUID" ] && [ "$NC_LOGINUID" = "$SNAP_LOGINUID" ]; then
        pass "net_close loginuid=${NC_LOGINUID} == snapshot loginuid"
    elif [ -n "$NC_LOGINUID" ]; then
        warn "net_close loginuid=${NC_LOGINUID} != snapshot loginuid=${SNAP_LOGINUID}"
    else
        fail "net_close loginuid пустой"
    fi
else
    fail "net_close loginuid (net_close отсутствует)"
fi

# ── ТЕСТ 38: net_close euid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 38: net_close euid ═══${NC}"
if [ -n "$NC_FILE" ]; then
    NC_EUID=$(csv_field "$NC_FILE" "net_close" "euid" "${PORT_TCP}")
    if [ -n "$NC_EUID" ] && [ "$NC_EUID" = "$SNAP_EUID" ]; then
        pass "net_close euid=${NC_EUID} == snapshot euid"
    elif [ -n "$NC_EUID" ]; then
        warn "net_close euid=${NC_EUID} != snapshot euid=${SNAP_EUID}"
    else
        fail "net_close euid пустой"
    fi
else
    fail "net_close euid (net_close отсутствует)"
fi

# ── ТЕСТ 39: net_close sessionid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 39: net_close sessionid ═══${NC}"
if [ -n "$NC_FILE" ]; then
    NC_SESSIONID=$(csv_field "$NC_FILE" "net_close" "sessionid" "${PORT_TCP}")
    if [ -n "$NC_SESSIONID" ] && [ "$NC_SESSIONID" = "$SNAP_SESSIONID" ]; then
        pass "net_close sessionid=${NC_SESSIONID} == snapshot sessionid"
    elif [ -n "$NC_SESSIONID" ]; then
        warn "net_close sessionid=${NC_SESSIONID} != snapshot sessionid=${SNAP_SESSIONID}"
    else
        fail "net_close sessionid пустой"
    fi
else
    fail "net_close sessionid (net_close отсутствует)"
fi

# ── ТЕСТ 40: net_connect uid == snapshot uid ──
log ""
log "${CYAN}═══ ТЕСТ 40: net_connect uid ═══${NC}"
NCONN_UID=$(csv_field "${TMPD}/all.csv" "net_connect" "uid" "${PORT_TCP}")
if [ -n "$NCONN_UID" ] && [ "$NCONN_UID" = "$EXPECTED_UID" ]; then
    pass "net_connect uid=${NCONN_UID} == snapshot uid"
elif [ -n "$NCONN_UID" ]; then
    fail "net_connect uid=${NCONN_UID} != snapshot uid=${EXPECTED_UID}"
else
    warn "net_connect uid недоступен"
fi

# ── ТЕСТ 41: net_connect loginuid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 41: net_connect loginuid ═══${NC}"
NCONN_LOGINUID=$(csv_field "${TMPD}/all.csv" "net_connect" "loginuid" "${PORT_TCP}")
if [ -n "$NCONN_LOGINUID" ] && [ "$NCONN_LOGINUID" = "$SNAP_LOGINUID" ]; then
    pass "net_connect loginuid=${NCONN_LOGINUID} == snapshot loginuid"
elif [ -n "$NCONN_LOGINUID" ]; then
    warn "net_connect loginuid=${NCONN_LOGINUID} != snapshot loginuid=${SNAP_LOGINUID}"
else
    warn "net_connect loginuid недоступен"
fi

# ── ТЕСТ 42: net_accept loginuid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 42: net_accept loginuid ═══${NC}"
NACC_LOGINUID=$(csv_field "${TMPD}/all.csv" "net_accept" "loginuid" "${PORT_TCP}")
if [ -n "$NACC_LOGINUID" ] && [ "$NACC_LOGINUID" = "$SNAP_LOGINUID" ]; then
    pass "net_accept loginuid=${NACC_LOGINUID} == snapshot loginuid"
elif [ -n "$NACC_LOGINUID" ]; then
    warn "net_accept loginuid=${NACC_LOGINUID} != snapshot loginuid=${SNAP_LOGINUID}"
else
    warn "net_accept loginuid недоступен"
fi

# ── ТЕСТ 43: net_listen loginuid заполнен ──
log ""
log "${CYAN}═══ ТЕСТ 43: net_listen loginuid ═══${NC}"
NLISTEN_LOGINUID=$(csv_field "${TMPD}/all.csv" "net_listen" "loginuid" "${PORT_TCP}")
if [ -n "$NLISTEN_LOGINUID" ] && [ "$NLISTEN_LOGINUID" = "$SNAP_LOGINUID" ]; then
    pass "net_listen loginuid=${NLISTEN_LOGINUID} == snapshot loginuid"
elif [ -n "$NLISTEN_LOGINUID" ]; then
    warn "net_listen loginuid=${NLISTEN_LOGINUID} != snapshot loginuid=${SNAP_LOGINUID}"
else
    warn "net_listen loginuid недоступен"
fi

# ── ТЕСТ 44: согласованность uid по всем сетевым событиям ──
log ""
log "${CYAN}═══ ТЕСТ 44: согласованность uid по всем сетевым событиям ═══${NC}"
ALL_UIDS_CONSISTENT=1
for evt in snapshot conn_snapshot net_close net_connect net_accept net_listen; do
    EVT_UID=$(csv_field "${TMPD}/all.csv" "$evt" "uid" "${PORT_TCP}")
    # Для snapshot ищем по exec
    [ -z "$EVT_UID" ] && EVT_UID=$(csv_field "${TMPD}/all.csv" "$evt" "uid" "NETTEST_tcp")
    if [ -n "$EVT_UID" ] && [ "$EVT_UID" != "$EXPECTED_UID" ]; then
        ALL_UIDS_CONSISTENT=0
        log "  ${evt}: uid=${EVT_UID} != expected=${EXPECTED_UID}"
    fi
done
if [ "$ALL_UIDS_CONSISTENT" -eq 1 ]; then
    pass "uid согласован по всем сетевым событиям (uid=${EXPECTED_UID})"
else
    fail "uid НЕ согласован по сетевым событиям"
fi

# ══════════════════════════════════════════════════════════════════
#  ДЕТАЛИЗАЦИЯ
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}── Детализация snapshot (NETTEST_tcp) ──${NC}"
for snap in snap1 snap2; do
    TX_V=$(csv_field "${TMPD}/${snap}.csv" "snapshot" "net_tx_bytes" "NETTEST_tcp")
    RX_V=$(csv_field "${TMPD}/${snap}.csv" "snapshot" "net_rx_bytes" "NETTEST_tcp")
    OC_V=$(csv_field "${TMPD}/${snap}.csv" "snapshot" "open_tcp_conns" "NETTEST_tcp")
    log "  ${snap}: net_tx=${TX_V:-N/A} net_rx=${RX_V:-N/A} open_conns=${OC_V:-N/A}"
done

log ""
log "${CYAN}── Детализация conn_snapshot (порт ${PORT_TCP}) ──${NC}"
for snap in snap1 snap2; do
    python3 -c "
import csv, sys
with open('${TMPD}/${snap}.csv', encoding='utf-8', errors='replace') as f:
    for row in csv.DictReader(f):
        if row.get('event_type') != 'conn_snapshot':
            continue
        lp = row.get('net_local_port','')
        rp = row.get('net_remote_port','')
        if '${PORT_TCP}' not in lp and '${PORT_TCP}' not in rp:
            continue
        print(f'    pid={row.get(\"pid\",\"?\")} laddr={row.get(\"net_local_addr\",\"?\")}:{lp} → raddr={row.get(\"net_remote_addr\",\"?\")}:{rp} tx={row.get(\"net_conn_tx_bytes\",\"?\")} rx={row.get(\"net_conn_rx_bytes\",\"?\")} tx_calls={row.get(\"net_conn_tx_calls\",\"?\")} rx_calls={row.get(\"net_conn_rx_calls\",\"?\")} dur={row.get(\"net_duration_ms\",\"?\")}ms state={row.get(\"state\",\"?\")}')
" 2>/dev/null | while IFS= read -r line; do
        log "  ${snap}: ${line}"
    done
done

log ""
log "${CYAN}── Детализация net_close (порт ${PORT_TCP}) ──${NC}"
for snap in snap2 snap3; do
    python3 -c "
import csv, sys
with open('${TMPD}/${snap}.csv', encoding='utf-8', errors='replace') as f:
    for row in csv.DictReader(f):
        if row.get('event_type') != 'net_close':
            continue
        lp = row.get('net_local_port','')
        rp = row.get('net_remote_port','')
        if '${PORT_TCP}' not in lp and '${PORT_TCP}' not in rp:
            continue
        print(f'    pid={row.get(\"pid\",\"?\")} laddr={row.get(\"net_local_addr\",\"?\")}:{lp} → raddr={row.get(\"net_remote_addr\",\"?\")}:{rp} tx={row.get(\"net_conn_tx_bytes\",\"?\")} rx={row.get(\"net_conn_rx_bytes\",\"?\")} tx_calls={row.get(\"net_conn_tx_calls\",\"?\")} rx_calls={row.get(\"net_conn_rx_calls\",\"?\")} dur={row.get(\"net_duration_ms\",\"?\")}ms state={row.get(\"state\",\"?\")}')
" 2>/dev/null | while IFS= read -r line; do
        log "  ${snap}: ${line}"
    done
done

log ""
log "${CYAN}── Распределение событий ──${NC}"
for snap in snap1 snap2 snap3; do
    EVT_DIST=$(tail -n +2 "${TMPD}/${snap}.csv" | awk -F',' '{print $3}' | sort | uniq -c | sort -rn | tr '\n' '; ')
    log "  ${snap}: ${EVT_DIST}"
done

# ══════════════════════════════════════════════════════════════════
#  ИТОГО
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  ИТОГОВЫЙ ОТЧЁТ: net_metrics"
log "${CYAN}════════════════════════════════════════════════════${NC}"
echo -e "$REPORT"
log "Итого: ${GREEN}PASS=${PASS}${NC}  ${RED}FAIL=${FAIL}${NC}  ${YELLOW}WARN=${WARN}${NC}"

if [ "$FAIL" -eq 0 ]; then
    log "${GREEN}РЕЗУЛЬТАТ: ВСЕ ОСНОВНЫЕ ТЕСТЫ ПРОЙДЕНЫ ✓${NC}"
    exit 0
else
    log "${RED}РЕЗУЛЬТАТ: ЕСТЬ ОШИБКИ (${FAIL} FAIL)${NC}"
    exit 1
fi
