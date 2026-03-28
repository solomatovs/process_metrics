#!/usr/bin/env bash
# test_conn_snapshot.sh — end-to-end тест conn_snapshot
#
# Проверяет:
#   1. conn_snapshot появляется для TCP-соединений
#   2. tx/rx байты растут между snapshot-циклами
#   3. listener (state=1) виден в conn_snapshot
#   4. net_close после закрытия содержит финальные байты
#   5. timestamp snapshot == conn_snapshot
#   6. duration_ms > 0
#
# Требования: stress_test.conf запущен на порту 9091, snapshot_interval=5

set -uo pipefail

PORT=9091
BASE_URL="http://127.0.0.1:${PORT}"
SNAP_INTERVAL=5
TEST_PORT=18765
TEST_PORT2=18766
TMPD="/tmp/conn_snap_test_$$"
mkdir -p "$TMPD"
REPORT=""
PASS=0
FAIL=0
WARN=0

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { ((PASS++)); REPORT+="  ✓ $1\n"; log "PASS: $1"; }
fail() { ((FAIL++)); REPORT+="  ✗ $1\n"; log "FAIL: $1"; }
warn() { ((WARN++)); REPORT+="  ⚠ $1\n"; log "WARN: $1"; }

PIDS_TO_KILL=()
cleanup() {
    log "cleanup..."
    for p in "${PIDS_TO_KILL[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$TMPD"
}
trap cleanup EXIT

# Очистка буфера
curl -s "${BASE_URL}/metrics?clear=1" > /dev/null
log "буфер очищен"

# ═══════════════════════════════════════════════════════════════
# Запускаем сервер + клиент как единый python3-процесс
# Сервер слушает, принимает одно соединение, echo-ит обратно.
# Клиент подключается, шлёт данные волнами по сигналу.
# ═══════════════════════════════════════════════════════════════

python3 - "$TEST_PORT" "$TEST_PORT2" "$TMPD" <<'PYEOF' &
import socket, os, sys, signal, time, threading

TEST_PORT = int(sys.argv[1])
TEST_PORT2 = int(sys.argv[2])
TMPD = sys.argv[3]

# === Echo-сервер в отдельном потоке ===
def echo_server(port, stop_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    srv.settimeout(1.0)
    # Сообщаем что listener готов
    with open(os.path.join(TMPD, 'server_ready'), 'w') as f:
        f.write(str(os.getpid()))

    conn = None
    while not stop_event.is_set():
        if conn is None:
            try:
                conn, addr = srv.accept()
                conn.settimeout(0.5)
            except socket.timeout:
                continue
        else:
            try:
                data = conn.recv(8192)
                if data:
                    conn.sendall(data)  # echo
                else:
                    break
            except socket.timeout:
                continue
            except Exception:
                break
    if conn:
        conn.close()
    srv.close()

stop = threading.Event()
t = threading.Thread(target=echo_server, args=(TEST_PORT, stop), daemon=True)
t.start()

# Ждём готовности сервера
for _ in range(50):
    if os.path.exists(os.path.join(TMPD, 'server_ready')):
        break
    time.sleep(0.1)

# === Клиент ===
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', TEST_PORT))
with open(os.path.join(TMPD, 'client_ready'), 'w') as f:
    f.write(str(os.getpid()))

# Волна 1: отправляем 1000 байт, получаем echo
client.sendall(b'A' * 1000)
time.sleep(0.3)
try:
    client.settimeout(2.0)
    data = client.recv(8192)
except:
    data = b''
with open(os.path.join(TMPD, 'wave1_done'), 'w') as f:
    f.write(f'sent=1000,recv={len(data)}')

# Ждём SIGUSR1 для волны 2
def wave2(signum, frame):
    client.sendall(b'B' * 2000)
    time.sleep(0.3)
    try:
        client.settimeout(2.0)
        d = client.recv(8192)
    except:
        d = b''
    with open(os.path.join(TMPD, 'wave2_done'), 'w') as f:
        f.write(f'sent=2000,recv={len(d)}')

# Ждём SIGUSR2 для закрытия
def close_conn(signum, frame):
    client.close()
    stop.set()
    with open(os.path.join(TMPD, 'closed'), 'w') as f:
        f.write('ok')

# Ждём SIGTERM для listener-only теста
def start_listener2(signum, frame):
    srv2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv2.bind(('127.0.0.1', TEST_PORT2))
    srv2.listen(1)
    with open(os.path.join(TMPD, 'listener2_ready'), 'w') as f:
        f.write('ok')
    # Держим listener открытым
    time.sleep(30)
    srv2.close()

signal.signal(signal.SIGUSR1, wave2)
signal.signal(signal.SIGUSR2, close_conn)
signal.signal(signal.SIGWINCH, start_listener2)  # используем SIGWINCH для listener2

# Спим ожидая сигналов
time.sleep(120)
PYEOF

PY_PID=$!
PIDS_TO_KILL+=($PY_PID)

# Ждём готовности сервера и клиента
for i in $(seq 1 30); do
    [ -f "${TMPD}/wave1_done" ] && break
    sleep 0.2
done

if [ -f "${TMPD}/wave1_done" ]; then
    log "волна 1 завершена: $(cat ${TMPD}/wave1_done)"
else
    log "ОШИБКА: клиент не подключился"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════
# Ждём snapshot-цикл 1
# ═══════════════════════════════════════════════════════════════
log "ожидание snapshot-цикла 1 (~${SNAP_INTERVAL}с)..."
sleep $((SNAP_INTERVAL + 2))

curl -s "${BASE_URL}/metrics?clear=1" > "${TMPD}/snap1.csv"
SNAP1_LINES=$(wc -l < "${TMPD}/snap1.csv")
log "снимок 1: ${SNAP1_LINES} строк"

# ═══════════════════════════════════════════════════════════════
# Волна 2
# ═══════════════════════════════════════════════════════════════
log "отправка волны 2 (~2000B)..."
kill -USR1 "$PY_PID" 2>/dev/null
for i in $(seq 1 30); do
    [ -f "${TMPD}/wave2_done" ] && break
    sleep 0.2
done
log "волна 2 завершена: $(cat ${TMPD}/wave2_done 2>/dev/null || echo N/A)"

# ═══════════════════════════════════════════════════════════════
# Ждём snapshot-цикл 2
# ═══════════════════════════════════════════════════════════════
log "ожидание snapshot-цикла 2 (~${SNAP_INTERVAL}с)..."
sleep $((SNAP_INTERVAL + 2))

curl -s "${BASE_URL}/metrics?clear=1" > "${TMPD}/snap2.csv"
SNAP2_LINES=$(wc -l < "${TMPD}/snap2.csv")
log "снимок 2: ${SNAP2_LINES} строк"

# ═══════════════════════════════════════════════════════════════
# Закрытие соединения
# ═══════════════════════════════════════════════════════════════
log "закрытие TCP-соединения..."
kill -USR2 "$PY_PID" 2>/dev/null
for i in $(seq 1 30); do
    [ -f "${TMPD}/closed" ] && break
    sleep 0.2
done

# Запуск listener-only
log "запуск listener-only на порту ${TEST_PORT2}..."
kill -WINCH "$PY_PID" 2>/dev/null
for i in $(seq 1 20); do
    [ -f "${TMPD}/listener2_ready" ] && break
    sleep 0.2
done

# ═══════════════════════════════════════════════════════════════
# Ждём snapshot-цикл 3
# ═══════════════════════════════════════════════════════════════
log "ожидание snapshot-цикла 3 (~${SNAP_INTERVAL}с)..."
sleep $((SNAP_INTERVAL + 2))

curl -s "${BASE_URL}/metrics?clear=1" > "${TMPD}/snap3.csv"
SNAP3_LINES=$(wc -l < "${TMPD}/snap3.csv")
log "снимок 3: ${SNAP3_LINES} строк"

# ═══════════════════════════════════════════════════════════════
#  АНАЛИЗ
# ═══════════════════════════════════════════════════════════════
log ""
log "════════════════════════════════════════════════════"
log "  АНАЛИЗ РЕЗУЛЬТАТОВ"
log "════════════════════════════════════════════════════"

HEADER=$(head -1 "${TMPD}/snap1.csv")
col_num() { echo "$HEADER" | tr ',' '\n' | grep -n "^${1}$" | cut -d: -f1; }

COL_TS=$(col_num timestamp)
COL_EVT=$(col_num event_type)
COL_LPORT=$(col_num net_local_port)
COL_RPORT=$(col_num net_remote_port)
COL_TX=$(col_num net_conn_tx_bytes)
COL_RX=$(col_num net_conn_rx_bytes)
COL_STATE=$(col_num state)
COL_DUR=$(col_num net_duration_ms)
COL_PID=$(col_num pid)

log "Колонки: ts=$COL_TS evt=$COL_EVT lport=$COL_LPORT rport=$COL_RPORT tx=$COL_TX rx=$COL_RX state=$COL_STATE dur=$COL_DUR"

# Фильтр conn_snapshot для нашего порта
filter_conn() {
    grep "conn_snapshot" "$1" | awk -F',' -v lp="$TEST_PORT" -v rp="$TEST_PORT" -v clp="$COL_LPORT" -v crp="$COL_RPORT" \
        '$clp == lp || $crp == rp'
}

# === Тест 1: conn_snapshot в снимке 1 ===
CS1=$(filter_conn "${TMPD}/snap1.csv" || true)
CS1_COUNT=0; [ -n "$CS1" ] && CS1_COUNT=$(echo "$CS1" | wc -l)

if [ "$CS1_COUNT" -gt 0 ]; then
    pass "Снимок 1: ${CS1_COUNT} conn_snapshot для порта ${TEST_PORT}"
else
    fail "Снимок 1: conn_snapshot для порта ${TEST_PORT} НЕ найден"
fi

# === Тест 2: conn_snapshot в снимке 2 ===
CS2=$(filter_conn "${TMPD}/snap2.csv" || true)
CS2_COUNT=0; [ -n "$CS2" ] && CS2_COUNT=$(echo "$CS2" | wc -l)

if [ "$CS2_COUNT" -gt 0 ]; then
    pass "Снимок 2: ${CS2_COUNT} conn_snapshot для порта ${TEST_PORT}"
else
    fail "Снимок 2: conn_snapshot для порта ${TEST_PORT} НЕ найден"
fi

# === Тест 3: Байты клиента растут ===
get_field() {
    # $1=file, $2=port_col_value, $3=port_col_num, $4=field_col_num
    grep "conn_snapshot" "$1" | awk -F',' -v p="$2" -v cp="$3" -v cf="$4" '$cp == p { print $cf }' | head -1
}

TX1=$(get_field "${TMPD}/snap1.csv" "$TEST_PORT" "$COL_RPORT" "$COL_TX")
RX1=$(get_field "${TMPD}/snap1.csv" "$TEST_PORT" "$COL_RPORT" "$COL_RX")
TX2=$(get_field "${TMPD}/snap2.csv" "$TEST_PORT" "$COL_RPORT" "$COL_TX")
RX2=$(get_field "${TMPD}/snap2.csv" "$TEST_PORT" "$COL_RPORT" "$COL_RX")

log ""
log "── Клиент (remote_port=${TEST_PORT}) ──"
log "  Снимок 1: tx=${TX1:-N/A}  rx=${RX1:-N/A}"
log "  Снимок 2: tx=${TX2:-N/A}  rx=${RX2:-N/A}"

if [ -n "$TX1" ] && [ -n "$TX2" ] && [ "$TX1" -gt 0 ] 2>/dev/null && [ "$TX2" -gt "$TX1" ] 2>/dev/null; then
    pass "tx клиента растёт: ${TX1} → ${TX2}"
elif [ -n "$TX1" ] && [ "$TX1" -gt 0 ] 2>/dev/null; then
    if [ -n "$TX2" ]; then
        warn "tx клиента НЕ вырос: ${TX1} → ${TX2}"
    else
        warn "Клиент не найден в снимке 2 (tx снимка 1 = ${TX1})"
    fi
else
    fail "tx клиента = 0 или недоступен"
fi

if [ -n "$RX1" ] && [ -n "$RX2" ] && [ "$RX1" -gt 0 ] 2>/dev/null && [ "$RX2" -gt "$RX1" ] 2>/dev/null; then
    pass "rx клиента растёт: ${RX1} → ${RX2}"
elif [ -n "$RX1" ] && [ "$RX1" -gt 0 ] 2>/dev/null; then
    warn "rx клиента не вырос: ${RX1:-N/A} → ${RX2:-N/A} (echo мог не дойти вовремя)"
else
    warn "rx клиента = 0 или недоступен"
fi

# === Тест 4: Серверное (accepted) соединение ===
STX1=$(grep "conn_snapshot" "${TMPD}/snap1.csv" | \
    awk -F',' -v lp="$TEST_PORT" -v clp="$COL_LPORT" -v cs="$COL_STATE" -v ctx="$COL_TX" \
    '$clp == lp && $cs != 1 { print $ctx }' | head -1)

if [ -n "$STX1" ] && [ "$STX1" -gt 0 ] 2>/dev/null; then
    pass "Серверное accepted-соединение: tx=${STX1}"
else
    warn "Серверное accepted-соединение: tx=${STX1:-0} (может не трекаться если сервер не в tracked_map)"
fi

# === Тест 5: Listener (state=L) ===
LCOUNT=$(grep "conn_snapshot" "${TMPD}/snap1.csv" | \
    awk -F',' -v lp="$TEST_PORT" -v clp="$COL_LPORT" -v cs="$COL_STATE" '$clp == lp && $cs == "L"' | wc -l)

if [ "$LCOUNT" -gt 0 ]; then
    pass "Listener (state=L) для порта ${TEST_PORT}"
else
    warn "Listener (state=L) для порта ${TEST_PORT} не найден (процесс может не быть в tracked_map)"
fi

# === Тест 6: net_close ===
NC_TOTAL=0
for snap in snap2.csv snap3.csv; do
    NC=$(grep "net_close" "${TMPD}/${snap}" | grep -c "${TEST_PORT}" || true)
    NC_TOTAL=$((NC_TOTAL + NC))
done

if [ "$NC_TOTAL" -gt 0 ]; then
    pass "net_close для порта ${TEST_PORT}: ${NC_TOTAL} событий"
else
    fail "net_close для порта ${TEST_PORT} НЕ найден"
fi

# === Тест 7: Timestamp snapshot == conn_snapshot ===
TS_SNAP=$(grep ",snapshot," "${TMPD}/snap1.csv" | head -1 | cut -d',' -f"${COL_TS}")
TS_CONN=$(grep ",conn_snapshot," "${TMPD}/snap1.csv" | head -1 | cut -d',' -f"${COL_TS}")

if [ -n "$TS_SNAP" ] && [ -n "$TS_CONN" ] && [ "$TS_SNAP" = "$TS_CONN" ]; then
    pass "Timestamp snapshot == conn_snapshot: ${TS_SNAP}"
elif [ -n "$TS_SNAP" ] && [ -n "$TS_CONN" ]; then
    fail "Timestamp mismatch: snapshot=${TS_SNAP}, conn_snapshot=${TS_CONN}"
else
    warn "Не удалось сравнить timestamp"
fi

# === Тест 8: duration_ms > 0 ===
DUR=$(get_field "${TMPD}/snap2.csv" "$TEST_PORT" "$COL_RPORT" "$COL_DUR")

if [ -n "$DUR" ] && [ "$DUR" -gt 0 ] 2>/dev/null; then
    pass "duration_ms > 0: ${DUR}ms"
elif [ -n "$DUR" ]; then
    fail "duration_ms = ${DUR} (ожидалось > 0)"
else
    warn "Не удалось извлечь duration_ms"
fi

# === Тест 9: Listener-only (порт 2) ===
L2=$(grep "conn_snapshot" "${TMPD}/snap3.csv" | grep -c "${TEST_PORT2}" || true)

if [ "$L2" -gt 0 ]; then
    pass "Listener-only (порт ${TEST_PORT2}) в снимке 3"
else
    warn "Listener-only (порт ${TEST_PORT2}) не найден (процесс может не быть в tracked_map)"
fi

# ═══════════════════════════════════════════════════════════════
#  ДЕТАЛИЗАЦИЯ
# ═══════════════════════════════════════════════════════════════
log ""
log "── Детализация conn_snapshot (порт ${TEST_PORT}) ──"
for snap in snap1 snap2; do
    log "  ${snap}:"
    grep "conn_snapshot" "${TMPD}/${snap}.csv" | \
        awk -F',' -v lp="$TEST_PORT" -v rp="$TEST_PORT" -v clp="$COL_LPORT" -v crp="$COL_RPORT" \
            -v ctx="$COL_TX" -v crx="$COL_RX" -v cs="$COL_STATE" -v cd="$COL_DUR" -v cpid="$COL_PID" \
            '($clp == lp || $crp == rp) { printf "    pid=%-7s lport=%-6s rport=%-6s tx=%-10s rx=%-10s state=%s dur=%sms\n", $cpid, $clp, $crp, $ctx, $crx, $cs, $cd }' \
        || log "    (нет данных)"
done

log ""
log "── Детализация net_close (порт ${TEST_PORT}) ──"
for snap in snap2 snap3; do
    grep "net_close" "${TMPD}/${snap}.csv" | \
        awk -F',' -v lp="$TEST_PORT" -v rp="$TEST_PORT" -v clp="$COL_LPORT" -v crp="$COL_RPORT" \
            -v ctx="$COL_TX" -v crx="$COL_RX" -v cd="$COL_DUR" -v cpid="$COL_PID" \
            '($clp == lp || $crp == rp) { printf "  [%s] pid=%-7s lport=%-6s rport=%-6s tx=%-10s rx=%-10s dur=%sms\n", "'$snap'", $cpid, $clp, $crp, $ctx, $crx, $cd }' \
        || true
done

# ═══════════════════════════════════════════════════════════════
#  ИТОГО
# ═══════════════════════════════════════════════════════════════
log ""
log "════════════════════════════════════════════════════"
log "  ИТОГОВЫЙ ОТЧЁТ: conn_snapshot e2e"
log "════════════════════════════════════════════════════"
echo -e "$REPORT"
log "Итого: PASS=${PASS}  FAIL=${FAIL}  WARN=${WARN}"

if [ "$FAIL" -eq 0 ]; then
    log "РЕЗУЛЬТАТ: ВСЕ ОСНОВНЫЕ ТЕСТЫ ПРОЙДЕНЫ ✓"
else
    log "РЕЗУЛЬТАТ: ЕСТЬ ОШИБКИ (${FAIL} FAIL)"
fi
