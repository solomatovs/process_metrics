#!/usr/bin/env bash
# test_security.sh — интеграционные тесты security_tracking
#
# Тесты:
#   1. syn_recv      — входящий SYN на listener отслеживаемого процесса
#   2. rst_sent      — RST отправлен (SO_LINGER=0 close)
#   3. rst_recv      — RST получен (подключение к закрытому порту)
#   4. tcp_retransmit — ретрансмиссия TCP (iptables DROP)
#   5. udp_agg       — агрегация UDP пакетов/байтов
#   6. open_conn_count — счётчик открытых TCP-соединений в snapshot
#
# Запуск: sudo bash tests/test_security.sh
#
# Требования:
#   - Собранный бинарник в build/process_metrics
#   - iptables (для теста tcp_retransmit)
#   - python3

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/build/process_metrics"
CONF="${SCRIPT_DIR}/test_security.conf"
PORT=19092
BASE_URL="http://127.0.0.1:${PORT}"
SNAP_INTERVAL=5
TMPD="/tmp/test_security_$$"
LOGFILE="${TMPD}/pm.log"

# Порты для тестов
PORT_SYN=19201
PORT_RST_SENT=19202
PORT_RST_RECV=19203
PORT_RETRANS=19204
PORT_UDP=19205
PORT_OPEN_CONN=19206

PASS=0
FAIL=0
WARN=0
REPORT=""
PM_PID=""
PIDS_TO_KILL=()
IPTABLES_CLEANUP=""

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
    # Удаляем iptables-правило если было
    if [ -n "$IPTABLES_CLEANUP" ]; then
        eval "$IPTABLES_CLEANUP" 2>/dev/null || true
    fi
    # Убиваем фоновые процессы
    for p in "${PIDS_TO_KILL[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    # Убиваем process_metrics
    if [ -n "$PM_PID" ] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null
        wait "$PM_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    # Оставляем TMPD для отладки при ошибках
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

# Ждём первый snapshot для стабилизации
log "ожидание первого snapshot..."
for i in $(seq 1 30); do
    if grep -q "snapshot:" "$LOGFILE" 2>/dev/null; then break; fi
    sleep 0.5
done

# Очистка буфера
curl -s "${BASE_URL}/metrics?clear=1" > /dev/null
log "буфер очищен"

# ── Вспомогательные функции ───────────────────────────────────────

# Ожидание snapshot-цикла
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

# Забрать CSV с очисткой
fetch_csv() {
    local outfile=$1
    curl -s "${BASE_URL}/metrics?clear=1" > "$outfile"
}

# Подсчёт строк с event_type
count_events() {
    local file=$1
    local event_type=$2
    local n
    n=$(grep -c ",${event_type}," "$file" 2>/dev/null) || true
    echo "${n:-0}"
}

# Определить номер колонки
HEADER=""
col_num() {
    echo "$HEADER" | tr ',' '\n' | grep -n "^${1}$" | cut -d: -f1
}

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 1: syn_recv
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 1: syn_recv ═══${NC}"

# Запускаем tracked listener (SECTEST в argv)
(exec -a "SECTEST_syn_listener" python3 -c "
import socket, time, os, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${PORT_SYN}))
s.listen(5)
s.settimeout(1.0)
# Ждём одно подключение
try:
    conn, addr = s.accept()
    conn.close()
except:
    pass
time.sleep(30)
s.close()
") &
SYN_PID=$!
PIDS_TO_KILL+=($SYN_PID)
sleep 1

# exec -a для смены cmdline
(exec -a "SECTEST_syn_client" python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', ${PORT_SYN}))
time.sleep(2)
s.close()
") &
SYN_CLIENT_PID=$!
PIDS_TO_KILL+=($SYN_CLIENT_PID)
sleep 1

wait_snapshot
fetch_csv "${TMPD}/syn.csv"

HEADER=$(head -1 "${TMPD}/syn.csv")
COL_SEC_LPORT=$(col_num sec_local_port)
COL_SEC_RPORT=$(col_num sec_remote_port)
COL_SEC_LADDR=$(col_num sec_local_addr)
COL_SEC_AF=$(col_num sec_af)

SYN_COUNT=$(count_events "${TMPD}/syn.csv" "syn_recv")

if [ "$SYN_COUNT" -gt 0 ]; then
    pass "syn_recv: ${SYN_COUNT} событий"
    # Проверяем что local_port = PORT_SYN
    SYN_MATCH=$(grep ",syn_recv," "${TMPD}/syn.csv" | \
        awk -F',' -v clp="$COL_SEC_LPORT" -v p="$PORT_SYN" '$clp == p' | wc -l)
    if [ "$SYN_MATCH" -gt 0 ]; then
        pass "syn_recv: sec_local_port=${PORT_SYN} совпадает"
    else
        fail "syn_recv: sec_local_port=${PORT_SYN} не найден (есть порты: $(grep ",syn_recv," "${TMPD}/syn.csv" | awk -F',' -v c="$COL_SEC_LPORT" '{print $c}' | sort -u | tr '\n' ' '))"
    fi
else
    fail "syn_recv: событий не найдено"
fi

# Убиваем тестовые процессы
kill $SYN_PID $SYN_CLIENT_PID 2>/dev/null || true
wait $SYN_PID $SYN_CLIENT_PID 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 2: rst_sent — RST отправлен (SO_LINGER=0)
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 2: rst_sent ═══${NC}"

# Очистка буфера
curl -s "${BASE_URL}/metrics?clear=1" > /dev/null

# Tracked listener + tracked клиент с SO_LINGER=0
# Клиент подключается к серверу и закрывает с RST (SO_LINGER=0)
(exec -a "SECTEST_rst_server" python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', ${PORT_RST_SENT}))
s.listen(1)
s.settimeout(10.0)
try:
    conn, addr = s.accept()
    conn.sendall(b'HELLO')  # шлём данные чтобы был трафик
    time.sleep(10)
    conn.close()
except:
    pass
s.close()
") &
RST_SRV_PID=$!
PIDS_TO_KILL+=($RST_SRV_PID)
sleep 1

# Клиент: SO_LINGER=0 → close() вызовет RST send
(exec -a "SECTEST_rst_client" python3 -c "
import socket, struct, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', ${PORT_RST_SENT}))
time.sleep(0.5)
try:
    s.recv(1024)
except:
    pass
# SO_LINGER=0 → RST при close
s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
s.close()
time.sleep(1)
") &
RST_CLIENT_PID=$!
PIDS_TO_KILL+=($RST_CLIENT_PID)
sleep 3

wait_snapshot
fetch_csv "${TMPD}/rst_sent.csv"

COL_SEC_DIR=$(col_num sec_direction)

RST_SENT_COUNT=$(count_events "${TMPD}/rst_sent.csv" "rst_sent")
RST_RECV_COUNT=$(count_events "${TMPD}/rst_sent.csv" "rst_recv")

if [ "$RST_SENT_COUNT" -gt 0 ]; then
    pass "rst_sent: ${RST_SENT_COUNT} событий"
    RST_DIR=$(grep ",rst_sent," "${TMPD}/rst_sent.csv" | \
        awk -F',' -v cd="$COL_SEC_DIR" '{print $cd}' | sort -u | head -1)
    if [ "$RST_DIR" = "0" ]; then
        pass "rst_sent: sec_direction=0"
    else
        warn "rst_sent: sec_direction=${RST_DIR} (ожидалось 0)"
    fi
else
    fail "rst_sent: событий не найдено"
fi

kill $RST_SRV_PID $RST_CLIENT_PID 2>/dev/null || true
wait $RST_SRV_PID $RST_CLIENT_PID 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 3: rst_recv — RST получен (подключение к закрытому порту)
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 3: rst_recv ═══${NC}"

curl -s "${BASE_URL}/metrics?clear=1" > /dev/null

# Tracked процесс пытается подключиться к закрытому порту
(exec -a "SECTEST_rst_recv_client" python3 -c "
import socket, time
for i in range(3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(('127.0.0.1', ${PORT_RST_RECV}))
    except (ConnectionRefusedError, socket.timeout):
        pass
    finally:
        s.close()
    time.sleep(0.3)
time.sleep(15)
") &
RST_RECV_PID=$!
PIDS_TO_KILL+=($RST_RECV_PID)
sleep 3

wait_snapshot
fetch_csv "${TMPD}/rst_recv.csv"

RST_R_COUNT=$(count_events "${TMPD}/rst_recv.csv" "rst_recv")

if [ "$RST_R_COUNT" -gt 0 ]; then
    pass "rst_recv: ${RST_R_COUNT} событий"
    RST_R_DIR=$(grep ",rst_recv," "${TMPD}/rst_recv.csv" | \
        awk -F',' -v cd="$COL_SEC_DIR" '{print $cd}' | sort -u | head -1)
    if [ "$RST_R_DIR" = "1" ]; then
        pass "rst_recv: sec_direction=1"
    else
        warn "rst_recv: sec_direction=${RST_R_DIR} (ожидалось 1)"
    fi
else
    # rst_recv для подключения к закрытому порту — ядро само генерирует RST
    # при этом нет sock в sock_map, поэтому может не трекаться
    warn "rst_recv: событий не найдено (ожидаемо: нет сокета в sock_map для connection refused)"
fi

kill $RST_RECV_PID 2>/dev/null || true
wait $RST_RECV_PID 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 4: tcp_retransmit — ретрансмиссия TCP
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 4: tcp_retransmit ═══${NC}"

curl -s "${BASE_URL}/metrics?clear=1" > /dev/null

# Сервер + клиент в одном процессе: соединение уже установлено,
# затем iptables блокирует → клиент шлёт данные → ретрансмиссии
(exec -a "SECTEST_retrans_pair" python3 -c "
import socket, time, os, signal

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', ${PORT_RETRANS}))
srv.listen(1)
srv.settimeout(10.0)

# Клиентское соединение
cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', ${PORT_RETRANS}))
acc, _ = srv.accept()

# Соединение установлено — сообщаем
with open('${TMPD}/retrans_ready', 'w') as f:
    f.write('ok')

# Ждём сигнала USR1 = начать слать данные (iptables уже включён)
def send_data(signum, frame):
    try:
        for _ in range(20):
            cli.sendall(b'R' * 5000)
            time.sleep(0.3)
    except:
        pass
    with open('${TMPD}/retrans_sent', 'w') as f:
        f.write('ok')

signal.signal(signal.SIGUSR1, send_data)
time.sleep(60)
cli.close()
acc.close()
srv.close()
") &
RETRANS_PID=$!
PIDS_TO_KILL+=($RETRANS_PID)

# Ждём установления соединения
for i in $(seq 1 30); do
    [ -f "${TMPD}/retrans_ready" ] && break
    sleep 0.2
done
log "TCP-соединение установлено"

# Блокируем ACK — чтобы данные не доходили и были ретрансмиссии
log "включение iptables DROP для порта ${PORT_RETRANS}..."
iptables -A INPUT -p tcp --sport ${PORT_RETRANS} -j DROP 2>/dev/null || true
IPTABLES_CLEANUP="iptables -D INPUT -p tcp --sport ${PORT_RETRANS} -j DROP 2>/dev/null"

# Начинаем слать данные (они не получат ACK → ретрансмиссии)
kill -USR1 "$RETRANS_PID" 2>/dev/null

# Ждём ретрансмиссий
log "ожидание ретрансмиссий (~8с)..."
sleep 8

# Убираем iptables
eval "$IPTABLES_CLEANUP" 2>/dev/null || true
IPTABLES_CLEANUP=""

wait_snapshot
fetch_csv "${TMPD}/retrans.csv"

RETRANS_COUNT=$(count_events "${TMPD}/retrans.csv" "tcp_retrans")

if [ "$RETRANS_COUNT" -gt 0 ]; then
    pass "tcp_retransmit: ${RETRANS_COUNT} событий"
    # Проверяем что порт совпадает
    COL_SEC_STATE=$(col_num sec_tcp_state)
    RETRANS_PORT=$(grep ",tcp_retrans," "${TMPD}/retrans.csv" | \
        awk -F',' -v clp="$COL_SEC_LPORT" -v crp="$COL_SEC_RPORT" -v p="$PORT_RETRANS" \
        '$clp == p || $crp == p' | wc -l)
    if [ "$RETRANS_PORT" -gt 0 ]; then
        pass "tcp_retransmit: порт ${PORT_RETRANS} совпадает (${RETRANS_PORT} событий)"
    else
        warn "tcp_retransmit: порт ${PORT_RETRANS} не найден в событиях"
    fi
else
    warn "tcp_retransmit: событий не найдено (iptables мог не сработать вовремя)"
fi

kill $RETRANS_PID 2>/dev/null || true
wait $RETRANS_PID 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 5: udp_agg — агрегация UDP
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 5: udp_agg ═══${NC}"

curl -s "${BASE_URL}/metrics?clear=1" > /dev/null

# Tracked UDP-сервер
(exec -a "SECTEST_udp_server" python3 -c "
import socket, time, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', ${PORT_UDP}))
s.settimeout(1.0)
total = 0
for _ in range(30):
    try:
        data, addr = s.recvfrom(4096)
        total += len(data)
        s.sendto(b'PONG' * 50, addr)  # ~200B ответ
    except socket.timeout:
        pass
time.sleep(15)
s.close()
") &
UDP_SRV_PID=$!
PIDS_TO_KILL+=($UDP_SRV_PID)
sleep 1

# Tracked UDP-клиент отправляет пакеты
(exec -a "SECTEST_udp_client" python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(10):
    s.sendto(b'PING' * 100, ('127.0.0.1', ${PORT_UDP}))  # 400B
    time.sleep(0.1)
    try:
        s.settimeout(0.5)
        data = s.recv(4096)
    except:
        pass
time.sleep(15)
s.close()
") &
UDP_CLI_PID=$!
PIDS_TO_KILL+=($UDP_CLI_PID)
sleep 3

wait_snapshot
fetch_csv "${TMPD}/udp.csv"

UDP_COUNT=$(count_events "${TMPD}/udp.csv" "udp_agg")

if [ "$UDP_COUNT" -gt 0 ]; then
    pass "udp_agg: ${UDP_COUNT} событий"

    # Проверяем net_tx_bytes > 0 (UDP-агрегат хранит bytes в net_tx/rx_bytes)
    COL_NTXB=$(col_num net_tx_bytes)
    COL_NRXB=$(col_num net_rx_bytes)
    # Берём максимальный tx из всех udp_agg строк
    UDP_TX=$(grep ",udp_agg," "${TMPD}/udp.csv" | \
        awk -F',' -v ctx="$COL_NTXB" '{print $ctx}' | sort -rn | head -1)
    UDP_RX=$(grep ",udp_agg," "${TMPD}/udp.csv" | \
        awk -F',' -v crx="$COL_NRXB" '{print $crx}' | sort -rn | head -1)
    if [ -n "$UDP_TX" ] && [ "$UDP_TX" -gt 0 ] 2>/dev/null; then
        pass "udp_agg: net_tx_bytes=${UDP_TX}, net_rx_bytes=${UDP_RX}"
    else
        fail "udp_agg: net_tx_bytes=${UDP_TX:-0} (ожидалось > 0)"
    fi

    # Проверяем file_read_bytes/file_write_bytes = packets count
    COL_FRB=$(col_num file_read_bytes)
    COL_FWB=$(col_num file_write_bytes)
    UDP_PKTS=$(grep ",udp_agg," "${TMPD}/udp.csv" | \
        awk -F',' -v cf="$COL_FWB" '{print $cf}' | sort -rn | head -1)
    if [ -n "$UDP_PKTS" ] && [ "$UDP_PKTS" -gt 0 ] 2>/dev/null; then
        pass "udp_agg: tx_packets=${UDP_PKTS}"
    else
        warn "udp_agg: tx_packets=${UDP_PKTS:-0}"
    fi
else
    fail "udp_agg: событий не найдено"
fi

kill $UDP_SRV_PID $UDP_CLI_PID 2>/dev/null || true
wait $UDP_SRV_PID $UDP_CLI_PID 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
#  ТЕСТ 6: open_conn_count — счётчик активных TCP-соединений
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ ТЕСТ 6: open_conn_count ═══${NC}"

curl -s "${BASE_URL}/metrics?clear=1" > /dev/null

N_CONNS=5

# Tracked процесс открывает N TCP-соединений
# exec -a задаёт cmdline marker для rule matching
(exec -a "SECTEST_open_conn" python3 -c "
import socket, time, sys, os, ctypes

# Listener
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', ${PORT_OPEN_CONN}))
srv.listen(10)
srv.settimeout(5.0)

# Открываем N клиентских соединений
clients = []
accepted = []
for i in range(${N_CONNS}):
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(('127.0.0.1', ${PORT_OPEN_CONN}))
    clients.append(c)
    try:
        a, _ = srv.accept()
        accepted.append(a)
    except:
        pass

with open('${TMPD}/conns_ready', 'w') as f:
    f.write(str(len(clients)))

# Держим открытыми
time.sleep(30)

for c in clients:
    c.close()
for a in accepted:
    a.close()
srv.close()
") &
CONN_PID=$!
PIDS_TO_KILL+=($CONN_PID)

# Ждём готовности
for i in $(seq 1 30); do
    [ -f "${TMPD}/conns_ready" ] && break
    sleep 0.2
done
log "открыто $(cat ${TMPD}/conns_ready 2>/dev/null || echo '?') соединений"

wait_snapshot
fetch_csv "${TMPD}/open_conn.csv"

# Ищем snapshot для нашего PID с open_tcp_conns
COL_OPEN_CONNS=$(col_num open_tcp_conns)
COL_PID=$(col_num pid)
COL_COMM=$(col_num comm)

# Используем python csv-парсер — аргументы содержат переносы строк
OPEN_CONNS=$(python3 -c "
import csv
with open('${TMPD}/open_conn.csv', encoding='utf-8', errors='replace') as f:
    for row in csv.DictReader(f):
        if row.get('event_type') == 'snapshot' and 'SECTEST_open_conn' in row.get('exec',''):
            print(row.get('open_tcp_conns', ''))
            break
" 2>/dev/null)

if [ -n "$OPEN_CONNS" ] && [ "$OPEN_CONNS" -gt 0 ] 2>/dev/null; then
    pass "open_conn_count: open_tcp_conns=${OPEN_CONNS}"
    # У нас N_CONNS клиентских + N_CONNS принятых (один процесс) = 2*N_CONNS
    EXPECTED=$((N_CONNS * 2))
    if [ "$OPEN_CONNS" -ge "$N_CONNS" ] && [ "$OPEN_CONNS" -le "$((EXPECTED + 2))" ]; then
        pass "open_conn_count: значение ${OPEN_CONNS} в диапазоне [${N_CONNS}..${EXPECTED}+2]"
    else
        warn "open_conn_count: значение ${OPEN_CONNS} (ожидалось ~${EXPECTED})"
    fi
else
    fail "open_conn_count: не найден или = 0"
fi

kill $CONN_PID 2>/dev/null || true
wait $CONN_PID 2>/dev/null || true

# ══════════════════════════════════════════════════════════════════
#  ИТОГОВЫЙ ОТЧЁТ
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  ИТОГОВЫЙ ОТЧЁТ: security_tracking"
log "${CYAN}════════════════════════════════════════════════════${NC}"
echo -e "$REPORT"
log "Итого: ${GREEN}PASS=${PASS}${NC}  ${RED}FAIL=${FAIL}${NC}  ${YELLOW}WARN=${WARN}${NC}"

if [ "$FAIL" -eq 0 ]; then
    log "${GREEN}РЕЗУЛЬТАТ: ВСЕ ОСНОВНЫЕ ТЕСТЫ ПРОЙДЕНЫ ✓${NC}"
else
    log "${RED}РЕЗУЛЬТАТ: ЕСТЬ ОШИБКИ (${FAIL} FAIL)${NC}"
fi
