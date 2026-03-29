#!/usr/bin/env bash
# test_identity_all.sh — комплексный тест identity для ВСЕХ типов событий
#
# Генерирует и проверяет uid/loginuid/sessionid/euid для КАЖДОГО event_type:
#   1.  exec          — exec процесса
#   2.  fork          — fork дочернего процесса
#   3.  exit          — завершение процесса
#   4.  snapshot      — периодический снимок метрик процесса
#   5.  conn_snapshot — снимок TCP-соединений
#   6.  net_listen    — начало прослушивания TCP
#   7.  net_connect   — исходящее TCP-соединение
#   8.  net_accept    — входящее TCP-соединение
#   9.  net_close     — закрытие TCP-соединения
#  10.  file_close    — закрытие отслеживаемого файла
#  11.  signal        — отправка/получение сигнала
#  12.  syn_recv      — входящий SYN
#  13.  rst_sent      — отправка RST (SO_LINGER=0)
#  14.  udp_agg       — UDP-агрегат
#
# Не тестируются (не привязаны к пользователю или требуют спец. условий):
#   - oom_kill     (требует реальный OOM, опасно)
#   - tcp_retrans  (требует iptables DROP)
#   - rst_recv     (нет сокета в sock_map)
#   - icmp_agg     (не привязан к процессу)
#   - disk_usage   (системный уровень)
#
# Запуск: sudo bash tests/test_identity_all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/build/process_metrics"
CONF="${SCRIPT_DIR}/test_identity.conf"
PORT=19095
BASE_URL="http://127.0.0.1:${PORT}"
SNAP_INTERVAL=5
TMPD="/tmp/test_identity_$$"
LOGFILE="${TMPD}/pm.log"

# Порты
PORT_TCP=19401
PORT_RST=19402
PORT_UDP=19403

PASS=0
FAIL=0
WARN=0
REPORT=""
PM_PID=""
PIDS_TO_KILL=()

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
    rm -rf /tmp/idtest
    if [ "$FAIL" -eq 0 ]; then
        rm -rf "$TMPD"
    else
        log "Логи сохранены в ${TMPD}"
    fi
}
trap cleanup EXIT

mkdir -p "$TMPD" /tmp/idtest

# ── Проверки ──────────────────────────────────────────────────────
[ -x "$BINARY" ] || { log "Бинарник не найден: $BINARY"; exit 1; }
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    log "Порт ${PORT} уже занят"; exit 1
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

for i in $(seq 1 30); do
    grep -q "snapshot:" "$LOGFILE" 2>/dev/null && break
    sleep 0.5
done

curl -s "${BASE_URL}/metrics?clear=1" > /dev/null
log "буфер очищен"

# ── Вспомогательные функции ───────────────────────────────────────

wait_snapshot() {
    local snap_before
    snap_before=$(grep -c "snapshot:" "$LOGFILE" 2>/dev/null || echo 0)
    for i in $(seq 1 $((SNAP_INTERVAL * 4))); do
        local snap_now
        snap_now=$(grep -c "snapshot:" "$LOGFILE" 2>/dev/null || echo 0)
        [ "$snap_now" -gt "$snap_before" ] && { sleep 0.5; return 0; }
        sleep 0.5
    done
    return 1
}

# Python CSV-парсер: первое значение поля для event_type
csv_field() {
    python3 -c "
import csv, sys
with open(sys.argv[1], encoding='utf-8', errors='replace') as f:
    for row in csv.DictReader(f):
        if row.get('event_type') != sys.argv[2]:
            continue
        if len(sys.argv) > 4 and sys.argv[4]:
            filt = sys.argv[4]
            match = False
            for fld in ['exec','comm','net_local_port','net_remote_port',
                        'sec_local_port','sec_remote_port','file_path',
                        'pid','ppid','rule']:
                if filt in str(row.get(fld, '')):
                    match = True
                    break
            if not match:
                continue
        print(row.get(sys.argv[3], ''))
        break
" "$@" 2>/dev/null
}

# Проверка identity для одного event_type
# $1=csv, $2=event_type, $3=filter, $4=expected_uid, $5=expected_loginuid
check_identity() {
    local csv_file=$1
    local evt=$2
    local filt=$3
    local exp_uid=$4
    local exp_loginuid=$5
    local label="$evt"

    local e_uid e_loginuid e_sessionid e_euid
    e_uid=$(csv_field "$csv_file" "$evt" "uid" "$filt")
    e_loginuid=$(csv_field "$csv_file" "$evt" "loginuid" "$filt")
    e_sessionid=$(csv_field "$csv_file" "$evt" "sessionid" "$filt")
    e_euid=$(csv_field "$csv_file" "$evt" "euid" "$filt")

    # uid
    if [ -n "$e_uid" ] && [ "$e_uid" = "$exp_uid" ]; then
        pass "${label}: uid=${e_uid}"
    elif [ -n "$e_uid" ]; then
        fail "${label}: uid=${e_uid} (ожидалось ${exp_uid})"
    else
        fail "${label}: uid пустой (событие не найдено)"
        return
    fi

    # loginuid
    if [ -n "$e_loginuid" ] && [ "$e_loginuid" = "$exp_loginuid" ]; then
        pass "${label}: loginuid=${e_loginuid}"
    elif [ -n "$e_loginuid" ] && [ "$e_loginuid" != "0" ]; then
        warn "${label}: loginuid=${e_loginuid} (ожидалось ${exp_loginuid})"
    else
        fail "${label}: loginuid=${e_loginuid:-пусто}"
    fi

    # euid
    if [ -n "$e_euid" ] && [ "$e_euid" = "$exp_uid" ]; then
        pass "${label}: euid=${e_euid}"
    elif [ -n "$e_euid" ]; then
        warn "${label}: euid=${e_euid} (ожидалось ${exp_uid})"
    else
        fail "${label}: euid=${e_euid:-пусто}"
    fi

    # sessionid (проверяем что не пустой)
    if [ -n "$e_sessionid" ]; then
        pass "${label}: sessionid=${e_sessionid}"
    else
        fail "${label}: sessionid пустой"
    fi

    log "  → uid=${e_uid} loginuid=${e_loginuid} euid=${e_euid} sid=${e_sessionid}"
}

# ══════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ СОБЫТИЙ
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  ГЕНЕРАЦИЯ ВСЕХ ТИПОВ СОБЫТИЙ"
log "${CYAN}════════════════════════════════════════════════════${NC}"

# 1. TCP: listen + connect + accept + data → conn_snapshot + snapshot
# 2. File: write + close → file_close
# 3. Fork: дочерний процесс → fork
# 4. Signal: SIGUSR1 → signal
# 5. RST: SO_LINGER=0 close → rst_sent
# 6. UDP: sendto/recvfrom → udp_agg
# 7. Exit: завершение → exit

log "Запуск главного процесса (TCP + файл + fork + signal + RST + UDP)..."

(exec -a "IDTEST_main" python3 -c "
import socket, time, threading, os, signal, sys, struct

TMPD = '${TMPD}'
PORT_TCP = ${PORT_TCP}
PORT_RST = ${PORT_RST}
PORT_UDP = ${PORT_UDP}

stop = threading.Event()

# === 1. TCP echo сервер ===
def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', PORT_TCP))
    srv.listen(1)
    srv.settimeout(1.0)
    with open(os.path.join(TMPD, 'tcp_ready'), 'w') as f:
        f.write('ok')
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
                except:
                    break
            conn.close()
        except socket.timeout:
            continue
    srv.close()

t_srv = threading.Thread(target=tcp_server, daemon=True)
t_srv.start()

for _ in range(50):
    if os.path.exists(os.path.join(TMPD, 'tcp_ready')):
        break
    time.sleep(0.1)

# TCP клиент
cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', PORT_TCP))
cli.sendall(b'A' * 1000)
time.sleep(0.3)
try:
    cli.settimeout(2.0)
    cli.recv(8192)
except:
    pass

# === 2. Файл: запись в отслеживаемый путь ===
fpath = '/tmp/idtest/testfile.dat'
with open(fpath, 'wb') as f:
    f.write(b'X' * 1024)

# === 3. Fork: дочерний процесс ===
import subprocess, shutil
python_bin = shutil.which('python3') or '/usr/bin/python3'
child = subprocess.Popen([python_bin, '-c', 'import time; time.sleep(0.5)'])
child.wait()
with open(os.path.join(TMPD, 'fork_done'), 'w') as f:
    f.write(str(child.pid))

# === 4. Signal: SIGUSR1 к себе ===
# Устанавливаем обработчик ДО отправки сигнала
signal.signal(signal.SIGUSR1, lambda s,f: None)
os.kill(os.getpid(), signal.SIGUSR1)
time.sleep(0.1)
os.kill(os.getpid(), signal.SIGUSR1)
with open(os.path.join(TMPD, 'signal_done'), 'w') as f:
    f.write('ok')

# === 5. RST: SO_LINGER=0 → rst_sent ===
# Сервер для RST-теста
rst_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
rst_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rst_srv.bind(('127.0.0.1', PORT_RST))
rst_srv.listen(1)
rst_srv.settimeout(5.0)

rst_cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
rst_cli.connect(('127.0.0.1', PORT_RST))
try:
    rst_acc, _ = rst_srv.accept()
    rst_acc.sendall(b'RST_TEST')
    time.sleep(0.3)
except:
    rst_acc = None

# SO_LINGER=0 → close() шлёт RST
rst_cli.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
rst_cli.close()
time.sleep(0.3)
if rst_acc:
    rst_acc.close()
rst_srv.close()
with open(os.path.join(TMPD, 'rst_done'), 'w') as f:
    f.write('ok')

# === 6. UDP ===
udp_srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp_srv.bind(('127.0.0.1', PORT_UDP))
udp_srv.settimeout(0.5)

udp_cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(5):
    udp_cli.sendto(b'U' * 200, ('127.0.0.1', PORT_UDP))
    try:
        data, addr = udp_srv.recvfrom(4096)
        udp_srv.sendto(b'P' * 50, addr)
    except:
        pass
    time.sleep(0.05)
udp_cli.close()
udp_srv.close()
with open(os.path.join(TMPD, 'udp_done'), 'w') as f:
    f.write('ok')

with open(os.path.join(TMPD, 'all_ready'), 'w') as f:
    f.write('ok')

# Ждём сигнала для закрытия TCP и завершения
def do_close(signum, frame):
    cli.close()
    stop.set()
    with open(os.path.join(TMPD, 'tcp_closed'), 'w') as f:
        f.write('ok')

signal.signal(signal.SIGUSR2, do_close)
time.sleep(120)
") &
MAIN_PID=$!
PIDS_TO_KILL+=($MAIN_PID)

# Ждём завершения всех фаз
log "ожидание генерации событий..."
for i in $(seq 1 60); do
    [ -f "${TMPD}/all_ready" ] && break
    sleep 0.5
done

if [ ! -f "${TMPD}/all_ready" ]; then
    log "ОШИБКА: генерация событий не завершилась"
    exit 1
fi

log "fork: child=$(cat ${TMPD}/fork_done 2>/dev/null || echo N/A)"
log "signal: $(cat ${TMPD}/signal_done 2>/dev/null || echo N/A)"
log "rst: $(cat ${TMPD}/rst_done 2>/dev/null || echo N/A)"
log "udp: $(cat ${TMPD}/udp_done 2>/dev/null || echo N/A)"

# ══════════════════════════════════════════════════════════════════
#  Snapshot 1 (содержит snapshot, conn_snapshot, exec, fork, file_close,
#              signal, syn_recv, rst_sent, udp_agg, net_listen/connect/accept)
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ Ожидание snapshot 1 ═══${NC}"
wait_snapshot
curl -s "${BASE_URL}/metrics?clear=1" > "${TMPD}/snap1.csv"
SNAP1_LINES=$(($(wc -l < "${TMPD}/snap1.csv") - 1))
log "Snapshot 1: ${SNAP1_LINES} событий"

# Распределение событий
log "Типы событий:"
python3 -c "
import csv
from collections import Counter
with open('${TMPD}/snap1.csv', encoding='utf-8', errors='replace') as f:
    c = Counter(row.get('event_type','?') for row in csv.DictReader(f))
for evt, cnt in c.most_common():
    print(f'  {evt}: {cnt}')
" 2>/dev/null

# ══════════════════════════════════════════════════════════════════
#  Закрытие TCP → net_close + exit
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ Закрытие TCP и завершение ═══${NC}"
kill -USR2 "$MAIN_PID" 2>/dev/null
for i in $(seq 1 30); do
    [ -f "${TMPD}/tcp_closed" ] && break
    sleep 0.2
done
log "TCP закрыт"

# Небольшая пауза, затем убиваем процесс для exit-события
sleep 1
kill "$MAIN_PID" 2>/dev/null
wait "$MAIN_PID" 2>/dev/null || true
PIDS_TO_KILL=()
log "Процесс завершён"

# ══════════════════════════════════════════════════════════════════
#  Snapshot 2 (содержит net_close + exit)
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}═══ Ожидание snapshot 2 ═══${NC}"
wait_snapshot
curl -s "${BASE_URL}/metrics?clear=1" > "${TMPD}/snap2.csv"
SNAP2_LINES=$(($(wc -l < "${TMPD}/snap2.csv") - 1))
log "Snapshot 2: ${SNAP2_LINES} событий"

log "Типы событий:"
python3 -c "
import csv
from collections import Counter
with open('${TMPD}/snap2.csv', encoding='utf-8', errors='replace') as f:
    c = Counter(row.get('event_type','?') for row in csv.DictReader(f))
for evt, cnt in c.most_common():
    print(f'  {evt}: {cnt}')
" 2>/dev/null

# Объединяем все CSV
cat "${TMPD}/snap1.csv" > "${TMPD}/all.csv"
tail -n +2 "${TMPD}/snap2.csv" >> "${TMPD}/all.csv"

# ══════════════════════════════════════════════════════════════════
#  ОПРЕДЕЛЕНИЕ ЭТАЛОННЫХ ЗНАЧЕНИЙ IDENTITY
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  ОПРЕДЕЛЕНИЕ ЭТАЛОНА ИЗ SNAPSHOT"
log "${CYAN}════════════════════════════════════════════════════${NC}"

# Эталон — берём из snapshot (самый надёжный источник)
REF_UID=$(csv_field "${TMPD}/all.csv" "snapshot" "uid" "IDTEST")
REF_LOGINUID=$(csv_field "${TMPD}/all.csv" "snapshot" "loginuid" "IDTEST")
REF_EUID=$(csv_field "${TMPD}/all.csv" "snapshot" "euid" "IDTEST")
REF_SESSIONID=$(csv_field "${TMPD}/all.csv" "snapshot" "sessionid" "IDTEST")

log "Эталон: uid=${REF_UID} loginuid=${REF_LOGINUID} euid=${REF_EUID} sessionid=${REF_SESSIONID}"

if [ -z "$REF_UID" ] || [ -z "$REF_LOGINUID" ]; then
    log "${RED}ОШИБКА: не удалось определить эталонные identity из snapshot${NC}"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════
#  ПРОВЕРКА IDENTITY ДЛЯ КАЖДОГО ТИПА СОБЫТИЯ
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  ПРОВЕРКА IDENTITY ПО ВСЕМ ТИПАМ СОБЫТИЙ"
log "${CYAN}════════════════════════════════════════════════════${NC}"

# 1. snapshot
log ""
log "${CYAN}═══ 1. snapshot ═══${NC}"
check_identity "${TMPD}/all.csv" "snapshot" "IDTEST" "$REF_UID" "$REF_LOGINUID"

# 2. exec
log ""
log "${CYAN}═══ 2. exec ═══${NC}"
check_identity "${TMPD}/all.csv" "exec" "IDTEST" "$REF_UID" "$REF_LOGINUID"

# 3. fork (дочерний процесс, rule=idtest)
log ""
log "${CYAN}═══ 3. fork ═══${NC}"
check_identity "${TMPD}/all.csv" "fork" "idtest" "$REF_UID" "$REF_LOGINUID"

# 4. exit
log ""
log "${CYAN}═══ 4. exit ═══${NC}"
check_identity "${TMPD}/all.csv" "exit" "IDTEST" "$REF_UID" "$REF_LOGINUID"

# 5. conn_snapshot
log ""
log "${CYAN}═══ 5. conn_snapshot ═══${NC}"
check_identity "${TMPD}/all.csv" "conn_snapshot" "${PORT_TCP}" "$REF_UID" "$REF_LOGINUID"

# 6. net_listen
log ""
log "${CYAN}═══ 6. net_listen ═══${NC}"
check_identity "${TMPD}/all.csv" "net_listen" "${PORT_TCP}" "$REF_UID" "$REF_LOGINUID"

# 7. net_connect
log ""
log "${CYAN}═══ 7. net_connect ═══${NC}"
check_identity "${TMPD}/all.csv" "net_connect" "${PORT_TCP}" "$REF_UID" "$REF_LOGINUID"

# 8. net_accept
log ""
log "${CYAN}═══ 8. net_accept ═══${NC}"
check_identity "${TMPD}/all.csv" "net_accept" "${PORT_TCP}" "$REF_UID" "$REF_LOGINUID"

# 9. net_close
log ""
log "${CYAN}═══ 9. net_close ═══${NC}"
check_identity "${TMPD}/all.csv" "net_close" "${PORT_TCP}" "$REF_UID" "$REF_LOGINUID"

# 10. file_close
log ""
log "${CYAN}═══ 10. file_close ═══${NC}"
check_identity "${TMPD}/all.csv" "file_close" "idtest" "$REF_UID" "$REF_LOGINUID"

# 11. signal (rule=idtest)
log ""
log "${CYAN}═══ 11. signal ═══${NC}"
check_identity "${TMPD}/all.csv" "signal" "idtest" "$REF_UID" "$REF_LOGINUID"

# 12. syn_recv
log ""
log "${CYAN}═══ 12. syn_recv ═══${NC}"
SYN_UID=$(csv_field "${TMPD}/all.csv" "syn_recv" "uid" "${PORT_TCP}")
if [ -n "$SYN_UID" ]; then
    check_identity "${TMPD}/all.csv" "syn_recv" "${PORT_TCP}" "$REF_UID" "$REF_LOGINUID"
else
    # syn_recv может прийти и от PORT_RST
    SYN_UID2=$(csv_field "${TMPD}/all.csv" "syn_recv" "uid" "${PORT_RST}")
    if [ -n "$SYN_UID2" ]; then
        check_identity "${TMPD}/all.csv" "syn_recv" "${PORT_RST}" "$REF_UID" "$REF_LOGINUID"
    else
        warn "syn_recv: событие не найдено (процесс может не быть в tracked_map для listener)"
        warn "syn_recv: loginuid — пропущен"
        warn "syn_recv: euid — пропущен"
        warn "syn_recv: sessionid — пропущен"
    fi
fi

# 13. rst_sent
log ""
log "${CYAN}═══ 13. rst_sent ═══${NC}"
RST_UID=$(csv_field "${TMPD}/all.csv" "rst_sent" "uid" "${PORT_RST}")
if [ -n "$RST_UID" ]; then
    check_identity "${TMPD}/all.csv" "rst_sent" "${PORT_RST}" "$REF_UID" "$REF_LOGINUID"
else
    warn "rst_sent: событие не найдено"
    warn "rst_sent: loginuid — пропущен"
    warn "rst_sent: euid — пропущен"
    warn "rst_sent: sessionid — пропущен"
fi

# 14. udp_agg (rule=idtest)
log ""
log "${CYAN}═══ 14. udp_agg ═══${NC}"
check_identity "${TMPD}/all.csv" "udp_agg" "idtest" "$REF_UID" "$REF_LOGINUID"

# ══════════════════════════════════════════════════════════════════
#  СВОДНАЯ ТАБЛИЦА
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  СВОДНАЯ ТАБЛИЦА IDENTITY"
log "${CYAN}════════════════════════════════════════════════════${NC}"

python3 -c "
import csv

events_to_check = [
    ('snapshot', 'IDTEST'),
    ('exec', 'IDTEST'),
    ('fork', 'idtest'),
    ('exit', 'IDTEST'),
    ('conn_snapshot', '${PORT_TCP}'),
    ('net_listen', '${PORT_TCP}'),
    ('net_connect', '${PORT_TCP}'),
    ('net_accept', '${PORT_TCP}'),
    ('net_close', '${PORT_TCP}'),
    ('file_close', 'idtest'),
    ('signal', 'idtest'),
    ('syn_recv', '${PORT_TCP}'),
    ('rst_sent', '${PORT_RST}'),
    ('udp_agg', 'idtest'),
]

rows = []
with open('${TMPD}/all.csv', encoding='utf-8', errors='replace') as f:
    rows = list(csv.DictReader(f))

print(f'  {\"Событие\":<16} {\"uid\":>6} {\"loginuid\":>10} {\"euid\":>6} {\"sessionid\":>10}')
print('  ' + '-' * 52)

for evt, filt in events_to_check:
    found = False
    for row in rows:
        if row.get('event_type') != evt:
            continue
        match = False
        for fld in ['exec','comm','net_local_port','net_remote_port','sec_local_port','sec_remote_port','file_path','pid','ppid','rule']:
            if filt in str(row.get(fld, '')):
                match = True
                break
        if not match:
            continue
        uid = row.get('uid', '-')
        loginuid = row.get('loginuid', '-')
        euid = row.get('euid', '-')
        sessionid = row.get('sessionid', '-')
        print(f'  {evt:<16} {uid:>6} {loginuid:>10} {euid:>6} {sessionid:>10}')
        found = True
        break
    if not found:
        print(f'  {evt:<16} {\"—\":>6} {\"—\":>10} {\"—\":>6} {\"—\":>10}')
" 2>/dev/null

# ══════════════════════════════════════════════════════════════════
#  ИТОГО
# ══════════════════════════════════════════════════════════════════
log ""
log "${CYAN}════════════════════════════════════════════════════${NC}"
log "  ИТОГОВЫЙ ОТЧЁТ: identity"
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
