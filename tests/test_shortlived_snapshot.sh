#!/bin/bash
# test_shortlived_snapshot.sh — тест: короткоживущие процессы попадают в один snapshot
#
# Проверяет, что N процессов, созданных в одном snapshot-интервале,
# все оказываются в ровно одном snapshot (не размазываются по двум).
#
# Запуск:
#   sudo bash tests/test_shortlived_snapshot.sh [count] [lifetime_sec]
#     count        — количество процессов (по умолчанию 50)
#     lifetime_sec — время жизни каждого процесса в секундах (по умолчанию 2)
#
# Требования:
#   - Порт 19091 свободен
#   - Запуск от root (или sudo) для BPF
#   - Собранный бинарник: build/process_metrics
#
# Принцип работы:
#   1. Запускает process_metrics с snapshot_interval=3s и единственным
#      правилом regex="SNAPMARKER"
#   2. Дожидается стабилизации (2 snapshot-цикла)
#   3. Порождает N процессов: bash -c "exec -a 'SNAPMARKER_proc_N' sleep <lifetime>"
#      Каждый процесс меняет argv[0] на SNAPMARKER через exec -a, что позволяет
#      BPF handle_exec обнаружить его и сопоставить с правилом "test"
#   4. Ждёт завершения всех процессов + 2 snapshot-цикла
#   5. Проверяет CSV: все snapshot-события с rule=test должны иметь один timestamp

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/build/process_metrics"
CONF="${SCRIPT_DIR}/test_shortlived_snapshot.conf"
PORT=19091
URL="http://127.0.0.1:${PORT}/metrics?format=csv"
COUNT=${1:-50}
LIFETIME=${2:-2}
LOGFILE="/tmp/pm_shortlived_test.log"
CSVFILE="/tmp/pm_shortlived_test.csv"

# ── цвета ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }

cleanup() {
    if [ -n "${PM_PID:-}" ] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null
        wait "$PM_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── проверки ───────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "Требуется root. Запустите: sudo $0 $*"
    exit 1
fi

if [ ! -x "$BINARY" ]; then
    echo "Бинарник не найден: $BINARY"
    echo "Соберите: make -C $ROOT_DIR all"
    exit 1
fi

if ss -tlnp | grep -q ":${PORT} " 2>/dev/null; then
    echo "Порт $PORT занят. Освободите его и повторите."
    exit 1
fi

# ── запуск process_metrics ─────────────────────────────────────────
info "Запуск process_metrics (snapshot_interval=3s, port=$PORT)"
"$BINARY" -c "$CONF" >"$LOGFILE" 2>&1 &
PM_PID=$!
sleep 3

if ! kill -0 "$PM_PID" 2>/dev/null; then
    fail "process_metrics не запустился"
    cat "$LOGFILE"
    exit 1
fi

# Ждём стабилизации (2 snapshot-цикла × 3s)
sleep 7

# ── очистка буфера ─────────────────────────────────────────────────
curl -sf "${URL}&clear=1" >/dev/null
info "Буфер очищен"

# ── синхронизация со snapshot-границей ─────────────────────────────
# Ждём появление нового snapshot в логе, затем сразу спавним.
# Это гарантирует что процессы создаются В НАЧАЛЕ интервала,
# успевают завершиться, и попадают в ровно один snapshot (как exited).
info "Синхронизация со snapshot-границей ..."
SNAP_BEFORE=$(grep -c "snapshot:" "$LOGFILE" || true)
while true; do
    SNAP_NOW=$(grep -c "snapshot:" "$LOGFILE" || true)
    if [ "$SNAP_NOW" -gt "$SNAP_BEFORE" ]; then
        break
    fi
    sleep 0.1
done
# Очищаем ещё раз — убираем данные до нашего старта
curl -sf "${URL}&clear=1" >/dev/null

# ── генерация процессов ────────────────────────────────────────────
SPAWN_TS=$(date '+%H:%M:%S.%3N')
info "Порождаю $COUNT процессов (lifetime=${LIFETIME}s) в $SPAWN_TS ..."

PIDS=""
for i in $(seq 1 "$COUNT"); do
    /bin/bash -c "exec -a 'SNAPMARKER_proc_${i}' sleep $LIFETIME" &
    PIDS="$PIDS $!"
done

for p in $PIDS; do
    wait "$p" 2>/dev/null || true
done
END_TS=$(date '+%H:%M:%S.%3N')
info "Все $COUNT процессов завершены в $END_TS"

# ── ожидание snapshot-циклов ───────────────────────────────────────
# 2 цикла по 3s + запас
info "Ожидание snapshot-циклов (8s) ..."
sleep 8

# ── сбор и анализ CSV ──────────────────────────────────────────────
curl -sf "$URL" > "$CSVFILE"
TOTAL=$(($(wc -l < "$CSVFILE") - 1))

SNAP_ROWS=$(grep -c "snapshot,test" "$CSVFILE" || true)
EXEC_ROWS=$(grep -c "exec,test" "$CSVFILE" || true)
EXIT_ROWS=$(grep -c "exit,test" "$CSVFILE" || true)
SNAP_TIMESTAMPS=$(grep "snapshot,test" "$CSVFILE" | awk -F',' '{print $1}' | sort -u | wc -l)

echo ""
echo "════════════════════════════════════════════════════════"
echo " Результаты теста: короткоживущие процессы в snapshot"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  Процессов:     $COUNT (lifetime=${LIFETIME}s)"
echo "  CSV строк:     $TOTAL"
echo "  exec событий:  $EXEC_ROWS"
echo "  exit событий:  $EXIT_ROWS"
echo "  snapshot:       $SNAP_ROWS"
echo "  Уникальных snapshot timestamp: $SNAP_TIMESTAMPS"
echo ""

if [ "$SNAP_TIMESTAMPS" -gt 0 ]; then
    echo "  Snapshot timestamps:"
    grep "snapshot,test" "$CSVFILE" | awk -F',' '{print $1}' | sort | uniq -c | \
        while read -r cnt ts; do
            echo "    $ts  — $cnt процессов"
        done
    echo ""
fi

# ── вердикт ────────────────────────────────────────────────────────
ERRORS=0

if [ "$EXEC_ROWS" -ne "$COUNT" ]; then
    fail "exec событий: $EXEC_ROWS (ожидалось $COUNT)"
    ERRORS=$((ERRORS + 1))
else
    pass "exec событий: $EXEC_ROWS/$COUNT"
fi

if [ "$EXIT_ROWS" -ne "$COUNT" ]; then
    fail "exit событий: $EXIT_ROWS (ожидалось $COUNT)"
    ERRORS=$((ERRORS + 1))
else
    pass "exit событий: $EXIT_ROWS/$COUNT"
fi

if [ "$SNAP_ROWS" -ne "$COUNT" ]; then
    fail "snapshot событий: $SNAP_ROWS (ожидалось $COUNT)"
    ERRORS=$((ERRORS + 1))
else
    pass "snapshot событий: $SNAP_ROWS/$COUNT"
fi

if [ "$SNAP_TIMESTAMPS" -eq 1 ]; then
    pass "все snapshot в одном timestamp"
elif [ "$SNAP_TIMESTAMPS" -eq 0 ]; then
    fail "нет snapshot событий"
    ERRORS=$((ERRORS + 1))
else
    fail "snapshot размазаны по $SNAP_TIMESTAMPS timestamp'ам"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}═══ ТЕСТ ПРОЙДЕН ═══${NC}"
else
    echo -e "${RED}═══ ТЕСТ ПРОВАЛЕН ($ERRORS ошибок) ═══${NC}"
    echo ""
    echo "Лог process_metrics: $LOGFILE"
    echo "CSV данные: $CSVFILE"
fi

exit "$ERRORS"
