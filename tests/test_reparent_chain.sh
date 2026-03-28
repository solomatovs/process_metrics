#!/bin/bash
# test_reparent_chain.sh — тест: поведение parent_pids при разрыве цепочки
#
# Создаёт цепочку A → B → C → D, убивает B (середину),
# ядро переназначает C → init (или subreaper).
# Проверяет что parent_pids в snapshot отражает изменение.
#
# Запуск: sudo bash tests/test_reparent_chain.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="${ROOT_DIR}/build/process_metrics"
CONF="${SCRIPT_DIR}/test_shortlived_snapshot.conf"
PORT=19091
URL="http://127.0.0.1:${PORT}/metrics?format=csv"
LOGFILE="/tmp/pm_reparent_test.log"
CSVFILE="/tmp/pm_reparent_test.csv"
PIDDIR="/tmp/pm_reparent_pids"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }
head_() { echo -e "${CYAN}── $1 ──${NC}"; }

cleanup() {
    for f in "$PIDDIR"/*; do
        [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true
    done
    if [ -n "${PM_PID:-}" ] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null; wait "$PM_PID" 2>/dev/null || true
    fi
    rm -rf "$PIDDIR" /tmp/pm_reparent_*.sh
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then echo "Требуется root: sudo $0"; exit 1; fi
if [ ! -x "$BINARY" ]; then echo "Нет бинарника: $BINARY"; exit 1; fi
if ss -tlnp | grep -q ":${PORT} " 2>/dev/null; then echo "Порт $PORT занят"; exit 1; fi

rm -rf "$PIDDIR"; mkdir -p "$PIDDIR"

# ── вспомогательные скрипты для цепочки ────────────────────────────
# D: leaf — просто sleep
cat > /tmp/pm_reparent_d.sh << 'SCRIPT_D'
#!/bin/bash
exec -a 'SNAPMARKER_D_leaf' sleep 300
SCRIPT_D

# C: запускает D, пишет PID D, ждёт
cat > /tmp/pm_reparent_c.sh << 'SCRIPT_C'
#!/bin/bash
exec -a 'SNAPMARKER_C_mid' bash -c '
    bash /tmp/pm_reparent_d.sh &
    echo $! > /tmp/pm_reparent_pids/D
    wait
'
SCRIPT_C

# B: запускает C, пишет PID C, ждёт
cat > /tmp/pm_reparent_b.sh << 'SCRIPT_B'
#!/bin/bash
exec -a 'SNAPMARKER_B_mid' bash -c '
    bash /tmp/pm_reparent_c.sh &
    echo $! > /tmp/pm_reparent_pids/C
    wait
'
SCRIPT_B

chmod +x /tmp/pm_reparent_{b,c,d}.sh

# ── запуск process_metrics ─────────────────────────────────────────
info "Запуск process_metrics"
"$BINARY" -c "$CONF" >"$LOGFILE" 2>&1 &
PM_PID=$!
sleep 3
if ! kill -0 "$PM_PID" 2>/dev/null; then
    fail "process_metrics не запустился"; cat "$LOGFILE"; exit 1
fi
sleep 7  # стабилизация

# Синхронизация со snapshot
SNAP_BEFORE=$(grep -c "snapshot:" "$LOGFILE" || true)
while true; do
    SNAP_NOW=$(grep -c "snapshot:" "$LOGFILE" || true)
    [ "$SNAP_NOW" -gt "$SNAP_BEFORE" ] && break
    sleep 0.1
done
curl -sf "${URL}&clear=1" >/dev/null

# ── создание цепочки A → B → C → D ────────────────────────────────
info "Создаю цепочку A → B → C → D"

bash /tmp/pm_reparent_b.sh &
PID_A=$!
echo $PID_A > "$PIDDIR/A"

# Ждём появления PID'ов
for name in C D; do
    for _ in $(seq 1 50); do
        [ -f "$PIDDIR/$name" ] && break
        sleep 0.1
    done
done

sleep 1  # даём время на exec -a

PID_B=$(cat "$PIDDIR/A")  # B это exec -a от A — тот же PID после exec
PID_C=$(cat "$PIDDIR/C" 2>/dev/null || echo "?")
PID_D=$(cat "$PIDDIR/D" 2>/dev/null || echo "?")

# Найдём реальные PID'ы через /proc — ищем SNAPMARKER в cmdline
find_pid() {
    local marker="$1"
    for p in /proc/[0-9]*/cmdline; do
        local pid=$(echo "$p" | cut -d/ -f3)
        if tr '\0' ' ' < "$p" 2>/dev/null | grep -q "$marker"; then
            echo "$pid"
            return
        fi
    done
    echo "?"
}

PID_B_REAL=$(find_pid "SNAPMARKER_B_mid")
PID_C_REAL=$(find_pid "SNAPMARKER_C_mid")
PID_D_REAL=$(find_pid "SNAPMARKER_D_leaf")

info "PID'ы из /proc:"
info "  B (SNAPMARKER_B_mid)  = $PID_B_REAL"
info "  C (SNAPMARKER_C_mid)  = $PID_C_REAL"
info "  D (SNAPMARKER_D_leaf) = $PID_D_REAL"

if [ "$PID_D_REAL" = "?" ]; then
    fail "Не удалось найти процесс D"; exit 1
fi

# Проверяем реальную цепочку через /proc
PPID_D=$(awk '{print $4}' /proc/$PID_D_REAL/stat 2>/dev/null || echo "?")
PPID_C=$(awk '{print $4}' /proc/$PID_C_REAL/stat 2>/dev/null || echo "?")
PPID_B=$(awk '{print $4}' /proc/$PID_B_REAL/stat 2>/dev/null || echo "?")

info "Реальная цепочка (ядро):"
info "  D($PID_D_REAL) → ppid=$PPID_D"
info "  C($PID_C_REAL) → ppid=$PPID_C"
info "  B($PID_B_REAL) → ppid=$PPID_B"

# ── snapshot ДО kill ───────────────────────────────────────────────
head_ "Ожидание snapshot ДО kill"
sleep 5

curl -sf "$URL" > "${CSVFILE}.before"

# Ищем parent_pids для D
BEFORE_D=$(grep "snapshot,test" "${CSVFILE}.before" | grep ",${PID_D_REAL}," | head -1)
BEFORE_CHAIN=$(echo "$BEFORE_D" | awk -F',' '{print $NF}' | tr -d '"')

info "parent_pids D($PID_D_REAL) ДО kill: $BEFORE_CHAIN"

# B должен быть в цепочке D
if echo "$BEFORE_CHAIN" | grep -q "$PID_B_REAL"; then
    pass "B ($PID_B_REAL) в цепочке D до kill"
else
    fail "B ($PID_B_REAL) НЕ в цепочке D до kill"
    info "Цепочка: $BEFORE_CHAIN"
fi

# C должен быть в цепочке D
if echo "$BEFORE_CHAIN" | grep -q "$PID_C_REAL"; then
    pass "C ($PID_C_REAL) в цепочке D до kill"
else
    fail "C ($PID_C_REAL) НЕ в цепочке D до kill"
fi

# ── kill B (середина цепочки) ──────────────────────────────────────
head_ "kill -9 B (PID $PID_B_REAL)"
kill -9 "$PID_B_REAL" 2>/dev/null || true
sleep 1

# Проверяем reparenting
PPID_C_AFTER=$(awk '{print $4}' /proc/$PID_C_REAL/stat 2>/dev/null || echo "dead")
PPID_D_AFTER=$(awk '{print $4}' /proc/$PID_D_REAL/stat 2>/dev/null || echo "dead")
info "После kill B:"
info "  C($PID_C_REAL) → ppid=$PPID_C_AFTER (было $PPID_C)"
info "  D($PID_D_REAL) → ppid=$PPID_D_AFTER (было $PPID_D, не должно измениться)"

# ── snapshot ПОСЛЕ kill ────────────────────────────────────────────
head_ "Ожидание snapshot ПОСЛЕ kill"
# НЕ очищаем буфер — exit B может быть уже там.
# Ждём 2 refresh+snapshot цикла (3s × 2) чтобы reparent обнаружился.
sleep 7

curl -sf "$URL" > "${CSVFILE}.after"

# Берём ПОСЛЕДНИЙ snapshot для D — он отражает состояние после reparent
AFTER_D=$(grep "snapshot,test" "${CSVFILE}.after" | grep ",${PID_D_REAL}," | tail -1)
AFTER_CHAIN=$(echo "$AFTER_D" | awk -F',' '{print $NF}' | tr -d '"')

info "parent_pids D($PID_D_REAL) ПОСЛЕ kill B: $AFTER_CHAIN"

# ── итоговый анализ ────────────────────────────────────────────────
echo ""
head_ "Итоговый анализ"

echo ""
echo "  Реальная цепочка (ядро) после kill B:"
echo "    D($PID_D_REAL) → C($PID_C_REAL) → ppid=$PPID_C_AFTER"
echo ""
echo "  Цепочка в process_metrics:"
echo "    ДО:    $BEFORE_CHAIN"
echo "    ПОСЛЕ: $AFTER_CHAIN"

echo ""
head_ "Проверки"
ERRORS=0

# 1. D должен быть жив
D_ALIVE=$(grep "snapshot,test" "${CSVFILE}.after" | grep -c ",${PID_D_REAL}," || true)
if [ "$D_ALIVE" -gt 0 ]; then
    pass "D ($PID_D_REAL) отслеживается после reparent"
else
    fail "D ($PID_D_REAL) потерян после reparent"
    ERRORS=$((ERRORS + 1))
fi

# 2. C должен быть жив
C_ALIVE=$(grep "snapshot,test" "${CSVFILE}.after" | grep -c ",${PID_C_REAL}," || true)
if [ "$C_ALIVE" -gt 0 ]; then
    pass "C ($PID_C_REAL) отслеживается после reparent"
else
    fail "C ($PID_C_REAL) потерян после reparent"
    ERRORS=$((ERRORS + 1))
fi

# 3. B должен быть в exit-событиях (может быть в before, after или уже слит)
B_EXIT=$(cat "${CSVFILE}.before" "${CSVFILE}.after" 2>/dev/null | grep "exit,test" | grep -c ",${PID_B_REAL}," || true)
if [ "$B_EXIT" -gt 0 ]; then
    pass "B ($PID_B_REAL) имеет exit-событие"
else
    # B мог не попасть в CSV если был убит до buffer clear — проверяем лог
    B_LOG=$(grep -c "EXIT.*pid=${PID_B_REAL}" "$LOGFILE" 2>/dev/null || true)
    if [ "$B_LOG" -gt 0 ]; then
        pass "B ($PID_B_REAL) exit зафиксирован в логе (CSV очищен до события)"
    else
        fail "B ($PID_B_REAL) exit-событие не найдено"
        ERRORS=$((ERRORS + 1))
    fi
fi

# 4. Главное: B НЕ должен быть в цепочке D ПОСЛЕ kill (reparent detection)
if echo "$AFTER_CHAIN" | grep -q "$PID_B_REAL"; then
    fail "B ($PID_B_REAL) остался в цепочке D — reparent не обнаружен"
    ERRORS=$((ERRORS + 1))
else
    pass "B ($PID_B_REAL) удалён из цепочки D — reparent обнаружен"
fi

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}═══ ТЕСТ ЗАВЕРШЁН (все процессы сохранены) ═══${NC}"
else
    echo -e "${RED}═══ ТЕСТ: $ERRORS ОШИБОК ═══${NC}"
fi

echo ""
echo "Файлы: ${CSVFILE}.before  ${CSVFILE}.after  $LOGFILE"
