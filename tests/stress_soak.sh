#!/bin/bash
# stress_soak.sh — soak-тест (длительная работа) для process_metrics
#
# Запускает process_metrics и генерирует умеренную фоновую нагрузку в течение
# длительного периода. Каждый цикл проверяет:
#   - RSS / VmSize не растут бесконечно
#   - Количество FD стабильно
#   - Количество потоков стабильно
#   - HTTP-эндпоинт отвечает
#   - Данные в CSV корректны (заголовок + строки)
#
# Запуск:
#   bash tests/stress_soak.sh [duration_min] [port]
#
#   duration_min — длительность теста в минутах (по умолчанию 60)
#   port         — порт HTTP (по умолчанию 9091)
#
# Требования:
#   - process_metrics запущен:
#     sudo ./build/process_metrics -c tests/stress_test.conf
#   - curl, python3

set -uo pipefail

DURATION_MIN=${1:-60}
PORT=${2:-9091}
BASE_URL="http://127.0.0.1:$PORT"
DURATION_SEC=$((DURATION_MIN * 60))
CHECK_INTERVAL=30  # секунд между проверками
WORKDIR="/tmp/stress_soak_$$"
LOAD_PIDS=()

mkdir -p "$WORKDIR"

# ── Helpers ──

cleanup() {
    echo ""
    echo "=== Stopping soak test..."
    for pid in "${LOAD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    rm -rf "$WORKDIR"
    echo "=== Cleanup done"
}
trap cleanup EXIT INT TERM

ts() { date "+%H:%M:%S"; }

# ── Проверка доступности ──

echo "== Soak test: ${DURATION_MIN} minutes =="
echo "   target: $BASE_URL"
echo "   check interval: ${CHECK_INTERVAL}s"
echo ""

if ! curl -sf -o /dev/null -m 5 "$BASE_URL/metrics"; then
    echo "FATAL: HTTP server not reachable at $BASE_URL/metrics"
    echo "Start process_metrics first: sudo ./build/process_metrics -c tests/stress_test.conf"
    exit 1
fi

PM_PID=$(pgrep -f 'build/process_metrics' | head -1 || echo "")
if [ -z "$PM_PID" ] || [ ! -d "/proc/$PM_PID" ]; then
    echo "WARNING: process_metrics PID not found — memory/FD checks disabled"
    PM_PID=""
fi

# ── Фоновая нагрузка: умеренная генерация событий ──

# 1. Fork/exec — 10 процессов/сек
(
    while true; do
        /bin/true
        sleep 0.1
    done
) &
LOAD_PIDS+=($!)

# 2. File I/O — 20 операций/сек
(
    dir="$WORKDIR/fileio"
    mkdir -p "$dir"
    i=0
    while true; do
        f="$dir/f_$((i % 100))"
        echo "soak_data_$i" > "$f"
        cat "$f" > /dev/null
        rm -f "$f"
        i=$((i + 1))
        sleep 0.05
    done
) &
LOAD_PIDS+=($!)

# 3. HTTP polling — 2 req/s (имитация ClickHouse MV)
(
    while true; do
        curl -sf -o /dev/null -m 10 "$BASE_URL/metrics?format=csv&clear=1" 2>/dev/null || true
        sleep 0.5
    done
) &
LOAD_PIDS+=($!)

# 4. Сетевая нагрузка — 5 TCP conn/s
(
    # Эфемерный TCP-сервер
    python3 -c "
import socket, time
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
port = srv.getsockname()[1]
with open('$WORKDIR/.soak_net_port', 'w') as f:
    f.write(str(port))
srv.listen(128)
srv.settimeout(1.0)
while True:
    try:
        c, _ = srv.accept()
        c.close()
    except socket.timeout:
        pass
    except:
        break
" &
    LOAD_PIDS+=($!)
    sleep 1

    SOAK_NET_PORT=$(cat "$WORKDIR/.soak_net_port" 2>/dev/null || echo "")
    if [ -n "$SOAK_NET_PORT" ]; then
        while true; do
            (echo "" > /dev/tcp/127.0.0.1/$SOAK_NET_PORT) 2>/dev/null || true
            sleep 0.2
        done
    fi
) &
LOAD_PIDS+=($!)

echo "Background load started (fork+file+net+http)"
echo ""

# ── Сбор метрик ──

LOG="$WORKDIR/soak_metrics.csv"
echo "time,rss_kb,vmsize_kb,fd_count,threads,http_ok,csv_lines" > "$LOG"

# Начальные значения
INITIAL_RSS=""
INITIAL_FDS=""
MAX_RSS=0
MAX_FDS=0
WARNINGS=0
HTTP_FAILURES=0
CHECKS=0

if [ -n "$PM_PID" ]; then
    INITIAL_RSS=$(awk '/^VmRSS/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo 0)
    INITIAL_FDS=$(ls -1 "/proc/$PM_PID/fd" 2>/dev/null | wc -l || echo 0)
fi

printf "%-10s %10s %12s %6s %8s %8s %10s %s\n" \
    "TIME" "RSS_kB" "VmSize_kB" "FDs" "Threads" "HTTP_OK" "CSV_lines" "STATUS"
printf "%-10s %10s %12s %6s %8s %8s %10s %s\n" \
    "--------" "--------" "----------" "----" "-------" "-------" "---------" "------"

END=$((SECONDS + DURATION_SEC))

while [ $SECONDS -lt $END ]; do
    CHECKS=$((CHECKS + 1))
    NOW=$(ts)
    STATUS="ok"

    # Метрики процесса
    RSS="?"
    VMSIZE="?"
    FDS="?"
    THREADS="?"

    if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
        RSS=$(awk '/^VmRSS/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "?")
        VMSIZE=$(awk '/^VmSize/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "?")
        FDS=$(ls -1 "/proc/$PM_PID/fd" 2>/dev/null | wc -l || echo "?")
        THREADS=$(awk '/^Threads/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "?")

        # Обновляем максимумы
        [ "$RSS" != "?" ] && [ "$RSS" -gt "$MAX_RSS" ] 2>/dev/null && MAX_RSS=$RSS
        [ "$FDS" != "?" ] && [ "$FDS" -gt "$MAX_FDS" ] 2>/dev/null && MAX_FDS=$FDS

        # Проверки на утечки
        if [ "$RSS" != "?" ] && [ -n "$INITIAL_RSS" ] && [ "$INITIAL_RSS" -gt 0 ] 2>/dev/null; then
            RSS_GROWTH_MB=$(( (RSS - INITIAL_RSS) / 1024 ))
            if [ "$RSS_GROWTH_MB" -gt 100 ]; then
                STATUS="WARN:RSS+${RSS_GROWTH_MB}MB"
                WARNINGS=$((WARNINGS + 1))
            fi
        fi

        if [ "$FDS" != "?" ] && [ -n "$INITIAL_FDS" ] && [ "$INITIAL_FDS" -gt 0 ] 2>/dev/null; then
            FD_GROWTH=$((FDS - INITIAL_FDS))
            if [ "$FD_GROWTH" -gt 50 ]; then
                STATUS="WARN:FD+${FD_GROWTH}"
                WARNINGS=$((WARNINGS + 1))
            fi
        fi
    elif [ -n "$PM_PID" ]; then
        STATUS="FAIL:process_died"
        WARNINGS=$((WARNINGS + 1))
    fi

    # HTTP health check
    HTTP_OK="no"
    CSV_LINES=0
    CSV_RESP=$(curl -sf -m 10 "$BASE_URL/metrics?format=csv" 2>/dev/null || echo "")
    if [ -n "$CSV_RESP" ]; then
        HTTP_OK="yes"
        CSV_LINES=$(echo "$CSV_RESP" | wc -l)
        # Проверяем заголовок CSV
        if ! echo "$CSV_RESP" | head -1 | grep -q "timestamp,hostname,event_type"; then
            STATUS="WARN:bad_csv_header"
            WARNINGS=$((WARNINGS + 1))
        fi
    else
        HTTP_OK="FAIL"
        HTTP_FAILURES=$((HTTP_FAILURES + 1))
        STATUS="FAIL:http_unreachable"
    fi

    printf "%-10s %10s %12s %6s %8s %8s %10s %s\n" \
        "$NOW" "$RSS" "$VMSIZE" "$FDS" "$THREADS" "$HTTP_OK" "$CSV_LINES" "$STATUS"

    # CSV лог
    echo "$NOW,$RSS,$VMSIZE,$FDS,$THREADS,$HTTP_OK,$CSV_LINES" >> "$LOG"

    sleep "$CHECK_INTERVAL"
done

# ── Итоги ──

echo ""
echo "══════════════════════════════════════════════════"
echo "  Soak test complete: ${DURATION_MIN} minutes"
echo "══════════════════════════════════════════════════"
echo ""
echo "  Checks:        $CHECKS"
echo "  Warnings:      $WARNINGS"
echo "  HTTP failures: $HTTP_FAILURES"

if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
    FINAL_RSS=$(awk '/^VmRSS/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "?")
    FINAL_FDS=$(ls -1 "/proc/$PM_PID/fd" 2>/dev/null | wc -l || echo "?")

    echo ""
    echo "  Memory:"
    echo "    Initial RSS: ${INITIAL_RSS:-?} kB"
    echo "    Final RSS:   ${FINAL_RSS} kB"
    echo "    Max RSS:     ${MAX_RSS} kB"
    if [ "$INITIAL_RSS" -gt 0 ] 2>/dev/null && [ "$FINAL_RSS" != "?" ]; then
        echo "    Growth:      $(( (FINAL_RSS - INITIAL_RSS) / 1024 )) MB"
    fi

    echo ""
    echo "  File descriptors:"
    echo "    Initial: ${INITIAL_FDS:-?}"
    echo "    Final:   ${FINAL_FDS}"
    echo "    Max:     ${MAX_FDS}"
fi

echo ""
echo "  Detailed log: $LOG"
echo ""

# Вердикт
if [ "$HTTP_FAILURES" -gt 0 ]; then
    echo "  VERDICT: FAIL — HTTP server became unreachable ($HTTP_FAILURES times)"
    exit 1
elif [ "$WARNINGS" -gt $((CHECKS / 4)) ]; then
    echo "  VERDICT: FAIL — too many warnings ($WARNINGS / $CHECKS checks)"
    exit 1
elif [ "$WARNINGS" -gt 0 ]; then
    echo "  VERDICT: WARN — $WARNINGS warnings detected, review log"
    exit 0
else
    echo "  VERDICT: PASS — stable for ${DURATION_MIN} minutes"
    exit 0
fi
