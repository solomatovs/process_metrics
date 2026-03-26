#!/bin/bash
# stress_generate.sh — генератор нагрузки для стресс-тестирования ring buffer'ов
#
# Запуск: bash tests/stress_generate.sh [duration_sec] [intensity]
#   duration_sec — длительность теста (по умолчанию 30)
#   intensity    — low/medium/high/extreme (по умолчанию medium)
#
# Генерирует три типа нагрузки параллельно:
#   1. fork/exec шторм — массовое порождение короткоживущих процессов
#   2. file I/O шторм  — массовое открытие/запись/закрытие файлов
#   3. network шторм   — массовое создание TCP-соединений
#
# После завершения выводит сводку.

set -euo pipefail

DURATION=${1:-30}
INTENSITY=${2:-medium}
WORKDIR="/tmp/stress_test"
PIDS=()

mkdir -p "$WORKDIR"

case "$INTENSITY" in
    low)
        FORK_WORKERS=2;  FORK_RATE=50
        FILE_WORKERS=2;  FILE_RATE=100
        NET_WORKERS=2;   NET_RATE=50
        ;;
    medium)
        FORK_WORKERS=4;  FORK_RATE=200
        FILE_WORKERS=4;  FILE_RATE=500
        NET_WORKERS=4;   NET_RATE=200
        ;;
    high)
        FORK_WORKERS=8;  FORK_RATE=500
        FILE_WORKERS=8;  FILE_RATE=2000
        NET_WORKERS=8;   NET_RATE=500
        ;;
    extreme)
        FORK_WORKERS=16; FORK_RATE=2000
        FILE_WORKERS=16; FILE_RATE=5000
        NET_WORKERS=16;  NET_RATE=2000
        ;;
    *)
        echo "Unknown intensity: $INTENSITY (use low/medium/high/extreme)"
        exit 1
        ;;
esac

cleanup() {
    echo ""
    echo "=== Stopping generators..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    rm -rf "$WORKDIR"
    echo "=== Cleanup done"
}
trap cleanup EXIT INT TERM

echo "=== Stress test: duration=${DURATION}s intensity=${INTENSITY}"
echo "    fork: ${FORK_WORKERS} workers x ${FORK_RATE}/s"
echo "    file: ${FILE_WORKERS} workers x ${FILE_RATE}/s"
echo "    net:  ${NET_WORKERS} workers x ${NET_RATE}/s"
echo ""

# ── 1. Fork/exec storm ──────────────────────────────────────────────
# Каждый воркер в цикле делает fork+exec короткоживущего процесса
fork_worker() {
    local rate=$1
    local delay
    delay=$(awk "BEGIN{printf \"%.6f\", 1.0/$rate}")
    local end=$((SECONDS + DURATION))
    local count=0
    while [ $SECONDS -lt $end ]; do
        # exec /bin/true — минимальный процесс, создаёт exec+exit события
        /bin/true &
        wait $! 2>/dev/null || true
        count=$((count + 1))
        # Грубый rate limit через usleep
        sleep "$delay" 2>/dev/null || true
    done
    echo "fork_worker: $count exec+exit events"
}

for i in $(seq 1 $FORK_WORKERS); do
    fork_worker $FORK_RATE &
    PIDS+=($!)
done

# ── 2. File I/O storm ───────────────────────────────────────────────
# Каждый воркер создаёт/пишет/закрывает файлы в /tmp/stress_test/
file_worker() {
    local rate=$1
    local id=$2
    local delay
    delay=$(awk "BEGIN{printf \"%.6f\", 1.0/$rate}")
    local end=$((SECONDS + DURATION))
    local count=0
    while [ $SECONDS -lt $end ]; do
        local f="$WORKDIR/file_${id}_${count}"
        echo "stress_worker_file_data_${count}" > "$f"
        cat "$f" > /dev/null
        rm -f "$f"
        count=$((count + 1))
        sleep "$delay" 2>/dev/null || true
    done
    echo "file_worker[$id]: $count open+write+close cycles"
}

for i in $(seq 1 $FILE_WORKERS); do
    file_worker $FILE_RATE $i &
    PIDS+=($!)
done

# ── 3. Network storm ────────────────────────────────────────────────
# Каждый воркер создаёт TCP-соединения к localhost на эфемерном порту
# Используем простой TCP connect+close через /dev/tcp или nc

# Запускаем временный TCP-сервер для приёма соединений
python3 -c "
import socket, threading, time, sys

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 0))
port = srv.getsockname()[1]
print(port, flush=True)
srv.listen(4096)
srv.settimeout(1.0)

end_time = time.time() + int(sys.argv[1]) + 5
while time.time() < end_time:
    try:
        conn, _ = srv.accept()
        conn.close()
    except socket.timeout:
        pass
srv.close()
" "$DURATION" > "$WORKDIR/.server_port" &
SERVER_PID=$!
PIDS+=($SERVER_PID)

# Ждём порт
sleep 0.5
NET_PORT=$(cat "$WORKDIR/.server_port" 2>/dev/null || echo "")
if [ -z "$NET_PORT" ]; then
    echo "WARNING: TCP server failed to start, skipping net stress"
else
    net_worker() {
        local rate=$1
        local port=$2
        local delay
        delay=$(awk "BEGIN{printf \"%.6f\", 1.0/$rate}")
        local end=$((SECONDS + DURATION))
        local count=0
        while [ $SECONDS -lt $end ]; do
            # Быстрый connect+close
            (echo "" > /dev/tcp/127.0.0.1/$port) 2>/dev/null || true
            count=$((count + 1))
            sleep "$delay" 2>/dev/null || true
        done
        echo "net_worker: $count TCP connect+close cycles"
    }

    for i in $(seq 1 $NET_WORKERS); do
        net_worker $NET_RATE "$NET_PORT" &
        PIDS+=($!)
    done
fi

echo "=== All generators started (PIDs: ${PIDS[*]})"
echo "=== Waiting ${DURATION}s..."
echo ""

# Мониторинг CPU/memory process_metrics каждые 5 секунд
PM_PID=$(pgrep -f 'build/process_metrics' | head -1 || echo "")
if [ -n "$PM_PID" ]; then
    echo "=== Monitoring process_metrics (PID=$PM_PID) every 5s:"
    echo "TIME          CPU%  RSS_MB  VSIZE_MB  THREADS"
    monitor_end=$((SECONDS + DURATION))
    while [ $SECONDS -lt $monitor_end ]; do
        if [ -d "/proc/$PM_PID" ]; then
            ps -p "$PM_PID" -o pcpu=,rss=,vsz=,nlwp= 2>/dev/null | \
                awk -v t="$(date +%H:%M:%S)" '{
                    printf "%s  %5s  %6.1f  %8.1f  %7s\n",
                        t, $1, $2/1024, $3/1024, $4
                }'
        fi
        sleep 5
    done &
    PIDS+=($!)
else
    echo "WARNING: process_metrics not found, skipping CPU/mem monitoring"
    echo "         Start it first: sudo ./build/process_metrics -c tests/stress_test.conf"
fi

# Ждём завершения всех воркеров
wait 2>/dev/null || true

echo ""
echo "=== Stress test complete (${DURATION}s, ${INTENSITY})"
echo ""
echo "Check process_metrics logs for 'ringbuf drops' warnings."
echo "If log_level=2, look for 'ringbuf totals' DEBUG lines."
