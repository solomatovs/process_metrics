#!/bin/bash
# collect.sh — запуск process_metrics и наблюдение за метриками в реальном времени
#
# Использование:
#   sudo ./tests/collect.sh                          # дефолт: tests/postgres.conf
#   sudo ./tests/collect.sh -c tests/postgres.conf   # указать конфиг
#   sudo ./tests/collect.sh -i 10                    # интервал 10 сек
#   sudo ./tests/collect.sh -d 300                   # собирать 5 минут
#   sudo ./tests/collect.sh --show-only              # только показать ранее собранные данные
#
# Запусти postgres отдельно (например):
#   docker run -d --name pg -e POSTGRES_PASSWORD=test -p 5433:5432 postgres:16
#   docker exec pg pgbench -i -s 10 -U postgres postgres
#   docker exec pg pgbench -c 4 -j 2 -T 60 -U postgres postgres
#
# Скрипт будет собирать снапшоты метрик и в конце выведет:
#   - timeline (агрегированные метрики по времени)
#   - per-process breakdown (последний снапшот)
#   - exited processes (завершившиеся backend'ы)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/bpf/build/process_metrics"

# Defaults
CONF="$SCRIPT_DIR/postgres.conf"
OUTDIR="/tmp/pm_collect"
TIMELINE_DIR="/tmp/pm_collect/timeline"
PROM_FILE="metrics.prom"
INTERVAL=5
DURATION=0        # 0 = бесконечно (до Ctrl+C)
SHOW_ONLY=0

# ── Parse args ──
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)   CONF="$2"; shift 2 ;;
        -i|--interval) INTERVAL="$2"; shift 2 ;;
        -d|--duration) DURATION="$2"; shift 2 ;;
        -o|--outdir)   OUTDIR="$2"; shift 2 ;;
        --show-only)   SHOW_ONLY=1; shift ;;
        -h|--help)
            sed -n '2,/^$/{ s/^# \?//; p }' "$0"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

TIMELINE_DIR="$OUTDIR/timeline"

# ── Show-only mode ──
if [[ "$SHOW_ONLY" -eq 1 ]]; then
    if [[ ! -d "$TIMELINE_DIR" ]]; then
        echo "No data in $TIMELINE_DIR"
        exit 1
    fi
    exec bash "$SCRIPT_DIR/show_timeline.sh" "$TIMELINE_DIR"
fi

# ── Checks ──
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: нужны root-права для BPF"
    echo "       sudo $0 $*"
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: бинарник не найден: $BINARY"
    echo "       cd $PROJECT_DIR/bpf && make all"
    exit 1
fi

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: конфиг не найден: $CONF"
    exit 1
fi

# ── Cleanup on exit ──
PM_PID=""
EXITING=0
cleanup() {
    [[ "$EXITING" -eq 1 ]] && return
    EXITING=1
    echo ""
    if [[ -n "$PM_PID" ]] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null || true
        wait "$PM_PID" 2>/dev/null || true
    fi
    echo "Collector stopped."
    echo ""
    bash "$SCRIPT_DIR/show_timeline.sh" "$TIMELINE_DIR"
}
trap cleanup EXIT

# ── Start ──
mkdir -p "$OUTDIR" "$TIMELINE_DIR"
rm -rf "${TIMELINE_DIR:?}"/*

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              process_metrics collector                    ║"
echo "╠═══════════════════════════════════════════════════════════╣"
echo "║ Config:   $CONF"
echo "║ Interval: ${INTERVAL}s"
echo "║ Duration: $([ "$DURATION" -eq 0 ] && echo "∞ (Ctrl+C to stop)" || echo "${DURATION}s")"
echo "║ Output:   $OUTDIR/$PROM_FILE"
echo "║ Timeline: $TIMELINE_DIR/"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Start collector
"$BINARY" -c "$CONF" -o "$OUTDIR" -f "$PROM_FILE" -i "$INTERVAL" &
PM_PID=$!
sleep 2

if ! kill -0 "$PM_PID" 2>/dev/null; then
    echo "FATAL: process_metrics не запустился"
    PM_PID=""
    exit 1
fi

echo "Collector running (PID=$PM_PID). Собираю снапшоты..."
echo "Press Ctrl+C to stop and see results."
echo ""

# ── Collect snapshots ──
SNAP=0
START_SEC=$SECONDS
while kill -0 "$PM_PID" 2>/dev/null; do
    # Check duration
    if [[ "$DURATION" -gt 0 ]] && [[ $((SECONDS - START_SEC)) -ge "$DURATION" ]]; then
        echo ""
        echo "Duration ${DURATION}s reached."
        break
    fi

    # Save snapshot
    if [[ -f "$OUTDIR/$PROM_FILE" ]]; then
        TS=$(date +%H:%M:%S)
        cp "$OUTDIR/$PROM_FILE" "$TIMELINE_DIR/snap_$(printf '%04d' $SNAP).prom"
        echo "$TS" > "$TIMELINE_DIR/snap_$(printf '%04d' $SNAP).ts"

        # Show live status
        PIDS=$(grep -c '^process_metrics_info{' "$OUTDIR/$PROM_FILE" || true)
        RSS=$(awk '/^process_metrics_rss_bytes\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.0f",s/1048576}' "$OUTDIR/$PROM_FILE")
        CPU=$(awk '/^process_metrics_cpu_usage_ratio\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.2f",s}' "$OUTDIR/$PROM_FILE")
        printf "\r  [%s] snap=%d  PIDs=%d  RSS=%sMB  CPU_ratio=%s    " \
            "$TS" "$SNAP" "${PIDS:-0}" "${RSS:-0}" "${CPU:-0}"

        SNAP=$((SNAP + 1))
    fi

    sleep "$INTERVAL" || break
done
