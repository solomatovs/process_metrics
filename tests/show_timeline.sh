#!/bin/bash
# show_timeline.sh — отображение собранных снапшотов метрик
#
# Использование:
#   ./tests/show_timeline.sh                       # дефолт: /tmp/pm_collect/timeline
#   ./tests/show_timeline.sh /path/to/timeline     # указать директорию

DIR="${1:-/tmp/pm_collect/timeline}"

if [[ ! -d "$DIR" ]] || ! ls "$DIR"/snap_*.prom >/dev/null 2>&1; then
    echo "No snapshots in $DIR"
    exit 1
fi

SNAP_COUNT=$(ls "$DIR"/snap_*.prom 2>/dev/null | wc -l)
LAST=$(ls "$DIR"/snap_*.prom | sort | tail -1)

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗"
echo "║                                    Metrics Timeline ($SNAP_COUNT snapshots)"
echo "╠══════════╦═════╦══════════╦══════════╦══════════╦══════════╦══════════╦══════════╦═════════╦════════╣"
echo "║ TIME     ║PIDs ║ CPU_s    ║CPU_ratio ║ RSS_MB   ║RSS_MAX_MB║ IO_W_MB  ║ IO_R_MB  ║ VOL_CSW ║MINFLT ║"
echo "╠══════════╬═════╬══════════╬══════════╬══════════╬══════════╬══════════╬══════════╬═════════╬════════╣"

for ts_file in $(ls "$DIR"/snap_*.ts 2>/dev/null | sort); do
    snap=$(basename "$ts_file" .ts)
    prom="$DIR/${snap}.prom"
    [[ -f "$prom" ]] || continue
    TS=$(cat "$ts_file")
    PIDS=$(grep -c '^process_metrics_info{' "$prom" || true)
    CPU=$(awk '/^process_metrics_cpu_seconds_total\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.2f",s}' "$prom")
    RATIO=$(awk '/^process_metrics_cpu_usage_ratio\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.4f",s}' "$prom")
    RSS=$(awk '/^process_metrics_rss_bytes\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.1f",s/1048576}' "$prom")
    RMAX=$(awk '/^process_metrics_rss_max_bytes\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.1f",s/1048576}' "$prom")
    IOW=$(awk '/^process_metrics_io_write_bytes_total\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.1f",s/1048576}' "$prom")
    IOR=$(awk '/^process_metrics_io_read_bytes_total\{/{gsub(/.*\} /,""); s+=$1}END{printf "%.1f",s/1048576}' "$prom")
    VCSW=$(awk '/^process_metrics_voluntary_ctxsw_total\{/{gsub(/.*\} /,""); s+=$1}END{printf "%d",s}' "$prom")
    MFLT=$(awk '/^process_metrics_minor_page_faults_total\{/{gsub(/.*\} /,""); s+=$1}END{printf "%d",s}' "$prom")
    printf "║ %-8s ║ %3d ║ %8s ║ %8s ║ %8s ║ %8s ║ %8s ║ %8s ║ %7d ║%7d ║\n" \
        "$TS" "${PIDS:-0}" "$CPU" "$RATIO" "$RSS" "$RMAX" "$IOW" "$IOR" "${VCSW:-0}" "${MFLT:-0}"
done

echo "╚══════════╩═════╩══════════╩══════════╩══════════╩══════════╩══════════╩══════════╩═════════╩════════╝"

# Per-process breakdown
echo ""
echo "=== Per-Process Breakdown (last snapshot) ==="
printf "  %-8s %-40s %8s %8s %8s %8s %7s %5s\n" \
    "PID" "CMDLINE" "RSS_MB" "CPU_s" "RATIO" "IO_W_MB" "VOL_CSW" "STATE"
printf "  %-8s %-40s %8s %8s %8s %8s %7s %5s\n" \
    "--------" "----------------------------------------" "--------" "--------" "--------" "--------" "-------" "-----"

grep '^process_metrics_info{' "$LAST" | while read -r line; do
    pid=$(echo "$line" | sed 's/.*pid="\([0-9]*\)".*/\1/')
    cmdline=$(echo "$line" | sed 's/.*cmdline="\([^"]*\)".*/\1/' | cut -c1-40)
    rss=$(grep "^process_metrics_rss_bytes{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
    cpu=$(grep "^process_metrics_cpu_seconds_total{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
    ratio=$(grep "^process_metrics_cpu_usage_ratio{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
    iow=$(grep "^process_metrics_io_write_bytes_total{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
    vcsw=$(grep "^process_metrics_voluntary_ctxsw_total{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
    state=$(grep "^process_metrics_state{.*pid=\"$pid\"" "$LAST" | head -1 | sed 's/.*state="\([^"]*\)".*/\1/')
    rss_mb=$(awk "BEGIN{printf \"%.1f\", ${rss:-0}/1048576}")
    iow_mb=$(awk "BEGIN{printf \"%.1f\", ${iow:-0}/1048576}")
    printf "  %-8s %-40s %8s %8s %8s %8s %7s %5s\n" \
        "$pid" "$cmdline" "$rss_mb" "${cpu:-0}" "${ratio:-0}" "$iow_mb" "${vcsw:-0}" "${state:-?}"
done

# Exited processes
EXITED=$(grep -c '^process_metrics_exited_exit_code{' "$LAST" || true)
if [[ "${EXITED:-0}" -gt 0 ]]; then
    echo ""
    echo "=== Exited Processes ($EXITED) ==="
    grep '^process_metrics_exited_exit_code{' "$LAST" | while read -r line; do
        pid=$(echo "$line" | sed 's/.*pid="\([0-9]*\)".*/\1/')
        cmdline=$(echo "$line" | sed 's/.*cmdline="\([^"]*\)".*/\1/' | cut -c1-45)
        code=$(echo "$line" | sed 's/.*} //')
        sig=$(grep "^process_metrics_exited_signal{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
        cpu=$(grep "^process_metrics_exited_cpu_seconds_total{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
        rss=$(grep "^process_metrics_exited_rss_max_bytes{.*pid=\"$pid\"}" "$LAST" | head -1 | sed 's/.*} //')
        rss_mb=$(awk "BEGIN{printf \"%.1f\", ${rss:-0}/1048576}")
        printf "  PID=%-8s %-45s exit=%-3s sig=%-3s cpu=%7ss rss_max=%sMB\n" \
            "$pid" "$cmdline" "${code:-?}" "${sig:-?}" "${cpu:-?}" "$rss_mb"
    done
fi

echo ""
echo "Raw .prom: $LAST"
echo "All snapshots: $DIR/"
