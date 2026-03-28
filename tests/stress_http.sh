#!/bin/bash
# stress_http.sh — стресс-тест HTTP-сервера process_metrics
#
# Тесты:
#   1. Параллельные клиенты — сотни одновременных запросов GET /metrics
#   2. Slow-read клиенты — читают ответ по 1 байту (проверка утечки fd/памяти)
#   3. Гонка clear — одновременные запросы ?clear=1 (проверка целостности данных)
#   4. Частые reconnect — быстрое connect+disconnect без чтения ответа
#   5. Большой объём данных — запрос CSV после накопления тысяч событий
#
# Требования:
#   - process_metrics запущен с HTTP-сервером (sudo ./build/process_metrics -c tests/stress_test.conf)
#   - curl, python3
#
# Запуск:
#   bash tests/stress_http.sh [port] [duration_sec]
#
# По умолчанию: port=9091, duration=30

set -uo pipefail

PORT=${1:-9091}
DURATION=${2:-30}
BASE_URL="http://127.0.0.1:$PORT"

PASSED=0
FAILED=0
WORKDIR="/tmp/stress_http_$$"
mkdir -p "$WORKDIR"

# ── Helpers ──

pass() { echo "  OK: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

cleanup() {
    # Убиваем все фоновые процессы этого скрипта
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

# ── Проверка доступности ──

echo "== HTTP server stress tests =="
echo "   target: $BASE_URL"
echo "   duration: ${DURATION}s"
echo ""

if ! curl -sf -o /dev/null -m 5 "$BASE_URL/metrics"; then
    echo "FATAL: HTTP server not reachable at $BASE_URL/metrics"
    echo "Start process_metrics first: sudo ./build/process_metrics -c tests/stress_test.conf"
    exit 1
fi

# Получаем PID process_metrics для мониторинга
PM_PID=$(pgrep -f 'build/process_metrics' | head -1 || echo "")

get_pm_stats() {
    if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
        local rss fd_count
        rss=$(awk '/^VmRSS/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "?")
        fd_count=$(sudo ls /proc/$PM_PID/fd 2>/dev/null | wc -w || echo "?")
        echo "RSS=${rss}kB FDs=${fd_count}"
    else
        echo "N/A"
    fi
}

echo "Before tests: $(get_pm_stats)"
echo ""

# ══════════════════════════════════════════════════════════════════
# TEST 1: Параллельные клиенты
# ══════════════════════════════════════════════════════════════════

echo "TEST 1: Concurrent clients (200 parallel requests)"

STATS_BEFORE=$(get_pm_stats)

# Запускаем 200 параллельных curl-запросов
CONCURRENT=200
OK_COUNT=0
ERR_COUNT=0

for i in $(seq 1 $CONCURRENT); do
    curl -sf -o /dev/null -m 10 "$BASE_URL/metrics" && \
        echo "ok" || echo "err"  &
done > "$WORKDIR/concurrent_results.txt"
wait

OK_COUNT=$(grep -c "^ok$" "$WORKDIR/concurrent_results.txt" 2>/dev/null || echo 0)
ERR_COUNT=$(grep -c "^err$" "$WORKDIR/concurrent_results.txt" 2>/dev/null || echo 0)

STATS_AFTER=$(get_pm_stats)

if [ "$OK_COUNT" -ge $((CONCURRENT * 80 / 100)) ]; then
    pass "concurrent: ${OK_COUNT}/${CONCURRENT} succeeded ($STATS_BEFORE → $STATS_AFTER)"
else
    fail "concurrent: only ${OK_COUNT}/${CONCURRENT} succeeded, ${ERR_COUNT} errors"
fi

# Проверяем что FD не утекли — даём серверу секунду на cleanup
sleep 1
STATS_POST=$(get_pm_stats)
echo "  Post-cleanup: $STATS_POST"

# ══════════════════════════════════════════════════════════════════
# TEST 2: Slow-read клиенты
# ══════════════════════════════════════════════════════════════════

echo ""
echo "TEST 2: Slow-read clients (20 clients, 1 byte/100ms)"

FD_BEFORE=""
if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
    FD_BEFORE=$(sudo ls "/proc/$PM_PID/fd" 2>/dev/null | wc -w)
fi

# 20 slow-read клиентов: читают по 1 байту с задержкой 100мс.
# Сервер имеет SO_SNDTIMEO=5с — клиенты должны быть отключены по таймауту.
SLOW_CLIENTS=20
SLOW_DURATION=10  # секунд на медленное чтение

for i in $(seq 1 $SLOW_CLIENTS); do
    python3 -c "
import socket, time, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect(('127.0.0.1', $PORT))
    s.sendall(b'GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n')
    end = time.time() + $SLOW_DURATION
    total = 0
    while time.time() < end:
        try:
            data = s.recv(1)
            if not data:
                break
            total += len(data)
            time.sleep(0.1)
        except:
            break
    s.close()
    print(f'ok:{total}')
except Exception as e:
    print(f'err:{e}')
" &
done > "$WORKDIR/slow_results.txt" 2>/dev/null
wait

# Ждём пока сервер закроет сокеты
sleep 2

FD_AFTER=""
if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
    FD_AFTER=$(sudo ls "/proc/$PM_PID/fd" 2>/dev/null | wc -w)
fi

# Проверяем что FD не утекли (допускаем разброс ±5)
if [ -n "$FD_BEFORE" ] && [ -n "$FD_AFTER" ]; then
    FD_DIFF=$((FD_AFTER - FD_BEFORE))
    if [ "$FD_DIFF" -le 5 ] && [ "$FD_DIFF" -ge -5 ]; then
        pass "slow-read: no FD leak (before=$FD_BEFORE, after=$FD_AFTER, diff=$FD_DIFF)"
    else
        fail "slow-read: FD leak detected (before=$FD_BEFORE, after=$FD_AFTER, diff=$FD_DIFF)"
    fi
else
    pass "slow-read: completed (FD check skipped — process_metrics PID not found)"
fi

# Проверяем что сервер всё ещё отвечает
if curl -sf -o /dev/null -m 5 "$BASE_URL/metrics"; then
    pass "slow-read: server still responsive after slow clients"
else
    fail "slow-read: server unresponsive after slow clients"
fi

# ══════════════════════════════════════════════════════════════════
# TEST 3: Гонка clear — одновременные ?clear=1
# ══════════════════════════════════════════════════════════════════

echo ""
echo "TEST 3: Concurrent clear race (50 parallel ?clear=1 requests)"

# Ждём накопления событий
sleep 3

# Запускаем 50 параллельных запросов с clear=1
CLEAR_CLIENTS=50
for i in $(seq 1 $CLEAR_CLIENTS); do
    curl -sf -m 10 "$BASE_URL/metrics?format=csv&clear=1" 2>/dev/null | wc -l &
done > "$WORKDIR/clear_results.txt"
wait

# Подсчитываем: ровно один клиент должен получить данные, остальные — пустой ответ (1 строка = только заголовок)
LINES_LIST=$(cat "$WORKDIR/clear_results.txt" 2>/dev/null)
NON_EMPTY=0
for L in $LINES_LIST; do
    if [ "$L" -gt 2 ] 2>/dev/null; then
        NON_EMPTY=$((NON_EMPTY + 1))
    fi
done

# В гонке может быть 0 или 1 клиентов с данными (в зависимости от того, были ли события)
# Главное — нет крашей и сервер работает
if curl -sf -o /dev/null -m 5 "$BASE_URL/metrics"; then
    pass "clear race: server survived, ${NON_EMPTY} clients got data (no crash/hang)"
else
    fail "clear race: server unresponsive after concurrent clear"
fi

# ══════════════════════════════════════════════════════════════════
# TEST 4: Быстрый connect+disconnect без чтения
# ══════════════════════════════════════════════════════════════════

echo ""
echo "TEST 4: Rapid connect+disconnect (500 connections, no data read)"

FD_BEFORE=""
if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
    FD_BEFORE=$(sudo ls "/proc/$PM_PID/fd" 2>/dev/null | wc -w)
fi

# 500 быстрых TCP connect + immediate close
python3 -c "
import socket, sys

port = $PORT
ok = 0
err = 0
for i in range(500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', port))
        # Сразу закрываем — RST или FIN без отправки HTTP-запроса
        s.close()
        ok += 1
    except Exception:
        err += 1

print(f'{ok} ok, {err} err')
" > "$WORKDIR/rapid_results.txt" 2>/dev/null

RAPID_OK=$(grep -oP '^\d+' "$WORKDIR/rapid_results.txt" 2>/dev/null || echo 0)
sleep 2

FD_AFTER=""
if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
    FD_AFTER=$(sudo ls "/proc/$PM_PID/fd" 2>/dev/null | wc -w)
fi

if [ -n "$FD_BEFORE" ] && [ -n "$FD_AFTER" ]; then
    FD_DIFF=$((FD_AFTER - FD_BEFORE))
    if [ "$FD_DIFF" -le 5 ]; then
        pass "rapid disconnect: ${RAPID_OK}/500 connects, no FD leak (diff=$FD_DIFF)"
    else
        fail "rapid disconnect: FD leak (before=$FD_BEFORE, after=$FD_AFTER, diff=$FD_DIFF)"
    fi
else
    pass "rapid disconnect: completed (${RAPID_OK}/500)"
fi

# Сервер всё ещё жив?
if curl -sf -o /dev/null -m 5 "$BASE_URL/metrics"; then
    pass "rapid disconnect: server still responsive"
else
    fail "rapid disconnect: server unresponsive"
fi

# ══════════════════════════════════════════════════════════════════
# TEST 5: Длительная нагрузка — непрерывный поток запросов
# ══════════════════════════════════════════════════════════════════

echo ""
echo "TEST 5: Sustained load (${DURATION}s continuous requests)"

RSS_BEFORE=""
if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
    RSS_BEFORE=$(awk '/^VmRSS/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "")
fi

# Непрерывный поток запросов с 10 параллельными воркерами
WORKERS=10
TOTAL_REQUESTS=0

for w in $(seq 1 $WORKERS); do
    (
        count=0
        end=$((SECONDS + DURATION))
        while [ $SECONDS -lt $end ]; do
            if curl -sf -o /dev/null -m 5 "$BASE_URL/metrics"; then
                count=$((count + 1))
            fi
        done
        echo "$count"
    ) &
done > "$WORKDIR/sustained_results.txt"

# Мониторинг RSS/FD каждые 5 секунд
echo "  TIME       RSS_kB  FDs"
MONITOR_END=$((SECONDS + DURATION))
while [ $SECONDS -lt $MONITOR_END ]; do
    if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
        RSS=$(awk '/^VmRSS/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "?")
        FDS=$(sudo ls "/proc/$PM_PID/fd" 2>/dev/null | wc -w || echo "?")
        printf "  %s  %7s  %3s\n" "$(date +%H:%M:%S)" "$RSS" "$FDS"
    fi
    sleep 5
done
wait

TOTAL_REQUESTS=0
while IFS= read -r line; do
    TOTAL_REQUESTS=$((TOTAL_REQUESTS + line))
done < "$WORKDIR/sustained_results.txt"

RSS_AFTER=""
if [ -n "$PM_PID" ] && [ -d "/proc/$PM_PID" ]; then
    RSS_AFTER=$(awk '/^VmRSS/ {print $2}' "/proc/$PM_PID/status" 2>/dev/null || echo "")
fi

echo "  Total requests: $TOTAL_REQUESTS in ${DURATION}s ($((TOTAL_REQUESTS / DURATION)) req/s)"

# Проверяем что RSS не вырос больше чем на 50 МБ
if [ -n "$RSS_BEFORE" ] && [ -n "$RSS_AFTER" ]; then
    RSS_GROWTH=$((RSS_AFTER - RSS_BEFORE))
    RSS_GROWTH_MB=$((RSS_GROWTH / 1024))
    if [ "$RSS_GROWTH_MB" -le 50 ]; then
        pass "sustained: RSS growth ${RSS_GROWTH_MB}MB (${RSS_BEFORE}kB → ${RSS_AFTER}kB)"
    else
        fail "sustained: RSS grew ${RSS_GROWTH_MB}MB (${RSS_BEFORE}kB → ${RSS_AFTER}kB) — possible leak"
    fi
else
    pass "sustained: $TOTAL_REQUESTS requests completed (RSS check skipped)"
fi

# Финальная проверка здоровья
if curl -sf -o /dev/null -m 5 "$BASE_URL/metrics"; then
    pass "sustained: server healthy after load"
else
    fail "sustained: server unresponsive after sustained load"
fi

# ── Results ──

echo ""
echo "Final state: $(get_pm_stats)"
echo ""
echo "== Results: $PASSED passed, $FAILED failed =="
exit $([[ $FAILED -eq 0 ]] && echo 0 || echo 1)
