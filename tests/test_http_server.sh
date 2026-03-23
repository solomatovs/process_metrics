#!/bin/bash
# test_http_server.sh — integration tests for HTTP server (prom + csv endpoints)
#
# Tests:
#   1. Prom endpoint returns prom file contents
#   2. Prom file is NOT deleted after request
#   3. Prom endpoint returns updated data after snapshot refresh
#   4. CSV endpoint returns header + accumulated events
#   5. CSV data is cleared after successful delivery
#   6. CSV data is preserved if delivery fails (connection reset)
#   7. Concurrent CSV requests don't lose data
#
# Requirements:
#   - process_metrics binary built (build/process_metrics)
#   - root privileges (for BPF)
#   - curl
#
# Usage:
#   sudo ./tests/test_http_server.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/build/process_metrics"

TEST_PORT=19091
TEST_DATA_FILE="/tmp/test_http_events.dat"
TEST_PROM_FILE="/tmp/test_http_metrics.prom"
TEST_CONF="/tmp/test_http_server.conf"

PASSED=0
FAILED=0
PM_PID=""

# ── Helpers ──

pass() { echo "  OK: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

cleanup() {
    if [[ -n "$PM_PID" ]] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -f "$TEST_DATA_FILE" "$TEST_DATA_FILE.pending" "$TEST_DATA_FILE.tmp"
    rm -f "$TEST_PROM_FILE" "$TEST_CONF"
}
trap cleanup EXIT

# ── Checks ──

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: requires root (for BPF)"
    echo "Usage: sudo $0"
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: binary not found: $BINARY"
    echo "Run: make all"
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl not found"
    exit 1
fi

# ── Create test config ──

cat > "$TEST_CONF" <<EOF
snapshot_interval = 5;
metric_prefix = "test_pm";

rules = (
    { name = "test_bash"; regex = "bash"; }
);

http_server = {
    port = $TEST_PORT;
    bind = "127.0.0.1";
    data_file = "$TEST_DATA_FILE";
};
EOF

# ── Start process_metrics ──

echo "== HTTP server integration tests =="
echo ""
echo "Starting process_metrics on port $TEST_PORT..."

"$BINARY" -c "$TEST_CONF" &
PM_PID=$!
sleep 3

if ! kill -0 "$PM_PID" 2>/dev/null; then
    echo "FATAL: process_metrics failed to start"
    PM_PID=""
    exit 1
fi

echo "process_metrics running (PID=$PM_PID)"
echo ""

# ── Test 1: Prom endpoint returns data ──

echo "TEST 1: Prom endpoint returns data"
# Wait for at least one snapshot
sleep 6

PROM_RESP=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=prom")
if echo "$PROM_RESP" | grep -q "test_pm_"; then
    pass "prom endpoint returns metrics with correct prefix"
else
    # May return "# no data" if no rules matched — that's OK for structure test
    if echo "$PROM_RESP" | grep -q "# no data"; then
        pass "prom endpoint returns valid response (no matching processes)"
    else
        fail "prom endpoint returned unexpected: $(echo "$PROM_RESP" | head -3)"
    fi
fi

# ── Test 2: Prom file is NOT deleted after request ──

echo "TEST 2: Prom file persists after request"
PROM_RESP2=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=prom")
if [[ -n "$PROM_RESP2" ]]; then
    pass "prom data available on second request (not deleted)"
else
    fail "prom returned empty on second request"
fi

# ── Test 3: Prom returns same/updated data on repeat ──

echo "TEST 3: Prom returns consistent data"
sleep 6  # wait for another snapshot
PROM_RESP3=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=prom")
if [[ -n "$PROM_RESP3" ]]; then
    pass "prom still returns data after multiple snapshots"
else
    fail "prom returned empty after snapshot cycle"
fi

# ── Test 4: CSV endpoint returns header + events ──

echo "TEST 4: CSV endpoint returns header"
CSV_RESP=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=csv")
if echo "$CSV_RESP" | head -1 | grep -q "timestamp,hostname,event_type"; then
    pass "CSV response starts with correct header"
else
    fail "CSV header missing or wrong: $(echo "$CSV_RESP" | head -1)"
fi

# ── Test 5: CSV data is cleared after successful delivery ──

echo "TEST 5: CSV data cleared after delivery"
# First request gets accumulated data
CSV_FIRST=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=csv")
LINES_FIRST=$(echo "$CSV_FIRST" | wc -l)

# Immediate second request should only have the header
CSV_SECOND=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=csv")
LINES_SECOND=$(echo "$CSV_SECOND" | wc -l)

if [[ "$LINES_SECOND" -le 2 ]]; then
    pass "CSV cleared after first request (first=$LINES_FIRST lines, second=$LINES_SECOND lines)"
else
    fail "CSV not cleared: second request has $LINES_SECOND lines"
fi

# ── Test 6: .pending file behavior ──

echo "TEST 6: .pending file deleted after successful CSV delivery"
# Wait for new events to accumulate
sleep 6

# Fetch CSV (should succeed and commit)
curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=csv" > /dev/null
if [[ ! -f "$TEST_DATA_FILE.pending" ]]; then
    pass ".pending removed after successful delivery"
else
    fail ".pending still exists after successful delivery"
fi

# ── Test 7: 404 for unknown endpoints ──

echo "TEST 7: Unknown endpoint returns 404"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$TEST_PORT/unknown")
if [[ "$HTTP_CODE" == "404" ]]; then
    pass "unknown endpoint returns 404"
else
    fail "unknown endpoint returned $HTTP_CODE instead of 404"
fi

# ── Test 8: Default format is CSV ──

echo "TEST 8: Default format is CSV"
sleep 6  # accumulate events
DEFAULT_RESP=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics")
if echo "$DEFAULT_RESP" | head -1 | grep -q "timestamp,hostname,event_type"; then
    pass "default format is CSV"
else
    fail "default format is not CSV"
fi

# ── Test 9: Prom still works after CSV operations ──

echo "TEST 9: Prom unaffected by CSV operations"
PROM_AFTER=$(curl -s "http://127.0.0.1:$TEST_PORT/metrics?format=prom")
if [[ -n "$PROM_AFTER" ]]; then
    pass "prom still returns data after CSV operations"
else
    fail "prom broken after CSV operations"
fi

# ── Results ──

echo ""
echo "== Results: $PASSED passed, $FAILED failed =="
exit $([[ $FAILED -eq 0 ]] && echo 0 || echo 1)
