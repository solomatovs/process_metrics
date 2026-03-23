#!/bin/bash
# test_clickhouse_integration.sh — end-to-end test: process_metrics → HTTP → ClickHouse
#
# What this test does:
#   1. Creates the process_metrics table in ClickHouse
#   2. Starts process_metrics with http_server enabled
#   3. Waits for events to accumulate
#   4. Inserts data into ClickHouse via url() table function
#   5. Verifies rows exist with correct structure
#   6. Creates a Refreshable Materialized View for auto-pull
#   7. Verifies auto-pull inserts new data
#   8. Cleans up
#
# Requirements:
#   - ClickHouse running (via docker or locally)
#   - process_metrics built (build/process_metrics)
#   - root privileges (for BPF)
#   - curl
#
# Usage:
#   sudo ./tests/test_clickhouse_integration.sh \
#       --ch-container ch01 --ch-user admin --ch-password secret

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/build/process_metrics"
SCHEMA="$PROJECT_DIR/examples/clickhouse_schema.sql"

# Defaults
CH_CONTAINER=""
CH_HOST="127.0.0.1"
CH_USER="default"
CH_PASSWORD=""
CH_DB="test_process_metrics_$$"
PM_PORT=19092
TEST_DATA_FILE="/tmp/test_ch_events.dat"
TEST_CONF="/tmp/test_ch_integration.conf"

PASSED=0
FAILED=0
PM_PID=""
DB_CREATED=0

# ── Parse args ──

while [[ $# -gt 0 ]]; do
    case $1 in
        --ch-container) CH_CONTAINER="$2"; shift 2 ;;
        --ch-host)      CH_HOST="$2"; shift 2 ;;
        --ch-user)      CH_USER="$2"; shift 2 ;;
        --ch-password)  CH_PASSWORD="$2"; shift 2 ;;
        --pm-port)      PM_PORT="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/{ s/^# \?//; p }' "$0"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ── Helpers ──

pass() { echo "  OK: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1"; FAILED=$((FAILED + 1)); }

# Run clickhouse-client — via docker exec or directly
ch_client() {
    local args=()
    [[ -n "$CH_USER" ]] && args+=(--user "$CH_USER")
    [[ -n "$CH_PASSWORD" ]] && args+=(--password "$CH_PASSWORD")
    args+=("$@")

    if [[ -n "$CH_CONTAINER" ]]; then
        docker exec "$CH_CONTAINER" clickhouse-client "${args[@]}" 2>/dev/null
    else
        clickhouse-client --host "$CH_HOST" "${args[@]}" 2>/dev/null
    fi
}

ch_query() {
    ch_client -d "$CH_DB" -q "$1"
}

ch_query_default() {
    ch_client -q "$1"
}

ch_query_stdin() {
    if [[ -n "$CH_CONTAINER" ]]; then
        local args=(--user "$CH_USER")
        [[ -n "$CH_PASSWORD" ]] && args+=(--password "$CH_PASSWORD")
        args+=(-d "$CH_DB")
        docker exec -i "$CH_CONTAINER" clickhouse-client "${args[@]}" 2>/dev/null
    else
        local args=(--host "$CH_HOST" --user "$CH_USER")
        [[ -n "$CH_PASSWORD" ]] && args+=(--password "$CH_PASSWORD")
        args+=(-d "$CH_DB")
        clickhouse-client "${args[@]}" 2>/dev/null
    fi
}

cleanup() {
    echo ""
    echo "Cleaning up..."

    if [[ -n "$PM_PID" ]] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null
        wait "$PM_PID" 2>/dev/null || true
    fi

    if [[ "$DB_CREATED" -eq 1 ]]; then
        ch_query_default "DROP DATABASE IF EXISTS $CH_DB" 2>/dev/null || true
    fi

    rm -f "$TEST_DATA_FILE" "$TEST_DATA_FILE.pending" "$TEST_DATA_FILE.tmp"
    rm -f "$TEST_CONF" /tmp/test_ch_pm_stderr.log
}
trap cleanup EXIT

# ── Checks ──

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: requires root (for BPF)"
    echo "Usage: sudo $0 --ch-container ch01 --ch-user admin --ch-password secret"
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

# Test ClickHouse connectivity
if ! ch_query_default "SELECT 1" >/dev/null 2>&1; then
    echo "ERROR: cannot connect to ClickHouse"
    if [[ -n "$CH_CONTAINER" ]]; then
        echo "Container: $CH_CONTAINER, user: $CH_USER"
    else
        echo "Host: $CH_HOST, user: $CH_USER"
    fi
    exit 1
fi

# Explicit column structure for url() — prevents ClickHouse from making
# a probe GET that would drain the CSV buffer before the real GET
URL_STRUCT="timestamp DateTime64(3), hostname String, event_type String, rule String,
root_pid UInt32, pid UInt32, ppid UInt32,
comm String, exec String, args String, cgroup String,
is_root UInt8, state String, exit_code UInt32,
cpu_ns UInt64, cpu_usage_ratio Float64,
rss_bytes UInt64, rss_min_bytes UInt64, rss_max_bytes UInt64,
shmem_bytes UInt64, swap_bytes UInt64, vsize_bytes UInt64,
io_read_bytes UInt64, io_write_bytes UInt64, maj_flt UInt64, min_flt UInt64,
nvcsw UInt64, nivcsw UInt64, threads UInt32, oom_score_adj Int16, oom_killed UInt8,
net_tx_bytes UInt64, net_rx_bytes UInt64, start_time_ns UInt64, uptime_seconds UInt64,
cgroup_memory_max Int64, cgroup_memory_current Int64, cgroup_swap_current Int64,
cgroup_cpu_weight Int64, cgroup_pids_current Int64"

CH_VERSION=$(ch_query_default "SELECT version()")

echo "== ClickHouse integration test =="
echo "   ClickHouse: $CH_VERSION"
echo "   Test DB:    $CH_DB"
echo "   PM port:    $PM_PORT"
echo ""

# ── Step 1: Create test database and table ──

echo "STEP 1: Create ClickHouse database and table"

ch_query_default "CREATE DATABASE IF NOT EXISTS $CH_DB"
DB_CREATED=1

# Apply schema via stdin
cat "$SCHEMA" | ch_query_stdin
if ch_query "SHOW TABLES" | grep -q "process_metrics"; then
    pass "table created in $CH_DB"
else
    fail "table creation failed"
    exit 1
fi

# ── Step 2: Start process_metrics ──

echo "STEP 2: Start process_metrics"

cat > "$TEST_CONF" <<EOF
snapshot_interval = 5;
metric_prefix = "test_pm";

rules = (
    { name = "test_bash"; regex = "bash"; }
);

http_server = {
    port = $PM_PORT;
    bind = "0.0.0.0";
    data_file = "$TEST_DATA_FILE";
};
EOF

"$BINARY" -c "$TEST_CONF" >/dev/null 2>/tmp/test_ch_pm_stderr.log &
PM_PID=$!
sleep 3

if ! kill -0 "$PM_PID" 2>/dev/null; then
    fail "process_metrics failed to start"
    PM_PID=""
    exit 1
fi
pass "process_metrics running (PID=$PM_PID)"

# ── Step 3: Wait for events ──

echo "STEP 3: Wait for events to accumulate"
sleep 8  # at least one snapshot cycle

# Verify HTTP serves CSV
CSV_CHECK=$(curl -s "http://127.0.0.1:$PM_PORT/metrics?format=csv" | head -1)
if echo "$CSV_CHECK" | grep -q "timestamp,hostname"; then
    pass "CSV endpoint responding"
else
    fail "CSV endpoint not responding"
    exit 1
fi

# ── Step 4: Insert into ClickHouse via url() ──

echo "STEP 4: Insert data via url() table function"

# Wait for more data
sleep 6

# Get the host IP accessible from inside docker container
HOST_IP=$(ip -4 addr show docker0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
[[ -z "$HOST_IP" ]] && HOST_IP="172.17.0.1"

INSERT_RESULT=$(ch_query "INSERT INTO process_metrics
SELECT * FROM url(
    'http://${HOST_IP}:$PM_PORT/metrics?format=csv',
    'CSVWithNames',
    '${URL_STRUCT}'
)" 2>&1)

if [[ $? -eq 0 ]]; then
    pass "INSERT via url() succeeded"
else
    fail "INSERT via url() failed: $INSERT_RESULT"
fi

# ── Step 5: Verify data in ClickHouse ──

echo "STEP 5: Verify data in ClickHouse"

ROW_COUNT=$(ch_query "SELECT count() FROM process_metrics")
if [[ -n "$ROW_COUNT" ]] && [[ "$ROW_COUNT" -gt 0 ]]; then
    pass "found $ROW_COUNT rows in process_metrics"
else
    fail "no rows found in process_metrics (count=$ROW_COUNT)"
fi

# Check event types
EVENT_TYPES=$(ch_query "SELECT DISTINCT event_type FROM process_metrics ORDER BY event_type")
if [[ -n "$EVENT_TYPES" ]]; then
    pass "event_types present: $(echo $EVENT_TYPES | tr '\n' ', ')"
else
    fail "no event_types found"
fi

# Check hostname is not empty
EMPTY_HOSTS=$(ch_query "SELECT count() FROM process_metrics WHERE hostname = ''")
if [[ "$EMPTY_HOSTS" == "0" ]]; then
    pass "all rows have hostname set"
else
    fail "$EMPTY_HOSTS rows with empty hostname"
fi

# Check timestamp is valid
VALID_TS=$(ch_query "SELECT count() FROM process_metrics WHERE timestamp > '2020-01-01'")
if [[ -n "$VALID_TS" ]] && [[ "$VALID_TS" -gt 0 ]]; then
    pass "timestamps are valid ($VALID_TS rows)"
else
    fail "no valid timestamps found"
fi

# ── Step 6: Verify CSV was cleared ──

echo "STEP 6: Verify CSV cleared after ClickHouse consumed it"
# The previous INSERT consumed the CSV data (commit). New events accumulate
# quickly (snapshot every 5s + exit events from test processes).
# We verify: drain returns data, immediate re-drain returns much less.
DRAIN1=$(curl -s "http://127.0.0.1:$PM_PORT/metrics?format=csv" | wc -l)
DRAIN2=$(curl -s "http://127.0.0.1:$PM_PORT/metrics?format=csv" | wc -l)
if [[ "$DRAIN2" -lt "$DRAIN1" ]] || [[ "$DRAIN2" -le 2 ]]; then
    pass "CSV buffer cleared after fetch (first=$DRAIN1, second=$DRAIN2)"
else
    fail "CSV buffer not cleared (first=$DRAIN1, second=$DRAIN2)"
fi

# ── Step 7: Test Refreshable Materialized View ──

echo "STEP 7: Test Refreshable Materialized View"

CH_MAJOR=$(echo "$CH_VERSION" | cut -d. -f1)
CH_MINOR=$(echo "$CH_VERSION" | cut -d. -f2)

if [[ "$CH_MAJOR" -gt 23 ]] || { [[ "$CH_MAJOR" -eq 23 ]] && [[ "$CH_MINOR" -ge 12 ]]; }; then
    # Create refreshable materialized view
    # Drain CSV buffer first so we start clean
    curl -s "http://127.0.0.1:$PM_PORT/metrics?format=csv" > /dev/null

    MV_RESULT=$(ch_query "
        CREATE MATERIALIZED VIEW IF NOT EXISTS process_metrics_pull_test
        REFRESH EVERY 10 SECOND
        TO process_metrics
        AS
        SELECT * FROM url(
            'http://${HOST_IP}:$PM_PORT/metrics?format=csv',
            'CSVWithNames',
            '${URL_STRUCT}'
        )
    " 2>&1)

    if [[ $? -eq 0 ]]; then
        pass "refreshable materialized view created"

        # Get current count
        COUNT_BEFORE=$(ch_query "SELECT count() FROM process_metrics" || echo "0")

        # Wait for at least two refresh cycles + snapshots
        echo "  Waiting 25s for auto-refresh..."
        sleep 25

        COUNT_AFTER=$(ch_query "SELECT count() FROM process_metrics" || echo "0")

        if [[ -n "$COUNT_AFTER" ]] && [[ -n "$COUNT_BEFORE" ]] && [[ "$COUNT_AFTER" -gt "$COUNT_BEFORE" ]]; then
            NEW_ROWS=$((COUNT_AFTER - COUNT_BEFORE))
            pass "auto-pull inserted $NEW_ROWS new rows ($COUNT_BEFORE → $COUNT_AFTER)"
        else
            # Show MV status for debugging
            MV_STATUS=$(ch_query "SELECT status, last_exception FROM system.view_refreshes WHERE view = 'process_metrics_pull_test' FORMAT TSV" 2>&1 || echo "no status")
            fail "no new rows from auto-pull ($COUNT_BEFORE → $COUNT_AFTER) MV status: $MV_STATUS"
        fi

        # Cleanup view
        ch_query "DROP VIEW IF EXISTS process_metrics_pull_test" 2>/dev/null || true
    else
        fail "failed to create materialized view: $MV_RESULT"
    fi
else
    echo "  SKIP: ClickHouse $CH_VERSION < 23.12 (REFRESH EVERY not supported)"
fi

# ── Step 8: Sample query ──

echo "STEP 8: Run sample query"

TOTAL=$(ch_query "SELECT count() FROM process_metrics" || echo "0")
SAMPLE=$(ch_query "
    SELECT timestamp, hostname, event_type, pid, comm,
           rss_bytes / 1048576 AS rss_mb
    FROM process_metrics
    ORDER BY timestamp DESC
    LIMIT 5
    FORMAT Pretty
" 2>&1)

if [[ -n "$SAMPLE" ]] && [[ "$TOTAL" -gt 0 ]]; then
    pass "sample query works (total=$TOTAL rows)"
    echo ""
    echo "$SAMPLE"
    echo ""
else
    fail "sample query returned nothing (total=$TOTAL)"
fi

# ── Results ──

echo ""
echo "== Results: $PASSED passed, $FAILED failed =="
exit $([[ $FAILED -eq 0 ]] && echo 0 || echo 1)
