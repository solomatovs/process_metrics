-- process_metrics — ClickHouse table schema (optimized)
--
-- One table for all event types: snapshot, fork, exec, exit, oom_kill.
-- Run this once on your ClickHouse server.
--
-- Design decisions:
--
--   ORDER BY (hostname, event_type, rule, pid, timestamp)
--     Almost every query filters by event_type, so it goes early in the key.
--     hostname first — enables efficient multi-tenant queries.
--     pid before timestamp — per-process history lookups read contiguous blocks.
--     timestamp last — range scans within a pid are sequential.
--
--   Codecs:
--     Delta    — for monotonically increasing counters (cpu_ns, io_*, faults, ctxsw).
--                Delta stores differences between consecutive values; for slowly
--                growing counters the deltas are small → ZSTD compresses them to bits.
--     Gorilla  — IEEE 754 XOR compression for floats (cpu_usage_ratio).
--                Adjacent snapshot values are close → most XOR bits are zero.
--     T64      — block packing for integers that never use the full 64-bit range
--                (PIDs, threads, exit_code, oom flags, cgroup limits).
--     ZSTD(1)  — final general-purpose compression on every column.
--                Level 1 gives ~95% of max ratio at ~10x faster compression.
--
--   LowCardinality — dictionary encoding for hostname, event_type, rule, cgroup, comm.
--     Replaces repeated strings with integer indices; huge win when cardinality < 10K.
--
--   Partitioning by month (toYYYYMM) instead of day:
--     With 30-day TTL and daily partitions you get 30 partitions to merge/drop.
--     Monthly = 1-2 active partitions, less merge overhead, same TTL granularity
--     (ClickHouse drops partitions where ALL rows are expired).
--
--   Skip indices:
--     bloom_filter on pid  — fast point lookups ("show me PID 12345 history")
--       without scanning entire partitions. Works because pid is not the first
--       key column, so without the index ClickHouse would scan all granules
--       within a (hostname, event_type, rule) prefix.

CREATE TABLE IF NOT EXISTS process_metrics (
    -- ── identification ──────────────────────────────────────────────
    timestamp              DateTime64(3)               CODEC(Delta, ZSTD(1)),
    hostname               LowCardinality(String)      CODEC(ZSTD(1)),
    event_type             LowCardinality(String)      CODEC(ZSTD(1)),
    rule                   LowCardinality(String)      CODEC(ZSTD(1)),
    root_pid               UInt32                      CODEC(T64, ZSTD(1)),
    pid                    UInt32                      CODEC(T64, ZSTD(1)),
    ppid                   UInt32                      CODEC(T64, ZSTD(1)),

    -- ── process metadata ────────────────────────────────────────────
    comm                   LowCardinality(String)      CODEC(ZSTD(1)),
    exec                   String                      CODEC(ZSTD(1)),
    args                   String                      CODEC(ZSTD(1)),
    cgroup                 LowCardinality(String)      CODEC(ZSTD(1)),
    is_root                UInt8                       CODEC(T64, ZSTD(1)),
    state                  LowCardinality(String)      CODEC(ZSTD(1)),
    exit_code              UInt32                      CODEC(T64, ZSTD(1)),

    -- ── CPU ─────────────────────────────────────────────────────────
    cpu_ns                 UInt64                      CODEC(Delta, ZSTD(1)),
    cpu_usage_ratio        Float64                     CODEC(Gorilla, ZSTD(1)),

    -- ── memory ──────────────────────────────────────────────────────
    rss_bytes              UInt64                      CODEC(Delta, ZSTD(1)),
    rss_min_bytes          UInt64                      CODEC(Delta, ZSTD(1)),
    rss_max_bytes          UInt64                      CODEC(Delta, ZSTD(1)),
    shmem_bytes            UInt64                      CODEC(Delta, ZSTD(1)),
    swap_bytes             UInt64                      CODEC(Delta, ZSTD(1)),
    vsize_bytes            UInt64                      CODEC(Delta, ZSTD(1)),

    -- ── disk I/O (monotonic counters) ───────────────────────────────
    io_read_bytes          UInt64                      CODEC(Delta, ZSTD(1)),
    io_write_bytes         UInt64                      CODEC(Delta, ZSTD(1)),
    maj_flt                UInt64                      CODEC(Delta, ZSTD(1)),
    min_flt                UInt64                      CODEC(Delta, ZSTD(1)),

    -- ── scheduler (monotonic counters) ──────────────────────────────
    nvcsw                  UInt64                      CODEC(Delta, ZSTD(1)),
    nivcsw                 UInt64                      CODEC(Delta, ZSTD(1)),

    -- ── misc ────────────────────────────────────────────────────────
    threads                UInt32                      CODEC(T64, ZSTD(1)),
    oom_score_adj          Int16                       CODEC(T64, ZSTD(1)),
    oom_killed             UInt8                       CODEC(T64, ZSTD(1)),

    -- ── network (monotonic counters) ────────────────────────────────
    net_tx_bytes           UInt64                      CODEC(Delta, ZSTD(1)),
    net_rx_bytes           UInt64                      CODEC(Delta, ZSTD(1)),

    -- ── timing ──────────────────────────────────────────────────────
    start_time_ns          UInt64                      CODEC(Delta, ZSTD(1)),
    uptime_seconds         UInt64                      CODEC(T64, ZSTD(1)),

    -- ── cgroup v2 metrics (filled on snapshot, -1 = not available) ──
    cgroup_memory_max      Int64                       CODEC(T64, ZSTD(1)),
    cgroup_memory_current  Int64                       CODEC(Delta, ZSTD(1)),
    cgroup_swap_current    Int64                       CODEC(Delta, ZSTD(1)),
    cgroup_cpu_weight      Int64                       CODEC(T64, ZSTD(1)),
    cgroup_pids_current    Int64                       CODEC(T64, ZSTD(1)),

    -- ── skip indices ────────────────────────────────────────────────
    INDEX idx_pid pid TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, event_type, rule, pid, timestamp)
TTL timestamp + INTERVAL 30 DAY
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 10485760,      -- 10 MB: small parts stay compact
    merge_with_ttl_timeout = 86400;          -- check TTL once per day


-- ══════════════════════════════════════════════════════════════════════
-- Refreshable Materialized View — auto-pull from process_metrics HTTP
--
-- ClickHouse periodically (every 30 seconds) fetches CSV from the
-- process_metrics HTTP server and inserts rows into process_metrics table.
--
-- Requirements:
--   - ClickHouse >= 23.12 (REFRESH EVERY support)
--   - process_metrics running with http_server.port on the target host
--
-- Usage:
--   1. Create the process_metrics table above
--   2. Create one view per target server (adjust URL)
--   3. ClickHouse will auto-pull metrics; the target clears data after delivery
--
-- IMPORTANT: explicit column structure is required in url() to prevent
-- ClickHouse from making a probe GET request that would drain the CSV buffer.
-- With explicit structure, ClickHouse makes only one GET request.
--
-- Timestamp is in ISO 8601 format (YYYY-MM-DD HH:MM:SS.mmm, UTC).
-- ══════════════════════════════════════════════════════════════════════

-- Example: pull from server1 every 30 seconds
-- CREATE MATERIALIZED VIEW process_metrics_pull_server1
-- REFRESH EVERY 30 SECOND
-- TO process_metrics
-- AS
-- SELECT *
-- FROM url(
--     'http://server1:9091/metrics?format=csv',
--     'CSVWithNames',
--     'timestamp DateTime64(3), hostname String, event_type String, rule String,
--      root_pid UInt32, pid UInt32, ppid UInt32,
--      comm String, exec String, args String, cgroup String,
--      is_root UInt8, state String, exit_code UInt32,
--      cpu_ns UInt64, cpu_usage_ratio Float64,
--      rss_bytes UInt64, rss_min_bytes UInt64, rss_max_bytes UInt64,
--      shmem_bytes UInt64, swap_bytes UInt64, vsize_bytes UInt64,
--      io_read_bytes UInt64, io_write_bytes UInt64, maj_flt UInt64, min_flt UInt64,
--      nvcsw UInt64, nivcsw UInt64, threads UInt32, oom_score_adj Int16, oom_killed UInt8,
--      net_tx_bytes UInt64, net_rx_bytes UInt64, start_time_ns UInt64, uptime_seconds UInt64,
--      cgroup_memory_max Int64, cgroup_memory_current Int64, cgroup_swap_current Int64,
--      cgroup_cpu_weight Int64, cgroup_pids_current Int64'
-- );

-- ══════════════════════════════════════════════════════════════════════
-- Alternative: one-shot import (no materialized view)
-- IMPORTANT: must include explicit structure to avoid double GET
-- ══════════════════════════════════════════════════════════════════════

-- INSERT INTO process_metrics
-- SELECT * FROM url(
--     'http://server1:9091/metrics?format=csv',
--     'CSVWithNames',
--     'timestamp DateTime64(3), hostname String, event_type String, rule String,
--      root_pid UInt32, pid UInt32, ppid UInt32,
--      comm String, exec String, args String, cgroup String,
--      is_root UInt8, state String, exit_code UInt32,
--      cpu_ns UInt64, cpu_usage_ratio Float64,
--      rss_bytes UInt64, rss_min_bytes UInt64, rss_max_bytes UInt64,
--      shmem_bytes UInt64, swap_bytes UInt64, vsize_bytes UInt64,
--      io_read_bytes UInt64, io_write_bytes UInt64, maj_flt UInt64, min_flt UInt64,
--      nvcsw UInt64, nivcsw UInt64, threads UInt32, oom_score_adj Int16, oom_killed UInt8,
--      net_tx_bytes UInt64, net_rx_bytes UInt64, start_time_ns UInt64, uptime_seconds UInt64,
--      cgroup_memory_max Int64, cgroup_memory_current Int64, cgroup_swap_current Int64,
--      cgroup_cpu_weight Int64, cgroup_pids_current Int64'
-- );
