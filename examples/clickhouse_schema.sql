-- clickhouse_schema.sql — идемпотентное создание/миграция process_metrics
--
-- Запуск: clickhouse-client --multiquery < clickhouse_schema.sql
-- Затем выполните сгенерированные команды из вывода.

-- ── Шаг 1: эталонная таблица ────────────────────────────────────────

DROP TABLE IF EXISTS _pm_target;

CREATE TABLE _pm_target (
    timestamp              DateTime64(3)               CODEC(Delta, ZSTD(1)),
    hostname               LowCardinality(String)      CODEC(ZSTD(1)),
    event_type             LowCardinality(String)      CODEC(ZSTD(1)),
    rule                   LowCardinality(String)      CODEC(ZSTD(1)),
    tags                   Array(String)               CODEC(ZSTD(1)),
    root_pid               UInt32                      CODEC(T64, ZSTD(1)),
    pid                    UInt32                      CODEC(T64, ZSTD(1)),
    ppid                   UInt32                      CODEC(T64, ZSTD(1)),
    uid                    UInt32                      CODEC(T64, ZSTD(1)),
    user_name              LowCardinality(String)      CODEC(ZSTD(1)),
    loginuid               UInt32                      CODEC(T64, ZSTD(1)),
    login_name             LowCardinality(String)      CODEC(ZSTD(1)),
    sessionid              UInt32                      CODEC(T64, ZSTD(1)),
    euid                   UInt32                      CODEC(T64, ZSTD(1)),
    euser_name             LowCardinality(String)      CODEC(ZSTD(1)),
    tty_nr                 UInt32                      CODEC(T64, ZSTD(1)),
    comm                   LowCardinality(String)      CODEC(ZSTD(1)),
    exec                   String                      CODEC(ZSTD(1)),
    args                   String                      CODEC(ZSTD(1)),
    cgroup                 LowCardinality(String)      CODEC(ZSTD(1)),
    pwd                    String                      CODEC(ZSTD(1)),
    is_root                UInt8                       CODEC(T64, ZSTD(1)),
    state                  LowCardinality(String)      CODEC(ZSTD(1)),
    exit_code              UInt32                      CODEC(T64, ZSTD(1)),
    sched_policy           UInt32                      CODEC(T64, ZSTD(1)),
    cpu_ns                 UInt64                      CODEC(Delta, ZSTD(1)),
    cpu_usage_ratio        Float64                     CODEC(Gorilla, ZSTD(1)),
    rss_bytes              UInt64                      CODEC(Delta, ZSTD(1)),
    rss_min_bytes          UInt64                      CODEC(T64, ZSTD(1)),
    rss_max_bytes          UInt64                      CODEC(T64, ZSTD(1)),
    shmem_bytes            UInt64                      CODEC(Delta, ZSTD(1)),
    swap_bytes             UInt64                      CODEC(Delta, ZSTD(1)),
    vsize_bytes            UInt64                      CODEC(Delta, ZSTD(1)),
    io_read_bytes          UInt64                      CODEC(Delta, ZSTD(1)),
    io_write_bytes         UInt64                      CODEC(Delta, ZSTD(1)),
    io_rchar               UInt64                      CODEC(Delta, ZSTD(1)),
    io_wchar               UInt64                      CODEC(Delta, ZSTD(1)),
    io_syscr               UInt64                      CODEC(Delta, ZSTD(1)),
    io_syscw               UInt64                      CODEC(Delta, ZSTD(1)),
    maj_flt                UInt64                      CODEC(Delta, ZSTD(1)),
    min_flt                UInt64                      CODEC(Delta, ZSTD(1)),
    nvcsw                  UInt64                      CODEC(Delta, ZSTD(1)),
    nivcsw                 UInt64                      CODEC(Delta, ZSTD(1)),
    threads                UInt32                      CODEC(T64, ZSTD(1)),
    oom_score_adj          Int16                       CODEC(T64, ZSTD(1)),
    oom_killed             UInt8                       CODEC(T64, ZSTD(1)),
    net_tx_bytes           UInt64                      CODEC(Delta, ZSTD(1)),
    net_rx_bytes           UInt64                      CODEC(Delta, ZSTD(1)),
    start_time_ns          UInt64                      CODEC(DoubleDelta, ZSTD(1)),
    uptime_seconds         UInt64                      CODEC(T64, ZSTD(1)),
    mnt_ns                 UInt32                      CODEC(T64, ZSTD(1)),
    pid_ns                 UInt32                      CODEC(T64, ZSTD(1)),
    net_ns                 UInt32                      CODEC(T64, ZSTD(1)),
    cgroup_ns              UInt32                      CODEC(T64, ZSTD(1)),
    preempted_by_pid       UInt32                      CODEC(T64, ZSTD(1)),
    preempted_by_comm      LowCardinality(String)      CODEC(ZSTD(1)),
    cgroup_memory_max      Int64                       CODEC(T64, ZSTD(1)),
    cgroup_memory_current  Int64                       CODEC(Delta, ZSTD(1)),
    cgroup_swap_current    Int64                       CODEC(Delta, ZSTD(1)),
    cgroup_cpu_weight      Int64                       CODEC(T64, ZSTD(1)),
    cgroup_cpu_max         Int64                       CODEC(T64, ZSTD(1)),
    cgroup_cpu_max_period  Int64                       CODEC(T64, ZSTD(1)),
    cgroup_cpu_nr_periods  Int64                       CODEC(Delta, ZSTD(1)),
    cgroup_cpu_nr_throttled Int64                      CODEC(Delta, ZSTD(1)),
    cgroup_cpu_throttled_usec Int64                    CODEC(Delta, ZSTD(1)),
    cgroup_pids_current    Int64                       CODEC(T64, ZSTD(1)),
    file_path              String                      CODEC(ZSTD(1)),
    file_flags             UInt32                      CODEC(T64, ZSTD(1)),
    file_read_bytes        UInt64                      CODEC(Delta, ZSTD(1)),
    file_write_bytes       UInt64                      CODEC(Delta, ZSTD(1)),
    file_open_count        UInt32                      CODEC(T64, ZSTD(1)),
    net_local_addr         String                      CODEC(ZSTD(1)),
    net_remote_addr        String                      CODEC(ZSTD(1)),
    net_local_port         UInt16                      CODEC(T64, ZSTD(1)),
    net_remote_port        UInt16                      CODEC(T64, ZSTD(1)),
    net_conn_tx_bytes      UInt64                      CODEC(Delta, ZSTD(1)),
    net_conn_rx_bytes      UInt64                      CODEC(Delta, ZSTD(1)),
    net_conn_tx_calls      UInt64                      CODEC(Delta, ZSTD(1)),
    net_conn_rx_calls      UInt64                      CODEC(Delta, ZSTD(1)),
    net_duration_ms        UInt64                      CODEC(T64, ZSTD(1)),
    sig_num                UInt32                      CODEC(T64, ZSTD(1)),
    sig_target_pid         UInt32                      CODEC(T64, ZSTD(1)),
    sig_target_comm        LowCardinality(String)      CODEC(ZSTD(1)),
    sig_code               Int32                       CODEC(T64, ZSTD(1)),
    sig_result             Int32                       CODEC(T64, ZSTD(1)),
    sec_local_addr         String                      CODEC(ZSTD(1)),
    sec_remote_addr        String                      CODEC(ZSTD(1)),
    sec_local_port         UInt16                      CODEC(T64, ZSTD(1)),
    sec_remote_port        UInt16                      CODEC(T64, ZSTD(1)),
    sec_af                 UInt8                       CODEC(T64, ZSTD(1)),
    sec_tcp_state          UInt8                       CODEC(T64, ZSTD(1)),
    sec_direction          UInt8                       CODEC(T64, ZSTD(1)),
    open_tcp_conns         UInt64                      CODEC(T64, ZSTD(1)),
    disk_total_bytes       UInt64                      CODEC(T64, ZSTD(1)),
    disk_used_bytes        UInt64                      CODEC(T64, ZSTD(1)),
    disk_avail_bytes       UInt64                      CODEC(T64, ZSTD(1)),
    parent_pids            Array(UInt32)               CODEC(ZSTD(1)),

    INDEX idx_pid       pid            TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_cgroup    cgroup         TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_login     login_name     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_sec_addr  sec_remote_addr TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, event_type, rule, pid, timestamp)
TTL
    timestamp + INTERVAL 7 DAY DELETE WHERE event_type = 'file_close',
    timestamp + INTERVAL 30 DAY DELETE
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 10485760,
    merge_with_ttl_timeout = 86400;


-- ── Шаг 2: INSERT для копирования данных ────────────────────────────
-- Генерирует INSERT с пересечением колонок. Выполните результат.
-- При первой установке — пропустите.

SELECT format(
    'INSERT INTO _pm_target ({0}) SELECT {0} FROM process_metrics SETTINGS max_insert_threads=4, max_execution_time=0;',
    cols
)
FROM (
    SELECT arrayStringConcat(groupArray(name), ', ') AS cols
    FROM (
        SELECT name FROM system.columns
        WHERE database = currentDatabase() AND table = 'process_metrics'
          AND name IN (SELECT name FROM system.columns
                       WHERE database = currentDatabase() AND table = '_pm_target')
        ORDER BY position
    )
)
WHERE (SELECT count() FROM system.tables
       WHERE database = currentDatabase() AND name = 'process_metrics') > 0;


-- ── Шаг 3: переключение ────────────────────────────────────────────
-- Выполните после шага 2.

SELECT if(
    (SELECT count() FROM system.tables
     WHERE database = currentDatabase() AND name = 'process_metrics') > 0,
    'EXCHANGE TABLES process_metrics AND _pm_target;',
    'RENAME TABLE _pm_target TO process_metrics;'
);


-- ── Шаг 4: projection ──────────────────────────────────────────────
-- Выполните после шага 3.

SELECT 'ALTER TABLE process_metrics ADD PROJECTION IF NOT EXISTS proj_time_series (SELECT * ORDER BY (hostname, event_type, timestamp, rule, pid));';
SELECT 'ALTER TABLE process_metrics MATERIALIZE PROJECTION proj_time_series;';


-- ── Шаг 5: пересоздание MV ─────────────────────────────────────────
-- Генерирует DROP+CREATE с прежним URL и актуальной структурой.
-- Выполните если менялся набор колонок в CSV.

SELECT format('DROP VIEW IF EXISTS {0};\nCREATE MATERIALIZED VIEW {0}\nREFRESH EVERY 3 SECOND RANDOMIZE FOR 1 SECOND APPEND\nTO {1}.process_metrics\nAS\nSELECT * REPLACE (\n    if(tags = '''', [], splitByChar(''|'', tags)) AS tags,\n    if(parent_pids = '''', [], arrayMap(x -> toUInt32(x), splitByChar(''|'', parent_pids))) AS parent_pids\n)\nFROM url(''{2}'', ''CSVWithNames'', ''{3}'');',
    mv.name,
    currentDatabase(),
    extractAll(mv.create_table_query, 'url\\(''([^'']+)''')[1],
    url_cols.cols
)
FROM system.tables AS mv
CROSS JOIN (
    SELECT arrayStringConcat(groupArray(
        name || ' ' || multiIf(
            name = 'timestamp', 'DateTime64(3, ''''UTC'''')',
            name IN ('tags', 'parent_pids'), 'String',
            type LIKE 'LowCardinality(%)', extractAll(type, 'LowCardinality\\((.+)\\)')[1],
            type
        )
    ), ', ') AS cols
    FROM (SELECT name, type FROM system.columns
          WHERE database = currentDatabase() AND table = '_pm_target'
          ORDER BY position)
) AS url_cols
WHERE mv.database = currentDatabase()
  AND mv.engine = 'MaterializedView'
  AND mv.create_table_query LIKE concat('%TO ', currentDatabase(), '.process_metrics%');


-- ── Шаг 6: очистка ─────────────────────────────────────────────────
-- Выполните после проверки.

SELECT 'DROP TABLE IF EXISTS _pm_target;';
