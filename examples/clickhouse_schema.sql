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
    rule_pid               UInt32                      CODEC(T64, ZSTD(1)),
    pid                    UInt32                      CODEC(T64, ZSTD(1)),
    ppid                   UInt32                      CODEC(T64, ZSTD(1)),
    process_chain            Array(UInt32)               CODEC(ZSTD(1)),
    uid                    UInt32                      CODEC(T64, ZSTD(1)),
    user_name              LowCardinality(String)      CODEC(ZSTD(1)),
    loginuid               UInt32                      CODEC(T64, ZSTD(1)),
    login_name             LowCardinality(String)      CODEC(ZSTD(1)),
    sessionid              UInt32                      CODEC(T64, ZSTD(1)),
    session_name           LowCardinality(String)      CODEC(ZSTD(1)),
    euid                   UInt32                      CODEC(T64, ZSTD(1)),
    euser_name             LowCardinality(String)      CODEC(ZSTD(1)),
    tty_nr                 UInt32                      CODEC(T64, ZSTD(1)),
    comm                   LowCardinality(String)      CODEC(ZSTD(1)),
    thread_name            LowCardinality(String)      CODEC(ZSTD(1)),
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
    file_opens             UInt64                      CODEC(Delta, ZSTD(1)),
    socket_creates         UInt64                      CODEC(Delta, ZSTD(1)),
    maj_flt                UInt64                      CODEC(Delta, ZSTD(1)),
    min_flt                UInt64                      CODEC(Delta, ZSTD(1)),
    nvcsw                  UInt64                      CODEC(Delta, ZSTD(1)),
    nivcsw                 UInt64                      CODEC(Delta, ZSTD(1)),
    threads                UInt32                      CODEC(T64, ZSTD(1)),
    oom_score_adj          Int16                       CODEC(T64, ZSTD(1)),
    oom_killed             UInt8                       CODEC(T64, ZSTD(1)),
    net_tcp_tx_bytes       UInt64                      CODEC(Delta, ZSTD(1)),
    net_tcp_rx_bytes       UInt64                      CODEC(Delta, ZSTD(1)),
    net_udp_tx_bytes       UInt64                      CODEC(Delta, ZSTD(1)),
    net_udp_rx_bytes       UInt64                      CODEC(Delta, ZSTD(1)),
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
    file_new_path          String                      CODEC(ZSTD(1)),
    file_flags             Array(String)               CODEC(ZSTD(1)),
    file_read_bytes        UInt64                      CODEC(Delta, ZSTD(1)),
    file_write_bytes       UInt64                      CODEC(Delta, ZSTD(1)),
    file_open_count        UInt32                      CODEC(T64, ZSTD(1)),
    file_fsync_count       UInt32                      CODEC(T64, ZSTD(1)),
    file_chmod_mode        UInt32                      CODEC(T64, ZSTD(1)),
    file_chown_uid         UInt32                      CODEC(T64, ZSTD(1)),
    file_chown_gid         UInt32                      CODEC(T64, ZSTD(1)),
    net_local_addr         String                      CODEC(ZSTD(1)),
    net_remote_addr        String                      CODEC(ZSTD(1)),
    net_local_port         UInt16                      CODEC(T64, ZSTD(1)),
    net_remote_port        UInt16                      CODEC(T64, ZSTD(1)),
    net_conn_tx_bytes      UInt64                      CODEC(Delta, ZSTD(1)),
    net_conn_rx_bytes      UInt64                      CODEC(Delta, ZSTD(1)),
    net_conn_tx_calls      UInt64                      CODEC(Delta, ZSTD(1)),
    net_conn_rx_calls      UInt64                      CODEC(Delta, ZSTD(1)),
    net_duration_ms        UInt64                      CODEC(T64, ZSTD(1)),
    net_tcp_state          LowCardinality(String)      CODEC(ZSTD(1)),
    sig_num                UInt32                      CODEC(T64, ZSTD(1)),
    sig_name               LowCardinality(String)      CODEC(ZSTD(1)),
    sig_sender_pid         UInt32                      CODEC(T64, ZSTD(1)),
    sig_sender_comm        LowCardinality(String)      CODEC(ZSTD(1)),
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

    INDEX idx_pid       pid            TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_cgroup    cgroup         TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_login     login_name     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_tags      tags           TYPE bloom_filter(0.01) GRANULARITY 4,
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


-- ── Шаг 2: остановка MV и копирование данных ────────────────────────
-- ВАЖНО: сначала остановите все MV чтобы они не очищали буфер
-- и не писали в таблицу во время миграции.
-- Выполните для каждого MV:  SYSTEM STOP VIEW <имя_mv>;
--
-- Генерирует INSERT с пересечением колонок. Выполните результат.
-- При первой установке — пропустите.

SELECT format('SYSTEM STOP VIEW {0};', name)
FROM system.tables
WHERE database = currentDatabase()
  AND engine = 'MaterializedView'
  AND create_table_query LIKE concat('%TO ', currentDatabase(), '.process_metrics%');

-- Генерирует INSERT с пересечением колонок + маппинг переименованных.
-- net_tx_bytes → net_tcp_tx_bytes, net_rx_bytes → net_tcp_rx_bytes
-- (старые данные не разделяли TCP/UDP, весь трафик был преимущественно TCP).
SELECT format(
    'INSERT INTO _pm_target ({0}) SELECT {1} FROM process_metrics SETTINGS max_insert_threads=4, max_execution_time=0;',
    dst_cols, src_cols
)
FROM (
    SELECT
        arrayStringConcat(groupArray(dst_name), ', ') AS dst_cols,
        arrayStringConcat(groupArray(src_expr), ', ') AS src_cols
    FROM (
        SELECT dst_name, src_expr FROM (
            SELECT name AS dst_name, name AS src_expr
            FROM system.columns
            WHERE database = currentDatabase() AND table = 'process_metrics'
              AND name IN (SELECT name FROM system.columns
                           WHERE database = currentDatabase() AND table = '_pm_target')

            UNION ALL

            -- Маппинг: net_tx_bytes → net_tcp_tx_bytes (если старая колонка есть)
            SELECT 'net_tcp_tx_bytes', 'net_tx_bytes'
            WHERE (SELECT count() FROM system.columns
                   WHERE database = currentDatabase() AND table = 'process_metrics'
                     AND name = 'net_tx_bytes') > 0
              AND (SELECT count() FROM system.columns
                   WHERE database = currentDatabase() AND table = 'process_metrics'
                     AND name = 'net_tcp_tx_bytes') = 0

            UNION ALL

            SELECT 'net_tcp_rx_bytes', 'net_rx_bytes'
            WHERE (SELECT count() FROM system.columns
                   WHERE database = currentDatabase() AND table = 'process_metrics'
                     AND name = 'net_rx_bytes') > 0
              AND (SELECT count() FROM system.columns
                   WHERE database = currentDatabase() AND table = 'process_metrics'
                     AND name = 'net_tcp_rx_bytes') = 0
        )
        ORDER BY dst_name
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

WITH
url_cols AS (
    SELECT arrayStringConcat(groupArray(
        name || ' ' || multiIf(
            name = 'timestamp',                                'DateTime64(3, ''UTC'')',
            name = 'start_time_ns',                            'DateTime64(9, ''UTC'')',
            name IN ('tags', 'process_chain', 'file_flags'),   'String',
            type LIKE 'LowCardinality(%)',                     extractAll(type, 'LowCardinality\\((.+)\\)')[1],
            type
        )
    ), ', ') AS cols
    FROM (SELECT name, type FROM system.columns
          WHERE database = currentDatabase() AND table = '_pm_target'
          ORDER BY position)
),
mv_list AS (
    SELECT
        name,
        extractAll(create_table_query, 'url\\(''([^'']+)''')[1] AS url
    FROM system.tables
    WHERE database = currentDatabase()
      AND engine = 'MaterializedView'
      AND create_table_query LIKE concat('%TO ', currentDatabase(), '.process_metrics%')
)
SELECT format($$DROP VIEW IF EXISTS {0};
CREATE MATERIALIZED VIEW {0}
REFRESH EVERY 3 SECOND APPEND
TO {1}.process_metrics
AS
SELECT * REPLACE (
    if(tags = '', [], splitByChar('|', tags)) AS tags,
    if(process_chain = '', [], arrayMap(x -> toUInt32(x), splitByChar('|', process_chain))) AS process_chain,
    if(file_flags = '', [], splitByChar('|', file_flags)) AS file_flags
)
FROM url('{2}', 'CSVWithNames', '{3}');$$,
    mv_list.name,
    currentDatabase(),
    mv_list.url,
    url_cols.cols
)
FROM mv_list, url_cols;


-- ── Шаг 6: очистка ─────────────────────────────────────────────────
-- Выполните после проверки.

SELECT 'DROP TABLE IF EXISTS _pm_target;';


-- ── Шаг 7: создание нового MV ──────────────────────────────────────
-- Замените <URL> на реальный адрес (http://host:port/metrics?format=csv&clear=1).

CREATE MATERIALIZED VIEW mv_process_metrics
REFRESH EVERY 3 SECOND APPEND
TO process_metrics
AS
SELECT * REPLACE (
    if(tags = '', [], splitByChar('|', tags))                                                    AS tags,
    if(process_chain = '', [], arrayMap(x -> toUInt32(x), splitByChar('|', process_chain)))      AS process_chain,
    if(file_flags = '', [], splitByChar('|', file_flags))                                        AS file_flags
)
FROM url('<URL>', 'CSVWithNames', $$
    timestamp              DateTime64(3, 'UTC'),
    hostname               String,
    event_type             String,
    rule                   String,
    tags                   String,
    rule_pid               UInt32,
    pid                    UInt32,
    ppid                   UInt32,
    process_chain          String,
    uid                    UInt32,
    user_name              String,
    loginuid               UInt32,
    login_name             String,
    sessionid              UInt32,
    session_name           String,
    euid                   UInt32,
    euser_name             String,
    tty_nr                 UInt32,
    comm                   String,
    thread_name            String,
    exec                   String,
    args                   String,
    cgroup                 String,
    pwd                    String,
    is_root                UInt8,
    state                  String,
    exit_code              UInt32,
    sched_policy           UInt32,
    cpu_ns                 UInt64,
    cpu_usage_ratio        Float64,
    rss_bytes              UInt64,
    rss_min_bytes          UInt64,
    rss_max_bytes          UInt64,
    shmem_bytes            UInt64,
    swap_bytes             UInt64,
    vsize_bytes            UInt64,
    io_read_bytes          UInt64,
    io_write_bytes         UInt64,
    io_rchar               UInt64,
    io_wchar               UInt64,
    io_syscr               UInt64,
    io_syscw               UInt64,
    file_opens             UInt64,
    socket_creates         UInt64,
    maj_flt                UInt64,
    min_flt                UInt64,
    nvcsw                  UInt64,
    nivcsw                 UInt64,
    threads                UInt32,
    oom_score_adj          Int16,
    oom_killed             UInt8,
    net_tcp_tx_bytes       UInt64,
    net_tcp_rx_bytes       UInt64,
    net_udp_tx_bytes       UInt64,
    net_udp_rx_bytes       UInt64,
    start_time_ns          DateTime64(9, 'UTC'),
    uptime_seconds         UInt64,
    mnt_ns                 UInt32,
    pid_ns                 UInt32,
    net_ns                 UInt32,
    cgroup_ns              UInt32,
    preempted_by_pid       UInt32,
    preempted_by_comm      String,
    cgroup_memory_max      Int64,
    cgroup_memory_current  Int64,
    cgroup_swap_current    Int64,
    cgroup_cpu_weight      Int64,
    cgroup_cpu_max         Int64,
    cgroup_cpu_max_period  Int64,
    cgroup_cpu_nr_periods  Int64,
    cgroup_cpu_nr_throttled Int64,
    cgroup_cpu_throttled_usec Int64,
    cgroup_pids_current    Int64,
    file_path              String,
    file_new_path          String,
    file_flags             String,
    file_read_bytes        UInt64,
    file_write_bytes       UInt64,
    file_open_count        UInt32,
    file_fsync_count       UInt32,
    file_chmod_mode        UInt32,
    file_chown_uid         UInt32,
    file_chown_gid         UInt32,
    net_local_addr         String,
    net_remote_addr        String,
    net_local_port         UInt16,
    net_remote_port        UInt16,
    net_conn_tx_bytes      UInt64,
    net_conn_rx_bytes      UInt64,
    net_conn_tx_calls      UInt64,
    net_conn_rx_calls      UInt64,
    net_duration_ms        UInt64,
    sig_num                UInt32,
    sig_name               String,
    sig_sender_pid         UInt32,
    sig_sender_comm        String,
    sig_code               Int32,
    sig_result             Int32,
    sec_local_addr         String,
    sec_remote_addr        String,
    sec_local_port         UInt16,
    sec_remote_port        UInt16,
    sec_af                 UInt8,
    sec_tcp_state          UInt8,
    sec_direction          UInt8,
    open_tcp_conns         UInt64,
    disk_total_bytes       UInt64,
    disk_used_bytes        UInt64,
    disk_avail_bytes       UInt64
$$);
