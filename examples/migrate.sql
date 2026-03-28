-- migrate.sql — универсальная миграция таблицы process_metrics
--
-- Сравнивает эталонную схему (process_metrics_reference) с существующей
-- таблицей (process_metrics) и генерирует ALTER TABLE ADD COLUMN
-- для каждой недостающей колонки, вставляя её в правильную позицию.
--
-- Использование:
--   1. Запустить этот скрипт — он выведет ALTER TABLE команды:
--        clickhouse-client --multiquery < migrate.sql
--
--   2. Выполнить сгенерированные ALTER TABLE команды.
--
--   3. Пересоздать MV с новой структурой url() (см. clickhouse_schema.sql).
--
-- Старые данные автоматически получают дефолтные значения для новых колонок:
--   String/LowCardinality(String) → ''
--   UInt*/Int* → 0
--   Float* → 0.0
--   Array → []
-- Никакого INSERT/SELECT не требуется.

-- ── Шаг 1: Создать эталонную таблицу (Engine = Null — не хранит данных) ──
-- Эта таблица содержит актуальную схему из clickhouse_schema.sql.
-- При добавлении новых колонок — обновите и здесь.

DROP TABLE IF EXISTS _pm_reference;
CREATE TABLE _pm_reference (
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
    parent_pids            Array(UInt32)               CODEC(ZSTD(1))
) ENGINE = Null;

-- ── Шаг 2: Сгенерировать ALTER TABLE для недостающих колонок ─────────
--
-- Вывод — готовые SQL-команды. Скопируйте и выполните.
-- Если таблица уже актуальна — вывод будет пустой.

SELECT concat(
    'ALTER TABLE process_metrics ADD COLUMN IF NOT EXISTS ',
    name, ' ', type,
    if(prev_name != '', concat(' AFTER ', prev_name), ''),
    ';'
) AS migration_sql
FROM (
    SELECT
        name,
        type,
        position,
        lag(name) OVER (ORDER BY position) AS prev_name
    FROM system.columns
    WHERE database = currentDatabase()
      AND table = '_pm_reference'
) AS r
WHERE name NOT IN (
    SELECT name FROM system.columns
    WHERE database = currentDatabase() AND table = 'process_metrics'
)
ORDER BY position;

-- ── Шаг 3: Очистка ─────────────────────────────────────────────────

DROP TABLE IF EXISTS _pm_reference;
