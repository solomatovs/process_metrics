-- process_metrics — схема таблицы ClickHouse (оптимизированная)
--
-- Одна таблица для всех типов событий: snapshot, fork, exec, exit, oom_kill,
-- file_close, net_close, signal, tcp_retrans, syn_recv, rst_sent, rst_recv,
-- udp_agg, icmp_agg.
-- Выполнить один раз на сервере ClickHouse.
--
-- Проектные решения:
--
--   ORDER BY (hostname, event_type, rule, pid, timestamp)
--     Почти каждый запрос фильтрует по event_type, поэтому он идёт рано в ключе.
--     hostname первым — эффективные запросы в мультитенантных средах.
--     pid перед timestamp — выборка истории процесса читает смежные блоки.
--     timestamp последним — диапазонные выборки внутри pid идут последовательно.
--
--   Кодеки:
--     Delta    — для монотонно возрастающих счётчиков (cpu_ns, io_*, faults, ctxsw).
--                Delta хранит разности между последовательными значениями; для медленно
--                растущих счётчиков разности малы → ZSTD сжимает их до битов.
--     Gorilla  — IEEE 754 XOR-сжатие для чисел с плавающей точкой (cpu_usage_ratio).
--                Соседние значения snapshot'ов близки → большинство XOR-битов нулевые.
--     T64      — блочная упаковка для целых чисел, не использующих весь 64-битный диапазон
--                (PID'ы, потоки, exit_code, OOM-флаги, лимиты cgroup).
--     ZSTD(1)  — финальное универсальное сжатие на каждой колонке.
--                Уровень 1 даёт ~95% максимальной степени сжатия при ~10x быстрее.
--
--   LowCardinality — словарное кодирование для hostname, event_type, rule, cgroup, comm.
--     Заменяет повторяющиеся строки целочисленными индексами; огромный выигрыш
--     при кардинальности < 10K.
--
--   Партиционирование по месяцам (toYYYYMM) вместо дней:
--     При TTL 30 дней и дневных партициях получаем 30 партиций для слияния/удаления.
--     Помесячно = 1-2 активные партиции, меньше накладных расходов на слияние,
--     та же гранулярность TTL (ClickHouse удаляет партиции, где ВСЕ строки истекли).
--
--   Skip-индексы:
--     bloom_filter на pid — быстрые точечные запросы ("покажи историю PID 12345")
--       без сканирования всех партиций. Работает потому что pid не является первой
--       колонкой ключа, и без индекса ClickHouse сканировал бы все гранулы
--       в пределах префикса (hostname, event_type, rule).

DROP TABLE IF EXISTS process_metrics;
CREATE TABLE IF NOT EXISTS process_metrics (
    -- ── идентификация ─────────────────────────────────────────────
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

    -- ── метаданные процесса ───────────────────────────────────────
    comm                   LowCardinality(String)      CODEC(ZSTD(1)),
    exec                   String                      CODEC(ZSTD(1)),
    args                   String                      CODEC(ZSTD(1)),
    cgroup                 LowCardinality(String)      CODEC(ZSTD(1)),
    pwd                    String                      CODEC(ZSTD(1)),
    is_root                UInt8                       CODEC(T64, ZSTD(1)),
    state                  LowCardinality(String)      CODEC(ZSTD(1)),
    exit_code              UInt32                      CODEC(T64, ZSTD(1)),
    sched_policy           UInt32                      CODEC(T64, ZSTD(1)),

    -- ── CPU ───────────────────────────────────────────────────────
    cpu_ns                 UInt64                      CODEC(Delta, ZSTD(1)),
    cpu_usage_ratio        Float64                     CODEC(Gorilla, ZSTD(1)),

    -- ── память ────────────────────────────────────────────────────
    rss_bytes              UInt64                      CODEC(Delta, ZSTD(1)),
    rss_min_bytes          UInt64                      CODEC(Delta, ZSTD(1)),
    rss_max_bytes          UInt64                      CODEC(Delta, ZSTD(1)),
    shmem_bytes            UInt64                      CODEC(Delta, ZSTD(1)),
    swap_bytes             UInt64                      CODEC(Delta, ZSTD(1)),
    vsize_bytes            UInt64                      CODEC(Delta, ZSTD(1)),

    -- ── I/O (монотонные счётчики) ───────────────────────────────
    io_read_bytes          UInt64                      CODEC(Delta, ZSTD(1)),
    io_write_bytes         UInt64                      CODEC(Delta, ZSTD(1)),
    io_rchar               UInt64                      CODEC(Delta, ZSTD(1)),
    io_wchar               UInt64                      CODEC(Delta, ZSTD(1)),
    io_syscr               UInt64                      CODEC(Delta, ZSTD(1)),
    io_syscw               UInt64                      CODEC(Delta, ZSTD(1)),
    maj_flt                UInt64                      CODEC(Delta, ZSTD(1)),
    min_flt                UInt64                      CODEC(Delta, ZSTD(1)),

    -- ── планировщик / потоки / OOM ──────────────────────────────
    nvcsw                  UInt64                      CODEC(Delta, ZSTD(1)),
    nivcsw                 UInt64                      CODEC(Delta, ZSTD(1)),
    threads                UInt32                      CODEC(T64, ZSTD(1)),
    oom_score_adj          Int16                       CODEC(T64, ZSTD(1)),
    oom_killed             UInt8                       CODEC(T64, ZSTD(1)),

    -- ── сеть процесса (монотонные счётчики) ─────────────────────
    net_tx_bytes           UInt64                      CODEC(Delta, ZSTD(1)),
    net_rx_bytes           UInt64                      CODEC(Delta, ZSTD(1)),

    -- ── временны́е метки ───────────────────────────────────────────
    start_time_ns          UInt64                      CODEC(Delta, ZSTD(1)),
    uptime_seconds         UInt64                      CODEC(T64, ZSTD(1)),

    -- ── пространства имён (inum из /proc/PID/ns) ────────────────
    mnt_ns                 UInt32                      CODEC(T64, ZSTD(1)),
    pid_ns                 UInt32                      CODEC(T64, ZSTD(1)),
    net_ns                 UInt32                      CODEC(T64, ZSTD(1)),
    cgroup_ns              UInt32                      CODEC(T64, ZSTD(1)),

    -- ── preemption tracking (snapshot only) ─────────────────────
    preempted_by_pid       UInt32                      CODEC(T64, ZSTD(1)),
    preempted_by_comm      LowCardinality(String)      CODEC(ZSTD(1)),

    -- ── метрики cgroup v2 (заполняются в snapshot, -1 = недоступно) ─
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

    -- ── файловый трекинг (только события file_close, для остальных — нули) ─
    file_path              String                      CODEC(ZSTD(1)),
    file_flags             UInt32                      CODEC(T64, ZSTD(1)),
    file_read_bytes        UInt64                      CODEC(Delta, ZSTD(1)),
    file_write_bytes       UInt64                      CODEC(Delta, ZSTD(1)),
    file_open_count        UInt32                      CODEC(T64, ZSTD(1)),

    -- ── сетевой трекинг (только события net_close, для остальных — пусто) ─
    net_local_addr         String                      CODEC(ZSTD(1)),
    net_remote_addr        String                      CODEC(ZSTD(1)),
    net_local_port         UInt16                      CODEC(T64, ZSTD(1)),
    net_remote_port        UInt16                      CODEC(T64, ZSTD(1)),
    net_conn_tx_bytes      UInt64                      CODEC(Delta, ZSTD(1)),
    net_conn_rx_bytes      UInt64                      CODEC(Delta, ZSTD(1)),
    net_duration_ms        UInt64                      CODEC(T64, ZSTD(1)),

    -- ── сигналы (только события signal, для остальных — нули/пусто) ─
    sig_num                UInt32                      CODEC(T64, ZSTD(1)),
    sig_target_pid         UInt32                      CODEC(T64, ZSTD(1)),
    sig_target_comm        LowCardinality(String)      CODEC(ZSTD(1)),
    sig_code               Int32                       CODEC(T64, ZSTD(1)),
    sig_result             Int32                       CODEC(T64, ZSTD(1)),

    -- ── security tracking (tcp_retrans, syn_recv, rst_sent/rst_recv) ─
    sec_local_addr         String                      CODEC(ZSTD(1)),
    sec_remote_addr        String                      CODEC(ZSTD(1)),
    sec_local_port         UInt16                      CODEC(T64, ZSTD(1)),
    sec_remote_port        UInt16                      CODEC(T64, ZSTD(1)),
    sec_af                 UInt8                       CODEC(T64, ZSTD(1)),
    sec_tcp_state          UInt8                       CODEC(T64, ZSTD(1)),
    sec_direction          UInt8                       CODEC(T64, ZSTD(1)),
    open_tcp_conns         UInt64                      CODEC(T64, ZSTD(1)),

    -- ── disk usage (только события disk_usage, для остальных — нули) ─
    disk_total_bytes       UInt64                      CODEC(T64, ZSTD(1)),
    disk_used_bytes        UInt64                      CODEC(T64, ZSTD(1)),
    disk_avail_bytes       UInt64                      CODEC(T64, ZSTD(1)),

    -- ── skip-индексы ──────────────────────────────────────────────
    INDEX idx_pid pid TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, event_type, rule, pid, timestamp)
TTL timestamp + INTERVAL 30 DAY
SETTINGS
    index_granularity = 8192,
    min_bytes_for_wide_part = 10485760,      -- 10 МБ: маленькие части остаются компактными
    merge_with_ttl_timeout = 86400;          -- проверка TTL раз в сутки


-- ══════════════════════════════════════════════════════════════════════
-- Обновляемое материализованное представление — автоматический pull
-- из HTTP-сервера process_metrics
--
-- ClickHouse периодически (каждые 30 секунд) забирает CSV с HTTP-сервера
-- process_metrics и вставляет строки в таблицу process_metrics.
--
-- Требования:
--   - ClickHouse >= 23.12 (поддержка REFRESH EVERY)
--   - process_metrics запущен с http_server.port на целевом хосте
--
-- Использование:
--   1. Создать таблицу process_metrics (см. выше)
--   2. Создать по одному view на каждый целевой сервер (изменить URL)
--   3. ClickHouse будет автоматически забирать метрики; целевой сервер
--      очищает данные после отдачи
--
-- ВАЖНО: используйте ключевое слово APPEND, чтобы данные накапливались
-- между обновлениями. Без APPEND каждое обновление ЗАМЕНЯЕТ все данные
-- в целевой таблице.
--
-- Используйте параметр &clear=1, чтобы буфер очищался после отдачи.
-- Без &clear=1 данные возвращаются, но НЕ очищаются (режим только чтения).
--
-- Явная структура колонок обязательна в url(), чтобы ClickHouse не делал
-- пробный GET-запрос. С явной структурой ClickHouse делает только один
-- GET-запрос.
--
-- Временна́я метка в формате ISO 8601 (YYYY-MM-DD HH:MM:SS.mmm, UTC).
-- ══════════════════════════════════════════════════════════════════════

-- Пример: забирать данные с server1 каждые 30 секунд
-- RANDOMIZE FOR — при ошибке (например, перезапуск process_metrics)
-- ClickHouse сдвигает следующий refresh на случайный интервал,
-- чтобы избежать зависания планировщика.
DROP VIEW IF EXISTS process_metrics_pull_server1;
CREATE MATERIALIZED VIEW process_metrics_pull_server1
REFRESH EVERY 3 SECOND RANDOMIZE FOR 1 SECOND APPEND
TO process_metrics
AS
SELECT * REPLACE (if(tags = '', [], splitByChar('|', tags)) AS tags)
FROM url(
    'http://server1:10003/metrics?format=csv&clear=1',
    'CSVWithNames',
    'timestamp DateTime64(3, 'UTC'), hostname String, event_type String, rule String, tags String,
     root_pid UInt32, pid UInt32, ppid UInt32, uid UInt32, user_name String,
     loginuid UInt32, login_name String, sessionid UInt32, euid UInt32, euser_name String, tty_nr UInt32,
     comm String, exec String, args String, cgroup String, pwd String,
     is_root UInt8, state String, exit_code UInt32, sched_policy UInt32,
     cpu_ns UInt64, cpu_usage_ratio Float64,
     rss_bytes UInt64, rss_min_bytes UInt64, rss_max_bytes UInt64,
     shmem_bytes UInt64, swap_bytes UInt64, vsize_bytes UInt64,
     io_read_bytes UInt64, io_write_bytes UInt64,
     io_rchar UInt64, io_wchar UInt64, io_syscr UInt64, io_syscw UInt64,
     maj_flt UInt64, min_flt UInt64,
     nvcsw UInt64, nivcsw UInt64, threads UInt32, oom_score_adj Int16, oom_killed UInt8,
     net_tx_bytes UInt64, net_rx_bytes UInt64,
     start_time_ns UInt64, uptime_seconds UInt64,
     mnt_ns UInt32, pid_ns UInt32, net_ns UInt32, cgroup_ns UInt32,
     preempted_by_pid UInt32, preempted_by_comm String,
     cgroup_memory_max Int64, cgroup_memory_current Int64, cgroup_swap_current Int64,
     cgroup_cpu_weight Int64, cgroup_cpu_max Int64, cgroup_cpu_max_period Int64,
     cgroup_cpu_nr_periods Int64, cgroup_cpu_nr_throttled Int64, cgroup_cpu_throttled_usec Int64,
     cgroup_pids_current Int64,
     file_path String, file_flags UInt32, file_read_bytes UInt64, file_write_bytes UInt64,
     file_open_count UInt32,
     net_local_addr String, net_remote_addr String, net_local_port UInt16, net_remote_port UInt16,
     net_conn_tx_bytes UInt64, net_conn_rx_bytes UInt64, net_duration_ms UInt64,
     sig_num UInt32, sig_target_pid UInt32, sig_target_comm String,
     sig_code Int32, sig_result Int32,
     sec_local_addr String, sec_remote_addr String,
     sec_local_port UInt16, sec_remote_port UInt16,
     sec_af UInt8, sec_tcp_state UInt8, sec_direction UInt8,
     open_tcp_conns UInt64,
     disk_total_bytes UInt64, disk_used_bytes UInt64, disk_avail_bytes UInt64'
);

-- ══════════════════════════════════════════════════════════════════════
-- Альтернатива: разовый импорт (без материализованного представления)
-- ВАЖНО: необходимо указать явную структуру, чтобы избежать двойного GET
-- ══════════════════════════════════════════════════════════════════════

INSERT INTO process_metrics
SELECT * FROM url(
    'http://server1:10003/metrics?format=csv&clear=1',
    'CSVWithNames',
    'timestamp DateTime64(3, 'UTC'), hostname String, event_type String, rule String, tags String,
     root_pid UInt32, pid UInt32, ppid UInt32, uid UInt32, user_name String,
     loginuid UInt32, login_name String, sessionid UInt32, euid UInt32, euser_name String, tty_nr UInt32,
     comm String, exec String, args String, cgroup String, pwd String,
     is_root UInt8, state String, exit_code UInt32, sched_policy UInt32,
     cpu_ns UInt64, cpu_usage_ratio Float64,
     rss_bytes UInt64, rss_min_bytes UInt64, rss_max_bytes UInt64,
     shmem_bytes UInt64, swap_bytes UInt64, vsize_bytes UInt64,
     io_read_bytes UInt64, io_write_bytes UInt64,
     io_rchar UInt64, io_wchar UInt64, io_syscr UInt64, io_syscw UInt64,
     maj_flt UInt64, min_flt UInt64,
     nvcsw UInt64, nivcsw UInt64, threads UInt32, oom_score_adj Int16, oom_killed UInt8,
     net_tx_bytes UInt64, net_rx_bytes UInt64,
     start_time_ns UInt64, uptime_seconds UInt64,
     mnt_ns UInt32, pid_ns UInt32, net_ns UInt32, cgroup_ns UInt32,
     preempted_by_pid UInt32, preempted_by_comm String,
     cgroup_memory_max Int64, cgroup_memory_current Int64, cgroup_swap_current Int64,
     cgroup_cpu_weight Int64, cgroup_cpu_max Int64, cgroup_cpu_max_period Int64,
     cgroup_cpu_nr_periods Int64, cgroup_cpu_nr_throttled Int64, cgroup_cpu_throttled_usec Int64,
     cgroup_pids_current Int64,
     file_path String, file_flags UInt32, file_read_bytes UInt64, file_write_bytes UInt64,
     file_open_count UInt32,
     net_local_addr String, net_remote_addr String, net_local_port UInt16, net_remote_port UInt16,
     net_conn_tx_bytes UInt64, net_conn_rx_bytes UInt64, net_duration_ms UInt64,
     sig_num UInt32, sig_target_pid UInt32, sig_target_comm String,
     sig_code Int32, sig_result Int32,
     sec_local_addr String, sec_remote_addr String,
     sec_local_port UInt16, sec_remote_port UInt16,
     sec_af UInt8, sec_tcp_state UInt8, sec_direction UInt8,
     open_tcp_conns UInt64,
     disk_total_bytes UInt64, disk_used_bytes UInt64, disk_avail_bytes UInt64'
);
