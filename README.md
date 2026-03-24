# process_metrics — event-driven BPF process metrics collector

Мониторит жизненный цикл процессов (exec/fork/exit) через eBPF tracepoints и экспортирует метрики через встроенный HTTP-сервер в формате Prometheus и/или CSV. Отслеживает только процессы, подходящие под пользовательские regex-правила, а также всех их потомков.

**Архитектура pull:** process_metrics накапливает события в файл и отдаёт их по HTTP. Внешний коллектор (ClickHouse, Vector, curl, Prometheus) периодически забирает данные.

## Сборка

```bash
# 1. Установка зависимостей
make deps          # автоопределение apt/yum
make deps-apt      # Astra Linux / Debian / Ubuntu
make deps-yum      # RHEL / CentOS / Rocky

# 2. Сборка (bpftool из vendored-исходников + process_metrics)
make all
make all CLANG=clang-15   # если clang установлен с суффиксом версии
```

Требуется: clang >= 10 (BPF CO-RE), libconfig.

## Запуск

```bash
./build/process_metrics -c process_metrics.conf
```

Единственный аргумент — путь к конфигурационному файлу. Все остальные параметры задаются в конфиге.

## Конфигурация

Вся конфигурация — в одном файле формата libconfig. Полный пример: [examples/process_metrics.conf](examples/process_metrics.conf).

```conf
# process_metrics.conf — минимальный пример

snapshot_interval = 3;
metric_prefix = "process_metrics";

rules = (
    { name = "nginx";    regex = "^nginx"; },
    { name = "dockerd";  regex = "/usr/bin/dockerd"; },
    { name = "other";    regex = "."; }
);

cgroup_metrics = true;

net_tracking = {
    enabled = true;
    track_bytes = false;
};

file_tracking = {
    enabled = true;
    track_bytes = false;
    include = ( "/home", "/opt", "/srv", "/var/lib", "/etc" );
    exclude = ( "/proc", "/sys", "/dev", "/run", "/tmp",
                "/etc/ld.so.cache", "/etc/passwd", "/etc/group",
                "/etc/nsswitch.conf", "/etc/localtime",
                "/etc/hosts", "/etc/resolv.conf",
                "/etc/host.conf", "/etc/gai.conf" );
};

http_server = {
    port = 9091;
    bind = "0.0.0.0";
    data_file = "/var/lib/process_metrics/events.dat";
};
```

### Общие параметры

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `hostname` | `gethostname()` | Идентификатор сервера (используется в prom-лейблах и CSV) |
| `snapshot_interval` | `30` | Интервал записи метрик (секунды) |
| `metric_prefix` | `process_metrics` | Префикс метрик |
| `cmdline_max_len` | `500` | Макс. длина args в выводе |
| `exec_rate_limit` | `0` (без лимита) | Лимит exec-событий в секунду |
| `log_level` | `1` | 0 = errors, 1 = info, 2 = debug |
| `refresh_proc` | `true` | Обновлять cmdline/comm из /proc каждый цикл |

### Правила (`rules`)

Список объектов `{ name, regex }`. Regex применяется к полной командной строке процесса. При совпадении процесс и все его потомки отслеживаются. Первое совпадение побеждает.

Перезагрузка правил без перезапуска:

```bash
kill -HUP <pid>
# или
systemctl reload process_metrics
```

### Коллекторы

| Коллектор | Описание | Overhead |
|-----------|----------|----------|
| `cgroup_metrics` | memory.max, memory.current, cpu.weight, pids.current из cgroup v2 | Минимальный |
| `net_tracking` | TCP connect/accept/close через kprobes. Генерирует `net_close` события с IP/портами | Низкий |
| `file_tracking` | open/close/read/write через eBPF tracepoints. Генерирует `file_close` события | ~3-4% CPU |

`net_tracking` и `file_tracking` — объекты с полями `enabled` и `track_bytes`. `track_bytes = true` добавляет учёт байт на каждый сокет/файл (повышает overhead).

`file_tracking` дополнительно поддерживает `include` и `exclude` — списки префиксов путей для фильтрации. Без `include` отслеживаются все пути (кроме `exclude`).

### HTTP-сервер (секция `http_server`)

Если секция `http_server` определена с `port` — запускается встроенный HTTP-сервер в отдельном потоке.

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `port` | `9091` | Порт HTTP-сервера |
| `bind` | `0.0.0.0` | Адрес привязки |
| `data_file` | `/tmp/process_metrics_events.dat` | Файл накопления событий |

#### Эндпоинты

**`GET /metrics?format=csv`** (или `GET /metrics`)
- Возвращает все накопленные события в формате CSV с заголовком
- Буфер **не очищается** — read-only снапшот текущих данных
- Подходит для отладки и ручного анализа

**`GET /metrics?format=csv&clear=1`**
- Возвращает все накопленные события в формате CSV с заголовком
- После успешной отдачи буфер **очищается**
- Двухфазная доставка: `swap → send → commit`
- При ошибке доставки (разрыв соединения) данные сохраняются в `.pending` файле и будут отданы при следующем запросе
- **Используйте этот URL для ClickHouse Materialized View**

**`GET /metrics?format=prom`**
- Возвращает текущий снапшот Prometheus-метрик
- Данные **не очищаются** — файл перезаписывается каждые `snapshot_interval` секунд
- Формат: Prometheus text exposition (совместим с Prometheus, VictoriaMetrics)

#### Согласованность данных

Запись снапшота (десятки `ef_append()` вызовов) защищена batch-мьютексом: `ef_batch_lock()` блокирует `ef_swap_fd()`/`ef_snapshot_fd()` до завершения всей серии записей. Это гарантирует, что HTTP-запрос с `clear=1` не разрежет снапшот пополам.

## Интеграция с ClickHouse

ClickHouse может самостоятельно забирать данные с целевых серверов через Refreshable Materialized View:

```sql
-- 1. Создать таблицу
clickhouse-client < examples/clickhouse_schema.sql

-- 2. Создать view для автоматического сбора (по одному на сервер)
-- ВАЖНО: APPEND — данные накапливаются, а не перезаписываются
-- ВАЖНО: &clear=1 — очищает буфер после успешной доставки
CREATE MATERIALIZED VIEW process_metrics_pull_server1
REFRESH EVERY 30 SECOND APPEND
TO process_metrics
AS
SELECT * FROM url(
    'http://server1:9091/metrics?format=csv&clear=1',
    'CSVWithNames',
    -- явная схема колонок (без неё ClickHouse делает GET-пробу):
    'timestamp DateTime64(9),
     hostname String,
     event_type String,
     rule String,
     root_pid UInt32,
     pid UInt32,
     ppid UInt32,
     uid UInt32,
     comm String,
     exec String,
     args String,
     cgroup String,
     is_root UInt8,
     state String,
     exit_code UInt32,
     cpu_ns UInt64,
     cpu_usage_ratio Float64,
     rss_bytes UInt64,
     rss_min_bytes UInt64,
     rss_max_bytes UInt64,
     shmem_bytes UInt64,
     swap_bytes UInt64,
     vsize_bytes UInt64,
     io_read_bytes UInt64,
     io_write_bytes UInt64,
     maj_flt UInt64,
     min_flt UInt64,
     nvcsw UInt64,
     nivcsw UInt64,
     threads UInt32,
     oom_score_adj Int16,
     oom_killed UInt8,
     net_tx_bytes UInt64,
     net_rx_bytes UInt64,
     start_time_ns UInt64,
     uptime_seconds UInt64,
     cgroup_memory_max Int64,
     cgroup_memory_current Int64,
     cgroup_swap_current Int64,
     cgroup_cpu_weight Int64,
     cgroup_pids_current Int64,
     file_path String,
     file_flags UInt32,
     file_read_bytes UInt64,
     file_write_bytes UInt64,
     file_open_count UInt32,
     net_local_addr String,
     net_remote_addr String,
     net_local_port UInt16,
     net_remote_port UInt16,
     net_conn_tx_bytes UInt64,
     net_conn_rx_bytes UInt64,
     net_duration_ms UInt64'
);
```

Требуется ClickHouse >= 23.12. Полная схема с кодеками и индексами — в [examples/clickhouse_schema.sql](examples/clickhouse_schema.sql).

### Оптимизация хранения

**ORDER BY** `(hostname, event_type, rule, pid, timestamp)`:
- `event_type` на втором месте — почти каждый запрос фильтрует по типу события
- `pid` перед `timestamp` — история одного процесса читается последовательно

**Кодеки (per-column)**:
| Кодек | Где применяется | Почему |
|-------|----------------|--------|
| `Delta + ZSTD` | timestamp, счётчики (cpu_ns, io_*, net_*, faults, ctxsw), rss/vsize/shmem/swap | Монотонно растущие значения → малые дельты → высокая компрессия |
| `Gorilla + ZSTD` | cpu_usage_ratio | IEEE 754 XOR-кодирование для float: соседние значения близки |
| `T64 + ZSTD` | PID-ы, threads, exit_code, oom_*, is_root, cgroup лимиты, uptime | Целые числа, не использующие полный диапазон UInt64 |
| `ZSTD(1)` | строки (hostname, rule, comm, exec, args, cgroup) | Уровень 1: ~95% сжатия при ~10x быстрее чем ZSTD(3) |
| `LowCardinality` | hostname, event_type, rule, comm, cgroup, state | Словарная кодировка: строки → integer indices |

### Типы event_type

| event_type | Когда записывается | Описание |
|------------|-------------------|----------|
| `snapshot` | Каждые `snapshot_interval` секунд | Снимок всех живых отслеживаемых процессов |
| `exec` | При exec() совпадающего процесса | Новый процесс подходит под правило |
| `fork` | При fork() от отслеживаемого | Порождение потомка |
| `exit` | При завершении процесса | Содержит финальные метрики (cpu, rss_max, exit_code) |
| `oom_kill` | При OOM kill | Процесс убит OOM killer |
| `net_close` | При закрытии TCP-соединения | IP-адреса, порты, длительность, байты (если track_bytes) |
| `file_close` | При закрытии файла | Путь, флаги, read/write bytes, open_count |

### Примеры запросов

```sql
-- Текущее состояние процессов (последний снимок)
SELECT pid, comm, exec, rule,
       rss_bytes / 1048576 AS rss_mb,
       cpu_usage_ratio
FROM process_metrics
WHERE event_type = 'snapshot'
  AND timestamp > now() - INTERVAL 1 MINUTE
ORDER BY rss_bytes DESC;

-- Все exit-события за последний час
SELECT timestamp, hostname, pid, comm, exec, args, rule,
       exit_code, cpu_ns / 1e9 AS cpu_sec,
       rss_max_bytes / 1048576 AS rss_max_mb
FROM process_metrics
WHERE event_type = 'exit'
  AND timestamp > now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;

-- Топ-10 файлов по записи за последний час
SELECT file_path,
       sum(file_write_bytes) AS total_write,
       count() AS close_count
FROM process_metrics
WHERE event_type = 'file_close'
  AND timestamp > now() - INTERVAL 1 HOUR
GROUP BY file_path
ORDER BY total_write DESC
LIMIT 10;

-- Сетевые соединения процесса
SELECT timestamp, net_remote_addr, net_remote_port,
       net_conn_tx_bytes, net_conn_rx_bytes,
       net_duration_ms / 1000 AS duration_sec
FROM process_metrics
WHERE event_type = 'net_close'
  AND pid = 1234
ORDER BY timestamp DESC;
```

## Capabilities и ядро

| Capability | Назначение |
|---|---|
| `CAP_BPF` | Загрузка BPF-программ (kernel 5.8+) |
| `CAP_PERFMON` | Подключение к tracepoints и kprobes |
| `CAP_SYS_PTRACE` | Чтение /proc/PID/* процессов других пользователей |
| `CAP_KILL` | kill(pid, 0) для проверки liveness чужих процессов |
| `CAP_DAC_READ_SEARCH` | Чтение /sys/fs/cgroup/* и /proc/*/cgroup |

### Требования к ядру

- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_EVENTS=y`
- BTF: `/sys/kernel/btf/vmlinux` (для CO-RE)
- `kernel.perf_event_paranoid <= 2` (Debian default=3)
- `kernel.unprivileged_bpf_disabled <= 1` (Debian default=2)

```bash
# Настройка sysctl (или скопируйте ci/99-process-metrics.conf)
sudo sysctl -w kernel.perf_event_paranoid=2
sudo sysctl -w kernel.unprivileged_bpf_disabled=1
```

### Установка

```bash
# 1. Создать пользователя
sudo useradd -r -s /usr/sbin/nologin process_metrics
sudo mkdir -p /var/lib/process_metrics
sudo chown process_metrics:process_metrics /var/lib/process_metrics

# 2. Установить бинарник и конфиг
sudo cp build/process_metrics /usr/local/bin/
sudo mkdir -p /etc/process_metrics
sudo cp examples/process_metrics.conf /etc/process_metrics/

# 3. Установить sysctl и systemd unit
sudo cp ci/99-process-metrics.conf /etc/sysctl.d/
sudo sysctl --system
sudo cp ci/process_metrics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now process_metrics
```

### Варианты запуска

**systemd unit (рекомендуется)**
```bash
sudo systemctl start process_metrics
sudo systemctl status process_metrics
journalctl -u process_metrics -f
```

**От root (для отладки)**
```bash
sudo ./build/process_metrics -c process_metrics.conf
```

## Метрики (Prometheus)

Отдаются через встроенный HTTP-сервер (`GET /metrics?format=prom`). Снапшот обновляется каждые `snapshot_interval` секунд. Все метрики используют префикс из `metric_prefix` (по умолчанию `process_metrics`).

Лейблы `hostname`, `rule`, `root_pid`, `pid` присутствуют на всех per-process метриках. Метрика `_info` дополнительно содержит `comm`, `exec`, `args`, `cgroup`.

### Per-process (живые процессы)

#### Информационные

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_info` | gauge | Информационная метрика (всегда 1). Несёт метаданные в лейблах |
| `{prefix}_start_time_seconds` | gauge | Время запуска процесса (unix epoch) |
| `{prefix}_uptime_seconds` | gauge | Время работы процесса в секундах |
| `{prefix}_is_root` | gauge | 1 — корневой процесс, 0 — потомок |

#### CPU

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_cpu_seconds_total` | counter | Суммарное CPU-время (user + system) |
| `{prefix}_cpu_usage_ratio` | gauge | Утилизация CPU за последний интервал (1.0 = 1 ядро) |

#### Память

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_rss_bytes` | gauge | Текущий RSS в байтах |
| `{prefix}_rss_min_bytes` | gauge | Минимальный RSS за время жизни |
| `{prefix}_rss_max_bytes` | gauge | Максимальный RSS за время жизни |
| `{prefix}_vsize_bytes` | gauge | Виртуальная память в байтах |
| `{prefix}_shmem_bytes` | gauge | Shared memory в байтах |
| `{prefix}_swap_bytes` | gauge | Swap usage в байтах |

#### Дисковый I/O

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_io_read_bytes_total` | counter | Фактически прочитано с диска |
| `{prefix}_io_write_bytes_total` | counter | Фактически записано на диск |
| `{prefix}_major_page_faults_total` | counter | Major page faults |
| `{prefix}_minor_page_faults_total` | counter | Minor page faults |

#### Планировщик

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_voluntary_ctxsw_total` | counter | Добровольные переключения контекста |
| `{prefix}_involuntary_ctxsw_total` | counter | Принудительные переключения контекста |

#### Сеть

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_net_tx_bytes_total` | counter | TCP+UDP байт отправлено |
| `{prefix}_net_rx_bytes_total` | counter | TCP+UDP байт получено |

#### Прочие

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_threads` | gauge | Количество потоков |
| `{prefix}_oom_score_adj` | gauge | OOM score adjustment |
| `{prefix}_oom_kill` | gauge | 1 если убит OOM killer |
| `{prefix}_state` | gauge | Состояние процесса (R/S/D/T/Z) |

### Exited (недавно завершившиеся)

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_exited_exit_code` | gauge | Код завершения |
| `{prefix}_exited_signal` | gauge | Сигнал (0 = нормальное завершение) |
| `{prefix}_exited_oom_kill` | gauge | 1 если OOM kill |
| `{prefix}_exited_cpu_seconds_total` | gauge | CPU-время завершившегося процесса |
| `{prefix}_exited_rss_max_bytes` | gauge | Максимальный RSS |
| `{prefix}_exited_net_tx_bytes_total` | gauge | Сетевой TX |
| `{prefix}_exited_net_rx_bytes_total` | gauge | Сетевой RX |

### Per-cgroup (cgroup v2)

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_cgroup_memory_max_bytes` | gauge | memory.max |
| `{prefix}_cgroup_memory_current_bytes` | gauge | memory.current |
| `{prefix}_cgroup_memory_swap_current_bytes` | gauge | memory.swap.current |
| `{prefix}_cgroup_cpu_weight` | gauge | cpu.weight |
| `{prefix}_cgroup_pids_current` | gauge | pids.current |

## Регенерация vmlinux.h

```bash
make vmlinux
```

## Структура проекта

```
examples/
  process_metrics.conf           — пример конфига (libconfig)
  clickhouse_schema.sql          — DDL таблицы + materialized view для pull
ci/
  process_metrics.service        — systemd unit
  99-process-metrics.conf        — sysctl для BPF capabilities
src/
  process_metrics.bpf.c          — BPF-программа (tracepoints, kprobes)
  process_metrics.c              — userspace: загрузчик, конфиг, снапшоты
  process_metrics_common.h       — общие типы (BPF ↔ userspace)
  event_file.h                   — API файлового буфера событий + struct metric_event
  event_file.c                   — двухфазная доставка (swap/commit), batch lock
  http_server.h                  — API встроенного HTTP-сервера
  http_server.c                  — HTTP/1.1 сервер (CSV read-only, CSV clear, Prometheus)
  vmlinux.h                      — типы ядра (CO-RE)
  bpftool/                       — vendored bpftool
build/                           — артефакты сборки
Makefile                         — сборка, установка зависимостей
```

## Сигналы

| Сигнал | Действие |
|--------|----------|
| `SIGTERM` / `SIGINT` | Корректное завершение |
| `SIGHUP` | Перезагрузка правил, пересканирование `/proc` |
