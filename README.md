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

Вся конфигурация — в одном файле формата libconfig.

```conf
# process_metrics.conf

hostname = "my-server-01";     # идентификатор сервера (по умолчанию gethostname())
snapshot_interval = 30;
metric_prefix = "process_metrics";
cmdline_max_len = 500;
exec_rate_limit = 0;

# Правила отслеживания
rules = (
    { name = "airflow_celery";    regex = "celery@.*MainProcess"; },
    { name = "airflow_scheduler"; regex = "airflow scheduler$"; },
    { name = "postgres";          regex = "bin/postgres.*-D"; },
    { name = "dockerd";           regex = "dockerd"; }
);

# HTTP pull server
http_server = {
    port = 9091;
    bind = "0.0.0.0";
    data_file = "/var/lib/process_metrics/events.dat";
    prom_path = "/var/lib/process_metrics/process_metrics.prom";
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

### Правила (`rules`)

Список объектов `{ name, regex }`. Regex применяется к полной командной строке процесса. При совпадении процесс и все его потомки отслеживаются.

Перезагрузка правил без перезапуска:

```bash
kill -HUP <pid>
```

### HTTP-сервер (секция `http_server`)

Если секция `http_server` определена с `port` — запускается встроенный HTTP-сервер в отдельном потоке.

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `port` | `9091` | Порт HTTP-сервера |
| `bind` | `0.0.0.0` | Адрес привязки |
| `data_file` | `/tmp/process_metrics_events.dat` | Файл накопления CSV-событий |
| `prom_path` | `/tmp/process_metrics.prom` | Файл снапшота Prometheus-метрик |

#### Эндпоинты

**`GET /metrics?format=csv`** (или `GET /metrics`)
- Возвращает все накопленные события в формате CSV с заголовком
- После успешной отдачи буфер очищается
- При ошибке доставки (разрыв соединения) данные сохраняются в `.pending` файле и будут отданы при следующем запросе
- Двухфазная доставка: `swap → send → commit`

**`GET /metrics?format=prom`**
- Возвращает текущий снапшот Prometheus-метрик
- Данные **не очищаются** — файл перезаписывается каждые `snapshot_interval` секунд
- Формат: Prometheus text exposition (совместим с Prometheus, VictoriaMetrics)

## Интеграция с ClickHouse

ClickHouse может самостоятельно забирать данные с целевых серверов через Refreshable Materialized View:

```sql
-- 1. Создать таблицу
clickhouse-client < examples/clickhouse_schema.sql

-- 2. Создать view для автоматического сбора (по одному на сервер)
CREATE MATERIALIZED VIEW process_metrics_pull_server1
REFRESH EVERY 30 SECOND
TO process_metrics
AS
SELECT * FROM url(
    'http://server1:9091/metrics?format=csv',
    'CSVWithNames'
);
```

ClickHouse будет каждые 30 секунд обращаться к HTTP-серверу process_metrics, забирать CSV и вставлять в таблицу. Требуется ClickHouse >= 23.12.

Полная схема с кодеками, индексами и примерами — в [examples/clickhouse_schema.sql](examples/clickhouse_schema.sql).

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

-- История RSS процесса по PID
SELECT timestamp,
       rss_bytes / 1048576 AS rss_mb
FROM process_metrics
WHERE event_type = 'snapshot'
  AND pid = 1234
ORDER BY timestamp;
```

## Capabilities и ядро

| Capability | Назначение |
|---|---|
| `CAP_BPF` | Загрузка BPF-программ (kernel 5.8+) |
| `CAP_PERFMON` | Подключение к tracepoints |

### Требования к ядру

- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_EVENTS=y`
- BTF: `/sys/kernel/btf/vmlinux` (для CO-RE)

### Варианты запуска

**systemd unit (рекомендуется)**
```ini
[Service]
User=process_metrics
AmbientCapabilities=CAP_BPF CAP_PERFMON
ExecStart=/opt/process_metrics/process_metrics -c /etc/process_metrics/process_metrics.conf
```

**От root**
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
src/
  process_metrics.bpf.c          — BPF-программа (tracepoints, kretprobes)
  process_metrics.c              — userspace: загрузчик, конфиг, HTTP-сервер
  process_metrics_common.h       — общие типы (BPF ↔ userspace)
  event_file.h                   — API файлового буфера событий + struct metric_event
  event_file.c                   — двухфазная доставка (swap/commit)
  http_server.h                  — API встроенного HTTP-сервера
  http_server.c                  — HTTP/1.1 сервер (CSV + Prometheus)
  vmlinux.h                      — типы ядра (CO-RE)
  bpftool/                       — vendored bpftool
tests/
  test_event_file.c              — unit-тесты event_file (swap/commit)
  test_http_server.sh            — интеграционные тесты HTTP (prom/csv)
  test_clickhouse_integration.sh — интеграционный тест с ClickHouse
build/                           — артефакты сборки
Makefile                         — сборка, установка зависимостей
```

## Сигналы

| Сигнал | Действие |
|--------|----------|
| `SIGTERM` / `SIGINT` | Корректное завершение |
| `SIGHUP` | Перезагрузка правил, пересканирование `/proc` |
