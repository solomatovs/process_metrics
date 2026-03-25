# process_metrics

Мониторинг процессов через eBPF. Отслеживает жизненный цикл (exec/fork/exit), сетевые соединения (TCP connect/accept/close), файловые операции (open/close/read/write) и экспортирует метрики через встроенный HTTP-сервер в формате Prometheus и CSV.

Работает по pull-модели: накапливает события в файл, отдаёт по HTTP. Внешний коллектор (ClickHouse, Prometheus, Vector) периодически забирает данные.

## Требования

- Ядро Linux >= 5.15 с `CONFIG_DEBUG_INFO_BTF=y`
- clang >= 10 (BPF CO-RE + компиляция userspace)
- gcc (только для сборки vendored bpftool)
- libbpf-dev, libelf-dev, zlib1g-dev, libconfig-dev

Проверено на:
- Astra Linux CE 2.12 (ядро 5.15, clang-10, libbpf 0.7)
- Debian 12 (ядро 6.1, clang-16, libbpf 1.1)

## Сборка

```bash
# Установка зависимостей (автоопределение apt/yum)
make deps

# Полная сборка: vmlinux.h + bpftool + BPF + статический бинарник
make all

# Или с явным указанием clang
make all CLANG=clang-15
```

### Цели сборки

| Цель | Описание |
|------|----------|
| `make all` | Полная сборка (vmlinux + bpftool + bpf + binary) |
| `make vmlinux` | Регенерация vmlinux.h из BTF текущего ядра |
| `make bpftool` | Сборка bpftool из vendored-исходников |
| `make bpf` | Компиляция BPF-объекта + генерация skeleton |
| `make binary` | Компиляция userspace-бинарника (требует skeleton) |
| `make clean` | Удаление артефактов сборки |
| `make deps` | Установка зависимостей (автоопределение apt/yum) |
| `make test` | Запуск unit-тестов |

### Компиляторы

| Что | Компилятор | Почему |
|-----|-----------|--------|
| BPF-код (`*.bpf.c`) | clang (`-target bpf`) | Единственный компилятор с backend для BPF-байткода |
| Userspace (`*.c`) | clang (`-static`) | Статический бинарник, переносимый между дистрибутивами |
| bpftool (vendored) | gcc | Внутренний Makefile bpftool требует gcc |

### Цепочка сборки

```
vmlinux.h ← bpftool btf dump /sys/kernel/btf/vmlinux
    ↓
process_metrics.bpf.c → clang -target bpf → .bpf.o
    ↓
bpftool gen skeleton → .skel.h (встроенный ELF ~500KB)
    ↓
process_metrics.c → clang -static → build/process_metrics
```

## Установка

```bash
# Бинарник
sudo cp build/process_metrics /usr/local/bin/

# Конфиг
sudo mkdir -p /etc/process_metrics
sudo cp examples/process_metrics.conf /etc/process_metrics/

# sysctl для BPF
sudo cp ci/99-process-metrics.conf /etc/sysctl.d/
sudo sysctl --system

# systemd
sudo cp ci/process_metrics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now process_metrics
```

## Запуск

```bash
# Через systemd (рекомендуется)
sudo systemctl start process_metrics
sudo systemctl status process_metrics
journalctl -u process_metrics -f

# Вручную (для отладки)
sudo ./build/process_metrics -c process_metrics.conf

# Перезагрузка правил без перезапуска
sudo systemctl reload process_metrics   # или kill -HUP <pid>
```

## Конфигурация

Один файл формата libconfig. Полный пример: [examples/process_metrics.conf](examples/process_metrics.conf).

```conf
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
| `hostname` | `gethostname()` | Идентификатор сервера |
| `snapshot_interval` | `30` | Интервал записи метрик (секунды) |
| `metric_prefix` | `process_metrics` | Префикс метрик |
| `cmdline_max_len` | `500` | Макс. длина args в выводе |
| `exec_rate_limit` | `0` (без лимита) | Лимит exec-событий в секунду |
| `log_level` | `1` | 0 = errors, 1 = info, 2 = debug |
| `refresh_proc` | `true` | Обновлять cmdline/comm из /proc каждый цикл |

### Правила (`rules`)

Список объектов `{ name, regex }`. Regex применяется к полной командной строке процесса. При совпадении процесс и все его потомки отслеживаются. Первое совпадение побеждает.

### Коллекторы

| Коллектор | Описание |
|-----------|----------|
| `cgroup_metrics` | memory.max, memory.current, cpu.weight, pids.current из cgroup v2 |
| `net_tracking` | TCP connect/accept/close через kprobes. События `net_close` с IP/портами |
| `file_tracking` | open/close/read/write через tracepoints. События `file_close` с путями |

`net_tracking` и `file_tracking` — объекты с полями `enabled` и `track_bytes`. `track_bytes = true` добавляет учёт байт (повышает нагрузку).

`file_tracking` поддерживает `include` и `exclude` — списки префиксов путей. Без `include` отслеживаются все пути (кроме `exclude`).

## HTTP-сервер

Если определена секция `http_server` с `port`, запускается встроенный HTTP-сервер.

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `port` | `9091` | Порт |
| `bind` | `0.0.0.0` | Адрес привязки |
| `data_file` | `/tmp/process_metrics_events.dat` | Файл накопления событий |

### Эндпоинты

| URL | Описание |
|-----|----------|
| `GET /metrics?format=csv` | CSV-снапшот (буфер НЕ очищается) |
| `GET /metrics?format=csv&clear=1` | CSV + очистка буфера (для ClickHouse) |
| `GET /metrics?format=prom` | Prometheus text exposition |

Запрос с `clear=1` использует двухфазную доставку: `swap → send → commit`. При разрыве соединения данные сохраняются в `.pending` файле.

## Интеграция с ClickHouse

ClickHouse забирает данные через Refreshable Materialized View:

```sql
-- 1. Создать таблицу
clickhouse-client < examples/clickhouse_schema.sql

-- 2. Создать view для автоматического сбора
CREATE MATERIALIZED VIEW process_metrics_pull_server1
REFRESH EVERY 30 SECOND APPEND
TO process_metrics
AS
SELECT * FROM url(
    'http://server1:9091/metrics?format=csv&clear=1',
    'CSVWithNames',
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

Требуется ClickHouse >= 23.12. Полная схема с кодеками — в [examples/clickhouse_schema.sql](examples/clickhouse_schema.sql).

### Типы событий

| event_type | Когда | Описание |
|------------|-------|----------|
| `snapshot` | Каждые N секунд | Снимок всех живых отслеживаемых процессов |
| `exec` | exec() | Новый процесс подходит под правило |
| `fork` | fork() | Потомок отслеживаемого процесса |
| `exit` | Завершение | Финальные метрики (cpu, rss_max, exit_code) |
| `oom_kill` | OOM | Процесс убит OOM killer |
| `net_close` | Закрытие TCP | IP-адреса, порты, длительность, байты |
| `file_close` | Закрытие файла | Путь, флаги, read/write bytes |

### Примеры запросов

```sql
-- Текущее состояние процессов
SELECT pid, comm, exec, rule,
       rss_bytes / 1048576 AS rss_mb,
       cpu_usage_ratio
FROM process_metrics
WHERE event_type = 'snapshot'
  AND timestamp > now() - INTERVAL 1 MINUTE
ORDER BY rss_bytes DESC;

-- Завершившиеся процессы за час
SELECT timestamp, hostname, pid, comm, exec, args, rule,
       exit_code, cpu_ns / 1e9 AS cpu_sec,
       rss_max_bytes / 1048576 AS rss_max_mb
FROM process_metrics
WHERE event_type = 'exit'
  AND timestamp > now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;

-- Топ-10 файлов по записи
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
| `CAP_BPF` | Загрузка BPF-программ (ядро 5.8+) |
| `CAP_PERFMON` | Подключение к tracepoints и kprobes |
| `CAP_SYS_PTRACE` | Чтение /proc/PID/* чужих процессов |
| `CAP_KILL` | kill(pid, 0) для проверки liveness |
| `CAP_DAC_READ_SEARCH` | Чтение /sys/fs/cgroup/* и /proc/*/cgroup |

### Требования к ядру

- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_EVENTS=y`
- `CONFIG_DEBUG_INFO_BTF=y` (для CO-RE)
- `kernel.perf_event_paranoid <= 2`
- `kernel.unprivileged_bpf_disabled <= 1`

```bash
sudo sysctl -w kernel.perf_event_paranoid=2
sudo sysctl -w kernel.unprivileged_bpf_disabled=1
```

## Метрики (Prometheus)

Отдаются через `GET /metrics?format=prom`. Обновляются каждые `snapshot_interval` секунд.

Лейблы: `hostname`, `rule`, `root_pid`, `pid`. Метрика `_info` дополнительно содержит `comm`, `exec`, `args`, `cgroup`.

### Per-process

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_info` | gauge | Метаданные в лейблах (всегда 1) |
| `{prefix}_start_time_seconds` | gauge | Время запуска (unix epoch) |
| `{prefix}_uptime_seconds` | gauge | Время работы |
| `{prefix}_cpu_seconds_total` | counter | CPU-время (user + system) |
| `{prefix}_cpu_usage_ratio` | gauge | Утилизация CPU (1.0 = 1 ядро) |
| `{prefix}_rss_bytes` | gauge | Текущий RSS |
| `{prefix}_rss_min_bytes` | gauge | Минимальный RSS |
| `{prefix}_rss_max_bytes` | gauge | Максимальный RSS |
| `{prefix}_vsize_bytes` | gauge | Виртуальная память |
| `{prefix}_shmem_bytes` | gauge | Shared memory |
| `{prefix}_swap_bytes` | gauge | Swap |
| `{prefix}_io_read_bytes_total` | counter | Прочитано с диска |
| `{prefix}_io_write_bytes_total` | counter | Записано на диск |
| `{prefix}_major_page_faults_total` | counter | Major page faults |
| `{prefix}_minor_page_faults_total` | counter | Minor page faults |
| `{prefix}_voluntary_ctxsw_total` | counter | Добровольные переключения контекста |
| `{prefix}_involuntary_ctxsw_total` | counter | Принудительные переключения контекста |
| `{prefix}_net_tx_bytes_total` | counter | TCP+UDP отправлено |
| `{prefix}_net_rx_bytes_total` | counter | TCP+UDP получено |
| `{prefix}_threads` | gauge | Потоки |
| `{prefix}_oom_score_adj` | gauge | OOM score adjustment |
| `{prefix}_state` | gauge | Состояние (R/S/D/T/Z) |

### Завершившиеся процессы

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_exited_exit_code` | gauge | Код завершения |
| `{prefix}_exited_signal` | gauge | Сигнал |
| `{prefix}_exited_cpu_seconds_total` | gauge | CPU-время |
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

## Структура проекта

```
src/
  process_metrics.bpf.c        — BPF-программа (tracepoints, kprobes)
  process_metrics.c            — userspace: загрузчик, конфиг, снапшоты
  process_metrics_common.h     — общие типы (BPF <-> userspace)
  event_file.c/h               — двухфазная доставка событий (swap/commit)
  http_server.c/h              — встроенный HTTP/1.1 сервер
  vmlinux.h                    — типы ядра (CO-RE, генерируется)
  bpftool/                     — vendored bpftool
examples/
  process_metrics.conf         — пример конфигурации
  clickhouse_schema.sql        — DDL таблицы + materialized view
ci/
  process_metrics.service      — systemd unit
  99-process-metrics.conf      — sysctl для BPF capabilities
build/                         — артефакты сборки
Makefile                       — сборка, установка зависимостей
```

## Сигналы

| Сигнал | Действие |
|--------|----------|
| `SIGTERM` / `SIGINT` | Корректное завершение |
| `SIGHUP` | Перезагрузка правил, пересканирование /proc |
