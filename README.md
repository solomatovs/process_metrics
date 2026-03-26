# process_metrics

Мониторинг процессов Linux через eBPF. Отслеживает жизненный цикл процессов (exec/fork/exit/OOM), сетевые соединения (TCP connect/accept/close), файловые операции (open/close/read/write), сигналы, заполненность дисков и сетевые аномалии (retransmit, SYN flood, RST, UDP/ICMP flood).

Работает по pull-модели: накапливает события в бинарный файл, отдаёт по HTTP в формате CSV или Prometheus. Внешний коллектор (ClickHouse Refreshable MV, Prometheus, Vector) периодически забирает данные.

## Возможности

- **15 типов событий**: snapshot, fork, exec, exit, oom_kill, file_close, net_close, signal, tcp_retrans, syn_recv, rst_sent, rst_recv, udp_agg, icmp_agg, disk_usage
- **65 метрик** на процесс: CPU, RSS, swap, I/O, page faults, context switches, threads, namespaces, cgroup v2, сеть, файлы, сигналы, диски
- **Правила отслеживания**: regex-фильтрация по командной строке с наследованием потомков
- **Двухфазная доставка**: swap → send → commit. При сбое данные не теряются
- **Security-пробы**: TCP retransmit, SYN flood, RST, UDP/ICMP — не привязаны к rules, захватывают весь трафик хоста
- **Ротация файла данных**: автоматическое усечение при превышении лимита (по умолчанию 1 ГБ)
- **Совместимость с ядрами 5.15+**: условная компиляция через макросы `BPF_ZERO` для обхода ограничений верификатора
- **Перезагрузка без рестарта**: `SIGHUP` — пересканирование /proc и перезагрузка правил
- **Статический бинарник**: один файл, переносимый между дистрибутивами

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
| `make test-http` | Тесты HTTP-сервера |
| `make test-clickhouse` | Интеграционные тесты ClickHouse |

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
process_metrics.bpf.c → clang -target bpf -DKERN_VER_MAJOR=N → .bpf.o
    ↓
bpftool gen skeleton → .skel.h (встроенный ELF ~500KB)
    ↓
process_metrics.c → clang -static → build/process_metrics
```

Makefile автоматически определяет версию ядра (`KERN_VER_MAJOR`, `KERN_VER_MINOR`) и передаёт в BPF-компиляцию. На ядрах < 6.0 активируется макрос `BPF_ZERO` для обнуления padding-байтов на стеке (требование верификатора 5.15).

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
snapshot_interval = 30;
metric_prefix = "process_metrics";

rules = (
    { name = "nginx";    regex = "^nginx: "; },
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
    include = ( "/home", "/var/lib", "/etc" );
    exclude = ( "/proc", "/sys", "/dev", "/run", "/tmp",
                "/etc/ld.so.cache", "/etc/passwd", "/etc/group" );
};

disk_tracking = {
    enabled = true;
    exclude = ( "/boot/efi" );
};

security_tracking = {
    tcp_retransmit = true;
    syn_tracking = false;
    rst_tracking = false;
    udp_tracking = false;
    icmp_tracking = false;
    open_conn_count = false;
};

http_server = {
    port = 9091;
    bind = "0.0.0.0";
    data_file = "/var/lib/process_metrics/events.dat";
    max_data_file_size = 1073741824;  # 1 ГБ
};
```

### Общие параметры

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `hostname` | `gethostname()` | Идентификатор сервера |
| `snapshot_interval` | `30` | Интервал снимков (секунды) |
| `metric_prefix` | `process_metrics` | Префикс Prometheus-метрик |
| `cmdline_max_len` | `500` | Макс. длина args в выводе |
| `exec_rate_limit` | `0` (без лимита) | Лимит exec-событий/сек в ringbuf |
| `log_level` | `1` | 0 = errors, 1 = info, 2 = debug |
| `refresh_proc` | `true` | Обновлять cmdline/comm из /proc каждый цикл |
| `cgroup_metrics` | `true` | Чтение cgroup v2 метрик |

### Правила (`rules`)

Список объектов `{ name, regex }`. Regex применяется к полной командной строке процесса (`/proc/<pid>/cmdline`). При совпадении процесс и все его потомки отслеживаются. Первое совпадение побеждает. Перезагружаются по `SIGHUP`.

### Коллекторы

| Коллектор | Описание | По умолчанию |
|-----------|----------|-------------|
| `cgroup_metrics` | memory.max, memory.current, cpu.weight, pids.current из cgroup v2 | вкл |
| `net_tracking` | TCP connect/accept/close через kprobes. События `net_close` | выкл |
| `file_tracking` | open/close/read/write через tracepoints. События `file_close` | выкл |
| `disk_tracking` | Заполненность дисков через statvfs(). События `disk_usage` | вкл |
| `security_tracking` | TCP retransmit, SYN, RST, UDP/ICMP через kprobes/tracepoints | выкл |

`net_tracking` и `file_tracking` — объекты с полями `enabled` и `track_bytes`. `track_bytes = true` добавляет учёт байтов на соединение/fd (повышает нагрузку).

`file_tracking` поддерживает `include` и `exclude` — списки префиксов путей. Без `include` отслеживаются все пути (кроме `exclude`).

`disk_tracking` поддерживает `fs_types` (типы ФС), `include` и `exclude` (префиксы точек монтирования). По умолчанию мониторит: ext2/3/4, xfs, btrfs, vfat, zfs, ntfs, fuseblk, f2fs. Дедуплицирует bind-mount'ы одного устройства.

### Security tracking

Сетевые security-пробы для обнаружения аномалий. **Не фильтруются по rules** — захватывают весь трафик хоста.

| Probe | Описание | Событие |
|-------|----------|---------|
| `tcp_retransmit` | Повторные передачи TCP-сегментов (потеря пакетов, DDoS) | `tcp_retrans` |
| `syn_tracking` | Входящие SYN-запросы (SYN flood) | `syn_recv` |
| `rst_tracking` | TCP RST отправленные/полученные (сканирование портов) | `rst_sent`, `rst_recv` |
| `udp_tracking` | Агрегация UDP пакетов/байтов по (remote_addr, port) | `udp_agg` |
| `icmp_tracking` | Агрегация ICMP по (src_addr, type, code) | `icmp_agg` |
| `open_conn_count` | Счётчик активных TCP-соединений на процесс | поле `open_tcp_conns` в snapshot |

### Docker resolve

Автоматический резолвинг имён Docker-контейнеров по cgroup path. Хэш контейнера в `docker-<hash>.scope` заменяется на имя контейнера. Кэш обновляется каждый `snapshot_interval`. `data_root` определяется из `daemon.json` или задаётся явно.

## HTTP-сервер

Если определена секция `http_server` с `port`, запускается встроенный HTTP-сервер.

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `port` | `9091` | Порт |
| `bind` | `0.0.0.0` | Адрес привязки |
| `data_file` | `/tmp/process_metrics_events.dat` | Файл накопления событий |
| `max_data_file_size` | `1073741824` (1 ГБ) | Макс. размер файла (0 = без лимита) |

### Эндпоинты

| URL | Описание |
|-----|----------|
| `GET /metrics?format=csv` | CSV-снапшот (буфер НЕ очищается) |
| `GET /metrics?format=csv&clear=1` | CSV + очистка буфера (для ClickHouse MV) |
| `GET /metrics?format=prom` | Prometheus text exposition |

Запрос с `clear=1` использует двухфазную доставку: `swap → send → commit`. При разрыве соединения данные сохраняются в `.pending` файле и отдаются при следующем запросе.

### Ротация файла данных

При превышении `max_data_file_size`:
- Файл `events.dat` усекается (`ftruncate`) — старые данные теряются
- Файл `.pending` (незабранные данные) также ограничен тем же лимитом — при превышении удаляется

Защищает от переполнения диска при недоступности коллектора.

## Типы событий

| event_type | Когда | Описание |
|------------|-------|----------|
| `snapshot` | Каждые N секунд | Снимок всех живых отслеживаемых процессов |
| `exec` | exec() | Новый процесс подходит под правило |
| `fork` | fork() | Потомок отслеживаемого процесса |
| `exit` | Завершение | Финальные метрики (cpu, rss_max, exit_code) |
| `oom_kill` | OOM | Процесс убит OOM killer |
| `file_close` | Закрытие файла | Путь, флаги, read/write bytes |
| `net_close` | Закрытие TCP | IP-адреса, порты, длительность, байты |
| `signal` | Доставка сигнала | Отправитель, получатель, номер, результат |
| `tcp_retrans` | TCP retransmit | Адреса, порты, TCP state |
| `syn_recv` | Входящий SYN | Адреса, порты |
| `rst_sent` | Отправлен RST | Адреса, порты |
| `rst_recv` | Получен RST | Адреса, порты |
| `udp_agg` | Каждый snapshot | Агрегация UDP: пакеты, байты по (addr, port) |
| `icmp_agg` | Каждый snapshot | Агрегация ICMP: count по (addr, type, code) |
| `disk_usage` | Каждый snapshot | Заполненность ФС: total, used, avail |

## Интеграция с ClickHouse

ClickHouse забирает данные через Refreshable Materialized View:

```sql
-- 1. Создать таблицу
clickhouse-client < examples/clickhouse_schema.sql

-- 2. Создать view для автоматического сбора (пример)
CREATE MATERIALIZED VIEW process_metrics_pull_server1
REFRESH EVERY 30 SECOND APPEND
TO process_metrics
AS SELECT * FROM url(
    'http://server1:9091/metrics?format=csv&clear=1',
    'CSVWithNames'
);
```

Требуется ClickHouse >= 23.12. Полная схема с кодеками и определением колонок — в [examples/clickhouse_schema.sql](examples/clickhouse_schema.sql).

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

-- TCP retransmissions (аномалии сети)
SELECT timestamp, sec_local_addr, sec_remote_addr,
       sec_local_port, sec_remote_port, sec_tcp_state
FROM process_metrics
WHERE event_type = 'tcp_retrans'
  AND timestamp > now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;

-- Заполненность дисков
SELECT timestamp, comm AS device, file_path AS mount_point,
       disk_total_bytes / 1073741824 AS total_gb,
       disk_used_bytes / 1073741824 AS used_gb,
       disk_avail_bytes / 1073741824 AS avail_gb,
       round(disk_used_bytes * 100.0 / disk_total_bytes, 1) AS usage_pct
FROM process_metrics
WHERE event_type = 'disk_usage'
  AND timestamp > now() - INTERVAL 5 MINUTE
ORDER BY usage_pct DESC;

-- Сигналы (кто кого killнул)
SELECT timestamp, comm, pid, sig_num, sig_target_pid, sig_target_comm, sig_result
FROM process_metrics
WHERE event_type = 'signal'
  AND timestamp > now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;
```

## Grafana

В `examples/` — готовые дашборды для импорта:

| Файл | Описание |
|------|----------|
| [grafana-dashboard.json](examples/grafana-dashboard.json) | Основной дашборд: процессы, CPU, память, I/O, сеть, файлы, диски |
| [grafana-security-dashboard.json](examples/grafana-security-dashboard.json) | Security: retransmissions, SYN flood, RST, UDP/ICMP, port scan detection |

Импорт: Grafana → Dashboards → Import → Upload JSON. Datasource — ClickHouse.

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

### Совместимость ядер 5.15 / 6.x

BPF верификатор ядра 5.15 требует инициализации каждого байта стековых переменных, включая padding. Ядро >= 6.0 допускает неинициализированный padding. Проект автоматически адаптируется: Makefile определяет `KERN_VER_MAJOR` и передаёт в BPF-компиляцию. Макрос `BPF_ZERO(var)` на ядрах < 6 выполняет `__builtin_memset`, на >= 6 — no-op.

## Systemd

Включены два варианта systemd unit:

| Файл | Описание |
|------|----------|
| [process_metrics.service](ci/process_metrics.service) | Современный: `AmbientCapabilities`, без root |
| [process_metrics-legacy.service](ci/process_metrics-legacy.service) | Для старых systemd: через root + `User=` |

Hardening в основном unit: `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `MemoryDenyWriteExecute=yes`, `MemoryMax=200M`, `CPUQuota=15%`.

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
  grafana-dashboard.json       — основной Grafana-дашборд
  grafana-security-dashboard.json — security-дашборд
ci/
  process_metrics.service      — systemd unit (современный)
  process_metrics-legacy.service — systemd unit (legacy)
  99-process-metrics.conf      — sysctl для BPF capabilities
tests/
  test_event_file.c            — unit-тесты event_file
  test_http_server.sh          — тесты HTTP-сервера
  test_clickhouse_integration.sh — интеграционные тесты ClickHouse
build/                         — артефакты сборки
Makefile                       — сборка, тесты, установка зависимостей
```

## Сигналы

| Сигнал | Действие |
|--------|----------|
| `SIGTERM` / `SIGINT` | Корректное завершение |
| `SIGHUP` | Перезагрузка правил, пересканирование /proc |
