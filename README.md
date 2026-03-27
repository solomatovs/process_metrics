# process_metrics

Мониторинг процессов Linux через eBPF. Отслеживает жизненный цикл процессов (exec/fork/exit/OOM), сетевые соединения (TCP connect/accept/close), файловые операции (open/close/read/write), сигналы, заполненность дисков и сетевые аномалии (retransmit, SYN flood, RST, UDP/ICMP flood).

Работает по pull-модели: накапливает события в кольцевой буфер в памяти и отдаёт по HTTP в формате CSV. Внешний коллектор (ClickHouse Refreshable MV) периодически забирает данные. Disk I/O на горячем пути отсутствует.

## Возможности

- **15 типов событий**: snapshot, fork, exec, exit, oom_kill, file_close, net_close, signal, tcp_retrans, syn_recv, rst_sent, rst_recv, udp_agg, icmp_agg, disk_usage
- **65+ метрик** на процесс: CPU, RSS, swap, I/O, page faults, context switches, threads, namespaces, cgroup v2, сеть, файлы, сигналы, диски
- **Правила отслеживания**: regex-фильтрация по командной строке с наследованием потомков
- **Кольцевой буфер в RAM**: все данные в памяти, без файлового I/O на горячем пути
- **Резолвинг пользователей**: uid/euid/loginuid → текстовые имена через NSS (LDAP, SSSD, локальные)
- **Аудит**: отслеживание loginuid (audit UID) для идентификации реального пользователя через sudo/su
- **Docker resolve**: автоматическое определение имён контейнеров по cgroup path (без Docker socket)
- **Security-пробы**: TCP retransmit, SYN flood, RST, UDP/ICMP — захватывают весь трафик хоста
- **cgroup v2**: memory, swap, cpu.weight, pids из /sys/fs/cgroup
- **Совместимость**: ядра 5.15+ (CO-RE + условная компиляция через `BPF_ZERO`)
- **Перезагрузка без рестарта**: `SIGHUP` — пересканирование /proc и перезагрузка правил
- **Минимальные привилегии**: работает без root, только точечные capabilities (CAP_BPF, CAP_PERFMON, ...)

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

# Полная сборка: vmlinux.h + bpftool + BPF + бинарник
make all

# Или с явным указанием clang
make all CLANG=clang-15
```

Бинарник линкуется частично динамически: glibc подключается динамически (для поддержки NSS — LDAP, SSSD, NIS), остальные библиотеки (libbpf, libelf, zlib, libconfig) — статически.

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

### Цепочка сборки

```
vmlinux.h ← bpftool btf dump /sys/kernel/btf/vmlinux
    ↓
process_metrics.bpf.c → clang -target bpf -DKERN_VER_MAJOR=N → .bpf.o
    ↓
bpftool gen skeleton → .skel.h (встроенный ELF ~500KB)
    ↓
process_metrics.c + csv_format.c + event_file.c + http_server.c
    → clang -Wl,-Bstatic (libbpf,libelf,zlib,libconfig) -Wl,-Bdynamic (libc)
    → build/process_metrics
```

## Установка

```bash
# Создание пользователя
sudo useradd -r -s /usr/sbin/nologin process_metrics

# Бинарник
sudo cp build/process_metrics /usr/local/bin/

# Конфиг
sudo mkdir -p /etc/process_metrics
sudo cp examples/process_metrics.conf /etc/process_metrics/

# sysctl для BPF (требуется на Debian/Astra Linux)
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

Один файл формата libconfig. Полный пример с описанием всех параметров: [examples/process_metrics.conf](examples/process_metrics.conf).

### Общие параметры

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `hostname` | `gethostname()` | Идентификатор сервера |
| `snapshot_interval` | `60` | Интервал снимков (секунды) |
| `cmdline_max_len` | `500` | Макс. длина args в выводе |
| `exec_rate_limit` | `0` (без лимита) | Лимит exec-событий/сек в ringbuf |
| `log_level` | `1` | 0 = errors, 1 = info, 2 = debug |
| `refresh_proc` | `true` | Обновлять cmdline/comm из /proc каждый цикл |
| `cgroup_metrics` | `true` | Чтение cgroup v2 метрик |

### Правила (`rules`)

Список объектов `{ name, regex, ignore }`. Regex применяется к полной командной строке процесса (`/proc/<pid>/cmdline`). При совпадении процесс и все его потомки отслеживаются. Первое совпадение побеждает. Перезагружаются по `SIGHUP`.

`ignore = true` — процесс и его потомки НЕ отслеживаются. Должно стоять перед более общими правилами.

### Коллекторы

| Коллектор | Описание | По умолчанию |
|-----------|----------|-------------|
| `cgroup_metrics` | memory.max, memory.current, memory.swap.current, cpu.weight, pids.current из cgroup v2 | вкл |
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

Автоматический резолвинг имён Docker-контейнеров по cgroup path. Хэш контейнера в `docker-<hash>.scope` заменяется на имя контейнера. Работает без Docker socket — читает hostname файлы напрямую из overlay2. Кэш обновляется каждый `snapshot_interval`.

### Резолвинг пользователей

При формировании CSV автоматически подставляются текстовые имена пользователей:

| Столбец | Источник | Описание |
|---------|----------|----------|
| `user_name` | uid | Эффективный владелец процесса |
| `login_name` | loginuid | Audit UID — реальный пользователь (сохраняется через sudo/su) |
| `euser_name` | euid | Effective UID |

Резолвинг через NSS (`getpwuid_r`) — поддерживает LDAP, SSSD, NIS и локальные /etc/passwd. Результаты кэшируются с rwlock. `loginuid=4294967295` (не установлен) записывается как `AUDIT_UID_UNSET`.

## HTTP-сервер

Встроенный HTTP/1.1 сервер с кольцевым буфером в памяти. Все данные в RAM — disk I/O отсутствует. Оптимизирован с помощью TCP_CORK и userspace буферизации (128 КБ чанки).

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `port` | `9091` | Порт |
| `bind` | `0.0.0.0` | Адрес привязки |
| `max_buffer_size` | `268435456` (256 МБ) | Размер кольцевого буфера |

### Эндпоинты

| URL | Описание |
|-----|----------|
| `GET /metrics` | CSV — все накопленные события (буфер НЕ очищается) |
| `GET /metrics?format=csv` | То же (явный формат) |
| `GET /metrics?format=csv&clear=1` | CSV + очистка буфера (для ClickHouse MV) |

При переполнении буфера старые события перезатираются (кольцевая семантика).

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

-- 2. Миграция с предыдущей версии (добавление новых столбцов)
clickhouse-client < examples/migrate.sql

-- 3. Создать view для автоматического сбора
CREATE MATERIALIZED VIEW process_metrics_pull_server1
REFRESH EVERY 3 SECOND APPEND
TO process_metrics
AS SELECT * FROM url(
    'http://server1:9091/metrics?format=csv&clear=1',
    'CSVWithNames'
);
```

Требуется ClickHouse >= 23.12. Полная схема — в [examples/clickhouse_schema.sql](examples/clickhouse_schema.sql). Миграция — [examples/migrate.sql](examples/migrate.sql).

### Примеры запросов

```sql
-- Текущее состояние процессов
SELECT pid, comm, exec, rule, user_name, login_name,
       rss_bytes / 1048576 AS rss_mb,
       cpu_usage_ratio
FROM process_metrics
WHERE event_type = 'snapshot'
  AND timestamp > now() - INTERVAL 1 MINUTE
ORDER BY rss_bytes DESC;

-- Действия конкретного пользователя (через sudo/su)
SELECT timestamp, comm, args, user_name, login_name
FROM process_metrics
WHERE login_name = 'solomatovs'
  AND event_type IN ('exec', 'exit')
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

-- TCP retransmissions
SELECT timestamp, sec_local_addr, sec_remote_addr,
       sec_local_port, sec_remote_port, sec_tcp_state
FROM process_metrics
WHERE event_type = 'tcp_retrans'
  AND timestamp > now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;
```

## Grafana

В `examples/` — готовые дашборды для импорта:

| Файл | Описание |
|------|----------|
| [grafana-dashboard.json](examples/grafana-dashboard.json) | Основной дашборд: процессы, CPU, память, I/O, сеть, файлы, диски |
| [grafana-dashboard-security.json](examples/grafana-dashboard-security.json) | Security: retransmissions, SYN flood, RST, UDP/ICMP |

Дашборды поддерживают фильтрацию по:
- **hostname** — сервер
- **login** — audit login (реальный пользователь, сохраняется через sudo/su)
- **user** — эффективный пользователь (текущий uid)
- **rule** — правило отслеживания

Импорт: Grafana → Dashboards → Import → Upload JSON. Datasource — ClickHouse.

## Systemd

Включены два варианта systemd unit:

| Файл | Описание |
|------|----------|
| [process_metrics.service](ci/process_metrics.service) | Современный (systemd >= 246): `AmbientCapabilities`, без root |
| [process_metrics-legacy.service](ci/process_metrics-legacy.service) | Для старых systemd: через root + `User=` |

### Ресурсы (по результатам стресс-тестирования)

Тестовые условия: ~1600 PIDs, все коллекторы включены, snapshot_interval=3s, fork/exec storm.

| Параметр | Значение | Описание |
|----------|----------|----------|
| CPUQuota | 25% | При 20% — 0 drops (граница), при 15% — 70% drops |
| MemoryMax | 384M | RSS ~287 МБ стабильно. OOM при < 256 МБ |

BPF ring buffers размещаются в ядре и не учитываются в cgroup memory. Userspace RSS ≈ 30 МБ + HTTP-буфер (max_buffer_size).

### Hardening

Основной unit включает: `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`, `SystemCallFilter=@system-service bpf perf_event_open`.

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
- `kernel.perf_event_paranoid <= 2` (Debian default=3 блокирует CAP_PERFMON)
- `kernel.unprivileged_bpf_disabled <= 1` (Debian default=2 блокирует CAP_BPF)

```bash
# Или через sysctl.d (файл ci/99-process-metrics.conf)
sudo cp ci/99-process-metrics.conf /etc/sysctl.d/
sudo sysctl --system
```

### Совместимость ядер 5.15 / 6.x

BPF верификатор ядра 5.15 требует инициализации каждого байта стековых переменных, включая padding. Ядро >= 6.0 допускает неинициализированный padding. Проект автоматически адаптируется: Makefile определяет `KERN_VER_MAJOR` и передаёт в BPF-компиляцию. Макрос `BPF_ZERO(var)` на ядрах < 6 выполняет `__builtin_memset`, на >= 6 — no-op.

## Структура проекта

```
src/
  process_metrics.bpf.c        — BPF-программа (tracepoints, kprobes)
  process_metrics.c            — userspace: загрузчик, конфиг, снапшоты, uid-кэш
  process_metrics_common.h     — общие типы (BPF <-> userspace)
  csv_format.c/h               — форматирование CSV (резолвинг uid → username)
  event_file.c/h               — кольцевой буфер событий в памяти
  http_server.c/h              — встроенный HTTP/1.1 сервер (TCP_CORK + 128KB буфер)
  vmlinux.h                    — типы ядра (CO-RE, генерируется)
  bpftool/                     — vendored bpftool
examples/
  process_metrics.conf         — пример конфигурации (все параметры)
  clickhouse_schema.sql        — DDL таблицы + materialized view
  migrate.sql                  — миграция схемы ClickHouse
  grafana-dashboard.json       — основной Grafana-дашборд
  grafana-dashboard-security.json — security-дашборд
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
