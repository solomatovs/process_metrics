# process_metrics

Мониторинг процессов Linux через eBPF. Отслеживает жизненный цикл процессов (exec/fork/exit/OOM), сетевые соединения (TCP connect/accept/close) с детализацией до каждого соединения, файловые операции (open/close/read/write), сигналы, заполненность дисков и сетевые аномалии (retransmit, SYN flood, RST, UDP/ICMP flood).

Работает по pull-модели: накапливает события в кольцевой буфер в памяти и отдаёт по HTTP в формате CSV. Внешний коллектор (ClickHouse Refreshable MV) периодически забирает данные. Disk I/O на горячем пути отсутствует.

## Возможности

- **19 типов событий**: snapshot, conn_snapshot, fork, exec, exit, oom_kill, file_close, net_listen, net_connect, net_accept, net_close, signal, tcp_retrans, syn_recv, rst_sent, rst_recv, udp_agg, icmp_agg, disk_usage
- **90+ полей** на событие: CPU, RSS, swap, I/O, page faults, context switches, threads, namespaces, cgroup v2, сеть (до каждого TCP-соединения с подсчётом вызовов), файлы, сигналы, диски
- **Правила отслеживания**: regex-фильтрация по командной строке с наследованием потомков
- **Кольцевой буфер в RAM**: все данные в памяти, без файлового I/O на горячем пути
- **Резолвинг пользователей**: uid/euid/loginuid → текстовые имена через NSS (LDAP, SSSD, локальные)
- **Аудит**: отслеживание loginuid (audit UID) для идентификации реального пользователя через sudo/su
- **Docker resolve**: автоматическое определение имён контейнеров по cgroup path (без Docker socket)
- **Security-пробы**: TCP retransmit, SYN flood, RST (включая SO_LINGER=0), UDP/ICMP — per-process через sock_map
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
| `make test-security` | Интеграционные тесты security_tracking |

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

| Коллектор | Описание | События | По умолчанию |
|-----------|----------|---------|-------------|
| `cgroup_metrics` | memory.max/current, swap, cpu.weight, pids из cgroup v2 | поля в `snapshot` | вкл |
| `net_tracking` | TCP/UDP lifecycle + security-пробы + per-connection снимки | `net_listen`, `net_connect`, `net_accept`, `net_close`, `conn_snapshot`, `tcp_retrans`, `syn_recv`, `rst_sent`, `rst_recv`, `udp_agg` | выкл |
| `file_tracking` | open/close/read/write через tracepoints | `file_close` | выкл |
| `disk_tracking` | Заполненность дисков через statvfs() | `disk_usage` | вкл |
| `icmp_tracking` | Глобальная агрегация ICMP (не привязана к процессам) | `icmp_agg` | выкл |

### net_tracking

Единая точка конфигурации для всего сетевого отслеживания. Все опции внутри используют общую инфраструктуру — BPF-карту `sock_map`, которая маппит `sk_ptr → (tgid, addr, port, bytes)`.

```conf
net_tracking = {
    enabled = true;          # net_listen/connect/accept/close + conn_snapshot

    # Per-connection метрики
    tcp_bytes = true;        # tx/rx байты + вызовы sendmsg/recvmsg
    udp_bytes = true;        # агрегация UDP байтов/пакетов по (addr, port)

    # TCP security-события
    tcp_retransmit = true;   # tcp_retrans: ретрансмиссии
    tcp_syn = true;          # syn_recv: входящие SYN
    tcp_rst = true;          # rst_sent/rst_recv: TCP RST

    # Счётчик
    tcp_open_conns = true;   # open_tcp_conns в snapshot
};
```

| Опция | Событие | Хук | Описание |
|-------|---------|-----|----------|
| `enabled` | `net_listen`, `net_connect`, `net_accept`, `net_close`, `conn_snapshot` | kprobe/tcp_close, kretprobe/connect/accept, kprobe/listen | Полный lifecycle TCP-соединений + per-connection снимки |
| `tcp_bytes` | — | kprobe/tcp_sendmsg, tcp_recvmsg | Per-connection подсчёт tx/rx байтов и вызовов sendmsg/recvmsg |
| `tcp_retransmit` | `tcp_retrans` | raw_tracepoint/tcp_retransmit_skb | Потеря пакетов, перегрузка, DDoS |
| `syn_tracking` | `syn_recv` | kprobe/tcp_conn_request | SYN flood detection |
| `rst_tracking` | `rst_sent`, `rst_recv` | raw_tracepoint/tcp_send_reset, tcp_receive_reset + kprobe/tcp_send_active_reset | Сканирование портов, отказы, SO_LINGER=0 |
| `udp_tracking` | `udp_agg` | kretprobe/udp_sendmsg, udp_recvmsg | UDP flood, DNS amplification |
| `open_conn_count` | поле в `snapshot` | — (из BPF-карты open_conn_map) | Утечка соединений |

**Автоматическая активация**: если включена любая TCP-security опция (tcp_retransmit, syn_tracking, rst_tracking, open_conn_count), инфраструктура sock_map включается автоматически, даже при `enabled = false`. `enabled` управляет только генерацией `net_close` и `conn_snapshot`.

При старте выполняется init-seed: сканирование `/proc/<pid>/fd/` + BPF iter/tcp для заполнения sock_map существующими сокетами.

**conn_snapshot** — снимок **каждого живого TCP-соединения** с тем же timestamp что и `snapshot` процесса. Поля: `net_conn_tx/rx_bytes` (кумулятивные байты), `net_conn_tx/rx_calls` (количество sendmsg/recvmsg), `net_duration_ms`, `state` (`L`=listener, `E`=established).

### Остальные коллекторы

`file_tracking` — объект с `enabled`, `tcp_bytes` (бывший `track_bytes`), `include` и `exclude` (списки префиксов путей). Без `include` отслеживаются все пути (кроме `exclude`).

`disk_tracking` поддерживает `fs_types` (типы ФС), `include` и `exclude` (префиксы точек монтирования). По умолчанию мониторит: ext2/3/4, xfs, btrfs, vfat, zfs, ntfs, fuseblk, f2fs. Дедуплицирует bind-mount'ы одного устройства.

`icmp_tracking` — глобальная агрегация ICMP-пакетов по (src_addr, type, code). Не привязана к процессам. Верхнеуровневая опция в конфиге.

### BPF ring buffer'ы

Настраиваемые через секцию `ring_buffers`. Дефолтные размеры выдерживают 35K+ TCP conn/sec с 0 drops (стресс-тестировано: 1M соединений за 30 сек при полном трекинге).

| Буфер | Дефолт | События | Когда увеличивать |
|-------|--------|---------|-------------------|
| `proc` | 2 МБ | fork/exec/exit/oom_kill | Fork-штормы (>10K fork/sec) |
| `file` | 2 МБ | file_close | Массовое открытие файлов |
| `net` | 4 МБ | net_listen/connect/accept/close, signal | >50K TCP conn/sec |
| `sec` | 1 МБ | tcp_retrans, syn_recv, rst_sent/recv | DDoS с >100K events/sec |
| `cgroup` | 128 КБ | cgroup mkdir/rmdir | Docker-штормы |

Ring buffer'ы аллоцируются ядром и не учитываются в cgroup memory лимитах. Значения автоматически округляются до степени 2.

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

16 типов событий, разделённых на 4 категории: жизненный цикл процесса, сетевые соединения, безопасность и инфраструктура.

### Жизненный цикл процесса

| event_type | Триггер | Ключевые поля | Описание |
|------------|---------|---------------|----------|
| `exec` | exec() системный вызов | pid, comm, exec, args, uid, cgroup, pwd | Новый процесс подходит под regex-правило. Первый exec запускает трекинг, все потомки наследуют правило |
| `fork` | fork() потомка tracked-процесса | pid, ppid, comm, args (наследуются от родителя) | Потомок автоматически отслеживается с тем же правилом. comm/args берутся из родителя до первого exec |
| `exit` | Завершение процесса | exit_code, cpu_ns, rss_max_bytes, io_read/write_bytes | Финальные кумулятивные метрики процесса. exit_code содержит код возврата (старшие 8 бит) и номер сигнала (младшие 7 бит) |
| `oom_kill` | OOM killer | pid, comm, oom_killed=1 | Процесс убит OOM killer. oom_killed всегда 1. Правило определяется по PID или родителю |
| `signal` | Доставка сигнала | sig_num, sig_target_pid, sig_target_comm, sig_code, sig_result | Любой сигнал: SIGTERM, SIGKILL и т.д. sig_code: SI_USER=0, SI_KERNEL=0x80. sig_result: 0 = успешно доставлен |

### Периодические снимки

| event_type | Триггер | Ключевые поля | Описание |
|------------|---------|---------------|----------|
| `snapshot` | Каждые `snapshot_interval` секунд | Все 90+ полей (см. детали ниже) | Полный снимок каждого отслеживаемого процесса. Одинаковый timestamp для всех процессов в одном цикле. Включает завершившиеся процессы (однократно) |
| `conn_snapshot` | Вместе с `snapshot` | net_local/remote_addr:port, net_conn_tx/rx_bytes, net_conn_tx/rx_calls, net_duration_ms, state | Снимок каждого живого TCP-соединения. state: `L`=listener, `E`=established. Байты и вызовы кумулятивные |

### Сетевые соединения и файлы

| event_type | Триггер | Ключевые поля | Описание |
|------------|---------|---------------|----------|
| `net_listen` | `listen()` | net_local_addr, net_local_port | Процесс начал слушать порт. remote_port=0 |
| `net_connect` | `connect()` завершён | net_local/remote_addr:port | Исходящее TCP-соединение установлено |
| `net_accept` | `accept()` вернул сокет | net_local/remote_addr:port | Входящее TCP-соединение принято |
| `net_close` | `close()` на TCP-сокет | net_conn_tx/rx_bytes, net_conn_tx/rx_calls, net_duration_ms, state | Соединение закрыто. state: `I`=initiator (процесс закрыл первым), `R`=responder (ответ на чужой FIN) |
| `file_close` | Закрытие tracked файла | file_path, file_flags, file_read/write_bytes, file_open_count | Метрики файлового I/O. Фильтруется по include/exclude префиксам |

### Security и инфраструктура

| event_type | Триггер | Ключевые поля | Описание |
|------------|---------|---------------|----------|
| `tcp_retrans` | TCP-ретрансмиссия (потеря пакета) | sec_local/remote_addr, sec_local/remote_port, sec_af, sec_tcp_state | Симптом потери пакетов, перегрузки или DDoS. sec_tcp_state содержит состояние TCP на момент ретрансмиссии |
| `syn_recv` | Входящий SYN-пакет | sec_local/remote_addr, sec_local/remote_port, sec_af | Каждый входящий TCP SYN. Массовое появление = SYN flood |
| `rst_sent` | Отправлен TCP RST | sec_local/remote_addr, sec_local/remote_port, sec_af, sec_direction=0 | RST отправлен. Включает: tracepoint tcp_send_reset + kprobe tcp_send_active_reset (SO_LINGER=0 close) |
| `rst_recv` | Получен TCP RST | sec_local/remote_addr, sec_local/remote_port, sec_af, sec_direction=1 | RST получен. Индикатор: сканирование портов, отказы соединений, connection refused |
| `udp_agg` | Каждый snapshot-цикл | sec_af, sec_remote_addr, sec_remote_port, net_tx/rx_bytes, file_write/read_bytes (пакеты) | Агрегированная статистика UDP за интервал по ключу (tgid, remote_addr, remote_port). Сбрасывается после каждого snapshot |
| `icmp_agg` | Каждый snapshot-цикл | sec_af, sec_remote_addr, sec_tcp_state (icmp_type), sec_direction (icmp_code), open_tcp_conns (count) | Агрегированная статистика ICMP по ключу (src_addr, type, code). Сбрасывается после каждого snapshot |
| `disk_usage` | Каждый snapshot-цикл | file_path (mount point), disk_total/used/avail_bytes, comm (device), sec_remote_addr (fstype) | Заполненность каждой файловой системы. Одно событие на точку монтирования. Дедуплицирует bind-mount'ы |

### Поля snapshot-события (полный список)

Событие `snapshot` содержит максимальное количество полей — полный снимок состояния процесса:

| Группа | Поля | Описание |
|--------|------|----------|
| Идентификация | pid, ppid, root_pid, uid, euid, loginuid, sessionid, tty_nr, comm, exec, args | PID, родитель, UID'ы (реальный, эффективный, audit), терминал, командная строка |
| Правило | rule, tags, is_root | Имя сработавшего правила, все правила через `\|`, корневой ли процесс в дереве |
| CPU | cpu_ns, cpu_usage_ratio, sched_policy | Суммарное CPU-время (нс), доля CPU за интервал (0.0–N.0), политика планировщика |
| Память | rss_bytes, rss_min/max_bytes, shmem_bytes, swap_bytes, vsize_bytes | RSS текущий/мин/макс, shared memory, swap, виртуальная память |
| I/O (блочный) | io_read/write_bytes | Реальный блочный I/O (без page cache) |
| I/O (полный) | io_rchar, io_wchar, io_syscr, io_syscw | Включая page cache: байты и количество системных вызовов |
| Page faults | maj_flt, min_flt | Major (disk) и minor (memory) page faults |
| Планировщик | nvcsw, nivcsw, threads, preempted_by_pid, preempted_by_comm | Добровольные/принудительные переключения контекста, потоки, последний вытеснитель |
| OOM | oom_score_adj, oom_killed | Приоритет OOM killer, был ли убит |
| Сеть (процесс) | net_tx/rx_bytes, open_tcp_conns | Суммарные байты процесса, счётчик активных соединений. Per-connection детали — в conn_snapshot (net_conn_tx/rx_bytes, net_conn_tx/rx_calls) |
| Время | start_time_ns, uptime_seconds | Время старта (boot ns), аптайм процесса (секунды) |
| Namespaces | mnt_ns, pid_ns, net_ns, cgroup_ns | Inode-номера пространств имён |
| cgroup v2 | cgroup_memory_max/current, cgroup_swap_current, cgroup_cpu_weight, cgroup_cpu_max/max_period, cgroup_cpu_nr_periods/nr_throttled/throttled_usec, cgroup_pids_current | Метрики cgroup v2: лимиты памяти, CPU-квоты, throttling, кол-во процессов |
| Файловая система | pwd, cgroup | Текущий рабочий каталог, путь cgroup |
| Родители | parent_pids | Цепочка PID предков: [ppid, ppid's parent, ..., 1] (до 32 уровней) |

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

-- Полный lifecycle TCP-соединений процесса
SELECT timestamp, event_type, pid, comm,
       net_local_addr, net_local_port,
       net_remote_addr, net_remote_port,
       net_conn_tx_bytes, net_conn_rx_bytes,
       net_conn_tx_calls, net_conn_rx_calls,
       net_duration_ms / 1000 AS duration_sec,
       state  -- I=initiator close, R=responder, L=listener, E=established
FROM process_metrics
WHERE event_type IN ('net_listen', 'net_connect', 'net_accept',
                     'conn_snapshot', 'net_close')
  AND timestamp > now() - INTERVAL 5 MINUTE
ORDER BY timestamp;
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
  test_shortlived_snapshot.sh  — тест короткоживущих процессов
  test_conn_snapshot.sh        — e2e тест conn_snapshot (TCP lifecycle)
  test_security.sh             — интеграционные тесты net_tracking security-пробы
  test_reparent_chain.sh       — тест цепочки parent_pids
  stress_net.sh                — сетевой стресс-тест (ring buffer drops)
  stress_net_ringbuf.sh        — подбор оптимальных ring buffer'ов
build/                         — артефакты сборки
Makefile                       — сборка, тесты, установка зависимостей
```

## Сигналы

| Сигнал | Действие |
|--------|----------|
| `SIGTERM` / `SIGINT` | Корректное завершение |
| `SIGHUP` | Перезагрузка правил, пересканирование /proc |
