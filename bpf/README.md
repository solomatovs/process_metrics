# process_metrics — event-driven BPF process metrics collector

Мониторит жизненный цикл процессов (exec/fork/exit) через eBPF tracepoints и экспортирует метрики в формате Prometheus. Отслеживает только процессы, подходящие под пользовательские regex-правила, а также всех их потомков.

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

Требуется clang >= 10 (для BPF CO-RE).

## Запуск

```bash
./build/process_metrics -c config.conf [-o dir] [-f file] [-i sec] [-p prefix]
```

### Аргументы командной строки

| Флаг | Переменная окружения | По умолчанию | Описание |
|------|---------------------|--------------|----------|
| `-c <path>` | `config_file` | — | Файл конфигурации (правила) |
| `-o <dir>` | `output_dir` | `/scripts/system_metrics` | Директория для .prom файла |
| `-f <file>` | `output_file` | `process_metrics.prom` | Имя выходного файла |
| `-i <sec>` | `snapshot_interval` | `30` | Интервал записи метрик (секунды) |
| `-p <prefix>` | `metric_prefix` | `process_metrics` | Префикс метрик |
| `-l <len>` | `cmdline_max_len` | `200` | Макс. длина cmdline в выводе |
| `-r <N>` | `exec_rate_limit` | `0` (без лимита) | Лимит exec-событий в секунду |
| `-h` | — | — | Справка |

## Конфигурация

Формат файла: `имя = /regex/`

```ini
# Комментарии начинаются с # или ;
airflow_celery    = /celery@.*MainProcess/
airflow_scheduler = /airflow scheduler$/
postgres          = /bin\/postgres.*-D/
dockerd           = /dockerd/
```

Regex применяется к полной командной строке процесса. При совпадении процесс и все его потомки отслеживаются.

Перезагрузка конфигурации без перезапуска:

```bash
kill -HUP <pid>
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
```

**От root**
```bash
sudo ./build/process_metrics -c config.conf
```

## Метрики

Пишутся в `.prom` файл с интервалом `-i` (по умолчанию 30 с). Все метрики используют префикс, задаваемый через `-p` (по умолчанию `process_metrics`).

В примерах ниже используется префикс `process_metrics`. Лейблы `rule`, `root_pid`, `pid` присутствуют на всех per-process метриках. Метрика `_info` дополнительно содержит `comm`, `cmdline`, `cgroup`.

### Per-process (живые процессы)

#### Информационные

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_info` | gauge | Информационная метрика (всегда 1). Несёт метаданные в лейблах: `comm`, `cmdline`, `cgroup` |
| `{prefix}_start_time_seconds` | gauge | Время запуска процесса (unix epoch, секунды) |
| `{prefix}_uptime_seconds` | gauge | Время работы процесса в секундах |
| `{prefix}_is_root` | gauge | 1 — корневой процесс (совпал с regex), 0 — потомок |

#### CPU

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_cpu_seconds_total` | counter | Суммарное CPU-время (user + system) в секундах |
| `{prefix}_cpu_usage_ratio` | gauge | Утилизация CPU за последний snapshot-интервал (1.0 = 1 ядро) |

#### Память

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_rss_bytes` | gauge | Текущий RSS (Resident Set Size) в байтах |
| `{prefix}_rss_min_bytes` | gauge | Минимальный наблюдаемый RSS за время жизни процесса |
| `{prefix}_rss_max_bytes` | gauge | Максимальный наблюдаемый RSS за время жизни процесса |
| `{prefix}_vsize_bytes` | gauge | Виртуальная память (total_vm) в байтах |
| `{prefix}_shmem_bytes` | gauge | Shared memory в байтах |
| `{prefix}_swap_bytes` | gauge | Swap usage в байтах |

#### Дисковый I/O

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_io_read_bytes_total` | counter | Фактически прочитано с диска (байт) |
| `{prefix}_io_write_bytes_total` | counter | Фактически записано на диск (байт) |
| `{prefix}_major_page_faults_total` | counter | Major page faults (потребовавшие дисковый I/O) |
| `{prefix}_minor_page_faults_total` | counter | Minor page faults (без дискового I/O) |

#### Планировщик / переключения контекста

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_voluntary_ctxsw_total` | counter | Добровольные переключения контекста (процесс уступил CPU) |
| `{prefix}_involuntary_ctxsw_total` | counter | Принудительные переключения контекста (вытеснение ядром) |

#### Сеть

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_net_tx_bytes_total` | counter | TCP+UDP байт отправлено |
| `{prefix}_net_rx_bytes_total` | counter | TCP+UDP байт получено |

#### Прочие

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_threads` | gauge | Количество потоков процесса |
| `{prefix}_oom_score_adj` | gauge | Текущий OOM score adjustment |
| `{prefix}_oom_kill` | gauge | 1 если процесс был убит OOM killer |
| `{prefix}_state` | gauge | Состояние процесса, лейбл `state` содержит символ: R=running, S=sleeping, D=disk_sleep, T=stopped, Z=zombie |

#### Пример вывода (живые процессы)

```promql
# HELP process_metrics_info Process info (value always 1, metadata in labels)
# TYPE process_metrics_info gauge
process_metrics_info{rule="postgres",root_pid="1234",pid="1234",comm="postgres",cmdline="/usr/bin/postgres -D /var/lib/postgresql/data",cgroup="/system.slice/postgresql.service"} 1
process_metrics_info{rule="postgres",root_pid="1234",pid="1250",comm="postgres",cmdline="postgres: checkpointer",cgroup="/system.slice/postgresql.service"} 1

# HELP process_metrics_start_time_seconds Process start time as unix epoch
# TYPE process_metrics_start_time_seconds gauge
process_metrics_start_time_seconds{rule="postgres",root_pid="1234",pid="1234"} 1711012345

# HELP process_metrics_uptime_seconds Process uptime in seconds
# TYPE process_metrics_uptime_seconds gauge
process_metrics_uptime_seconds{rule="postgres",root_pid="1234",pid="1234"} 86400

# HELP process_metrics_is_root Whether PID is a root of tracked tree (1=root, 0=child)
# TYPE process_metrics_is_root gauge
process_metrics_is_root{rule="postgres",root_pid="1234",pid="1234"} 1
process_metrics_is_root{rule="postgres",root_pid="1234",pid="1250"} 0

# HELP process_metrics_cpu_seconds_total Total CPU time (user + system) in seconds
# TYPE process_metrics_cpu_seconds_total counter
process_metrics_cpu_seconds_total{rule="postgres",root_pid="1234",pid="1234"} 1523.45

# HELP process_metrics_cpu_usage_ratio CPU usage ratio over last snapshot interval (1.0 = 1 core)
# TYPE process_metrics_cpu_usage_ratio gauge
process_metrics_cpu_usage_ratio{rule="postgres",root_pid="1234",pid="1234"} 0.0312

# HELP process_metrics_rss_bytes Process RSS memory in bytes
# TYPE process_metrics_rss_bytes gauge
process_metrics_rss_bytes{rule="postgres",root_pid="1234",pid="1234"} 134217728

# HELP process_metrics_rss_min_bytes Min observed RSS memory in bytes
# TYPE process_metrics_rss_min_bytes gauge
process_metrics_rss_min_bytes{rule="postgres",root_pid="1234",pid="1234"} 67108864

# HELP process_metrics_rss_max_bytes Max observed RSS memory in bytes
# TYPE process_metrics_rss_max_bytes gauge
process_metrics_rss_max_bytes{rule="postgres",root_pid="1234",pid="1234"} 268435456

# HELP process_metrics_vsize_bytes Process virtual memory in bytes
# TYPE process_metrics_vsize_bytes gauge
process_metrics_vsize_bytes{rule="postgres",root_pid="1234",pid="1234"} 536870912

# HELP process_metrics_shmem_bytes Shared memory in bytes
# TYPE process_metrics_shmem_bytes gauge
process_metrics_shmem_bytes{rule="postgres",root_pid="1234",pid="1234"} 16777216

# HELP process_metrics_swap_bytes Swap usage in bytes
# TYPE process_metrics_swap_bytes gauge
process_metrics_swap_bytes{rule="postgres",root_pid="1234",pid="1234"} 0

# HELP process_metrics_io_read_bytes_total Actual disk read bytes
# TYPE process_metrics_io_read_bytes_total counter
process_metrics_io_read_bytes_total{rule="postgres",root_pid="1234",pid="1234"} 10485760

# HELP process_metrics_io_write_bytes_total Actual disk write bytes
# TYPE process_metrics_io_write_bytes_total counter
process_metrics_io_write_bytes_total{rule="postgres",root_pid="1234",pid="1234"} 52428800

# HELP process_metrics_major_page_faults_total Major page faults (required disk IO)
# TYPE process_metrics_major_page_faults_total counter
process_metrics_major_page_faults_total{rule="postgres",root_pid="1234",pid="1234"} 42

# HELP process_metrics_minor_page_faults_total Minor page faults (no disk IO)
# TYPE process_metrics_minor_page_faults_total counter
process_metrics_minor_page_faults_total{rule="postgres",root_pid="1234",pid="1234"} 98765

# HELP process_metrics_voluntary_ctxsw_total Voluntary context switches (process yielded CPU)
# TYPE process_metrics_voluntary_ctxsw_total counter
process_metrics_voluntary_ctxsw_total{rule="postgres",root_pid="1234",pid="1234"} 54321

# HELP process_metrics_involuntary_ctxsw_total Involuntary context switches (preempted by kernel)
# TYPE process_metrics_involuntary_ctxsw_total counter
process_metrics_involuntary_ctxsw_total{rule="postgres",root_pid="1234",pid="1234"} 1234

# HELP process_metrics_net_tx_bytes_total TCP+UDP bytes sent
# TYPE process_metrics_net_tx_bytes_total counter
process_metrics_net_tx_bytes_total{rule="postgres",root_pid="1234",pid="1234"} 1048576

# HELP process_metrics_net_rx_bytes_total TCP+UDP bytes received
# TYPE process_metrics_net_rx_bytes_total counter
process_metrics_net_rx_bytes_total{rule="postgres",root_pid="1234",pid="1234"} 2097152

# HELP process_metrics_threads Number of threads
# TYPE process_metrics_threads gauge
process_metrics_threads{rule="postgres",root_pid="1234",pid="1234"} 8

# HELP process_metrics_oom_score_adj Current OOM score adjustment
# TYPE process_metrics_oom_score_adj gauge
process_metrics_oom_score_adj{rule="postgres",root_pid="1234",pid="1234"} -500

# HELP process_metrics_oom_kill Process was killed by OOM killer (1=killed)
# TYPE process_metrics_oom_kill gauge
process_metrics_oom_kill{rule="postgres",root_pid="1234",pid="1234"} 0

# HELP process_metrics_state Process state (R=running, S=sleeping, D=disk_sleep, T=stopped, Z=zombie)
# TYPE process_metrics_state gauge
process_metrics_state{rule="postgres",root_pid="1234",pid="1234",state="S"} 1
```

### Exited (недавно завершившиеся процессы)

Метрики завершившихся процессов хранятся в кольцевом буфере и выводятся до вытеснения новыми записями. Лейблы: `rule`, `root_pid`, `pid`, `comm`, `cmdline`.

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_exited_exit_code` | gauge | Код завершения процесса (WEXITSTATUS) |
| `{prefix}_exited_signal` | gauge | Сигнал, убивший процесс (0 = нормальное завершение) |
| `{prefix}_exited_oom_kill` | gauge | 1 если процесс был убит OOM killer |
| `{prefix}_exited_cpu_seconds_total` | gauge | Суммарное CPU-время завершившегося процесса |
| `{prefix}_exited_rss_max_bytes` | gauge | Максимальный RSS за время жизни завершившегося процесса |
| `{prefix}_exited_net_tx_bytes_total` | gauge | TCP+UDP байт отправлено завершившимся процессом |
| `{prefix}_exited_net_rx_bytes_total` | gauge | TCP+UDP байт получено завершившимся процессом |

#### Пример вывода (exited)

```promql
# HELP process_metrics_exited_exit_code Exit code of recently exited process
# TYPE process_metrics_exited_exit_code gauge
process_metrics_exited_exit_code{rule="airflow_celery",root_pid="5000",pid="5120",comm="python3",cmdline="python3 /opt/airflow/task.py"} 0

# HELP process_metrics_exited_signal Signal that killed recently exited process (0=normal)
# TYPE process_metrics_exited_signal gauge
process_metrics_exited_signal{rule="airflow_celery",root_pid="5000",pid="5120",comm="python3",cmdline="python3 /opt/airflow/task.py"} 0

# HELP process_metrics_exited_oom_kill Process was killed by OOM killer
# TYPE process_metrics_exited_oom_kill gauge
process_metrics_exited_oom_kill{rule="airflow_celery",root_pid="5000",pid="5120",comm="python3",cmdline="python3 /opt/airflow/task.py"} 0

# HELP process_metrics_exited_cpu_seconds_total Total CPU of exited process
# TYPE process_metrics_exited_cpu_seconds_total gauge
process_metrics_exited_cpu_seconds_total{rule="airflow_celery",root_pid="5000",pid="5120",comm="python3",cmdline="python3 /opt/airflow/task.py"} 12.34

# HELP process_metrics_exited_rss_max_bytes Max RSS of exited process
# TYPE process_metrics_exited_rss_max_bytes gauge
process_metrics_exited_rss_max_bytes{rule="airflow_celery",root_pid="5000",pid="5120",comm="python3",cmdline="python3 /opt/airflow/task.py"} 536870912

# HELP process_metrics_exited_net_tx_bytes_total TCP+UDP bytes sent by exited process
# TYPE process_metrics_exited_net_tx_bytes_total gauge
process_metrics_exited_net_tx_bytes_total{rule="airflow_celery",root_pid="5000",pid="5120",comm="python3",cmdline="python3 /opt/airflow/task.py"} 4096

# HELP process_metrics_exited_net_rx_bytes_total TCP+UDP bytes received by exited process
# TYPE process_metrics_exited_net_rx_bytes_total gauge
process_metrics_exited_net_rx_bytes_total{rule="airflow_celery",root_pid="5000",pid="5120",comm="python3",cmdline="python3 /opt/airflow/task.py"} 8192
```

### Per-cgroup (cgroup v2)

Метрики cgroup выводятся для каждой уникальной cgroup, в которой обнаружены отслеживаемые процессы. Лейблы: `rule`, `cgroup`.

| Метрика | Тип | Описание |
|---------|-----|----------|
| `{prefix}_cgroup_memory_max_bytes` | gauge | `memory.max` — лимит памяти cgroup (0 = unlimited) |
| `{prefix}_cgroup_memory_current_bytes` | gauge | `memory.current` — текущее потребление памяти cgroup |
| `{prefix}_cgroup_memory_swap_current_bytes` | gauge | `memory.swap.current` — текущий swap cgroup |
| `{prefix}_cgroup_cpu_weight` | gauge | `cpu.weight` — вес CPU cgroup |
| `{prefix}_cgroup_pids_current` | gauge | `pids.current` — текущее число процессов в cgroup |

#### Пример вывода (cgroup)

```promql
# HELP process_metrics_cgroup_memory_max_bytes Cgroup memory.max (0=unlimited)
# TYPE process_metrics_cgroup_memory_max_bytes gauge
process_metrics_cgroup_memory_max_bytes{rule="postgres",cgroup="/system.slice/postgresql.service"} 2147483648

# HELP process_metrics_cgroup_memory_current_bytes Cgroup memory.current
# TYPE process_metrics_cgroup_memory_current_bytes gauge
process_metrics_cgroup_memory_current_bytes{rule="postgres",cgroup="/system.slice/postgresql.service"} 314572800

# HELP process_metrics_cgroup_memory_swap_current_bytes Cgroup memory.swap.current
# TYPE process_metrics_cgroup_memory_swap_current_bytes gauge
process_metrics_cgroup_memory_swap_current_bytes{rule="postgres",cgroup="/system.slice/postgresql.service"} 0

# HELP process_metrics_cgroup_cpu_weight Cgroup cpu.weight
# TYPE process_metrics_cgroup_cpu_weight gauge
process_metrics_cgroup_cpu_weight{rule="postgres",cgroup="/system.slice/postgresql.service"} 100

# HELP process_metrics_cgroup_pids_current Cgroup pids.current
# TYPE process_metrics_cgroup_pids_current gauge
process_metrics_cgroup_pids_current{rule="postgres",cgroup="/system.slice/postgresql.service"} 12
```

## Регенерация vmlinux.h

Если целевое ядро отличается от ядра сборки:

```bash
make vmlinux
```

## Структура проекта

```
src/
  process_metrics.bpf.c       — BPF-программа (tracepoints: exec, fork, exit, sched_switch; kretprobes: tcp/udp)
  process_metrics.c            — userspace: загрузчик, конфиг, экспорт метрик
  process_metrics_common.h     — общие типы (BPF ↔ userspace)
  vmlinux.h                    — типы ядра (CO-RE, генерируется из BTF)
  bpftool/                     — vendored bpftool
build/                         — артефакты сборки (gitignored)
  bpftool                      — собранный bpftool
  process_metrics              — итоговый бинарник
  process_metrics.bpf.o        — BPF ELF-объект
  process_metrics.skel.h       — сгенерированный skeleton
Makefile                       — сборка, установка зависимостей
```

## Сигналы

| Сигнал | Действие |
|--------|----------|
| `SIGTERM` / `SIGINT` | Корректное завершение |
| `SIGHUP` | Перезагрузка конфигурации, пересканирование `/proc` |
