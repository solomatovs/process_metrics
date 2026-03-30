# metric_event: структура snapshot-данных

Структура `struct metric_event` (определена в `src/event_file.h`) — универсальный контейнер
для всех типов событий (snapshot, exit, fork, file_close, net_close и т.д.).
При `event_type = "snapshot"` заполняются поля из BPF `proc_map`, userspace-кэшей
и `/sys/fs/cgroup`.

Все поля помечены:
- **Кумулятивный** — монотонно растёт от рождения до смерти процесса. Для rate нужна дельта между snapshot'ами.
- **Мгновенный** — значение на момент snapshot'а, может уменьшаться.
- **Фиксированный** — устанавливается один раз, не меняется.

## Идентификация процесса

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `timestamp` | u64 | `clock_gettime(REALTIME)` | — | Время создания snapshot |
| `hostname` | char[] | `gethostname()` / конфиг | — | Фиксируется при старте |
| `event_type` | char[] | userspace | — | Константа `"snapshot"` |
| `rule` | char[] | userspace `rules[]` | `sched_process_exec` | Фиксированный. Сопоставление regex при exec, наследуется при fork |
| `tags` | char[] | userspace `tags_ht` | `sched_process_exec` | Фиксированный. Pipe-separated список всех совпавших правил |
| `root_pid` | u32 | BPF `tracked_map` | `sched_process_fork` | Фиксированный. PID корневого отслеживаемого предка |
| `pid` | u32 | BPF `proc_map.tgid` | `sched_process_fork` | Фиксированный. Thread Group ID (= PID главного потока) |
| `ppid` | u32 | BPF `proc_map.ppid` | `sched_process_fork` | Фиксированный. PID родителя |
| `uid` | u32 | BPF `proc_map.uid` | `sched_switch` → `task->cred->uid` | Мгновенный. Реальный UID, обновляется при каждом переключении контекста |
| `loginuid` | u32 | BPF `proc_map.loginuid` | `sched_switch` → `task->loginuid` | Мгновенный. Audit loginuid |
| `sessionid` | u32 | BPF `proc_map.sessionid` | `sched_switch` → `task->sessionid` | Мгновенный. Audit session ID |
| `euid` | u32 | BPF `proc_map.euid` | `sched_switch` → `task->cred->euid` | Мгновенный. Effective UID |
| `tty_nr` | u32 | BPF `proc_map.tty_nr` | `sched_switch` → `task->signal->tty` | Мгновенный. Управляющий терминал |
| `comm` | char[16] | BPF `proc_map.comm` | `sched_switch` → `task->comm` | Мгновенный. Обновляется также из `/proc/PID/comm` при refresh |
| `exec_path` | char[] | BPF `proc_map.cmdline` | `sched_process_exec` → `/proc/PID/cmdline` | Фиксированный. argv[0] |
| `args` | char[] | BPF `proc_map.cmdline` | `sched_process_exec` → `/proc/PID/cmdline` | Фиксированный. argv[1..] |
| `cgroup` | char[] | userspace cgroup_cache | `stat()` → inode → path | Мгновенный. Путь cgroup v2 (или `docker/<name>`) |
| `pwd` | char[] | userspace pwd_ht | `sys_exit_chdir` / `readlink(/proc/PID/cwd)` | Мгновенный. Текущий рабочий каталог |
| `is_root` | u8 | BPF `tracked_map` | `sched_process_exec` | Фиксированный. 1 = корень отслеживаемого дерева |
| `state` | u8 | BPF `proc_map.state` | `sched_switch` → `task->__state` | Мгновенный. 'R','S','D','T','Z',... |
| `sched_policy` | u32 | BPF `proc_map.sched_policy` | `sched_switch` → `task->policy` | Мгновенный. SCHED_NORMAL=0, SCHED_FIFO=1, SCHED_RR=2 |
| `parent_pids` | u32[] | userspace pidtree_ht | `sched_process_fork` / `sched_process_exit` | Мгновенный. Цепочка [ppid, ppid's parent, ..., 1], до 16 уровней |

## CPU

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `cpu_ns` | u64 | BPF `proc_map.cpu_ns` | `sched_switch` → `task->signal->{utime+stime}` | **Кумулятивный**. Дельта-аккумуляция через `thread_cpu_map` при каждом переключении контекста |
| `cpu_usage_ratio` | double | userspace | — (вычисляется) | **Rate**. `(cpu_ns - prev_cpu_ns) / (wall_time_ns × N_cpus)` за интервал между snapshot'ами. Единственное не-кумулятивное I/O поле |

## Память

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `rss_bytes` | u64 | BPF `proc_map.rss_pages` × PAGE_SIZE | `sched_switch` → `mm->rss_stat` (MM_FILEPAGES + MM_ANONPAGES) | **Мгновенный**. Текущий RSS |
| `rss_min_bytes` | u64 | BPF `proc_map.rss_min_pages` × PAGE_SIZE | `sched_switch` → `min(current, prev_min)` | **Кумулятивный** (monotone down). Минимум RSS за всё время жизни |
| `rss_max_bytes` | u64 | BPF `proc_map.rss_max_pages` × PAGE_SIZE | `sched_switch` → `max(current, prev_max)` | **Кумулятивный** (monotone up). Максимум RSS за всё время жизни |
| `shmem_bytes` | u64 | BPF `proc_map.shmem_pages` × PAGE_SIZE | `sched_switch` → `mm->rss_stat[MM_SHMEMPAGES]` | **Мгновенный**. Разделяемая память |
| `swap_bytes` | u64 | BPF `proc_map.swap_pages` × PAGE_SIZE | `sched_switch` → `mm->rss_stat[MM_SWAPENTS]` | **Мгновенный**. Использование swap |
| `vsize_bytes` | u64 | BPF `proc_map.vsize_pages` × PAGE_SIZE | `sched_switch` → `mm->total_vm` | **Мгновенный**. Виртуальная память (вкл. mmap, стек, heap) |

## I/O

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `io_read_bytes` | u64 | BPF `proc_map.io_read_bytes` | `sched_switch` → `task->ioac.read_bytes` | **Кумулятивный**. Фактические чтения **с диска**, минуя page cache. `read()` файла из кэша не увеличивает этот счётчик |
| `io_write_bytes` | u64 | BPF `proc_map.io_write_bytes` | `sched_switch` → `task->ioac.write_bytes` | **Кумулятивный**. Фактические записи **на диск**, после writeback. Асинхронная запись через page cache задерживает отражение |
| `io_rchar` | u64 | BPF `proc_map.io_rchar` | `sched_switch` → `task->ioac.rchar` | **Кумулятивный**. **Все** прочитанные байты: `read()`, `pread()`, `readv()` включая page cache. Всегда `>= io_read_bytes` |
| `io_wchar` | u64 | BPF `proc_map.io_wchar` | `sched_switch` → `task->ioac.wchar` | **Кумулятивный**. **Все** записанные байты: `write()`, `pwrite()`, `writev()` включая page cache. Всегда `>= io_write_bytes` |
| `io_syscr` | u64 | BPF `proc_map.io_syscr` | `sched_switch` → `task->ioac.syscr` | **Кумулятивный**. Количество syscall чтения: `read()`, `pread64()`, `readv()`, `preadv()` |
| `io_syscw` | u64 | BPF `proc_map.io_syscw` | `sched_switch` → `task->ioac.syscw` | **Кумулятивный**. Количество syscall записи: `write()`, `pwrite64()`, `writev()`, `pwritev()` |
| `file_opens` | u64 | BPF `proc_map.file_opens` | `sys_enter_openat` → `__sync_fetch_and_add` | **Кумулятивный**. Все `openat()` tracked-процесса, до include/exclude фильтров. Только файлы (openat не создаёт сокеты/пайпы) |

## Page faults

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `maj_flt` | u64 | BPF `proc_map.maj_flt` | `sched_switch` → `task->signal->maj_flt + task->maj_flt` | **Кумулятивный**. Мажорные page faults — данные загружены с диска (swap in, mmap read) |
| `min_flt` | u64 | BPF `proc_map.min_flt` | `sched_switch` → `task->signal->min_flt + task->min_flt` | **Кумулятивный**. Минорные page faults — COW, zero page, уже в памяти |

## Планировщик / потоки / OOM

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `nvcsw` | u64 | BPF `proc_map.nvcsw` | `sched_switch` → `task->signal->nvcsw + task->nvcsw` | **Кумулятивный**. Добровольные переключения (процесс вызвал `sleep()`, `read()` с блокировкой, `futex()` и т.д.) |
| `nivcsw` | u64 | BPF `proc_map.nivcsw` | `sched_switch` → `task->signal->nivcsw + task->nivcsw` | **Кумулятивный**. Принудительные переключения (исчерпан timeslice, вытеснен более приоритетным) |
| `threads` | u32 | BPF `proc_map.threads` | `sched_switch` → `task->signal->nr_threads` | **Мгновенный**. Количество потоков в thread group |
| `oom_score_adj` | s16 | BPF `proc_map.oom_score_adj` | `sched_switch` → `task->signal->oom_score_adj` | **Мгновенный**. Приоритет OOM killer (-1000..+1000) |
| `oom_killed` | u8 | BPF `proc_map.oom_killed` | `raw_tracepoint/mark_victim` | **Флаг**. Устанавливается в 1 при выборе OOM killer, не сбрасывается |
| `exit_code` | u32 | BPF `proc_map.exit_code` | `sched_process_exit` → `task->exit_code` | **Фиксированный**. Заполняется при exit: `(exit_code >> 8) & 0xff`. 0 для живых процессов |

## Сеть процесса

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `net_tx_bytes` | u64 | BPF `proc_map.net_tx_bytes` | `kretprobe/tcp_sendmsg`, `kretprobe/udp_sendmsg` → `__sync_fetch_and_add` | **Кумулятивный**. TCP+UDP байт отправлено за всё время жизни |
| `net_rx_bytes` | u64 | BPF `proc_map.net_rx_bytes` | `kretprobe/tcp_recvmsg`, `kretprobe/udp_recvmsg` → `__sync_fetch_and_add` | **Кумулятивный**. TCP+UDP байт получено за всё время жизни |
| `open_tcp_conns` | u64 | userspace | iteration `sock_map` в `write_snapshot()` | **Мгновенный**. Подсчёт записей в BPF `sock_map` для данного tgid |

## Время жизни

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `start_time_ns` | u64 | BPF `proc_map.start_ns` | `sched_process_fork` → `bpf_ktime_get_boot_ns()` + wall offset | **Фиксированный**. Время рождения, устанавливается один раз |
| `uptime_seconds` | u64 | userspace | — (вычисляется) | **Мгновенный**. `monotonic_now - start_ns / 1e9` на момент snapshot'а |

## Пространства имён

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `mnt_ns_inum` | u32 | BPF `proc_map.mnt_ns_inum` | `sched_switch` → `task->nsproxy->mnt_ns->ns.inum` | **Мгновенный**. Может меняться при `setns()` / `unshare()` |
| `pid_ns_inum` | u32 | BPF `proc_map.pid_ns_inum` | `sched_switch` → `task->nsproxy->pid_ns_for_children` | **Мгновенный** |
| `net_ns_inum` | u32 | BPF `proc_map.net_ns_inum` | `sched_switch` → `task->nsproxy->net_ns` | **Мгновенный** |
| `cgroup_ns_inum` | u32 | BPF `proc_map.cgroup_ns_inum` | `sched_switch` → `task->nsproxy->cgroup_ns` | **Мгновенный** |

## Вытеснение

| Поле | Тип | Источник | Syscall / Hook | Как обновляется |
|------|-----|----------|----------------|-----------------|
| `preempted_by_pid` | u32 | BPF `proc_map.preempted_by_pid` | `sched_switch` (prev->state != TASK_RUNNING) | **Мгновенный**. PID последнего вытеснителя. Обновляется только при принудительном переключении |
| `preempted_by_comm` | char[16] | BPF `proc_map.preempted_by_comm` | `sched_switch` → `tid_tgid_map` lookup | **Мгновенный**. comm главного потока вытеснителя (резолвлен из TID через `tid_tgid_map`) |

## Cgroup v2

Все поля заполняются в userspace `refresh_processes()` через чтение файлов из `/sys/fs/cgroup/<path>/`.
Кэшируются в `cg_metrics[]`, применяются к snapshot по cgroup path.

| Поле | Тип | Источник (файл в sysfs) | Syscall | Описание |
|------|-----|-------------------------|---------|----------|
| `cgroup_memory_max` | s64 | `memory.max` | `open()` + `read()` | **Мгновенный**. Лимит памяти cgroup. `max` = без ограничений → 0 |
| `cgroup_memory_current` | s64 | `memory.current` | `open()` + `read()` | **Мгновенный**. Текущее потребление памяти cgroup |
| `cgroup_swap_current` | s64 | `memory.swap.current` | `open()` + `read()` | **Мгновенный**. Текущее использование swap cgroup |
| `cgroup_cpu_weight` | s64 | `cpu.weight` | `open()` + `read()` | **Мгновенный**. Вес CPU (1-10000, default 100) |
| `cgroup_cpu_max` | s64 | `cpu.max` (первое число) | `open()` + `read()` | **Мгновенный**. Квота CPU за период (мкс). `max` → 0 |
| `cgroup_cpu_max_period` | s64 | `cpu.max` (второе число) | `open()` + `read()` | **Мгновенный**. Период планирования (мкс), обычно 100000 |
| `cgroup_cpu_nr_periods` | s64 | `cpu.stat: nr_periods` | `open()` + `read()` | **Кумулятивный**. Общее число периодов планирования |
| `cgroup_cpu_nr_throttled` | s64 | `cpu.stat: nr_throttled` | `open()` + `read()` | **Кумулятивный**. Периоды с throttling'ом |
| `cgroup_cpu_throttled_usec` | s64 | `cpu.stat: throttled_usec` | `open()` + `read()` | **Кумулятивный**. Суммарное время throttling (микросекунды) |
| `cgroup_pids_current` | s64 | `pids.current` | `open()` + `read()` | **Мгновенный**. Количество процессов в cgroup |

## Потоки данных

```
                    BPF (ядро)                           Userspace
                    ==========                           =========

sched_switch ─────► proc_map (30+ полей)
  каждое переключ.    rss, cpu_ns, io_*,
  контекста           nvcsw, state, threads...
                         │
sys_exit_openat ─────► proc_map.file_opens++
sys_enter_close ─────► proc_map.file_closes++
                         │
ret_tcp_sendmsg ─────► proc_map.net_tx_bytes+=
ret_tcp_recvmsg ─────► proc_map.net_rx_bytes+=
                         │
mark_victim ─────────► proc_map.oom_killed=1
                         │
                         ▼
                  bpf_map_lookup_batch ──► write_snapshot()
                  (каждые snapshot_interval)     │
                                                 ├─ cpu_prev_cache → cpu_usage_ratio
                                                 ├─ cg_metrics[]   → cgroup_* поля
                                                 ├─ tags_ht        → tags
                                                 ├─ pwd_ht         → pwd
                                                 ├─ pidtree_ht     → parent_pids
                                                 ├─ sock_map iter  → open_tcp_conns
                                                 └─ ef_append()    → HTTP ring buffer → CSV
```
