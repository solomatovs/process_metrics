# Типы событий process_metrics

Все события записываются в единую структуру `struct metric_event` ([event_file.h](../src/event_file.h))
и сериализуются в CSV. Поля, не относящиеся к данному типу события, остаются нулевыми.

## Содержание

- [Жизненный цикл процесса](#жизненный-цикл-процесса): fork, exec, exit, oom_kill
- [Файловые операции](#файловые-операции): file_open, file_close, file_rename, file_unlink, file_truncate, file_chmod, file_chown
- [Сеть](#сеть): net_listen, net_connect, net_accept, net_close
- [Сигналы](#сигналы): signal
- [Безопасность](#безопасность): tcp_retrans, syn_recv, rst_sent, rst_recv
- [Агрегация](#агрегация): udp_agg, icmp_agg
- [Снимки](#снимки): snapshot, conn_snapshot, file_snapshot
- [Диск](#диск): disk_usage

---

## Жизненный цикл процесса

Источник: BPF `struct event` → ring buffer `events_proc` → userspace `event_from_bpf()`.

### fork

Новый процесс создан через `clone()`/`fork()`.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | `clock_gettime(REALTIME)` | Время получения события |
| event_type | | `"fork"` |
| rule, tags | userspace: наследуется от родителя | Правило отслеживания |
| root_pid | BPF `tracked_map` (наследуется) | Корневой PID дерева |
| pid | BPF `event.tgid` | PID нового процесса |
| ppid | BPF `event.ppid` | PID родителя |
| uid | BPF `event.uid` | Реальный UID |
| comm | BPF `event.comm` | Имя процесса |
| exec_path, args | BPF `event.cmdline` (от родителя) | Командная строка родителя |
| cgroup | userspace cgroup_cache | Путь cgroup |
| loginuid, sessionid, euid, tty_nr | BPF `event.*` | Identity |
| sched_policy | BPF `event.sched_policy` | Политика планировщика |
| mnt_ns, pid_ns, net_ns, cgroup_ns | BPF `event.*_inum` | Namespaces |
| pwd | userspace pwd_ht | Рабочий каталог (наследуется) |
| parent_pids | userspace pidtree_ht | Цепочка предков |

### exec

Процесс выполнил `execve()` — загрузил новый бинарник.

| Поле | Отличие от fork |
|------|-----------------|
| event_type | `"exec"` |
| exec_path, args | Новый бинарник и аргументы |
| rule, tags | Пересопоставляется по новой cmdline |

### exit

Процесс завершился (exit/kill/oom).

| Поле | Отличие от fork |
|------|-----------------|
| event_type | `"exit"` |
| exit_code | `(task->exit_code >> 8) & 0xff` — код возврата |
| cpu_ns | Финальное значение CPU time |
| rss_max_bytes, rss_min_bytes | Пиковые значения за всё время жизни |
| oom_killed | 1, если убит OOM killer |
| net_tx_bytes, net_rx_bytes | Финальные значения сетевого I/O |
| io_rchar, io_wchar | Финальные значения всего I/O (включая page cache) |
| io_read_bytes, io_write_bytes | Финальные значения фактического disk I/O (минуя cache) |
| io_syscr, io_syscw | Финальные счётчики syscall read/write |
| start_time_ns | Время рождения (для вычисления uptime) |

### oom_kill

OOM killer выбрал процесс жертвой. Поля идентичны exit, плюс:

| Поле | Описание |
|------|----------|
| event_type | `"oom_kill"` |
| oom_killed | Всегда 1 |

---

## Файловые операции

Источник: BPF `struct file_event` → ring buffer `events_file` или `events_file_ops`.

### file_open

Процесс открыл файл через `openat()`. Ring buffer: `events_file`.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | BPF `boot_ns` + wall offset | Время открытия |
| event_type | | `"file_open"` |
| rule, tags | userspace | По tracked_map |
| pid, ppid, uid, comm | BPF `file_event` | Идентификация |
| loginuid, sessionid, euid, tty_nr | BPF `proc_map` lookup | Identity |
| cgroup | userspace cgroup_cache | Путь cgroup |
| file_path | BPF: аргумент `pathname` из `openat()` | Абсолютный путь к файлу |
| file_flags | BPF: аргумент `flags` из `openat()` | O_RDONLY, O_WRONLY, O_CREAT и т.д. |
| pwd | userspace pwd_ht | Рабочий каталог |
| parent_pids | userspace pidtree_ht | Цепочка предков |

### file_close

Процесс закрыл файл через `close()`. Ring buffer: `events_file`.
Содержит **накопленные** метрики I/O за время жизни fd.

| Поле | Источник | Описание |
|------|----------|----------|
| (все поля file_open) | | |
| file_read_bytes | BPF `fd_map`: `__sync_fetch_and_add` в handle_read/pread/readv | Суммарно прочитано байт через этот fd |
| file_write_bytes | BPF `fd_map`: `__sync_fetch_and_add` в handle_write/pwrite/writev | Суммарно записано байт через этот fd |
| file_open_count | BPF `fd_map.open_count` | Сколько раз fd был переоткрыт (обычно 1) |
| file_fsync_count | BPF `fd_map.fsync_count` | Количество fsync/fdatasync вызовов |

### file_rename

Файл переименован через `rename()`/`renameat2()`. Ring buffer: `events_file`.

| Поле | Источник | Описание |
|------|----------|----------|
| (идентификация как file_open) | | |
| file_path | BPF: старый путь | Исходный путь |
| file_new_path | BPF `file_event.path2` | Новый путь |

### file_unlink

Файл удалён через `unlink()`/`unlinkat()`. Ring buffer: `events_file`.

| Поле | Описание |
|------|----------|
| file_path | Путь удалённого файла |

### file_truncate

Файл обрезан через `truncate()`/`ftruncate()`. Ring buffer: `events_file`.

| Поле | Описание |
|------|----------|
| file_path | Путь файла |
| file_write_bytes | Новый размер файла (truncate_size) |

### file_chmod

Изменены права через `fchmodat()`. Ring buffer: `events_file_ops`.

| Поле | Описание |
|------|----------|
| file_path | Путь файла |
| file_chmod_mode | Новый mode (octal) |

### file_chown

Изменён владелец через `fchownat()`. Ring buffer: `events_file_ops`.

| Поле | Описание |
|------|----------|
| file_path | Путь файла |
| file_chown_uid | Новый UID |
| file_chown_gid | Новый GID |

---

## Сеть

Источник: BPF `struct net_event` → ring buffer `events_net`.

Все сетевые события заполняют одинаковый набор полей:

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | BPF `boot_ns` + wall offset | Время события |
| event_type | | `"net_listen"` / `"net_connect"` / `"net_accept"` / `"net_close"` |
| rule, tags | userspace | По tracked_map |
| pid, ppid, uid, comm | BPF `net_event` | Идентификация |
| loginuid, sessionid, euid, tty_nr | BPF `proc_map` lookup | Identity |
| cgroup | userspace cgroup_cache | Путь cgroup |
| net_local_addr | BPF: форматированный IPv4/IPv6 | Локальный IP-адрес |
| net_remote_addr | BPF: форматированный IPv4/IPv6 | Удалённый IP-адрес |
| net_local_port | BPF `net_event.local_port` | Локальный порт |
| net_remote_port | BPF `net_event.remote_port` | Удалённый порт |
| net_conn_tx_bytes | BPF `net_event.tx_bytes` | Байт отправлено через соединение |
| net_conn_rx_bytes | BPF `net_event.rx_bytes` | Байт получено через соединение |
| net_conn_tx_calls | BPF `net_event.tx_calls` | Количество sendmsg вызовов |
| net_conn_rx_calls | BPF `net_event.rx_calls` | Количество recvmsg вызовов |
| net_duration_ms | BPF `duration_ns / 1000000` | Длительность соединения (мс) |
| state | только net_close: TCP state | `'I'`=initiator (ESTABLISHED), `'R'`=responder (CLOSE_WAIT) |
| pwd | userspace pwd_ht | Рабочий каталог |
| parent_pids | userspace pidtree_ht | Цепочка предков |

---

## Сигналы

Источник: BPF `struct signal_event` → ring buffer `events_proc`.

### signal

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | `clock_gettime(REALTIME)` | Время доставки |
| event_type | | `"signal"` |
| rule, tags | userspace: по отправителю или получателю | |
| pid | BPF `signal_event.sender_tgid` | PID отправителя |
| uid | BPF `signal_event.sender_uid` | UID отправителя |
| comm | BPF `signal_event.sender_comm` | Имя отправителя |
| loginuid, sessionid, euid, tty_nr | BPF `proc_map` (отправитель) | Identity |
| cgroup | userspace | Cgroup отправителя |
| sig_num | BPF `signal_event.sig` | Номер сигнала (9=SIGKILL, 15=SIGTERM и т.д.) |
| sig_target_pid | BPF `signal_event.target_pid` | PID получателя |
| sig_target_comm | userspace: `/proc/target/comm` | Имя получателя |
| sig_code | BPF `signal_event.sig_code` | SI_USER=0, SI_KERNEL=0x80 |
| sig_result | BPF `signal_event.sig_result` | 0 = успешно доставлен |

---

## Безопасность

### tcp_retrans

Источник: BPF `struct retransmit_event` → ring buffer `events_sec`.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | `clock_gettime(REALTIME)` | Время ретрансмиссии |
| event_type | | `"tcp_retrans"` |
| pid, uid, comm | BPF `retransmit_event` | Процесс-владелец сокета |
| sec_af | BPF | AF_INET=2, AF_INET6=10 |
| sec_local_addr, sec_remote_addr | BPF: форматированный IP | Адреса |
| sec_local_port, sec_remote_port | BPF | Порты |
| sec_tcp_state | BPF | TCP state на момент ретрансмита |

### syn_recv

Источник: BPF `struct syn_event` → ring buffer `events_sec`.
Поля как tcp_retrans, без `sec_tcp_state`.

### rst_sent / rst_recv

Источник: BPF `struct rst_event` → ring buffer `events_sec`.
Поля как tcp_retrans, плюс:

| Поле | Описание |
|------|----------|
| sec_direction | 0 = RST отправлен, 1 = RST получен |

---

## Агрегация

### udp_agg

Источник: BPF `udp_agg_map` → drain в `refresh_processes()` каждый refresh_interval.
Агрегация по (tgid, remote_addr, remote_port) за интервал.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | `clock_gettime(REALTIME)` | Время flush |
| event_type | | `"udp_agg"` |
| pid | BPF `udp_agg_key.tgid` | PID процесса |
| sec_af | BPF | Семейство адресов |
| sec_remote_addr | BPF `udp_agg_key.remote_addr` | Адрес назначения |
| sec_remote_port | BPF `udp_agg_key.remote_port` | Порт назначения |
| net_conn_tx_bytes | BPF `udp_agg_val.tx_bytes` | Суммарно отправлено байт |
| net_conn_rx_bytes | BPF `udp_agg_val.rx_bytes` | Суммарно получено байт |
| file_read_bytes | BPF `udp_agg_val.rx_packets` | Количество принятых пакетов |
| file_write_bytes | BPF `udp_agg_val.tx_packets` | Количество отправленных пакетов |

### icmp_agg

Источник: BPF `icmp_agg_map` → drain в `refresh_processes()`.
Агрегация по (src_addr, icmp_type, icmp_code) за интервал.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | `clock_gettime(REALTIME)` | Время flush |
| event_type | | `"icmp_agg"` |
| sec_remote_addr | BPF `icmp_agg_key.src_addr` | IP-адрес источника ICMP |
| sec_tcp_state | BPF `icmp_agg_key.icmp_type` | Тип ICMP (8=echo request, 0=echo reply) |
| sec_direction | BPF `icmp_agg_key.icmp_code` | Код ICMP |
| open_tcp_conns | BPF `icmp_agg_val.count` | Количество ICMP-пакетов за интервал |

---

## Снимки

### snapshot

Периодический снимок каждого живого tracked-процесса. Подробное описание полей:
[docs/snapshot_fields.md](snapshot_fields.md).

### conn_snapshot

Снимок каждого живого TCP-соединения tracked-процесса.
Источник: BPF `sock_map` iteration в `write_snapshot()`.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | snapshot timestamp | Время снимка |
| event_type | | `"conn_snapshot"` |
| rule, tags | userspace | По tracked_map |
| pid, uid, comm, ppid | BPF `sock_info` + `proc_map` | Идентификация |
| loginuid, sessionid, euid, tty_nr | BPF `proc_map` | Identity |
| net_local_addr, net_remote_addr | BPF `sock_info` → formatted | Адреса |
| net_local_port, net_remote_port | BPF `sock_info` | Порты |
| net_conn_tx_bytes | BPF `sock_info.tx_bytes` | Кумулятивно отправлено |
| net_conn_rx_bytes | BPF `sock_info.rx_bytes` | Кумулятивно получено |
| net_conn_tx_calls | BPF `sock_info.tx_calls` | Количество sendmsg |
| net_conn_rx_calls | BPF `sock_info.rx_calls` | Количество recvmsg |
| net_duration_ms | `(boot_ns - sock_info.start_ns) / 1e6` | Время жизни соединения |
| state | `sock_info.is_listener` | `'L'`=listener, `'E'`=established |

### file_snapshot

Снимок каждого открытого файла tracked-процесса.
Источник: BPF `fd_map` iteration в `write_snapshot()`.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | snapshot timestamp | Время снимка |
| event_type | | `"file_snapshot"` |
| rule, tags | userspace | По tracked_map |
| pid, uid, comm, ppid | BPF `fd_key.tgid` + `proc_map` | Идентификация |
| loginuid, sessionid, euid, tty_nr | BPF `proc_map` | Identity |
| file_path | BPF `fd_info.path` | Путь к открытому файлу |
| file_flags | BPF `fd_info.flags` | Флаги открытия |
| file_read_bytes | BPF `fd_info.read_bytes` | Прочитано байт (текущий момент) |
| file_write_bytes | BPF `fd_info.write_bytes` | Записано байт (текущий момент) |
| file_open_count | BPF `fd_info.open_count` | Количество открытий fd |
| file_fsync_count | BPF `fd_info.fsync_count` | Количество fsync вызовов |
| net_duration_ms | `(boot_ns - fd_info.start_ns) / 1e6` | Время жизни fd (мс) |

---

## Диск

### disk_usage

Источник: `emit_disk_usage_events()` → `/proc/mounts` + `statvfs()`.
Генерируется каждый refresh_interval для каждой уникальной файловой системы.

| Поле | Источник | Описание |
|------|----------|----------|
| timestamp_ns | snapshot timestamp | Время снимка |
| event_type | | `"disk_usage"` |
| rule | | `"NOT_MATCH"` (не привязан к процессу) |
| comm | `basename(mntent.mnt_fsname)` | Имя устройства (sda1, nvme0n1p2) |
| file_path | `mntent.mnt_dir` | Точка монтирования (`/`, `/home`) |
| sec_remote_addr | `mntent.mnt_type` | Тип ФС (ext4, xfs, btrfs) |
| disk_total_bytes | `statvfs.f_blocks × f_frsize` | Общий размер ФС |
| disk_used_bytes | `(f_blocks - f_bfree) × f_frsize` | Использовано |
| disk_avail_bytes | `statvfs.f_bavail × f_frsize` | Доступно (для non-root) |

---

## Карта ring buffer → тип события

| Ring buffer | Размер (default) | Типы событий |
|-------------|-----------------|--------------|
| `events_proc` | 96 MB | fork, exec, exit, oom_kill, signal, chdir |
| `events_file` | 96 MB | file_open, file_close, file_rename, file_unlink, file_truncate |
| `events_file_ops` | 1 MB | file_chmod, file_chown |
| `events_net` | 96 MB | net_listen, net_connect, net_accept, net_close |
| `events_sec` | 1 MB | tcp_retrans, syn_recv, rst_sent, rst_recv |
| `events_cgroup` | 128 KB | (внутренние cgroup события, не emit) |
| — (userspace) | — | snapshot, conn_snapshot, file_snapshot, disk_usage, udp_agg, icmp_agg |
