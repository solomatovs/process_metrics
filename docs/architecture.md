# process_metrics — архитектура

## Обзор

Событийный eBPF-коллектор метрик процессов. Ядро генерирует события через BPF-программы,
userspace обрабатывает их в callback и периодически снимает snapshot всех отслеживаемых процессов.

## Event-driven flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        KERNEL (BPF)                             │
│                                                                 │
│  ── lifecycle ──────────────────────────────────────────────    │
│  raw_tp/sched_process_fork          → EVENT_FORK                │
│  tp/sched/sched_process_exec        → EVENT_EXEC                │
│  tp/sched/sched_process_exit        → EVENT_EXIT                │
│                                                                 │
│  ── file tracking ──────────────────────────────────────────    │
│  tp/syscalls/sys_enter_openat       → fd_map (если tracked)     │
│  tp/syscalls/sys_exit_openat        → fd_map update             │
│  tp/syscalls/sys_enter_read         → fd_info.read_bytes++      │
│  tp/syscalls/sys_exit_read          → fd_info.read_bytes += ret │
│  tp/syscalls/sys_enter_write        → fd_info.write_bytes++     │
│  tp/syscalls/sys_exit_write         → fd_info.write_bytes += ret│
│  tp/syscalls/sys_enter_close        → EVENT_FILE_CLOSE          │
│                                                                 │
│  ── net tracking ───────────────────────────────────────────    │
│  kprobe/tcp_v4_connect              → sock_map                  │
│  kretprobe/tcp_v4_connect           → sock_map update           │
│  kprobe/tcp_v6_connect              → sock_map                  │
│  kretprobe/tcp_v6_connect           → sock_map update           │
│  kretprobe/inet_csk_accept          → sock_map                  │
│  kprobe/tcp_sendmsg                 → sock_info.tx_bytes++      │
│  kprobe/tcp_recvmsg                 → sock_info.rx_bytes++      │
│  kprobe/tcp_close                   → EVENT_NET_CLOSE           │
│                                                                 │
│  ── security probes ────────────────────────────────────────    │
│  tp/tcp/tcp_retransmit_skb          → EVENT_TCP_RETRANSMIT      │
│  kprobe/tcp_conn_request            → EVENT_SYN_RECV            │
│  tp/tcp/tcp_send_reset              → EVENT_RST                 │
│  tp/tcp/tcp_receive_reset           → EVENT_RST                 │
│                                                                 │
│  ── signal tracking ────────────────────────────────────────    │
│  tp/signal/signal_deliver           → EVENT_SIGNAL              │
│                                                                 │
│  Все события → bpf_ringbuf_submit() → ring buffer (shared mmap)│
└──────────────────────────────┬──────────────────────────────────┘
                               │ epoll wakeup
                               ▼
                       ring_buffer__poll()
                               │
                               ▼
                       handle_event()
```

## BPF-фильтрация (что попадает в ring buffer)

| Источник | Фильтр | Что попадает |
|---|---|---|
| fork | `tracked_map` lookup родителя | Только потомки отслеживаемых процессов. BPF сразу наследует `track_info` в `tracked_map`. |
| exec | Без фильтра | Все exec-события. Userspace решает по regex. |
| exit | `tracked_map` lookup | Только отслеживаемые. |
| openat | `tracked_map` lookup + include/exclude path | Только tracked PID + файлы по белому списку. |
| close | `fd_map` lookup | Только fd, открытые через отфильтрованный openat. |
| read/write | `fd_map` lookup | Аналогично close. |
| tcp_connect | Без фильтра | Все TCP-соединения. |
| tcp_close | `sock_map` lookup | Только соединения из sock_map. |

## Инициализация — `main()`

```
main()
  ├─ parse_rules_from_config()     чтение rules из libconfig (name + regex + ignore)
  ├─ process_metrics_bpf__open()   открытие BPF-объекта (skeleton)
  ├─ process_metrics_bpf__load()   загрузка BPF-программ в ядро
  ├─ process_metrics_bpf__attach() подключение ко всем tracepoints/kprobes
  ├─ ring_buffer__new(events_fd, handle_event)
  │                                создание ring buffer с callback
  ├─ initial_scan()                обход /proc — заполнение tracked_map
  │    └─ для каждого PID:
  │         read_proc_cmdline()    open+read+close /proc/PID/cmdline
  │         match_rules_all()      regexec × N правил
  │         track_pid_from_proc()  bpf_map_update_elem(tracked_map)
  ├─ refresh_boot_to_wall()        вычисление offset boot_ns → wall_ns
  ├─ http_server_start()           запуск HTTP-потока (отдельный thread)
  └─ → main loop
```

## Main loop — событийное ожидание

```
while (g_running) {
    ┌─────────────────────────────────────────────────────┐
    │  ring_buffer__poll(rb, 1000)                        │
    │    ├─ epoll_wait(epoll_fd, ..., 1000ms)             │
    │    │   ПРОЦЕСС СПИТ. CPU = 0.                       │
    │    │   Ядро будит при bpf_ringbuf_submit().          │
    │    │                                                 │
    │    └─ ringbuf_process_ring():                        │
    │         while (cons_pos < prod_pos):                 │
    │             handle_event(sample)  ← для каждого      │
    │             advance cons_pos                         │
    │         re-check prod_pos                            │
    │         (выходит когда ring пуст)                    │
    └─────────────────────────────────────────────────────┘

    if (g_reload)  → SIGHUP: перечитать config, пересканить /proc

    if (time() - last_snapshot >= interval)
        ├─ build_cgroup_cache()      обход /sys/fs/cgroup
        ├─ refresh_boot_to_wall()    пересчёт offset boot_ns → wall_ns
        └─ write_snapshot()          снимок всех tracked PID
}
```

Единственная точка ожидания — `epoll_wait` внутри `ring_buffer__poll`.
Процесс не потребляет CPU пока нет событий.

## `handle_event()` — callback для каждого BPF-события

```
handle_event(ctx, data, size)
  │
  ├─ EVENT_FILE_CLOSE               ~115/сек, самый частый
  │    ├─ bpf_map_lookup_elem()     1 syscall — есть ли PID в tracked_map?
  │    │   не найден → return 0     (процесс умер между open и close)
  │    ├─ rules[ti.rule_id].name    O(1) — имя правила из track_info
  │    ├─ tags_lookup(tgid)         O(1) — hash table lookup
  │    ├─ resolve_cgroup_fast()     O(N) — линейный поиск, ~50 записей, без rebuild
  │    ├─ заполнение metric_event   4× snprintf (CPU, без syscall)
  │    │   timestamp = BPF boot_ns + g_boot_to_wall_ns
  │    └─ ef_append()               1 write() syscall
  │
  ├─ EVENT_NET_CLOSE                ~9/сек
  │    ├─ bpf_map_lookup_elem()     1 syscall
  │    │   не найден → return 0     (BPF connect/accept не фильтрует по tracked)
  │    └─ ... аналогично file_close + форматирование IP ...
  │
  ├─ EVENT_EXEC                     ~4/сек
  │    ├─ read_proc_cmdline(pid)    open+read+close /proc/PID/cmdline
  │    ├─ match_rules_all()         regexec × N правил (тяжёлый, но редкий)
  │    ├─ bpf_map_update_elem()     обновление tracked_map
  │    ├─ tags_store()              запись тегов в hash table
  │    └─ ef_append()
  │
  ├─ EVENT_FORK                     ~4/сек
  │    ├─ (BPF уже наследовал tracked_map от родителя)
  │    ├─ bpf_map_lookup_elem()     чтение proc_info потомка
  │    ├─ tags_inherit()            наследование тегов от родителя
  │    └─ ef_append()
  │
  ├─ EVENT_EXIT                     ~4/сек
  │    ├─ bpf_map_lookup + delete   удаление из tracked_map
  │    ├─ сохранение в exited_ring  кольцевой буфер для snapshot
  │    └─ ef_append()
  │
  ├─ EVENT_SIGNAL                   редкий
  ├─ EVENT_TCP_RETRANSMIT           редкий
  ├─ EVENT_SYN_RECV                 редкий
  ├─ EVENT_RST                      редкий
  │
  └─ return 0                       ВСЕГДА 0 — не прерывает ring processing
```

Стоимость на одно событие (FILE_CLOSE / NET_CLOSE):
- 1× `bpf_map_lookup_elem` — syscall bpf()
- 1× `write()` в ef_append — syscall
- Остальное — чтение памяти и snprintf (без syscall)

## `ef_append()` — запись события в буферный файл

```
ef_append(event, hostname)
  ├─ pthread_mutex_lock()
  ├─ if g_cur_size + sizeof(rec) > max_size
  │    └─ ftruncate() + reset       защита от переполнения диска
  ├─ write(g_fd, &rec, sizeof)      1 syscall, O_APPEND
  ├─ g_cur_size += n                кэшированный размер (без lseek)
  └─ pthread_mutex_unlock()
```

Файл `events.dat` — бинарный, append-only. Размер записи фиксирован (`sizeof(ef_record)`).
Размер файла отслеживается в памяти (`g_cur_size`), lseek не вызывается.

## `write_snapshot()` — периодический снимок

```
write_snapshot()
  ├─ для каждого PID в tracked_map:
  │    ├─ read /proc/PID/stat       CPU, RSS, state, threads
  │    ├─ read /proc/PID/cgroup     (если refresh_proc включён)
  │    ├─ read /proc/PID/cmdline    (если refresh_proc включён)
  │    ├─ emit Prometheus metrics   → .prom файл
  │    └─ ef_append(snapshot event) → events.dat
  ├─ для каждого exited_proc:
  │    └─ ef_append(exit event)
  ├─ emit_disk_usage_events()
  │    └─ для каждого mount: statvfs() → ef_append(disk_usage)
  └─ emit cgroup metrics
```

Snapshot блокирует main loop на время выполнения (обход /proc).
Это нормально — snapshot выполняется раз в `snapshot_interval` секунд.

## HTTP-сервер (отдельный thread)

```
GET /metrics?format=csv&clear=1     ClickHouse забирает данные
  ├─ ef_swap()                      rename events.dat → .tmp, open new
  │    └─ read .pending + .tmp      объединение с предыдущей неудачной доставкой
  ├─ send CSV по HTTP
  └─ ef_commit()                    удаление .pending при успехе

GET /metrics?format=prom            Prometheus scrape
  └─ read .prom файл               последний snapshot
```

Двухфазная доставка: swap → send → commit.
При сбое доставки данные сохраняются в `.pending` и повторяются при следующем запросе.

## BPF maps

| Map | Тип | Ключ → Значение | Назначение |
|---|---|---|---|
| `tracked_map` | hash | tgid → track_info | Какие процессы отслеживаются (rule_id, root_pid) |
| `proc_map` | hash | tgid → proc_info | Метаданные процесса (ppid, uid, cmdline, cpu_ns) |
| `fd_map` | hash | {tgid, fd} → fd_info | Открытые файлы (path, read/write bytes) |
| `sock_map` | hash | sock_ptr → sock_info | Активные TCP-соединения |
| `events` | ringbuf | — | Кольцевой буфер событий kernel → userspace |
| `openat_args_map` | hash | pid_tgid → openat_args | Временное хранилище между enter/exit openat |
| `connect_args_map` | hash | pid_tgid → connect_args | Временное хранилище между kprobe/kretprobe connect |
| `open_conn_map` | hash | tgid → count | Счётчик открытых TCP-соединений на процесс |
| `scratch_pi` | per-cpu array | 0 → proc_info | Scratch buffer для fork (обход лимита стека BPF) |
