# sock_map: жизненный цикл

BPF hash map, отслеживающий все живые TCP-соединения tracked-процессов.
Определена в `process_metrics.bpf.c`.

```
Ключ:   __u64 sk_ptr          (указатель на struct sock в ядре)
Значение: struct sock_info    (tgid, uid, addr, port, bytes, calls, start_ns, is_listener)
Макс:   NET_MAX_SOCKETS = 65536
```

## Кто создаёт записи

| Когда | Hook | Что происходит |
|-------|------|----------------|
| **Исходящее TCP-соединение (IPv4)** | `kprobe/tcp_v4_connect` → сохраняет `sk_ptr` в `connect_args_map`; `kretprobe/tcp_v4_connect` → если `ret == 0` (connect начат) | Создаёт `sock_map[sk_ptr]` = `{tgid, uid, local/remote addr+port, start_ns}`. Читает адреса из `struct sock` через `BPF_CORE_READ`. Эмитит `EVENT_NET_CONNECT` |
| **Исходящее TCP-соединение (IPv6)** | `kprobe/tcp_v6_connect` → `kretprobe/tcp_v6_connect` | Аналогично IPv4, читает 16-байтные IPv6-адреса |
| **Входящее TCP-соединение** | `kretprobe/inet_csk_accept` | Создаёт `sock_map[sk_ptr]` при успешном `accept()`. Эмитит `EVENT_NET_ACCEPT` |
| **Слушающий сокет** | `kprobe/inet_csk_listen_start` | Создаёт `sock_map[sk_ptr]` с `is_listener = 1`. Эмитит `EVENT_NET_LISTEN` |
| **Initial seed (при старте)** | `iter/tcp` (`seed_sock_map_iter`) | Userspace сканирует `/proc/PID/fd` всех tracked-процессов, собирает socket inodes в `seed_inode_map`. BPF iter проходит все TCP-сокеты ядра, для найденных в `seed_inode_map` создаёт `sock_map` записи |

Все записи создаются с `BPF_NOEXIST` — дубликаты не перезаписывают.

## Кто обновляет записи (in-place)

| Когда | Hook | Что обновляется |
|-------|------|-----------------|
| **Отправка данных (TCP)** | `kretprobe/tcp_sendmsg` | `sock_map[sk_ptr].tx_bytes += ret`, `tx_calls++` (atomic `__sync_fetch_and_add`) |
| **Получение данных (TCP)** | `kretprobe/tcp_recvmsg` | `sock_map[sk_ptr].rx_bytes += ret`, `rx_calls++` (atomic) |

Обновление происходит **только если `kprobe/tcp_sendmsg`** сохранил `sk_ptr` в `sendmsg_args_map`
(per-thread temporary storage между kprobe enter и kretprobe exit).

Одновременно с sock_map обновляется **proc_map**: `proc_map[tgid].net_tx_bytes += ret`.
Это два независимых уровня агрегации: per-connection (sock_map) и per-process (proc_map).

## Кто удаляет записи

| Когда | Hook | Что происходит |
|-------|------|----------------|
| **Закрытие соединения** | `kprobe/tcp_close` (фаза 1) | Считывает финальные метрики из `sock_map[sk_ptr]`. Если `is_listener` — удаляет сразу и выходит. Иначе: эмитит `EVENT_NET_CLOSE` в ring buffer, декрементирует `open_conn_map[tgid]`, сохраняет `sk_ptr` в per-CPU `tcp_close_sk` для kretprobe |
| **Закрытие соединения** | `kretprobe/tcp_close` (фаза 2) | Удаляет `sock_map[sk_ptr]`. Отложено от kprobe чтобы `tcp_send_active_reset` (SO_LINGER=0, RST) мог найти сокет между kprobe и kretprobe |

### Почему close в 2 фазы (kprobe + kretprobe)?

```
tcp_close(sk):
  kprobe ──► emit NET_CLOSE + декремент open_conn
  │          (sock_map ещё жива — sk_ptr валиден)
  │
  │  tcp_send_active_reset(sk) ← вызывается ядром внутри tcp_close
  │          (BPF kprobe/tcp_send_active_reset читает sock_map[sk_ptr]
  │           для эмиссии RST события — нужна живая запись)
  │
  kretprobe ──► sock_map[sk_ptr] DELETE
               (теперь безопасно удалять)
```

## Кто читает sock_map

| Когда | Где | Зачем |
|-------|-----|-------|
| **Каждый snapshot** | userspace `write_snapshot()` → `bpf_map_get_next_key` iteration | Генерация `conn_snapshot` событий для каждого живого соединения |
| **TCP retransmit** | BPF `handle_tcp_retransmit` | Lookup для определения tgid/tracked при ретрансмите (не всегда — retransmit может прийти из softirq без контекста процесса) |
| **TCP send/recv** | BPF `ret_tcp_sendmsg` / `ret_tcp_recvmsg` | Аккумуляция per-connection bytes |
| **TCP RST** | BPF `kp_tcp_send_active_reset` | Lookup для эмиссии RST-события с адресами |

## Связь с open_conn_map

`open_conn_map` — отдельная BPF hash map `{tgid → __u64 count}`.
Инкрементируется при connect/accept/seed, декрементируется при close.
Читается в `write_snapshot()` → поле `open_tcp_conns` в snapshot.

| Операция | open_conn_map |
|----------|---------------|
| connect/accept/seed (не listener) | `count++` |
| tcp_close (не listener) | `count--` |
| Listener close | не меняется |

## Поля struct sock_info

| Поле | Тип | Когда устанавливается | Как обновляется |
|------|-----|-----------------------|-----------------|
| `tgid` | u32 | При создании (connect/accept/seed) | **Фиксированный** |
| `uid` | u32 | При создании | **Фиксированный** |
| `af` | u8 | При создании (`sk->__sk_common.skc_family`) | **Фиксированный**. AF_INET=2, AF_INET6=10 |
| `local_addr` | u8[16] | При создании (`BPF_CORE_READ`) | **Фиксированный** |
| `remote_addr` | u8[16] | При создании | **Фиксированный** |
| `local_port` | u16 | При создании | **Фиксированный** |
| `remote_port` | u16 | При создании | **Фиксированный** |
| `tx_bytes` | u64 | 0 при создании | **Кумулятивный**. `__sync_fetch_and_add` в `ret_tcp_sendmsg` |
| `rx_bytes` | u64 | 0 при создании | **Кумулятивный**. `__sync_fetch_and_add` в `ret_tcp_recvmsg` |
| `tx_calls` | u64 | 0 при создании | **Кумулятивный**. `__sync_fetch_and_add` в `ret_tcp_sendmsg` |
| `rx_calls` | u64 | 0 при создании | **Кумулятивный**. `__sync_fetch_and_add` в `ret_tcp_recvmsg` |
| `start_ns` | u64 | `bpf_ktime_get_boot_ns()` при создании | **Фиксированный**. Используется для вычисления `net_duration_ms` |
| `is_listener` | u8 | При создании: 1 для `listen_start`, 0 для connect/accept | **Фиксированный** |

## Визуализация полного цикла

```
                         СОЗДАНИЕ
                         ========

  connect() ──► kp_tcp_v4_connect ──► sendmsg_args_map[pid_tgid] = sk_ptr
                krp_tcp_v4_connect ──► sock_map[sk_ptr] = {tgid, addr, port}
                                      open_conn_map[tgid]++
                                      ring buffer ← NET_CONNECT

  accept()  ──► krp_inet_csk_accept ► sock_map[sk_ptr] = {...}
                                      open_conn_map[tgid]++
                                      ring buffer ← NET_ACCEPT

  listen()  ──► kp_inet_csk_listen  ► sock_map[sk_ptr] = {..., is_listener=1}
                                      ring buffer ← NET_LISTEN

  startup   ──► seed_sock_map_iter  ► sock_map[sk_ptr] = {...}
                                      open_conn_map[tgid]++ (если не listener)

                         ОБНОВЛЕНИЕ (hot path)
                         ==========

  sendmsg() ──► kp_tcp_sendmsg ────► sendmsg_args_map[pid_tgid] = sk_ptr
                ret_tcp_sendmsg ───► sock_map[sk_ptr].tx_bytes += ret
                                     sock_map[sk_ptr].tx_calls++
                                     proc_map[tgid].net_tx_bytes += ret

  recvmsg() ──► kp_tcp_recvmsg ────► sendmsg_args_map[pid_tgid] = sk_ptr
                ret_tcp_recvmsg ───► sock_map[sk_ptr].rx_bytes += ret
                                     sock_map[sk_ptr].rx_calls++
                                     proc_map[tgid].net_rx_bytes += ret

                         ЧТЕНИЕ (snapshot)
                         ======

  write_snapshot() ──► bpf_map_get_next_key(sock_map) iteration
                       │  для каждого sock_info:
                       │    tracked_map lookup → rule, tags
                       │    proc_map lookup → comm, ppid, identity
                       │    format addr/port → CSV
                       └─► ef_append(conn_snapshot)

                         УДАЛЕНИЕ
                         ========

  close()   ──► kp_tcp_close ──────► ring buffer ← NET_CLOSE (финальные метрики)
                                     open_conn_map[tgid]--
                                     tcp_close_sk = sk_ptr
                kretp_tcp_close ───► sock_map[sk_ptr] DELETE
```
