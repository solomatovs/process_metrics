# conn_snapshot: снимок живых TCP-соединений

Генерируется в `write_snapshot()` каждые `snapshot_interval` секунд.
Для каждого живого TCP-соединения tracked-процесса создаётся одна запись.

Источник данных: BPF `sock_map` (hash map, ключ = указатель на `struct sock`).
`sock_map` обновляется в реальном времени kprobe'ами: `tcp_v4_connect`, `tcp_v6_connect`,
`inet_csk_accept`, `inet_csk_listen_start`, `tcp_close`, `tcp_sendmsg`, `tcp_recvmsg`.

## Идентификация

| Поле | Тип | Источник | Syscall / Hook | Как заполняется |
|------|-----|----------|----------------|-----------------|
| `timestamp` | u64 | `clock_gettime(REALTIME)` | — | Общий timestamp snapshot'а |
| `hostname` | char[] | `gethostname()` / конфиг | — | **Фиксированный**. Устанавливается при старте |
| `event_type` | char[] | userspace | — | Константа `"conn_snapshot"` |
| `rule` | char[] | BPF `tracked_map.rule_id` → userspace `rules[]` | `sched_process_exec` | **Фиксированный**. Сопоставление regex при exec, наследуется при fork |
| `tags` | char[] | userspace `tags_ht` snapshot-копия | `sched_process_exec` | **Фиксированный**. Все совпавшие правила через `\|` |
| `root_pid` | u32 | BPF `tracked_map.root_pid` | `sched_process_fork` | **Фиксированный**. Корневой PID дерева отслеживания |
| `pid` | u32 | BPF `sock_info.tgid` | `kprobe/tcp_v4_connect`, `kretprobe/inet_csk_accept` | **Фиксированный**. PID процесса-владельца сокета |
| `ppid` | u32 | BPF `proc_map.ppid` | `sched_process_fork` | **Фиксированный**. PID родителя (lookup по tgid) |
| `uid` | u32 | BPF `sock_info.uid` | `kprobe/tcp_v4_connect`, `kretprobe/inet_csk_accept` | **Фиксированный**. Реальный UID на момент создания сокета |
| `is_root` | u8 | BPF `tracked_map.is_root` | `sched_process_exec` | **Фиксированный**. 1 = корень отслеживаемого дерева |
| `comm` | char[16] | BPF `proc_map.comm` | `sched_switch` → `task->comm` | **Мгновенный**. Имя процесса на момент snapshot'а |
| `loginuid` | u32 | BPF `proc_map.loginuid` | `sched_switch` → `task->loginuid` | **Мгновенный**. Audit loginuid |
| `sessionid` | u32 | BPF `proc_map.sessionid` | `sched_switch` → `task->sessionid` | **Мгновенный**. Audit session ID |
| `euid` | u32 | BPF `proc_map.euid` | `sched_switch` → `task->cred->euid` | **Мгновенный**. Effective UID |
| `tty_nr` | u32 | BPF `proc_map.tty_nr` | `sched_switch` → `task->signal->tty` | **Мгновенный**. Управляющий терминал |

## Адреса и порты

| Поле | Тип | Источник | Syscall / Hook | Как заполняется |
|------|-----|----------|----------------|-----------------|
| `net_local_addr` | char[] | BPF `sock_info.local_addr` → `fmt_ipv4()` / `inet_ntop(AF_INET6)` | `kprobe/tcp_v4_connect`, `kretprobe/inet_csk_accept` | **Фиксированный**. Локальный IP-адрес, устанавливается при создании сокета |
| `net_remote_addr` | char[] | BPF `sock_info.remote_addr` → аналогично | аналогично | **Фиксированный**. Удалённый IP-адрес |
| `net_local_port` | u16 | BPF `sock_info.local_port` | аналогично | **Фиксированный**. Локальный порт (host byte order) |
| `net_remote_port` | u16 | BPF `sock_info.remote_port` | аналогично | **Фиксированный**. Удалённый порт (host byte order) |

## Метрики соединения

| Поле | Тип | Источник | Syscall / Hook | Как заполняется |
|------|-----|----------|----------------|-----------------|
| `net_conn_tx_bytes` | u64 | BPF `sock_info.tx_bytes` | `kretprobe/tcp_sendmsg` → `__sync_fetch_and_add` | **Кумулятивный**. Байт отправлено через это соединение с момента создания |
| `net_conn_rx_bytes` | u64 | BPF `sock_info.rx_bytes` | `kretprobe/tcp_recvmsg` → `__sync_fetch_and_add` | **Кумулятивный**. Байт получено через это соединение с момента создания |
| `net_conn_tx_calls` | u64 | BPF `sock_info.tx_calls` | `kretprobe/tcp_sendmsg` → `__sync_fetch_and_add` | **Кумулятивный**. Количество вызовов `sendmsg()` / `send()` / `write()` на этом сокете |
| `net_conn_rx_calls` | u64 | BPF `sock_info.rx_calls` | `kretprobe/tcp_recvmsg` → `__sync_fetch_and_add` | **Кумулятивный**. Количество вызовов `recvmsg()` / `recv()` / `read()` на этом сокете |
| `net_duration_ms` | u64 | `(boot_ns - sock_info.start_ns) / 1e6` | — (вычисляется в userspace) | **Мгновенный**. Время жизни соединения на момент snapshot'а (мс) |
| `state` | u8 | BPF `sock_info.is_listener` | `kprobe/inet_csk_listen_start` | **Фиксированный**. `'L'` = listening socket, `'E'` = established connection |

## Жизненный цикл sock_map

```
kprobe/tcp_v4_connect  ──► sock_map[sock_ptr] = {tgid, addr, port, ...}
kprobe/tcp_v6_connect  ──►   (запись создаётся при connect)
kretprobe/inet_csk_accept ► sock_map[sock_ptr] = {...}
                              (запись создаётся при accept)
kprobe/inet_csk_listen_start ► sock_map[sock_ptr] = {..., is_listener=1}
                                 (запись для listening socket)

kretprobe/tcp_sendmsg  ──► sock_map[sock_ptr].tx_bytes += ret
                           sock_map[sock_ptr].tx_calls++
kretprobe/tcp_recvmsg  ──► sock_map[sock_ptr].rx_bytes += ret
                           sock_map[sock_ptr].rx_calls++

kprobe/tcp_close       ──► ring buffer ← EVENT_NET_CLOSE (финальные метрики)
                           sock_map[sock_ptr] DELETE
```

## Что означает каждая строка conn_snapshot

Одна строка = один живой TCP-сокет на момент snapshot'а.
Для сервера с 40 active connections — 40 строк conn_snapshot за один snapshot_interval.

Пример запроса ClickHouse — соединения с наибольшим трафиком:

```sql
SELECT
    comm, pid,
    net_local_port, net_remote_addr, net_remote_port,
    net_conn_tx_bytes, net_conn_rx_bytes,
    net_duration_ms / 1000 AS duration_sec,
    state
FROM process_metrics
WHERE event_type = 'conn_snapshot'
  AND timestamp >= now() - INTERVAL 5 MINUTE
ORDER BY net_conn_tx_bytes + net_conn_rx_bytes DESC
LIMIT 20
```
