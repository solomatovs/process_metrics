# file_snapshot: снимок открытых файлов

Генерируется в `write_snapshot()` каждые `snapshot_interval` секунд.
Для каждого открытого файла tracked-процесса создаётся одна запись.

Источник данных: BPF `fd_map` (hash map, ключ = `{tgid, fd}`).
`fd_map` обновляется в реальном времени tracepoint'ами: `sys_exit_openat` (создание),
`sys_enter_close` (удаление), `sys_exit_read/write/pread/pwrite/readv/writev/sendfile`
(аккумуляция байтов), `sys_enter_fsync/fdatasync` (счётчик fsync).

Попадают только файлы, прошедшие фильтры в `handle_openat_enter`:
`tracked_map` check → `absolute_paths_only` → `path_matches_include` → `path_matches_exclude`.
Дополнительно при snapshot применяется userspace-фильтр `file_path_allowed()`.

## Идентификация

| Поле | Тип | Источник | Syscall / Hook | Как заполняется |
|------|-----|----------|----------------|-----------------|
| `timestamp` | u64 | `clock_gettime(REALTIME)` | — | Общий timestamp snapshot'а |
| `hostname` | char[] | `gethostname()` / конфиг | — | **Фиксированный**. Устанавливается при старте |
| `event_type` | char[] | userspace | — | Константа `"file_snapshot"` |
| `rule` | char[] | BPF `tracked_map.rule_id` → userspace `rules[]` | `sched_process_exec` | **Фиксированный**. Сопоставление regex при exec, наследуется при fork |
| `tags` | char[] | userspace `tags_ht` snapshot-копия | `sched_process_exec` | **Фиксированный**. Все совпавшие правила через `\|` |
| `root_pid` | u32 | BPF `tracked_map.root_pid` | `sched_process_fork` | **Фиксированный**. Корневой PID дерева отслеживания |
| `pid` | u32 | BPF `fd_key.tgid` | `sys_exit_openat` | **Фиксированный**. PID процесса-владельца fd |
| `ppid` | u32 | BPF `proc_map.ppid` | `sched_process_fork` | **Фиксированный**. PID родителя (lookup по tgid) |
| `uid` | u32 | BPF `proc_map.uid` | `sched_switch` → `task->cred->uid` | **Мгновенный**. Реальный UID на момент snapshot'а |
| `is_root` | u8 | BPF `tracked_map.is_root` | `sched_process_exec` | **Фиксированный**. 1 = корень отслеживаемого дерева |
| `comm` | char[16] | BPF `proc_map.comm` | `sched_switch` → `task->comm` | **Мгновенный**. Имя процесса на момент snapshot'а |
| `loginuid` | u32 | BPF `proc_map.loginuid` | `sched_switch` → `task->loginuid` | **Мгновенный**. Audit loginuid |
| `sessionid` | u32 | BPF `proc_map.sessionid` | `sched_switch` → `task->sessionid` | **Мгновенный**. Audit session ID |
| `euid` | u32 | BPF `proc_map.euid` | `sched_switch` → `task->cred->euid` | **Мгновенный**. Effective UID |
| `tty_nr` | u32 | BPF `proc_map.tty_nr` | `sched_switch` → `task->signal->tty` | **Мгновенный**. Управляющий терминал |
| `parent_pids` | u32[] | userspace `pidtree_ht` snapshot-копия | `sched_process_fork` / `sched_process_exit` | **Мгновенный**. Цепочка предков [ppid, ..., 1], до 16 уровней |

## Метрики файла

| Поле | Тип | Источник | Syscall / Hook | Как заполняется |
|------|-----|----------|----------------|-----------------|
| `file_path` | char[] | BPF `fd_info.path` | `sys_enter_openat` → `bpf_probe_read_user_str` | **Фиксированный**. Абсолютный путь к файлу. Устанавливается при open, не меняется |
| `file_flags` | u32 | BPF `fd_info.flags` | `sys_enter_openat` → `ctx->args[2]` | **Фиксированный**. Флаги открытия: O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0x40 и т.д. |
| `file_read_bytes` | u64 | BPF `fd_info.read_bytes` | `sys_exit_read`, `sys_exit_pread64`, `sys_exit_readv`, `sys_exit_sendfile64` → `__sync_fetch_and_add` | **Кумулятивный**. Байт прочитано через этот fd с момента open. Включает page cache (аналог io_rchar, но per-fd) |
| `file_write_bytes` | u64 | BPF `fd_info.write_bytes` | `sys_exit_write`, `sys_exit_pwrite64`, `sys_exit_writev`, `sys_exit_sendfile64` → `__sync_fetch_and_add` | **Кумулятивный**. Байт записано через этот fd с момента open. Включает page cache (аналог io_wchar, но per-fd) |
| `file_open_count` | u32 | BPF `fd_info.open_count` | `sys_exit_openat` | **Фиксированный**. Сколько раз этот fd number был переоткрыт (обычно 1) |
| `file_fsync_count` | u32 | BPF `fd_info.fsync_count` | `sys_enter_fsync`, `sys_enter_fdatasync` → `__sync_fetch_and_add` | **Кумулятивный**. Количество `fsync()` / `fdatasync()` вызовов на этот fd |
| `net_duration_ms` | u64 | `(boot_ns - fd_info.start_ns) / 1e6` | — (вычисляется в userspace) | **Мгновенный**. Время жизни fd на момент snapshot'а (мс). Переиспользует поле `net_duration_ms` |

## Жизненный цикл fd_map

```
sys_enter_openat ─────► фильтры (tracked_map, absolute_paths_only,
                         include/exclude) → openat_args_map[pid_tgid]
                              │
sys_exit_openat ──────► fd_map[{tgid, fd}] = {path, flags, read=0, write=0,
                              │                 open_count=1, fsync=0, start_ns}
                              │
sys_exit_read         ► fd_map[{tgid, fd}].read_bytes += ret
sys_exit_pread64      ►   (atomic __sync_fetch_and_add, без ring buffer)
sys_exit_readv        ►
sys_exit_sendfile64   ► fd_map[{tgid, fd}].read_bytes += in_bytes
                              │
sys_exit_write        ► fd_map[{tgid, fd}].write_bytes += ret
sys_exit_pwrite64     ►   (atomic __sync_fetch_and_add, без ring buffer)
sys_exit_writev       ►
sys_exit_sendfile64   ► fd_map[{tgid, fd}].write_bytes += out_bytes
                              │
sys_enter_fsync       ► fd_map[{tgid, fd}].fsync_count++
sys_enter_fdatasync   ►   (atomic, без ring buffer)
                              │
              ┌───────────────┤
              │               │
  write_snapshot()      sys_enter_close
  (каждые N сек)              │
      │                       ├── ring buffer ← EVENT_FILE_CLOSE
      │                       │     (финальные read/write/fsync)
      ▼                       │
  file_snapshot          fd_map[{tgid, fd}] DELETE
  (мгновенный срез
   текущего состояния)
```

## Что означает каждая строка file_snapshot

Одна строка = один открытый файловый дескриптор на момент snapshot'а.
Показывает **текущее** состояние I/O: сколько байт прочитано/записано **с момента open** до snapshot.

Долгоживущие fd (лог-файлы, БД) будут в каждом snapshot с растущими `file_read_bytes` / `file_write_bytes`.
Короткоживущие fd (Python .pyc imports) появляются и исчезают между snapshot'ами —
их данные фиксируются только в `file_close` событии.

## Отличие от file_close

| | file_snapshot | file_close |
|---|---|---|
| **Когда** | Каждые snapshot_interval | При закрытии fd |
| **Данные** | Промежуточные (текущий момент) | Финальные (полный итог) |
| **Охват** | Только открытые прямо сейчас | Все закрытые (вкл. короткоживущие) |
| **read/write bytes** | Накоплено с open до snapshot | Накоплено с open до close |

Пример запроса ClickHouse — топ файлов по записи прямо сейчас:

```sql
SELECT
    comm, pid, file_path,
    file_read_bytes, file_write_bytes, file_fsync_count,
    net_duration_ms / 1000 AS open_seconds
FROM process_metrics
WHERE event_type = 'file_snapshot'
  AND timestamp >= now() - INTERVAL 10 SECOND
ORDER BY file_write_bytes DESC
LIMIT 20
```
