# File Tracking Roadmap

## Фаза 1 — file_snapshot + pread/pwrite byte tracking

### 1.1 file_snapshot (итерация fd_map в userspace)

Аналог `conn_snapshot` для файлов. Каждый snapshot_interval итерируем `fd_map`
и генерируем событие `file_snapshot` для каждого открытого fd.

**Зачем:**
- Долгоживущие файлы (WAL PostgreSQL, логи ClickHouse) невидимы до close()
- При крахе процесса (SIGKILL/OOM) file_close не генерируется → потеря данных
- Мониторинг I/O-нагрузки в реальном времени (MB/s на файл в Grafana)

**Что нужно:**
- Добавить `start_ns` (__u64) в `struct fd_info` (process_metrics_common.h)
  — заполнять `bpf_ktime_get_boot_ns()` при openat
- В `write_snapshot()` (process_metrics.c): итерация fd_map через
  `bpf_map_get_next_key()`, lookup fd_info + tracked_map, emit file_snapshot event
- event_type = "file_snapshot"
- Поля: file_path, file_flags, file_read_bytes, file_write_bytes,
  file_open_count, file_duration_ms (boot_now - start_ns)
- Применять include/exclude фильтры при итерации (переиспользовать существующую логику)

**Стоимость:** ~0 CPU overhead — итерация userspace map, никаких новых BPF-программ.

### 1.2 pread64/pwrite64 byte tracking

Базы данных (PostgreSQL, ClickHouse, SQLite) используют позиционные
read/write вместо обычных read()/write(). Без трекинга pread64/pwrite64
теряем весь I/O от баз данных.

**Что нужно:**
- Добавить 4 BPF-программы (по аналогии с handle_read_enter/exit, handle_write_enter/exit):
  - `tracepoint/syscalls/sys_enter_pread64`
  - `tracepoint/syscalls/sys_exit_pread64`
  - `tracepoint/syscalls/sys_enter_pwrite64`
  - `tracepoint/syscalls/sys_exit_pwrite64`
- Логика идентична read/write: lookup fd_map, atomic_add bytes
- Переиспользовать `rw_args_map` для хранения fd между enter→exit

**Стоимость:** +4 tracepoints. Overhead пропорционален частоте pread/pwrite.

---

## Фаза 2 — мутирующие операции (security/аудит)

### 2.1 rename (renameat2)

Фиксация переименования/перемещения файлов.

- Tracepoint: `sys_enter_renameat2` (olddfd, oldname, newdfd, newname, flags)
- Event type: `file_rename`
- Поля: old_path, new_path, pid, comm, uid
- Применять include/exclude к old_path и new_path

### 2.2 unlink (unlinkat)

Фиксация удаления файлов и директорий.

- Tracepoint: `sys_enter_unlinkat` (dfd, pathname, flag)
- Event type: `file_unlink` (flag & AT_REMOVEDIR → `dir_rmdir`)
- Поля: path, pid, comm, uid
- Применять include/exclude к path

### 2.3 truncate

Фиксация обрезки файлов.

- Tracepoints: `sys_enter_truncate` (path, length), `sys_enter_ftruncate` (fd, length)
- Event type: `file_truncate`
- Поля: path (или fd→path через fd_map), new_size, pid, comm, uid

---

## Фаза 3 — полнота учёта байтов и метаданных

### 3.1 chmod/chown (security audit)

- `sys_enter_fchmodat` → event `file_chmod` (path, old_mode, new_mode)
- `sys_enter_fchownat` → event `file_chown` (path, new_uid, new_gid)

### 3.2 readv/writev (scatter/gather I/O)

- `sys_enter/exit_readv`, `sys_enter/exit_writev`
- Аналогично read/write, но байты из iov_len суммируются

### 3.3 sendfile (zero-copy)

- `sys_enter/exit_sendfile64` (out_fd, in_fd, count)
- Начислять read_bytes на in_fd, write_bytes на out_fd

### 3.4 fsync/fdatasync

- `sys_enter_fsync`, `sys_enter_fdatasync` (fd)
- Event type: `file_fsync`
- Индикатор durability pressure (частые fsync = bottleneck)
