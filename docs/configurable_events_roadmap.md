# Configurable Event Emission — реализовано

## Статус: ГОТОВО

Реализовано управление отправкой событий через `emit_*` флаги внутри секций коллекторов.

## Архитектура

```
┌─────────────────────────────────────────────────────────────────┐
│  Уровень 1: BPF хуки (tracepoint/kprobe)                       │
│  Обновляют BPF-карты: proc_map, tracked_map, sock_map, fd_map   │
│  → ВСЕГДА РАБОТАЮТ, если коллектор включён                      │
├─────────────────────────────────────────────────────────────────┤
│  Уровень 2: Ring buffer (BPF → userspace)                       │
│  State-логика: pidtree, tags, cgroup_cache                      │
│  → ВСЕГДА РАБОТАЕТ для fork/exec/exit/cgroup                    │
├─────────────────────────────────────────────────────────────────┤
│  Уровень 3: ef_append (CSV → HTTP → ClickHouse)                │
│  → УПРАВЛЯЕТСЯ emit_* флагами в конфиге                        │
└─────────────────────────────────────────────────────────────────┘
```

## Конфигурация

```conf
process_tracking = {
    emit_exec     = true;    # exec событие в CSV
    emit_fork     = true;    # fork событие в CSV
    emit_exit     = true;    # exit событие в CSV
    emit_oom_kill = true;    # oom_kill событие в CSV
    emit_signal   = true;    # signal событие в CSV
    emit_chdir    = true;    # chdir событие в CSV
};

file_tracking = {
    enabled = true;          # BPF хуки (CPU)
    track_bytes = true;      # read/write/pread/pwrite/readv/writev/sendfile
    emit_open     = true;    # file_open в CSV (частый, можно отключить)
    emit_close    = true;    # file_close в CSV (содержит байты)
    emit_rename   = true;    # file_rename в CSV (аудит)
    emit_unlink   = true;    # file_unlink в CSV (аудит)
    emit_truncate = true;    # file_truncate в CSV (аудит)
    emit_chmod    = true;    # file_chmod в CSV (security)
    emit_chown    = true;    # file_chown в CSV (security)
};

net_tracking = {
    enabled = true;          # BPF хуки (CPU)
    emit_listen     = true;  # net_listen в CSV
    emit_connect    = true;  # net_connect в CSV
    emit_accept     = true;  # net_accept в CSV
    emit_close      = true;  # net_close в CSV
    emit_retransmit = true;  # tcp_retrans в CSV
    emit_syn_recv   = true;  # syn_recv в CSV
    emit_rst        = true;  # rst_sent/rst_recv в CSV
    emit_udp_agg    = true;  # udp_agg в CSV
};

emit_cgroup_events = true;   # cgroup_mkdir/rmdir/rename в CSV
```

## Реализация

- 27 `cfg_emit_*` переменных в `src/process_metrics.c`
- Парсинг через существующие `config_setting_lookup_bool()` в секциях коллекторов
- Guards перед `ef_append()` — для proc events после state-логики
- По умолчанию все true — полная обратная совместимость
- Snapshot/conn_snapshot/file_snapshot не затрагиваются — генерируются всегда
