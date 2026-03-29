# Configurable Event Emission — план реализации

## Мотивация

Программа генерирует ~30 типов событий. На высоконагруженных серверах значительная
часть трафика в ClickHouse — streaming-события (file_close, net_close, signal и т.д.),
которые не влияют на snapshot. Нужна возможность выборочно отключать отправку событий
в выходной CSV-буфер без нарушения корректности snapshot/conn_snapshot/file_snapshot.

## Архитектурный принцип

Разделяем три уровня:

```
┌─────────────────────────────────────────────────────────────────┐
│  Уровень 1: BPF-хук (tracepoint/kprobe)                       │
│  Обновляет BPF-карты: proc_map, tracked_map, sock_map, fd_map  │
│  → ВСЕГДА РАБОТАЕТ, если коллектор включён (net_tracking и пр.)│
├─────────────────────────────────────────────────────────────────┤
│  Уровень 2: Эмиссия в ring buffer (BPF → userspace)            │
│  Передаёт событие в userspace для обновления состояния:         │
│  pidtree, tags, cgroup_cache, try_track_pid                    │
│  → ВСЕГДА РАБОТАЕТ для fork/exec/exit/cgroup                   │
│  → Управляется sec_config для security-событий                 │
├─────────────────────────────────────────────────────────────────┤
│  Уровень 3: Отправка в ef_buf (CSV → HTTP → ClickHouse)        │
│  Вызов ef_append() — единственное место фильтрации             │
│  → УПРАВЛЯЕТСЯ секцией events {} в конфиге                     │
└─────────────────────────────────────────────────────────────────┘
```

Секция `events {}` управляет **только уровнем 3** — ef_append(). BPF-хуки и ring buffer
продолжают работать. Snapshot читает BPF-карты напрямую через bpf_map_lookup_batch()
и не зависит от ef_buf.

## Классификация событий по влиянию на snapshot

### Критичные (хук + ringbuf обязательны, фильтруется только ef_append)

| Событие | Уровень 1 (BPF) | Уровень 2 (ringbuf→userspace) | Уровень 3 (ef_append) |
|---------|-----------------|-------------------------------|----------------------|
| **fork** | Создаёт tracked_map + proc_map для ребёнка | pidtree_store_ts, tags_inherit_ts, pwd_inherit_ts | `cfg_emit_fork` |
| **exec** | Обновляет proc_map (comm, cmdline, identity) | try_track_pid для новых процессов, pidtree_store_ts | `cfg_emit_exec` |
| **exit** | Ставит PROC_STATUS_EXITED, финальные метрики | tags_remove_ts, определение rule_id | `cfg_emit_exit` |

### Важные для userspace-кэшей (ringbuf нужен, фильтруется ef_append)

| Событие | Уровень 2 (что делает userspace) | Уровень 3 |
|---------|----------------------------------|-----------|
| **oom_kill** | Определяет rule по pid/parent | `cfg_emit_oom_kill` |
| **chdir** | Обновляет pwd-кэш (readlink /proc/pid/cwd) | `cfg_emit_chdir` |
| **cgroup_mkdir** | cgroup_cache_add(id, path) | `cfg_emit_cgroup` |
| **cgroup_rmdir** | cgroup_cache_remove(id) | `cfg_emit_cgroup` |
| **cgroup_rename** | cgroup_cache_add(id, new_path) | `cfg_emit_cgroup` |
| **cgroup_attach_task** | Лог (state в proc_map обновляется BPF) | `cfg_emit_cgroup` |

### Чисто streaming (можно фильтровать и в BPF, и в ef_append)

| Событие | ringbuf → userspace | Уровень 3 |
|---------|---------------------|-----------|
| **file_close** | ef_append напрямую | `cfg_emit_file_close` |
| **file_rename** | ef_append напрямую | `cfg_emit_file_rename` |
| **file_unlink** | ef_append напрямую | `cfg_emit_file_unlink` |
| **file_truncate** | ef_append напрямую | `cfg_emit_file_truncate` |
| **file_chmod** | ef_append напрямую | `cfg_emit_file_chmod` |
| **file_chown** | ef_append напрямую | `cfg_emit_file_chown` |
| **net_listen** | ef_append напрямую | `cfg_emit_net_listen` |
| **net_connect** | ef_append напрямую | `cfg_emit_net_connect` |
| **net_accept** | ef_append напрямую | `cfg_emit_net_accept` |
| **net_close** | ef_append напрямую | `cfg_emit_net_close` |
| **tcp_retransmit** | ef_append напрямую | `cfg_emit_tcp_retransmit` |
| **syn_recv** | ef_append напрямую | `cfg_emit_syn_recv` |
| **rst** | ef_append напрямую | `cfg_emit_rst` |
| **signal** | ef_append напрямую | `cfg_emit_signal` |

---

## Шаг 1: Статические переменные конфигурации

**Файл:** `src/process_metrics.c`, после строки ~119 (`cfg_tcp_open_conns`).

```c
/* ── Управление отправкой событий в ef_buf (CSV → ClickHouse) ──── */
/* По умолчанию все события включены. events {} в конфиге переопределяет. */

/* Жизненный цикл процессов */
static int cfg_emit_exec           = 1;
static int cfg_emit_fork           = 1;
static int cfg_emit_exit           = 1;
static int cfg_emit_oom_kill       = 1;

/* Файловые события */
static int cfg_emit_file_close     = 1;
static int cfg_emit_file_rename    = 1;
static int cfg_emit_file_unlink    = 1;
static int cfg_emit_file_truncate  = 1;
static int cfg_emit_file_chmod     = 1;
static int cfg_emit_file_chown     = 1;

/* Сетевые события */
static int cfg_emit_net_listen     = 1;
static int cfg_emit_net_connect    = 1;
static int cfg_emit_net_accept     = 1;
static int cfg_emit_net_close      = 1;

/* Security-события */
static int cfg_emit_tcp_retransmit = 1;
static int cfg_emit_syn_recv       = 1;
static int cfg_emit_rst            = 1;
static int cfg_emit_signal         = 1;

/* Прочие */
static int cfg_emit_chdir          = 1;
static int cfg_emit_cgroup         = 1;
```

---

## Шаг 2: Парсинг секции events {} из конфига

**Файл:** `src/process_metrics.c`, в функции парсинга конфига (после парсинга
`icmp_tracking` / `disk_tracking`, ~строка 1785).

```c
/* ── Секция events: управление отправкой событий в CSV ──────── */
config_setting_t *ev = config_lookup(&cfg, "events");
if (ev) {
    /* Жизненный цикл процессов */
    config_setting_lookup_bool(ev, "exec",           &cfg_emit_exec);
    config_setting_lookup_bool(ev, "fork",           &cfg_emit_fork);
    config_setting_lookup_bool(ev, "exit",           &cfg_emit_exit);
    config_setting_lookup_bool(ev, "oom_kill",       &cfg_emit_oom_kill);

    /* Файловые события */
    config_setting_lookup_bool(ev, "file_close",     &cfg_emit_file_close);
    config_setting_lookup_bool(ev, "file_rename",    &cfg_emit_file_rename);
    config_setting_lookup_bool(ev, "file_unlink",    &cfg_emit_file_unlink);
    config_setting_lookup_bool(ev, "file_truncate",  &cfg_emit_file_truncate);
    config_setting_lookup_bool(ev, "file_chmod",     &cfg_emit_file_chmod);
    config_setting_lookup_bool(ev, "file_chown",     &cfg_emit_file_chown);

    /* Сетевые события */
    config_setting_lookup_bool(ev, "net_listen",     &cfg_emit_net_listen);
    config_setting_lookup_bool(ev, "net_connect",    &cfg_emit_net_connect);
    config_setting_lookup_bool(ev, "net_accept",     &cfg_emit_net_accept);
    config_setting_lookup_bool(ev, "net_close",      &cfg_emit_net_close);

    /* Security-события */
    config_setting_lookup_bool(ev, "tcp_retransmit", &cfg_emit_tcp_retransmit);
    config_setting_lookup_bool(ev, "syn_recv",       &cfg_emit_syn_recv);
    config_setting_lookup_bool(ev, "rst",            &cfg_emit_rst);
    config_setting_lookup_bool(ev, "signal",         &cfg_emit_signal);

    /* Прочие */
    config_setting_lookup_bool(ev, "chdir",          &cfg_emit_chdir);
    config_setting_lookup_bool(ev, "cgroup",         &cfg_emit_cgroup);
}
```

---

## Шаг 3: Фильтрация в handle_event (events_proc ring buffer callback)

**Файл:** `src/process_metrics.c`, функция `handle_event` (~строка 3125+).

### 3.1 EVENT_EXEC (~строка 3125)

Userspace-логика (pidtree, try_track_pid, tags) выполняется **всегда**.
Фильтруется только блок ef_append:

```c
case EVENT_EXEC: {
    pidtree_store_ts(e->tgid, e->ppid);          // ВСЕГДА

    struct track_info ti;
    if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0)
        return 0;                                  // уже отслеживается

    /* ... match_rules_all, bpf_map_update_elem ... */  // ВСЕГДА

    if (first >= 0 && !rules[first].ignore) {
        /* tracking logic — ВСЕГДА */
        bpf_map_update_elem(tracked_map_fd, &e->tgid, &new_ti, BPF_ANY);
        tags_store_ts(e->tgid, tags_buf);
        pwd_read_and_store(e->tgid);
        bpf_map_update_elem(proc_map_fd, &e->tgid, &pi, BPF_ANY);

        /* ▼ ФИЛЬТРАЦИЯ: только ef_append оборачивается проверкой */
        if (cfg_emit_exec && g_http_cfg.enabled) {
            /* ... resolve_cgroup_fast_ts, event_from_bpf, ef_append ... */
        }
    }
    return 0;
}
```

### 3.2 EVENT_FORK (~строка 3192)

```c
case EVENT_FORK: {
    pidtree_store_ts(e->tgid, e->ppid);          // ВСЕГДА
    tags_inherit_ts(e->tgid, e->ppid);            // ВСЕГДА
    pwd_inherit_ts(e->tgid, e->ppid);             // ВСЕГДА

    /* ... parent_ti lookup ... */                 // ВСЕГДА (для tags)

    /* ▼ ФИЛЬТРАЦИЯ */
    if (cfg_emit_fork && g_http_cfg.enabled) {
        /* ... resolve_cgroup_fast_ts, event_from_bpf, ef_append ... */
    }
    return 0;
}
```

### 3.3 EVENT_EXIT (~строка 3234)

```c
case EVENT_EXIT: {
    /* rule_id lookup — ВСЕГДА (нужен для tags_remove) */
    __u32 exit_rule_id = e->rule_id;
    /* ... fallback lookup ... */

    /* tags cleanup — ВСЕГДА */
    tags_remove_ts(e->tgid);

    /* ▼ ФИЛЬТРАЦИЯ */
    if (cfg_emit_exit && g_http_cfg.enabled) {
        /* ... event_from_bpf, ef_append ... */
    }
    return 0;
}
```

### 3.4 EVENT_OOM_KILL (~строка 3314)

```c
case EVENT_OOM_KILL: {
    /* rule lookup — ВСЕГДА (дёшево, нужен для логирования) */
    struct track_info ti;
    /* ... lookup ... */

    /* ▼ ФИЛЬТРАЦИЯ */
    if (cfg_emit_oom_kill && g_http_cfg.enabled) {
        /* ... event_from_bpf, ef_append ... */
    }
    return 0;
}
```

### 3.5 EVENT_CHDIR (~строка 3302)

```c
case EVENT_CHDIR: {
    /* pwd update — ВСЕГДА */
    pwd_read_and_store(e->tgid);

    /* ▼ ФИЛЬТРАЦИЯ */
    if (cfg_emit_chdir && g_http_cfg.enabled) {
        /* ... ef_append ... */
    }
    return 0;
}
```

---

## Шаг 4: Фильтрация файловых событий

**Файл:** `src/process_metrics.c`, callback для events_file ring buffer.

Файловые события (file_close, file_rename и т.д.) приходят из events_file ring buffer
и в текущей реализации сразу формируют metric_event → ef_append(). Нет промежуточного
обновления userspace-состояния — BPF-хуки уже обновили fd_map.

Найти switch/if по `fe->type` (struct file_event) и добавить проверку:

```c
/* Маппинг event_type → cfg_emit_* для файловых событий */
static int file_event_allowed(uint32_t type)
{
    switch (type) {
    case EVENT_FILE_CLOSE:    return cfg_emit_file_close;
    case EVENT_FILE_OPEN:     return 1; /* open не генерирует ef_append */
    case EVENT_FILE_RENAME:   return cfg_emit_file_rename;
    case EVENT_FILE_UNLINK:   return cfg_emit_file_unlink;
    case EVENT_FILE_TRUNCATE: return cfg_emit_file_truncate;
    case EVENT_FILE_CHMOD:    return cfg_emit_file_chmod;
    case EVENT_FILE_CHOWN:    return cfg_emit_file_chown;
    default:                  return 1;
    }
}
```

В callback перед ef_append:

```c
if (!file_event_allowed(fe->type))
    return 0;
```

---

## Шаг 5: Фильтрация сетевых событий

**Файл:** `src/process_metrics.c`, callback для events_net ring buffer.

Сетевые события (net_listen, net_connect, net_accept, net_close) приходят как
`struct net_event`. Аналогично файловым — BPF уже обновил sock_map.

```c
static int net_event_allowed(uint32_t type)
{
    switch (type) {
    case EVENT_NET_LISTEN:  return cfg_emit_net_listen;
    case EVENT_NET_CONNECT: return cfg_emit_net_connect;
    case EVENT_NET_ACCEPT:  return cfg_emit_net_accept;
    case EVENT_NET_CLOSE:   return cfg_emit_net_close;
    default:                return 1;
    }
}
```

**ВАЖНО:** `EVENT_NET_CLOSE` и `EVENT_FILE_OPEN` имеют одинаковое значение (= 6)
в текущем enum. Это баг или legacy — при реализации проверить, как различаются
в callback (по ring buffer source: events_file vs events_net).

---

## Шаг 6: Фильтрация security-событий

**Файл:** `src/process_metrics.c`, callback для events_sec ring buffer.

Security-события фильтруются на **двух уровнях**:

1. **BPF-уровень** (уже реализовано): `sec_config.tcp_retransmit/tcp_syn/tcp_rst`
   в BPF-программах — событие не эмитируется в ring buffer вообще.
2. **Userspace-уровень** (новое): `cfg_emit_*` перед ef_append().

Двойная фильтрация нужна, потому что sec_config управляет подключением BPF-хуков
(экономия CPU), а events.tcp_retransmit управляет выводом в CSV (экономия трафика
в ClickHouse при сохранении BPF-мониторинга для логов).

```c
/* В callback events_sec: */
switch (type) {
case EVENT_TCP_RETRANSMIT:
    if (!cfg_emit_tcp_retransmit) return 0;
    break;
case EVENT_SYN_RECV:
    if (!cfg_emit_syn_recv) return 0;
    break;
case EVENT_RST:
    if (!cfg_emit_rst) return 0;
    break;
}
```

### Фильтрация signal

Signal приходит в events_net ring buffer как `struct signal_event`:

```c
case EVENT_SIGNAL:
    if (!cfg_emit_signal) return 0;
    /* ... ef_append ... */
```

---

## Шаг 7: Фильтрация cgroup-событий

**Файл:** `src/process_metrics.c`, callback для events_cgroup ring buffer.

Cgroup-события обновляют `cgroup_cache` в userspace. Кэш нужен для резолвинга
cgroup_id → path в snapshot. Поэтому cgroup_cache_add/remove выполняется **всегда**,
фильтруется только ef_append:

```c
case EVENT_CGROUP_MKDIR:
    cgroup_cache_add(ce->id, ce->path);           // ВСЕГДА
    if (cfg_emit_cgroup && g_http_cfg.enabled) {
        /* ... ef_append ... */
    }
    break;

case EVENT_CGROUP_RMDIR:
    cgroup_cache_remove(ce->id);                   // ВСЕГДА
    if (cfg_emit_cgroup && g_http_cfg.enabled) {
        /* ... ef_append ... */
    }
    break;

case EVENT_CGROUP_RENAME:
    cgroup_cache_add(ce->id, ce->path);            // ВСЕГДА
    if (cfg_emit_cgroup && g_http_cfg.enabled) {
        /* ... ef_append ... */
    }
    break;

/* EVENT_CGROUP_RELEASE, ATTACH_TASK, TRANSFER_TASKS,
   POPULATED, FREEZE, UNFREEZE, FROZEN — только логирование + ef_append */
default:
    if (!cfg_emit_cgroup) return 0;
    /* ... ef_append ... */
```

---

## Шаг 8: Логирование состояния при старте

**Файл:** `src/process_metrics.c`, после загрузки конфига (~строка после парсинга events).

При log_level >= 1 вывести список отключённых событий:

```c
if (cfg_log_level >= 1) {
    struct { const char *name; int enabled; } ev_flags[] = {
        {"exec",           cfg_emit_exec},
        {"fork",           cfg_emit_fork},
        {"exit",           cfg_emit_exit},
        {"oom_kill",       cfg_emit_oom_kill},
        {"file_close",     cfg_emit_file_close},
        {"file_rename",    cfg_emit_file_rename},
        {"file_unlink",    cfg_emit_file_unlink},
        {"file_truncate",  cfg_emit_file_truncate},
        {"file_chmod",     cfg_emit_file_chmod},
        {"file_chown",     cfg_emit_file_chown},
        {"net_listen",     cfg_emit_net_listen},
        {"net_connect",    cfg_emit_net_connect},
        {"net_accept",     cfg_emit_net_accept},
        {"net_close",      cfg_emit_net_close},
        {"tcp_retransmit", cfg_emit_tcp_retransmit},
        {"syn_recv",       cfg_emit_syn_recv},
        {"rst",            cfg_emit_rst},
        {"signal",         cfg_emit_signal},
        {"chdir",          cfg_emit_chdir},
        {"cgroup",         cfg_emit_cgroup},
    };
    int suppressed = 0;
    for (int i = 0; i < (int)(sizeof(ev_flags)/sizeof(ev_flags[0])); i++)
        if (!ev_flags[i].enabled) suppressed++;

    if (suppressed > 0) {
        log_ts("INFO", "events suppressed (%d):", suppressed);
        for (int i = 0; i < (int)(sizeof(ev_flags)/sizeof(ev_flags[0])); i++)
            if (!ev_flags[i].enabled)
                log_ts("INFO", "  %s = false", ev_flags[i].name);
    }
}
```

---

## Шаг 9: Обновление примера конфига

**Файл:** `examples/process_metrics.conf`, после секции `disk_tracking` (~строка 228).

```conf
# ── Управление отправкой событий ─────────────────────────────────
#
# Контролирует, какие события попадают в выходной CSV-буфер (→ ClickHouse).
# НЕ влияет на BPF-хуки и карты — snapshot/conn_snapshot/file_snapshot
# генерируются корректно независимо от этих настроек.
#
# Все события включены по умолчанию (true).
# Отключение снижает объём данных и нагрузку на ClickHouse/сеть,
# но не уменьшает CPU BPF-стороны (хуки продолжают обновлять карты).
#
# Для снижения CPU-нагрузки BPF используйте:
#   net_tracking.enabled = false   — отключает BPF-хуки сети
#   file_tracking.enabled = false  — отключает BPF-хуки файлов
#   net_tracking.tcp_retransmit/tcp_syn/tcp_rst = false
#                                  — отключает BPF-хуки security

events = {
    # ── Жизненный цикл процессов ────────────────────────────────
    # BPF-хуки и ring buffer для fork/exec/exit работают всегда
    # (нужны для корректного tracking). Флаги управляют только
    # отправкой строки события в CSV-буфер.
    exec          = true;
    fork          = true;
    exit          = true;
    oom_kill      = true;

    # ── Файловые события ────────────────────────────────────────
    # BPF-хуки обновляют fd_map → file_snapshot работает всегда.
    file_close    = true;
    file_rename   = true;
    file_unlink   = true;
    file_truncate = true;
    file_chmod    = true;
    file_chown    = true;

    # ── Сетевые события ─────────────────────────────────────────
    # BPF-хуки обновляют sock_map → conn_snapshot работает всегда.
    net_listen    = true;
    net_connect   = true;
    net_accept    = true;
    net_close     = true;

    # ── Security-события ────────────────────────────────────────
    # Чисто streaming. Для полного отключения (включая BPF-хуки)
    # используйте net_tracking.tcp_retransmit и т.д.
    tcp_retransmit = true;
    syn_recv       = true;
    rst            = true;
    signal         = true;

    # ── Прочие ──────────────────────────────────────────────────
    chdir         = true;

    # ── Cgroup-события ──────────────────────────────────────────
    # Внутренний cgroup_cache обновляется всегда (нужен для
    # резолвинга cgroup path в snapshot). Флаг управляет
    # отправкой cgroup_mkdir/rmdir/rename/attach событий в CSV.
    cgroup        = true;
};
```

---

## Шаг 10: Поддержка SIGHUP (hot reload)

Секция `events {}` должна перечитываться при SIGHUP наравне с `rules`.
В текущей реализации SIGHUP перезагружает правила из конфига без перезапуска.

**Файл:** `src/process_metrics.c`, обработчик SIGHUP.

Добавить повторный парсинг секции `events {}` (код из шага 2) в обработчик SIGHUP.
Переменные `cfg_emit_*` — глобальные static int, потокобезопасно читаются из
callback'ов ring buffer (single-writer / multiple-reader на aligned int — safe на x86/arm).

---

## Порядок реализации

| Этап | Шаги | Описание | Сложность |
|------|-------|----------|-----------|
| **A** | 1, 2, 9 | Переменные, парсинг, пример конфига | Низкая |
| **B** | 3 | Фильтрация proc-событий (fork/exec/exit/oom/chdir) | Средняя — нужна аккуратность с сохранением state-логики |
| **C** | 4, 5, 6 | Фильтрация file/net/security событий | Низкая — чистый guard перед ef_append |
| **D** | 7 | Фильтрация cgroup-событий | Низкая — аналогично proc, cgroup_cache всегда |
| **E** | 8 | Логирование | Низкая |
| **F** | 10 | SIGHUP hot reload | Низкая — копирование парсинга |

Рекомендуемый порядок: A → C → B → D → E → F.

Этап C проще всего — guard перед ef_append без risk для state. Начать с него
для быстрой проверки концепции. Этап B требует наибольшей осторожности:
важно не обернуть в `if (cfg_emit_*)` код, который обновляет pidtree/tags/tracking.

---

## Что НЕ входит в scope

- **Отключение BPF-хуков** — управляется существующими `net_tracking.enabled`,
  `file_tracking.enabled`, `sec_config.*`. Новая секция `events {}` не дублирует
  эту функциональность.
- **Per-rule фильтрация** (отправлять exec только для rule="java") — потенциальное
  расширение, но не в первой итерации.
- **BPF-level emit config** — передача `events {}` флагов в BPF через карту для
  подавления эмиссии в ring buffer. Оптимизация второго этапа: экономит CPU на
  bpf_ringbuf_reserve/submit и poll в userspace. Имеет смысл для высокочастотных
  streaming-событий (file_close, net_close).

---

## Заметка: дублирование EVENT_FILE_OPEN и EVENT_NET_CLOSE

В текущем enum (process_metrics_common.h:152-153):
```c
EVENT_FILE_OPEN      = 6,
EVENT_NET_CLOSE      = 6,
```

Оба имеют значение 6. Это работает, потому что они приходят из разных ring buffer'ов
(events_file vs events_net) и обрабатываются разными callback'ами. Но при реализации
`file_event_allowed()` / `net_event_allowed()` нужно учитывать, что switch по type
в общем callback'е не различит эти события. Фильтрация должна быть в соответствующих
per-ringbuf callback'ах, а не в общем handle_event.
