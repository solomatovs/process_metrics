/* SPDX-License-Identifier: GPL-2.0 */
/*
 * process_metrics_common.h — общие типы для BPF и пространства пользователя
 */

#ifndef PROCESS_METRICS_COMMON_H
#define PROCESS_METRICS_COMMON_H

#ifndef __bpf__
#include <linux/types.h>
#endif

#define COMM_LEN        16
#define CMDLINE_MAX     4096
#define MAX_PROCS       65536

/* ── размеры буферов для /proc и текстового ввода-вывода ──────────── */
#define PROC_PATH_LEN   64    /* "/proc/<pid>/stat", "/proc/<pid>/cmdline" и т.д. */
#define PROC_STAT_LEN   1024  /* строка из /proc/<pid>/stat (~350 символов) */
#define PROC_IO_LINE    128   /* строка из /proc/<pid>/io ("read_bytes: 12345\n") */
#define PROC_STATUS_LINE 256  /* строка из /proc/<pid>/status */
#define PROC_BUF_SMALL  512   /* /proc/<pid>/cgroup, небольшие буферы */
#define PATH_MAX_LEN    512   /* общие пути: cgroup fs, mount info и т.д. */
#define LINE_BUF_LEN    128   /* буфер для однострочного чтения (comm, mountinfo) */
#define CONFIG_BUF_LEN  4096  /* буфер для чтения конфигурационных файлов */
#define HTTP_HEADER_LEN 512   /* буфер для HTTP-заголовков */
#define HTTP_BUF_LEN    4096  /* буфер для HTTP-запросов/ответов */
#define USERNAME_LEN    64    /* имя пользователя (getpwuid_r) */
#define PWD_BUF_LEN     1024  /* буфер для getpwuid_r */
#define PROC_VAL_LEN    64    /* однострочное значение: oom_score_adj, cgroup cpu.max */
#define BIND_ADDR_LEN   64    /* адрес привязки HTTP-сервера */
#define HTTP_MAX_ALLOW  32    /* макс. кол-во записей в allow-списке */

/* ── ёмкости хеш-таблиц и кешей (userspace) ───────────────────────── */
#define MAX_RULES            64     /* максимум правил трекинга */
#define MAX_CGROUPS          256    /* максимум cgroup в кеше */
#define TAGS_HT_SIZE         16384  /* хеш-таблица тегов (степень 2) */
#define PIDTREE_HT_SIZE      65536  /* дерево pid→ppid (степень 2, покрывает pid_max) */
#define CHAIN_CACHE_SIZE     16384  /* кеш цепочек parent_pids (степень 2) */
#define PWD_HT_SIZE          16384  /* хеш-таблица рабочих каталогов (степень 2) */
#define MAX_CPU_PREV         8192   /* кеш предыдущих значений CPU */
#define DOCKER_NAME_CACHE_SIZE 256  /* кеш имён Docker-контейнеров */
#define UID_NAME_CACHE_SIZE  512    /* кеш uid→username */
#define MAX_SCAN             8192   /* макс. итераций сканирования /proc */
#define DEAD_KEYS_CAP        4096   /* буфер мёртвых ключей для удаления */

/* ── ёмкости дисковых и файловых массивов ──────────────────────────── */
#define DISK_MAX_PREFIXES    32     /* макс. префиксов disk_include */
#define DISK_PREFIX_MAX      256    /* длина строки префикса диска */
#define DISK_FS_TYPE_LEN     32     /* длина имени файловой системы */
#define DISK_MAX_DEVS        64     /* макс. уникальных устройств в statvfs */
#define DISK_DEV_NAME_LEN    256    /* длина имени устройства */

/* ── ёмкости BPF map (не ring buffer) ─────────────────────────────── */
#define BPF_ARGS_MAP_SIZE    8192   /* временные аргументы syscall (per-CPU inflight) */
#define BPF_FD_MAP_SIZE      65536  /* отслеживание файловых дескрипторов */
#define BPF_MISSED_EXEC_SIZE 1024   /* пропущенные exec для восстановления */
#define BPF_UDP_AGG_SIZE     16384  /* агрегация UDP-трафика */
#define BPF_ICMP_AGG_SIZE    8192   /* агрегация ICMP-трафика */

/* ── HTTP-сервер ───────────────────────────────────────────────────── */
#define HTTP_SEND_BUF_SIZE       (128 * 1024) /* буфер отправки HTTP (128 КБ) */
#define HTTP_ROW_BUF_SIZE        8192         /* буфер одной CSV-строки */
#define HTTP_SOCK_TIMEOUT_SEC    5            /* таймаут клиентского сокета */
#define HTTP_LISTEN_TIMEOUT_SEC  1            /* таймаут listen-цикла */

/* ── event_file ────────────────────────────────────────────────────── */
#define EF_MAX_CAPACITY      1000000      /* макс. записей в кольцевом буфере */
/*
 * Размеры кольцевых буферов для передачи событий из BPF в userspace.
 * Пять раздельных буферов — каждый под свой тип событий:
 *
 *   events_proc   — fork/exec/exit/oom_kill (struct event, ~450 байт)
 *   events_file   — закрытие файлов (struct file_event, ~300 байт)
 *   events_net    — сетевые и signal события (~60–120 байт)
 *   events_sec    — security: retransmit/syn/rst (~90 байт), отдельно от net
 *   events_cgroup — cgroup: запуск/остановка контейнера, миграция (~290 байт)
 *
 * Параметризация через количество событий при компиляции:
 *   -DRINGBUF_PROC_EVENTS=N   (по умолчанию 8192)
 *   -DRINGBUF_FILE_EVENTS=N   (по умолчанию 12288)
 *   -DRINGBUF_NET_EVENTS=N    (по умолчанию 32768)
 *   -DRINGBUF_SEC_EVENTS=N    (по умолчанию 8192)
 *   -DRINGBUF_CGROUP_EVENTS=N (по умолчанию 768)
 *
 * Итоговый размер = кол-во событий * размер слота, округлён вверх
 * до степени двойки (требование ядра для BPF ring buffer).
 * Каждый слот = sizeof(struct) + 8 байт BPF_RINGBUF_HDR_SZ, с запасом.
 */

/* Вычисление ближайшей степени двойки >= x (compile-time) */
#define _RINGBUF_POW2(x) \
	((x) <= 1 ? 1 : \
	 1U << (32 - __builtin_clz((unsigned)((x) - 1))))

#ifndef RINGBUF_PROC_EVENTS
#define RINGBUF_PROC_EVENTS  2048   /* struct event=4320B → 2048 × 4352 = 16 MB */
#endif
#ifndef RINGBUF_FILE_EVENTS
#define RINGBUF_FILE_EVENTS  4096   /* struct file_event=2152B → 4096 × 2176 = 16 MB */
#endif
#ifndef RINGBUF_FOPEN_EVENTS
#define RINGBUF_FOPEN_EVENTS 2048   /* struct file_event=2152B → 2048 × 2176 = 4 MB (шумный, допустимы потери) */
#endif
#ifndef RINGBUF_NET_EVENTS
#define RINGBUF_NET_EVENTS   32768
#endif
#ifndef RINGBUF_SEC_EVENTS
#define RINGBUF_SEC_EVENTS   8192
#endif

/* Размер слота: sizeof(struct) + 8 (BPF_RINGBUF_HDR_SZ), для расчёта ёмкости.
 * BPF ring buffer аллоцирует реальный sizeof при reserve, слот — только для
 * вычисления RINGBUF_*_SIZE = POW2(events × slot).
 * ВАЖНО: слот должен быть >= sizeof(struct) + 8, иначе реальная ёмкость
 * будет меньше заявленной. */
#define _RINGBUF_PROC_SLOT   4352  /* struct event (4320) + 8 + padding */
#define _RINGBUF_FILE_SLOT   2176  /* struct file_event (2152) + 8 + padding */
#define _RINGBUF_NET_SLOT    256   /* struct net_event (136) + 8 */
#define _RINGBUF_SEC_SLOT    128   /* struct retransmit_event/syn_event/rst_event (88) + 8 */

#define RINGBUF_PROC_SIZE   _RINGBUF_POW2(RINGBUF_PROC_EVENTS  * _RINGBUF_PROC_SLOT)
#define RINGBUF_FILE_SIZE   _RINGBUF_POW2(RINGBUF_FILE_EVENTS  * _RINGBUF_FILE_SLOT)
#define RINGBUF_FOPEN_SIZE  _RINGBUF_POW2(RINGBUF_FOPEN_EVENTS * _RINGBUF_FILE_SLOT)
#define RINGBUF_NET_SIZE    _RINGBUF_POW2(RINGBUF_NET_EVENTS   * _RINGBUF_NET_SLOT)
#define RINGBUF_SEC_SIZE    _RINGBUF_POW2(RINGBUF_SEC_EVENTS   * _RINGBUF_SEC_SLOT)

/*
 * Счётчики потерь событий в ring buffer'ах.
 * Инкрементируются в BPF при неудачном bpf_ringbuf_reserve (буфер переполнен).
 * Читаются из userspace для диагностики.
 */
struct ringbuf_stats {
	__u64 drop_proc;       /* потери в events_proc */
	__u64 drop_file;       /* потери в events_file (close/rename/chmod/...) */
	__u64 drop_fopen;      /* потери в events_fopen (file_open) */
	__u64 drop_net;        /* потери в events_net */
	__u64 drop_sec;        /* потери в events_sec (security: retransmit, syn, rst) */
	__u64 drop_cgroup;     /* потери в events_cgroup */
	__u64 total_proc;      /* всего событий proc */
	__u64 total_file;      /* всего событий file (close/rename/chmod/...) */
	__u64 total_fopen;     /* всего событий fopen */
	__u64 total_net;       /* всего событий net */
	__u64 total_sec;       /* всего событий sec */
	__u64 total_cgroup;    /* всего событий cgroup */
	__u64 drop_missed_exec; /* missed_exec_map overflow (ENOSPC) */
};

/*
 * Состояние ограничителя частоты для exec-событий.
 * Одноэлементная BPF-карта (array), отслеживает события в 1-секундном окне.
 */
struct rate_state {
	__u64 window_ns;
	__u64 count;
};

enum event_type {
	EVENT_FORK           = 1,
	EVENT_EXEC           = 2,
	EVENT_EXIT           = 3,
	EVENT_OOM_KILL       = 4,
	EVENT_FILE_CLOSE     = 5,
	EVENT_FILE_OPEN      = 6,
	EVENT_NET_CLOSE      = 6,
	EVENT_NET_LISTEN     = 12,
	EVENT_NET_CONNECT    = 13,
	EVENT_NET_ACCEPT     = 14,
	EVENT_SIGNAL         = 7,
	EVENT_TCP_RETRANSMIT = 8,
	EVENT_SYN_RECV       = 9,
	EVENT_RST            = 10,
	EVENT_CHDIR          = 11,
	EVENT_FILE_RENAME    = 15,
	EVENT_FILE_UNLINK    = 16,
	EVENT_FILE_TRUNCATE  = 17,
	EVENT_FILE_CHMOD     = 18,
	EVENT_FILE_CHOWN     = 19,
	/* события жизненного цикла cgroup */
	EVENT_CGROUP_MKDIR           = 20,
	EVENT_CGROUP_RMDIR           = 21,
	EVENT_CGROUP_RENAME          = 22,
	EVENT_CGROUP_RELEASE         = 23,
	/* миграция процессов между cgroup */
	EVENT_CGROUP_ATTACH_TASK     = 24,
	EVENT_CGROUP_TRANSFER_TASKS  = 25,
	/* состояние cgroup */
	EVENT_CGROUP_POPULATED       = 26,
	EVENT_CGROUP_FREEZE          = 27,
	EVENT_CGROUP_UNFREEZE        = 28,
	EVENT_CGROUP_FROZEN          = 29,
};

/* ── состояние жизненного цикла процесса ────────────────────────── */

enum proc_status {
	PROC_STATUS_ALIVE  = 0,   /* процесс жив (default после memset/BPF_ZERO) */
	PROC_STATUS_EXITED = 1,   /* процесс завершился (exit/kill/oom) */
};

/* ── отслеживание cgroup ─────────────────────────────────────────── */

#define CGROUP_PATH_MAX  256

/*
 * Размер кольцевого буфера для cgroup-событий.
 * Cgroup-события редкие (запуск/остановка контейнера, миграция процесса),
 * поэтому достаточно небольшого буфера.
 */
#ifndef RINGBUF_CGROUP_EVENTS
#define RINGBUF_CGROUP_EVENTS  768
#endif
#define _RINGBUF_CGROUP_SLOT  512   /* struct cgroup_event ~290 + 8 */
#define RINGBUF_CGROUP_SIZE  _RINGBUF_POW2(RINGBUF_CGROUP_EVENTS * _RINGBUF_CGROUP_SLOT)

/*
 * Событие cgroup — отправляется из BPF в пространство пользователя через
 * выделенный кольцевой буфер.
 * Первое поле — __u32 type (EVENT_CGROUP_*), единая конвенция диспетчеризации.
 */
struct cgroup_event {
	__u32 type;              /* EVENT_CGROUP_* */
	__u64 id;                /* cgroup inode (matches bpf_get_current_cgroup_id) */
	__u32 level;             /* глубина в иерархии */
	__u32 pid;               /* для attach/transfer — какой PID перемещён */
	__s32 val;               /* для populated/frozen — 1/0 */
	__u64 timestamp_ns;
	char  path[CGROUP_PATH_MAX]; /* путь внутри иерархии cgroup */
	char  comm[COMM_LEN];        /* для attach/transfer — имя процесса */
};

/* ── константы отслеживания файлов ────────────────────────────────── */

#define FILE_PATH_MAX        4096  /* userspace: metric_event, CSV, ClickHouse */
#define BPF_FILE_PATH_MAX   1024  /* BPF: fd_info, file_event, openat_args (ядерные карты) */
#define FILE_MAX_PREFIXES    16
#define FILE_PREFIX_LEN      128
#define PREFIX_CMP_MAX       32    /* макс. сравниваемых байт для include/exclude фильтров */

/*
 * Конфигурация, передаваемая из пространства пользователя в BPF через карты.
 */
struct file_config {
	__u8  enabled;       /* 1 = отслеживать open/close */
	__u8  track_bytes;   /* 1 = также считать байты чтения/записи по fd */
};

/*
 * Запись префикса для списков включения/исключения.
 * Хранится в BPF array-картах, сравнивается в развёрнутых циклах.
 * Расположение: сначала len, затем prefix — чтобы структура была степенью двойки
 * (128+1 → плохое выравнивание). При len по смещению 0: sizeof = 1 + FILE_PREFIX_LEN = 129,
 * но верификатор ядра 5.15 требует удобный value_size.
 * Поэтому prefix укорочен на 1, чтобы получить ровно 128 байт.
 */
#define FILE_PREFIX_CAP  (FILE_PREFIX_LEN - 1)  /* 127: полезных байт префикса */

struct file_prefix {
	__u8  len;           /* фактическая длина (0 = неиспользуемый слот) */
	char  prefix[FILE_PREFIX_CAP];
};

/*
 * Временное хранилище аргументов openat() между входом и выходом из syscall.
 * Ключ: pid_tgid (__u64)
 */
struct openat_args {
	char  path[BPF_FILE_PATH_MAX];
	int   flags;
};

/*
 * Временное хранилище аргументов read/write между входом и выходом из syscall.
 * Ключ: pid_tgid (__u64)
 */
struct rw_args {
	int   fd;
};

/*
 * Временное хранилище аргументов sendfile64 между входом и выходом из syscall.
 * Ключ: pid_tgid (__u64)
 */
struct sendfile_args {
	int   out_fd;
	int   in_fd;
};

/*
 * Состояние отслеживания по fd в fd_map.
 * Ключ: struct fd_key { __u32 tgid; int fd; }
 */
struct fd_key {
	__u32 tgid;
	__s32 fd;
};

struct fd_info {
	char  path[BPF_FILE_PATH_MAX];
	int   flags;
	__u64 read_bytes;
	__u64 write_bytes;
	__u32 open_count;    /* сколько раз этот fd был открыт */
	__u32 fsync_count;   /* количество fsync/fdatasync вызовов */
	__u64 start_ns;      /* время открытия файла (boot ns) */
};

/*
 * Событие закрытия файла — отправляется из BPF в пространство пользователя
 * через кольцевой буфер.
 * Первое поле — __u32 type (= EVENT_FILE_CLOSE), то же смещение, что и
 * в struct event, что позволяет callback кольцевого буфера диспетчеризовать по type.
 */
struct file_event {
	__u32 type;           /* EVENT_FILE_CLOSE / EVENT_FILE_RENAME / ... */
	__u32 tgid;
	__u32 ppid;
	__u32 uid;            /* реальный UID процесса */
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	char  path[BPF_FILE_PATH_MAX];
	int   flags;
	__u64 read_bytes;
	__u64 write_bytes;
	__u32 open_count;
	__u32 fsync_count;              /* fsync/fdatasync вызовы */
	char  path2[BPF_FILE_PATH_MAX]; /* rename: new_path */
	__u64 truncate_size;            /* truncate: new_size */
	__u32 chmod_mode;               /* chmod: новый mode */
	__u32 chown_uid;                /* chown: новый uid */
	__u32 chown_gid;                /* chown: новый gid */
};

/*
 * Метрики процесса, обновляемые в sched_switch.
 * Ключ: tgid (__u32)
 */
struct proc_info {
	__u32 tgid;
	__u32 ppid;
	__u32 uid;               /* реальный UID процесса */

	/* ── жизненный цикл (event-driven) ─────────────────────── */
	__u8  status;            /* enum proc_status: ALIVE=0 → EXITED=1 */
	__u64 start_ns;          /* время рождения (CLOCK_MONOTONIC boot_ns) */
	__u64 exit_ns;           /* время смерти (boot_ns), 0 = жив */
	__u64 cpu_ns;            /* signal->{utime+stime} + leader->{utime+stime} */
	__u64 rss_pages;         /* текущий RSS в страницах */
	__u64 rss_min_pages;     /* минимальный наблюдаемый RSS в страницах */
	__u64 rss_max_pages;     /* максимальный наблюдаемый RSS в страницах */
	__u64 shmem_pages;       /* MM_SHMEMPAGES (разделяемая память) */
	__u64 swap_pages;        /* MM_SWAPENTS (использование подкачки) */
	__u64 io_read_bytes;     /* ioac.read_bytes (фактические чтения с диска) */
	__u64 io_write_bytes;    /* ioac.write_bytes (фактические записи на диск) */
	__u64 maj_flt;           /* мажорные страничные отказы (чтение с диска) */
	__u64 min_flt;           /* минорные страничные отказы */
	__u64 nvcsw;             /* добровол��ные переключения контекста */
	__u64 nivcsw;            /* принудительные переключения контекста */
	__u8  oom_killed;        /* 1, если убит OOM killer */
	__u32 exit_code;         /* task->exit_code (устанавливается при завершении) */
	__u64 vsize_pages;       /* mm->total_vm */
	__u32 threads;           /* signal->nr_threads */
	__s16 oom_score_adj;     /* signal->oom_score_adj */
	__u64 cgroup_id;         /* inode cgroup v2 */
	__u8  state;             /* состояние процесса: 'R','S','D','T','Z',... */
	__u64 net_tx_bytes;      /* TCP+UDP отправлено байт */
	__u64 net_rx_bytes;      /* TCP+UDP получено байт */
	char  comm[COMM_LEN];
	char  cmdline[CMDLINE_MAX];
	__u16 cmdline_len;

	/* ── идентификация ──────────────────────────────────────── */
	__u32 loginuid;          /* audit loginuid (4294967295 = не задан) */
	__u32 sessionid;         /* идентификатор сессии аудита */
	__u32 euid;              /* effective UID (cred->euid) */
	__u32 tty_nr;            /* управляющий терминал (major<<8|minor), 0 = нет */

	/* ── планировщик ─────────────────────────────────────────── */
	__u32 sched_policy;      /* SCHED_NORMAL=0, SCHED_FIFO=1, SCHED_RR=2, ... */

	/* ── учёт ввода-вывода (включая page cache) ──────────────── */
	__u64 io_rchar;          /* всего прочитано байт (включая кэш) */
	__u64 io_wchar;          /* всего записано байт (включая кэш) */
	__u64 io_syscr;          /* количество системных вызовов чтения */
	__u64 io_syscw;          /* количество системных вызовов записи */

	/* ── inode пространств имён (namespace) ──────────────────── */
	__u32 mnt_ns_inum;       /* пространство монтирования */
	__u32 pid_ns_inum;       /* пространство PID */
	__u32 net_ns_inum;       /* сетевое пространство */
	__u32 cgroup_ns_inum;    /* пространство cgroup */

	/* ── отслеживание вытеснения ─────────────────────────────── */
	__u32 preempted_by_pid;  /* tgid последнего вытеснителя (принудит. переключение) */
	char  preempted_by_comm[COMM_LEN]; /* comm последнего вытеснителя (резолвлен до главного потока) */
	__u64 preempted_by_cgroup_id;      /* cgroup последнего вытеснителя */
};

/*
 * Маппинг TID → TGID+comm для резолвинга имён при вытеснении.
 * Позволяет преобразовывать имена потоков (ThreadPool, Worker-N и т.д.)
 * в comm их родительского процесса (clickhouse-serv, java и т.д.).
 * Совместимо с ядром 5.x (не требует bpf_task_from_pid).
 */
struct tid_info {
	__u32 tgid;
	char  comm[COMM_LEN];    /* comm главного потока (group leader) */
};

/*
 * Метаданные отслеживания, управляются из userspace + наследуются при fork.
 * Ключ: tgid (__u32)
 */
struct track_info {
	__u32 root_pid;
	__u16 rule_id;
	__u8  is_root;
	__u8  _pad;       /* явное выравнивание — верификатор ядра 5.15 требует инициализации всех байт стека */
} __attribute__((aligned(8)));

/*
 * Событие кольцевого буфера — отправляется из BPF в userspace при fork/exec/exit.
 */
struct event {
	__u32 type;              /* enum event_type (тип события) */
	__u32 tgid;
	__u32 ppid;
	__u32 uid;               /* реальный UID процесса */
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	char  cmdline[CMDLINE_MAX];
	__u16 cmdline_len;
	/* информация отслеживания (скопирована из tracked_map перед удалением) */
	__u32 root_pid;
	__u16 rule_id;
	/* финальные метрики при завершении (exit) */
	__u64 cpu_ns;
	__u64 rss_pages;
	__u64 rss_min_pages;
	__u64 rss_max_pages;
	__u64 vsize_pages;
	__u32 threads;
	__s16 oom_score_adj;
	__u32 exit_code;
	__u64 start_ns;
	__u8  oom_killed;
	__u64 net_tx_bytes;
	__u64 net_rx_bytes;

	/* ── идентификация ──────────────────────────────────────── */
	__u32 loginuid;
	__u32 sessionid;
	__u32 euid;
	__u32 tty_nr;

	/* ── планировщик ─────────────────────────────────────────── */
	__u32 sched_policy;

	/* ── учёт ввода-вывода ────────────────────────────────────── */
	__u64 io_rchar;
	__u64 io_wchar;
	__u64 io_syscr;
	__u64 io_syscw;

	/* ── inode пространств имён ──────────────────────────────── */
	__u32 mnt_ns_inum;
	__u32 pid_ns_inum;
	__u32 net_ns_inum;
	__u32 cgroup_ns_inum;
};

/* ── константы отслеживания сети ──────────────────────────────────── */

#define NET_MAX_SOCKETS  65536

/*
 * Конфигурация, передаваемая из пространства пользователя в BPF через карты.
 */
struct net_config {
	__u8  enabled;       /* 1 = отслеживать connect/accept/close */
	__u8  track_bytes;   /* 1 = также считать отправленные/принятые байты по сокету */
};

/*
 * Временное хранилище аргументов tcp_v4_connect / tcp_v6_connect.
 * Ключ: pid_tgid (__u64)
 */
struct connect_args {
	__u64 sock_ptr;      /* struct sock * */
};

/*
 * Временное хранилище аргументов tcp_sendmsg / tcp_recvmsg.
 * Ключ: pid_tgid (__u64)
 */
struct sendmsg_args {
	__u64 sock_ptr;      /* struct sock * */
};

/*
 * Состояние отслеживания по сокету в sock_map.
 * Ключ: указатель на sock (__u64)
 */
struct sock_info {
	__u32 tgid;
	__u32 uid;
	__u8  af;             /* AF_INET=2, AF_INET6=10 */
	__u8  local_addr[16]; /* IPv4 в первых 4 байтах, или полный IPv6 */
	__u8  remote_addr[16];
	__u16 local_port;     /* порядок байт хоста */
	__u16 remote_port;    /* порядок байт хоста */
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 tx_calls;       /* количество вызовов sendmsg */
	__u64 rx_calls;       /* количество вызовов recvmsg */
	__u64 start_ns;       /* время начала соединения (boot ns) */
	__u8  is_listener;    /* 1 = слушающий сокет (не соединение) */
} __attribute__((aligned(8)));

/*
 * Событие закрытия сетевого соединения — отправляется из BPF в userspace
 * через кольцевой буфер.
 * Первое поле — __u32 type (EVENT_NET_OPEN или EVENT_NET_CLOSE).
 */
struct net_event {
	__u32 type;           /* EVENT_NET_OPEN или EVENT_NET_CLOSE */
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	__u8  af;             /* AF_INET=2, AF_INET6=10 */
	__u8  local_addr[16];
	__u8  remote_addr[16];
	__u16 local_port;
	__u16 remote_port;
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 tx_calls;       /* количество вызовов sendmsg */
	__u64 rx_calls;       /* количество вызовов recvmsg */
	__u64 duration_ns;    /* сколько времени соединение было открыто */
	__u8  tcp_state;      /* TCP state на момент close (ESTABLISHED=1, CLOSE_WAIT=8, ...) */
};

/*
 * Событие сигнала — отправляется из BPF в userspace при доставке сигнала.
 * Захватывает информацию об отправителе (текущая задача) и получателе из tracepoint.
 */
struct signal_event {
	__u32 type;           /* EVENT_SIGNAL */
	__u32 sender_tgid;    /* PID отправителя */
	__u32 sender_uid;     /* UID отправителя */
	__u32 target_pid;     /* PID получателя (из tracepoint) */
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  sender_comm[COMM_LEN];
	int   sig;            /* номер сигнала (SIGKILL=9 и т.д.) */
	int   sig_code;       /* SI_USER=0, SI_KERNEL=0x80 и т.д. */
	int   sig_result;     /* 0 = успешно доставлен */
};

/* ── отслеживание безопасности ────────────────────────────────────── */

/*
 * Конфигурация для проб безопасности (передаётся из userspace в BPF).
 */
struct sec_config {
	__u8 tcp_retransmit;     /* 1 = отслеживать TCP-ретрансмиты */
	__u8 tcp_syn;            /* 1 = отслеживать SYN-recv события */
	__u8 tcp_rst;            /* 1 = отслеживать RST-события */
	__u8 udp_bytes;          /* 1 = учёт UDP байтов/пакетов по (addr, port) */
	__u8 icmp_tracking;      /* 1 = агрегировать ICMP-пакеты */
	__u8 tcp_open_conns;     /* 1 = считать открытые TCP-соединения */
};

/*
 * Событие TCP-ретрансмита — отправляется через кольцевой буфер.
 */
struct retransmit_event {
	__u32 type;           /* EVENT_TCP_RETRANSMIT */
	__u32 tgid;
	__u32 uid;
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	__u8  af;             /* AF_INET=2, AF_INET6=10 */
	__u8  local_addr[16];
	__u8  remote_addr[16];
	__u16 local_port;
	__u16 remote_port;
	__u8  state;          /* состояние TCP на момент ретрансмита */
};

/*
 * Событие SYN-recv — входящий TCP SYN (полу-открытое соединение).
 */
struct syn_event {
	__u32 type;           /* EVENT_SYN_RECV */
	__u32 tgid;
	__u32 uid;
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	__u8  af;
	__u8  local_addr[16];
	__u8  remote_addr[16];
	__u16 local_port;
	__u16 remote_port;
};

/*
 * Событие RST — TCP reset отправлен или получен.
 */
struct rst_event {
	__u32 type;           /* EVENT_RST */
	__u32 tgid;
	__u32 uid;
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	__u8  af;
	__u8  local_addr[16];
	__u8  remote_addr[16];
	__u16 local_port;
	__u16 remote_port;
	__u8  direction;      /* 0 = отправлен, 1 = получен */
};

/*
 * Агрегация UDP (BPF-карта, сбрасывается из userspace при snapshot).
 */
struct udp_agg_key {
	__u32 tgid;
	__u8  af;
	__u8  remote_addr[16];
	__u16 remote_port;
} __attribute__((aligned(8)));

struct udp_agg_val {
	__u64 tx_packets;
	__u64 rx_packets;
	__u64 tx_bytes;
	__u64 rx_bytes;
};

/*
 * Агрегация ICMP (BPF-карта, сбрасывается из userspace при snapshot).
 */
struct icmp_agg_key {
	__u8  src_addr[16];
	__u8  icmp_type;
	__u8  icmp_code;
} __attribute__((aligned(8)));

struct icmp_agg_val {
	__u64 count;
};

#endif /* PROCESS_METRICS_COMMON_H */
