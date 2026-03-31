/*
 * event_file.h — кольцевой буфер в памяти для событий метрик
 *
 * Накапливает записи metric_event в кольцевом буфере фиксированного размера.
 * Старые записи перезаписываются при заполнении буфера (кольцевая семантика).
 *
 * Два режима доступа через HTTP:
 *   GET /metrics              — снимок: итерация по всем записям (только чтение)
 *   GET /metrics?clear=1      — потребление: итерация по всем записям с последующей очисткой
 */

#ifndef EVENT_FILE_H
#define EVENT_FILE_H

#include <linux/types.h>
#include "process_metrics_common.h"

/* ── размеры полей metric_event ──────────────────────────────────── */

#define EV_EVENT_TYPE_LEN \
	16 /* "fork","exec","exit","oom_kill","snapshot","conn_snapshot","file_close" */
#define EV_RULE_LEN	   64  /* имя правила */
#define EV_TAGS_LEN	   512 /* список всех сработавших правил, разделённых символом | */
#define EV_CGROUP_LEN	   512 /* путь cgroup */
#define EV_ADDR_LEN	   46  /* форматированная строка IP (INET6_ADDRSTRLEN) */
#define EV_PWD_LEN	   512 /* текущий рабочий каталог */
#define EV_PARENT_PIDS_MAX 32  /* макс. глубина цепочки предков процесса */

/*
 * Наихудший случай экранирования CSV: каждый символ удвоен + 2 кавычки + NUL.
 * ESC(n) = (n) * 2 + 3
 */
#define EV_ESC_SIZE(n) ((n) * 2 + 3)

/* ── событие метрики (используется в event_file, http_server, main) ── */

struct metric_event {
	/* ── общие поля ───────────────────────────────────────────── */
	__u64 timestamp_ns;
	char event_type[EV_EVENT_TYPE_LEN];
	char rule[EV_RULE_LEN];
	char tags[EV_TAGS_LEN]; /* список всех сработавших правил, разделённых символом | */
	__u32 root_pid;
	__u32 pid;
	__u32 ppid;
	__u32 uid; /* реальный UID процесса */
	char comm[COMM_LEN];
	char thread_name
	    [COMM_LEN]; /* имя потока (может отличаться от comm у многопоточных процессов) */
	char exec_path[CMDLINE_MAX]; /* путь к исполняемому файлу (argv[0]) */
	char args[CMDLINE_MAX];	     /* аргументы (argv[1..]) */
	char cgroup[EV_CGROUP_LEN];
	__u8 is_root;
	__u8 state;

	/* ── метрики процесса ─────────────────────────────────────── */
	__u32 exit_code;
	__u64 cpu_ns;
	double cpu_usage_ratio;
	__u64 rss_bytes;
	__u64 rss_min_bytes;
	__u64 rss_max_bytes;
	__u64 shmem_bytes;
	__u64 swap_bytes;
	__u64 vsize_bytes;
	__u64 io_read_bytes;
	__u64 io_write_bytes;
	__u64 maj_flt;
	__u64 min_flt;
	__u64 nvcsw;
	__u64 nivcsw;
	__u32 threads;
	__s16 oom_score_adj;
	__u8 oom_killed;
	__u64 net_tcp_tx_bytes;
	__u64 net_tcp_rx_bytes;
	__u64 net_udp_tx_bytes;
	__u64 net_udp_rx_bytes;
	__u64 start_time_ns;
	__u64 uptime_seconds;

	/* ── метрики cgroup v2 (-1 = недоступно) ────────────────────── */
	__s64 cgroup_memory_max;
	__s64 cgroup_memory_current;
	__s64 cgroup_swap_current;
	__s64 cgroup_cpu_weight;
	__s64 cgroup_cpu_max;		 /* квота за период (мкс), 0 = "max" (без ограничений) */
	__s64 cgroup_cpu_max_period;	 /* период (мкс), обычно 100000 */
	__s64 cgroup_cpu_nr_periods;	 /* общее число периодов планирования */
	__s64 cgroup_cpu_nr_throttled;	 /* периоды, в которых происходило троттлинг */
	__s64 cgroup_cpu_throttled_usec; /* суммарное время троттлинга (мкс) */
	__s64 cgroup_pids_current;

	/* ── метрики отслеживания файлов ─────────────────────────────── */
	char file_path[FILE_PATH_MAX];	   /* путь к файлу (4096) */
	char file_new_path[FILE_PATH_MAX]; /* rename: новый путь (4096) */
	__u32 file_flags;
	__u64 file_read_bytes;
	__u64 file_write_bytes;
	__u32 file_open_count;
	__u32 file_fsync_count;
	__u32 file_chmod_mode; /* chmod: новый mode (octal) */
	__u32 file_chown_uid;  /* chown: новый uid */
	__u32 file_chown_gid;  /* chown: новый gid */

	/* ── метрики отслеживания сети (только EVENT_NET_CLOSE) ────── */
	char net_local_addr[EV_ADDR_LEN];  /* форматированная строка IP */
	char net_remote_addr[EV_ADDR_LEN]; /* форматированная строка IP */
	__u16 net_local_port;
	__u16 net_remote_port;
	__u64 net_conn_tx_bytes; /* байт отправлено через это соединение */
	__u64 net_conn_rx_bytes; /* байт получено через это соединение */
	__u64 net_conn_tx_calls; /* количество вызовов sendmsg */
	__u64 net_conn_rx_calls; /* количество вызовов recvmsg */
	__u64 net_duration_ms;	 /* длительность соединения в миллисекундах */

	/* ── идентификация ───────────────────────────────────────── */
	__u32 loginuid;	 /* audit loginuid (4294967295 = не задан) */
	__u32 sessionid; /* идентификатор audit-сессии */
	__u32 euid;	 /* эффективный UID */
	__u32 tty_nr;	 /* управляющий терминал (major<<8|minor), 0 = отсутствует */

	/* ── планировщик ─────────────────────────────────────────── */
	__u32 sched_policy; /* SCHED_NORMAL=0, SCHED_FIFO=1, ... */

	/* ── учёт ввода-вывода (включая page cache) ─────────────── */
	__u64 io_rchar;	      /* всего байт прочитано (вкл. кеш) */
	__u64 io_wchar;	      /* всего байт записано (вкл. кеш) */
	__u64 io_syscr;	      /* количество системных вызовов чтения */
	__u64 io_syscw;	      /* количество системных вызовов записи */
	__u64 file_opens;     /* кумулятивный: кол-во openat вызовов */
	__u64 socket_creates; /* кумулятивный: кол-во socket() вызовов */

	/* ── номера inode пространств имён ──────────────────────── */
	__u32 mnt_ns_inum;    /* пространство имён монтирования */
	__u32 pid_ns_inum;    /* пространство имён PID */
	__u32 net_ns_inum;    /* сетевое пространство имён */
	__u32 cgroup_ns_inum; /* пространство имён cgroup */

	/* ── отслеживание вытеснения (только snapshot) ──────────── */
	__u32 preempted_by_pid;		  /* tgid последнего вытеснителя */
	char preempted_by_comm[COMM_LEN]; /* comm последнего вытеснителя */

	/* ── файловая система ────────────────────────────────────── */
	char pwd[EV_PWD_LEN]; /* текущий рабочий каталог */

	/* ── отслеживание сигналов (только EVENT_SIGNAL) ─────────── */
	__u32 sig_num;			/* номер сигнала (SIGKILL=9 и т.д.) */
	__u32 sig_target_pid;		/* PID процесса-получателя сигнала */
	char sig_target_comm[COMM_LEN]; /* comm процесса-получателя */
	__s32 sig_code;			/* SI_USER=0, SI_KERNEL=0x80 и т.д. */
	__s32 sig_result;		/* 0 = успешно доставлен */

	/* ── отслеживание безопасности ────────────────────────────── */
	/* TCP-ретрансмиссия (EVENT_TCP_RETRANSMIT) */
	char sec_local_addr[EV_ADDR_LEN];  /* форматированная строка IP */
	char sec_remote_addr[EV_ADDR_LEN]; /* форматированная строка IP */
	__u16 sec_local_port;
	__u16 sec_remote_port;
	__u8 sec_af;	    /* AF_INET=2, AF_INET6=10 */
	__u8 sec_tcp_state; /* состояние TCP на момент ретрансмиссии */
	__u8 sec_direction; /* RST: 0=отправлен, 1=получен */

	/* открытые TCP-соединения (только snapshot) */
	__u64 open_tcp_conns;

	/* ── использование диска (только событие disk_usage) ─────────── */
	__u64 disk_total_bytes;
	__u64 disk_used_bytes;
	__u64 disk_avail_bytes;

	/* ── цепочка предков процесса ────────────────────────────────── */
	__u32 parent_pids[EV_PARENT_PIDS_MAX]; /* [ppid, ppid's parent, ..., 1] */
	__u8 parent_pids_len;		       /* число валидных элементов */
};

/* ── запись файла событий (hostname + событие) ───────────────────── */

#define EF_HOSTNAME_LEN 256

struct ef_record {
	char hostname[EF_HOSTNAME_LEN];
	struct metric_event event;
};

/* ── публичный API ───────────────────────────────────────────────── */

/*
 * Инициализация кольцевого буфера в памяти.
 * max_size_bytes: общий бюджет памяти (делится на sizeof(ef_record)
 * для получения ёмкости). 0 = по умолчанию (256 МБ).
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int ef_init(__u64 max_size_bytes);

/*
 * Добавить одно событие в кольцевой буфер (потокобезопасно, без блокировок для читателей).
 * Если буфер заполнен, самая старая запись перезаписывается.
 */
void ef_append(const struct metric_event *ev, const char *hostname);

/*
 * API итерации для чтения записей из кольцевого буфера.
 *
 * ef_read_begin() делает согласованный снимок head/tail,
 * возвращает непрозрачный итератор и количество доступных записей.
 *
 * ef_read_next() возвращает следующую запись или NULL, когда записи исчерпаны.
 *
 * ef_read_end() освобождает снимок. Если clear=1, все записи
 * до точки снимка удаляются.
 *
 * Пример использования:
 *   struct ef_iter iter;
 *   int n = ef_read_begin(&iter);
 *   for (int i = 0; i < n; i++) {
 *       const struct ef_record *r = ef_read_next(&iter);
 *       // ... форматирование и отправка r ...
 *   }
 *   ef_read_end(&iter, clear);
 */

struct ef_iter {
	__u32 pos;	/* текущая позиция чтения в кольце */
	__u32 end;	/* конечная позиция (не включительно) */
	__u32 capacity; /* ёмкость кольца */
	int count;	/* общее количество записей для чтения */
	int read;	/* уже прочитанных записей */
};

int ef_read_begin(struct ef_iter *it);
const struct ef_record *ef_read_next(struct ef_iter *it);
void ef_read_end(struct ef_iter *it, int clear);

/*
 * Блокировка пакета: не позволяет ef_read_begin() увидеть неполный пакет.
 *
 * Использование: вызовите ef_batch_lock() перед серией вызовов ef_append()
 * (например, в цикле snapshot) и ef_batch_unlock() после.
 */
void ef_batch_lock(void);
void ef_batch_unlock(void);

/*
 * Очистка: освобождение памяти кольцевого буфера.
 */
void ef_cleanup(void);

#endif /* EVENT_FILE_H */
