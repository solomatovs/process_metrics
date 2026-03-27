/* SPDX-License-Identifier: GPL-2.0 */
/*
 * process_metrics_common.h — shared types between BPF and userspace
 */

#ifndef PROCESS_METRICS_COMMON_H
#define PROCESS_METRICS_COMMON_H

#ifndef __bpf__
#include <linux/types.h>
#endif

#define COMM_LEN        16
#define CMDLINE_MAX     256   /* must be power of 2 */
#define MAX_PROCS       65536
/*
 * Размеры кольцевых буферов для передачи событий из BPF в userspace.
 * Три раздельных буфера — каждый под свой тип событий:
 *
 *   events      — fork/exec/exit/oom_kill (struct event, ~450 байт)
 *   events_file — закрытие файлов (struct file_event, ~300 байт)
 *   events_net  — сетевые и signal события (~60–120 байт)
 *
 * Параметризация через количество событий при компиляции:
 *   -DRINGBUF_PROC_EVENTS=4096  (по умолчанию 2048)
 *   -DRINGBUF_FILE_EVENTS=4096  (по умолчанию 2048)
 *   -DRINGBUF_NET_EVENTS=4096   (по умолчанию 2048)
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
#define RINGBUF_PROC_EVENTS  4096
#endif
#ifndef RINGBUF_FILE_EVENTS
#define RINGBUF_FILE_EVENTS  4096
#endif
#ifndef RINGBUF_NET_EVENTS
#define RINGBUF_NET_EVENTS   4096
#endif

/* Размер слота: sizeof(struct) + заголовок, округлено вверх до степени двойки */
#define _RINGBUF_PROC_SLOT   512   /* struct event ~450 + 8 */
#define _RINGBUF_FILE_SLOT   512   /* struct file_event ~300 + 8 */
#define _RINGBUF_NET_SLOT    256   /* struct net_event ~120 + 8 (макс. из сетевых) */

#define RINGBUF_PROC_SIZE  _RINGBUF_POW2(RINGBUF_PROC_EVENTS * _RINGBUF_PROC_SLOT)
#define RINGBUF_FILE_SIZE  _RINGBUF_POW2(RINGBUF_FILE_EVENTS * _RINGBUF_FILE_SLOT)
#define RINGBUF_NET_SIZE   _RINGBUF_POW2(RINGBUF_NET_EVENTS  * _RINGBUF_NET_SLOT)

/*
 * Счётчики потерь событий в ring buffer'ах.
 * Инкрементируются в BPF при неудачном bpf_ringbuf_reserve (буфер переполнен).
 * Читаются из userspace для диагностики.
 */
struct ringbuf_stats {
	__u64 drop_proc;       /* потери в events_proc */
	__u64 drop_file;       /* потери в events_file */
	__u64 drop_net;        /* потери в events_net */
	__u64 drop_cgroup;     /* потери в events_cgroup */
	__u64 total_proc;      /* всего событий proc */
	__u64 total_file;      /* всего событий file */
	__u64 total_net;       /* всего событий net */
	__u64 total_cgroup;    /* всего событий cgroup */
};

/*
 * Rate limiting state for exec events.
 * Single-element array map, tracks events per 1-second window.
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
	EVENT_NET_CLOSE      = 6,
	EVENT_SIGNAL         = 7,
	EVENT_TCP_RETRANSMIT = 8,
	EVENT_SYN_RECV       = 9,
	EVENT_RST            = 10,
	/* cgroup lifecycle events */
	EVENT_CGROUP_MKDIR           = 20,
	EVENT_CGROUP_RMDIR           = 21,
	EVENT_CGROUP_RENAME          = 22,
	EVENT_CGROUP_RELEASE         = 23,
	/* cgroup process migration */
	EVENT_CGROUP_ATTACH_TASK     = 24,
	EVENT_CGROUP_TRANSFER_TASKS  = 25,
	/* cgroup state */
	EVENT_CGROUP_POPULATED       = 26,
	EVENT_CGROUP_FREEZE          = 27,
	EVENT_CGROUP_UNFREEZE        = 28,
	EVENT_CGROUP_FROZEN          = 29,
};

/* ── cgroup tracking ─────────────────────────────────────────────── */

#define CGROUP_PATH_MAX  256

/*
 * Ring buffer size for cgroup events.
 * Cgroup events are rare (container start/stop, process migration),
 * so a small buffer is sufficient.
 */
#ifndef RINGBUF_CGROUP_EVENTS
#define RINGBUF_CGROUP_EVENTS  256
#endif
#define _RINGBUF_CGROUP_SLOT  512   /* struct cgroup_event ~290 + 8 */
#define RINGBUF_CGROUP_SIZE  _RINGBUF_POW2(RINGBUF_CGROUP_EVENTS * _RINGBUF_CGROUP_SLOT)

/*
 * Cgroup event — sent from BPF to userspace via dedicated ring buffer.
 * First field is __u32 type (EVENT_CGROUP_*), same dispatch convention.
 */
struct cgroup_event {
	__u32 type;              /* EVENT_CGROUP_* */
	__u64 id;                /* cgroup inode (matches bpf_get_current_cgroup_id) */
	__u32 level;             /* depth in hierarchy */
	__u32 pid;               /* for attach/transfer — which PID moved */
	__s32 val;               /* for populated/frozen — 1/0 */
	__u64 timestamp_ns;
	char  path[CGROUP_PATH_MAX]; /* path within cgroup hierarchy */
	char  comm[COMM_LEN];        /* for attach/transfer — process name */
};

/* ── file tracking constants ──────────────────────────────────────── */

#define FILE_PATH_MAX    256
#define FILE_MAX_PREFIXES 16
#define FILE_PREFIX_LEN  128

/*
 * Configuration pushed from userspace to BPF via maps.
 */
struct file_config {
	__u8  enabled;       /* 1 = track open/close */
	__u8  track_bytes;   /* 1 = also track read/write bytes per fd */
};

/*
 * Prefix entry for include/exclude lists.
 * Stored in BPF array maps, matched with unrolled loops.
 * Layout: len first, then prefix — keeps struct size a power-of-2 (128+1→
 * padded poorly). With len at offset 0, struct size = 1 + FILE_PREFIX_LEN = 129
 * but the verifier on 5.15 needs the value_size to be friendly.
 * So we shrink prefix by 1 to get exactly 128 bytes total.
 */
#define FILE_PREFIX_CAP  (FILE_PREFIX_LEN - 1)  /* 127: usable prefix bytes */

struct file_prefix {
	__u8  len;           /* actual length (0 = unused slot) */
	char  prefix[FILE_PREFIX_CAP];
};

/*
 * Temporary storage for openat() args between enter and exit.
 * Key: pid_tgid (__u64)
 */
struct openat_args {
	char  path[FILE_PATH_MAX];
	int   flags;
};

/*
 * Temporary storage for read/write args between enter and exit.
 * Key: pid_tgid (__u64)
 */
struct rw_args {
	int   fd;
};

/*
 * Per-fd tracking state in fd_map.
 * Key: struct fd_key { __u32 tgid; int fd; }
 */
struct fd_key {
	__u32 tgid;
	__s32 fd;
};

struct fd_info {
	char  path[FILE_PATH_MAX];
	int   flags;
	__u64 read_bytes;
	__u64 write_bytes;
	__u32 open_count;    /* how many times this fd was opened */
};

/*
 * File close event — sent from BPF to userspace via ring buffer.
 * First field is __u32 type (= EVENT_FILE_CLOSE), same offset as struct event,
 * so the ring buffer callback can dispatch on type.
 */
struct file_event {
	__u32 type;           /* EVENT_FILE_CLOSE */
	__u32 tgid;
	__u32 ppid;
	__u32 uid;            /* real UID of the process */
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	char  path[FILE_PATH_MAX];
	int   flags;
	__u64 read_bytes;
	__u64 write_bytes;
	__u32 open_count;
};

/*
 * Per-process metrics, updated on sched_switch.
 * Key: tgid (__u32)
 */
struct proc_info {
	__u32 tgid;
	__u32 ppid;
	__u32 uid;               /* real UID of the process */
	__u64 start_ns;          /* task->start_time (CLOCK_MONOTONIC ns) */
	__u64 cpu_ns;            /* signal->{utime+stime} + leader->{utime+stime} */
	__u64 rss_pages;         /* current RSS in pages */
	__u64 rss_min_pages;     /* min observed RSS in pages */
	__u64 rss_max_pages;     /* max observed RSS in pages */
	__u64 shmem_pages;       /* MM_SHMEMPAGES (shared memory) */
	__u64 swap_pages;        /* MM_SWAPENTS (swap usage) */
	__u64 io_read_bytes;     /* ioac.read_bytes (actual disk reads) */
	__u64 io_write_bytes;    /* ioac.write_bytes (actual disk writes) */
	__u64 maj_flt;           /* major page faults (disk reads) */
	__u64 min_flt;           /* minor page faults */
	__u64 nvcsw;             /* voluntary context switches */
	__u64 nivcsw;            /* involuntary context switches */
	__u8  oom_killed;        /* 1 if killed by OOM killer */
	__u32 exit_code;         /* task->exit_code (set on exit) */
	__u64 vsize_pages;       /* mm->total_vm */
	__u32 threads;           /* signal->nr_threads */
	__s16 oom_score_adj;     /* signal->oom_score_adj */
	__u64 cgroup_id;         /* cgroup v2 inode */
	__u8  state;             /* process state: 'R','S','D','T','Z',... */
	__u64 net_tx_bytes;      /* TCP+UDP bytes sent */
	__u64 net_rx_bytes;      /* TCP+UDP bytes received */
	char  comm[COMM_LEN];
	char  cmdline[CMDLINE_MAX];
	__u16 cmdline_len;

	/* ── identity ────────────────────────────────────────────── */
	__u32 loginuid;          /* audit loginuid (4294967295 = unset) */
	__u32 sessionid;         /* audit session id */
	__u32 euid;              /* effective UID (cred->euid) */
	__u32 tty_nr;            /* controlling terminal (major<<8|minor), 0 = none */

	/* ── scheduler ───────────────────────────────────────────── */
	__u32 sched_policy;      /* SCHED_NORMAL=0, SCHED_FIFO=1, SCHED_RR=2, ... */

	/* ── I/O accounting (includes page cache) ────────────────── */
	__u64 io_rchar;          /* total bytes read (incl. cache) */
	__u64 io_wchar;          /* total bytes written (incl. cache) */
	__u64 io_syscr;          /* read syscall count */
	__u64 io_syscw;          /* write syscall count */

	/* ── namespace inums ─────────────────────────────────────── */
	__u32 mnt_ns_inum;       /* mount namespace */
	__u32 pid_ns_inum;       /* PID namespace */
	__u32 net_ns_inum;       /* network namespace */
	__u32 cgroup_ns_inum;    /* cgroup namespace */

	/* ── preemption tracking ─────────────────────────────────── */
	__u32 preempted_by_pid;  /* tgid of last preemptor (involuntary switch) */
	char  preempted_by_comm[COMM_LEN]; /* comm of last preemptor (resolved to main thread) */
	__u64 preempted_by_cgroup_id;      /* cgroup of last preemptor */
};

/*
 * TID → TGID+comm mapping for preemption resolution.
 * Allows resolving thread names (ThreadPool, Worker-N, etc.)
 * to their parent process comm (clickhouse-serv, java, etc.).
 * Compatible with kernel 5.x (no bpf_task_from_pid needed).
 */
struct tid_info {
	__u32 tgid;
	char  comm[COMM_LEN];    /* comm of the main thread (group leader) */
};

/*
 * Tracking metadata, managed by userspace + inherited on fork.
 * Key: tgid (__u32)
 */
struct track_info {
	__u32 root_pid;
	__u16 rule_id;
	__u8  is_root;
	__u8  _pad;       /* explicit padding — kernel 5.15 verifier requires all stack bytes initialized */
};

/*
 * Ring buffer event — sent from BPF to userspace on fork/exec/exit.
 */
struct event {
	__u32 type;              /* enum event_type */
	__u32 tgid;
	__u32 ppid;
	__u32 uid;               /* real UID of the process */
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  comm[COMM_LEN];
	char  cmdline[CMDLINE_MAX];
	__u16 cmdline_len;
	/* tracking info (copied from tracked_map before deletion) */
	__u32 root_pid;
	__u16 rule_id;
	/* exit-specific final metrics */
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

	/* ── identity ────────────────────────────────────────────── */
	__u32 loginuid;
	__u32 sessionid;
	__u32 euid;
	__u32 tty_nr;

	/* ── scheduler ───────────────────────────────────────────── */
	__u32 sched_policy;

	/* ── I/O accounting ──────────────────────────────────────── */
	__u64 io_rchar;
	__u64 io_wchar;
	__u64 io_syscr;
	__u64 io_syscw;

	/* ── namespace inums ─────────────────────────────────────── */
	__u32 mnt_ns_inum;
	__u32 pid_ns_inum;
	__u32 net_ns_inum;
	__u32 cgroup_ns_inum;
};

/* ── network tracking constants ──────────────────────────────────── */

#define NET_MAX_SOCKETS  65536

/*
 * Configuration pushed from userspace to BPF via maps.
 */
struct net_config {
	__u8  enabled;       /* 1 = track connect/accept/close */
	__u8  track_bytes;   /* 1 = also track send/recv bytes per socket */
};

/*
 * Temporary storage for tcp_v4_connect / tcp_v6_connect args.
 * Key: pid_tgid (__u64)
 */
struct connect_args {
	__u64 sock_ptr;      /* struct sock * */
};

/*
 * Temporary storage for tcp_sendmsg / tcp_recvmsg args.
 * Key: pid_tgid (__u64)
 */
struct sendmsg_args {
	__u64 sock_ptr;      /* struct sock * */
};

/*
 * Per-socket tracking state in sock_map.
 * Key: sock pointer (__u64)
 */
struct sock_info {
	__u32 tgid;
	__u32 uid;
	__u8  af;             /* AF_INET=2, AF_INET6=10 */
	__u8  local_addr[16]; /* IPv4 in first 4 bytes, or full IPv6 */
	__u8  remote_addr[16];
	__u16 local_port;     /* host byte order */
	__u16 remote_port;    /* host byte order */
	__u64 tx_bytes;
	__u64 rx_bytes;
	__u64 start_ns;       /* connection start time (boot ns) */
};

/*
 * Network close event — sent from BPF to userspace via ring buffer.
 * First field is __u32 type (= EVENT_NET_CLOSE), same dispatch as others.
 */
struct net_event {
	__u32 type;           /* EVENT_NET_CLOSE */
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
	__u64 duration_ns;    /* how long the connection was open */
};

/*
 * Signal event — sent from BPF to userspace when a signal is delivered.
 * Captures sender (current task) and target info from the tracepoint.
 */
struct signal_event {
	__u32 type;           /* EVENT_SIGNAL */
	__u32 sender_tgid;    /* sender PID */
	__u32 sender_uid;     /* sender UID */
	__u32 target_pid;     /* target PID (from tracepoint) */
	__u64 timestamp_ns;
	__u64 cgroup_id;
	char  sender_comm[COMM_LEN];
	int   sig;            /* signal number (SIGKILL=9, etc.) */
	int   sig_code;       /* SI_USER=0, SI_KERNEL=0x80, etc. */
	int   sig_result;     /* 0 = delivered successfully */
};

/* ── security tracking ────────────────────────────────────────────── */

/*
 * Configuration for security probes (pushed from userspace to BPF).
 */
struct sec_config {
	__u8 tcp_retransmit;     /* 1 = track TCP retransmissions */
	__u8 syn_tracking;       /* 1 = track SYN-recv events */
	__u8 rst_tracking;       /* 1 = track RST events */
	__u8 udp_tracking;       /* 1 = aggregate UDP packets */
	__u8 icmp_tracking;      /* 1 = aggregate ICMP packets */
	__u8 open_conn_count;    /* 1 = count open TCP connections */
};

/*
 * TCP retransmit event — per-event, sent via ringbuf.
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
	__u8  state;          /* TCP state at retransmit time */
};

/*
 * SYN-recv event — incoming TCP SYN (half-open connection).
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
 * RST event — TCP reset sent or received.
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
	__u8  direction;      /* 0 = sent, 1 = received */
};

/*
 * UDP aggregation (BPF map, flushed by userspace on snapshot).
 */
struct udp_agg_key {
	__u32 tgid;
	__u8  af;
	__u8  remote_addr[16];
	__u16 remote_port;
};

struct udp_agg_val {
	__u64 tx_packets;
	__u64 rx_packets;
	__u64 tx_bytes;
	__u64 rx_bytes;
};

/*
 * ICMP aggregation (BPF map, flushed by userspace on snapshot).
 */
struct icmp_agg_key {
	__u8  src_addr[16];
	__u8  icmp_type;
	__u8  icmp_code;
};

struct icmp_agg_val {
	__u64 count;
};

#endif /* PROCESS_METRICS_COMMON_H */
