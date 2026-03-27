/*
 * event_file.h — in-memory ring buffer for metric events
 *
 * Accumulates metric_event records in a fixed-size ring buffer in memory.
 * Old records are overwritten when the buffer is full (ring semantics).
 *
 * Two access modes via HTTP:
 *   GET /metrics              — snapshot: iterate all records (read-only)
 *   GET /metrics?clear=1      — consume: iterate all records, then clear
 */

#ifndef EVENT_FILE_H
#define EVENT_FILE_H

#include <linux/types.h>
#include "process_metrics_common.h"

/* ── metric_event field sizes ────────────────────────────────────── */

#define EV_EVENT_TYPE_LEN  12    /* "fork","exec","exit","oom_kill","snapshot","file_close" */
#define EV_RULE_LEN        64   /* rule name */
#define EV_TAGS_LEN        512  /* pipe-separated list of all matched rules */
#define EV_CGROUP_LEN      512  /* cgroup path */
#define EV_ADDR_LEN        46   /* formatted IP string (INET6_ADDRSTRLEN) */
#define EV_PWD_LEN         512  /* current working directory */

/*
 * CSV escape worst case: every char doubled + 2 quotes + NUL.
 * ESC(n) = (n) * 2 + 3
 */
#define EV_ESC_SIZE(n) ((n) * 2 + 3)

/* ── metric event (shared by event_file, http_server, main) ──────── */

struct metric_event {
	/* ── common fields ─────────────────────────────────────────── */
	__u64 timestamp_ns;
	char  event_type[EV_EVENT_TYPE_LEN];
	char  rule[EV_RULE_LEN];
	char  tags[EV_TAGS_LEN];     /* pipe-separated list of all matched rules */
	__u32 root_pid;
	__u32 pid;
	__u32 ppid;
	__u32 uid;                    /* real UID of the process */
	char  comm[COMM_LEN];
	char  exec_path[CMDLINE_MAX]; /* executable path (argv[0]) */
	char  args[CMDLINE_MAX];      /* arguments (argv[1..]) */
	char  cgroup[EV_CGROUP_LEN];
	__u8  is_root;
	__u8  state;

	/* ── process metrics ───────────────────────────────────────── */
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
	__u8  oom_killed;
	__u64 net_tx_bytes;
	__u64 net_rx_bytes;
	__u64 start_time_ns;
	__u64 uptime_seconds;

	/* ── cgroup v2 metrics (-1 = not available) ────────────────── */
	__s64 cgroup_memory_max;
	__s64 cgroup_memory_current;
	__s64 cgroup_swap_current;
	__s64 cgroup_cpu_weight;
	__s64 cgroup_cpu_max;           /* quota per period (usec), 0 = "max" (unlimited) */
	__s64 cgroup_cpu_max_period;    /* period (usec), typically 100000 */
	__s64 cgroup_cpu_nr_periods;    /* total scheduling periods */
	__s64 cgroup_cpu_nr_throttled;  /* periods where throttling occurred */
	__s64 cgroup_cpu_throttled_usec; /* total throttled time (usec) */
	__s64 cgroup_pids_current;

	/* ── file tracking metrics (EVENT_FILE_CLOSE only) ─────────── */
	char  file_path[FILE_PATH_MAX];
	__u32 file_flags;
	__u64 file_read_bytes;
	__u64 file_write_bytes;
	__u32 file_open_count;

	/* ── network tracking metrics (EVENT_NET_CLOSE only) ───────── */
	char  net_local_addr[EV_ADDR_LEN];   /* formatted IP string */
	char  net_remote_addr[EV_ADDR_LEN];  /* formatted IP string */
	__u16 net_local_port;
	__u16 net_remote_port;
	__u64 net_conn_tx_bytes;    /* bytes sent on this connection */
	__u64 net_conn_rx_bytes;    /* bytes received on this connection */
	__u64 net_duration_ms;      /* connection duration in milliseconds */

	/* ── identity ─────────────────────────────────────────────── */
	__u32 loginuid;             /* audit loginuid (4294967295 = unset) */
	__u32 sessionid;            /* audit session id */
	__u32 euid;                 /* effective UID */
	__u32 tty_nr;               /* controlling terminal (major<<8|minor), 0 = none */

	/* ── scheduler ────────────────────────────────────────────── */
	__u32 sched_policy;         /* SCHED_NORMAL=0, SCHED_FIFO=1, ... */

	/* ── I/O accounting (includes page cache) ─────────────────── */
	__u64 io_rchar;             /* total bytes read (incl. cache) */
	__u64 io_wchar;             /* total bytes written (incl. cache) */
	__u64 io_syscr;             /* read syscall count */
	__u64 io_syscw;             /* write syscall count */

	/* ── namespace inums ──────────────────────────────────────── */
	__u32 mnt_ns_inum;          /* mount namespace */
	__u32 pid_ns_inum;          /* PID namespace */
	__u32 net_ns_inum;          /* network namespace */
	__u32 cgroup_ns_inum;       /* cgroup namespace */

	/* ── preemption tracking (snapshot only) ─────────────────── */
	__u32 preempted_by_pid;     /* tgid of last preemptor */
	char  preempted_by_comm[COMM_LEN]; /* comm of last preemptor */

	/* ── filesystem ───────────────────────────────────────────── */
	char  pwd[EV_PWD_LEN];      /* current working directory */

	/* ── signal tracking (EVENT_SIGNAL only) ──────────────────── */
	__u32 sig_num;              /* signal number (SIGKILL=9, etc.) */
	__u32 sig_target_pid;       /* target PID that received the signal */
	char  sig_target_comm[COMM_LEN]; /* target process comm */
	__s32 sig_code;             /* SI_USER=0, SI_KERNEL=0x80, etc. */
	__s32 sig_result;           /* 0 = delivered successfully */

	/* ── security tracking ────────────────────────────────────── */
	/* TCP retransmit (EVENT_TCP_RETRANSMIT) */
	char  sec_local_addr[EV_ADDR_LEN];   /* formatted IP string */
	char  sec_remote_addr[EV_ADDR_LEN];  /* formatted IP string */
	__u16 sec_local_port;
	__u16 sec_remote_port;
	__u8  sec_af;               /* AF_INET=2, AF_INET6=10 */
	__u8  sec_tcp_state;        /* TCP state at retransmit time */
	__u8  sec_direction;        /* RST: 0=sent, 1=received */

	/* open TCP connections (snapshot only) */
	__u64 open_tcp_conns;

	/* ── disk usage (disk_usage event only) ──────────────────────── */
	__u64 disk_total_bytes;
	__u64 disk_used_bytes;
	__u64 disk_avail_bytes;
};

/* ── event file record (hostname + event) ────────────────────────── */

#define EF_HOSTNAME_LEN 256

struct ef_record {
	char               hostname[EF_HOSTNAME_LEN];
	struct metric_event event;
};

/* ── public API ──────────────────────────────────────────────────── */

/*
 * Initialize in-memory ring buffer.
 * max_size_bytes: total memory budget (divided by sizeof(ef_record)
 * to get capacity). 0 = default (256 MB).
 * Returns 0 on success, -1 on error.
 */
int ef_init(__u64 max_size_bytes);

/*
 * Append one event to the ring buffer (thread-safe, lock-free for readers).
 * If the buffer is full, the oldest record is overwritten.
 */
void ef_append(const struct metric_event *ev, const char *hostname);

/*
 * Iteration API for reading records from the ring buffer.
 *
 * ef_read_begin() takes a consistent snapshot of head/tail,
 * returns an opaque iterator and the number of records available.
 *
 * ef_read_next() returns the next record or NULL when exhausted.
 *
 * ef_read_end() releases the snapshot. If clear=1, all records
 * up to the snapshot point are discarded.
 *
 * Usage:
 *   struct ef_iter iter;
 *   int n = ef_read_begin(&iter);
 *   for (int i = 0; i < n; i++) {
 *       const struct ef_record *r = ef_read_next(&iter);
 *       // ... format and send r ...
 *   }
 *   ef_read_end(&iter, clear);
 */

struct ef_iter {
	__u32 pos;       /* current read position in ring */
	__u32 end;       /* end position (exclusive) */
	__u32 capacity;  /* ring capacity */
	int   count;     /* total records to read */
	int   read;      /* records already read */
};

int ef_read_begin(struct ef_iter *it);
const struct ef_record *ef_read_next(struct ef_iter *it);
void ef_read_end(struct ef_iter *it, int clear);

/*
 * Batch lock: prevents ef_read_begin() from seeing a partial batch.
 *
 * Usage: call ef_batch_lock() before a series of ef_append() calls
 * (e.g. the snapshot loop) and ef_batch_unlock() after.
 */
void ef_batch_lock(void);
void ef_batch_unlock(void);

/*
 * Clean up: free the ring buffer.
 */
void ef_cleanup(void);

#endif /* EVENT_FILE_H */
