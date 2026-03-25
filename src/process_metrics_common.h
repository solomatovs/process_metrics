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
#define RINGBUF_SIZE    (1 << 20)  /* 1 MB */

/*
 * Rate limiting state for exec events.
 * Single-element array map, tracks events per 1-second window.
 */
struct rate_state {
	__u64 window_ns;
	__u64 count;
};

enum event_type {
	EVENT_FORK       = 1,
	EVENT_EXEC       = 2,
	EVENT_EXIT       = 3,
	EVENT_OOM_KILL   = 4,
	EVENT_FILE_CLOSE = 5,
	EVENT_NET_CLOSE  = 6,
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
};

/*
 * Tracking metadata, managed by userspace + inherited on fork.
 * Key: tgid (__u32)
 */
struct track_info {
	__u32 root_pid;
	__u16 rule_id;
	__u8  is_root;
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

#endif /* PROCESS_METRICS_COMMON_H */
