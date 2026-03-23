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
	EVENT_FORK     = 1,
	EVENT_EXEC     = 2,
	EVENT_EXIT     = 3,
	EVENT_OOM_KILL = 4,
};

/*
 * Per-process metrics, updated on sched_switch.
 * Key: tgid (__u32)
 */
struct proc_info {
	__u32 tgid;
	__u32 ppid;
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
};

#endif /* PROCESS_METRICS_COMMON_H */
