// SPDX-License-Identifier: GPL-2.0
/*
 * process_metrics.bpf.c — event-driven process metrics via BPF
 *
 * Tracepoints:
 *   sched_process_exec  → capture pid, cmdline, comm, cgroup
 *   sched_process_fork  → inherit tracking from parent (raw_tp)
 *   sched_switch        → update rss, cpu, vsize for tracked PIDs
 *   sched_process_exit  → finalize metrics, send to userspace
 *   mark_victim         → OOM killer selected process (raw_tp)
 *
 * Maps:
 *   proc_map    — per-process live metrics    (hash: tgid → proc_info)
 *   tracked_map — tracking metadata           (hash: tgid → track_info)
 *   events      — lifecycle events ring buffer
 *
 * Userspace manages tracking decisions (exec rule matching).
 * BPF only collects data for tracked PIDs and sends lifecycle events.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "process_metrics_common.h"

/* ── rodata (configurable from userspace before load) ─────────────── */

/* Max exec events per second sent to ring buffer. 0 = unlimited. */
volatile const __u32 max_exec_events_per_sec = 0;

/* ── maps ─────────────────────────────────────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, struct proc_info);
} proc_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, struct track_info);
} tracked_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_state);
} exec_rate SEC(".maps");

/* ── rate limiter ─────────────────────────────────────────────────── */

/*
 * Per-second sliding window rate limiter for exec events.
 * Returns 1 if event should be emitted, 0 if rate exceeded.
 * Slightly racy on multi-CPU (counter may overshoot), acceptable.
 */
static __always_inline int exec_rate_check(void)
{
	__u32 key = 0;
	struct rate_state *rs;

	if (!max_exec_events_per_sec)
		return 1;

	rs = bpf_map_lookup_elem(&exec_rate, &key);
	if (!rs)
		return 1;

	__u64 now = bpf_ktime_get_ns();

	/* New 1-second window — reset counter */
	if (now - rs->window_ns >= 1000000000ULL) {
		rs->window_ns = now;
		rs->count = 1;
		return 1;
	}

	rs->count++;
	return rs->count <= max_exec_events_per_sec;
}

/* ── helpers ──────────────────────────────────────────────────────── */

struct mem_info {
	__u64 rss_pages;    /* file + anon + shmem */
	__u64 shmem_pages;  /* shared memory only */
	__u64 swap_pages;   /* swap entries */
};

static __always_inline struct mem_info read_mem_pages(struct task_struct *task)
{
	struct mem_info mi = {0};
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return mi;

	/* MM_FILEPAGES=0, MM_ANONPAGES=1, MM_SWAPENTS=2, MM_SHMEMPAGES=3 */
	long v0 = 0, v1 = 0, v2 = 0, v3 = 0;
	bpf_core_read(&v0, sizeof(v0), &mm->rss_stat.count[0].counter);
	bpf_core_read(&v1, sizeof(v1), &mm->rss_stat.count[1].counter);
	bpf_core_read(&v2, sizeof(v2), &mm->rss_stat.count[2].counter);
	bpf_core_read(&v3, sizeof(v3), &mm->rss_stat.count[3].counter);

	long total = v0 + v1 + v3;
	mi.rss_pages   = total > 0 ? (__u64)total : 0;
	mi.shmem_pages = v3 > 0 ? (__u64)v3 : 0;
	mi.swap_pages  = v2 > 0 ? (__u64)v2 : 0;
	return mi;
}

static __always_inline __u64 read_cpu_ns(struct task_struct *task)
{
	/*
	 * signal->{utime,stime} accumulates CPU of dead threads.
	 * Add group_leader's live CPU for an approximation.
	 * Exact for single-threaded processes.
	 */
	__u64 u = BPF_CORE_READ(task, signal, utime);
	__u64 s = BPF_CORE_READ(task, signal, stime);

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		u += BPF_CORE_READ(leader, utime);
		s += BPF_CORE_READ(leader, stime);
	}
	return u + s;
}

static __always_inline __u64 read_vsize_pages(struct task_struct *task)
{
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	return mm ? (__u64)BPF_CORE_READ(mm, total_vm) : 0;
}

static __always_inline __u32 read_nr_threads(struct task_struct *task)
{
	return (__u32)BPF_CORE_READ(task, signal, nr_threads);
}

static __always_inline __s16 read_oom_score_adj(struct task_struct *task)
{
	return (__s16)BPF_CORE_READ(task, signal, oom_score_adj);
}

/*
 * IO accounting: actual disk bytes read/written.
 * task->ioac accumulates across all threads via signal->ioac on exit,
 * but for live threads we read from group_leader + signal.
 */
static __always_inline void read_io_bytes(struct task_struct *task,
					  __u64 *r, __u64 *w)
{
	/* signal->ioac accumulates dead threads' IO */
	*r = BPF_CORE_READ(task, signal, ioac.read_bytes);
	*w = BPF_CORE_READ(task, signal, ioac.write_bytes);

	/* Add group_leader's live IO */
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		*r += BPF_CORE_READ(leader, ioac.read_bytes);
		*w += BPF_CORE_READ(leader, ioac.write_bytes);
	}
}

/*
 * Page faults: signal accumulates dead threads, add leader's live counts.
 */
static __always_inline void read_faults(struct task_struct *task,
					__u64 *maj, __u64 *min)
{
	*maj = BPF_CORE_READ(task, signal, cmaj_flt);
	*min = BPF_CORE_READ(task, signal, cmin_flt);

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		*maj += BPF_CORE_READ(leader, maj_flt);
		*min += BPF_CORE_READ(leader, min_flt);
	}
}

/*
 * Context switches: signal accumulates dead threads, add leader's live counts.
 */
static __always_inline void read_ctxsw(struct task_struct *task,
					__u64 *vol, __u64 *invol)
{
	*vol   = BPF_CORE_READ(task, signal, nvcsw);
	*invol = BPF_CORE_READ(task, signal, nivcsw);

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		*vol   += BPF_CORE_READ(leader, nvcsw);
		*invol += BPF_CORE_READ(leader, nivcsw);
	}
}

/*
 * Convert numeric task state to ps-style character.
 * prev_state from sched_switch or task->__state.
 */
static __always_inline __u8 state_to_char(long state)
{
	if (state == 0)    return 'R'; /* TASK_RUNNING (preempted) */
	if (state & 0x01)  return 'S'; /* TASK_INTERRUPTIBLE */
	if (state & 0x02)  return 'D'; /* TASK_UNINTERRUPTIBLE */
	if (state & 0x04)  return 'T'; /* __TASK_STOPPED */
	if (state & 0x08)  return 't'; /* __TASK_TRACED */
	if (state & 0x20)  return 'Z'; /* EXIT_ZOMBIE */
	if (state & 0x10)  return 'X'; /* EXIT_DEAD */
	return '?';
}

/*
 * Read cmdline from current process mm->arg_start..arg_end
 * into dst[CMDLINE_MAX]. Returns length read.
 */
static __always_inline __u16 read_cmdline(struct task_struct *task,
					  char *dst)
{
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
	unsigned long arg_end   = BPF_CORE_READ(mm, arg_end);
	if (arg_end <= arg_start)
		return 0;

	__u64 len = arg_end - arg_start;
	if (len >= CMDLINE_MAX)
		len = CMDLINE_MAX - 1;

	/* Mask for verifier: CMDLINE_MAX is 256, so mask = 0xFF */
	len &= (CMDLINE_MAX - 1);
	bpf_probe_read_user(dst, len, (void *)arg_start);
	return (__u16)len;
}

/* ── EXEC ─────────────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Skip kernel tasks (PID 0) early */
	if (tgid == 0)
		return 0;

	/* Rate limit exec events to avoid ring buffer flooding */
	if (!exec_rate_check())
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* ppid */
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	__u32 ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;

	/* Send EXEC event — always, for rule matching in userspace */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_EXEC;
	e->tgid         = tgid;
	e->ppid         = ppid;
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	e->cgroup_id    = bpf_get_current_cgroup_id();
	e->start_ns     = BPF_CORE_READ(task, start_time);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->cmdline_len  = read_cmdline(task, e->cmdline);

	bpf_ringbuf_submit(e, 0);

	/* If already tracked (fork-inherited), refresh cmdline/comm */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info) {
		bpf_get_current_comm(info->comm, sizeof(info->comm));
		info->cgroup_id   = bpf_get_current_cgroup_id();
		info->cmdline_len = read_cmdline(task, info->cmdline);
	}

	return 0;
}

/* ── FORK (raw tracepoint to access child task_struct) ────────────── */

SEC("raw_tracepoint/sched_process_fork")
int handle_fork(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx->args[0];
	struct task_struct *child  = (struct task_struct *)ctx->args[1];

	__u32 child_pid  = BPF_CORE_READ(child, pid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);

	/* Only process forks, not thread clones */
	if (child_pid != child_tgid)
		return 0;

	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);

	/* Only notify userspace if parent is tracked */
	if (!bpf_map_lookup_elem(&tracked_map, &parent_tgid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_FORK;
	e->tgid         = child_tgid;       /* new child process */
	e->ppid         = parent_tgid;       /* parent process */
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	e->cgroup_id    = bpf_get_current_cgroup_id();
	e->start_ns     = BPF_CORE_READ(child, start_time);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	/* cmdline inherited, userspace copies from parent's proc_info */

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── SCHED_SWITCH — hot path, update metrics for tracked PIDs ─────── */

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Fast bail-out for non-tracked PIDs */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (!info)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* Memory (pages) — RSS, shared, swap */
	struct mem_info mi = read_mem_pages(task);
	info->rss_pages   = mi.rss_pages;
	info->shmem_pages = mi.shmem_pages;
	info->swap_pages  = mi.swap_pages;
	if (mi.rss_pages > 0 &&
	    (info->rss_min_pages == 0 || mi.rss_pages < info->rss_min_pages))
		info->rss_min_pages = mi.rss_pages;
	if (mi.rss_pages > info->rss_max_pages)
		info->rss_max_pages = mi.rss_pages;

	/* CPU time (ns) — approximate for multi-threaded */
	info->cpu_ns = read_cpu_ns(task);

	/* Virtual memory (pages) */
	info->vsize_pages = read_vsize_pages(task);

	/* Thread count */
	info->threads = read_nr_threads(task);

	/* OOM score adjustment */
	info->oom_score_adj = read_oom_score_adj(task);

	/* IO bytes (actual disk reads/writes) */
	read_io_bytes(task, &info->io_read_bytes, &info->io_write_bytes);

	/* Page faults */
	read_faults(task, &info->maj_flt, &info->min_flt);

	/* Context switches */
	read_ctxsw(task, &info->nvcsw, &info->nivcsw);

	/* Cgroup — may change if process is moved between cgroups */
	info->cgroup_id = bpf_get_current_cgroup_id();

	/* Process state — task->__state (kernel 5.14+) */
	unsigned int task_state = BPF_CORE_READ(task, __state);
	info->state = state_to_char(task_state);

	/* UID — refresh on each sched_switch (may change via setuid) */
	info->uid = (__u32)bpf_get_current_uid_gid();

	return 0;
}

/* ── EXIT ─────────────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid  = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Only handle thread group leader (process) exit */
	if (pid != tgid)
		return 0;

	/* Only for tracked processes */
	struct track_info *ti = bpf_map_lookup_elem(&tracked_map, &tgid);
	if (!ti)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* Send EXIT event with final metrics */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_EXIT;
	e->tgid         = tgid;
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	/* Copy tracking info before maps are deleted */
	e->root_pid = ti->root_pid;
	e->rule_id  = ti->rule_id;

	/* Final metrics snapshot */
	e->cpu_ns        = read_cpu_ns(task);
	struct mem_info exit_mi = read_mem_pages(task);
	e->rss_pages     = exit_mi.rss_pages;
	e->vsize_pages   = read_vsize_pages(task);
	e->threads       = read_nr_threads(task);
	e->oom_score_adj = read_oom_score_adj(task);
	e->exit_code     = BPF_CORE_READ(task, exit_code);

	/* Carry over min/max rss, start_ns, oom_killed from proc_info */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info) {
		e->rss_min_pages = info->rss_min_pages;
		e->rss_max_pages = info->rss_max_pages;
		e->start_ns      = info->start_ns;
		e->cgroup_id     = info->cgroup_id;
		e->ppid          = info->ppid;
		e->cmdline_len   = info->cmdline_len;
		e->oom_killed    = info->oom_killed;
		e->net_tx_bytes  = info->net_tx_bytes;
		e->net_rx_bytes  = info->net_rx_bytes;
		__builtin_memcpy(e->cmdline, info->cmdline, CMDLINE_MAX);
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&tracked_map, &tgid);
	bpf_map_delete_elem(&proc_map, &tgid);
	return 0;
}

/* ── OOM KILL — mark_victim tracepoint ─────────────────────────────── */

/*
 * mark_victim fires when OOM killer selects a process to kill.
 * raw_tracepoint args: (struct task_struct *task)
 */
SEC("raw_tracepoint/mark_victim")
int handle_mark_victim(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task = (struct task_struct *)ctx->args[0];
	__u32 tgid = BPF_CORE_READ(task, tgid);

	/* Only for tracked processes */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	/* Mark in proc_info */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		info->oom_killed = 1;

	/* Send OOM_KILL event to userspace */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_OOM_KILL;
	e->tgid         = tgid;
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm),
				  BPF_CORE_READ(task, comm));

	if (info) {
		e->ppid          = info->ppid;
		e->cgroup_id     = info->cgroup_id;
		e->rss_pages     = info->rss_pages;
		e->rss_min_pages = info->rss_min_pages;
		e->rss_max_pages = info->rss_max_pages;
		e->cpu_ns        = info->cpu_ns;
		e->start_ns      = info->start_ns;
		e->cmdline_len   = info->cmdline_len;
		__builtin_memcpy(e->cmdline, info->cmdline, CMDLINE_MAX);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── File tracking: openat/close/read/write ───────────────────────── */

/*
 * Configuration and prefix lists — populated by userspace before attach.
 * file_cfg: single-element array with enabled/track_bytes flags.
 * file_include_prefixes / file_exclude_prefixes: up to FILE_MAX_PREFIXES
 * path prefixes for filtering in BPF.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_config);
} file_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FILE_MAX_PREFIXES);
	__type(key, __u32);
	__type(value, struct file_prefix);
} file_include_prefixes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FILE_MAX_PREFIXES);
	__type(key, __u32);
	__type(value, struct file_prefix);
} file_exclude_prefixes SEC(".maps");

/* Temporary args storage between syscall enter and exit */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);    /* pid_tgid */
	__type(value, struct openat_args);
} openat_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);    /* pid_tgid */
	__type(value, struct rw_args);
} rw_args_map SEC(".maps");

/* Per-fd tracking: accumulate read/write bytes until close */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct fd_key);
	__type(value, struct fd_info);
} fd_map SEC(".maps");

/*
 * Check if path matches any prefix in include list.
 * If no include prefixes are configured (all len=0), allows everything.
 * Returns 1 if path should be included.
 */
/*
 * Compare up to 'len' bytes of two strings.
 * Returns 1 if first 'len' bytes match.
 * Uses a fixed iteration count for BPF verifier compatibility.
 */
/*
 * KERN_VER is passed from Makefile as major*100+minor (e.g. 515, 601).
 * Kernels < 5.18 have a weaker BPF verifier with a 8192 jump-sequence
 * limit.  Two nested loops (16 prefixes × N chars) inside one program
 * can exceed that budget.  We reduce PREFIX_CMP_MAX on old kernels and
 * skip #pragma unroll so the verifier stays within its limits.
 */
#ifndef KERN_VER
#define KERN_VER 600
#endif

#if KERN_VER >= 518
#define PREFIX_CMP_MAX 32
#else
#define PREFIX_CMP_MAX 20
#endif

static __always_inline int prefix_match(const char *path,
					const char *prefix, int len)
{
	if (len <= 0 || len > PREFIX_CMP_MAX)
		len = PREFIX_CMP_MAX;

	for (int j = 0; j < PREFIX_CMP_MAX; j++) {
		if (j >= len)
			return 1;
		/* Mask so the 5.15 verifier can prove the access is in-bounds.
		 * PREFIX_CMP_MAX is a power-of-two-minus-one friendly value
		 * (20 or 32), mask with 31 keeps idx < 32 < FILE_PREFIX_CAP. */
		int idx = j & 31;
		if (path[idx] != prefix[idx])
			return 0;
	}
	return 1;
}

static __always_inline int path_matches_include(const char *path)
{
	int has_any = 0;

#if KERN_VER >= 518
	#pragma unroll
#endif
	for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
		__u32 idx = i;
		struct file_prefix *fp = bpf_map_lookup_elem(
			&file_include_prefixes, &idx);
		if (!fp || fp->len == 0)
			continue;
		has_any = 1;

		if (prefix_match(path, fp->prefix, fp->len))
			return 1;
	}

	/* If no include prefixes defined, include everything */
	return !has_any;
}

/*
 * Check if path matches any prefix in exclude list.
 * Returns 1 if path should be excluded.
 */
static __always_inline int path_matches_exclude(const char *path)
{
#if KERN_VER >= 518
	#pragma unroll
#endif
	for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
		__u32 idx = i;
		struct file_prefix *fp = bpf_map_lookup_elem(
			&file_exclude_prefixes, &idx);
		if (!fp || fp->len == 0)
			continue;

		if (prefix_match(path, fp->prefix, fp->len))
			return 1;
	}
	return 0;
}

/*
 * sys_enter_openat: save path and flags for the exit handler.
 * Only for tracked processes. Path filtering happens here.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Only tracked processes */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	/* Read path from userspace */
	struct openat_args oa = {0};
	const char *pathname = (const char *)ctx->args[1];
	bpf_probe_read_user_str(oa.path, sizeof(oa.path), pathname);
	oa.flags = (int)ctx->args[2];

	/* Filter by path prefix */
	if (!path_matches_include(oa.path))
		return 0;
	if (path_matches_exclude(oa.path))
		return 0;

	bpf_map_update_elem(&openat_args_map, &pid_tgid, &oa, BPF_ANY);
	return 0;
}

/*
 * sys_exit_openat: if open succeeded, create fd_info entry.
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct openat_args *oa = bpf_map_lookup_elem(
		&openat_args_map, &pid_tgid);
	if (!oa)
		return 0;

	long ret = ctx->ret;
	if (ret < 0) {
		bpf_map_delete_elem(&openat_args_map, &pid_tgid);
		return 0;
	}

	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct fd_key fk = { .tgid = tgid, .fd = (__s32)ret };

	struct fd_info fi = {0};
	__builtin_memcpy(fi.path, oa->path, FILE_PATH_MAX);
	fi.flags = oa->flags;
	fi.open_count = 1;

	bpf_map_update_elem(&fd_map, &fk, &fi, BPF_ANY);
	bpf_map_delete_elem(&openat_args_map, &pid_tgid);
	return 0;
}

/*
 * sys_enter_close: emit file_close event with accumulated stats.
 */
SEC("tracepoint/syscalls/sys_enter_close")
int handle_close_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	int fd = (int)ctx->args[0];

	struct fd_key fk = { .tgid = tgid, .fd = fd };
	struct fd_info *fi = bpf_map_lookup_elem(&fd_map, &fk);
	if (!fi)
		return 0;

	/* Emit file close event via ring buffer */
	struct file_event *fe = bpf_ringbuf_reserve(&events, sizeof(*fe), 0);
	if (fe) {
		__builtin_memset(fe, 0, sizeof(*fe));
		fe->type = EVENT_FILE_CLOSE;
		fe->tgid = tgid;
		fe->timestamp_ns = bpf_ktime_get_boot_ns();
		fe->cgroup_id = bpf_get_current_cgroup_id();
		bpf_get_current_comm(fe->comm, sizeof(fe->comm));
		__builtin_memcpy(fe->path, fi->path, FILE_PATH_MAX);
		fe->flags = fi->flags;
		fe->read_bytes = fi->read_bytes;
		fe->write_bytes = fi->write_bytes;
		fe->open_count = fi->open_count;

		/* Get ppid */
		struct task_struct *task =
			(struct task_struct *)bpf_get_current_task();
		struct task_struct *parent = BPF_CORE_READ(task, real_parent);
		fe->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
		fe->uid  = (__u32)bpf_get_current_uid_gid();

		bpf_ringbuf_submit(fe, 0);
	}

	bpf_map_delete_elem(&fd_map, &fk);
	return 0;
}

/*
 * sys_enter_read: save fd for the exit handler.
 */
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 key0 = 0;
	struct file_config *fc = bpf_map_lookup_elem(&file_cfg, &key0);
	if (!fc || !fc->track_bytes)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Quick check: is this fd tracked? */
	int fd = (int)ctx->args[0];
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	if (!bpf_map_lookup_elem(&fd_map, &fk))
		return 0;

	struct rw_args ra = { .fd = fd };
	bpf_map_update_elem(&rw_args_map, &pid_tgid, &ra, BPF_ANY);
	return 0;
}

/*
 * sys_exit_read: accumulate bytes read.
 */
SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct rw_args *ra = bpf_map_lookup_elem(&rw_args_map, &pid_tgid);
	if (!ra)
		return 0;

	long ret = ctx->ret;
	int fd = ra->fd;
	bpf_map_delete_elem(&rw_args_map, &pid_tgid);

	if (ret <= 0)
		return 0;

	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	struct fd_info *fi = bpf_map_lookup_elem(&fd_map, &fk);
	if (fi)
		__sync_fetch_and_add(&fi->read_bytes, (__u64)ret);

	return 0;
}

/*
 * sys_enter_write: save fd for the exit handler.
 */
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 key0 = 0;
	struct file_config *fc = bpf_map_lookup_elem(&file_cfg, &key0);
	if (!fc || !fc->track_bytes)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	int fd = (int)ctx->args[0];
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	if (!bpf_map_lookup_elem(&fd_map, &fk))
		return 0;

	struct rw_args ra = { .fd = fd };
	bpf_map_update_elem(&rw_args_map, &pid_tgid, &ra, BPF_ANY);
	return 0;
}

/*
 * sys_exit_write: accumulate bytes written.
 */
SEC("tracepoint/syscalls/sys_exit_write")
int handle_write_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct rw_args *ra = bpf_map_lookup_elem(&rw_args_map, &pid_tgid);
	if (!ra)
		return 0;

	long ret = ctx->ret;
	int fd = ra->fd;
	bpf_map_delete_elem(&rw_args_map, &pid_tgid);

	if (ret <= 0)
		return 0;

	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	struct fd_info *fi = bpf_map_lookup_elem(&fd_map, &fk);
	if (fi)
		__sync_fetch_and_add(&fi->write_bytes, (__u64)ret);

	return 0;
}

/* ── Network: TCP/UDP send/receive (kretprobe for actual byte count) ── */

/* ── Network tracking: TCP connection lifecycle + byte counting ───── */

/*
 * net_cfg: single-element array with enabled/track_bytes flags.
 * sock_map: per-socket state keyed by sock pointer.
 * connect_args_map: temp storage between kprobe/kretprobe of tcp_v4_connect.
 * sendmsg_args_map: temp storage between kprobe/kretprobe of tcp_sendmsg.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct net_config);
} net_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NET_MAX_SOCKETS);
	__type(key, __u64);           /* sock pointer as u64 */
	__type(value, struct sock_info);
} sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);           /* pid_tgid */
	__type(value, struct connect_args);
} connect_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);           /* pid_tgid */
	__type(value, struct sendmsg_args);
} sendmsg_args_map SEC(".maps");

/*
 * Read socket addresses into sock_info.
 * Handles both AF_INET and AF_INET6.
 */
static __always_inline void read_sock_addrs(struct sock *sk,
					    struct sock_info *si)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	si->af = (__u8)family;
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	si->remote_port = __bpf_ntohs(dport);
	si->local_port  = BPF_CORE_READ(sk, __sk_common.skc_num);

	if (family == 2) { /* AF_INET */
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(si->remote_addr, &daddr, 4);
		__builtin_memcpy(si->local_addr, &saddr, 4);
	} else if (family == 10) { /* AF_INET6 */
		BPF_CORE_READ_INTO(si->remote_addr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(si->local_addr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
}

/*
 * Emit NET_CLOSE event from sock_info.
 */
static __always_inline void emit_net_close(struct sock_info *si,
					   __u64 now_ns)
{
	struct net_event *ne = bpf_ringbuf_reserve(&events, sizeof(*ne), 0);
	if (!ne)
		return;

	__builtin_memset(ne, 0, sizeof(*ne));
	ne->type         = EVENT_NET_CLOSE;
	ne->tgid         = si->tgid;
	ne->uid          = si->uid;
	ne->timestamp_ns = now_ns;
	ne->cgroup_id    = bpf_get_current_cgroup_id();
	bpf_get_current_comm(ne->comm, sizeof(ne->comm));

	/* Get ppid */
	struct task_struct *task =
		(struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	ne->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;

	ne->af = si->af;
	__builtin_memcpy(ne->local_addr, si->local_addr, 16);
	__builtin_memcpy(ne->remote_addr, si->remote_addr, 16);
	ne->local_port  = si->local_port;
	ne->remote_port = si->remote_port;
	ne->tx_bytes    = si->tx_bytes;
	ne->rx_bytes    = si->rx_bytes;
	ne->duration_ns = (now_ns > si->start_ns) ? now_ns - si->start_ns : 0;

	bpf_ringbuf_submit(ne, 0);
}

/* ── tcp_v4_connect: track outbound IPv4 connections ─────────────── */

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp_v4_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&connect_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(krp_tcp_v4_connect, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args *args = bpf_map_lookup_elem(&connect_args_map,
							&pid_tgid);
	if (!args) return 0;

	__u64 sk_ptr = args->sock_ptr;
	bpf_map_delete_elem(&connect_args_map, &pid_tgid);

	if (ret != 0)
		return 0;

	struct sock *sk = (struct sock *)sk_ptr;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	struct sock_info si = {};
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);
	return 0;
}

/* ── tcp_v6_connect: track outbound IPv6 connections ─────────────── */

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kp_tcp_v6_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&connect_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(krp_tcp_v6_connect, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args *args = bpf_map_lookup_elem(&connect_args_map,
							&pid_tgid);
	if (!args) return 0;

	__u64 sk_ptr = args->sock_ptr;
	bpf_map_delete_elem(&connect_args_map, &pid_tgid);

	if (ret != 0)
		return 0;

	struct sock *sk = (struct sock *)sk_ptr;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	struct sock_info si = {};
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);
	return 0;
}

/* ── inet_csk_accept: track inbound TCP connections ──────────────── */

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(krp_inet_csk_accept, struct sock *sk)
{
	if (!sk)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	__u64 sk_ptr = (__u64)sk;

	struct sock_info si = {};
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);
	return 0;
}

/* ── tcp_close: emit NET_CLOSE event ─────────────────────────────── */

SEC("kprobe/tcp_close")
int BPF_KPROBE(kp_tcp_close, struct sock *sk)
{
	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	emit_net_close(si, bpf_ktime_get_boot_ns());
	bpf_map_delete_elem(&sock_map, &sk_ptr);
	return 0;
}

/* ── tcp_sendmsg / tcp_recvmsg: per-connection + per-process bytes ── */

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kp_tcp_sendmsg, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&sendmsg_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(ret_tcp_sendmsg, int ret)
{
	if (ret <= 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args *args = bpf_map_lookup_elem(&sendmsg_args_map,
							&pid_tgid);
	__u64 sk_ptr = args ? args->sock_ptr : 0;
	bpf_map_delete_elem(&sendmsg_args_map, &pid_tgid);

	/* Per-process aggregate (always, if tracked) */
	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_tx_bytes, (__u64)ret);

	/* Per-connection (if socket is in sock_map) */
	if (sk_ptr) {
		struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
		if (si)
			__sync_fetch_and_add(&si->tx_bytes, (__u64)ret);
	}
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kp_tcp_recvmsg, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&sendmsg_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(ret_tcp_recvmsg, int ret)
{
	if (ret <= 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args *args = bpf_map_lookup_elem(&sendmsg_args_map,
							&pid_tgid);
	__u64 sk_ptr = args ? args->sock_ptr : 0;
	bpf_map_delete_elem(&sendmsg_args_map, &pid_tgid);

	/* Per-process aggregate (always, if tracked) */
	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_rx_bytes, (__u64)ret);

	/* Per-connection (if socket is in sock_map) */
	if (sk_ptr) {
		struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
		if (si)
			__sync_fetch_and_add(&si->rx_bytes, (__u64)ret);
	}
	return 0;
}

/* ── UDP: per-process aggregate bytes only (no connection lifecycle) ── */

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg, int ret)
{
	if (ret <= 0)
		return 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_tx_bytes, (__u64)ret);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(ret_udp_recvmsg, int ret)
{
	if (ret <= 0)
		return 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_rx_bytes, (__u64)ret);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
