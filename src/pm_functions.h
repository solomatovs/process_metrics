/*
 * pm_functions.h — прототипы функций, разделяемых между файлами.
 *
 * Функции определены в process_metrics.c, используются в refresh.c и др.
 */

#ifndef PM_FUNCTIONS_H
#define PM_FUNCTIONS_H

#include "process_metrics_common.h"
#include "event_file.h"

/* ── Время ───────────────────────────────────────────────────────── */
void refresh_boot_to_wall(void);

/* ── Трекинг процессов ───────────────────────────────────────────── */
int try_track_pid(__u32 pid);

/* ── Pidtree ─────────────────────────────────────────────────────── */
void pidtree_store_ts(__u32 pid, __u32 ppid);

/* ── PWD ─────────────────────────────────────────────────────────── */
void pwd_read_and_store(__u32 tgid);

/* ── /proc чтение ────────────────────────────────────────────────── */
int read_proc_cmdline(__u32 pid, char *dst, int dstlen);
__u32 read_proc_ppid(__u32 pid);

/* ── Cgroup resolve ──────────────────────────────────────────────── */
void resolve_cgroup_ts(__u64 cgroup_id, char *buf, int buflen);
void resolve_cgroup_fs_ts(__u64 cgroup_id, char *buf, int buflen);

/* ── Cgroup sysfs ────────────────────────────────────────────────── */
long long read_cgroup_value(const char *cg_path, const char *file);
void read_cgroup_cpu_max(const char *cg_path, long long *max, long long *period);
void read_cgroup_cpu_stat(const char *cg_path, long long *nr_periods,
			  long long *nr_throttled, long long *throttled_usec);

/* ── Emit guards ─────────────────────────────────────────────────── */
int should_emit_icmp(void);
int should_emit_disk(void);

/* ── Fill helpers ────────────────────────────────────────────────── */
void fill_parent_pids(struct metric_event *cev);
void fill_rule(struct metric_event *cev, const char *rname);

/* ── Cache removal (thread-safe wrappers) ────────────────────────── */
void cpu_prev_remove(__u32 tgid);
void pwd_remove_ts(__u32 tgid);
void tags_remove_ts(__u32 tgid);
void pidtree_remove_ts(__u32 pid);

/* ── Dead keys flush ─────────────────────────────────────────────── */
int flush_dead_keys(__u32 *keys, int count);

/* ── Disk usage ──────────────────────────────────────────────────── */
int emit_disk_usage_events(__u64 timestamp_ns, const char *hostname);

/* ── Refresh ─────────────────────────────────────────────────────── */
void refresh_processes(void);

#endif /* PM_FUNCTIONS_H */
