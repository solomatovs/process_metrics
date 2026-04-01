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
void fill_from_proc_info(struct metric_event *cev, const struct proc_info *pi);
void fill_identity_from_proc_info(struct metric_event *cev, const struct proc_info *pi);
void fill_metrics_from_proc_info(struct metric_event *cev, const struct proc_info *pi);
void fill_from_track_info(struct metric_event *cev, const struct track_info *ti,
			  int tracked);
void fill_from_sock_info(struct metric_event *cev, const struct sock_info *si, __u64 boot_ns);
void fill_track_info_for_pid(struct metric_event *cev, __u32 tgid);
void fill_tags(struct metric_event *cev, __u32 tgid);
void fill_cgroup(struct metric_event *cev, __u64 cgroup_id);
void fill_cgroup_metrics(struct metric_event *cev);
void fill_pwd(struct metric_event *cev, __u32 tgid);

/* ── String helpers ──────────────────────────────────────────────── */
void fast_strcpy(char *dst, int cap, const char *src);
void cmdline_split(const char *raw, __u16 len, char *exec_out, int exec_len,
		   char *args_out, int args_len);

/* ── Tags ────────────────────────────────────────────────────────── */
void ensure_tags(__u32 tgid, char *buf, int buflen);
void tags_inherit_ts(__u32 child, __u32 parent);

/* ── Pidtree ─────────────────────────────────────────────────────── */
__u32 pidtree_lookup_in(const __u32 *p_pid, const __u32 *p_ppid, __u32 pid);
int pidtree_walk_chain(const __u32 *p_pid, const __u32 *p_ppid, __u32 pid,
		       __u32 *out, int max_depth);
void pidtree_remove(__u32 pid);

/* ── PWD ─────────────────────────────────────────────────────────── */
void pwd_inherit_ts(__u32 child, __u32 parent);

/* ── Tracked ─────────────────────────────────────────────────────── */
int is_pid_tracked(__u32 tgid, struct track_info *ti);
const char *resolve_rule_tracked(const struct track_info *ti, int tracked);

/* ── CPU prev cache ──────────────────────────────────────────────── */
__u64 cpu_prev_lookup(__u32 tgid);
void cpu_prev_update(__u32 tgid, __u64 cpu_ns);

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

/* ── Snapshot ────────────────────────────────────────────────────── */
void write_snapshot(void);
void snapshot_reset(void);

#endif /* PM_FUNCTIONS_H */
