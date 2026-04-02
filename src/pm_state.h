/*
 * pm_state.h — глобальное рантайм-состояние process_metrics.
 *
 * Переменные, которые изменяются во время работы программы.
 * Конфигурация (из файла) — в pm_config.h.
 */

#ifndef PM_STATE_H
#define PM_STATE_H

#include <signal.h>
#include <pthread.h>
#include <regex.h>
#include "process_metrics_common.h"
#include "event_file.h"

/* ── Правила трекинга ────────────────────────────────────────────── */

#define RULE_NOT_MATCH "NOT_MATCH"

struct rule {
	char    name[EV_RULE_LEN];
	regex_t regex;
	int     ignore;
};

extern struct rule rules[MAX_RULES];
extern int num_rules;

/* ── BPF ─────────────────────────────────────────────────────────── */

struct process_metrics_bpf;
extern struct process_metrics_bpf *skel;
extern int proc_map_fd;
extern int missed_exec_fd;

/* ── Сигналы и lifecycle ─────────────────────────────────────────── */

extern volatile sig_atomic_t g_running;
extern volatile sig_atomic_t g_reload;

/* ── Время ───────────────────────────────────────────────────────── */

extern __s64 g_boot_to_wall_ns;

/* ── Счётчики ────────────────────────────────────────────────────── */

extern int g_last_map_count;
extern int g_last_conn_count;

/* ── Cgroup cache ────────────────────────────────────────────────── */

struct cgroup_entry {
	__u64 id;
	char  path[EV_CGROUP_LEN];
	char  fs_path[EV_CGROUP_LEN];
};

extern struct cgroup_entry *cgroup_cache;
extern int cgroup_cache_count;

struct cgroup_metrics {
	char      path[EV_CGROUP_LEN];
	long long mem_max, mem_cur, swap_cur;
	long long cpu_weight, cpu_max, cpu_max_period;
	long long cpu_nr_periods, cpu_nr_throttled, cpu_throttled_usec;
	long long pids_cur;
	int       valid;
};

extern struct cgroup_metrics *cg_metrics;
extern int cg_metrics_count;

/* ── Locks ───────────────────────────────────────────────────────── */

extern pthread_rwlock_t g_tags_lock;
extern pthread_rwlock_t g_cgroup_lock;
extern pthread_rwlock_t g_pidtree_lock;

/* ── Tags hash table ────────────────────────────────────────────── */

#define TAGS_MAX_LEN EV_TAGS_LEN

extern __u32 tags_tgid[TAGS_HT_SIZE];
extern char tags_data[TAGS_HT_SIZE][TAGS_MAX_LEN];

/* ── Pidtree arrays ─────────────────────────────────────────────── */

extern __u32 pt_pid[PIDTREE_HT_SIZE];
extern __u32 pt_ppid[PIDTREE_HT_SIZE];
extern __u64 pt_generation;

/* ── CPU prev cache ─────────────────────────────────────────────── */

struct cpu_prev {
	__u32 tgid;
	__u64 cpu_ns;
};

extern struct cpu_prev cpu_prev_cache[MAX_CPU_PREV];
extern int cpu_prev_count;

#endif /* PM_STATE_H */
