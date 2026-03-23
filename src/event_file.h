/*
 * event_file.h — thread-safe file-based event buffer
 *
 * Accumulates metric_event records in a binary file. On request (ef_swap),
 * atomically renames the file and returns all accumulated events.
 * New events go into a fresh file while the caller processes the old data.
 *
 * Two-phase delivery:
 *   ef_swap()   — swap file, return accumulated data (kept as .pending)
 *   ef_commit() — confirm delivery, delete .pending
 *   If ef_commit() is never called, next ef_swap() picks up .pending
 *   and combines it with newly accumulated events.
 */

#ifndef EVENT_FILE_H
#define EVENT_FILE_H

#include <linux/types.h>
#include "process_metrics_common.h"

/* ── metric event (shared by event_file, http_server, main) ──────── */

struct metric_event {
	__u64 timestamp_ns;
	char  event_type[12];         /* "fork","exec","exit","oom_kill","snapshot" */
	char  rule[64];
	__u32 root_pid;
	__u32 pid;
	__u32 ppid;
	char  comm[COMM_LEN];
	char  exec_path[CMDLINE_MAX]; /* executable path (argv[0]) */
	char  args[CMDLINE_MAX];      /* arguments (argv[1..]) */
	char  cgroup[256];
	__u8  is_root;
	__u8  state;
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
	/* cgroup v2 metrics (-1 = not available) */
	__s64 cgroup_memory_max;
	__s64 cgroup_memory_current;
	__s64 cgroup_swap_current;
	__s64 cgroup_cpu_weight;
	__s64 cgroup_pids_current;
};

/* ── event file record (hostname + event) ────────────────────────── */

#define EF_HOSTNAME_LEN 256

struct ef_record {
	char               hostname[EF_HOSTNAME_LEN];
	struct metric_event event;
};

/* ── public API ──────────────────────────────────────────────────── */

/*
 * Initialize event file at the given path.
 * Creates the file if it doesn't exist.
 * Returns 0 on success, -1 on error.
 */
int ef_init(const char *path);

/*
 * Append one event to the file (thread-safe).
 */
void ef_append(const struct metric_event *ev, const char *hostname);

/*
 * Atomically swap the event file and return accumulated events.
 *
 * If a previous ef_swap() was not committed (delivery failed),
 * its data is combined with newly accumulated events.
 *
 * On success, *out points to a malloc'd array of ef_record,
 * *count is the number of records. Caller must free(*out).
 * Caller MUST call ef_commit() after successful delivery.
 * Returns 0 on success, -1 on error.
 */
int ef_swap(struct ef_record **out, int *count);

/*
 * Atomically swap the event file and return an open fd for streaming.
 *
 * Same swap logic as ef_swap(), but instead of reading all records
 * into memory, returns an fd to the .pending file for record-by-record
 * reading. Each read of sizeof(struct ef_record) bytes yields one record.
 *
 * Returns open fd (>= 0) on success, -1 if no data.
 * Caller reads records, then calls ef_commit() on success or
 * close(fd) on failure (.pending preserved for next swap).
 */
int ef_swap_fd(void);

/*
 * Confirm successful delivery — delete the .pending file.
 * Call this only after the data from ef_swap() has been fully sent.
 */
void ef_commit(void);

/*
 * Clean up: close file, destroy mutex.
 */
void ef_cleanup(void);

#endif /* EVENT_FILE_H */
