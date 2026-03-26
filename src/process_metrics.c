/*
 * process_metrics — event-driven process metrics collector
 *
 * Loads BPF programs, listens to ring buffer events, matches exec'd
 * processes against config rules, and periodically writes metrics.
 * Serves metrics via built-in HTTP server (CSV and Prometheus formats).
 *
 * Usage:
 *   ./process_metrics -c config.conf
 *
 * Requires: root (CAP_BPF + CAP_PERFMON)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <mntent.h>
#include <arpa/inet.h>
#include <regex.h>
#include <libconfig.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf_version.h>
#include <linux/types.h>
#include "process_metrics_common.h"
#include "process_metrics.skel.h"
#include "event_file.h"
#include "http_server.h"

/*
 * bpf_program__set_autoload  — libbpf >= 0.6 (skips load + attach)
 * bpf_program__set_autoattach — libbpf >= 0.8 (loads but skips attach)
 *
 * For disabling optional programs we need set_autoload (don't even
 * send to verifier).  Astra Linux ships libbpf 0.7 which has
 * set_autoload but not set_autoattach.
 */
#if LIBBPF_MAJOR_VERSION > 0 || LIBBPF_MINOR_VERSION >= 8
#define BPF_PROG_DISABLE(prog) bpf_program__set_autoattach((prog), false)
#else
#define BPF_PROG_DISABLE(prog) bpf_program__set_autoload((prog), false)
#endif

/* ── configuration ────────────────────────────────────────────────── */

#define MAX_RULES    64
#define MAX_CGROUPS  256
#define PATH_MAX_LEN 512

struct rule {
	char    name[64];
	regex_t regex;
	int     ignore;   /* 1 = не отслеживать совпавший процесс */
};

static struct rule rules[MAX_RULES];
static int         num_rules;

/* Configuration values (loaded from libconfig) */
static const char *cfg_config_file     = NULL;
static char        cfg_hostname[256]               = "";
static int         cfg_snapshot_interval           = 30;
static char        cfg_metric_prefix[128]          = "process_metrics";
static int         cfg_cmdline_max_len             = 500;
static int         cfg_exec_rate_limit             = 0;  /* 0 = unlimited */
static int         cfg_cgroup_metrics              = 1;  /* 1 = read cgroup files */
static int         cfg_refresh_proc                = 1;  /* 1 = refresh cmdline/comm from /proc */
static int         cfg_log_level                   = 1;  /* 0=error, 1=info, 2=debug */

/* HTTP server config */
static struct http_config g_http_cfg;
static char cfg_data_file[PATH_MAX_LEN]    = "";
static char cfg_prom_path[PATH_MAX_LEN]    = "";  /* internal prom file for HTTP */
static long long cfg_max_data_file_size    = 1LL * 1024 * 1024 * 1024; /* 1 GB */

/* Network tracking config */
static int cfg_net_tracking_enabled         = 0;
static int cfg_net_track_bytes              = 0;

/* File tracking config */
static int cfg_file_tracking_enabled        = 0;
static int cfg_file_track_bytes             = 0;

/* Docker resolve config */
static char cfg_docker_data_root[PATH_MAX_LEN] = "";
static char cfg_docker_daemon_json[PATH_MAX_LEN] = "/etc/docker/daemon.json";

/* Disk tracking config */
static int cfg_disk_tracking_enabled       = 1;  /* enabled by default */
#define DISK_MAX_PREFIXES 32
#define DISK_PREFIX_MAX   256
static char cfg_disk_include[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
static int  cfg_disk_include_count         = 0;
static char cfg_disk_exclude[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
static int  cfg_disk_exclude_count         = 0;
static char cfg_disk_fs_types[DISK_MAX_PREFIXES][32];
static int  cfg_disk_fs_types_count        = 0;

/* Security tracking config */
static int cfg_sec_tcp_retransmit  = 0;
static int cfg_sec_syn_tracking    = 0;
static int cfg_sec_rst_tracking    = 0;
static int cfg_sec_udp_tracking    = 0;
static int cfg_sec_icmp_tracking   = 0;
static int cfg_sec_open_conn_count = 0;
static struct file_prefix cfg_file_include[FILE_MAX_PREFIXES];
static int cfg_file_include_count           = 0;
static struct file_prefix cfg_file_exclude[FILE_MAX_PREFIXES];
static int cfg_file_exclude_count           = 0;

/* ── globals ──────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_running   = 1;
static volatile sig_atomic_t g_reload    = 0;
static struct process_metrics_bpf *skel;
static int tracked_map_fd, proc_map_fd;

/* Forward declarations */
static void write_snapshot(void);
static void build_cgroup_cache(void);

/* Boot-time to wall-clock offset (computed once at startup,
 * refreshed each snapshot). BPF sends bpf_ktime_get_boot_ns(),
 * wall_ns = boot_ns + g_boot_to_wall_ns. */
static __s64 g_boot_to_wall_ns;

static void refresh_boot_to_wall(void)
{
	struct timespec rt, bt;
	clock_gettime(CLOCK_REALTIME, &rt);
	clock_gettime(CLOCK_BOOTTIME, &bt);
	__s64 rt_ns = (__s64)rt.tv_sec * 1000000000LL + rt.tv_nsec;
	__s64 bt_ns = (__s64)bt.tv_sec * 1000000000LL + bt.tv_nsec;
	g_boot_to_wall_ns = rt_ns - bt_ns;
}

/* ── tags hash table (userspace-only, per-tgid) ──────────────────── */

#define TAGS_MAX_LEN 512
#define TAGS_HT_SIZE 16384  /* must be power of 2 */

struct tags_entry {
	__u32 tgid;           /* 0 = empty slot */
	char  tags[TAGS_MAX_LEN];
};

static struct tags_entry tags_ht[TAGS_HT_SIZE];

/* Forward declaration — used by tags_inherit() */
static int try_track_pid(__u32 pid);

static void tags_store(__u32 tgid, const char *tags)
{
	__u32 idx = tgid & (TAGS_HT_SIZE - 1);
	for (int i = 0; i < TAGS_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (tags_ht[slot].tgid == 0 || tags_ht[slot].tgid == tgid) {
			tags_ht[slot].tgid = tgid;
			snprintf(tags_ht[slot].tags, TAGS_MAX_LEN, "%s", tags);
			return;
		}
	}
}

static const char *tags_lookup(__u32 tgid)
{
	__u32 idx = tgid & (TAGS_HT_SIZE - 1);
	for (int i = 0; i < TAGS_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (tags_ht[slot].tgid == tgid)
			return tags_ht[slot].tags;
		if (tags_ht[slot].tgid == 0)
			return "";
	}
	return "";
}

static void tags_remove(__u32 tgid)
{
	__u32 idx = tgid & (TAGS_HT_SIZE - 1);
	for (int i = 0; i < TAGS_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (tags_ht[slot].tgid == tgid) {
			tags_ht[slot].tgid = 0;
			tags_ht[slot].tags[0] = '\0';
			return;
		}
		if (tags_ht[slot].tgid == 0)
			return;
	}
}

static void tags_inherit(__u32 child_tgid, __u32 parent_tgid)
{
	const char *pt = tags_lookup(parent_tgid);
	if (pt[0]) {
		tags_store(child_tgid, pt);
		return;
	}
	/* Parent has no tags — try to resolve by reading /proc/ppid/cmdline */
	if (try_track_pid(parent_tgid) >= 0) {
		pt = tags_lookup(parent_tgid);
		tags_store(child_tgid, pt);
	}
}

static void tags_clear(void)
{
	memset(tags_ht, 0, sizeof(tags_ht));
}

/*
 * Match cmdline against ALL rules, build pipe-separated tags string.
 * Returns the index of the first matching rule, or -1 if no match.
 */
static int match_rules_all(const char *cmdline, char *tags, int tags_size)
{
	int first = -1;
	int off = 0;
	for (int i = 0; i < num_rules; i++) {
		if (regexec(&rules[i].regex, cmdline, 0, NULL, 0) != 0)
			continue;
		if (first < 0)
			first = i;
		if (off > 0 && off < tags_size - 1)
			tags[off++] = '|';
		int n = snprintf(tags + off, tags_size - off, "%s",
				 rules[i].name);
		if (n > 0 && off + n < tags_size)
			off += n;
	}
	if (off == 0 && tags_size > 0)
		tags[0] = '\0';
	return first;
}

/* Forward declarations for try_track_pid */
static void cmdline_to_str(const char *raw, __u16 len, char *out, int outlen);
static int read_proc_cmdline(__u32 pid, char *dst, int dstlen);
static void track_pid_from_proc(__u32 pid, int rule_id, __u32 root_pid,
				__u8 is_root);
static void log_debug(const char *fmt, ...);

/*
 * Try to track an unknown PID by reading /proc/<pid>/cmdline.
 * Called when file_close/net_close/oom_kill/exit arrives for a PID
 * not in tracked_map. Reads cmdline, matches against all rules,
 * and adds to tracked_map + tags hash if matched.
 * Returns the first matched rule index, or -1 if no match / process gone.
 */
static int try_track_pid(__u32 pid)
{
	char cmdline_raw[CMDLINE_MAX];
	int clen = read_proc_cmdline(pid, cmdline_raw, sizeof(cmdline_raw));
	if (clen <= 0)
		return -1;

	char cmdline_str[CMDLINE_MAX + 1];
	cmdline_to_str(cmdline_raw, (__u16)clen, cmdline_str,
		       sizeof(cmdline_str));

	char tags_buf[TAGS_MAX_LEN];
	int first = match_rules_all(cmdline_str, tags_buf, sizeof(tags_buf));
	if (first < 0)
		return -1;
	if (rules[first].ignore)
		return -1;

	track_pid_from_proc(pid, first, pid, 1);
	tags_store(pid, tags_buf);
	log_debug("LATE_TRACK: pid=%u rule=%s tags=%s cmdline=%.60s",
		  pid, rules[first].name, tags_buf, cmdline_str);
	return first;
}

/* ── exited process cache (circular buffer for last N exits) ──────── */

#define MAX_EXITED 256

struct exited_proc {
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 exit_code;
	__u16 rule_id;
	__u32 root_pid;
	__u64 cpu_ns;
	__u64 rss_max_pages;
	__u64 rss_min_pages;
	__u8  oom_killed;
	__u64 net_tx_bytes;
	__u64 net_rx_bytes;
	__u64 timestamp_ns;       /* when process exited */
	char  comm[COMM_LEN];
	char  cmdline[CMDLINE_MAX];
	__u16 cmdline_len;
	char  tags[TAGS_MAX_LEN];
};

static struct exited_proc exited_ring[MAX_EXITED];
static int exited_head;   /* next write position */
static int exited_count;  /* total entries (max MAX_EXITED) */

static void record_exit(const struct event *e)
{
	struct exited_proc *ep = &exited_ring[exited_head % MAX_EXITED];
	ep->tgid         = e->tgid;
	ep->ppid         = e->ppid;
	ep->uid          = e->uid;
	ep->exit_code    = e->exit_code;
	ep->rule_id      = e->rule_id;
	ep->root_pid     = e->root_pid;
	ep->cpu_ns       = e->cpu_ns;
	ep->rss_max_pages = e->rss_max_pages;
	ep->rss_min_pages = e->rss_min_pages;
	ep->oom_killed   = e->oom_killed;
	ep->net_tx_bytes = e->net_tx_bytes;
	ep->net_rx_bytes = e->net_rx_bytes;
	ep->timestamp_ns = e->timestamp_ns;
	memcpy(ep->comm, e->comm, COMM_LEN);
	memcpy(ep->cmdline, e->cmdline, CMDLINE_MAX);
	ep->cmdline_len  = e->cmdline_len;
	/* Save tags before removing from hash table */
	snprintf(ep->tags, sizeof(ep->tags), "%s", tags_lookup(e->tgid));
	exited_head = (exited_head + 1) % MAX_EXITED;
	if (exited_count < MAX_EXITED)
		exited_count++;
}

/* ── CPU usage cache (for computing per-interval ratio) ───────────── */

#define MAX_CPU_PREV 8192

struct cpu_prev {
	__u32 tgid;
	__u64 cpu_ns;
};

static struct cpu_prev cpu_prev_cache[MAX_CPU_PREV];
static int cpu_prev_count;
static struct timespec prev_snapshot_ts;

static __u64 cpu_prev_lookup(__u32 tgid)
{
	for (int i = 0; i < cpu_prev_count; i++)
		if (cpu_prev_cache[i].tgid == tgid)
			return cpu_prev_cache[i].cpu_ns;
	return 0;
}

static void cpu_prev_update(__u32 tgid, __u64 cpu_ns)
{
	for (int i = 0; i < cpu_prev_count; i++) {
		if (cpu_prev_cache[i].tgid == tgid) {
			cpu_prev_cache[i].cpu_ns = cpu_ns;
			return;
		}
	}
	if (cpu_prev_count < MAX_CPU_PREV) {
		cpu_prev_cache[cpu_prev_count].tgid = tgid;
		cpu_prev_cache[cpu_prev_count].cpu_ns = cpu_ns;
		cpu_prev_count++;
	}
}

static void cpu_prev_remove(__u32 tgid)
{
	for (int i = 0; i < cpu_prev_count; i++) {
		if (cpu_prev_cache[i].tgid == tgid) {
			cpu_prev_cache[i] = cpu_prev_cache[--cpu_prev_count];
			return;
		}
	}
}

/* ── cgroup cache ─────────────────────────────────────────────────── */

struct cgroup_entry {
	__u64 id;
	char  path[256];    /* display name (docker/xxx or original) */
	char  fs_path[256]; /* real filesystem path under /sys/fs/cgroup */
};

static struct cgroup_entry cgroup_cache[MAX_CGROUPS];
static int cgroup_cache_count;
static char docker_data_root[PATH_MAX_LEN] = "";

/*
 * Detect Docker data-root. Priority:
 *   1. cfg_docker_data_root (from config file)
 *   2. Parsed from cfg_docker_daemon_json ("data-root" key)
 *   3. Fallback: /var/lib/docker
 */
static void detect_docker_data_root(void)
{
	if (docker_data_root[0])
		return;

	/* Use explicit config value if set */
	if (cfg_docker_data_root[0]) {
		snprintf(docker_data_root, sizeof(docker_data_root),
			 "%s", cfg_docker_data_root);
		return;
	}

	/* Try to parse from daemon.json */
	FILE *f = fopen(cfg_docker_daemon_json, "r");
	if (f) {
		char buf[4096];
		size_t n = fread(buf, 1, sizeof(buf) - 1, f);
		fclose(f);
		buf[n] = '\0';
		char *key = strstr(buf, "\"data-root\"");
		if (key) {
			char *colon = strchr(key + 11, ':');
			if (colon) {
				char *q1 = strchr(colon, '"');
				if (q1) {
					q1++;
					char *q2 = strchr(q1, '"');
					if (q2 && (size_t)(q2 - q1) < sizeof(docker_data_root)) {
						memcpy(docker_data_root, q1, q2 - q1);
						docker_data_root[q2 - q1] = '\0';
					}
				}
			}
		}
	}

	if (!docker_data_root[0])
		snprintf(docker_data_root, sizeof(docker_data_root),
			 "/var/lib/docker");
}

/*
 * Try to resolve a Docker container name from cgroup path.
 * Looks for pattern "docker-<64hex>.scope" and reads the container name
 * from config.v2.json. Returns 1 on success (dst filled), 0 otherwise.
 */
static int resolve_docker_name(const char *rel, char *dst, size_t dstlen)
{
	/* Find "docker-" prefix in the last path component */
	const char *last = strrchr(rel, '/');
	const char *base = last ? last + 1 : rel;

	if (strncmp(base, "docker-", 7) != 0)
		return 0;
	const char *hash_start = base + 7;
	const char *dot = strstr(hash_start, ".scope");
	if (!dot || (dot - hash_start) != 64)
		return 0;

	char container_id[65];
	memcpy(container_id, hash_start, 64);
	container_id[64] = '\0';

	detect_docker_data_root();

	char config_path[PATH_MAX_LEN];
	snprintf(config_path, sizeof(config_path),
		 "%s/containers/%s/config.v2.json",
		 docker_data_root, container_id);

	FILE *f = fopen(config_path, "r");
	if (!f)
		return 0;

	char buf[4096];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	/* Parse "Name":"/container_name" — Name is typically the first field */
	char *key = strstr(buf, "\"Name\"");
	if (!key)
		return 0;
	char *colon = strchr(key + 6, ':');
	if (!colon)
		return 0;
	char *q1 = strchr(colon, '"');
	if (!q1)
		return 0;
	q1++;
	/* Skip leading / in container name */
	if (*q1 == '/')
		q1++;
	char *q2 = strchr(q1, '"');
	if (!q2 || q1 == q2)
		return 0;

	/* Build path: "docker/<container_name>" */
	size_t name_len = q2 - q1;
	if (name_len + 8 > dstlen)  /* "docker/" + name + NUL */
		return 0;
	snprintf(dst, dstlen, "docker/%.*s", (int)name_len, q1);
	return 1;
}

static void scan_cgroup_dir(const char *base, const char *rel)
{
	char full[PATH_MAX_LEN];
	snprintf(full, sizeof(full), "%s/%s", base, rel);

	struct stat st;
	if (stat(full, &st) == 0 && cgroup_cache_count < MAX_CGROUPS) {
		cgroup_cache[cgroup_cache_count].id = (__u64)st.st_ino;

		/* Always store real filesystem path */
		snprintf(cgroup_cache[cgroup_cache_count].fs_path,
			 sizeof(cgroup_cache[0].fs_path), "%s", rel);

		/* Try to resolve Docker container name for display */
		char docker_name[256];
		if (resolve_docker_name(rel, docker_name, sizeof(docker_name)))
			snprintf(cgroup_cache[cgroup_cache_count].path,
				 sizeof(cgroup_cache[0].path), "%s", docker_name);
		else
			snprintf(cgroup_cache[cgroup_cache_count].path,
				 sizeof(cgroup_cache[0].path), "%s", rel);
		cgroup_cache_count++;
	}

	DIR *d = opendir(full);
	if (!d)
		return;

	struct dirent *entry;
	while ((entry = readdir(d)) != NULL) {
		if (entry->d_type != DT_DIR || entry->d_name[0] == '.')
			continue;
		if (cgroup_cache_count >= MAX_CGROUPS)
			break;
		char child[PATH_MAX_LEN];
		if (rel[0])
			snprintf(child, sizeof(child), "%s/%s", rel, entry->d_name);
		else
			snprintf(child, sizeof(child), "%s", entry->d_name);
		scan_cgroup_dir(base, child);
	}
	closedir(d);
}

static void build_cgroup_cache(void)
{
	cgroup_cache_count = 0;
	if (access("/sys/fs/cgroup", R_OK) == 0)
		scan_cgroup_dir("/sys/fs/cgroup", "");
}

static int resolve_cgroup_idx(__u64 cgroup_id)
{
	if (cgroup_id == 0)
		return -1;

	for (int i = 0; i < cgroup_cache_count; i++)
		if (cgroup_cache[i].id == cgroup_id)
			return i;

	/* Cache miss — rebuild once */
	build_cgroup_cache();
	for (int i = 0; i < cgroup_cache_count; i++)
		if (cgroup_cache[i].id == cgroup_id)
			return i;

	return -1;
}

/* Display name (docker/xxx or original path) */
static const char *resolve_cgroup(__u64 cgroup_id)
{
	int idx = resolve_cgroup_idx(cgroup_id);
	return idx >= 0 ? cgroup_cache[idx].path : "";
}

/* Real filesystem path (for reading cgroup files) */
static const char *resolve_cgroup_fs(__u64 cgroup_id)
{
	int idx = resolve_cgroup_idx(cgroup_id);
	return idx >= 0 ? cgroup_cache[idx].fs_path : "";
}

/* Fast cgroup resolve for hot path — no cache rebuild on miss.
 * Cache is rebuilt every snapshot_interval anyway. */
static const char *resolve_cgroup_fast(__u64 cgroup_id)
{
	if (cgroup_id == 0)
		return "";
	for (int i = 0; i < cgroup_cache_count; i++)
		if (cgroup_cache[i].id == cgroup_id)
			return cgroup_cache[i].path;
	return "";
}

/* ── rules parser (from libconfig) ────────────────────────────────── */

static void free_rules(void)
{
	for (int i = 0; i < num_rules; i++)
		regfree(&rules[i].regex);
	num_rules = 0;
}

static int parse_rules_from_config(const char *path)
{
	config_t cfg;
	config_init(&cfg);

	if (!config_read_file(&cfg, path)) {
		fprintf(stderr, "FATAL: %s:%d - %s\n",
			config_error_file(&cfg) ? config_error_file(&cfg) : path,
			config_error_line(&cfg),
			config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	config_setting_t *rs = config_lookup(&cfg, "rules");
	if (!rs || !config_setting_is_list(rs)) {
		fprintf(stderr, "FATAL: 'rules' list not found in %s\n", path);
		config_destroy(&cfg);
		return -1;
	}

	free_rules();

	int count = config_setting_length(rs);
	for (int i = 0; i < count && num_rules < MAX_RULES; i++) {
		config_setting_t *entry = config_setting_get_elem(rs, i);
		if (!entry)
			continue;

		const char *name = NULL, *regex = NULL;
		if (!config_setting_lookup_string(entry, "name", &name) ||
		    !config_setting_lookup_string(entry, "regex", &regex)) {
			fprintf(stderr, "WARN: rules[%d]: missing 'name' or 'regex'\n", i);
			continue;
		}

		if (regcomp(&rules[num_rules].regex, regex,
			    REG_EXTENDED | REG_NOSUB) != 0) {
			fprintf(stderr, "WARN: rules[%d]: bad regex: %s\n", i, regex);
			continue;
		}
		snprintf(rules[num_rules].name, sizeof(rules[0].name), "%s", name);

		int ignore_val = 0;
		config_setting_lookup_bool(entry, "ignore", &ignore_val);
		rules[num_rules].ignore = ignore_val;

		num_rules++;
	}

	config_destroy(&cfg);
	fprintf(stderr, "INFO: loaded %d rules from %s\n", num_rules, path);
	return num_rules;
}

/* ── libconfig configuration loader ───────────────────────────────── */

static int load_config(const char *path)
{
	config_t cfg;
	config_init(&cfg);

	if (!config_read_file(&cfg, path)) {
		fprintf(stderr, "FATAL: %s:%d - %s\n",
			config_error_file(&cfg) ? config_error_file(&cfg) : path,
			config_error_line(&cfg),
			config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	const char *str_val;
	int int_val;

	/* General settings */
	if (config_lookup_string(&cfg, "hostname", &str_val))
		snprintf(cfg_hostname, sizeof(cfg_hostname), "%s", str_val);
	if (!cfg_hostname[0])
		gethostname(cfg_hostname, sizeof(cfg_hostname));
	if (config_lookup_int(&cfg, "snapshot_interval", &int_val))
		cfg_snapshot_interval = int_val;
	if (config_lookup_string(&cfg, "metric_prefix", &str_val))
		snprintf(cfg_metric_prefix, sizeof(cfg_metric_prefix), "%s", str_val);
	if (config_lookup_int(&cfg, "cmdline_max_len", &int_val))
		cfg_cmdline_max_len = int_val;
	if (config_lookup_int(&cfg, "exec_rate_limit", &int_val))
		cfg_exec_rate_limit = int_val;

	int bool_val;
	if (config_lookup_bool(&cfg, "cgroup_metrics", &bool_val))
		cfg_cgroup_metrics = bool_val;
	if (config_lookup_bool(&cfg, "refresh_proc", &bool_val))
		cfg_refresh_proc = bool_val;
	if (config_lookup_int(&cfg, "log_level", &int_val))
		cfg_log_level = int_val;

	/* HTTP server settings (enabled if section with port exists) */
	memset(&g_http_cfg, 0, sizeof(g_http_cfg));
	g_http_cfg.port = 9091;
	snprintf(g_http_cfg.bind, sizeof(g_http_cfg.bind), "0.0.0.0");

	config_setting_t *hs = config_lookup(&cfg, "http_server");
	if (hs) {
		if (config_setting_lookup_int(hs, "port", &int_val)) {
			g_http_cfg.port = int_val;
			g_http_cfg.enabled = 1;
		}
		if (config_setting_lookup_string(hs, "bind", &str_val))
			snprintf(g_http_cfg.bind, sizeof(g_http_cfg.bind),
				 "%s", str_val);
		if (config_setting_lookup_string(hs, "data_file", &str_val))
			snprintf(cfg_data_file, sizeof(cfg_data_file),
				 "%s", str_val);
		long long ll_val;
		if (config_setting_lookup_int64(hs, "max_data_file_size", &ll_val))
			cfg_max_data_file_size = ll_val;
	}

	/* net_tracking settings */
	config_setting_t *nt = config_lookup(&cfg, "net_tracking");
	if (nt) {
		if (config_setting_lookup_bool(nt, "enabled", &bool_val))
			cfg_net_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(nt, "track_bytes", &bool_val))
			cfg_net_track_bytes = bool_val;
	}

	/* File tracking settings */
	config_setting_t *ft = config_lookup(&cfg, "file_tracking");
	if (ft) {
		if (config_setting_lookup_bool(ft, "enabled", &bool_val))
			cfg_file_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(ft, "track_bytes", &bool_val))
			cfg_file_track_bytes = bool_val;

		/* Include prefixes */
		config_setting_t *inc = config_setting_lookup(ft, "include");
		if (inc && config_setting_is_list(inc)) {
			int n = config_setting_length(inc);
			if (n > FILE_MAX_PREFIXES) n = FILE_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s = config_setting_get_string_elem(inc, i);
				if (s) {
					int slen = (int)strlen(s);
					if (slen > FILE_PREFIX_CAP - 1)
						slen = FILE_PREFIX_CAP - 1;
					memcpy(cfg_file_include[i].prefix, s, slen);
					cfg_file_include[i].prefix[slen] = '\0';
					cfg_file_include[i].len = (__u8)slen;
					cfg_file_include_count++;
				}
			}
		}

		/* Exclude prefixes */
		config_setting_t *exc = config_setting_lookup(ft, "exclude");
		if (exc && config_setting_is_list(exc)) {
			int n = config_setting_length(exc);
			if (n > FILE_MAX_PREFIXES) n = FILE_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s = config_setting_get_string_elem(exc, i);
				if (s) {
					int slen = (int)strlen(s);
					if (slen > FILE_PREFIX_CAP - 1)
						slen = FILE_PREFIX_CAP - 1;
					memcpy(cfg_file_exclude[i].prefix, s, slen);
					cfg_file_exclude[i].prefix[slen] = '\0';
					cfg_file_exclude[i].len = (__u8)slen;
					cfg_file_exclude_count++;
				}
			}
		}
	}

	/* Docker resolve settings */
	config_setting_t *dk = config_lookup(&cfg, "docker");
	if (dk) {
		if (config_setting_lookup_string(dk, "data_root", &str_val))
			snprintf(cfg_docker_data_root, sizeof(cfg_docker_data_root),
				 "%s", str_val);
		if (config_setting_lookup_string(dk, "daemon_json", &str_val))
			snprintf(cfg_docker_daemon_json, sizeof(cfg_docker_daemon_json),
				 "%s", str_val);
	}

	/* Security tracking settings */
	config_setting_t *st = config_lookup(&cfg, "security_tracking");
	if (st) {
		if (config_setting_lookup_bool(st, "tcp_retransmit", &bool_val))
			cfg_sec_tcp_retransmit = bool_val;
		if (config_setting_lookup_bool(st, "syn_tracking", &bool_val))
			cfg_sec_syn_tracking = bool_val;
		if (config_setting_lookup_bool(st, "rst_tracking", &bool_val))
			cfg_sec_rst_tracking = bool_val;
		if (config_setting_lookup_bool(st, "udp_tracking", &bool_val))
			cfg_sec_udp_tracking = bool_val;
		if (config_setting_lookup_bool(st, "icmp_tracking", &bool_val))
			cfg_sec_icmp_tracking = bool_val;
		if (config_setting_lookup_bool(st, "open_conn_count", &bool_val))
			cfg_sec_open_conn_count = bool_val;
	}

	/* Disk tracking settings */
	config_setting_t *dt = config_lookup(&cfg, "disk_tracking");
	if (dt) {
		if (config_setting_lookup_bool(dt, "enabled", &bool_val))
			cfg_disk_tracking_enabled = bool_val;

		/* Filesystem types to include (overrides built-in list) */
		config_setting_t *fst = config_setting_lookup(dt, "fs_types");
		if (fst && config_setting_is_list(fst)) {
			int n = config_setting_length(fst);
			if (n > DISK_MAX_PREFIXES) n = DISK_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s =
					config_setting_get_string_elem(fst, i);
				if (s)
					snprintf(cfg_disk_fs_types
						 [cfg_disk_fs_types_count++],
						 32, "%s", s);
			}
		}

		/* Mount point include prefixes */
		config_setting_t *inc = config_setting_lookup(dt, "include");
		if (inc && config_setting_is_list(inc)) {
			int n = config_setting_length(inc);
			if (n > DISK_MAX_PREFIXES) n = DISK_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s =
					config_setting_get_string_elem(inc, i);
				if (s)
					snprintf(cfg_disk_include
						 [cfg_disk_include_count++],
						 DISK_PREFIX_MAX, "%s", s);
			}
		}

		/* Mount point exclude prefixes */
		config_setting_t *exc = config_setting_lookup(dt, "exclude");
		if (exc && config_setting_is_list(exc)) {
			int n = config_setting_length(exc);
			if (n > DISK_MAX_PREFIXES) n = DISK_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s =
					config_setting_get_string_elem(exc, i);
				if (s)
					snprintf(cfg_disk_exclude
						 [cfg_disk_exclude_count++],
						 DISK_PREFIX_MAX, "%s", s);
			}
		}
	}

	/* Default paths when http_server is enabled */
	if (g_http_cfg.enabled) {
		if (!cfg_data_file[0])
			snprintf(cfg_data_file, sizeof(cfg_data_file),
				 "/tmp/process_metrics_events.dat");
		/* Prom snapshot file path: <data_file_base>.prom */
		snprintf(cfg_prom_path, sizeof(cfg_prom_path),
			 "/tmp/process_metrics.prom");
	}

	config_destroy(&cfg);
	return 0;
}

/* ── helpers ──────────────────────────────────────────────────────── */

static void cmdline_to_str(const char *raw, __u16 len, char *out, int outlen)
{
	int n = len < outlen - 1 ? len : outlen - 1;
	for (int i = 0; i < n; i++)
		out[i] = (raw[i] == '\0') ? ' ' : raw[i];
	/* trim trailing space */
	while (n > 0 && out[n-1] == ' ')
		n--;
	out[n] = '\0';
}

/*
 * Split raw cmdline (null-separated argv) into exec_path and args.
 * exec_path = argv[0], args = argv[1..] joined with spaces.
 */
static void cmdline_split(const char *raw, __u16 len,
			  char *exec_out, int exec_len,
			  char *args_out, int args_len)
{
	exec_out[0] = '\0';
	args_out[0] = '\0';

	if (len == 0)
		return;

	/* argv[0]: up to first NUL */
	int first_nul = -1;
	for (int i = 0; i < len; i++) {
		if (raw[i] == '\0') {
			first_nul = i;
			break;
		}
	}

	if (first_nul < 0) {
		/* No NUL found — entire cmdline is exec */
		int n = len < exec_len - 1 ? len : exec_len - 1;
		memcpy(exec_out, raw, n);
		exec_out[n] = '\0';
		return;
	}

	/* exec = raw[0..first_nul) */
	int elen = first_nul < exec_len - 1 ? first_nul : exec_len - 1;
	memcpy(exec_out, raw, elen);
	exec_out[elen] = '\0';

	/* args = raw[first_nul+1..len), NULs → spaces */
	int start = first_nul + 1;
	int alen = len - start;
	if (alen <= 0)
		return;
	if (alen > args_len - 1)
		alen = args_len - 1;
	for (int i = 0; i < alen; i++)
		args_out[i] = (raw[start + i] == '\0') ? ' ' : raw[start + i];
	/* trim trailing spaces */
	while (alen > 0 && args_out[alen - 1] == ' ')
		alen--;
	args_out[alen] = '\0';
}

static void escape_label(const char *src, char *dst, int dstlen)
{
	int j = 0;
	for (int i = 0; src[i] && j < dstlen - 2; i++) {
		switch (src[i]) {
		case '\\': dst[j++] = '\\'; if (j < dstlen-1) dst[j++] = '\\'; break;
		case '"':  dst[j++] = '\\'; if (j < dstlen-1) dst[j++] = '"';  break;
		case '\n': dst[j++] = '\\'; if (j < dstlen-1) dst[j++] = 'n';  break;
		default:   dst[j++] = src[i]; break;
		}
	}
	dst[j] = '\0';
}

static void log_ts(const char *level, const char *fmt, ...)
{
	fprintf(stderr, "[%s] ", level);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

/* Debug log — only printed when log_level >= 2 */
static void log_debug(const char *fmt, ...)
{
	if (cfg_log_level < 2)
		return;
	fprintf(stderr, "[DEBUG] ");
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

/* ── event builder ────────────────────────────────────────────────── */

/* Build a metric_event from a BPF ring buffer event */
static void event_from_bpf(struct metric_event *out, const struct event *e,
			    const char *event_type, const char *rule_name,
			    const char *tags, const char *cgroup)
{
	memset(out, 0, sizeof(*out));
	/* Use wall-clock time instead of boot-relative BPF timestamp */
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	out->timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
			  + (__u64)ts_now.tv_nsec;
	snprintf(out->event_type, sizeof(out->event_type), "%s", event_type);
	snprintf(out->rule, sizeof(out->rule), "%s", rule_name);
	if (tags)
		snprintf(out->tags, sizeof(out->tags), "%s", tags);
	out->root_pid = e->root_pid;
	out->pid = e->tgid;
	out->ppid = e->ppid;
	out->uid = e->uid;
	memcpy(out->comm, e->comm, COMM_LEN);
	cmdline_split(e->cmdline, e->cmdline_len,
		      out->exec_path, sizeof(out->exec_path),
		      out->args, sizeof(out->args));
	if (cgroup)
		snprintf(out->cgroup, sizeof(out->cgroup), "%s", cgroup);
	/* exit-specific fields */
	out->exit_code = (e->exit_code >> 8) & 0xff;
	out->cpu_ns = e->cpu_ns;
	out->rss_max_bytes = e->rss_max_pages * (unsigned long)sysconf(_SC_PAGESIZE);
	out->rss_min_bytes = e->rss_min_pages * (unsigned long)sysconf(_SC_PAGESIZE);
	out->oom_killed = e->oom_killed;
	out->net_tx_bytes = e->net_tx_bytes;
	out->net_rx_bytes = e->net_rx_bytes;
	out->start_time_ns = e->start_ns;
	/* new fields */
	out->loginuid      = e->loginuid;
	out->sessionid     = e->sessionid;
	out->euid          = e->euid;
	out->tty_nr        = e->tty_nr;
	out->sched_policy  = e->sched_policy;
	out->io_rchar      = e->io_rchar;
	out->io_wchar      = e->io_wchar;
	out->io_syscr      = e->io_syscr;
	out->io_syscw      = e->io_syscw;
	out->mnt_ns_inum   = e->mnt_ns_inum;
	out->pid_ns_inum   = e->pid_ns_inum;
	out->net_ns_inum   = e->net_ns_inum;
	out->cgroup_ns_inum = e->cgroup_ns_inum;
}

/* ── initial process scan (one-time /proc read at startup) ────────── */

/*
 * Parse /proc/PID/stat: extract comm, state, ppid, utime, stime,
 * threads, starttime, vsize, rss.
 */
static int read_proc_stat(__u32 pid, struct proc_info *pi)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char buf[1024];
	if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
	fclose(f);

	/* comm: between first '(' and last ')' */
	char *lp = strchr(buf, '(');
	char *rp = strrchr(buf, ')');
	if (!lp || !rp || rp <= lp) return -1;
	int clen = (int)(rp - lp - 1);
	if (clen > COMM_LEN - 1) clen = COMM_LEN - 1;
	memcpy(pi->comm, lp + 1, clen);
	pi->comm[clen] = '\0';

	/* fields after ") " :
	 * state ppid pgrp session tty_nr tpgid flags
	 * minflt cminflt majflt cmajflt utime stime cutime cstime
	 * priority nice num_threads itrealvalue starttime vsize rss */
	char *p = rp + 2;
	char state;
	int ppid;
	int tty_nr;
	unsigned long minflt, cminflt, majflt, cmajflt;
	unsigned long utime, stime, starttime, vsize;
	long rss;
	int threads;
	if (sscanf(p,
		   "%c %d %*d %*d %d %*d %*d "
		   "%lu %lu %lu %lu %lu %lu %*d %*d "
		   "%*d %*d %d %*d %lu %lu %ld",
		   &state, &ppid, &tty_nr,
		   &minflt, &cminflt, &majflt, &cmajflt,
		   &utime, &stime,
		   &threads, &starttime, &vsize, &rss) != 13)
		return -1;

	pi->ppid = (__u32)ppid;
	pi->tty_nr = (__u32)(tty_nr > 0 ? tty_nr : 0);
	pi->state = (__u8)state;
	pi->threads = (__u32)threads;
	pi->rss_pages = rss > 0 ? (__u64)rss : 0;
	pi->rss_min_pages = pi->rss_pages;
	pi->rss_max_pages = pi->rss_pages;
	pi->maj_flt = (__u64)(majflt + cmajflt);
	pi->min_flt = (__u64)(minflt + cminflt);

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = 4096;
	pi->vsize_pages = (__u64)(vsize / page_size);

	long clk_tck = sysconf(_SC_CLK_TCK);
	if (clk_tck <= 0) clk_tck = 100;
	pi->cpu_ns = ((__u64)(utime + stime) * 1000000000ULL) / (__u64)clk_tck;
	pi->start_ns = ((__u64)starttime * 1000000000ULL) / (__u64)clk_tck;

	/* Read extra fields from /proc/PID/status */
	char spath[64];
	snprintf(spath, sizeof(spath), "/proc/%u/status", pid);
	FILE *sf = fopen(spath, "r");
	if (sf) {
		char sline[256];
		while (fgets(sline, sizeof(sline), sf)) {
			unsigned long val;
			unsigned int uid_val;
			if (sscanf(sline, "Uid:\t%u", &uid_val) == 1)
				pi->uid = (__u32)uid_val;
			else if (sscanf(sline, "RssShmem: %lu kB", &val) == 1)
				pi->shmem_pages = (__u64)(val * 1024 / page_size);
			else if (sscanf(sline, "VmSwap: %lu kB", &val) == 1)
				pi->swap_pages = (__u64)(val * 1024 / page_size);
			else if (sscanf(sline, "voluntary_ctxt_switches: %lu", &val) == 1)
				pi->nvcsw = (__u64)val;
			else if (sscanf(sline, "nonvoluntary_ctxt_switches: %lu", &val) == 1)
				pi->nivcsw = (__u64)val;
		}
		fclose(sf);
	}

	/* Read IO from /proc/PID/io (requires root or ptrace) */
	char iopath[64];
	snprintf(iopath, sizeof(iopath), "/proc/%u/io", pid);
	FILE *iof = fopen(iopath, "r");
	if (iof) {
		char ioline[128];
		while (fgets(ioline, sizeof(ioline), iof)) {
			unsigned long long val;
			if (sscanf(ioline, "read_bytes: %llu", &val) == 1)
				pi->io_read_bytes = (__u64)val;
			else if (sscanf(ioline, "write_bytes: %llu", &val) == 1)
				pi->io_write_bytes = (__u64)val;
		}
		fclose(iof);
	}

	return 0;
}

static int read_proc_cmdline(__u32 pid, char *dst, int dstlen)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	int len = (int)fread(dst, 1, dstlen - 1, f);
	fclose(f);
	if (len < 0) len = 0;
	dst[len] = '\0';
	return len;
}

static __u64 read_proc_cgroup_id(__u32 pid)
{
	char path[64], buf[512];
	snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;

	/* Find cgroup v2 line "0::/path" or fallback to first line */
	char cg_path[256] = "";
	while (fgets(buf, sizeof(buf), f)) {
		buf[strcspn(buf, "\n")] = '\0';
		if (strncmp(buf, "0::", 3) == 0) {
			snprintf(cg_path, sizeof(cg_path), "%s", buf + 3);
			break;
		}
		if (cg_path[0] == '\0') {
			char *last = strrchr(buf, ':');
			if (last) snprintf(cg_path, sizeof(cg_path), "%s", last + 1);
		}
	}
	fclose(f);

	if (cg_path[0] == '\0' || strcmp(cg_path, "/") == 0)
		return 0;

	/* Strip leading / */
	char *rel = cg_path;
	if (*rel == '/') rel++;

	/* stat the cgroup dir to get inode = cgroup_id */
	char full[PATH_MAX_LEN];
	snprintf(full, sizeof(full), "/sys/fs/cgroup/%s", rel);
	struct stat st;
	if (stat(full, &st) == 0)
		return (__u64)st.st_ino;
	return 0;
}

static __s16 read_proc_oom(__u32 pid)
{
	char path[64], buf[32];
	snprintf(path, sizeof(path), "/proc/%u/oom_score_adj", pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
	fclose(f);
	return (__s16)atoi(buf);
}

/*
 * Read tty_nr from /proc/PID/stat (field 7 after pid and comm).
 * Returns 0 if process has no controlling terminal.
 */
static __u32 read_proc_tty_nr(__u32 pid)
{
	char path[64], buf[512];
	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
	fclose(f);
	char *rp = strrchr(buf, ')');
	if (!rp) return 0;
	/* fields: state ppid pgrp session tty_nr */
	char state;
	int ppid, pgrp, session, tty;
	if (sscanf(rp + 2, "%c %d %d %d %d", &state, &ppid, &pgrp, &session, &tty) != 5)
		return 0;
	return (__u32)(tty > 0 ? tty : 0);
}

/*
 * One-time startup scan: read /proc, match rules, populate BPF maps.
 * After this, all tracking is event-driven via BPF.
 */

struct scan_entry {
	__u32 pid;
	__u32 ppid;
};

#define MAX_SCAN 8192

static void track_pid_from_proc(__u32 pid, int rule_id, __u32 root_pid,
				__u8 is_root)
{
	struct track_info ti = {
		.root_pid = root_pid,
		.rule_id  = (__u16)rule_id,
		.is_root  = is_root,
	};
	bpf_map_update_elem(tracked_map_fd, &pid, &ti, BPF_ANY);

	struct proc_info pi = {0};
	pi.tgid = pid;
	if (read_proc_stat(pid, &pi) != 0)
		return;
	pi.cmdline_len = (__u16)read_proc_cmdline(pid, pi.cmdline, CMDLINE_MAX);
	pi.cgroup_id = read_proc_cgroup_id(pid);
	pi.oom_score_adj = read_proc_oom(pid);
	bpf_map_update_elem(proc_map_fd, &pid, &pi, BPF_ANY);
}

static void add_descendants(struct scan_entry *entries, int count,
			    __u32 parent, int rule_id, __u32 root_pid,
			    int *tracked)
{
	for (int i = 0; i < count; i++) {
		if (entries[i].ppid != parent)
			continue;
		__u32 child = entries[i].pid;
		/* Skip if already tracked */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &child, &ti) == 0)
			continue;
		track_pid_from_proc(child, rule_id, root_pid, 0);
		tags_inherit(child, parent);
		(*tracked)++;
		add_descendants(entries, count, child, rule_id, root_pid, tracked);
	}
}

static void initial_scan(void)
{
	log_ts("INFO", "initial scan: reading /proc...");

	DIR *pd = opendir("/proc");
	if (!pd) {
		log_ts("WARN", "cannot open /proc, skipping initial scan");
		return;
	}

	static struct scan_entry entries[MAX_SCAN];
	int count = 0;
	__u32 our_pid = (__u32)getpid();

	/* Pass 1: collect all PIDs and ppids */
	struct dirent *de;
	while ((de = readdir(pd)) != NULL && count < MAX_SCAN) {
		if (de->d_type != DT_DIR && de->d_type != DT_UNKNOWN)
			continue;
		int pid = atoi(de->d_name);
		if (pid <= 0) continue;

		char path[64], buf[512];
		snprintf(path, sizeof(path), "/proc/%d/stat", pid);
		FILE *f = fopen(path, "r");
		if (!f) continue;
		if (!fgets(buf, sizeof(buf), f)) { fclose(f); continue; }
		fclose(f);

		char *rp = strrchr(buf, ')');
		if (!rp) continue;
		int ppid = 0;
		sscanf(rp + 2, "%*c %d", &ppid);

		entries[count].pid = (__u32)pid;
		entries[count].ppid = (__u32)ppid;
		count++;
	}
	closedir(pd);

	/* Pass 2: match cmdlines against rules, find roots */
	int tracked = 0;
	for (int i = 0; i < count; i++) {
		__u32 pid = entries[i].pid;
		if (pid == our_pid || pid <= 1)
			continue;

		char cmdline_raw[CMDLINE_MAX];
		int clen = read_proc_cmdline(pid, cmdline_raw, sizeof(cmdline_raw));
		if (clen <= 0)
			continue;

		char cmdline_str[CMDLINE_MAX + 1];
		cmdline_to_str(cmdline_raw, (__u16)clen, cmdline_str,
			       sizeof(cmdline_str));

		char tags_buf[TAGS_MAX_LEN];
		int first = match_rules_all(cmdline_str, tags_buf,
					    sizeof(tags_buf));
		if (first >= 0 && !rules[first].ignore) {
			/* Root match */
			track_pid_from_proc(pid, first, pid, 1);
			tags_store(pid, tags_buf);
			tracked++;
			log_debug("SCAN: pid=%u rule=%s tags=%s cmdline=%.60s",
				  pid, rules[first].name, tags_buf,
				  cmdline_str);

			/* Find all descendants */
			add_descendants(entries, count, pid, first, pid,
					&tracked);
		}
	}

	log_ts("INFO", "initial scan: %d processes scanned, %d tracked",
	       count, tracked);
}

/* ── ring buffer event handler ────────────────────────────────────── */

/*
 * handle_event — callback для каждого BPF-события из ring buffer.
 *
 * Вызывается из ring_buffer__poll() → ringbuf_process_ring().
 * Всегда возвращает 0, чтобы не прерывать обработку очереди.
 *
 * Типы событий:
 *   FILE_CLOSE       — закрытие отслеживаемого файла (~115/сек, самый частый)
 *   NET_CLOSE        — закрытие TCP-соединения (~9/сек)
 *   SIGNAL           — доставка сигнала (редкий)
 *   TCP_RETRANSMIT   — повторная передача TCP-сегмента (редкий)
 *   SYN_RECV         — входящий SYN-запрос (редкий)
 *   RST              — отправка/получение TCP RST (редкий)
 *   EXEC             — вызов exec (~4/сек)
 *   FORK             — создание процесса (~4/сек)
 *   EXIT             — завершение процесса (~4/сек)
 *   OOM_KILL         — убийство процесса OOM killer (редкий)
 */
static int handle_event(void *ctx, void *data, size_t size)
{
	(void)ctx;

	/* Все структуры событий имеют __u32 type по смещению 0 */
	if (size < sizeof(__u32))
		return 0;
	__u32 type = *(const __u32 *)data;

	/* ── FILE_CLOSE — закрытие отслеживаемого файла ──────────────────
	 *
	 * Самое частое событие (~115/сек). Оптимизирован для минимума syscall:
	 *   1× bpf_map_lookup_elem — проверка, что процесс всё ещё отслеживается
	 *   1× write()            — запись в буферный файл (ef_append)
	 *
	 * BPF-сторона (openat) уже фильтрует по tracked_map, поэтому сюда
	 * приходят только события от отслеживаемых процессов.
	 * Временная метка берётся из BPF (boot_ns) + g_boot_to_wall_ns,
	 * без вызова clock_gettime.
	 * Cgroup резолвится из кэша (resolve_cgroup_fast), без обхода /sys.
	 */
	if (type == EVENT_FILE_CLOSE) {
		if (size < sizeof(struct file_event))
			return 0;
		const struct file_event *fe = data;

		/* Единственный lookup — пропускаем, если процесс умер между open и close */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &fe->tgid, &ti) != 0)
			return 0;

		/* Имя правила по rule_id из track_info (O(1)) */
		const char *rname = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : "?";

		log_debug("FILE_CLOSE: pid=%u rule=%s path=%.60s "
			  "read=%llu write=%llu opens=%u",
			  fe->tgid, rname, fe->path,
			  (unsigned long long)fe->read_bytes,
			  (unsigned long long)fe->write_bytes,
			  fe->open_count);

		if (g_http_cfg.enabled) {
			/* Формирование metric_event для записи в буфер */
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			/* Время: BPF boot_ns → wall clock через предвычисленное смещение */
			cev.timestamp_ns = fe->timestamp_ns
					 + (__u64)g_boot_to_wall_ns;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 "file_close");
			snprintf(cev.rule, sizeof(cev.rule), "%s", rname);

			/* Теги из userspace hash table (O(1)) */
			snprintf(cev.tags, sizeof(cev.tags), "%s",
				 tags_lookup(fe->tgid));
			cev.root_pid = ti.root_pid;
			cev.is_root = ti.is_root;
			cev.pid = fe->tgid;
			cev.ppid = fe->ppid;
			cev.uid = fe->uid;
			memcpy(cev.comm, fe->comm, COMM_LEN);

			/* Cgroup из кэша — линейный поиск по ~50 записям, без syscall */
			const char *cg = resolve_cgroup_fast(fe->cgroup_id);
			if (cg[0])
				snprintf(cev.cgroup, sizeof(cev.cgroup),
					 "%s", cg);

			/* Файловые метрики: путь, флаги, прочитано/записано, кол-во открытий */
			snprintf(cev.file_path, sizeof(cev.file_path),
				 "%s", fe->path);
			cev.file_flags = (__u32)fe->flags;
			cev.file_read_bytes = fe->read_bytes;
			cev.file_write_bytes = fe->write_bytes;
			cev.file_open_count = fe->open_count;

			/* Запись в буферный файл (1× write syscall) */
			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	/* ── NET_CLOSE — закрытие TCP-соединения ─────────────────────────
	 *
	 * Второе по частоте событие (~9/сек). Оптимизирован аналогично FILE_CLOSE.
	 *
	 * ВАЖНО: BPF-сторона (tcp_connect/accept) НЕ фильтрует по tracked_map —
	 * события приходят для ВСЕХ процессов на хосте. Фильтрация выполняется
	 * здесь одним bpf_map_lookup_elem: если PID не в tracked_map — пропускаем.
	 */
	if (type == EVENT_NET_CLOSE) {
		if (size < sizeof(struct net_event))
			return 0;
		const struct net_event *ne = data;

		/* Единственный lookup — пропускаем неотслеживаемые процессы */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &ne->tgid, &ti) != 0)
			return 0;

		/* Имя правила по rule_id (O(1)) */
		const char *rname = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : "?";

		log_debug("NET_CLOSE: pid=%u rule=%s port=%u→%u "
			  "tx=%llu rx=%llu dur=%llums",
			  ne->tgid, rname, ne->local_port, ne->remote_port,
			  (unsigned long long)ne->tx_bytes,
			  (unsigned long long)ne->rx_bytes,
			  (unsigned long long)(ne->duration_ns / 1000000));

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			/* Время: BPF boot_ns → wall clock */
			cev.timestamp_ns = ne->timestamp_ns
					 + (__u64)g_boot_to_wall_ns;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 "net_close");
			snprintf(cev.rule, sizeof(cev.rule), "%s", rname);
			snprintf(cev.tags, sizeof(cev.tags), "%s",
				 tags_lookup(ne->tgid));
			cev.root_pid = ti.root_pid;
			cev.is_root = ti.is_root;
			cev.pid = ne->tgid;
			cev.ppid = ne->ppid;
			cev.uid = ne->uid;
			memcpy(cev.comm, ne->comm, COMM_LEN);

			/* Cgroup из кэша */
			const char *cg = resolve_cgroup_fast(ne->cgroup_id);
			if (cg[0])
				snprintf(cev.cgroup, sizeof(cev.cgroup),
					 "%s", cg);

			/* Форматирование IP-адресов */
			if (ne->af == 2) { /* AF_INET — IPv4 */
				snprintf(cev.net_local_addr,
					 sizeof(cev.net_local_addr),
					 "%u.%u.%u.%u",
					 ne->local_addr[0], ne->local_addr[1],
					 ne->local_addr[2], ne->local_addr[3]);
				snprintf(cev.net_remote_addr,
					 sizeof(cev.net_remote_addr),
					 "%u.%u.%u.%u",
					 ne->remote_addr[0], ne->remote_addr[1],
					 ne->remote_addr[2], ne->remote_addr[3]);
			} else if (ne->af == 10) { /* AF_INET6 — IPv6 */
				inet_ntop(AF_INET6, ne->local_addr,
					  cev.net_local_addr,
					  sizeof(cev.net_local_addr));
				inet_ntop(AF_INET6, ne->remote_addr,
					  cev.net_remote_addr,
					  sizeof(cev.net_remote_addr));
			}

			/* Сетевые метрики: порты, байты, длительность */
			cev.net_local_port = ne->local_port;
			cev.net_remote_port = ne->remote_port;
			cev.net_conn_tx_bytes = ne->tx_bytes;
			cev.net_conn_rx_bytes = ne->rx_bytes;
			cev.net_duration_ms = ne->duration_ns / 1000000;

			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	/* ── SIGNAL — доставка сигнала ───────────────────────────────────
	 *
	 * Редкое событие. Захватывает все сигналы (SIGTERM, SIGKILL, и т.д.).
	 * Правило определяется сначала по отправителю, затем по получателю.
	 * Имя процесса-получателя читается из /proc/<pid>/comm.
	 */
	if (type == EVENT_SIGNAL) {
		if (size < sizeof(struct signal_event))
			return 0;
		const struct signal_event *se = data;

		/* Определяем правило: сначала по отправителю, потом по получателю */
		struct track_info ti;
		const char *rname = "?";
		if (bpf_map_lookup_elem(tracked_map_fd, &se->sender_tgid, &ti) == 0)
			rname = (ti.rule_id < num_rules)
				? rules[ti.rule_id].name : "?";
		if (rname[0] == '?' && rname[1] == '\0') {
			if (bpf_map_lookup_elem(tracked_map_fd, &se->target_pid, &ti) == 0)
				rname = (ti.rule_id < num_rules)
					? rules[ti.rule_id].name : "?";
		}

		log_debug("SIGNAL: sender=%u→target=%u sig=%d code=%d result=%d "
			  "rule=%s comm=%.16s",
			  se->sender_tgid, se->target_pid, se->sig,
			  se->sig_code, se->sig_result, rname,
			  se->sender_comm);

		if (g_http_cfg.enabled) {
			const char *cg = resolve_cgroup(se->cgroup_id);
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			/* Время: clock_gettime (сигналы редкие, допустим syscall) */
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
					 + (__u64)ts_now.tv_nsec;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 "signal");
			snprintf(cev.rule, sizeof(cev.rule), "%s", rname);

			/* Теги: сначала отправителя, потом получателя */
			const char *sig_tags = tags_lookup(se->sender_tgid);
			if (!sig_tags[0])
				sig_tags = tags_lookup(se->target_pid);
			snprintf(cev.tags, sizeof(cev.tags), "%s", sig_tags);

			/* Данные отправителя из tracked_map */
			if (bpf_map_lookup_elem(tracked_map_fd,
						&se->sender_tgid, &ti) == 0) {
				cev.root_pid = ti.root_pid;
				cev.is_root = ti.is_root;
			}
			cev.pid = se->sender_tgid;
			cev.uid = se->sender_uid;
			memcpy(cev.comm, se->sender_comm, COMM_LEN);
			if (cg)
				snprintf(cev.cgroup, sizeof(cev.cgroup),
					 "%s", cg);

			/* Идентификация отправителя из proc_info (loginuid, tty, ...) */
			struct proc_info sender_pi;
			if (bpf_map_lookup_elem(proc_map_fd,
						&se->sender_tgid,
						&sender_pi) == 0) {
				cev.loginuid = sender_pi.loginuid;
				cev.sessionid = sender_pi.sessionid;
				cev.euid = sender_pi.euid;
				cev.tty_nr = sender_pi.tty_nr;
			}

			/* Поля сигнала: номер, PID получателя, код, результат */
			cev.sig_num = (__u32)se->sig;
			cev.sig_target_pid = se->target_pid;
			cev.sig_code = se->sig_code;
			cev.sig_result = se->sig_result;

			/* Чтение имени процесса-получателя из /proc/<pid>/comm */
			char tcomm_path[64], tcomm_buf[COMM_LEN + 2];
			snprintf(tcomm_path, sizeof(tcomm_path),
				 "/proc/%u/comm", se->target_pid);
			FILE *tcf = fopen(tcomm_path, "r");
			if (tcf) {
				if (fgets(tcomm_buf, sizeof(tcomm_buf), tcf)) {
					tcomm_buf[strcspn(tcomm_buf, "\n")] = 0;
					snprintf(cev.sig_target_comm,
						 sizeof(cev.sig_target_comm),
						 "%s", tcomm_buf);
				}
				fclose(tcf);
			}

			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	/* ── TCP_RETRANSMIT — повторная передача TCP-сегмента ────────────
	 *
	 * Редкое событие. Симптом потери пакетов, перегрузки сети или DDoS.
	 * НЕ фильтруется по tracked_map — захватывает ВСЕ соединения на хосте.
	 */
	if (type == EVENT_TCP_RETRANSMIT) {
		if (size < sizeof(struct retransmit_event))
			return 0;
		const struct retransmit_event *re = data;

		log_debug("TCP_RETRANSMIT: pid=%u port=%u→%u state=%u",
			  re->tgid, re->local_port, re->remote_port,
			  re->state);

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			/* Время: clock_gettime (ретрансмиты редкие) */
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
					 + (__u64)ts_now.tv_nsec;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 "tcp_retrans");
			cev.pid = re->tgid;
			cev.uid = re->uid;
			memcpy(cev.comm, re->comm, COMM_LEN);
			const char *cg = resolve_cgroup(re->cgroup_id);
			if (cg)
				snprintf(cev.cgroup, sizeof(cev.cgroup),
					 "%s", cg);

			/* Определяем правило, если процесс отслеживается */
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd,
						&re->tgid, &ti) == 0) {
				if (ti.rule_id < num_rules)
					snprintf(cev.rule, sizeof(cev.rule),
						 "%s", rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				const char *t = tags_lookup(re->tgid);
				snprintf(cev.tags, sizeof(cev.tags), "%s", t);
			}

			/* Адреса и порты TCP-соединения */
			cev.sec_af = re->af;
			cev.sec_local_port = re->local_port;
			cev.sec_remote_port = re->remote_port;
			cev.sec_tcp_state = re->state;
			if (re->af == 2) {
				snprintf(cev.sec_local_addr,
					 sizeof(cev.sec_local_addr),
					 "%u.%u.%u.%u",
					 re->local_addr[0], re->local_addr[1],
					 re->local_addr[2], re->local_addr[3]);
				snprintf(cev.sec_remote_addr,
					 sizeof(cev.sec_remote_addr),
					 "%u.%u.%u.%u",
					 re->remote_addr[0], re->remote_addr[1],
					 re->remote_addr[2], re->remote_addr[3]);
			} else if (re->af == 10) {
				inet_ntop(AF_INET6, re->local_addr,
					  cev.sec_local_addr,
					  sizeof(cev.sec_local_addr));
				inet_ntop(AF_INET6, re->remote_addr,
					  cev.sec_remote_addr,
					  sizeof(cev.sec_remote_addr));
			}
			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	/* ── SYN_RECV — входящий SYN-запрос (полу-открытое соединение) ───
	 *
	 * Редкое событие. Полезно для обнаружения SYN flood атак.
	 * НЕ фильтруется по tracked_map — захватывает ВСЕ входящие SYN.
	 */
	if (type == EVENT_SYN_RECV) {
		if (size < sizeof(struct syn_event))
			return 0;
		const struct syn_event *se_syn = data;

		log_debug("SYN_RECV: pid=%u port=%u←%u",
			  se_syn->tgid, se_syn->local_port,
			  se_syn->remote_port);

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
					 + (__u64)ts_now.tv_nsec;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 "syn_recv");
			cev.pid = se_syn->tgid;
			cev.uid = se_syn->uid;
			memcpy(cev.comm, se_syn->comm, COMM_LEN);
			const char *cg = resolve_cgroup(se_syn->cgroup_id);
			if (cg)
				snprintf(cev.cgroup, sizeof(cev.cgroup),
					 "%s", cg);
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd,
						&se_syn->tgid, &ti) == 0) {
				if (ti.rule_id < num_rules)
					snprintf(cev.rule, sizeof(cev.rule),
						 "%s", rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				const char *t = tags_lookup(se_syn->tgid);
				snprintf(cev.tags, sizeof(cev.tags), "%s", t);
			}
			cev.sec_af = se_syn->af;
			cev.sec_local_port = se_syn->local_port;
			cev.sec_remote_port = se_syn->remote_port;
			if (se_syn->af == 2) {
				snprintf(cev.sec_local_addr,
					 sizeof(cev.sec_local_addr),
					 "%u.%u.%u.%u",
					 se_syn->local_addr[0],
					 se_syn->local_addr[1],
					 se_syn->local_addr[2],
					 se_syn->local_addr[3]);
				snprintf(cev.sec_remote_addr,
					 sizeof(cev.sec_remote_addr),
					 "%u.%u.%u.%u",
					 se_syn->remote_addr[0],
					 se_syn->remote_addr[1],
					 se_syn->remote_addr[2],
					 se_syn->remote_addr[3]);
			} else if (se_syn->af == 10) {
				inet_ntop(AF_INET6, se_syn->local_addr,
					  cev.sec_local_addr,
					  sizeof(cev.sec_local_addr));
				inet_ntop(AF_INET6, se_syn->remote_addr,
					  cev.sec_remote_addr,
					  sizeof(cev.sec_remote_addr));
			}
			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	/* ── RST — отправка/получение TCP RST пакета ────────────────────
	 *
	 * Редкое событие. Много RST = сканирование портов или обрыв соединений.
	 * НЕ фильтруется по tracked_map — захватывает ВСЕ RST на хосте.
	 * Поле direction: 0 = отправлен (sent), 1 = получен (recv).
	 */
	if (type == EVENT_RST) {
		if (size < sizeof(struct rst_event))
			return 0;
		const struct rst_event *rste = data;

		log_debug("RST: pid=%u port=%u↔%u dir=%s",
			  rste->tgid, rste->local_port, rste->remote_port,
			  rste->direction ? "recv" : "sent");

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
					 + (__u64)ts_now.tv_nsec;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 rste->direction ? "rst_recv" : "rst_sent");
			cev.pid = rste->tgid;
			cev.uid = rste->uid;
			memcpy(cev.comm, rste->comm, COMM_LEN);
			const char *cg = resolve_cgroup(rste->cgroup_id);
			if (cg)
				snprintf(cev.cgroup, sizeof(cev.cgroup),
					 "%s", cg);
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd,
						&rste->tgid, &ti) == 0) {
				if (ti.rule_id < num_rules)
					snprintf(cev.rule, sizeof(cev.rule),
						 "%s", rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				const char *t = tags_lookup(rste->tgid);
				snprintf(cev.tags, sizeof(cev.tags), "%s", t);
			}
			cev.sec_af = rste->af;
			cev.sec_local_port = rste->local_port;
			cev.sec_remote_port = rste->remote_port;
			cev.sec_direction = rste->direction;
			if (rste->af == 2) {
				snprintf(cev.sec_local_addr,
					 sizeof(cev.sec_local_addr),
					 "%u.%u.%u.%u",
					 rste->local_addr[0],
					 rste->local_addr[1],
					 rste->local_addr[2],
					 rste->local_addr[3]);
				snprintf(cev.sec_remote_addr,
					 sizeof(cev.sec_remote_addr),
					 "%u.%u.%u.%u",
					 rste->remote_addr[0],
					 rste->remote_addr[1],
					 rste->remote_addr[2],
					 rste->remote_addr[3]);
			} else if (rste->af == 10) {
				inet_ntop(AF_INET6, rste->local_addr,
					  cev.sec_local_addr,
					  sizeof(cev.sec_local_addr));
				inet_ntop(AF_INET6, rste->remote_addr,
					  cev.sec_remote_addr,
					  sizeof(cev.sec_remote_addr));
			}
			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	/* ── Основные события жизненного цикла процесса ─────────────────
	 *
	 * Общая структура struct event (содержит cmdline, proc info и т.д.).
	 * EXEC, FORK, EXIT — по ~4/сек каждый, OOM_KILL — крайне редкий.
	 */
	const struct event *e = data;
	if (size < sizeof(*e))
		return 0;

	switch (e->type) {

	/* ── EXEC — вызов exec (запуск нового процесса) ──────────────── */
	case EVENT_EXEC: {
		/* Уже отслеживается? BPF обновил proc_info, нам делать нечего */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0)
			break;

		/* Преобразуем cmdline из BPF (нуль-разделённые аргументы) в строку */
		char cmdline[CMDLINE_MAX + 1];
		cmdline_to_str(e->cmdline, e->cmdline_len, cmdline, sizeof(cmdline));

		/* Проверяем все правила (regexec × N правил) — тяжёлый, но exec редкий */
		char tags_buf[TAGS_MAX_LEN];
		int first = match_rules_all(cmdline, tags_buf,
					    sizeof(tags_buf));
		if (first >= 0 && !rules[first].ignore) {
			/* Совпадение — начинаем отслеживание */
			struct track_info new_ti = {
				.root_pid = e->tgid,
				.rule_id  = (__u16)first,
				.is_root  = 1,
			};
			bpf_map_update_elem(tracked_map_fd, &e->tgid,
					    &new_ti, BPF_ANY);
			tags_store(e->tgid, tags_buf);

			/* Сохраняем метаданные процесса в proc_map */
			struct proc_info pi = {0};
			pi.tgid      = e->tgid;
			pi.ppid      = e->ppid;
			pi.start_ns  = e->start_ns;
			pi.cgroup_id = e->cgroup_id;
			memcpy(pi.comm, e->comm, COMM_LEN);
			memcpy(pi.cmdline, e->cmdline, CMDLINE_MAX);
			pi.cmdline_len = e->cmdline_len;
			bpf_map_update_elem(proc_map_fd, &e->tgid, &pi, BPF_ANY);

			log_debug("TRACK: pid=%u rule=%s tags=%s comm=%.16s",
				  e->tgid, rules[first].name, tags_buf,
				  e->comm);

			/* Отправляем exec-событие в буферный файл (→ ClickHouse) */
			if (g_http_cfg.enabled) {
				const char *cg = resolve_cgroup(e->cgroup_id);
				struct metric_event cev;
				event_from_bpf(&cev, e, "exec",
					       rules[first].name,
					       tags_buf, cg);
				cev.is_root = 1;
				ef_append(&cev, cfg_hostname);
			}
		}
		break;
	}

	/* ── FORK — создание дочернего процесса ──────────────────────── */
	case EVENT_FORK: {
		/* BPF handle_fork уже создал tracked_map и proc_info записи.
		 * Здесь только наследуем tags (они живут в userspace hash table). */
		struct track_info parent_ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->ppid, &parent_ti) != 0)
			break;
		tags_inherit(e->tgid, e->ppid);

		/* Наследуем tty_nr от родителя (BPF не может читать signal->tty).
		 * Дочерний процесс наследует управляющий терминал при fork. */
		__u32 child_tty = 0;
		{
			struct proc_info parent_pi;
			if (bpf_map_lookup_elem(proc_map_fd, &e->ppid, &parent_pi) == 0)
				child_tty = parent_pi.tty_nr;
		}
		/* Если у родителя нет tty — читаем из /proc */
		if (!child_tty)
			child_tty = read_proc_tty_nr(e->tgid);
		if (child_tty) {
			struct proc_info pi;
			if (bpf_map_lookup_elem(proc_map_fd, &e->tgid, &pi) == 0) {
				pi.tty_nr = child_tty;
				bpf_map_update_elem(proc_map_fd, &e->tgid, &pi, BPF_EXIST);
			}
		}

		/* Отправляем fork-событие в буферный файл */
		if (g_http_cfg.enabled) {
			const char *rname = (parent_ti.rule_id < num_rules)
				? rules[parent_ti.rule_id].name : "unknown";
			const char *cg = resolve_cgroup(e->cgroup_id);
			struct metric_event cev;
			event_from_bpf(&cev, e, "fork", rname,
				       tags_lookup(e->tgid), cg);
			cev.root_pid = parent_ti.root_pid;
			cev.tty_nr = child_tty;
			ef_append(&cev, cfg_hostname);
		}
		break;
	}

	/* ── EXIT — завершение процесса ──────────────────────────────── */
	case EVENT_EXIT: {
		/* Определяем rule_id — BPF передаёт его в event, но может быть невалидным */
		__u32 exit_rule_id = e->rule_id;
		if (exit_rule_id >= num_rules) {
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) != 0)
				try_track_pid(e->tgid);
			if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0)
				exit_rule_id = ti.rule_id;
		}
		const char *rname = (exit_rule_id < num_rules)
			? rules[exit_rule_id].name : "?";

		/* Теги: если нет — пробуем отследить или наследовать от родителя */
		const char *exit_tags = tags_lookup(e->tgid);
		if (!exit_tags[0]) {
			if (try_track_pid(e->tgid) < 0)
				tags_inherit(e->tgid, e->ppid);
			exit_tags = tags_lookup(e->tgid);
		}

		/* Декодирование кода завершения: сигнал (младшие 7 бит) + статус */
		int sig = e->exit_code & 0x7f;
		int status = (e->exit_code >> 8) & 0xff;

		log_debug("EXIT: pid=%u rule=%s exit_code=%d "
			  "signal=%d cpu=%.2fs rss_max=%lluMB%s",
			  e->tgid, rname, status, sig,
			  (double)e->cpu_ns / 1e9,
			  (unsigned long long)(e->rss_max_pages * 4 / 1024),
			  e->oom_killed ? " [OOM]" : "");

		/* Сохраняем в кольцевой буфер завершённых процессов (для snapshot) */
		record_exit(e);
		tags_remove(e->tgid);

		/* Отправляем exit-событие в буферный файл */
		if (g_http_cfg.enabled) {
			const char *cg = resolve_cgroup(e->cgroup_id);
			struct metric_event cev;
			event_from_bpf(&cev, e, "exit", rname, exit_tags, cg);
			ef_append(&cev, cfg_hostname);
		}
		/* BPF уже удалил запись из tracked_map и proc_map */
		break;
	}

	/* ── OOM_KILL — убийство процесса OOM killer ─────────────────── */
	case EVENT_OOM_KILL: {
		/* Пробуем определить правило: сначала по PID, потом по родителю */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) != 0)
			try_track_pid(e->tgid);
		const char *rname = "?";
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0)
			rname = (ti.rule_id < num_rules)
				? rules[ti.rule_id].name : "?";
		if (rname[0] == '?' && rname[1] == '\0') {
			if (bpf_map_lookup_elem(tracked_map_fd, &e->ppid, &ti) == 0)
				rname = (ti.rule_id < num_rules)
					? rules[ti.rule_id].name : "?";
		}
		log_ts("WARN", "OOM_KILL: pid=%u rule=%s comm=%.16s "
		       "rss=%lluMB",
		       e->tgid, rname, e->comm,
		       (unsigned long long)(e->rss_pages * 4 / 1024));

		/* Отправляем oom_kill-событие в буферный файл */
		if (g_http_cfg.enabled) {
			const char *cg = resolve_cgroup(e->cgroup_id);
			struct metric_event cev;
			event_from_bpf(&cev, e, "oom_kill", rname,
				       tags_lookup(e->tgid), cg);
			ef_append(&cev, cfg_hostname);
		}
		break;
	}

	default:
		break;
	}

	/* Всегда 0 — не прерывает обработку ring buffer */
	return 0;
}


/* ── snapshot: write .prom file ───────────────────────────────────── */

static long long read_cgroup_value(const char *cg_path, const char *file)
{
	char path[PATH_MAX_LEN];
	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s", cg_path, file);
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	char buf[64];
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	if (strncmp(buf, "max", 3) == 0)
		return 0;
	return strtoll(buf, NULL, 10);
}

/*
 * Emit disk_usage events for each unique real filesystem.
 * Reads /proc/mounts, applies fs_type/include/exclude filters,
 * deduplicates by device, calls statvfs().
 */
static int emit_disk_usage_events(__u64 timestamp_ns, const char *hostname)
{
	/* Default fs types if none configured */
	static const char *default_fs[] = {
		"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat",
		"zfs", "ntfs", "fuseblk", "f2fs", NULL
	};

	FILE *mf = setmntent("/proc/mounts", "r");
	if (!mf)
		return 0;

	char seen_devs[64][256];
	int seen_count = 0;
	int disk_count = 0;

	struct mntent *ent;
	while ((ent = getmntent(mf)) != NULL) {
		/* Filter by filesystem type */
		int is_real = 0;
		if (cfg_disk_fs_types_count > 0) {
			for (int i = 0; i < cfg_disk_fs_types_count; i++) {
				if (strcmp(ent->mnt_type,
					   cfg_disk_fs_types[i]) == 0) {
					is_real = 1;
					break;
				}
			}
		} else {
			for (int i = 0; default_fs[i]; i++) {
				if (strcmp(ent->mnt_type,
					   default_fs[i]) == 0) {
					is_real = 1;
					break;
				}
			}
		}
		if (!is_real)
			continue;

		/* Exclude filter (mount point prefix) */
		int excluded = 0;
		for (int i = 0; i < cfg_disk_exclude_count; i++) {
			if (strncmp(ent->mnt_dir, cfg_disk_exclude[i],
				    strlen(cfg_disk_exclude[i])) == 0) {
				excluded = 1;
				break;
			}
		}
		if (excluded)
			continue;

		/* Include filter (mount point prefix) — if set, only matching */
		if (cfg_disk_include_count > 0) {
			int included = 0;
			for (int i = 0; i < cfg_disk_include_count; i++) {
				if (strncmp(ent->mnt_dir, cfg_disk_include[i],
					    strlen(cfg_disk_include[i])) == 0) {
					included = 1;
					break;
				}
			}
			if (!included)
				continue;
		}

		/* Skip duplicate devices */
		int dup = 0;
		for (int i = 0; i < seen_count; i++) {
			if (strcmp(seen_devs[i], ent->mnt_fsname) == 0) {
				dup = 1;
				break;
			}
		}
		if (dup)
			continue;
		if (seen_count < 64)
			snprintf(seen_devs[seen_count++], 256,
				 "%s", ent->mnt_fsname);

		struct statvfs svfs;
		if (statvfs(ent->mnt_dir, &svfs) != 0)
			continue;

		struct metric_event cev;
		memset(&cev, 0, sizeof(cev));
		cev.timestamp_ns = timestamp_ns;
		snprintf(cev.event_type, sizeof(cev.event_type), "disk_usage");

		/* mount point */
		snprintf(cev.file_path, sizeof(cev.file_path),
			 "%s", ent->mnt_dir);

		/* device basename in comm */
		const char *devname = strrchr(ent->mnt_fsname, '/');
		devname = devname ? devname + 1 : ent->mnt_fsname;
		snprintf(cev.comm, sizeof(cev.comm), "%s", devname);

		/* fs type */
		snprintf(cev.sec_remote_addr, sizeof(cev.sec_remote_addr),
			 "%s", ent->mnt_type);

		__u64 bsz = (__u64)svfs.f_frsize;
		cev.disk_total_bytes = bsz * (__u64)svfs.f_blocks;
		cev.disk_used_bytes  = bsz * ((__u64)svfs.f_blocks -
					      (__u64)svfs.f_bfree);
		cev.disk_avail_bytes = bsz * (__u64)svfs.f_bavail;

		ef_append(&cev, hostname);
		disk_count++;
	}

	endmntent(mf);
	return disk_count;
}

static void write_snapshot(void)
{
	char tmp_path[PATH_MAX_LEN];
	FILE *f = NULL;

	if (g_http_cfg.enabled && cfg_prom_path[0]) {
		snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d",
			 cfg_prom_path, getpid());
		f = fopen(tmp_path, "w");
		if (!f)
			log_ts("ERROR", "cannot create temp file: %s", tmp_path);
	}

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = 4096;

	/* Compute boot offset: monotonic → epoch */
	struct timespec mono;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	time_t now_epoch = time(NULL);
	double mono_now = (double)mono.tv_sec + (double)mono.tv_nsec / 1e9;

	/* Elapsed time since previous snapshot (for cpu_usage_ratio) */
	double elapsed_ns = 0;
	if (prev_snapshot_ts.tv_sec > 0) {
		elapsed_ns = (double)(mono.tv_sec - prev_snapshot_ts.tv_sec) * 1e9
			   + (double)(mono.tv_nsec - prev_snapshot_ts.tv_nsec);
	}
	prev_snapshot_ts = mono;

	const char *pfx = cfg_metric_prefix;

	/* HELP/TYPE headers — always present */
	if (f) fprintf(f,
		"# HELP %s_info Process info (value always 1, metadata in labels)\n"
		"# TYPE %s_info gauge\n"
		"# HELP %s_start_time_seconds Process start time as unix epoch\n"
		"# TYPE %s_start_time_seconds gauge\n"
		"# HELP %s_uptime_seconds Process uptime in seconds\n"
		"# TYPE %s_uptime_seconds gauge\n"
		"# HELP %s_is_root Whether PID is a root of tracked tree (1=root, 0=child)\n"
		"# TYPE %s_is_root gauge\n",
		pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx);

	/* HELP/TYPE headers — sched_switch metrics */
	if (f) fprintf(f,
		"# HELP %s_rss_bytes Process RSS memory in bytes\n"
		"# TYPE %s_rss_bytes gauge\n"
		"# HELP %s_rss_min_bytes Min observed RSS memory in bytes\n"
		"# TYPE %s_rss_min_bytes gauge\n"
		"# HELP %s_rss_max_bytes Max observed RSS memory in bytes\n"
		"# TYPE %s_rss_max_bytes gauge\n"
		"# HELP %s_shmem_bytes Shared memory in bytes\n"
		"# TYPE %s_shmem_bytes gauge\n"
		"# HELP %s_swap_bytes Swap usage in bytes\n"
		"# TYPE %s_swap_bytes gauge\n"
		"# HELP %s_oom_kill Process was killed by OOM killer (1=killed)\n"
		"# TYPE %s_oom_kill gauge\n"
		"# HELP %s_vsize_bytes Process virtual memory in bytes\n"
		"# TYPE %s_vsize_bytes gauge\n"
		"# HELP %s_cpu_seconds_total Total CPU time (user + system) in seconds\n"
		"# TYPE %s_cpu_seconds_total counter\n"
		"# HELP %s_cpu_usage_ratio CPU usage ratio over last snapshot interval (1.0 = 1 core)\n"
		"# TYPE %s_cpu_usage_ratio gauge\n"
		"# HELP %s_io_read_bytes_total Actual disk read bytes\n"
		"# TYPE %s_io_read_bytes_total counter\n"
		"# HELP %s_io_write_bytes_total Actual disk write bytes\n"
		"# TYPE %s_io_write_bytes_total counter\n"
		"# HELP %s_major_page_faults_total Major page faults (required disk IO)\n"
		"# TYPE %s_major_page_faults_total counter\n"
		"# HELP %s_minor_page_faults_total Minor page faults (no disk IO)\n"
		"# TYPE %s_minor_page_faults_total counter\n"
		"# HELP %s_voluntary_ctxsw_total Voluntary context switches (process yielded CPU)\n"
		"# TYPE %s_voluntary_ctxsw_total counter\n"
		"# HELP %s_involuntary_ctxsw_total Involuntary context switches (preempted by kernel)\n"
		"# TYPE %s_involuntary_ctxsw_total counter\n"
		"# HELP %s_threads Number of threads\n"
		"# TYPE %s_threads gauge\n"
		"# HELP %s_oom_score_adj Current OOM score adjustment\n"
		"# TYPE %s_oom_score_adj gauge\n"
		"# HELP %s_state Process state (R=running, S=sleeping, D=disk_sleep, T=stopped, Z=zombie)\n"
		"# TYPE %s_state gauge\n",
		pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx,
		pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx,
		pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx,
		pfx, pfx, pfx, pfx, pfx, pfx);

	/* HELP/TYPE headers — network kretprobe metrics */
	if (f) fprintf(f,
		"# HELP %s_net_tx_bytes_total TCP+UDP bytes sent\n"
		"# TYPE %s_net_tx_bytes_total counter\n"
		"# HELP %s_net_rx_bytes_total TCP+UDP bytes received\n"
		"# TYPE %s_net_rx_bytes_total counter\n",
		pfx, pfx, pfx, pfx);

	/* Iterate proc_map */
	__u32 key = 0;
	struct proc_info pi;
	int pid_count = 0;

	/* Collect unique cgroups for cgroup metrics (with cached values) */
	struct {
		char path[256];
		char rule[64];
		long long mem_max, mem_cur, swap_cur, cpu_weight, pids_cur;
		int read;  /* 1 = values read from /sys/fs/cgroup */
	} seen_cg[MAX_CGROUPS];
	int seen_cg_count = 0;

	/* Collect keys to delete (dead processes missed due to ringbuf overflow) */
	__u32 dead_keys[256];
	int dead_count = 0;

	/* Event file snapshot batch */
	/* Single stack-based event for streaming to event file */
	int snap_count = 0;

	/* Single timestamp for all snapshot events in this cycle */
	struct timespec snap_ts;
	clock_gettime(CLOCK_REALTIME, &snap_ts);
	__u64 snap_timestamp_ns = (__u64)snap_ts.tv_sec * 1000000000ULL
				+ (__u64)snap_ts.tv_nsec;

	/* Lock batch to prevent ef_swap_fd/ef_snapshot_fd from
	 * splitting this snapshot across two deliveries */
	ef_batch_lock();

	/* Collect all keys first to avoid iterator invalidation
	 * from concurrent BPF map modifications (fork/exit events) */
	__u32 *all_keys = NULL;
	int all_keys_count = 0;
	int all_keys_cap = 4096;
	all_keys = malloc(all_keys_cap * sizeof(__u32));
	if (all_keys) {
		__u32 iter_key;
		int err2 = bpf_map_get_next_key(proc_map_fd, NULL, &iter_key);
		while (err2 == 0) {
			if (all_keys_count >= all_keys_cap) {
				all_keys_cap *= 2;
				__u32 *tmp = realloc(all_keys,
						     all_keys_cap * sizeof(__u32));
				if (!tmp) break;
				all_keys = tmp;
			}
			all_keys[all_keys_count++] = iter_key;
			err2 = bpf_map_get_next_key(proc_map_fd, &iter_key,
						     &iter_key);
		}
	}

	for (int ki = 0; ki < all_keys_count; ki++) {
		key = all_keys[ki];
		if (bpf_map_lookup_elem(proc_map_fd, &key, &pi) != 0)
			continue;

		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &key, &ti) != 0)
			continue;

		/* Check if process is still alive */
		if (kill((pid_t)key, 0) != 0 && errno == ESRCH) {
			if (dead_count < 256)
				dead_keys[dead_count++] = key;
			continue;
		}

		const char *rule_name = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : "unknown";

		/* Refresh cmdline + comm from /proc */
		if (cfg_refresh_proc) {
			char fresh[CMDLINE_MAX];
			int flen = read_proc_cmdline(key, fresh, sizeof(fresh));
			if (flen > 0) {
				memcpy(pi.cmdline, fresh, CMDLINE_MAX);
				pi.cmdline_len = (__u16)flen;
				bpf_map_update_elem(proc_map_fd, &key, &pi,
						    BPF_EXIST);
			}
			char cpath[128];
			snprintf(cpath, sizeof(cpath), "/proc/%u/comm", key);
			FILE *cf = fopen(cpath, "r");
			if (cf) {
				char cbuf[COMM_LEN];
				if (fgets(cbuf, sizeof(cbuf), cf)) {
					cbuf[strcspn(cbuf, "\n")] = '\0';
					memcpy(pi.comm, cbuf, COMM_LEN);
				}
				fclose(cf);
			}
		}

		/* Split cmdline into exec + args */
		char exec_path[CMDLINE_MAX], args[CMDLINE_MAX];
		cmdline_split(pi.cmdline, pi.cmdline_len,
			      exec_path, sizeof(exec_path),
			      args, sizeof(args));
		if ((int)strlen(args) > cfg_cmdline_max_len) {
			args[cfg_cmdline_max_len] = '\0';
			strcat(args, "...");
		}

		/* Resolve cgroup: display name + real fs path */
		const char *cg_path = resolve_cgroup(pi.cgroup_id);
		const char *cg_fs_path = resolve_cgroup_fs(pi.cgroup_id);

		/* Escape labels */
		char comm_esc[64], exec_esc[CMDLINE_MAX * 2];
		char args_esc[CMDLINE_MAX * 2], cg_esc[512], host_esc[512];
		escape_label(pi.comm, comm_esc, sizeof(comm_esc));
		escape_label(exec_path, exec_esc, sizeof(exec_esc));
		escape_label(args, args_esc, sizeof(args_esc));
		escape_label(cg_path, cg_esc, sizeof(cg_esc));
		escape_label(cfg_hostname, host_esc, sizeof(host_esc));

		/* Compute times */
		double uptime_sec = mono_now - (double)pi.start_ns / 1e9;
		if (uptime_sec < 0) uptime_sec = 0;
		time_t start_epoch = now_epoch - (time_t)uptime_sec;

		/* CPU usage ratio */
		double cpu_ratio = 0;
		if (elapsed_ns > 0) {
			__u64 prev_ns = cpu_prev_lookup(key);
			cpu_ratio = (prev_ns > 0 && pi.cpu_ns >= prev_ns)
				? (double)(pi.cpu_ns - prev_ns) / elapsed_ns : 0;
		}
		cpu_prev_update(key, pi.cpu_ns);

		/* Write Prometheus metrics */
		if (f) {
		char tags_esc[TAGS_MAX_LEN * 2];
		escape_label(tags_lookup(key), tags_esc, sizeof(tags_esc));
		fprintf(f, "%s_info{hostname=\"%s\",rule=\"%s\",tags=\"%s\","
			"root_pid=\"%u\","
			"pid=\"%u\",uid=\"%u\",comm=\"%s\",exec=\"%s\",args=\"%s\","
			"cgroup=\"%s\"} 1\n",
			pfx, host_esc, rule_name, tags_esc, ti.root_pid,
			pi.tgid,
			pi.uid, comm_esc, exec_esc, args_esc, cg_esc);
		fprintf(f, "%s_start_time_seconds{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %ld\n",
			pfx, rule_name, ti.root_pid, pi.tgid, (long)start_epoch);
		fprintf(f, "%s_uptime_seconds{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %ld\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(long)(uptime_sec > 0 ? uptime_sec : 0));
		fprintf(f, "%s_is_root{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %u\n",
			pfx, rule_name, ti.root_pid, pi.tgid, ti.is_root);

		fprintf(f, "%s_rss_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.rss_pages * page_size));
		fprintf(f, "%s_rss_min_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.rss_min_pages * page_size));
		fprintf(f, "%s_rss_max_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.rss_max_pages * page_size));
		fprintf(f, "%s_shmem_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.shmem_pages * page_size));
		fprintf(f, "%s_swap_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.swap_pages * page_size));
		fprintf(f, "%s_oom_kill{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %u\n",
			pfx, rule_name, ti.root_pid, pi.tgid, pi.oom_killed);
		fprintf(f, "%s_vsize_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.vsize_pages * page_size));
		fprintf(f, "%s_cpu_seconds_total{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %.2f\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(double)pi.cpu_ns / 1e9);

		if (elapsed_ns > 0) {
			fprintf(f, "%s_cpu_usage_ratio{rule=\"%s\",root_pid=\"%u\","
				"pid=\"%u\"} %.4f\n",
				pfx, rule_name, ti.root_pid, pi.tgid, cpu_ratio);
		}

		fprintf(f, "%s_io_read_bytes_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.io_read_bytes);
		fprintf(f, "%s_io_write_bytes_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.io_write_bytes);
		fprintf(f, "%s_major_page_faults_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.maj_flt);
		fprintf(f, "%s_minor_page_faults_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.min_flt);
		fprintf(f, "%s_voluntary_ctxsw_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.nvcsw);
		fprintf(f, "%s_involuntary_ctxsw_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.nivcsw);
		fprintf(f, "%s_threads{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %u\n",
			pfx, rule_name, ti.root_pid, pi.tgid, pi.threads);
		fprintf(f, "%s_oom_score_adj{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %d\n",
			pfx, rule_name, ti.root_pid, pi.tgid, pi.oom_score_adj);
		char state_str[2] = { (char)(pi.state ? pi.state : '?'), '\0' };
		fprintf(f, "%s_state{rule=\"%s\",root_pid=\"%u\",pid=\"%u\","
			"state=\"%s\"} 1\n",
			pfx, rule_name, ti.root_pid, pi.tgid, state_str);

		fprintf(f, "%s_net_tx_bytes_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.net_tx_bytes);
		fprintf(f, "%s_net_rx_bytes_total{rule=\"%s\",root_pid=\"%u\","
			"pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)pi.net_rx_bytes);
		} /* if (f) */

		/* Collect unique cgroup for cgroup-level metrics + cache values */
		int cg_idx = -1;
		if (cg_path[0] && seen_cg_count < MAX_CGROUPS) {
			for (int i = 0; i < seen_cg_count; i++) {
				if (strcmp(seen_cg[i].path, cg_path) == 0) {
					cg_idx = i;
					break;
				}
			}
			if (cg_idx < 0) {
				cg_idx = seen_cg_count;
				snprintf(seen_cg[cg_idx].path,
					 sizeof(seen_cg[0].path), "%s", cg_path);
				snprintf(seen_cg[cg_idx].rule,
					 sizeof(seen_cg[0].rule), "%s", rule_name);
				seen_cg[cg_idx].read = 0;
				if (cfg_cgroup_metrics && cg_fs_path[0]) {
					seen_cg[cg_idx].mem_max =
						read_cgroup_value(cg_fs_path, "memory.max");
					seen_cg[cg_idx].mem_cur =
						read_cgroup_value(cg_fs_path, "memory.current");
					seen_cg[cg_idx].swap_cur =
						read_cgroup_value(cg_fs_path, "memory.swap.current");
					seen_cg[cg_idx].cpu_weight =
						read_cgroup_value(cg_fs_path, "cpu.weight");
					seen_cg[cg_idx].pids_cur =
						read_cgroup_value(cg_fs_path, "pids.current");
					seen_cg[cg_idx].read = 1;
				}
				seen_cg_count++;
			}
		}

		/* Stream snapshot event directly to event file (no buffering) */
		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			cev.timestamp_ns = snap_timestamp_ns;
			snprintf(cev.event_type, sizeof(cev.event_type), "snapshot");
			snprintf(cev.rule, sizeof(cev.rule), "%s", rule_name);
			const char *snap_tags = tags_lookup(key);
			if (!snap_tags[0]) {
				try_track_pid(key);
				snap_tags = tags_lookup(key);
			}
			snprintf(cev.tags, sizeof(cev.tags), "%s", snap_tags);
			cev.root_pid = ti.root_pid;
			cev.pid = pi.tgid;
			cev.ppid = pi.ppid;
			cev.uid = pi.uid;
			memcpy(cev.comm, pi.comm, COMM_LEN);
			cmdline_split(pi.cmdline, pi.cmdline_len,
				      cev.exec_path, sizeof(cev.exec_path),
				      cev.args, sizeof(cev.args));
			snprintf(cev.cgroup, sizeof(cev.cgroup), "%s", cg_path);
			cev.is_root = ti.is_root;
			cev.state = pi.state;
			cev.cpu_ns = pi.cpu_ns;
			cev.cpu_usage_ratio = cpu_ratio;
			cev.rss_bytes = pi.rss_pages * page_size;
			cev.rss_min_bytes = pi.rss_min_pages * page_size;
			cev.rss_max_bytes = pi.rss_max_pages * page_size;
			cev.shmem_bytes = pi.shmem_pages * page_size;
			cev.swap_bytes = pi.swap_pages * page_size;
			cev.vsize_bytes = pi.vsize_pages * page_size;
			cev.io_read_bytes = pi.io_read_bytes;
			cev.io_write_bytes = pi.io_write_bytes;
			cev.maj_flt = pi.maj_flt;
			cev.min_flt = pi.min_flt;
			cev.nvcsw = pi.nvcsw;
			cev.nivcsw = pi.nivcsw;
			cev.threads = pi.threads;
			cev.oom_score_adj = pi.oom_score_adj;
			cev.oom_killed = pi.oom_killed;
			cev.net_tx_bytes = pi.net_tx_bytes;
			cev.net_rx_bytes = pi.net_rx_bytes;
			cev.start_time_ns = pi.start_ns;
			cev.uptime_seconds = (__u64)(uptime_sec > 0 ? uptime_sec : 0);

			/* New fields from proc_info */
			cev.loginuid       = pi.loginuid;
			cev.sessionid      = pi.sessionid;
			cev.euid           = pi.euid;
			cev.tty_nr         = pi.tty_nr;
			cev.sched_policy   = pi.sched_policy;
			cev.io_rchar       = pi.io_rchar;
			cev.io_wchar       = pi.io_wchar;
			cev.io_syscr       = pi.io_syscr;
			cev.io_syscw       = pi.io_syscw;
			cev.mnt_ns_inum    = pi.mnt_ns_inum;
			cev.pid_ns_inum    = pi.pid_ns_inum;
			cev.net_ns_inum    = pi.net_ns_inum;
			cev.cgroup_ns_inum = pi.cgroup_ns_inum;

			/* pwd via readlink /proc/PID/cwd (userspace only) */
			{
				char cwd_path[64];
				snprintf(cwd_path, sizeof(cwd_path),
					 "/proc/%u/cwd", pi.tgid);
				ssize_t cwd_len = readlink(cwd_path, cev.pwd,
							   sizeof(cev.pwd) - 1);
				if (cwd_len > 0)
					cev.pwd[cwd_len] = '\0';
			}

			/* Fill cgroup metrics from cache */
			if (cg_idx >= 0 && seen_cg[cg_idx].read) {
				cev.cgroup_memory_max = seen_cg[cg_idx].mem_max;
				cev.cgroup_memory_current = seen_cg[cg_idx].mem_cur;
				cev.cgroup_swap_current = seen_cg[cg_idx].swap_cur;
				cev.cgroup_cpu_weight = seen_cg[cg_idx].cpu_weight;
				cev.cgroup_pids_current = seen_cg[cg_idx].pids_cur;
			}

			/* Open TCP connections count */
			if (cfg_sec_open_conn_count) {
				__u64 conn_cnt = 0;
				int occ_fd = bpf_map__fd(skel->maps.open_conn_map);
				__u32 occ_key = pi.tgid;
				if (bpf_map_lookup_elem(occ_fd, &occ_key,
							&conn_cnt) == 0)
					cev.open_tcp_conns = conn_cnt;
			}

			ef_append(&cev, cfg_hostname);
			snap_count++;
		}
		pid_count++;
	}
	free(all_keys);

	/* Flush UDP aggregation map before unlocking batch */
	if (cfg_sec_udp_tracking && g_http_cfg.enabled) {
		int udp_fd = bpf_map__fd(skel->maps.udp_agg_map);
		struct udp_agg_key ukey;
		struct udp_agg_val uval;
		int udp_count = 0;

		while (bpf_map_get_next_key(udp_fd, NULL, &ukey) == 0) {
			if (bpf_map_lookup_elem(udp_fd, &ukey, &uval) == 0
			    && (uval.tx_packets || uval.rx_packets)) {
				struct metric_event cev;
				memset(&cev, 0, sizeof(cev));
				cev.timestamp_ns = snap_timestamp_ns;
				snprintf(cev.event_type, sizeof(cev.event_type),
					 "udp_agg");
				cev.pid = ukey.tgid;
				cev.sec_af = ukey.af;
				cev.sec_remote_port = ukey.remote_port;
				if (ukey.af == 2) {
					snprintf(cev.sec_remote_addr,
						 sizeof(cev.sec_remote_addr),
						 "%u.%u.%u.%u",
						 ukey.remote_addr[0],
						 ukey.remote_addr[1],
						 ukey.remote_addr[2],
						 ukey.remote_addr[3]);
				} else if (ukey.af == 10) {
					inet_ntop(AF_INET6,
						  ukey.remote_addr,
						  cev.sec_remote_addr,
						  sizeof(cev.sec_remote_addr));
				}
				cev.net_tx_bytes = uval.tx_bytes;
				cev.net_rx_bytes = uval.rx_bytes;
				cev.file_read_bytes = uval.rx_packets;
				cev.file_write_bytes = uval.tx_packets;

				struct proc_info upi;
				if (bpf_map_lookup_elem(proc_map_fd,
							&ukey.tgid,
							&upi) == 0) {
					memcpy(cev.comm, upi.comm, COMM_LEN);
					const char *ucg = resolve_cgroup(
						upi.cgroup_id);
					if (ucg)
						snprintf(cev.cgroup,
							 sizeof(cev.cgroup),
							 "%s", ucg);
				}
				struct track_info uti;
				if (bpf_map_lookup_elem(tracked_map_fd,
							&ukey.tgid,
							&uti) == 0) {
					if (uti.rule_id < num_rules)
						snprintf(cev.rule,
							 sizeof(cev.rule),
							 "%s",
							 rules[uti.rule_id].name);
					cev.root_pid = uti.root_pid;
					const char *ut = tags_lookup(ukey.tgid);
					snprintf(cev.tags, sizeof(cev.tags),
						 "%s", ut);
				}
				ef_append(&cev, cfg_hostname);
				udp_count++;
			}
			bpf_map_delete_elem(udp_fd, &ukey);
		}
		if (udp_count > 0)
			log_debug("UDP flush: %d aggregates", udp_count);
	}

	/* Flush ICMP aggregation map before unlocking batch */
	if (cfg_sec_icmp_tracking && g_http_cfg.enabled) {
		int icmp_fd = bpf_map__fd(skel->maps.icmp_agg_map);
		struct icmp_agg_key ikey;
		struct icmp_agg_val ival;
		int icmp_count = 0;

		while (bpf_map_get_next_key(icmp_fd, NULL, &ikey) == 0) {
			if (bpf_map_lookup_elem(icmp_fd, &ikey, &ival) == 0
			    && ival.count > 0) {
				struct metric_event cev;
				memset(&cev, 0, sizeof(cev));
				cev.timestamp_ns = snap_timestamp_ns;
				snprintf(cev.event_type, sizeof(cev.event_type),
					 "icmp_agg");
				int is_v4 = 1;
				for (int b = 4; b < 16; b++) {
					if (ikey.src_addr[b]) {
						is_v4 = 0;
						break;
					}
				}
				if (is_v4) {
					cev.sec_af = 2;
					snprintf(cev.sec_remote_addr,
						 sizeof(cev.sec_remote_addr),
						 "%u.%u.%u.%u",
						 ikey.src_addr[0],
						 ikey.src_addr[1],
						 ikey.src_addr[2],
						 ikey.src_addr[3]);
				} else {
					cev.sec_af = 10;
					inet_ntop(AF_INET6,
						  ikey.src_addr,
						  cev.sec_remote_addr,
						  sizeof(cev.sec_remote_addr));
				}
				cev.sec_tcp_state = ikey.icmp_type;
				cev.sec_direction = ikey.icmp_code;
				cev.open_tcp_conns = ival.count;
				ef_append(&cev, cfg_hostname);
				icmp_count++;
			}
			bpf_map_delete_elem(icmp_fd, &ikey);
		}
		if (icmp_count > 0)
			log_debug("ICMP flush: %d aggregates", icmp_count);
	}

	/* Emit disk usage events */
	if (g_http_cfg.enabled && cfg_disk_tracking_enabled) {
		int disk_ev = emit_disk_usage_events(snap_timestamp_ns,
						     cfg_hostname);
		snap_count += disk_ev;
	}

	/* Unlock batch — snapshot is complete, safe for swap/snapshot_fd */
	ef_batch_unlock();

	/* Clean up dead processes */
	for (int i = 0; i < dead_count; i++) {
		bpf_map_delete_elem(tracked_map_fd, &dead_keys[i]);
		bpf_map_delete_elem(proc_map_fd, &dead_keys[i]);
		cpu_prev_remove(dead_keys[i]);
		tags_remove(dead_keys[i]);
	}
	if (dead_count > 0)
		log_ts("INFO", "cleaned up %d dead PIDs", dead_count);

	/* Recently exited processes */
	if (f && exited_count > 0) {
		fprintf(f,
			"# HELP %s_exited_exit_code Exit code of recently exited process\n"
			"# TYPE %s_exited_exit_code gauge\n"
			"# HELP %s_exited_signal Signal that killed recently exited process (0=normal)\n"
			"# TYPE %s_exited_signal gauge\n"
			"# HELP %s_exited_oom_kill Process was killed by OOM killer\n"
			"# TYPE %s_exited_oom_kill gauge\n"
			"# HELP %s_exited_cpu_seconds_total Total CPU of exited process\n"
			"# TYPE %s_exited_cpu_seconds_total gauge\n"
			"# HELP %s_exited_rss_max_bytes Max RSS of exited process\n"
			"# TYPE %s_exited_rss_max_bytes gauge\n",
			pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx);

		fprintf(f,
			"# HELP %s_exited_net_tx_bytes_total TCP+UDP bytes sent by exited process\n"
			"# TYPE %s_exited_net_tx_bytes_total gauge\n"
			"# HELP %s_exited_net_rx_bytes_total TCP+UDP bytes received by exited process\n"
			"# TYPE %s_exited_net_rx_bytes_total gauge\n",
			pfx, pfx, pfx, pfx);

		int start = (exited_count < MAX_EXITED) ? 0 : exited_head;
		for (int i = 0; i < exited_count; i++) {
			int idx = (start + i) % MAX_EXITED;
			struct exited_proc *ep = &exited_ring[idx];
			const char *rname = (ep->rule_id < num_rules)
				? rules[ep->rule_id].name : "unknown";

			char ep_exec[CMDLINE_MAX], ep_args[CMDLINE_MAX + 4];
			cmdline_split(ep->cmdline, ep->cmdline_len,
				      ep_exec, sizeof(ep_exec),
				      ep_args, sizeof(ep_args));
			if ((int)strlen(ep_args) > cfg_cmdline_max_len) {
				ep_args[cfg_cmdline_max_len] = '\0';
				strcat(ep_args, "...");
			}

			char comm_esc[64], exec_esc[CMDLINE_MAX * 2];
			char args_esc[CMDLINE_MAX * 2], host_esc[512];
			escape_label(ep->comm, comm_esc, sizeof(comm_esc));
			escape_label(ep_exec, exec_esc, sizeof(exec_esc));
			escape_label(ep_args, args_esc, sizeof(args_esc));
			escape_label(cfg_hostname, host_esc, sizeof(host_esc));

			int sig = ep->exit_code & 0x7f;
			int status = (ep->exit_code >> 8) & 0xff;

			fprintf(f, "%s_exited_exit_code{hostname=\"%s\","
				"rule=\"%s\",root_pid=\"%u\","
				"pid=\"%u\",comm=\"%s\",exec=\"%s\","
				"args=\"%s\"} %d\n",
				pfx, host_esc, rname, ep->root_pid,
				ep->tgid, comm_esc, exec_esc,
				args_esc, status);
			fprintf(f, "%s_exited_signal{rule=\"%s\",root_pid=\"%u\","
				"pid=\"%u\"} %d\n",
				pfx, rname, ep->root_pid, ep->tgid, sig);
			fprintf(f, "%s_exited_oom_kill{rule=\"%s\",root_pid=\"%u\","
				"pid=\"%u\"} %u\n",
				pfx, rname, ep->root_pid, ep->tgid, ep->oom_killed);
			fprintf(f, "%s_exited_cpu_seconds_total{rule=\"%s\","
				"root_pid=\"%u\",pid=\"%u\"} %.2f\n",
				pfx, rname, ep->root_pid, ep->tgid,
				(double)ep->cpu_ns / 1e9);
			fprintf(f, "%s_exited_rss_max_bytes{rule=\"%s\","
				"root_pid=\"%u\",pid=\"%u\"} %llu\n",
				pfx, rname, ep->root_pid, ep->tgid,
				(unsigned long long)(ep->rss_max_pages * page_size));
			fprintf(f, "%s_exited_net_tx_bytes_total{rule=\"%s\","
				"root_pid=\"%u\",pid=\"%u\"} %llu\n",
				pfx, rname, ep->root_pid, ep->tgid,
				(unsigned long long)ep->net_tx_bytes);
			fprintf(f, "%s_exited_net_rx_bytes_total{rule=\"%s\","
				"root_pid=\"%u\",pid=\"%u\"} %llu\n",
				pfx, rname, ep->root_pid, ep->tgid,
				(unsigned long long)ep->net_rx_bytes);
		}
	}

	/* Cgroup v2 metrics from /sys/fs/cgroup */
	if (f && cfg_cgroup_metrics && seen_cg_count > 0) {
		fprintf(f,
			"# HELP %s_cgroup_memory_max_bytes Cgroup memory.max (0=unlimited)\n"
			"# TYPE %s_cgroup_memory_max_bytes gauge\n"
			"# HELP %s_cgroup_memory_current_bytes Cgroup memory.current\n"
			"# TYPE %s_cgroup_memory_current_bytes gauge\n"
			"# HELP %s_cgroup_memory_swap_current_bytes Cgroup memory.swap.current\n"
			"# TYPE %s_cgroup_memory_swap_current_bytes gauge\n"
			"# HELP %s_cgroup_cpu_weight Cgroup cpu.weight\n"
			"# TYPE %s_cgroup_cpu_weight gauge\n"
			"# HELP %s_cgroup_pids_current Cgroup pids.current\n"
			"# TYPE %s_cgroup_pids_current gauge\n",
			pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx);

		for (int i = 0; i < seen_cg_count; i++) {
			if (!seen_cg[i].read)
				continue;
			char cg_esc[512];
			escape_label(seen_cg[i].path, cg_esc, sizeof(cg_esc));

			struct { const char *metric; long long val; } kv[] = {
				{ "memory_max_bytes",          seen_cg[i].mem_max },
				{ "memory_current_bytes",      seen_cg[i].mem_cur },
				{ "memory_swap_current_bytes", seen_cg[i].swap_cur },
				{ "cpu_weight",                seen_cg[i].cpu_weight },
				{ "pids_current",              seen_cg[i].pids_cur },
			};
			for (int k = 0; k < 5; k++) {
				if (kv[k].val >= 0) {
					fprintf(f, "%s_cgroup_%s{rule=\"%s\","
						"cgroup=\"%s\"} %lld\n",
						pfx, kv[k].metric,
						seen_cg[i].rule, cg_esc,
						kv[k].val);
				}
			}
		}
	}

	if (f) {
		fclose(f);

		/* Atomic rename */
		if (rename(tmp_path, cfg_prom_path) == 0)
			chmod(cfg_prom_path, 0644);
		else
			log_ts("ERROR", "rename %s → %s: %s",
			       tmp_path, cfg_prom_path, strerror(errno));

		log_ts("INFO", "snapshot: %d PIDs, %d cgroups, %d events → %s",
		       pid_count, seen_cg_count, snap_count, cfg_prom_path);
	} else {
		log_ts("INFO", "snapshot: %d PIDs, %d cgroups, %d events",
		       pid_count, seen_cg_count, snap_count);
	}

	/* snap_count events were streamed directly via ef_append above */

	/* Логируем статистику ring buffer'ов */
	{
		__u32 key = 0;
		struct ringbuf_stats rs = {0};
		int stats_fd = bpf_map__fd(skel->maps.ringbuf_stats);
		if (stats_fd >= 0 &&
		    bpf_map_lookup_elem(stats_fd, &key, &rs) == 0) {
			if (rs.drop_proc || rs.drop_file || rs.drop_net) {
				log_ts("WARN",
				       "ringbuf drops: proc=%llu/%llu file=%llu/%llu net=%llu/%llu",
				       (unsigned long long)rs.drop_proc,
				       (unsigned long long)rs.total_proc,
				       (unsigned long long)rs.drop_file,
				       (unsigned long long)rs.total_file,
				       (unsigned long long)rs.drop_net,
				       (unsigned long long)rs.total_net);
			} else if (cfg_log_level >= 2) {
				log_ts("DEBUG",
				       "ringbuf totals: proc=%llu file=%llu net=%llu",
				       (unsigned long long)rs.total_proc,
				       (unsigned long long)rs.total_file,
				       (unsigned long long)rs.total_net);
			}
		}
	}
}

/* ── signals ──────────────────────────────────────────────────────── */

static void sig_term(int sig) { (void)sig; g_running = 0; }
static void sig_hup(int sig)  { (void)sig; g_reload = 1; }

/* ── libbpf log ───────────────────────────────────────────────────── */

static int libbpf_print(enum libbpf_print_level level,
			const char *fmt, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

/* ── main ─────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -c <config_file>\n"
		"  -c <path>   configuration file (libconfig format)\n"
		"  -h          show this help\n",
		prog);
}

int main(int argc, char *argv[])
{
	/* Parse command line — only -c and -h */
	int opt;
	while ((opt = getopt(argc, argv, "c:h")) != -1) {
		switch (opt) {
		case 'c': cfg_config_file = optarg; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	/* Find config file */
	if (!cfg_config_file) {
		/* Try directory of binary, then cwd */
		static char cfgbuf[PATH_MAX_LEN];
		char *slash = strrchr(argv[0], '/');
		if (slash) {
			int dirlen = (int)(slash - argv[0]);
			snprintf(cfgbuf, sizeof(cfgbuf),
				 "%.*s/process_metrics.conf", dirlen, argv[0]);
		} else {
			snprintf(cfgbuf, sizeof(cfgbuf), "process_metrics.conf");
		}
		cfg_config_file = cfgbuf;
	}

	/* Load configuration (libconfig) */
	if (load_config(cfg_config_file) < 0)
		return 1;

	/* Load rules from config */
	if (parse_rules_from_config(cfg_config_file) < 0)
		return 1;
	if (num_rules == 0) {
		fprintf(stderr, "FATAL: no rules loaded\n");
		return 1;
	}

	/* Initialize event file if HTTP server is enabled */
	if (g_http_cfg.enabled) {
		if (ef_init(cfg_data_file, (__u64)cfg_max_data_file_size) < 0) {
			fprintf(stderr, "FATAL: event file init failed: %s\n",
				cfg_data_file);
			return 1;
		}
	}

	/* Build cgroup cache */
	build_cgroup_cache();

	/* Setup libbpf */
	libbpf_set_print(libbpf_print);

	/* Open BPF skeleton */
	skel = process_metrics_bpf__open();
	if (!skel) {
		fprintf(stderr, "FATAL: failed to open BPF skeleton\n");
		return 1;
	}

	/* Set rodata before loading */
	skel->rodata->max_exec_events_per_sec = (__u32)cfg_exec_rate_limit;

	/* Conditionally disable network tracking programs */
	if (!cfg_net_tracking_enabled) {
		/* Connection lifecycle: connect/accept/close */
		BPF_PROG_DISABLE(skel->progs.kp_tcp_v4_connect);
		BPF_PROG_DISABLE(skel->progs.krp_tcp_v4_connect);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_v6_connect);
		BPF_PROG_DISABLE(skel->progs.krp_tcp_v6_connect);
		BPF_PROG_DISABLE(skel->progs.krp_inet_csk_accept);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_close);
	}
	if (!cfg_net_tracking_enabled || !cfg_net_track_bytes) {
		/* Per-connection byte counting (kprobe enter + kretprobe) */
		BPF_PROG_DISABLE(skel->progs.kp_tcp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_recvmsg);
	}
	if (!cfg_net_tracking_enabled) {
		/* Per-process aggregate byte counting (TCP + UDP kretprobes) */
		BPF_PROG_DISABLE(skel->progs.ret_tcp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.ret_tcp_recvmsg);
		BPF_PROG_DISABLE(skel->progs.ret_udp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.ret_udp_recvmsg);
	}

	/* Conditionally disable file tracking programs */
	if (!cfg_file_tracking_enabled) {
		BPF_PROG_DISABLE(skel->progs.handle_openat_enter);
		BPF_PROG_DISABLE(skel->progs.handle_openat_exit);
		BPF_PROG_DISABLE(skel->progs.handle_close_enter);
		BPF_PROG_DISABLE(skel->progs.handle_read_enter);
		BPF_PROG_DISABLE(skel->progs.handle_read_exit);
		BPF_PROG_DISABLE(skel->progs.handle_write_enter);
		BPF_PROG_DISABLE(skel->progs.handle_write_exit);
	}

	/* Conditionally disable security tracking programs */
	if (!cfg_sec_tcp_retransmit)
		BPF_PROG_DISABLE(skel->progs.handle_tcp_retransmit);
	if (!cfg_sec_syn_tracking)
		BPF_PROG_DISABLE(skel->progs.kp_tcp_conn_request);
	if (!cfg_sec_rst_tracking) {
		BPF_PROG_DISABLE(skel->progs.handle_tcp_send_reset);
		BPF_PROG_DISABLE(skel->progs.handle_tcp_receive_reset);
	}
	if (!cfg_sec_udp_tracking) {
		BPF_PROG_DISABLE(skel->progs.kp_udp_sendmsg_sec);
		BPF_PROG_DISABLE(skel->progs.ret_udp_sendmsg_sec);
		BPF_PROG_DISABLE(skel->progs.kp_udp_recvmsg_sec);
		BPF_PROG_DISABLE(skel->progs.ret_udp_recvmsg_sec);
	}
	if (!cfg_sec_icmp_tracking)
		BPF_PROG_DISABLE(skel->progs.kp_icmp_rcv);

	/* Load BPF programs */
	if (process_metrics_bpf__load(skel)) {
		fprintf(stderr, "FATAL: failed to load BPF programs\n");
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Push file tracking config to BPF maps */
	if (cfg_file_tracking_enabled) {
		int file_cfg_fd = bpf_map__fd(skel->maps.file_cfg);
		__u32 key0 = 0;
		struct file_config fc = {
			.enabled = 1,
			.track_bytes = (__u8)cfg_file_track_bytes,
		};
		bpf_map_update_elem(file_cfg_fd, &key0, &fc, BPF_ANY);

		int inc_fd = bpf_map__fd(skel->maps.file_include_prefixes);
		for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
			__u32 idx = (__u32)i;
			if (i < cfg_file_include_count)
				bpf_map_update_elem(inc_fd, &idx,
					&cfg_file_include[i], BPF_ANY);
		}

		int exc_fd = bpf_map__fd(skel->maps.file_exclude_prefixes);
		for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
			__u32 idx = (__u32)i;
			if (i < cfg_file_exclude_count)
				bpf_map_update_elem(exc_fd, &idx,
					&cfg_file_exclude[i], BPF_ANY);
		}
	}

	/* Push net tracking config to BPF maps */
	if (cfg_net_tracking_enabled) {
		int net_cfg_fd = bpf_map__fd(skel->maps.net_cfg);
		__u32 key0 = 0;
		struct net_config nc = {
			.enabled = 1,
			.track_bytes = (__u8)cfg_net_track_bytes,
		};
		bpf_map_update_elem(net_cfg_fd, &key0, &nc, BPF_ANY);
	}

	/* Push security tracking config to BPF maps */
	{
		int sec_cfg_fd = bpf_map__fd(skel->maps.sec_cfg);
		__u32 key0 = 0;
		struct sec_config sc = {
			.tcp_retransmit  = (__u8)cfg_sec_tcp_retransmit,
			.syn_tracking    = (__u8)cfg_sec_syn_tracking,
			.rst_tracking    = (__u8)cfg_sec_rst_tracking,
			.udp_tracking    = (__u8)cfg_sec_udp_tracking,
			.icmp_tracking   = (__u8)cfg_sec_icmp_tracking,
			.open_conn_count = (__u8)cfg_sec_open_conn_count,
		};
		bpf_map_update_elem(sec_cfg_fd, &key0, &sc, BPF_ANY);
	}

	if (process_metrics_bpf__attach(skel)) {
		fprintf(stderr, "FATAL: failed to attach BPF programs\n");
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Get map FDs */
	tracked_map_fd = bpf_map__fd(skel->maps.tracked_map);
	proc_map_fd    = bpf_map__fd(skel->maps.proc_map);

	/* Ring buffers: процессы, файлы, сеть — каждый со своим буфером,
	 * но общий callback handle_event (различает по полю type). */
	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events_proc), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "FATAL: failed to create ring buffer\n");
		process_metrics_bpf__destroy(skel);
		return 1;
	}
	if (ring_buffer__add(rb, bpf_map__fd(skel->maps.events_file),
			     handle_event, NULL)) {
		fprintf(stderr, "FATAL: failed to add events_file ring buffer\n");
		ring_buffer__free(rb);
		process_metrics_bpf__destroy(skel);
		return 1;
	}
	if (ring_buffer__add(rb, bpf_map__fd(skel->maps.events_net),
			     handle_event, NULL)) {
		fprintf(stderr, "FATAL: failed to add events_net ring buffer\n");
		ring_buffer__free(rb);
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Signals */
	signal(SIGTERM, sig_term);
	signal(SIGINT,  sig_term);
	signal(SIGHUP,  sig_hup);

	/* One-time startup scan: find already-running processes */
	initial_scan();
	refresh_boot_to_wall();

	/* Start HTTP server if enabled */
	if (g_http_cfg.enabled) {
		if (http_server_start(&g_http_cfg, cfg_prom_path) < 0) {
			fprintf(stderr, "FATAL: HTTP server start failed\n");
			ring_buffer__free(rb);
			process_metrics_bpf__destroy(skel);
			return 1;
		}
	}

	log_ts("INFO", "started: %d rules, snapshot every %ds, "
	       "exec_rate_limit=%d/s, http_server=%s, "
	       "cgroup_metrics=%s, refresh_proc=%s, "
	       "net_tracking=%s%s, file_tracking=%s%s, "
	       "security=[retransmit=%s syn=%s rst=%s udp=%s icmp=%s open_conn=%s], "
	       "disk_tracking=%s, max_data_file_size=%lld",
	       num_rules, cfg_snapshot_interval,
	       cfg_exec_rate_limit,
	       g_http_cfg.enabled ? "on" : "off",
	       cfg_cgroup_metrics ? "on" : "off",
	       cfg_refresh_proc ? "on" : "off",
	       cfg_net_tracking_enabled ? "on" : "off",
	       cfg_net_track_bytes ? "+bytes" : "",
	       cfg_file_tracking_enabled ? "on" : "off",
	       cfg_file_track_bytes ? "+bytes" : "",
	       cfg_sec_tcp_retransmit ? "on" : "off",
	       cfg_sec_syn_tracking ? "on" : "off",
	       cfg_sec_rst_tracking ? "on" : "off",
	       cfg_sec_udp_tracking ? "on" : "off",
	       cfg_sec_icmp_tracking ? "on" : "off",
	       cfg_sec_open_conn_count ? "on" : "off",
	       cfg_disk_tracking_enabled ? "on" : "off",
	       (long long)cfg_max_data_file_size);

	/* Main loop — event-driven via ring_buffer__poll (epoll_wait inside).
	 * Блокируется до прихода BPF-событий или таймаута 1 сек. */
	time_t last_snapshot = 0;

	while (g_running) {
		int err = ring_buffer__poll(rb, 1000 /* 1 second timeout */);
		if (err == -EINTR)
			continue;
		if (err < 0 && err != -EINTR) {
			log_ts("ERROR", "ring_buffer__poll: %d", err);
			break;
		}

		/* Config reload on SIGHUP */
		if (g_reload) {
			g_reload = 0;
			log_ts("INFO", "SIGHUP: reloading rules...");

			/* Clear all tracking — delete from beginning each time */
			__u32 del_key;
			while (bpf_map_get_next_key(tracked_map_fd, NULL, &del_key) == 0) {
				bpf_map_delete_elem(tracked_map_fd, &del_key);
				bpf_map_delete_elem(proc_map_fd, &del_key);
			}

			tags_clear();
			parse_rules_from_config(cfg_config_file);
			build_cgroup_cache();
			exited_head = exited_count = 0;
			cpu_prev_count = 0;
			prev_snapshot_ts = (struct timespec){0};
			initial_scan();
		}

		/* Periodic snapshot */
		time_t now = time(NULL);
		if (now - last_snapshot >= cfg_snapshot_interval) {
			build_cgroup_cache();
			refresh_boot_to_wall();
			write_snapshot();
			last_snapshot = now;
		}
	}

	/* Stop HTTP server */
	http_server_stop();

	/* Clean up event file */
	ef_cleanup();

	ring_buffer__free(rb);
	process_metrics_bpf__destroy(skel);
	free_rules();

	log_ts("INFO", "stopped");
	return 0;
}
