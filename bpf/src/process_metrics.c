/*
 * process_metrics — event-driven process metrics collector
 *
 * Loads BPF programs, listens to ring buffer events, matches exec'd
 * processes against config rules, and periodically writes .prom file
 * from BPF maps. No /proc polling — everything comes from the kernel.
 *
 * Usage:
 *   ./process_metrics [-c config] [-o dir] [-f file] [-i interval] [-p prefix]
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
#include <regex.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include "process_metrics_common.h"
#include "process_metrics.skel.h"

/* ── configuration ────────────────────────────────────────────────── */

#define MAX_RULES    64
#define MAX_CGROUPS  256
#define PATH_MAX_LEN 512

struct rule {
	char    name[64];
	regex_t regex;
};

static struct rule rules[MAX_RULES];
static int         num_rules;

static const char *cfg_config_file     = NULL;
static const char *cfg_output_dir      = "/scripts/system_metrics";
static const char *cfg_output_file     = "process_metrics.prom";
static int         cfg_snapshot_interval = 30;
static const char *cfg_metric_prefix   = "process_metrics";
static int         cfg_cmdline_max_len = 200;
static int         cfg_exec_rate_limit = 0;  /* 0 = unlimited */

/* ── globals ──────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_running   = 1;
static volatile sig_atomic_t g_reload    = 0;
static struct process_metrics_bpf *skel;
static int tracked_map_fd, proc_map_fd;

/* ── cgroup cache ─────────────────────────────────────────────────── */

struct cgroup_entry {
	__u64 id;
	char  path[256];
};

static struct cgroup_entry cgroup_cache[MAX_CGROUPS];
static int cgroup_cache_count;

static void scan_cgroup_dir(const char *base, const char *rel)
{
	char full[PATH_MAX_LEN];
	snprintf(full, sizeof(full), "%s/%s", base, rel);

	struct stat st;
	if (stat(full, &st) == 0 && cgroup_cache_count < MAX_CGROUPS) {
		cgroup_cache[cgroup_cache_count].id = (__u64)st.st_ino;
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

static const char *resolve_cgroup(__u64 cgroup_id)
{
	if (cgroup_id == 0)
		return "";

	for (int i = 0; i < cgroup_cache_count; i++)
		if (cgroup_cache[i].id == cgroup_id)
			return cgroup_cache[i].path;

	/* Cache miss — rebuild once */
	build_cgroup_cache();
	for (int i = 0; i < cgroup_cache_count; i++)
		if (cgroup_cache[i].id == cgroup_id)
			return cgroup_cache[i].path;

	return "";
}

/* ── config parser ────────────────────────────────────────────────── */

static void free_rules(void)
{
	for (int i = 0; i < num_rules; i++)
		regfree(&rules[i].regex);
	num_rules = 0;
}

static int parse_config(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "FATAL: cannot read config: %s\n", path);
		return -1;
	}

	free_rules();

	char line[1024];
	int lineno = 0;
	while (fgets(line, sizeof(line), f)) {
		lineno++;
		/* strip trailing whitespace */
		char *end = line + strlen(line) - 1;
		while (end >= line && (*end == '\n' || *end == '\r' ||
		       *end == ' '  || *end == '\t'))
			*end-- = '\0';

		/* skip leading whitespace */
		char *p = line;
		while (*p == ' ' || *p == '\t') p++;

		/* skip empty / comments */
		if (*p == '\0' || *p == '#' || *p == ';')
			continue;

		/* parse: name = /pattern/ */
		char name[64], pattern[512];
		char *eq = strchr(p, '=');
		if (!eq) {
			fprintf(stderr, "WARN: config line %d: no '=' found\n", lineno);
			continue;
		}

		/* name: everything before '=' trimmed */
		int nlen = (int)(eq - p);
		while (nlen > 0 && (p[nlen-1] == ' ' || p[nlen-1] == '\t'))
			nlen--;
		if (nlen <= 0 || nlen >= (int)sizeof(name)) {
			fprintf(stderr, "WARN: config line %d: bad name\n", lineno);
			continue;
		}
		memcpy(name, p, nlen);
		name[nlen] = '\0';

		/* pattern: everything after '=', trimmed, strip /.../ delimiters */
		char *pat = eq + 1;
		while (*pat == ' ' || *pat == '\t') pat++;

		int plen = (int)strlen(pat);
		if (plen >= 2 && pat[0] == '/' && pat[plen-1] == '/') {
			pat++;
			plen -= 2;
		}
		if (plen <= 0 || plen >= (int)sizeof(pattern)) {
			fprintf(stderr, "WARN: config line %d: bad pattern\n", lineno);
			continue;
		}
		memcpy(pattern, pat, plen);
		pattern[plen] = '\0';

		if (num_rules >= MAX_RULES) {
			fprintf(stderr, "WARN: max rules (%d) reached\n", MAX_RULES);
			break;
		}

		if (regcomp(&rules[num_rules].regex, pattern,
			    REG_EXTENDED | REG_NOSUB) != 0) {
			fprintf(stderr, "WARN: config line %d: bad regex: %s\n",
				lineno, pattern);
			continue;
		}
		snprintf(rules[num_rules].name, sizeof(rules[0].name), "%s", name);
		num_rules++;
	}

	fclose(f);
	fprintf(stderr, "INFO: loaded %d rules from %s\n", num_rules, path);
	return num_rules;
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
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	char ts[32];
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
	fprintf(stderr, "%s [%s] ", ts, level);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
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

	/* fields after ") " */
	char *p = rp + 2;
	char state;
	int ppid;
	unsigned long utime, stime, starttime, vsize;
	long rss;
	int threads;
	/* state ppid pgrp session tty_nr tpgid flags
	   minflt cminflt majflt cmajflt utime stime cutime cstime
	   priority nice num_threads itrealvalue starttime vsize rss */
	if (sscanf(p,
		   "%c %d %*d %*d %*d %*d %*u "
		   "%*lu %*lu %*lu %*lu %lu %lu %*ld %*ld "
		   "%*d %*d %d %*ld %lu %lu %ld",
		   &state, &ppid, &utime, &stime,
		   &threads, &starttime, &vsize, &rss) != 8)
		return -1;

	pi->ppid = (__u32)ppid;
	pi->state = (__u8)state;
	pi->threads = (__u32)threads;
	pi->rss_pages = rss > 0 ? (__u64)rss : 0;
	pi->rss_max_pages = pi->rss_pages;

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = 4096;
	pi->vsize_pages = (__u64)(vsize / page_size);

	long clk_tck = sysconf(_SC_CLK_TCK);
	if (clk_tck <= 0) clk_tck = 100;
	pi->cpu_ns = ((__u64)(utime + stime) * 1000000000ULL) / (__u64)clk_tck;
	pi->start_ns = ((__u64)starttime * 1000000000ULL) / (__u64)clk_tck;

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

		for (int r = 0; r < num_rules; r++) {
			if (regexec(&rules[r].regex, cmdline_str, 0, NULL, 0) != 0)
				continue;

			/* Root match */
			track_pid_from_proc(pid, r, pid, 1);
			tracked++;
			log_ts("INFO", "SCAN: pid=%u rule=%s cmdline=%.60s",
			       pid, rules[r].name, cmdline_str);

			/* Find all descendants */
			add_descendants(entries, count, pid, r, pid, &tracked);
			break;
		}
	}

	log_ts("INFO", "initial scan: %d processes scanned, %d tracked",
	       count, tracked);
}

/* ── ring buffer event handler ────────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	const struct event *e = data;
	if (size < sizeof(*e))
		return 0;

	switch (e->type) {
	case EVENT_EXEC: {
		/* Already tracked? Just update proc_info (BPF did it too) */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0)
			break;

		/* Convert cmdline for regex matching */
		char cmdline[CMDLINE_MAX + 1];
		cmdline_to_str(e->cmdline, e->cmdline_len, cmdline, sizeof(cmdline));

		/* Match against rules */
		for (int i = 0; i < num_rules; i++) {
			if (regexec(&rules[i].regex, cmdline, 0, NULL, 0) != 0)
				continue;

			/* Match — start tracking */
			struct track_info new_ti = {
				.root_pid = e->tgid,
				.rule_id  = (__u16)i,
				.is_root  = 1,
			};
			bpf_map_update_elem(tracked_map_fd, &e->tgid,
					    &new_ti, BPF_ANY);

			struct proc_info pi = {0};
			pi.tgid      = e->tgid;
			pi.ppid      = e->ppid;
			pi.start_ns  = e->start_ns;
			pi.cgroup_id = e->cgroup_id;
			memcpy(pi.comm, e->comm, COMM_LEN);
			memcpy(pi.cmdline, e->cmdline, CMDLINE_MAX);
			pi.cmdline_len = e->cmdline_len;
			bpf_map_update_elem(proc_map_fd, &e->tgid, &pi, BPF_ANY);

			log_ts("INFO", "TRACK: pid=%u rule=%s comm=%.16s",
			       e->tgid, rules[i].name, e->comm);
			break;
		}
		break;
	}

	case EVENT_FORK: {
		/* Parent must be tracked (BPF already filtered) */
		struct track_info parent_ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->ppid, &parent_ti) != 0)
			break;

		/* Copy parent's proc_info for cmdline inheritance */
		struct proc_info parent_pi;
		int has_parent_pi =
			(bpf_map_lookup_elem(proc_map_fd, &e->ppid, &parent_pi) == 0);

		/* Track child with inherited rule/root */
		struct track_info child_ti = {
			.root_pid = parent_ti.root_pid,
			.rule_id  = parent_ti.rule_id,
			.is_root  = 0,
		};
		bpf_map_update_elem(tracked_map_fd, &e->tgid, &child_ti, BPF_ANY);

		/* Initialize child proc_info */
		struct proc_info child_pi = {0};
		child_pi.tgid      = e->tgid;
		child_pi.ppid      = e->ppid;
		child_pi.start_ns  = e->start_ns;
		child_pi.cgroup_id = e->cgroup_id;
		memcpy(child_pi.comm, e->comm, COMM_LEN);
		if (has_parent_pi) {
			memcpy(child_pi.cmdline, parent_pi.cmdline, CMDLINE_MAX);
			child_pi.cmdline_len = parent_pi.cmdline_len;
		}
		bpf_map_update_elem(proc_map_fd, &e->tgid, &child_pi, BPF_ANY);
		break;
	}

	case EVENT_EXIT: {
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0) {
			const char *rname = (ti.rule_id < num_rules)
				? rules[ti.rule_id].name : "?";
			log_ts("INFO", "EXIT: pid=%u rule=%s cpu=%.2fs rss_max=%lluMB",
			       e->tgid, rname,
			       (double)e->cpu_ns / 1e9,
			       (unsigned long long)(e->rss_max_pages * 4 / 1024));
		}
		/* BPF already deleted from maps */
		break;
	}
	}
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

static void write_snapshot(void)
{
	char tmp_path[PATH_MAX_LEN];
	snprintf(tmp_path, sizeof(tmp_path), "%s/.%s.tmp.%d",
		 cfg_output_dir, cfg_output_file, getpid());

	FILE *f = fopen(tmp_path, "w");
	if (!f) {
		log_ts("ERROR", "cannot create temp file: %s", tmp_path);
		return;
	}

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = 4096;

	/* Compute boot offset: monotonic → epoch */
	struct timespec mono;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	time_t now_epoch = time(NULL);
	double mono_now = (double)mono.tv_sec + (double)mono.tv_nsec / 1e9;

	const char *pfx = cfg_metric_prefix;

	/* HELP/TYPE headers */
	fprintf(f,
		"# HELP %s_info Process info (value always 1, metadata in labels)\n"
		"# TYPE %s_info gauge\n"
		"# HELP %s_rss_bytes Process RSS memory in bytes\n"
		"# TYPE %s_rss_bytes gauge\n"
		"# HELP %s_rss_max_bytes Max observed RSS memory in bytes\n"
		"# TYPE %s_rss_max_bytes gauge\n"
		"# HELP %s_vsize_bytes Process virtual memory in bytes\n"
		"# TYPE %s_vsize_bytes gauge\n"
		"# HELP %s_cpu_seconds_total Total CPU time (user + system) in seconds\n"
		"# TYPE %s_cpu_seconds_total counter\n"
		"# HELP %s_threads Number of threads\n"
		"# TYPE %s_threads gauge\n"
		"# HELP %s_start_time_seconds Process start time as unix epoch\n"
		"# TYPE %s_start_time_seconds gauge\n"
		"# HELP %s_uptime_seconds Process uptime in seconds\n"
		"# TYPE %s_uptime_seconds gauge\n"
		"# HELP %s_oom_score_adj Current OOM score adjustment\n"
		"# TYPE %s_oom_score_adj gauge\n"
		"# HELP %s_is_root Whether PID is a root of tracked tree (1=root, 0=child)\n"
		"# TYPE %s_is_root gauge\n"
		"# HELP %s_state Process state (R=running, S=sleeping, D=disk_sleep, T=stopped, Z=zombie)\n"
		"# TYPE %s_state gauge\n",
		pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx,
		pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx, pfx,
		pfx, pfx);

	/* Iterate proc_map */
	__u32 key = 0, next_key;
	struct proc_info pi;
	int pid_count = 0;

	/* Collect unique cgroups for cgroup metrics */
	struct { char path[256]; char rule[64]; } seen_cg[MAX_CGROUPS];
	int seen_cg_count = 0;

	/* Collect keys to delete (dead processes missed due to ringbuf overflow) */
	__u32 dead_keys[256];
	int dead_count = 0;

	int err = bpf_map_get_next_key(proc_map_fd, NULL, &next_key);
	while (err == 0) {
		key = next_key;
		if (bpf_map_lookup_elem(proc_map_fd, &key, &pi) != 0)
			goto next;

		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &key, &ti) != 0)
			goto next;

		/* Check if process is still alive (no /proc needed) */
		if (kill((pid_t)key, 0) != 0 && errno == ESRCH) {
			if (dead_count < 256)
				dead_keys[dead_count++] = key;
			goto next;
		}

		const char *rule_name = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : "unknown";

		/* Convert cmdline */
		char cmdline[CMDLINE_MAX + 4];
		cmdline_to_str(pi.cmdline, pi.cmdline_len, cmdline, sizeof(cmdline));
		/* Truncate */
		if ((int)strlen(cmdline) > cfg_cmdline_max_len) {
			cmdline[cfg_cmdline_max_len] = '\0';
			strcat(cmdline, "...");
		}

		/* Resolve cgroup */
		const char *cg_path = resolve_cgroup(pi.cgroup_id);

		/* Escape labels */
		char comm_esc[64], cmdline_esc[CMDLINE_MAX * 2], cg_esc[512];
		escape_label(pi.comm, comm_esc, sizeof(comm_esc));
		escape_label(cmdline, cmdline_esc, sizeof(cmdline_esc));
		escape_label(cg_path, cg_esc, sizeof(cg_esc));

		/* Compute times */
		double uptime_sec = mono_now - (double)pi.start_ns / 1e9;
		if (uptime_sec < 0) uptime_sec = 0;
		time_t start_epoch = now_epoch - (time_t)uptime_sec;

		/* Write metrics */
		fprintf(f, "%s_info{rule=\"%s\",root_pid=\"%u\",pid=\"%u\","
			"comm=\"%s\",cmdline=\"%s\",cgroup=\"%s\"} 1\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			comm_esc, cmdline_esc, cg_esc);
		fprintf(f, "%s_rss_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.rss_pages * page_size));
		fprintf(f, "%s_rss_max_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.rss_max_pages * page_size));
		fprintf(f, "%s_vsize_bytes{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %llu\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(unsigned long long)(pi.vsize_pages * page_size));
		fprintf(f, "%s_cpu_seconds_total{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %.2f\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(double)pi.cpu_ns / 1e9);
		fprintf(f, "%s_threads{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %u\n",
			pfx, rule_name, ti.root_pid, pi.tgid, pi.threads);
		fprintf(f, "%s_start_time_seconds{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %ld\n",
			pfx, rule_name, ti.root_pid, pi.tgid, (long)start_epoch);
		fprintf(f, "%s_uptime_seconds{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %ld\n",
			pfx, rule_name, ti.root_pid, pi.tgid,
			(long)(uptime_sec > 0 ? uptime_sec : 0));
		fprintf(f, "%s_oom_score_adj{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %d\n",
			pfx, rule_name, ti.root_pid, pi.tgid, pi.oom_score_adj);
		fprintf(f, "%s_is_root{rule=\"%s\",root_pid=\"%u\",pid=\"%u\"} %u\n",
			pfx, rule_name, ti.root_pid, pi.tgid, ti.is_root);
		char state_str[2] = { (char)(pi.state ? pi.state : '?'), '\0' };
		fprintf(f, "%s_state{rule=\"%s\",root_pid=\"%u\",pid=\"%u\","
			"state=\"%s\"} 1\n",
			pfx, rule_name, ti.root_pid, pi.tgid, state_str);

		/* Collect unique cgroup for cgroup-level metrics */
		if (cg_path[0] && seen_cg_count < MAX_CGROUPS) {
			int found = 0;
			for (int i = 0; i < seen_cg_count; i++) {
				if (strcmp(seen_cg[i].path, cg_path) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				snprintf(seen_cg[seen_cg_count].path,
					 sizeof(seen_cg[0].path), "%s", cg_path);
				snprintf(seen_cg[seen_cg_count].rule,
					 sizeof(seen_cg[0].rule), "%s", rule_name);
				seen_cg_count++;
			}
		}
		pid_count++;
next:
		err = bpf_map_get_next_key(proc_map_fd, &key, &next_key);
	}

	/* Clean up dead processes */
	for (int i = 0; i < dead_count; i++) {
		bpf_map_delete_elem(tracked_map_fd, &dead_keys[i]);
		bpf_map_delete_elem(proc_map_fd, &dead_keys[i]);
	}
	if (dead_count > 0)
		log_ts("INFO", "cleaned up %d dead PIDs", dead_count);

	/* Cgroup v2 metrics from /sys/fs/cgroup */
	if (seen_cg_count > 0) {
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
			char cg_esc[512];
			escape_label(seen_cg[i].path, cg_esc, sizeof(cg_esc));

			struct { const char *file; const char *metric; } kv[] = {
				{ "memory.max",          "memory_max_bytes" },
				{ "memory.current",      "memory_current_bytes" },
				{ "memory.swap.current", "memory_swap_current_bytes" },
				{ "cpu.weight",          "cpu_weight" },
				{ "pids.current",        "pids_current" },
			};
			for (int k = 0; k < 5; k++) {
				long long v = read_cgroup_value(seen_cg[i].path,
								kv[k].file);
				if (v >= 0) {
					fprintf(f, "%s_cgroup_%s{rule=\"%s\","
						"cgroup=\"%s\"} %lld\n",
						pfx, kv[k].metric,
						seen_cg[i].rule, cg_esc, v);
				}
			}
		}
	}

	fclose(f);

	/* Atomic rename */
	char dest[PATH_MAX_LEN];
	snprintf(dest, sizeof(dest), "%s/%s", cfg_output_dir, cfg_output_file);
	if (rename(tmp_path, dest) == 0)
		chmod(dest, 0644);
	else
		log_ts("ERROR", "rename %s → %s: %s", tmp_path, dest, strerror(errno));

	log_ts("INFO", "snapshot: %d PIDs, %d cgroups → %s",
	       pid_count, seen_cg_count, dest);
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
		"Usage: %s [options]\n"
		"  -c <path>     config file     (env: config_file)\n"
		"  -o <dir>      output dir      (env: output_dir,  default: /scripts/system_metrics)\n"
		"  -f <file>     output file     (env: output_file, default: process_metrics.prom)\n"
		"  -i <seconds>  snapshot interval (env: snapshot_interval, default: 30)\n"
		"  -p <prefix>   metric prefix   (env: metric_prefix, default: process_metrics)\n"
		"  -l <len>      cmdline max len (env: cmdline_max_len, default: 200)\n"
		"  -r <N>        exec event rate limit per sec (env: exec_rate_limit, 0=unlimited)\n"
		"  -h            show this help\n",
		prog);
}

int main(int argc, char *argv[])
{
	/* Defaults from environment */
	const char *env;
	if ((env = getenv("config_file")))     cfg_config_file = env;
	if ((env = getenv("output_dir")))      cfg_output_dir = env;
	if ((env = getenv("output_file")))     cfg_output_file = env;
	if ((env = getenv("snapshot_interval"))) cfg_snapshot_interval = atoi(env);
	if ((env = getenv("metric_prefix")))   cfg_metric_prefix = env;
	if ((env = getenv("cmdline_max_len"))) cfg_cmdline_max_len = atoi(env);
	if ((env = getenv("exec_rate_limit"))) cfg_exec_rate_limit = atoi(env);

	/* Command-line overrides */
	int opt;
	while ((opt = getopt(argc, argv, "c:o:f:i:p:l:r:h")) != -1) {
		switch (opt) {
		case 'c': cfg_config_file = optarg; break;
		case 'o': cfg_output_dir = optarg; break;
		case 'f': cfg_output_file = optarg; break;
		case 'i': cfg_snapshot_interval = atoi(optarg); break;
		case 'p': cfg_metric_prefix = optarg; break;
		case 'l': cfg_cmdline_max_len = atoi(optarg); break;
		case 'r': cfg_exec_rate_limit = atoi(optarg); break;
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

	/* Parse config */
	if (parse_config(cfg_config_file) < 0)
		return 1;
	if (num_rules == 0) {
		fprintf(stderr, "FATAL: no rules loaded\n");
		return 1;
	}

	/* Check output dir */
	struct stat st;
	if (stat(cfg_output_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "FATAL: output dir not found: %s\n", cfg_output_dir);
		return 1;
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

	/* Load BPF programs */
	if (process_metrics_bpf__load(skel)) {
		fprintf(stderr, "FATAL: failed to load BPF programs\n");
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Attach all probes */
	if (process_metrics_bpf__attach(skel)) {
		fprintf(stderr, "FATAL: failed to attach BPF programs\n");
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Get map FDs */
	tracked_map_fd = bpf_map__fd(skel->maps.tracked_map);
	proc_map_fd    = bpf_map__fd(skel->maps.proc_map);

	/* Ring buffer */
	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "FATAL: failed to create ring buffer\n");
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Signals */
	signal(SIGTERM, sig_term);
	signal(SIGINT,  sig_term);
	signal(SIGHUP,  sig_hup);

	/* One-time startup scan: find already-running processes */
	initial_scan();

	log_ts("INFO", "started: %d rules, snapshot every %ds, output=%s/%s, exec_rate_limit=%d/s",
	       num_rules, cfg_snapshot_interval, cfg_output_dir, cfg_output_file,
	       cfg_exec_rate_limit);

	/* Main loop */
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
			log_ts("INFO", "SIGHUP: reloading config...");

			/* Clear all tracking — delete from beginning each time */
			__u32 del_key;
			while (bpf_map_get_next_key(tracked_map_fd, NULL, &del_key) == 0) {
				bpf_map_delete_elem(tracked_map_fd, &del_key);
				bpf_map_delete_elem(proc_map_fd, &del_key);
			}

			parse_config(cfg_config_file);
			build_cgroup_cache();
			initial_scan();
		}

		/* Periodic snapshot */
		time_t now = time(NULL);
		if (now - last_snapshot >= cfg_snapshot_interval) {
			write_snapshot();
			last_snapshot = now;
		}
	}

	ring_buffer__free(rb);
	process_metrics_bpf__destroy(skel);
	free_rules();

	log_ts("INFO", "stopped");
	return 0;
}
