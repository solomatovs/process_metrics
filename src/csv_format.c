/*
 * csv_format.c — fast CSV formatting without snprintf
 *
 * Replaces the single giant snprintf() call in format_csv_row() with
 * direct buffer writes: memcpy for strings, hand-rolled u64/i64/u32/i32
 * to decimal, and a fixed-point double→string for cpu_usage_ratio.
 *
 * Profiling showed snprintf + _IO_default_xsputn + _itoa_word + __printf_fp_l
 * consuming ~48% of total CPU.  This file eliminates all of that.
 */

#define _GNU_SOURCE
#include <string.h>
#include <time.h>

#include "csv_format.h"
#include "event_file.h"

/* ── CSV header (identical to the old one in http_server.c) ───────── */

static const char CSV_HEADER_STR[] =
	"timestamp,hostname,event_type,rule,tags,"
	"root_pid,pid,ppid,uid,user_name,loginuid,login_name,sessionid,euid,euser_name,tty_nr,"
	"comm,exec,args,cgroup,pwd,is_root,state,exit_code,sched_policy,"
	"cpu_ns,cpu_usage_ratio,"
	"rss_bytes,rss_min_bytes,rss_max_bytes,shmem_bytes,swap_bytes,vsize_bytes,"
	"io_read_bytes,io_write_bytes,io_rchar,io_wchar,io_syscr,io_syscw,"
	"maj_flt,min_flt,"
	"nvcsw,nivcsw,threads,oom_score_adj,oom_killed,"
	"net_tx_bytes,net_rx_bytes,"
	"start_time_ns,uptime_seconds,"
	"mnt_ns,pid_ns,net_ns,cgroup_ns,"
	"preempted_by_pid,preempted_by_comm,"
	"cgroup_memory_max,cgroup_memory_current,cgroup_swap_current,"
	"cgroup_cpu_weight,"
	"cgroup_cpu_max,cgroup_cpu_max_period,"
	"cgroup_cpu_nr_periods,cgroup_cpu_nr_throttled,cgroup_cpu_throttled_usec,"
	"cgroup_pids_current,"
	"file_path,file_flags,file_read_bytes,file_write_bytes,file_open_count,"
	"net_local_addr,net_remote_addr,net_local_port,net_remote_port,"
	"net_conn_tx_bytes,net_conn_rx_bytes,net_duration_ms,"
	"sig_num,sig_target_pid,sig_target_comm,sig_code,sig_result,"
	"sec_local_addr,sec_remote_addr,sec_local_port,sec_remote_port,"
	"sec_af,sec_tcp_state,sec_direction,open_tcp_conns,"
	"disk_total_bytes,disk_used_bytes,disk_avail_bytes\n";

const char *csv_header(int *len)
{
	if (len)
		*len = (int)(sizeof(CSV_HEADER_STR) - 1);
	return CSV_HEADER_STR;
}

/* ── fast integer → decimal ───────────────────────────────────────── */

/*
 * Write unsigned 64-bit integer as decimal into buf.
 * Returns pointer to one past last written byte.
 * Caller must ensure at least 20 bytes available.
 */
static inline char *put_u64(char *p, unsigned long long v)
{
	/* Reverse digits into tmp, then copy forward */
	char tmp[20];
	int i = 0;
	if (v == 0) {
		*p++ = '0';
		return p;
	}
	while (v) {
		tmp[i++] = '0' + (char)(v % 10);
		v /= 10;
	}
	while (i > 0)
		*p++ = tmp[--i];
	return p;
}

/* Signed 64-bit */
static inline char *put_i64(char *p, long long v)
{
	if (v < 0) {
		*p++ = '-';
		/* Handle LLONG_MIN safely */
		return put_u64(p, (unsigned long long)(-(v + 1)) + 1);
	}
	return put_u64(p, (unsigned long long)v);
}

/* Unsigned 32-bit (same code, narrower type avoids cast at call site) */
static inline char *put_u32(char *p, unsigned int v)
{
	return put_u64(p, v);
}

/* Signed 32-bit */
static inline char *put_i32(char *p, int v)
{
	if (v < 0) {
		*p++ = '-';
		return put_u32(p, (unsigned int)(-(v + 1)) + 1);
	}
	return put_u32(p, (unsigned int)v);
}

/* ── fast double → "N.NNNN" (4 decimals, matching %.4f) ──────────── */

static inline char *put_f64_4(char *p, double v)
{
	if (v < 0.0) {
		*p++ = '-';
		v = -v;
	}
	/* integer part */
	unsigned long long ipart = (unsigned long long)v;
	p = put_u64(p, ipart);
	*p++ = '.';
	/* fractional part: 4 digits */
	double frac = v - (double)ipart;
	unsigned int f4 = (unsigned int)(frac * 10000.0 + 0.5);
	if (f4 >= 10000) { f4 = 9999; }  /* clamp rounding overflow */
	p[0] = '0' + (char)(f4 / 1000); f4 %= 1000;
	p[1] = '0' + (char)(f4 / 100);  f4 %= 100;
	p[2] = '0' + (char)(f4 / 10);   f4 %= 10;
	p[3] = '0' + (char)f4;
	return p + 4;
}

/* ── CSV field escaping (inline, no intermediate buffer) ──────────── */

/*
 * Write CSV-escaped string field directly to *p.
 * Returns pointer past the last byte written.
 * Always wraps in double quotes; doubles internal quotes;
 * replaces \n \r with space.
 *
 * limit: max source bytes to scan (strlen-safe for fixed-size fields).
 */
static inline char *put_str(char *p, const char *src, int limit)
{
	*p++ = '"';
	for (int i = 0; i < limit && src[i]; i++) {
		char c = src[i];
		if (c == '"') {
			*p++ = '"';
			*p++ = '"';
		} else if (c == '\n' || c == '\r') {
			*p++ = ' ';
		} else {
			*p++ = c;
		}
	}
	*p++ = '"';
	return p;
}

/* ── timestamp formatting ─────────────────────────────────────────── */

/*
 * Format timestamp_ns as "YYYY-MM-DD HH:MM:SS.mmm" (23 bytes).
 * Returns pointer past the last byte written.
 */
static inline char *put_timestamp(char *p, unsigned long long ts_ns)
{
	if (ts_ns == 0) {
		memcpy(p, "0000-00-00 00:00:00.000", 23);
		return p + 23;
	}
	time_t sec = (time_t)(ts_ns / 1000000000ULL);
	unsigned ms = (unsigned)((ts_ns % 1000000000ULL) / 1000000);
	struct tm tm;
	gmtime_r(&sec, &tm);

	/* YYYY-MM-DD HH:MM:SS.mmm — hand-write each part */
	int y = tm.tm_year + 1900;
	p[0] = '0' + (char)(y / 1000); y %= 1000;
	p[1] = '0' + (char)(y / 100);  y %= 100;
	p[2] = '0' + (char)(y / 10);   y %= 10;
	p[3] = '0' + (char)y;
	p[4] = '-';
	int m = tm.tm_mon + 1;
	p[5] = '0' + (char)(m / 10);
	p[6] = '0' + (char)(m % 10);
	p[7] = '-';
	p[8] = '0' + (char)(tm.tm_mday / 10);
	p[9] = '0' + (char)(tm.tm_mday % 10);
	p[10] = ' ';
	p[11] = '0' + (char)(tm.tm_hour / 10);
	p[12] = '0' + (char)(tm.tm_hour % 10);
	p[13] = ':';
	p[14] = '0' + (char)(tm.tm_min / 10);
	p[15] = '0' + (char)(tm.tm_min % 10);
	p[16] = ':';
	p[17] = '0' + (char)(tm.tm_sec / 10);
	p[18] = '0' + (char)(tm.tm_sec % 10);
	p[19] = '.';
	p[20] = '0' + (char)(ms / 100); ms %= 100;
	p[21] = '0' + (char)(ms / 10);  ms %= 10;
	p[22] = '0' + (char)ms;
	return p + 23;
}

/* ── helpers ──────────────────────────────────────────────────────── */

/* Append comma */
#define COMMA() (*p++ = ',')

/* Append string field + comma */
#define STR(field, maxlen) do { p = put_str(p, (field), (maxlen)); COMMA(); } while(0)

/* Append unsigned 64-bit + comma */
#define U64(v) do { p = put_u64(p, (unsigned long long)(v)); COMMA(); } while(0)

/* Append signed 64-bit + comma */
#define I64(v) do { p = put_i64(p, (long long)(v)); COMMA(); } while(0)

/* Append unsigned 32-bit + comma */
#define U32(v) do { p = put_u32(p, (unsigned int)(v)); COMMA(); } while(0)

/* Append signed 32-bit + comma */
#define I32(v) do { p = put_i32(p, (int)(v)); COMMA(); } while(0)

/* Append double (4 decimals) + comma */
#define F64(v) do { p = put_f64_4(p, (v)); COMMA(); } while(0)

/* ── main formatting function ─────────────────────────────────────── */

int csv_format_row(char *buf, int buflen,
		   const struct ef_record *rec,
		   const struct csv_resolvers *resolvers)
{
	/*
	 * Worst-case row size estimate:
	 *   ~90 fields × average 20 chars = ~1800 bytes
	 *   String fields with escaping could expand to 2×, but the largest
	 *   (args, exec, tags, cgroup, pwd) are bounded by EV_ESC_SIZE.
	 *   Total worst case: ~6000 bytes.  8192-byte buf is safe.
	 */
	if (buflen < 4096)
		return -1;

	const struct metric_event *ev = &rec->event;
	char *p = buf;

	/* ── timestamp ──────────────────────────────────────────────── */
	p = put_timestamp(p, ev->timestamp_ns);
	COMMA();

	/* ── identification ─────────────────────────────────────────── */
	STR(rec->hostname, EF_HOSTNAME_LEN);
	STR(ev->event_type, EV_EVENT_TYPE_LEN);
	STR(ev->rule, EV_RULE_LEN);
	STR(ev->tags, EV_TAGS_LEN);

	U32(ev->root_pid);
	U32(ev->pid);
	U32(ev->ppid);
	U32(ev->uid);
	/* user_name (resolved from uid) */
	if (resolvers && resolvers->resolve_uid) {
		char uname[64];
		resolvers->resolve_uid(ev->uid, uname, sizeof(uname));
		STR(uname, 64);
	} else {
		*p++ = '"'; *p++ = '"'; COMMA();
	}
	U32(ev->loginuid);
	/* login_name (resolved from loginuid) */
	if (resolvers && resolvers->resolve_uid &&
	    ev->loginuid != 4294967295U) {
		char lname[64];
		resolvers->resolve_uid(ev->loginuid, lname, sizeof(lname));
		STR(lname, 64);
	} else {
		*p++ = '"'; *p++ = '"'; COMMA();
	}
	U32(ev->sessionid);
	U32(ev->euid);
	/* euser_name (resolved from euid) */
	if (resolvers && resolvers->resolve_uid) {
		char ename[64];
		resolvers->resolve_uid(ev->euid, ename, sizeof(ename));
		STR(ename, 64);
	} else {
		*p++ = '"'; *p++ = '"'; COMMA();
	}
	U32(ev->tty_nr);

	/* ── process metadata ───────────────────────────────────────── */
	STR(ev->comm, COMM_LEN);
	STR(ev->exec_path, CMDLINE_MAX);
	STR(ev->args, CMDLINE_MAX);

	/* cgroup: resolve docker names if callback provided */
	if (resolvers && resolvers->resolve_cgroup) {
		char cg_resolved[EV_CGROUP_LEN];
		resolvers->resolve_cgroup(ev->cgroup, cg_resolved,
					  sizeof(cg_resolved));
		STR(cg_resolved, EV_CGROUP_LEN);
	} else {
		STR(ev->cgroup, EV_CGROUP_LEN);
	}

	STR(ev->pwd, EV_PWD_LEN);
	U32(ev->is_root);

	/* state: single char field */
	{
		char state_raw[2] = { (char)(ev->state ? ev->state : '\0'), '\0' };
		STR(state_raw, 2);
	}

	U32(ev->exit_code);
	U32(ev->sched_policy);

	/* ── CPU ─────────────────────────────────────────────────────── */
	U64(ev->cpu_ns);
	F64(ev->cpu_usage_ratio);

	/* ── memory ──────────────────────────────────────────────────── */
	U64(ev->rss_bytes);
	U64(ev->rss_min_bytes);
	U64(ev->rss_max_bytes);
	U64(ev->shmem_bytes);
	U64(ev->swap_bytes);
	U64(ev->vsize_bytes);

	/* ── I/O ─────────────────────────────────────────────────────── */
	U64(ev->io_read_bytes);
	U64(ev->io_write_bytes);
	U64(ev->io_rchar);
	U64(ev->io_wchar);
	U64(ev->io_syscr);
	U64(ev->io_syscw);
	U64(ev->maj_flt);
	U64(ev->min_flt);

	/* ── scheduler / threads / OOM ───────────────────────────────── */
	U64(ev->nvcsw);
	U64(ev->nivcsw);
	U32(ev->threads);
	I32(ev->oom_score_adj);
	U32(ev->oom_killed);

	/* ── process network ─────────────────────────────────────────── */
	U64(ev->net_tx_bytes);
	U64(ev->net_rx_bytes);

	/* ── time ────────────────────────────────────────────────────── */
	U64(ev->start_time_ns);
	U64(ev->uptime_seconds);

	/* ── namespaces ──────────────────────────────────────────────── */
	U32(ev->mnt_ns_inum);
	U32(ev->pid_ns_inum);
	U32(ev->net_ns_inum);
	U32(ev->cgroup_ns_inum);

	/* ── preemption ──────────────────────────────────────────────── */
	U32(ev->preempted_by_pid);
	STR(ev->preempted_by_comm, COMM_LEN);

	/* ── cgroup v2 ───────────────────────────────────────────────── */
	I64(ev->cgroup_memory_max);
	I64(ev->cgroup_memory_current);
	I64(ev->cgroup_swap_current);
	I64(ev->cgroup_cpu_weight);
	I64(ev->cgroup_cpu_max);
	I64(ev->cgroup_cpu_max_period);
	I64(ev->cgroup_cpu_nr_periods);
	I64(ev->cgroup_cpu_nr_throttled);
	I64(ev->cgroup_cpu_throttled_usec);
	I64(ev->cgroup_pids_current);

	/* ── file tracking ───────────────────────────────────────────── */
	STR(ev->file_path, FILE_PATH_MAX);
	U32(ev->file_flags);
	U64(ev->file_read_bytes);
	U64(ev->file_write_bytes);
	U32(ev->file_open_count);

	/* ── network tracking ────────────────────────────────────────── */
	STR(ev->net_local_addr, EV_ADDR_LEN);
	STR(ev->net_remote_addr, EV_ADDR_LEN);
	U32(ev->net_local_port);
	U32(ev->net_remote_port);
	U64(ev->net_conn_tx_bytes);
	U64(ev->net_conn_rx_bytes);
	U64(ev->net_duration_ms);

	/* ── signals ─────────────────────────────────────────────────── */
	U32(ev->sig_num);
	U32(ev->sig_target_pid);
	STR(ev->sig_target_comm, COMM_LEN);
	I32(ev->sig_code);
	I32(ev->sig_result);

	/* ── security tracking ───────────────────────────────────────── */
	STR(ev->sec_local_addr, EV_ADDR_LEN);
	STR(ev->sec_remote_addr, EV_ADDR_LEN);
	U32(ev->sec_local_port);
	U32(ev->sec_remote_port);
	U32(ev->sec_af);
	U32(ev->sec_tcp_state);
	U32(ev->sec_direction);
	U64(ev->open_tcp_conns);

	/* ── disk usage (last 3 fields — no trailing comma on last) ── */
	U64(ev->disk_total_bytes);
	U64(ev->disk_used_bytes);
	/* last field: no trailing comma, newline instead */
	p = put_u64(p, (unsigned long long)ev->disk_avail_bytes);
	*p++ = '\n';

	/* Check we didn't overflow */
	int written = (int)(p - buf);
	if (written >= buflen)
		return -1;

	*p = '\0';
	return written;
}
