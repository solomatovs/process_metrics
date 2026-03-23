/*
 * http_server.c — embedded HTTP server for process_metrics
 *
 * Minimal HTTP/1.1 server with two endpoints:
 *
 *   GET /metrics?format=prom — returns the current .prom snapshot file as-is.
 *                              File is NOT cleared (overwritten by write_snapshot).
 *
 *   GET /metrics?format=csv  — swaps the event file, formats accumulated events
 *   GET /metrics             — as CSV, and clears the buffer only after successful
 *                              delivery. If delivery fails, events are preserved.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include "http_server.h"
#include "event_file.h"

/* ── state ───────────────────────────────────────────────────────── */

static int           g_listen_fd = -1;
static pthread_t     g_thread;
static volatile int  g_running;
static char          g_prom_path[512];

/* ── CSV formatting ──────────────────────────────────────────────── */

static const char *CSV_HEADER =
	"timestamp,hostname,event_type,rule,root_pid,pid,ppid,"
	"comm,exec,args,cgroup,is_root,state,exit_code,"
	"cpu_ns,cpu_usage_ratio,rss_bytes,rss_min_bytes,rss_max_bytes,"
	"shmem_bytes,swap_bytes,vsize_bytes,"
	"io_read_bytes,io_write_bytes,maj_flt,min_flt,"
	"nvcsw,nivcsw,threads,oom_score_adj,oom_killed,"
	"net_tx_bytes,net_rx_bytes,start_time_ns,uptime_seconds,"
	"cgroup_memory_max,cgroup_memory_current,cgroup_swap_current,"
	"cgroup_cpu_weight,cgroup_pids_current\n";

static int csv_escape_field(const char *src, char *dst, int dstlen)
{
	int j = 0;
	if (j < dstlen) dst[j++] = '"';
	for (int i = 0; src[i] && j < dstlen - 3; i++) {
		if (src[i] == '"') {
			dst[j++] = '"';
			dst[j++] = '"';
		} else {
			dst[j++] = src[i];
		}
	}
	if (j < dstlen) dst[j++] = '"';
	dst[j] = '\0';
	return j;
}

static int format_csv_row(char *buf, int buflen, const struct ef_record *rec)
{
	const struct metric_event *ev = &rec->event;
	char hostname_esc[600], comm_esc[200], exec_esc[600];
	char args_esc[600], cgroup_esc[600];

	csv_escape_field(rec->hostname, hostname_esc, sizeof(hostname_esc));
	csv_escape_field(ev->comm, comm_esc, sizeof(comm_esc));
	csv_escape_field(ev->exec_path, exec_esc, sizeof(exec_esc));
	csv_escape_field(ev->args, args_esc, sizeof(args_esc));
	csv_escape_field(ev->cgroup, cgroup_esc, sizeof(cgroup_esc));

	/* Format timestamp as ISO 8601: YYYY-MM-DD HH:MM:SS.mmm
	 * This format is natively parsed by ClickHouse DateTime64(3) */
	char ts_str[32] = "0000-00-00 00:00:00.000";
	if (ev->timestamp_ns > 0) {
		time_t sec = (time_t)(ev->timestamp_ns / 1000000000ULL);
		unsigned ms = (unsigned)((ev->timestamp_ns % 1000000000ULL) / 1000000);
		struct tm tm;
		gmtime_r(&sec, &tm);
		snprintf(ts_str, sizeof(ts_str),
			 "%04d-%02d-%02d %02d:%02d:%02d.%03u",
			 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			 tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
	}

	char state_str[2] = { (char)(ev->state ? ev->state : '?'), '\0' };

	int n = snprintf(buf, buflen,
		"%s,%s,%s,%s,%u,%u,%u,"
		"%s,%s,%s,%s,%u,%s,%u,"
		"%llu,%.4f,%llu,%llu,%llu,"
		"%llu,%llu,%llu,"
		"%llu,%llu,%llu,%llu,"
		"%llu,%llu,%u,%d,%u,"
		"%llu,%llu,%llu,%llu,"
		"%lld,%lld,%lld,%lld,%lld\n",
		ts_str,
		hostname_esc,
		ev->event_type,
		ev->rule,
		ev->root_pid,
		ev->pid,
		ev->ppid,
		comm_esc,
		exec_esc,
		args_esc,
		cgroup_esc,
		(unsigned)ev->is_root,
		state_str,
		ev->exit_code,
		(unsigned long long)ev->cpu_ns,
		ev->cpu_usage_ratio,
		(unsigned long long)ev->rss_bytes,
		(unsigned long long)ev->rss_min_bytes,
		(unsigned long long)ev->rss_max_bytes,
		(unsigned long long)ev->shmem_bytes,
		(unsigned long long)ev->swap_bytes,
		(unsigned long long)ev->vsize_bytes,
		(unsigned long long)ev->io_read_bytes,
		(unsigned long long)ev->io_write_bytes,
		(unsigned long long)ev->maj_flt,
		(unsigned long long)ev->min_flt,
		(unsigned long long)ev->nvcsw,
		(unsigned long long)ev->nivcsw,
		ev->threads,
		(int)ev->oom_score_adj,
		(unsigned)ev->oom_killed,
		(unsigned long long)ev->net_tx_bytes,
		(unsigned long long)ev->net_rx_bytes,
		(unsigned long long)ev->start_time_ns,
		(unsigned long long)ev->uptime_seconds,
		(long long)ev->cgroup_memory_max,
		(long long)ev->cgroup_memory_current,
		(long long)ev->cgroup_swap_current,
		(long long)ev->cgroup_cpu_weight,
		(long long)ev->cgroup_pids_current);

	return n < buflen ? n : -1;
}

/*
 * Send full HTTP response. Returns 0 on success, -1 on error.
 */
static int send_response(int fd, int status, const char *content_type,
			 const char *body, int body_len)
{
	const char *status_text = (status == 200) ? "OK" : "Not Found";
	char header[512];
	int hlen = snprintf(header, sizeof(header),
		"HTTP/1.1 %d %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n",
		status, status_text, content_type, body_len);

	/* Send header */
	ssize_t sent = send(fd, header, hlen, MSG_NOSIGNAL);
	if (sent != hlen)
		return -1;

	/* Send body in chunks */
	ssize_t total = 0;
	while (total < body_len) {
		ssize_t n = send(fd, body + total, body_len - total,
				 MSG_NOSIGNAL);
		if (n <= 0)
			return -1;
		total += n;
	}

	return 0;
}

/*
 * Send HTTP header without Content-Length.
 * With Connection: close, the client reads until EOF.
 */
static int send_stream_header(int fd, const char *content_type)
{
	char header[512];
	int hlen = snprintf(header, sizeof(header),
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		content_type);
	ssize_t sent = send(fd, header, hlen, MSG_NOSIGNAL);
	return (sent == hlen) ? 0 : -1;
}

/*
 * Send all bytes to socket. Returns 0 on success, -1 on error.
 */
static int send_all(int fd, const char *buf, int len)
{
	ssize_t total = 0;
	while (total < len) {
		ssize_t n = send(fd, buf + total, len - total, MSG_NOSIGNAL);
		if (n <= 0)
			return -1;
		total += n;
	}
	return 0;
}

/*
 * Stream CSV response: read records one at a time from data_fd,
 * format each as CSV, and send directly to the socket.
 * No large memory allocations — uses only stack buffers.
 */
static void handle_csv_stream(int client_fd)
{
	int data_fd = ef_swap_fd();

	if (data_fd < 0) {
		/* No events — return header only */
		send_response(client_fd, 200, "text/csv; charset=utf-8",
			      CSV_HEADER, (int)strlen(CSV_HEADER));
		ef_commit();
		return;
	}

	/* Send HTTP header (no Content-Length — stream until close) */
	if (send_stream_header(client_fd, "text/csv; charset=utf-8") < 0) {
		close(data_fd);
		return; /* .pending preserved */
	}

	/* Send CSV column header */
	if (send_all(client_fd, CSV_HEADER, (int)strlen(CSV_HEADER)) < 0) {
		close(data_fd);
		return;
	}

	/* Stream records one at a time */
	struct ef_record rec;
	char row_buf[4096];
	int ok = 1;

	while (ok) {
		ssize_t r = read(data_fd, &rec, sizeof(rec));
		if (r == 0)
			break;  /* EOF */
		if (r != (ssize_t)sizeof(rec))
			break;  /* partial record */

		int n = format_csv_row(row_buf, sizeof(row_buf), &rec);
		if (n <= 0)
			continue;

		if (send_all(client_fd, row_buf, n) < 0) {
			ok = 0;
			break;
		}
	}

	close(data_fd);

	if (ok)
		ef_commit();
	/* else: .pending preserved for next request */
}

/* ── Prom: read .prom file ───────────────────────────────────────── */

static char *read_prom_file(int *out_len)
{
	*out_len = 0;

	struct stat st;
	if (stat(g_prom_path, &st) != 0 || st.st_size == 0)
		return NULL;

	int fd = open(g_prom_path, O_RDONLY);
	if (fd < 0)
		return NULL;

	char *buf = malloc(st.st_size + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}

	ssize_t total = 0;
	while (total < st.st_size) {
		ssize_t r = read(fd, buf + total, st.st_size - total);
		if (r <= 0)
			break;
		total += r;
	}
	close(fd);

	if (total <= 0) {
		free(buf);
		return NULL;
	}

	buf[total] = '\0';
	*out_len = (int)total;
	return buf;
}

/* ── HTTP response ───────────────────────────────────────────────── */

enum format_type { FMT_CSV, FMT_PROM };

static enum format_type parse_format(const char *request)
{
	if (strstr(request, "format=prom"))
		return FMT_PROM;
	return FMT_CSV;
}

/* ── request handler ─────────────────────────────────────────────── */

static void handle_request(int client_fd,
			   const struct sockaddr_in *peer)
{
	char buf[4096];
	int n = (int)recv(client_fd, buf, sizeof(buf) - 1, 0);
	if (n <= 0)
		return;
	buf[n] = '\0';

	char peer_ip[INET_ADDRSTRLEN] = "?";
	inet_ntop(AF_INET, &peer->sin_addr, peer_ip, sizeof(peer_ip));

	/* Handle HEAD /metrics — ClickHouse url() sends HEAD to check availability */
	if (strncmp(buf, "HEAD /metrics", 13) == 0) {
		fprintf(stderr, "[INFO] http: HEAD /metrics from %s\n", peer_ip);
		send_response(client_fd, 200, "text/csv; charset=utf-8",
			      "", 0);
		return;
	}

	/* Only handle GET /metrics */
	if (strncmp(buf, "GET /metrics", 12) != 0) {
		fprintf(stderr, "[WARN] http: 404 from %s: %.40s\n",
			peer_ip, buf);
		const char *msg = "Not Found\n";
		send_response(client_fd, 404, "text/plain",
			      msg, (int)strlen(msg));
		return;
	}

	enum format_type fmt = parse_format(buf);

	if (fmt == FMT_PROM) {
		/* Prom: just read and return the snapshot file (no clearing) */
		int body_len = 0;
		char *body = read_prom_file(&body_len);

		if (body && body_len > 0) {
			send_response(client_fd, 200,
				"text/plain; version=0.0.4; charset=utf-8",
				body, body_len);
			fprintf(stderr, "[INFO] http: GET /metrics?format=prom "
				"from %s → %d bytes\n", peer_ip, body_len);
		} else {
			/* No snapshot yet */
			const char *empty = "# no data\n";
			send_response(client_fd, 200, "text/plain",
				      empty, (int)strlen(empty));
			fprintf(stderr, "[INFO] http: GET /metrics?format=prom "
				"from %s → no data\n", peer_ip);
		}
		free(body);
	} else {
		/* CSV: stream from event file directly to socket */
		fprintf(stderr, "[INFO] http: GET /metrics?format=csv "
			"from %s\n", peer_ip);
		handle_csv_stream(client_fd);
	}
}

/* ── server thread ───────────────────────────────────────────────── */

static void *server_thread(void *arg)
{
	(void)arg;

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while (g_running) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);

		int client_fd = accept(g_listen_fd,
				       (struct sockaddr *)&client_addr,
				       &addr_len);
		if (client_fd < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			if (!g_running)
				break;
			fprintf(stderr, "ERROR: http_server: accept: %s\n",
				strerror(errno));
			continue;
		}

		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
		setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
			   &tv, sizeof(tv));

		handle_request(client_fd, &client_addr);
		close(client_fd);
	}

	return NULL;
}

/* ── public API ──────────────────────────────────────────────────── */

int http_server_start(const struct http_config *cfg,
		      const char *prom_path)
{
	if (!cfg->enabled)
		return 0;

	snprintf(g_prom_path, sizeof(g_prom_path), "%s", prom_path);

	g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_fd < 0) {
		fprintf(stderr, "ERROR: http_server: socket: %s\n",
			strerror(errno));
		return -1;
	}

	int opt = 1;
	setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg->port);

	if (cfg->bind[0] && strcmp(cfg->bind, "0.0.0.0") != 0)
		inet_pton(AF_INET, cfg->bind, &addr.sin_addr);
	else
		addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "ERROR: http_server: bind(%s:%d): %s\n",
			cfg->bind[0] ? cfg->bind : "0.0.0.0",
			cfg->port, strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}

	if (listen(g_listen_fd, 5) < 0) {
		fprintf(stderr, "ERROR: http_server: listen: %s\n",
			strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}

	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(g_listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	g_running = 1;

	if (pthread_create(&g_thread, NULL, server_thread, NULL) != 0) {
		fprintf(stderr, "ERROR: http_server: pthread_create: %s\n",
			strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}

	fprintf(stderr, "INFO: http_server: listening on %s:%d\n",
		cfg->bind[0] ? cfg->bind : "0.0.0.0", cfg->port);
	return 0;
}

void http_server_stop(void)
{
	if (!g_running)
		return;

	g_running = 0;

	if (g_listen_fd >= 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
	}

	pthread_join(g_thread, NULL);
}
