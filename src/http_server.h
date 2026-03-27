/*
 * http_server.h — embedded HTTP server for process_metrics
 *
 * Serves metrics via HTTP (CSV format for ClickHouse):
 *   GET /metrics                     — accumulated events as CSV (read-only)
 *   GET /metrics?format=csv         — same as above (explicit format)
 *   GET /metrics?format=csv&clear=1 — returns CSV and clears buffer after delivery
 */

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <linux/types.h>

struct http_config {
	int  port;           /* listen port (default: 9091) */
	char bind[64];       /* bind address (default: "0.0.0.0") */
	int  enabled;        /* 0 = disabled */
};

/*
 * Resolve cgroup path for display.
 * If docker resolve is enabled and cgroup contains docker-<hash>.scope,
 * replaces it with docker/<container_name>.
 * buf must be at least EV_CGROUP_LEN bytes.
 */
void http_resolve_cgroup(const char *raw, char *buf, int buflen);

/*
 * Resolve UID to username from /etc/passwd (cached).
 * If not found, buf is set to empty string.
 */
void http_resolve_uid(__u32 uid, char *buf, int buflen);

/*
 * Start the HTTP server in a background thread.
 * Returns 0 on success, -1 on error.
 */
int http_server_start(const struct http_config *cfg);

/*
 * Stop the HTTP server and join the thread.
 */
void http_server_stop(void);

#endif /* HTTP_SERVER_H */
