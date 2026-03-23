/*
 * http_server.h — embedded HTTP server for process_metrics
 *
 * Serves metrics via HTTP in two modes:
 *   GET /metrics?format=prom  — current snapshot (read from prom file, not cleared)
 *   GET /metrics?format=csv   — accumulated events (CSV, cleared after delivery)
 *   GET /metrics              — defaults to CSV
 */

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

struct http_config {
	int  port;           /* listen port (default: 9091) */
	char bind[64];       /* bind address (default: "0.0.0.0") */
	int  enabled;        /* 0 = disabled */
};

/*
 * Start the HTTP server in a background thread.
 * prom_path: path to the .prom snapshot file (written by write_snapshot)
 * metric_prefix: unused for now (prom content comes from file)
 * Returns 0 on success, -1 on error.
 */
int http_server_start(const struct http_config *cfg,
		      const char *prom_path);

/*
 * Stop the HTTP server and join the thread.
 */
void http_server_stop(void);

#endif /* HTTP_SERVER_H */
