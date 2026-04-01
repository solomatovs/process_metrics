/*
 * pm_config.h — структура конфигурации process_metrics.
 *
 * Все настройки из файла конфигурации собраны в одну структуру.
 * Глобальный экземпляр: extern struct pm_config cfg;
 */

#ifndef PM_CONFIG_H
#define PM_CONFIG_H

#include "process_metrics_common.h"
#include "http_server.h"

struct pm_config {
	/* ── Основные параметры ───────────────────────────────── */
	const char *config_file;
	char        hostname[EF_HOSTNAME_LEN];
	int         snapshot_interval;      /* секунды между snapshot */
	int         refresh_interval;       /* секунды между refresh (0 = snapshot_interval) */
	int         exec_rate_limit;        /* макс exec/сек (0 = без ограничений) */
	int         cgroup_metrics;         /* 1 = читать файлы cgroup */
	int         refresh_enabled;         /* 1 = вызывать refresh_processes (по умолчанию включён) */
	int         refresh_proc;           /* 1 = обновлять cmdline/comm из /proc */
	int         max_cgroups;            /* макс записей в cgroup cache */

	/* ── Логирование ──────────────────────────────────────── */
	int         log_level;              /* 0=error, 1=info, 2=debug */
	int         heartbeat_interval;     /* секунды (0 = отключить) */
	int         log_snapshot;           /* логировать snapshot строки */
	int         log_refresh;            /* логировать refresh строки */

	/* ── HTTP ─────────────────────────────────────────────── */
	struct http_config http;
	long long   max_data_size;          /* ring buffer для event_file */

	/* ── Ring buffers (BPF) ───────────────────────────────── */
	long long   ringbuf_proc;
	long long   ringbuf_file;
	long long   ringbuf_file_ops;
	long long   ringbuf_net;
	long long   ringbuf_sec;
	long long   ringbuf_cgroup;

	/* ── Сеть ─────────────────────────────────────────────── */
	int         net_tracking_enabled;
	int         net_track_bytes;
	int         need_sock_map;          /* net_tracking || TCP-security */

	/* ── Файлы ────────────────────────────────────────────── */
	int         file_tracking_enabled;
	int         file_track_bytes;
	int         file_absolute_paths_only;
	struct file_prefix file_include[FILE_MAX_PREFIXES];
	int         file_include_count;
	struct file_prefix file_exclude[FILE_MAX_PREFIXES];
	int         file_exclude_count;

	/* ── Docker ───────────────────────────────────────────── */
	int         docker_resolve_names;
	char        docker_data_root[PATH_MAX_LEN];
	char        docker_daemon_json[PATH_MAX_LEN];

	/* ── Диск ─────────────────────────────────────────────── */
	int         disk_tracking_enabled;
	char        disk_include[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
	int         disk_include_count;
	char        disk_exclude[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
	int         disk_exclude_count;
	char        disk_fs_types[DISK_MAX_PREFIXES][DISK_FS_TYPE_LEN];
	int         disk_fs_types_count;

	/* ── Security probes ──────────────────────────────────── */
	int         tcp_retransmit;
	int         tcp_syn;
	int         tcp_rst;
	int         icmp_tracking;
	int         tcp_open_conns;

	/* ── Emit flags (какие события отправлять в CSV) ──────── */
	struct {
		int exec;
		int fork;
		int exit;
		int oom_kill;
		int signal;
		int chdir;
		int file_open;
		int file_close;
		int file_rename;
		int file_unlink;
		int file_truncate;
		int file_chmod;
		int file_chown;
		int net_listen;
		int net_connect;
		int net_accept;
		int net_close;
		int tcp_retransmit;
		int syn_recv;
		int rst;
		int cgroup;
	} emit;
};

/* Глобальный экземпляр конфигурации */
extern struct pm_config cfg;

#endif /* PM_CONFIG_H */
