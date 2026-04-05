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
	int         refresh_enabled;         /* 0 = событийная модель (по умолчанию), 1 = периодический /proc polling */
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

	/* ── Файлы (опции, не emit) ───────────────────────────── */
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
	int         disk_metrics;
	char        disk_include[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
	int         disk_include_count;
	char        disk_exclude[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
	int         disk_exclude_count;
	char        disk_fs_types[DISK_MAX_PREFIXES][DISK_FS_TYPE_LEN];
	int         disk_fs_types_count;

	/* ── Прочее (subsystem-level, без event_type) ───────────── */
	int         tcp_open_conns;

	/* ── Настройки перехвата syscall/tracepoint (0/1/2) ───── */
	/* Имя поля = имя перехватываемого syscall/tracepoint    */
	struct {
		/* process_event */
		enum event_ctl_mode sched_process_exec;
		enum event_ctl_mode sched_process_fork;
		enum event_ctl_mode sched_process_exit;
		enum event_ctl_mode mark_victim;
		enum event_ctl_mode sched_switch;
		enum event_ctl_mode signal_generate;
		enum event_ctl_mode sys_chdir;
		/* file_event */
		enum event_ctl_mode sys_openat;
		enum event_ctl_mode sys_close;
		enum event_ctl_mode sys_read;
		enum event_ctl_mode sys_pread64;
		enum event_ctl_mode sys_readv;
		enum event_ctl_mode sys_write;
		enum event_ctl_mode sys_pwrite64;
		enum event_ctl_mode sys_writev;
		enum event_ctl_mode sys_sendfile64;
		enum event_ctl_mode sys_fsync;
		enum event_ctl_mode sys_fdatasync;
		enum event_ctl_mode sys_socket;
		enum event_ctl_mode sys_rename;
		enum event_ctl_mode sys_unlink;
		enum event_ctl_mode sys_truncate;
		enum event_ctl_mode sys_fchmodat;
		enum event_ctl_mode sys_fchownat;
		/* net_event */
		enum event_ctl_mode inet_csk_listen_start;
		enum event_ctl_mode tcp_connect;
		enum event_ctl_mode inet_csk_accept;
		enum event_ctl_mode tcp_close;
		enum event_ctl_mode tcp_sendmsg;
		enum event_ctl_mode tcp_recvmsg;
		enum event_ctl_mode udp_sendmsg;
		enum event_ctl_mode udp_recvmsg;
		enum event_ctl_mode tcp_retransmit_skb;
		enum event_ctl_mode tcp_conn_request;
		enum event_ctl_mode tcp_send_reset;
		enum event_ctl_mode tcp_receive_reset;
		enum event_ctl_mode icmp_rcv;
		/* cgroup_event */
		enum event_ctl_mode cgroup_mkdir;
		enum event_ctl_mode cgroup_rmdir;
		enum event_ctl_mode cgroup_rename;
		enum event_ctl_mode cgroup_release;
		enum event_ctl_mode cgroup_attach_task;
		enum event_ctl_mode cgroup_transfer_tasks;
		enum event_ctl_mode cgroup_notify_populated;
		enum event_ctl_mode cgroup_notify_frozen;
		enum event_ctl_mode cgroup_freeze;
		enum event_ctl_mode cgroup_unfreeze;
	} syscall;
};

/* Глобальный экземпляр конфигурации */
extern struct pm_config cfg;

/* ── Config initialization and BPF program control ───────────────── */

struct process_metrics_bpf;

int  init_event_ctl(struct process_metrics_bpf *s);
void apply_event_ctl_disable(void);
int  compute_need_sock_map(void);

/* ── Config file loading ─────────────────────────────────────────── */

int load_config(const char *path);
int parse_rules_from_config(const char *path);
void free_rules(void);

/* ── Event emission checks (used by ring buffer callbacks) ───────── */

int event_emit_enabled(enum event_type type);
int should_emit_event(enum event_type type);

#endif /* PM_CONFIG_H */
