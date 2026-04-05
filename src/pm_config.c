/*
 * pm_config.c — конфигурация и event_ctl инфраструктура process_metrics.
 *
 * Содержит:
 *   - таблицу управления BPF-событиями (event_ctl)
 *   - глобальный экземпляр конфигурации cfg
 *   - парсер конфигурационного файла (libconfig)
 *   - определения rules[], num_rules, g_need_sock_map
 *   - event_emit_enabled(), should_emit_event()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <regex.h>
#include <arpa/inet.h>
#include <libconfig.h>
#include <bpf/libbpf.h>
#include "process_metrics_common.h"
#include "event_file.h"
#include "process_metrics.skel.h"
#include "pm_config.h"
#include "pm_state.h"
#include "log.h"

/*
 * BPF_PROG_DISABLE: полностью отключает BPF-программу (не загружать,
 * не подключать). Используем set_autoload(false), а не set_autoattach(false),
 * потому что set_autoattach всё равно загружает программу в ядро (верификатор,
 * создание prog fd) — и при destroy close(fd) вызывает synchronize_rcu,
 * что добавляет ~0.15с на каждую программу к времени завершения.
 * set_autoload полностью пропускает программу — нет fd, нет задержки.
 */
#define BPF_PROG_DISABLE(prog) bpf_program__set_autoload((prog), false)

/* ── Единая таблица управления pipeline событий ──────────────────── */

#define EVENT_CTL_MAX_PROGS 4
#define EVENT_CTL_TABLE_SIZE 64

struct event_ctl {
	const char *name;            /* имя syscall/tracepoint, совпадает с ключом в конфиге */
	enum event_ctl_mode *mode;   /* указатель на cfg.syscall.xxx — текущий уровень активации */
	enum event_ctl_mode min_mode; /* нижняя граница: конфиг не может задать меньше */
	int prog_count;              /* сколько BPF-программ управляется этой записью */
	struct bpf_program *progs[EVENT_CTL_MAX_PROGS]; /* программы для BPF_PROG_DISABLE при mode=0 */
	int type_count;              /* сколько event_type генерирует этот syscall */
	enum event_type types[EVENT_CTL_MAX_PROGS];     /* типы событий для should_emit_event() lookup */
};

static struct event_ctl event_ctl_table[EVENT_CTL_TABLE_SIZE];
static int event_ctl_count;

/* Быстрый lookup: event_type → max mode across all producers */
static enum event_ctl_mode mode_max_by_type[EVENT_TYPE_MAX];

/*
 * init_event_ctl — заполнение таблицы после bpf__open(), до load.
 */
int init_event_ctl(struct process_metrics_bpf *s)
{
	int n = 0;

#define CTL_BEGIN(nm, flag, min) do {                            \
	if (n >= EVENT_CTL_TABLE_SIZE) { return -1; }            \
	struct event_ctl *e = &event_ctl_table[n]; \
	e->name = (nm);                            \
	e->mode = (flag);                          \
	e->min_mode = (min);                       \
	e->prog_count = 0;                         \
	e->type_count = 0;

#define CTL_PROG(p) e->progs[e->prog_count++] = (p);
#define CTL_TYPE(t) e->types[e->type_count++] = (t);
#define CTL_END()   n++; } while (0);

	/* ── process_event (min = BPF_EVENT_ENABLE: нужны для учёта процессов) ── */
	CTL_BEGIN("sched_process_exec", &cfg.syscall.sched_process_exec, EVENT_CTL_BPF_EVENT_ENABLE)
	CTL_TYPE(EVENT_EXEC)
	CTL_END()

	CTL_BEGIN("sched_process_fork", &cfg.syscall.sched_process_fork, EVENT_CTL_BPF_EVENT_ENABLE)
	CTL_TYPE(EVENT_FORK)
	CTL_END()

	CTL_BEGIN("sched_process_exit", &cfg.syscall.sched_process_exit, EVENT_CTL_BPF_EVENT_ENABLE)
	CTL_TYPE(EVENT_EXIT)
	CTL_END()

	CTL_BEGIN("mark_victim",        &cfg.syscall.mark_victim,        EVENT_CTL_BPF_EVENT_ENABLE)
	CTL_TYPE(EVENT_OOM_KILL)
	CTL_END()

	CTL_BEGIN("sched_switch",       &cfg.syscall.sched_switch,       EVENT_CTL_BPF_EVENT_ENABLE)
	CTL_PROG(s->progs.handle_sched_switch)
	CTL_END()

	CTL_BEGIN("signal_generate",    &cfg.syscall.signal_generate,    EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_signal_generate)
	CTL_TYPE(EVENT_SIGNAL)
	CTL_END()

	CTL_BEGIN("sys_chdir",          &cfg.syscall.sys_chdir,          EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_sys_exit_chdir)
	CTL_PROG(s->progs.handle_sys_exit_fchdir)
	CTL_TYPE(EVENT_CHDIR)
	CTL_END()

	/* ── file_event ─────────────────────────────────────────── */
	CTL_BEGIN("sys_openat",    &cfg.syscall.sys_openat,    EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_openat_enter)
	CTL_PROG(s->progs.handle_openat_exit)
	CTL_TYPE(EVENT_FILE_OPEN)
	CTL_END()

	CTL_BEGIN("sys_close",     &cfg.syscall.sys_close,     EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_close_enter)
	CTL_TYPE(EVENT_FILE_CLOSE)
	CTL_END()

	CTL_BEGIN("sys_read",      &cfg.syscall.sys_read,      EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_read_enter)
	CTL_PROG(s->progs.handle_read_exit)
	CTL_END()

	CTL_BEGIN("sys_pread64",   &cfg.syscall.sys_pread64,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_pread_enter)
	CTL_PROG(s->progs.handle_pread_exit)
	CTL_END()

	CTL_BEGIN("sys_readv",     &cfg.syscall.sys_readv,     EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_readv_enter)
	CTL_PROG(s->progs.handle_readv_exit)
	CTL_END()

	CTL_BEGIN("sys_write",     &cfg.syscall.sys_write,     EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_write_enter)
	CTL_PROG(s->progs.handle_write_exit)
	CTL_END()

	CTL_BEGIN("sys_pwrite64",  &cfg.syscall.sys_pwrite64,  EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_pwrite_enter)
	CTL_PROG(s->progs.handle_pwrite_exit)
	CTL_END()

	CTL_BEGIN("sys_writev",    &cfg.syscall.sys_writev,    EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_writev_enter)
	CTL_PROG(s->progs.handle_writev_exit)
	CTL_END()

	CTL_BEGIN("sys_sendfile64", &cfg.syscall.sys_sendfile64, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_sendfile_enter)
	CTL_PROG(s->progs.handle_sendfile_exit)
	CTL_END()

	CTL_BEGIN("sys_fsync",     &cfg.syscall.sys_fsync,     EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_fsync_enter)
	CTL_END()

	CTL_BEGIN("sys_fdatasync", &cfg.syscall.sys_fdatasync, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_fdatasync_enter)
	CTL_END()

	CTL_BEGIN("sys_socket",    &cfg.syscall.sys_socket,    EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_socket_enter)
	CTL_END()

	CTL_BEGIN("sys_rename",    &cfg.syscall.sys_rename,    EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_rename)
	CTL_PROG(s->progs.handle_renameat2)
	CTL_TYPE(EVENT_FILE_RENAME)
	CTL_END()

	CTL_BEGIN("sys_unlink",    &cfg.syscall.sys_unlink,    EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_unlink)
	CTL_PROG(s->progs.handle_unlinkat)
	CTL_TYPE(EVENT_FILE_UNLINK)
	CTL_END()

	CTL_BEGIN("sys_truncate",  &cfg.syscall.sys_truncate,  EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_truncate)
	CTL_PROG(s->progs.handle_ftruncate)
	CTL_TYPE(EVENT_FILE_TRUNCATE)
	CTL_END()

	CTL_BEGIN("sys_fchmodat",  &cfg.syscall.sys_fchmodat,  EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_fchmodat_enter)
	CTL_TYPE(EVENT_FILE_CHMOD)
	CTL_END()

	CTL_BEGIN("sys_fchownat",  &cfg.syscall.sys_fchownat,  EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_fchownat_enter)
	CTL_TYPE(EVENT_FILE_CHOWN)
	CTL_END()

	/* ── net_event ──────────────────────────────────────────── */
	CTL_BEGIN("inet_csk_listen_start", &cfg.syscall.inet_csk_listen_start, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_inet_csk_listen_start)
	CTL_TYPE(EVENT_NET_LISTEN)
	CTL_END()

	CTL_BEGIN("tcp_connect",   &cfg.syscall.tcp_connect,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_tcp_v4_connect)
	CTL_PROG(s->progs.krp_tcp_v4_connect)
	CTL_PROG(s->progs.kp_tcp_v6_connect)
	CTL_PROG(s->progs.krp_tcp_v6_connect)
	CTL_TYPE(EVENT_NET_CONNECT)
	CTL_END()

	CTL_BEGIN("inet_csk_accept", &cfg.syscall.inet_csk_accept, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.krp_inet_csk_accept)
	CTL_TYPE(EVENT_NET_ACCEPT)
	CTL_END()

	CTL_BEGIN("tcp_close",     &cfg.syscall.tcp_close,     EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_tcp_close)
	CTL_PROG(s->progs.kretp_tcp_close)
	CTL_TYPE(EVENT_NET_CLOSE)
	CTL_END()

	CTL_BEGIN("tcp_sendmsg",   &cfg.syscall.tcp_sendmsg,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_tcp_sendmsg)
	CTL_PROG(s->progs.ret_tcp_sendmsg)
	CTL_END()

	CTL_BEGIN("tcp_recvmsg",   &cfg.syscall.tcp_recvmsg,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_tcp_recvmsg)
	CTL_PROG(s->progs.ret_tcp_recvmsg)
	CTL_END()

	CTL_BEGIN("udp_sendmsg",   &cfg.syscall.udp_sendmsg,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_udp_sendmsg)
	CTL_PROG(s->progs.ret_udp_sendmsg)
	CTL_END()

	CTL_BEGIN("udp_recvmsg",   &cfg.syscall.udp_recvmsg,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_udp_recvmsg)
	CTL_PROG(s->progs.ret_udp_recvmsg)
	CTL_END()

	CTL_BEGIN("tcp_retransmit_skb", &cfg.syscall.tcp_retransmit_skb, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_tcp_retransmit)
	CTL_TYPE(EVENT_TCP_RETRANSMIT)
	CTL_END()

	CTL_BEGIN("tcp_conn_request", &cfg.syscall.tcp_conn_request, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_tcp_conn_request)
	CTL_TYPE(EVENT_SYN_RECV)
	CTL_END()

	CTL_BEGIN("tcp_send_reset", &cfg.syscall.tcp_send_reset, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_tcp_send_reset)
	CTL_PROG(s->progs.kp_tcp_send_active_reset)
	CTL_TYPE(EVENT_RST)
	CTL_END()

	CTL_BEGIN("tcp_receive_reset", &cfg.syscall.tcp_receive_reset, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_tcp_receive_reset)
	CTL_TYPE(EVENT_RST)
	CTL_END()

	CTL_BEGIN("icmp_rcv",      &cfg.syscall.icmp_rcv,      EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.kp_icmp_rcv)
	CTL_END()

	/* ── cgroup_event ───────────────────────────────────────── */
	CTL_BEGIN("cgroup_mkdir",   &cfg.syscall.cgroup_mkdir,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_mkdir)
	CTL_TYPE(EVENT_CGROUP_MKDIR)
	CTL_END()

	CTL_BEGIN("cgroup_rmdir",   &cfg.syscall.cgroup_rmdir,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_rmdir)
	CTL_TYPE(EVENT_CGROUP_RMDIR)
	CTL_END()

	CTL_BEGIN("cgroup_rename",  &cfg.syscall.cgroup_rename,  EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_rename)
	CTL_TYPE(EVENT_CGROUP_RENAME)
	CTL_END()

	CTL_BEGIN("cgroup_release", &cfg.syscall.cgroup_release, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_release)
	CTL_TYPE(EVENT_CGROUP_RELEASE)
	CTL_END()

	CTL_BEGIN("cgroup_attach_task", &cfg.syscall.cgroup_attach_task, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_attach_task)
	CTL_TYPE(EVENT_CGROUP_ATTACH_TASK)
	CTL_END()

	CTL_BEGIN("cgroup_transfer_tasks", &cfg.syscall.cgroup_transfer_tasks, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_transfer_tasks)
	CTL_TYPE(EVENT_CGROUP_TRANSFER_TASKS)
	CTL_END()

	CTL_BEGIN("cgroup_notify_populated", &cfg.syscall.cgroup_notify_populated, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_populated)
	CTL_TYPE(EVENT_CGROUP_POPULATED)
	CTL_END()

	CTL_BEGIN("cgroup_notify_frozen", &cfg.syscall.cgroup_notify_frozen, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_frozen)
	CTL_TYPE(EVENT_CGROUP_FROZEN)
	CTL_END()

	/* kernel compat: по умолчанию отключены (default=0), layout может отличаться */
	CTL_BEGIN("cgroup_freeze",   &cfg.syscall.cgroup_freeze,   EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_freeze)
	CTL_TYPE(EVENT_CGROUP_FREEZE)
	CTL_END()

	CTL_BEGIN("cgroup_unfreeze", &cfg.syscall.cgroup_unfreeze, EVENT_CTL_BPF_ENABLE)
	CTL_PROG(s->progs.handle_cgroup_unfreeze)
	CTL_TYPE(EVENT_CGROUP_UNFREEZE)
	CTL_END()

#undef CTL_BEGIN
#undef CTL_PROG
#undef CTL_TYPE
#undef CTL_END

	event_ctl_count = n;

	/* Валидация min_mode: проверяем, что пользователь не занизил уровень */
	for (int i = 0; i < event_ctl_count; i++) {
		struct event_ctl *entry = &event_ctl_table[i];
		if (*entry->mode < entry->min_mode) {
			LOG_FATAL("emit_%s = %d is below minimum %d "
				  "(this event is required for process tracking)",
				  entry->name, *entry->mode, entry->min_mode);
			return -1;
		}
	}

	/* Заполняем быстрый lookup event_type → max mode across all producers */
	memset(mode_max_by_type, 0, sizeof(mode_max_by_type));
	for (int i = 0; i < event_ctl_count; i++) {
		struct event_ctl *entry = &event_ctl_table[i];
		for (int j = 0; j < entry->type_count; j++) {
			int t = entry->types[j];
			if (t >= 0 && t < EVENT_TYPE_MAX &&
			    *entry->mode > mode_max_by_type[t])
				mode_max_by_type[t] = *entry->mode;
		}
	}
	return 0;
}

/*
 * apply_event_ctl_disable — отключает BPF-программы для событий
 * в режиме bpf_enable, у которых есть программы для отключения.
 * Вызывается после init_event_ctl(), до bpf__load().
 */
void apply_event_ctl_disable(void)
{
	for (int i = 0; i < event_ctl_count; i++) {
		struct event_ctl *e = &event_ctl_table[i];
		if (*e->mode > EVENT_CTL_BPF_ENABLE || e->prog_count == 0)
			continue;
		for (int j = 0; j < e->prog_count; j++)
			BPF_PROG_DISABLE(e->progs[j]);
	}
}

/*
 * compute_need_sock_map — проверяет, нужна ли инфраструктура sock_map.
 * Возвращает 1, если любой net/security emit-флаг > BPF_ENABLE
 * или включён tcp_open_conns.
 */
int compute_need_sock_map(void)
{
	static const char *net_names[] = {
		"tcp_connect", "inet_csk_accept", "inet_csk_listen_start",
		"tcp_close", "tcp_sendmsg", "tcp_recvmsg",
		"udp_sendmsg", "udp_recvmsg", "tcp_retransmit_skb",
		"tcp_conn_request", "tcp_send_reset", "tcp_receive_reset",
		"sys_socket", NULL
	};
	for (int i = 0; i < event_ctl_count; i++) {
		for (const char **p = net_names; *p; p++) {
			if (strcmp(event_ctl_table[i].name, *p) == 0 &&
			    *event_ctl_table[i].mode > EVENT_CTL_BPF_ENABLE)
				return 1;
		}
	}
	return cfg.tcp_open_conns;
}

/* ── конфигурация ─────────────────────────────────────────────────── */

/* rule, num_rules — определены здесь, объявлены в pm_state.h */
struct rule rules[MAX_RULES];
int num_rules;

int g_need_sock_map; /* вычисляется из event_ctl_table в main */

struct pm_config cfg = {
    .snapshot_interval = 30,
    .refresh_interval = 0,
    .cgroup_metrics = 1,
    .refresh_enabled = 0,
    .refresh_proc = 1,
    .log_level = 1,
    .heartbeat_interval = 30,
    .log_snapshot = 1,
    .log_refresh = 1,
    .max_data_size = (long long)EF_DEFAULT_SIZE_BYTES,
    .file_absolute_paths_only = 1,
    .disk_metrics = 1,
    .max_cgroups = MAX_CGROUPS,
    .syscall =
	{
	    /* process_event */
	    .sched_process_exec = EVENT_CTL_EVENT_ENABLE,
	    .sched_process_fork = EVENT_CTL_EVENT_ENABLE,
	    .sched_process_exit = EVENT_CTL_EVENT_ENABLE,
	    .mark_victim = EVENT_CTL_EVENT_ENABLE,
	    .sched_switch = EVENT_CTL_EVENT_ENABLE,
	    .signal_generate = EVENT_CTL_EVENT_ENABLE,
	    .sys_chdir = EVENT_CTL_EVENT_ENABLE,
	    /* file_event */
	    .sys_openat = EVENT_CTL_EVENT_ENABLE,
	    .sys_close = EVENT_CTL_EVENT_ENABLE,
	    .sys_read = EVENT_CTL_EVENT_ENABLE,
	    .sys_pread64 = EVENT_CTL_EVENT_ENABLE,
	    .sys_readv = EVENT_CTL_EVENT_ENABLE,
	    .sys_write = EVENT_CTL_EVENT_ENABLE,
	    .sys_pwrite64 = EVENT_CTL_EVENT_ENABLE,
	    .sys_writev = EVENT_CTL_EVENT_ENABLE,
	    .sys_sendfile64 = EVENT_CTL_EVENT_ENABLE,
	    .sys_fsync = EVENT_CTL_EVENT_ENABLE,
	    .sys_fdatasync = EVENT_CTL_EVENT_ENABLE,
	    .sys_socket = EVENT_CTL_EVENT_ENABLE,
	    .sys_rename = EVENT_CTL_EVENT_ENABLE,
	    .sys_unlink = EVENT_CTL_EVENT_ENABLE,
	    .sys_truncate = EVENT_CTL_EVENT_ENABLE,
	    .sys_fchmodat = EVENT_CTL_EVENT_ENABLE,
	    .sys_fchownat = EVENT_CTL_EVENT_ENABLE,
	    /* net_event */
	    .inet_csk_listen_start = EVENT_CTL_EVENT_ENABLE,
	    .tcp_connect = EVENT_CTL_EVENT_ENABLE,
	    .inet_csk_accept = EVENT_CTL_EVENT_ENABLE,
	    .tcp_close = EVENT_CTL_EVENT_ENABLE,
	    .tcp_sendmsg = EVENT_CTL_EVENT_ENABLE,
	    .tcp_recvmsg = EVENT_CTL_EVENT_ENABLE,
	    .udp_sendmsg = EVENT_CTL_EVENT_ENABLE,
	    .udp_recvmsg = EVENT_CTL_EVENT_ENABLE,
	    .tcp_retransmit_skb = EVENT_CTL_EVENT_ENABLE,
	    .tcp_conn_request = EVENT_CTL_EVENT_ENABLE,
	    .tcp_send_reset = EVENT_CTL_EVENT_ENABLE,
	    .tcp_receive_reset = EVENT_CTL_EVENT_ENABLE,
	    .icmp_rcv = EVENT_CTL_EVENT_ENABLE,
	    /* cgroup_event */
	    .cgroup_mkdir = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_rmdir = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_rename = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_release = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_attach_task = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_transfer_tasks = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_notify_populated = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_notify_frozen = EVENT_CTL_EVENT_ENABLE,
	    .cgroup_freeze = EVENT_CTL_BPF_ENABLE,
	    .cgroup_unfreeze = EVENT_CTL_BPF_ENABLE,
	},
};

/* ── event emission checks ───────────────────────────────────────── */

/*
 * event_emit_enabled — проверяет, разрешён ли emit для данного типа события.
 * Источник истины: mode_max_by_type[], заполняется из event_ctl_table
 * в init_event_ctl(). Если несколько producers генерируют один event_type,
 * берётся максимальный mode.
 */
int event_emit_enabled(enum event_type type)
{
	if ((__u32)type >= EVENT_TYPE_MAX)
		return 0;
	return mode_max_by_type[type] >= EVENT_CTL_EVENT_ENABLE;
}

/*
 * Проверяет, нужно ли формировать metric_event и отправлять в CSV.
 * Объединяет: тип разрешён в конфиге + HTTP-сервер включён.
 */
int should_emit_event(enum event_type type)
{
	return cfg.http.enabled && event_emit_enabled(type);
}

/* ── парсер правил (из libconfig) ─────────────────────────────────── */

void free_rules(void)
{
	for (int i = 0; i < num_rules; i++)
		regfree(&rules[i].regex);
	num_rules = 0;
}

int parse_rules_from_config(const char *path)
{
	config_t lc;
	config_init(&lc);

	if (!config_read_file(&lc, path)) {
		LOG_FATAL("%s:%d - %s", config_error_file(&lc) ? config_error_file(&lc) : path,
			  config_error_line(&lc), config_error_text(&lc));
		config_destroy(&lc);
		return -1;
	}

	config_setting_t *rs = config_lookup(&lc, "rules");
	if (!rs || !config_setting_is_list(rs)) {
		LOG_FATAL("'rules' list not found in %s", path);
		config_destroy(&lc);
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
			LOG_WARN("rules[%d]: missing 'name' or 'regex'", i);
			continue;
		}

		if (regcomp(&rules[num_rules].regex, regex, REG_EXTENDED | REG_NOSUB) != 0) {
			LOG_WARN("rules[%d]: bad regex: %s", i, regex);
			continue;
		}
		snprintf(rules[num_rules].name, sizeof(rules[0].name), "%s", name);

		int ignore_val = 0;
		config_setting_lookup_bool(entry, "ignore", &ignore_val);
		rules[num_rules].ignore = ignore_val;

		num_rules++;
	}

	config_destroy(&lc);
	LOG_INFO("loaded %d rules from %s", num_rules, path);
	return num_rules;
}

/*
 * cfg_lookup_emit — чтение event_ctl_mode (int 0/1/2) из libconfig.
 * Значения: 0 = bpf_enable, 1 = bpf_event_enable, 2 = event_enable.
 */
static int cfg_lookup_emit(config_setting_t *parent, const char *name,
			   enum event_ctl_mode *out)
{
	int v;
	if (!config_setting_lookup_int(parent, name, &v))
		return 0;
	if (v < EVENT_CTL_BPF_ENABLE || v > EVENT_CTL_EVENT_ENABLE) {
		LOG_FATAL("invalid emit value for '%s': %d (expected 0, 1 or 2)", name, v);
		return -1;
	}
	*out = (enum event_ctl_mode)v;
	return 1;
}

/* Макрос для вызова cfg_lookup_emit с проверкой ошибки */
#define CFG_EMIT(parent, name, field) do {                         \
	if (cfg_lookup_emit((parent), (name), &(field)) < 0) {    \
		config_destroy(&lc);                               \
		return -1;                                         \
	}                                                          \
} while (0)

/* ── загрузчик конфигурации libconfig ─────────────────────────────── */

int load_config(const char *path)
{
	config_t lc;
	config_init(&lc);

	if (!config_read_file(&lc, path)) {
		LOG_FATAL("%s:%d - %s", config_error_file(&lc) ? config_error_file(&lc) : path,
			  config_error_line(&lc), config_error_text(&lc));
		config_destroy(&lc);
		return -1;
	}

	const char *str_val;
	int int_val;

	/* Общие настройки */
	if (config_lookup_string(&lc, "hostname", &str_val))
		snprintf(cfg.hostname, sizeof(cfg.hostname), "%s", str_val);
	if (!cfg.hostname[0])
		gethostname(cfg.hostname, sizeof(cfg.hostname));
	if (config_lookup_int(&lc, "snapshot_interval", &int_val))
		cfg.snapshot_interval = int_val;
	if (config_lookup_int(&lc, "refresh_interval", &int_val))
		cfg.refresh_interval = int_val;

	/* refresh_interval: если не задан — берётся snapshot_interval;
	 * если больше snapshot_interval — приравнивается */
	if (cfg.refresh_interval <= 0)
		cfg.refresh_interval = cfg.snapshot_interval;
	if (cfg.refresh_interval > cfg.snapshot_interval)
		cfg.refresh_interval = cfg.snapshot_interval;

	if (config_lookup_int(&lc, "exec_rate_limit", &int_val))
		cfg.exec_rate_limit = int_val;

	int bool_val;
	if (config_lookup_bool(&lc, "cgroup_metrics", &bool_val))
		cfg.cgroup_metrics = bool_val;
	if (config_lookup_bool(&lc, "refresh_enabled", &bool_val))
		cfg.refresh_enabled = bool_val;
	if (config_lookup_bool(&lc, "refresh_proc", &bool_val))
		cfg.refresh_proc = bool_val;
	if (config_lookup_int(&lc, "log_level", &int_val))
		cfg.log_level = int_val;
	if (config_lookup_int(&lc, "max_cgroups", &int_val) && int_val > 0)
		cfg.max_cgroups = int_val;
	if (config_lookup_int(&lc, "heartbeat_interval", &int_val))
		cfg.heartbeat_interval = int_val;
	if (config_lookup_bool(&lc, "log_snapshot", &bool_val))
		cfg.log_snapshot = bool_val;
	if (config_lookup_bool(&lc, "log_refresh", &bool_val))
		cfg.log_refresh = bool_val;

	/* Настройки HTTP-сервера (включается при наличии секции с портом) */
	memset(&cfg.http, 0, sizeof(cfg.http));
	cfg.http.port = HTTP_DEFAULT_PORT;
	cfg.http.max_connections = HTTP_DEFAULT_MAX_CONNS;
	cfg.http.log_requests = 1;
	snprintf(cfg.http.bind, sizeof(cfg.http.bind), HTTP_DEFAULT_BIND);

	config_setting_t *hs = config_lookup(&lc, "http_server");
	if (hs) {
		if (config_setting_lookup_int(hs, "port", &int_val)) {
			cfg.http.port = int_val;
			cfg.http.enabled = 1;
		}
		if (config_setting_lookup_string(hs, "bind", &str_val))
			snprintf(cfg.http.bind, sizeof(cfg.http.bind), "%s", str_val);
		if (config_setting_lookup_int(hs, "max_connections", &int_val))
			cfg.http.max_connections = int_val;
		if (config_setting_lookup_bool(hs, "log_requests", &bool_val))
			cfg.http.log_requests = bool_val;

		/* allow = ("10.0.0.0/8", "192.168.1.0/24", "127.0.0.1"); */
		config_setting_t *allow = config_setting_get_member(hs, "allow");
		if (allow) {
			int cnt = config_setting_length(allow);
			if (cnt > HTTP_MAX_ALLOW) {
				LOG_WARN("http_server: allow list truncated to %d entries",
					 HTTP_MAX_ALLOW);
				cnt = HTTP_MAX_ALLOW;
			}
			for (int i = 0; i < cnt; i++) {
				const char *cidr = config_setting_get_string_elem(allow, i);
				if (!cidr)
					continue;

				char ip_buf[64];
				snprintf(ip_buf, sizeof(ip_buf), "%s", cidr);

				int prefix = 32;
				char *slash = strchr(ip_buf, '/');
				if (slash) {
					*slash = '\0';
					prefix = atoi(slash + 1);
					if (prefix < 0 || prefix > 32) {
						LOG_ERROR("http_server: invalid prefix /%d in '%s'",
							  prefix, cidr);
						config_destroy(&lc);
						return 1;
					}
				}

				struct in_addr parsed;
				if (inet_pton(AF_INET, ip_buf, &parsed) != 1) {
					LOG_ERROR("http_server: invalid IP in '%s'", cidr);
					config_destroy(&lc);
					return 1;
				}

				in_addr_t mask =
				    (prefix == 0) ? 0 : htonl(~((1U << (32 - prefix)) - 1));
				cfg.http.allow[cfg.http.allow_count].mask = ntohl(mask);
				cfg.http.allow[cfg.http.allow_count].network =
				    ntohl(parsed.s_addr) & ntohl(mask);
				cfg.http.allow_count++;
			}
		}

		long long ll_val;
		if (config_setting_lookup_int64(hs, "max_buffer_size", &ll_val))
			cfg.max_data_size = ll_val;
	}

	/* Настройки сетевых событий */
	config_setting_t *nt = config_lookup(&lc, "net_event");
	if (nt) {
		if (config_setting_lookup_bool(nt, "tcp_open_conns", &bool_val))
			cfg.tcp_open_conns = bool_val;

		CFG_EMIT(nt, "inet_csk_listen_start", cfg.syscall.inet_csk_listen_start);
		CFG_EMIT(nt, "tcp_connect", cfg.syscall.tcp_connect);
		CFG_EMIT(nt, "inet_csk_accept", cfg.syscall.inet_csk_accept);
		CFG_EMIT(nt, "tcp_close", cfg.syscall.tcp_close);
		CFG_EMIT(nt, "tcp_sendmsg", cfg.syscall.tcp_sendmsg);
		CFG_EMIT(nt, "tcp_recvmsg", cfg.syscall.tcp_recvmsg);
		CFG_EMIT(nt, "udp_sendmsg", cfg.syscall.udp_sendmsg);
		CFG_EMIT(nt, "udp_recvmsg", cfg.syscall.udp_recvmsg);
		CFG_EMIT(nt, "tcp_retransmit_skb", cfg.syscall.tcp_retransmit_skb);
		CFG_EMIT(nt, "tcp_conn_request", cfg.syscall.tcp_conn_request);
		CFG_EMIT(nt, "tcp_send_reset", cfg.syscall.tcp_send_reset);
		CFG_EMIT(nt, "tcp_receive_reset", cfg.syscall.tcp_receive_reset);
		CFG_EMIT(nt, "icmp_rcv", cfg.syscall.icmp_rcv);
		CFG_EMIT(nt, "sys_socket", cfg.syscall.sys_socket);

		long long ll_val;
		if (config_setting_lookup_int64(nt, "ring_buffer_size", &ll_val))
			cfg.ringbuf_net = ll_val;
		if (config_setting_lookup_int64(nt, "ring_buffer_sec_size", &ll_val))
			cfg.ringbuf_sec = ll_val;
	}

	/* Настройки отслеживания файлов */
	config_setting_t *ft = config_lookup(&lc, "file_event");
	if (ft) {
		if (config_setting_lookup_bool(ft, "absolute_paths_only", &bool_val))
			cfg.file_absolute_paths_only = bool_val;

		CFG_EMIT(ft, "sys_openat", cfg.syscall.sys_openat);
		CFG_EMIT(ft, "sys_close", cfg.syscall.sys_close);
		CFG_EMIT(ft, "sys_read", cfg.syscall.sys_read);
		CFG_EMIT(ft, "sys_pread64", cfg.syscall.sys_pread64);
		CFG_EMIT(ft, "sys_readv", cfg.syscall.sys_readv);
		CFG_EMIT(ft, "sys_write", cfg.syscall.sys_write);
		CFG_EMIT(ft, "sys_pwrite64", cfg.syscall.sys_pwrite64);
		CFG_EMIT(ft, "sys_writev", cfg.syscall.sys_writev);
		CFG_EMIT(ft, "sys_sendfile64", cfg.syscall.sys_sendfile64);
		CFG_EMIT(ft, "sys_fsync", cfg.syscall.sys_fsync);
		CFG_EMIT(ft, "sys_fdatasync", cfg.syscall.sys_fdatasync);
		CFG_EMIT(ft, "sys_rename", cfg.syscall.sys_rename);
		CFG_EMIT(ft, "sys_unlink", cfg.syscall.sys_unlink);
		CFG_EMIT(ft, "sys_truncate", cfg.syscall.sys_truncate);
		CFG_EMIT(ft, "sys_fchmodat", cfg.syscall.sys_fchmodat);
		CFG_EMIT(ft, "sys_fchownat", cfg.syscall.sys_fchownat);

		long long ll_val;
		if (config_setting_lookup_int64(ft, "ring_buffer_size", &ll_val))
			cfg.ringbuf_file = ll_val;
		if (config_setting_lookup_int64(ft, "ring_buffer_ops_size", &ll_val))
			cfg.ringbuf_file_ops = ll_val;

		/* Включающие префиксы */
		config_setting_t *inc = config_setting_lookup(ft, "include");
		if (inc && config_setting_is_list(inc)) {
			int n = config_setting_length(inc);
			if (n > FILE_MAX_PREFIXES)
				n = FILE_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s = config_setting_get_string_elem(inc, i);
				if (s) {
					int slen = (int)strlen(s);
					if (slen > FILE_PREFIX_CAP - 1)
						slen = FILE_PREFIX_CAP - 1;
					memcpy(cfg.file_include[i].prefix, s, slen);
					cfg.file_include[i].prefix[slen] = '\0';
					cfg.file_include[i].len = (__u8)slen;
					cfg.file_include_count++;
				}
			}
		}

		/* Исключающие префиксы */
		config_setting_t *exc = config_setting_lookup(ft, "exclude");
		if (exc && config_setting_is_list(exc)) {
			int n = config_setting_length(exc);
			if (n > FILE_MAX_PREFIXES)
				n = FILE_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s = config_setting_get_string_elem(exc, i);
				if (s) {
					int slen = (int)strlen(s);
					if (slen > FILE_PREFIX_CAP - 1)
						slen = FILE_PREFIX_CAP - 1;
					memcpy(cfg.file_exclude[i].prefix, s, slen);
					cfg.file_exclude[i].prefix[slen] = '\0';
					cfg.file_exclude[i].len = (__u8)slen;
					cfg.file_exclude_count++;
				}
			}
		}
	}

	/* Настройки определения имён Docker */
	config_setting_t *dk = config_lookup(&lc, "docker");
	if (dk) {
		if (config_setting_lookup_bool(dk, "resolve_names", &bool_val))
			cfg.docker_resolve_names = bool_val;
		if (config_setting_lookup_string(dk, "data_root", &str_val))
			snprintf(cfg.docker_data_root, sizeof(cfg.docker_data_root), "%s", str_val);
		if (config_setting_lookup_string(dk, "daemon_json", &str_val))
			snprintf(cfg.docker_daemon_json, sizeof(cfg.docker_daemon_json), "%s",
				 str_val);
	}

	config_setting_t *ct = config_lookup(&lc, "cgroup_event");
	if (ct) {
		CFG_EMIT(ct, "cgroup_mkdir", cfg.syscall.cgroup_mkdir);
		CFG_EMIT(ct, "cgroup_rmdir", cfg.syscall.cgroup_rmdir);
		CFG_EMIT(ct, "cgroup_rename", cfg.syscall.cgroup_rename);
		CFG_EMIT(ct, "cgroup_release", cfg.syscall.cgroup_release);
		CFG_EMIT(ct, "cgroup_attach_task", cfg.syscall.cgroup_attach_task);
		CFG_EMIT(ct, "cgroup_transfer_tasks", cfg.syscall.cgroup_transfer_tasks);
		CFG_EMIT(ct, "cgroup_notify_populated", cfg.syscall.cgroup_notify_populated);
		CFG_EMIT(ct, "cgroup_notify_frozen", cfg.syscall.cgroup_notify_frozen);
		CFG_EMIT(ct, "cgroup_freeze", cfg.syscall.cgroup_freeze);
		CFG_EMIT(ct, "cgroup_unfreeze", cfg.syscall.cgroup_unfreeze);

		long long ll_val;
		if (config_setting_lookup_int64(ct, "ring_buffer_size", &ll_val))
			cfg.ringbuf_cgroup = ll_val;
	}

	config_setting_t *pt = config_lookup(&lc, "process_event");
	if (pt) {
		CFG_EMIT(pt, "sched_process_exec", cfg.syscall.sched_process_exec);
		CFG_EMIT(pt, "sched_process_fork", cfg.syscall.sched_process_fork);
		CFG_EMIT(pt, "sched_process_exit", cfg.syscall.sched_process_exit);
		CFG_EMIT(pt, "mark_victim", cfg.syscall.mark_victim);
		CFG_EMIT(pt, "sched_switch", cfg.syscall.sched_switch);
		CFG_EMIT(pt, "signal_generate", cfg.syscall.signal_generate);
		CFG_EMIT(pt, "sys_chdir", cfg.syscall.sys_chdir);

		long long ll_val;
		if (config_setting_lookup_int64(pt, "ring_buffer_size", &ll_val))
			cfg.ringbuf_proc = ll_val;
	}

	/* Настройки отслеживания дисков */
	config_setting_t *dt = config_lookup(&lc, "disk_metrics");
	if (dt) {
		if (config_setting_lookup_bool(dt, "enabled", &bool_val))
			cfg.disk_metrics = bool_val;

		/* Типы файловых систем для включения (переопределяют встроенный список) */
		config_setting_t *fst = config_setting_lookup(dt, "fs_types");
		if (fst && config_setting_is_list(fst)) {
			int n = config_setting_length(fst);
			if (n > DISK_MAX_PREFIXES)
				n = DISK_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s = config_setting_get_string_elem(fst, i);
				if (s)
					snprintf(cfg.disk_fs_types[cfg.disk_fs_types_count++], 32,
						 "%s", s);
			}
		}

		/* Включающие префиксы точек монтирования */
		config_setting_t *inc = config_setting_lookup(dt, "include");
		if (inc && config_setting_is_list(inc)) {
			int n = config_setting_length(inc);
			if (n > DISK_MAX_PREFIXES)
				n = DISK_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s = config_setting_get_string_elem(inc, i);
				if (s)
					snprintf(cfg.disk_include[cfg.disk_include_count++],
						 DISK_PREFIX_MAX, "%s", s);
			}
		}

		/* Исключающие префиксы точек монтирования */
		config_setting_t *exc = config_setting_lookup(dt, "exclude");
		if (exc && config_setting_is_list(exc)) {
			int n = config_setting_length(exc);
			if (n > DISK_MAX_PREFIXES)
				n = DISK_MAX_PREFIXES;
			for (int i = 0; i < n; i++) {
				const char *s = config_setting_get_string_elem(exc, i);
				if (s)
					snprintf(cfg.disk_exclude[cfg.disk_exclude_count++],
						 DISK_PREFIX_MAX, "%s", s);
			}
		}
	}

	config_destroy(&lc);

	/* Нормализация: секционный enabled — master-switch.
	 * Если net_tracking.enabled=false, все net-подопции принудительно 0,
	 * чтобы соответствующие BPF-программы не загружались в ядро. */
	/* Нормализация удалена: subsystem-флаги заменены на emit-таблицу.
	 * Каждый emit-флаг контролируется индивидуально. */

	return 0;
}
