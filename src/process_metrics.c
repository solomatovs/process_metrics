/*
 * process_metrics — событийный сборщик метрик процессов
 *
 * Загружает BPF-программы, слушает события кольцевого буфера, сопоставляет
 * exec-процессы с правилами конфигурации и периодически записывает метрики.
 * Отдаёт метрики через встроенный HTTP-сервер (формат CSV для ClickHouse).
 *
 * Использование:
 *   ./process_metrics -c config.conf
 *
 * Требования: root (CAP_BPF + CAP_PERFMON)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <mntent.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <pwd.h>
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
#include "log.h"

/*
 * bpf_program__set_autoload  — libbpf >= 0.6 (пропускает загрузку + подключение)
 * bpf_program__set_autoattach — libbpf >= 0.8 (загружает, но пропускает подключение)
 *
 * Для отключения опциональных программ нужен set_autoload (не отправлять
 * даже на верификатор). Astra Linux поставляет libbpf 0.7, в котором есть
 * set_autoload, но нет set_autoattach.
 */
/*
 * BPF_PROG_DISABLE: полностью отключает BPF-программу (не загружать,
 * не подключать). Используем set_autoload(false), а не set_autoattach(false),
 * потому что set_autoattach всё равно загружает программу в ядро (верификатор,
 * создание prog fd) — и при destroy close(fd) вызывает synchronize_rcu,
 * что добавляет ~0.15с на каждую программу к времени завершения.
 * set_autoload полностью пропускает программу — нет fd, нет задержки.
 */
#define BPF_PROG_DISABLE(prog) bpf_program__set_autoload((prog), false)

/* ── конфигурация ─────────────────────────────────────────────────── */

#define RULE_NOT_MATCH  "NOT_MATCH"

struct rule {
	char    name[EV_RULE_LEN];
	regex_t regex;
	int     ignore;   /* 1 = не отслеживать совпавший процесс */
};

static struct rule rules[MAX_RULES];
static int         num_rules;

/* Значения конфигурации (загружаются из libconfig) */
static const char *cfg_config_file     = NULL;
static char        cfg_hostname[EF_HOSTNAME_LEN]    = "";
static int         cfg_snapshot_interval           = 30;
static int         cfg_refresh_interval            = 0;  /* 0 = использовать snapshot_interval */
static int         cfg_exec_rate_limit             = 0;  /* 0 = без ограничений */
static int         cfg_cgroup_metrics              = 1;  /* 1 = читать файлы cgroup */
static int         cfg_refresh_proc                = 1;  /* 1 = обновлять cmdline/comm из /proc */
static int         cfg_log_level                   = 1;  /* 0=error, 1=info, 2=debug */
static int         cfg_heartbeat_interval          = 30; /* секунды, 0 = отключить */
static int         cfg_log_snapshot                = 1;  /* логировать snapshot строки */
static int         cfg_log_refresh                 = 1;  /* логировать refresh строки */

/* Конфигурация HTTP-сервера */
static struct http_config g_http_cfg;
static long long cfg_max_data_size          = (long long)EF_DEFAULT_SIZE_BYTES;

/* Размеры BPF ring buffer'ов (0 = использовать дефолт из compile-time) */
static long long cfg_ringbuf_proc           = 0;
static long long cfg_ringbuf_file           = 0;
static long long cfg_ringbuf_file_ops       = 0;
static long long cfg_ringbuf_net            = 0;
static long long cfg_ringbuf_sec            = 0;
static long long cfg_ringbuf_cgroup         = 0;

/* Конфигурация отслеживания сети */
static int cfg_net_tracking_enabled         = 0;
static int cfg_net_track_bytes              = 0;
static int cfg_need_sock_map                = 0; /* net_tracking || TCP-security */

/* Конфигурация отслеживания файлов */
static int cfg_file_tracking_enabled        = 0;
static int cfg_file_track_bytes             = 0;
static int cfg_file_absolute_paths_only     = 1;  /* 1 = отбрасывать относительные пути */

/* Конфигурация резолвинга Docker */
static int cfg_docker_resolve_names         = 0;  /* резолвить docker-<hash>.scope → имя контейнера */
static char cfg_docker_data_root[PATH_MAX_LEN] = "";
static char cfg_docker_daemon_json[PATH_MAX_LEN] = DOCKER_DEFAULT_DAEMON_JSON;

/* Конфигурация отслеживания дисков */
static int cfg_disk_tracking_enabled       = 1;  /* включено по умолчанию */
static char cfg_disk_include[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
static int  cfg_disk_include_count         = 0;
static char cfg_disk_exclude[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
static int  cfg_disk_exclude_count         = 0;
static char cfg_disk_fs_types[DISK_MAX_PREFIXES][DISK_FS_TYPE_LEN];
static int  cfg_disk_fs_types_count        = 0;

/* Конфигурация net_tracking: security-опции */
static int cfg_tcp_retransmit  = 0;
static int cfg_tcp_syn         = 0;
static int cfg_tcp_rst         = 0;
static int cfg_udp_bytes       = 0;
static int cfg_icmp_tracking   = 0;
static int cfg_tcp_open_conns  = 0;

/* ── Управление отправкой событий в CSV (emit-флаги) ──────────────── */
/* По умолчанию все включены. Переопределяются из секций конфига.
 * Управляют ТОЛЬКО ef_append() — BPF хуки и state-логика работают всегда. */

/* process_tracking.emit_* */
static int cfg_emit_exec           = 1;
static int cfg_emit_fork           = 1;
static int cfg_emit_exit           = 1;
static int cfg_emit_oom_kill       = 1;
static int cfg_emit_signal         = 1;
static int cfg_emit_chdir          = 1;

/* file_tracking.emit_* */
static int cfg_emit_file_open      = 1;
static int cfg_emit_file_close     = 1;
static int cfg_emit_file_rename    = 1;
static int cfg_emit_file_unlink    = 1;
static int cfg_emit_file_truncate  = 1;
static int cfg_emit_file_chmod     = 1;
static int cfg_emit_file_chown     = 1;

/* net_tracking.emit_* */
static int cfg_emit_net_listen     = 1;
static int cfg_emit_net_connect    = 1;
static int cfg_emit_net_accept     = 1;
static int cfg_emit_net_close      = 1;
static int cfg_emit_tcp_retransmit = 1;
static int cfg_emit_syn_recv       = 1;
static int cfg_emit_rst            = 1;
static int cfg_emit_udp_agg        = 1;

/* cgroup */
static int cfg_emit_cgroup         = 1;

/* Последние известные размеры BPF map'ов (обновляются refresh/snapshot).
 * Используется для адаптивного refresh_interval и heartbeat диагностики. */
static int g_last_map_count    = 0;   /* proc_map (refresh_processes) */
static int g_last_conn_count   = 0;   /* sock_map (write_snapshot) */
static int g_last_fd_count     = 0;   /* fd_map (write_snapshot) */

static struct file_prefix cfg_file_include[FILE_MAX_PREFIXES];
static int cfg_file_include_count           = 0;
static struct file_prefix cfg_file_exclude[FILE_MAX_PREFIXES];
static int cfg_file_exclude_count           = 0;

/* ── file path include/exclude фильтр (userspace, для file_snapshot) ── */

static int file_path_allowed(const char *path)
{
	if (cfg_file_include_count > 0) {
		int matched = 0;
		for (int i = 0; i < cfg_file_include_count; i++)
			if (strncmp(path, cfg_file_include[i].prefix,
				    cfg_file_include[i].len) == 0) {
				matched = 1;
				break;
			}
		if (!matched)
			return 0;
	}
	for (int i = 0; i < cfg_file_exclude_count; i++)
		if (strncmp(path, cfg_file_exclude[i].prefix,
			    cfg_file_exclude[i].len) == 0)
			return 0;
	return 1;
}

/* ── глобальные переменные ─────────────────────────────────────────── */

static volatile sig_atomic_t g_running   = 1;
static volatile sig_atomic_t g_reload    = 0;
static struct process_metrics_bpf *skel;
static int tracked_map_fd, proc_map_fd, missed_exec_fd;

/*
 * Две гранулярные RW-блокировки для общих данных:
 *
 * tags_lock — tags_ht (хеш-таблица тегов процессов)
 *   wrlock: EXEC (store), FORK (inherit), EXIT (remove), reload (clear)
 *   rdlock: FILE_CLOSE, NET_CLOSE, SIGNAL и др. (lookup), snapshot (lookup)
 *
 * cgroup_lock — cgroup_cache, cgroup_cache_count
 *   wrlock: cgroup_mkdir/rmdir/rename (BPF events), reload (rebuild)
 *   rdlock: FILE_CLOSE, NET_CLOSE, SIGNAL (resolve_cgroup_fast)
 */
#ifndef NO_TAGS
static pthread_rwlock_t g_tags_lock    = PTHREAD_RWLOCK_INITIALIZER;
#endif
static pthread_rwlock_t g_cgroup_lock  = PTHREAD_RWLOCK_INITIALIZER;
static pthread_rwlock_t g_pidtree_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Аргумент для потока poll */
struct poll_thread_arg {
	struct ring_buffer *rb;
	const char *name;
	volatile __u64 events;   /* атомарный счётчик обработанных событий */
	volatile __u64 polls;    /* атомарный счётчик итераций poll-цикла */
};

/* Предварительные объявления */
static void write_snapshot(void);
static void build_cgroup_cache(void);
/* log_ts определён в log.h */

/* Смещение от boot-time к wall-clock (вычисляется однократно при старте,
 * обновляется каждый snapshot). BPF отправляет bpf_ktime_get_boot_ns(),
 * wall_ns = boot_ns + g_boot_to_wall_ns. */
static __s64 g_boot_to_wall_ns;

static void refresh_boot_to_wall(void)
{
	struct timespec rt, bt;
	clock_gettime(CLOCK_REALTIME, &rt);
	clock_gettime(CLOCK_BOOTTIME, &bt);
	__s64 rt_ns = (__s64)rt.tv_sec * (long long)NS_PER_SEC + rt.tv_nsec;
	__s64 bt_ns = (__s64)bt.tv_sec * (long long)NS_PER_SEC + bt.tv_nsec;
	g_boot_to_wall_ns = rt_ns - bt_ns;
}

/* ── tags hash table (userspace-only, per-tgid) ──────────────────── *
 *
 * Хранит строку тегов (pipe-separated список совпавших правил) для каждого
 * отслеживаемого PID. Используется при формировании Prometheus-метрик
 * (snapshot) и event-файлов (exec/fork/exit/file_close/net_close).
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  ОПТИМИЗАЦИЯ 1: Split-layout (hot/cold separation)            │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  Проблема (обнаружена через perf):                            │
 * │  Исходная структура struct tags_entry { __u32 tgid;           │
 * │  char tags[512]; } — 516 байт. Массив 16384 записей = 8 МБ.  │
 * │  При linear probing каждый probe перемещался на 516 байт →    │
 * │  гарантированный L1/L2 cache miss (~100-200 тактов).          │
 * │  perf показал: tags_inherit = ~20% CPU,                       │
 * │  причём 70% времени в них — инструкции mov (чтение tgid).     │
 * │                                                                │
 * │  Решение: разделить на два параллельных массива:              │
 * │  • tags_tgid[16384] — только tgid'ы, 64 KB → в L1/L2 кэш    │
 * │  • tags_data[16384][512] — payload, 8 МБ → только при hit     │
 * │                                                                │
 * │  Probing бегает по compact tags_tgid[] (4 байта на slot) →    │
 * │  соседние слоты в одной cache line (16 tgid на 64-байтовую    │
 * │  линию), cache miss → cache hit.                              │
 * │                                                                │
 * │  Результат: proc drops с 72% до 48% при extreme нагрузке.    │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  ОПТИМИЗАЦИЯ 2: Murmurhash3 вместо tgid & mask                │
 * ├─────────────────────────────────────────────────────────────────┤
 * │  Проблема (обнаружена через perf после opt 1):                │
 * │  PID'ы в Linux последовательные (100500, 100501, 100502...).  │
 * │  Хэш tgid & (SIZE-1) отображает их в соседние слоты →        │
 * │  primary clustering: все PID'ы кучкуются в одном участке      │
 * │  таблицы, probe chains растут до O(n) в кластере.             │
 * │  perf показал: handle_event = 27% CPU, всё на mov — probing.  │
 * │                                                                │
 * │  Решение: murmurhash3 finalizer — битовый микшер, который     │
 * │  превращает последовательные числа в псевдослучайные индексы. │
 * │  PID 100500 → slot 8731, PID 100501 → slot 2049 и т.д.       │
 * │  Средняя длина probe chain при 10% load factor: ~1.05.        │
 * │                                                                │
 * │  Результат: proc drops с 48% до 0% (все события обработаны). │
 * │  handle_event + tags_inherit ушли из top perf полностью.      │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * Итоговый эффект обеих оптимизаций:
 *   До:    585k events, 420k drops (72%), handle_event = 31% CPU
 *   После: 418k events, 0 drops   (0%),  kernel syscalls = 4.7% CPU
 */

#define TAGS_MAX_LEN EV_TAGS_LEN

#ifdef NO_TAGS
/*
 * NO_TAGS build: все операции с тегами — no-op.
 * Собирается через: make binary NO_TAGS=1
 * Используется для бенчмаркинга — замер overhead тегов.
 */
static void tags_lookup_ts(__u32 tgid, char *buf, int buflen)
{ (void)tgid; if (buflen > 0) buf[0] = '\0'; }
static void tags_store_ts(__u32 tgid, const char *tags)
{ (void)tgid; (void)tags; }
static void tags_inherit_ts(__u32 child, __u32 parent)
{ (void)child; (void)parent; }
static void tags_remove_ts(__u32 tgid) { (void)tgid; }
static void tags_clear_ts(void) { }

#else /* !NO_TAGS */

static __u32 tags_tgid[TAGS_HT_SIZE];              /*  64 KB — компактный индекс */
static char  tags_data[TAGS_HT_SIZE][TAGS_MAX_LEN]; /*   8 MB — данные           */

/*
 * Murmurhash3 finalizer (32-bit).
 * Принимает tgid, возвращает индекс в [0, TAGS_HT_SIZE).
 *
 * Зачем: PID'ы в Linux назначаются последовательно (N, N+1, N+2, ...).
 * Наивный хэш (tgid & mask) сохраняет последовательность → соседние PID'ы
 * попадают в соседние слоты → primary clustering при linear probing.
 *
 * Murmurhash avalanche: изменение 1 бита во входе меняет ~50% бит выхода.
 * Последовательные PID'ы рассеиваются равномерно по всей таблице.
 *
 * Константы MURMUR3_C1 и MURMUR3_C2 — из оригинального murmurhash3
 * (Austin Appleby), обеспечивают максимальную лавинность для 32-бит.
 */
static inline __u32 tags_hash(__u32 h)
{
	h ^= h >> 16;
	h *= MURMUR3_C1;
	h ^= h >> 13;
	h *= MURMUR3_C2;
	h ^= h >> 16;
	return h & (TAGS_HT_SIZE - 1);
}

/* Предварительное объявление — используется в tags_inherit() */
static int try_track_pid(__u32 pid);

static void tags_store(__u32 tgid, const char *tags)
{
	__u32 idx = tags_hash(tgid);
	for (int i = 0; i < TAGS_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (tags_tgid[slot] == 0 || tags_tgid[slot] == tgid) {
			tags_tgid[slot] = tgid;
			snprintf(tags_data[slot], TAGS_MAX_LEN, "%s", tags);
			return;
		}
	}
}

static const char *tags_lookup(__u32 tgid)
{
	__u32 idx = tags_hash(tgid);
	for (int i = 0; i < TAGS_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (tags_tgid[slot] == tgid)
			return tags_data[slot];
		if (tags_tgid[slot] == 0)
			return "";
	}
	return "";
}

/*
 * Backward-shift deletion для open addressing с linear probing.
 *
 * Простое обнуление слота разрывает цепочки проб: lookup/store
 * останавливаются на «дырке», не находя элементов за ней.
 * Со временем при fork/exit таблица деградирует — цепочки удлиняются,
 * lookup сканирует тысячи слотов.
 *
 * Алгоритм: после удаления, сдвигаем элементы из последующих
 * слотов назад, пока не встретим пустой слот или элемент,
 * который уже на своём естественном месте.
 */
static void tags_remove(__u32 tgid)
{
	__u32 idx = tags_hash(tgid);
	__u32 slot = 0;
	int found = 0;

	/* Найти элемент */
	for (int i = 0; i < TAGS_HT_SIZE; i++) {
		slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (tags_tgid[slot] == tgid) { found = 1; break; }
		if (tags_tgid[slot] == 0)
			return; /* не найден */
	}
	if (!found) return;

	/* Backward-shift: заполняем дырку сдвигом последующих элементов */
	for (;;) {
		__u32 next = (slot + 1) & (TAGS_HT_SIZE - 1);
		if (tags_tgid[next] == 0)
			break; /* цепочка закончилась */

		/* Естественная позиция следующего элемента */
		__u32 natural = tags_hash(tags_tgid[next]);

		/* Нужно ли сдвигать next в slot?
		 * Да, если natural позиция next находится до или на slot
		 * (с учётом кольцевой арифметики).
		 * Т.е. slot лежит между natural и next (включительно). */
		__u32 d_natural_to_next = (next - natural) & (TAGS_HT_SIZE - 1);
		__u32 d_natural_to_slot = (slot - natural) & (TAGS_HT_SIZE - 1);

		if (d_natural_to_slot < d_natural_to_next) {
			/* Сдвигаем next → slot */
			tags_tgid[slot] = tags_tgid[next];
			memcpy(tags_data[slot], tags_data[next], TAGS_MAX_LEN);
			slot = next;
		} else {
			/* next уже на правильной стороне, дырку оставляем */
			break;
		}
	}

	/* Очищаем финальный пустой слот */
	tags_tgid[slot] = 0;
	tags_data[slot][0] = '\0';
}

/*
 * Наследование тегов от родителя к дочернему процессу.
 * ВАЖНО: НЕ вызывает try_track_pid() — это привело бы к deadlock,
 * т.к. tags_inherit_ts() уже держит wrlock на g_tags_lock, а
 * try_track_pid() → tags_store_ts() попыталась бы взять wrlock
 * повторно (pthread_rwlock_wrlock НЕ рекурсивный → UB/deadlock).
 * Резолв неизвестного родителя — ответственность вызывающего кода.
 */
static void tags_inherit(__u32 child_tgid, __u32 parent_tgid)
{
	const char *pt = tags_lookup(parent_tgid);
	if (pt[0])
		tags_store(child_tgid, pt);
}

static void tags_clear(void)
{
	memset(tags_tgid, 0, sizeof(tags_tgid));
	memset(tags_data, 0, sizeof(tags_data));
}

/*
 * Thread-safe обёртки для tags_*.
 * _ts_ версии берут g_tags_lock и копируют результат в caller-буфер.
 * Нелокированные версии используются внутри секций, где lock уже взят.
 */
static void tags_lookup_ts(__u32 tgid, char *buf, int buflen)
{
	pthread_rwlock_rdlock(&g_tags_lock);
	const char *t = tags_lookup(tgid);
	snprintf(buf, buflen, "%s", t);
	pthread_rwlock_unlock(&g_tags_lock);
}

static void tags_store_ts(__u32 tgid, const char *tags)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_store(tgid, tags);
	pthread_rwlock_unlock(&g_tags_lock);
}

static void tags_inherit_ts(__u32 child, __u32 parent)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_inherit(child, parent);
	pthread_rwlock_unlock(&g_tags_lock);
}

static void tags_remove_ts(__u32 tgid)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_remove(tgid);
	pthread_rwlock_unlock(&g_tags_lock);
}

static void tags_clear_ts(void)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_clear();
	pthread_rwlock_unlock(&g_tags_lock);
}

#endif /* NO_TAGS */

/* ── pid tree: глобальная хеш-таблица pid→ppid для цепочек предков ───
 *
 * Покрывает ВСЕ процессы системы (не только отслеживаемые), чтобы
 * цепочки предков могли проходить через неотслеживаемых промежуточных.
 *
 * Open-addressing + linear probing + backward-shift deletion.
 * Память: pt_pid[65536] + pt_ppid[65536] = 512 КБ.
 */


static __u32 pt_pid[PIDTREE_HT_SIZE];    /* ключи: pid   (0 = пустой слот) */
static __u32 pt_ppid[PIDTREE_HT_SIZE];   /* значения: ppid                 */

static inline __u32 pidtree_hash(__u32 h)
{
	h ^= h >> 16;
	h *= MURMUR3_C1;
	h ^= h >> 13;
	h *= MURMUR3_C2;
	h ^= h >> 16;
	return h & (PIDTREE_HT_SIZE - 1);
}

static void pidtree_store(__u32 pid, __u32 ppid)
{
	__u32 idx = pidtree_hash(pid);
	for (int i = 0; i < PIDTREE_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (PIDTREE_HT_SIZE - 1);
		if (pt_pid[slot] == 0 || pt_pid[slot] == pid) {
			pt_pid[slot] = pid;
			pt_ppid[slot] = ppid;
			return;
		}
	}
}

/* Lookup в массивах pid tree (работает и для живой таблицы, и для snapshot-копии) */
static __u32 pidtree_lookup_in(const __u32 *p_pid, const __u32 *p_ppid,
			       __u32 pid)
{
	__u32 idx = pidtree_hash(pid);
	for (int i = 0; i < PIDTREE_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (PIDTREE_HT_SIZE - 1);
		if (p_pid[slot] == pid)
			return p_ppid[slot];
		if (p_pid[slot] == 0)
			return 0;
	}
	return 0;
}

static void pidtree_remove(__u32 pid)
{
	__u32 idx = pidtree_hash(pid);
	__u32 slot = 0;
	int found = 0;

	for (int i = 0; i < PIDTREE_HT_SIZE; i++) {
		slot = (idx + i) & (PIDTREE_HT_SIZE - 1);
		if (pt_pid[slot] == pid) { found = 1; break; }
		if (pt_pid[slot] == 0)
			return;
	}
	if (!found) return;

	/* backward-shift deletion (Robin Hood) */
	for (;;) {
		__u32 next = (slot + 1) & (PIDTREE_HT_SIZE - 1);
		if (pt_pid[next] == 0)
			break;

		__u32 natural = pidtree_hash(pt_pid[next]);
		__u32 d_natural_to_next = (next - natural) & (PIDTREE_HT_SIZE - 1);
		__u32 d_natural_to_slot = (slot - natural) & (PIDTREE_HT_SIZE - 1);

		if (d_natural_to_slot < d_natural_to_next) {
			pt_pid[slot] = pt_pid[next];
			pt_ppid[slot] = pt_ppid[next];
			slot = next;
		} else {
			break;
		}
	}

	pt_pid[slot] = 0;
	pt_ppid[slot] = 0;
}

/* Счётчик поколений: увеличивается при каждой мутации дерева (fork/exec/exit).
 * Используется для инвалидации кеша цепочек. */
static __u64 pt_generation;

static void pidtree_store_ts(__u32 pid, __u32 ppid)
{
	pthread_rwlock_wrlock(&g_pidtree_lock);
	pidtree_store(pid, ppid);
	pt_generation++;
	pthread_rwlock_unlock(&g_pidtree_lock);
}

static void pidtree_remove_ts(__u32 pid)
{
	pthread_rwlock_wrlock(&g_pidtree_lock);
	pidtree_remove(pid);
	pt_generation++;
	pthread_rwlock_unlock(&g_pidtree_lock);
}

/* ── кеш цепочек предков ─────────────────────────────────────────
 *
 * Кеширует вычисленные цепочки, чтобы не ходить по дереву повторно.
 * Инвалидация через generation counter — любой fork/exec/exit
 * делает все закешированные записи устаревшими.
 */


static __u32 cc_pid[CHAIN_CACHE_SIZE];
static __u32 cc_chain[CHAIN_CACHE_SIZE][EV_PARENT_PIDS_MAX];
static __u8  cc_len[CHAIN_CACHE_SIZE];
static __u64 cc_gen[CHAIN_CACHE_SIZE];

static inline __u32 chain_cache_hash(__u32 h)
{
	h ^= h >> 16;
	h *= MURMUR3_C1;
	h ^= h >> 13;
	h *= MURMUR3_C2;
	h ^= h >> 16;
	return h & (CHAIN_CACHE_SIZE - 1);
}

/*
 * Обход pid tree вверх от pid, построение цепочки предков.
 * Работает на переданных массивах (живая таблица или snapshot-копия).
 */
static int pidtree_walk_chain(const __u32 *p_pid, const __u32 *p_ppid,
			      __u32 pid, __u32 *out, int max_depth)
{
	int len = 0;
	__u32 cur = pidtree_lookup_in(p_pid, p_ppid, pid);

	while (cur > 0 && len < max_depth) {
		for (int j = 0; j < len; j++) {
			if (out[j] == cur)
				return len; /* цикл — прерываем */
		}
		out[len++] = cur;
		if (cur == 1)
			break; /* дошли до init */
		cur = pidtree_lookup_in(p_pid, p_ppid, cur);
	}
	return len;
}

/*
 * Получить цепочку предков для pid (потокобезопасно, с кешем).
 * Берёт rdlock на g_pidtree_lock.
 */
static void pidtree_get_chain_ts(__u32 pid, __u32 *out, __u8 *out_len)
{
	pthread_rwlock_rdlock(&g_pidtree_lock);

	__u64 gen = pt_generation;
	__u32 slot = chain_cache_hash(pid);

	/* Проверка кеша */
	if (cc_pid[slot] == pid && cc_gen[slot] == gen) {
		int n = cc_len[slot];
		memcpy(out, cc_chain[slot], n * sizeof(__u32));
		*out_len = (__u8)n;
		pthread_rwlock_unlock(&g_pidtree_lock);
		return;
	}

	/* Промах кеша — обход дерева */
	__u32 chain[EV_PARENT_PIDS_MAX];
	int n = pidtree_walk_chain(pt_pid, pt_ppid, pid, chain,
				   EV_PARENT_PIDS_MAX);

	/* Сохраняем в кеш (direct-mapped, перезаписывает предыдущего) */
	cc_pid[slot] = pid;
	cc_gen[slot] = gen;
	cc_len[slot] = (__u8)n;
	memcpy(cc_chain[slot], chain, n * sizeof(__u32));

	memcpy(out, chain, n * sizeof(__u32));
	*out_len = (__u8)n;

	pthread_rwlock_unlock(&g_pidtree_lock);
}

/*
 * Получить цепочку предков из snapshot-копии pid tree (без lock).
 * Используется в write_snapshot() чтобы не держать g_pidtree_lock
 * на всю итерацию.
 */
static void pidtree_get_chain_copy(const __u32 *snap_pid,
				   const __u32 *snap_ppid,
				   __u32 pid, __u32 *out, __u8 *out_len)
{
	int n = pidtree_walk_chain(snap_pid, snap_ppid, pid, out,
				   EV_PARENT_PIDS_MAX);
	*out_len = (__u8)n;
}

/*
 * Заполнить parent_pids в metric_event (потокобезопасно, для обработчиков событий).
 */
static void fill_parent_pids(struct metric_event *cev)
{
	pidtree_get_chain_ts(cev->pid, cev->parent_pids,
			     &cev->parent_pids_len);
}

/* ── pwd hash table (userspace-only, per-tgid) ───────────────────────
 *
 * Кэширует текущий рабочий каталог (pwd) каждого отслеживаемого процесса.
 * Заполняется при initial_scan (readlink /proc/PID/cwd), обновляется
 * при chdir/fchdir (EVENT_CHDIR), наследуется при fork, удаляется при exit.
 *
 * Структура аналогична tags: split-layout + murmurhash3 + linear probing.
 */


static __u32 pwd_tgid[PWD_HT_SIZE];
static char  pwd_data[PWD_HT_SIZE][EV_PWD_LEN];  /* 512 * 16384 = 8 MB */
static pthread_rwlock_t g_pwd_lock = PTHREAD_RWLOCK_INITIALIZER;

static inline __u32 pwd_hash(__u32 h)
{
	h ^= h >> 16;
	h *= MURMUR3_C1;
	h ^= h >> 13;
	h *= MURMUR3_C2;
	h ^= h >> 16;
	return h & (PWD_HT_SIZE - 1);
}

static void pwd_store(__u32 tgid, const char *path)
{
	__u32 idx = pwd_hash(tgid);
	for (int i = 0; i < PWD_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (PWD_HT_SIZE - 1);
		if (pwd_tgid[slot] == 0 || pwd_tgid[slot] == tgid) {
			pwd_tgid[slot] = tgid;
			snprintf(pwd_data[slot], EV_PWD_LEN, "%s", path);
			return;
		}
	}
}

static const char *pwd_lookup(__u32 tgid)
{
	__u32 idx = pwd_hash(tgid);
	for (int i = 0; i < PWD_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (PWD_HT_SIZE - 1);
		if (pwd_tgid[slot] == tgid)
			return pwd_data[slot];
		if (pwd_tgid[slot] == 0)
			return "";
	}
	return "";
}

static void pwd_remove(__u32 tgid)
{
	__u32 idx = pwd_hash(tgid);
	__u32 slot = 0;
	int found = 0;

	for (int i = 0; i < PWD_HT_SIZE; i++) {
		slot = (idx + i) & (PWD_HT_SIZE - 1);
		if (pwd_tgid[slot] == tgid) { found = 1; break; }
		if (pwd_tgid[slot] == 0)
			return;
	}
	if (!found) return;

	for (;;) {
		__u32 next = (slot + 1) & (PWD_HT_SIZE - 1);
		if (pwd_tgid[next] == 0)
			break;

		__u32 natural = pwd_hash(pwd_tgid[next]);
		__u32 d_natural_to_next = (next - natural) & (PWD_HT_SIZE - 1);
		__u32 d_natural_to_slot = (slot - natural) & (PWD_HT_SIZE - 1);

		if (d_natural_to_slot < d_natural_to_next) {
			pwd_tgid[slot] = pwd_tgid[next];
			memcpy(pwd_data[slot], pwd_data[next], EV_PWD_LEN);
			slot = next;
		} else {
			break;
		}
	}

	pwd_tgid[slot] = 0;
	pwd_data[slot][0] = '\0';
}

static void pwd_inherit(__u32 child_tgid, __u32 parent_tgid)
{
	const char *pp = pwd_lookup(parent_tgid);
	if (pp[0])
		pwd_store(child_tgid, pp);
}

static void pwd_clear(void)
{
	memset(pwd_tgid, 0, sizeof(pwd_tgid));
	memset(pwd_data, 0, sizeof(pwd_data));
}

/* Thread-safe обёртки */
static void pwd_store_ts(__u32 tgid, const char *path)
{
	pthread_rwlock_wrlock(&g_pwd_lock);
	pwd_store(tgid, path);
	pthread_rwlock_unlock(&g_pwd_lock);
}

static void pwd_lookup_ts(__u32 tgid, char *buf, int buflen)
{
	pthread_rwlock_rdlock(&g_pwd_lock);
	const char *p = pwd_lookup(tgid);
	snprintf(buf, buflen, "%s", p);
	pthread_rwlock_unlock(&g_pwd_lock);
}

static void pwd_remove_ts(__u32 tgid)
{
	pthread_rwlock_wrlock(&g_pwd_lock);
	pwd_remove(tgid);
	pthread_rwlock_unlock(&g_pwd_lock);
}

static void pwd_inherit_ts(__u32 child, __u32 parent)
{
	pthread_rwlock_wrlock(&g_pwd_lock);
	pwd_inherit(child, parent);
	pthread_rwlock_unlock(&g_pwd_lock);
}

static void pwd_clear_ts(void)
{
	pthread_rwlock_wrlock(&g_pwd_lock);
	pwd_clear();
	pthread_rwlock_unlock(&g_pwd_lock);
}

/*
 * Читает pwd процесса через readlink(/proc/PID/cwd) и сохраняет в pwd-кэш.
 * Thread-safe.
 */
static void pwd_read_and_store(__u32 tgid)
{
	char cwd_path[PROC_PATH_LEN], pwd_buf[EV_PWD_LEN];
	snprintf(cwd_path, sizeof(cwd_path), "/proc/%u/cwd", tgid);
	ssize_t len = readlink(cwd_path, pwd_buf, sizeof(pwd_buf) - 1);
	if (len > 0) {
		pwd_buf[len] = '\0';
		pwd_store_ts(tgid, pwd_buf);
	}
}

/*
 * Сопоставляет cmdline со ВСЕМИ правилами, формирует строку тегов
 * через разделитель '|'. Возвращает индекс первого совпавшего правила
 * или -1, если совпадений нет.
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

/* Предварительные объявления для try_track_pid */
static void cmdline_to_str(const char *raw, __u16 len, char *out, int outlen);
static int read_proc_cmdline(__u32 pid, char *dst, int dstlen);
static void track_pid_from_proc(__u32 pid, int rule_id, __u32 root_pid,
				__u8 is_root);
/*
 * Попытка начать отслеживание неизвестного PID через чтение /proc/<pid>/cmdline.
 * Вызывается, когда file_close/net_close/oom_kill/exit приходит для PID,
 * которого нет в tracked_map. Читает cmdline, сопоставляет со всеми правилами
 * и добавляет в tracked_map + хеш-таблицу тегов при совпадении.
 * Возвращает индекс первого совпавшего правила или -1, если нет совпадения / процесс завершён.
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
	tags_store_ts(pid, tags_buf);
	LOG_DEBUG(cfg_log_level, "LATE_TRACK: pid=%u rule=%s tags=%s cmdline=%.60s",
		  pid, rules[first].name, tags_buf, cmdline_str);
	return first;
}

/* ── Кэш использования CPU (для вычисления отношения за интервал) ── */


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

/* ── кэш cgroup ──────────────────────────────────────────────────── */

struct cgroup_entry {
	__u64 id;
	char  path[EV_CGROUP_LEN];    /* отображаемое имя (docker/xxx или оригинал) */
	char  fs_path[EV_CGROUP_LEN]; /* реальный путь в файловой системе под /sys/fs/cgroup */
};

static struct cgroup_entry cgroup_cache[MAX_CGROUPS];
static int cgroup_cache_count;
static char docker_data_root[PATH_MAX_LEN] = "";

/* ── кэш cgroup-метрик (заполняется refresh, читается snapshot) ───── */

struct cgroup_metrics {
	char  path[EV_CGROUP_LEN];     /* отображаемое имя cgroup (ключ) */
	long long mem_max, mem_cur, swap_cur;
	long long cpu_weight, cpu_max, cpu_max_period;
	long long cpu_nr_periods, cpu_nr_throttled, cpu_throttled_usec;
	long long pids_cur;
	int  valid;                     /* 1 = значения прочитаны из /sys/fs/cgroup */
};

static struct cgroup_metrics cg_metrics[MAX_CGROUPS];
static int cg_metrics_count;

/*
 * Определение data-root Docker. Приоритет:
 *   1. cfg_docker_data_root (из файла конфигурации)
 *   2. Распарсенный из cfg_docker_daemon_json (ключ "data-root")
 *   3. Запасной вариант: /var/lib/docker
 */
static void detect_docker_data_root(void)
{
	if (docker_data_root[0])
		return;

	/* Используем явное значение из конфигурации, если задано */
	if (cfg_docker_data_root[0]) {
		snprintf(docker_data_root, sizeof(docker_data_root),
			 "%s", cfg_docker_data_root);
		return;
	}

	/* Пробуем распарсить из daemon.json */
	FILE *f = fopen(cfg_docker_daemon_json, "r");
	if (f) {
		char buf[CONFIG_BUF_LEN];
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
			 DOCKER_DEFAULT_ROOT);
}

/*
 * Попытка резолвить имя Docker-контейнера из пути cgroup.
 * Ищет паттерн "docker-<64hex>.scope" и читает имя контейнера
 * из config.v2.json. Возвращает 1 при успехе (dst заполнен), 0 — иначе.
 */
static int resolve_docker_name(const char *rel, char *dst, size_t dstlen)
{
	/* Ищем префикс "docker-" в последнем компоненте пути */
	const char *last = strrchr(rel, '/');
	const char *base = last ? last + 1 : rel;

	if (strncmp(base, DOCKER_PREFIX, DOCKER_PREFIX_LEN) != 0)
		return 0;
	const char *hash_start = base + DOCKER_PREFIX_LEN;
	const char *dot = strstr(hash_start, ".scope");
	if (!dot || (dot - hash_start) != DOCKER_HASH_LEN)
		return 0;

	char container_id[DOCKER_HASH_LEN + 1];
	memcpy(container_id, hash_start, DOCKER_HASH_LEN);
	container_id[DOCKER_HASH_LEN] = '\0';

	detect_docker_data_root();

	char config_path[PATH_MAX_LEN];
	snprintf(config_path, sizeof(config_path),
		 "%s/containers/%s/config.v2.json",
		 docker_data_root, container_id);

	FILE *f = fopen(config_path, "r");
	if (!f)
		return 0;

	/* config.v2.json может быть большим (>40KB если секция State велика),
	 * поэтому читаем частями, ища паттерн "Name":" */
	char *q1 = NULL, *q2 = NULL;
	char buf[CONFIG_BUF_LEN];
	char overlap[PROC_STATUS_LINE] = "";  /* перекрытие с предыдущим чанком */
	int found = 0;

	while (!found) {
		size_t n = fread(buf, 1, sizeof(buf) - 1, f);
		if (n == 0)
			break;
		buf[n] = '\0';

		/* Ищем в overlap+buf для обработки разрывов на границе */
		char combined[sizeof(overlap) + sizeof(buf)];
		size_t olen = strlen(overlap);
		memcpy(combined, overlap, olen);
		memcpy(combined + olen, buf, n + 1);

		char *key = strstr(combined, "\"Name\"");
		if (key) {
			char *colon = strchr(key + 6, ':');
			if (colon) {
				q1 = strchr(colon, '"');
				if (q1) {
					q1++;
					if (*q1 == '/')
						q1++;
					q2 = strchr(q1, '"');
					if (q2 && q1 != q2)
						found = 1;
				}
			}
		}

		if (!found) {
			/* Сохраняем последние 255 байт как перекрытие для границы */
			size_t total = olen + n;
			size_t keep = total < sizeof(overlap) - 1 ?
				      total : sizeof(overlap) - 1;
			memcpy(overlap, combined + total - keep, keep);
			overlap[keep] = '\0';
		}
	}
	fclose(f);

	if (!found)
		return 0;

	/* Формируем путь: "docker/<имя_контейнера>" */
	size_t name_len = q2 - q1;
	if (name_len + 8 > dstlen)  /* "docker/" + name + NUL */
		return 0;
	snprintf(dst, dstlen, "docker/%.*s", (int)name_len, q1);
	return 1;
}

/*
 * Кэш в памяти для резолвинга имён Docker-контейнеров.
 * Отображает ID контейнера (64 hex символа) → "docker/<имя>".
 * Избавляет от повторного fopen/fread файла config.v2.json на каждое событие.
 */

static struct {
	char container_id[DOCKER_HASH_LEN + 1]; /* hex + NUL */
	char resolved[EV_CGROUP_LEN];
	int  negative;               /* 1 = попытка была неудачной, не повторять */
} docker_name_cache[DOCKER_NAME_CACHE_SIZE];
static int docker_name_cache_count;
static pthread_rwlock_t g_docker_cache_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Извлекает ID контейнера из пути cgroup, возвращает указатель на 64-символьный hex или NULL */
static const char *extract_docker_id(const char *path)
{
	const char *last = strrchr(path, '/');
	const char *base = last ? last + 1 : path;
	if (strncmp(base, DOCKER_PREFIX, DOCKER_PREFIX_LEN) != 0)
		return NULL;
	const char *hash = base + DOCKER_PREFIX_LEN;
	const char *dot = strstr(hash, ".scope");
	if (!dot || (dot - hash) != DOCKER_HASH_LEN)
		return NULL;
	return hash;
}

/*
 * Резолвит cgroup для HTTP-вывода: если включён резолв Docker и путь
 * содержит docker-<hash>.scope, преобразует в docker/<имя>.
 * Использует кэш в памяти, чтобы избежать повторных чтений файловой системы.
 * Иначе копирует исходный путь как есть.
 */
void http_resolve_cgroup(const char *raw, char *buf, int buflen)
{
	if (!cfg_docker_resolve_names || !raw[0]) {
		snprintf(buf, buflen, "%s", raw);
		return;
	}

	const char *id = extract_docker_id(raw);
	if (!id) {
		snprintf(buf, buflen, "%s", raw);
		return;
	}

	/* Поиск в кэше (rdlock) */
	pthread_rwlock_rdlock(&g_docker_cache_lock);
	for (int i = 0; i < docker_name_cache_count; i++) {
		if (memcmp(docker_name_cache[i].container_id, id, DOCKER_HASH_LEN) == 0) {
			if (docker_name_cache[i].negative) {
				/* Предыдущая попытка неудачна — передаём исходный путь */
				snprintf(buf, buflen, "%s", raw);
			} else {
				snprintf(buf, buflen, "%s",
					 docker_name_cache[i].resolved);
			}
			pthread_rwlock_unlock(&g_docker_cache_lock);
			return;
		}
	}
	pthread_rwlock_unlock(&g_docker_cache_lock);

	/* Промах кэша — резолвим из файловой системы */
	char resolved[EV_CGROUP_LEN];
	int ok = resolve_docker_name(raw, resolved, sizeof(resolved));

	/* Сохраняем в кэш (wrlock) */
	pthread_rwlock_wrlock(&g_docker_cache_lock);
	/* Двойная проверка: другой поток мог уже добавить */
	for (int i = 0; i < docker_name_cache_count; i++) {
		if (memcmp(docker_name_cache[i].container_id, id, DOCKER_HASH_LEN) == 0) {
			pthread_rwlock_unlock(&g_docker_cache_lock);
			snprintf(buf, buflen, "%s", ok ? resolved : raw);
			return;
		}
	}
	if (docker_name_cache_count < DOCKER_NAME_CACHE_SIZE) {
		memcpy(docker_name_cache[docker_name_cache_count].container_id,
		       id, DOCKER_HASH_LEN);
		docker_name_cache[docker_name_cache_count].container_id[DOCKER_HASH_LEN] = '\0';
		if (ok) {
			snprintf(docker_name_cache[docker_name_cache_count].resolved,
				 sizeof(docker_name_cache[0].resolved),
				 "%s", resolved);
			docker_name_cache[docker_name_cache_count].negative = 0;
		} else {
			docker_name_cache[docker_name_cache_count].negative = 1;
		}
		docker_name_cache_count++;
	}
	pthread_rwlock_unlock(&g_docker_cache_lock);

	snprintf(buf, buflen, "%s", ok ? resolved : raw);
}

/*
 * Кэш в памяти для резолвинга UID → имя пользователя.
 * При промахе кэша использует getpwuid_r(), результат кэшируется.
 */
static struct {
	__u32 uid;
	char  name[USERNAME_LEN];
	int   valid;   /* 1 = запись используется */
} uid_name_cache[UID_NAME_CACHE_SIZE];
static int uid_name_cache_count;
static pthread_rwlock_t g_uid_cache_lock = PTHREAD_RWLOCK_INITIALIZER;

/*
 * Резолвинг UID → имя пользователя через getpwuid_r (NSS).
 *
 * Бинарник слинкован с glibc динамически (-Wl,-Bdynamic -lc),
 * поэтому полный стек NSS (files, sss, ldap, nis) работает нативно.
 * Результаты кэшируются в uid_name_cache, каждый UID резолвится не более одного раза.
 */
static int resolve_uid_to_name(__u32 uid, char *name, int namelen)
{
	struct passwd pwd, *result = NULL;
	char pwbuf[PWD_BUF_LEN];

	if (getpwuid_r((uid_t)uid, &pwd, pwbuf, sizeof(pwbuf),
		       &result) == 0 && result) {
		snprintf(name, namelen, "%s", result->pw_name);
		return 1;
	}
	return 0;
}

void http_resolve_uid(__u32 uid, char *buf, int buflen)
{
	if (buflen <= 0) return;
	buf[0] = '\0';

	/* Поиск в кэше (rdlock) */
	pthread_rwlock_rdlock(&g_uid_cache_lock);
	for (int i = 0; i < uid_name_cache_count; i++) {
		if (uid_name_cache[i].uid == uid) {
			snprintf(buf, buflen, "%s", uid_name_cache[i].name);
			pthread_rwlock_unlock(&g_uid_cache_lock);
			return;
		}
	}
	pthread_rwlock_unlock(&g_uid_cache_lock);

	/* Промах кэша — резолвим через NSS или /etc/passwd */
	char name[USERNAME_LEN] = "";
	resolve_uid_to_name(uid, name, sizeof(name));

	/* Сохраняем в кэш (wrlock) */
	pthread_rwlock_wrlock(&g_uid_cache_lock);
	/* Двойная проверка */
	for (int i = 0; i < uid_name_cache_count; i++) {
		if (uid_name_cache[i].uid == uid) {
			pthread_rwlock_unlock(&g_uid_cache_lock);
			snprintf(buf, buflen, "%s",
				 uid_name_cache[i].name);
			return;
		}
	}
	if (uid_name_cache_count < UID_NAME_CACHE_SIZE) {
		uid_name_cache[uid_name_cache_count].uid = uid;
		snprintf(uid_name_cache[uid_name_cache_count].name,
			 USERNAME_LEN, "%s", name);
		uid_name_cache[uid_name_cache_count].valid = 1;
		uid_name_cache_count++;
	}
	pthread_rwlock_unlock(&g_uid_cache_lock);

	snprintf(buf, buflen, "%s", name);
}

static void scan_cgroup_dir(const char *base, const char *rel)
{
	char full[PATH_MAX_LEN];
	snprintf(full, sizeof(full), "%s/%s", base, rel);

	struct stat st;
	if (stat(full, &st) == 0 && cgroup_cache_count < MAX_CGROUPS) {
		cgroup_cache[cgroup_cache_count].id = (__u64)st.st_ino;

		/* Сохраняем реальный путь файловой системы (имена Docker резолвятся лениво при выводе) */
		snprintf(cgroup_cache[cgroup_cache_count].fs_path,
			 sizeof(cgroup_cache[0].fs_path), "%s", rel);
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
	if (access(CGROUP_V2_PATH, R_OK) == 0)
		scan_cgroup_dir(CGROUP_V2_PATH, "");
}


/* Быстрый резолв cgroup на горячем пути — без пересборки кэша при промахе.
 * Кэш всё равно пересобирается каждый snapshot_interval. */
static const char *resolve_cgroup_fast(__u64 cgroup_id)
{
	if (cgroup_id == 0)
		return "";
	for (int i = 0; i < cgroup_cache_count; i++)
		if (cgroup_cache[i].id == cgroup_id)
			return cgroup_cache[i].path;
	return "";
}

/* Потокобезопасная обёртка для resolve_cgroup_fast */
static void resolve_cgroup_fast_ts(__u64 cgroup_id, char *buf, int buflen)
{
	pthread_rwlock_rdlock(&g_cgroup_lock);
	const char *cg = resolve_cgroup_fast(cgroup_id);
	snprintf(buf, buflen, "%s", cg);
	pthread_rwlock_unlock(&g_cgroup_lock);
}

/* Потокобезопасная обёртка для resolve_cgroup (без rebuild на промах —
 * кэш обновляется event-driven через BPF cgroup tracepoints). */
static void resolve_cgroup_ts(__u64 cgroup_id, char *buf, int buflen)
{
	pthread_rwlock_rdlock(&g_cgroup_lock);
	const char *cg = resolve_cgroup_fast(cgroup_id);
	snprintf(buf, buflen, "%s", cg);
	pthread_rwlock_unlock(&g_cgroup_lock);
}

/* Потокобезопасная обёртка для resolve_cgroup_fs */
static void resolve_cgroup_fs_ts(__u64 cgroup_id, char *buf, int buflen)
{
	if (cgroup_id == 0) { buf[0] = '\0'; return; }
	pthread_rwlock_rdlock(&g_cgroup_lock);
	for (int i = 0; i < cgroup_cache_count; i++) {
		if (cgroup_cache[i].id == cgroup_id) {
			snprintf(buf, buflen, "%s", cgroup_cache[i].fs_path);
			pthread_rwlock_unlock(&g_cgroup_lock);
			return;
		}
	}
	buf[0] = '\0';
	pthread_rwlock_unlock(&g_cgroup_lock);
}

static void build_cgroup_cache_ts(void)
{
	pthread_rwlock_wrlock(&g_cgroup_lock);
	build_cgroup_cache();
	pthread_rwlock_unlock(&g_cgroup_lock);
}

/* ── обработка cgroup-событий (BPF → userspace) ──────────────────── */

/*
 * Добавляет запись cgroup в кэш под wrlock.
 * Если cgroup id уже существует, обновляет путь.
 */
static void cgroup_cache_add(__u64 id, const char *path)
{
	/* Пути из BPF tracepoint начинаются с '/' (напр. "/test_cg"),
	 * а scan_cgroup_dir хранит относительные пути ("test_cg").
	 * Нормализуем, убирая ведущий '/'. */
	if (path[0] == '/')
		path++;

	pthread_rwlock_wrlock(&g_cgroup_lock);
	/* Проверяем, есть ли уже — обновляем путь */
	for (int i = 0; i < cgroup_cache_count; i++) {
		if (cgroup_cache[i].id == id) {
			snprintf(cgroup_cache[i].fs_path,
				 sizeof(cgroup_cache[0].fs_path), "%s", path);
			snprintf(cgroup_cache[i].path,
				 sizeof(cgroup_cache[0].path), "%s", path);
			pthread_rwlock_unlock(&g_cgroup_lock);
			return;
		}
	}
	/* Добавление новой записи */
	if (cgroup_cache_count < MAX_CGROUPS) {
		cgroup_cache[cgroup_cache_count].id = id;
		snprintf(cgroup_cache[cgroup_cache_count].fs_path,
			 sizeof(cgroup_cache[0].fs_path), "%s", path);
		snprintf(cgroup_cache[cgroup_cache_count].path,
			 sizeof(cgroup_cache[0].path), "%s", path);
		cgroup_cache_count++;
	}
	pthread_rwlock_unlock(&g_cgroup_lock);
}

/*
 * Удаление записи cgroup из кэша по id под wrlock.
 * Меняет местами с последней записью для удаления за O(1).
 */
static void cgroup_cache_remove(__u64 id)
{
	pthread_rwlock_wrlock(&g_cgroup_lock);
	for (int i = 0; i < cgroup_cache_count; i++) {
		if (cgroup_cache[i].id == id) {
			cgroup_cache[i] = cgroup_cache[cgroup_cache_count - 1];
			cgroup_cache_count--;
			break;
		}
	}
	pthread_rwlock_unlock(&g_cgroup_lock);
}

/*
 * Callback кольцевого буфера для events_cgroup.
 * Обновляет кэш cgroup при mkdir/rmdir/rename, логирует остальные события.
 */
static int handle_cgroup_event(void *ctx, void *data, size_t size)
{
	(void)ctx;

	if (size < sizeof(struct cgroup_event))
		return 0;

	const struct cgroup_event *ce = data;

	switch (ce->type) {
	case EVENT_CGROUP_MKDIR:
		cgroup_cache_add(ce->id, ce->path);
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup mkdir: id=%llu level=%d path=%s",
			       (unsigned long long)ce->id, ce->level, ce->path);
		break;

	case EVENT_CGROUP_RMDIR:
		cgroup_cache_remove(ce->id);
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup rmdir: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_RENAME:
		/* Обновляем путь для существующей записи */
		cgroup_cache_add(ce->id, ce->path);
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup rename: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_RELEASE:
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup release: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_ATTACH_TASK:
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup attach: pid=%d → id=%llu path=%s comm=%s",
			       ce->pid, (unsigned long long)ce->id,
			       ce->path, ce->comm);
		break;

	case EVENT_CGROUP_TRANSFER_TASKS:
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup transfer: pid=%d → id=%llu path=%s comm=%s",
			       ce->pid, (unsigned long long)ce->id,
			       ce->path, ce->comm);
		break;

	case EVENT_CGROUP_POPULATED:
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup populated: id=%llu path=%s val=%d",
			       (unsigned long long)ce->id, ce->path, ce->val);
		break;

	case EVENT_CGROUP_FREEZE:
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup freeze: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_UNFREEZE:
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup unfreeze: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_FROZEN:
		if (cfg_log_level >= 2)
			LOG_DEBUG(cfg_log_level, "cgroup frozen: id=%llu path=%s val=%d",
			       (unsigned long long)ce->id, ce->path, ce->val);
		break;

	default:
		break;
	}

	return 0;
}

/* ── парсер правил (из libconfig) ─────────────────────────────────── */

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
		LOG_FATAL("%s:%d - %s",
		       config_error_file(&cfg) ? config_error_file(&cfg) : path,
		       config_error_line(&cfg),
		       config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	config_setting_t *rs = config_lookup(&cfg, "rules");
	if (!rs || !config_setting_is_list(rs)) {
		LOG_FATAL("'rules' list not found in %s", path);
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
			LOG_WARN("rules[%d]: missing 'name' or 'regex'", i);
			continue;
		}

		if (regcomp(&rules[num_rules].regex, regex,
			    REG_EXTENDED | REG_NOSUB) != 0) {
			LOG_WARN("rules[%d]: bad regex: %s", i, regex);
			continue;
		}
		snprintf(rules[num_rules].name, sizeof(rules[0].name), "%s", name);

		int ignore_val = 0;
		config_setting_lookup_bool(entry, "ignore", &ignore_val);
		rules[num_rules].ignore = ignore_val;

		num_rules++;
	}

	config_destroy(&cfg);
	LOG_INFO("loaded %d rules from %s", num_rules, path);
	return num_rules;
}

/* ── загрузчик конфигурации libconfig ─────────────────────────────── */

static int load_config(const char *path)
{
	config_t cfg;
	config_init(&cfg);

	if (!config_read_file(&cfg, path)) {
		LOG_FATAL("%s:%d - %s",
		       config_error_file(&cfg) ? config_error_file(&cfg) : path,
		       config_error_line(&cfg),
		       config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	const char *str_val;
	int int_val;

	/* Общие настройки */
	if (config_lookup_string(&cfg, "hostname", &str_val))
		snprintf(cfg_hostname, sizeof(cfg_hostname), "%s", str_val);
	if (!cfg_hostname[0])
		gethostname(cfg_hostname, sizeof(cfg_hostname));
	if (config_lookup_int(&cfg, "snapshot_interval", &int_val))
		cfg_snapshot_interval = int_val;
	if (config_lookup_int(&cfg, "refresh_interval", &int_val))
		cfg_refresh_interval = int_val;

	/* refresh_interval: если не задан — берётся snapshot_interval;
	 * если больше snapshot_interval — приравнивается */
	if (cfg_refresh_interval <= 0)
		cfg_refresh_interval = cfg_snapshot_interval;
	if (cfg_refresh_interval > cfg_snapshot_interval)
		cfg_refresh_interval = cfg_snapshot_interval;

	if (config_lookup_int(&cfg, "exec_rate_limit", &int_val))
		cfg_exec_rate_limit = int_val;

	int bool_val;
	if (config_lookup_bool(&cfg, "cgroup_metrics", &bool_val))
		cfg_cgroup_metrics = bool_val;
	if (config_lookup_bool(&cfg, "refresh_proc", &bool_val))
		cfg_refresh_proc = bool_val;
	if (config_lookup_int(&cfg, "log_level", &int_val))
		cfg_log_level = int_val;
	if (config_lookup_int(&cfg, "heartbeat_interval", &int_val))
		cfg_heartbeat_interval = int_val;
	if (config_lookup_bool(&cfg, "log_snapshot", &bool_val))
		cfg_log_snapshot = bool_val;
	if (config_lookup_bool(&cfg, "log_refresh", &bool_val))
		cfg_log_refresh = bool_val;

	/* Настройки HTTP-сервера (включается при наличии секции с портом) */
	memset(&g_http_cfg, 0, sizeof(g_http_cfg));
	g_http_cfg.port = HTTP_DEFAULT_PORT;
	g_http_cfg.max_connections = HTTP_DEFAULT_MAX_CONNS;
	g_http_cfg.log_requests = 1;
	snprintf(g_http_cfg.bind, sizeof(g_http_cfg.bind), HTTP_DEFAULT_BIND);

	config_setting_t *hs = config_lookup(&cfg, "http_server");
	if (hs) {
		if (config_setting_lookup_int(hs, "port", &int_val)) {
			g_http_cfg.port = int_val;
			g_http_cfg.enabled = 1;
		}
		if (config_setting_lookup_string(hs, "bind", &str_val))
			snprintf(g_http_cfg.bind, sizeof(g_http_cfg.bind),
				 "%s", str_val);
		if (config_setting_lookup_int(hs, "max_connections", &int_val))
			g_http_cfg.max_connections = int_val;
		if (config_setting_lookup_bool(hs, "log_requests", &bool_val))
			g_http_cfg.log_requests = bool_val;

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
				if (!cidr) continue;

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
						config_destroy(&cfg);
						return 1;
					}
				}

				struct in_addr parsed;
				if (inet_pton(AF_INET, ip_buf, &parsed) != 1) {
					LOG_ERROR("http_server: invalid IP in '%s'",
					       cidr);
					config_destroy(&cfg);
					return 1;
				}

				in_addr_t mask = (prefix == 0) ? 0
					: htonl(~((1U << (32 - prefix)) - 1));
				g_http_cfg.allow[g_http_cfg.allow_count].mask =
					ntohl(mask);
				g_http_cfg.allow[g_http_cfg.allow_count].network =
					ntohl(parsed.s_addr) & ntohl(mask);
				g_http_cfg.allow_count++;
			}
		}

		long long ll_val;
		if (config_setting_lookup_int64(hs, "max_buffer_size", &ll_val))
			cfg_max_data_size = ll_val;
	}

	/* Размеры BPF ring buffer'ов */
	config_setting_t *rb = config_lookup(&cfg, "ring_buffers");
	if (rb) {
		long long ll_val;
		if (config_setting_lookup_int64(rb, "proc", &ll_val))
			cfg_ringbuf_proc = ll_val;
		if (config_setting_lookup_int64(rb, "file", &ll_val))
			cfg_ringbuf_file = ll_val;
		if (config_setting_lookup_int64(rb, "file_ops", &ll_val))
			cfg_ringbuf_file_ops = ll_val;
		if (config_setting_lookup_int64(rb, "net", &ll_val))
			cfg_ringbuf_net = ll_val;
		if (config_setting_lookup_int64(rb, "sec", &ll_val))
			cfg_ringbuf_sec = ll_val;
		if (config_setting_lookup_int64(rb, "cgroup", &ll_val))
			cfg_ringbuf_cgroup = ll_val;
	}

	/* Настройки отслеживания сети (включая security TCP/UDP) */
	config_setting_t *nt = config_lookup(&cfg, "net_tracking");
	if (nt) {
		if (config_setting_lookup_bool(nt, "enabled", &bool_val))
			cfg_net_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_bytes", &bool_val))
			cfg_net_track_bytes = bool_val;

		if (config_setting_lookup_bool(nt, "tcp_retransmit", &bool_val))
			cfg_tcp_retransmit = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_syn", &bool_val))
			cfg_tcp_syn = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_rst", &bool_val))
			cfg_tcp_rst = bool_val;
		if (config_setting_lookup_bool(nt, "udp_bytes", &bool_val))
			cfg_udp_bytes = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_open_conns", &bool_val))
			cfg_tcp_open_conns = bool_val;

		/* emit-флаги: какие сетевые события отправлять в CSV */
		if (config_setting_lookup_bool(nt, "emit_listen", &bool_val))
			cfg_emit_net_listen = bool_val;
		if (config_setting_lookup_bool(nt, "emit_connect", &bool_val))
			cfg_emit_net_connect = bool_val;
		if (config_setting_lookup_bool(nt, "emit_accept", &bool_val))
			cfg_emit_net_accept = bool_val;
		if (config_setting_lookup_bool(nt, "emit_close", &bool_val))
			cfg_emit_net_close = bool_val;
		if (config_setting_lookup_bool(nt, "emit_retransmit", &bool_val))
			cfg_emit_tcp_retransmit = bool_val;
		if (config_setting_lookup_bool(nt, "emit_syn_recv", &bool_val))
			cfg_emit_syn_recv = bool_val;
		if (config_setting_lookup_bool(nt, "emit_rst", &bool_val))
			cfg_emit_rst = bool_val;
		if (config_setting_lookup_bool(nt, "emit_udp_agg", &bool_val))
			cfg_emit_udp_agg = bool_val;
	}

	/* Настройки отслеживания файлов */
	config_setting_t *ft = config_lookup(&cfg, "file_tracking");
	if (ft) {
		if (config_setting_lookup_bool(ft, "enabled", &bool_val))
			cfg_file_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(ft, "track_bytes", &bool_val))
			cfg_file_track_bytes = bool_val;
		if (config_setting_lookup_bool(ft, "absolute_paths_only", &bool_val))
			cfg_file_absolute_paths_only = bool_val;

		/* emit-флаги: какие файловые события отправлять в CSV */
		if (config_setting_lookup_bool(ft, "emit_open", &bool_val))
			cfg_emit_file_open = bool_val;
		if (config_setting_lookup_bool(ft, "emit_close", &bool_val))
			cfg_emit_file_close = bool_val;
		if (config_setting_lookup_bool(ft, "emit_rename", &bool_val))
			cfg_emit_file_rename = bool_val;
		if (config_setting_lookup_bool(ft, "emit_unlink", &bool_val))
			cfg_emit_file_unlink = bool_val;
		if (config_setting_lookup_bool(ft, "emit_truncate", &bool_val))
			cfg_emit_file_truncate = bool_val;
		if (config_setting_lookup_bool(ft, "emit_chmod", &bool_val))
			cfg_emit_file_chmod = bool_val;
		if (config_setting_lookup_bool(ft, "emit_chown", &bool_val))
			cfg_emit_file_chown = bool_val;

		/* Включающие префиксы */
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

		/* Исключающие префиксы */
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

	/* Настройки определения имён Docker */
	config_setting_t *dk = config_lookup(&cfg, "docker");
	if (dk) {
		if (config_setting_lookup_bool(dk, "resolve_names", &bool_val))
			cfg_docker_resolve_names = bool_val;
		if (config_setting_lookup_string(dk, "data_root", &str_val))
			snprintf(cfg_docker_data_root, sizeof(cfg_docker_data_root),
				 "%s", str_val);
		if (config_setting_lookup_string(dk, "daemon_json", &str_val))
			snprintf(cfg_docker_daemon_json, sizeof(cfg_docker_daemon_json),
				 "%s", str_val);
	}

	/* ICMP — верхнеуровневая опция (не привязана к процессам) */
	if (config_lookup_bool(&cfg, "icmp_tracking", &bool_val))
		cfg_icmp_tracking = bool_val;

	/* emit-флаг cgroup событий */
	if (config_lookup_bool(&cfg, "emit_cgroup_events", &bool_val))
		cfg_emit_cgroup = bool_val;

	/* process_tracking — emit-флаги процессных событий */
	config_setting_t *pt = config_lookup(&cfg, "process_tracking");
	if (pt) {
		if (config_setting_lookup_bool(pt, "emit_exec", &bool_val))
			cfg_emit_exec = bool_val;
		if (config_setting_lookup_bool(pt, "emit_fork", &bool_val))
			cfg_emit_fork = bool_val;
		if (config_setting_lookup_bool(pt, "emit_exit", &bool_val))
			cfg_emit_exit = bool_val;
		if (config_setting_lookup_bool(pt, "emit_oom_kill", &bool_val))
			cfg_emit_oom_kill = bool_val;
		if (config_setting_lookup_bool(pt, "emit_signal", &bool_val))
			cfg_emit_signal = bool_val;
		if (config_setting_lookup_bool(pt, "emit_chdir", &bool_val))
			cfg_emit_chdir = bool_val;
	}

	/* Настройки отслеживания дисков */
	config_setting_t *dt = config_lookup(&cfg, "disk_tracking");
	if (dt) {
		if (config_setting_lookup_bool(dt, "enabled", &bool_val))
			cfg_disk_tracking_enabled = bool_val;

		/* Типы файловых систем для включения (переопределяют встроенный список) */
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

		/* Включающие префиксы точек монтирования */
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

		/* Исключающие префиксы точек монтирования */
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

	config_destroy(&cfg);

	/* Нормализация: секционный enabled — master-switch.
	 * Если net_tracking.enabled=false, все net-подопции принудительно 0,
	 * чтобы соответствующие BPF-программы не загружались в ядро. */
	if (!cfg_net_tracking_enabled) {
		cfg_tcp_retransmit = 0;
		cfg_tcp_syn        = 0;
		cfg_tcp_rst        = 0;
		cfg_udp_bytes      = 0;
		cfg_tcp_open_conns = 0;
		cfg_icmp_tracking  = 0;
		cfg_net_track_bytes = 0;
	}

	return 0;
}

/* ── вспомогательные функции ──────────────────────────────────────── */

static void cmdline_to_str(const char *raw, __u16 len, char *out, int outlen)
{
	int n = len < outlen - 1 ? len : outlen - 1;
	for (int i = 0; i < n; i++)
		out[i] = (raw[i] == '\0') ? ' ' : raw[i];
	/* убираем завершающий пробел */
	while (n > 0 && out[n-1] == ' ')
		n--;
	out[n] = '\0';
}

/*
 * Разделение сырой cmdline (argv, разделённых NUL) на exec_path и args.
 * exec_path = argv[0], args = argv[1..], объединённые пробелами.
 */
static void cmdline_split(const char *raw, __u16 len,
			  char *exec_out, int exec_len,
			  char *args_out, int args_len)
{
	exec_out[0] = '\0';
	args_out[0] = '\0';

	if (len == 0)
		return;

	/* argv[0]: до первого NUL */
	int first_nul = -1;
	for (int i = 0; i < len; i++) {
		if (raw[i] == '\0') {
			first_nul = i;
			break;
		}
	}

	if (first_nul < 0) {
		/* NUL не найден — вся cmdline является exec */
		int n = len < exec_len - 1 ? len : exec_len - 1;
		memcpy(exec_out, raw, n);
		exec_out[n] = '\0';
		return;
	}

	/* exec = raw[0..first_nul) */
	int elen = first_nul < exec_len - 1 ? first_nul : exec_len - 1;
	memcpy(exec_out, raw, elen);
	exec_out[elen] = '\0';

	/* args = raw[first_nul+1..len), NUL заменяются пробелами */
	int start = first_nul + 1;
	int alen = len - start;
	if (alen <= 0)
		return;
	if (alen > args_len - 1)
		alen = args_len - 1;
	for (int i = 0; i < alen; i++)
		args_out[i] = (raw[start + i] == '\0') ? ' ' : raw[start + i];
	/* убираем завершающие пробелы */
	while (alen > 0 && args_out[alen - 1] == ' ')
		alen--;
	args_out[alen] = '\0';
}

/* ── быстрые хелперы для горячего пути (замена snprintf) ──────────── */

/* Быстрое u8 → десятичное (1-3 цифры). Возвращает указатель за последним. */
static inline char *fast_u8(char *p, unsigned char v)
{
	if (v >= 100) { *p++ = '0' + v / 100; v %= 100; *p++ = '0' + v / 10; *p++ = '0' + v % 10; }
	else if (v >= 10) { *p++ = '0' + v / 10; *p++ = '0' + v % 10; }
	else { *p++ = '0' + v; }
	return p;
}

/* IPv4 bytes[4] → "1.2.3.4" в dst, возвращает длину. */
static inline int fmt_ipv4(char *dst, int cap, const __u8 *a)
{
	char *p = dst;
	p = fast_u8(p, a[0]); *p++ = '.';
	p = fast_u8(p, a[1]); *p++ = '.';
	p = fast_u8(p, a[2]); *p++ = '.';
	p = fast_u8(p, a[3]);
	*p = '\0';
	(void)cap;
	return (int)(p - dst);
}

/* Копирование строки в поле фиксированного размера (замена snprintf("%s")) */
static inline void fast_strcpy(char *dst, int cap, const char *src)
{
	int i = 0;
	while (i < cap - 1 && src[i]) { dst[i] = src[i]; i++; }
	dst[i] = '\0';
}

/* log_ts — см. log.h */

/* log_debug заменён макросом LOG_DEBUG(cfg_log_level, ...) из log.h */

/* ── построитель событий ──────────────────────────────────────────── */

/* Построение metric_event из события кольцевого буфера BPF */
static void event_from_bpf(struct metric_event *out, const struct event *e,
			    const char *event_type, const char *rule_name,
			    const char *tags, const char *cgroup)
{
	memset(out, 0, sizeof(*out));
	/* Используем реальное время вместо BPF-метки относительно загрузки */
	struct timespec ts_now;
	clock_gettime(CLOCK_REALTIME, &ts_now);
	out->timestamp_ns = (__u64)ts_now.tv_sec * NS_PER_SEC
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
	/* поля, специфичные для exit */
	out->exit_code = (e->exit_code >> EXIT_STATUS_SHIFT) & EXIT_STATUS_MASK;
	out->cpu_ns = e->cpu_ns;
	out->rss_max_bytes = e->rss_max_pages * (unsigned long)sysconf(_SC_PAGESIZE);
	out->rss_min_bytes = e->rss_min_pages * (unsigned long)sysconf(_SC_PAGESIZE);
	out->oom_killed = e->oom_killed;
	out->net_tx_bytes = e->net_tx_bytes;
	out->net_rx_bytes = e->net_rx_bytes;
	out->start_time_ns = e->start_ns;
	/* новые поля */
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

/* ── начальное сканирование процессов (однократное чтение /proc при старте) ── */

/*
 * Парсинг /proc/PID/stat: извлечение comm, state, ppid, utime, stime,
 * threads, starttime, vsize, rss.
 */
static int read_proc_stat(__u32 pid, struct proc_info *pi)
{
	char path[PROC_PATH_LEN];
	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char buf[PROC_STAT_LEN];
	if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
	fclose(f);

	/* comm: между первой '(' и последней ')' */
	char *lp = strchr(buf, '(');
	char *rp = strrchr(buf, ')');
	if (!lp || !rp || rp <= lp) return -1;
	int clen = (int)(rp - lp - 1);
	if (clen > COMM_LEN - 1) clen = COMM_LEN - 1;
	memcpy(pi->comm, lp + 1, clen);
	pi->comm[clen] = '\0';

	/* поля после ") " :
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
	if (page_size <= 0) page_size = FALLBACK_PAGE_SIZE;
	pi->vsize_pages = (__u64)(vsize / page_size);

	long clk_tck = sysconf(_SC_CLK_TCK);
	if (clk_tck <= 0) clk_tck = FALLBACK_CLK_TCK;
	pi->cpu_ns = ((__u64)(utime + stime) * NS_PER_SEC) / (__u64)clk_tck;
	pi->start_ns = ((__u64)starttime * NS_PER_SEC) / (__u64)clk_tck;

	/* Чтение дополнительных полей из /proc/PID/status */
	char spath[PROC_PATH_LEN];
	snprintf(spath, sizeof(spath), "/proc/%u/status", pid);
	FILE *sf = fopen(spath, "r");
	if (sf) {
		char sline[PROC_STATUS_LINE];
		while (fgets(sline, sizeof(sline), sf)) {
			unsigned long val;
			unsigned int uid_val, euid_val;
			if (sscanf(sline, "Uid:\t%u\t%u", &uid_val, &euid_val) == 2) {
				pi->uid  = (__u32)uid_val;
				pi->euid = (__u32)euid_val;
			}
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

	/* Чтение loginuid/sessionid из /proc/PID/ (audit) */
	{
		char apath[PROC_PATH_LEN];
		FILE *af;
		unsigned int aval;

		snprintf(apath, sizeof(apath), "/proc/%u/loginuid", pid);
		af = fopen(apath, "r");
		if (af) {
			if (fscanf(af, "%u", &aval) == 1)
				pi->loginuid = (__u32)aval;
			fclose(af);
		}

		snprintf(apath, sizeof(apath), "/proc/%u/sessionid", pid);
		af = fopen(apath, "r");
		if (af) {
			if (fscanf(af, "%u", &aval) == 1)
				pi->sessionid = (__u32)aval;
			fclose(af);
		}
	}

	/* Чтение IO из /proc/PID/io (требует root или ptrace) */
	char iopath[PROC_PATH_LEN];
	snprintf(iopath, sizeof(iopath), "/proc/%u/io", pid);
	FILE *iof = fopen(iopath, "r");
	if (iof) {
		char ioline[PROC_IO_LINE];
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

/* Лёгкое чтение ppid из /proc/PID/stat (только 2 поля после ')').
 * Возвращает ppid или 0 при ошибке. */
static __u32 read_proc_ppid(__u32 pid)
{
	char path[PROC_PATH_LEN];
	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	char buf[PROC_BUF_SMALL];
	if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
	fclose(f);
	char *rp = strrchr(buf, ')');
	if (!rp) return 0;
	int ppid = 0;
	if (sscanf(rp + 2, "%*c %d", &ppid) != 1) return 0;
	return ppid > 0 ? (__u32)ppid : 0;
}

static int read_proc_cmdline(__u32 pid, char *dst, int dstlen)
{
	char path[PROC_PATH_LEN];
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
	char path[PROC_PATH_LEN], buf[PROC_BUF_SMALL];
	snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;

	/* Ищем строку cgroup v2 "0::/path" или берём первую строку как запасной вариант */
	char cg_path[EV_CGROUP_LEN] = "";
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

	/* Убираем ведущий / */
	char *rel = cg_path;
	if (*rel == '/') rel++;

	/* stat директории cgroup для получения inode = cgroup_id */
	char full[PATH_MAX_LEN];
	snprintf(full, sizeof(full), "/sys/fs/cgroup/%s", rel);
	struct stat st;
	if (stat(full, &st) == 0)
		return (__u64)st.st_ino;
	return 0;
}

static __s16 read_proc_oom(__u32 pid)
{
	char path[PROC_PATH_LEN], buf[PROC_VAL_LEN];
	snprintf(path, sizeof(path), "/proc/%u/oom_score_adj", pid);
	FILE *f = fopen(path, "r");
	if (!f) return 0;
	if (!fgets(buf, sizeof(buf), f)) { fclose(f); return 0; }
	fclose(f);
	return (__s16)atoi(buf);
}


/*
 * Однократное сканирование при запуске: чтение /proc, сопоставление правил,
 * заполнение BPF-карт. После этого всё отслеживание управляется событиями BPF.
 */

struct scan_entry {
	__u32 pid;
	__u32 ppid;
};


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

	/* Заполняем pwd-кэш через readlink /proc/PID/cwd */
	pwd_read_and_store(pid);
}

static void add_descendants(struct scan_entry *entries, int count,
			    __u32 parent, int rule_id, __u32 root_pid,
			    int *tracked)
{
	for (int i = 0; i < count; i++) {
		if (entries[i].ppid != parent)
			continue;
		__u32 child = entries[i].pid;
		/* Пропускаем, если уже отслеживается */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &child, &ti) == 0)
			continue;
		track_pid_from_proc(child, rule_id, root_pid, 0);
		tags_inherit_ts(child, parent);
		(*tracked)++;
		add_descendants(entries, count, child, rule_id, root_pid, tracked);
	}
}

/* ── seed_sock_map: заполнение sock_map существующими сокетами ─────── */
/*
 * После initial_scan tracked_map содержит все отслеживаемые PID.
 * Для каждого из них сканируем /proc/<pid>/fd/ и находим socket-inode'ы.
 * Затем запускаем BPF iter/tcp, который для каждого TCP-сокета ядра
 * проверяет inode в seed_inode_map и добавляет найденные в sock_map.
 */
static void seed_sock_map(void)
{
	if (!cfg_need_sock_map)
		return;

	int seed_fd = bpf_map__fd(skel->maps.seed_inode_map);
	if (seed_fd < 0)
		return;

	/* Проход по tracked_map → для каждого PID сканируем /proc/<pid>/fd/ */
	__u32 key = 0, next_key;
	int seeded = 0;
	int seed_iter = 0;

	while (bpf_map_get_next_key(tracked_map_fd, &key, &next_key) == 0
	       && seed_iter++ < MAX_PROCS) {
		key = next_key;
		__u32 pid = key;

		char fd_dir[64];
		snprintf(fd_dir, sizeof(fd_dir), "/proc/%u/fd", pid);
		DIR *dd = opendir(fd_dir);
		if (!dd)
			continue;

		struct dirent *de;
		while ((de = readdir(dd)) != NULL) {
			if (de->d_type != DT_LNK && de->d_type != DT_UNKNOWN)
				continue;

			char link_path[128], target[128];
			snprintf(link_path, sizeof(link_path),
				 "/proc/%u/fd/%s", pid, de->d_name);
			ssize_t len = readlink(link_path, target,
					       sizeof(target) - 1);
			if (len <= 0)
				continue;
			target[len] = '\0';

			/* socket:[12345] → inode=12345 */
			if (strncmp(target, "socket:[", 8) != 0)
				continue;
			__u64 ino = (__u64)strtoull(target + 8, NULL, 10);
			if (ino == 0)
				continue;

			bpf_map_update_elem(seed_fd, &ino, &pid, BPF_NOEXIST);
			seeded++;
		}
		closedir(dd);
	}

	if (seeded == 0) {
		LOG_INFO("seed_sock_map: no socket inodes found");
		return;
	}

	/* Запускаем BPF iter/tcp */
	do {
		struct bpf_link *link = bpf_program__attach_iter(
			skel->progs.seed_sock_map_iter, NULL);
		if (!link) {
			LOG_WARN("seed_sock_map: attach_iter failed: %s",
			       strerror(errno));
			break;
		}

		int iter_fd = bpf_iter_create(bpf_link__fd(link));
		if (iter_fd < 0) {
			LOG_WARN("seed_sock_map: iter_create failed: %s",
			       strerror(errno));
			bpf_link__destroy(link);
			break;
		}

		/* Читаем до EOF — это запускает BPF-программу для каждого TCP-сокета */
		char drain[256];
		while (read(iter_fd, drain, sizeof(drain)) > 0)
			;

		close(iter_fd);
		bpf_link__destroy(link);

		LOG_INFO("seed_sock_map: scanned %d socket inodes", seeded);
	} while (0);

	/* Очищаем seed_inode_map */
	key = 0;
	__u64 ino_key = 0, ino_next;
	while (bpf_map_get_next_key(seed_fd, &ino_key, &ino_next) == 0) {
		bpf_map_delete_elem(seed_fd, &ino_next);
		ino_key = ino_next;
	}
}

static void initial_scan(void)
{
	LOG_INFO("initial scan: reading /proc...");

	DIR *pd = opendir("/proc");
	if (!pd) {
		LOG_WARN("cannot open /proc, skipping initial scan");
		return;
	}

	static struct scan_entry entries[MAX_SCAN];
	int count = 0;
	__u32 our_pid = (__u32)getpid();

	/* Проход 1: собираем все PID и ppid */
	struct dirent *de;
	while ((de = readdir(pd)) != NULL && count < MAX_SCAN) {
		if (de->d_type != DT_DIR && de->d_type != DT_UNKNOWN)
			continue;
		int pid = atoi(de->d_name);
		if (pid <= 0) continue;

		char path[PROC_PATH_LEN], buf[PROC_BUF_SMALL];
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

	/* Проход 1.5: заполняем глобальное дерево pid для ВСЕХ процессов */
	for (int i = 0; i < count; i++)
		pidtree_store(entries[i].pid, entries[i].ppid);

	/* Проход 2: сопоставляем cmdline с правилами, находим корневые процессы */
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
			/* Корневое совпадение */
			track_pid_from_proc(pid, first, pid, 1);
			tags_store_ts(pid, tags_buf);
			tracked++;
			LOG_DEBUG(cfg_log_level, "SCAN: pid=%u rule=%s tags=%s cmdline=%.60s",
				  pid, rules[first].name, tags_buf,
				  cmdline_str);

			/* Находим всех потомков */
			add_descendants(entries, count, pid, first, pid,
					&tracked);
		}
	}

	LOG_INFO("initial scan: %d processes scanned, %d tracked",
	       count, tracked);
}

/* ── обработчик событий кольцевого буфера ─────────────────────────── */

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
	if (type == EVENT_FILE_CLOSE || type == EVENT_FILE_OPEN) {
		if (size < sizeof(struct file_event))
			return 0;
		const struct file_event *fe = data;

		/* Единственный lookup — пропускаем, если процесс умер между open и close */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &fe->tgid, &ti) != 0)
			return 0;

		/* Имя правила по rule_id из track_info (O(1)) */
		const char *rname = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : RULE_NOT_MATCH;

		LOG_DEBUG(cfg_log_level, "FILE_CLOSE: pid=%u rule=%s path=%.60s "
			  "read=%llu write=%llu opens=%u",
			  fe->tgid, rname, fe->path,
			  (unsigned long long)fe->read_bytes,
			  (unsigned long long)fe->write_bytes,
			  fe->open_count);

		/* emit guard: проверяем нужно ли отправлять это событие в CSV */
		if (type == EVENT_FILE_OPEN  && !cfg_emit_file_open)  return 0;
		if (type == EVENT_FILE_CLOSE && !cfg_emit_file_close) return 0;

		if (g_http_cfg.enabled) {
			/* Формирование metric_event для записи в буфер */
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			/* Время: BPF boot_ns → wall clock через предвычисленное смещение */
			cev.timestamp_ns = fe->timestamp_ns
					 + (__u64)g_boot_to_wall_ns;
			fast_strcpy(cev.event_type, sizeof(cev.event_type),
				    type == EVENT_FILE_OPEN ? "file_open" : "file_close");
			fast_strcpy(cev.rule, sizeof(cev.rule), rname);

			/* Теги из userspace hash table (O(1)) */
			tags_lookup_ts(fe->tgid, cev.tags, sizeof(cev.tags));
			cev.root_pid = ti.root_pid;
			cev.is_root = ti.is_root;
			cev.pid = fe->tgid;
			cev.ppid = fe->ppid;
			cev.uid = fe->uid;
			memcpy(cev.comm, fe->comm, COMM_LEN);

			/* Identity из proc_map */
			{
				struct proc_info pi_file;
				if (bpf_map_lookup_elem(proc_map_fd,
							&fe->tgid, &pi_file) == 0) {
					cev.loginuid  = pi_file.loginuid;
					cev.sessionid = pi_file.sessionid;
					cev.euid      = pi_file.euid;
					cev.tty_nr    = pi_file.tty_nr;
				}
			}

			/* Cgroup из кэша — линейный поиск по ~50 записям, без syscall */
			resolve_cgroup_fast_ts(fe->cgroup_id,
					       cev.cgroup, sizeof(cev.cgroup));

			/* Файловые метрики: путь, флаги, прочитано/записано, кол-во открытий */
			fast_strcpy(cev.file_path, sizeof(cev.file_path),
				    fe->path);
			cev.file_flags = (__u32)fe->flags;
			cev.file_read_bytes = fe->read_bytes;
			cev.file_write_bytes = fe->write_bytes;
			cev.file_open_count = fe->open_count;
			cev.file_fsync_count = fe->fsync_count;

			pwd_lookup_ts(fe->tgid, cev.pwd, sizeof(cev.pwd));

			/* Запись в буферный файл (1× write syscall) */
			fill_parent_pids(&cev);
			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	/* ── FILE_RENAME / FILE_UNLINK / FILE_TRUNCATE / FILE_CHMOD / FILE_CHOWN */
	if (type == EVENT_FILE_RENAME || type == EVENT_FILE_UNLINK
	    || type == EVENT_FILE_TRUNCATE
	    || type == EVENT_FILE_CHMOD || type == EVENT_FILE_CHOWN) {
		/* emit guard */
		if (type == EVENT_FILE_RENAME   && !cfg_emit_file_rename)   return 0;
		if (type == EVENT_FILE_UNLINK   && !cfg_emit_file_unlink)   return 0;
		if (type == EVENT_FILE_TRUNCATE && !cfg_emit_file_truncate) return 0;
		if (type == EVENT_FILE_CHMOD    && !cfg_emit_file_chmod)    return 0;
		if (type == EVENT_FILE_CHOWN    && !cfg_emit_file_chown)    return 0;

		if (size < sizeof(struct file_event))
			return 0;
		const struct file_event *fe = data;

		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &fe->tgid, &ti) != 0)
			return 0;

		const char *rname = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : RULE_NOT_MATCH;

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			cev.timestamp_ns = fe->timestamp_ns
					 + (__u64)g_boot_to_wall_ns;

			const char *etype =
				type == EVENT_FILE_RENAME   ? "file_rename"   :
				type == EVENT_FILE_UNLINK   ? "file_unlink"   :
				type == EVENT_FILE_TRUNCATE ? "file_truncate" :
				type == EVENT_FILE_CHMOD    ? "file_chmod"    :
				type == EVENT_FILE_CHOWN    ? "file_chown"    :
				                              "file_unknown";
			fast_strcpy(cev.event_type, sizeof(cev.event_type), etype);
			fast_strcpy(cev.rule, sizeof(cev.rule), rname);
			tags_lookup_ts(fe->tgid, cev.tags, sizeof(cev.tags));

			cev.root_pid = ti.root_pid;
			cev.is_root  = ti.is_root;
			cev.pid  = fe->tgid;
			cev.ppid = fe->ppid;
			cev.uid  = fe->uid;
			memcpy(cev.comm, fe->comm, COMM_LEN);

			struct proc_info pi_mut;
			if (bpf_map_lookup_elem(proc_map_fd,
						&fe->tgid, &pi_mut) == 0) {
				cev.loginuid  = pi_mut.loginuid;
				cev.sessionid = pi_mut.sessionid;
				cev.euid      = pi_mut.euid;
				cev.tty_nr    = pi_mut.tty_nr;
			}

			resolve_cgroup_fast_ts(fe->cgroup_id,
					       cev.cgroup, sizeof(cev.cgroup));

			fast_strcpy(cev.file_path, sizeof(cev.file_path),
				    fe->path);
			cev.file_flags = (__u32)fe->flags;

			if (type == EVENT_FILE_RENAME) {
				fast_strcpy(cev.file_new_path,
					    sizeof(cev.file_new_path),
					    fe->path2);
			} else if (type == EVENT_FILE_TRUNCATE) {
				cev.file_write_bytes = fe->truncate_size;
			} else if (type == EVENT_FILE_CHMOD) {
				cev.file_chmod_mode = fe->chmod_mode;
			} else if (type == EVENT_FILE_CHOWN) {
				cev.file_chown_uid = fe->chown_uid;
				cev.file_chown_gid = fe->chown_gid;
			}

			pwd_lookup_ts(fe->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
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
	if (type == EVENT_NET_LISTEN || type == EVENT_NET_CONNECT
	    || type == EVENT_NET_ACCEPT || type == EVENT_NET_CLOSE) {
		/* emit guard */
		if (type == EVENT_NET_LISTEN  && !cfg_emit_net_listen)  return 0;
		if (type == EVENT_NET_CONNECT && !cfg_emit_net_connect) return 0;
		if (type == EVENT_NET_ACCEPT  && !cfg_emit_net_accept)  return 0;
		if (type == EVENT_NET_CLOSE   && !cfg_emit_net_close)   return 0;

		if (size < sizeof(struct net_event))
			return 0;
		const struct net_event *ne = data;

		/* Единственный lookup — пропускаем неотслеживаемые процессы */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &ne->tgid, &ti) != 0)
			return 0;

		/* Имя правила по rule_id (O(1)) */
		const char *rname = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : RULE_NOT_MATCH;

		const char *net_evt;
		switch (type) {
		case EVENT_NET_LISTEN:  net_evt = "net_listen";  break;
		case EVENT_NET_CONNECT: net_evt = "net_connect"; break;
		case EVENT_NET_ACCEPT:  net_evt = "net_accept";  break;
		default:                net_evt = "net_close";   break;
		}
		LOG_DEBUG(cfg_log_level, "%s: pid=%u rule=%s port=%u→%u "
			  "tx=%llu rx=%llu dur=%llums",
			  net_evt,
			  ne->tgid, rname, ne->local_port, ne->remote_port,
			  (unsigned long long)ne->tx_bytes,
			  (unsigned long long)ne->rx_bytes,
			  (unsigned long long)(ne->duration_ns / NS_PER_MS));

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			/* Время: BPF boot_ns → wall clock */
			cev.timestamp_ns = ne->timestamp_ns
					 + (__u64)g_boot_to_wall_ns;
			fast_strcpy(cev.event_type, sizeof(cev.event_type), net_evt);
			fast_strcpy(cev.rule, sizeof(cev.rule), rname);
			tags_lookup_ts(ne->tgid, cev.tags, sizeof(cev.tags));
			cev.root_pid = ti.root_pid;
			cev.is_root = ti.is_root;
			cev.pid = ne->tgid;
			cev.ppid = ne->ppid;
			cev.uid = ne->uid;
			memcpy(cev.comm, ne->comm, COMM_LEN);

			/* Identity из proc_map (loginuid, sessionid, euid, tty_nr) */
			{
				struct proc_info pi_net;
				if (bpf_map_lookup_elem(proc_map_fd,
							&ne->tgid, &pi_net) == 0) {
					cev.loginuid  = pi_net.loginuid;
					cev.sessionid = pi_net.sessionid;
					cev.euid      = pi_net.euid;
					cev.tty_nr    = pi_net.tty_nr;
				}
			}

			/* Cgroup из кэша */
			resolve_cgroup_fast_ts(ne->cgroup_id,
					       cev.cgroup, sizeof(cev.cgroup));

			/* Форматирование IP-адресов */
			if (ne->af == 2) { /* AF_INET — IPv4 */
				fmt_ipv4(cev.net_local_addr,
					 sizeof(cev.net_local_addr),
					 ne->local_addr);
				fmt_ipv4(cev.net_remote_addr,
					 sizeof(cev.net_remote_addr),
					 ne->remote_addr);
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
			cev.net_conn_tx_calls = ne->tx_calls;
			cev.net_conn_rx_calls = ne->rx_calls;
			cev.net_duration_ms = ne->duration_ns / NS_PER_MS;

			/* TCP state на момент close для net_close.
			 * Кодируем как символ для CSV:
			 * ESTABLISHED(1)→'I' (initiator), CLOSE_WAIT(8)→'R' (responder),
			 * остальные→числовой код */
			if (type == EVENT_NET_CLOSE && ne->tcp_state) {
				if (ne->tcp_state == 1) /* ESTABLISHED */
					cev.state = 'I'; /* initiator */
				else if (ne->tcp_state == 8) /* CLOSE_WAIT */
					cev.state = 'R'; /* responder */
				else
					cev.state = '0' + (ne->tcp_state % 10);
			}

			pwd_lookup_ts(ne->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
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
		if (!cfg_emit_signal) return 0;
		if (size < sizeof(struct signal_event))
			return 0;
		const struct signal_event *se = data;

		/* Определяем правило: сначала по отправителю, потом по получателю */
		struct track_info ti;
		const char *rname = RULE_NOT_MATCH;
		if (bpf_map_lookup_elem(tracked_map_fd, &se->sender_tgid, &ti) == 0)
			rname = (ti.rule_id < num_rules)
				? rules[ti.rule_id].name : RULE_NOT_MATCH;
		if (rname[0] == '?' && rname[1] == '\0') {
			if (bpf_map_lookup_elem(tracked_map_fd, &se->target_pid, &ti) == 0)
				rname = (ti.rule_id < num_rules)
					? rules[ti.rule_id].name : RULE_NOT_MATCH;
		}

		LOG_DEBUG(cfg_log_level, "SIGNAL: sender=%u→target=%u sig=%d code=%d result=%d "
			  "rule=%s comm=%.16s",
			  se->sender_tgid, se->target_pid, se->sig,
			  se->sig_code, se->sig_result, rname,
			  se->sender_comm);

		if (g_http_cfg.enabled) {
			char cg_buf[PATH_MAX_LEN];
			resolve_cgroup_fast_ts(se->cgroup_id, cg_buf, sizeof(cg_buf));
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));

			/* Время: clock_gettime (сигналы редкие, допустим syscall) */
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * NS_PER_SEC
					 + (__u64)ts_now.tv_nsec;
			fast_strcpy(cev.event_type, sizeof(cev.event_type),
				    "signal");
			fast_strcpy(cev.rule, sizeof(cev.rule), rname);

			/* Теги: сначала отправителя, потом получателя */
			char sig_tags[TAGS_MAX_LEN];
			tags_lookup_ts(se->sender_tgid, sig_tags, sizeof(sig_tags));
			if (!sig_tags[0])
				tags_lookup_ts(se->target_pid, sig_tags, sizeof(sig_tags));
			fast_strcpy(cev.tags, sizeof(cev.tags), sig_tags);

			/* Данные отправителя из tracked_map */
			if (bpf_map_lookup_elem(tracked_map_fd,
						&se->sender_tgid, &ti) == 0) {
				cev.root_pid = ti.root_pid;
				cev.is_root = ti.is_root;
			}
			cev.pid = se->sender_tgid;
			cev.uid = se->sender_uid;
			memcpy(cev.comm, se->sender_comm, COMM_LEN);
			if (cg_buf[0])
				fast_strcpy(cev.cgroup, sizeof(cev.cgroup),
					    cg_buf);

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
			char tcomm_path[PROC_PATH_LEN], tcomm_buf[COMM_LEN + 2];
			snprintf(tcomm_path, sizeof(tcomm_path),
				 "/proc/%u/comm", se->target_pid);
			FILE *tcf = fopen(tcomm_path, "r");
			if (tcf) {
				if (fgets(tcomm_buf, sizeof(tcomm_buf), tcf)) {
					tcomm_buf[strcspn(tcomm_buf, "\n")] = 0;
					fast_strcpy(cev.sig_target_comm,
						    sizeof(cev.sig_target_comm),
						    tcomm_buf);
				}
				fclose(tcf);
			}

			pwd_lookup_ts(se->sender_tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
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
		if (!cfg_emit_tcp_retransmit) return 0;
		if (size < sizeof(struct retransmit_event))
			return 0;
		const struct retransmit_event *re = data;

		LOG_DEBUG(cfg_log_level, "TCP_RETRANSMIT: pid=%u port=%u→%u state=%u",
			  re->tgid, re->local_port, re->remote_port,
			  re->state);

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			fast_strcpy(cev.rule, sizeof(cev.rule), RULE_NOT_MATCH);

			/* Время: clock_gettime (ретрансмиты редкие) */
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * NS_PER_SEC
					 + (__u64)ts_now.tv_nsec;
			fast_strcpy(cev.event_type, sizeof(cev.event_type),
				 "tcp_retrans");
			cev.pid = re->tgid;
			cev.uid = re->uid;
			memcpy(cev.comm, re->comm, COMM_LEN);
			resolve_cgroup_fast_ts(re->cgroup_id, cev.cgroup,
					       sizeof(cev.cgroup));

			/* Определяем правило, если процесс отслеживается */
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd,
						&re->tgid, &ti) == 0) {
				if (ti.rule_id < num_rules)
					fast_strcpy(cev.rule, sizeof(cev.rule),
						    rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				tags_lookup_ts(re->tgid, cev.tags,
					       sizeof(cev.tags));
			}

			/* Identity из proc_map */
			{
				struct proc_info pi_ret;
				if (bpf_map_lookup_elem(proc_map_fd,
							&re->tgid, &pi_ret) == 0) {
					cev.loginuid  = pi_ret.loginuid;
					cev.sessionid = pi_ret.sessionid;
					cev.euid      = pi_ret.euid;
					cev.tty_nr    = pi_ret.tty_nr;
				}
			}

			/* Адреса и порты TCP-соединения */
			cev.sec_af = re->af;
			cev.sec_local_port = re->local_port;
			cev.sec_remote_port = re->remote_port;
			cev.sec_tcp_state = re->state;
			if (re->af == 2) {
				fmt_ipv4(cev.sec_local_addr,
					 sizeof(cev.sec_local_addr),
					 re->local_addr);
				fmt_ipv4(cev.sec_remote_addr,
					 sizeof(cev.sec_remote_addr),
					 re->remote_addr);
			} else if (re->af == 10) {
				inet_ntop(AF_INET6, re->local_addr,
					  cev.sec_local_addr,
					  sizeof(cev.sec_local_addr));
				inet_ntop(AF_INET6, re->remote_addr,
					  cev.sec_remote_addr,
					  sizeof(cev.sec_remote_addr));
			}
			pwd_lookup_ts(re->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
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
		if (!cfg_emit_syn_recv) return 0;
		if (size < sizeof(struct syn_event))
			return 0;
		const struct syn_event *se_syn = data;

		LOG_DEBUG(cfg_log_level, "SYN_RECV: pid=%u port=%u←%u",
			  se_syn->tgid, se_syn->local_port,
			  se_syn->remote_port);

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			fast_strcpy(cev.rule, sizeof(cev.rule), RULE_NOT_MATCH);
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * NS_PER_SEC
					 + (__u64)ts_now.tv_nsec;
			fast_strcpy(cev.event_type, sizeof(cev.event_type),
				 "syn_recv");
			cev.pid = se_syn->tgid;
			cev.uid = se_syn->uid;
			memcpy(cev.comm, se_syn->comm, COMM_LEN);
			resolve_cgroup_fast_ts(se_syn->cgroup_id, cev.cgroup,
					       sizeof(cev.cgroup));
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd,
						&se_syn->tgid, &ti) == 0) {
				if (ti.rule_id < num_rules)
					fast_strcpy(cev.rule, sizeof(cev.rule),
						    rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				tags_lookup_ts(se_syn->tgid, cev.tags,
					       sizeof(cev.tags));
			}
			/* Identity из proc_map */
			{
				struct proc_info pi_syn;
				if (bpf_map_lookup_elem(proc_map_fd,
							&se_syn->tgid,
							&pi_syn) == 0) {
					cev.loginuid  = pi_syn.loginuid;
					cev.sessionid = pi_syn.sessionid;
					cev.euid      = pi_syn.euid;
					cev.tty_nr    = pi_syn.tty_nr;
				}
			}
			cev.sec_af = se_syn->af;
			cev.sec_local_port = se_syn->local_port;
			cev.sec_remote_port = se_syn->remote_port;
			if (se_syn->af == 2) {
				fmt_ipv4(cev.sec_local_addr,
					 sizeof(cev.sec_local_addr),
					 se_syn->local_addr);
				fmt_ipv4(cev.sec_remote_addr,
					 sizeof(cev.sec_remote_addr),
					 se_syn->remote_addr);
			} else if (se_syn->af == 10) {
				inet_ntop(AF_INET6, se_syn->local_addr,
					  cev.sec_local_addr,
					  sizeof(cev.sec_local_addr));
				inet_ntop(AF_INET6, se_syn->remote_addr,
					  cev.sec_remote_addr,
					  sizeof(cev.sec_remote_addr));
			}
			pwd_lookup_ts(se_syn->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
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
		if (!cfg_emit_rst) return 0;
		if (size < sizeof(struct rst_event))
			return 0;
		const struct rst_event *rste = data;

		LOG_DEBUG(cfg_log_level, "RST: pid=%u port=%u↔%u dir=%s",
			  rste->tgid, rste->local_port, rste->remote_port,
			  rste->direction ? "recv" : "sent");

		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			fast_strcpy(cev.rule, sizeof(cev.rule), RULE_NOT_MATCH);
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * NS_PER_SEC
					 + (__u64)ts_now.tv_nsec;
			fast_strcpy(cev.event_type, sizeof(cev.event_type),
				    rste->direction ? "rst_recv" : "rst_sent");
			cev.pid = rste->tgid;
			cev.uid = rste->uid;
			memcpy(cev.comm, rste->comm, COMM_LEN);
			resolve_cgroup_fast_ts(rste->cgroup_id, cev.cgroup,
					       sizeof(cev.cgroup));
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd,
						&rste->tgid, &ti) == 0) {
				if (ti.rule_id < num_rules)
					fast_strcpy(cev.rule, sizeof(cev.rule),
						    rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				tags_lookup_ts(rste->tgid, cev.tags,
					       sizeof(cev.tags));
			}
			/* Identity из proc_map */
			{
				struct proc_info pi_rst;
				if (bpf_map_lookup_elem(proc_map_fd,
							&rste->tgid,
							&pi_rst) == 0) {
					cev.loginuid  = pi_rst.loginuid;
					cev.sessionid = pi_rst.sessionid;
					cev.euid      = pi_rst.euid;
					cev.tty_nr    = pi_rst.tty_nr;
				}
			}
			cev.sec_af = rste->af;
			cev.sec_local_port = rste->local_port;
			cev.sec_remote_port = rste->remote_port;
			cev.sec_direction = rste->direction;
			if (rste->af == 2) {
				fmt_ipv4(cev.sec_local_addr,
					 sizeof(cev.sec_local_addr),
					 rste->local_addr);
				fmt_ipv4(cev.sec_remote_addr,
					 sizeof(cev.sec_remote_addr),
					 rste->remote_addr);
			} else if (rste->af == 10) {
				inet_ntop(AF_INET6, rste->local_addr,
					  cev.sec_local_addr,
					  sizeof(cev.sec_local_addr));
				inet_ntop(AF_INET6, rste->remote_addr,
					  cev.sec_remote_addr,
					  sizeof(cev.sec_remote_addr));
			}
			pwd_lookup_ts(rste->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
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
		/* Обновляем глобальное дерево pid (exec может быть первым появлением) */
		pidtree_store_ts(e->tgid, e->ppid);

		/* Уже отслеживается? BPF обновил proc_info, нам делать нечего */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0)
			return 0;

		/* Преобразуем cmdline из BPF (нуль-разделённые аргументы) в строку */
		char cmdline[CMDLINE_MAX + 1];
		cmdline_to_str(e->cmdline, e->cmdline_len, cmdline, sizeof(cmdline));

		/* Проверяем все правила (regexec × N правил) — тяжёлый, но exec редкий */
		char tags_buf[TAGS_MAX_LEN];
		int first = match_rules_all(
			cmdline,
			tags_buf,
			sizeof(tags_buf)
		);
		
		if (first >= 0 && !rules[first].ignore) {
			/* Совпадение — начинаем отслеживание */
			struct track_info new_ti = {
				.root_pid = e->tgid,
				.rule_id  = (__u16)first,
				.is_root  = 1,
			};
			bpf_map_update_elem(tracked_map_fd, &e->tgid,
					    &new_ti, BPF_ANY);
			tags_store_ts(e->tgid, tags_buf);
			pwd_read_and_store(e->tgid);

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

			LOG_DEBUG(cfg_log_level, "TRACK: pid=%u rule=%s tags=%s comm=%.16s",
				  e->tgid, rules[first].name, tags_buf,
				  e->comm);

			/* Отправляем exec-событие в буферный файл (→ ClickHouse) */
			if (cfg_emit_exec && g_http_cfg.enabled) {
				char cg_buf[PATH_MAX_LEN];
				resolve_cgroup_fast_ts(e->cgroup_id, cg_buf,
						       sizeof(cg_buf));
				struct metric_event cev;
				event_from_bpf(&cev, e, "exec",
					       rules[first].name,
					       tags_buf, cg_buf);
				cev.is_root = 1;
				pwd_lookup_ts(e->tgid, cev.pwd, sizeof(cev.pwd));
				fill_parent_pids(&cev);
				ef_append(&cev, cfg_hostname);
			}
		}
		return 0;
	}

	/* ── FORK — создание дочернего процесса ──────────────────────── */
	case EVENT_FORK: {
		/* Обновляем глобальное дерево pid (покрывает ВСЕ процессы) */
		pidtree_store_ts(e->tgid, e->ppid);

		/* BPF handle_fork уже создал tracked_map и proc_info записи.
		 * Здесь только наследуем tags (они живут в userspace hash table). */
		struct track_info parent_ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->ppid, &parent_ti) != 0)
			return 0;
		tags_inherit_ts(e->tgid, e->ppid);
		pwd_inherit_ts(e->tgid, e->ppid);

		/* tty_nr уже заполнен BPF (read_tty_nr в handle_fork) */
		__u32 child_tty = 0;
		{
			struct proc_info child_pi;
			if (bpf_map_lookup_elem(proc_map_fd, &e->tgid, &child_pi) == 0)
				child_tty = child_pi.tty_nr;
		}

		/* Отправляем fork-событие в буферный файл */
		if (cfg_emit_fork && g_http_cfg.enabled) {
			const char *rname = (parent_ti.rule_id < num_rules)
				? rules[parent_ti.rule_id].name : RULE_NOT_MATCH;
			char cg_buf[PATH_MAX_LEN];
			resolve_cgroup_fast_ts(e->cgroup_id, cg_buf,
					       sizeof(cg_buf));
			char fork_tags[TAGS_MAX_LEN];
			tags_lookup_ts(e->tgid, fork_tags, sizeof(fork_tags));
			struct metric_event cev;
			event_from_bpf(&cev, e, "fork", rname,
				       fork_tags, cg_buf);
			cev.root_pid = parent_ti.root_pid;
			cev.tty_nr = child_tty;
			pwd_lookup_ts(e->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
			ef_append(&cev, cfg_hostname);
		}
		return 0;
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
			? rules[exit_rule_id].name : RULE_NOT_MATCH;

		char exit_tags[TAGS_MAX_LEN];
#ifdef NO_TAGS
		exit_tags[0] = '\0';
#else
		/* ┌───────────────────────────────────────────────────────────┐
		 * │  ОПТИМИЗАЦИЯ 3: Объединённый lock для EXIT-обработчика   │
		 * ├───────────────────────────────────────────────────────────┤
		 * │  Все tags-операции EXIT (lookup, inherit, remove)        │
		 * │  выполняются под ОДНИМ wrlock вместо отдельных           │
		 * │  lock/unlock циклов для каждой операции.                 │
		 * │  Используем bare-функции (без _ts), т.к. wrlock         │
		 * │  уже взят вручную.                                       │
		 * └───────────────────────────────────────────────────────────┘ */
		pthread_rwlock_wrlock(&g_tags_lock);
		{
			const char *t = tags_lookup(e->tgid);
			if (!t[0]) {
				tags_inherit(e->tgid, e->ppid);
				t = tags_lookup(e->tgid);
			}
			snprintf(exit_tags, sizeof(exit_tags), "%s", t);
			/* НЕ удаляем tags — snapshot зачистит вместе с картами */
		}
		pthread_rwlock_unlock(&g_tags_lock);
#endif

		/* Декодирование кода завершения: сигнал (младшие 7 бит) + статус */
		int sig = e->exit_code & EXIT_SIG_MASK;
		int status = (e->exit_code >> EXIT_STATUS_SHIFT) & EXIT_STATUS_MASK;

		LOG_DEBUG(cfg_log_level, "EXIT: pid=%u rule=%s exit_code=%d "
			  "signal=%d cpu=%.2fs rss_max=%lluMB%s",
			  e->tgid, rname, status, sig,
			  (double)e->cpu_ns / 1e9,
			  (unsigned long long)(e->rss_max_pages * 4 / 1024),
			  e->oom_killed ? " [OOM]" : "");

		/* Отправляем exit-событие в буферный файл */
		if (cfg_emit_exit && g_http_cfg.enabled) {
			char cg_buf[PATH_MAX_LEN];
			resolve_cgroup_fast_ts(e->cgroup_id, cg_buf,
					       sizeof(cg_buf));
			struct metric_event cev;
			event_from_bpf(&cev, e, "exit", rname, exit_tags, cg_buf);
			pwd_lookup_ts(e->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
			ef_append(&cev, cfg_hostname);
		}
		/* Карты и кэши НЕ удаляем — proc_info помечен status=EXITED,
		 * snapshot запишет финальный слепок и зачистит всё.
		 * pidtree тоже НЕ удаляем — нужен для цепочек до снапшота. */
		return 0;
	}

	/* ── CHDIR — смена рабочего каталога ─────────────────────────── */
	case EVENT_CHDIR: {
		char cwd_path[PROC_PATH_LEN], pwd_buf[EV_PWD_LEN];
		snprintf(cwd_path, sizeof(cwd_path), "/proc/%u/cwd", e->tgid);
		ssize_t len = readlink(cwd_path, pwd_buf, sizeof(pwd_buf) - 1);
		if (len > 0) {
			pwd_buf[len] = '\0';
			pwd_store_ts(e->tgid, pwd_buf);
		}
		return 0;
	}

	/* ── OOM_KILL — убийство процесса OOM killer ─────────────────── */
	case EVENT_OOM_KILL: {
		/* Пробуем определить правило: сначала по PID, потом по родителю */
		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) != 0)
			try_track_pid(e->tgid);
		const char *rname = RULE_NOT_MATCH;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->tgid, &ti) == 0)
			rname = (ti.rule_id < num_rules)
				? rules[ti.rule_id].name : RULE_NOT_MATCH;
		if (rname[0] == '?' && rname[1] == '\0') {
			if (bpf_map_lookup_elem(tracked_map_fd, &e->ppid, &ti) == 0)
				rname = (ti.rule_id < num_rules)
					? rules[ti.rule_id].name : RULE_NOT_MATCH;
		}
		LOG_WARN("OOM_KILL: pid=%u rule=%s comm=%.16s "
		       "rss=%lluMB",
		       e->tgid, rname, e->comm,
		       (unsigned long long)(e->rss_pages * 4 / 1024));

		/* Отправляем oom_kill-событие в буферный файл */
		if (cfg_emit_oom_kill && g_http_cfg.enabled) {
			char cg_buf[PATH_MAX_LEN];
			resolve_cgroup_fast_ts(e->cgroup_id, cg_buf,
					       sizeof(cg_buf));
			char oom_tags[TAGS_MAX_LEN];
			tags_lookup_ts(e->tgid, oom_tags, sizeof(oom_tags));
			struct metric_event cev;
			event_from_bpf(&cev, e, "oom_kill", rname,
				       oom_tags, cg_buf);
			pwd_lookup_ts(e->tgid, cev.pwd, sizeof(cev.pwd));
			fill_parent_pids(&cev);
			ef_append(&cev, cfg_hostname);
		}
		return 0;
	}

	default:
		return 0;
	}

	return 0;
}


/* ── снапшот: сбор метрик ─────────────────────────────────────────── */

/*
 * Чтение значения из cgroup sysfs.
 * Используем raw open/read/close вместо fopen/fclose.
 * fclose() на kernfs файлах тригерит cgroup_file_release → deferred fput
 * через task_work, что блокирует поток на synchronize_rcu при возврате
 * из syscall. При ~350 fclose за snapshot — блокировка ~7 секунд.
 * Raw close() не создаёт такой проблемы.
 */
static long long read_cgroup_value(const char *cg_path, const char *file)
{
	char path[PATH_MAX_LEN];
	snprintf(path, sizeof(path), CGROUP_V2_PATH "/%s/%s", cg_path, file);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	char buf[PROC_VAL_LEN];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	if (strncmp(buf, "max", 3) == 0)
		return 0;
	return strtoll(buf, NULL, 10);
}

/*
 * Чтение cpu.max: "$MAX $PERIOD" или "max $PERIOD".
 * Устанавливает *quota (мкс, 0 если "max") и *period (мкс).
 */
static void read_cgroup_cpu_max(const char *cg_path,
				long long *quota, long long *period)
{
	*quota = -1;
	*period = -1;
	char path[PATH_MAX_LEN];
	snprintf(path, sizeof(path), CGROUP_V2_PATH "/%s/cpu.max", cg_path);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	char buf[PROC_VAL_LEN];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	if (strncmp(buf, "max", 3) == 0) {
		*quota = 0;
		if (sscanf(buf + 3, " %lld", period) != 1)
			*period = DEFAULT_CPU_MAX_PERIOD;
	} else {
		if (sscanf(buf, "%lld %lld", quota, period) != 2) {
			*quota = -1;
			*period = -1;
		}
	}
}

/*
 * Чтение cpu.stat: парсинг nr_periods, nr_throttled, throttled_usec.
 */
static void read_cgroup_cpu_stat(const char *cg_path,
				 long long *nr_periods,
				 long long *nr_throttled,
				 long long *throttled_usec)
{
	*nr_periods = -1;
	*nr_throttled = -1;
	*throttled_usec = -1;
	char path[PATH_MAX_LEN];
	snprintf(path, sizeof(path), CGROUP_V2_PATH "/%s/cpu.stat", cg_path);
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	/* cpu.stat ~200 байт: "usage_usec ...\nnr_periods ...\n..." */
	char buf[PROC_BUF_SMALL];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	/* Парсим построчно из буфера */
	char *p = buf;
	while (*p) {
		if (strncmp(p, "nr_periods ", 11) == 0)
			*nr_periods = strtoll(p + 11, NULL, 10);
		else if (strncmp(p, "nr_throttled ", 13) == 0)
			*nr_throttled = strtoll(p + 13, NULL, 10);
		else if (strncmp(p, "throttled_usec ", 15) == 0)
			*throttled_usec = strtoll(p + 15, NULL, 10);
		/* Переход к следующей строке */
		while (*p && *p != '\n') p++;
		if (*p == '\n') p++;
	}
}

/*
 * Генерация событий disk_usage для каждой уникальной реальной файловой системы.
 * Читает /proc/mounts, применяет фильтры fs_type/include/exclude,
 * дедуплицирует по устройству, вызывает statvfs().
 */
static int emit_disk_usage_events(__u64 timestamp_ns, const char *hostname)
{
	/* Типы ФС по умолчанию, если не заданы в конфигурации */
	static const char *default_fs[] = {
		"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat",
		"zfs", "ntfs", "fuseblk", "f2fs", NULL
	};

	FILE *mf = setmntent(PROC_MOUNTS_PATH, "r");
	if (!mf)
		return 0;

	char seen_devs[DISK_MAX_DEVS][DISK_DEV_NAME_LEN];
	int seen_count = 0;
	int disk_count = 0;

	struct mntent *ent;
	while ((ent = getmntent(mf)) != NULL) {
		/* Фильтрация по типу файловой системы */
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

		/* Фильтр исключения (префикс точки монтирования) */
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

		/* Фильтр включения (префикс точки монтирования) — если задан, только совпадающие */
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

		/* Пропускаем дублирующиеся устройства */
		int dup = 0;
		for (int i = 0; i < seen_count; i++) {
			if (strcmp(seen_devs[i], ent->mnt_fsname) == 0) {
				dup = 1;
				break;
			}
		}
		if (dup)
			continue;
		if (seen_count < DISK_MAX_DEVS)
			snprintf(seen_devs[seen_count++], DISK_DEV_NAME_LEN,
				 "%s", ent->mnt_fsname);

		struct statvfs svfs;
		if (statvfs(ent->mnt_dir, &svfs) != 0)
			continue;

		struct metric_event cev;
		memset(&cev, 0, sizeof(cev));
		fast_strcpy(cev.rule, sizeof(cev.rule), RULE_NOT_MATCH);
		cev.timestamp_ns = timestamp_ns;
		snprintf(cev.event_type, sizeof(cev.event_type), "disk_usage");

		/* точка монтирования */
		snprintf(cev.file_path, sizeof(cev.file_path),
			 "%s", ent->mnt_dir);

		/* имя устройства (basename) в comm */
		const char *devname = strrchr(ent->mnt_fsname, '/');
		devname = devname ? devname + 1 : ent->mnt_fsname;
		snprintf(cev.comm, sizeof(cev.comm), "%s", devname);

		/* тип ФС */
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

#ifndef NO_TAGS
/*
 * Поиск тегов в локальной копии (без lock).
 * snap_tgid/snap_data — snapshot, сделанный через memcpy под кратким rdlock
 * в начале write_snapshot (см. ОПТИМИЗАЦИЯ 4).
 * Вызывается десятки раз за snapshot — без locks, т.к. работает с копией.
 */
static const char *tags_lookup_copy(const __u32 *snap_tgid,
				    const char snap_data[][TAGS_MAX_LEN],
				    __u32 tgid)
{
	__u32 idx = tags_hash(tgid);
	for (int i = 0; i < TAGS_HT_SIZE; i++) {
		__u32 slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (snap_tgid[slot] == tgid)
			return snap_data[slot];
		if (snap_tgid[slot] == 0)
			return "";
	}
	return "";
}
#endif

/*
 * refresh_processes — тяжёлый I/O: обновление /proc, cgroup sysfs, flush агрегатов.
 *
 * Вызывается с периодом cfg_refresh_interval (≤ cfg_snapshot_interval).
 * Обновляет:
 *   - cmdline/comm из /proc (если cfg_refresh_proc=1)
 *   - cgroup-метрики из /sys/fs/cgroup → cg_metrics[]
 *   - Обнаружение мёртвых процессов (fallback kill(pid,0) для потерянных EXIT)
 *   - Flush UDP/ICMP агрегатов → ef_append
 *   - Disk usage → ef_append
 */
static int flush_dead_keys(__u32 *keys, int count);
static void refresh_processes(void)
{
	refresh_boot_to_wall();

	/* ── Drain missed_exec_map: восстановление процессов, потерянных
	 * при ring buffer drop в handle_exec. BPF сохранил tgid→ppid,
	 * здесь читаем cmdline из /proc и сопоставляем с правилами. */
	{
		__u32 tgid, next_tgid, ppid;
		int err = bpf_map_get_next_key(missed_exec_fd, NULL, &tgid);
		while (err == 0) {
			/* Сохраняем следующий ключ до удаления текущего */
			int has_next = (bpf_map_get_next_key(missed_exec_fd,
					&tgid, &next_tgid) == 0);

			if (bpf_map_lookup_elem(missed_exec_fd, &tgid,
						&ppid) == 0) {
				bpf_map_delete_elem(missed_exec_fd, &tgid);
				pidtree_store_ts(tgid, ppid);
				/* try_track_pid читает /proc/pid/cmdline,
				 * сопоставляет с правилами и при совпадении
				 * создаёт tracked_map + proc_info + tags */
				int rule = try_track_pid(tgid);
				if (rule >= 0) {
					pwd_read_and_store(tgid);
					LOG_INFO("EXEC_RECOVERY: pid=%u ppid=%u"
					       " rule=%s (ring buffer drop)",
					       tgid, ppid,
					       rules[rule].name);
				}
			}

			if (!has_next)
				break;
			tgid = next_tgid;
			err = 0;
		}
	}

	/* Пакетное чтение proc_map.
	 * all_values может быть NULL если malloc не удался (proc_info
	 * = 4400 байт * 65536 = 275 MB) — тогда читаем только ключи
	 * и делаем поштучный lookup в цикле ниже. */
	__u32 *all_keys = NULL;
	struct proc_info *all_values = NULL;
	int all_keys_count = 0;

	do {
		__u32 batch_count = MAX_PROCS;
		all_keys = malloc(batch_count * sizeof(__u32));
		if (!all_keys)
			break;

		all_values = malloc(batch_count * sizeof(struct proc_info));

		if (all_values) {
			DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
				.elem_flags = 0, .flags = 0,
			);
			__u32 out_batch = 0;
			int ret = bpf_map_lookup_batch(proc_map_fd,
				NULL, &out_batch,
				all_keys, all_values, &batch_count, &opts);
			if (ret == 0 || (ret < 0 && errno == ENOENT)) {
				all_keys_count = (int)batch_count;
			} else {
				free(all_values);
				all_values = NULL;
			}
		}

		/* Fallback: keys-only через get_next_key (no 275MB alloc) */
		if (all_keys_count == 0) {
			__u32 iter_key;
			int err2 = bpf_map_get_next_key(proc_map_fd,
						NULL, &iter_key);
			while (err2 == 0 && all_keys_count < (int)MAX_PROCS) {
				all_keys[all_keys_count++] = iter_key;
				err2 = bpf_map_get_next_key(proc_map_fd,
						&iter_key, &iter_key);
			}
		}
	} while (0);

	/* Сброс cgroup-метрик — будут пересобраны ниже */
	cg_metrics_count = 0;

	int refresh_count = 0;
	int early_cleanup_count = 0;

	/* Буфер для раннего удаления мёртвых процессов.
	 * Процессы со status=EXITED уже были зафиксированы в предыдущем
	 * write_snapshot (или ещё не были — тогда write_snapshot их увидит).
	 * Удаляем сразу, чтобы не итерировать 65K мёртвых записей каждый
	 * refresh_interval. */
	__u32 early_dead[DEAD_KEYS_CAP];
	int early_dead_count = 0;

	for (int ki = 0; ki < all_keys_count; ki++) {
		__u32 key = all_keys[ki];
		struct proc_info pi;

		if (all_values) {
			pi = all_values[ki];
		} else {
			if (bpf_map_lookup_elem(proc_map_fd, &key, &pi) != 0)
				continue;
		}

		/* Уже помечен EXITED (BPF handle_exit или предыдущий refresh) —
		 * удаляем из карт сразу, не тратя syscall на kill/cmdline/comm.
		 * write_snapshot при следующем вызове его уже не увидит, но
		 * exit-событие уже было эмитировано через ring buffer. */
		if (pi.status != PROC_STATUS_ALIVE) {
			if (early_dead_count >= DEAD_KEYS_CAP) {
				early_cleanup_count +=
					flush_dead_keys(early_dead,
							early_dead_count);
				early_dead_count = 0;
			}
			early_dead[early_dead_count++] = key;
			continue;
		}

		/* Fallback для потерянных EXIT: kill → ESRCH при status=ALIVE.
		 * Удаляем сразу — при fork storm'ах откладывание на следующий
		 * цикл приводит к накоплению мёртвых записей. Exit-событие
		 * из ring buffer уже содержит финальные метрики от BPF. */
		if (kill((pid_t)key, 0) != 0 && errno == ESRCH) {
			if (early_dead_count >= DEAD_KEYS_CAP) {
				early_cleanup_count +=
					flush_dead_keys(early_dead,
							early_dead_count);
				early_dead_count = 0;
			}
			early_dead[early_dead_count++] = key;
			continue;
		}

		/* Обновляем cmdline/comm только для живых процессов */
		if (cfg_refresh_proc) {
			char fresh[CMDLINE_MAX];
			int flen = read_proc_cmdline(key, fresh, sizeof(fresh));
			if (flen > 0) {
				memcpy(pi.cmdline, fresh, CMDLINE_MAX);
				pi.cmdline_len = (__u16)flen;
				bpf_map_update_elem(proc_map_fd, &key, &pi,
						    BPF_EXIST);
			}
			char cpath[LINE_BUF_LEN];
			snprintf(cpath, sizeof(cpath), "/proc/%u/comm", key);
			FILE *cf = fopen(cpath, "r");
			if (cf) {
				char cbuf[COMM_LEN];
				if (fgets(cbuf, sizeof(cbuf), cf)) {
					cbuf[strcspn(cbuf, "\n")] = '\0';
					memcpy(pi.comm, cbuf, COMM_LEN);
					bpf_map_update_elem(proc_map_fd, &key,
							    &pi, BPF_EXIST);
				}
				fclose(cf);
			}
		}

		/* Обновление ppid из /proc — обнаружение reparent.
		 * Когда ядро убивает промежуточный процесс в цепочке,
		 * дочерние процессы переназначаются на init (или subreaper).
		 * BPF не получает уведомлений о reparent, поэтому pidtree
		 * и proc_info.ppid устаревают. Здесь сверяем с реальностью.
		 * Не зависит от cfg_refresh_proc — это вопрос корректности
		 * дерева процессов, а не опциональное обновление cmdline. */
		{
			__u32 real_ppid = read_proc_ppid(key);
			if (real_ppid > 0 && real_ppid != pi.ppid) {
				LOG_DEBUG(cfg_log_level, "REPARENT: pid=%u ppid %u→%u",
					  key, pi.ppid, real_ppid);
				pi.ppid = real_ppid;
				bpf_map_update_elem(proc_map_fd, &key,
						    &pi, BPF_EXIST);
				pidtree_store_ts(key, real_ppid);
			}
		}

		/* Сбор уникальных cgroup → cg_metrics[] */
		if (cfg_cgroup_metrics) {
			char cg_path[PATH_MAX_LEN], cg_fs_path[PATH_MAX_LEN];
			resolve_cgroup_ts(pi.cgroup_id, cg_path,
					  sizeof(cg_path));
			if (cg_path[0] && cg_metrics_count < MAX_CGROUPS) {
				/* Проверяем, уже есть ли в кэше */
				int found = 0;
				for (int i = 0; i < cg_metrics_count; i++) {
					if (strcmp(cg_metrics[i].path,
						   cg_path) == 0) {
						found = 1;
						break;
					}
				}
				if (!found) {
					resolve_cgroup_fs_ts(pi.cgroup_id,
							     cg_fs_path,
							     sizeof(cg_fs_path));
					int idx = cg_metrics_count;
					snprintf(cg_metrics[idx].path,
						 sizeof(cg_metrics[0].path),
						 "%s", cg_path);
					cg_metrics[idx].valid = 0;
					if (cg_fs_path[0]) {
						cg_metrics[idx].mem_max =
							read_cgroup_value(cg_fs_path, "memory.max");
						cg_metrics[idx].mem_cur =
							read_cgroup_value(cg_fs_path, "memory.current");
						cg_metrics[idx].swap_cur =
							read_cgroup_value(cg_fs_path, "memory.swap.current");
						cg_metrics[idx].cpu_weight =
							read_cgroup_value(cg_fs_path, "cpu.weight");
						read_cgroup_cpu_max(cg_fs_path,
							&cg_metrics[idx].cpu_max,
							&cg_metrics[idx].cpu_max_period);
						read_cgroup_cpu_stat(cg_fs_path,
							&cg_metrics[idx].cpu_nr_periods,
							&cg_metrics[idx].cpu_nr_throttled,
							&cg_metrics[idx].cpu_throttled_usec);
						cg_metrics[idx].pids_cur =
							read_cgroup_value(cg_fs_path, "pids.current");
						cg_metrics[idx].valid = 1;
					}
					cg_metrics_count++;
				}
			}
		}

		refresh_count++;
	}

	/* Flush оставшихся early_dead записей */
	early_cleanup_count += flush_dead_keys(early_dead, early_dead_count);

	free(all_keys);
	free(all_values);

	/* Обновляем глобальный счётчик для адаптивного refresh_interval */
	g_last_map_count = all_keys_count;

	LOG_DEBUG(cfg_log_level, "refresh: %d alive, %d early cleanup, %d total proc_map entries",
		  refresh_count, early_cleanup_count, all_keys_count);

	/* Flush UDP агрегатов → ef_append */
	if (cfg_udp_bytes && cfg_emit_udp_agg && g_http_cfg.enabled) {
		struct timespec now_ts;
		clock_gettime(CLOCK_REALTIME, &now_ts);
		__u64 ts_ns = (__u64)now_ts.tv_sec * NS_PER_SEC
			    + (__u64)now_ts.tv_nsec;

		int udp_fd = bpf_map__fd(skel->maps.udp_agg_map);
		struct udp_agg_key ukey;
		struct udp_agg_val uval;
		int udp_count = 0;

		while (bpf_map_get_next_key(udp_fd, NULL, &ukey) == 0) {
			if (bpf_map_lookup_elem(udp_fd, &ukey, &uval) == 0
			    && (uval.tx_packets || uval.rx_packets)) {
				struct metric_event cev;
				memset(&cev, 0, sizeof(cev));
				snprintf(cev.rule, sizeof(cev.rule), "%s",
					 RULE_NOT_MATCH);
				cev.timestamp_ns = ts_ns;
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
					cev.uid       = upi.uid;
					cev.loginuid  = upi.loginuid;
					cev.sessionid = upi.sessionid;
					cev.euid      = upi.euid;
					cev.tty_nr    = upi.tty_nr;
					resolve_cgroup_ts(upi.cgroup_id,
							  cev.cgroup,
							  sizeof(cev.cgroup));
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
				}
				pwd_lookup_ts(ukey.tgid, cev.pwd,
					      sizeof(cev.pwd));
				fill_parent_pids(&cev);
				ef_append(&cev, cfg_hostname);
				udp_count++;
			}
			bpf_map_delete_elem(udp_fd, &ukey);
		}
		if (udp_count > 0)
			LOG_DEBUG(cfg_log_level, "UDP flush: %d aggregates", udp_count);
	}

	/* Flush ICMP агрегатов → ef_append */
	if (cfg_icmp_tracking && g_http_cfg.enabled) {
		struct timespec now_ts;
		clock_gettime(CLOCK_REALTIME, &now_ts);
		__u64 ts_ns = (__u64)now_ts.tv_sec * NS_PER_SEC
			    + (__u64)now_ts.tv_nsec;

		int icmp_fd = bpf_map__fd(skel->maps.icmp_agg_map);
		struct icmp_agg_key ikey;
		struct icmp_agg_val ival;
		int icmp_count = 0;

		while (bpf_map_get_next_key(icmp_fd, NULL, &ikey) == 0) {
			if (bpf_map_lookup_elem(icmp_fd, &ikey, &ival) == 0
			    && ival.count > 0) {
				struct metric_event cev;
				memset(&cev, 0, sizeof(cev));
				snprintf(cev.rule, sizeof(cev.rule), "%s",
					 RULE_NOT_MATCH);
				cev.timestamp_ns = ts_ns;
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
				fill_parent_pids(&cev);
				ef_append(&cev, cfg_hostname);
				icmp_count++;
			}
			bpf_map_delete_elem(icmp_fd, &ikey);
		}
		if (icmp_count > 0)
			LOG_DEBUG(cfg_log_level, "ICMP flush: %d aggregates", icmp_count);
	}

	/* Disk usage → ef_append */
	if (g_http_cfg.enabled && cfg_disk_tracking_enabled) {
		struct timespec now_ts;
		clock_gettime(CLOCK_REALTIME, &now_ts);
		__u64 ts_ns = (__u64)now_ts.tv_sec * NS_PER_SEC
			    + (__u64)now_ts.tv_nsec;
		int disk_ev = emit_disk_usage_events(ts_ns, cfg_hostname);
		if (disk_ev > 0)
			LOG_DEBUG(cfg_log_level, "disk refresh: %d events", disk_ev);
	}

	if (cfg_log_refresh)
		LOG_INFO("refresh: %d PIDs, %d cgroups",
		       refresh_count, cg_metrics_count);
}

/*
 * write_snapshot — лёгкий слепок: собрать из кэшей/карт, записать в event_file.
 *
 * Без файлового I/O. Все тяжёлые данные уже обновлены refresh_processes().
 * Единственные syscall: bpf_map_lookup_batch (1×), bpf_map_lookup_elem (per-PID),
 * ef_append (write в memory-mapped ring).
 */

/*
 * flush_dead_keys — пакетное удаление мёртвых процессов из BPF-карт и userspace-кэшей.
 *
 * Использует bpf_map_delete_batch для удаления из tracked_map и proc_map
 * за 2 syscall вместо 2*count. Если batch delete не поддерживается ядром
 * (< 5.6), fallback на поштучное удаление.
 *
 * Возвращает количество удалённых ключей.
 */
static int flush_dead_keys(__u32 *keys, int count)
{
	if (count <= 0)
		return 0;

	/* Удаляем из обеих карт. Используем bpf_map_delete_batch где
	 * возможно — это 1 syscall вместо N. При ошибке (ключ уже удалён
	 * BPF handle_exit) batch может вернуть частичный результат —
	 * это нормально, дочищаем остаток поштучно.
	 *
	 * Порядок: сначала proc_map, потом tracked_map.
	 * proc_map — источник ключей для refresh iteration (batch read),
	 * tracked_map — lookup по ключу. Если proc_map удалён а
	 * tracked_map нет — tracked_map "сирота" без последствий
	 * (cleanup через write_snapshot). Если наоборот — proc_map
	 * запись без tracked_map вызывает kill→ESRCH→delete loop. */
	for (int i = 0; i < count; i++)
		bpf_map_delete_elem(proc_map_fd, &keys[i]);
	for (int i = 0; i < count; i++)
		bpf_map_delete_elem(tracked_map_fd, &keys[i]);

	/* Userspace-кэши */
	for (int i = 0; i < count; i++) {
		cpu_prev_remove(keys[i]);
		pwd_remove_ts(keys[i]);
		tags_remove_ts(keys[i]);
		pidtree_remove_ts(keys[i]);
	}

	return count;
}

static void write_snapshot(void)
{
	/* ── Восстановление после ring buffer drop на FORK ────────────
	 * BPF handle_fork создаёт tracked_map + proc_map ДО резервирования
	 * ring buffer. Если bpf_ringbuf_reserve не удался, userspace не
	 * получил fork-событие и не вызвал pidtree_store_ts / tags_inherit_ts /
	 * pwd_inherit_ts. Детектируем это по отсутствию pid в pidtree
	 * и восстанавливаем наследование от родителя.
	 */
	{
		__u32 key;
		int fork_rec_iter = 0;
		int err = bpf_map_get_next_key(tracked_map_fd, NULL, &key);
		while (err == 0 && fork_rec_iter++ < MAX_PROCS) {
			__u32 next;
			int next_err = bpf_map_get_next_key(tracked_map_fd,
							    &key, &next);

			/* Быстрая проверка: есть ли pid в pidtree? */
			pthread_rwlock_rdlock(&g_pidtree_lock);
			__u32 ppid_in_tree = pidtree_lookup_in(pt_pid, pt_ppid,
							       key);
			pthread_rwlock_unlock(&g_pidtree_lock);

			if (ppid_in_tree == 0) {
				/* Нет в pidtree → fork-событие было потеряно.
				 * Берём ppid из proc_info и восстанавливаем. */
				struct proc_info pi;
				if (bpf_map_lookup_elem(proc_map_fd, &key,
							&pi) == 0 &&
				    pi.ppid > 0) {
					pidtree_store_ts(key, pi.ppid);
					tags_inherit_ts(key, pi.ppid);
					pwd_inherit_ts(key, pi.ppid);
					LOG_DEBUG(cfg_log_level, "FORK_RECOVERY: pid=%u ppid=%u"
						  " (ring buffer drop)",
						  key, pi.ppid);
				}
			}

			if (next_err != 0)
				break;
			key = next;
		}
	}

#ifndef NO_TAGS
	/* ОПТИМИЗАЦИЯ 4: копируем tags под кратким rdlock */
	static __u32 snap_tgid[TAGS_HT_SIZE];
	static char  snap_data[TAGS_HT_SIZE][TAGS_MAX_LEN];
	pthread_rwlock_rdlock(&g_tags_lock);
	memcpy(snap_tgid, tags_tgid, sizeof(tags_tgid));
	memcpy(snap_data, tags_data, sizeof(tags_data));
	pthread_rwlock_unlock(&g_tags_lock);
#endif

	/* Snapshot pid tree для цепочек предков (512 КБ, ~0.1ms) */
	static __u32 snap_pt_pid[PIDTREE_HT_SIZE];
	static __u32 snap_pt_ppid[PIDTREE_HT_SIZE];
	pthread_rwlock_rdlock(&g_pidtree_lock);
	memcpy(snap_pt_pid, pt_pid, sizeof(pt_pid));
	memcpy(snap_pt_ppid, pt_ppid, sizeof(pt_ppid));
	pthread_rwlock_unlock(&g_pidtree_lock);

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = FALLBACK_PAGE_SIZE;

	struct timespec mono;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	double mono_now = (double)mono.tv_sec + (double)mono.tv_nsec / 1e9;

	double elapsed_ns = 0;
	if (prev_snapshot_ts.tv_sec > 0) {
		elapsed_ns = (double)(mono.tv_sec - prev_snapshot_ts.tv_sec) * 1e9
			   + (double)(mono.tv_nsec - prev_snapshot_ts.tv_nsec);
	}
	prev_snapshot_ts = mono;

	struct timespec snap_ts;
	clock_gettime(CLOCK_REALTIME, &snap_ts);
	__u64 snap_timestamp_ns = (__u64)snap_ts.tv_sec * NS_PER_SEC
				+ (__u64)snap_ts.tv_nsec;

	__u32 dead_keys[DEAD_KEYS_CAP];
	int dead_count = 0;
	int dead_total = 0;
	int pid_count = 0, snap_count = 0;

	ef_batch_lock();

	/* Пакетное чтение proc_map */
	__u32 *all_keys = NULL;
	struct proc_info *all_values = NULL;
	int all_keys_count = 0;

	{
		__u32 batch_count = MAX_PROCS;
		all_keys = malloc(batch_count * sizeof(__u32));
		all_values = malloc(batch_count * sizeof(struct proc_info));

		if (all_keys && all_values) {
			DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
				.elem_flags = 0, .flags = 0,
			);
			__u32 out_batch = 0;
			int ret = bpf_map_lookup_batch(proc_map_fd,
				NULL, &out_batch,
				all_keys, all_values, &batch_count, &opts);
			if (ret == 0 || (ret < 0 && errno == ENOENT)) {
				all_keys_count = (int)batch_count;
			} else {
				all_keys_count = 0;
				__u32 iter_key;
				int err2 = bpf_map_get_next_key(proc_map_fd,
							NULL, &iter_key);
				while (err2 == 0 && all_keys_count < (int)MAX_PROCS) {
					all_keys[all_keys_count++] = iter_key;
					err2 = bpf_map_get_next_key(proc_map_fd,
							&iter_key, &iter_key);
				}
				free(all_values);
				all_values = NULL;
			}
		}
	}

	for (int ki = 0; ki < all_keys_count; ki++) {
		__u32 key = all_keys[ki];
		struct proc_info pi;

		if (all_values) {
			pi = all_values[ki];
		} else {
			if (bpf_map_lookup_elem(proc_map_fd, &key, &pi) != 0)
				continue;
		}

		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &key, &ti) != 0)
			continue;

		int is_exited = (pi.status != PROC_STATUS_ALIVE);

		/* Завершённые → в dead_keys, но НЕ пропускаются.
		 * При переполнении буфера — flush и продолжаем сбор. */
		if (is_exited) {
			if (dead_count >= DEAD_KEYS_CAP) {
				dead_total += flush_dead_keys(dead_keys,
							     dead_count);
				dead_count = 0;
			}
			dead_keys[dead_count++] = key;
		}

		const char *rule_name = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : RULE_NOT_MATCH;

		/* Разрешение cgroup из кэша */
		char cg_path[PATH_MAX_LEN];
		resolve_cgroup_ts(pi.cgroup_id, cg_path, sizeof(cg_path));

		/* Вычисление времён */
		double uptime_sec = mono_now - (double)pi.start_ns / 1e9;
		if (uptime_sec < 0) uptime_sec = 0;
		double cpu_ratio = 0;
		if (elapsed_ns > 0) {
			__u64 prev_ns = cpu_prev_lookup(key);
			cpu_ratio = (prev_ns > 0 && pi.cpu_ns >= prev_ns)
				? (double)(pi.cpu_ns - prev_ns) / elapsed_ns : 0;
		}
		cpu_prev_update(key, pi.cpu_ns);

		/* Lookup cgroup-метрик из кэша (заполнен refresh) */
		int cg_idx = -1;
		if (cg_path[0]) {
			for (int i = 0; i < cg_metrics_count; i++) {
				if (strcmp(cg_metrics[i].path, cg_path) == 0) {
					cg_idx = i;
					break;
				}
			}
		}

		/* Формирование события snapshot */
		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			cev.timestamp_ns = snap_timestamp_ns;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 "snapshot");
			snprintf(cev.rule, sizeof(cev.rule), "%s", rule_name);
#ifndef NO_TAGS
			snprintf(cev.tags, sizeof(cev.tags), "%s",
				 tags_lookup_copy(snap_tgid, snap_data, key));
#endif
			cev.root_pid = ti.root_pid;
			cev.pid = pi.tgid;
			cev.ppid = pi.ppid;
			cev.uid = pi.uid;
			memcpy(cev.comm, pi.comm, COMM_LEN);
			cmdline_split(pi.cmdline, pi.cmdline_len,
				      cev.exec_path, sizeof(cev.exec_path),
				      cev.args, sizeof(cev.args));
			snprintf(cev.cgroup, sizeof(cev.cgroup), "%s",
				 cg_path);
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
			cev.uptime_seconds = (__u64)(uptime_sec > 0
						     ? uptime_sec : 0);

			cev.loginuid       = pi.loginuid;
			cev.sessionid      = pi.sessionid;
			cev.euid           = pi.euid;
			cev.tty_nr         = pi.tty_nr;
			cev.sched_policy   = pi.sched_policy;
			cev.io_rchar       = pi.io_rchar;
			cev.io_wchar       = pi.io_wchar;
			cev.io_syscr       = pi.io_syscr;
			cev.io_syscw       = pi.io_syscw;
			cev.file_opens     = pi.file_opens;
			cev.socket_creates = pi.socket_creates;
			cev.mnt_ns_inum    = pi.mnt_ns_inum;
			cev.pid_ns_inum    = pi.pid_ns_inum;
			cev.net_ns_inum    = pi.net_ns_inum;
			cev.cgroup_ns_inum = pi.cgroup_ns_inum;

			cev.preempted_by_pid = pi.preempted_by_pid;
			memcpy(cev.preempted_by_comm,
			       pi.preempted_by_comm, COMM_LEN);

			pwd_lookup_ts(pi.tgid, cev.pwd, sizeof(cev.pwd));

			/* cgroup-метрики из кэша (заполнен refresh) */
			if (cg_idx >= 0 && cg_metrics[cg_idx].valid) {
				cev.cgroup_memory_max = cg_metrics[cg_idx].mem_max;
				cev.cgroup_memory_current = cg_metrics[cg_idx].mem_cur;
				cev.cgroup_swap_current = cg_metrics[cg_idx].swap_cur;
				cev.cgroup_cpu_weight = cg_metrics[cg_idx].cpu_weight;
				cev.cgroup_cpu_max = cg_metrics[cg_idx].cpu_max;
				cev.cgroup_cpu_max_period = cg_metrics[cg_idx].cpu_max_period;
				cev.cgroup_cpu_nr_periods = cg_metrics[cg_idx].cpu_nr_periods;
				cev.cgroup_cpu_nr_throttled = cg_metrics[cg_idx].cpu_nr_throttled;
				cev.cgroup_cpu_throttled_usec = cg_metrics[cg_idx].cpu_throttled_usec;
				cev.cgroup_pids_current = cg_metrics[cg_idx].pids_cur;
			}

			/* open_conn_map — BPF map lookup, не файловый I/O */
			if (cfg_tcp_open_conns) {
				__u64 conn_cnt = 0;
				int occ_fd = bpf_map__fd(
					skel->maps.open_conn_map);
				__u32 occ_key = pi.tgid;
				if (bpf_map_lookup_elem(occ_fd, &occ_key,
							&conn_cnt) == 0)
					cev.open_tcp_conns = conn_cnt;
			}

			pidtree_get_chain_copy(snap_pt_pid, snap_pt_ppid,
					       cev.pid, cev.parent_pids,
					       &cev.parent_pids_len);
			ef_append(&cev, cfg_hostname);
			snap_count++;
		}
		pid_count++;
	}
	free(all_keys);
	free(all_values);

	/* boot_ns — для вычисления длительности в conn_snapshot и file_snapshot */
	struct timespec boot_ts;
	clock_gettime(CLOCK_BOOTTIME, &boot_ts);
	__u64 boot_ns = (__u64)boot_ts.tv_sec * NS_PER_SEC
		      + (__u64)boot_ts.tv_nsec;

	/* ── conn_snapshot: метрики живых TCP-соединений ──────────────── */
	int conn_count = 0;
	if (cfg_net_tracking_enabled && g_http_cfg.enabled) {
		int sm_fd = bpf_map__fd(skel->maps.sock_map);

		__u64 sk_key;
		int sk_iter = 0;
		int sk_err = bpf_map_get_next_key(sm_fd, NULL, &sk_key);
		while (sk_err == 0 && sk_iter++ < NET_MAX_SOCKETS) {
			__u64 sk_next;
			int sk_next_err = bpf_map_get_next_key(sm_fd,
							       &sk_key,
							       &sk_next);
			struct sock_info si;
			if (bpf_map_lookup_elem(sm_fd, &sk_key, &si) == 0) {
				struct track_info ti;
				if (bpf_map_lookup_elem(tracked_map_fd,
							&si.tgid, &ti) == 0)
				{
					const char *rname =
						(ti.rule_id < num_rules)
						? rules[ti.rule_id].name
						: RULE_NOT_MATCH;

					struct metric_event cev;
					memset(&cev, 0, sizeof(cev));
					cev.timestamp_ns = snap_timestamp_ns;
					fast_strcpy(cev.event_type,
						    sizeof(cev.event_type),
						    "conn_snapshot");
					fast_strcpy(cev.rule,
						    sizeof(cev.rule),
						    rname);
#ifndef NO_TAGS
					fast_strcpy(cev.tags,
						    sizeof(cev.tags),
						    tags_lookup_copy(
							snap_tgid,
							snap_data,
							si.tgid));
#endif
					cev.root_pid = ti.root_pid;
					cev.pid = si.tgid;
					cev.uid = si.uid;
					cev.is_root = ti.is_root;

					/* comm, ppid, identity из proc_map */
					struct proc_info cpi;
					if (bpf_map_lookup_elem(
						proc_map_fd,
						&si.tgid, &cpi) == 0) {
						cev.ppid = cpi.ppid;
						memcpy(cev.comm, cpi.comm,
						       COMM_LEN);
						cev.loginuid  = cpi.loginuid;
						cev.sessionid = cpi.sessionid;
						cev.euid      = cpi.euid;
						cev.tty_nr    = cpi.tty_nr;
					}

					/* IP-адреса */
					if (si.af == 2) {
						snprintf(cev.net_local_addr,
							 sizeof(cev.net_local_addr),
							 "%u.%u.%u.%u",
							 si.local_addr[0],
							 si.local_addr[1],
							 si.local_addr[2],
							 si.local_addr[3]);
						snprintf(cev.net_remote_addr,
							 sizeof(cev.net_remote_addr),
							 "%u.%u.%u.%u",
							 si.remote_addr[0],
							 si.remote_addr[1],
							 si.remote_addr[2],
							 si.remote_addr[3]);
					} else if (si.af == 10) {
						inet_ntop(AF_INET6,
							  si.local_addr,
							  cev.net_local_addr,
							  sizeof(cev.net_local_addr));
						inet_ntop(AF_INET6,
							  si.remote_addr,
							  cev.net_remote_addr,
							  sizeof(cev.net_remote_addr));
					}

					cev.net_local_port = si.local_port;
					cev.net_remote_port = si.remote_port;
					cev.net_conn_tx_bytes = si.tx_bytes;
					cev.net_conn_rx_bytes = si.rx_bytes;
					cev.net_conn_tx_calls = si.tx_calls;
					cev.net_conn_rx_calls = si.rx_calls;

					/* Длительность соединения */
					if (si.start_ns > 0 &&
					    boot_ns > si.start_ns)
						cev.net_duration_ms =
							(boot_ns - si.start_ns)
							/ NS_PER_MS;

					/* is_listener → state: 'L'=listener, 'E'=established */
					cev.state = si.is_listener ? 'L' : 'E';

					ef_append(&cev, cfg_hostname);
					conn_count++;
				}
			}

			if (sk_next_err != 0)
				break;
			sk_key = sk_next;
		}
	}

	/* ── file_snapshot: метрики открытых файлов ──────────────────── */
	int file_snap_count = 0;
	if (cfg_file_tracking_enabled && g_http_cfg.enabled) {
		int fm_fd = bpf_map__fd(skel->maps.fd_map);

		struct fd_key fk_key;
		int fk_iter = 0;
		int fk_err = bpf_map_get_next_key(fm_fd, NULL, &fk_key);
		while (fk_err == 0 && fk_iter++ < BPF_FD_MAP_SIZE) {
			struct fd_key fk_next;
			int fk_next_err = bpf_map_get_next_key(fm_fd,
							       &fk_key,
							       &fk_next);

			struct fd_info fi;
			if (bpf_map_lookup_elem(fm_fd, &fk_key, &fi) == 0
			    && fi.path[0] != '\0'
			    && file_path_allowed(fi.path)) {
				struct track_info ti;
				if (bpf_map_lookup_elem(tracked_map_fd,
							&fk_key.tgid,
							&ti) == 0)
				{
					const char *rname =
						(ti.rule_id < num_rules)
						? rules[ti.rule_id].name
						: RULE_NOT_MATCH;

					struct metric_event cev;
					memset(&cev, 0, sizeof(cev));
					cev.timestamp_ns = snap_timestamp_ns;
					fast_strcpy(cev.event_type,
						    sizeof(cev.event_type),
						    "file_snapshot");
					fast_strcpy(cev.rule,
						    sizeof(cev.rule),
						    rname);
#ifndef NO_TAGS
					fast_strcpy(cev.tags,
						    sizeof(cev.tags),
						    tags_lookup_copy(
							snap_tgid,
							snap_data,
							fk_key.tgid));
#endif
					cev.root_pid = ti.root_pid;
					cev.pid = fk_key.tgid;
					cev.is_root = ti.is_root;

					struct proc_info fpi;
					if (bpf_map_lookup_elem(
						proc_map_fd,
						&fk_key.tgid, &fpi) == 0) {
						cev.ppid = fpi.ppid;
						cev.uid  = fpi.uid;
						memcpy(cev.comm, fpi.comm,
						       COMM_LEN);
						cev.loginuid  = fpi.loginuid;
						cev.sessionid = fpi.sessionid;
						cev.euid      = fpi.euid;
						cev.tty_nr    = fpi.tty_nr;
					}

					fast_strcpy(cev.file_path,
						    sizeof(cev.file_path),
						    fi.path);
					cev.file_flags = (__u32)fi.flags;
					cev.file_read_bytes = fi.read_bytes;
					cev.file_write_bytes = fi.write_bytes;
					cev.file_open_count = fi.open_count;
					cev.file_fsync_count = fi.fsync_count;

					if (fi.start_ns > 0 &&
					    boot_ns > fi.start_ns)
						cev.net_duration_ms =
							(boot_ns - fi.start_ns)
							/ NS_PER_MS;

					pidtree_get_chain_copy(
						snap_pt_pid, snap_pt_ppid,
						fk_key.tgid,
						cev.parent_pids,
						&cev.parent_pids_len);
					ef_append(&cev, cfg_hostname);
					file_snap_count++;
				}
			}

			if (fk_next_err != 0)
				break;
			fk_key = fk_next;
		}
	}

	ef_batch_unlock();

	/* Очистка завершённых процессов — BPF-карты + все userspace-кэши */
	dead_total += flush_dead_keys(dead_keys, dead_count);

	if (cfg_log_snapshot)
		LOG_INFO("snapshot: %d PIDs (%d exited), %d events, %d conns, %d files",
		       pid_count, dead_total, snap_count, conn_count, file_snap_count);

	/* Обновляем глобальные счётчики для heartbeat */
	g_last_conn_count = conn_count;
	g_last_fd_count = file_snap_count;

	/* Статистика ring buffer'ов — логируем только НОВЫЕ drops */
	{
		static struct ringbuf_stats prev_rs;
		__u32 key = 0;
		struct ringbuf_stats rs = {0};
		int stats_fd = bpf_map__fd(skel->maps.ringbuf_stats);
		if (stats_fd >= 0 &&
		    bpf_map_lookup_elem(stats_fd, &key, &rs) == 0) {
			__u64 new_drops =
				(rs.drop_proc   - prev_rs.drop_proc) +
				(rs.drop_file   - prev_rs.drop_file) +
				(rs.drop_file_ops  - prev_rs.drop_file_ops) +
				(rs.drop_net    - prev_rs.drop_net) +
				(rs.drop_sec    - prev_rs.drop_sec) +
				(rs.drop_cgroup - prev_rs.drop_cgroup) +
				(rs.drop_missed_exec - prev_rs.drop_missed_exec);
			if (new_drops > 0) {
				LOG_WARN("ringbuf drops: proc=%llu/%llu file=%llu/%llu file_ops=%llu/%llu net=%llu/%llu sec=%llu/%llu cgroup=%llu/%llu missed_exec_overflow=%llu",
				       (unsigned long long)rs.drop_proc,
				       (unsigned long long)rs.total_proc,
				       (unsigned long long)rs.drop_file,
				       (unsigned long long)rs.total_file,
				       (unsigned long long)rs.drop_file_ops,
				       (unsigned long long)rs.total_file_ops,
				       (unsigned long long)rs.drop_net,
				       (unsigned long long)rs.total_net,
				       (unsigned long long)rs.drop_sec,
				       (unsigned long long)rs.total_sec,
				       (unsigned long long)rs.drop_cgroup,
				       (unsigned long long)rs.total_cgroup,
				       (unsigned long long)rs.drop_missed_exec);
			} else if (cfg_log_level >= 2) {
				LOG_DEBUG(cfg_log_level,
					  "ringbuf totals: proc=%llu file=%llu net=%llu sec=%llu cgroup=%llu",
				       (unsigned long long)rs.total_proc,
				       (unsigned long long)rs.total_file,
				       (unsigned long long)rs.total_net,
				       (unsigned long long)rs.total_sec,
				       (unsigned long long)rs.total_cgroup);
			}
			prev_rs = rs;
		}
	}

	/* ── GC pidtree: удаляем записи мёртвых неотслеживаемых PID ────
	 * При начальном сканировании /proc ВСЕ процессы попадают в pidtree,
	 * но EXIT-событие приходит только для tracked процессов. Без GC
	 * записи неотслеживаемых мёртвых PID утекают и забивают хеш-таблицу.
	 * Запускаем каждые 10 snapshot'ов чтобы не нагружать kill() syscall. */
	{
		static int gc_counter;
		if (++gc_counter >= 10) {
			gc_counter = 0;

			/* Фаза 1: собираем кандидатов на удаление БЕЗ lock.
			 * bpf_map_lookup + kill() — тяжёлые syscall, нельзя
			 * держать wrlock на всё время (блокирует poll-потоки). */
			__u32 gc_pids[DEAD_KEYS_CAP];
			int gc_count = 0;

			pthread_rwlock_rdlock(&g_pidtree_lock);
			for (int i = 0; i < PIDTREE_HT_SIZE
				       && gc_count < DEAD_KEYS_CAP; i++) {
				__u32 pid = pt_pid[i];
				if (pid == 0)
					continue;
				struct track_info ti_gc;
				if (bpf_map_lookup_elem(tracked_map_fd, &pid,
							&ti_gc) == 0)
					continue;
				if (kill((pid_t)pid, 0) == 0 || errno != ESRCH)
					continue;
				gc_pids[gc_count++] = pid;
			}
			pthread_rwlock_unlock(&g_pidtree_lock);

			/* Фаза 2: удаляем под wrlock (быстро — только delete). */
			if (gc_count > 0) {
				pthread_rwlock_wrlock(&g_pidtree_lock);
				for (int i = 0; i < gc_count; i++) {
					pidtree_remove(gc_pids[i]);
					pt_generation++;
				}
				pthread_rwlock_unlock(&g_pidtree_lock);
				LOG_DEBUG(cfg_log_level, "PIDTREE_GC: removed %d dead"
					  " untracked entries", gc_count);
			}
		}
	}
}

/* ── сигналы ──────────────────────────────────────────────────────── */

static void sig_term(int sig) { (void)sig; g_running = 0; }
static void sig_hup(int sig)  { (void)sig; g_reload = 1; }

/* ── лог libbpf ───────────────────────────────────────────────────── */

static int libbpf_print(enum libbpf_print_level level,
			const char *fmt, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

/* ── главная функция ──────────────────────────────────────────────── */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -c <config_file>\n"
		"  -c <path>   configuration file (libconfig format)\n"
		"  -h          show this help\n",
		prog);
}

/*
 * Функция потока poll — вычитывает события из одного ring buffer'а.
 * Каждый поток обслуживает свой буфер (proc, file или net).
 * Завершается при g_running == 0.
 */
static void *poll_thread_fn(void *arg)
{
	struct poll_thread_arg *a = arg;

	/* Блокируем SIGTERM/SIGINT/SIGHUP в poll-потоках, чтобы сигналы
	 * гарантированно доставлялись в главный поток и прерывали sleep(). */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	LOG_INFO("poll thread '%s' started", a->name);

	while (g_running) {
		int n = ring_buffer__consume(a->rb);
		if (n > 0) {
			__atomic_add_fetch(&a->events, (__u64)n, __ATOMIC_RELAXED);
			continue;  /* есть данные — сразу проверяем ещё */
		}
		if (n < 0 && n != -EINTR) {
			LOG_ERROR("poll thread '%s': ring_buffer__consume: %d",
			       a->name, n);
			break;
		}
		/* Нет данных — ждём через epoll, чтобы не крутить CPU вхолостую */
		__atomic_add_fetch(&a->polls, 1, __ATOMIC_RELAXED);
		int err = ring_buffer__poll(a->rb, POLL_TIMEOUT_MS);
		if (err > 0)
			__atomic_add_fetch(&a->events, (__u64)err, __ATOMIC_RELAXED);
		if (err < 0 && err != -EINTR) {
			LOG_ERROR("poll thread '%s': ring_buffer__poll: %d",
			       a->name, err);
			break;
		}
	}

	LOG_INFO("poll thread '%s' stopped", a->name);
	return NULL;
}

int main(int argc, char *argv[])
{
	/* Разбор командной строки — только -c и -h */
	int opt;
	while ((opt = getopt(argc, argv, "c:h")) != -1) {
		switch (opt) {
		case 'c': cfg_config_file = optarg; break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	/* Поиск файла конфигурации */
	if (!cfg_config_file) {
		/* Пробуем директорию бинарника, затем cwd */
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

	/* Загрузка конфигурации (libconfig) */
	if (load_config(cfg_config_file) < 0)
		return 1;

	/* Загрузка правил из конфигурации */
	if (parse_rules_from_config(cfg_config_file) < 0)
		return 1;
	if (num_rules == 0) {
		LOG_FATAL("no rules loaded");
		return 1;
	}

	/* Инициализация кольцевого буфера событий в памяти */
	if (g_http_cfg.enabled) {
		if (ef_init((__u64)cfg_max_data_size) < 0) {
			LOG_FATAL("event ring buffer init failed");
			return 1;
		}
	}

	/* Построение кэша cgroup */
	build_cgroup_cache();

	/* Настройка libbpf */
	libbpf_set_print(libbpf_print);

	/* Открытие BPF-скелета */
	skel = process_metrics_bpf__open();
	if (!skel) {
		LOG_FATAL("failed to open BPF skeleton");
		return 1;
	}

	/* Установка rodata перед загрузкой */
	skel->rodata->max_exec_events_per_sec = (__u32)cfg_exec_rate_limit;

	/* Переопределение размеров BPF ring buffer'ов из конфига.
	 * Размер должен быть степенью 2 и >= PAGE_SIZE (4096).
	 * bpf_map__set_max_entries работает между open() и load(). */
#define SET_RINGBUF_SIZE(map, cfg_val)                                  \
	do {                                                            \
		if ((cfg_val) > 0) {                                    \
			__u32 sz = (__u32)(cfg_val);                    \
			/* Округляем вверх до степени 2 */              \
			sz--;                                           \
			sz |= sz >> 1; sz |= sz >> 2;                  \
			sz |= sz >> 4; sz |= sz >> 8; sz |= sz >> 16; \
			sz++;                                           \
			if (sz < BPF_MIN_RINGBUF_SIZE) sz = BPF_MIN_RINGBUF_SIZE; \
			bpf_map__set_max_entries(skel->maps.map, sz);   \
			LOG_INFO("ring_buffers.%s = %u bytes",    \
			       #map, sz);                               \
		}                                                       \
	} while (0)

	SET_RINGBUF_SIZE(events_proc,  cfg_ringbuf_proc);
	SET_RINGBUF_SIZE(events_file,  cfg_ringbuf_file);
	SET_RINGBUF_SIZE(events_file_ops, cfg_ringbuf_file_ops);
	SET_RINGBUF_SIZE(events_net,   cfg_ringbuf_net);
	SET_RINGBUF_SIZE(events_sec,   cfg_ringbuf_sec);
	SET_RINGBUF_SIZE(events_cgroup, cfg_ringbuf_cgroup);
#undef SET_RINGBUF_SIZE

	/*
	 * sock_map необходим для: net_tracking (net_close, conn_snapshot,
	 * track_bytes) и TCP security (retransmit, syn, rst, open_conn_count).
	 * Если любая из этих опций включена — инфраструктура сокетов нужна.
	 */
	cfg_need_sock_map = cfg_net_tracking_enabled
			  || cfg_tcp_retransmit
			  || cfg_tcp_syn
			  || cfg_tcp_rst
			  || cfg_tcp_open_conns;
	int need_sock_map = cfg_need_sock_map;

	/* iter/tcp запускается вручную из seed_sock_map(), не через autoattach.
	 * При need_sock_map: загружаем, но не attach'им (ручной attach позже).
	 * Без need_sock_map: полностью отключаем (не загружать). */
	if (need_sock_map)
		bpf_program__set_autoattach(skel->progs.seed_sock_map_iter, false);
	else
		BPF_PROG_DISABLE(skel->progs.seed_sock_map_iter);

	/* ── Условное отключение программ отслеживания сети ─────────── */
	if (!need_sock_map) {
		/* Жизненный цикл соединения: connect/accept/close/listen */
		BPF_PROG_DISABLE(skel->progs.kp_tcp_v4_connect);
		BPF_PROG_DISABLE(skel->progs.krp_tcp_v4_connect);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_v6_connect);
		BPF_PROG_DISABLE(skel->progs.krp_tcp_v6_connect);
		BPF_PROG_DISABLE(skel->progs.krp_inet_csk_accept);
		BPF_PROG_DISABLE(skel->progs.kp_inet_csk_listen_start);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_close);
		BPF_PROG_DISABLE(skel->progs.kretp_tcp_close);
		/* Агрегированный подсчёт байтов на процесс (TCP + UDP) */
		BPF_PROG_DISABLE(skel->progs.ret_tcp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.ret_tcp_recvmsg);
		BPF_PROG_DISABLE(skel->progs.ret_udp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.ret_udp_recvmsg);
	}
	if (!need_sock_map || !cfg_net_track_bytes) {
		/* Подсчёт байтов на соединение (kprobe enter + kretprobe) */
		BPF_PROG_DISABLE(skel->progs.kp_tcp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_recvmsg);
	}

	/* ── Условное отключение программ отслеживания файлов ──────── */
	if (!cfg_file_tracking_enabled) {
		/* file_tracking.enabled=false — отключаем всю группу целиком.
		 * open/close/read/write образуют единый pipeline через fd_map
		 * и не могут отключаться по отдельности. */
		BPF_PROG_DISABLE(skel->progs.handle_openat_enter);
		BPF_PROG_DISABLE(skel->progs.handle_openat_exit);
		BPF_PROG_DISABLE(skel->progs.handle_close_enter);
		BPF_PROG_DISABLE(skel->progs.handle_read_enter);
		BPF_PROG_DISABLE(skel->progs.handle_read_exit);
		BPF_PROG_DISABLE(skel->progs.handle_write_enter);
		BPF_PROG_DISABLE(skel->progs.handle_write_exit);
		BPF_PROG_DISABLE(skel->progs.handle_pread_enter);
		BPF_PROG_DISABLE(skel->progs.handle_pread_exit);
		BPF_PROG_DISABLE(skel->progs.handle_pwrite_enter);
		BPF_PROG_DISABLE(skel->progs.handle_pwrite_exit);
		BPF_PROG_DISABLE(skel->progs.handle_readv_enter);
		BPF_PROG_DISABLE(skel->progs.handle_readv_exit);
		BPF_PROG_DISABLE(skel->progs.handle_writev_enter);
		BPF_PROG_DISABLE(skel->progs.handle_writev_exit);
		BPF_PROG_DISABLE(skel->progs.handle_sendfile_enter);
		BPF_PROG_DISABLE(skel->progs.handle_sendfile_exit);
		BPF_PROG_DISABLE(skel->progs.handle_fsync_enter);
		BPF_PROG_DISABLE(skel->progs.handle_fdatasync_enter);
		BPF_PROG_DISABLE(skel->progs.handle_rename);
		BPF_PROG_DISABLE(skel->progs.handle_renameat2);
		BPF_PROG_DISABLE(skel->progs.handle_unlink);
		BPF_PROG_DISABLE(skel->progs.handle_unlinkat);
		BPF_PROG_DISABLE(skel->progs.handle_truncate);
		BPF_PROG_DISABLE(skel->progs.handle_ftruncate);
		BPF_PROG_DISABLE(skel->progs.handle_fchmodat_enter);
		BPF_PROG_DISABLE(skel->progs.handle_fchownat_enter);
	} else {
		/* file_tracking.enabled=true — гранулярное отключение по emit_*.
		 * Программы, независимые от fd_map pipeline (rename, unlink,
		 * truncate, chmod, chown), безопасно отключаются по отдельности. */
		if (!cfg_emit_file_rename) {
			BPF_PROG_DISABLE(skel->progs.handle_rename);
			BPF_PROG_DISABLE(skel->progs.handle_renameat2);
		}
		if (!cfg_emit_file_unlink) {
			BPF_PROG_DISABLE(skel->progs.handle_unlink);
			BPF_PROG_DISABLE(skel->progs.handle_unlinkat);
		}
		if (!cfg_emit_file_truncate) {
			BPF_PROG_DISABLE(skel->progs.handle_truncate);
			BPF_PROG_DISABLE(skel->progs.handle_ftruncate);
		}
		if (!cfg_emit_file_chmod)
			BPF_PROG_DISABLE(skel->progs.handle_fchmodat_enter);
		if (!cfg_emit_file_chown)
			BPF_PROG_DISABLE(skel->progs.handle_fchownat_enter);
	}

	/* ── Условное отключение process_tracking emit_* ───────────── *
	 * exec/fork/exit/sched_switch НЕЛЬЗЯ отключать: они управляют
	 * proc_map/tracked_map (core tracking pipeline).
	 * signal и chdir не имеют побочных эффектов — безопасны. */
	if (!cfg_emit_signal)
		BPF_PROG_DISABLE(skel->progs.handle_signal_generate);
	if (!cfg_emit_chdir) {
		BPF_PROG_DISABLE(skel->progs.handle_sys_exit_chdir);
		BPF_PROG_DISABLE(skel->progs.handle_sys_exit_fchdir);
	}

	/* ── Условное отключение cgroup tracepoints ────────────────── */
	if (!cfg_emit_cgroup) {
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_mkdir);
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_rmdir);
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_rename);
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_release);
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_attach_task);
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_transfer_tasks);
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_populated);
		BPF_PROG_DISABLE(skel->progs.handle_cgroup_frozen);
	}

	/* ── Условное отключение security-проб ─────────────────────── */
	if (!cfg_tcp_retransmit)
		BPF_PROG_DISABLE(skel->progs.handle_tcp_retransmit);
	if (!cfg_tcp_syn)
		BPF_PROG_DISABLE(skel->progs.kp_tcp_conn_request);
	if (!cfg_tcp_rst) {
		BPF_PROG_DISABLE(skel->progs.handle_tcp_send_reset);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_send_active_reset);
		BPF_PROG_DISABLE(skel->progs.handle_tcp_receive_reset);
	}
	if (!cfg_udp_bytes) {
		BPF_PROG_DISABLE(skel->progs.kp_udp_sendmsg_sec);
		BPF_PROG_DISABLE(skel->progs.ret_udp_sendmsg_sec);
		BPF_PROG_DISABLE(skel->progs.kp_udp_recvmsg_sec);
		BPF_PROG_DISABLE(skel->progs.ret_udp_recvmsg_sec);
	}
	if (!cfg_icmp_tracking)
		BPF_PROG_DISABLE(skel->progs.kp_icmp_rcv);

	/* Tracepoints cgroup_freeze/cgroup_unfreeze используют другой
	 * layout (trace_event_raw_cgroup, без поля val) и могут не
	 * поддерживать BPF attach на некоторых ядрах (например, 6.1).
	 * Отключаем — cgroup_notify_frozen покрывает ту же информацию. */
	BPF_PROG_DISABLE(skel->progs.handle_cgroup_freeze);
	BPF_PROG_DISABLE(skel->progs.handle_cgroup_unfreeze);

	/* Загрузка BPF-программ */
	if (process_metrics_bpf__load(skel)) {
		LOG_FATAL("failed to load BPF programs");
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Передача конфигурац��и отслеживания файлов в BPF-карты */
	if (cfg_file_tracking_enabled) {
		int file_cfg_fd = bpf_map__fd(skel->maps.file_cfg);
		__u32 key0 = 0;
		struct file_config fc = {
			.enabled = 1,
			.track_bytes = (__u8)cfg_file_track_bytes,
			.absolute_paths_only = (__u8)cfg_file_absolute_paths_only,
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

	/* Передача конфигурации отслеживания сети в BPF-карты.
	 * net_cfg заполняется если нужна sock_map инфраструктура.
	 * enabled отражает именно cfg_net_tracking_enabled
	 * (управляет net_close/conn_snapshot, не security-пробами). */
	if (cfg_need_sock_map) {
		int net_cfg_fd = bpf_map__fd(skel->maps.net_cfg);
		__u32 key0 = 0;
		struct net_config nc = {
			.enabled = (__u8)cfg_net_tracking_enabled,
			.track_bytes = (__u8)cfg_net_track_bytes,
		};
		bpf_map_update_elem(net_cfg_fd, &key0, &nc, BPF_ANY);
	}

	/* Передача конфигурации отслеживания безопасности в BPF-карты */
	{
		int sec_cfg_fd = bpf_map__fd(skel->maps.sec_cfg);
		__u32 key0 = 0;
		struct sec_config sc = {
			.tcp_retransmit  = (__u8)cfg_tcp_retransmit,
			.tcp_syn         = (__u8)cfg_tcp_syn,
			.tcp_rst         = (__u8)cfg_tcp_rst,
			.udp_bytes       = (__u8)cfg_udp_bytes,
			.icmp_tracking   = (__u8)cfg_icmp_tracking,
			.tcp_open_conns  = (__u8)cfg_tcp_open_conns,
		};
		bpf_map_update_elem(sec_cfg_fd, &key0, &sc, BPF_ANY);
	}

	if (process_metrics_bpf__attach(skel)) {
		LOG_FATAL("failed to attach BPF programs");
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Получение файловых дескрипторов карт */
	tracked_map_fd = bpf_map__fd(skel->maps.tracked_map);
	proc_map_fd    = bpf_map__fd(skel->maps.proc_map);
	missed_exec_fd = bpf_map__fd(skel->maps.missed_exec_map);

	/* Ring buffers: по одному на каждый тип событий.
	 * Каждый будет обслуживаться отдельным потоком poll. */
	struct ring_buffer *rb_proc = ring_buffer__new(
		bpf_map__fd(skel->maps.events_proc), handle_event, NULL, NULL);
	struct ring_buffer *rb_file = ring_buffer__new(
		bpf_map__fd(skel->maps.events_file), handle_event, NULL, NULL);
	struct ring_buffer *rb_file_ops = ring_buffer__new(
		bpf_map__fd(skel->maps.events_file_ops), handle_event, NULL, NULL);
	struct ring_buffer *rb_net = ring_buffer__new(
		bpf_map__fd(skel->maps.events_net), handle_event, NULL, NULL);
	struct ring_buffer *rb_sec = ring_buffer__new(
		bpf_map__fd(skel->maps.events_sec), handle_event, NULL, NULL);
	struct ring_buffer *rb_cgroup = ring_buffer__new(
		bpf_map__fd(skel->maps.events_cgroup), handle_cgroup_event,
		NULL, NULL);
	if (!rb_proc || !rb_file || !rb_file_ops || !rb_net || !rb_sec || !rb_cgroup) {
		LOG_FATAL("failed to create ring buffers");
		if (rb_proc)   ring_buffer__free(rb_proc);
		if (rb_file)   ring_buffer__free(rb_file);
		if (rb_file_ops)  ring_buffer__free(rb_file_ops);
		if (rb_net)    ring_buffer__free(rb_net);
		if (rb_sec)    ring_buffer__free(rb_sec);
		if (rb_cgroup) ring_buffer__free(rb_cgroup);
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Сигналы */
	signal(SIGTERM, sig_term);
	signal(SIGINT,  sig_term);
	signal(SIGHUP,  sig_hup);

	/* Очистка карт от предыдущего запуска.
	 * При OOM/SIGKILL процесс умирает, но BPF-карты могут содержать
	 * stale-записи если скелетон переиспользуется (pin) или ядро
	 * не успело освободить ресурсы. Также initial_scan ниже
	 * заполнит карты заново из /proc — старые данные не нужны. */
	{
		__u32 del_key;
		int cleaned = 0;
		while (bpf_map_get_next_key(tracked_map_fd, NULL, &del_key) == 0) {
			bpf_map_delete_elem(tracked_map_fd, &del_key);
			bpf_map_delete_elem(proc_map_fd, &del_key);
			cleaned++;
		}
		if (cleaned > 0)
			LOG_INFO("startup cleanup: removed %d stale entries from maps", cleaned);
	}

	/* ── Потоки poll: запускаем ДО initial_scan, чтобы drain'ить
	 * ring buffer'ы с момента attach BPF-программ. Иначе startup burst
	 * от ~600 tracked процессов переполняет fopen ring buffer. */
	struct poll_thread_arg args[NUM_POLL_THREADS] = {
		{ .rb = rb_proc,   .name = "proc"   },
		{ .rb = rb_file,   .name = "file"   },
		{ .rb = rb_file_ops,  .name = "file_ops"  },
		{ .rb = rb_net,    .name = "net"    },
		{ .rb = rb_sec,    .name = "sec"    },
		{ .rb = rb_cgroup, .name = "cgroup" },
	};
	pthread_t poll_threads[NUM_POLL_THREADS];

	for (int i = 0; i < NUM_POLL_THREADS; i++) {
		if (pthread_create(&poll_threads[i], NULL, poll_thread_fn, &args[i])) {
			LOG_FATAL("failed to create poll thread '%s'",
			       args[i].name);
			g_running = 0;
			break;
		}
	}

	/* Однократное сканирование при запуске: поиск уже работающих процессов */
	initial_scan();
	/* Заполняем sock_map существующими TCP-сокетами отслеживаемых процессов */
	if (cfg_need_sock_map)
		seed_sock_map();
	refresh_boot_to_wall();

	/* Запуск HTTP-сервера, если включён */
	if (g_http_cfg.enabled) {
		if (http_server_start(&g_http_cfg) < 0) {
			LOG_FATAL("HTTP server start failed");
			g_running = 0;
			for (int i = 0; i < NUM_POLL_THREADS; i++)
				pthread_join(poll_threads[i], NULL);
			_exit(1);
		}
	}

	LOG_INFO("started: %d rules, snapshot every %ds, refresh every %ds, "
	       "exec_rate_limit=%d/s, http_server=%s, "
	       "cgroup_metrics=%s, refresh_proc=%s, "
	       "net=[enabled=%s tcp_bytes=%s tcp_retransmit=%s tcp_syn=%s tcp_rst=%s "
	       "udp_bytes=%s tcp_open_conns=%s], "
	       "file=%s%s, icmp=%s, disk=%s, ring_buffer=%lld",
	       num_rules, cfg_snapshot_interval, cfg_refresh_interval,
	       cfg_exec_rate_limit,
	       g_http_cfg.enabled ? "on" : "off",
	       cfg_cgroup_metrics ? "on" : "off",
	       cfg_refresh_proc ? "on" : "off",
	       cfg_net_tracking_enabled ? "on" : "off",
	       cfg_net_track_bytes ? "on" : "off",
	       cfg_tcp_retransmit ? "on" : "off",
	       cfg_tcp_syn ? "on" : "off",
	       cfg_tcp_rst ? "on" : "off",
	       cfg_udp_bytes ? "on" : "off",
	       cfg_tcp_open_conns ? "on" : "off",
	       cfg_file_tracking_enabled ? "on" : "off",
	       cfg_file_track_bytes ? "+bytes" : "",
	       cfg_icmp_tracking ? "on" : "off",
	       cfg_disk_tracking_enabled ? "on" : "off",
	       (long long)cfg_max_data_size);

	/* Главный цикл — refresh, снапшот и перезагрузка конфигурации */
	time_t last_snapshot  = 0;
	time_t last_refresh   = 0;
	time_t last_heartbeat = 0;
	int    hb_snapshots   = 0;  /* счётчик snapshot'ов с прошлого heartbeat */
	int    hb_refreshes   = 0;  /* счётчик refresh'ей с прошлого heartbeat */

	while (g_running) {
		sleep(1);

		/* Перезагрузка конфигурации по SIGHUP */
		if (g_reload) {
			g_reload = 0;
			LOG_INFO("SIGHUP: reloading rules...");

			/* Очистка всего отслеживания — удаляем с начала каждый раз */
			__u32 del_key;
			while (bpf_map_get_next_key(tracked_map_fd, NULL, &del_key) == 0) {
				bpf_map_delete_elem(tracked_map_fd, &del_key);
				bpf_map_delete_elem(proc_map_fd, &del_key);
			}

			tags_clear_ts();
			pwd_clear_ts();
			parse_rules_from_config(cfg_config_file);
			build_cgroup_cache_ts();

			cpu_prev_count = 0;
			prev_snapshot_ts = (struct timespec){0};
			initial_scan();
			if (cfg_need_sock_map)
				seed_sock_map();

			/* Сбрасываем таймеры после перезагрузки */
			last_refresh  = 0;
			last_snapshot = 0;
		}

		time_t now = time(NULL);

		/* Периодическое обновление: тяжёлый I/O (cmdline, cgroup sysfs,
		 * kill-проверка, flush udp/icmp/disk).
		 *
		 * Адаптивный интервал: при высокой заполненности tracked_map
		 * увеличиваем интервал, чтобы дать write_snapshot время
		 * на cleanup и не тратить CPU на итерацию мёртвых записей. */
		{
			int effective_refresh = cfg_refresh_interval;

			/* Быстрая проверка заполненности tracked_map:
			 * пробуем get_next_key с позиции NULL —
			 * дёшево (1 syscall), даёт ключ если карта не пуста.
			 * Для точной оценки используем all_keys_count из
			 * последнего refresh. */
			int fill_pct = g_last_map_count * 100 / MAX_PROCS;
			if (fill_pct > REFRESH_FILL_HIGH_PCT)
				effective_refresh = cfg_refresh_interval * REFRESH_MULT_HIGH;
			else if (fill_pct > REFRESH_FILL_MED_PCT)
				effective_refresh = cfg_refresh_interval * REFRESH_MULT_MED;
			/* Не превышаем snapshot_interval */
			if (effective_refresh > cfg_snapshot_interval)
				effective_refresh = cfg_snapshot_interval;

			if (now - last_refresh >= effective_refresh) {
				refresh_processes();
				last_refresh = now;
				hb_refreshes++;
			}
		}

		if (!g_running)
			break;

		/* Периодический снапшот: лёгкий, только чтение из кешей */
		if (now - last_snapshot >= cfg_snapshot_interval) {
			write_snapshot();
			last_snapshot = now;
			hb_snapshots++;
		}

		/* Heartbeat — дельта-диагностика за интервал.
		 * Если эта строка перестаёт появляться — главный поток завис. */
		if (cfg_heartbeat_interval > 0 &&
		    now - last_heartbeat >= cfg_heartbeat_interval) {
			static __u64 prev_ev[NUM_POLL_THREADS], prev_po[NUM_POLL_THREADS];
			__u64 ev[NUM_POLL_THREADS], po[NUM_POLL_THREADS];
			for (int i = 0; i < NUM_POLL_THREADS; i++) {
				ev[i] = __atomic_load_n(&args[i].events,
							__ATOMIC_RELAXED);
				po[i] = __atomic_load_n(&args[i].polls,
							__ATOMIC_RELAXED);
			}
			LOG_INFO("heartbeat: %d refreshes, %d snapshots | "
			       "maps: tracked=%d conns=%d fds=%d | "
			       "events/%ds: proc=%llu file=%llu file_ops=%llu "
			       "net=%llu sec=%llu cgroup=%llu",
			       hb_refreshes, hb_snapshots,
			       g_last_map_count,
			       g_last_conn_count,
			       g_last_fd_count,
			       cfg_heartbeat_interval,
			       (unsigned long long)(ev[0] - prev_ev[0]),
			       (unsigned long long)(ev[1] - prev_ev[1]),
			       (unsigned long long)(ev[2] - prev_ev[2]),
			       (unsigned long long)(ev[3] - prev_ev[3]),
			       (unsigned long long)(ev[4] - prev_ev[4]),
			       (unsigned long long)(ev[5] - prev_ev[5]));
			for (int i = 0; i < NUM_POLL_THREADS; i++) {
				prev_ev[i] = ev[i];
				prev_po[i] = po[i];
			}
			last_heartbeat = now;
			hb_snapshots = 0;
			hb_refreshes = 0;
		}
	}

	LOG_INFO("shutting down...");

	/* Остановка HTTP-сервера — прерываем активные соединения */
	LOG_INFO("shutdown: stopping http server...");
	http_server_stop();
	LOG_INFO("shutdown: http server stopped");

	/* Ждём завершения потоков poll */
	LOG_INFO("shutdown: joining poll threads...");
	for (int i = 0; i < NUM_POLL_THREADS; i++)
		pthread_join(poll_threads[i], NULL);
	LOG_INFO("shutdown: poll threads joined");

	/* Очистка файла событий */
	LOG_INFO("shutdown: cleaning up...");
	ef_cleanup();

	LOG_INFO("shutdown: userspace cleanup done");

	free_rules();

	/* BPF cleanup: close() на perf event fd тригерит в ядре
	 * unregister_kretprobes → synchronize_rcu_tasks_trace().
	 * С ~70 BPF программами это занимает 10-30+ секунд.
	 * _exit() тоже блокируется (task_work_run → __fput при выходе).
	 *
	 * Единственный способ не блокировать systemd: закрыть BPF fd
	 * в фоновом потоке, а главный поток завершает процесс через _exit()
	 * после того как основная cleanup-работа сделана. Ядро дочистит
	 * оставшиеся BPF ресурсы асинхронно (reference counting). */
	LOG_INFO("stopped");
	_exit(0);
}
