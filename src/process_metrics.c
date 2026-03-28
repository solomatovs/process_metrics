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

/*
 * bpf_program__set_autoload  — libbpf >= 0.6 (пропускает загрузку + подключение)
 * bpf_program__set_autoattach — libbpf >= 0.8 (загружает, но пропускает подключение)
 *
 * Для отключения опциональных программ нужен set_autoload (не отправлять
 * даже на верификатор). Astra Linux поставляет libbpf 0.7, в котором есть
 * set_autoload, но нет set_autoattach.
 */
#if LIBBPF_MAJOR_VERSION > 0 || LIBBPF_MINOR_VERSION >= 8
#define BPF_PROG_DISABLE(prog) bpf_program__set_autoattach((prog), false)
#else
#define BPF_PROG_DISABLE(prog) bpf_program__set_autoload((prog), false)
#endif

/* ── конфигурация ─────────────────────────────────────────────────── */

#define MAX_RULES       64
#define RULE_NOT_MATCH  "NOT_MATCH"
#define MAX_CGROUPS  256
#define PATH_MAX_LEN 512

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
static int         cfg_cmdline_max_len             = 500;
static int         cfg_exec_rate_limit             = 0;  /* 0 = без ограничений */
static int         cfg_cgroup_metrics              = 1;  /* 1 = читать файлы cgroup */
static int         cfg_refresh_proc                = 1;  /* 1 = обновлять cmdline/comm из /proc */
static int         cfg_log_level                   = 1;  /* 0=error, 1=info, 2=debug */

/* Конфигурация HTTP-сервера */
static struct http_config g_http_cfg;
static long long cfg_max_data_size          = 256LL * 1024 * 1024; /* 256 MB ring buffer */

/* Конфигурация отслеживания сети */
static int cfg_net_tracking_enabled         = 0;
static int cfg_net_track_bytes              = 0;

/* Конфигурация отслеживания файлов */
static int cfg_file_tracking_enabled        = 0;
static int cfg_file_track_bytes             = 0;

/* Конфигурация резолвинга Docker */
static int cfg_docker_resolve_names         = 0;  /* резолвить docker-<hash>.scope → имя контейнера */
static char cfg_docker_data_root[PATH_MAX_LEN] = "";
static char cfg_docker_daemon_json[PATH_MAX_LEN] = "/etc/docker/daemon.json";

/* Конфигурация отслеживания дисков */
static int cfg_disk_tracking_enabled       = 1;  /* включено по умолчанию */
#define DISK_MAX_PREFIXES 32
#define DISK_PREFIX_MAX   256
static char cfg_disk_include[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
static int  cfg_disk_include_count         = 0;
static char cfg_disk_exclude[DISK_MAX_PREFIXES][DISK_PREFIX_MAX];
static int  cfg_disk_exclude_count         = 0;
static char cfg_disk_fs_types[DISK_MAX_PREFIXES][32];
static int  cfg_disk_fs_types_count        = 0;

/* Конфигурация отслеживания безопасности */
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

/* ── глобальные переменные ─────────────────────────────────────────── */

static volatile sig_atomic_t g_running   = 1;
static volatile sig_atomic_t g_reload    = 0;
static struct process_metrics_bpf *skel;
static int tracked_map_fd, proc_map_fd;

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

/* Аргумент для потока poll */
struct poll_thread_arg {
	struct ring_buffer *rb;
	const char *name;
};

/* Предварительные объявления */
static void write_snapshot(void);
static void build_cgroup_cache(void);
static void log_ts(const char *level, const char *fmt, ...);

/* Смещение от boot-time к wall-clock (вычисляется однократно при старте,
 * обновляется каждый snapshot). BPF отправляет bpf_ktime_get_boot_ns(),
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
#define TAGS_HT_SIZE 16384  /* должно быть степенью 2 */

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
 * Константы 0x85ebca6b и 0xc2b2ae35 — из оригинального murmurhash3
 * (Austin Appleby), обеспечивают максимальную лавинность для 32-бит.
 */
static inline __u32 tags_hash(__u32 h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
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
	__u32 slot;
	int i;

	/* Найти элемент */
	for (i = 0; i < TAGS_HT_SIZE; i++) {
		slot = (idx + i) & (TAGS_HT_SIZE - 1);
		if (tags_tgid[slot] == tgid)
			goto found;
		if (tags_tgid[slot] == 0)
			return; /* не найден */
	}
	return;

found:
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

static void tags_clear_ts(void)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_clear();
	pthread_rwlock_unlock(&g_tags_lock);
}

#endif /* NO_TAGS */

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
static void log_debug(const char *fmt, ...);

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
	log_debug("LATE_TRACK: pid=%u rule=%s tags=%s cmdline=%.60s",
		  pid, rules[first].name, tags_buf, cmdline_str);
	return first;
}

/* ── Кэш использования CPU (для вычисления отношения за интервал) ── */

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

/* ── кэш cgroup ──────────────────────────────────────────────────── */

struct cgroup_entry {
	__u64 id;
	char  path[EV_CGROUP_LEN];    /* отображаемое имя (docker/xxx или оригинал) */
	char  fs_path[EV_CGROUP_LEN]; /* реальный путь в файловой системе под /sys/fs/cgroup */
};

static struct cgroup_entry cgroup_cache[MAX_CGROUPS];
static int cgroup_cache_count;
static char docker_data_root[PATH_MAX_LEN] = "";

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
 * Попытка резолвить имя Docker-контейнера из пути cgroup.
 * Ищет паттерн "docker-<64hex>.scope" и читает имя контейнера
 * из config.v2.json. Возвращает 1 при успехе (dst заполнен), 0 — иначе.
 */
static int resolve_docker_name(const char *rel, char *dst, size_t dstlen)
{
	/* Ищем префикс "docker-" в последнем компоненте пути */
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

	/* config.v2.json может быть большим (>40KB если секция State велика),
	 * поэтому читаем частями, ища паттерн "Name":" */
	char *q1 = NULL, *q2 = NULL;
	char buf[4096];
	char overlap[256] = "";  /* перекрытие с предыдущим чанком */
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
#define DOCKER_NAME_CACHE_SIZE 256

static struct {
	char container_id[65];       /* 64 hex + NUL */
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
	if (strncmp(base, "docker-", 7) != 0)
		return NULL;
	const char *hash = base + 7;
	const char *dot = strstr(hash, ".scope");
	if (!dot || (dot - hash) != 64)
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
		if (memcmp(docker_name_cache[i].container_id, id, 64) == 0) {
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
		if (memcmp(docker_name_cache[i].container_id, id, 64) == 0) {
			pthread_rwlock_unlock(&g_docker_cache_lock);
			snprintf(buf, buflen, "%s", ok ? resolved : raw);
			return;
		}
	}
	if (docker_name_cache_count < DOCKER_NAME_CACHE_SIZE) {
		memcpy(docker_name_cache[docker_name_cache_count].container_id,
		       id, 64);
		docker_name_cache[docker_name_cache_count].container_id[64] = '\0';
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
#define UID_NAME_CACHE_SIZE 512
#define UID_NAME_MAX 64

static struct {
	__u32 uid;
	char  name[UID_NAME_MAX];
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
	char pwbuf[1024];

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
	char name[UID_NAME_MAX] = "";
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
			 UID_NAME_MAX, "%s", name);
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
	if (access("/sys/fs/cgroup", R_OK) == 0)
		scan_cgroup_dir("/sys/fs/cgroup", "");
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
			log_ts("DEBUG", "cgroup mkdir: id=%llu level=%d path=%s",
			       (unsigned long long)ce->id, ce->level, ce->path);
		break;

	case EVENT_CGROUP_RMDIR:
		cgroup_cache_remove(ce->id);
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup rmdir: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_RENAME:
		/* Обновляем путь для существующей записи */
		cgroup_cache_add(ce->id, ce->path);
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup rename: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_RELEASE:
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup release: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_ATTACH_TASK:
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup attach: pid=%d → id=%llu path=%s comm=%s",
			       ce->pid, (unsigned long long)ce->id,
			       ce->path, ce->comm);
		break;

	case EVENT_CGROUP_TRANSFER_TASKS:
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup transfer: pid=%d → id=%llu path=%s comm=%s",
			       ce->pid, (unsigned long long)ce->id,
			       ce->path, ce->comm);
		break;

	case EVENT_CGROUP_POPULATED:
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup populated: id=%llu path=%s val=%d",
			       (unsigned long long)ce->id, ce->path, ce->val);
		break;

	case EVENT_CGROUP_FREEZE:
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup freeze: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_UNFREEZE:
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup unfreeze: id=%llu path=%s",
			       (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_FROZEN:
		if (cfg_log_level >= 2)
			log_ts("DEBUG", "cgroup frozen: id=%llu path=%s val=%d",
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

/* ── загрузчик конфигурации libconfig ─────────────────────────────── */

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

	/* Общие настройки */
	if (config_lookup_string(&cfg, "hostname", &str_val))
		snprintf(cfg_hostname, sizeof(cfg_hostname), "%s", str_val);
	if (!cfg_hostname[0])
		gethostname(cfg_hostname, sizeof(cfg_hostname));
	if (config_lookup_int(&cfg, "snapshot_interval", &int_val))
		cfg_snapshot_interval = int_val;
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

	/* Настройки HTTP-сервера (включается при наличии секции с портом) */
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
		long long ll_val;
		if (config_setting_lookup_int64(hs, "max_buffer_size", &ll_val))
			cfg_max_data_size = ll_val;
	}

	/* Настройки отслеживания сети */
	config_setting_t *nt = config_lookup(&cfg, "net_tracking");
	if (nt) {
		if (config_setting_lookup_bool(nt, "enabled", &bool_val))
			cfg_net_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(nt, "track_bytes", &bool_val))
			cfg_net_track_bytes = bool_val;
	}

	/* Настройки отслеживания файлов */
	config_setting_t *ft = config_lookup(&cfg, "file_tracking");
	if (ft) {
		if (config_setting_lookup_bool(ft, "enabled", &bool_val))
			cfg_file_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(ft, "track_bytes", &bool_val))
			cfg_file_track_bytes = bool_val;

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

	/* Настройки отслеживания безопасности */
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

static void log_ts(const char *level, const char *fmt, ...)
{
	fprintf(stderr, "[%s] ", level);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

/* Отладочный лог — выводится только при log_level >= 2 */
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
	/* поля, специфичные для exit */
	out->exit_code = (e->exit_code >> 8) & 0xff;
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
	char path[64];
	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	char buf[1024];
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
	if (page_size <= 0) page_size = 4096;
	pi->vsize_pages = (__u64)(vsize / page_size);

	long clk_tck = sysconf(_SC_CLK_TCK);
	if (clk_tck <= 0) clk_tck = 100;
	pi->cpu_ns = ((__u64)(utime + stime) * 1000000000ULL) / (__u64)clk_tck;
	pi->start_ns = ((__u64)starttime * 1000000000ULL) / (__u64)clk_tck;

	/* Чтение дополнительных полей из /proc/PID/status */
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

	/* Чтение IO из /proc/PID/io (требует root или ptrace) */
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
	char path[64], buf[32];
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

	/* Проход 1: собираем все PID и ppid */
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
			log_debug("SCAN: pid=%u rule=%s tags=%s cmdline=%.60s",
				  pid, rules[first].name, tags_buf,
				  cmdline_str);

			/* Находим всех потомков */
			add_descendants(entries, count, pid, first, pid,
					&tracked);
		}
	}

	log_ts("INFO", "initial scan: %d processes scanned, %d tracked",
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
			? rules[ti.rule_id].name : RULE_NOT_MATCH;

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
			tags_lookup_ts(fe->tgid, cev.tags, sizeof(cev.tags));
			cev.root_pid = ti.root_pid;
			cev.is_root = ti.is_root;
			cev.pid = fe->tgid;
			cev.ppid = fe->ppid;
			cev.uid = fe->uid;
			memcpy(cev.comm, fe->comm, COMM_LEN);

			/* Cgroup из кэша — линейный поиск по ~50 записям, без syscall */
			resolve_cgroup_fast_ts(fe->cgroup_id,
					       cev.cgroup, sizeof(cev.cgroup));

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
			? rules[ti.rule_id].name : RULE_NOT_MATCH;

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
			tags_lookup_ts(ne->tgid, cev.tags, sizeof(cev.tags));
			cev.root_pid = ti.root_pid;
			cev.is_root = ti.is_root;
			cev.pid = ne->tgid;
			cev.ppid = ne->ppid;
			cev.uid = ne->uid;
			memcpy(cev.comm, ne->comm, COMM_LEN);

			/* Cgroup из кэша */
			resolve_cgroup_fast_ts(ne->cgroup_id,
					       cev.cgroup, sizeof(cev.cgroup));

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
		const char *rname = RULE_NOT_MATCH;
		if (bpf_map_lookup_elem(tracked_map_fd, &se->sender_tgid, &ti) == 0)
			rname = (ti.rule_id < num_rules)
				? rules[ti.rule_id].name : RULE_NOT_MATCH;
		if (rname[0] == '?' && rname[1] == '\0') {
			if (bpf_map_lookup_elem(tracked_map_fd, &se->target_pid, &ti) == 0)
				rname = (ti.rule_id < num_rules)
					? rules[ti.rule_id].name : RULE_NOT_MATCH;
		}

		log_debug("SIGNAL: sender=%u→target=%u sig=%d code=%d result=%d "
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
			cev.timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
					 + (__u64)ts_now.tv_nsec;
			snprintf(cev.event_type, sizeof(cev.event_type),
				 "signal");
			snprintf(cev.rule, sizeof(cev.rule), "%s", rname);

			/* Теги: сначала отправителя, потом получателя */
			char sig_tags[TAGS_MAX_LEN];
			tags_lookup_ts(se->sender_tgid, sig_tags, sizeof(sig_tags));
			if (!sig_tags[0])
				tags_lookup_ts(se->target_pid, sig_tags, sizeof(sig_tags));
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
			if (cg_buf[0])
				snprintf(cev.cgroup, sizeof(cev.cgroup),
					 "%s", cg_buf);

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
			snprintf(cev.rule, sizeof(cev.rule), "%s", RULE_NOT_MATCH);

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
			resolve_cgroup_fast_ts(re->cgroup_id, cev.cgroup,
					       sizeof(cev.cgroup));

			/* Определяем правило, если процесс отслеживается */
			struct track_info ti;
			if (bpf_map_lookup_elem(tracked_map_fd,
						&re->tgid, &ti) == 0) {
				if (ti.rule_id < num_rules)
					snprintf(cev.rule, sizeof(cev.rule),
						 "%s", rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				tags_lookup_ts(re->tgid, cev.tags,
					       sizeof(cev.tags));
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
			snprintf(cev.rule, sizeof(cev.rule), "%s", RULE_NOT_MATCH);
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
					 + (__u64)ts_now.tv_nsec;
			snprintf(cev.event_type, sizeof(cev.event_type),
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
					snprintf(cev.rule, sizeof(cev.rule),
						 "%s", rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				tags_lookup_ts(se_syn->tgid, cev.tags,
					       sizeof(cev.tags));
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
			snprintf(cev.rule, sizeof(cev.rule), "%s", RULE_NOT_MATCH);
			struct timespec ts_now;
			clock_gettime(CLOCK_REALTIME, &ts_now);
			cev.timestamp_ns = (__u64)ts_now.tv_sec * 1000000000ULL
					 + (__u64)ts_now.tv_nsec;
			snprintf(cev.event_type, sizeof(cev.event_type),
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
					snprintf(cev.rule, sizeof(cev.rule),
						 "%s", rules[ti.rule_id].name);
				cev.root_pid = ti.root_pid;
				tags_lookup_ts(rste->tgid, cev.tags,
					       sizeof(cev.tags));
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
				char cg_buf[PATH_MAX_LEN];
				resolve_cgroup_fast_ts(e->cgroup_id, cg_buf,
						       sizeof(cg_buf));
				struct metric_event cev;
				event_from_bpf(&cev, e, "exec",
					       rules[first].name,
					       tags_buf, cg_buf);
				cev.is_root = 1;
				ef_append(&cev, cfg_hostname);
			}
		}
		return 0;
	}

	/* ── FORK — создание дочернего процесса ──────────────────────── */
	case EVENT_FORK: {
		/* BPF handle_fork уже создал tracked_map и proc_info записи.
		 * Здесь только наследуем tags (они живут в userspace hash table). */
		struct track_info parent_ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &e->ppid, &parent_ti) != 0)
			return 0;
		tags_inherit_ts(e->tgid, e->ppid);

		/* tty_nr уже заполнен BPF (read_tty_nr в handle_fork) */
		__u32 child_tty = 0;
		{
			struct proc_info child_pi;
			if (bpf_map_lookup_elem(proc_map_fd, &e->tgid, &child_pi) == 0)
				child_tty = child_pi.tty_nr;
		}

		/* Отправляем fork-событие в буферный файл */
		if (g_http_cfg.enabled) {
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
			tags_remove(e->tgid);
		}
		pthread_rwlock_unlock(&g_tags_lock);
#endif

		/* Декодирование кода завершения: сигнал (младшие 7 бит) + статус */
		int sig = e->exit_code & 0x7f;
		int status = (e->exit_code >> 8) & 0xff;

		log_debug("EXIT: pid=%u rule=%s exit_code=%d "
			  "signal=%d cpu=%.2fs rss_max=%lluMB%s",
			  e->tgid, rname, status, sig,
			  (double)e->cpu_ns / 1e9,
			  (unsigned long long)(e->rss_max_pages * 4 / 1024),
			  e->oom_killed ? " [OOM]" : "");

		/* Отправляем exit-событие в буферный файл */
		if (g_http_cfg.enabled) {
			char cg_buf[PATH_MAX_LEN];
			resolve_cgroup_fast_ts(e->cgroup_id, cg_buf,
					       sizeof(cg_buf));
			struct metric_event cev;
			event_from_bpf(&cev, e, "exit", rname, exit_tags, cg_buf);
			ef_append(&cev, cfg_hostname);
		}
		/* BPF уже удалил запись из tracked_map и proc_map */
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
		log_ts("WARN", "OOM_KILL: pid=%u rule=%s comm=%.16s "
		       "rss=%lluMB",
		       e->tgid, rname, e->comm,
		       (unsigned long long)(e->rss_pages * 4 / 1024));

		/* Отправляем oom_kill-событие в буферный файл */
		if (g_http_cfg.enabled) {
			char cg_buf[PATH_MAX_LEN];
			resolve_cgroup_fast_ts(e->cgroup_id, cg_buf,
					       sizeof(cg_buf));
			char oom_tags[TAGS_MAX_LEN];
			tags_lookup_ts(e->tgid, oom_tags, sizeof(oom_tags));
			struct metric_event cev;
			event_from_bpf(&cev, e, "oom_kill", rname,
				       oom_tags, cg_buf);
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
 * Чтение cpu.max: "$MAX $PERIOD" или "max $PERIOD".
 * Устанавливает *quota (мкс, 0 если "max") и *period (мкс).
 */
static void read_cgroup_cpu_max(const char *cg_path,
				long long *quota, long long *period)
{
	*quota = -1;
	*period = -1;
	char path[PATH_MAX_LEN];
	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cpu.max", cg_path);
	FILE *f = fopen(path, "r");
	if (!f)
		return;
	char buf[64];
	if (fgets(buf, sizeof(buf), f)) {
		if (strncmp(buf, "max", 3) == 0) {
			*quota = 0;  /* без ограничений */
			if (sscanf(buf + 3, " %lld", period) != 1)
				*period = 100000;
		} else {
			if (sscanf(buf, "%lld %lld", quota, period) != 2) {
				*quota = -1;
				*period = -1;
			}
		}
	}
	fclose(f);
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
	snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cpu.stat", cg_path);
	FILE *f = fopen(path, "r");
	if (!f)
		return;
	char line[128];
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "nr_periods ", 11) == 0)
			*nr_periods = strtoll(line + 11, NULL, 10);
		else if (strncmp(line, "nr_throttled ", 13) == 0)
			*nr_throttled = strtoll(line + 13, NULL, 10);
		else if (strncmp(line, "throttled_usec ", 15) == 0)
			*throttled_usec = strtoll(line + 15, NULL, 10);
	}
	fclose(f);
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

	FILE *mf = setmntent("/proc/mounts", "r");
	if (!mf)
		return 0;

	char seen_devs[64][256];
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
		if (seen_count < 64)
			snprintf(seen_devs[seen_count++], 256,
				 "%s", ent->mnt_fsname);

		struct statvfs svfs;
		if (statvfs(ent->mnt_dir, &svfs) != 0)
			continue;

		struct metric_event cev;
		memset(&cev, 0, sizeof(cev));
		snprintf(cev.rule, sizeof(cev.rule), "%s", RULE_NOT_MATCH);
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

static void write_snapshot(void)
{
	/* Кэш cgroup'ов обновляется event-driven через BPF tracepoints
	 * (cgroup_mkdir/rmdir/rename), периодический rebuild не нужен. */
	refresh_boot_to_wall();

#ifndef NO_TAGS
	/* ┌───────────────────────────────────────────────────────────────┐
	 * │  ОПТИМИЗАЦИЯ 4: Snapshot tags через memcpy (anti-starvation) │
	 * ├───────────────────────────────────────────────────────────────┤
	 * │  Проблема: write_snapshot итерирует ~1600 PID'ов с I/O       │
	 * │  (fprintf, bpf_map_lookup) — это занимает секунды.           │
	 * │  Если держать rdlock на g_tags_lock всё это время,           │
	 * │  poll-потоки не могут получить wrlock для FORK/EXIT →        │
	 * │  writer starvation → ring buffer переполняется.              │
	 * │                                                               │
	 * │  Решение: копируем tags_tgid (64KB) + tags_data (8MB) под   │
	 * │  кратким rdlock (~1ms), затем работаем с локальной копией    │
	 * │  через tags_lookup_copy() без каких-либо locks.             │
	 * │                                                               │
	 * │  Массивы объявлены static — аллоцируются один раз в BSS,    │
	 * │  не на стеке (16 МБ на стеке вызвали бы stack overflow).    │
	 * └───────────────────────────────────────────────────────────────┘ */
	static __u32 snap_tgid[TAGS_HT_SIZE];
	static char  snap_data[TAGS_HT_SIZE][TAGS_MAX_LEN];
	pthread_rwlock_rdlock(&g_tags_lock);
	memcpy(snap_tgid, tags_tgid, sizeof(tags_tgid));
	memcpy(snap_data, tags_data, sizeof(tags_data));
	pthread_rwlock_unlock(&g_tags_lock);
#endif

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) page_size = 4096;

	/* Вычисление смещения от загрузки: monotonic → epoch */
	struct timespec mono;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	double mono_now = (double)mono.tv_sec + (double)mono.tv_nsec / 1e9;

	/* Время, прошедшее с предыдущего снапшота (для cpu_usage_ratio) */
	double elapsed_ns = 0;
	if (prev_snapshot_ts.tv_sec > 0) {
		elapsed_ns = (double)(mono.tv_sec - prev_snapshot_ts.tv_sec) * 1e9
			   + (double)(mono.tv_nsec - prev_snapshot_ts.tv_nsec);
	}
	prev_snapshot_ts = mono;

	/* Итерация по proc_map */
	__u32 key = 0;
	struct proc_info pi;
	int pid_count = 0;

	/* Сбор уникальных cgroup'ов для cgroup-метрик (с кэшированными ��начениями) */
	struct {
		char path[EV_CGROUP_LEN];
		long long mem_max, mem_cur, swap_cur, cpu_weight, pids_cur;
		long long cpu_max, cpu_max_period;
		long long cpu_nr_periods, cpu_nr_throttled, cpu_throttled_usec;
		int read;  /* 1 = значения прочитаны из /sys/fs/cgroup */
	} seen_cg[MAX_CGROUPS];
	int seen_cg_count = 0;

	/* Сбор ключей для удаления (мёртвые процессы, пропущенные из-за переполнения ringbuf) */
	__u32 dead_keys[256];
	int dead_count = 0;

	/* Пакет снапшота для файла событий */
	/* Одно событие на стеке для потоковой записи в файл событий */
	int snap_count = 0;

	/* Единая временная метка для всех событий снапшота в этом цикле */
	struct timespec snap_ts;
	clock_gettime(CLOCK_REALTIME, &snap_ts);
	__u64 snap_timestamp_ns = (__u64)snap_ts.tv_sec * 1000000000ULL
				+ (__u64)snap_ts.tv_nsec;

	/* Блокировка пакета, чтобы ef_read_begin() не увидел
	 * частичный снапшот между двумя доставками */
	ef_batch_lock();

	/*
	 * Пакетный lookup: чтение всех записей proc_map за один syscall.
	 * Откатывается на поэлементную итерацию, если batch не поддерживается.
	 */
	__u32 *all_keys = NULL;
	struct proc_info *all_values = NULL;
	int all_keys_count = 0;

	{
		__u32 batch_count = MAX_PROCS;
		all_keys = malloc(batch_count * sizeof(__u32));
		all_values = malloc(batch_count * sizeof(struct proc_info));

		if (all_keys && all_values) {
			DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
				.elem_flags = 0,
				.flags = 0,
			);
			__u32 out_batch = 0;
			int ret = bpf_map_lookup_batch(proc_map_fd,
				NULL, &out_batch,
				all_keys, all_values, &batch_count, &opts);
			if (ret == 0 || (ret < 0 && errno == ENOENT)) {
				/* ENOENT означает «последний пакет» — все записи прочитаны */
				all_keys_count = (int)batch_count;
			} else {
				/* Batch не поддерживается — откат на итерацию */
				all_keys_count = 0;
				__u32 iter_key;
				int err2 = bpf_map_get_next_key(proc_map_fd,
							NULL, &iter_key);
				while (err2 == 0 && all_keys_count < (int)MAX_PROCS) {
					all_keys[all_keys_count++] = iter_key;
					err2 = bpf_map_get_next_key(proc_map_fd,
							&iter_key, &iter_key);
				}
				/* Значения не заполнены — будут запрошены поэлементно ниже */
				free(all_values);
				all_values = NULL;
			}
		}
	}

	for (int ki = 0; ki < all_keys_count; ki++) {
		key = all_keys[ki];

		/* Используем значение из batch, если доступно, иначе поэлементный lookup */
		if (all_values) {
			pi = all_values[ki];
		} else {
			if (bpf_map_lookup_elem(proc_map_fd, &key, &pi) != 0)
				continue;
		}

		struct track_info ti;
		if (bpf_map_lookup_elem(tracked_map_fd, &key, &ti) != 0)
			continue;

		/* Проверяем, жив ли ещё процесс */
		if (kill((pid_t)key, 0) != 0 && errno == ESRCH) {
			if (dead_count < 256)
				dead_keys[dead_count++] = key;
			continue;
		}

		const char *rule_name = (ti.rule_id < num_rules)
			? rules[ti.rule_id].name : RULE_NOT_MATCH;

		/* Обновление cmdline + comm из /proc */
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

		/* Разделение cmdline на exec + args */
		char exec_path[CMDLINE_MAX], args[CMDLINE_MAX];
		cmdline_split(pi.cmdline, pi.cmdline_len,
			      exec_path, sizeof(exec_path),
			      args, sizeof(args));
		if ((int)strlen(args) > cfg_cmdline_max_len) {
			args[cfg_cmdline_max_len] = '\0';
			strcat(args, "...");
		}

		/* Разрешение cgroup: отображаемое имя + реальный путь ФС */
		char cg_path[PATH_MAX_LEN], cg_fs_path[PATH_MAX_LEN];
		resolve_cgroup_ts(pi.cgroup_id, cg_path, sizeof(cg_path));
		resolve_cgroup_fs_ts(pi.cgroup_id, cg_fs_path, sizeof(cg_fs_path));

		/* Вычисление времён */
		double uptime_sec = mono_now - (double)pi.start_ns / 1e9;
		if (uptime_sec < 0) uptime_sec = 0;
		/* Коэффициент использования CPU */
		double cpu_ratio = 0;
		if (elapsed_ns > 0) {
			__u64 prev_ns = cpu_prev_lookup(key);
			cpu_ratio = (prev_ns > 0 && pi.cpu_ns >= prev_ns)
				? (double)(pi.cpu_ns - prev_ns) / elapsed_ns : 0;
		}
		cpu_prev_update(key, pi.cpu_ns);

		/* Сбор уникальных cgroup для cgroup-метрик + кэширование значений */
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
					read_cgroup_cpu_max(cg_fs_path,
						&seen_cg[cg_idx].cpu_max,
						&seen_cg[cg_idx].cpu_max_period);
					read_cgroup_cpu_stat(cg_fs_path,
						&seen_cg[cg_idx].cpu_nr_periods,
						&seen_cg[cg_idx].cpu_nr_throttled,
						&seen_cg[cg_idx].cpu_throttled_usec);
					seen_cg[cg_idx].pids_cur =
						read_cgroup_value(cg_fs_path, "pids.current");
					seen_cg[cg_idx].read = 1;
				}
				seen_cg_count++;
			}
		}

		/* Потоковая запись события снапшота напрямую в файл событий (без буферизации) */
		if (g_http_cfg.enabled) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			cev.timestamp_ns = snap_timestamp_ns;
			snprintf(cev.event_type, sizeof(cev.event_type), "snapshot");
			snprintf(cev.rule, sizeof(cev.rule), "%s", rule_name);
#ifndef NO_TAGS
			snprintf(cev.tags, sizeof(cev.tags), "%s", tags_lookup_copy(snap_tgid, snap_data, key));
#endif
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

			/* Новые поля из proc_info */
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

			/* Вытеснение: последний процесс, который принудительно вытеснил нас */
			cev.preempted_by_pid = pi.preempted_by_pid;
			memcpy(cev.preempted_by_comm,
			       pi.preempted_by_comm, COMM_LEN);

			/* pwd через readlink /proc/PID/cwd (только в userspace) */
			{
				char cwd_path[64];
				snprintf(cwd_path, sizeof(cwd_path),
					 "/proc/%u/cwd", pi.tgid);
				ssize_t cwd_len = readlink(cwd_path, cev.pwd,
							   sizeof(cev.pwd) - 1);
				if (cwd_len > 0)
					cev.pwd[cwd_len] = '\0';
			}

			/* Заполнение cgroup-метрик из кэша */
			if (cg_idx >= 0 && seen_cg[cg_idx].read) {
				cev.cgroup_memory_max = seen_cg[cg_idx].mem_max;
				cev.cgroup_memory_current = seen_cg[cg_idx].mem_cur;
				cev.cgroup_swap_current = seen_cg[cg_idx].swap_cur;
				cev.cgroup_cpu_weight = seen_cg[cg_idx].cpu_weight;
				cev.cgroup_cpu_max = seen_cg[cg_idx].cpu_max;
				cev.cgroup_cpu_max_period = seen_cg[cg_idx].cpu_max_period;
				cev.cgroup_cpu_nr_periods = seen_cg[cg_idx].cpu_nr_periods;
				cev.cgroup_cpu_nr_throttled = seen_cg[cg_idx].cpu_nr_throttled;
				cev.cgroup_cpu_throttled_usec = seen_cg[cg_idx].cpu_throttled_usec;
				cev.cgroup_pids_current = seen_cg[cg_idx].pids_cur;
			}

			/* Количество открытых TCP-соединений */
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
	free(all_values);

	/* Сброс карты агрегации UDP перед разблокировкой пакета */
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
				snprintf(cev.rule, sizeof(cev.rule), "%s", RULE_NOT_MATCH);
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
	#ifndef NO_TAGS
				snprintf(cev.tags, sizeof(cev.tags),
						 "%s", tags_lookup_copy(snap_tgid, snap_data, ukey.tgid));
#endif
				}
				ef_append(&cev, cfg_hostname);
				udp_count++;
			}
			bpf_map_delete_elem(udp_fd, &ukey);
		}
		if (udp_count > 0)
			log_debug("UDP flush: %d aggregates", udp_count);
	}

	/* Сброс карты агрегации ICMP перед разблокировкой пакета */
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
				snprintf(cev.rule, sizeof(cev.rule), "%s", RULE_NOT_MATCH);
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

	/* Генерация событий использования дисков */
	if (g_http_cfg.enabled && cfg_disk_tracking_enabled) {
		int disk_ev = emit_disk_usage_events(snap_timestamp_ns,
						     cfg_hostname);
		snap_count += disk_ev;
	}

	/* Разблокировка пакета — снапшот завершён, безопасно для swap/snapshot_fd */
	ef_batch_unlock();

	/* Очистка мёртвых процессов (BPF-карты — без lock) */
	for (int i = 0; i < dead_count; i++) {
		bpf_map_delete_elem(tracked_map_fd, &dead_keys[i]);
		bpf_map_delete_elem(proc_map_fd, &dead_keys[i]);
		cpu_prev_remove(dead_keys[i]);
	}

	log_ts("INFO", "snapshot: %d PIDs, %d cgroups, %d events",
	       pid_count, seen_cg_count, snap_count);

	/* snap_count событий были потоково записаны через ef_append выше */

	/* Логируем статистику ring buffer'ов */
	{
		__u32 key = 0;
		struct ringbuf_stats rs = {0};
		int stats_fd = bpf_map__fd(skel->maps.ringbuf_stats);
		if (stats_fd >= 0 &&
		    bpf_map_lookup_elem(stats_fd, &key, &rs) == 0) {
			if (rs.drop_proc || rs.drop_file || rs.drop_net || rs.drop_cgroup) {
				log_ts("WARN",
				       "ringbuf drops: proc=%llu/%llu file=%llu/%llu net=%llu/%llu cgroup=%llu/%llu",
				       (unsigned long long)rs.drop_proc,
				       (unsigned long long)rs.total_proc,
				       (unsigned long long)rs.drop_file,
				       (unsigned long long)rs.total_file,
				       (unsigned long long)rs.drop_net,
				       (unsigned long long)rs.total_net,
				       (unsigned long long)rs.drop_cgroup,
				       (unsigned long long)rs.total_cgroup);
			} else if (cfg_log_level >= 2) {
				log_ts("DEBUG",
				       "ringbuf totals: proc=%llu file=%llu net=%llu cgroup=%llu",
				       (unsigned long long)rs.total_proc,
				       (unsigned long long)rs.total_file,
				       (unsigned long long)rs.total_net,
				       (unsigned long long)rs.total_cgroup);
			}
		}
	}

	if (dead_count > 0) {
#ifndef NO_TAGS
		/* Удаляем теги мёртвых процессов (wrlock) */
		pthread_rwlock_wrlock(&g_tags_lock);
		for (int i = 0; i < dead_count; i++)
			tags_remove(dead_keys[i]);
		pthread_rwlock_unlock(&g_tags_lock);
#endif
		log_ts("INFO", "cleaned up %d dead PIDs", dead_count);
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
	log_ts("INFO", "poll thread '%s' started", a->name);

	while (g_running) {
		int n = ring_buffer__consume(a->rb);
		if (n > 0)
			continue;  /* есть данные — сразу проверяем ещё */
		if (n < 0 && n != -EINTR) {
			log_ts("ERROR", "poll thread '%s': ring_buffer__consume: %d",
			       a->name, n);
			break;
		}
		/* Нет данных — ждём через epoll, чтобы не крутить CPU вхолостую */
		int err = ring_buffer__poll(a->rb, 100);
		if (err < 0 && err != -EINTR) {
			log_ts("ERROR", "poll thread '%s': ring_buffer__poll: %d",
			       a->name, err);
			break;
		}
	}

	log_ts("INFO", "poll thread '%s' stopped", a->name);
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
		fprintf(stderr, "FATAL: no rules loaded\n");
		return 1;
	}

	/* Инициализация кольцевого буфера событий в памяти */
	if (g_http_cfg.enabled) {
		if (ef_init((__u64)cfg_max_data_size) < 0) {
			fprintf(stderr, "FATAL: event ring buffer init failed\n");
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
		fprintf(stderr, "FATAL: failed to open BPF skeleton\n");
		return 1;
	}

	/* Установка rodata перед загрузкой */
	skel->rodata->max_exec_events_per_sec = (__u32)cfg_exec_rate_limit;

	/* Условное отключение программ отслеживания сети */
	if (!cfg_net_tracking_enabled) {
		/* Жизненный цикл соединения: connect/accept/close */
		BPF_PROG_DISABLE(skel->progs.kp_tcp_v4_connect);
		BPF_PROG_DISABLE(skel->progs.krp_tcp_v4_connect);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_v6_connect);
		BPF_PROG_DISABLE(skel->progs.krp_tcp_v6_connect);
		BPF_PROG_DISABLE(skel->progs.krp_inet_csk_accept);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_close);
	}
	if (!cfg_net_tracking_enabled || !cfg_net_track_bytes) {
		/* Подсчёт байтов на соединение (kprobe enter + kretprobe) */
		BPF_PROG_DISABLE(skel->progs.kp_tcp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_recvmsg);
	}
	if (!cfg_net_tracking_enabled) {
		/* Агрегированный подсчёт байтов на процесс (TCP + UDP kretprobes) */
		BPF_PROG_DISABLE(skel->progs.ret_tcp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.ret_tcp_recvmsg);
		BPF_PROG_DISABLE(skel->progs.ret_udp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.ret_udp_recvmsg);
	}

	/* Условное отключение программ отслеживания файлов */
	if (!cfg_file_tracking_enabled) {
		BPF_PROG_DISABLE(skel->progs.handle_openat_enter);
		BPF_PROG_DISABLE(skel->progs.handle_openat_exit);
		BPF_PROG_DISABLE(skel->progs.handle_close_enter);
		BPF_PROG_DISABLE(skel->progs.handle_read_enter);
		BPF_PROG_DISABLE(skel->progs.handle_read_exit);
		BPF_PROG_DISABLE(skel->progs.handle_write_enter);
		BPF_PROG_DISABLE(skel->progs.handle_write_exit);
	}

	/* Условное отключение программ отслеживания безопасности */
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

	/* Tracepoints cgroup_freeze/cgroup_unfreeze используют другой
	 * layout (trace_event_raw_cgroup, без поля val) и могут не
	 * поддерживать BPF attach на некоторых ядрах (например, 6.1).
	 * Отключаем — cgroup_notify_frozen покрывает ту же информацию. */
	BPF_PROG_DISABLE(skel->progs.handle_cgroup_freeze);
	BPF_PROG_DISABLE(skel->progs.handle_cgroup_unfreeze);

	/* Загрузка BPF-программ */
	if (process_metrics_bpf__load(skel)) {
		fprintf(stderr, "FATAL: failed to load BPF programs\n");
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

	/* Передача конфигурации отслеживания сети в BPF-карты */
	if (cfg_net_tracking_enabled) {
		int net_cfg_fd = bpf_map__fd(skel->maps.net_cfg);
		__u32 key0 = 0;
		struct net_config nc = {
			.enabled = 1,
			.track_bytes = (__u8)cfg_net_track_bytes,
		};
		bpf_map_update_elem(net_cfg_fd, &key0, &nc, BPF_ANY);
	}

	/* Передача конфигурации отслеживания безопасности в BPF-карты */
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

	/* Получение файловых дескрипторов карт */
	tracked_map_fd = bpf_map__fd(skel->maps.tracked_map);
	proc_map_fd    = bpf_map__fd(skel->maps.proc_map);

	/* Ring buffers: по одному на каждый тип событий.
	 * Каждый будет обслуживаться отдельным потоком poll. */
	struct ring_buffer *rb_proc = ring_buffer__new(
		bpf_map__fd(skel->maps.events_proc), handle_event, NULL, NULL);
	struct ring_buffer *rb_file = ring_buffer__new(
		bpf_map__fd(skel->maps.events_file), handle_event, NULL, NULL);
	struct ring_buffer *rb_net = ring_buffer__new(
		bpf_map__fd(skel->maps.events_net), handle_event, NULL, NULL);
	struct ring_buffer *rb_cgroup = ring_buffer__new(
		bpf_map__fd(skel->maps.events_cgroup), handle_cgroup_event,
		NULL, NULL);
	if (!rb_proc || !rb_file || !rb_net || !rb_cgroup) {
		fprintf(stderr, "FATAL: failed to create ring buffers\n");
		if (rb_proc)   ring_buffer__free(rb_proc);
		if (rb_file)   ring_buffer__free(rb_file);
		if (rb_net)    ring_buffer__free(rb_net);
		if (rb_cgroup) ring_buffer__free(rb_cgroup);
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Сигналы */
	signal(SIGTERM, sig_term);
	signal(SIGINT,  sig_term);
	signal(SIGHUP,  sig_hup);

	/* Однократное сканирование при запуске: поиск уже работающих процессов */
	initial_scan();
	refresh_boot_to_wall();

	/* Запуск HTTP-сервера, если включён */
	if (g_http_cfg.enabled) {
		if (http_server_start(&g_http_cfg) < 0) {
			fprintf(stderr, "FATAL: HTTP server start failed\n");
			ring_buffer__free(rb_proc);
			ring_buffer__free(rb_file);
			ring_buffer__free(rb_net);
			ring_buffer__free(rb_cgroup);
			process_metrics_bpf__destroy(skel);
			return 1;
		}
	}

	log_ts("INFO", "started: %d rules, snapshot every %ds, "
	       "exec_rate_limit=%d/s, http_server=%s, "
	       "cgroup_metrics=%s, refresh_proc=%s, "
	       "net_tracking=%s%s, file_tracking=%s%s, "
	       "security=[retransmit=%s syn=%s rst=%s udp=%s icmp=%s open_conn=%s], "
	       "disk_tracking=%s, ring_buffer_size=%lld",
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
	       (long long)cfg_max_data_size);

	/* ── Потоки poll: по одному на каждый ring buffer ────────────────
	 *
	 * Каждый поток вызывает ring_buffer__poll() в цикле, пока g_running.
	 * handle_event внутри использует гранулярные rwlock'и:
	 *   g_tags_lock   — tags_ht (lookup/store/remove/inherit)
	 *   g_cgroup_lock — cgroup_cache (resolve_cgroup_fast)
	 * handle_cgroup_event обновляет cgroup_cache под wrlock
	 *   при mkdir/rmdir/rename.
	 * Основной поток занимается snapshot и config reload.
	 */
	struct poll_thread_arg args[4] = {
		{ .rb = rb_proc,   .name = "proc"   },
		{ .rb = rb_file,   .name = "file"   },
		{ .rb = rb_net,    .name = "net"    },
		{ .rb = rb_cgroup, .name = "cgroup" },
	};
	pthread_t poll_threads[4];

	for (int i = 0; i < 4; i++) {
		if (pthread_create(&poll_threads[i], NULL, poll_thread_fn, &args[i])) {
			fprintf(stderr, "FATAL: failed to create poll thread '%s'\n",
				args[i].name);
			g_running = 0;
			break;
		}
	}

	/* Главный цикл — снапшот и перезагрузка конфигурации */
	time_t last_snapshot = 0;

	while (g_running) {
		sleep(1);

		/* Перезагрузка конфигурации по SIGHUP */
		if (g_reload) {
			g_reload = 0;
			log_ts("INFO", "SIGHUP: reloading rules...");

			/* Очистка всего отслеживания — удаляем с начала каждый раз */
			__u32 del_key;
			while (bpf_map_get_next_key(tracked_map_fd, NULL, &del_key) == 0) {
				bpf_map_delete_elem(tracked_map_fd, &del_key);
				bpf_map_delete_elem(proc_map_fd, &del_key);
			}

			tags_clear_ts();
			parse_rules_from_config(cfg_config_file);
			build_cgroup_cache_ts();

			cpu_prev_count = 0;
			prev_snapshot_ts = (struct timespec){0};
			initial_scan();
		}

		/* Периодический снапшот */
		time_t now = time(NULL);
		if (now - last_snapshot >= cfg_snapshot_interval) {
			/* build_cgroup_cache и refresh_boot_to_wall вызываются
			 * внутри write_snapshot под wrlock */
			write_snapshot();
			last_snapshot = now;
		}
	}

	/* Ждём завершения потоков poll */
	for (int i = 0; i < 4; i++)
		pthread_join(poll_threads[i], NULL);

	/* Остановка HTTP-сервера */
	http_server_stop();

	/* Очистка файла событий */
	ef_cleanup();

	ring_buffer__free(rb_proc);
	ring_buffer__free(rb_file);
	ring_buffer__free(rb_net);
	ring_buffer__free(rb_cgroup);
	process_metrics_bpf__destroy(skel);
	free_rules();

	log_ts("INFO", "stopped");
	return 0;
}
