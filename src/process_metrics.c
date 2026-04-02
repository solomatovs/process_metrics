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
#include "pm_config.h"
#include "pm_state.h"
#include "pm_functions.h"
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

/* rule, num_rules — определены здесь, объявлены в pm_state.h */
struct rule rules[MAX_RULES];
int num_rules;

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
	.disk_tracking_enabled = 1,
	.max_cgroups = MAX_CGROUPS,
	.emit = {
		.exec = 1, .fork = 1, .exit = 1, .oom_kill = 1,
		.signal = 1, .chdir = 1,
		.file_open = 1, .file_close = 1, .file_rename = 1,
		.file_unlink = 1, .file_truncate = 1, .file_chmod = 1, .file_chown = 1,
		.net_listen = 1, .net_connect = 1, .net_accept = 1, .net_close = 1,
		.tcp_retransmit = 1, .syn_recv = 1, .rst = 1, .cgroup = 1,
	},
};

/* Последние известные размеры BPF map'ов (обновляются refresh/snapshot).
 * Используется для адаптивного refresh_interval и heartbeat диагностики. */
/* Глобальное состояние — определения (объявлены в pm_state.h) */
int g_last_map_count = 0;
int g_last_conn_count = 0;
volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_reload = 0;
struct process_metrics_bpf *skel;
int tracked_map_fd, proc_map_fd, missed_exec_fd;

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
pthread_rwlock_t g_tags_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t g_cgroup_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t g_pidtree_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Аргумент для потока poll */
struct poll_thread_arg {
	struct ring_buffer *rb;
	const char *name;
	volatile __u64 events; /* атомарный счётчик обработанных событий */
	volatile __u64 polls;  /* атомарный счётчик итераций poll-цикла */
};

/* Предварительные объявления */
static void build_cgroup_cache(void);
void cmdline_split(const char *raw, __u16 len, char *exec_out, int exec_len, char *args_out,
		   int args_len);
void fast_strcpy(char *dst, int cap, const char *src);
static const char *event_type_name(enum event_type type);
void fill_from_proc_info(struct metric_event *cev, const struct proc_info *pi);
void fill_identity_from_proc_info(struct metric_event *cev, const struct proc_info *pi);
void fill_metrics_from_proc_info(struct metric_event *cev, const struct proc_info *pi);
void fill_from_track_info(struct metric_event *cev, const struct track_info *ti,
			  int tracked);
static void fill_proc_info_from_event(struct proc_info *pi, const struct event *e);
void fill_track_info_for_pid(struct metric_event *cev, __u32 tgid);
void fill_tags(struct metric_event *cev, __u32 tgid);
void fill_cgroup(struct metric_event *cev, __u64 cgroup_id);
void fill_pwd(struct metric_event *cev, __u32 tgid);
void fill_parent_pids(struct metric_event *cev);
void ensure_tags(__u32 tgid, char *buf, int buflen);
/* log_ts определён в log.h */

/* Смещение от boot-time к wall-clock (вычисляется однократно при старте,
 * обновляется каждый snapshot). BPF отправляет bpf_ktime_get_boot_ns(),
 * wall_ns = boot_ns + g_boot_to_wall_ns. */
__s64 g_boot_to_wall_ns;

void refresh_boot_to_wall(void)
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

/* TAGS_MAX_LEN определён в pm_state.h */

__u32 tags_tgid[TAGS_HT_SIZE];		   /*  64 KB — компактный индекс */
char tags_data[TAGS_HT_SIZE][TAGS_MAX_LEN]; /*   8 MB — данные           */

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
int try_track_pid(__u32 pid);

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
		if (tags_tgid[slot] == tgid) {
			found = 1;
			break;
		}
		if (tags_tgid[slot] == 0)
			return; /* не найден */
	}
	if (!found)
		return;

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

void tags_inherit_ts(__u32 child, __u32 parent)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_inherit(child, parent);
	pthread_rwlock_unlock(&g_tags_lock);
}

void tags_remove_ts(__u32 tgid)
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

/* ── pid tree: глобальная хеш-таблица pid→ppid для цепочек предков ───
 *
 * Покрывает ВСЕ процессы системы (не только отслеживаемые), чтобы
 * цепочки предков могли проходить через неотслеживаемых промежуточных.
 *
 * Open-addressing + linear probing + backward-shift deletion.
 * Память: pt_pid[65536] + pt_ppid[65536] = 512 КБ.
 */

__u32 pt_pid[PIDTREE_HT_SIZE];  /* ключи: pid   (0 = пустой слот) */
__u32 pt_ppid[PIDTREE_HT_SIZE]; /* значения: ppid                 */

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
__u32 pidtree_lookup_in(const __u32 *p_pid, const __u32 *p_ppid, __u32 pid)
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

void pidtree_remove(__u32 pid)
{
	__u32 idx = pidtree_hash(pid);
	__u32 slot = 0;
	int found = 0;

	for (int i = 0; i < PIDTREE_HT_SIZE; i++) {
		slot = (idx + i) & (PIDTREE_HT_SIZE - 1);
		if (pt_pid[slot] == pid) {
			found = 1;
			break;
		}
		if (pt_pid[slot] == 0)
			return;
	}
	if (!found)
		return;

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
__u64 pt_generation;

void pidtree_store_ts(__u32 pid, __u32 ppid)
{
	pthread_rwlock_wrlock(&g_pidtree_lock);
	pidtree_store(pid, ppid);
	pt_generation++;
	pthread_rwlock_unlock(&g_pidtree_lock);
}

void pidtree_remove_ts(__u32 pid)
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
static __u8 cc_len[CHAIN_CACHE_SIZE];
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
int pidtree_walk_chain(const __u32 *p_pid, const __u32 *p_ppid, __u32 pid, __u32 *out,
		       int max_depth)
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
	int n = pidtree_walk_chain(pt_pid, pt_ppid, pid, chain, EV_PARENT_PIDS_MAX);

	/* Сохраняем в кеш (direct-mapped, перезаписывает предыдущего) */
	cc_pid[slot] = pid;
	cc_gen[slot] = gen;
	cc_len[slot] = (__u8)n;
	memcpy(cc_chain[slot], chain, n * sizeof(__u32));

	memcpy(out, chain, n * sizeof(__u32));
	*out_len = (__u8)n;

	pthread_rwlock_unlock(&g_pidtree_lock);
}

/* pidtree_get_chain_copy — moved to snapshot.c */

/*
 * Заполнить parent_pids в metric_event (потокобезопасно, для обработчиков событий).
 */
void fill_parent_pids(struct metric_event *cev)
{
	pidtree_get_chain_ts(cev->pid, cev->parent_pids, &cev->parent_pids_len);
}

/*
 * Преобразует enum event_type в строковое имя для CSV/ClickHouse.
 */
/*
 * Проверяет, разрешена ли отправка события данного типа в CSV.
 * Возвращает 1 если разрешена, 0 если отключена в конфиге.
 * Без default — clang -Wswitch предупредит при добавлении нового enum.
 */
static int event_emit_enabled(enum event_type type)
{
	switch (type) {
	case EVENT_FORK:
		return cfg.emit.fork;
	case EVENT_EXEC:
		return cfg.emit.exec;
	case EVENT_EXIT:
		return cfg.emit.exit;
	case EVENT_OOM_KILL:
		return cfg.emit.oom_kill;
	case EVENT_FILE_CLOSE:
		return cfg.emit.file_close;
	case EVENT_FILE_OPEN:
		return cfg.emit.file_open;
	case EVENT_FILE_RENAME:
		return cfg.emit.file_rename;
	case EVENT_FILE_UNLINK:
		return cfg.emit.file_unlink;
	case EVENT_FILE_TRUNCATE:
		return cfg.emit.file_truncate;
	case EVENT_FILE_CHMOD:
		return cfg.emit.file_chmod;
	case EVENT_FILE_CHOWN:
		return cfg.emit.file_chown;
	case EVENT_NET_CLOSE:
		return cfg.emit.net_close;
	case EVENT_NET_LISTEN:
		return cfg.emit.net_listen;
	case EVENT_NET_CONNECT:
		return cfg.emit.net_connect;
	case EVENT_NET_ACCEPT:
		return cfg.emit.net_accept;
	case EVENT_SIGNAL:
		return cfg.emit.signal;
	case EVENT_TCP_RETRANSMIT:
		return cfg.emit.tcp_retransmit;
	case EVENT_SYN_RECV:
		return cfg.emit.syn_recv;
	case EVENT_RST:
		return cfg.emit.rst;
	case EVENT_CHDIR:
		return cfg.emit.chdir;
	case EVENT_CGROUP_MKDIR:
	case EVENT_CGROUP_RMDIR:
	case EVENT_CGROUP_RENAME:
	case EVENT_CGROUP_RELEASE:
	case EVENT_CGROUP_ATTACH_TASK:
	case EVENT_CGROUP_TRANSFER_TASKS:
	case EVENT_CGROUP_POPULATED:
	case EVENT_CGROUP_FREEZE:
	case EVENT_CGROUP_UNFREEZE:
	case EVENT_CGROUP_FROZEN:
		return cfg.emit.cgroup;
	}
	return 0;
}

/*
 * Классификаторы типов событий.
 * Каждая функция — одна группа, используется вместо цепочек if (type == X || ...).
 */
/*
 * Проверяет, нужно ли формировать metric_event и отправлять в CSV.
 * Объединяет: тип разрешён в конфиге + HTTP-сервер включён.
 */
static int should_emit_event(enum event_type type)
{
	return cfg.http.enabled && event_emit_enabled(type);
}

/* should_emit_snapshot, should_emit_conn_snapshot — moved to snapshot.c */

int should_emit_icmp(void)
{
	return cfg.icmp_tracking && cfg.http.enabled;
}

int should_emit_disk(void)
{
	return cfg.disk_tracking_enabled && cfg.http.enabled;
}

/* should_include_conn — moved to snapshot.c */

/*
 * Close-события допускают неотслеживаемые процессы — процесс мог
 * завершиться до обработки close из ring buffer.
 */
static int is_close_event(enum event_type t)
{
	return t == EVENT_FILE_CLOSE || t == EVENT_NET_CLOSE;
}

/*
 * Проверяет, нужно ли пропустить событие от неотслеживаемого процесса.
 * Возвращает 1 (пропустить) если процесс не tracked и это не close-событие.
 */
static int should_skip_untracked(enum event_type type, int tracked)
{
	return !tracked && !is_close_event(type);
}

/*
 * Извлекает тип события из сырых данных ring buffer.
 * Все BPF event structs имеют __u32 type по смещению 0.
 */
static enum event_type event_type_from_data(const void *data)
{
	return (enum event_type)(*(const __u32 *)data);
}

static int is_exec_event(enum event_type t)
{
	return t == EVENT_EXEC;
}
static int is_fork_event(enum event_type t)
{
	return t == EVENT_FORK;
}
static int is_exit_event(enum event_type t)
{
	return t == EVENT_EXIT;
}
static int is_chdir_event(enum event_type t)
{
	return t == EVENT_CHDIR;
}
static int is_oom_event(enum event_type t)
{
	return t == EVENT_OOM_KILL;
}

static int is_file_event(enum event_type t)
{
	return t == EVENT_FILE_CLOSE || t == EVENT_FILE_OPEN || t == EVENT_FILE_RENAME ||
	       t == EVENT_FILE_UNLINK || t == EVENT_FILE_TRUNCATE || t == EVENT_FILE_CHMOD ||
	       t == EVENT_FILE_CHOWN;
}

static int is_net_event(enum event_type t)
{
	return t == EVENT_NET_CLOSE || t == EVENT_NET_LISTEN || t == EVENT_NET_CONNECT ||
	       t == EVENT_NET_ACCEPT;
}

static int is_signal_event(enum event_type t)
{
	return t == EVENT_SIGNAL;
}

static int is_retransmit_event(enum event_type t)
{
	return t == EVENT_TCP_RETRANSMIT;
}

static int is_syn_event(enum event_type t)
{
	return t == EVENT_SYN_RECV;
}

static int is_rst_event(enum event_type t)
{
	return t == EVENT_RST;
}

/*
 * Преобразует TCP state number в имя.
 * Linux kernel TCP states (include/net/tcp_states.h).
 */
static const char *tcp_state_name(__u8 state)
{
	switch (state) {
	case 1:  return "ESTABLISHED";
	case 2:  return "SYN_SENT";
	case 3:  return "SYN_RECV";
	case 4:  return "FIN_WAIT1";
	case 5:  return "FIN_WAIT2";
	case 6:  return "TIME_WAIT";
	case 7:  return "CLOSE";
	case 8:  return "CLOSE_WAIT";
	case 9:  return "LAST_ACK";
	case 10: return "LISTEN";
	case 11: return "CLOSING";
	}
	return "";
}

/*
 * Преобразует номер сигнала в имя (SIGKILL, SIGTERM, ...).
 * Linux x86_64 signal numbers.
 */
static const char *signal_name(int sig)
{
	switch (sig) {
	case 1:  return "SIGHUP";
	case 2:  return "SIGINT";
	case 3:  return "SIGQUIT";
	case 4:  return "SIGILL";
	case 5:  return "SIGTRAP";
	case 6:  return "SIGABRT";
	case 7:  return "SIGBUS";
	case 8:  return "SIGFPE";
	case 9:  return "SIGKILL";
	case 10: return "SIGUSR1";
	case 11: return "SIGSEGV";
	case 12: return "SIGUSR2";
	case 13: return "SIGPIPE";
	case 14: return "SIGALRM";
	case 15: return "SIGTERM";
	case 16: return "SIGSTKFLT";
	case 17: return "SIGCHLD";
	case 18: return "SIGCONT";
	case 19: return "SIGSTOP";
	case 20: return "SIGTSTP";
	case 21: return "SIGTTIN";
	case 22: return "SIGTTOU";
	case 23: return "SIGURG";
	case 24: return "SIGXCPU";
	case 25: return "SIGXFSZ";
	case 26: return "SIGVTALRM";
	case 27: return "SIGPROF";
	case 28: return "SIGWINCH";
	case 29: return "SIGIO";
	case 30: return "SIGPWR";
	case 31: return "SIGSYS";
	}
	return "";
}

/*
 * Резолвит имя правила из rule_id.
 */
/*
 * Инициализация metric_event: обнуление + установка event_type.
 */
static void init_metric_event(struct metric_event *cev)
{
	memset(cev, 0, sizeof(*cev));
}

static void set_event_type(struct metric_event *cev, enum event_type type)
{
	fast_strcpy(cev->event_type, sizeof(cev->event_type), event_type_name(type));
}

/*
 * Lookup proc_info по tgid и заполнить metric_event.
 * Возвращает 1 если найден, 0 если нет.
 */
/*
 * Создаёт запись proc_info из BPF-события и сохраняет в proc_map.
 * Используется при позднем трекинге (exec).
 */
static void store_proc_info_from_event(const struct event *e)
{
	struct proc_info pi = {0};
	fill_proc_info_from_event(&pi, e);
	bpf_map_update_elem(proc_map_fd, &e->tgid, &pi, BPF_ANY);
}

/*
 * Контекст события — общие поля, извлечённые из любого BPF event struct.
 * Все BPF struct'ы содержат type, tgid (или sender_tgid), cgroup_id,
 * но на разных смещениях — поэтому вызывающий код извлекает их.
 */
struct event_ctx {
	enum event_type type;
	__u32 tgid;
	__u32 uid;
	__u64 timestamp_ns;
	__u64 cgroup_id;
	const char *comm;         /* NULL если нет в BPF event */
	const char *thread_name;  /* NULL если нет в BPF event */
};

/*
 * Общая подготовка metric_event: init + общие поля + track_info + tags + metrics + cgroup.
 * После вызова остаётся: fill_from_*_event (специфика) + finalize + ef_append.
 */
static void prepare_metric_event(struct metric_event *cev, const struct event_ctx *ctx)
{
	init_metric_event(cev);
	set_event_type(cev, ctx->type);

	/* Базовая идентификация из proc_map (baseline) */
	cev->pid = ctx->tgid;
	{
		struct proc_info pi;
		if (bpf_map_lookup_elem(proc_map_fd, &ctx->tgid, &pi) == 0) {
			fill_identity_from_proc_info(cev, &pi);
			fill_metrics_from_proc_info(cev, &pi);
		}
	}

	/* Override из BPF события (актуальнее на момент события) */
	cev->uid = ctx->uid;
	cev->timestamp_ns = ctx->timestamp_ns + (__u64)g_boot_to_wall_ns;
	if (ctx->comm)
		memcpy(cev->comm, ctx->comm, COMM_LEN);
	if (ctx->thread_name)
		memcpy(cev->thread_name, ctx->thread_name, COMM_LEN);

	/* Обогащение из BPF maps */
	fill_track_info_for_pid(cev, ctx->tgid);
	fill_tags(cev, ctx->tgid);
	fill_cgroup(cev, ctx->cgroup_id);
}

/*
 * Финализация metric_event: pwd + parent_pids.
 */
static void finalize_metric_event(struct metric_event *cev, __u32 tgid)
{
	fill_pwd(cev, tgid);
	fill_parent_pids(cev);
}

/*
 * Заполняет rule/tags из tracked_map для процесса.
 * Если процесс не отслеживается — rule остаётся RULE_NOT_MATCH (из init_metric_event).
 * Используется для sec events (retransmit, syn_recv, rst) где tracked_map
 * может не содержать запись.
 */
/*
 * Проверяет, отслеживается ли процесс. Заполняет ti если найден.
 * Возвращает 1 если tracked, 0 если нет.
 */
int is_pid_tracked(__u32 tgid, struct track_info *ti)
{
	return bpf_map_lookup_elem(tracked_map_fd, &tgid, ti) == 0;
}

/*
 * Устанавливает rule в metric_event из строки.
 */
void fill_rule(struct metric_event *cev, const char *rname)
{
	fast_strcpy(cev->rule, sizeof(cev->rule), rname);
}

void fill_track_info_for_pid(struct metric_event *cev, __u32 tgid)
{
	struct track_info ti;
	if (is_pid_tracked(tgid, &ti))
		fill_from_track_info(cev, &ti, 1);
}

/*
 * Заполняет теги в metric_event из proc_map cmdline → match_rules.
 */
void fill_tags(struct metric_event *cev, __u32 tgid)
{
	ensure_tags(tgid, cev->tags, sizeof(cev->tags));
}

/*
 * Резолвит имя правила из rule_id.
 */
static const char *resolve_rule_name(__u16 rule_id)
{
	return (rule_id < num_rules) ? rules[rule_id].name : RULE_NOT_MATCH;
}

/*
 * Резолвит имя правила из track_info, если процесс отслеживается.
 */
const char *resolve_rule_tracked(const struct track_info *ti, int tracked)
{
	return tracked ? resolve_rule_name(ti->rule_id) : RULE_NOT_MATCH;
}

/*
 * Резолвит имя правила для процесса с fallback на родителя.
 * Используется для OOM/signal когда процесс может быть не в tracked_map.
 */
/*
 * Резолвит правило для proc event (exit/oom).
 * Порядок: BPF rule_id → tracked_map → try_track → fallback ppid.
 */
static const char *resolve_rule_for_proc_event(const struct event *e)
{
	/* BPF может передать валидный rule_id */
	if (e->rule_id < num_rules)
		return rules[e->rule_id].name;

	/* Попробуем отследить процесс */
	try_track_pid(e->tgid);

	/* Lookup tgid → fallback ppid */
	struct track_info ti;
	if (is_pid_tracked(e->tgid, &ti))
		return resolve_rule_name(ti.rule_id);
	if (e->ppid > 0 && is_pid_tracked(e->ppid, &ti))
		return resolve_rule_name(ti.rule_id);
	return RULE_NOT_MATCH;
}


static const char *event_type_name(enum event_type type)
{
	switch (type) {
	case EVENT_FORK:
		return "fork";
	case EVENT_EXEC:
		return "exec";
	case EVENT_EXIT:
		return "exit";
	case EVENT_OOM_KILL:
		return "oom_kill";
	case EVENT_FILE_CLOSE:
		return "file_close";
	case EVENT_FILE_OPEN:
		return "file_open";
	case EVENT_FILE_RENAME:
		return "file_rename";
	case EVENT_FILE_UNLINK:
		return "file_unlink";
	case EVENT_FILE_TRUNCATE:
		return "file_truncate";
	case EVENT_FILE_CHMOD:
		return "file_chmod";
	case EVENT_FILE_CHOWN:
		return "file_chown";
	case EVENT_NET_CLOSE:
		return "net_close";
	case EVENT_NET_LISTEN:
		return "net_listen";
	case EVENT_NET_CONNECT:
		return "net_connect";
	case EVENT_NET_ACCEPT:
		return "net_accept";
	case EVENT_SIGNAL:
		return "signal";
	case EVENT_TCP_RETRANSMIT:
		return "tcp_retrans";
	case EVENT_SYN_RECV:
		return "syn_recv";
	case EVENT_RST:
		return "rst";
	case EVENT_CHDIR:
		return "chdir";
	/* cgroup events — не используются в CSV, но покрываем для -Wswitch */
	case EVENT_CGROUP_MKDIR:
		return "cgroup_mkdir";
	case EVENT_CGROUP_RMDIR:
		return "cgroup_rmdir";
	case EVENT_CGROUP_RENAME:
		return "cgroup_rename";
	case EVENT_CGROUP_RELEASE:
		return "cgroup_release";
	case EVENT_CGROUP_ATTACH_TASK:
		return "cgroup_attach";
	case EVENT_CGROUP_TRANSFER_TASKS:
		return "cgroup_transfer";
	case EVENT_CGROUP_POPULATED:
		return "cgroup_populated";
	case EVENT_CGROUP_FREEZE:
		return "cgroup_freeze";
	case EVENT_CGROUP_UNFREEZE:
		return "cgroup_unfreeze";
	case EVENT_CGROUP_FROZEN:
		return "cgroup_frozen";
	}
	/* unreachable если enum покрыт полностью;
	 * clang -Wswitch предупредит при добавлении нового enum */
	return "unknown";
}

/*
 * Преобразует RST direction (0=sent, 1=recv) в имя события.
 */
/* Декодирование exit_code: статус (биты 8-15) */
static int exit_status(int exit_code)
{
	return (exit_code >> EXIT_STATUS_SHIFT) & EXIT_STATUS_MASK;
}

/* Декодирование exit_code: сигнал (биты 0-6) */
static int exit_signal(int exit_code)
{
	return exit_code & EXIT_SIG_MASK;
}

static const char *rst_event_name(__u8 direction)
{
	return direction ? "rst_recv" : "rst_sent";
}

/*
 * Заполняет proc_info из BPF struct event (exec/fork).
 * Используется при позднем трекинге — когда процесс не был в proc_map
 * и мы создаём запись из данных BPF-события.
 */
static void fill_proc_info_from_event(struct proc_info *pi, const struct event *e)
{
	pi->tgid = e->tgid;
	pi->ppid = e->ppid;
	pi->uid = e->uid;
	pi->start_ns = e->start_ns;
	pi->cgroup_id = e->cgroup_id;
	memcpy(pi->comm, e->comm, COMM_LEN);
	memcpy(pi->thread_name, e->thread_name, COMM_LEN);
	memcpy(pi->cmdline, e->cmdline, CMDLINE_MAX);
	pi->cmdline_len = e->cmdline_len;
	pi->loginuid = e->loginuid;
	pi->sessionid = e->sessionid;
	pi->euid = e->euid;
	pi->tty_nr = e->tty_nr;
	pi->sched_policy = e->sched_policy;
	pi->mnt_ns_inum = e->mnt_ns_inum;
	pi->pid_ns_inum = e->pid_ns_inum;
	pi->net_ns_inum = e->net_ns_inum;
	pi->cgroup_ns_inum = e->cgroup_ns_inum;
}

/*
 * Заполняет metric_event всеми доступными полями из proc_info.
 * Единая точка копирования — вызывается из ВСЕХ обработчиков событий.
 *
 * Поля, которые НЕ заполняются (специфичны для типа события):
 *   - timestamp_ns, event_type, rule, tags — заполняются обработчиком
 *   - pid, root_pid — заполняются из BPF-события или tracked_map
 *   - cgroup — резолвится отдельно через resolve_cgroup_*
 *   - file_*, net_local/remote_*, sig_*, sec_* — специфичны для типа
 *   - pwd, parent_pids — заполняются отдельными вызовами
 *   - exit_code — только при exit
 */
/*
 * Заполняет идентификацию процесса из proc_info.
 * Базовые значения — перезаписываются fill_from_*_event для BPF-событий.
 * Для snapshot/conn_snapshot — финальные значения (нет BPF event override).
 */
void fill_identity_from_proc_info(struct metric_event *cev,
				  const struct proc_info *pi)
{
	cev->pid = pi->tgid;
	cev->ppid = pi->ppid;
	cev->uid = pi->uid;
	memcpy(cev->comm, pi->comm, COMM_LEN);
	memcpy(cev->thread_name, pi->thread_name, COMM_LEN);
	cmdline_split(pi->cmdline, pi->cmdline_len,
		      cev->exec_path, sizeof(cev->exec_path),
		      cev->args, sizeof(cev->args));
	cev->state = pi->state;
	cev->loginuid = pi->loginuid;
	cev->sessionid = pi->sessionid;
	cev->euid = pi->euid;
	cev->tty_nr = pi->tty_nr;
	cev->sched_policy = pi->sched_policy;
	cev->start_time_ns = pi->start_ns
		? pi->start_ns + (__u64)g_boot_to_wall_ns : 0;
}

/*
 * Заполняет метрики процесса из proc_info.
 * Эти поля не перезаписываются fill_from_*_event — уникальный источник.
 */
void fill_metrics_from_proc_info(struct metric_event *cev,
				 const struct proc_info *pi)
{
	static long cached_page_size = 0;
	if (!cached_page_size) {
		cached_page_size = sysconf(_SC_PAGESIZE);
		if (cached_page_size <= 0)
			cached_page_size = FALLBACK_PAGE_SIZE;
	}

	/* ── CPU ──────────────────────────────────────────────── */
	cev->cpu_ns = pi->cpu_ns;

	/* ── память ───────────────────────────────────────────── */
	cev->rss_bytes = pi->rss_pages * cached_page_size;
	cev->rss_min_bytes = pi->rss_min_pages * cached_page_size;
	cev->rss_max_bytes = pi->rss_max_pages * cached_page_size;
	cev->shmem_bytes = pi->shmem_pages * cached_page_size;
	cev->swap_bytes = pi->swap_pages * cached_page_size;
	cev->vsize_bytes = pi->vsize_pages * cached_page_size;

	/* ── I/O (диск) ───────────────────────────────────────── */
	cev->io_read_bytes = pi->io_read_bytes;
	cev->io_write_bytes = pi->io_write_bytes;
	cev->io_rchar = pi->io_rchar;
	cev->io_wchar = pi->io_wchar;
	cev->io_syscr = pi->io_syscr;
	cev->io_syscw = pi->io_syscw;
	cev->file_opens = pi->file_opens;
	cev->socket_creates = pi->socket_creates;

	/* ── страничные отказы / переключения ─────────────────── */
	cev->maj_flt = pi->maj_flt;
	cev->min_flt = pi->min_flt;
	cev->nvcsw = pi->nvcsw;
	cev->nivcsw = pi->nivcsw;

	/* ── потоки / OOM ─────────────────────────────────────── */
	cev->threads = pi->threads;
	cev->oom_score_adj = pi->oom_score_adj;
	cev->oom_killed = pi->oom_killed;

	/* ── сеть (per-process) ───────────────────────────────── */
	cev->net_tcp_tx_bytes = pi->net_tcp_tx_bytes;
	cev->net_tcp_rx_bytes = pi->net_tcp_rx_bytes;
	cev->net_udp_tx_bytes = pi->net_udp_tx_bytes;
	cev->net_udp_rx_bytes = pi->net_udp_rx_bytes;

	/* ── пространства имён ────────────────────────────────── */
	cev->mnt_ns_inum = pi->mnt_ns_inum;
	cev->pid_ns_inum = pi->pid_ns_inum;
	cev->net_ns_inum = pi->net_ns_inum;
	cev->cgroup_ns_inum = pi->cgroup_ns_inum;

	/* ── вытеснение ───────────────────────────────────────── */
	cev->preempted_by_pid = pi->preempted_by_pid;
	memcpy(cev->preempted_by_comm, pi->preempted_by_comm, COMM_LEN);
}

/*
 * Заполняет ВСЕ поля из proc_info (идентификация + метрики).
 * Используется для snapshot/conn_snapshot где нет BPF event override.
 */
void fill_from_proc_info(struct metric_event *cev,
			 const struct proc_info *pi)
{
	fill_identity_from_proc_info(cev, pi);
	fill_metrics_from_proc_info(cev, pi);
}

/*
 * Заполняет metric_event из track_info (tracked_map).
 * Устанавливает rule, root_pid, is_root.
 * tracked=0 означает процесс не в tracked_map — rule остаётся RULE_NOT_MATCH.
 */
void fill_from_track_info(struct metric_event *cev, const struct track_info *ti, int tracked)
{
	if (tracked && ti) {
		cev->root_pid = ti->root_pid;
		cev->is_root = ti->is_root;
		if (ti->rule_id < num_rules)
			snprintf(cev->rule, sizeof(cev->rule), "%s", rules[ti->rule_id].name);
	}
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
static char pwd_data[PWD_HT_SIZE][EV_PWD_LEN]; /* 512 * 16384 = 8 MB */
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
		if (pwd_tgid[slot] == tgid) {
			found = 1;
			break;
		}
		if (pwd_tgid[slot] == 0)
			return;
	}
	if (!found)
		return;

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

void pwd_remove_ts(__u32 tgid)
{
	pthread_rwlock_wrlock(&g_pwd_lock);
	pwd_remove(tgid);
	pthread_rwlock_unlock(&g_pwd_lock);
}

void pwd_inherit_ts(__u32 child, __u32 parent)
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
void pwd_read_and_store(__u32 tgid)
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
		int n = snprintf(tags + off, tags_size - off, "%s", rules[i].name);
		if (n > 0 && off + n < tags_size)
			off += n;
	}
	if (off == 0 && tags_size > 0)
		tags[0] = '\0';
	return first;
}

/* Предварительные объявления для try_track_pid */
static void cmdline_to_str(const char *raw, __u16 len, char *out, int outlen);
int read_proc_cmdline(__u32 pid, char *dst, int dstlen);
static void track_pid_from_proc(__u32 pid, int rule_id, __u32 root_pid, __u8 is_root);
/*
 * Попытка начать отслеживание неизвестного PID через чтение /proc/<pid>/cmdline.
 * Вызывается, когда file_close/net_close/oom_kill/exit приходит для PID,
 * которого нет в tracked_map. Читает cmdline, сопоставляет со всеми правилами
 * и добавляет в tracked_map + хеш-таблицу тегов при совпадении.
 * Возвращает индекс первого совпавшего правила или -1, если нет совпадения / процесс завершён.
 */
int try_track_pid(__u32 pid)
{
	char cmdline_raw[CMDLINE_MAX];
	int clen = read_proc_cmdline(pid, cmdline_raw, sizeof(cmdline_raw));
	if (clen <= 0)
		return -1;

	char cmdline_str[CMDLINE_MAX + 1];
	cmdline_to_str(cmdline_raw, (__u16)clen, cmdline_str, sizeof(cmdline_str));

	char tags_buf[TAGS_MAX_LEN];
	int first = match_rules_all(cmdline_str, tags_buf, sizeof(tags_buf));
	if (first < 0)
		return -1;
	if (rules[first].ignore)
		return -1;

	track_pid_from_proc(pid, first, pid, 1);
	tags_store_ts(pid, tags_buf);
	LOG_DEBUG(cfg.log_level, "LATE_TRACK: pid=%u rule=%s tags=%s cmdline=%.60s", pid,
		  rules[first].name, tags_buf, cmdline_str);
	return first;
}

/*
 * Гарантирует заполнение tags для PID.
 * Если tags_ht пуст (fork event ещё не обработан) — читает cmdline,
 * матчит правила и сохраняет в tags_ht + копирует в buf.
 */
/*
 * ensure_tags_from_cmdline — матчит теги по готовому cmdline (raw, NUL-separated).
 * Общая логика для ensure_tags и ensure_tags_bpf_event.
 */
static void ensure_tags_from_cmdline(__u32 tgid, char *buf, int buflen, const char *cmdline_raw,
				     int cmdline_len)
{
	if (cmdline_len <= 0)
		return;

	char cmdline_str[CMDLINE_MAX + 1];
	int clen = cmdline_len < CMDLINE_MAX ? cmdline_len : CMDLINE_MAX - 1;
	cmdline_to_str(cmdline_raw, (__u16)clen, cmdline_str, sizeof(cmdline_str));

	char tags_buf[TAGS_MAX_LEN];
	if (match_rules_all(cmdline_str, tags_buf, sizeof(tags_buf)) >= 0) {
		tags_store_ts(tgid, tags_buf);
		snprintf(buf, buflen, "%s", tags_buf);
	}
}

/*
 * ensure_tags — гарантирует наличие тегов для процесса.
 * Источник cmdline: proc_map BPF-карта (O(1) hash lookup).
 * Используется для событий без встроенного cmdline (file, net, signal, snapshot).
 */
void ensure_tags(__u32 tgid, char *buf, int buflen)
{
	tags_lookup_ts(tgid, buf, buflen);
	if (buf[0])
		return;

	if (proc_map_fd < 0)
		return;

	struct proc_info pi;
	if (bpf_map_lookup_elem(proc_map_fd, &tgid, &pi) != 0 || pi.cmdline_len == 0)
		return;

	ensure_tags_from_cmdline(tgid, buf, buflen, pi.cmdline, pi.cmdline_len);
}

/* ── Кэш использования CPU (для вычисления отношения за интервал) ── */
/* struct cpu_prev определён в pm_state.h */

struct cpu_prev cpu_prev_cache[MAX_CPU_PREV];
int cpu_prev_count;

__u64 cpu_prev_lookup(__u32 tgid)
{
	for (int i = 0; i < cpu_prev_count; i++)
		if (cpu_prev_cache[i].tgid == tgid)
			return cpu_prev_cache[i].cpu_ns;
	return 0;
}

void cpu_prev_update(__u32 tgid, __u64 cpu_ns)
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

void cpu_prev_remove(__u32 tgid)
{
	for (int i = 0; i < cpu_prev_count; i++) {
		if (cpu_prev_cache[i].tgid == tgid) {
			cpu_prev_cache[i] = cpu_prev_cache[--cpu_prev_count];
			return;
		}
	}
}

/* ── кэш cgroup ──────────────────────────────────────────────────── */

/* cgroup_entry определён в pm_state.h */
struct cgroup_entry *cgroup_cache;
int cgroup_cache_count;
static char docker_data_root[PATH_MAX_LEN] = "";

/* ── кэш cgroup-метрик (заполняется refresh, читается snapshot) ───── */

/* cgroup_metrics определён в pm_state.h */
struct cgroup_metrics *cg_metrics;
int cg_metrics_count;

/*
 * Определение data-root Docker. Приоритет:
 *   1. cfg.docker_data_root (из файла конфигурации)
 *   2. Распарсенный из cfg.docker_daemon_json (ключ "data-root")
 *   3. Запасной вариант: /var/lib/docker
 */
static void detect_docker_data_root(void)
{
	if (docker_data_root[0])
		return;

	/* Используем явное значение из конфигурации, если задано */
	if (cfg.docker_data_root[0]) {
		snprintf(docker_data_root, sizeof(docker_data_root), "%s", cfg.docker_data_root);
		return;
	}

	/* Пробуем распарсить из daemon.json */
	FILE *f = fopen(cfg.docker_daemon_json, "r");
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
		snprintf(docker_data_root, sizeof(docker_data_root), DOCKER_DEFAULT_ROOT);
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
	snprintf(config_path, sizeof(config_path), "%s/containers/%s/config.v2.json",
		 docker_data_root, container_id);

	FILE *f = fopen(config_path, "r");
	if (!f)
		return 0;

	/* config.v2.json может быть большим (>40KB если секция State велика),
	 * поэтому читаем частями, ища паттерн "Name":" */
	char *q1 = NULL, *q2 = NULL;
	char buf[CONFIG_BUF_LEN];
	char overlap[PROC_STATUS_LINE] = ""; /* перекрытие с предыдущим чанком */
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
			size_t keep = total < sizeof(overlap) - 1 ? total : sizeof(overlap) - 1;
			memcpy(overlap, combined + total - keep, keep);
			overlap[keep] = '\0';
		}
	}
	fclose(f);

	if (!found)
		return 0;

	/* Формируем путь: "docker/<имя_контейнера>" */
	size_t name_len = q2 - q1;
	if (name_len + 8 > dstlen) /* "docker/" + name + NUL */
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
	int negative; /* 1 = попытка была неудачной, не повторять */
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
	if (!cfg.docker_resolve_names || !raw[0]) {
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
				snprintf(buf, buflen, "%s", docker_name_cache[i].resolved);
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
		memcpy(docker_name_cache[docker_name_cache_count].container_id, id,
		       DOCKER_HASH_LEN);
		docker_name_cache[docker_name_cache_count].container_id[DOCKER_HASH_LEN] = '\0';
		if (ok) {
			snprintf(docker_name_cache[docker_name_cache_count].resolved,
				 sizeof(docker_name_cache[0].resolved), "%s", resolved);
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
	char name[USERNAME_LEN];
	int valid; /* 1 = запись используется */
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

	if (getpwuid_r((uid_t)uid, &pwd, pwbuf, sizeof(pwbuf), &result) == 0 && result) {
		snprintf(name, namelen, "%s", result->pw_name);
		return 1;
	}
	return 0;
}

void http_resolve_uid(__u32 uid, char *buf, int buflen)
{
	if (buflen <= 0)
		return;
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
	if (!resolve_uid_to_name(uid, name, sizeof(name)))
		snprintf(name, sizeof(name), "NOT_FOUND");

	/* Сохраняем в кэш (wrlock) */
	pthread_rwlock_wrlock(&g_uid_cache_lock);
	/* Двойная проверка */
	for (int i = 0; i < uid_name_cache_count; i++) {
		if (uid_name_cache[i].uid == uid) {
			pthread_rwlock_unlock(&g_uid_cache_lock);
			snprintf(buf, buflen, "%s", uid_name_cache[i].name);
			return;
		}
	}
	if (uid_name_cache_count < UID_NAME_CACHE_SIZE) {
		uid_name_cache[uid_name_cache_count].uid = uid;
		snprintf(uid_name_cache[uid_name_cache_count].name, USERNAME_LEN, "%s", name);
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
	if (stat(full, &st) == 0) {
		if (cgroup_cache_count < cfg.max_cgroups) {
			cgroup_cache[cgroup_cache_count].id = (__u64)st.st_ino;

			/* Сохраняем реальный путь файловой системы (имена Docker резолвятся лениво при выводе) */
			snprintf(cgroup_cache[cgroup_cache_count].fs_path,
				 sizeof(cgroup_cache[0].fs_path), "%s", rel);
			snprintf(cgroup_cache[cgroup_cache_count].path,
				 sizeof(cgroup_cache[0].path), "%s", rel);
			cgroup_cache_count++;
		} else {
			LOG_WARN("cgroup cache full (%d) during scan, skipping: %s",
				 cfg.max_cgroups, rel);
		}
	}

	DIR *d = opendir(full);
	if (!d)
		return;

	struct dirent *entry;
	while ((entry = readdir(d)) != NULL) {
		if (entry->d_type != DT_DIR || entry->d_name[0] == '.')
			continue;
		if (cgroup_cache_count >= cfg.max_cgroups)
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
void resolve_cgroup_ts(__u64 cgroup_id, char *buf, int buflen)
{
	pthread_rwlock_rdlock(&g_cgroup_lock);
	const char *cg = resolve_cgroup_fast(cgroup_id);
	snprintf(buf, buflen, "%s", cg);
	pthread_rwlock_unlock(&g_cgroup_lock);
}

/* Потокобезопасная обёртка для resolve_cgroup_fs */
void resolve_cgroup_fs_ts(__u64 cgroup_id, char *buf, int buflen)
{
	if (cgroup_id == 0) {
		buf[0] = '\0';
		return;
	}
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

/*
 * Резолвит cgroup_id → путь и заполняет cev->cgroup.
 */
void fill_cgroup(struct metric_event *cev, __u64 cgroup_id)
{
	resolve_cgroup_fast_ts(cgroup_id, cev->cgroup, sizeof(cev->cgroup));
}

/*
 * Заполняет cgroup-метрики из кэша cg_metrics[] (заполняется в refresh).
 * Ищет по имени cgroup (cev->cgroup должен быть уже заполнен через fill_cgroup).
 * Используется только в snapshot — метрики читаются из /sys/fs/cgroup периодически.
 */
void fill_cgroup_metrics(struct metric_event *cev)
{
	if (!cev->cgroup[0])
		return;

	for (int i = 0; i < cg_metrics_count; i++) {
		if (strcmp(cg_metrics[i].path, cev->cgroup) != 0)
			continue;
		if (!cg_metrics[i].valid)
			break;

		cev->cgroup_memory_max = cg_metrics[i].mem_max;
		cev->cgroup_memory_current = cg_metrics[i].mem_cur;
		cev->cgroup_swap_current = cg_metrics[i].swap_cur;
		cev->cgroup_cpu_weight = cg_metrics[i].cpu_weight;
		cev->cgroup_cpu_max = cg_metrics[i].cpu_max;
		cev->cgroup_cpu_max_period = cg_metrics[i].cpu_max_period;
		cev->cgroup_cpu_nr_periods = cg_metrics[i].cpu_nr_periods;
		cev->cgroup_cpu_nr_throttled = cg_metrics[i].cpu_nr_throttled;
		cev->cgroup_cpu_throttled_usec = cg_metrics[i].cpu_throttled_usec;
		cev->cgroup_pids_current = cg_metrics[i].pids_cur;
		break;
	}
}

/*
 * Заполняет pwd в metric_event: lookup из кэша, fallback на /proc/PID/cwd.
 */
void fill_pwd(struct metric_event *cev, __u32 tgid)
{
	pwd_lookup_ts(tgid, cev->pwd, sizeof(cev->pwd));
	if (!cev->pwd[0]) {
		pwd_read_and_store(tgid);
		pwd_lookup_ts(tgid, cev->pwd, sizeof(cev->pwd));
	}
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
			snprintf(cgroup_cache[i].fs_path, sizeof(cgroup_cache[0].fs_path), "%s",
				 path);
			snprintf(cgroup_cache[i].path, sizeof(cgroup_cache[0].path), "%s", path);
			pthread_rwlock_unlock(&g_cgroup_lock);
			return;
		}
	}
	/* Добавление новой записи */
	if (cgroup_cache_count < cfg.max_cgroups) {
		cgroup_cache[cgroup_cache_count].id = id;
		snprintf(cgroup_cache[cgroup_cache_count].fs_path, sizeof(cgroup_cache[0].fs_path),
			 "%s", path);
		snprintf(cgroup_cache[cgroup_cache_count].path, sizeof(cgroup_cache[0].path), "%s",
			 path);
		cgroup_cache_count++;
	} else {
		LOG_WARN("cgroup cache full (%d), dropping: id=%llu path=%s", cfg.max_cgroups,
			 (unsigned long long)id, path);
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
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup mkdir: id=%llu level=%d path=%s",
				  (unsigned long long)ce->id, ce->level, ce->path);
		break;

	case EVENT_CGROUP_RMDIR:
		cgroup_cache_remove(ce->id);
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup rmdir: id=%llu path=%s",
				  (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_RENAME:
		/* Обновляем путь для существующей записи */
		cgroup_cache_add(ce->id, ce->path);
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup rename: id=%llu path=%s",
				  (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_RELEASE:
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup release: id=%llu path=%s",
				  (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_ATTACH_TASK:
		/* Процесс перемещён в cgroup — убедимся, что она в кэше
		 * (BPF уже обновил proc_map.cgroup_id, но userspace может
		 * не знать эту cgroup, если mkdir-событие было дропнуто) */
		cgroup_cache_add(ce->id, ce->path);
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup attach: pid=%d → id=%llu path=%s comm=%s",
				  ce->pid, (unsigned long long)ce->id, ce->path, ce->comm);
		break;

	case EVENT_CGROUP_TRANSFER_TASKS:
		cgroup_cache_add(ce->id, ce->path);
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level,
				  "cgroup transfer: pid=%d → id=%llu path=%s comm=%s", ce->pid,
				  (unsigned long long)ce->id, ce->path, ce->comm);
		break;

	case EVENT_CGROUP_POPULATED:
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup populated: id=%llu path=%s val=%d",
				  (unsigned long long)ce->id, ce->path, ce->val);
		break;

	case EVENT_CGROUP_FREEZE:
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup freeze: id=%llu path=%s",
				  (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_UNFREEZE:
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup unfreeze: id=%llu path=%s",
				  (unsigned long long)ce->id, ce->path);
		break;

	case EVENT_CGROUP_FROZEN:
		if (cfg.log_level >= 2)
			LOG_DEBUG(cfg.log_level, "cgroup frozen: id=%llu path=%s val=%d",
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

/* ── загрузчик конфигурации libconfig ─────────────────────────────── */

static int load_config(const char *path)
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

	/* Размеры BPF ring buffer'ов */
	config_setting_t *rb = config_lookup(&lc, "ring_buffers");
	if (rb) {
		long long ll_val;
		if (config_setting_lookup_int64(rb, "proc", &ll_val))
			cfg.ringbuf_proc = ll_val;
		if (config_setting_lookup_int64(rb, "file", &ll_val))
			cfg.ringbuf_file = ll_val;
		if (config_setting_lookup_int64(rb, "file_ops", &ll_val))
			cfg.ringbuf_file_ops = ll_val;
		if (config_setting_lookup_int64(rb, "net", &ll_val))
			cfg.ringbuf_net = ll_val;
		if (config_setting_lookup_int64(rb, "sec", &ll_val))
			cfg.ringbuf_sec = ll_val;
		if (config_setting_lookup_int64(rb, "cgroup", &ll_val))
			cfg.ringbuf_cgroup = ll_val;
	}

	/* Настройки отслеживания сети (включая security TCP/UDP) */
	config_setting_t *nt = config_lookup(&lc, "net_tracking");
	if (nt) {
		if (config_setting_lookup_bool(nt, "enabled", &bool_val))
			cfg.net_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_bytes", &bool_val))
			cfg.net_track_bytes = bool_val;

		if (config_setting_lookup_bool(nt, "tcp_retransmit", &bool_val))
			cfg.tcp_retransmit = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_syn", &bool_val))
			cfg.tcp_syn = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_rst", &bool_val))
			cfg.tcp_rst = bool_val;
		if (config_setting_lookup_bool(nt, "tcp_open_conns", &bool_val))
			cfg.tcp_open_conns = bool_val;

		/* emit-флаги: какие сетевые события отправлять в CSV */
		if (config_setting_lookup_bool(nt, "emit_listen", &bool_val))
			cfg.emit.net_listen = bool_val;
		if (config_setting_lookup_bool(nt, "emit_connect", &bool_val))
			cfg.emit.net_connect = bool_val;
		if (config_setting_lookup_bool(nt, "emit_accept", &bool_val))
			cfg.emit.net_accept = bool_val;
		if (config_setting_lookup_bool(nt, "emit_close", &bool_val))
			cfg.emit.net_close = bool_val;
		if (config_setting_lookup_bool(nt, "emit_retransmit", &bool_val))
			cfg.emit.tcp_retransmit = bool_val;
		if (config_setting_lookup_bool(nt, "emit_syn_recv", &bool_val))
			cfg.emit.syn_recv = bool_val;
		if (config_setting_lookup_bool(nt, "emit_rst", &bool_val))
			cfg.emit.rst = bool_val;
	}

	/* Настройки отслеживания файлов */
	config_setting_t *ft = config_lookup(&lc, "file_tracking");
	if (ft) {
		if (config_setting_lookup_bool(ft, "enabled", &bool_val))
			cfg.file_tracking_enabled = bool_val;
		if (config_setting_lookup_bool(ft, "track_bytes", &bool_val))
			cfg.file_track_bytes = bool_val;
		if (config_setting_lookup_bool(ft, "absolute_paths_only", &bool_val))
			cfg.file_absolute_paths_only = bool_val;

		/* emit-флаги: какие файловые события отправлять в CSV */
		if (config_setting_lookup_bool(ft, "emit_open", &bool_val))
			cfg.emit.file_open = bool_val;
		if (config_setting_lookup_bool(ft, "emit_close", &bool_val))
			cfg.emit.file_close = bool_val;
		if (config_setting_lookup_bool(ft, "emit_rename", &bool_val))
			cfg.emit.file_rename = bool_val;
		if (config_setting_lookup_bool(ft, "emit_unlink", &bool_val))
			cfg.emit.file_unlink = bool_val;
		if (config_setting_lookup_bool(ft, "emit_truncate", &bool_val))
			cfg.emit.file_truncate = bool_val;
		if (config_setting_lookup_bool(ft, "emit_chmod", &bool_val))
			cfg.emit.file_chmod = bool_val;
		if (config_setting_lookup_bool(ft, "emit_chown", &bool_val))
			cfg.emit.file_chown = bool_val;

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

	/* ICMP — верхнеуровневая опция (не привязана к процессам) */
	if (config_lookup_bool(&lc, "icmp_tracking", &bool_val))
		cfg.icmp_tracking = bool_val;

	/* emit-флаг cgroup событий */
	if (config_lookup_bool(&lc, "emit_cgroup_events", &bool_val))
		cfg.emit.cgroup = bool_val;

	/* process_tracking — emit-флаги процессных событий */
	config_setting_t *pt = config_lookup(&lc, "process_tracking");
	if (pt) {
		if (config_setting_lookup_bool(pt, "emit_exec", &bool_val))
			cfg.emit.exec = bool_val;
		if (config_setting_lookup_bool(pt, "emit_fork", &bool_val))
			cfg.emit.fork = bool_val;
		if (config_setting_lookup_bool(pt, "emit_exit", &bool_val))
			cfg.emit.exit = bool_val;
		if (config_setting_lookup_bool(pt, "emit_oom_kill", &bool_val))
			cfg.emit.oom_kill = bool_val;
		if (config_setting_lookup_bool(pt, "emit_signal", &bool_val))
			cfg.emit.signal = bool_val;
		if (config_setting_lookup_bool(pt, "emit_chdir", &bool_val))
			cfg.emit.chdir = bool_val;
	}

	/* Настройки отслеживания дисков */
	config_setting_t *dt = config_lookup(&lc, "disk_tracking");
	if (dt) {
		if (config_setting_lookup_bool(dt, "enabled", &bool_val))
			cfg.disk_tracking_enabled = bool_val;

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
	if (!cfg.net_tracking_enabled) {
		cfg.tcp_retransmit = 0;
		cfg.tcp_syn = 0;
		cfg.tcp_rst = 0;
		cfg.tcp_open_conns = 0;
		cfg.icmp_tracking = 0;
		cfg.net_track_bytes = 0;
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
	while (n > 0 && out[n - 1] == ' ')
		n--;
	out[n] = '\0';
}

/*
 * Разделение сырой cmdline (argv, разделённых NUL) на exec_path и args.
 * exec_path = argv[0], args = argv[1..], объединённые пробелами.
 */
void cmdline_split(const char *raw, __u16 len, char *exec_out, int exec_len, char *args_out,
		   int args_len)
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
	if (v >= 100) {
		*p++ = '0' + v / 100;
		v %= 100;
		*p++ = '0' + v / 10;
		*p++ = '0' + v % 10;
	} else if (v >= 10) {
		*p++ = '0' + v / 10;
		*p++ = '0' + v % 10;
	} else {
		*p++ = '0' + v;
	}
	return p;
}

/* IPv4 bytes[4] → "1.2.3.4" в dst, возвращает длину. */
static inline int fmt_ipv4(char *dst, int cap, const __u8 *a)
{
	char *p = dst;
	p = fast_u8(p, a[0]);
	*p++ = '.';
	p = fast_u8(p, a[1]);
	*p++ = '.';
	p = fast_u8(p, a[2]);
	*p++ = '.';
	p = fast_u8(p, a[3]);
	*p = '\0';
	(void)cap;
	return (int)(p - dst);
}

/* Копирование строки в поле фиксированного размера (замена snprintf("%s")) */
void fast_strcpy(char *dst, int cap, const char *src)
{
	int i = 0;
	while (i < cap - 1 && src[i]) {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
}

/* ── построитель событий ──────────────────────────────────────────── */
/*
 * Заполняет поля metric_event, специфичные для proc events (struct event).
 * cmdline из BPF-события (может отличаться от proc_map), exit_code, oom_killed.
 *
 * Общие поля (timestamp, uid, comm, thread_name) устанавливаются в
 * prepare_metric_event через event_ctx.
 *
 * Вызывается ПОСЛЕ prepare_metric_event.
 */
static void fill_from_proc_event(struct metric_event *cev, const struct event *e)
{
	/* cmdline из BPF-события (может отличаться от proc_map) */
	cmdline_split(e->cmdline, e->cmdline_len,
		      cev->exec_path, sizeof(cev->exec_path),
		      cev->args, sizeof(cev->args));

	/* Поля, уникальные для proc events (нет в proc_info) */
	cev->exit_code = exit_status(e->exit_code);
	cev->oom_killed = e->oom_killed;
}

/* ── fill-функции для типизированных BPF-событий ────────────────────
 *
 * Каждая функция копирует специфичные для типа события поля из
 * BPF-структуры в metric_event.
 *
 * Общие поля (timestamp, pid, uid, comm, thread_name) устанавливаются
 * в prepare_metric_event через event_ctx.
 */

/* ── fill_sec_addrs: общий хелпер для sec_* адресов ───────────────── */
static void fill_sec_addrs(struct metric_event *cev, __u8 af, const void *local_addr,
			   const void *remote_addr, __u16 local_port, __u16 remote_port)
{
	cev->sec_af = af;
	cev->sec_local_port = local_port;
	cev->sec_remote_port = remote_port;
	if (af == 2) {
		fmt_ipv4(cev->sec_local_addr, sizeof(cev->sec_local_addr),
			 (const __u8 *)local_addr);
		fmt_ipv4(cev->sec_remote_addr, sizeof(cev->sec_remote_addr),
			 (const __u8 *)remote_addr);
	} else if (af == 10) {
		inet_ntop(AF_INET6, local_addr, cev->sec_local_addr, sizeof(cev->sec_local_addr));
		inet_ntop(AF_INET6, remote_addr, cev->sec_remote_addr,
			  sizeof(cev->sec_remote_addr));
	}
}

/* ── fill_from_file_event: все файловые события ───────────────────── */
static void fill_from_file_event(struct metric_event *cev, const struct file_event *fe,
				 enum event_type type)
{
	/* Общие файловые поля */
	fast_strcpy(cev->file_path, sizeof(cev->file_path), fe->path);
	cev->file_flags = (__u32)fe->flags;
	cev->file_read_bytes = fe->read_bytes;
	cev->file_write_bytes = fe->write_bytes;
	cev->file_open_count = fe->open_count;
	cev->file_fsync_count = fe->fsync_count;

	/* Поля, специфичные для подтипов */
	if (type == EVENT_FILE_RENAME)
		fast_strcpy(cev->file_new_path, sizeof(cev->file_new_path), fe->path2);
	else if (type == EVENT_FILE_TRUNCATE)
		cev->file_write_bytes = fe->truncate_size;
	else if (type == EVENT_FILE_CHMOD)
		cev->file_chmod_mode = fe->chmod_mode;
	else if (type == EVENT_FILE_CHOWN) {
		cev->file_chown_uid = fe->chown_uid;
		cev->file_chown_gid = fe->chown_gid;
	}
}

/* ── fill_from_net_event: NET_LISTEN/CONNECT/ACCEPT/CLOSE ─────────── */
static void fill_from_net_event(struct metric_event *cev, const struct net_event *ne)
{
	if (ne->af == 2) {
		fmt_ipv4(cev->net_local_addr, sizeof(cev->net_local_addr), ne->local_addr);
		fmt_ipv4(cev->net_remote_addr, sizeof(cev->net_remote_addr), ne->remote_addr);
	} else if (ne->af == 10) {
		inet_ntop(AF_INET6, ne->local_addr, cev->net_local_addr,
			  sizeof(cev->net_local_addr));
		inet_ntop(AF_INET6, ne->remote_addr, cev->net_remote_addr,
			  sizeof(cev->net_remote_addr));
	}

	cev->net_local_port = ne->local_port;
	cev->net_remote_port = ne->remote_port;
	cev->net_conn_tx_bytes = ne->tx_bytes;
	cev->net_conn_rx_bytes = ne->rx_bytes;
	cev->net_conn_tx_calls = ne->tx_calls;
	cev->net_conn_rx_calls = ne->rx_calls;
	cev->net_duration_ms = ne->duration_ns / NS_PER_MS;

	/* TCP state на момент close */
	if (ne->tcp_state)
		fast_strcpy(cev->net_tcp_state, sizeof(cev->net_tcp_state),
			    tcp_state_name(ne->tcp_state));
}

/* ── fill_from_signal_event: SIGNAL ───────────────────────────────── */
/*
 * Signal event привязан к ПОЛУЧАТЕЛЮ сигнала (target_pid).
 * prepare_metric_event заполнил идентификацию target из proc_map + метрики.
 * Здесь: сигнальные поля и информация об отправителе.
 */
static void fill_from_signal_event(struct metric_event *cev, const struct signal_event *se)
{
	/* Информация о сигнале */
	cev->sig_num = (__u32)se->sig;
	fast_strcpy(cev->sig_name, sizeof(cev->sig_name), signal_name(se->sig));
	cev->sig_code   = se->sig_code;
	cev->sig_result = se->sig_result;

	/* Информация об отправителе */
	cev->sig_sender_pid = se->sender_tgid;
	memcpy(cev->sig_sender_comm, se->sender_comm, COMM_LEN);
}

/* ── fill_from_retransmit_event: TCP_RETRANSMIT ───────────────────── */
static void fill_from_retransmit_event(struct metric_event *cev, const struct retransmit_event *re)
{
	fill_sec_addrs(cev, re->af, re->local_addr, re->remote_addr, re->local_port,
		       re->remote_port);
	cev->sec_tcp_state = re->state;
}

/* ── fill_from_syn_event: SYN_RECV ────────────────────────────────── */
static void fill_from_syn_event(struct metric_event *cev, const struct syn_event *se)
{
	fill_sec_addrs(
		cev,
		se->af,
		se->local_addr,
		se->remote_addr,
		se->local_port,
		se->remote_port
	);
}

/* ── fill_from_rst_event: RST ─────────────────────────────────────── */
static void fill_from_rst_event(struct metric_event *cev, const struct rst_event *re)
{
	fill_sec_addrs(cev, re->af, re->local_addr, re->remote_addr, re->local_port,
		       re->remote_port);
	cev->sec_direction = re->direction;

	/* Override event_type: rst_sent / rst_recv */
	fast_strcpy(cev->event_type, sizeof(cev->event_type), rst_event_name(re->direction));
}

/* ── fill_from_sock_info: conn_snapshot ───────────────────────────── */
void fill_from_sock_info(struct metric_event *cev, const struct sock_info *si, __u64 boot_ns)
{
	cev->pid = si->tgid;
	cev->uid = si->uid;

	/* IP-адреса */
	if (si->af == 2) {
		snprintf(cev->net_local_addr, sizeof(cev->net_local_addr), "%u.%u.%u.%u",
			 si->local_addr[0], si->local_addr[1], si->local_addr[2],
			 si->local_addr[3]);
		snprintf(cev->net_remote_addr, sizeof(cev->net_remote_addr), "%u.%u.%u.%u",
			 si->remote_addr[0], si->remote_addr[1], si->remote_addr[2],
			 si->remote_addr[3]);
	} else if (si->af == 10) {
		inet_ntop(AF_INET6, si->local_addr, cev->net_local_addr,
			  sizeof(cev->net_local_addr));
		inet_ntop(AF_INET6, si->remote_addr, cev->net_remote_addr,
			  sizeof(cev->net_remote_addr));
	}

	cev->net_local_port = si->local_port;
	cev->net_remote_port = si->remote_port;
	cev->net_conn_tx_bytes = si->tx_bytes;
	cev->net_conn_rx_bytes = si->rx_bytes;
	cev->net_conn_tx_calls = si->tx_calls;
	cev->net_conn_rx_calls = si->rx_calls;

	/* Длительность соединения */
	if (si->start_ns > 0 && boot_ns > si->start_ns)
		cev->net_duration_ms = (boot_ns - si->start_ns) / NS_PER_MS;

	/* is_listener → state: 'L'=listener, 'E'=established */
	cev->state = si->is_listener ? 'L' : 'E';
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
	if (!f)
		return -1;
	char buf[PROC_STAT_LEN];
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);

	/* comm: между первой '(' и последней ')' */
	char *lp = strchr(buf, '(');
	char *rp = strrchr(buf, ')');
	if (!lp || !rp || rp <= lp)
		return -1;
	int clen = (int)(rp - lp - 1);
	if (clen > COMM_LEN - 1)
		clen = COMM_LEN - 1;
	memcpy(pi->comm, lp + 1, clen);
	pi->comm[clen] = '\0';
	memcpy(pi->thread_name, pi->comm, COMM_LEN);

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
		   &state, &ppid, &tty_nr, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime,
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
	if (page_size <= 0)
		page_size = FALLBACK_PAGE_SIZE;
	pi->vsize_pages = (__u64)(vsize / page_size);

	long clk_tck = sysconf(_SC_CLK_TCK);
	if (clk_tck <= 0)
		clk_tck = FALLBACK_CLK_TCK;
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
				pi->uid = (__u32)uid_val;
				pi->euid = (__u32)euid_val;
			} else if (sscanf(sline, "RssShmem: %lu kB", &val) == 1)
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
__u32 read_proc_ppid(__u32 pid)
{
	char path[PROC_PATH_LEN];
	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	char buf[PROC_BUF_SMALL];
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return 0;
	}
	fclose(f);
	char *rp = strrchr(buf, ')');
	if (!rp)
		return 0;
	int ppid = 0;
	if (sscanf(rp + 2, "%*c %d", &ppid) != 1)
		return 0;
	return ppid > 0 ? (__u32)ppid : 0;
}

int read_proc_cmdline(__u32 pid, char *dst, int dstlen)
{
	char path[PROC_PATH_LEN];
	snprintf(path, sizeof(path), "/proc/%u/cmdline", pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	int len = (int)fread(dst, 1, dstlen - 1, f);
	fclose(f);
	if (len < 0)
		len = 0;
	dst[len] = '\0';
	return len;
}

static __u64 read_proc_cgroup_id(__u32 pid)
{
	char path[PROC_PATH_LEN], buf[PROC_BUF_SMALL];
	snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;

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
			if (last)
				snprintf(cg_path, sizeof(cg_path), "%s", last + 1);
		}
	}
	fclose(f);

	if (cg_path[0] == '\0' || strcmp(cg_path, "/") == 0)
		return 0;

	/* Убираем ведущий / */
	char *rel = cg_path;
	if (*rel == '/')
		rel++;

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
	if (!f)
		return 0;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return 0;
	}
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

/*
 * Начать отслеживание процесса: создать запись в tracked_map.
 */
static void start_tracking(__u32 pid, int rule_id, __u32 root_pid, __u8 is_root)
{
	struct track_info ti = {
	    .root_pid = root_pid,
	    .rule_id = (__u16)rule_id,
	    .is_root = is_root,
	};
	bpf_map_update_elem(tracked_map_fd, &pid, &ti, BPF_ANY);
}

static void track_pid_from_proc(__u32 pid, int rule_id, __u32 root_pid, __u8 is_root)
{
	start_tracking(pid, rule_id, root_pid, is_root);

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

static void add_descendants(struct scan_entry *entries, int count, __u32 parent, int rule_id,
			    __u32 root_pid, int *tracked)
{
	for (int i = 0; i < count; i++) {
		if (entries[i].ppid != parent)
			continue;
		__u32 child = entries[i].pid;
		/* Пропускаем, если уже отслеживается */
		struct track_info ti;
		if (is_pid_tracked(child, &ti))
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
	if (!cfg.need_sock_map)
		return;

	int seed_fd = bpf_map__fd(skel->maps.seed_inode_map);
	if (seed_fd < 0)
		return;

	/* Проход по tracked_map → для каждого PID сканируем /proc/<pid>/fd/ */
	__u32 key = 0, next_key;
	int seeded = 0;
	int seed_iter = 0;

	while (bpf_map_get_next_key(tracked_map_fd, &key, &next_key) == 0 && seed_iter++ < MAX_PROCS) {
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
			snprintf(link_path, sizeof(link_path), "/proc/%u/fd/%s", pid, de->d_name);
			ssize_t len = readlink(link_path, target, sizeof(target) - 1);
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
		struct bpf_link *link =
		    bpf_program__attach_iter(skel->progs.seed_sock_map_iter, NULL);
		if (!link) {
			LOG_WARN("seed_sock_map: attach_iter failed: %s", strerror(errno));
			break;
		}

		int iter_fd = bpf_iter_create(bpf_link__fd(link));
		if (iter_fd < 0) {
			LOG_WARN("seed_sock_map: iter_create failed: %s", strerror(errno));
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
		if (pid <= 0)
			continue;

		char path[PROC_PATH_LEN], buf[PROC_BUF_SMALL];
		snprintf(path, sizeof(path), "/proc/%d/stat", pid);
		FILE *f = fopen(path, "r");
		if (!f)
			continue;
		if (!fgets(buf, sizeof(buf), f)) {
			fclose(f);
			continue;
		}
		fclose(f);

		char *rp = strrchr(buf, ')');
		if (!rp)
			continue;
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
		cmdline_to_str(cmdline_raw, (__u16)clen, cmdline_str, sizeof(cmdline_str));

		char tags_buf[TAGS_MAX_LEN];
		int first = match_rules_all(cmdline_str, tags_buf, sizeof(tags_buf));
		if (first >= 0 && !rules[first].ignore) {
			/* Корневое совпадение */
			track_pid_from_proc(pid, first, pid, 1);
			tags_store_ts(pid, tags_buf);
			tracked++;
			LOG_DEBUG(cfg.log_level, "SCAN: pid=%u rule=%s tags=%s cmdline=%.60s", pid,
				  rules[first].name, tags_buf, cmdline_str);

			/* Находим всех потомков */
			add_descendants(entries, count, pid, first, pid, &tracked);
		}
	}

	LOG_INFO("initial scan: %d processes scanned, %d tracked", count, tracked);
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

	if (size < sizeof(__u32))
		return 0;
	enum event_type type = event_type_from_data(data);

	/* ── FILE events — file_open/close/rename/unlink/truncate/chmod/chown ── */
	if (is_file_event(type)) {
		if (size < sizeof(struct file_event))
			return 0;
		const struct file_event *fe = data;

		/* Lookup tracked_map. Для FILE_CLOSE допускаем отсутствие —
		 * процесс мог завершиться до обработки close из ring buffer. */
		struct track_info ti;
		int tracked = is_pid_tracked(fe->tgid, &ti);
		if (should_skip_untracked(type, tracked))
			return 0;

		LOG_DEBUG(cfg.log_level,
			  "FILE: pid=%u type=%s path=%.60s "
			  "read=%llu write=%llu opens=%u",
			  fe->tgid, event_type_name(type), fe->path,
			  (unsigned long long)fe->read_bytes, (unsigned long long)fe->write_bytes,
			  fe->open_count);

		if (should_emit_event(type)) {
			struct metric_event cev;
			struct event_ctx ctx = {type, fe->tgid, fe->uid, fe->timestamp_ns, fe->cgroup_id, fe->comm, fe->thread_name};
			prepare_metric_event(&cev, &ctx);
			fill_from_file_event(&cev, fe, type);
			finalize_metric_event(&cev, fe->tgid);
			ef_append(&cev, cfg.hostname);
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
	if (is_net_event(type)) {
		/* emit guard */

		if (size < sizeof(struct net_event))
			return 0;
		const struct net_event *ne = data;

		/* Lookup tracked_map. Для NET_CLOSE допускаем отсутствие —
		 * процесс мог завершиться (handle_exit удалил tracked_map)
		 * до обработки net_close из ring buffer. */
		struct track_info ti;
		int tracked = is_pid_tracked(ne->tgid, &ti);
		if (should_skip_untracked(type, tracked))
			return 0;

		if (should_emit_event(type)) {
			const char *net_evt = event_type_name(type);
			LOG_DEBUG(cfg.log_level,
				  "%s: pid=%u rule=%s port=%u→%u "
				  "tx=%llu rx=%llu dur=%llums",
				  net_evt, ne->tgid, resolve_rule_tracked(&ti, tracked),
				  ne->local_port, ne->remote_port, (unsigned long long)ne->tx_bytes,
				  (unsigned long long)ne->rx_bytes,
				  (unsigned long long)(ne->duration_ns / NS_PER_MS));

			struct metric_event cev;
			struct event_ctx ctx = {type, ne->tgid, ne->uid, ne->timestamp_ns, ne->cgroup_id, ne->comm, ne->thread_name};
			prepare_metric_event(&cev, &ctx);
			fill_from_net_event(&cev, ne);
			finalize_metric_event(&cev, ne->tgid);
			ef_append(&cev, cfg.hostname);
		}
		return 0;
	}

	/* ── SIGNAL — доставка сигнала ───────────────────────────────────
	 *
	 * Редкое событие. Захватывает все сигналы (SIGTERM, SIGKILL, и т.д.).
	 * Правило определяется сначала по отправителю, затем по получателю.
	 * Имя процесса-получателя читается из /proc/<pid>/comm.
	 */
	if (is_signal_event(type)) {
		if (size < sizeof(struct signal_event))
			return 0;
		const struct signal_event *se = data;

		LOG_DEBUG(cfg.log_level,
			  "SIGNAL: sender=%u→target=%u sig=%d code=%d result=%d",
			  se->sender_tgid, se->target_pid, se->sig,
			  se->sig_code, se->sig_result);

		if (should_emit_event(type)) {
			struct metric_event cev;
			struct event_ctx ctx = {EVENT_SIGNAL, se->target_pid, se->sender_uid, se->timestamp_ns, se->cgroup_id, NULL, NULL};
			prepare_metric_event(&cev, &ctx);
			fill_from_signal_event(&cev, se);
			finalize_metric_event(&cev, se->target_pid);
			ef_append(&cev, cfg.hostname);
		}
		return 0;
	}

	/* ── TCP_RETRANSMIT — повторная передача TCP-сегмента ────────────
	 *
	 * Редкое событие. Симптом потери пакетов, перегрузки сети или DDoS.
	 * НЕ фильтруется по tracked_map — захватывает ВСЕ соединения на хосте.
	 */
	if (is_retransmit_event(type)) {
		if (size < sizeof(struct retransmit_event))
			return 0;
		const struct retransmit_event *re = data;

		LOG_DEBUG(cfg.log_level, "TCP_RETRANSMIT: pid=%u port=%u→%u state=%u", re->tgid,
			  re->local_port, re->remote_port, re->state);

		if (should_emit_event(type)) {
			struct metric_event cev;
			struct event_ctx ctx = {EVENT_TCP_RETRANSMIT, re->tgid, re->uid, re->timestamp_ns, re->cgroup_id, re->comm, NULL};
			prepare_metric_event(&cev, &ctx);
			fill_from_retransmit_event(&cev, re);
			finalize_metric_event(&cev, re->tgid);
			ef_append(&cev, cfg.hostname);
		}
		return 0;
	}

	/* ── SYN_RECV — входящий SYN-запрос (полу-открытое соединение) ───
	 *
	 * Редкое событие. Полезно для обнаружения SYN flood атак.
	 * НЕ фильтруется по tracked_map — захватывает ВСЕ входящие SYN.
	 */
	if (is_syn_event(type)) {
		if (size < sizeof(struct syn_event))
			return 0;
		const struct syn_event *se_syn = data;

		LOG_DEBUG(cfg.log_level, "SYN_RECV: pid=%u port=%u←%u", se_syn->tgid,
			  se_syn->local_port, se_syn->remote_port);

		if (should_emit_event(type)) {
			struct metric_event cev;
			struct event_ctx ctx = {EVENT_SYN_RECV, se_syn->tgid, se_syn->uid, se_syn->timestamp_ns, se_syn->cgroup_id, se_syn->comm, NULL};
			prepare_metric_event(&cev, &ctx);
			fill_from_syn_event(&cev, se_syn);
			finalize_metric_event(&cev, se_syn->tgid);
			ef_append(&cev, cfg.hostname);
		}
		return 0;
	}

	/* ── RST — отправка/получение TCP RST пакета ────────────────────
	 *
	 * Редкое событие. Много RST = сканирование портов или обрыв соединений.
	 * НЕ фильтруется по tracked_map — захватывает ВСЕ RST на хосте.
	 * Поле direction: 0 = отправлен (sent), 1 = получен (recv).
	 */
	if (is_rst_event(type)) {
		if (size < sizeof(struct rst_event))
			return 0;

		const struct rst_event *rste = data;

		LOG_DEBUG(cfg.log_level, "RST: pid=%u port=%u↔%u dir=%s", rste->tgid,
			  rste->local_port, rste->remote_port, rste->direction ? "recv" : "sent");

		if (should_emit_event(type)) {
			struct metric_event cev;
			struct event_ctx ctx = {EVENT_RST, rste->tgid, rste->uid, rste->timestamp_ns, rste->cgroup_id, rste->comm, NULL};
			prepare_metric_event(&cev, &ctx);
			fill_from_rst_event(&cev, rste);
			finalize_metric_event(&cev, rste->tgid);
			ef_append(&cev, cfg.hostname);
		}

		return 0;
	}

	/* ── EXEC — вызов exec (запуск нового процесса) ──────────────── */
	if (is_exec_event(type)) {
		if (size < sizeof(struct event))
			return 0;
		const struct event *e = data;
		/* Обновляем глобальное дерево pid (exec может быть первым появлением) */
		pidtree_store_ts(e->tgid, e->ppid);

		/* Уже отслеживается? BPF обновил proc_info, нам делать нечего */
		struct track_info ti;
		if (is_pid_tracked(e->tgid, &ti))
			return 0;

		/* Преобразуем cmdline из BPF (нуль-разделённые аргументы) в строку */
		char cmdline[CMDLINE_MAX + 1];
		cmdline_to_str(e->cmdline, e->cmdline_len, cmdline, sizeof(cmdline));

		/* Проверяем все правила (regexec × N правил) — тяжёлый, но exec редкий */
		char tags_buf[TAGS_MAX_LEN];
		int first = match_rules_all(cmdline, tags_buf, sizeof(tags_buf));

		if (first >= 0 && !rules[first].ignore) {
			/* Совпадение — начинаем отслеживание */
			start_tracking(e->tgid, first, e->tgid, 1);
			tags_store_ts(e->tgid, tags_buf);
			pwd_read_and_store(e->tgid);

			store_proc_info_from_event(e);

			LOG_DEBUG(cfg.log_level, "TRACK: pid=%u rule=%s tags=%s comm=%.16s",
				  e->tgid, rules[first].name, tags_buf, e->comm);

			/* Отправляем exec-событие в буферный файл (→ ClickHouse) */
			if (should_emit_event(EVENT_EXEC)) {
				struct metric_event cev;
				struct event_ctx ctx = {EVENT_EXEC, e->tgid, e->uid, e->timestamp_ns, e->cgroup_id, e->comm, e->thread_name};
				prepare_metric_event(&cev, &ctx);
				fill_from_proc_event(&cev, e);
				finalize_metric_event(&cev, e->tgid);
				ef_append(&cev, cfg.hostname);
			}
		}
		return 0;
	}

	/* ── FORK — создание дочернего процесса ──────────────────────── */
	if (is_fork_event(type)) {
		if (size < sizeof(struct event))
			return 0;
		const struct event *e = data;
		/* Обновляем глобальное дерево pid (покрывает ВСЕ процессы) */
		pidtree_store_ts(e->tgid, e->ppid);

		/* BPF handle_fork уже создал tracked_map и proc_info записи.
		 * Здесь только наследуем tags (они живут в userspace hash table). */
		struct track_info parent_ti;
		if (!is_pid_tracked(e->ppid, &parent_ti))
			return 0;

		tags_inherit_ts(e->tgid, e->ppid);
		pwd_inherit_ts(e->tgid, e->ppid);

		/* Отправляем fork-событие в буферный файл */
		if (should_emit_event(EVENT_FORK)) {
			struct metric_event cev;
			struct event_ctx ctx = {EVENT_FORK, e->tgid, e->uid, e->timestamp_ns, e->cgroup_id, e->comm, e->thread_name};
			prepare_metric_event(&cev, &ctx);
			fill_from_proc_event(&cev, e);
			finalize_metric_event(&cev, e->tgid);
			ef_append(&cev, cfg.hostname);
		}
		return 0;
	}

	/* ── EXIT — завершение процесса ──────────────────────────────── */
	if (is_exit_event(type)) {
		if (size < sizeof(struct event))
			return 0;
		const struct event *e = data;

		/* Отправляем exit-событие в буферный файл */
		if (should_emit_event(EVENT_EXIT)) {
			LOG_DEBUG(cfg.log_level,
				  "EXIT: pid=%u exit_code=%d signal=%d "
				  "cpu=%.2fs rss_max=%lluMB%s",
				  e->tgid, exit_status(e->exit_code), exit_signal(e->exit_code),
				  (double)e->cpu_ns / 1e9,
				  (unsigned long long)(e->rss_max_pages * 4 / 1024),
				  e->oom_killed ? " [OOM]" : "");

			struct metric_event cev;
			struct event_ctx ctx = {e->type, e->tgid, e->uid, e->timestamp_ns, e->cgroup_id, e->comm, e->thread_name};
			prepare_metric_event(&cev, &ctx);
			fill_from_proc_event(&cev, e);
			finalize_metric_event(&cev, e->tgid);
			ef_append(&cev, cfg.hostname);
		}
		/* Карты и кэши НЕ удаляем — proc_info помечен status=EXITED,
		 * snapshot запишет финальный слепок и зачистит всё.
		 * pidtree тоже НЕ удаляем — нужен для цепочек до снапшота. */
		return 0;
	}

	/* ── CHDIR — смена рабочего каталога ─────────────────────────── */
	if (is_chdir_event(type)) {
		if (size < sizeof(struct event))
			return 0;
		const struct event *e = data;
		pwd_read_and_store(e->tgid);
		return 0;
	}

	/* ── OOM_KILL — убийство процесса OOM killer ─────────────────── */
	if (is_oom_event(type)) {
		if (size < sizeof(struct event))
			return 0;
		const struct event *e = data;
		const char *rname = resolve_rule_for_proc_event(e);
		LOG_WARN("OOM_KILL: pid=%u rule=%s comm=%.16s "
			 "rss=%lluMB",
			 e->tgid, rname, e->comm, (unsigned long long)(e->rss_pages * 4 / 1024));

		/* Отправляем oom_kill-событие в буферный файл */
		if (should_emit_event(EVENT_OOM_KILL)) {
			struct metric_event cev;
			struct event_ctx ctx = {e->type, e->tgid, e->uid, e->timestamp_ns, e->cgroup_id, e->comm, e->thread_name};
			prepare_metric_event(&cev, &ctx);
			fill_from_proc_event(&cev, e);
			finalize_metric_event(&cev, e->tgid);
			ef_append(&cev, cfg.hostname);
		}
		return 0;
	}

	return 0;
}

/* read_cgroup_value, read_cgroup_cpu_max, read_cgroup_cpu_stat,
 * emit_disk_usage_events — moved to refresh.c */

/* tags_lookup_copy — moved to snapshot.c */

/* refresh_processes — moved to refresh.c */

/* write_snapshot — moved to snapshot.c */

/* flush_dead_keys — moved to refresh.c */

/* ── сигналы ──────────────────────────────────────────────────────── */

static void sig_term(int sig)
{
	(void)sig;
	g_running = 0;
}
static void sig_hup(int sig)
{
	(void)sig;
	g_reload = 1;
}

/* ── лог libbpf ───────────────────────────────────────────────────── */

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
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
			continue; /* есть данные — сразу проверяем ещё */
		}
		if (n < 0 && n != -EINTR) {
			LOG_ERROR("poll thread '%s': ring_buffer__consume: %d", a->name, n);
			break;
		}
		/* Нет данных — ждём через epoll, чтобы не крутить CPU вхолостую */
		__atomic_add_fetch(&a->polls, 1, __ATOMIC_RELAXED);
		int err = ring_buffer__poll(a->rb, POLL_TIMEOUT_MS);
		if (err > 0)
			__atomic_add_fetch(&a->events, (__u64)err, __ATOMIC_RELAXED);
		if (err < 0 && err != -EINTR) {
			LOG_ERROR("poll thread '%s': ring_buffer__poll: %d", a->name, err);
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
		case 'c':
			cfg.config_file = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* Поиск файла конфигурации */
	if (!cfg.config_file) {
		/* Пробуем директорию бинарника, затем cwd */
		static char cfgbuf[PATH_MAX_LEN];
		char *slash = strrchr(argv[0], '/');
		if (slash) {
			int dirlen = (int)(slash - argv[0]);
			snprintf(cfgbuf, sizeof(cfgbuf), "%.*s/process_metrics.conf", dirlen,
				 argv[0]);
		} else {
			snprintf(cfgbuf, sizeof(cfgbuf), "process_metrics.conf");
		}
		cfg.config_file = cfgbuf;
	}

	/* Инициализация значений по умолчанию, которые нельзя задать в struct init */
	snprintf(cfg.docker_daemon_json, sizeof(cfg.docker_daemon_json),
		 "%s", DOCKER_DEFAULT_DAEMON_JSON);

	/* Загрузка конфигурации (libconfig) */
	if (load_config(cfg.config_file) < 0)
		return 1;

	/* Загрузка правил из конфигурации */
	if (parse_rules_from_config(cfg.config_file) < 0)
		return 1;
	if (num_rules == 0) {
		LOG_FATAL("no rules loaded");
		return 1;
	}

	/* Инициализация кольцевого буфера событий в памяти */
	if (cfg.http.enabled) {
		if (ef_init((__u64)cfg.max_data_size) < 0) {
			LOG_FATAL("event ring buffer init failed");
			return 1;
		}
	}

	/* Выделение памяти под кэши cgroup */
	cgroup_cache = calloc(cfg.max_cgroups, sizeof(*cgroup_cache));
	cg_metrics = calloc(cfg.max_cgroups, sizeof(*cg_metrics));
	if (!cgroup_cache || !cg_metrics) {
		LOG_FATAL("failed to allocate cgroup cache (%d entries)", cfg.max_cgroups);
		return 1;
	}
	LOG_INFO("max_cgroups = %d", cfg.max_cgroups);

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
	skel->rodata->max_exec_events_per_sec = (__u32)cfg.exec_rate_limit;

	/* Переопределение размеров BPF ring buffer'ов из конфига.
	 * Размер должен быть степенью 2 и >= PAGE_SIZE (4096).
	 * bpf_map__set_max_entries работает между open() и load(). */
#define SET_RINGBUF_SIZE(map, cfg_val)                                    \
	do {                                                              \
		if ((cfg_val) > 0) {                                      \
			__u32 sz = (__u32)(cfg_val);                      \
			/* Округляем вверх до степени 2 */                \
			sz--;                                             \
			sz |= sz >> 1;                                    \
			sz |= sz >> 2;                                    \
			sz |= sz >> 4;                                    \
			sz |= sz >> 8;                                    \
			sz |= sz >> 16;                                   \
			sz++;                                             \
			if (sz < BPF_MIN_RINGBUF_SIZE)                    \
				sz = BPF_MIN_RINGBUF_SIZE;                \
			bpf_map__set_max_entries(skel->maps.map, sz);     \
			LOG_INFO("ring_buffers.%s = %u bytes", #map, sz); \
		}                                                         \
	} while (0)

	SET_RINGBUF_SIZE(events_proc, cfg.ringbuf_proc);
	SET_RINGBUF_SIZE(events_file, cfg.ringbuf_file);
	SET_RINGBUF_SIZE(events_file_ops, cfg.ringbuf_file_ops);
	SET_RINGBUF_SIZE(events_net, cfg.ringbuf_net);
	SET_RINGBUF_SIZE(events_sec, cfg.ringbuf_sec);
	SET_RINGBUF_SIZE(events_cgroup, cfg.ringbuf_cgroup);
#undef SET_RINGBUF_SIZE

	/*
	 * sock_map необходим для: net_tracking (net_close, conn_snapshot,
	 * track_bytes) и TCP security (retransmit, syn, rst, open_conn_count).
	 * Если любая из этих опций включена — инфраструктура сокетов нужна.
	 */
	cfg.need_sock_map = cfg.net_tracking_enabled || cfg.tcp_retransmit || cfg.tcp_syn ||
			    cfg.tcp_rst || cfg.tcp_open_conns;
	int need_sock_map = cfg.need_sock_map;

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
	if (!need_sock_map || !cfg.net_track_bytes) {
		/* Подсчёт байтов на соединение (kprobe enter + kretprobe) */
		BPF_PROG_DISABLE(skel->progs.kp_tcp_sendmsg);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_recvmsg);
	}

	/* ── Условное отключение программ отслеживания файлов ──────── */
	if (!cfg.file_tracking_enabled) {
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
		if (!cfg.emit.file_rename) {
			BPF_PROG_DISABLE(skel->progs.handle_rename);
			BPF_PROG_DISABLE(skel->progs.handle_renameat2);
		}
		if (!cfg.emit.file_unlink) {
			BPF_PROG_DISABLE(skel->progs.handle_unlink);
			BPF_PROG_DISABLE(skel->progs.handle_unlinkat);
		}
		if (!cfg.emit.file_truncate) {
			BPF_PROG_DISABLE(skel->progs.handle_truncate);
			BPF_PROG_DISABLE(skel->progs.handle_ftruncate);
		}
		if (!cfg.emit.file_chmod)
			BPF_PROG_DISABLE(skel->progs.handle_fchmodat_enter);
		if (!cfg.emit.file_chown)
			BPF_PROG_DISABLE(skel->progs.handle_fchownat_enter);
	}

	/* ── Условное отключение process_tracking emit_* ───────────── *
	 * exec/fork/exit/sched_switch НЕЛЬЗЯ отключать: они управляют
	 * proc_map/tracked_map (core tracking pipeline).
	 * signal и chdir не имеют побочных эффектов — безопасны. */
	if (!cfg.emit.signal)
		BPF_PROG_DISABLE(skel->progs.handle_signal_generate);
	if (!cfg.emit.chdir) {
		BPF_PROG_DISABLE(skel->progs.handle_sys_exit_chdir);
		BPF_PROG_DISABLE(skel->progs.handle_sys_exit_fchdir);
	}

	/* ── Условное отключение cgroup tracepoints ────────────────── */
	if (!cfg.emit.cgroup) {
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
	if (!cfg.tcp_retransmit)
		BPF_PROG_DISABLE(skel->progs.handle_tcp_retransmit);
	if (!cfg.tcp_syn)
		BPF_PROG_DISABLE(skel->progs.kp_tcp_conn_request);
	if (!cfg.tcp_rst) {
		BPF_PROG_DISABLE(skel->progs.handle_tcp_send_reset);
		BPF_PROG_DISABLE(skel->progs.kp_tcp_send_active_reset);
		BPF_PROG_DISABLE(skel->progs.handle_tcp_receive_reset);
	}
	if (!cfg.icmp_tracking)
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

	/* Передача конфигурации отслеживания файлов в BPF-карты */
	if (cfg.file_tracking_enabled) {
		int file_cfg_fd = bpf_map__fd(skel->maps.file_cfg);
		__u32 key0 = 0;
		struct file_config fc = {
		    .enabled = 1,
		    .track_bytes = (__u8)cfg.file_track_bytes,
		    .absolute_paths_only = (__u8)cfg.file_absolute_paths_only,
		};
		bpf_map_update_elem(file_cfg_fd, &key0, &fc, BPF_ANY);

		int inc_fd = bpf_map__fd(skel->maps.file_include_prefixes);
		for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
			__u32 idx = (__u32)i;
			if (i < cfg.file_include_count)
				bpf_map_update_elem(inc_fd, &idx, &cfg.file_include[i], BPF_ANY);
		}

		int exc_fd = bpf_map__fd(skel->maps.file_exclude_prefixes);
		for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
			__u32 idx = (__u32)i;
			if (i < cfg.file_exclude_count)
				bpf_map_update_elem(exc_fd, &idx, &cfg.file_exclude[i], BPF_ANY);
		}
	}

	/* Передача конфигурации отслеживания сети в BPF-карты.
	 * net_cfg заполняется если нужна sock_map инфраструктура.
	 * enabled отражает именно cfg.net_tracking_enabled
	 * (управляет net_close/conn_snapshot, не security-пробами). */
	if (cfg.need_sock_map) {
		int net_cfg_fd = bpf_map__fd(skel->maps.net_cfg);
		__u32 key0 = 0;
		struct net_config nc = {
		    .enabled = (__u8)cfg.net_tracking_enabled,
		    .track_bytes = (__u8)cfg.net_track_bytes,
		};
		bpf_map_update_elem(net_cfg_fd, &key0, &nc, BPF_ANY);
	}

	/* Передача конфигурации отслеживания безопасности в BPF-карты */
	{
		int sec_cfg_fd = bpf_map__fd(skel->maps.sec_cfg);
		__u32 key0 = 0;
		struct sec_config sc = {
		    .tcp_retransmit = (__u8)cfg.tcp_retransmit,
		    .tcp_syn = (__u8)cfg.tcp_syn,
		    .tcp_rst = (__u8)cfg.tcp_rst,
		    .icmp_tracking = (__u8)cfg.icmp_tracking,
		    .tcp_open_conns = (__u8)cfg.tcp_open_conns,
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
	proc_map_fd = bpf_map__fd(skel->maps.proc_map);
	missed_exec_fd = bpf_map__fd(skel->maps.missed_exec_map);

	/* Ring buffers: по одному на каждый тип событий.
	 * Каждый будет обслуживаться отдельным потоком poll. */
	struct ring_buffer *rb_proc =
	    ring_buffer__new(bpf_map__fd(skel->maps.events_proc), handle_event, NULL, NULL);
	struct ring_buffer *rb_file =
	    ring_buffer__new(bpf_map__fd(skel->maps.events_file), handle_event, NULL, NULL);
	struct ring_buffer *rb_file_ops =
	    ring_buffer__new(bpf_map__fd(skel->maps.events_file_ops), handle_event, NULL, NULL);
	struct ring_buffer *rb_net =
	    ring_buffer__new(bpf_map__fd(skel->maps.events_net), handle_event, NULL, NULL);
	struct ring_buffer *rb_sec =
	    ring_buffer__new(bpf_map__fd(skel->maps.events_sec), handle_event, NULL, NULL);
	struct ring_buffer *rb_cgroup = ring_buffer__new(bpf_map__fd(skel->maps.events_cgroup),
							 handle_cgroup_event, NULL, NULL);
	if (!rb_proc || !rb_file || !rb_file_ops || !rb_net || !rb_sec || !rb_cgroup) {
		LOG_FATAL("failed to create ring buffers");
		if (rb_proc)
			ring_buffer__free(rb_proc);
		if (rb_file)
			ring_buffer__free(rb_file);
		if (rb_file_ops)
			ring_buffer__free(rb_file_ops);
		if (rb_net)
			ring_buffer__free(rb_net);
		if (rb_sec)
			ring_buffer__free(rb_sec);
		if (rb_cgroup)
			ring_buffer__free(rb_cgroup);
		process_metrics_bpf__destroy(skel);
		return 1;
	}

	/* Сигналы */
	signal(SIGTERM, sig_term);
	signal(SIGINT, sig_term);
	signal(SIGHUP, sig_hup);

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
	    {.rb = rb_proc, .name = "proc"},	     {.rb = rb_file, .name = "file"},
	    {.rb = rb_file_ops, .name = "file_ops"}, {.rb = rb_net, .name = "net"},
	    {.rb = rb_sec, .name = "sec"},	     {.rb = rb_cgroup, .name = "cgroup"},
	};
	pthread_t poll_threads[NUM_POLL_THREADS];

	for (int i = 0; i < NUM_POLL_THREADS; i++) {
		if (pthread_create(&poll_threads[i], NULL, poll_thread_fn, &args[i])) {
			LOG_FATAL("failed to create poll thread '%s'", args[i].name);
			g_running = 0;
			break;
		}
	}

	/* Однократное сканирование при запуске: поиск уже работающих процессов */
	initial_scan();
	/* Заполняем sock_map существующими TCP-сокетами отслеживаемых процессов */
	if (cfg.need_sock_map)
		seed_sock_map();
	refresh_boot_to_wall();

	/* Запуск HTTP-сервера, если включён */
	if (cfg.http.enabled) {
		if (http_server_start(&cfg.http) < 0) {
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
		 "tcp_open_conns=%s], "
		 "file=%s%s, icmp=%s, disk=%s, ring_buffer=%lld",
		 num_rules, cfg.snapshot_interval, cfg.refresh_interval, cfg.exec_rate_limit,
		 cfg.http.enabled ? "on" : "off", cfg.cgroup_metrics ? "on" : "off",
		 cfg.refresh_proc ? "on" : "off", cfg.net_tracking_enabled ? "on" : "off",
		 cfg.net_track_bytes ? "on" : "off", cfg.tcp_retransmit ? "on" : "off",
		 cfg.tcp_syn ? "on" : "off", cfg.tcp_rst ? "on" : "off",
		 cfg.tcp_open_conns ? "on" : "off", cfg.file_tracking_enabled ? "on" : "off",
		 cfg.file_track_bytes ? "+bytes" : "", cfg.icmp_tracking ? "on" : "off",
		 cfg.disk_tracking_enabled ? "on" : "off", (long long)cfg.max_data_size);

	/* Главный цикл — refresh, снапшот и перезагрузка конфигурации */
	time_t last_snapshot = 0;
	time_t last_refresh = 0;
	time_t last_heartbeat = 0;
	int hb_snapshots = 0; /* счётчик snapshot'ов с прошлого heartbeat */
	int hb_refreshes = 0; /* счётчик refresh'ей с прошлого heartbeat */

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
			parse_rules_from_config(cfg.config_file);
			build_cgroup_cache_ts();

			cpu_prev_count = 0;
			snapshot_reset();
			initial_scan();
			if (cfg.need_sock_map)
				seed_sock_map();

			/* Сбрасываем таймеры после перезагрузки */
			last_refresh = 0;
			last_snapshot = 0;
		}

		time_t now = time(NULL);

		/* Периодическое обновление: тяжёлый I/O (cmdline, cgroup sysfs,
		 * kill-проверка, flush udp/icmp/disk).
		 *
		 * Адаптивный интервал: при высокой заполненности tracked_map
		 * увеличиваем интервал, чтобы дать write_snapshot время
		 * на cleanup и не тратить CPU на итерацию мёртвых записей. */
		if (cfg.refresh_enabled) {
			int effective_refresh = cfg.refresh_interval;
			int fill_pct = g_last_map_count * 100 / MAX_PROCS;
			if (fill_pct > REFRESH_FILL_HIGH_PCT)
				effective_refresh = cfg.refresh_interval * REFRESH_MULT_HIGH;
			else if (fill_pct > REFRESH_FILL_MED_PCT)
				effective_refresh = cfg.refresh_interval * REFRESH_MULT_MED;
			if (effective_refresh > cfg.snapshot_interval)
				effective_refresh = cfg.snapshot_interval;

			if (now - last_refresh >= effective_refresh) {
				refresh_processes();
				last_refresh = now;
				hb_refreshes++;
			}
		}

		if (!g_running)
			break;

		/* Периодический снапшот: лёгкий, только чтение из кешей */
		if (now - last_snapshot >= cfg.snapshot_interval) {
			write_snapshot();
			last_snapshot = now;
			hb_snapshots++;
		}

		/* Heartbeat — дельта-диагностика за интервал.
		 * Если эта строка перестаёт появляться — главный поток завис. */
		if (cfg.heartbeat_interval > 0 && now - last_heartbeat >= cfg.heartbeat_interval) {
			static __u64 prev_ev[NUM_POLL_THREADS], prev_po[NUM_POLL_THREADS];
			__u64 ev[NUM_POLL_THREADS], po[NUM_POLL_THREADS];
			for (int i = 0; i < NUM_POLL_THREADS; i++) {
				ev[i] = __atomic_load_n(&args[i].events, __ATOMIC_RELAXED);
				po[i] = __atomic_load_n(&args[i].polls, __ATOMIC_RELAXED);
			}
			LOG_INFO("heartbeat: %d refreshes, %d snapshots | "
				 "maps: tracked=%d conns=%d | "
				 "events/%ds: proc=%llu file=%llu file_ops=%llu "
				 "net=%llu sec=%llu cgroup=%llu",
				 hb_refreshes, hb_snapshots, g_last_map_count, g_last_conn_count,
				 cfg.heartbeat_interval, (unsigned long long)(ev[0] - prev_ev[0]),
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

	free(cgroup_cache);
	free(cg_metrics);
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
