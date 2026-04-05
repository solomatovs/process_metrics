/*
 * snapshot.c — периодический snapshot: сбор метрик из BPF-карт и кэшей.
 *
 * Функции, вынесенные из process_metrics.c:
 *   - write_snapshot
 *   - tags_lookup_copy, pidtree_get_chain_copy
 *   - should_emit_snapshot, should_emit_conn_snapshot, should_include_conn
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "process_metrics_common.h"
#include "event_file.h"
#include "pm_config.h"
#include "pm_state.h"
#include "pm_functions.h"
#include "pm_rules.h"
#include "constants.h"
#include "process_metrics.skel.h"
#include "log.h"

/* ── локальные определения ───────────────────────────────────────── */

#define TAGS_MAX_LEN EV_TAGS_LEN

/* prev_snapshot_ts — используется только в write_snapshot */
static struct timespec prev_snapshot_ts;

/* ── snapshot guards ─────────────────────────────────────────────── */

static int should_emit_snapshot(void)
{
	return cfg.http.enabled;
}

static int should_emit_conn_snapshot(void)
{
	return g_need_sock_map && cfg.http.enabled;
}

/* ── snapshot-only helpers ───────────────────────────────────────── */

/*
 * Murmurhash3 finalizer для tags hash table.
 * Дублируется из process_metrics.c — используется tags_lookup_copy.
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

/*
 * Поиск тегов в локальной копии (без lock).
 * snap_tgid/snap_data — snapshot, сделанный через memcpy под кратким rdlock
 * в начале write_snapshot (см. ОПТИМИЗАЦИЯ 4).
 * Вызывается десятки раз за snapshot — без locks, т.к. работает с копией.
 */
static const char *tags_lookup_copy(const __u32 *snap_tgid, const char snap_data[][TAGS_MAX_LEN],
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

/*
 * Получить цепочку предков из snapshot-копии pid tree (без lock).
 * Используется в write_snapshot() чтобы не держать g_pidtree_lock
 * на всю итерацию.
 */
static void pidtree_get_chain_copy(const __u32 *snap_pid, const __u32 *snap_ppid, __u32 pid,
				   __u32 *out, __u8 *out_len)
{
	int n = pidtree_walk_chain(snap_pid, snap_ppid, pid, out, EV_PARENT_PIDS_MAX);
	*out_len = (__u8)n;
}

/*
 * Сброс состояния snapshot (при reload конфигурации).
 */
void snapshot_reset(void)
{
	prev_snapshot_ts = (struct timespec){0};
}

/* ── write_snapshot ──────────────────────────────────────────────── */

/*
 * write_snapshot — лёгкий слепок: собрать из кэшей/карт, записать в event_file.
 *
 * Без файлового I/O. Все тяжёлые данные уже обновлены refresh_processes().
 * Единственные syscall: bpf_map_lookup_batch (1x), bpf_map_lookup_elem (per-PID),
 * ef_append (write в memory-mapped ring).
 */
void write_snapshot(void)
{
	/* ── Восстановление после ring buffer drop на FORK ────────────
	 * BPF handle_fork создаёт proc_map запись ДО резервирования
	 * ring buffer. Если bpf_ringbuf_reserve не удался, userspace не
	 * получил fork-событие и не вызвал pidtree_store_ts / tags_inherit_ts /
	 * pwd_inherit_ts. Детектируем это по отсутствию pid в pidtree
	 * и восстанавливаем наследование от родителя.
	 */
	{
		__u32 key;
		int fork_rec_iter = 0;
		int err = bpf_map_get_next_key(proc_map_fd, NULL, &key);
		while (err == 0 && fork_rec_iter++ < MAX_PROCS) {
			__u32 next;
			int next_err = bpf_map_get_next_key(proc_map_fd, &key, &next);

			/* Быстрая проверка: есть ли pid в pidtree? */
			pthread_rwlock_rdlock(&g_pidtree_lock);
			__u32 ppid_in_tree = pidtree_lookup_in(pt_pid, pt_ppid, key);
			pthread_rwlock_unlock(&g_pidtree_lock);

			if (ppid_in_tree == 0) {
				/* Нет в pidtree → fork-событие было потеряно.
				 * Берём ppid из proc_info и восстанавливаем. */
				struct proc_info pi;
				if (bpf_map_lookup_elem(proc_map_fd, &key, &pi) == 0 &&
				    pi.ppid > 0) {
					pidtree_store_ts(key, pi.ppid);
					tags_inherit_ts(key, pi.ppid);
					pwd_inherit_ts(key, pi.ppid);
					LOG_DEBUG(cfg.log_level,
						  "FORK_RECOVERY: pid=%u ppid=%u"
						  " (ring buffer drop)",
						  key, pi.ppid);
				}
			}

			if (next_err != 0)
				break;
			key = next;
		}
	}

	/* ОПТИМИЗАЦИЯ 4: копируем tags под кратким rdlock */
	static __u32 snap_tgid[TAGS_HT_SIZE];
	static char snap_data[TAGS_HT_SIZE][TAGS_MAX_LEN];
	pthread_rwlock_rdlock(&g_tags_lock);
	memcpy(snap_tgid, tags_tgid, sizeof(tags_tgid));
	memcpy(snap_data, tags_data, sizeof(tags_data));
	pthread_rwlock_unlock(&g_tags_lock);

	/* Snapshot pid tree для цепочек предков (512 КБ, ~0.1ms) */
	static __u32 snap_pt_pid[PIDTREE_HT_SIZE];
	static __u32 snap_pt_ppid[PIDTREE_HT_SIZE];
	pthread_rwlock_rdlock(&g_pidtree_lock);
	memcpy(snap_pt_pid, pt_pid, sizeof(pt_pid));
	memcpy(snap_pt_ppid, pt_ppid, sizeof(pt_ppid));
	pthread_rwlock_unlock(&g_pidtree_lock);

	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		page_size = FALLBACK_PAGE_SIZE;

	struct timespec mono;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	double mono_now = (double)mono.tv_sec + (double)mono.tv_nsec / 1e9;

	double elapsed_ns = 0;
	if (prev_snapshot_ts.tv_sec > 0) {
		elapsed_ns = (double)(mono.tv_sec - prev_snapshot_ts.tv_sec) * 1e9 +
			     (double)(mono.tv_nsec - prev_snapshot_ts.tv_nsec);
	}
	prev_snapshot_ts = mono;

	struct timespec snap_ts;
	clock_gettime(CLOCK_REALTIME, &snap_ts);
	__u64 snap_timestamp_ns = (__u64)snap_ts.tv_sec * NS_PER_SEC + (__u64)snap_ts.tv_nsec;

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
			DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts, .elem_flags = 0,
					    .flags = 0, );
			__u32 out_batch = 0;
			int ret = bpf_map_lookup_batch(proc_map_fd, NULL, &out_batch, all_keys,
						       all_values, &batch_count, &opts);
			if (ret == 0 || (ret < 0 && errno == ENOENT)) {
				all_keys_count = (int)batch_count;
			} else {
				all_keys_count = 0;
				__u32 iter_key;
				int err2 = bpf_map_get_next_key(proc_map_fd, NULL, &iter_key);
				while (err2 == 0 && all_keys_count < (int)MAX_PROCS) {
					all_keys[all_keys_count++] = iter_key;
					err2 =
					    bpf_map_get_next_key(proc_map_fd, &iter_key, &iter_key);
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

		int tracked = (pi.rule_id != RULE_ID_NONE);
		int is_exited = (pi.status != PROC_STATUS_ALIVE);

		/* Завершённые → в dead_keys, но НЕ пропускаются.
		 * При переполнении буфера — flush и продолжаем сбор. */
		if (is_exited) {
			if (dead_count >= DEAD_KEYS_CAP) {
				dead_total += flush_dead_keys(dead_keys, dead_count);
				dead_count = 0;
			}
			dead_keys[dead_count++] = key;
		}

		const char *rule_name =
		    (tracked && pi.rule_id < num_rules) ? rules[pi.rule_id].name : RULE_NOT_MATCH;

		/* Вычисление времён */
		double uptime_sec = mono_now - (double)pi.start_ns / 1e9;
		if (uptime_sec < 0)
			uptime_sec = 0;
		double cpu_ratio = 0;
		if (elapsed_ns > 0) {
			__u64 prev_ns = cpu_prev_lookup(key);
			cpu_ratio = (prev_ns > 0 && pi.cpu_ns >= prev_ns)
					? (double)(pi.cpu_ns - prev_ns) / elapsed_ns
					: 0;
		}
		cpu_prev_update(key, pi.cpu_ns);

		/* Формирование события snapshot */
		if (should_emit_snapshot()) {
			struct metric_event cev;
			memset(&cev, 0, sizeof(cev));
			cev.timestamp_ns = snap_timestamp_ns;
			snprintf(cev.event_type, sizeof(cev.event_type), "snapshot");
			fill_rule(&cev, rule_name);
			{
				const char *snap_tags = tags_lookup_copy(snap_tgid, snap_data, key);
				if (snap_tags[0])
					snprintf(cev.tags, sizeof(cev.tags), "%s", snap_tags);
				else
					ensure_tags(key, cev.tags, sizeof(cev.tags));
			}
			cev.root_pid = pi.root_pid;
			cev.is_root = pi.is_root;
			fill_from_proc_info(&cev, &pi);
			fill_cgroup(&cev, pi.cgroup_id);
			fill_cgroup_metrics(&cev);
			cev.cpu_usage_ratio = cpu_ratio;
			cev.uptime_seconds = (__u64)(uptime_sec > 0 ? uptime_sec : 0);

			fill_pwd(&cev, pi.tgid);

			/* open_conn_map — BPF map lookup, не файловый I/O */
			if (cfg.tcp_open_conns) {
				__u64 conn_cnt = 0;
				int occ_fd = bpf_map__fd(skel->maps.open_conn_map);
				__u32 occ_key = pi.tgid;
				if (bpf_map_lookup_elem(occ_fd, &occ_key, &conn_cnt) == 0)
					cev.open_tcp_conns = conn_cnt;
			}

			pidtree_get_chain_copy(snap_pt_pid, snap_pt_ppid, cev.pid, cev.parent_pids,
					       &cev.parent_pids_len);
			ef_append(&cev, cfg.hostname);
			snap_count++;
		}
		pid_count++;
	}
	free(all_keys);
	free(all_values);

	/* boot_ns — для вычисления длительности в conn_snapshot и file_snapshot */
	struct timespec boot_ts;
	clock_gettime(CLOCK_BOOTTIME, &boot_ts);
	__u64 boot_ns = (__u64)boot_ts.tv_sec * NS_PER_SEC + (__u64)boot_ts.tv_nsec;

	/* ── conn_snapshot: метрики живых TCP-соединений ──────────────── */
	int conn_count = 0;
	if (should_emit_conn_snapshot()) {
		int sm_fd = bpf_map__fd(skel->maps.sock_map);

		int closed_sock_count = 0;

		__u64 sk_key;
		int sk_iter = 0;
		int sk_err = bpf_map_get_next_key(sm_fd, NULL, &sk_key);
		while (sk_err == 0 && sk_iter++ < NET_MAX_SOCKETS) {
			__u64 sk_next;
			int sk_next_err = bpf_map_get_next_key(sm_fd, &sk_key, &sk_next);
			struct sock_info si;
			if (bpf_map_lookup_elem(sm_fd, &sk_key, &si) == 0) {

				{
					struct metric_event cev;
					memset(&cev, 0, sizeof(cev));
					cev.timestamp_ns = snap_timestamp_ns;
					fast_strcpy(cev.event_type, sizeof(cev.event_type),
						    "conn_snapshot");
					struct proc_info conn_pi;
					if (bpf_map_lookup_elem(proc_map_fd, &si.tgid, &conn_pi) ==
					    0) {
						cev.root_pid = conn_pi.root_pid;
						cev.is_root = conn_pi.is_root;
						if (conn_pi.rule_id < num_rules)
							fill_rule(&cev,
								  rules[conn_pi.rule_id].name);
						fill_from_proc_info(&cev, &conn_pi);
					}
					{
						const char *cs_tags =
						    tags_lookup_copy(snap_tgid, snap_data, si.tgid);
						if (cs_tags[0])
							fast_strcpy(cev.tags, sizeof(cev.tags),
								    cs_tags);
						else
							ensure_tags(si.tgid, cev.tags,
								    sizeof(cev.tags));
					}

					fill_from_sock_info(&cev, &si, boot_ns);

					pidtree_get_chain_copy(snap_pt_pid, snap_pt_ppid, si.tgid,
							       cev.parent_pids,
							       &cev.parent_pids_len);
					ef_append(&cev, cfg.hostname);
					conn_count++;
				}

				/* CLOSED → удаляем ПОСЛЕ snapshot записи */
				if (si.status == SOCK_STATUS_CLOSED) {
					bpf_map_delete_elem(sm_fd, &sk_key);
					closed_sock_count++;
				}
			}

			if (sk_next_err != 0)
				break;
			sk_key = sk_next;
		}

		if (closed_sock_count > 0)
			LOG_DEBUG(cfg.log_level, "conn_snapshot: cleaned %d closed socks",
				  closed_sock_count);
	}

	/* file_snapshot убран: file_open/file_close events через ring buffer
	 * полностью покрывают файловый I/O, включая короткоживущие fd. */

	ef_batch_unlock();

	/* Очистка завершённых процессов — BPF-карты + все userspace-кэши */
	dead_total += flush_dead_keys(dead_keys, dead_count);

	if (cfg.log_snapshot)
		LOG_INFO("snapshot: %d PIDs (%d exited), %d events, %d conns", pid_count,
			 dead_total, snap_count, conn_count);

	/* Обновляем глобальные счётчики для heartbeat */
	g_last_conn_count = conn_count;

	/* Статистика ring buffer'ов — логируем только НОВЫЕ drops */
	{
		static struct ringbuf_stats prev_rs;
		__u32 key = 0;
		struct ringbuf_stats rs = {0};
		int stats_fd = bpf_map__fd(skel->maps.ringbuf_stats);
		if (stats_fd >= 0 && bpf_map_lookup_elem(stats_fd, &key, &rs) == 0) {
			__u64 new_drops = (rs.drop_proc - prev_rs.drop_proc) +
					  (rs.drop_file - prev_rs.drop_file) +
					  (rs.drop_file_ops - prev_rs.drop_file_ops) +
					  (rs.drop_net - prev_rs.drop_net) +
					  (rs.drop_sec - prev_rs.drop_sec) +
					  (rs.drop_cgroup - prev_rs.drop_cgroup);
			if (new_drops > 0) {
				LOG_WARN("ringbuf drops: proc=%llu/%llu file=%llu/%llu "
					 "file_ops=%llu/%llu net=%llu/%llu sec=%llu/%llu "
					 "cgroup=%llu/%llu",
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
					 (unsigned long long)rs.total_cgroup);
			} else if (cfg.log_level >= 2) {
				LOG_DEBUG(cfg.log_level,
					  "ringbuf totals: proc=%llu file=%llu net=%llu sec=%llu "
					  "cgroup=%llu",
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
			for (int i = 0; i < PIDTREE_HT_SIZE && gc_count < DEAD_KEYS_CAP; i++) {
				__u32 pid = pt_pid[i];
				if (pid == 0)
					continue;
				if (is_pid_in_proc_map(pid, NULL))
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
				LOG_DEBUG(cfg.log_level,
					  "PIDTREE_GC: removed %d dead"
					  " untracked entries",
					  gc_count);
			}
		}
	}
}
