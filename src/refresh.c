/*
 * refresh.c — периодическое обновление /proc, cgroup sysfs, flush агрегатов.
 *
 * Функции, вынесенные из process_metrics.c:
 *   - read_cgroup_value, read_cgroup_cpu_max, read_cgroup_cpu_stat
 *   - emit_disk_usage_events
 *   - flush_dead_keys
 *   - refresh_processes
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <mntent.h>
#include <arpa/inet.h>
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

/* ── снапшот: сбор метрик ─────────────────────────────────────────── */

/*
 * Чтение значения из cgroup sysfs.
 * Используем raw open/read/close вместо fopen/fclose.
 * fclose() на kernfs файлах тригерит cgroup_file_release → deferred fput
 * через task_work, что блокирует поток на synchronize_rcu при возврате
 * из syscall. При ~350 fclose за snapshot — блокировка ~7 секунд.
 * Raw close() не создаёт такой проблемы.
 */
long long read_cgroup_value(const char *cg_path, const char *file)
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
void read_cgroup_cpu_max(const char *cg_path, long long *quota, long long *period)
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
void read_cgroup_cpu_stat(const char *cg_path, long long *nr_periods, long long *nr_throttled,
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
		while (*p && *p != '\n')
			p++;
		if (*p == '\n')
			p++;
	}
}

/*
 * Генерация событий disk_usage для каждой уникальной реальной файловой системы.
 * Читает /proc/mounts, применяет фильтры fs_type/include/exclude,
 * дедуплицирует по устройству, вызывает statvfs().
 */
int emit_disk_usage_events(__u64 timestamp_ns, const char *hostname)
{
	/* Типы ФС по умолчанию, если не заданы в конфигурации */
	static const char *default_fs[] = {"ext2", "ext3", "ext4",    "xfs",  "btrfs", "vfat",
					   "zfs",  "ntfs", "fuseblk", "f2fs", NULL};

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
		if (cfg.disk_fs_types_count > 0) {
			for (int i = 0; i < cfg.disk_fs_types_count; i++) {
				if (strcmp(ent->mnt_type, cfg.disk_fs_types[i]) == 0) {
					is_real = 1;
					break;
				}
			}
		} else {
			for (int i = 0; default_fs[i]; i++) {
				if (strcmp(ent->mnt_type, default_fs[i]) == 0) {
					is_real = 1;
					break;
				}
			}
		}
		if (!is_real)
			continue;

		/* Фильтр исключения (префикс точки монтирования) */
		int excluded = 0;
		for (int i = 0; i < cfg.disk_exclude_count; i++) {
			if (strncmp(ent->mnt_dir, cfg.disk_exclude[i],
				    strlen(cfg.disk_exclude[i])) == 0) {
				excluded = 1;
				break;
			}
		}
		if (excluded)
			continue;

		/* Фильтр включения (префикс точки монтирования) — если задан, только совпадающие */
		if (cfg.disk_include_count > 0) {
			int included = 0;
			for (int i = 0; i < cfg.disk_include_count; i++) {
				if (strncmp(ent->mnt_dir, cfg.disk_include[i],
					    strlen(cfg.disk_include[i])) == 0) {
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
			snprintf(seen_devs[seen_count++], DISK_DEV_NAME_LEN, "%s", ent->mnt_fsname);

		struct statvfs svfs;
		if (statvfs(ent->mnt_dir, &svfs) != 0)
			continue;

		struct metric_event cev;
		memset(&cev, 0, sizeof(cev));
		fill_rule(&cev, RULE_NOT_MATCH);
		cev.timestamp_ns = timestamp_ns;
		snprintf(cev.event_type, sizeof(cev.event_type), "disk_usage");

		/* точка монтирования */
		snprintf(cev.file_path, sizeof(cev.file_path), "%s", ent->mnt_dir);

		/* имя устройства (basename) в comm */
		const char *devname = strrchr(ent->mnt_fsname, '/');
		devname = devname ? devname + 1 : ent->mnt_fsname;
		snprintf(cev.comm, sizeof(cev.comm), "%s", devname);

		/* тип ФС */
		snprintf(cev.sec_remote_addr, sizeof(cev.sec_remote_addr), "%s", ent->mnt_type);

		__u64 bsz = (__u64)svfs.f_frsize;
		cev.disk_total_bytes = bsz * (__u64)svfs.f_blocks;
		cev.disk_used_bytes = bsz * ((__u64)svfs.f_blocks - (__u64)svfs.f_bfree);
		cev.disk_avail_bytes = bsz * (__u64)svfs.f_bavail;

		ef_append(&cev, hostname);
		disk_count++;
	}

	endmntent(mf);
	return disk_count;
}

/*
 * flush_dead_keys — пакетное удаление мёртвых процессов из BPF-карт и userspace-кэшей.
 *
 * Использует bpf_map_delete_batch для удаления из proc_map и proc_map
 * за 2 syscall вместо 2*count. Если batch delete не поддерживается ядром
 * (< 5.6), fallback на поштучное удаление.
 *
 * Возвращает количество удалённых ключей.
 */
int flush_dead_keys(__u32 *keys, int count)
{
	if (count <= 0)
		return 0;

	/* Удаляем из обеих карт. Используем bpf_map_delete_batch где
	 * возможно — это 1 syscall вместо N. При ошибке (ключ уже удалён
	 * BPF handle_exit) batch может вернуть частичный результат —
	 * это нормально, дочищаем остаток поштучно.
	 *
	 * Порядок: сначала proc_map, потом proc_map.
	 * proc_map — источник ключей для refresh iteration (batch read),
	 * proc_map — единственная карта отслеживания. */
	for (int i = 0; i < count; i++)
		bpf_map_delete_elem(proc_map_fd, &keys[i]);

	/* Userspace-кэши */
	for (int i = 0; i < count; i++) {
		cpu_prev_remove(keys[i]);
		pwd_remove_ts(keys[i]);
		tags_remove_ts(keys[i]);
		pidtree_remove_ts(keys[i]);
	}

	return count;
}

/*
 * refresh_processes — тяжёлый I/O: обновление /proc, cgroup sysfs, flush агрегатов.
 *
 * Вызывается с периодом cfg.refresh_interval (≤ cfg.snapshot_interval).
 * Обновляет:
 *   - cmdline/comm из /proc (если cfg.refresh_proc=1)
 *   - cgroup-метрики из /sys/fs/cgroup → cg_metrics[]
 *   - Обнаружение мёртвых процессов (fallback kill(pid,0) для потерянных EXIT)
 *   - Flush UDP/ICMP агрегатов → ef_append
 *   - Disk usage → ef_append
 */
void refresh_processes(void)
{
	refresh_boot_to_wall();

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
			DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts, .elem_flags = 0,
					    .flags = 0, );
			__u32 out_batch = 0;
			int ret = bpf_map_lookup_batch(proc_map_fd, NULL, &out_batch, all_keys,
						       all_values, &batch_count, &opts);
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
			int err2 = bpf_map_get_next_key(proc_map_fd, NULL, &iter_key);
			while (err2 == 0 && all_keys_count < (int)MAX_PROCS) {
				all_keys[all_keys_count++] = iter_key;
				err2 = bpf_map_get_next_key(proc_map_fd, &iter_key, &iter_key);
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
				    flush_dead_keys(early_dead, early_dead_count);
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
				    flush_dead_keys(early_dead, early_dead_count);
				early_dead_count = 0;
			}
			early_dead[early_dead_count++] = key;
			continue;
		}

		/* Обновляем cmdline/comm только для живых процессов */
		if (cfg.refresh_proc) {
			char fresh[CMDLINE_MAX];
			int flen = read_proc_cmdline(key, fresh, sizeof(fresh));
			if (flen > 0) {
				memcpy(pi.cmdline, fresh, CMDLINE_MAX);
				pi.cmdline_len = (__u16)flen;
				bpf_map_update_elem(proc_map_fd, &key, &pi, BPF_EXIST);
			}
			char cpath[LINE_BUF_LEN];
			snprintf(cpath, sizeof(cpath), "/proc/%u/comm", key);
			FILE *cf = fopen(cpath, "r");
			if (cf) {
				char cbuf[COMM_LEN];
				if (fgets(cbuf, sizeof(cbuf), cf)) {
					cbuf[strcspn(cbuf, "\n")] = '\0';
					memcpy(pi.comm, cbuf, COMM_LEN);
					memcpy(pi.thread_name, cbuf, COMM_LEN);
					bpf_map_update_elem(proc_map_fd, &key, &pi, BPF_EXIST);
				}
				fclose(cf);
			}
		}

		/* Обновление ppid из /proc — обнаружение reparent.
		 * Когда ядро убивает промежуточный процесс в цепочке,
		 * дочерние процессы переназначаются на init (или subreaper).
		 * BPF не получает уведомлений о reparent, поэтому pidtree
		 * и proc_info.ppid устаревают. Здесь сверяем с реальностью.
		 * Не зависит от cfg.refresh_proc — это вопрос корректности
		 * дерева процессов, а не опциональное обновление cmdline. */
		{
			__u32 real_ppid = read_proc_ppid(key);
			if (real_ppid > 0 && real_ppid != pi.ppid) {
				LOG_DEBUG(cfg.log_level, "REPARENT: pid=%u ppid %u→%u", key,
					  pi.ppid, real_ppid);
				pi.ppid = real_ppid;
				bpf_map_update_elem(proc_map_fd, &key, &pi, BPF_EXIST);
				pidtree_store_ts(key, real_ppid);
			}
		}

		/* Сбор уникальных cgroup → cg_metrics[] */
		if (cfg.cgroup_metrics) {
			char cg_path[PATH_MAX_LEN], cg_fs_path[PATH_MAX_LEN];
			resolve_cgroup_ts(pi.cgroup_id, cg_path, sizeof(cg_path));
			if (cg_path[0] && cg_metrics_count < cfg.max_cgroups) {
				/* Проверяем, уже есть ли в кэше */
				int found = 0;
				for (int i = 0; i < cg_metrics_count; i++) {
					if (strcmp(cg_metrics[i].path, cg_path) == 0) {
						found = 1;
						break;
					}
				}
				if (!found) {
					resolve_cgroup_fs_ts(pi.cgroup_id, cg_fs_path,
							     sizeof(cg_fs_path));
					int idx = cg_metrics_count;
					snprintf(cg_metrics[idx].path, sizeof(cg_metrics[0].path),
						 "%s", cg_path);
					cg_metrics[idx].valid = 0;
					if (cg_fs_path[0]) {
						cg_metrics[idx].mem_max =
						    read_cgroup_value(cg_fs_path, "memory.max");
						cg_metrics[idx].mem_cur =
						    read_cgroup_value(cg_fs_path, "memory.current");
						cg_metrics[idx].swap_cur = read_cgroup_value(
						    cg_fs_path, "memory.swap.current");
						cg_metrics[idx].cpu_weight =
						    read_cgroup_value(cg_fs_path, "cpu.weight");
						read_cgroup_cpu_max(
						    cg_fs_path, &cg_metrics[idx].cpu_max,
						    &cg_metrics[idx].cpu_max_period);
						read_cgroup_cpu_stat(
						    cg_fs_path, &cg_metrics[idx].cpu_nr_periods,
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

	LOG_DEBUG(cfg.log_level, "refresh: %d alive, %d early cleanup, %d total proc_map entries",
		  refresh_count, early_cleanup_count, all_keys_count);

	/* Flush ICMP агрегатов → ef_append */
	if (should_emit_icmp()) {
		struct timespec now_ts;
		clock_gettime(CLOCK_REALTIME, &now_ts);
		__u64 ts_ns = (__u64)now_ts.tv_sec * NS_PER_SEC + (__u64)now_ts.tv_nsec;

		int icmp_fd = bpf_map__fd(skel->maps.icmp_agg_map);
		struct icmp_agg_key ikey;
		struct icmp_agg_val ival;
		int icmp_count = 0;

		while (bpf_map_get_next_key(icmp_fd, NULL, &ikey) == 0) {
			if (bpf_map_lookup_elem(icmp_fd, &ikey, &ival) == 0 && ival.count > 0) {
				struct metric_event cev;
				memset(&cev, 0, sizeof(cev));
				fill_rule(&cev, RULE_NOT_MATCH);
				cev.timestamp_ns = ts_ns;
				snprintf(cev.event_type, sizeof(cev.event_type), "icmp_agg");
				int is_v4 = 1;
				for (int b = 4; b < 16; b++) {
					if (ikey.src_addr[b]) {
						is_v4 = 0;
						break;
					}
				}
				if (is_v4) {
					cev.sec_af = 2;
					snprintf(cev.sec_remote_addr, sizeof(cev.sec_remote_addr),
						 "%u.%u.%u.%u", ikey.src_addr[0], ikey.src_addr[1],
						 ikey.src_addr[2], ikey.src_addr[3]);
				} else {
					cev.sec_af = 10;
					inet_ntop(AF_INET6, ikey.src_addr, cev.sec_remote_addr,
						  sizeof(cev.sec_remote_addr));
				}
				cev.sec_tcp_state = ikey.icmp_type;
				cev.sec_direction = ikey.icmp_code;
				cev.open_tcp_conns = ival.count;
				fill_parent_pids(&cev);
				ef_append(&cev, cfg.hostname);
				icmp_count++;
			}
			bpf_map_delete_elem(icmp_fd, &ikey);
		}
		if (icmp_count > 0)
			LOG_DEBUG(cfg.log_level, "ICMP flush: %d aggregates", icmp_count);
	}

	/* Disk usage → ef_append */
	if (should_emit_disk()) {
		struct timespec now_ts;
		clock_gettime(CLOCK_REALTIME, &now_ts);
		__u64 ts_ns = (__u64)now_ts.tv_sec * NS_PER_SEC + (__u64)now_ts.tv_nsec;
		int disk_ev = emit_disk_usage_events(ts_ns, cfg.hostname);
		if (disk_ev > 0)
			LOG_DEBUG(cfg.log_level, "disk refresh: %d events", disk_ev);
	}

	if (cfg.log_refresh)
		LOG_INFO("refresh: %d PIDs, %d cgroups", refresh_count, cg_metrics_count);
}
