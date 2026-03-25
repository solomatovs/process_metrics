// SPDX-License-Identifier: GPL-2.0
/*
 * process_metrics.bpf.c — событийный сбор метрик процессов через BPF
 *
 * Точки трассировки:
 *   sched_process_exec  → захват pid, cmdline, comm, cgroup
 *   sched_process_fork  → наследование отслеживания от родителя (raw_tp)
 *   sched_switch        → обновление rss, cpu, vsize для отслеживаемых PID
 *   sched_process_exit  → финализация метрик, отправка в пространство пользователя
 *   mark_victim         → OOM killer выбрал процесс (raw_tp)
 *
 * Карты (maps):
 *   proc_map    — метрики процессов в реальном времени (hash: tgid → proc_info)
 *   tracked_map — метаданные отслеживания            (hash: tgid → track_info)
 *   events      — кольцевой буфер событий жизненного цикла
 *
 * Пространство пользователя управляет решениями об отслеживании (сопоставление правил exec).
 * BPF только собирает данные для отслеживаемых PID и отправляет события жизненного цикла.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "process_metrics_common.h"

/* ── rodata (настраивается из пространства пользователя перед загрузкой) ── */

/* Макс. событий exec в секунду, отправляемых в кольцевой буфер. 0 = без ограничений. */
volatile const __u32 max_exec_events_per_sec = 0;

/* ── карты (maps) ─────────────────────────────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, struct proc_info);
} proc_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, struct track_info);
} tracked_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_state);
} exec_rate SEC(".maps");

/*
 * Per-CPU scratch buffer for building proc_info on the stack
 * (proc_info exceeds 512-byte BPF stack limit).
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proc_info);
} scratch_pi SEC(".maps");

/* ── ограничитель частоты ─────────────────────────────────────────── */

/*
 * Посекундный скользящий ограничитель частоты для событий exec.
 * Возвращает 1, если событие должно быть отправлено, 0 — если лимит превышен.
 * Небольшая гонка на нескольких CPU (счётчик может превысить лимит) — допустимо.
 */
static __always_inline int exec_rate_check(void)
{
	__u32 key = 0;
	struct rate_state *rs;

	if (!max_exec_events_per_sec)
		return 1;

	rs = bpf_map_lookup_elem(&exec_rate, &key);
	if (!rs)
		return 1;

	__u64 now = bpf_ktime_get_ns();

	/* Новое 1-секундное окно — сброс счётчика */
	if (now - rs->window_ns >= 1000000000ULL) {
		rs->window_ns = now;
		rs->count = 1;
		return 1;
	}

	rs->count++;
	return rs->count <= max_exec_events_per_sec;
}

/* ── вспомогательные функции ──────────────────────────────────────── */

struct mem_info {
	__u64 rss_pages;    /* файловые + анонимные + shmem */
	__u64 shmem_pages;  /* только разделяемая память */
	__u64 swap_pages;   /* записи подкачки */
};

static __always_inline struct mem_info read_mem_pages(struct task_struct *task)
{
	struct mem_info mi = {0};
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return mi;

	/* MM_FILEPAGES=0, MM_ANONPAGES=1, MM_SWAPENTS=2, MM_SHMEMPAGES=3 */
	long v0 = 0, v1 = 0, v2 = 0, v3 = 0;
	bpf_core_read(&v0, sizeof(v0), &mm->rss_stat.count[0].counter);
	bpf_core_read(&v1, sizeof(v1), &mm->rss_stat.count[1].counter);
	bpf_core_read(&v2, sizeof(v2), &mm->rss_stat.count[2].counter);
	bpf_core_read(&v3, sizeof(v3), &mm->rss_stat.count[3].counter);

	long total = v0 + v1 + v3;
	mi.rss_pages   = total > 0 ? (__u64)total : 0;
	mi.shmem_pages = v3 > 0 ? (__u64)v3 : 0;
	mi.swap_pages  = v2 > 0 ? (__u64)v2 : 0;
	return mi;
}

static __always_inline __u64 read_cpu_ns(struct task_struct *task)
{
	/*
	 * signal->{utime,stime} накапливает CPU завершённых потоков.
	 * Добавляем CPU group_leader для приближённого значения.
	 * Точно для однопоточных процессов.
	 */
	__u64 u = BPF_CORE_READ(task, signal, utime);
	__u64 s = BPF_CORE_READ(task, signal, stime);

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		u += BPF_CORE_READ(leader, utime);
		s += BPF_CORE_READ(leader, stime);
	}
	return u + s;
}

static __always_inline __u64 read_vsize_pages(struct task_struct *task)
{
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	return mm ? (__u64)BPF_CORE_READ(mm, total_vm) : 0;
}

static __always_inline __u32 read_nr_threads(struct task_struct *task)
{
	return (__u32)BPF_CORE_READ(task, signal, nr_threads);
}

static __always_inline __s16 read_oom_score_adj(struct task_struct *task)
{
	return (__s16)BPF_CORE_READ(task, signal, oom_score_adj);
}

/*
 * Учёт ввода-вывода: фактические байты чтения/записи на диск.
 * task->ioac накапливается по всем потокам через signal->ioac при завершении,
 * но для живых потоков читаем из group_leader + signal.
 */
static __always_inline void read_io_bytes(struct task_struct *task,
					  __u64 *r, __u64 *w)
{
	/* signal->ioac накапливает IO завершённых потоков */
	*r = BPF_CORE_READ(task, signal, ioac.read_bytes);
	*w = BPF_CORE_READ(task, signal, ioac.write_bytes);

	/* Добавляем IO group_leader */
	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		*r += BPF_CORE_READ(leader, ioac.read_bytes);
		*w += BPF_CORE_READ(leader, ioac.write_bytes);
	}
}

/*
 * Страничные отказы: signal накапливает завершённые потоки, добавляем счётчики leader.
 */
static __always_inline void read_faults(struct task_struct *task,
					__u64 *maj, __u64 *min)
{
	*maj = BPF_CORE_READ(task, signal, cmaj_flt);
	*min = BPF_CORE_READ(task, signal, cmin_flt);

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		*maj += BPF_CORE_READ(leader, maj_flt);
		*min += BPF_CORE_READ(leader, min_flt);
	}
}

/*
 * Переключения контекста: signal накапливает завершённые потоки, добавляем счётчики leader.
 */
static __always_inline void read_ctxsw(struct task_struct *task,
					__u64 *vol, __u64 *invol)
{
	*vol   = BPF_CORE_READ(task, signal, nvcsw);
	*invol = BPF_CORE_READ(task, signal, nivcsw);

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		*vol   += BPF_CORE_READ(leader, nvcsw);
		*invol += BPF_CORE_READ(leader, nivcsw);
	}
}

/*
 * I/O accounting: rchar/wchar/syscr/syscw (includes page cache, not just disk).
 * Same signal + leader pattern as read_io_bytes.
 */
static __always_inline void read_io_accounting(struct task_struct *task,
					       __u64 *rchar, __u64 *wchar,
					       __u64 *syscr, __u64 *syscw)
{
	*rchar = BPF_CORE_READ(task, signal, ioac.rchar);
	*wchar = BPF_CORE_READ(task, signal, ioac.wchar);
	*syscr = BPF_CORE_READ(task, signal, ioac.syscr);
	*syscw = BPF_CORE_READ(task, signal, ioac.syscw);

	struct task_struct *leader = BPF_CORE_READ(task, group_leader);
	if (leader) {
		*rchar += BPF_CORE_READ(leader, ioac.rchar);
		*wchar += BPF_CORE_READ(leader, ioac.wchar);
		*syscr += BPF_CORE_READ(leader, ioac.syscr);
		*syscw += BPF_CORE_READ(leader, ioac.syscw);
	}
}

/*
 * Read identity fields: loginuid, sessionid, euid.
 */
static __always_inline void read_identity(struct task_struct *task,
					  __u32 *loginuid, __u32 *sessionid,
					  __u32 *euid)
{
	*loginuid  = BPF_CORE_READ(task, loginuid.val);
	*sessionid = BPF_CORE_READ(task, sessionid);
	*euid      = BPF_CORE_READ(task, cred, euid.val);
}

/*
 * Read controlling terminal device number.
 * Encodes as (major << 8 | (minor_start + index)), matching /proc/PID/stat tty_nr.
 * Returns 0 if no controlling tty.
 */
static __always_inline __u32 read_tty_nr(struct task_struct *task)
{
	struct signal_struct *sig = BPF_CORE_READ(task, signal);
	if (!sig)
		return 0;
	struct tty_struct *tty = BPF_CORE_READ(sig, tty);
	if (!tty)
		return 0;
	struct tty_driver *driver = BPF_CORE_READ(tty, driver);
	if (!driver)
		return 0;
	int major = BPF_CORE_READ(driver, major);
	int minor_start = BPF_CORE_READ(driver, minor_start);
	int index = BPF_CORE_READ(tty, index);
	return (__u32)((major << 8) | (minor_start + index));
}

/*
 * Read namespace inode numbers. nsproxy can be NULL during exit.
 */
static __always_inline void read_ns_inums(struct task_struct *task,
					  __u32 *mnt_ns, __u32 *pid_ns,
					  __u32 *net_ns, __u32 *cgroup_ns)
{
	*mnt_ns = 0;
	*pid_ns = 0;
	*net_ns = 0;
	*cgroup_ns = 0;

	struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
	if (!nsp)
		return;

	struct mnt_namespace *mnt = BPF_CORE_READ(nsp, mnt_ns);
	if (mnt)
		*mnt_ns = BPF_CORE_READ(mnt, ns.inum);

	struct pid_namespace *pidns = BPF_CORE_READ(nsp, pid_ns_for_children);
	if (pidns)
		*pid_ns = BPF_CORE_READ(pidns, ns.inum);

	struct net *netns = BPF_CORE_READ(nsp, net_ns);
	if (netns)
		*net_ns = BPF_CORE_READ(netns, ns.inum);

	struct cgroup_namespace *cgns = BPF_CORE_READ(nsp, cgroup_ns);
	if (cgns)
		*cgroup_ns = BPF_CORE_READ(cgns, ns.inum);
}

/*
 * Преобразование числового состояния задачи в символ в стиле ps.
 * prev_state из sched_switch или task->__state.
 */
static __always_inline __u8 state_to_char(long state)
{
	if (state == 0)    return 'R'; /* TASK_RUNNING (вытеснен) */
	if (state & 0x01)  return 'S'; /* TASK_INTERRUPTIBLE */
	if (state & 0x02)  return 'D'; /* TASK_UNINTERRUPTIBLE */
	if (state & 0x04)  return 'T'; /* __TASK_STOPPED */
	if (state & 0x08)  return 't'; /* __TASK_TRACED */
	if (state & 0x20)  return 'Z'; /* EXIT_ZOMBIE */
	if (state & 0x10)  return 'X'; /* EXIT_DEAD */
	return '?';
}

/*
 * Чтение cmdline из mm->arg_start..arg_end текущего процесса
 * в dst[CMDLINE_MAX]. Возвращает длину прочитанного.
 */
static __always_inline __u16 read_cmdline(struct task_struct *task,
					  char *dst)
{
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
	unsigned long arg_end   = BPF_CORE_READ(mm, arg_end);
	if (arg_end <= arg_start)
		return 0;

	__u64 len = arg_end - arg_start;
	if (len >= CMDLINE_MAX)
		len = CMDLINE_MAX - 1;

	/* Маска для верификатора: CMDLINE_MAX = 256, маска = 0xFF */
	len &= (CMDLINE_MAX - 1);
	bpf_probe_read_user(dst, len, (void *)arg_start);
	return (__u16)len;
}

/* ── EXEC ─────────────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Пропускаем задачи ядра (PID 0) сразу */
	if (tgid == 0)
		return 0;

	/* Ограничение частоты событий exec во избежание переполнения кольцевого буфера */
	if (!exec_rate_check())
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* ppid */
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	__u32 ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;

	/* Отправляем событие EXEC — всегда, для сопоставления правил в пространстве пользователя */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_EXEC;
	e->tgid         = tgid;
	e->ppid         = ppid;
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	e->cgroup_id    = bpf_get_current_cgroup_id();
	e->start_ns     = BPF_CORE_READ(task, start_time);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->cmdline_len  = read_cmdline(task, e->cmdline);
	read_identity(task, &e->loginuid, &e->sessionid, &e->euid);
	e->sched_policy = BPF_CORE_READ(task, policy);
	read_ns_inums(task, &e->mnt_ns_inum, &e->pid_ns_inum,
		      &e->net_ns_inum, &e->cgroup_ns_inum);

	bpf_ringbuf_submit(e, 0);

	/* Если уже отслеживается (унаследовано через fork), обновляем cmdline/comm */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info) {
		bpf_get_current_comm(info->comm, sizeof(info->comm));
		info->cgroup_id   = bpf_get_current_cgroup_id();
		info->cmdline_len = read_cmdline(task, info->cmdline);
		read_identity(task, &info->loginuid, &info->sessionid,
			      &info->euid);
		/* tty_nr preserved from userspace */
		info->sched_policy = BPF_CORE_READ(task, policy);
		read_ns_inums(task, &info->mnt_ns_inum, &info->pid_ns_inum,
			      &info->net_ns_inum, &info->cgroup_ns_inum);
	}

	return 0;
}

/* ── FORK (raw tracepoint для доступа к task_struct потомка) ───────── */

SEC("raw_tracepoint/sched_process_fork")
int handle_fork(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx->args[0];
	struct task_struct *child  = (struct task_struct *)ctx->args[1];

	__u32 child_pid  = BPF_CORE_READ(child, pid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);

	/* Обрабатываем только fork процессов, не clone потоков */
	if (child_pid != child_tgid)
		return 0;

	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);

	/* Уведомляем пространство пользователя только если родитель отслеживается */
	struct track_info *parent_ti = bpf_map_lookup_elem(&tracked_map, &parent_tgid);
	if (!parent_ti)
		return 0;

	/* Создаём tracked_map запись для потомка прямо в BPF,
	 * чтобы handle_exec мог найти proc_info до обработки в userspace */
	struct track_info child_ti = {
		.root_pid = parent_ti->root_pid,
		.rule_id  = parent_ti->rule_id,
		.is_root  = 0,
	};
	bpf_map_update_elem(&tracked_map, &child_tgid, &child_ti, BPF_NOEXIST);

	/* Создаём proc_info для потомка через per-CPU scratch buffer
	 * (proc_info превышает 512-байтовый лимит стека BPF) */
	__u32 scratch_key = 0;
	struct proc_info *child_pi = bpf_map_lookup_elem(&scratch_pi, &scratch_key);
	if (!child_pi)
		return 0;

	__builtin_memset(child_pi, 0, sizeof(*child_pi));
	child_pi->tgid      = child_tgid;
	child_pi->ppid      = parent_tgid;
	child_pi->uid       = (__u32)bpf_get_current_uid_gid();
	child_pi->cgroup_id = bpf_get_current_cgroup_id();
	child_pi->start_ns  = BPF_CORE_READ(child, start_time);
	bpf_get_current_comm(child_pi->comm, sizeof(child_pi->comm));

	/* Inherit identity/scheduler/namespaces from parent */
	read_identity(parent, &child_pi->loginuid, &child_pi->sessionid,
		      &child_pi->euid);
	/* tty_nr will be filled by userspace fork handler */
	child_pi->sched_policy = BPF_CORE_READ(parent, policy);
	read_ns_inums(parent, &child_pi->mnt_ns_inum, &child_pi->pid_ns_inum,
		      &child_pi->net_ns_inum, &child_pi->cgroup_ns_inum);

	struct proc_info *parent_pi = bpf_map_lookup_elem(&proc_map, &parent_tgid);
	if (parent_pi) {
		__builtin_memcpy(child_pi->cmdline, parent_pi->cmdline, CMDLINE_MAX);
		child_pi->cmdline_len = parent_pi->cmdline_len;
	}
	bpf_map_update_elem(&proc_map, &child_tgid, child_pi, BPF_NOEXIST);

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_FORK;
	e->tgid         = child_tgid;
	e->ppid         = parent_tgid;
	e->uid          = child_pi->uid;
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	e->cgroup_id    = child_pi->cgroup_id;
	e->start_ns     = child_pi->start_ns;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── SCHED_SWITCH — горячий путь, обновление метрик для отслеживаемых PID ── */

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Быстрый выход для неотслеживаемых PID */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (!info)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* Память (страницы) — RSS, разделяемая, подкачка */
	struct mem_info mi = read_mem_pages(task);
	info->rss_pages   = mi.rss_pages;
	info->shmem_pages = mi.shmem_pages;
	info->swap_pages  = mi.swap_pages;
	if (mi.rss_pages > 0 &&
	    (info->rss_min_pages == 0 || mi.rss_pages < info->rss_min_pages))
		info->rss_min_pages = mi.rss_pages;
	if (mi.rss_pages > info->rss_max_pages)
		info->rss_max_pages = mi.rss_pages;

	/* Время CPU (нс) — приблизительно для многопоточных */
	info->cpu_ns = read_cpu_ns(task);

	/* Виртуальная память (страницы) */
	info->vsize_pages = read_vsize_pages(task);

	/* Количество потоков */
	info->threads = read_nr_threads(task);

	/* Корректировка OOM score */
	info->oom_score_adj = read_oom_score_adj(task);

	/* Байты IO (фактические чтения/записи на диск) */
	read_io_bytes(task, &info->io_read_bytes, &info->io_write_bytes);

	/* Страничные отказы */
	read_faults(task, &info->maj_flt, &info->min_flt);

	/* Переключения контекста */
	read_ctxsw(task, &info->nvcsw, &info->nivcsw);

	/* Cgroup — может измениться при перемещении процесса между cgroup */
	info->cgroup_id = bpf_get_current_cgroup_id();

	/* Состояние процесса — task->__state (ядро 5.14+) */
	unsigned int task_state = BPF_CORE_READ(task, __state);
	info->state = state_to_char(task_state);

	/* UID — обновляем при каждом sched_switch (может измениться через setuid) */
	info->uid = (__u32)bpf_get_current_uid_gid();

	/* Identity: loginuid, sessionid, euid */
	read_identity(task, &info->loginuid, &info->sessionid, &info->euid);
	/* tty_nr is set by userspace (BPF can't reliably read signal->tty) */

	/* Scheduling policy */
	info->sched_policy = BPF_CORE_READ(task, policy);

	/* I/O accounting (includes page cache) */
	read_io_accounting(task, &info->io_rchar, &info->io_wchar,
			   &info->io_syscr, &info->io_syscw);

	/* Namespace inode numbers */
	read_ns_inums(task, &info->mnt_ns_inum, &info->pid_ns_inum,
		      &info->net_ns_inum, &info->cgroup_ns_inum);

	return 0;
}

/* ── ВЫХОД (EXIT) ─────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid  = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Обрабатываем только выход лидера группы потоков (процесса) */
	if (pid != tgid)
		return 0;

	/* Только для отслеживаемых процессов */
	struct track_info *ti = bpf_map_lookup_elem(&tracked_map, &tgid);
	if (!ti)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* Отправляем событие EXIT с финальными метриками */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		goto cleanup;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_EXIT;
	e->tgid         = tgid;
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	/* Копируем данные отслеживания перед удалением из карт */
	e->root_pid = ti->root_pid;
	e->rule_id  = ti->rule_id;

	/* Финальный снимок метрик */
	e->cpu_ns        = read_cpu_ns(task);
	struct mem_info exit_mi = read_mem_pages(task);
	e->rss_pages     = exit_mi.rss_pages;
	e->vsize_pages   = read_vsize_pages(task);
	e->threads       = read_nr_threads(task);
	e->oom_score_adj = read_oom_score_adj(task);
	e->exit_code     = BPF_CORE_READ(task, exit_code);

	/* Переносим min/max rss, start_ns, oom_killed из proc_info */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info) {
		e->rss_min_pages = info->rss_min_pages;
		e->rss_max_pages = info->rss_max_pages;
		e->start_ns      = info->start_ns;
		e->cgroup_id     = info->cgroup_id;
		e->ppid          = info->ppid;
		e->cmdline_len   = info->cmdline_len;
		e->oom_killed    = info->oom_killed;
		e->net_tx_bytes  = info->net_tx_bytes;
		e->net_rx_bytes  = info->net_rx_bytes;
		__builtin_memcpy(e->cmdline, info->cmdline, CMDLINE_MAX);

		/* Copy new fields from last sched_switch snapshot */
		e->loginuid      = info->loginuid;
		e->sessionid     = info->sessionid;
		e->euid          = info->euid;
		e->tty_nr        = info->tty_nr;
		e->sched_policy  = info->sched_policy;
		e->io_rchar      = info->io_rchar;
		e->io_wchar      = info->io_wchar;
		e->io_syscr      = info->io_syscr;
		e->io_syscw      = info->io_syscw;
		e->mnt_ns_inum   = info->mnt_ns_inum;
		e->pid_ns_inum   = info->pid_ns_inum;
		e->net_ns_inum   = info->net_ns_inum;
		e->cgroup_ns_inum = info->cgroup_ns_inum;
	}

	bpf_ringbuf_submit(e, 0);

cleanup:
	bpf_map_delete_elem(&tracked_map, &tgid);
	bpf_map_delete_elem(&proc_map, &tgid);
	return 0;
}

/* ── УБИЙСТВО OOM — точка трассировки mark_victim ──────────────────── */

/*
 * mark_victim срабатывает, когда OOM killer выбирает процесс для завершения.
 * Аргументы raw_tracepoint: (struct task_struct *task)
 */
SEC("raw_tracepoint/mark_victim")
int handle_mark_victim(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task = (struct task_struct *)ctx->args[0];
	__u32 tgid = BPF_CORE_READ(task, tgid);

	/* Только для отслеживаемых процессов */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	/* Помечаем в proc_info */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		info->oom_killed = 1;

	/* Отправляем событие OOM_KILL в пространство пользователя */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_OOM_KILL;
	e->tgid         = tgid;
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm),
				  BPF_CORE_READ(task, comm));

	if (info) {
		e->ppid          = info->ppid;
		e->cgroup_id     = info->cgroup_id;
		e->rss_pages     = info->rss_pages;
		e->rss_min_pages = info->rss_min_pages;
		e->rss_max_pages = info->rss_max_pages;
		e->cpu_ns        = info->cpu_ns;
		e->start_ns      = info->start_ns;
		e->cmdline_len   = info->cmdline_len;
		__builtin_memcpy(e->cmdline, info->cmdline, CMDLINE_MAX);
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── Отслеживание файлов: openat/close/read/write ─────────────────── */

/*
 * Конфигурация и списки префиксов — заполняются пространством пользователя перед подключением.
 * file_cfg: одноэлементный массив с флагами enabled/track_bytes.
 * file_include_prefixes / file_exclude_prefixes: до FILE_MAX_PREFIXES
 * префиксов путей для фильтрации в BPF.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct file_config);
} file_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FILE_MAX_PREFIXES);
	__type(key, __u32);
	__type(value, struct file_prefix);
} file_include_prefixes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FILE_MAX_PREFIXES);
	__type(key, __u32);
	__type(value, struct file_prefix);
} file_exclude_prefixes SEC(".maps");

/* Временное хранилище аргументов между входом и выходом из системного вызова */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);    /* pid_tgid */
	__type(value, struct openat_args);
} openat_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);    /* pid_tgid */
	__type(value, struct rw_args);
} rw_args_map SEC(".maps");

/* Отслеживание по файловым дескрипторам: накопление байт чтения/записи до закрытия */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct fd_key);
	__type(value, struct fd_info);
} fd_map SEC(".maps");

/*
 * Проверяет, совпадает ли путь с одним из префиксов в списке включения.
 * Если include-префиксы не заданы (все len=0), разрешает всё.
 * Возвращает 1, если путь должен быть включён.
 */
/*
 * Сравнивает до 'len' байт двух строк.
 * Возвращает 1, если первые 'len' байт совпадают.
 * Фиксированное число итераций для совместимости с BPF-верификатором.
 */
#define PREFIX_CMP_MAX 32   /* макс. сравниваемых байт (покрывает реальные префиксы путей) */

/*
 * ВНИМАНИЕ: НЕ МЕНЯТЬ СТРУКТУРУ prefix_match!
 *
 * Верификатор BPF в ядрах 5.15 и старше имеет два жёстких ограничения:
 *
 * 1) Лимит 8192 jump-последовательностей на одном пути выполнения.
 *    Ранние return (break/return внутри цикла) создают ветвления,
 *    которые при развёртке 16 префиксов × 32 символа дают >8192 путей.
 *
 * 2) Отслеживание указателей через циклы.
 *    Верификатор 5.15 не может доказать, что указатель на map value
 *    или стек остаётся в границах при инкременте в bounded loop.
 *    Это вызывает "invalid access to map value, off=N size=1".
 *
 * Решение — комбинация двух приёмов:
 *   - #pragma unroll: clang полностью разворачивает цикл, все смещения
 *     становятся compile-time константами, верификатор не трекает указатели.
 *   - Без early return: вместо return 0/1 используем флаг match.
 *     Нет ветвлений = нет взрыва jump-путей.
 *
 * Результат: верификатор видит линейный код с фиксированными offset-ами,
 * работает на ядрах от 5.15 до 6.x без изменений.
 */
static __always_inline int prefix_match(const char *path,
					const char *prefix, int len)
{
	if (len <= 0 || len > PREFIX_CMP_MAX)
		len = PREFIX_CMP_MAX;

	int match = 1;
	#pragma unroll
	for (int j = 0; j < PREFIX_CMP_MAX; j++) {
		if (j < len && path[j] != prefix[j])
			match = 0;
	}
	return match;
}

/* Проверяет, совпадает ли путь с одним из include-префиксов.
 * Если ни одного префикса не задано, пропускает всё. */
static __always_inline int path_matches_include(const char *path)
{
	int has_any = 0;

	#pragma unroll
	for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
		__u32 idx = i;
		struct file_prefix *fp = bpf_map_lookup_elem(
			&file_include_prefixes, &idx);
		if (!fp || fp->len == 0)
			continue;
		has_any = 1;

		if (prefix_match(path, fp->prefix, fp->len))
			return 1;
	}

	return !has_any;
}

/* Проверяет, совпадает ли путь с одним из exclude-префиксов.
 * Возвращает 1 если путь нужно исключить. */
static __always_inline int path_matches_exclude(const char *path)
{
	#pragma unroll
	for (int i = 0; i < FILE_MAX_PREFIXES; i++) {
		__u32 idx = i;
		struct file_prefix *fp = bpf_map_lookup_elem(
			&file_exclude_prefixes, &idx);
		if (!fp || fp->len == 0)
			continue;

		if (prefix_match(path, fp->prefix, fp->len))
			return 1;
	}
	return 0;
}

/*
 * sys_enter_openat: сохраняем путь и флаги для обработчика выхода.
 * Только для отслеживаемых процессов. Фильтрация по пути происходит здесь.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Только отслеживаемые процессы */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	/* Читаем путь из пространства пользователя */
	struct openat_args oa = {0};
	const char *pathname = (const char *)ctx->args[1];
	bpf_probe_read_user_str(oa.path, sizeof(oa.path), pathname);
	oa.flags = (int)ctx->args[2];

	/* Фильтрация по префиксу пути */
	if (!path_matches_include(oa.path))
		return 0;
	if (path_matches_exclude(oa.path))
		return 0;

	bpf_map_update_elem(&openat_args_map, &pid_tgid, &oa, BPF_ANY);
	return 0;
}

/*
 * sys_exit_openat: если open успешен, создаём запись fd_info.
 */
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct openat_args *oa = bpf_map_lookup_elem(
		&openat_args_map, &pid_tgid);
	if (!oa)
		return 0;

	long ret = ctx->ret;
	if (ret < 0) {
		bpf_map_delete_elem(&openat_args_map, &pid_tgid);
		return 0;
	}

	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct fd_key fk = { .tgid = tgid, .fd = (__s32)ret };

	struct fd_info fi = {0};
	__builtin_memcpy(fi.path, oa->path, FILE_PATH_MAX);
	fi.flags = oa->flags;
	fi.open_count = 1;

	bpf_map_update_elem(&fd_map, &fk, &fi, BPF_ANY);
	bpf_map_delete_elem(&openat_args_map, &pid_tgid);
	return 0;
}

/*
 * sys_enter_close: отправляем событие file_close с накопленной статистикой.
 */
SEC("tracepoint/syscalls/sys_enter_close")
int handle_close_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	int fd = (int)ctx->args[0];

	struct fd_key fk = { .tgid = tgid, .fd = fd };
	struct fd_info *fi = bpf_map_lookup_elem(&fd_map, &fk);
	if (!fi)
		return 0;

	/* Отправляем событие закрытия файла через кольцевой буфер */
	struct file_event *fe = bpf_ringbuf_reserve(&events, sizeof(*fe), 0);
	if (fe) {
		__builtin_memset(fe, 0, sizeof(*fe));
		fe->type = EVENT_FILE_CLOSE;
		fe->tgid = tgid;
		fe->timestamp_ns = bpf_ktime_get_boot_ns();
		fe->cgroup_id = bpf_get_current_cgroup_id();
		bpf_get_current_comm(fe->comm, sizeof(fe->comm));
		__builtin_memcpy(fe->path, fi->path, FILE_PATH_MAX);
		fe->flags = fi->flags;
		fe->read_bytes = fi->read_bytes;
		fe->write_bytes = fi->write_bytes;
		fe->open_count = fi->open_count;

		/* Получаем ppid */
		struct task_struct *task =
			(struct task_struct *)bpf_get_current_task();
		struct task_struct *parent = BPF_CORE_READ(task, real_parent);
		fe->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
		fe->uid  = (__u32)bpf_get_current_uid_gid();

		bpf_ringbuf_submit(fe, 0);
	}

	bpf_map_delete_elem(&fd_map, &fk);
	return 0;
}

/*
 * sys_enter_read: сохраняем fd для обработчика выхода.
 */
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 key0 = 0;
	struct file_config *fc = bpf_map_lookup_elem(&file_cfg, &key0);
	if (!fc || !fc->track_bytes)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Быстрая проверка: отслеживается ли этот fd? */
	int fd = (int)ctx->args[0];
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	if (!bpf_map_lookup_elem(&fd_map, &fk))
		return 0;

	struct rw_args ra = { .fd = fd };
	bpf_map_update_elem(&rw_args_map, &pid_tgid, &ra, BPF_ANY);
	return 0;
}

/*
 * sys_exit_read: накапливаем прочитанные байты.
 */
SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct rw_args *ra = bpf_map_lookup_elem(&rw_args_map, &pid_tgid);
	if (!ra)
		return 0;

	long ret = ctx->ret;
	int fd = ra->fd;
	bpf_map_delete_elem(&rw_args_map, &pid_tgid);

	if (ret <= 0)
		return 0;

	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	struct fd_info *fi = bpf_map_lookup_elem(&fd_map, &fk);
	if (fi)
		__sync_fetch_and_add(&fi->read_bytes, (__u64)ret);

	return 0;
}

/*
 * sys_enter_write: сохраняем fd для обработчика выхода.
 */
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u32 key0 = 0;
	struct file_config *fc = bpf_map_lookup_elem(&file_cfg, &key0);
	if (!fc || !fc->track_bytes)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	int fd = (int)ctx->args[0];
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	if (!bpf_map_lookup_elem(&fd_map, &fk))
		return 0;

	struct rw_args ra = { .fd = fd };
	bpf_map_update_elem(&rw_args_map, &pid_tgid, &ra, BPF_ANY);
	return 0;
}

/*
 * sys_exit_write: накапливаем записанные байты.
 */
SEC("tracepoint/syscalls/sys_exit_write")
int handle_write_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	struct rw_args *ra = bpf_map_lookup_elem(&rw_args_map, &pid_tgid);
	if (!ra)
		return 0;

	long ret = ctx->ret;
	int fd = ra->fd;
	bpf_map_delete_elem(&rw_args_map, &pid_tgid);

	if (ret <= 0)
		return 0;

	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct fd_key fk = { .tgid = tgid, .fd = fd };
	struct fd_info *fi = bpf_map_lookup_elem(&fd_map, &fk);
	if (fi)
		__sync_fetch_and_add(&fi->write_bytes, (__u64)ret);

	return 0;
}

/* ── Сеть: TCP/UDP отправка/приём (kretprobe для фактического количества байт) ── */

/* ── Отслеживание сети: жизненный цикл TCP-соединений + подсчёт байт ── */

/*
 * net_cfg: одноэлементный массив с флагами enabled/track_bytes.
 * sock_map: состояние сокета по ключу — указателю на sock.
 * connect_args_map: временное хранилище между kprobe/kretprobe tcp_v4_connect.
 * sendmsg_args_map: временное хранилище между kprobe/kretprobe tcp_sendmsg.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct net_config);
} net_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NET_MAX_SOCKETS);
	__type(key, __u64);           /* указатель на sock как u64 */
	__type(value, struct sock_info);
} sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);           /* pid_tgid */
	__type(value, struct connect_args);
} connect_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);           /* pid_tgid */
	__type(value, struct sendmsg_args);
} sendmsg_args_map SEC(".maps");

/*
 * Чтение адресов сокета в sock_info.
 * Поддерживает AF_INET и AF_INET6.
 */
static __always_inline void read_sock_addrs(struct sock *sk,
					    struct sock_info *si)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	si->af = (__u8)family;
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	si->remote_port = __bpf_ntohs(dport);
	si->local_port  = BPF_CORE_READ(sk, __sk_common.skc_num);

	if (family == 2) { /* AF_INET */
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(si->remote_addr, &daddr, 4);
		__builtin_memcpy(si->local_addr, &saddr, 4);
	} else if (family == 10) { /* AF_INET6 */
		BPF_CORE_READ_INTO(si->remote_addr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(si->local_addr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
}

/*
 * Отправка события NET_CLOSE из sock_info.
 */
static __always_inline void emit_net_close(struct sock_info *si,
					   __u64 now_ns)
{
	struct net_event *ne = bpf_ringbuf_reserve(&events, sizeof(*ne), 0);
	if (!ne)
		return;

	__builtin_memset(ne, 0, sizeof(*ne));
	ne->type         = EVENT_NET_CLOSE;
	ne->tgid         = si->tgid;
	ne->uid          = si->uid;
	ne->timestamp_ns = now_ns;
	ne->cgroup_id    = bpf_get_current_cgroup_id();
	bpf_get_current_comm(ne->comm, sizeof(ne->comm));

	/* Получаем ppid */
	struct task_struct *task =
		(struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	ne->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;

	ne->af = si->af;
	__builtin_memcpy(ne->local_addr, si->local_addr, 16);
	__builtin_memcpy(ne->remote_addr, si->remote_addr, 16);
	ne->local_port  = si->local_port;
	ne->remote_port = si->remote_port;
	ne->tx_bytes    = si->tx_bytes;
	ne->rx_bytes    = si->rx_bytes;
	ne->duration_ns = (now_ns > si->start_ns) ? now_ns - si->start_ns : 0;

	bpf_ringbuf_submit(ne, 0);
}

/* ── tcp_v4_connect: отслеживание исходящих IPv4-соединений ──────── */

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp_v4_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&connect_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(krp_tcp_v4_connect, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args *args = bpf_map_lookup_elem(&connect_args_map,
							&pid_tgid);
	if (!args) return 0;

	__u64 sk_ptr = args->sock_ptr;
	bpf_map_delete_elem(&connect_args_map, &pid_tgid);

	if (ret != 0)
		return 0;

	struct sock *sk = (struct sock *)sk_ptr;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	struct sock_info si = {};
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);
	return 0;
}

/* ── tcp_v6_connect: отслеживание исходящих IPv6-соединений ──────── */

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kp_tcp_v6_connect, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&connect_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(krp_tcp_v6_connect, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connect_args *args = bpf_map_lookup_elem(&connect_args_map,
							&pid_tgid);
	if (!args) return 0;

	__u64 sk_ptr = args->sock_ptr;
	bpf_map_delete_elem(&connect_args_map, &pid_tgid);

	if (ret != 0)
		return 0;

	struct sock *sk = (struct sock *)sk_ptr;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	struct sock_info si = {};
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);
	return 0;
}

/* ── inet_csk_accept: отслеживание входящих TCP-соединений ────────── */

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(krp_inet_csk_accept, struct sock *sk)
{
	if (!sk)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	__u64 sk_ptr = (__u64)sk;

	struct sock_info si = {};
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);
	return 0;
}

/* ── tcp_close: отправка события NET_CLOSE ────────────────────────── */

SEC("kprobe/tcp_close")
int BPF_KPROBE(kp_tcp_close, struct sock *sk)
{
	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	emit_net_close(si, bpf_ktime_get_boot_ns());
	bpf_map_delete_elem(&sock_map, &sk_ptr);
	return 0;
}

/* ── tcp_sendmsg / tcp_recvmsg: байты на соединение + на процесс ─── */

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kp_tcp_sendmsg, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&sendmsg_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(ret_tcp_sendmsg, int ret)
{
	if (ret <= 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args *args = bpf_map_lookup_elem(&sendmsg_args_map,
							&pid_tgid);
	__u64 sk_ptr = args ? args->sock_ptr : 0;
	bpf_map_delete_elem(&sendmsg_args_map, &pid_tgid);

	/* Агрегат на процесс (всегда, если отслеживается) */
	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_tx_bytes, (__u64)ret);

	/* На соединение (если сокет есть в sock_map) */
	if (sk_ptr) {
		struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
		if (si)
			__sync_fetch_and_add(&si->tx_bytes, (__u64)ret);
	}
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kp_tcp_recvmsg, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&sendmsg_args_map, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(ret_tcp_recvmsg, int ret)
{
	if (ret <= 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args *args = bpf_map_lookup_elem(&sendmsg_args_map,
							&pid_tgid);
	__u64 sk_ptr = args ? args->sock_ptr : 0;
	bpf_map_delete_elem(&sendmsg_args_map, &pid_tgid);

	/* Агрегат на процесс (всегда, если отслеживается) */
	__u32 tgid = (__u32)(pid_tgid >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_rx_bytes, (__u64)ret);

	/* На соединение (если сокет есть в sock_map) */
	if (sk_ptr) {
		struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
		if (si)
			__sync_fetch_and_add(&si->rx_bytes, (__u64)ret);
	}
	return 0;
}

/* ── UDP: агрегат байт на процесс (без жизненного цикла соединений) ── */

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg, int ret)
{
	if (ret <= 0)
		return 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_tx_bytes, (__u64)ret);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(ret_udp_recvmsg, int ret)
{
	if (ret <= 0)
		return 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info)
		__sync_fetch_and_add(&info->net_rx_bytes, (__u64)ret);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
