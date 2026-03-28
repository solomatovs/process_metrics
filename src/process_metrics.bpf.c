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
 *   events_proc — кольцевой буфер событий жизненного цикла процессов
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

/*
 * BPF_ZERO(var) — обнуляет ВСЕ байты структуры на стеке, включая padding.
 *
 * Необходимо ВСЕГДА обнулять структуры перед bpf_map_update_elem /
 * bpf_ringbuf_submit, иначе поля, не заданные явно (например tx_bytes,
 * rx_bytes в sock_info), будут содержать мусор со стека BPF.
 */
#define BPF_ZERO(var) __builtin_memset(&(var), 0, sizeof(var))

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

/* Ring buffer для событий процессов: fork/exec/exit/oom_kill (struct event) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_PROC_SIZE);
} events_proc SEC(".maps");

/* Ring buffer для файловых событий (struct file_event) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_FILE_SIZE);
} events_file SEC(".maps");

/* Ring buffer для сетевых и signal событий (net_event, signal_event) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_NET_SIZE);
} events_net SEC(".maps");

/* Ring buffer для security событий (retransmit, syn, rst) — отдельный от net,
 * чтобы security flood не вытеснял net_close/signal события */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_SEC_SIZE);
} events_sec SEC(".maps");

/* Ring buffer для cgroup событий (struct cgroup_event) */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_CGROUP_SIZE);
} events_cgroup SEC(".maps");

/*
 * thread_cpu_map: предыдущее значение utime+stime каждого потока
 * для дельта-трекинга CPU в sched_switch (O(1) вместо обхода thread list).
 * Ключ = pid (thread ID), значение = последнее utime+stime.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);           /* pid (thread id) */
	__type(value, __u64);         /* last seen utime+stime */
} thread_cpu_map SEC(".maps");

/*
 * tid_tgid_map: TID → {TGID, comm} mapping для резолвинга имён потоков
 * в имена основных процессов при preemption tracking.
 *
 * Заполняется в sched_switch для ВСЕХ процессов (до проверки tracked_map),
 * позволяя определить реального владельца потока-вытеснителя.
 * Например: ThreadPool(TID) → clickhouse-serv(TGID).
 *
 * Совместимо с ядром 5.x (не требует bpf_task_from_pid).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);           /* tid (thread id) */
	__type(value, struct tid_info);
} tid_tgid_map SEC(".maps");

/* Статистика ring buffer'ов: потери и общее количество событий */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ringbuf_stats);
} ringbuf_stats SEC(".maps");

/* Инкремент счётчика в ringbuf_stats.
 * field — смещение поля в структуре (offsetof). */
static __always_inline void rb_stat_inc(__u64 offset)
{
	__u32 key = 0;
	struct ringbuf_stats *s = bpf_map_lookup_elem(&ringbuf_stats, &key);
	if (s)
		__sync_fetch_and_add((__u64 *)((char *)s + offset), 1);
}

#define RB_STAT_TOTAL_PROC()  rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, total_proc))
#define RB_STAT_TOTAL_FILE()  rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, total_file))
#define RB_STAT_TOTAL_NET()   rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, total_net))
#define RB_STAT_DROP_PROC()   rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, drop_proc))
#define RB_STAT_DROP_FILE()   rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, drop_file))
#define RB_STAT_DROP_NET()    rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, drop_net))
#define RB_STAT_TOTAL_SEC()   rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, total_sec))
#define RB_STAT_DROP_SEC()    rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, drop_sec))
#define RB_STAT_TOTAL_CGROUP() rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, total_cgroup))
#define RB_STAT_DROP_CGROUP()  rb_stat_inc(__builtin_offsetof(struct ringbuf_stats, drop_cgroup))

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rate_state);
} exec_rate SEC(".maps");

/*
 * Per-CPU буфер для построения proc_info на стеке
 * (proc_info превышает 512-байтовый лимит стека BPF).
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proc_info);
} scratch_pi SEC(".maps");

/*
 * missed_exec_map: fallback при ring buffer drop в handle_exec.
 * Когда ringbuf_reserve не удаётся для нового (не fork-наследованного)
 * процесса, BPF сохраняет tgid → ppid в эту карту. Userspace периодически
 * дрейнит её и вызывает try_track_pid() для восстановления.
 * Без этого процесс полностью теряется — ни snapshot, ни exit не увидят его.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);           /* tgid */
	__type(value, __u32);         /* ppid */
} missed_exec_map SEC(".maps");

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

	/* Поиск состояния rate limiter в BPF-карте по ключу.
	 * Состояние (rate_state) хранит:
	 *   window_ns — начало текущего секундного окна,
	 *   count     — количество exec-событий в этом окне.
	 * Возвращает указатель на значение или NULL если ключ не найден. */
	rs = bpf_map_lookup_elem(&exec_rate, &key);
	if (!rs)
		return 1;

	/* Монотонное время ядра в наносекундах (с момента загрузки).
	 * Не зависит от смены системного времени (NTP, settimeofday). */
	__u64 now = bpf_ktime_get_ns();

	/* Прошла ли 1 секунда (10⁹ нс) с начала текущего окна?
	 * Если да — начинаем новое окно: сбрасываем счётчик,
	 * текущее событие считается первым, пропускаем его. */
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

/*
 * CO-RE совместимость task_struct.state (ядро < 5.14) vs __state (ядро >= 5.14).
 * В ванильном ядре 5.14 поле было переименовано state → __state.
 * CentOS/RHEL 9 (ядро 5.14) уже содержит __state (backport).
 */
struct task_struct___old {
	long unsigned int state;
};

/*
 * Структура mm_rss_stat — для CO-RE совместимости с ядрами 6.x,
 * где mm_struct.rss_stat это struct mm_rss_stat { atomic_long_t count[4]; }.
 * В ядрах 5.x (CentOS 9, RHEL 9) rss_stat — массив percpu_counter[4]
 * без вложенной структуры mm_rss_stat.
 */
struct mm_rss_stat___new {
	atomic_long_t count[4];
};

struct mm_struct___new {
	struct mm_rss_stat___new rss_stat;
};

struct mm_struct___old {
	struct percpu_counter rss_stat[4];
};

static __always_inline struct mem_info read_mem_pages(struct task_struct *task)
{
	struct mem_info mi = {0};
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return mi;

	/* MM_FILEPAGES=0, MM_ANONPAGES=1, MM_SWAPENTS=2, MM_SHMEMPAGES=3 */
	long v0 = 0, v1 = 0, v2 = 0, v3 = 0;

	if (bpf_core_field_exists(((struct mm_struct___new *)0)->rss_stat.count)) {
		/*
		 * Ядро 6.x: mm->rss_stat это struct mm_rss_stat { atomic_long_t count[4]; }
		 */
		struct mm_struct___new *mm_new = (void *)mm;
		bpf_core_read(&v0, sizeof(v0), &mm_new->rss_stat.count[0].counter);
		bpf_core_read(&v1, sizeof(v1), &mm_new->rss_stat.count[1].counter);
		bpf_core_read(&v2, sizeof(v2), &mm_new->rss_stat.count[2].counter);
		bpf_core_read(&v3, sizeof(v3), &mm_new->rss_stat.count[3].counter);
	} else {
		/*
		 * Ядро 5.x: mm->rss_stat это percpu_counter[4],
		 * читаем приблизительное значение из percpu_counter.count (s64).
		 */
		struct mm_struct___old *mm_old = (void *)mm;
		bpf_core_read(&v0, sizeof(v0), &mm_old->rss_stat[0].count);
		bpf_core_read(&v1, sizeof(v1), &mm_old->rss_stat[1].count);
		bpf_core_read(&v2, sizeof(v2), &mm_old->rss_stat[2].count);
		bpf_core_read(&v3, sizeof(v3), &mm_old->rss_stat[3].count);
	}

	long total = v0 + v1 + v3;
	mi.rss_pages   = total > 0 ? (__u64)total : 0;
	mi.shmem_pages = v3 > 0 ? (__u64)v3 : 0;
	mi.swap_pages  = v2 > 0 ? (__u64)v2 : 0;
	return mi;
}

/* read_cpu_ns удалён — CPU считается через дельта-трекинг
 * в sched_switch (thread_cpu_map), см. handle_sched_switch. */

/*
 * Виртуальная память процесса в страницах.
 * Читает mm->total_vm — общий размер адресного пространства.
 * Для ядерных потоков (mm == NULL) возвращает 0.
 */
static __always_inline __u64 read_vsize_pages(struct task_struct *task)
{
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	return mm ? (__u64)BPF_CORE_READ(mm, total_vm) : 0;
}

/*
 * Количество потоков в группе (процессе).
 * signal->nr_threads учитывает все живые потоки,
 * включая group_leader.
 */
static __always_inline __u32 read_nr_threads(struct task_struct *task)
{
	return (__u32)BPF_CORE_READ(task, signal, nr_threads);
}

/*
 * Корректировка OOM-score процесса (-1000..1000).
 * Влияет на приоритет уничтожения при нехватке памяти:
 * чем выше значение, тем вероятнее процесс будет убит OOM killer.
 */
static __always_inline __s16 read_oom_score_adj(struct task_struct *task)
{
	return (__s16)BPF_CORE_READ(task, signal, oom_score_adj);
}

/*
 * Учёт ввода-вывода: фактические байты чтения/записи на диск.
 * task->ioac накапливается по всем потокам через signal->ioac при завершении,
 * но для живых потоков читаем из group_leader + signal.
 */
static __always_inline void read_io_bytes(struct task_struct *task, __u64 *r, __u64 *w)
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
 * Страничные отказы (page faults) — события, когда процесс обращается
 * к странице памяти, которой нет в физической RAM.
 *
 * minor fault — страница найдена в page cache (например, уже загружена
 *               другим процессом), копирование без обращения к диску.
 * major fault — страница отсутствует, требуется чтение с диска (swap,
 *               mmap-файл и т.д.), поэтому значительно медленнее.
 *
 * signal->cmaj_flt/cmin_flt — суммарные faults завершившихся потоков
 *                              и дочерних процессов.
 * leader->maj_flt/min_flt   — faults живого главного потока.
 *
 * Faults остальных живых потоков не учтены (ограничение BPF).
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
 * Переключения контекста (context switches) — события смены процесса на CPU.
 *
 * voluntary (nvcsw)   — поток сам отдал CPU: ждёт I/O, sleep, мьютекс.
 *                       Нормальное поведение для I/O-bound задач.
 * involuntary (nivcsw) — ядро принудительно сняло поток с CPU: истёк квант
 *                        времени или появился более приоритетный поток.
 *                        Много involuntary = нехватка CPU.
 *
 * signal накапливает завершённые потоки, добавляем счётчики leader.
 * Живые рабочие потоки (кроме leader) не учтены (ограничение BPF).
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
 * Учёт ввода-вывода на уровне системных вызовов.
 *
 * rchar — байты, прочитанные через read/pread (включая page cache, не только диск).
 * wchar — байты, записанные через write/pwrite (включая page cache).
 * syscr — количество системных вызовов чтения (read, pread и т.д.).
 * syscw — количество системных вызовов записи (write, pwrite и т.д.).
 *
 * signal накапливает завершённые потоки, добавляем счётчики leader.
 * Живые рабочие потоки (кроме leader) не учтены (ограничение BPF).
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
 * Идентификация процесса:
 * loginuid   — UID пользователя, выполнившего вход (устанавливается PAM при логине,
 *              не меняется при su/sudo). -1 (AUDIT_UID_UNSET) если не установлен.
 * sessionid  — идентификатор сессии аудита (audit session).
 * euid       — effective UID, определяющий права доступа процесса.
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
 * Номер управляющего терминала процесса (tty).
 * Кодируется как (major << 8 | (minor_start + index)),
 * совпадает с tty_nr из /proc/PID/stat.
 * Возвращает 0, если у процесса нет управляющего терминала
 * (демоны, сервисы, контейнерные процессы).
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
 * Номера inode пространств имён (namespaces) процесса.
 * Позволяют определить, в каком контейнере/изоляции работает процесс.
 *
 * mnt_ns    — пространство монтирования (изоляция файловой системы).
 * pid_ns    — пространство PID (процесс видит свои PID'ы).
 * net_ns    — сетевое пространство (изоляция сетевых интерфейсов).
 * cgroup_ns — пространство cgroup (изоляция групп ресурсов).
 *
 * nsproxy может быть NULL во время завершения процесса.
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
static __always_inline __u16 read_cmdline(struct task_struct *task, char *dst)
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

/*
 * Tracepoint sched_process_exec — срабатывает при вызове execve/execveat,
 * когда процесс заменяет свой образ новой программой.
 * В этот момент PID уже существует (создан через fork), но загружается
 * новый бинарник — обновляются comm, cmdline, mm и другие метаданные.
 * Используем для перечитывания информации о процессе после exec.
 */
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

	/* Если уже отслеживается (унаследовано через fork), обновляем
	 * cmdline/comm в proc_map и НЕ отправляем event — userspace
	 * всё равно вернул бы return 0 (already tracked).
	 * Это экономит место в ring buffer при интенсивном fork+exec. */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info) {
		bpf_get_current_comm(info->comm, sizeof(info->comm));
		info->cgroup_id   = bpf_get_current_cgroup_id();
		info->cmdline_len = read_cmdline(task, info->cmdline);
		read_identity(
			task,
			&info->loginuid,
			&info->sessionid,
			&info->euid
		);
		info->sched_policy = BPF_CORE_READ(task, policy);
		read_ns_inums(
			task,
			&info->mnt_ns_inum,
			&info->pid_ns_inum,
			&info->net_ns_inum,
			&info->cgroup_ns_inum
		);
		return 0;
	}

	/* ppid */
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	__u32 ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;

	/* Новый процесс — отправляем event для сопоставления правил в userspace */
	RB_STAT_TOTAL_PROC();
	struct event *e = bpf_ringbuf_reserve(&events_proc, sizeof(*e), 0);
	if (!e) {
		RB_STAT_DROP_PROC();
		/* Сохраняем tgid→ppid в fallback-карту, чтобы userspace мог
		 * обнаружить и отследить процесс через try_track_pid().
		 * Без этого процесс полностью теряется. */
		if (bpf_map_update_elem(&missed_exec_map, &tgid, &ppid,
					BPF_NOEXIST) != 0)
			rb_stat_inc(__builtin_offsetof(
				struct ringbuf_stats, drop_missed_exec));
		return 0;
	}

	/* Обнуляем структуру события (требование BPF-верификатора) */
	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_EXEC;
	e->tgid         = tgid;
	e->ppid         = ppid;
	/* UID текущего процесса (младшие 32 бита uid_gid) */
	e->uid          = (__u32)bpf_get_current_uid_gid();
	/* Время с момента загрузки системы, включая suspend (нс) */
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	/* ID cgroup v2, в которой работает процесс */
	e->cgroup_id    = bpf_get_current_cgroup_id();
	/* Время старта процесса из task_struct (CO-RE) */
	e->start_ns     = BPF_CORE_READ(task, start_time);
	/* Имя процесса (comm, до 16 байт) */
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	/* Полная командная строка из mm->arg_start..arg_end (читается из RAM
	 * процесса через bpf_probe_read_user, без обращения к диску/VFS) */
	e->cmdline_len  = read_cmdline(task, e->cmdline);
	/* loginuid, sessionid (audit) и effective UID */
	read_identity(task, &e->loginuid, &e->sessionid, &e->euid);
	/* Политика планировщика (SCHED_NORMAL, SCHED_FIFO и т.д.) */
	e->sched_policy = BPF_CORE_READ(task, policy);
	/* Номера inode namespace'ов: mnt, pid, net, cgroup */
	read_ns_inums(
		task,
		&e->mnt_ns_inum,
		&e->pid_ns_inum,
		&e->net_ns_inum,
		&e->cgroup_ns_inum
	);

	bpf_ringbuf_submit(e, 0);
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
	 * чтобы handle_exec мог найти proc_info до обработки в userspace.
	 * Без этого возникает гонка: exec потомка может сработать раньше,
	 * чем userspace прочитает fork-событие из ring buffer и добавит
	 * запись в tracked_map — тогда exec будет пропущен. */
	struct track_info child_ti;
	BPF_ZERO(child_ti);
	child_ti.root_pid = parent_ti->root_pid;
	child_ti.rule_id  = parent_ti->rule_id;
	child_ti.is_root  = 0;
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

	/* Наследуем identity/планировщик/пространства имён от родителя */
	read_identity(parent, &child_pi->loginuid, &child_pi->sessionid,
		      &child_pi->euid);
	child_pi->tty_nr = read_tty_nr(child);
	child_pi->sched_policy = BPF_CORE_READ(parent, policy);
	read_ns_inums(parent, &child_pi->mnt_ns_inum, &child_pi->pid_ns_inum,
		      &child_pi->net_ns_inum, &child_pi->cgroup_ns_inum);

	struct proc_info *parent_pi = bpf_map_lookup_elem(&proc_map, &parent_tgid);
	if (parent_pi) {
		__builtin_memcpy(child_pi->cmdline, parent_pi->cmdline, CMDLINE_MAX);
		child_pi->cmdline_len = parent_pi->cmdline_len;
	}
	bpf_map_update_elem(&proc_map, &child_tgid, child_pi, BPF_NOEXIST);

	RB_STAT_TOTAL_PROC();
	struct event *e = bpf_ringbuf_reserve(&events_proc, sizeof(*e), 0);
	if (!e) {
		RB_STAT_DROP_PROC();
		return 0;
	}

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

/*
 * Раскладка контекста tracepoint sched_switch (из /sys/kernel/tracing/events/sched/sched_switch/format):
 *   смещение  0: common_type (u16), common_flags (u8), common_preempt_count (u8), common_pid (s32)
 *   смещение  8: prev_comm[16]
 *   смещение 24: prev_pid (s32)
 *   смещение 28: prev_prio (s32)
 *   смещение 32: prev_state (s64)
 *   смещение 40: next_comm[16]
 *   смещение 56: next_pid (s32)
 *   смещение 60: next_prio (s32)
 */
struct sched_switch_args {
	/* первые 8 байт: общие поля (type, flags, preempt_count, pid) */
	__u64 __pad;
	char  prev_comm[16];
	__s32 prev_pid;
	__s32 prev_prio;
	long  prev_state;
	char  next_comm[16];
	__s32 next_pid;
	__s32 next_prio;
};

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid  = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/*
	 * Обновляем tid_tgid_map для текущего (prev) процесса ДО проверки
	 * tracked_map: нужно знать TGID+comm всех процессов в системе,
	 * чтобы резолвить имена потоков-вытеснителей.
	 *
	 * Обновляем только если TID != TGID (т.е. это дочерний поток),
	 * потому что для главного потока comm совпадает с preempted_by_comm.
	 */
	if (tid != tgid) {
		struct tid_info *existing = bpf_map_lookup_elem(&tid_tgid_map,
								&tid);
		if (!existing) {
			struct task_struct *leader;
			struct task_struct *curr =
				(struct task_struct *)bpf_get_current_task();
			struct tid_info ti = { .tgid = tgid };

			leader = BPF_CORE_READ(curr, group_leader);
			if (leader)
				bpf_probe_read_kernel_str(ti.comm,
							  sizeof(ti.comm),
							  &leader->comm);
			else
				bpf_probe_read_kernel(ti.comm,
						      COMM_LEN,
						      ctx->prev_comm);
			ti.comm[COMM_LEN - 1] = '\0';
			bpf_map_update_elem(&tid_tgid_map, &tid,
					    &ti, BPF_NOEXIST);
		}
	}

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

	/*
	 * CPU (нс) — дельта-трекинг по task->utime + task->stime.
	 *
	 * Читаем ТОЛЬКО per-thread utime/stime (не signal->utime),
	 * чтобы избежать двойного подсчёта при смерти потоков.
	 * O(1) на sched_switch, без лимита на число потоков.
	 *
	 * Первый sched_switch для каждого потока: запоминаем значение,
	 * дельту не добавляем. cpu_ns растёт с момента начала трекинга.
	 */
	{
		__u32 tid = (__u32)pid_tgid;
		__u64 thr_cpu = BPF_CORE_READ(task, utime)
			      + BPF_CORE_READ(task, stime);
		__u64 *prev = bpf_map_lookup_elem(&thread_cpu_map, &tid);
		if (prev) {
			if (thr_cpu > *prev)
				__sync_fetch_and_add(&info->cpu_ns,
						     thr_cpu - *prev);
			*prev = thr_cpu;
		} else {
			bpf_map_update_elem(&thread_cpu_map, &tid,
					    &thr_cpu, BPF_NOEXIST);
		}
	}

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

	/* Состояние процесса — task->__state (ядро 5.14+), task->state (ядро < 5.14) */
	unsigned int task_state = 0;
	if (bpf_core_field_exists(task->__state))
		task_state = BPF_CORE_READ(task, __state);
	else
		task_state = (unsigned int)BPF_CORE_READ((struct task_struct___old *)task, state);
	info->state = state_to_char(task_state);

	/* UID — обновляем при каждом sched_switch (может измениться через setuid) */
	info->uid = (__u32)bpf_get_current_uid_gid();

	/* Identity: loginuid, sessionid, euid */
	read_identity(task, &info->loginuid, &info->sessionid, &info->euid);
	info->tty_nr = read_tty_nr(task);

	/* Политика планировщика */
	info->sched_policy = BPF_CORE_READ(task, policy);

	/* Учёт ввода-вывода (включая page cache) */
	read_io_accounting(task, &info->io_rchar, &info->io_wchar,
			   &info->io_syscr, &info->io_syscw);

	/* Номера inode пространств имён */
	read_ns_inums(task, &info->mnt_ns_inum, &info->pid_ns_inum,
		      &info->net_ns_inum, &info->cgroup_ns_inum);

	/*
	 * Отслеживание вытеснения: prev_state == 0 означает TASK_RUNNING,
	 * т.е. процесс был принудительно вытеснен процессом `next`.
	 * Записываем, кто нас вытеснил («шумный сосед»).
	 */
	if (ctx->prev_state == 0 && ctx->next_pid > 0) {
		__u32 next_tid = (__u32)ctx->next_pid;

		/*
		 * Резолвим TID вытеснителя в TGID + comm основного процесса
		 * через tid_tgid_map. Если TID — дочерний поток (ThreadPool,
		 * Worker-N и т.д.), получим comm главного процесса
		 * (clickhouse-serv, java и т.д.).
		 * Если записи нет — это главный поток, берём данные из
		 * tracepoint args как есть.
		 */
		struct tid_info *ti = bpf_map_lookup_elem(&tid_tgid_map,
							  &next_tid);
		if (ti) {
			info->preempted_by_pid = ti->tgid;
			__builtin_memcpy(info->preempted_by_comm,
					 ti->comm, COMM_LEN);
		} else {
			info->preempted_by_pid = next_tid;
			bpf_probe_read_kernel(info->preempted_by_comm,
					      COMM_LEN,
					      ctx->next_comm);
		}
		info->preempted_by_comm[COMM_LEN - 1] = '\0';
		info->preempted_by_cgroup_id = 0;
	}

	return 0;
}

/* ── ВЫХОД (EXIT) ─────────────────────────────────────────────────── */

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid  = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Cleanup tid_tgid_map для завершающегося потока (до проверки tracked) */
	if (pid != tgid)
		bpf_map_delete_elem(&tid_tgid_map, &pid);

	/* Только для отслеживаемых процессов */
	struct track_info *ti = bpf_map_lookup_elem(&tracked_map, &tgid);
	if (!ti)
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* Финальная дельта CPU для этого потока + cleanup thread_cpu_map */
	{
		struct proc_info *pi = bpf_map_lookup_elem(&proc_map, &tgid);
		if (pi) {
			__u64 thr_cpu = BPF_CORE_READ(task, utime)
				      + BPF_CORE_READ(task, stime);
			__u64 *prev = bpf_map_lookup_elem(&thread_cpu_map,
							  &pid);
			if (prev && thr_cpu > *prev)
				__sync_fetch_and_add(&pi->cpu_ns,
						     thr_cpu - *prev);
		}
		bpf_map_delete_elem(&thread_cpu_map, &pid);
	}

	/* Для потоков (не лидера) — только дельта+cleanup, без события */
	if (pid != tgid)
		return 0;

	/* Финальный снимок метрик из task_struct */
	struct mem_info exit_mi = read_mem_pages(task);
	__u64 final_vsize    = read_vsize_pages(task);
	__u32 final_threads  = read_nr_threads(task);
	__s16 final_oom_adj  = read_oom_score_adj(task);
	__u32 final_exit_code = BPF_CORE_READ(task, exit_code);
	__u64 exit_ts        = bpf_ktime_get_boot_ns();

	/* Помечаем proc_info как завершённый + обновляем финальные метрики.
	 * Карты НЕ удаляем — snapshot прочитает и зачистит */
	struct proc_info *info = bpf_map_lookup_elem(&proc_map, &tgid);
	if (info) {
		info->status        = PROC_STATUS_EXITED;
		info->exit_ns       = exit_ts;
		info->exit_code     = final_exit_code;
		info->rss_pages     = exit_mi.rss_pages;
		info->vsize_pages   = final_vsize;
		info->threads       = final_threads;
		info->oom_score_adj = final_oom_adj;
	}

	/* Отправляем событие EXIT в ring buffer */
	RB_STAT_TOTAL_PROC();
	struct event *e = bpf_ringbuf_reserve(&events_proc, sizeof(*e), 0);
	if (!e) {
		RB_STAT_DROP_PROC();
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->type         = EVENT_EXIT;
	e->tgid         = tgid;
	e->uid          = (__u32)bpf_get_current_uid_gid();
	e->timestamp_ns = exit_ts;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	/* Данные отслеживания */
	e->root_pid = ti->root_pid;
	e->rule_id  = ti->rule_id;

	/* Финальные метрики */
	e->rss_pages     = exit_mi.rss_pages;
	e->vsize_pages   = final_vsize;
	e->threads       = final_threads;
	e->oom_score_adj = final_oom_adj;
	e->exit_code     = final_exit_code;

	/* Накопленные метрики из proc_info */
	if (info) {
		e->cpu_ns        = info->cpu_ns;
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
	RB_STAT_TOTAL_PROC();
	struct event *e = bpf_ringbuf_reserve(&events_proc, sizeof(*e), 0);
	if (!e) {
		RB_STAT_DROP_PROC();
		return 0;
	}

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

/* ── СИГНАЛ (SIGNAL) — перехват отправки сигналов ──────────────────── */

/*
 * signal_generate срабатывает при доставке сигнала.
 * Перехватываем только пользовательские сигналы (SI_USER, SI_TKILL, SI_QUEUE)
 * от/к отслеживаемым процессам.
 *
 * Tracepoint args: sig, errno, code, comm(__data_loc), pid, group, result
 */
SEC("raw_tracepoint/signal_generate")
int handle_signal_generate(struct bpf_raw_tracepoint_args *ctx)
{
	/*
	 * btf_trace_signal_generate(void *, int sig, struct kernel_siginfo *info,
	 *                           struct task_struct *task, int group, int result)
	 * raw_tracepoint args:
	 *   args[0] = int sig
	 *   args[1] = struct kernel_siginfo *info
	 *   args[2] = struct task_struct *task  (target)
	 *   args[3] = int group
	 *   args[4] = int result
	 */
	int sig        = (int)ctx->args[0];
	int result     = (int)ctx->args[4];
	struct task_struct *target = (struct task_struct *)ctx->args[2];
	int target_pid = BPF_CORE_READ(target, tgid);

	/* Читаем код сигнала из kernel_siginfo */
	struct kernel_siginfo *sinfo = (struct kernel_siginfo *)ctx->args[1];
	int code = 0;
	bpf_probe_read_kernel(&code, sizeof(code), &sinfo->si_code);

	/* Только пользовательские сигналы через kill(): SI_USER=0.
	 * Пропускаем SI_TKILL (-6) — слишком шумный от Go runtime SIGURG и pthread_kill.
	 * Пропускаем SI_KERNEL (128) и другие ядерные коды (>0). */
	if (code != 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 sender_tgid = (__u32)(pid_tgid >> 32);
	__u32 target_tgid = (__u32)target_pid;

	/* Отправляем событие, если отправитель ИЛИ получатель отслеживается */
	if (!bpf_map_lookup_elem(&tracked_map, &sender_tgid) &&
	    !bpf_map_lookup_elem(&tracked_map, &target_tgid))
		return 0;

	RB_STAT_TOTAL_NET();
	struct signal_event *se = bpf_ringbuf_reserve(&events_net, sizeof(*se), 0);
	if (!se) {
		RB_STAT_DROP_NET();
		return 0;
	}

	__builtin_memset(se, 0, sizeof(*se));
	se->type         = EVENT_SIGNAL;
	se->sender_tgid  = sender_tgid;
	se->sender_uid   = (__u32)bpf_get_current_uid_gid();
	se->target_pid   = target_tgid;
	se->timestamp_ns = bpf_ktime_get_boot_ns();
	se->sig          = sig;
	se->sig_code     = code;
	se->sig_result   = result;
	bpf_get_current_comm(se->sender_comm, sizeof(se->sender_comm));

	/* cgroup id отправителя */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	se->cgroup_id = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);

	bpf_ringbuf_submit(se, 0);
	return 0;
}

/* ── CHDIR/FCHDIR — трекинг смены рабочего каталога ─────────────────── */

/*
 * sys_exit_chdir: при успешном chdir() отправляем уведомление в userspace,
 * который прочитает актуальный pwd через readlink(/proc/PID/cwd).
 */
SEC("tracepoint/syscalls/sys_exit_chdir")
int handle_sys_exit_chdir(struct trace_event_raw_sys_exit *ctx)
{
	if (ctx->ret != 0)
		return 0;

	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	RB_STAT_TOTAL_PROC();
	struct event *e = bpf_ringbuf_reserve(&events_proc, sizeof(*e), 0);
	if (!e) {
		RB_STAT_DROP_PROC();
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_CHDIR;
	e->tgid = tgid;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int handle_sys_exit_fchdir(struct trace_event_raw_sys_exit *ctx)
{
	if (ctx->ret != 0)
		return 0;

	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	RB_STAT_TOTAL_PROC();
	struct event *e = bpf_ringbuf_reserve(&events_proc, sizeof(*e), 0);
	if (!e) {
		RB_STAT_DROP_PROC();
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_CHDIR;
	e->tgid = tgid;
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
	struct openat_args oa;
	BPF_ZERO(oa);
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

	struct fd_info fi;
	BPF_ZERO(fi);
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
	RB_STAT_TOTAL_FILE();
	struct file_event *fe = bpf_ringbuf_reserve(&events_file, sizeof(*fe), 0);
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
	} else {
		RB_STAT_DROP_FILE();
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

/* Счётчик открытых TCP-соединений по tgid (определён в секции безопасности,
 * объявлен здесь для использования в хуках connect/close) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PROCS);
	__type(key, __u32);
	__type(value, __u64);
} open_conn_map SEC(".maps");

/* Временная карта для init-seed: inode сокета → tgid владельца.
 * Заполняется из userspace при старте, используется iter/tcp. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NET_MAX_SOCKETS);
	__type(key, __u64);           /* inode number */
	__type(value, __u32);         /* tgid */
} seed_inode_map SEC(".maps");

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
	RB_STAT_TOTAL_NET();
	struct net_event *ne = bpf_ringbuf_reserve(&events_net, sizeof(*ne), 0);
	if (!ne) {
		RB_STAT_DROP_NET();
		return;
	}

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

	/* Только для отслеживаемых процессов */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	struct sock_info si; BPF_ZERO(si);
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);

	/* open_conn_count: инкремент */
	__u64 *cnt = bpf_map_lookup_elem(&open_conn_map, &tgid);
	if (cnt) __sync_fetch_and_add(cnt, 1);
	else { __u64 one = 1; bpf_map_update_elem(&open_conn_map, &tgid, &one, BPF_NOEXIST); }

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

	/* Только для отслеживаемых процессов */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	struct sock_info si; BPF_ZERO(si);
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);

	/* open_conn_count: инкремент */
	__u64 *cnt = bpf_map_lookup_elem(&open_conn_map, &tgid);
	if (cnt) __sync_fetch_and_add(cnt, 1);
	else { __u64 one = 1; bpf_map_update_elem(&open_conn_map, &tgid, &one, BPF_NOEXIST); }

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

	/* Только для отслеживаемых процессов */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	struct sock_info si; BPF_ZERO(si);
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);

	/* open_conn_count: инкремент */
	__u64 *cnt = bpf_map_lookup_elem(&open_conn_map, &tgid);
	if (cnt) __sync_fetch_and_add(cnt, 1);
	else { __u64 one = 1; bpf_map_update_elem(&open_conn_map, &tgid, &one, BPF_NOEXIST); }

	return 0;
}

/* ── inet_csk_listen_start: регистрация слушающих сокетов ─────────── */

SEC("kprobe/inet_csk_listen_start")
int BPF_KPROBE(kp_inet_csk_listen_start, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);

	/* Только для отслеживаемых процессов */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;

	__u64 sk_ptr = (__u64)sk;
	struct sock_info si; BPF_ZERO(si);
	si.tgid = tgid;
	si.uid = (__u32)bpf_get_current_uid_gid();
	si.start_ns = bpf_ktime_get_boot_ns();
	si.is_listener = 1;
	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);
	return 0;
}

/* ── tcp_close: отправка события NET_CLOSE ────────────────────────── */

/*
 * tcp_close:
 *   kprobe  — эмитим NET_CLOSE + декремент open_conn, сохраняем sk_ptr
 *             в per-CPU map для kretprobe. НЕ удаляем из sock_map, чтобы
 *             tcp_send_active_reset (SO_LINGER=0) мог найти сокет.
 *   kretprobe — удаляем из sock_map.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);	/* sk_ptr, 0 = не ожидаем kretprobe */
} tcp_close_sk SEC(".maps");

SEC("kprobe/tcp_close")
int BPF_KPROBE(kp_tcp_close, struct sock *sk)
{
	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	/* Слушающий сокет: удаляем из sock_map, без NET_CLOSE и open_conn */
	if (si->is_listener) {
		bpf_map_delete_elem(&sock_map, &sk_ptr);
		return 0;
	}

	/* open_conn_count: декремент */
	__u32 tgid = si->tgid;
	__u64 *cnt = bpf_map_lookup_elem(&open_conn_map, &tgid);
	if (cnt && *cnt > 0) __sync_fetch_and_add(cnt, -1);

	emit_net_close(si, bpf_ktime_get_boot_ns());

	/* Сохраняем sk_ptr для kretprobe (отложенное удаление из sock_map) */
	__u32 zero = 0;
	bpf_map_update_elem(&tcp_close_sk, &zero, &sk_ptr, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_close")
int BPF_KRETPROBE(kretp_tcp_close)
{
	__u32 zero = 0;
	__u64 *sk_ptr_p = bpf_map_lookup_elem(&tcp_close_sk, &zero);
	if (!sk_ptr_p || !*sk_ptr_p)
		return 0;

	__u64 sk_ptr = *sk_ptr_p;
	*sk_ptr_p = 0; /* сбрасываем */
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

/* ── Пробы безопасности ──────────────────────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sec_config);
} sec_cfg SEC(".maps");

/* Карта агрегации UDP — сбрасывается из userspace при snapshot */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct udp_agg_key);
	__type(value, struct udp_agg_val);
} udp_agg_map SEC(".maps");

/* Карта агрегации ICMP — сбрасывается из userspace при snapshot */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct icmp_agg_key);
	__type(value, struct icmp_agg_val);
} icmp_agg_map SEC(".maps");

/* open_conn_map уже объявлена в секции сети выше */

/*
 * Вспомогательная функция: проверяет, включён ли флаг sec_config.
 */
static __always_inline int sec_enabled(int offset)
{
	__u32 zero = 0;
	struct sec_config *cfg = bpf_map_lookup_elem(&sec_cfg, &zero);
	if (!cfg) return 0;
	return *((__u8 *)cfg + offset);
}

#define SEC_TCP_RETRANSMIT  0
#define SEC_SYN_TRACKING    1
#define SEC_RST_TRACKING    2
#define SEC_UDP_TRACKING    3
#define SEC_ICMP_TRACKING   4
#define SEC_OPEN_CONN_COUNT 5

/*
 * Вспомогательная функция: читает адреса сокета в плоские поля
 * (переиспользует логику парсинга sock).
 */
static __always_inline void read_sock_to_event(
	struct sock *sk,
	__u8 *af, __u8 *local_addr, __u8 *remote_addr,
	__u16 *local_port, __u16 *remote_port)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	*af = (__u8)family;
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	*remote_port = __bpf_ntohs(dport);
	*local_port  = BPF_CORE_READ(sk, __sk_common.skc_num);

	if (family == 2) { /* AF_INET */
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(remote_addr, &daddr, 4);
		__builtin_memcpy(local_addr, &saddr, 4);
	} else if (family == 10) { /* AF_INET6 */
		BPF_CORE_READ_INTO(remote_addr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(local_addr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}
}

/* ── TCP retransmit: raw_tracepoint/tcp_retransmit_skb ───────────── */

SEC("raw_tracepoint/tcp_retransmit_skb")
int handle_tcp_retransmit(struct bpf_raw_tracepoint_args *ctx)
{
	if (!sec_enabled(SEC_TCP_RETRANSMIT))
		return 0;

	/* args[0] = const struct sock *sk, args[1] = const struct sk_buff *skb */
	struct sock *sk = (struct sock *)ctx->args[0];

	/* Только для сокетов отслеживаемых процессов */
	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	RB_STAT_TOTAL_SEC();
	struct retransmit_event *re =
		bpf_ringbuf_reserve(&events_sec, sizeof(*re), 0);
	if (!re) {
		RB_STAT_DROP_SEC();
		return 0;
	}

	__builtin_memset(re, 0, sizeof(*re));
	re->type = EVENT_TCP_RETRANSMIT;
	re->timestamp_ns = bpf_ktime_get_boot_ns();

	/* tgid/uid из sock_map (в softirq bpf_get_current_pid_tgid = 0) */
	re->tgid = si->tgid;
	re->uid  = si->uid;

	/* comm и cgroup из proc_map */
	struct proc_info *pi = bpf_map_lookup_elem(&proc_map, &si->tgid);
	if (pi) {
		__builtin_memcpy(re->comm, pi->comm, COMM_LEN);
		re->cgroup_id = pi->cgroup_id;
	}

	/* адреса из sock */
	read_sock_to_event(sk, &re->af, re->local_addr, re->remote_addr,
			   &re->local_port, &re->remote_port);

	/* Состояние TCP */
	re->state = (__u8)BPF_CORE_READ(sk, __sk_common.skc_state);

	bpf_ringbuf_submit(re, 0);
	return 0;
}

/* ── SYN flood: kprobe/tcp_conn_request ───────────────────────────── */

SEC("kprobe/tcp_conn_request")
int BPF_KPROBE(kp_tcp_conn_request, struct request_sock_ops *rsk_ops,
	       const void *af_ops, struct sock *sk, struct sk_buff *skb)
{
	if (!sec_enabled(SEC_SYN_TRACKING))
		return 0;

	/* Только для слушающих сокетов отслеживаемых процессов */
	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	RB_STAT_TOTAL_SEC();
	struct syn_event *se =
		bpf_ringbuf_reserve(&events_sec, sizeof(*se), 0);
	if (!se) {
		RB_STAT_DROP_SEC();
		return 0;
	}

	__builtin_memset(se, 0, sizeof(*se));
	se->type = EVENT_SYN_RECV;
	se->timestamp_ns = bpf_ktime_get_boot_ns();

	/* tgid/uid из sock_map (в softirq bpf_get_current_pid_tgid = 0) */
	se->tgid = si->tgid;
	se->uid  = si->uid;

	/* comm и cgroup из proc_map */
	struct proc_info *pi = bpf_map_lookup_elem(&proc_map, &si->tgid);
	if (pi) {
		__builtin_memcpy(se->comm, pi->comm, COMM_LEN);
		se->cgroup_id = pi->cgroup_id;
	}

	/* Локальный адрес/порт слушающего сокета */
	se->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	se->af = (__u8)family;

	if (family == 2) { /* AF_INET */
		__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(se->local_addr, &saddr, 4);
	} else if (family == 10) { /* AF_INET6 */
		BPF_CORE_READ_INTO(se->local_addr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}

	/* Удалённый адрес из IP-заголовка skb */
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 nh_off = BPF_CORE_READ(skb, network_header);
	if (family == 2) {
		struct iphdr *iph = (struct iphdr *)(head + nh_off);
		__u32 src;
		bpf_probe_read_kernel(&src, 4, &iph->saddr);
		__builtin_memcpy(se->remote_addr, &src, 4);
	} else if (family == 10) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(head + nh_off);
		bpf_probe_read_kernel(se->remote_addr, 16, &ip6h->saddr);
	}

	/* Удалённый порт из TCP-заголовка */
	__u16 th_off = BPF_CORE_READ(skb, transport_header);
	struct tcphdr *th = (struct tcphdr *)(head + th_off);
	__be16 sport;
	bpf_probe_read_kernel(&sport, 2, &th->source);
	se->remote_port = __bpf_ntohs(sport);

	bpf_ringbuf_submit(se, 0);
	return 0;
}

/* ── Отправка RST: raw_tracepoint/tcp_send_reset ─────────────────── */

SEC("raw_tracepoint/tcp_send_reset")
int handle_tcp_send_reset(struct bpf_raw_tracepoint_args *ctx)
{
	if (!sec_enabled(SEC_RST_TRACKING))
		return 0;

	/* args[0] = const struct sock *sk (может быть NULL), args[1] = struct sk_buff *skb */
	struct sock *sk = (struct sock *)ctx->args[0];
	if (!sk)
		return 0;

	/* Только для сокетов отслеживаемых процессов */
	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	RB_STAT_TOTAL_SEC();
	struct rst_event *re =
		bpf_ringbuf_reserve(&events_sec, sizeof(*re), 0);
	if (!re) {
		RB_STAT_DROP_SEC();
		return 0;
	}

	__builtin_memset(re, 0, sizeof(*re));
	re->type = EVENT_RST;
	re->direction = 0; /* отправлен */
	re->timestamp_ns = bpf_ktime_get_boot_ns();

	/* tgid/uid из sock_map */
	re->tgid = si->tgid;
	re->uid  = si->uid;

	/* comm и cgroup из proc_map */
	struct proc_info *pi = bpf_map_lookup_elem(&proc_map, &si->tgid);
	if (pi) {
		__builtin_memcpy(re->comm, pi->comm, COMM_LEN);
		re->cgroup_id = pi->cgroup_id;
	}

	read_sock_to_event(sk, &re->af, re->local_addr, re->remote_addr,
			   &re->local_port, &re->remote_port);

	bpf_ringbuf_submit(re, 0);
	return 0;
}

/* ── Отправка active RST (SO_LINGER=0 close): kprobe ─────────────── */

SEC("kprobe/tcp_send_active_reset")
int BPF_KPROBE(kp_tcp_send_active_reset, struct sock *sk)
{
	if (!sec_enabled(SEC_RST_TRACKING))
		return 0;

	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	RB_STAT_TOTAL_SEC();
	struct rst_event *re =
		bpf_ringbuf_reserve(&events_sec, sizeof(*re), 0);
	if (!re) {
		RB_STAT_DROP_SEC();
		return 0;
	}

	__builtin_memset(re, 0, sizeof(*re));
	re->type = EVENT_RST;
	re->direction = 0; /* отправлен */
	re->timestamp_ns = bpf_ktime_get_boot_ns();

	re->tgid = si->tgid;
	re->uid  = si->uid;

	struct proc_info *pi = bpf_map_lookup_elem(&proc_map, &si->tgid);
	if (pi) {
		__builtin_memcpy(re->comm, pi->comm, COMM_LEN);
		re->cgroup_id = pi->cgroup_id;
	}

	read_sock_to_event(sk, &re->af, re->local_addr, re->remote_addr,
			   &re->local_port, &re->remote_port);

	bpf_ringbuf_submit(re, 0);
	return 0;
}

/* ── Получение RST: raw_tracepoint/tcp_receive_reset ─────────────── */

SEC("raw_tracepoint/tcp_receive_reset")
int handle_tcp_receive_reset(struct bpf_raw_tracepoint_args *ctx)
{
	if (!sec_enabled(SEC_RST_TRACKING))
		return 0;

	/* args[0] = struct sock *sk */
	struct sock *sk = (struct sock *)ctx->args[0];

	/* Только для сокетов отслеживаемых процессов */
	__u64 sk_ptr = (__u64)sk;
	struct sock_info *si = bpf_map_lookup_elem(&sock_map, &sk_ptr);
	if (!si)
		return 0;

	RB_STAT_TOTAL_SEC();
	struct rst_event *re =
		bpf_ringbuf_reserve(&events_sec, sizeof(*re), 0);
	if (!re) {
		RB_STAT_DROP_SEC();
		return 0;
	}

	__builtin_memset(re, 0, sizeof(*re));
	re->type = EVENT_RST;
	re->direction = 1; /* получен */
	re->timestamp_ns = bpf_ktime_get_boot_ns();

	/* tgid/uid из sock_map */
	re->tgid = si->tgid;
	re->uid  = si->uid;

	/* comm и cgroup из proc_map */
	struct proc_info *pi = bpf_map_lookup_elem(&proc_map, &si->tgid);
	if (pi) {
		__builtin_memcpy(re->comm, pi->comm, COMM_LEN);
		re->cgroup_id = pi->cgroup_id;
	}

	read_sock_to_event(sk, &re->af, re->local_addr, re->remote_addr,
			   &re->local_port, &re->remote_port);

	bpf_ringbuf_submit(re, 0);
	return 0;
}

/* ── UDP flood: kprobe вход + kretprobe агрегация ────────────────── */

/* Сохраняем указатель на sock при входе для извлечения адресов */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);           /* pid_tgid */
	__type(value, struct sendmsg_args);
} udp_sendmsg_args SEC(".maps");

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kp_udp_sendmsg_sec, struct sock *sk)
{
	if (!sec_enabled(SEC_UDP_TRACKING))
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	/* Только для отслеживаемых процессов */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;
	struct sendmsg_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&udp_sendmsg_args, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(ret_udp_sendmsg_sec, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args *args =
		bpf_map_lookup_elem(&udp_sendmsg_args, &pid_tgid);
	if (!args)
		return 0;
	struct sock *sk = (struct sock *)args->sock_ptr;
	bpf_map_delete_elem(&udp_sendmsg_args, &pid_tgid);

	if (ret <= 0)
		return 0;

	struct udp_agg_key key; BPF_ZERO(key);
	key.tgid = (__u32)(pid_tgid >> 32);
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	key.af = (__u8)family;
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	key.remote_port = __bpf_ntohs(dport);
	if (family == 2) {
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(key.remote_addr, &daddr, 4);
	} else if (family == 10) {
		BPF_CORE_READ_INTO(key.remote_addr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}

	struct udp_agg_val *val = bpf_map_lookup_elem(&udp_agg_map, &key);
	if (val) {
		__sync_fetch_and_add(&val->tx_packets, 1);
		__sync_fetch_and_add(&val->tx_bytes, (__u64)ret);
	} else {
		struct udp_agg_val new_val = {
			.tx_packets = 1, .tx_bytes = (__u64)ret
		};
		bpf_map_update_elem(&udp_agg_map, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kp_udp_recvmsg_sec, struct sock *sk)
{
	if (!sec_enabled(SEC_UDP_TRACKING))
		return 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = (__u32)(pid_tgid >> 32);
	/* Только для отслеживаемых процессов */
	if (!bpf_map_lookup_elem(&tracked_map, &tgid))
		return 0;
	struct sendmsg_args args = { .sock_ptr = (__u64)sk };
	bpf_map_update_elem(&udp_sendmsg_args, &pid_tgid, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(ret_udp_recvmsg_sec, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sendmsg_args *args =
		bpf_map_lookup_elem(&udp_sendmsg_args, &pid_tgid);
	if (!args)
		return 0;
	struct sock *sk = (struct sock *)args->sock_ptr;
	bpf_map_delete_elem(&udp_sendmsg_args, &pid_tgid);

	if (ret <= 0)
		return 0;

	struct udp_agg_key key; BPF_ZERO(key);
	key.tgid = (__u32)(pid_tgid >> 32);
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	key.af = (__u8)family;
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
	key.remote_port = __bpf_ntohs(dport);
	if (family == 2) {
		__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(key.remote_addr, &daddr, 4);
	} else if (family == 10) {
		BPF_CORE_READ_INTO(key.remote_addr, sk,
				   __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}

	struct udp_agg_val *val = bpf_map_lookup_elem(&udp_agg_map, &key);
	if (val) {
		__sync_fetch_and_add(&val->rx_packets, 1);
		__sync_fetch_and_add(&val->rx_bytes, (__u64)ret);
	} else {
		struct udp_agg_val new_val = {
			.rx_packets = 1, .rx_bytes = (__u64)ret
		};
		bpf_map_update_elem(&udp_agg_map, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

/* ── ICMP flood: kprobe/icmp_rcv ──────────────────────────────────── */

SEC("kprobe/icmp_rcv")
int BPF_KPROBE(kp_icmp_rcv, struct sk_buff *skb)
{
	if (!sec_enabled(SEC_ICMP_TRACKING))
		return 0;

	struct icmp_agg_key key; BPF_ZERO(key);

	/* Читаем IP-адрес источника из IP-заголовка */
	unsigned char *head = BPF_CORE_READ(skb, head);
	__u16 nh_off = BPF_CORE_READ(skb, network_header);
	struct iphdr *iph = (struct iphdr *)(head + nh_off);
	__u32 saddr;
	bpf_probe_read_kernel(&saddr, 4, &iph->saddr);
	__builtin_memcpy(key.src_addr, &saddr, 4);

	/* Читаем ICMP type/code из транспортного заголовка */
	__u16 th_off = BPF_CORE_READ(skb, transport_header);
	struct icmphdr *icmph = (struct icmphdr *)(head + th_off);
	bpf_probe_read_kernel(&key.icmp_type, 1, &icmph->type);
	bpf_probe_read_kernel(&key.icmp_code, 1, &icmph->code);

	struct icmp_agg_val *val = bpf_map_lookup_elem(&icmp_agg_map, &key);
	if (val) {
		__sync_fetch_and_add(&val->count, 1);
	} else {
		struct icmp_agg_val new_val = { .count = 1 };
		bpf_map_update_elem(&icmp_agg_map, &key, &new_val, BPF_NOEXIST);
	}
	return 0;
}

/* ── Счётчик открытых соединений: инструментирование connect/close ── */
/* Инкремент при успешном connect/accept, декремент при tcp_close.
 * Реализовано через open_conn_map с ключом tgid.
 * Userspace читает при snapshot. */

/* ── tracepoint'ы жизненного цикла cgroup ─────────────────────────── */

/*
 * Вспомогательная функция: чтение строки __data_loc из контекста tracepoint.
 * __data_loc — это __u32, где младшие 16 бит = смещение от начала структуры,
 * старшие 16 бит = длина.
 */
static __always_inline int read_data_loc_str(void *ctx, __u32 data_loc,
					     char *buf, int buflen)
{
	__u16 offset = data_loc & 0xFFFF;
	return bpf_probe_read_kernel_str(buf, buflen, (char *)ctx + offset);
}

/* cgroup_mkdir / cgroup_rmdir / cgroup_rename / cgroup_release
 * Все используют общую раскладку struct trace_event_raw_cgroup:
 *   int root, int level, u64 id, __data_loc path */
static __always_inline int emit_cgroup_event(void *ctx, __u32 type)
{
	struct trace_event_raw_cgroup *tp = ctx;

	RB_STAT_TOTAL_CGROUP();
	struct cgroup_event *ce = bpf_ringbuf_reserve(&events_cgroup,
						      sizeof(*ce), 0);
	if (!ce) {
		RB_STAT_DROP_CGROUP();
		return 0;
	}

	__builtin_memset(ce, 0, sizeof(*ce));
	ce->type         = type;
	ce->id           = tp->id;
	ce->level        = tp->level;
	ce->timestamp_ns = bpf_ktime_get_boot_ns();

	read_data_loc_str(ctx, tp->__data_loc_path,
			  ce->path, sizeof(ce->path));

	bpf_ringbuf_submit(ce, 0);
	return 0;
}

SEC("tracepoint/cgroup/cgroup_mkdir")
int handle_cgroup_mkdir(void *ctx)
{
	return emit_cgroup_event(ctx, EVENT_CGROUP_MKDIR);
}

SEC("tracepoint/cgroup/cgroup_rmdir")
int handle_cgroup_rmdir(void *ctx)
{
	return emit_cgroup_event(ctx, EVENT_CGROUP_RMDIR);
}

SEC("tracepoint/cgroup/cgroup_rename")
int handle_cgroup_rename(void *ctx)
{
	return emit_cgroup_event(ctx, EVENT_CGROUP_RENAME);
}

SEC("tracepoint/cgroup/cgroup_release")
int handle_cgroup_release(void *ctx)
{
	return emit_cgroup_event(ctx, EVENT_CGROUP_RELEASE);
}

/* cgroup_attach_task / cgroup_transfer_tasks
 * Структура trace_event_raw_cgroup_migrate:
 *   int dst_root, int dst_level, u64 dst_id, int pid,
 *   __data_loc dst_path, __data_loc comm */
static __always_inline int emit_cgroup_migrate(void *ctx, __u32 type)
{
	struct trace_event_raw_cgroup_migrate *tp = ctx;

	/* Обновляем cgroup_id в proc_map, чтобы snapshot видел новую cgroup */
	__u32 tgid = (__u32)tp->pid;
	struct proc_info *pi = bpf_map_lookup_elem(&proc_map, &tgid);
	if (pi)
		pi->cgroup_id = tp->dst_id;

	RB_STAT_TOTAL_CGROUP();
	struct cgroup_event *ce = bpf_ringbuf_reserve(&events_cgroup,
						      sizeof(*ce), 0);
	if (!ce) {
		RB_STAT_DROP_CGROUP();
		return 0;
	}

	__builtin_memset(ce, 0, sizeof(*ce));
	ce->type         = type;
	ce->id           = tp->dst_id;
	ce->level        = tp->dst_level;
	ce->pid          = tp->pid;
	ce->timestamp_ns = bpf_ktime_get_boot_ns();

	read_data_loc_str(ctx, tp->__data_loc_dst_path,
			  ce->path, sizeof(ce->path));
	read_data_loc_str(ctx, tp->__data_loc_comm,
			  ce->comm, sizeof(ce->comm));

	bpf_ringbuf_submit(ce, 0);
	return 0;
}

SEC("tracepoint/cgroup/cgroup_attach_task")
int handle_cgroup_attach_task(void *ctx)
{
	return emit_cgroup_migrate(ctx, EVENT_CGROUP_ATTACH_TASK);
}

SEC("tracepoint/cgroup/cgroup_transfer_tasks")
int handle_cgroup_transfer_tasks(void *ctx)
{
	return emit_cgroup_migrate(ctx, EVENT_CGROUP_TRANSFER_TASKS);
}

/* cgroup_notify_populated / cgroup_freeze / cgroup_unfreeze / cgroup_notify_frozen
 * Структура trace_event_raw_cgroup_event:
 *   int root, int level, u64 id, __data_loc path, int val */
static __always_inline int emit_cgroup_state(void *ctx, __u32 type)
{
	struct trace_event_raw_cgroup_event *tp = ctx;

	RB_STAT_TOTAL_CGROUP();
	struct cgroup_event *ce = bpf_ringbuf_reserve(&events_cgroup,
						      sizeof(*ce), 0);
	if (!ce) {
		RB_STAT_DROP_CGROUP();
		return 0;
	}

	__builtin_memset(ce, 0, sizeof(*ce));
	ce->type         = type;
	ce->id           = tp->id;
	ce->level        = tp->level;
	ce->val          = tp->val;
	ce->timestamp_ns = bpf_ktime_get_boot_ns();

	read_data_loc_str(ctx, tp->__data_loc_path,
			  ce->path, sizeof(ce->path));

	bpf_ringbuf_submit(ce, 0);
	return 0;
}

SEC("tracepoint/cgroup/cgroup_notify_populated")
int handle_cgroup_populated(void *ctx)
{
	return emit_cgroup_state(ctx, EVENT_CGROUP_POPULATED);
}

SEC("tracepoint/cgroup/cgroup_freeze")
int handle_cgroup_freeze(void *ctx)
{
	return emit_cgroup_state(ctx, EVENT_CGROUP_FREEZE);
}

SEC("tracepoint/cgroup/cgroup_unfreeze")
int handle_cgroup_unfreeze(void *ctx)
{
	return emit_cgroup_state(ctx, EVENT_CGROUP_UNFREEZE);
}

SEC("tracepoint/cgroup/cgroup_notify_frozen")
int handle_cgroup_frozen(void *ctx)
{
	return emit_cgroup_state(ctx, EVENT_CGROUP_FROZEN);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Init-seed: заполнение sock_map существующими TCP-сокетами
 *  отслеживаемых процессов при старте (bpf_iter/tcp).
 *
 *  Userspace:
 *    1) для каждого tracked PID сканирует /proc/<pid>/fd/ → socket:[ino]
 *    2) записывает ino → tgid в seed_inode_map
 *    3) запускает этот итератор (attach + read до EOF)
 *    4) очищает seed_inode_map
 * ══════════════════════════════════════════════════════════════════════ */

SEC("iter/tcp")
int seed_sock_map_iter(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk_common = ctx->sk_common;
	if (!sk_common)
		return 0;

	struct sock *sk = (struct sock *)sk_common;

	/* Читаем inode файла сокета: sk→sk_socket→file→f_inode→i_ino */
	struct socket *sock = BPF_CORE_READ(sk, sk_socket);
	if (!sock)
		return 0;
	struct file *f = BPF_CORE_READ(sock, file);
	if (!f)
		return 0;
	__u64 ino = BPF_CORE_READ(f, f_inode, i_ino);
	if (!ino)
		return 0;

	/* Проверяем, принадлежит ли сокет отслеживаемому процессу */
	__u32 *tgid_ptr = bpf_map_lookup_elem(&seed_inode_map, &ino);
	if (!tgid_ptr)
		return 0;

	__u32 tgid = *tgid_ptr;
	__u64 sk_ptr = (__u64)sk;

	/* Уже в sock_map? (race с kprobe при параллельном connect) */
	if (bpf_map_lookup_elem(&sock_map, &sk_ptr))
		return 0;

	struct sock_info si; BPF_ZERO(si);
	si.tgid = tgid;
	si.uid  = ctx->uid;
	si.start_ns = bpf_ktime_get_boot_ns();

	/* TCP_LISTEN = 10 */
	__u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (state == 10)
		si.is_listener = 1;

	read_sock_addrs(sk, &si);

	bpf_map_update_elem(&sock_map, &sk_ptr, &si, BPF_NOEXIST);

	/* open_conn_count: инкремент (только для соединений, не listener) */
	if (!si.is_listener) {
		__u64 *cnt = bpf_map_lookup_elem(&open_conn_map, &tgid);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
		else {
			__u64 one = 1;
			bpf_map_update_elem(&open_conn_map, &tgid, &one,
					    BPF_NOEXIST);
		}
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
