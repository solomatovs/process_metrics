/*
 * pm_rules.c — правила трекинга и хеш-таблица тегов процессов.
 *
 * Содержит логику сопоставления exec-процессов с правилами конфигурации,
 * управление pipe-separated тегами (store/lookup/merge/inherit/remove/clear)
 * и thread-safe обёртки для конкурентного доступа.
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <regex.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "process_metrics_common.h"
#include "event_file.h"
#include "pm_config.h"
#include "pm_state.h"
#include "pm_rules.h"
#include "pm_functions.h"
#include "log.h"

/* ── tags hash table (userspace-only, per-tgid) ────────────────────── *
 *
 * Split-layout: tags_tgid[] — компактный индекс (64 KB, в L1/L2 кэш),
 * tags_data[] — payload (8 MB, только при hit).
 * Murmurhash3 finalizer для равномерного рассеивания последовательных PID.
 * Подробности оптимизаций — см. комментарии в pm_state.h.
 */

__u32 tags_tgid[TAGS_HT_SIZE];			/*  64 KB — компактный индекс */
char tags_data[TAGS_HT_SIZE][TAGS_MAX_LEN];	/*   8 MB — данные           */

/*
 * Murmurhash3 finalizer (32-bit).
 * Принимает tgid, возвращает индекс в [0, TAGS_HT_SIZE).
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

		__u32 d_natural_to_next = (next - natural) & (TAGS_HT_SIZE - 1);
		__u32 d_natural_to_slot = (slot - natural) & (TAGS_HT_SIZE - 1);

		if (d_natural_to_slot < d_natural_to_next) {
			/* Сдвигаем next → slot */
			tags_tgid[slot] = tags_tgid[next];
			memcpy(tags_data[slot], tags_data[next], TAGS_MAX_LEN);
			slot = next;
		} else {
			break;
		}
	}

	/* Очищаем финальный пустой слот */
	tags_tgid[slot] = 0;
	tags_data[slot][0] = '\0';
}

/*
 * Наследование тегов от родителя к дочернему процессу.
 */
static void tags_inherit(__u32 child_tgid, __u32 parent_tgid)
{
	const char *pt = tags_lookup(parent_tgid);
	if (pt[0])
		tags_store(child_tgid, pt);
}

/*
 * Объединяет унаследованные tags родителя с новыми match'ами.
 * Результат: "parent_tag1|parent_tag2|new_tag1|new_tag2" (без дубликатов).
 */
static void tags_merge(__u32 tgid, const char *new_tags)
{
	const char *existing = tags_lookup(tgid);
	if (!existing[0]) {
		/* Нет существующих tags — просто записываем */
		tags_store(tgid, new_tags);
		return;
	}
	if (!new_tags[0])
		return;

	/* Собираем merged = existing + new (без дубликатов) */
	char merged[TAGS_MAX_LEN];
	int off = snprintf(merged, sizeof(merged), "%s", existing);

	/* Разбираем new_tags по '|' и добавляем отсутствующие */
	char buf[TAGS_MAX_LEN];
	snprintf(buf, sizeof(buf), "%s", new_tags);
	char *saveptr;
	for (char *tok = strtok_r(buf, "|", &saveptr); tok;
	     tok = strtok_r(NULL, "|", &saveptr)) {
		/* Проверяем, есть ли уже в merged */
		int found = 0;
		char check[TAGS_MAX_LEN];
		snprintf(check, sizeof(check), "%s", merged);
		char *sp2;
		for (char *t2 = strtok_r(check, "|", &sp2); t2;
		     t2 = strtok_r(NULL, "|", &sp2)) {
			if (strcmp(t2, tok) == 0) {
				found = 1;
				break;
			}
		}
		if (!found && off < (int)sizeof(merged) - 2) {
			int n = snprintf(merged + off, sizeof(merged) - off, "|%s", tok);
			if (n > 0)
				off += n;
		}
	}
	tags_store(tgid, merged);
}

static void tags_clear(void)
{
	memset(tags_tgid, 0, sizeof(tags_tgid));
	memset(tags_data, 0, sizeof(tags_data));
}

/*
 * Thread-safe обёртки для tags_*.
 * _ts_ версии берут g_tags_lock и копируют результат в caller-буфер.
 */
void tags_lookup_ts(__u32 tgid, char *buf, int buflen)
{
	pthread_rwlock_rdlock(&g_tags_lock);
	const char *t = tags_lookup(tgid);
	snprintf(buf, buflen, "%s", t);
	pthread_rwlock_unlock(&g_tags_lock);
}

void tags_inherit_ts(__u32 child, __u32 parent)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_inherit(child, parent);
	pthread_rwlock_unlock(&g_tags_lock);
}

void tags_merge_ts(__u32 tgid, const char *new_tags)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_merge(tgid, new_tags);
	pthread_rwlock_unlock(&g_tags_lock);
}

void tags_remove_ts(__u32 tgid)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_remove(tgid);
	pthread_rwlock_unlock(&g_tags_lock);
}

void tags_clear_ts(void)
{
	pthread_rwlock_wrlock(&g_tags_lock);
	tags_clear();
	pthread_rwlock_unlock(&g_tags_lock);
}

/* ── Fill tags ──────────────────────────────────────────────────────── */

void fill_tags(struct metric_event *cev, __u32 tgid)
{
	ensure_tags(tgid, cev->tags, sizeof(cev->tags));
}

/* ── Rule resolve ───────────────────────────────────────────────────── */

const char *resolve_rule_name(__u16 rule_id)
{
	return (rule_id < num_rules) ? rules[rule_id].name : RULE_NOT_MATCH;
}

const char *resolve_rule_for_pid(__u32 tgid)
{
	struct proc_info pi;
	if (is_pid_in_proc_map(tgid, &pi))
		return resolve_rule_name(pi.rule_id);
	return RULE_NOT_MATCH;
}

/*
 * Резолвит правило для proc event (exit/oom).
 * Порядок: BPF rule_id → proc_map → try_track → fallback ppid.
 */
const char *resolve_rule_for_proc_event(const struct event *e)
{
	/* BPF может передать валидный rule_id */
	if (e->rule_id < num_rules)
		return rules[e->rule_id].name;

	/* Попробуем отследить процесс */
	try_track_pid(e->tgid);

	/* Lookup tgid → fallback ppid */
	struct proc_info pi;
	if (is_pid_in_proc_map(e->tgid, &pi))
		return resolve_rule_name(pi.rule_id);
	if (e->ppid > 0 && is_pid_in_proc_map(e->ppid, &pi))
		return resolve_rule_name(pi.rule_id);
	return RULE_NOT_MATCH;
}

/* ── Rule matching ──────────────────────────────────────────────────── */

int match_rules_all(const char *cmdline, char *tags, int tags_size)
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

/*
 * apply_rule_and_tags — единая точка назначения rule и обогащения tags.
 *
 * Логика (одинаковая для initial scan, exec, try_track_pid):
 *  1. match_rules_all(cmdline) — найти совпавшие rules
 *  2. tags_merge — добавить новые match'и к унаследованным tags (без дубликатов)
 *  3. start_tracking — назначить rule ТОЛЬКО если ещё нет (RULE_ID_NONE)
 *
 * cmdline — строка (пробел-разделённая, из cmdline_to_str).
 * Возвращает индекс первого совпавшего rule или -1.
 */
int apply_rule_and_tags(__u32 pid, const char *cmdline)
{
	char tags_buf[TAGS_MAX_LEN];
	int first = match_rules_all(cmdline, tags_buf, sizeof(tags_buf));

	/* Обогащаем tags независимо от наличия rule */
	if (first >= 0 && !rules[first].ignore)
		tags_merge_ts(pid, tags_buf);

	/* Назначаем rule только если ещё нет */
	struct proc_info pi;
	int in_map = is_pid_in_proc_map(pid, &pi);
	if (first >= 0 && !rules[first].ignore && in_map && pi.rule_id == RULE_ID_NONE) {
		start_tracking(pid, first, pid, 1);
		LOG_DEBUG(cfg.log_level, "RULE: pid=%u rule=%s cmdline=%.60s",
			  pid, rules[first].name, cmdline);
	}

	return first;
}

/*
 * ensure_tags_from_cmdline — матчит теги по готовому cmdline (raw, NUL-separated).
 * Общая логика для ensure_tags и ensure_tags_bpf_event.
 */
void ensure_tags_from_cmdline(__u32 tgid, char *buf, int buflen, const char *cmdline_raw,
			      int cmdline_len)
{
	if (cmdline_len <= 0)
		return;

	char cmdline_str[CMDLINE_MAX + 1];
	int clen = cmdline_len < CMDLINE_MAX ? cmdline_len : CMDLINE_MAX - 1;
	cmdline_to_str(cmdline_raw, (__u16)clen, cmdline_str, sizeof(cmdline_str));

	char tags_buf[TAGS_MAX_LEN];
	if (match_rules_all(cmdline_str, tags_buf, sizeof(tags_buf)) >= 0) {
		tags_merge_ts(tgid, tags_buf);
		tags_lookup_ts(tgid, buf, buflen);
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
