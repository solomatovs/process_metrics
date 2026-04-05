/*
 * pm_rules.h — правила трекинга и теги процессов.
 *
 * Функции сопоставления процессов с правилами конфигурации,
 * хеш-таблица тегов (pipe-separated списки совпавших правил).
 */

#ifndef PM_RULES_H
#define PM_RULES_H

#include "process_metrics_common.h"
#include "event_file.h"

/* ── Tags (thread-safe wrappers) ────────────────────────────────────── */
void tags_lookup_ts(__u32 tgid, char *buf, int buflen);
void tags_inherit_ts(__u32 child, __u32 parent);
void tags_merge_ts(__u32 tgid, const char *new_tags);
void tags_remove_ts(__u32 tgid);
void tags_clear_ts(void);

/* ── Fill helpers ────────────────────────────────────────────────────── */
void fill_tags(struct metric_event *cev, __u32 tgid);
void ensure_tags(__u32 tgid, char *buf, int buflen);

/* ── Rule matching ──────────────────────────────────────────────────── */
int  match_rules_all(const char *cmdline, char *tags, int tags_size);
int  apply_rule_and_tags(__u32 pid, const char *cmdline);
void ensure_tags_from_cmdline(__u32 tgid, char *buf, int buflen,
			      const char *cmdline_raw, int cmdline_len);

/* ── Rule resolve ───────────────────────────────────────────────────── */
const char *resolve_rule_name(__u16 rule_id);
const char *resolve_rule_for_pid(__u32 tgid);
const char *resolve_rule_for_proc_event(const struct event *e);

/* ── Extern from process_metrics.c (needed by pm_rules.c) ──────────── */
void start_tracking(__u32 pid, int rule_id, __u32 root_pid, __u8 is_root);

#endif /* PM_RULES_H */
