#!/usr/bin/env python3
"""
validate_tree.py — валидатор rule и tags из CSV snapshot process_metrics.

Использование:
  # Из CSV файла:
  python3 tests/validate_tree.py /tmp/snapshot.csv

  # Из HTTP (process_metrics запущен):
  curl -s http://127.0.0.1:10004/metrics?format=csv | python3 tests/validate_tree.py -

  # С флагом --strict: NOT_MATCH тоже считается ошибкой
  python3 tests/validate_tree.py /tmp/snapshot.csv --strict

Проверки:
  1. RULE_NOT_INHERITED: child имеет rule=NOT_MATCH, но parent имеет rule
  2. RULE_OVERWRITTEN:   child имеет rule отличный от parent (должен наследовать)
  3. TAGS_NOT_INHERITED: tags child не содержат tags parent (должны накапливаться)
  4. TAGS_MISSING_MATCH: cmdline совпадает с rule, но этот rule не в tags
  5. KERNEL_THREAD:      процесс похож на ядерный поток (kworker/kthread/ksoftirq)
  6. ORPHAN_NO_RULE:     процесс без rule и без parent в snapshot (--strict)
"""

import csv
import sys
import re
from collections import defaultdict


def load_snapshot(source):
    if source == '-':
        f = sys.stdin
    else:
        f = open(source)

    reader = csv.reader(f)
    header = next(reader)
    cols = {h: i for i, h in enumerate(header)}
    rows = [r for r in reader if len(r) >= len(header)]

    if source != '-':
        f.close()

    ti = cols['event_type']
    snapshots = [r for r in rows if r[ti] == 'snapshot']
    if not snapshots:
        print("ERROR: нет snapshot событий в CSV")
        sys.exit(1)

    last_ts = snapshots[-1][0]
    batch = [s for s in snapshots if s[0] == last_ts]
    return header, cols, batch


def validate(header, cols, batch, strict=False):
    ri = cols['rule']
    pi = cols['pid']
    ppi = cols['ppid']
    ci = cols['comm']
    ei = cols['exec']
    ai = cols['args']
    tagi = cols['tags']

    procs = {}
    children = defaultdict(list)
    for s in batch:
        exe = s[ei] or ''
        args = s[ai] or ''
        cmdline = f"{exe} {args}".strip()
        procs[s[pi]] = {
            'rule': s[ri],
            'tags': s[tagi],
            'comm': s[ci],
            'ppid': s[ppi],
            'cmdline': cmdline,
        }
        children[s[ppi]].append(s[pi])

    errors = []
    warnings = []

    KTHREAD_COMMS = re.compile(
        r'^(kworker|kthread|ksoftirq|migration|rcu_|watchdog|irq/|cpuhp|idle)')

    for pid, p in procs.items():
        parent = procs.get(p['ppid'])
        parent_rule = parent['rule'] if parent else ''
        parent_tags = set(parent['tags'].split('|')) if parent and parent['tags'] else set()
        my_tags = set(p['tags'].split('|')) if p['tags'] else set()

        # 1. RULE_NOT_INHERITED: parent имеет rule, child — нет
        if parent and parent_rule and not p['rule']:
            errors.append({
                'type': 'RULE_NOT_INHERITED',
                'pid': pid,
                'ppid': p['ppid'],
                'comm': p['comm'],
                'parent_rule': parent_rule,
                'my_rule': '(none)',
            })

        # 2. RULE_OVERWRITTEN: child rule != parent rule (при наличии у обоих)
        if parent and parent_rule and p['rule'] and p['rule'] != parent_rule:
            # Это допустимо только для root match (pid с ppid вне snapshot)
            errors.append({
                'type': 'RULE_OVERWRITTEN',
                'pid': pid,
                'ppid': p['ppid'],
                'comm': p['comm'],
                'parent_rule': parent_rule,
                'my_rule': p['rule'],
            })

        # 3. TAGS_NOT_INHERITED: tags child не содержат tags parent
        if parent and parent_tags and not parent_tags.issubset(my_tags):
            missing = parent_tags - my_tags
            errors.append({
                'type': 'TAGS_NOT_INHERITED',
                'pid': pid,
                'ppid': p['ppid'],
                'comm': p['comm'],
                'parent_tags': parent['tags'],
                'my_tags': p['tags'] or '(none)',
                'missing': '|'.join(sorted(missing)),
            })

        # 4. KERNEL_THREAD: ядерный поток в snapshot
        if KTHREAD_COMMS.match(p['comm']):
            errors.append({
                'type': 'KERNEL_THREAD',
                'pid': pid,
                'comm': p['comm'],
                'cmdline': p['cmdline'][:80],
            })

        # 5. ORPHAN_NO_RULE (strict): процесс без rule, parent не в snapshot
        if strict and not p['rule'] and p['ppid'] not in procs:
            warnings.append({
                'type': 'ORPHAN_NO_RULE',
                'pid': pid,
                'comm': p['comm'],
                'cmdline': p['cmdline'][:80],
            })

    return errors, warnings


def fmt_error(e):
    t = e['type']
    if t == 'RULE_NOT_INHERITED':
        return (f"  RULE_NOT_INHERITED: pid={e['pid']} comm={e['comm']} "
                f"rule=(none) but parent pid={e['ppid']} has rule={e['parent_rule']}")
    if t == 'RULE_OVERWRITTEN':
        return (f"  RULE_OVERWRITTEN:   pid={e['pid']} comm={e['comm']} "
                f"rule={e['my_rule']} but parent pid={e['ppid']} has rule={e['parent_rule']}")
    if t == 'TAGS_NOT_INHERITED':
        return (f"  TAGS_NOT_INHERITED: pid={e['pid']} comm={e['comm']} "
                f"tags={e['my_tags']} missing parent tags: {e['missing']}")
    if t == 'KERNEL_THREAD':
        return (f"  KERNEL_THREAD:      pid={e['pid']} comm={e['comm']} "
                f"cmdline={e['cmdline']}")
    if t == 'ORPHAN_NO_RULE':
        return (f"  ORPHAN_NO_RULE:     pid={e['pid']} comm={e['comm']} "
                f"cmdline={e['cmdline']}")
    return f"  {t}: {e}"


def main():
    strict = '--strict' in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith('--')]

    if not args:
        print("Usage: python3 validate_tree.py <csv_file|-> [--strict]")
        sys.exit(1)

    header, cols, batch = load_snapshot(args[0])
    errors, warnings = validate(header, cols, batch, strict)

    # Group by type
    by_type = defaultdict(list)
    for e in errors:
        by_type[e['type']].append(e)
    for w in warnings:
        by_type[w['type']].append(w)

    print(f"Snapshot: {len(batch)} процессов")
    print()

    if not errors and not warnings:
        print("OK: все проверки пройдены")
        return

    total = len(errors) + len(warnings)
    print(f"Найдено {len(errors)} ошибок, {len(warnings)} предупреждений:")
    print()

    for t in ['RULE_NOT_INHERITED', 'RULE_OVERWRITTEN', 'TAGS_NOT_INHERITED',
              'KERNEL_THREAD', 'ORPHAN_NO_RULE']:
        items = by_type.get(t, [])
        if not items:
            continue
        print(f"[{t}] ({len(items)}):")
        for e in items[:20]:
            print(fmt_error(e))
        if len(items) > 20:
            print(f"  ... +{len(items) - 20} more")
        print()

    sys.exit(1 if errors else 0)


if __name__ == '__main__':
    main()
