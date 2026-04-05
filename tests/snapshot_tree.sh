#!/bin/bash
# snapshot_tree.sh — снимок дерева процессов с rule и tags
#
# Два режима:
#   1. Полный цикл (запуск process_metrics + snapshot + отчёт):
#      sudo ./tests/snapshot_tree.sh
#      sudo ./tests/snapshot_tree.sh -c examples/process_metrics.conf
#
#   2. Только отчёт (process_metrics уже запущен):
#      ./tests/snapshot_tree.sh --report-only
#      ./tests/snapshot_tree.sh --report-only -p 10004
#
# Опции:
#   -c CONFIG    конфиг (по умолчанию examples/process_metrics.conf)
#   -p PORT      HTTP порт (по умолчанию определяется из конфига)
#   -w SECONDS   ожидание после запуска (по умолчанию 15)
#   -o FILE      файл отчёта (по умолчанию /tmp/process_tree_report.txt)
#   --report-only  не запускать/останавливать process_metrics
#   --no-stop      не останавливать process_metrics после отчёта

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/build/process_metrics"
CONF="$PROJECT_DIR/examples/process_metrics.conf"
PORT=""
WAIT=15
OUTPUT="/tmp/process_tree_report.txt"
REPORT_ONLY=0
NO_STOP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c) CONF="$2"; shift 2 ;;
        -p) PORT="$2"; shift 2 ;;
        -w) WAIT="$2"; shift 2 ;;
        -o) OUTPUT="$2"; shift 2 ;;
        --report-only) REPORT_ONLY=1; shift ;;
        --no-stop) NO_STOP=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Определяем порт из конфига если не задан
if [[ -z "$PORT" ]]; then
    PORT=$(grep -oP 'port\s*=\s*\K[0-9]+' "$CONF" 2>/dev/null | head -1)
    PORT="${PORT:-10003}"
fi

URL="http://127.0.0.1:${PORT}/metrics?format=csv"

if [[ "$REPORT_ONLY" -eq 0 ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: полный режим требует sudo (BPF программы)"
        exit 1
    fi

    if [[ ! -x "$BINARY" ]]; then
        echo "ERROR: бинарник не найден: $BINARY"
        echo "Запустите: make all"
        exit 1
    fi

    echo "Останавливаю предыдущий экземпляр..."
    killall process_metrics 2>/dev/null || true
    sleep 1

    echo "Запускаю: $BINARY -c $CONF"
    "$BINARY" -c "$CONF" >/dev/null 2>&1 &
    PM_PID=$!

    echo "Ожидаю ${WAIT}с (init scan + первые snapshot'ы)..."
    sleep "$WAIT"

    # Проверяем что процесс жив
    if ! kill -0 "$PM_PID" 2>/dev/null; then
        echo "ERROR: process_metrics завершился"
        exit 1
    fi
fi

echo "Собираю snapshot с $URL ..."
CSV=$(mktemp /tmp/pm_snapshot_XXXXXX.csv)
curl -sf "$URL" > "$CSV"
LINES=$(wc -l < "$CSV")

if [[ "$LINES" -lt 2 ]]; then
    echo "ERROR: пустой ответ от HTTP ($LINES строк)"
    echo "Проверьте: curl -s '$URL' | head"
    rm -f "$CSV"
    exit 1
fi

echo "Получено $LINES строк CSV, генерирую отчёт..."

python3 << PYEOF
import csv
from collections import defaultdict

with open('$CSV') as f:
    reader = csv.reader(f)
    header = next(reader)
    cols = {h: i for i, h in enumerate(header)}
    rows = [r for r in reader if len(r) >= len(header)]

ti, ri, pi, ppi, ci, ei, ai, tagi = (
    cols['event_type'], cols['rule'], cols['pid'], cols['ppid'],
    cols['comm'], cols['exec'], cols['args'], cols['tags'])

snapshots = [r for r in rows if r[ti] == 'snapshot']
if not snapshots:
    print("ERROR: нет snapshot событий в CSV")
    exit(1)

last_ts = snapshots[-1][0]
batch = [s for s in snapshots if s[0] == last_ts]

procs = {}
children = defaultdict(list)
for s in batch:
    exe = s[ei] or ''; args = s[ai] or ''
    cmdline = f"{exe} {args}".strip()
    if len(cmdline) > 60: cmdline = cmdline[:57] + "..."
    if not cmdline: cmdline = s[ci]
    procs[s[pi]] = {'rule': s[ri] or '(no rule)', 'tags': s[tagi] or '—',
                    'comm': s[ci], 'ppid': s[ppi], 'cmdline': cmdline}
    children[s[ppi]].append(s[pi])

out = []

def ptree(pid, prefix='', is_last=True, maxd=99, d=0):
    if pid not in procs or d > maxd: return
    p = procs[pid]
    conn = '' if d == 0 else ('└── ' if is_last else '├── ')
    lp = '' if d == 0 else prefix
    out.append(f"{lp}{conn}{p['comm']:18s} rule={p['rule']:16s} tags={p['tags']:50s} {p['cmdline']}")
    kids = sorted(children.get(pid, []), key=lambda x: int(x))
    cp = '' if d == 0 else (prefix + ('    ' if is_last else '│   '))
    for i, c in enumerate(kids):
        ptree(c, cp, i == len(kids) - 1, maxd, d + 1)

all_pids = set(procs.keys())
roots = sorted([pid for pid, p in procs.items() if p['ppid'] not in all_pids],
               key=lambda x: int(x))

out.append('=' * 160)
out.append(f'ДЕРЕВО ПРОЦЕССОВ  |  {last_ts}  |  {len(batch)} процессов')
out.append('=' * 160)
out.append('')

for root in roots:
    ptree(root)
    out.append('')

out.append('=' * 160)
out.append('СТАТИСТИКА')
out.append('=' * 160)

rules = defaultdict(int)
for s in batch:
    rules[s[ri] if s[ri] else '(no rule)'] += 1
out.append(f'Всего процессов: {len(batch)}')
out.append('')
out.append('Распределение rule:')
for r, c in sorted(rules.items(), key=lambda x: -x[1]):
    out.append(f'  {r:20s} {c:>4d}')

out.append('')
combos = defaultdict(int)
for pid, p in procs.items():
    combos[p['tags']] += 1
out.append('Комбинации tags:')
for t, c in sorted(combos.items(), key=lambda x: -x[1]):
    out.append(f'  {c:>4d}  {t}')

with open('$OUTPUT', 'w') as f:
    f.write('\n'.join(out) + '\n')

print(f"Отчёт: $OUTPUT ({len(out)} строк, {len(batch)} процессов)")
PYEOF

rm -f "$CSV"

if [[ "$REPORT_ONLY" -eq 0 && "$NO_STOP" -eq 0 ]]; then
    echo "Останавливаю process_metrics..."
    kill "$PM_PID" 2>/dev/null
    wait "$PM_PID" 2>/dev/null || true
fi

echo "Готово."
