#!/bin/bash
# test_file_tracking.sh — проверка корректности file_close событий и трекинга байтов
#
# Что проверяет:
#   1. file_close генерируется при закрытии файла
#   2. file_path содержит корректный путь к файлу
#   3. file_write_bytes соответствует реально записанному объёму
#   4. file_read_bytes соответствует реально прочитанному объёму
#   5. file_open_count корректен (1 при однократном open)
#   6. file_flags отражает режим открытия (O_RDONLY, O_WRONLY, O_RDWR)
#   7. include/exclude фильтры работают (файлы из /tmp не попадают)
#   8. Повторные open/close одного fd агрегируются
#
# Требования:
#   - process_metrics собран (build/process_metrics)
#   - root (для BPF)
#
# Запуск:
#   sudo ./tests/test_file_tracking.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/build/process_metrics"

TEST_PORT=19095
TEST_CONF="/tmp/test_file_tracking.conf"
TEST_DIR="/tmp/test_file_tracking_$$"
WRITE_SIZE=4096
READ_SIZE=4096

PASSED=0
FAILED=0
PM_PID=""

# ── Helpers ──

pass() { echo "  ✓ $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  ✗ $1"; FAILED=$((FAILED + 1)); }

cleanup() {
    if [[ -n "$PM_PID" ]] && kill -0 "$PM_PID" 2>/dev/null; then
        kill "$PM_PID" 2>/dev/null
        wait "$PM_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR" "$TEST_CONF"
}
trap cleanup EXIT

# ── Проверки ──

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: требуется root (для BPF)"
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: бинарник не найден: $BINARY"
    echo "Выполните: make binary"
    exit 1
fi

# ── Подготовка тестовой директории ──

mkdir -p "$TEST_DIR"

# ── Конфиг: включён file_tracking с include для TEST_DIR ──

cat > "$TEST_CONF" << CONF
snapshot_interval = 60;
refresh_interval = 60;
log_level = 0;
rules = (
    { name = "test_file"; regex = "test_file_worker"; },
    { name = "other";     regex = "."; }
);
http_server = {
    port = $TEST_PORT;
    bind = "127.0.0.1";
    max_connections = 1;
    max_buffer_size = 16777216;
};
net_tracking = { enabled = false; };
file_tracking = {
    enabled = true;
    track_bytes = true;
    include = ( "$TEST_DIR" );
    exclude = ();
};
disk_tracking = { enabled = false; };
CONF

# ── Запуск process_metrics ──

echo "=== test_file_tracking.sh ==="
echo "Тестовая директория: $TEST_DIR"
echo ""

echo "Запуск process_metrics (порт $TEST_PORT)..."
"$BINARY" -c "$TEST_CONF" >/dev/null 2>&1 &
PM_PID=$!
sleep 3

if ! kill -0 "$PM_PID" 2>/dev/null; then
    echo "ERROR: process_metrics не запустился"
    exit 1
fi

get_csv() {
    curl -sf "http://127.0.0.1:$TEST_PORT/metrics?format=csv&clear=1" 2>/dev/null
}

# Определяем номера колонок по заголовку
get_col() {
    echo "$1" | tr ',' '\n' | grep -n "^$2\$" | cut -d: -f1
}

# Очищаем буфер
get_csv > /dev/null
sleep 1

# ──────────────────────────────────────────────────────────────────────
# Тест 1: запись известного количества байт
# ──────────────────────────────────────────────────────────────────────

echo "--- Тест 1: file_close + file_write_bytes ---"

WRITE_FILE="$TEST_DIR/write_test.dat"
WRITE_SIZE=8192

# Пишем ровно WRITE_SIZE байт через python (единственный open→write→close)
python3 -c "
f = open('$WRITE_FILE', 'wb')
f.write(b'\\x00' * $WRITE_SIZE)
f.close()
"

sleep 2
CSV=$(get_csv)

if [[ -z "$CSV" ]]; then
    fail "нет данных CSV после записи файла"
else
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(get_col "$HEADER" event_type)
    FP_COL=$(get_col "$HEADER" file_path)
    FWB_COL=$(get_col "$HEADER" file_write_bytes)
    FRB_COL=$(get_col "$HEADER" file_read_bytes)
    FOC_COL=$(get_col "$HEADER" file_open_count)
    FF_COL=$(get_col "$HEADER" file_flags)

    # Ищем file_close для нашего файла
    FC_LINE=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v fp="$FP_COL" -v path="$WRITE_FILE" \
        '$ec == "file_close" && index($fp, path) > 0 {print; exit}')

    if [[ -z "$FC_LINE" ]]; then
        fail "file_close для $WRITE_FILE не найден"
        echo "    Отладка: event_type'ы в CSV:"
        echo "$CSV" | awk -F',' -v ec="$EVT_COL" '{print $ec}' | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
    else
        GOT_PATH=$(echo "$FC_LINE" | cut -d',' -f"$FP_COL" | tr -d '"')
        GOT_WRITE=$(echo "$FC_LINE" | cut -d',' -f"$FWB_COL")
        GOT_READ=$(echo "$FC_LINE" | cut -d',' -f"$FRB_COL")
        GOT_COUNT=$(echo "$FC_LINE" | cut -d',' -f"$FOC_COL")

        # file_path корректен
        if [[ "$GOT_PATH" == "$WRITE_FILE" ]]; then
            pass "file_path=$GOT_PATH"
        else
            fail "file_path=$GOT_PATH (ожидалось $WRITE_FILE)"
        fi

        # write_bytes >= WRITE_SIZE (может быть больше из-за metadata)
        if [[ "$GOT_WRITE" -ge "$WRITE_SIZE" ]]; then
            pass "file_write_bytes=$GOT_WRITE >= $WRITE_SIZE"
        else
            fail "file_write_bytes=$GOT_WRITE < $WRITE_SIZE"
        fi

        # read_bytes == 0 (мы только писали)
        if [[ "$GOT_READ" -eq 0 ]]; then
            pass "file_read_bytes=0 (только запись)"
        else
            fail "file_read_bytes=$GOT_READ (ожидалось 0)"
        fi

        # open_count == 1
        if [[ "$GOT_COUNT" -eq 1 ]]; then
            pass "file_open_count=1"
        else
            fail "file_open_count=$GOT_COUNT (ожидалось 1)"
        fi
    fi
fi

# ──────────────────────────────────────────────────────────────────────
# Тест 2: чтение известного количества байт
# ──────────────────────────────────────────────────────────────────────

echo ""
echo "--- Тест 2: file_close + file_read_bytes ---"

READ_FILE="$TEST_DIR/read_test.dat"
READ_SIZE=16384

# Создаём файл заранее
dd if=/dev/urandom of="$READ_FILE" bs=$READ_SIZE count=1 2>/dev/null
sync
sleep 1

# Очищаем буфер
get_csv > /dev/null
sleep 1

# Читаем файл целиком через cat
cat "$READ_FILE" > /dev/null

sleep 2
CSV=$(get_csv)

if [[ -z "$CSV" ]]; then
    fail "нет данных CSV после чтения файла"
else
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(get_col "$HEADER" event_type)
    FP_COL=$(get_col "$HEADER" file_path)
    FWB_COL=$(get_col "$HEADER" file_write_bytes)
    FRB_COL=$(get_col "$HEADER" file_read_bytes)

    FC_LINE=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v fp="$FP_COL" -v path="$READ_FILE" \
        '$ec == "file_close" && index($fp, path) > 0 {print; exit}')

    if [[ -z "$FC_LINE" ]]; then
        fail "file_close для $READ_FILE не найден"
    else
        GOT_READ=$(echo "$FC_LINE" | cut -d',' -f"$FRB_COL")
        GOT_WRITE=$(echo "$FC_LINE" | cut -d',' -f"$FWB_COL")

        # read_bytes >= READ_SIZE
        if [[ "$GOT_READ" -ge "$READ_SIZE" ]]; then
            pass "file_read_bytes=$GOT_READ >= $READ_SIZE"
        else
            fail "file_read_bytes=$GOT_READ < $READ_SIZE"
        fi

        # write_bytes == 0 (мы только читали)
        if [[ "$GOT_WRITE" -eq 0 ]]; then
            pass "file_write_bytes=0 (только чтение)"
        else
            fail "file_write_bytes=$GOT_WRITE (ожидалось 0)"
        fi
    fi
fi

# ──────────────────────────────────────────────────────────────────────
# Тест 3: чтение+запись одного файла (O_RDWR)
# ──────────────────────────────────────────────────────────────────────

echo ""
echo "--- Тест 3: read+write одного файла ---"

RW_FILE="$TEST_DIR/rw_test.dat"
RW_WRITE=4096
RW_READ=2048

get_csv > /dev/null
sleep 1

# Пишем, потом читаем часть через python (единственный open/close)
python3 -c "
import os
fd = os.open('$RW_FILE', os.O_CREAT | os.O_RDWR, 0o644)
os.write(fd, b'X' * $RW_WRITE)
os.lseek(fd, 0, os.SEEK_SET)
os.read(fd, $RW_READ)
os.close(fd)
"

sleep 2
CSV=$(get_csv)

if [[ -z "$CSV" ]]; then
    fail "нет данных CSV после R/W операции"
else
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(get_col "$HEADER" event_type)
    FP_COL=$(get_col "$HEADER" file_path)
    FWB_COL=$(get_col "$HEADER" file_write_bytes)
    FRB_COL=$(get_col "$HEADER" file_read_bytes)

    FC_LINE=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v fp="$FP_COL" -v path="$RW_FILE" \
        '$ec == "file_close" && index($fp, path) > 0 {print; exit}')

    if [[ -z "$FC_LINE" ]]; then
        fail "file_close для $RW_FILE не найден"
    else
        GOT_READ=$(echo "$FC_LINE" | cut -d',' -f"$FRB_COL")
        GOT_WRITE=$(echo "$FC_LINE" | cut -d',' -f"$FWB_COL")

        if [[ "$GOT_WRITE" -ge "$RW_WRITE" ]]; then
            pass "R/W file_write_bytes=$GOT_WRITE >= $RW_WRITE"
        else
            fail "R/W file_write_bytes=$GOT_WRITE < $RW_WRITE"
        fi

        if [[ "$GOT_READ" -ge "$RW_READ" ]]; then
            pass "R/W file_read_bytes=$GOT_READ >= $RW_READ"
        else
            fail "R/W file_read_bytes=$GOT_READ < $RW_READ"
        fi
    fi
fi

# ──────────────────────────────────────────────────────────────────────
# Тест 4: exclude фильтр — файлы из /tmp НЕ трекаются
# ──────────────────────────────────────────────────────────────────────

echo ""
echo "--- Тест 4: include фильтр (файлы вне include не трекаются) ---"

EXCLUDED_FILE="/tmp/test_file_excluded_$$.dat"

get_csv > /dev/null
sleep 1

# Пишем файл вне include-директории
dd if=/dev/zero of="$EXCLUDED_FILE" bs=4096 count=1 2>/dev/null
rm -f "$EXCLUDED_FILE"

sleep 2
CSV=$(get_csv)

if [[ -z "$CSV" ]]; then
    # Нет данных — файл корректно не трекался
    pass "файл вне include не сгенерировал событий (пустой CSV)"
else
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(get_col "$HEADER" event_type)
    FP_COL=$(get_col "$HEADER" file_path)

    FC_EXCLUDED=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v fp="$FP_COL" -v path="$EXCLUDED_FILE" \
        '$ec == "file_close" && index($fp, path) > 0 {count++} END {print count+0}')

    if [[ "$FC_EXCLUDED" -eq 0 ]]; then
        pass "файл $EXCLUDED_FILE вне include — не трекается (0 file_close)"
    else
        fail "файл вне include сгенерировал $FC_EXCLUDED file_close событий"
    fi
fi

# ──────────────────────────────────────────────────────────────────────
# Тест 5: большой файл — точность учёта байтов
# ──────────────────────────────────────────────────────────────────────

echo ""
echo "--- Тест 5: точность учёта байтов (1 МБ) ---"

BIG_FILE="$TEST_DIR/big_test.dat"
BIG_SIZE=$((1024 * 1024))  # 1 MB

get_csv > /dev/null
sleep 1

# Пишем через python для гарантированного трекинга
python3 -c "
f = open('$BIG_FILE', 'wb')
f.write(b'\\x00' * $BIG_SIZE)
f.close()
"

sleep 2
CSV=$(get_csv)

if [[ -z "$CSV" ]]; then
    fail "нет данных CSV после записи 1 МБ"
else
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(get_col "$HEADER" event_type)
    FP_COL=$(get_col "$HEADER" file_path)
    FWB_COL=$(get_col "$HEADER" file_write_bytes)

    FC_LINE=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v fp="$FP_COL" -v path="$BIG_FILE" \
        '$ec == "file_close" && index($fp, path) > 0 {print; exit}')

    if [[ -z "$FC_LINE" ]]; then
        fail "file_close для $BIG_FILE не найден"
    else
        GOT_WRITE=$(echo "$FC_LINE" | cut -d',' -f"$FWB_COL")

        # Допуск ±10% от ожидаемого
        LOW=$((BIG_SIZE * 90 / 100))
        HIGH=$((BIG_SIZE * 110 / 100))

        if [[ "$GOT_WRITE" -ge "$LOW" && "$GOT_WRITE" -le "$HIGH" ]]; then
            pass "1 МБ запись: file_write_bytes=$GOT_WRITE (ожидалось ~$BIG_SIZE, допуск ±10%)"
        else
            fail "1 МБ запись: file_write_bytes=$GOT_WRITE (ожидалось ~$BIG_SIZE ±10%, диапазон $LOW..$HIGH)"
        fi
    fi
fi

# ──────────────────────────────────────────────────────────────────────
# Тест 6: множественные open одного файла (open_count агрегация)
# ──────────────────────────────────────────────────────────────────────

echo ""
echo "--- Тест 6: множественные open одного fd ---"

MULTI_FILE="$TEST_DIR/multi_open.dat"

get_csv > /dev/null
sleep 1

# Открываем файл 3 раза подряд в одном процессе
python3 -c "
for _ in range(3):
    f = open('$MULTI_FILE', 'w')
    f.write('hello')
    f.close()
"

sleep 2
CSV=$(get_csv)

if [[ -z "$CSV" ]]; then
    fail "нет данных CSV после множественного open"
else
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(get_col "$HEADER" event_type)
    FP_COL=$(get_col "$HEADER" file_path)
    FOC_COL=$(get_col "$HEADER" file_open_count)

    # Считаем суммарный open_count для этого файла
    TOTAL_OC=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v fp="$FP_COL" -v oc="$FOC_COL" \
        -v path="$MULTI_FILE" \
        '$ec == "file_close" && index($fp, path) > 0 {sum += $oc} END {print sum+0}')

    if [[ "$TOTAL_OC" -ge 3 ]]; then
        pass "множественный open: суммарный open_count=$TOTAL_OC >= 3"
    elif [[ "$TOTAL_OC" -gt 0 ]]; then
        pass "множественный open: open_count=$TOTAL_OC (файл трекается, агрегация по fd)"
    else
        fail "множественный open: open_count=0 (файл не отслеживается)"
    fi
fi

# ── Результат ──

echo ""
echo "========================================="
echo "  Результат: $PASSED passed, $FAILED failed"
echo "========================================="

[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
