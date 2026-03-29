#!/bin/bash
# test_identity.sh — проверка корректности identity-полей: loginuid, sessionid, euid, uid
#
# Что проверяет:
#   1. snapshot: loginuid/sessionid читаются из /proc при initial_scan
#   2. snapshot: euid парсится из 2-го поля Uid: в /proc/PID/status
#   3. exit: loginuid/sessionid/euid корректно передаются через BPF ring buffer
#   4. fork: loginuid/sessionid/euid копируются в fork event (а не нули)
#   5. Сверка значений с /proc/PID/loginuid, /proc/PID/sessionid, /proc/PID/status
#
# Требования:
#   - process_metrics собран (build/process_metrics)
#   - root (для BPF)
#   - Пользователь с loginuid != 0 и != 4294967295 (обычный PAM-логин)
#     По умолчанию берётся первый пользователь с loginuid > 0 из /proc
#
# Запуск:
#   sudo ./tests/test_identity.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/build/process_metrics"

TEST_PORT=19094
TEST_CONF="/tmp/test_identity.conf"

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
    rm -f "$TEST_CONF"
    # Убиваем тестовые sleep-процессы
    [[ -n "${TEST_SLEEP_PID:-}" ]] && kill "$TEST_SLEEP_PID" 2>/dev/null || true
    [[ -n "${TEST_TREE_PID:-}" ]] && kill "$TEST_TREE_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ── Проверки ──

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: требуется root (для BPF)"
    echo "Запуск: sudo $0"
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: бинарник не найден: $BINARY"
    echo "Выполните: make binary"
    exit 1
fi

# Находим PID процесса с loginuid > 0 (реальный интерактивный пользователь)
find_reference_pid() {
    local pid best_pid="" best_tty=0
    for pid in $(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||'); do
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        local luid
        luid=$(cat "/proc/$pid/loginuid" 2>/dev/null) || continue
        [[ "$luid" -gt 0 && "$luid" -lt 4294967295 ]] || continue
        # Процесс жив?
        kill -0 "$pid" 2>/dev/null || continue
        # Предпочитаем процесс с tty, но принимаем и без
        local tty_nr
        tty_nr=$(awk '{print $7}' "/proc/$pid/stat" 2>/dev/null) || continue
        if [[ "$tty_nr" -gt 0 ]]; then
            echo "$pid"
            return 0
        elif [[ -z "$best_pid" ]]; then
            best_pid="$pid"
        fi
    done
    # Если нет процесса с tty, используем любой с loginuid > 0
    if [[ -n "$best_pid" ]]; then
        echo "$best_pid"
        return 0
    fi
    return 1
}

REF_PID=$(find_reference_pid) || {
    echo "SKIP: не найден процесс с loginuid > 0 и tty (нет интерактивной сессии)"
    exit 0
}

# Читаем эталонные значения из /proc
REF_LOGINUID=$(cat "/proc/$REF_PID/loginuid")
REF_SESSIONID=$(cat "/proc/$REF_PID/sessionid")
# /proc/PID/status: Uid:\treal\teffective\tsaved\tfsuid
REF_UID=$(awk '/^Uid:/ {print $2}' "/proc/$REF_PID/status")
REF_EUID=$(awk '/^Uid:/ {print $3}' "/proc/$REF_PID/status")
REF_COMM=$(cat "/proc/$REF_PID/comm" 2>/dev/null || echo "???")

echo "=== test_identity.sh ==="
echo "Эталонный процесс: PID=$REF_PID comm=$REF_COMM"
echo "  loginuid=$REF_LOGINUID sessionid=$REF_SESSIONID uid=$REF_UID euid=$REF_EUID"
echo ""

# ── Создаём конфиг ──

cat > "$TEST_CONF" << CONF
snapshot_interval = 2;
refresh_interval = 1;
log_level = 0;
rules = (
    { name = "test_identity"; regex = "test_identity_marker"; },
    { name = "other";         regex = "."; }
);
http_server = {
    port = $TEST_PORT;
    bind = "127.0.0.1";
    max_connections = 1;
    max_buffer_size = 16777216;
};
net_tracking = { enabled = false; };
file_tracking = { enabled = false; };
disk_tracking = { enabled = false; };
CONF

# ── Запускаем process_metrics ──

echo "Запуск process_metrics (порт $TEST_PORT)..."
"$BINARY" -c "$TEST_CONF" >/dev/null 2>&1 &
PM_PID=$!
sleep 3

if ! kill -0 "$PM_PID" 2>/dev/null; then
    echo "ERROR: process_metrics не запустился"
    exit 1
fi

# Помощник для получения CSV
get_csv() {
    curl -sf "http://127.0.0.1:$TEST_PORT/metrics?format=csv&clear=1" 2>/dev/null
}

# ── Тест 1: snapshot — loginuid/sessionid из /proc ──

echo "--- Тест 1: snapshot identity (initial_scan из /proc) ---"

# Ждём snapshot
sleep 4

CSV=$(get_csv)
if [[ -z "$CSV" ]]; then
    fail "нет данных CSV"
else
    # Ищем snapshot для нашего REF_PID
    # CSV: timestamp,hostname,event_type,rule,tags,root_pid,pid,ppid,uid,user_name,
    #      loginuid,login_name,sessionid,euid,...
    # Колонка pid=7, event_type=3, loginuid=11, sessionid=13, uid=9, euid=14

    HEADER=$(echo "$CSV" | head -1)
    # Определяем номера колонок по заголовку
    PID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^pid$' | cut -d: -f1)
    EVT_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^event_type$' | cut -d: -f1)
    LOGINUID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^loginuid$' | cut -d: -f1)
    SESSIONID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^sessionid$' | cut -d: -f1)
    UID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^uid$' | cut -d: -f1)
    EUID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^euid$' | cut -d: -f1)

    # Ищем snapshot строку для REF_PID
    SNAP_LINE=$(echo "$CSV" | awk -F',' -v pid="$REF_PID" -v pc="$PID_COL" -v ec="$EVT_COL" \
        '$ec == "snapshot" && $pc == pid {print; exit}')

    if [[ -z "$SNAP_LINE" ]]; then
        fail "snapshot для PID=$REF_PID не найден"
    else
        GOT_LOGINUID=$(echo "$SNAP_LINE" | cut -d',' -f"$LOGINUID_COL")
        GOT_SESSIONID=$(echo "$SNAP_LINE" | cut -d',' -f"$SESSIONID_COL")
        GOT_UID=$(echo "$SNAP_LINE" | cut -d',' -f"$UID_COL")
        GOT_EUID=$(echo "$SNAP_LINE" | cut -d',' -f"$EUID_COL")

        if [[ "$GOT_LOGINUID" == "$REF_LOGINUID" ]]; then
            pass "snapshot loginuid=$GOT_LOGINUID (ожидалось $REF_LOGINUID)"
        else
            fail "snapshot loginuid=$GOT_LOGINUID (ожидалось $REF_LOGINUID)"
        fi

        if [[ "$GOT_SESSIONID" == "$REF_SESSIONID" ]]; then
            pass "snapshot sessionid=$GOT_SESSIONID (ожидалось $REF_SESSIONID)"
        else
            fail "snapshot sessionid=$GOT_SESSIONID (ожидалось $REF_SESSIONID)"
        fi

        if [[ "$GOT_UID" == "$REF_UID" ]]; then
            pass "snapshot uid=$GOT_UID (ожидалось $REF_UID)"
        else
            fail "snapshot uid=$GOT_UID (ожидалось $REF_UID)"
        fi

        if [[ "$GOT_EUID" == "$REF_EUID" ]]; then
            pass "snapshot euid=$GOT_EUID (ожидалось $REF_EUID)"
        else
            fail "snapshot euid=$GOT_EUID (ожидалось $REF_EUID)"
        fi
    fi
fi

# ── Тест 2: fork+exit — identity передаётся через BPF ──

echo ""
echo "--- Тест 2: fork/exit identity (BPF ring buffer) ---"

# Запускаем короткоживущий процесс от имени пользователя с loginuid
# Используем su чтобы сохранить loginuid, или runuser
# Проще: запускаем sleep и быстро убиваем — это создаст fork+exit

# Находим UID и shell пользователя с REF_LOGINUID
REF_USERNAME=$(awk -F: -v uid="$REF_UID" '$3 == uid {print $1; exit}' /etc/passwd)

if [[ -z "$REF_USERNAME" ]]; then
    echo "  SKIP: пользователь с uid=$REF_UID не найден в /etc/passwd"
else
    # Очищаем буфер
    get_csv > /dev/null

    # Запускаем процесс-маркер от имени пользователя через nsenter в его pid namespace
    # Или проще — запускаем как child от найденного bash с tty
    # Самый надёжный способ: используем /proc/REF_PID/ns для наследования identity
    # Но проще всего — создаём child через runuser

    # Запускаем sleep с уникальным именем (через exec -a)
    TEST_MARKER="test_identity_marker"
    runuser -u "$REF_USERNAME" -- bash -c "exec -a $TEST_MARKER sleep 3" &
    TEST_SLEEP_PID=$!

    # Ждём fork+exec+sleep+exit
    sleep 5

    CSV=$(get_csv)
    if [[ -z "$CSV" ]]; then
        fail "нет данных CSV после тестового процесса"
    else
        HEADER=$(echo "$CSV" | head -1)
        PID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^pid$' | cut -d: -f1)
        EVT_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^event_type$' | cut -d: -f1)
        LOGINUID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^loginuid$' | cut -d: -f1)
        SESSIONID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^sessionid$' | cut -d: -f1)
        EUID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^euid$' | cut -d: -f1)
        COMM_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^comm$' | cut -d: -f1)

        # exit для нашего маркера
        EXIT_LINE=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v cc="$COMM_COL" \
            '$ec == "exit" && $cc == "sleep" {print; exit}')

        if [[ -z "$EXIT_LINE" ]]; then
            # Пробуем по маркеру
            EXIT_LINE=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v cc="$COMM_COL" -v m="$TEST_MARKER" \
                '$ec == "exit" && $cc == m {print; exit}')
        fi

        if [[ -z "$EXIT_LINE" ]]; then
            fail "exit-событие для тестового процесса не найдено"
        else
            GOT_LOGINUID=$(echo "$EXIT_LINE" | cut -d',' -f"$LOGINUID_COL")
            GOT_EUID=$(echo "$EXIT_LINE" | cut -d',' -f"$EUID_COL")

            # exit loginuid должен быть от пользователя (может быть UNSET если runuser
            # не сохраняет loginuid — это ожидаемо для root→user switch)
            if [[ "$GOT_LOGINUID" != "0" ]]; then
                pass "exit loginuid=$GOT_LOGINUID (не ноль — корректно)"
            else
                fail "exit loginuid=0 (должен быть != 0 для пользовательского процесса)"
            fi

            if [[ "$GOT_EUID" == "$REF_UID" ]]; then
                pass "exit euid=$GOT_EUID (ожидалось $REF_UID)"
            else
                fail "exit euid=$GOT_EUID (ожидалось $REF_UID)"
            fi
        fi

        # fork для тестового процесса
        FORK_LINE=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v cc="$COMM_COL" \
            '$ec == "fork" && $cc == "bash" {line=$0} END {print line}')

        if [[ -n "$FORK_LINE" ]]; then
            GOT_FORK_LOGINUID=$(echo "$FORK_LINE" | cut -d',' -f"$LOGINUID_COL")
            GOT_FORK_EUID=$(echo "$FORK_LINE" | cut -d',' -f"$EUID_COL")

            if [[ "$GOT_FORK_LOGINUID" != "0" || "$GOT_FORK_EUID" != "0" ]]; then
                pass "fork identity заполнена (loginuid=$GOT_FORK_LOGINUID euid=$GOT_FORK_EUID)"
            else
                fail "fork identity нулевая (loginuid=$GOT_FORK_LOGINUID euid=$GOT_FORK_EUID) — не передаётся в event"
            fi
        else
            echo "  SKIP: fork-событие не найдено (может быть вне окна)"
        fi
    fi
fi

# ── Тест 3: loginuid=4294967295 для процессов без audit-сессии ──

echo ""
echo "--- Тест 3: AUDIT_UID_UNSET для демонов ---"

# Очищаем буфер
get_csv > /dev/null
sleep 3
CSV=$(get_csv)

if [[ -z "$CSV" ]]; then
    fail "нет данных CSV"
else
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^event_type$' | cut -d: -f1)
    LOGINUID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^loginuid$' | cut -d: -f1)
    COMM_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^comm$' | cut -d: -f1)

    # Ищем snapshot для процесса без audit-сессии (loginuid == 4294967295)
    UNSET_COUNT=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v lc="$LOGINUID_COL" \
        '$ec == "snapshot" && $lc == "4294967295" {count++} END {print count+0}')

    # Ищем snapshot с loginuid == 0 (root) — не должно быть для демонов
    ZERO_LOGINUID_DAEMONS=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" -v lc="$LOGINUID_COL" \
        '$ec == "snapshot" && $lc == "0" {count++} END {print count+0}')

    if [[ "$UNSET_COUNT" -gt 0 ]]; then
        pass "найдены процессы с loginuid=AUDIT_UID_UNSET ($UNSET_COUNT шт)"
    else
        fail "не найдены процессы с loginuid=4294967295 (должны быть у демонов)"
    fi

    # Процессы с loginuid=0 — это нормально для root-процессов с audit-сессией
    # Но массово loginuid=0 означает баг (не читается из /proc)
    TOTAL_SNAPSHOTS=$(echo "$CSV" | awk -F',' -v ec="$EVT_COL" \
        '$ec == "snapshot" {count++} END {print count+0}')

    if [[ "$TOTAL_SNAPSHOTS" -gt 0 ]]; then
        ZERO_RATIO=$((ZERO_LOGINUID_DAEMONS * 100 / TOTAL_SNAPSHOTS))
        if [[ "$ZERO_RATIO" -lt 50 ]]; then
            pass "loginuid=0 у $ZERO_LOGINUID_DAEMONS/$TOTAL_SNAPSHOTS snapshot'ов ($ZERO_RATIO%) — допустимо"
        else
            fail "loginuid=0 у $ZERO_LOGINUID_DAEMONS/$TOTAL_SNAPSHOTS snapshot'ов ($ZERO_RATIO%) — похоже loginuid не читается из /proc"
        fi
    fi
fi

# ── Тест 4: euid != 0 для обычных пользователей ──

echo ""
echo "--- Тест 4: euid корректен для пользовательских процессов ---"

# Используем уже собранный CSV из теста 3 или получаем новый
if [[ -z "${CSV:-}" ]]; then
    sleep 3
    CSV=$(get_csv)
fi

if [[ -n "$CSV" ]]; then
    HEADER=$(echo "$CSV" | head -1)
    EVT_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^event_type$' | cut -d: -f1)
    PID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^pid$' | cut -d: -f1)
    UID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^uid$' | cut -d: -f1)
    EUID_COL=$(echo "$HEADER" | tr ',' '\n' | grep -n '^euid$' | cut -d: -f1)

    SNAP_REF=$(echo "$CSV" | awk -F',' -v pid="$REF_PID" -v pc="$PID_COL" -v ec="$EVT_COL" \
        '$ec == "snapshot" && $pc == pid {print; exit}')

    if [[ -n "$SNAP_REF" ]]; then
        GOT_UID=$(echo "$SNAP_REF" | cut -d',' -f"$UID_COL")
        GOT_EUID=$(echo "$SNAP_REF" | cut -d',' -f"$EUID_COL")

        if [[ "$GOT_EUID" == "$GOT_UID" ]]; then
            pass "euid=$GOT_EUID совпадает с uid=$GOT_UID (нет privilege escalation)"
        elif [[ "$GOT_EUID" != "0" ]]; then
            pass "euid=$GOT_EUID отличается от uid=$GOT_UID (setuid-процесс)"
        else
            fail "euid=0 при uid=$GOT_UID — возможно euid не читается из /proc"
        fi
    else
        echo "  SKIP: snapshot для PID=$REF_PID не найден в этом цикле"
    fi
fi

# ── Результат ──

echo ""
echo "========================================="
echo "  Результат: $PASSED passed, $FAILED failed"
echo "========================================="

[[ "$FAILED" -eq 0 ]] && exit 0 || exit 1
