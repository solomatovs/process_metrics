/* SPDX-License-Identifier: GPL-2.0 */
/*
 * constants.h — общие константы для process_metrics
 *
 * Все «магические числа», ранее разбросанные по .c-файлам,
 * собраны здесь для единообразия и удобства изменения.
 */

#ifndef CONSTANTS_H
#define CONSTANTS_H

/* ── преобразование единиц времени ──────────────────────────────── */
#define NS_PER_SEC          1000000000ULL   /* наносекунд в секунде */
#define NS_PER_MS           1000000ULL      /* наносекунд в миллисекунде */

/* ── murmurhash3 finalizer (32-bit) ─────────────────────────────── */
#define MURMUR3_C1          0x85ebca6b
#define MURMUR3_C2          0xc2b2ae35

/* ── HTTP-сервер: значения по умолчанию ─────────────────────────── */
#define HTTP_DEFAULT_PORT        10003
#define HTTP_DEFAULT_BIND        "127.0.0.1"
#define HTTP_DEFAULT_MAX_CONNS   1
#define HTTP_LISTEN_BACKLOG      5

/* ── кольцевой буфер событий: значения по умолчанию ─────────────── */
#define EF_DEFAULT_SIZE_BYTES    (256ULL * 1024 * 1024)  /* 256 МБ */
#define EF_MIN_CAPACITY          64

/* ── BPF ring buffer ────────────────────────────────────────────── */
#define BPF_MIN_RINGBUF_SIZE     4096       /* минимальный размер (PAGE_SIZE) */
#define POLL_TIMEOUT_MS          100        /* таймаут epoll в poll-потоке */

/* ── fallback-значения sysconf ──────────────────────────────────── */
#define FALLBACK_PAGE_SIZE       4096
#define FALLBACK_CLK_TCK         100

/* ── декодирование exit_code (wait status) ──────────────────────── */
#define EXIT_SIG_MASK            0x7f       /* WTERMSIG: младшие 7 бит */
#define EXIT_STATUS_SHIFT        8          /* WEXITSTATUS: сдвиг */
#define EXIT_STATUS_MASK         0xff       /* WEXITSTATUS: маска */

/* ── audit UID ──────────────────────────────────────────────────── */
#define AUDIT_UID_UNSET          4294967295U /* (uid_t)-1, loginuid не задан */

/* ── Docker ──────────────────────────────────────────────────────── */
#define DOCKER_HASH_LEN          64         /* длина hex ID контейнера */
#define DOCKER_PREFIX            "docker-"
#define DOCKER_PREFIX_LEN        7
#define DOCKER_DEFAULT_ROOT      "/var/lib/docker"
#define DOCKER_DEFAULT_DAEMON_JSON "/etc/docker/daemon.json"

/* ── пути файловой системы ──────────────────────────────────────── */
#define CGROUP_V2_PATH           "/sys/fs/cgroup"
#define PROC_MOUNTS_PATH         "/proc/mounts"

/* ── cgroup cpu.max ─────────────────────────────────────────────── */
#define DEFAULT_CPU_MAX_PERIOD   100000LL   /* период по умолчанию (мкс) */

/* ── адаптивный refresh ─────────────────────────────────────────── */
#define REFRESH_FILL_HIGH_PCT    80
#define REFRESH_FILL_MED_PCT     50
#define REFRESH_MULT_HIGH        4
#define REFRESH_MULT_MED         2

/* ── CSV ────────────────────────────────────────────────────────── */
#define CSV_MIN_BUF_SIZE         4096       /* мин. размер буфера csv_format_row */

#endif /* CONSTANTS_H */
