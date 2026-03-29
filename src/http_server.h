/*
 * http_server.h — встроенный HTTP-сервер для process_metrics
 *
 * Отдаёт метрики по HTTP (формат CSV для ClickHouse):
 *   GET /metrics                     — накопленные события в CSV (только чтение)
 *   GET /metrics?format=csv         — то же самое (явное указание формата)
 *   GET /metrics?format=csv&clear=1 — возвращает CSV и очищает буфер после доставки
 */

#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <linux/types.h>
#include "process_metrics_common.h"

struct http_config {
	int  port;           /* порт для прослушивания (по умолчанию: 9091) */
	char bind[BIND_ADDR_LEN]; /* адрес привязки (по умолчанию: "0.0.0.0") */
	int  enabled;        /* 0 = отключён */
	int  max_connections; /* макс. одновременных подключений (по умолчанию: 1) */
};

/*
 * Разрешает путь cgroup для отображения.
 * Если включено разрешение docker и cgroup содержит docker-<hash>.scope,
 * заменяет его на docker/<container_name>.
 * buf должен быть не менее EV_CGROUP_LEN байт.
 */
void http_resolve_cgroup(const char *raw, char *buf, int buflen);

/*
 * Разрешает UID в имя пользователя из /etc/passwd (с кэшированием).
 * Если не найдено, buf устанавливается в пустую строку.
 */
void http_resolve_uid(__u32 uid, char *buf, int buflen);

/*
 * Запускает HTTP-сервер в фоновом потоке.
 * Возвращает 0 при успехе, -1 при ошибке.
 */
int http_server_start(const struct http_config *cfg);

/*
 * Останавливает HTTP-сервер и дожидается завершения потока.
 */
void http_server_stop(void);

#endif /* HTTP_SERVER_H — конец заголовка */
