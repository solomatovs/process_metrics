/*
 * http_server.c — встроенный HTTP-сервер для process_metrics
 *
 * Минимальный HTTP/1.1-сервер со следующими эндпоинтами:
 *
 *   GET /metrics                     — возвращает накопленные события в CSV (только чтение).
 *   GET /metrics?format=csv         — то же самое (явное указание формата).
 *
 *   GET /metrics?format=csv&clear=1 — возвращает накопленные события в CSV И очищает
 *                                     буфер после успешной доставки.
 *                                     Предназначено для материализованных представлений ClickHouse.
 *                                     При ошибке доставки события сохраняются.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include "http_server.h"
#include "event_file.h"
#include "csv_format.h"

/* ── состояние ───────────────────────────────────────────────────── */

static int           g_listen_fd = -1;
static pthread_t     g_thread;
static volatile int  g_running;

/* ── форматирование CSV (делегировано csv_format.c) ──────────────── */

static int format_csv_row(char *buf, int buflen, const struct ef_record *rec)
{
	static const struct csv_resolvers resolvers = {
		.resolve_cgroup = http_resolve_cgroup,
		.resolve_uid    = http_resolve_uid,
	};
	return csv_format_row(buf, buflen, rec, &resolvers);
}

/*
 * Отправляет полный HTTP-ответ. Возвращает 0 при успехе, -1 при ошибке.
 */
static int send_response(int fd, int status, const char *content_type,
			 const char *body, int body_len)
{
	const char *status_text = (status == 200) ? "OK" : "Not Found";
	char header[512];
	int hlen = snprintf(header, sizeof(header),
		"HTTP/1.1 %d %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"\r\n",
		status, status_text, content_type, body_len);

	/* Отправляем заголовок */
	ssize_t sent = send(fd, header, hlen, MSG_NOSIGNAL);
	if (sent != hlen)
		return -1;

	/* Отправляем тело по частям */
	ssize_t total = 0;
	while (total < body_len) {
		ssize_t n = send(fd, body + total, body_len - total,
				 MSG_NOSIGNAL);
		if (n <= 0)
			return -1;
		total += n;
	}

	return 0;
}

/*
 * Отправляет HTTP-заголовок без Content-Length.
 * При Connection: close клиент читает до EOF.
 */
static int send_stream_header(int fd, const char *content_type)
{
	char header[512];
	int hlen = snprintf(header, sizeof(header),
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: %s\r\n"
		"Connection: close\r\n"
		"\r\n",
		content_type);
	ssize_t sent = send(fd, header, hlen, MSG_NOSIGNAL);
	return (sent == hlen) ? 0 : -1;
}

/*
 * Отправляет все байты в сокет. Возвращает 0 при успехе, -1 при ошибке.
 */
static int send_all(int fd, const char *buf, int len)
{
	ssize_t total = 0;
	while (total < len) {
		ssize_t n = send(fd, buf + total, len - total, MSG_NOSIGNAL);
		if (n <= 0)
			return -1;
		total += n;
	}
	return 0;
}

/*
 * Сбрасывает буфер отправки в сокет. Возвращает 0 при успехе, -1 при ошибке.
 */
static int flush_sendbuf(int fd, char *buf, int *used)
{
	if (*used <= 0)
		return 0;
	int rc = send_all(fd, buf, *used);
	*used = 0;
	return rc;
}

/*
 * Добавляет данные в буфер отправки, сбрасывая при заполнении.
 * Возвращает 0 при успехе, -1 при ошибке отправки.
 */
static int buf_append(int fd, char *buf, int bufsize, int *used,
		      const char *data, int len)
{
	while (len > 0) {
		int avail = bufsize - *used;
		int chunk = len < avail ? len : avail;
		memcpy(buf + *used, data, chunk);
		*used += chunk;
		data += chunk;
		len -= chunk;
		if (*used >= bufsize) {
			if (flush_sendbuf(fd, buf, used) < 0)
				return -1;
		}
	}
	return 0;
}

#define SEND_BUF_SIZE (128 * 1024)

/*
 * Потоково передаёт записи из кольцевого буфера в CSV на client_fd.
 * Использует TCP_CORK + 128 КБ пользовательский буфер для минимизации системных вызовов.
 * Если clear=1, прочитанные записи удаляются после успешной доставки.
 */
static void handle_csv_stream(int client_fd, int clear)
{
	struct ef_iter iter;
	int n = ef_read_begin(&iter);

	/* TCP_CORK: удерживаем мелкие сегменты до снятия пробки или заполнения буфера */
	int cork = 1;
	setsockopt(client_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));

	/* Отправляем HTTP-заголовок (без Content-Length — поток до закрытия) */
	if (send_stream_header(client_fd, "text/csv; charset=utf-8") < 0) {
		ef_read_end(&iter, 0);
		goto uncork;
	}

	char *sendbuf = malloc(SEND_BUF_SIZE);
	if (!sendbuf) {
		ef_read_end(&iter, 0);
		goto uncork;
	}
	int used = 0;

	/* Заголовок столбцов CSV */
	int hdr_len;
	const char *hdr = csv_header(&hdr_len);
	if (buf_append(client_fd, sendbuf, SEND_BUF_SIZE, &used,
		       hdr, hdr_len) < 0) {
		ef_read_end(&iter, 0);
		free(sendbuf);
		goto uncork;
	}

	int ok = 1;
	char row_buf[8192];
	for (int i = 0; i < n; i++) {
		const struct ef_record *rec = ef_read_next(&iter);
		if (!rec)
			break;

		int len = format_csv_row(row_buf, sizeof(row_buf), rec);
		if (len <= 0)
			continue;

		if (buf_append(client_fd, sendbuf, SEND_BUF_SIZE, &used,
			       row_buf, len) < 0) {
			ok = 0;
			break;
		}
	}

	/* Сбрасываем оставшиеся данные */
	if (ok && flush_sendbuf(client_fd, sendbuf, &used) < 0)
		ok = 0;

	ef_read_end(&iter, clear && ok);
	free(sendbuf);

uncork:
	cork = 0;
	setsockopt(client_fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
}

/* ── HTTP-ответ ──────────────────────────────────────────────────── */

static int parse_format_csv(const char *request)
{
	/* По умолчанию CSV; явный format=csv тоже принимается */
	const char *fmt = strstr(request, "format=");
	if (!fmt)
		return 1;  /* формат не указан → CSV */
	return strncmp(fmt + 7, "csv", 3) == 0;
}

static int parse_clear(const char *request)
{
	return strstr(request, "clear=1") != NULL;
}

/* ── обработчик запросов ─────────────────────────────────────────── */

static void handle_request(int client_fd,
			   const struct sockaddr_in *peer)
{
	char buf[4096];
	int n = (int)recv(client_fd, buf, sizeof(buf) - 1, 0);
	if (n <= 0)
		return;
	buf[n] = '\0';

	char peer_ip[INET_ADDRSTRLEN] = "?";
	inet_ntop(AF_INET, &peer->sin_addr, peer_ip, sizeof(peer_ip));

	/* Обработка HEAD /metrics — ClickHouse url() отправляет HEAD для проверки доступности */
	if (strncmp(buf, "HEAD /metrics", 13) == 0) {
		fprintf(stderr, "[INFO] http: HEAD /metrics from %s\n", peer_ip);
		send_response(client_fd, 200, "text/csv; charset=utf-8",
			      "", 0);
		return;
	}

	/* Обрабатываем только GET /metrics */
	if (strncmp(buf, "GET /metrics", 12) != 0) {
		fprintf(stderr, "[WARN] http: 404 from %s: %.40s\n",
			peer_ip, buf);
		const char *msg = "Not Found\n";
		send_response(client_fd, 404, "text/plain",
			      msg, (int)strlen(msg));
		return;
	}

	if (!parse_format_csv(buf)) {
		const char *fmt = strstr(buf, "format=");
		char fmt_val[32] = "?";
		if (fmt) {
			int i = 0;
			fmt += 7;
			while (*fmt && *fmt != '&' && *fmt != ' ' &&
			       *fmt != '\r' && i < 31)
				fmt_val[i++] = *fmt++;
			fmt_val[i] = '\0';
		}
		fprintf(stderr,
			"[WARN] http: unknown format=%s from %s, serving csv\n",
			fmt_val, peer_ip);
	}

	int do_clear = parse_clear(buf);
	fprintf(stderr, "[INFO] http: GET /metrics%s from %s\n",
		do_clear ? "?clear=1" : "", peer_ip);
	handle_csv_stream(client_fd, do_clear);
}

/* ── серверный поток ─────────────────────────────────────────────── */

static void *server_thread(void *arg)
{
	(void)arg;

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while (g_running) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);

		int fd = g_listen_fd;
		if (fd < 0)
			break;

		int client_fd = accept(fd,
				       (struct sockaddr *)&client_addr,
				       &addr_len);
		if (client_fd < 0) {
			if (errno == EINTR || errno == EAGAIN ||
			    errno == EBADF || errno == EINVAL)
				continue;
			if (!g_running)
				break;
			fprintf(stderr, "ERROR: http_server: accept: %s\n",
				strerror(errno));
			continue;
		}

		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
		setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
			   &tv, sizeof(tv));
		setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO,
			   &tv, sizeof(tv));

		handle_request(client_fd, &client_addr);
		close(client_fd);
	}

	return NULL;
}

/* ── публичный API ───────────────────────────────────────────────── */

int http_server_start(const struct http_config *cfg)
{
	if (!cfg->enabled)
		return 0;

	g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_fd < 0) {
		fprintf(stderr, "ERROR: http_server: socket: %s\n",
			strerror(errno));
		return -1;
	}

	int opt = 1;
	setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(cfg->port);

	if (cfg->bind[0] && strcmp(cfg->bind, "0.0.0.0") != 0)
		inet_pton(AF_INET, cfg->bind, &addr.sin_addr);
	else
		addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "ERROR: http_server: bind(%s:%d): %s\n",
			cfg->bind[0] ? cfg->bind : "0.0.0.0",
			cfg->port, strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}

	if (listen(g_listen_fd, 5) < 0) {
		fprintf(stderr, "ERROR: http_server: listen: %s\n",
			strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}

	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
	setsockopt(g_listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	g_running = 1;

	if (pthread_create(&g_thread, NULL, server_thread, NULL) != 0) {
		fprintf(stderr, "ERROR: http_server: pthread_create: %s\n",
			strerror(errno));
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}

	fprintf(stderr, "INFO: http_server: listening on %s:%d\n",
		cfg->bind[0] ? cfg->bind : "0.0.0.0", cfg->port);
	return 0;
}

void http_server_stop(void)
{
	if (!g_running)
		return;

	g_running = 0;

	/* shutdown() будит accept(), заблокированный в другом потоке;
	 * close() в одиночку не гарантирует этого в Linux. */
	if (g_listen_fd >= 0) {
		shutdown(g_listen_fd, SHUT_RDWR);
		close(g_listen_fd);
		g_listen_fd = -1;
	}

	pthread_join(g_thread, NULL);
}
