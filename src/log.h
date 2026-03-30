/*
 * log.h — минимальный логгер для process_metrics
 *
 * Потокобезопасный (fprintf на stderr атомарен для коротких строк).
 * Формат: [LEVEL] message\n
 *
 * Использование:
 *   LOG_INFO("started %d rules", n);
 *   LOG_WARN("ringbuf drops: %d", drops);
 *   LOG_ERROR("bind failed: %s", strerror(errno));
 *   LOG_FATAL("no rules loaded");
 *   LOG_DEBUG(cfg_log_level, "event pid=%u", pid);
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>

static inline void log_ts(const char *level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static inline void log_ts(const char *level, const char *fmt, ...)
{
	fprintf(stderr, "[%s] ", level);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define LOG_FATAL(...) log_ts("FATAL", __VA_ARGS__)
#define LOG_ERROR(...) log_ts("ERROR", __VA_ARGS__)
#define LOG_WARN(...)  log_ts("WARN",  __VA_ARGS__)
#define LOG_INFO(...)  log_ts("INFO",  __VA_ARGS__)

/* LOG_DEBUG проверяет уровень логирования, чтобы не форматировать строку зря.
 * Первый аргумент — переменная уровня (cfg_log_level). */
#define LOG_DEBUG(level, ...) do { if ((level) >= 2) log_ts("DEBUG", __VA_ARGS__); } while (0)

#endif /* LOG_H */
