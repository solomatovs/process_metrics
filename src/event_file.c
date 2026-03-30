/*
 * event_file.c — кольцевой буфер в памяти для событий метрик
 *
 * Кольцевой буфер фиксированного размера из структур ef_record.
 * На горячем пути нет дисковых операций:
 *   ef_append()     → memcpy в слот кольца (защищено мьютексом)
 *   ef_read_begin() → снимок head/tail для итерации
 *   ef_read_end()   → опционально сдвигает tail (очистка прочитанных записей)
 *
 * При заполнении кольца самая старая запись молча перезаписывается.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "event_file.h"

/* ── состояние ───────────────────────────────────────────────────── */

static struct ef_record *g_ring;        /* массив кольцевого буфера */
static __u32             g_capacity;    /* количество слотов */
static __u32             g_head;        /* следующая позиция записи */
static __u32             g_tail;        /* позиция самой старой непрочитанной записи */
static int               g_full;        /* head догнал tail */
static int               g_initialized;

static pthread_mutex_t   g_mutex       = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t   g_batch_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── вспомогательные функции ──────────────────────────────────────── */

static __u32 ring_count(void)
{
	if (g_full)
		return g_capacity;
	return (g_head >= g_tail)
		? g_head - g_tail
		: g_capacity - g_tail + g_head;
}

/* ── публичный API ───────────────────────────────────────────────── */

int ef_init(__u64 max_size_bytes)
{
	if (max_size_bytes == 0)
		max_size_bytes = EF_DEFAULT_SIZE_BYTES;

	__u64 cap = max_size_bytes / sizeof(struct ef_record);
	if (cap < EF_MIN_CAPACITY)
		cap = EF_MIN_CAPACITY;
	if (cap > EF_MAX_CAPACITY)
		cap = EF_MAX_CAPACITY; /* предельное ограничение: ~2.7 ГБ */

	g_ring = calloc((size_t)cap, sizeof(struct ef_record));
	if (!g_ring) {
		fprintf(stderr, "ERROR: ef_init: calloc(%llu records) failed\n",
			(unsigned long long)cap);
		return -1;
	}

	g_capacity    = (__u32)cap;
	g_head        = 0;
	g_tail        = 0;
	g_full        = 0;
	g_initialized = 1;
	return 0;
}

void ef_append(const struct metric_event *ev, const char *hostname)
{
	if (!g_initialized)
		return;

	pthread_mutex_lock(&g_mutex);

	struct ef_record *slot = &g_ring[g_head];
	snprintf(slot->hostname, sizeof(slot->hostname), "%s", hostname);
	slot->event = *ev;

	g_head = (g_head + 1) % g_capacity;
	if (g_full) {
		/* Перезапись самой старой записи — сдвигаем tail */
		g_tail = g_head;
	}
	if (g_head == g_tail)
		g_full = 1;

	pthread_mutex_unlock(&g_mutex);
}

int ef_read_begin(struct ef_iter *it)
{
	pthread_mutex_lock(&g_batch_mutex);
	pthread_mutex_lock(&g_mutex);

	__u32 n = ring_count();
	it->pos      = g_tail;
	it->end      = g_head;
	it->capacity = g_capacity;
	it->count    = (int)n;
	it->read     = 0;

	pthread_mutex_unlock(&g_mutex);
	/* g_batch_mutex остаётся захваченным — не допускает новые пакеты во время итерации */
	return (int)n;
}

const struct ef_record *ef_read_next(struct ef_iter *it)
{
	if (it->read >= it->count)
		return NULL;

	const struct ef_record *rec = &g_ring[it->pos];
	it->pos = (it->pos + 1) % it->capacity;
	it->read++;
	return rec;
}

void ef_read_end(struct ef_iter *it, int clear)
{
	if (clear && it->count > 0) {
		pthread_mutex_lock(&g_mutex);
		/* Сдвигаем tail за все прочитанные записи.
		 * Новые записи, добавленные во время итерации, сохраняются. */
		g_tail = it->end;
		g_full = 0;
		pthread_mutex_unlock(&g_mutex);
	}

	pthread_mutex_unlock(&g_batch_mutex);
}

void ef_batch_lock(void)
{
	pthread_mutex_lock(&g_batch_mutex);
}

void ef_batch_unlock(void)
{
	pthread_mutex_unlock(&g_batch_mutex);
}

void ef_cleanup(void)
{
	if (!g_initialized)
		return;

	pthread_mutex_lock(&g_mutex);
	free(g_ring);
	g_ring = NULL;
	g_capacity = 0;
	g_head = 0;
	g_tail = 0;
	g_full = 0;
	g_initialized = 0;
	pthread_mutex_unlock(&g_mutex);
}
