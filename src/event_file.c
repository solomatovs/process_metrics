/*
 * event_file.c — in-memory ring buffer for metric events
 *
 * Fixed-size ring buffer of ef_record structs. No disk I/O on the hot path:
 *   ef_append()     → memcpy into ring slot (mutex-protected)
 *   ef_read_begin() → snapshot head/tail for iteration
 *   ef_read_end()   → optionally advance tail (clear consumed records)
 *
 * When the ring is full, the oldest record is silently overwritten.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "event_file.h"

/* ── state ───────────────────────────────────────────────────────── */

static struct ef_record *g_ring;        /* ring buffer array */
static __u32             g_capacity;    /* number of slots */
static __u32             g_head;        /* next write position */
static __u32             g_tail;        /* oldest unread position */
static int               g_full;        /* head caught up with tail */
static int               g_initialized;

static pthread_mutex_t   g_mutex       = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t   g_batch_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── helpers ─────────────────────────────────────────────────────── */

static __u32 ring_count(void)
{
	if (g_full)
		return g_capacity;
	return (g_head >= g_tail)
		? g_head - g_tail
		: g_capacity - g_tail + g_head;
}

/* ── public API ──────────────────────────────────────────────────── */

int ef_init(__u64 max_size_bytes)
{
	if (max_size_bytes == 0)
		max_size_bytes = 256ULL * 1024 * 1024; /* 256 MB default */

	__u64 cap = max_size_bytes / sizeof(struct ef_record);
	if (cap < 64)
		cap = 64;
	if (cap > 1000000)
		cap = 1000000; /* sanity cap: ~2.7 GB */

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
		/* Overwrite oldest — advance tail */
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
	/* g_batch_mutex stays held — prevents new batches during iteration */
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
		/* Advance tail past everything we read.
		 * New records appended during iteration are preserved. */
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
