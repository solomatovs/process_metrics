/*
 * event_file.c — thread-safe file-based event buffer
 *
 * Binary file of ef_record structs with two-phase delivery:
 *   ef_swap()   → rename file, return data (kept as .pending)
 *   ef_commit() → delete .pending after successful delivery
 *   Next ef_swap() picks up uncommitted .pending data automatically.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>

#include "event_file.h"

/* ── state ───────────────────────────────────────────────────────── */

static char          g_path[512];
static char          g_tmp_path[520];      /* .tmp — used during swap */
static char          g_pending_path[520];  /* .pending — awaiting commit */
static int           g_fd = -1;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_batch_mutex = PTHREAD_MUTEX_INITIALIZER;
static int           g_initialized;
static __u64         g_max_size;           /* 0 = unlimited */
static __u64         g_cur_size;           /* tracked size, avoids lseek */

/* ── helpers ─────────────────────────────────────────────────────── */

static int open_append(void)
{
	g_fd = open(g_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (g_fd < 0) {
		fprintf(stderr, "ERROR: event_file: open(%s): %s\n",
			g_path, strerror(errno));
		return -1;
	}
	off_t pos = lseek(g_fd, 0, SEEK_END);
	g_cur_size = (pos > 0) ? (__u64)pos : 0;
	return 0;
}

/*
 * Read all ef_record structs from a file.
 * Returns 0 on success (even if file is empty or missing).
 * On success, caller must free(*out).
 */
static int read_records(const char *path,
			struct ef_record **out, int *count)
{
	*out = NULL;
	*count = 0;

	struct stat st;
	if (stat(path, &st) != 0 || st.st_size == 0)
		return 0;

	int n = (int)(st.st_size / sizeof(struct ef_record));
	if (n <= 0)
		return 0;

	struct ef_record *buf = malloc(n * sizeof(struct ef_record));
	if (!buf) {
		fprintf(stderr, "ERROR: event_file: malloc(%d records) failed\n", n);
		return -1;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		free(buf);
		return -1;
	}

	ssize_t total = 0;
	ssize_t target = n * (ssize_t)sizeof(struct ef_record);
	while (total < target) {
		ssize_t r = read(fd, (char *)buf + total, target - total);
		if (r <= 0)
			break;
		total += r;
	}
	close(fd);

	int actual = (int)(total / sizeof(struct ef_record));
	if (actual <= 0) {
		free(buf);
		return 0;
	}

	*out = buf;
	*count = actual;
	return 0;
}

/*
 * Write ef_record array to a file (overwrite).
 */
static int write_records(const char *path,
			 const struct ef_record *recs, int count)
{
	if (count <= 0)
		return 0;

	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -1;

	ssize_t total = count * (ssize_t)sizeof(struct ef_record);
	ssize_t written = 0;
	while (written < total) {
		ssize_t w = write(fd, (const char *)recs + written,
				  total - written);
		if (w <= 0) {
			close(fd);
			return -1;
		}
		written += w;
	}
	close(fd);
	return 0;
}

/* ── public API ──────────────────────────────────────────────────── */

int ef_init(const char *path, __u64 max_size_bytes)
{
	snprintf(g_path, sizeof(g_path), "%s", path);
	snprintf(g_tmp_path, sizeof(g_tmp_path), "%s.tmp", path);
	snprintf(g_pending_path, sizeof(g_pending_path), "%s.pending", path);

	g_max_size = max_size_bytes;

	if (open_append() < 0)
		return -1;

	g_initialized = 1;
	return 0;
}

void ef_append(const struct metric_event *ev, const char *hostname)
{
	if (!g_initialized)
		return;

	struct ef_record rec;
	memset(&rec, 0, sizeof(rec));
	snprintf(rec.hostname, sizeof(rec.hostname), "%s", hostname);
	rec.event = *ev;

	pthread_mutex_lock(&g_mutex);
	if (g_fd >= 0) {
		/* Check file size limit (tracked, no lseek per call) */
		if (g_max_size > 0 &&
		    g_cur_size + sizeof(rec) > g_max_size) {
			fprintf(stderr,
				"WARN: event file %s reached size"
				" limit (%llu bytes), truncating\n",
				g_path,
				(unsigned long long)g_max_size);
			ftruncate(g_fd, 0);
			lseek(g_fd, 0, SEEK_SET);
			g_cur_size = 0;
		}
		ssize_t n = write(g_fd, &rec, sizeof(rec));
		if (n > 0)
			g_cur_size += (__u64)n;
	}
	pthread_mutex_unlock(&g_mutex);
}

int ef_swap(struct ef_record **out, int *count)
{
	*out = NULL;
	*count = 0;

	if (!g_initialized)
		return 0;

	/* Step 1: Read leftover .pending from previous failed delivery */
	struct ef_record *old = NULL;
	int old_count = 0;
	read_records(g_pending_path, &old, &old_count);

	/* Step 2: Atomically swap the current event file */
	pthread_mutex_lock(&g_mutex);

	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}

	int has_new = (rename(g_path, g_tmp_path) == 0);

	/* Open new empty file for future appends */
	open_append();

	pthread_mutex_unlock(&g_mutex);

	/* Step 3: Read newly swapped data */
	struct ef_record *cur = NULL;
	int cur_count = 0;
	if (has_new)
		read_records(g_tmp_path, &cur, &cur_count);
	unlink(g_tmp_path);

	/* Step 4: Combine old (pending) + new (current) */
	int total = old_count + cur_count;
	if (total <= 0) {
		free(old);
		free(cur);
		/* Remove stale .pending if it was empty */
		if (old_count == 0)
			unlink(g_pending_path);
		return 0;
	}

	struct ef_record *combined = malloc(total * sizeof(struct ef_record));
	if (!combined) {
		fprintf(stderr, "ERROR: event_file: malloc(%d records) failed\n",
			total);
		free(old);
		free(cur);
		return -1;
	}

	if (old_count > 0)
		memcpy(combined, old, old_count * sizeof(struct ef_record));
	if (cur_count > 0)
		memcpy(combined + old_count, cur,
		       cur_count * sizeof(struct ef_record));

	free(old);
	free(cur);

	/* Step 5: Write combined data to .pending
	 * If delivery succeeds, ef_commit() deletes it.
	 * If delivery fails, next ef_swap() picks it up.
	 */
	write_records(g_pending_path, combined, total);

	*out = combined;
	*count = total;
	return 0;
}

/*
 * Append contents of src file to dst file using a small stack buffer.
 * Deletes src on success.
 */
static int append_file_to(const char *dst, const char *src)
{
	int sfd = open(src, O_RDONLY);
	if (sfd < 0)
		return -1;
	int dfd = open(dst, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (dfd < 0) {
		close(sfd);
		return -1;
	}
	char buf[8192];
	ssize_t n;
	int ok = 0;
	while ((n = read(sfd, buf, sizeof(buf))) > 0) {
		ssize_t written = 0;
		while (written < n) {
			ssize_t w = write(dfd, buf + written, n - written);
			if (w <= 0) { ok = -1; goto done; }
			written += w;
		}
	}
done:
	close(sfd);
	close(dfd);
	if (ok == 0)
		unlink(src);
	return ok;
}

int ef_swap_fd(void)
{
	if (!g_initialized)
		return -1;

	/* Wait for any in-progress batch (e.g. snapshot loop) to finish */
	pthread_mutex_lock(&g_batch_mutex);

	/* Step 1: Atomically swap the current event file */
	pthread_mutex_lock(&g_mutex);

	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}

	int has_new = (rename(g_path, g_tmp_path) == 0);

	/* Open new empty file for future appends */
	open_append();

	pthread_mutex_unlock(&g_mutex);
	pthread_mutex_unlock(&g_batch_mutex);

	/* Step 2: Merge .tmp into .pending */
	struct stat st;
	int has_pending = (stat(g_pending_path, &st) == 0 && st.st_size > 0);

	/* Drop stale .pending if it exceeds the size limit
	 * (delivery keeps failing → don't let disk fill up) */
	if (has_pending && g_max_size > 0 && (__u64)st.st_size > g_max_size) {
		fprintf(stderr,
			"WARN: pending file %s exceeded limit "
			"(%llu > %llu), discarding stale data\n",
			g_pending_path,
			(unsigned long long)st.st_size,
			(unsigned long long)g_max_size);
		unlink(g_pending_path);
		has_pending = 0;
	}

	if (has_new && has_pending) {
		/* Append new data to existing pending */
		append_file_to(g_pending_path, g_tmp_path);
	} else if (has_new && !has_pending) {
		/* Just rename .tmp → .pending */
		rename(g_tmp_path, g_pending_path);
	}
	/* else: only .pending exists (previous failed delivery), or nothing */

	/* Clean up .tmp if still around */
	unlink(g_tmp_path);

	/* Step 3: Open .pending for streaming read */
	int fd = open(g_pending_path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) != 0 || st.st_size == 0) {
		close(fd);
		unlink(g_pending_path);
		return -1;
	}

	return fd;
}

int ef_snapshot_fd(void)
{
	if (!g_initialized)
		return -1;

	static char snap_path[520];
	snprintf(snap_path, sizeof(snap_path), "%s.snap", g_path);

	/* Wait for any in-progress batch (e.g. snapshot loop) to finish */
	pthread_mutex_lock(&g_batch_mutex);
	pthread_mutex_lock(&g_mutex);

	/* Close fd to flush all pending writes */
	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}

	/* Hard-link: instant copy, no data transfer */
	unlink(snap_path);
	int has_data = (link(g_path, snap_path) == 0);

	/* Reopen for future appends */
	open_append();

	pthread_mutex_unlock(&g_mutex);
	pthread_mutex_unlock(&g_batch_mutex);

	if (!has_data)
		return -1;

	int fd = open(snap_path, O_RDONLY);
	if (fd < 0) {
		unlink(snap_path);
		return -1;
	}

	struct stat st;
	if (fstat(fd, &st) != 0 || st.st_size == 0) {
		close(fd);
		unlink(snap_path);
		return -1;
	}

	/* Unlink snapshot — fd stays valid until close() */
	unlink(snap_path);

	return fd;
}

void ef_batch_lock(void)
{
	pthread_mutex_lock(&g_batch_mutex);
}

void ef_batch_unlock(void)
{
	pthread_mutex_unlock(&g_batch_mutex);
}

void ef_commit(void)
{
	if (!g_initialized)
		return;
	unlink(g_pending_path);
}

void ef_cleanup(void)
{
	if (!g_initialized)
		return;

	pthread_mutex_lock(&g_mutex);
	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}
	g_initialized = 0;
	pthread_mutex_unlock(&g_mutex);
}
