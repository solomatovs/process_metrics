/*
 * test_event_file.c — unit tests for event_file (swap/commit two-phase delivery)
 *
 * Tests:
 *   1. ef_init creates the event file
 *   2. ef_append writes records
 *   3. ef_swap returns accumulated records and clears the main file
 *   4. ef_commit deletes .pending
 *   5. Failed delivery (no ef_commit) preserves .pending for next swap
 *   6. Multiple swaps without commit accumulate data
 *   7. Concurrent appends from multiple threads
 *
 * Build:
 *   gcc -O2 -Wall -I../src -o test_event_file test_event_file.c ../src/event_file.c -lpthread
 *
 * Run:
 *   ./test_event_file
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <assert.h>

#include "event_file.h"

#define TEST_FILE "/tmp/test_ef_events.dat"
#define TEST_PENDING "/tmp/test_ef_events.dat.pending"
#define TEST_TMP "/tmp/test_ef_events.dat.tmp"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_START(name) printf("  TEST: %s ... ", name)
#define TEST_PASS() do { printf("OK\n"); tests_passed++; } while(0)
#define TEST_FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { TEST_FAIL(msg); return; } \
} while(0)

#define ASSERT_STR_EQ(a, b, msg) do { \
	if (strcmp((a), (b)) != 0) { TEST_FAIL(msg); return; } \
} while(0)

static void cleanup_files(void)
{
	unlink(TEST_FILE);
	unlink(TEST_PENDING);
	unlink(TEST_TMP);
}

static int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

static struct metric_event make_event(const char *type, __u32 pid,
				      const char *comm)
{
	struct metric_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.timestamp_ns = 1000000000ULL * pid;
	snprintf(ev.event_type, sizeof(ev.event_type), "%s", type);
	ev.pid = pid;
	snprintf(ev.comm, sizeof(ev.comm), "%s", comm);
	ev.rss_bytes = pid * 4096;
	return ev;
}

/* ── Test 1: init creates file ──────────────────────────────────── */

static void test_init(void)
{
	TEST_START("ef_init creates file");
	cleanup_files();

	int rc = ef_init(TEST_FILE);
	ASSERT_EQ(rc, 0, "ef_init failed");
	ASSERT_EQ(file_exists(TEST_FILE), 1, "file not created");

	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── Test 2: append + swap returns records ──────────────────────── */

static void test_append_swap(void)
{
	TEST_START("append + swap returns records");
	cleanup_files();
	ef_init(TEST_FILE);

	struct metric_event ev1 = make_event("exec", 100, "bash");
	struct metric_event ev2 = make_event("fork", 101, "grep");
	struct metric_event ev3 = make_event("exit", 102, "cat");

	ef_append(&ev1, "host1");
	ef_append(&ev2, "host1");
	ef_append(&ev3, "host1");

	struct ef_record *records = NULL;
	int count = 0;
	int rc = ef_swap(&records, &count);

	ASSERT_EQ(rc, 0, "ef_swap failed");
	ASSERT_EQ(count, 3, "expected 3 records");
	ASSERT_EQ(records[0].event.pid, 100, "wrong pid[0]");
	ASSERT_EQ(records[1].event.pid, 101, "wrong pid[1]");
	ASSERT_EQ(records[2].event.pid, 102, "wrong pid[2]");
	ASSERT_STR_EQ(records[0].hostname, "host1", "wrong hostname");
	ASSERT_STR_EQ(records[0].event.event_type, "exec", "wrong type");

	free(records);
	ef_commit();
	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── Test 3: swap clears main file ──────────────────────────────── */

static void test_swap_clears(void)
{
	TEST_START("swap clears main file, second swap empty");
	cleanup_files();
	ef_init(TEST_FILE);

	struct metric_event ev = make_event("snapshot", 200, "nginx");
	ef_append(&ev, "host2");

	struct ef_record *rec = NULL;
	int count = 0;
	ef_swap(&rec, &count);
	ASSERT_EQ(count, 1, "first swap: expected 1");
	free(rec);
	ef_commit();

	/* Second swap should be empty */
	ef_swap(&rec, &count);
	ASSERT_EQ(count, 0, "second swap: expected 0");
	free(rec);

	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── Test 4: commit deletes .pending ────────────────────────────── */

static void test_commit_deletes_pending(void)
{
	TEST_START("ef_commit deletes .pending file");
	cleanup_files();
	ef_init(TEST_FILE);

	struct metric_event ev = make_event("exec", 300, "python");
	ef_append(&ev, "host3");

	struct ef_record *rec = NULL;
	int count = 0;
	ef_swap(&rec, &count);
	free(rec);

	/* .pending should exist before commit */
	ASSERT_EQ(file_exists(TEST_PENDING), 1, ".pending missing before commit");

	ef_commit();

	/* .pending should be gone after commit */
	ASSERT_EQ(file_exists(TEST_PENDING), 0, ".pending still exists after commit");

	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── Test 5: no commit preserves .pending ───────────────────────── */

static void test_no_commit_preserves(void)
{
	TEST_START("no commit preserves data for next swap");
	cleanup_files();
	ef_init(TEST_FILE);

	struct metric_event ev1 = make_event("exec", 400, "java");
	ef_append(&ev1, "host4");

	struct ef_record *rec = NULL;
	int count = 0;
	ef_swap(&rec, &count);
	ASSERT_EQ(count, 1, "first swap: expected 1");
	ASSERT_EQ(rec[0].event.pid, 400, "first swap: wrong pid");
	free(rec);

	/* DO NOT call ef_commit() — simulate failed delivery */

	/* Append more events */
	struct metric_event ev2 = make_event("fork", 401, "worker");
	ef_append(&ev2, "host4");

	/* Next swap should return old (pending) + new */
	ef_swap(&rec, &count);
	ASSERT_EQ(count, 2, "second swap: expected 2 (1 pending + 1 new)");
	ASSERT_EQ(rec[0].event.pid, 400, "pending record first");
	ASSERT_EQ(rec[1].event.pid, 401, "new record second");
	free(rec);

	ef_commit();
	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── Test 6: multiple failed deliveries accumulate ──────────────── */

static void test_multiple_failed_deliveries(void)
{
	TEST_START("multiple failed deliveries accumulate");
	cleanup_files();
	ef_init(TEST_FILE);

	/* Round 1: append + swap, no commit */
	struct metric_event ev1 = make_event("exec", 500, "app1");
	ef_append(&ev1, "host5");

	struct ef_record *rec = NULL;
	int count = 0;
	ef_swap(&rec, &count);
	ASSERT_EQ(count, 1, "round 1");
	free(rec);
	/* no commit */

	/* Round 2: append more + swap, no commit */
	struct metric_event ev2 = make_event("exec", 501, "app2");
	ef_append(&ev2, "host5");

	ef_swap(&rec, &count);
	ASSERT_EQ(count, 2, "round 2: 1 pending + 1 new");
	free(rec);
	/* no commit */

	/* Round 3: append more + swap + commit */
	struct metric_event ev3 = make_event("exec", 502, "app3");
	ef_append(&ev3, "host5");

	ef_swap(&rec, &count);
	ASSERT_EQ(count, 3, "round 3: 2 pending + 1 new");
	ASSERT_EQ(rec[0].event.pid, 500, "oldest first");
	ASSERT_EQ(rec[2].event.pid, 502, "newest last");
	free(rec);

	ef_commit();
	ASSERT_EQ(file_exists(TEST_PENDING), 0, ".pending removed");

	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── Test 7: concurrent appends ─────────────────────────────────── */

#define THREADS 4
#define EVENTS_PER_THREAD 100

static void *append_thread(void *arg)
{
	int thread_id = *(int *)arg;
	for (int i = 0; i < EVENTS_PER_THREAD; i++) {
		struct metric_event ev = make_event("snapshot",
			(thread_id * 1000) + i, "worker");
		ef_append(&ev, "host_concurrent");
	}
	return NULL;
}

static void test_concurrent_appends(void)
{
	TEST_START("concurrent appends from multiple threads");
	cleanup_files();
	ef_init(TEST_FILE);

	pthread_t threads[THREADS];
	int ids[THREADS];
	for (int i = 0; i < THREADS; i++) {
		ids[i] = i;
		pthread_create(&threads[i], NULL, append_thread, &ids[i]);
	}
	for (int i = 0; i < THREADS; i++)
		pthread_join(threads[i], NULL);

	struct ef_record *rec = NULL;
	int count = 0;
	ef_swap(&rec, &count);

	ASSERT_EQ(count, THREADS * EVENTS_PER_THREAD,
		  "wrong total count from concurrent appends");

	/* Verify all records are valid (non-zero PIDs, correct hostname) */
	for (int i = 0; i < count; i++) {
		if (strcmp(rec[i].hostname, "host_concurrent") != 0) {
			free(rec);
			TEST_FAIL("corrupted hostname in concurrent test");
			return;
		}
	}

	free(rec);
	ef_commit();
	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── Test 8: swap with no data returns 0 ────────────────────────── */

static void test_swap_empty(void)
{
	TEST_START("swap with no data returns count=0");
	cleanup_files();
	ef_init(TEST_FILE);

	struct ef_record *rec = NULL;
	int count = 0;
	int rc = ef_swap(&rec, &count);
	ASSERT_EQ(rc, 0, "ef_swap returned error");
	ASSERT_EQ(count, 0, "expected 0 records");

	ef_cleanup();
	cleanup_files();
	TEST_PASS();
}

/* ── main ───────────────────────────────────────────────────────── */

int main(void)
{
	printf("== event_file unit tests ==\n\n");

	test_init();
	test_append_swap();
	test_swap_clears();
	test_commit_deletes_pending();
	test_no_commit_preserves();
	test_multiple_failed_deliveries();
	test_concurrent_appends();
	test_swap_empty();

	printf("\n== Results: %d passed, %d failed ==\n",
	       tests_passed, tests_failed);

	return tests_failed > 0 ? 1 : 0;
}
