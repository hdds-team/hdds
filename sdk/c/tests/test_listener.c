// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test: Reader / writer listeners from C
 *
 * Tests:
 *   - Argument checks; clearing with no listener installed is a no-op
 *   - on_data_available fires with the written bytes, on the writer's thread
 *     for an intra-process delivery
 *   - A callback may take() from its own reader
 *   - on_subscription_matched / on_publication_matched report the status
 *     values of a reader and a writer of two UDP participants, and
 *     on_data_available fires for samples arriving over the network (and
 *     can take() them from inside the callback)
 *   - on_sample_written reports the bytes and increasing sequence numbers
 *   - Clearing the listener while a callback runs on another thread waits
 *     for that callback (its user_data is freed right after: ASan proves the
 *     callback no longer touches it)
 *   - Destroying the reader while a callback runs waits the same way
 *   - Clearing the listener from inside its own callback does not deadlock,
 *     and no callback fires afterwards
 *   - A NULL callback is not called and does not stop the others
 *   - hdds_*_exchange_listener reports the replaced listener's user_data
 *   - Destroying a writer from inside its own callback does not free it
 *     under the write that called back (it is leaked, the listener removed)
 *
 * Build (from the repository root, after `cargo build -p hdds-c --release`):
 *   cc -std=c11 -Wall -Wextra -o test_listener sdk/c/tests/test_listener.c \
 *      -Isdk/c/include -Ltarget/release -lhdds_c -lpthread
 *   LD_LIBRARY_PATH=target/release ./test_listener
 * Add -fsanitize=address -g for an AddressSanitizer run.
 *
 * The generated header names struct fields in SCREAMING_SNAKE_CASE (as
 * every struct of hdds.h): `l.ON_DATA_AVAILABLE`, `l.USER_DATA`,
 * `status->CURRENT_COUNT`.
 *
 * Network part: set HDDS_INTERFACE=lo on a host whose default route is a
 * VPN or a container bridge.
 */

#define _POSIX_C_SOURCE 200809L

#include <hdds.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int passed = 0;

#define RUN_TEST(fn) do {          \
    printf("  %-58s", #fn);        \
    fflush(stdout);                \
    fn();                          \
    printf("[PASS]\n");            \
    passed++;                      \
} while (0)

#define CHECK(cond) do {                                                  \
    if (!(cond)) {                                                        \
        fprintf(stderr, "\n%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
                #cond);                                                   \
        exit(1);                                                          \
    }                                                                     \
} while (0)

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* Poll `flag` until it reaches `want` or `timeout_ms` elapses. */
static int wait_int_at_least(atomic_int *flag, int want, long timeout_ms) {
    for (long waited = 0; waited < timeout_ms; waited += 5) {
        if (atomic_load(flag) >= want) {
            return 1;
        }
        sleep_ms(5);
    }
    return atomic_load(flag) >= want;
}

static struct HddsParticipant *intra_participant(const char *name) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport(name, HDDS_TRANSPORT_INTRA_PROCESS);
    CHECK(p != NULL);
    return p;
}

static struct HddsQoS *keep_last_qos(void) {
    struct HddsQoS *qos = hdds_qos_reliable();
    CHECK(qos != NULL);
    CHECK(hdds_qos_set_history_depth(qos, 64) == HDDS_OK);
    return qos;
}

/* ---- Argument checks ---- */

static void test_null_arguments(void) {
    HddsReaderListener rl;
    HddsWriterListener wl;
    memset(&rl, 0, sizeof(rl));
    memset(&wl, 0, sizeof(wl));
    CHECK(hdds_reader_set_listener(NULL, &rl) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_reader_clear_listener(NULL) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_writer_set_listener(NULL, &wl) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_writer_clear_listener(NULL) == HDDS_INVALID_ARGUMENT);

    struct HddsParticipant *p = intra_participant("c_listener_null_args");
    struct HddsDataReader *r = hdds_reader_create(p, "c_listener_null_args");
    struct HddsDataWriter *w = hdds_writer_create(p, "c_listener_null_args");
    CHECK(r != NULL && w != NULL);
    CHECK(hdds_reader_set_listener(r, NULL) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_writer_set_listener(w, NULL) == HDDS_INVALID_ARGUMENT);
    /* Nothing installed: clearing is a no-op. */
    CHECK(hdds_reader_clear_listener(r) == HDDS_OK);
    CHECK(hdds_writer_clear_listener(w) == HDDS_OK);
    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

/* ---- on_data_available, intra-process ---- */

typedef struct {
    atomic_int count;
    int other_thread;      /* a callback ran on a thread other than `writer_thread` */
    pthread_t writer_thread;
    unsigned char last[64];
    size_t last_len;
    struct HddsDataReader *take_from; /* when set, the callback takes from it */
    atomic_int taken;
} DataCtx;

static void on_data(const uint8_t *data, size_t len, void *user_data) {
    DataCtx *ctx = (DataCtx *)user_data;
    if (!pthread_equal(pthread_self(), ctx->writer_thread)) {
        ctx->other_thread = 1;
    }
    if (len <= sizeof(ctx->last)) {
        memcpy(ctx->last, data, len);
        ctx->last_len = len;
    }
    if (ctx->take_from != NULL) {
        unsigned char buf[64];
        size_t got = 0;
        while (hdds_reader_take(ctx->take_from, buf, sizeof(buf), &got) == HDDS_OK) {
            atomic_fetch_add(&ctx->taken, 1);
        }
    }
    atomic_fetch_add(&ctx->count, 1);
}

static void test_data_available_intra_process(void) {
    struct HddsParticipant *p = intra_participant("c_listener_intra");
    struct HddsQoS *qos = keep_last_qos();
    struct HddsDataReader *r = hdds_reader_create_with_qos(p, "c_listener_intra", qos);
    struct HddsDataWriter *w = hdds_writer_create_with_qos(p, "c_listener_intra", qos);
    CHECK(r != NULL && w != NULL);

    DataCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.writer_thread = pthread_self();

    HddsReaderListener l;
    memset(&l, 0, sizeof(l));
    l.ON_DATA_AVAILABLE = on_data;
    l.USER_DATA = &ctx;
    CHECK(hdds_reader_set_listener(r, &l) == HDDS_OK);

    for (int i = 0; i < 3; i++) {
        char msg[32];
        int n = snprintf(msg, sizeof(msg), "intra-%d", i);
        CHECK(hdds_writer_write(w, msg, (size_t)n) == HDDS_OK);
    }
    /* Intra-process delivery calls the listener inside write(). */
    CHECK(atomic_load(&ctx.count) == 3);
    CHECK(ctx.other_thread == 0);
    CHECK(ctx.last_len == strlen("intra-2"));
    CHECK(memcmp(ctx.last, "intra-2", ctx.last_len) == 0);

    /* Every sample is still in the reader. */
    unsigned char buf[64];
    size_t got = 0;
    int taken = 0;
    while (hdds_reader_take(r, buf, sizeof(buf), &got) == HDDS_OK) {
        taken++;
    }
    CHECK(taken == 3);

    CHECK(hdds_reader_clear_listener(r) == HDDS_OK);
    CHECK(hdds_writer_write(w, "after", 5) == HDDS_OK);
    CHECK(atomic_load(&ctx.count) == 3);

    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
}

static void test_take_inside_callback(void) {
    struct HddsParticipant *p = intra_participant("c_listener_take_inside");
    struct HddsQoS *qos = keep_last_qos();
    struct HddsDataReader *r = hdds_reader_create_with_qos(p, "c_listener_take_inside", qos);
    struct HddsDataWriter *w = hdds_writer_create_with_qos(p, "c_listener_take_inside", qos);
    CHECK(r != NULL && w != NULL);

    DataCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.writer_thread = pthread_self();
    ctx.take_from = r;

    HddsReaderListener l;
    memset(&l, 0, sizeof(l));
    l.ON_DATA_AVAILABLE = on_data;
    l.USER_DATA = &ctx;
    CHECK(hdds_reader_set_listener(r, &l) == HDDS_OK);
    for (int i = 0; i < 4; i++) {
        CHECK(hdds_writer_write(w, "x", 1) == HDDS_OK);
    }
    CHECK(atomic_load(&ctx.count) == 4);
    CHECK(atomic_load(&ctx.taken) == 4);

    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
}

/* ---- Matched statuses + network delivery ---- */

typedef struct {
    atomic_int calls;
    HddsSubscriptionMatchedStatus last;
} SubMatchCtx;

typedef struct {
    SubMatchCtx matched;
    DataCtx data;
} ReaderCtx;

static void on_sub_matched(const HddsSubscriptionMatchedStatus *status, void *user_data) {
    ReaderCtx *ctx = (ReaderCtx *)user_data;
    ctx->matched.last = *status;
    atomic_fetch_add(&ctx->matched.calls, 1);
}

static void on_reader_data(const uint8_t *data, size_t len, void *user_data) {
    ReaderCtx *ctx = (ReaderCtx *)user_data;
    on_data(data, len, &ctx->data);
}

typedef struct {
    atomic_int matched_calls;
    HddsPublicationMatchedStatus last_matched;
    atomic_int written;
    uint64_t last_seq;
    int seq_increasing;
    size_t last_written_len;
} WriterCtx;

static void on_pub_matched(const HddsPublicationMatchedStatus *status, void *user_data) {
    WriterCtx *ctx = (WriterCtx *)user_data;
    ctx->last_matched = *status;
    atomic_fetch_add(&ctx->matched_calls, 1);
}

static void on_written(const uint8_t *data, size_t len, uint64_t seq, void *user_data) {
    WriterCtx *ctx = (WriterCtx *)user_data;
    (void)data;
    if (atomic_load(&ctx->written) > 0 && seq <= ctx->last_seq) {
        ctx->seq_increasing = 0;
    }
    ctx->last_seq = seq;
    ctx->last_written_len = len;
    atomic_fetch_add(&ctx->written, 1);
}

static void test_matched_and_network_data(void) {
    struct HddsParticipant *sub = hdds_participant_create("c_listener_net_sub");
    struct HddsParticipant *pub = hdds_participant_create("c_listener_net_pub");
    CHECK(sub != NULL && pub != NULL);
    struct HddsQoS *qos = keep_last_qos();
    struct HddsDataReader *r = hdds_reader_create_with_qos(sub, "c_listener_net", qos);
    CHECK(r != NULL);

    ReaderCtx rctx;
    memset(&rctx, 0, sizeof(rctx));
    rctx.data.writer_thread = pthread_self();
    /* The callback takes from its own reader: the network delivery path
     * holds no lock take() needs. */
    rctx.data.take_from = r;
    HddsReaderListener rl;
    memset(&rl, 0, sizeof(rl));
    rl.ON_DATA_AVAILABLE = on_reader_data;
    rl.ON_SUBSCRIPTION_MATCHED = on_sub_matched;
    rl.USER_DATA = &rctx;
    CHECK(hdds_reader_set_listener(r, &rl) == HDDS_OK);

    struct HddsDataWriter *w = hdds_writer_create_with_qos(pub, "c_listener_net", qos);
    CHECK(w != NULL);
    WriterCtx wctx;
    memset(&wctx, 0, sizeof(wctx));
    wctx.seq_increasing = 1;
    HddsWriterListener wl;
    memset(&wl, 0, sizeof(wl));
    wl.ON_PUBLICATION_MATCHED = on_pub_matched;
    wl.ON_SAMPLE_WRITTEN = on_written;
    wl.USER_DATA = &wctx;
    CHECK(hdds_writer_set_listener(w, &wl) == HDDS_OK);

    /* The reader's listener was installed before the writer existed: it
     * hears the match itself. */
    CHECK(wait_int_at_least(&rctx.matched.calls, 1, 10000));
    CHECK(rctx.matched.last.TOTAL_COUNT == 1);
    CHECK(rctx.matched.last.TOTAL_COUNT_CHANGE == 1);
    CHECK(rctx.matched.last.CURRENT_COUNT == 1);
    CHECK(rctx.matched.last.CURRENT_COUNT_CHANGE == 1);

    /* The writer's listener may have been installed after its match:
     * wait for the writer side, then check the published count. */
    CHECK(hdds_writer_wait_for_matched_readers(w, 1, 10000) == HDDS_OK);

    for (int i = 0; i < 5; i++) {
        char msg[32];
        int n = snprintf(msg, sizeof(msg), "net-%d", i);
        CHECK(hdds_writer_write(w, msg, (size_t)n) == HDDS_OK);
    }
    CHECK(atomic_load(&wctx.written) == 5);
    CHECK(wctx.seq_increasing);
    CHECK(wctx.last_written_len > 0);

    CHECK(wait_int_at_least(&rctx.data.count, 5, 10000));
    sleep_ms(200); /* a duplicate would show up here */
    CHECK(atomic_load(&rctx.data.count) == 5);
    /* Network delivery runs on an HDDS thread, not on the writer's. */
    CHECK(rctx.data.other_thread == 1);
    CHECK(rctx.data.last_len == strlen("net-4"));
    CHECK(memcmp(rctx.data.last, "net-4", rctx.data.last_len) == 0);
    CHECK(atomic_load(&rctx.data.taken) == 5);

    /* A second reader: the writer's listener reports it. */
    int before = atomic_load(&wctx.matched_calls);
    struct HddsDataReader *r2 = hdds_reader_create_with_qos(sub, "c_listener_net", qos);
    CHECK(r2 != NULL);
    CHECK(wait_int_at_least(&wctx.matched_calls, before + 1, 10000));
    CHECK(wctx.last_matched.CURRENT_COUNT == 2);
    CHECK(wctx.last_matched.CURRENT_COUNT_CHANGE == 1);
    CHECK(wctx.last_matched.TOTAL_COUNT >= 2);

    /* Unmatch: destroying the writer reports current_count 0 to the
     * reader. */
    int calls_before_unmatch = atomic_load(&rctx.matched.calls);
    hdds_writer_destroy(w);
    CHECK(wait_int_at_least(&rctx.matched.calls, calls_before_unmatch + 1, 15000));
    CHECK(rctx.matched.last.CURRENT_COUNT == 0);
    CHECK(rctx.matched.last.CURRENT_COUNT_CHANGE == -1);

    hdds_reader_destroy(r2);
    hdds_reader_destroy(r);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(pub);
    hdds_participant_destroy(sub);
}

/* ---- Removal while a callback runs ---- */

typedef struct {
    atomic_int entered;
    atomic_int finished;
    long hold_ms;
    unsigned char *scratch; /* touched by the callback after its sleep */
} SlowCtx;

static void on_data_slow(const uint8_t *data, size_t len, void *user_data) {
    SlowCtx *ctx = (SlowCtx *)user_data;
    (void)data;
    (void)len;
    atomic_store(&ctx->entered, 1);
    sleep_ms(ctx->hold_ms);
    /* Use the user data after the sleep: if removal returned early and the
     * test freed it, ASan reports a heap-use-after-free here. */
    ctx->scratch[0] ^= 1;
    atomic_store(&ctx->finished, 1);
}

typedef struct {
    struct HddsDataWriter *writer;
} WriteJob;

static void *write_once(void *arg) {
    WriteJob *job = (WriteJob *)arg;
    CHECK(hdds_writer_write(job->writer, "slow", 4) == HDDS_OK);
    return NULL;
}

/* `destroy_reader`: remove by destroying the reader instead of clearing. */
static void removal_waits_for_running_callback(int destroy_reader) {
    struct HddsParticipant *p = intra_participant("c_listener_removal");
    struct HddsQoS *qos = keep_last_qos();
    struct HddsDataReader *r = hdds_reader_create_with_qos(p, "c_listener_removal", qos);
    struct HddsDataWriter *w = hdds_writer_create_with_qos(p, "c_listener_removal", qos);
    CHECK(r != NULL && w != NULL);

    SlowCtx *ctx = calloc(1, sizeof(*ctx));
    CHECK(ctx != NULL);
    ctx->hold_ms = 300;
    ctx->scratch = calloc(1, 16);
    CHECK(ctx->scratch != NULL);

    HddsReaderListener l;
    memset(&l, 0, sizeof(l));
    l.ON_DATA_AVAILABLE = on_data_slow;
    l.USER_DATA = ctx;
    CHECK(hdds_reader_set_listener(r, &l) == HDDS_OK);

    /* The intra-process delivery runs the callback on the writing thread. */
    WriteJob job = { w };
    pthread_t t;
    CHECK(pthread_create(&t, NULL, write_once, &job) == 0);
    for (int i = 0; i < 2000 && !atomic_load(&ctx->entered); i++) {
        sleep_ms(1);
    }
    CHECK(atomic_load(&ctx->entered) == 1);

    if (destroy_reader) {
        hdds_reader_destroy(r);
        r = NULL;
    } else {
        CHECK(hdds_reader_clear_listener(r) == HDDS_OK);
    }
    /* Removal returned: the running callback must have finished. */
    CHECK(atomic_load(&ctx->finished) == 1);
    free(ctx->scratch);
    free(ctx);

    CHECK(pthread_join(t, NULL) == 0);
    if (r != NULL) {
        /* No callback after removal (ctx is freed: one would be a UAF). */
        CHECK(hdds_writer_write(w, "late", 4) == HDDS_OK);
        hdds_reader_destroy(r);
    }
    hdds_writer_destroy(w);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
}

static void test_clear_waits_for_running_callback(void) {
    removal_waits_for_running_callback(0);
}

static void test_destroy_waits_for_running_callback(void) {
    removal_waits_for_running_callback(1);
}

/* ---- Removal from inside the callback ---- */

typedef struct {
    struct HddsDataReader *reader;
    atomic_int count;
    int clear_rc;
} SelfClearCtx;

static void on_data_self_clear(const uint8_t *data, size_t len, void *user_data) {
    SelfClearCtx *ctx = (SelfClearCtx *)user_data;
    (void)data;
    (void)len;
    atomic_fetch_add(&ctx->count, 1);
    ctx->clear_rc = (int)hdds_reader_clear_listener(ctx->reader);
}

static void test_clear_from_inside_callback(void) {
    struct HddsParticipant *p = intra_participant("c_listener_self_clear");
    struct HddsQoS *qos = keep_last_qos();
    struct HddsDataReader *r = hdds_reader_create_with_qos(p, "c_listener_self_clear", qos);
    struct HddsDataWriter *w = hdds_writer_create_with_qos(p, "c_listener_self_clear", qos);
    CHECK(r != NULL && w != NULL);

    SelfClearCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.reader = r;
    ctx.clear_rc = -1;
    HddsReaderListener l;
    memset(&l, 0, sizeof(l));
    l.ON_DATA_AVAILABLE = on_data_self_clear;
    l.USER_DATA = &ctx;
    CHECK(hdds_reader_set_listener(r, &l) == HDDS_OK);

    CHECK(hdds_writer_write(w, "a", 1) == HDDS_OK);
    CHECK(atomic_load(&ctx.count) == 1);
    CHECK(ctx.clear_rc == HDDS_OK);
    CHECK(hdds_writer_write(w, "b", 1) == HDDS_OK);
    CHECK(atomic_load(&ctx.count) == 1);

    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
}

/* ---- Replacing a listener ---- */

static void test_replace_listener(void) {
    struct HddsParticipant *p = intra_participant("c_listener_replace");
    struct HddsQoS *qos = keep_last_qos();
    struct HddsDataReader *r = hdds_reader_create_with_qos(p, "c_listener_replace", qos);
    struct HddsDataWriter *w = hdds_writer_create_with_qos(p, "c_listener_replace", qos);
    CHECK(r != NULL && w != NULL);

    DataCtx first, second;
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    first.writer_thread = second.writer_thread = pthread_self();

    HddsReaderListener l;
    memset(&l, 0, sizeof(l));
    l.ON_DATA_AVAILABLE = on_data;
    l.USER_DATA = &first;
    CHECK(hdds_reader_set_listener(r, &l) == HDDS_OK);
    CHECK(hdds_writer_write(w, "1", 1) == HDDS_OK);

    l.USER_DATA = &second;
    CHECK(hdds_reader_set_listener(r, &l) == HDDS_OK);
    CHECK(hdds_writer_write(w, "2", 1) == HDDS_OK);
    CHECK(hdds_writer_write(w, "3", 1) == HDDS_OK);

    CHECK(atomic_load(&first.count) == 1);
    CHECK(atomic_load(&second.count) == 2);

    /* A listener with only NULL callbacks reports nothing. */
    memset(&l, 0, sizeof(l));
    CHECK(hdds_reader_set_listener(r, &l) == HDDS_OK);
    CHECK(hdds_writer_write(w, "4", 1) == HDDS_OK);
    CHECK(atomic_load(&second.count) == 2);

    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
}

/* ---- Exchange: the replaced listener's user_data ---- */

static void on_written_noop(const uint8_t *data, size_t len, uint64_t seq, void *user_data) {
    (void)data;
    (void)len;
    (void)seq;
    (void)user_data;
}

static void test_exchange_reports_previous_user_data(void) {
    struct HddsParticipant *p = intra_participant("c_listener_exchange");
    struct HddsDataReader *r = hdds_reader_create(p, "c_listener_exchange");
    struct HddsDataWriter *w = hdds_writer_create(p, "c_listener_exchange");
    CHECK(r != NULL && w != NULL);
    int a = 0, b = 0;
    void *prev = (void *)&prev;

    HddsReaderListener rl;
    memset(&rl, 0, sizeof(rl));
    rl.ON_DATA_AVAILABLE = on_data;
    rl.USER_DATA = &a;
    CHECK(hdds_reader_exchange_listener(r, &rl, &prev) == HDDS_OK);
    CHECK(prev == NULL);
    rl.USER_DATA = &b;
    CHECK(hdds_reader_exchange_listener(r, &rl, &prev) == HDDS_OK);
    CHECK(prev == &a);
    CHECK(hdds_reader_exchange_listener(r, NULL, &prev) == HDDS_OK);
    CHECK(prev == &b);
    CHECK(hdds_reader_exchange_listener(r, NULL, &prev) == HDDS_OK);
    CHECK(prev == NULL);
    CHECK(hdds_reader_exchange_listener(r, NULL, NULL) == HDDS_OK);
    CHECK(hdds_reader_exchange_listener(NULL, &rl, &prev) == HDDS_INVALID_ARGUMENT);

    HddsWriterListener wl;
    memset(&wl, 0, sizeof(wl));
    wl.ON_SAMPLE_WRITTEN = on_written_noop;
    wl.USER_DATA = &a;
    CHECK(hdds_writer_exchange_listener(w, &wl, &prev) == HDDS_OK);
    CHECK(prev == NULL);
    CHECK(hdds_writer_set_listener(w, &wl) == HDDS_OK);
    CHECK(hdds_writer_exchange_listener(w, NULL, &prev) == HDDS_OK);
    CHECK(prev == &a);

    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

/* ---- Destroy from inside the entity's own callback ---- */

static struct HddsDataWriter *g_leaked_writer; /* kept reachable for LSan */

typedef struct {
    struct HddsDataWriter *writer;
    atomic_int calls;
} DestroyInsideCtx;

static void on_written_destroy(const uint8_t *data, size_t len, uint64_t seq, void *user_data) {
    DestroyInsideCtx *ctx = (DestroyInsideCtx *)user_data;
    (void)data;
    (void)len;
    (void)seq;
    atomic_fetch_add(&ctx->calls, 1);
    /* write() continues on the writer after this returns: HDDS must not
     * free it here (it leaks it and logs an error instead). */
    hdds_writer_destroy(ctx->writer);
}

static void test_destroy_inside_own_callback_does_not_free(void) {
    struct HddsParticipant *p = intra_participant("c_listener_destroy_inside");
    struct HddsDataWriter *w = hdds_writer_create(p, "c_listener_destroy_inside");
    CHECK(w != NULL);
    g_leaked_writer = w;
    DestroyInsideCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.writer = w;
    HddsWriterListener wl;
    memset(&wl, 0, sizeof(wl));
    wl.ON_SAMPLE_WRITTEN = on_written_destroy;
    wl.USER_DATA = &ctx;
    CHECK(hdds_writer_set_listener(w, &wl) == HDDS_OK);
    CHECK(hdds_writer_write(w, "x", 1) == HDDS_OK);
    CHECK(atomic_load(&ctx.calls) == 1);
    /* The listener was removed by the destroy. */
    CHECK(hdds_writer_write(w, "y", 1) == HDDS_OK);
    CHECK(atomic_load(&ctx.calls) == 1);
    hdds_participant_destroy(p);
}

int main(void) {
    printf("=== HDDS C SDK: Listener Tests ===\n\n");

    RUN_TEST(test_null_arguments);
    RUN_TEST(test_data_available_intra_process);
    RUN_TEST(test_take_inside_callback);
    RUN_TEST(test_replace_listener);
    RUN_TEST(test_clear_waits_for_running_callback);
    RUN_TEST(test_destroy_waits_for_running_callback);
    RUN_TEST(test_clear_from_inside_callback);
    RUN_TEST(test_exchange_reports_previous_user_data);
    RUN_TEST(test_destroy_inside_own_callback_does_not_free);
    RUN_TEST(test_matched_and_network_data);

    printf("\n%d tests passed\n", passed);
    return 0;
}
