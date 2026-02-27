// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test: WaitSet Operations
 *
 * Tests:
 *   - Create / destroy waitset
 *   - Attach / detach guard condition
 *   - Attach / detach status condition
 *   - Wait with timeout (should timeout with no data)
 *   - Trigger guard condition, verify wait returns
 *   - Multiple conditions attached simultaneously
 */

#include <hdds.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int passed = 0;
static int failed = 0;

#define RUN_TEST(fn) do {          \
    printf("  %-50s", #fn);        \
    fn();                          \
    printf("[PASS]\n");            \
    passed++;                      \
} while (0)

/* ---- Tests ---- */

static void test_waitset_create_destroy(void) {
    struct HddsWaitSet *ws = hdds_waitset_create();
    assert(ws != NULL);
    hdds_waitset_destroy(ws);
}

static void test_guard_condition_create_destroy(void) {
    const struct HddsGuardCondition *gc = hdds_guard_condition_create();
    assert(gc != NULL);
    hdds_guard_condition_release(gc);
}

static void test_attach_detach_guard(void) {
    struct HddsWaitSet *ws = hdds_waitset_create();
    const struct HddsGuardCondition *gc = hdds_guard_condition_create();

    enum HddsError err = hdds_waitset_attach_guard_condition(ws, gc);
    assert(err == HDDS_OK);

    err = hdds_waitset_detach_condition(ws, (const void *)gc);
    assert(err == HDDS_OK);

    hdds_guard_condition_release(gc);
    hdds_waitset_destroy(ws);
}

static void test_attach_detach_status_condition(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("WSStatusTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    struct HddsDataReader *r = hdds_reader_create(p, "WSTestTopic");
    assert(r != NULL);

    const struct HddsStatusCondition *sc = hdds_reader_get_status_condition(r);
    assert(sc != NULL);

    struct HddsWaitSet *ws = hdds_waitset_create();

    enum HddsError err = hdds_waitset_attach_status_condition(ws, sc);
    assert(err == HDDS_OK);

    err = hdds_waitset_detach_condition(ws, (const void *)sc);
    assert(err == HDDS_OK);

    hdds_status_condition_release(sc);
    hdds_waitset_destroy(ws);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

static void test_wait_timeout(void) {
    struct HddsWaitSet *ws = hdds_waitset_create();
    const struct HddsGuardCondition *gc = hdds_guard_condition_create();
    hdds_waitset_attach_guard_condition(ws, gc);

    const void *triggered[4];
    size_t count = 0;

    /* 100ms timeout — nothing triggered, should return with count=0 */
    hdds_waitset_wait(ws, 100000000LL, triggered, 4, &count);
    assert(count == 0);

    hdds_waitset_detach_condition(ws, (const void *)gc);
    hdds_guard_condition_release(gc);
    hdds_waitset_destroy(ws);
}

static void test_guard_trigger_wakes_wait(void) {
    struct HddsWaitSet *ws = hdds_waitset_create();
    const struct HddsGuardCondition *gc = hdds_guard_condition_create();
    hdds_waitset_attach_guard_condition(ws, gc);

    /* Trigger before waiting */
    hdds_guard_condition_set_trigger(gc, true);

    const void *triggered[4];
    size_t count = 0;

    enum HddsError err = hdds_waitset_wait(ws, 1000000000LL, triggered, 4, &count);
    assert(err == HDDS_OK);
    assert(count >= 1);

    /* Verify the guard condition is among the triggered conditions */
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (triggered[i] == (const void *)gc) {
            found = 1;
        }
    }
    assert(found);

    /* Reset */
    hdds_guard_condition_set_trigger(gc, false);

    hdds_waitset_detach_condition(ws, (const void *)gc);
    hdds_guard_condition_release(gc);
    hdds_waitset_destroy(ws);
}

static void test_multiple_guards(void) {
    struct HddsWaitSet *ws = hdds_waitset_create();
    const struct HddsGuardCondition *gc1 = hdds_guard_condition_create();
    const struct HddsGuardCondition *gc2 = hdds_guard_condition_create();

    hdds_waitset_attach_guard_condition(ws, gc1);
    hdds_waitset_attach_guard_condition(ws, gc2);

    /* Trigger only gc2 */
    hdds_guard_condition_set_trigger(gc2, true);

    const void *triggered[4];
    size_t count = 0;
    hdds_waitset_wait(ws, 500000000LL, triggered, 4, &count);
    assert(count >= 1);

    /* gc2 should be triggered */
    int found_gc2 = 0;
    for (size_t i = 0; i < count; i++) {
        if (triggered[i] == (const void *)gc2) found_gc2 = 1;
    }
    assert(found_gc2);

    hdds_guard_condition_set_trigger(gc2, false);

    hdds_waitset_detach_condition(ws, (const void *)gc1);
    hdds_waitset_detach_condition(ws, (const void *)gc2);
    hdds_guard_condition_release(gc1);
    hdds_guard_condition_release(gc2);
    hdds_waitset_destroy(ws);
}

static void test_data_triggers_status_condition(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("WSDataTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    struct HddsDataWriter *w = hdds_writer_create(p, "WSTriggerTopic");
    struct HddsDataReader *r = hdds_reader_create(p, "WSTriggerTopic");
    assert(w != NULL);
    assert(r != NULL);

    const struct HddsStatusCondition *sc = hdds_reader_get_status_condition(r);
    struct HddsWaitSet *ws = hdds_waitset_create();
    hdds_waitset_attach_status_condition(ws, sc);

    /* Write data */
    const char *msg = "trigger";
    hdds_writer_write(w, msg, strlen(msg) + 1);

    /* Wait — should be triggered by new data */
    const void *triggered[4];
    size_t count = 0;
    hdds_waitset_wait(ws, 1000000000LL, triggered, 4, &count);

    /* Drain the reader */
    uint8_t buf[128];
    size_t len;
    int received = 0;
    while (hdds_reader_take(r, buf, sizeof(buf), &len) == HDDS_OK) {
        received++;
    }
    assert(received >= 1);

    hdds_waitset_detach_condition(ws, (const void *)sc);
    hdds_status_condition_release(sc);
    hdds_waitset_destroy(ws);
    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

/* ---- Main ---- */

int main(void) {
    printf("test_waitset\n");

    RUN_TEST(test_waitset_create_destroy);
    RUN_TEST(test_guard_condition_create_destroy);
    RUN_TEST(test_attach_detach_guard);
    RUN_TEST(test_attach_detach_status_condition);
    RUN_TEST(test_wait_timeout);
    RUN_TEST(test_guard_trigger_wakes_wait);
    RUN_TEST(test_multiple_guards);
    RUN_TEST(test_data_triggers_status_condition);

    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
