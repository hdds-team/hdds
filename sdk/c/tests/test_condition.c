// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test: ContentFilteredTopic, ReadCondition, QueryCondition
 *
 * `condition_ffi.rs` was never mod-declared in `crates/hdds-c/src/lib.rs`
 * (unlike `dynamic_ffi`/`filter_ffi`/`rpc_ffi`, since fixed), so none of
 * this API was ever compiled into libhdds_c, let alone exercised from C.
 * This suite links against the real library and drives it end to end.
 *
 * `hdds_create_query_condition` and `hdds_create_content_filtered_topic`
 * now take a `HddsTypeDescriptor *` (dynamic-type schema): the C reader
 * carries an opaque byte payload, so a filter or a query that looks INSIDE
 * a sample needs to know its layout to decode it. A payload the descriptor
 * cannot decode is rejected by a filter and matched by no query, whatever
 * the expression -- see `crates/hdds-c/src/condition_ffi.rs` module docs.
 *
 * Tests:
 *   - ReadCondition: create, mask getters, initial trigger value, delete
 *   - QueryCondition: create, expression/parameter getters, delete
 *   - ContentFilteredTopic: create, expression getter (with a too-small
 *     buffer), set_params, delete
 *   - ContentFilteredTopic -> DataReader: the filtered reader is a REAL
 *     DataReader bound to the related topic, and the filter genuinely
 *     decodes and evaluates the payload (proven by writing samples on
 *     both sides of the threshold and comparing what the filtered reader
 *     and a plain reader each observe).
 *   - WaitSet attach/detach for ReadCondition/QueryCondition: duplicate
 *     attach rejected, detach removes the registration, destruction order
 *     (condition-then-waitset and waitset-then-condition) is memory-safe.
 *   - A ReadCondition attached to a WaitSet DOES wake when matching data
 *     arrives on its DataReader -- see test_read_condition_wakes_on_data_arrival().
 *     This used to be a documented gap (no DataReader called
 *     ReadCondition::set_trigger_value); the reader side is now wired
 *     (DataReader::create_readcondition + an arrival hook on the reader's
 *     StatusCondition), so this test asserts the wake instead of its
 *     absence.
 *   - NULL-safety on every entry point
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

/* ---- Shared fixture: a one-field int32 type descriptor ---- */

static struct HddsTypeDescriptor *one_field_type(const char *type_name, const char *field_name) {
    struct HddsTypeBuilder *tb = hdds_type_builder_new(type_name);
    assert(tb != NULL);
    assert(hdds_type_builder_add_field(tb, field_name, HDDS_PRIM_I32) == HDDS_OK);
    struct HddsTypeDescriptor *desc = hdds_type_builder_build(tb);
    assert(desc != NULL);
    return desc;
}

static size_t encode_one_field(const struct HddsTypeDescriptor *desc, const char *field_name,
                               int32_t value, uint8_t *buf, size_t cap) {
    struct HddsDynamicData *data = hdds_dynamic_data_new(desc);
    assert(data != NULL);
    assert(hdds_dynamic_data_set_i32(data, field_name, value) == HDDS_OK);
    size_t len = 0;
    assert(hdds_dynamic_data_encode(data, buf, cap, &len) == HDDS_OK);
    hdds_dynamic_data_destroy(data);
    return len;
}

/* ---- Tests ---- */

static void test_read_condition_lifecycle(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("RCLifecycle", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsDataReader *r = hdds_reader_create(p, "RCTopic");
    assert(r != NULL);

    struct HddsReadCondition *cond = hdds_create_read_condition(r, 0x3, 0x3, 0x7);
    assert(cond != NULL);

    assert(hdds_read_condition_get_sample_state_mask(cond) == 0x3);
    assert(hdds_read_condition_get_view_state_mask(cond) == 0x3);
    assert(hdds_read_condition_get_instance_state_mask(cond) == 0x7);
    /* Freshly created, no reader has pushed a matching transition yet. */
    assert(hdds_read_condition_get_trigger(cond) == false);

    hdds_read_condition_delete(cond);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

static void test_query_condition_lifecycle(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("QCLifecycle", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsDataReader *r = hdds_reader_create(p, "QCTopic");
    assert(r != NULL);
    struct HddsTypeDescriptor *desc = one_field_type("Reading", "temperature");

    const char *params[] = {"25"};
    struct HddsQueryCondition *cond = hdds_create_query_condition(
        r, 0x3, 0x3, 0x7, desc, "temperature > %0", params, 1);
    assert(cond != NULL);

    char buf[64] = {0};
    size_t needed = hdds_query_condition_get_expression(cond, buf, sizeof(buf));
    assert(needed == strlen("temperature > %0"));
    assert(strcmp(buf, "temperature > %0") == 0);

    /* Buffer too small: the returned count is still the bytes needed. */
    char small[4];
    size_t needed_small = hdds_query_condition_get_expression(cond, small, sizeof(small));
    assert(needed_small == needed);

    const char *new_params[] = {"30"};
    assert(hdds_query_condition_set_parameters(cond, new_params, 1) == HDDS_OK);

    /* No type descriptor, no condition. */
    assert(hdds_create_query_condition(r, 0x3, 0x3, 0x7, NULL, "temperature > %0", params, 1)
           == NULL);

    hdds_query_condition_delete(cond);
    hdds_type_descriptor_destroy(desc);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

static void test_content_filtered_topic_lifecycle(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("CFTLifecycle", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsTypeDescriptor *desc = one_field_type("Temperature", "value");

    const char *params[] = {"25"};
    struct HddsContentFilteredTopic *cft = hdds_create_content_filtered_topic(
        p, "HighTemp", "Temperature", desc, "value > %0", params, 1);
    assert(cft != NULL);

    char buf[64] = {0};
    size_t needed = hdds_content_filtered_topic_get_expression(cft, buf, sizeof(buf));
    assert(needed == strlen("value > %0"));
    assert(strcmp(buf, "value > %0") == 0);

    /* Capacity too small still reports the number of bytes needed. */
    char small[4];
    size_t needed_small = hdds_content_filtered_topic_get_expression(cft, small, sizeof(small));
    assert(needed_small == needed);

    const char *new_params[] = {"30"};
    assert(hdds_content_filtered_topic_set_params(cft, new_params, 1) == HDDS_OK);

    /* An invalid filter expression must fail closed, not hand back a CFT
     * that will silently pass everything or nothing by accident. */
    struct HddsContentFilteredTopic *bad = hdds_create_content_filtered_topic(
        p, "Bad", "Temperature", desc, "@@not an expression", NULL, 0);
    assert(bad == NULL);

    /* No type descriptor, no CFT. */
    assert(hdds_create_content_filtered_topic(p, "Bad2", "Temperature", NULL, "value > %0",
                                              params, 1) == NULL);

    hdds_content_filtered_topic_delete(cft);
    hdds_type_descriptor_destroy(desc);
    hdds_participant_destroy(p);
}

/* The filtered reader must be a real DataReader wired to the related topic,
 * and the filter must genuinely decode and evaluate the payload against
 * the type descriptor: prove it by writing one sample on each side of the
 * threshold and comparing what the filtered reader and a plain reader each
 * observe.
 */
static void test_filtered_reader_end_to_end(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("CFTReader", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsTypeDescriptor *desc = one_field_type("Reading", "value");

    struct HddsDataWriter *w = hdds_writer_create(p, "CFCondTopic");
    assert(w != NULL);

    const char *params[] = {"25"};
    struct HddsContentFilteredTopic *cft = hdds_create_content_filtered_topic(
        p, "HighValue", "CFCondTopic", desc, "value > %0", params, 1);
    assert(cft != NULL);

    struct HddsDataReader *filtered = hdds_create_reader_filtered(p, cft, NULL);
    assert(filtered != NULL);

    struct HddsDataReader *plain = hdds_reader_create(p, "CFCondTopic");
    assert(plain != NULL);

    uint8_t buf[64];
    size_t len = 0;

    /* Below the threshold: the plain reader sees it, the filtered one does not. */
    len = encode_one_field(desc, "value", 10, buf, sizeof(buf));
    assert(hdds_writer_write(w, buf, len) == HDDS_OK);

    uint8_t take_buf[64];
    size_t take_len = 0;
    assert(hdds_reader_take(plain, take_buf, sizeof(take_buf), &take_len) == HDDS_OK);
    assert(take_len == len);
    assert(hdds_reader_take(filtered, take_buf, sizeof(take_buf), &take_len) == HDDS_NOT_FOUND);

    /* Above the threshold: both readers see it. */
    len = encode_one_field(desc, "value", 42, buf, sizeof(buf));
    assert(hdds_writer_write(w, buf, len) == HDDS_OK);
    assert(hdds_reader_take(plain, take_buf, sizeof(take_buf), &take_len) == HDDS_OK);
    assert(hdds_reader_take(filtered, take_buf, sizeof(take_buf), &take_len) == HDDS_OK);
    assert(take_len == len);

    hdds_reader_destroy(plain);
    hdds_reader_destroy(filtered);
    hdds_content_filtered_topic_delete(cft);
    hdds_type_descriptor_destroy(desc);
    hdds_writer_destroy(w);
    hdds_participant_destroy(p);
}

/* Attach is real WaitSet plumbing (same Condition::add_waitset_signal hook
 * StatusCondition/GuardCondition use), not a validate-and-log stub. Prove
 * it the same way test_waitset.c proves it for guard/status conditions:
 * duplicate attach is rejected and detach actually removes the
 * registration (a second detach reports NOT_FOUND).
 */
static void test_waitset_attach_conditions(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("CondWaitSet", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsDataReader *r = hdds_reader_create(p, "CondWSTopic");
    assert(r != NULL);
    struct HddsTypeDescriptor *desc = one_field_type("Reading", "id");
    struct HddsWaitSet *ws = hdds_waitset_create();
    assert(ws != NULL);

    struct HddsReadCondition *rc = hdds_create_read_condition(r, 0x3, 0x3, 0x7);
    assert(rc != NULL);
    assert(hdds_waitset_attach_read_condition(ws, rc) == HDDS_OK);
    /* Attaching the same ReadCondition twice to the same WaitSet must be
     * rejected, exactly like attach_status_condition/attach_guard_condition. */
    assert(hdds_waitset_attach_read_condition(ws, rc) != HDDS_OK);

    const char *qparams[] = {"1"};
    struct HddsQueryCondition *qc =
        hdds_create_query_condition(r, 0x3, 0x3, 0x7, desc, "id > %0", qparams, 1);
    assert(qc != NULL);
    assert(hdds_waitset_attach_query_condition(ws, qc) == HDDS_OK);

    /* Detach must be real too: it removes the registration, so a repeat
     * detach on the same pointer reports NOT_FOUND. */
    assert(hdds_waitset_detach_condition(ws, rc) == HDDS_OK);
    assert(hdds_waitset_detach_condition(ws, rc) == HDDS_NOT_FOUND);
    assert(hdds_waitset_detach_condition(ws, qc) == HDDS_OK);

    hdds_query_condition_delete(qc);
    hdds_read_condition_delete(rc);
    hdds_type_descriptor_destroy(desc);
    hdds_waitset_destroy(ws);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

/* Ownership: whichever of {condition, waitset} is destroyed first must not
 * leave the other with a dangling pointer. Both a ReadCondition and a
 * QueryCondition are attached via an Arc clone held by the WaitSet
 * (independent of the C-side handle's own refcount, see the ownership note
 * in crates/hdds-c/src/waitset/mod.rs), so either destruction order is
 * memory-safe. This test exercises both orders; it is a crash/UB check
 * (run it under valgrind/ASan for the real proof), not a functional check.
 */
static void test_condition_waitset_destruction_order(void) {
    struct HddsParticipant *p = hdds_participant_create_with_transport(
        "CondDestroyOrder", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsDataReader *r = hdds_reader_create(p, "CondDestroyTopic");
    assert(r != NULL);
    struct HddsTypeDescriptor *desc = one_field_type("Reading", "id");

    /* Order 1: destroy the WaitSet while the condition handle is still
     * live. The condition must remain usable afterward. */
    {
        struct HddsWaitSet *ws = hdds_waitset_create();
        struct HddsReadCondition *rc = hdds_create_read_condition(r, 0x3, 0x3, 0x7);
        assert(hdds_waitset_attach_read_condition(ws, rc) == HDDS_OK);
        hdds_waitset_destroy(ws);
        assert(hdds_read_condition_get_trigger(rc) == false);
        hdds_read_condition_delete(rc);
    }

    /* Order 2: release the condition handle while it is still attached.
     * The WaitSet's own Arc clone must keep it alive; waiting must not
     * crash or read freed memory. */
    {
        struct HddsWaitSet *ws = hdds_waitset_create();
        const char *qparams[] = {"1"};
        struct HddsQueryCondition *qc =
            hdds_create_query_condition(r, 0x3, 0x3, 0x7, desc, "id > %0", qparams, 1);
        assert(hdds_waitset_attach_query_condition(ws, qc) == HDDS_OK);
        hdds_query_condition_delete(qc);

        const void *triggered[2];
        size_t count = 0;
        hdds_waitset_wait(ws, 50000000LL /* 50ms */, triggered, 2, &count);
        hdds_waitset_destroy(ws);
    }

    /* Repeated delete on the same (now-freed) handle value is a documented
     * safe no-op, not a double-free: the registry backing the handle
     * refuses the second release. Exercised here rather than asserted
     * structurally, since there is nothing left to inspect from C. */
    {
        struct HddsReadCondition *rc = hdds_create_read_condition(r, 0x3, 0x3, 0x7);
        hdds_read_condition_delete(rc);
        hdds_read_condition_delete(rc);
    }

    hdds_type_descriptor_destroy(desc);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

/* A ReadCondition attached to a WaitSet wakes it when matching data
 * arrives on its associated DataReader: DataReader::create_readcondition
 * registers an arrival hook on the reader's StatusCondition (see
 * crates/hdds/src/dds/reader/conditions.rs), so a DATA_AVAILABLE raise on
 * the reader signals every WaitSet attached through the condition, which
 * then re-evaluates the trigger before returning it.
 *
 * This test used to assert the OPPOSITE on purpose (no DataReader called
 * ReadCondition::set_trigger_value); now that the reader side is wired,
 * it asserts the wake instead of the gap.
 */
static void test_read_condition_wakes_on_data_arrival(void) {
    struct HddsParticipant *p = hdds_participant_create_with_transport(
        "CondWakes", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsDataWriter *w = hdds_writer_create(p, "CondWakesTopic");
    struct HddsDataReader *r = hdds_reader_create(p, "CondWakesTopic");
    assert(w != NULL && r != NULL);

    struct HddsReadCondition *rc = hdds_create_read_condition(r, 0x3, 0x3, 0x7);
    assert(rc != NULL);
    struct HddsWaitSet *ws = hdds_waitset_create();
    assert(hdds_waitset_attach_read_condition(ws, rc) == HDDS_OK);

    /* Nothing written yet: a short wait times out with nothing triggered. */
    const void *triggered[4];
    size_t count = 99;
    assert(hdds_waitset_wait(ws, 100000000LL /* 100ms */, triggered, 4, &count) == HDDS_OK);
    assert(count == 0);
    assert(hdds_read_condition_get_trigger(rc) == false);

    const char *msg = "payload";
    assert(hdds_writer_write(w, msg, strlen(msg) + 1) == HDDS_OK);

    /* The write wakes the WaitSet, reporting this condition. */
    assert(hdds_waitset_wait(ws, 2000000000LL /* 2s */, triggered, 4, &count) == HDDS_OK);
    assert(count == 1);
    assert(triggered[0] == (const void *)rc);
    assert(hdds_read_condition_get_trigger(rc) == true);

    /* take_w_condition drains the match; the trigger drops and the WaitSet
     * blocks again. */
    uint8_t buf[64];
    size_t len = 0;
    struct HddsSampleInfo info;
    memset(&info, 0, sizeof(info));
    assert(hdds_reader_take_w_condition(r, rc, buf, sizeof(buf), &len, &info) == HDDS_OK);
    assert(len == strlen(msg) + 1);
    assert(strcmp((char *)buf, msg) == 0);
    assert(info.VALID_DATA == true);
    assert(hdds_read_condition_get_trigger(rc) == false);

    count = 99;
    assert(hdds_waitset_wait(ws, 100000000LL, triggered, 4, &count) == HDDS_OK);
    assert(count == 0);

    hdds_read_condition_delete(rc);
    hdds_waitset_destroy(ws);
    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

static void test_null_safety(void) {
    assert(hdds_create_content_filtered_topic(NULL, NULL, NULL, NULL, NULL, NULL, 0) == NULL);
    assert(hdds_create_read_condition(NULL, 0, 0, 0) == NULL);
    assert(hdds_create_query_condition(NULL, 0, 0, 0, NULL, NULL, NULL, 0) == NULL);
    assert(hdds_create_reader_filtered(NULL, NULL, NULL) == NULL);
    assert(hdds_read_condition_get_trigger(NULL) == false);
    assert(hdds_read_condition_get_sample_state_mask(NULL) == 0);
    assert(hdds_read_condition_get_view_state_mask(NULL) == 0);
    assert(hdds_read_condition_get_instance_state_mask(NULL) == 0);
    assert(hdds_content_filtered_topic_get_expression(NULL, NULL, 0) == 0);

    /* Delete on NULL is a documented no-op. */
    hdds_content_filtered_topic_delete(NULL);
    hdds_read_condition_delete(NULL);
    hdds_query_condition_delete(NULL);
    hdds_content_filtered_topic_set_params(NULL, NULL, 0);

    assert(hdds_waitset_attach_read_condition(NULL, NULL) == HDDS_INVALID_ARGUMENT);
    assert(hdds_waitset_attach_query_condition(NULL, NULL) == HDDS_INVALID_ARGUMENT);
    assert(hdds_query_condition_set_parameters(NULL, NULL, 0) == HDDS_INVALID_ARGUMENT);
}

/* ---- Main ---- */

int main(void) {
    printf("test_condition\n");

    RUN_TEST(test_read_condition_lifecycle);
    RUN_TEST(test_query_condition_lifecycle);
    RUN_TEST(test_content_filtered_topic_lifecycle);
    RUN_TEST(test_filtered_reader_end_to_end);
    RUN_TEST(test_waitset_attach_conditions);
    RUN_TEST(test_condition_waitset_destruction_order);
    RUN_TEST(test_read_condition_wakes_on_data_arrival);
    RUN_TEST(test_null_safety);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
