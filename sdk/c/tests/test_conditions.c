// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test: ReadCondition, QueryCondition, ContentFilteredTopic
 *
 * Tests (one per family, on an intra-process participant):
 *   - ReadCondition attached to a WaitSet wakes on arrival, and only then
 *   - QueryCondition with a %0 parameter selects on content; set_parameters
 *   - ContentFilteredTopic reader receives only the matching samples
 *
 * Samples are `{ int32 id; int32 value; }` bodies produced with the dynamic
 * type API, which is also what the conditions decode the payload with.
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

/* ---- Fixture ---- */

static struct HddsTypeDescriptor *reading_type(void) {
    struct HddsTypeBuilder *tb = hdds_type_builder_new("Reading");
    assert(tb != NULL);
    assert(hdds_type_builder_add_field(tb, "id", HDDS_PRIM_I32) == HDDS_OK);
    assert(hdds_type_builder_add_field(tb, "value", HDDS_PRIM_I32) == HDDS_OK);
    struct HddsTypeDescriptor *desc = hdds_type_builder_build(tb);
    assert(desc != NULL);
    return desc;
}

static size_t encode_reading(const struct HddsTypeDescriptor *desc, int32_t id, int32_t value,
                             uint8_t *buf, size_t cap) {
    struct HddsDynamicData *data = hdds_dynamic_data_new(desc);
    assert(data != NULL);
    assert(hdds_dynamic_data_set_i32(data, "id", id) == HDDS_OK);
    assert(hdds_dynamic_data_set_i32(data, "value", value) == HDDS_OK);
    size_t len = 0;
    assert(hdds_dynamic_data_encode(data, buf, cap, &len) == HDDS_OK);
    hdds_dynamic_data_destroy(data);
    return len;
}

static void write_reading(struct HddsDataWriter *w, const struct HddsTypeDescriptor *desc,
                          int32_t id, int32_t value) {
    uint8_t buf[64];
    size_t len = encode_reading(desc, id, value, buf, sizeof(buf));
    assert(hdds_writer_write(w, buf, len) == HDDS_OK);
}

static int32_t decode_value(const struct HddsTypeDescriptor *desc, const uint8_t *buf, size_t len) {
    struct HddsDynamicData *data = hdds_dynamic_data_decode(desc, buf, len);
    assert(data != NULL);
    int32_t value = 0;
    assert(hdds_dynamic_data_get_i32(data, "value", &value) == HDDS_OK);
    hdds_dynamic_data_destroy(data);
    return value;
}

/* ---- Tests ---- */

static void test_read_condition_on_waitset(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("CondReadTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsTypeDescriptor *desc = reading_type();
    struct HddsDataWriter *w = hdds_writer_create(p, "CondReadTopic");
    struct HddsDataReader *r = hdds_reader_create(p, "CondReadTopic");
    assert(w != NULL && r != NULL);

    struct HddsReadCondition *rc = hdds_create_read_condition(
        r, HDDS_SAMPLE_STATE_NOT_READ, HDDS_VIEW_STATE_ANY, HDDS_INSTANCE_STATE_ALIVE);
    assert(rc != NULL);
    assert(hdds_read_condition_get_sample_state_mask(rc) == HDDS_SAMPLE_STATE_NOT_READ);
    assert(hdds_read_condition_get_trigger(rc) == false);

    struct HddsWaitSet *ws = hdds_waitset_create();
    assert(hdds_waitset_attach_read_condition(ws, rc) == HDDS_OK);

    /* Nothing written: a short wait times out with nothing triggered. */
    const void *triggered[4];
    size_t count = 99;
    assert(hdds_waitset_wait(ws, 100000000LL, triggered, 4, &count) == HDDS_OK);
    assert(count == 0);

    /* Written: the wait returns this condition. */
    write_reading(w, desc, 1, 42);
    assert(hdds_waitset_wait(ws, 2000000000LL, triggered, 4, &count) == HDDS_OK);
    assert(count == 1);
    assert(triggered[0] == (const void *)rc);
    assert(hdds_read_condition_get_trigger(rc) == true);

    /* take_w_condition drains it with its SampleInfo. */
    uint8_t buf[64];
    size_t len = 0;
    struct HddsSampleInfo info;
    memset(&info, 0, sizeof(info));
    assert(hdds_reader_take_w_condition(r, rc, buf, sizeof(buf), &len, &info) == HDDS_OK);
    assert(decode_value(desc, buf, len) == 42);
    assert(info.VALID_DATA == true);
    assert(info.SAMPLE_STATE == HDDS_SAMPLE_STATE_NOT_READ);
    assert(info.VIEW_STATE == HDDS_VIEW_STATE_NEW);
    assert(info.INSTANCE_STATE == HDDS_INSTANCE_STATE_ALIVE);
    assert(hdds_reader_take_w_condition(r, rc, buf, sizeof(buf), &len, NULL) == HDDS_NOT_FOUND);
    assert(hdds_read_condition_get_trigger(rc) == false);

    /* Taken: the WaitSet blocks again. */
    assert(hdds_waitset_wait(ws, 100000000LL, triggered, 4, &count) == HDDS_OK);
    assert(count == 0);

    /* A read leaves the sample but lowers a NOT_READ condition. */
    write_reading(w, desc, 2, 7);
    assert(hdds_read_condition_get_trigger(rc) == true);
    assert(hdds_reader_read_w_condition(r, rc, buf, sizeof(buf), &len, &info) == HDDS_OK);
    assert(decode_value(desc, buf, len) == 7);
    assert(info.SAMPLE_STATE == HDDS_SAMPLE_STATE_NOT_READ);
    assert(hdds_read_condition_get_trigger(rc) == false);
    assert(hdds_reader_take(r, buf, sizeof(buf), &len) == HDDS_OK);

    assert(hdds_waitset_detach_condition(ws, (const void *)rc) == HDDS_OK);
    hdds_read_condition_delete(rc);

    /* Deleting a condition detaches it from the reader even while the
     * WaitSet still holds it: a later arrival must not return it. */
    struct HddsReadCondition *doomed = hdds_create_read_condition(
        r, HDDS_SAMPLE_STATE_ANY, HDDS_VIEW_STATE_ANY, HDDS_INSTANCE_STATE_ANY);
    assert(doomed != NULL);
    assert(hdds_waitset_attach_read_condition(ws, doomed) == HDDS_OK);
    const void *doomed_key = (const void *)doomed;
    hdds_read_condition_delete(doomed);
    write_reading(w, desc, 3, 9);
    assert(hdds_waitset_wait(ws, 200000000LL, triggered, 4, &count) == HDDS_OK);
    assert(count == 0);
    assert(hdds_waitset_detach_condition(ws, doomed_key) == HDDS_OK);
    assert(hdds_reader_take(r, buf, sizeof(buf), &len) == HDDS_OK);

    hdds_waitset_destroy(ws);
    hdds_reader_destroy(r);
    hdds_writer_destroy(w);
    hdds_type_descriptor_destroy(desc);
    hdds_participant_destroy(p);
}

static void test_query_condition_with_parameters(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("CondQueryTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsTypeDescriptor *desc = reading_type();
    struct HddsDataWriter *w = hdds_writer_create(p, "CondQueryTopic");
    struct HddsDataReader *r = hdds_reader_create(p, "CondQueryTopic");
    assert(w != NULL && r != NULL);

    const char *params[] = { "10" };
    struct HddsQueryCondition *qc = hdds_create_query_condition(
        r, HDDS_SAMPLE_STATE_ANY, HDDS_VIEW_STATE_ANY, HDDS_INSTANCE_STATE_ANY,
        desc, "value > %0", params, 1);
    assert(qc != NULL);
    char expr[32];
    assert(hdds_query_condition_get_expression(qc, expr, sizeof(expr)) == strlen("value > %0"));
    assert(strcmp(expr, "value > %0") == 0);

    /* A bad expression or a missing descriptor yields no condition. */
    assert(hdds_create_query_condition(r, HDDS_SAMPLE_STATE_ANY, HDDS_VIEW_STATE_ANY,
                                       HDDS_INSTANCE_STATE_ANY, desc, "value >>> 1",
                                       NULL, 0) == NULL);
    assert(hdds_create_query_condition(r, HDDS_SAMPLE_STATE_ANY, HDDS_VIEW_STATE_ANY,
                                       HDDS_INSTANCE_STATE_ANY, NULL, "value > 1",
                                       NULL, 0) == NULL);

    write_reading(w, desc, 1, 5);
    assert(hdds_query_condition_get_trigger(qc) == false); /* 5 > 10 is false */
    write_reading(w, desc, 2, 20);
    assert(hdds_query_condition_get_trigger(qc) == true);

    /* Only the matching sample is taken. */
    uint8_t buf[64];
    size_t len = 0;
    struct HddsSampleInfo info;
    assert(hdds_reader_take_w_query_condition(r, qc, buf, sizeof(buf), &len, &info) == HDDS_OK);
    assert(decode_value(desc, buf, len) == 20);
    assert(info.VALID_DATA == true);
    assert(hdds_reader_take_w_query_condition(r, qc, buf, sizeof(buf), &len, NULL)
           == HDDS_NOT_FOUND);
    assert(hdds_query_condition_get_trigger(qc) == false);

    /* The WaitSet returns only for a sample satisfying the query. */
    struct HddsWaitSet *ws = hdds_waitset_create();
    assert(hdds_waitset_attach_query_condition(ws, qc) == HDDS_OK);
    const void *triggered[4];
    size_t count = 99;
    write_reading(w, desc, 3, 1);
    assert(hdds_waitset_wait(ws, 100000000LL, triggered, 4, &count) == HDDS_OK);
    assert(count == 0); /* 1 > 10 is false: the cold sample does not end the wait */
    write_reading(w, desc, 4, 11);
    assert(hdds_waitset_wait(ws, 2000000000LL, triggered, 4, &count) == HDDS_OK);
    assert(count == 1 && triggered[0] == (const void *)qc);
    assert(hdds_reader_take_w_query_condition(r, qc, buf, sizeof(buf), &len, NULL) == HDDS_OK);
    assert(decode_value(desc, buf, len) == 11);
    assert(hdds_waitset_detach_condition(ws, (const void *)qc) == HDDS_OK);
    hdds_waitset_destroy(ws);

    /* set_query_parameters: the cold samples (5 and 1) now satisfy "> 0". */
    const char *lower[] = { "0" };
    assert(hdds_query_condition_set_parameters(qc, lower, 1) == HDDS_OK);
    assert(hdds_query_condition_set_parameters(qc, NULL, 0) == HDDS_INVALID_ARGUMENT);
    assert(hdds_query_condition_get_trigger(qc) == true);
    int taken = 0;
    while (hdds_reader_take_w_query_condition(r, qc, buf, sizeof(buf), &len, NULL) == HDDS_OK) {
        taken++;
    }
    assert(taken == 2);
    assert(hdds_query_condition_get_trigger(qc) == false);

    hdds_query_condition_delete(qc);
    hdds_reader_destroy(r);
    hdds_writer_destroy(w);
    hdds_type_descriptor_destroy(desc);
    hdds_participant_destroy(p);
}

static void test_content_filtered_topic_delivery(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("CondCftTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsTypeDescriptor *desc = reading_type();
    struct HddsDataWriter *w = hdds_writer_create(p, "CondCftTopic");
    assert(w != NULL);

    const char *params[] = { "10" };
    struct HddsContentFilteredTopic *cft = hdds_create_content_filtered_topic(
        p, "HotReadings", "CondCftTopic", desc, "value >= %0", params, 1);
    assert(cft != NULL);
    /* No descriptor, no filter. */
    assert(hdds_create_content_filtered_topic(p, "Bad", "CondCftTopic", NULL, "value >= %0",
                                              params, 1) == NULL);
    char expr[32];
    assert(hdds_content_filtered_topic_get_expression(cft, expr, sizeof(expr))
           == strlen("value >= %0"));
    assert(strcmp(expr, "value >= %0") == 0);

    struct HddsDataReader *filtered = hdds_create_reader_filtered(p, cft, NULL);
    struct HddsDataReader *plain = hdds_reader_create(p, "CondCftTopic");
    assert(filtered != NULL && plain != NULL);

    write_reading(w, desc, 1, 1);
    write_reading(w, desc, 2, 15);
    write_reading(w, desc, 3, 3);

    uint8_t buf[64];
    size_t len = 0;
    int filtered_count = 0;
    int32_t filtered_value = 0;
    while (hdds_reader_take(filtered, buf, sizeof(buf), &len) == HDDS_OK) {
        filtered_count++;
        filtered_value = decode_value(desc, buf, len);
    }
    assert(filtered_count == 1);
    assert(filtered_value == 15);
    int plain_count = 0;
    while (hdds_reader_take(plain, buf, sizeof(buf), &len) == HDDS_OK) {
        plain_count++;
    }
    assert(plain_count == 3);

    /* A payload the descriptor cannot decode is rejected even by a
     * tautology on a real field: id > -1 admits every well-formed sample
     * of this fixture (id is always positive) and no malformed one. Annex
     * B requires at least one comparison operand to be a field name, so a
     * literal-vs-literal "1 = 1" is not a legal expression. */
    struct HddsContentFilteredTopic *all = hdds_create_content_filtered_topic(
        p, "Everything", "CondCftTopic", desc, "id > -1", NULL, 0);
    assert(all != NULL);
    struct HddsDataReader *all_filtered = hdds_create_reader_filtered(p, all, NULL);
    assert(all_filtered != NULL);
    const uint8_t truncated[2] = { 0x01, 0x00 };
    assert(hdds_writer_write(w, truncated, sizeof(truncated)) == HDDS_OK);
    write_reading(w, desc, 9, 90);
    int through = 0;
    int32_t through_value = 0;
    while (hdds_reader_take(all_filtered, buf, sizeof(buf), &len) == HDDS_OK) {
        through++;
        through_value = decode_value(desc, buf, len);
    }
    assert(through == 1);
    assert(through_value == 90);
    hdds_reader_destroy(all_filtered);
    hdds_content_filtered_topic_delete(all);
    /* The plain reader saw both; the value >= 10 reader saw the whole
     * one (90) and not the truncated payload either. */
    plain_count = 0;
    while (hdds_reader_take(plain, buf, sizeof(buf), &len) == HDDS_OK) {
        plain_count++;
    }
    assert(plain_count == 2);
    filtered_count = 0;
    while (hdds_reader_take(filtered, buf, sizeof(buf), &len) == HDDS_OK) {
        filtered_count++;
        filtered_value = decode_value(desc, buf, len);
    }
    assert(filtered_count == 1);
    assert(filtered_value == 90);

    /* New parameters apply to the reader already created from the topic. */
    const char *lower[] = { "2" };
    assert(hdds_content_filtered_topic_set_params(cft, lower, 1) == HDDS_OK);
    assert(hdds_content_filtered_topic_set_params(cft, NULL, 0) == HDDS_INVALID_ARGUMENT);
    write_reading(w, desc, 4, 1);
    write_reading(w, desc, 5, 3);
    filtered_count = 0;
    while (hdds_reader_take(filtered, buf, sizeof(buf), &len) == HDDS_OK) {
        filtered_count++;
        filtered_value = decode_value(desc, buf, len);
    }
    assert(filtered_count == 1);
    assert(filtered_value == 3);

    hdds_content_filtered_topic_delete(cft);
    hdds_reader_destroy(filtered);
    hdds_reader_destroy(plain);
    hdds_writer_destroy(w);
    hdds_type_descriptor_destroy(desc);
    hdds_participant_destroy(p);
}

/* ---- Main ---- */

int main(void) {
    printf("test_conditions\n");

    RUN_TEST(test_read_condition_on_waitset);
    RUN_TEST(test_query_condition_with_parameters);
    RUN_TEST(test_content_filtered_topic_delivery);

    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
