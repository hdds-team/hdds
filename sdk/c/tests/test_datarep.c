// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test: DATA_REPRESENTATION through the C ABI (DDS-XTypes 1.3 7.6.3.1.1)
 *
 * Tests:
 *   - hdds_qos_set_data_representation / _get: XCDR and XCDR2 only
 *   - a reader requesting [XCDR, XCDR2] takes an XCDR writer's sample with
 *     CDR_LE (0x0001) and an XCDR2 writer's with CDR2_LE (0x0007)
 *     (hdds_reader_take_ex), the bytes unchanged
 *   - a reader that sets no list requests XCDR2 and misses an XCDR writer
 *   - hdds_writer_create_with_extensibility refuses an unknown value
 *   - hdds_publisher_create_writer_with_extensibility takes the three
 *     extensibilities and refuses an unknown value (the identifiers on the
 *     wire are checked by the hdds-c tests and scripts/test-sdk-typed.sh)
 */

#include <hdds.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int passed = 0;
static int failed = 0;

#define RUN_TEST(fn) do {          \
    printf("  %-60s", #fn);        \
    fn();                          \
    printf("[PASS]\n");            \
    passed++;                      \
} while (0)

static struct HddsQoS *reliable_with(const int16_t *ids, size_t count) {
    struct HddsQoS *qos = hdds_qos_reliable();
    assert(qos != NULL);
    assert(hdds_qos_set_data_representation(qos, ids, count) == HDDS_OK);
    return qos;
}

static void test_setter_takes_xcdr_and_xcdr2_only(void) {
    struct HddsQoS *qos = hdds_qos_default();
    int16_t ids[4];
    size_t count = 9;
    assert(hdds_qos_get_data_representation(qos, ids, 4, &count) == HDDS_OK);
    assert(count == 0);

    const int16_t both[2] = {HDDS_XCDR_DATA_REPRESENTATION, HDDS_XCDR2_DATA_REPRESENTATION};
    assert(hdds_qos_set_data_representation(qos, both, 2) == HDDS_OK);
    assert(hdds_qos_get_data_representation(qos, ids, 4, &count) == HDDS_OK);
    assert(count == 2 && ids[0] == 0 && ids[1] == 2);

    const int16_t xml[1] = {1};
    assert(hdds_qos_set_data_representation(qos, xml, 1) == HDDS_INVALID_ARGUMENT);
    assert(hdds_qos_get_data_representation(qos, ids, 4, &count) == HDDS_OK);
    assert(count == 2);

    assert(hdds_qos_set_data_representation(qos, NULL, 0) == HDDS_OK);
    assert(hdds_qos_get_data_representation(qos, NULL, 0, &count) == HDDS_OK);
    assert(count == 0);
    hdds_qos_destroy(qos);
}

static void test_take_ex_reports_each_samples_representation(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("c_datarep", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    const int16_t x1[1] = {HDDS_XCDR_DATA_REPRESENTATION};
    const int16_t both[2] = {HDDS_XCDR_DATA_REPRESENTATION, HDDS_XCDR2_DATA_REPRESENTATION};
    struct HddsQoS *q1 = reliable_with(x1, 1);
    struct HddsQoS *q2 = hdds_qos_reliable();
    struct HddsQoS *qr = reliable_with(both, 2);
    struct HddsDataWriter *w1 = hdds_writer_create_with_qos(p, "c_datarep", q1);
    struct HddsDataWriter *w2 = hdds_writer_create_with_qos(p, "c_datarep", q2);
    struct HddsDataReader *r = hdds_reader_create_with_qos(p, "c_datarep", qr);
    assert(w1 && w2 && r);

    const uint8_t a[4] = {1, 2, 3, 4};
    const uint8_t b[4] = {5, 6, 7, 8};
    assert(hdds_writer_write(w1, a, 4) == HDDS_OK);
    assert(hdds_writer_write(w2, b, 4) == HDDS_OK);

    uint8_t buf[16];
    size_t len = 0;
    uint16_t id = 0;
    assert(hdds_reader_take_ex(r, buf, sizeof(buf), &len, &id) == HDDS_OK);
    assert(len == 4 && memcmp(buf, a, 4) == 0 && id == 0x0001);
    assert(hdds_reader_take_ex(r, buf, sizeof(buf), &len, &id) == HDDS_OK);
    assert(len == 4 && memcmp(buf, b, 4) == 0 && id == 0x0007);
    assert(hdds_reader_take_ex(r, buf, sizeof(buf), &len, &id) == HDDS_NOT_FOUND);

    hdds_reader_destroy(r);
    hdds_writer_destroy(w1);
    hdds_writer_destroy(w2);
    hdds_qos_destroy(q1);
    hdds_qos_destroy(q2);
    hdds_qos_destroy(qr);
    hdds_participant_destroy(p);
}

static void test_default_reader_misses_an_xcdr_writer(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("c_datarep_default", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    const int16_t x1[1] = {HDDS_XCDR_DATA_REPRESENTATION};
    struct HddsQoS *q1 = reliable_with(x1, 1);
    struct HddsDataReader *r = hdds_reader_create(p, "c_datarep_default");
    struct HddsDataWriter *w1 = hdds_writer_create_with_qos(p, "c_datarep_default", q1);
    assert(r && w1);
    const uint8_t a[4] = {1, 0, 0, 0};
    assert(hdds_writer_write(w1, a, 4) == HDDS_OK);
    uint8_t buf[16];
    size_t len = 0;
    assert(hdds_reader_take(r, buf, sizeof(buf), &len) == HDDS_NOT_FOUND);
    hdds_reader_destroy(r);
    hdds_writer_destroy(w1);
    hdds_qos_destroy(q1);
    hdds_participant_destroy(p);
}

static void test_unknown_extensibility_is_refused(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("c_datarep_ext", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    assert(hdds_writer_create_with_extensibility(p, "c_datarep_ext", NULL, NULL, 3) == NULL);
    hdds_participant_destroy(p);
}

static void test_publisher_writer_takes_an_extensibility(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("c_datarep_pub_ext", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    struct HddsPublisher *pub = hdds_publisher_create(p);
    assert(pub != NULL);
    const uint32_t kinds[3] = {HDDS_EXTENSIBILITY_FINAL, HDDS_EXTENSIBILITY_APPENDABLE,
                               HDDS_EXTENSIBILITY_MUTABLE};
    for (int i = 0; i < 3; i++) {
        struct HddsDataWriter *w =
            hdds_publisher_create_writer_with_extensibility(pub, "c_datarep_pub_ext", NULL, kinds[i]);
        assert(w != NULL);
        const uint8_t body[8] = {4, 0, 0, 0, 0x2a, 0, 0, 0};
        assert(hdds_writer_write(w, body, sizeof(body)) == HDDS_OK);
        hdds_writer_destroy(w);
    }
    assert(hdds_publisher_create_writer_with_extensibility(pub, "c_datarep_pub_ext", NULL, 3) == NULL);
    hdds_publisher_destroy(pub);
    hdds_participant_destroy(p);
}

int main(void) {
    printf("HDDS C SDK: DATA_REPRESENTATION\n");
    RUN_TEST(test_setter_takes_xcdr_and_xcdr2_only);
    RUN_TEST(test_take_ex_reports_each_samples_representation);
    RUN_TEST(test_default_reader_misses_an_xcdr_writer);
    RUN_TEST(test_unknown_extensibility_is_refused);
    RUN_TEST(test_publisher_writer_takes_an_extensibility);
    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
