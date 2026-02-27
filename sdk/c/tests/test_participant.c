// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test: Participant Lifecycle
 *
 * Tests:
 *   - Create / destroy participant (default transport)
 *   - Create with intra-process transport
 *   - Query domain_id, name, id
 *   - Writer / reader topic name query
 *   - Version string is non-NULL
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

static void test_create_destroy_default(void) {
    struct HddsParticipant *p = hdds_participant_create("TestDefault");
    assert(p != NULL);
    hdds_participant_destroy(p);
}

static void test_create_destroy_intra(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("TestIntra", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);
    hdds_participant_destroy(p);
}

static void test_participant_name(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("MyName", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    const char *name = hdds_participant_name(p);
    assert(name != NULL);
    assert(strcmp(name, "MyName") == 0);

    hdds_participant_destroy(p);
}

static void test_participant_domain_id(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("DomainTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    uint32_t domain = hdds_participant_domain_id(p);
    /* Default domain is 0 */
    assert(domain == 0);

    hdds_participant_destroy(p);
}

static void test_participant_id(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("IdTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    uint8_t id = hdds_participant_id(p);
    /* Should be a valid id (0-119), not the error sentinel 0xFF */
    assert(id != 0xFF);

    hdds_participant_destroy(p);
}

static void test_writer_topic_name(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("TopicTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    struct HddsDataWriter *w = hdds_writer_create(p, "SensorTopic");
    assert(w != NULL);

    char buf[128];
    size_t len = 0;
    enum HddsError err = hdds_writer_topic_name(w, buf, sizeof(buf), &len);
    assert(err == HDDS_OK);
    assert(len > 0);
    assert(strcmp(buf, "SensorTopic") == 0);

    hdds_writer_destroy(w);
    hdds_participant_destroy(p);
}

static void test_reader_topic_name(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("TopicTest2", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    struct HddsDataReader *r = hdds_reader_create(p, "ActuatorTopic");
    assert(r != NULL);

    char buf[128];
    size_t len = 0;
    enum HddsError err = hdds_reader_topic_name(r, buf, sizeof(buf), &len);
    assert(err == HDDS_OK);
    assert(len > 0);
    assert(strcmp(buf, "ActuatorTopic") == 0);

    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
}

static void test_version_string(void) {
    const char *ver = hdds_version();
    assert(ver != NULL);
    assert(strlen(ver) > 0);
    printf("(v%s) ", ver);
}

static void test_publisher_subscriber_lifecycle(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("PubSubTest", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    struct HddsPublisher *pub = hdds_publisher_create(p);
    assert(pub != NULL);

    struct HddsSubscriber *sub = hdds_subscriber_create(p);
    assert(sub != NULL);

    /* Create writer from publisher, reader from subscriber */
    struct HddsDataWriter *w = hdds_publisher_create_writer(pub, "PSTopic");
    assert(w != NULL);

    struct HddsDataReader *r = hdds_subscriber_create_reader(sub, "PSTopic");
    assert(r != NULL);

    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_publisher_destroy(pub);
    hdds_subscriber_destroy(sub);
    hdds_participant_destroy(p);
}

static void test_write_read_roundtrip(void) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("RoundTrip", HDDS_TRANSPORT_INTRA_PROCESS);
    assert(p != NULL);

    struct HddsDataWriter *w = hdds_writer_create(p, "RTTopic");
    struct HddsDataReader *r = hdds_reader_create(p, "RTTopic");
    assert(w != NULL);
    assert(r != NULL);

    const char *msg = "test payload";
    enum HddsError err = hdds_writer_write(w, msg, strlen(msg) + 1);
    assert(err == HDDS_OK);

    uint8_t buf[256];
    size_t len = 0;
    err = hdds_reader_take(r, buf, sizeof(buf), &len);
    assert(err == HDDS_OK);
    assert(len == strlen(msg) + 1);
    assert(strcmp((char *)buf, msg) == 0);

    hdds_reader_destroy(r);
    hdds_writer_destroy(w);
    hdds_participant_destroy(p);
}

/* ---- Main ---- */

int main(void) {
    printf("test_participant\n");

    RUN_TEST(test_create_destroy_default);
    RUN_TEST(test_create_destroy_intra);
    RUN_TEST(test_participant_name);
    RUN_TEST(test_participant_domain_id);
    RUN_TEST(test_participant_id);
    RUN_TEST(test_writer_topic_name);
    RUN_TEST(test_reader_topic_name);
    RUN_TEST(test_version_string);
    RUN_TEST(test_publisher_subscriber_lifecycle);
    RUN_TEST(test_write_read_roundtrip);

    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
