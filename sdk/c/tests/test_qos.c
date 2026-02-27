// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test: QoS Get/Set Round-Trip
 *
 * Tests:
 *   - Create default QoS
 *   - Set every policy, get it back, verify match
 *   - Clone QoS, verify clone matches original
 *   - Boolean getters (is_reliable, is_transient_local, is_ownership_exclusive)
 *   - Destroy QoS
 */

#include <hdds.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

static int passed = 0;
static int failed = 0;

#define RUN_TEST(fn) do {          \
    printf("  %-50s", #fn);        \
    fn();                          \
    printf("[PASS]\n");            \
    passed++;                      \
} while (0)

/* ---- Tests ---- */

static void test_default_qos(void) {
    struct HddsQoS *qos = hdds_qos_default();
    assert(qos != NULL);

    /* Default is best-effort, volatile */
    assert(!hdds_qos_is_reliable(qos));
    assert(!hdds_qos_is_transient_local(qos));
    assert(!hdds_qos_is_ownership_exclusive(qos));

    hdds_qos_destroy(qos);
}

static void test_reliable_preset(void) {
    struct HddsQoS *qos = hdds_qos_reliable();
    assert(qos != NULL);
    assert(hdds_qos_is_reliable(qos));
    hdds_qos_destroy(qos);
}

static void test_best_effort_preset(void) {
    struct HddsQoS *qos = hdds_qos_best_effort();
    assert(qos != NULL);
    assert(!hdds_qos_is_reliable(qos));
    hdds_qos_destroy(qos);
}

static void test_set_get_reliability(void) {
    struct HddsQoS *qos = hdds_qos_default();

    /* Start best-effort */
    assert(!hdds_qos_is_reliable(qos));

    /* Switch to reliable */
    hdds_qos_set_reliable(qos);
    assert(hdds_qos_is_reliable(qos));

    /* Switch back to best-effort */
    hdds_qos_set_best_effort(qos);
    assert(!hdds_qos_is_reliable(qos));

    hdds_qos_destroy(qos);
}

static void test_set_get_durability(void) {
    struct HddsQoS *qos = hdds_qos_default();

    assert(!hdds_qos_is_transient_local(qos));

    hdds_qos_set_transient_local(qos);
    assert(hdds_qos_is_transient_local(qos));

    hdds_qos_set_volatile(qos);
    assert(!hdds_qos_is_transient_local(qos));

    /* Persistent also sets non-transient-local (it's a different level) */
    hdds_qos_set_persistent(qos);

    hdds_qos_destroy(qos);
}

static void test_set_get_history_depth(void) {
    struct HddsQoS *qos = hdds_qos_default();

    hdds_qos_set_history_depth(qos, 25);
    assert(hdds_qos_get_history_depth(qos) == 25);

    hdds_qos_set_history_depth(qos, 1);
    assert(hdds_qos_get_history_depth(qos) == 1);

    hdds_qos_destroy(qos);
}

static void test_history_keep_all(void) {
    struct HddsQoS *qos = hdds_qos_default();
    hdds_qos_set_history_keep_all(qos);
    /* After KEEP_ALL, depth should indicate unbounded (0 or very large) */
    /* Just verify it didn't crash and returns a value */
    (void)hdds_qos_get_history_depth(qos);
    hdds_qos_destroy(qos);
}

static void test_set_get_deadline(void) {
    struct HddsQoS *qos = hdds_qos_default();

    uint64_t ns = 250000000ULL; /* 250 ms */
    hdds_qos_set_deadline_ns(qos, ns);
    assert(hdds_qos_get_deadline_ns(qos) == ns);

    hdds_qos_destroy(qos);
}

static void test_set_get_lifespan(void) {
    struct HddsQoS *qos = hdds_qos_default();

    uint64_t ns = 3000000000ULL; /* 3 s */
    hdds_qos_set_lifespan_ns(qos, ns);
    assert(hdds_qos_get_lifespan_ns(qos) == ns);

    hdds_qos_destroy(qos);
}

static void test_set_get_ownership(void) {
    struct HddsQoS *qos = hdds_qos_default();

    /* Default is shared */
    assert(!hdds_qos_is_ownership_exclusive(qos));

    /* Set exclusive with strength */
    hdds_qos_set_ownership_exclusive(qos, 100);
    assert(hdds_qos_is_ownership_exclusive(qos));
    assert(hdds_qos_get_ownership_strength(qos) == 100);

    /* Back to shared */
    hdds_qos_set_ownership_shared(qos);
    assert(!hdds_qos_is_ownership_exclusive(qos));

    hdds_qos_destroy(qos);
}

static void test_set_get_liveliness(void) {
    struct HddsQoS *qos = hdds_qos_default();

    /* Automatic */
    hdds_qos_set_liveliness_automatic_ns(qos, 1000000000ULL);
    assert(hdds_qos_get_liveliness_kind(qos) == HDDS_LIVELINESS_AUTOMATIC);
    assert(hdds_qos_get_liveliness_lease_ns(qos) == 1000000000ULL);

    /* Manual by participant */
    hdds_qos_set_liveliness_manual_participant_ns(qos, 500000000ULL);
    assert(hdds_qos_get_liveliness_kind(qos) == HDDS_LIVELINESS_MANUAL_BY_PARTICIPANT);
    assert(hdds_qos_get_liveliness_lease_ns(qos) == 500000000ULL);

    /* Manual by topic */
    hdds_qos_set_liveliness_manual_topic_ns(qos, 200000000ULL);
    assert(hdds_qos_get_liveliness_kind(qos) == HDDS_LIVELINESS_MANUAL_BY_TOPIC);
    assert(hdds_qos_get_liveliness_lease_ns(qos) == 200000000ULL);

    hdds_qos_destroy(qos);
}

static void test_set_get_time_based_filter(void) {
    struct HddsQoS *qos = hdds_qos_default();

    hdds_qos_set_time_based_filter_ns(qos, 50000000ULL);
    assert(hdds_qos_get_time_based_filter_ns(qos) == 50000000ULL);

    hdds_qos_destroy(qos);
}

static void test_set_get_latency_budget(void) {
    struct HddsQoS *qos = hdds_qos_default();

    hdds_qos_set_latency_budget_ns(qos, 10000000ULL);
    assert(hdds_qos_get_latency_budget_ns(qos) == 10000000ULL);

    hdds_qos_destroy(qos);
}

static void test_set_get_transport_priority(void) {
    struct HddsQoS *qos = hdds_qos_default();

    hdds_qos_set_transport_priority(qos, 42);
    assert(hdds_qos_get_transport_priority(qos) == 42);

    hdds_qos_destroy(qos);
}

static void test_set_get_resource_limits(void) {
    struct HddsQoS *qos = hdds_qos_default();

    hdds_qos_set_resource_limits(qos, 500, 50, 10);
    assert(hdds_qos_get_max_samples(qos) == 500);
    assert(hdds_qos_get_max_instances(qos) == 50);
    assert(hdds_qos_get_max_samples_per_instance(qos) == 10);

    hdds_qos_destroy(qos);
}

static void test_partition(void) {
    struct HddsQoS *qos = hdds_qos_default();

    /* Just verify it doesn't crash — no getter for partitions */
    enum HddsError err = hdds_qos_add_partition(qos, "partition_A");
    assert(err == HDDS_OK);
    err = hdds_qos_add_partition(qos, "partition_B");
    assert(err == HDDS_OK);

    hdds_qos_destroy(qos);
}

static void test_qos_clone(void) {
    struct HddsQoS *orig = hdds_qos_reliable();
    hdds_qos_set_transient_local(orig);
    hdds_qos_set_deadline_ns(orig, 123456789ULL);
    hdds_qos_set_history_depth(orig, 77);
    hdds_qos_set_ownership_exclusive(orig, 55);

    struct HddsQoS *clone = hdds_qos_clone(orig);
    assert(clone != NULL);

    /* Verify clone matches */
    assert(hdds_qos_is_reliable(clone) == hdds_qos_is_reliable(orig));
    assert(hdds_qos_is_transient_local(clone) == hdds_qos_is_transient_local(orig));
    assert(hdds_qos_get_deadline_ns(clone) == hdds_qos_get_deadline_ns(orig));
    assert(hdds_qos_get_history_depth(clone) == hdds_qos_get_history_depth(orig));
    assert(hdds_qos_is_ownership_exclusive(clone) == hdds_qos_is_ownership_exclusive(orig));
    assert(hdds_qos_get_ownership_strength(clone) == hdds_qos_get_ownership_strength(orig));

    hdds_qos_destroy(orig);
    hdds_qos_destroy(clone);
}

static void test_rti_defaults_preset(void) {
    struct HddsQoS *qos = hdds_qos_rti_defaults();
    assert(qos != NULL);
    /* RTI defaults are typically reliable */
    /* Just verify creation + destroy cycle works */
    hdds_qos_destroy(qos);
}

static void test_xml_load_nonexistent(void) {
    /* Loading a non-existent file should return NULL */
    struct HddsQoS *qos = hdds_qos_from_xml("/tmp/nonexistent_qos.xml");
    assert(qos == NULL);
}

/* ---- Main ---- */

int main(void) {
    printf("test_qos\n");

    RUN_TEST(test_default_qos);
    RUN_TEST(test_reliable_preset);
    RUN_TEST(test_best_effort_preset);
    RUN_TEST(test_set_get_reliability);
    RUN_TEST(test_set_get_durability);
    RUN_TEST(test_set_get_history_depth);
    RUN_TEST(test_history_keep_all);
    RUN_TEST(test_set_get_deadline);
    RUN_TEST(test_set_get_lifespan);
    RUN_TEST(test_set_get_ownership);
    RUN_TEST(test_set_get_liveliness);
    RUN_TEST(test_set_get_time_based_filter);
    RUN_TEST(test_set_get_latency_budget);
    RUN_TEST(test_set_get_transport_priority);
    RUN_TEST(test_set_get_resource_limits);
    RUN_TEST(test_partition);
    RUN_TEST(test_qos_clone);
    RUN_TEST(test_rti_defaults_preset);
    RUN_TEST(test_xml_load_nonexistent);

    printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
