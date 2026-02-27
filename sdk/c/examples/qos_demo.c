// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Example: QoS Demo (C)
 *
 * Demonstrates common QoS patterns available through the HDDS C API.
 * Each pattern is in its own function; main() calls them sequentially.
 *
 * Patterns demonstrated:
 *   1. Reliable + Transient Local (durable messaging)
 *   2. Best Effort + Volatile (fire-and-forget)
 *   3. History Keep-Last with depth
 *   4. Deadline monitoring
 *   5. Liveliness automatic
 *   6. Ownership exclusive
 *   7. Partition filtering
 *   8. QoS cloning
 *   9. Miscellaneous getters
 *
 * Build: cmake --build . --target qos_demo
 * Usage: ./qos_demo
 */

#include <hdds.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

/* Helper: print a separator line */
static void section(const char *title) {
    printf("\n=== %s ===\n", title);
}

/**
 * Pattern 1: Reliable + Transient Local
 *
 * Ensures delivery and retains last sample for late-joining readers.
 * Use for: command messages, configuration topics.
 */
static void demo_reliable_transient_local(void) {
    section("Reliable + Transient Local (durable messaging)");

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);

    printf("is_reliable:       %s\n",
           hdds_qos_is_reliable(qos) ? "true" : "false");
    printf("is_transient_local:%s\n",
           hdds_qos_is_transient_local(qos) ? "true" : "false");

    hdds_qos_destroy(qos);
}

/**
 * Pattern 2: Best Effort + Volatile
 *
 * No delivery guarantee, no sample retention. Lowest overhead.
 * Use for: high-frequency sensor streams, video frames.
 */
static void demo_best_effort_volatile(void) {
    section("Best Effort + Volatile (fire-and-forget)");

    struct HddsQoS *qos = hdds_qos_best_effort();
    hdds_qos_set_volatile(qos);

    printf("is_reliable:       %s\n",
           hdds_qos_is_reliable(qos) ? "true" : "false");
    printf("is_transient_local:%s\n",
           hdds_qos_is_transient_local(qos) ? "true" : "false");

    hdds_qos_destroy(qos);
}

/**
 * Pattern 3: History Keep-Last with depth
 *
 * Only retain the last N samples per instance.
 */
static void demo_history_depth(void) {
    section("History Keep-Last with Depth");

    struct HddsQoS *qos = hdds_qos_default();
    printf("default depth:      %u\n", hdds_qos_get_history_depth(qos));

    hdds_qos_set_history_depth(qos, 50);
    printf("after set_depth(50): %u\n", hdds_qos_get_history_depth(qos));

    hdds_qos_set_history_keep_all(qos);
    printf("after keep_all:      %u (0 or max means KEEP_ALL)\n",
           hdds_qos_get_history_depth(qos));

    hdds_qos_destroy(qos);
}

/**
 * Pattern 4: Deadline monitoring
 *
 * Writer must publish at least once per deadline period, otherwise
 * a deadline-missed status is raised.
 */
static void demo_deadline(void) {
    section("Deadline Monitoring");

    struct HddsQoS *qos = hdds_qos_default();

    /* 100 ms deadline */
    hdds_qos_set_deadline_ns(qos, 100000000ULL);
    printf("deadline: %lu ns\n", (unsigned long)hdds_qos_get_deadline_ns(qos));

    /* 5 second lifespan (how long a sample stays valid) */
    hdds_qos_set_lifespan_ns(qos, 5000000000ULL);
    printf("lifespan: %lu ns\n", (unsigned long)hdds_qos_get_lifespan_ns(qos));

    hdds_qos_destroy(qos);
}

/**
 * Pattern 5: Liveliness automatic
 *
 * DDS infrastructure automatically asserts liveliness on behalf of
 * the writer at the specified lease duration.
 */
static void demo_liveliness_automatic(void) {
    section("Liveliness Automatic");

    struct HddsQoS *qos = hdds_qos_default();

    /* Automatic liveliness, 2-second lease */
    hdds_qos_set_liveliness_automatic_ns(qos, 2000000000ULL);
    printf("kind:  %d (0=AUTOMATIC, 1=MANUAL_PARTICIPANT, 2=MANUAL_TOPIC)\n",
           hdds_qos_get_liveliness_kind(qos));
    printf("lease: %lu ns\n", (unsigned long)hdds_qos_get_liveliness_lease_ns(qos));

    /* Switch to manual-by-topic for comparison */
    hdds_qos_set_liveliness_manual_topic_ns(qos, 500000000ULL);
    printf("kind:  %d  (after manual-by-topic)\n",
           hdds_qos_get_liveliness_kind(qos));
    printf("lease: %lu ns\n", (unsigned long)hdds_qos_get_liveliness_lease_ns(qos));

    hdds_qos_destroy(qos);
}

/**
 * Pattern 6: Ownership exclusive
 *
 * Only the writer with the highest ownership strength can publish
 * to a given instance. Lower-strength writers are silently ignored.
 */
static void demo_ownership_exclusive(void) {
    section("Ownership Exclusive");

    struct HddsQoS *qos = hdds_qos_default();
    printf("default exclusive: %s\n",
           hdds_qos_is_ownership_exclusive(qos) ? "true" : "false");

    hdds_qos_set_ownership_exclusive(qos, 42);
    printf("after exclusive:   %s, strength=%d\n",
           hdds_qos_is_ownership_exclusive(qos) ? "true" : "false",
           hdds_qos_get_ownership_strength(qos));

    hdds_qos_set_ownership_shared(qos);
    printf("after shared:      %s\n",
           hdds_qos_is_ownership_exclusive(qos) ? "true" : "false");

    hdds_qos_destroy(qos);
}

/**
 * Pattern 7: Partition filtering
 *
 * Partitions act as logical sub-channels. Only endpoints with matching
 * partition names will communicate. Useful for multi-tenant systems.
 */
static void demo_partition_filtering(void) {
    section("Partition Filtering");

    struct HddsQoS *writer_qos = hdds_qos_default();
    hdds_qos_add_partition(writer_qos, "sensors/lidar");
    hdds_qos_add_partition(writer_qos, "sensors/camera");
    printf("Writer partitions: sensors/lidar, sensors/camera\n");

    struct HddsQoS *reader_qos = hdds_qos_default();
    hdds_qos_add_partition(reader_qos, "sensors/lidar");
    printf("Reader partitions: sensors/lidar\n");
    printf("(Only lidar data would be received — camera is filtered out)\n");

    hdds_qos_destroy(writer_qos);
    hdds_qos_destroy(reader_qos);
}

/**
 * QoS cloning: duplicate a configured profile and verify
 * the clone matches the original.
 */
static void demo_qos_clone(void) {
    section("QoS Cloning");

    struct HddsQoS *original = hdds_qos_reliable();
    hdds_qos_set_transient_local(original);
    hdds_qos_set_deadline_ns(original, 200000000ULL);

    struct HddsQoS *clone = hdds_qos_clone(original);
    printf("original -> reliable=%s, tl=%s, deadline=%lu\n",
           hdds_qos_is_reliable(original) ? "true" : "false",
           hdds_qos_is_transient_local(original) ? "true" : "false",
           (unsigned long)hdds_qos_get_deadline_ns(original));
    printf("clone    -> reliable=%s, tl=%s, deadline=%lu\n",
           hdds_qos_is_reliable(clone) ? "true" : "false",
           hdds_qos_is_transient_local(clone) ? "true" : "false",
           (unsigned long)hdds_qos_get_deadline_ns(clone));

    hdds_qos_destroy(original);
    hdds_qos_destroy(clone);
}

/**
 * Miscellaneous getters: resource limits, time-based filter,
 * latency budget, transport priority.
 */
static void demo_misc_getters(void) {
    section("Miscellaneous Getters");

    struct HddsQoS *qos = hdds_qos_default();

    /* Resource limits */
    hdds_qos_set_resource_limits(qos, 1000, 100, 10);
    printf("max_samples:              %zu\n", hdds_qos_get_max_samples(qos));
    printf("max_instances:            %zu\n", hdds_qos_get_max_instances(qos));
    printf("max_samples_per_instance: %zu\n", hdds_qos_get_max_samples_per_instance(qos));

    /* Time-based filter, latency budget, transport priority */
    hdds_qos_set_time_based_filter_ns(qos, 10000000ULL);
    hdds_qos_set_latency_budget_ns(qos, 5000000ULL);
    hdds_qos_set_transport_priority(qos, 7);

    printf("time_based_filter:  %lu ns\n",
           (unsigned long)hdds_qos_get_time_based_filter_ns(qos));
    printf("latency_budget:     %lu ns\n",
           (unsigned long)hdds_qos_get_latency_budget_ns(qos));
    printf("transport_priority: %d\n",
           hdds_qos_get_transport_priority(qos));

    hdds_qos_destroy(qos);
}

int main(void) {
    printf("HDDS QoS Demo\n");
    printf("=============\n");

    demo_reliable_transient_local();
    demo_best_effort_volatile();
    demo_history_depth();
    demo_deadline();
    demo_liveliness_automatic();
    demo_ownership_exclusive();
    demo_partition_filtering();
    demo_qos_clone();
    demo_misc_getters();

    printf("\nAll QoS demos complete.\n");
    return 0;
}
