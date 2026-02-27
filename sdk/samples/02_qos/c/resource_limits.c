// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Resource Limits (C)
 *
 * Demonstrates RESOURCE_LIMITS QoS for bounding memory usage.
 * Limits the number of samples, instances, and samples-per-instance
 * that a reader will store. Excess samples are discarded.
 *
 * This sample runs as a single process: publishes all data with
 * transient_local durability, then reads from two readers with
 * different resource limits.
 *
 * Usage:
 *     ./resource_limits        # Run full demo (single process)
 *     ./resource_limits pub    # Publisher only
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES        20
#define MAX_SAMPLES_LIMITED 5

void run_publisher(struct HddsParticipant* participant) {
    /* Create writer with reliable + transient_local + deep history */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_history_depth(qos, 100);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "ResourceTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages with reliable + deep history...\n\n", NUM_MESSAGES);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Data point #%d value=%d", i + 1, (i + 1) * 10);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("  [%ld.%03ld] Sent id=%d: \"%s\"\n",
               ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, msg.message);

        usleep(50 * 1000);  /* 50ms between sends */
    }

    printf("\nDone publishing. Keeping writer alive for readers...\n");
    sleep(5);

    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /*
     * Single-process mode: create writer, publish all, then create readers
     * and read from them. Uses transient_local for durability.
     */

    /* Create writer with reliable + transient_local + deep history */
    struct HddsQoS* qos_wr = hdds_qos_reliable();
    hdds_qos_set_history_depth(qos_wr, 100);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "ResourceTopic", qos_wr);
    hdds_qos_destroy(qos_wr);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages...\n\n", NUM_MESSAGES);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Data point #%d value=%d", i + 1, (i + 1) * 10);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
        hdds_writer_write(writer, buffer, len);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("  [%ld.%03ld] Sent id=%d\n",
               ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);

        usleep(50 * 1000);
    }

    printf("\nAll messages published. Creating readers...\n\n");

    /* Brief pause before creating readers */
    usleep(500 * 1000);

    /* Reader A: limited resources (max 5 samples) */
    struct HddsQoS* qos_limited = hdds_qos_reliable();
    hdds_qos_set_resource_limits(qos_limited, MAX_SAMPLES_LIMITED, 1, MAX_SAMPLES_LIMITED);

    struct HddsDataReader* reader_limited = hdds_reader_create_with_qos(participant, "ResourceTopic", qos_limited);
    hdds_qos_destroy(qos_limited);

    if (!reader_limited) {
        fprintf(stderr, "Failed to create limited reader\n");
        hdds_writer_destroy(writer);
        return;
    }

    /* Reader B: no resource limits */
    struct HddsQoS* qos_unlimited = hdds_qos_reliable();
    hdds_qos_set_history_depth(qos_unlimited, 100);

    struct HddsDataReader* reader_unlimited = hdds_reader_create_with_qos(participant, "ResourceTopic", qos_unlimited);
    hdds_qos_destroy(qos_unlimited);

    if (!reader_unlimited) {
        fprintf(stderr, "Failed to create unlimited reader\n");
        hdds_reader_destroy(reader_limited);
        hdds_writer_destroy(writer);
        return;
    }

    /* Wait for data delivery */
    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader_unlimited);
    hdds_waitset_attach_status_condition(waitset, cond);

    const void* triggered[1];
    size_t triggered_count;
    hdds_waitset_wait(waitset, 3000000000LL, triggered, 1, &triggered_count);

    /* Additional wait for all samples to arrive */
    usleep(500 * 1000);

    /* Read from limited reader */
    printf("Reader A (max %d samples, 1 instance):\n", MAX_SAMPLES_LIMITED);
    int count_limited = 0;
    uint8_t buffer[512];
    size_t len;

    while (hdds_reader_take(reader_limited, buffer, sizeof(buffer), &len) == HDDS_OK) {
        HelloWorld msg;
        if (HelloWorld_deserialize(&msg, buffer, len)) {
            printf("  id=%d: \"%s\"\n", msg.id, msg.message);
            count_limited++;
        }
    }

    printf("\nReader B (no limits):\n");
    int count_unlimited = 0;

    while (hdds_reader_take(reader_unlimited, buffer, sizeof(buffer), &len) == HDDS_OK) {
        HelloWorld msg;
        if (HelloWorld_deserialize(&msg, buffer, len)) {
            printf("  id=%d: \"%s\"\n", msg.id, msg.message);
            count_unlimited++;
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Results:\n");
    printf("  Reader A (limited to %d samples): %d messages received\n",
           MAX_SAMPLES_LIMITED, count_limited);
    printf("  Reader B (no limits):             %d messages received\n",
           count_unlimited);
    printf("\nResource limits protect against unbounded memory growth by\n");
    printf("capping the number of stored samples. Older samples are dropped\n");
    printf("when the limit is reached.\n");
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader_limited);
    hdds_reader_destroy(reader_unlimited);
    hdds_writer_destroy(writer);
}

int main(int argc, char** argv) {
    int pub_only = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Resource Limits Demo\n");
    printf("QoS: RESOURCE_LIMITS - bound memory by limiting stored samples\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("ResourceLimitsDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (pub_only) {
        run_publisher(participant);
    } else {
        run_subscriber(participant);
    }

    hdds_participant_destroy(participant);
    return 0;
}
