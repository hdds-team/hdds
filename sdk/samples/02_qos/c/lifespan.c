// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Lifespan (C)
 *
 * Demonstrates LIFESPAN QoS for automatic data expiration.
 * Data samples expire after a configured duration and are removed
 * from the reader cache. Late-joining subscribers only see recent messages.
 *
 * Usage:
 *     ./lifespan        # Subscriber (joins late, sees only recent data)
 *     ./lifespan pub    # Publisher (sends 10 messages with 2s lifespan)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define LIFESPAN_NS     2000000000ULL  /* 2 seconds */
#define NUM_MESSAGES    10
#define SEND_INTERVAL_MS 500           /* 500ms between messages */
#define LATE_JOIN_SEC    3             /* subscriber joins 3s after start */

void run_publisher(struct HddsParticipant* participant) {
    /* Create writer with transient_local + lifespan QoS */
    struct HddsQoS* qos = hdds_qos_transient_local();
    hdds_qos_set_lifespan_ns(qos, LIFESPAN_NS);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "LifespanTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages at %dms intervals (lifespan: 2s)\n", NUM_MESSAGES, SEND_INTERVAL_MS);
    printf("Messages older than 2s will expire from the cache.\n\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Sample #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("  [%ld.%03ld] Sent id=%d: \"%s\"\n",
               ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, msg.message);

        usleep(SEND_INTERVAL_MS * 1000);
    }

    printf("\nAll messages sent. Keeping writer alive for late joiners...\n");
    /* Keep alive so transient_local can serve late joiners */
    sleep(5);

    printf("Done publishing.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    printf("Waiting %d seconds before creating reader (simulating late join)...\n\n", LATE_JOIN_SEC);
    sleep(LATE_JOIN_SEC);

    /* Create reader with transient_local + lifespan QoS */
    struct HddsQoS* qos = hdds_qos_transient_local();
    hdds_qos_set_lifespan_ns(qos, LIFESPAN_NS);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "LifespanTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Reader created. Reading all available data...\n\n");

    /* Wait briefly for transient_local delivery */
    const void* triggered[1];
    size_t triggered_count;
    hdds_waitset_wait(waitset, 2000000000LL, triggered, 1, &triggered_count);

    int received = 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint8_t buffer[512];
    size_t len;

    while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
        HelloWorld msg;
        if (HelloWorld_deserialize(&msg, buffer, len)) {
            received++;
            printf("  Received id=%d: \"%s\" (survived lifespan)\n", msg.id, msg.message);
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Summary: %d of %d messages survived (older messages expired)\n",
           received, NUM_MESSAGES);
    printf("Expected: ~%d messages (those sent within last 2s before join)\n",
           (int)(LIFESPAN_NS / 1000000000ULL * 1000 / SEND_INTERVAL_MS));
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Lifespan Demo\n");
    printf("QoS: LIFESPAN - automatic data expiration after 2 seconds\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("LifespanDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (is_publisher) {
        run_publisher(participant);
    } else {
        run_subscriber(participant);
    }

    hdds_participant_destroy(participant);
    return 0;
}
