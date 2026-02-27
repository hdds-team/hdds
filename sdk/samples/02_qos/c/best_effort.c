// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Best Effort (C)
 *
 * Demonstrates BEST_EFFORT QoS for fire-and-forget messaging.
 * Lower latency than RELIABLE, but no delivery guarantees.
 *
 * Usage:
 *     ./best_effort        # Subscriber
 *     ./best_effort pub    # Publisher
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 20

void run_publisher(struct HddsParticipant* participant) {
    /* Create BEST_EFFORT writer */
    struct HddsQoS* qos = hdds_qos_best_effort();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "BestEffortTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages with BEST_EFFORT QoS...\n", NUM_MESSAGES);
    printf("(Some messages may be lost - fire-and-forget)\n\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "BestEffort #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);
        printf("  [SENT] id=%d msg='%s'\n", msg.id, msg.message);

        usleep(50000);  /* 50ms - fast publishing */
    }

    printf("\nDone publishing. Some messages may have been dropped.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create BEST_EFFORT reader */
    struct HddsQoS* qos = hdds_qos_best_effort();
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "BestEffortTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Waiting for BEST_EFFORT messages...\n");
    printf("(Lower latency, but delivery not guaranteed)\n\n");

    int received = 0;
    int timeouts = 0;
    const int max_timeouts = 3;

    while (timeouts < max_timeouts) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 2000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    printf("  [RECV] id=%d msg='%s'\n", msg.id, msg.message);
                    received++;
                }
            }
            timeouts = 0;  /* Reset timeout counter on data */
        } else {
            timeouts++;
            printf("  (timeout %d/%d)\n", timeouts, max_timeouts);
        }
    }

    printf("\nReceived %d/%d messages. BEST_EFFORT trades reliability for speed.\n",
           received, NUM_MESSAGES);

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Best Effort Demo\n");
    printf("QoS: BEST_EFFORT - fire-and-forget, lowest latency\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("BestEffortDemo");
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
