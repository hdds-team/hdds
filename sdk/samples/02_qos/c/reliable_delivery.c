// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Reliable Delivery (C)
 *
 * Demonstrates RELIABLE QoS for guaranteed message delivery.
 * Messages are retransmitted if lost (NACK-based recovery).
 *
 * Usage:
 *     ./reliable_delivery        # Subscriber
 *     ./reliable_delivery pub    # Publisher
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 10

void run_publisher(struct HddsParticipant* participant) {
    /* Create RELIABLE writer */
    struct HddsQoS* qos = hdds_qos_reliable();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "ReliableTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages with RELIABLE QoS...\n\n", NUM_MESSAGES);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Reliable message #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        enum HddsError err = hdds_writer_write(writer, buffer, len);
        if (err == HDDS_OK) {
            printf("  [SENT] id=%d msg='%s'\n", msg.id, msg.message);
        } else {
            printf("  [FAIL] id=%d error=%d\n", msg.id, err);
        }

        usleep(100000);  /* 100ms between messages */
    }

    printf("\nDone publishing. RELIABLE ensures all messages delivered.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create RELIABLE reader */
    struct HddsQoS* qos = hdds_qos_reliable();
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "ReliableTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Waiting for RELIABLE messages...\n\n");

    int received = 0;
    while (received < NUM_MESSAGES) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 5000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    printf("  [RECV] id=%d msg='%s'\n", msg.id, msg.message);
                    received++;
                }
            }
        } else {
            printf("  (timeout waiting for messages)\n");
        }
    }

    printf("\nReceived all %d messages. RELIABLE QoS guarantees delivery!\n", received);

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Reliable Delivery Demo\n");
    printf("QoS: RELIABLE - guaranteed delivery via NACK retransmission\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("ReliableDemo");
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
