// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Transient Local (C)
 *
 * Demonstrates TRANSIENT_LOCAL durability for late-joiner support.
 * New subscribers receive historical data from publishers' cache.
 *
 * Usage:
 *     ./transient_local        # Late subscriber (joins after pub)
 *     ./transient_local pub    # Publisher (publishes and waits)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 5

void run_publisher(struct HddsParticipant* participant) {
    /* Create TRANSIENT_LOCAL writer - caches data for late joiners */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, NUM_MESSAGES);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "TransientTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages with TRANSIENT_LOCAL QoS...\n\n", NUM_MESSAGES);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Historical data #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);
        printf("  [CACHED] id=%d msg='%s'\n", msg.id, msg.message);
    }

    printf("\nAll messages cached. Waiting for late-joining subscribers...\n");
    printf("(Run './transient_local' in another terminal to see late-join)\n");
    printf("Press Ctrl+C to exit.\n");

    /* Keep writer alive so cache persists */
    while (1) {
        sleep(1);
    }

    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    printf("Creating TRANSIENT_LOCAL subscriber (late-joiner)...\n");
    printf("If publisher ran first, we should receive cached historical data.\n\n");

    /* Create TRANSIENT_LOCAL reader */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "TransientTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    /* Give time for discovery and history transfer */
    printf("Waiting for historical data...\n\n");

    int received = 0;
    int timeouts = 0;

    while (timeouts < 2) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 3000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    printf("  [HISTORICAL] id=%d msg='%s'\n", msg.id, msg.message);
                    received++;
                }
            }
            timeouts = 0;
        } else {
            timeouts++;
        }
    }

    if (received > 0) {
        printf("\nReceived %d historical messages via TRANSIENT_LOCAL!\n", received);
        printf("Late-joiners automatically get cached data.\n");
    } else {
        printf("\nNo historical data received. Start publisher first:\n");
        printf("  ./transient_local pub\n");
    }

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Transient Local Demo\n");
    printf("QoS: TRANSIENT_LOCAL - late-joiners receive historical data\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("TransientLocalDemo");
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
