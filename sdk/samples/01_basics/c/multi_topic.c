// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Multi-Topic (C)
 *
 * Demonstrates pub/sub on multiple topics from a single participant.
 *
 * Usage:
 *     ./multi_topic        # Subscriber
 *     ./multi_topic pub    # Publisher
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_TOPICS 3
static const char* TOPICS[NUM_TOPICS] = {"SensorData", "Commands", "Status"};

static void run_publisher(HddsParticipant* participant) {
    HddsDataWriter* writers[NUM_TOPICS];

    for (int t = 0; t < NUM_TOPICS; t++) {
        writers[t] = hdds_writer_create(participant, TOPICS[t]);
        printf("  Created writer for '%s'\n", TOPICS[t]);
    }

    printf("\nPublishing to all topics...\n");

    for (int i = 0; i < 5; i++) {
        for (int t = 0; t < NUM_TOPICS; t++) {
            HelloWorld msg;
            HelloWorld_init(&msg);
            snprintf(msg.message, sizeof(msg.message), "%s message", TOPICS[t]);
            msg.id = i;

            uint8_t buffer[512];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writers[t], buffer, len);
            printf("  [%s] Sent #%d\n", TOPICS[t], i);
        }
        usleep(500000);
    }

    printf("Done publishing.\n");

    for (int t = 0; t < NUM_TOPICS; t++) {
        hdds_writer_destroy(writers[t]);
    }
}

static void run_subscriber(HddsParticipant* participant) {
    HddsDataReader* readers[NUM_TOPICS];
    HddsWaitSet* waitset = hdds_waitset_create();
    int received[NUM_TOPICS] = {0};

    for (int t = 0; t < NUM_TOPICS; t++) {
        readers[t] = hdds_reader_create(participant, TOPICS[t]);
        hdds_waitset_attach_status_condition(waitset, hdds_reader_get_status_condition(readers[t]));
        printf("  Created reader for '%s'\n", TOPICS[t]);
    }

    printf("\nWaiting for messages on all topics...\n");
    int total_expected = NUM_TOPICS * 5;
    int total_received = 0;

    while (total_received < total_expected) {
        const void* triggered[NUM_TOPICS];
        size_t count;

        if (hdds_waitset_wait(waitset, 3000000000LL, triggered, NUM_TOPICS, &count) == HDDS_OK && count > 0) {
            for (int t = 0; t < NUM_TOPICS; t++) {
                uint8_t buffer[512];
                size_t len;

                while (hdds_reader_take(readers[t], buffer, sizeof(buffer), &len) == HDDS_OK) {
                    HelloWorld msg;
                    HelloWorld_deserialize(&msg, buffer, len);
                    printf("  [%s] Received: %s #%d\n", TOPICS[t], msg.message, msg.id);
                    received[t]++;
                    total_received++;
                }
            }
        } else {
            printf("  (timeout)\n");
        }
    }

    printf("\nReceived counts:\n");
    for (int t = 0; t < NUM_TOPICS; t++) {
        printf("  %s: %d messages\n", TOPICS[t], received[t]);
    }
    printf("Done receiving.\n");

    hdds_waitset_destroy(waitset);
    for (int t = 0; t < NUM_TOPICS; t++) {
        hdds_reader_destroy(readers[t]);
    }
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(3);

    printf("============================================================\n");
    printf("Multi-Topic Demo\n");
    printf("Topics: %s, %s, %s\n", TOPICS[0], TOPICS[1], TOPICS[2]);
    printf("============================================================\n");

    HddsParticipant* participant = hdds_participant_create("MultiTopicDemo");
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
