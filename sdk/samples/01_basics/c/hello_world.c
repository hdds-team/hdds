// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Hello World (C)
 *
 * Demonstrates basic pub/sub with HDDS C API.
 *
 * Usage:
 *     # Terminal 1 - Subscriber
 *     ./hello_world
 *
 *     # Terminal 2 - Publisher
 *     ./hello_world pub
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

static void run_publisher(HddsParticipant* participant) {
    printf("Creating writer...\n");
    HddsDataWriter* writer = hdds_writer_create(participant, "HelloWorldTopic");
    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing messages...\n");
    HelloWorld msg;
    HelloWorld_init(&msg);
    strcpy(msg.message, "Hello from HDDS C!");

    for (int i = 0; i < 10; i++) {
        msg.id = i;

        // Serialize and write
        uint8_t buffer[1024];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
            printf("  Published: %s (id=%d)\n", msg.message, msg.id);
        } else {
            fprintf(stderr, "  Failed to publish message %d\n", i);
        }

        usleep(500000);  // 500ms
    }

    printf("Done publishing.\n");
    hdds_writer_destroy(writer);
}

static void run_subscriber(HddsParticipant* participant) {
    printf("Creating reader...\n");
    HddsDataReader* reader = hdds_reader_create(participant, "HelloWorldTopic");
    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    // Create waitset
    HddsWaitSet* waitset = hdds_waitset_create();
    const HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Waiting for messages (Ctrl+C to exit)...\n");
    int received = 0;

    while (received < 10) {
        // Wait up to 5 seconds
        const void* triggered[1];
        size_t count;

        if (hdds_waitset_wait(waitset, 5000000000LL, triggered, 1, &count) == HDDS_OK && count > 0) {
            // Take all available samples
            uint8_t buffer[1024];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                HelloWorld_deserialize(&msg, buffer, len);
                printf("  Received: %s (id=%d)\n", msg.message, msg.id);
                received++;
            }
        } else {
            printf("  (timeout - no messages)\n");
        }
    }

    printf("Done receiving.\n");
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 &&
        (strcmp(argv[1], "pub") == 0 ||
         strcmp(argv[1], "publisher") == 0 ||
         strcmp(argv[1], "-p") == 0));

    // Initialize logging
    hdds_logging_init(3);  // INFO level

    // Create participant
    printf("Creating participant...\n");
    HddsParticipant* participant = hdds_participant_create("HelloWorld");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (is_publisher) {
        run_publisher(participant);
    } else {
        run_subscriber(participant);
    }

    // Cleanup
    hdds_participant_destroy(participant);
    printf("Cleanup complete.\n");

    return 0;
}
