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
#include "../../common/sample_decode.h"

SAMPLE_DEFINE_DECODE(decode_checked, hdds_samples_HelloWorld, hdds_samples_helloworld_decode_cdr2_le_alloc)

/* The publisher gives up if no subscriber matches within this time. */
#define DISCOVERY_TIMEOUT_MS 30000u
/* The subscriber exits when no message arrives for this long. */
#define IDLE_TIMEOUT_MS 30000u

static int run_publisher(HddsParticipant* participant) {
    printf("Creating writer...\n");
    HddsDataWriter* writer = hdds_samples_helloworld_create_writer(participant, "HelloWorldTopic", NULL);
    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return 1;
    }

    /* A sample written before discovery completes is never delivered,
     * so wait until a subscriber has matched. */
    printf("Waiting for a subscriber...\n");
    if (hdds_writer_wait_for_matched_readers(writer, 1, DISCOVERY_TIMEOUT_MS) != HDDS_OK) {
        fprintf(stderr, "No subscriber matched within %u s; start the subscriber first\n",
                DISCOVERY_TIMEOUT_MS / 1000u);
        hdds_writer_destroy(writer);
        return 1;
    }

    printf("Publishing messages...\n");
    hdds_samples_HelloWorld msg;
    msg.id = 0;
    msg.message = "Hello from HDDS C!";

    for (int i = 0; i < 10; i++) {
        msg.id = i;

        // Serialize and write
        uint8_t buffer[1024];
        int len = hdds_samples_helloworld_encode_cdr2_le(&msg, buffer, sizeof(buffer));
        if (len < 0) { fprintf(stderr, "  Encode error %d\n", len); continue; }

        if (hdds_writer_write(writer, buffer, (size_t)len) == HDDS_OK) {
            printf("  Published: %s (id=%d)\n", msg.message, msg.id);
        } else {
            fprintf(stderr, "  Failed to publish message %d\n", i);
        }

        usleep(500000);  // 500ms
    }

    printf("Done publishing.\n");
    hdds_writer_destroy(writer);
    return 0;
}

static void run_subscriber(HddsParticipant* participant) {
    printf("Creating reader...\n");
    HddsDataReader* reader = hdds_reader_create_with_type(participant, "HelloWorldTopic", hdds_samples_hello_world_type_name(), NULL);
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
    unsigned idle_ms = 0;

    while (received < 10 && idle_ms < IDLE_TIMEOUT_MS) {
        // Wait up to 1 second, so the idle check runs regularly
        const void* triggered[1];
        size_t count;

        if (hdds_waitset_wait(waitset, 1000000000LL, triggered, 1, &count) == HDDS_OK && count > 0) {
            idle_ms = 0;
            // Take all available samples
            uint8_t buffer[1024];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                hdds_samples_HelloWorld msg = {0};
                char message_buf[256];
                msg.message = message_buf;
                if (decode_checked(&msg, buffer, len) <= 0) {
                    continue;
                }
                printf("  Received: %s (id=%d)\n", msg.message, msg.id);
                received++;
            }
        } else {
            idle_ms += 1000;
        }
    }

    if (received < 10) {
        printf("  No message for %u s, giving up.\n", IDLE_TIMEOUT_MS / 1000u);
    }
    printf("Done receiving. Received %d of 10 messages.\n", received);
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

    // Create participant. No domain is passed: the library reads HDDS_DOMAIN_ID
    // (a malformed value makes this fail), else uses domain 0.
    HddsParticipant* participant = hdds_participant_create("HelloWorld");
    if (!participant) {
        fprintf(stderr, "Failed to create participant (is HDDS_DOMAIN_ID valid?)\n");
        return 1;
    }
    printf("Participant created (domain %u)\n", hdds_participant_domain_id(participant));

    int status = 0;
    if (is_publisher) {
        status = run_publisher(participant);
    } else {
        run_subscriber(participant);
    }

    // Cleanup
    hdds_participant_destroy(participant);
    printf("Cleanup complete.\n");

    return status;
}
