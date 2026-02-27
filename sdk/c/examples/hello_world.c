// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Example: Hello World (C)
 *
 * Self-contained pub/sub demo using intra-process transport.
 * Creates a participant, writer and reader on the same topic,
 * publishes 10 messages using raw byte buffers, then uses a
 * WaitSet for event-driven receive.
 *
 * Build: cmake --build . --target hello_world
 * Usage: ./hello_world
 *
 * Expected output:
 *     Creating participant...
 *     Published 10 messages.
 *     Received: Hello #0 from HDDS C!
 *     ...
 *     Total received: 10 / 10
 *     Cleanup complete.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_MESSAGES 10

int main(void) {
    /* Initialize logging at INFO level */
    hdds_logging_init(HDDS_LOG_INFO);

    /* Create an intra-process participant (no network needed) */
    printf("Creating participant...\n");
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("HelloWorldExample", HDDS_TRANSPORT_INTRA_PROCESS);
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    /* Create writer and reader on the same topic */
    struct HddsDataWriter *writer = hdds_writer_create(participant, "HelloTopic");
    struct HddsDataReader *reader = hdds_reader_create(participant, "HelloTopic");
    if (!writer || !reader) {
        fprintf(stderr, "Failed to create writer or reader\n");
        hdds_participant_destroy(participant);
        return 1;
    }

    /* Publish messages using raw byte buffers */
    for (int i = 0; i < NUM_MESSAGES; i++) {
        char payload[64];
        int len = snprintf(payload, sizeof(payload), "Hello #%d from HDDS C!", i);

        enum HddsError err = hdds_writer_write(writer, payload, (size_t)len + 1);
        if (err != HDDS_OK) {
            fprintf(stderr, "Write failed: error %d\n", err);
        }
    }
    printf("Published %d messages.\n", NUM_MESSAGES);

    /* Set up WaitSet for event-driven receive */
    struct HddsWaitSet *waitset = hdds_waitset_create();
    if (!waitset) {
        fprintf(stderr, "Failed to create waitset\n");
        goto cleanup_entities;
    }

    const struct HddsStatusCondition *status_cond =
        hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, status_cond);

    /* Wait for data to arrive (up to 2 seconds) */
    const void *triggered[4];
    size_t trigger_count = 0;
    enum HddsError wait_err = hdds_waitset_wait(
        waitset, 2000000000LL, triggered, 4, &trigger_count);

    /* Take all available messages */
    uint8_t buf[256];
    size_t received_len;
    int count = 0;

    if (wait_err == HDDS_OK && trigger_count > 0) {
        while (hdds_reader_take(reader, buf, sizeof(buf), &received_len) == HDDS_OK) {
            printf("Received: %s\n", (char *)buf);
            count++;
        }
    }

    printf("Total received: %d / %d\n", count, NUM_MESSAGES);

    /* Detach condition and destroy waitset */
    hdds_waitset_detach_condition(waitset, (const void *)status_cond);
    hdds_status_condition_release(status_cond);
    hdds_waitset_destroy(waitset);

cleanup_entities:
    /* Clean teardown — destroy in reverse creation order */
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    printf("Cleanup complete.\n");

    return 0;
}
