// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: History Keep Last (C)
 *
 * Demonstrates KEEP_LAST history QoS with configurable depth.
 * Only the N most recent samples are retained per instance.
 *
 * Usage:
 *     ./history_keep_last        # Subscriber (default depth=3)
 *     ./history_keep_last pub    # Publisher (burst of 10 messages)
 *     ./history_keep_last sub 5  # Subscriber with depth=5
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 10

void run_publisher(struct HddsParticipant* participant) {
    /* Create writer with KEEP_LAST history */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, NUM_MESSAGES);  /* Keep all on writer side */

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "HistoryTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages in rapid succession...\n\n", NUM_MESSAGES);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Message #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);
        printf("  [SENT] id=%d msg='%s'\n", msg.id, msg.message);
    }

    printf("\nAll %d messages published.\n", NUM_MESSAGES);
    printf("Subscriber with history depth < %d will only see most recent.\n", NUM_MESSAGES);
    printf("Press Enter to exit (keep writer alive for late-join test)...\n");
    getchar();

    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant, int history_depth) {
    /* Create reader with KEEP_LAST history */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, history_depth);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "HistoryTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Subscribing with KEEP_LAST history (depth=%d)...\n", history_depth);
    printf("Will only retain the %d most recent samples.\n\n", history_depth);

    int received = 0;
    int timeouts = 0;

    while (timeouts < 2) {
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
            timeouts = 0;
        } else {
            timeouts++;
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Summary: Received %d messages (history depth was %d)\n", received, history_depth);

    if (received <= history_depth) {
        printf("All received messages fit within history depth.\n");
    } else {
        printf("Note: If publisher sent more than %d messages,\n", history_depth);
        printf("only the most recent %d were retained in history.\n", history_depth);
    }
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);
    int history_depth = 3;  /* Default history depth */

    if (argc > 2) {
        history_depth = atoi(argv[2]);
        if (history_depth < 1) history_depth = 1;
    }

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("History Keep Last Demo\n");
    printf("QoS: KEEP_LAST - retain N most recent samples per instance\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("HistoryDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (is_publisher) {
        run_publisher(participant);
    } else {
        run_subscriber(participant, history_depth);
    }

    hdds_participant_destroy(participant);
    return 0;
}
