// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Discovery Listeners (C)
 *
 * Demonstrates using the graph guard condition to detect discovery events.
 * The guard condition triggers when participants or endpoints are discovered.
 *
 * Usage:
 *     Terminal 1: ./discovery_listeners
 *     Terminal 2: ./discovery_listeners (or any other HDDS app)
 *
 * Key concepts:
 * - Graph guard condition for discovery notifications
 * - WaitSet-based event detection
 * - Monitoring participant and endpoint changes
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "generated/HelloWorld.h"

volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("Discovery Listeners Demo\n");
    printf("Monitor discovery events using graph guard condition\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    signal(SIGINT, signal_handler);

    /* Create participant */
    struct HddsParticipant* participant = hdds_participant_create("DiscoveryListeners");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));
    printf("     Participant ID: %u\n", hdds_participant_id(participant));

    /* Get graph guard condition - triggers on discovery events */
    const struct HddsGuardCondition* graph_cond = hdds_participant_graph_guard_condition(participant);
    if (!graph_cond) {
        fprintf(stderr, "Failed to get graph guard condition\n");
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] Graph guard condition obtained\n");

    /* Create writer and reader to participate in discovery */
    struct HddsDataWriter* writer = hdds_writer_create(participant, "ListenerDemo");
    struct HddsDataReader* reader = hdds_reader_create(participant, "ListenerDemo");

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] DataWriter created on topic 'ListenerDemo'\n");
    printf("[OK] DataReader created on topic 'ListenerDemo'\n");

    /* Set up WaitSet with both data and graph conditions */
    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* data_cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, data_cond);
    hdds_waitset_attach_guard_condition(waitset, graph_cond);

    printf("\n--- Listening for Discovery Events ---\n");
    printf("Run other HDDS applications to see discovery events.\n");
    printf("Press Ctrl+C to exit.\n\n");

    int event_count = 0;
    time_t last_event = time(NULL);
    int timeout_seconds = 30;

    while (running) {
        const void* triggered[4];
        size_t triggered_count;

        if (hdds_waitset_wait(waitset, 1000000000LL, triggered, 4, &triggered_count) == HDDS_OK && triggered_count > 0) {
            for (size_t i = 0; i < triggered_count; i++) {
                if (triggered[i] == graph_cond) {
                    event_count++;
                    printf("[EVENT %d] Discovery graph changed!\n", event_count);
                    printf("          A participant or endpoint was discovered/lost\n\n");
                    last_event = time(NULL);
                } else if (triggered[i] == data_cond) {
                    /* Handle data */
                    uint8_t buffer[512];
                    size_t len;

                    while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                        HelloWorld msg;
                        if (HelloWorld_deserialize(&msg, buffer, len)) {
                            printf("[DATA] id=%d msg='%s'\n", msg.id, msg.message);
                        }
                    }
                }
            }
        }

        /* Send periodic heartbeat */
        static int heartbeat = 0;
        if (++heartbeat % 5 == 0) {
            HelloWorld msg = {.id = heartbeat};
            snprintf(msg.message, sizeof(msg.message), "Heartbeat %d", heartbeat);

            uint8_t buffer[256];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writer, buffer, len);
        }

        /* Check timeout */
        if (time(NULL) - last_event > timeout_seconds && event_count > 0) {
            printf("--- No new events for %d seconds ---\n", timeout_seconds);
            break;
        }
    }

    /* Summary */
    printf("\n--- Discovery Summary ---\n");
    printf("Total discovery events detected: %d\n", event_count);

    /* Cleanup */
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Discovery Listeners Demo Complete ===\n");
    return 0;
}
