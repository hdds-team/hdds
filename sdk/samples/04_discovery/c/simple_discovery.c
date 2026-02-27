// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Simple Discovery (C)
 *
 * Demonstrates automatic multicast discovery between DDS participants.
 * Participants automatically discover each other using SPDP over multicast.
 *
 * Usage:
 *     Terminal 1: ./simple_discovery
 *     Terminal 2: ./simple_discovery
 *
 * Key concepts:
 * - Automatic peer discovery via multicast
 * - No manual configuration required
 * - Graph guard condition for discovery events
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 10

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Simple Discovery Demo\n");
    printf("Automatic multicast discovery (SPDP)\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    /* Get instance ID from args or use PID */
    uint32_t instance_id = (argc > 1) ? (uint32_t)atoi(argv[1]) : (uint32_t)getpid();
    printf("Instance ID: %u\n\n", instance_id);

    /* Create participant - discovery starts automatically */
    char name_buf[64];
    snprintf(name_buf, sizeof(name_buf), "SimpleDiscovery_%u", instance_id);

    struct HddsParticipant* participant = hdds_participant_create(name_buf);
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));
    printf("     Participant ID: %u\n", hdds_participant_id(participant));

    /* Create writer and reader for demonstration */
    struct HddsDataWriter* writer = hdds_writer_create(participant, "DiscoveryDemo");
    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] DataWriter created on topic 'DiscoveryDemo'\n");

    struct HddsDataReader* reader = hdds_reader_create(participant, "DiscoveryDemo");
    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] DataReader created on topic 'DiscoveryDemo'\n");

    /* Set up WaitSet for data reception */
    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("\n--- Discovery in Progress ---\n");
    printf("Waiting for other participants to join...\n");
    printf("(Run another instance of this sample to see discovery)\n\n");

    /* Announce ourselves and listen for others */
    for (int i = 0; i < NUM_MESSAGES; i++) {
        /* Send an announcement */
        char text[64];
        snprintf(text, sizeof(text), "Hello from instance %u (#%d)", instance_id, i + 1);

        HelloWorld msg = {.id = (int32_t)(instance_id % 10000)};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
            printf("[SENT] %s\n", text);
        }

        /* Check for messages from other participants */
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 500000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t recv_buf[512];
            size_t recv_len;

            while (hdds_reader_take(reader, recv_buf, sizeof(recv_buf), &recv_len) == HDDS_OK) {
                HelloWorld recv_msg;
                if (HelloWorld_deserialize(&recv_msg, recv_buf, recv_len)) {
                    printf("[RECV] id=%d msg='%s'\n", recv_msg.id, recv_msg.message);
                }
            }
        }

        sleep(2);
    }

    printf("\n--- Sample complete (%d announcements sent) ---\n", NUM_MESSAGES);

    /* Cleanup */
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Discovery Demo Complete ===\n");
    return 0;
}
