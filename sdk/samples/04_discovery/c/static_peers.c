// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Static Peers (C)
 *
 * Demonstrates static peer configuration for discovery when multicast
 * is not available. Uses IntraProcess transport for testing.
 *
 * In production, you would use UDP with explicit peer addresses.
 *
 * Usage:
 *     Terminal 1: ./static_peers
 *     Terminal 2: ./static_peers 2
 *
 * Key concepts:
 * - Transport mode selection
 * - IntraProcess vs UdpMulticast transports
 * - Multiple participants in same process
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 5

void run_publisher(struct HddsParticipant* participant, int instance_id) {
    struct HddsQoS* qos = hdds_qos_reliable();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "StaticPeersTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("[OK] DataWriter created\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Peer %d message #%d", instance_id, i + 1);

        HelloWorld msg = {.id = instance_id * 100 + i};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
            printf("[SENT] id=%d msg='%s'\n", msg.id, msg.message);
        }

        usleep(500000);  /* 500ms */
    }

    printf("\nPublisher done.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant, int instance_id) {
    struct HddsQoS* qos = hdds_qos_reliable();
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "StaticPeersTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    printf("[OK] DataReader created\n");

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Waiting for messages from other peers...\n\n");

    int received = 0;
    int timeouts = 0;

    while (timeouts < 3) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 2000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    printf("[RECV] id=%d msg='%s'\n", msg.id, msg.message);
                    received++;
                }
            }
            timeouts = 0;
        } else {
            timeouts++;
            printf("  (waiting for peers...)\n");
        }
    }

    printf("\nSubscriber done. Received %d messages.\n", received);

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Static Peers Demo\n");
    printf("Transport mode selection for peer-to-peer discovery\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    int instance_id = (argc > 1) ? atoi(argv[1]) : 1;
    int is_publisher = (argc > 2 && strcmp(argv[2], "pub") == 0);

    printf("Instance ID: %d\n", instance_id);
    printf("Mode: %s\n", is_publisher ? "Publisher" : "Subscriber");
    printf("Transport: UdpMulticast (default)\n\n");

    /* Create participant with default UDP multicast transport */
    char name_buf[64];
    snprintf(name_buf, sizeof(name_buf), "StaticPeer_%d", instance_id);

    struct HddsParticipant* participant = hdds_participant_create(name_buf);
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));
    printf("     Participant ID: %u\n\n", hdds_participant_id(participant));

    printf("--- Connection Status ---\n");
    printf("Using multicast discovery on default ports.\n");
    printf("For static peer configuration, use transport config API.\n\n");

    if (is_publisher) {
        run_publisher(participant, instance_id);
    } else {
        run_subscriber(participant, instance_id);
    }

    hdds_participant_destroy(participant);

    printf("\n=== Static Peers Demo Complete ===\n");
    return 0;
}
