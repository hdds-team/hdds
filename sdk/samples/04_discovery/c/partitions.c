// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Partitions (C)
 *
 * Demonstrates logical data separation using partition QoS.
 * Only endpoints with matching partitions will communicate.
 *
 * Usage:
 *     ./partitions A          # Publish/subscribe to partition A
 *     ./partitions B          # Publish/subscribe to partition B (no match)
 *     ./partitions A pub      # Publisher only in partition A
 *
 * Key concepts:
 * - Partition QoS for logical separation
 * - Endpoints only match when partitions overlap
 * - Same topic, different partitions = no communication
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 10

void run_publisher(struct HddsParticipant* participant, const char* partition) {
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_add_partition(qos, partition);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "PartitionTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("[OK] DataWriter created in partition '%s'\n\n", partition);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "[%s] Message #%d", partition, i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
            printf("[SENT:%s] id=%d msg='%s'\n", partition, msg.id, msg.message);
        }

        usleep(500000);  /* 500ms */
    }

    printf("\nDone publishing to partition '%s'.\n", partition);
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant, const char* partition) {
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_add_partition(qos, partition);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "PartitionTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    printf("[OK] DataReader created in partition '%s'\n", partition);

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Waiting for messages in partition '%s'...\n\n", partition);

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
                    printf("[RECV:%s] id=%d msg='%s'\n", partition, msg.id, msg.message);
                    received++;
                }
            }
            timeouts = 0;
        } else {
            timeouts++;
            printf("  (waiting in partition '%s'...)\n", partition);
        }
    }

    if (received > 0) {
        printf("\nReceived %d messages in partition '%s'.\n", received, partition);
    } else {
        printf("\nNo messages received in partition '%s'.\n", partition);
        printf("Ensure publisher is using the same partition.\n");
    }

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Partitions Demo\n");
    printf("Logical data separation using partition QoS\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    /* Parse arguments */
    const char* partition = (argc > 1) ? argv[1] : "DefaultPartition";
    int is_publisher = (argc > 2 && strcmp(argv[2], "pub") == 0);
    int is_subscriber = (argc > 2 && strcmp(argv[2], "sub") == 0);

    printf("Partition: %s\n", partition);
    printf("Mode: %s\n\n", is_publisher ? "Publisher" : (is_subscriber ? "Subscriber" : "Both"));

    printf("--- Partition Matching Rules ---\n");
    printf("Endpoints only communicate if they share at least one partition.\n");
    printf("Example: 'A' matches 'A', but 'A' does NOT match 'B'\n\n");

    /* Create participant */
    struct HddsParticipant* participant = hdds_participant_create("PartitionsDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));

    if (is_publisher) {
        run_publisher(participant, partition);
    } else if (is_subscriber) {
        run_subscriber(participant, partition);
    } else {
        /* Run both publisher and subscriber */
        printf("\n--- Publisher ---\n");
        run_publisher(participant, partition);
        printf("\n--- Subscriber ---\n");
        run_subscriber(participant, partition);
    }

    hdds_participant_destroy(participant);

    printf("\n=== Partitions Demo Complete ===\n");
    return 0;
}
