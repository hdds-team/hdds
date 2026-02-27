// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Partition Filter (C)
 *
 * Demonstrates PARTITION QoS for logical data filtering.
 * Writers and readers only communicate when partitions match.
 *
 * Usage:
 *     ./partition_filter                # Subscriber (partition A)
 *     ./partition_filter pub            # Publisher (partition A)
 *     ./partition_filter pub B          # Publisher (partition B - no match)
 *     ./partition_filter sub B          # Subscriber (partition B)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 5

void run_publisher(struct HddsParticipant* participant, const char* partition) {
    /* Create writer with partition */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_add_partition(qos, partition);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "PartitionTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing to partition '%s'...\n\n", partition);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "[%s] Message #%d", partition, i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);
        printf("  [SENT:%s] id=%d msg='%s'\n", partition, msg.id, msg.message);

        usleep(200000);  /* 200ms */
    }

    printf("\nDone publishing to partition '%s'.\n", partition);
    printf("Only readers in matching partition will receive data.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant, const char* partition) {
    /* Create reader with partition */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_add_partition(qos, partition);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "PartitionTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Subscribing to partition '%s'...\n", partition);
    printf("Only publishers in matching partition will be received.\n\n");

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
                    printf("  [RECV:%s] id=%d msg='%s'\n", partition, msg.id, msg.message);
                    received++;
                }
            }
            timeouts = 0;
        } else {
            timeouts++;
            printf("  (waiting for partition '%s'...)\n", partition);
        }
    }

    if (received > 0) {
        printf("\nReceived %d messages in partition '%s'.\n", received, partition);
    } else {
        printf("\nNo messages received. Is there a publisher in partition '%s'?\n", partition);
        printf("Try: ./partition_filter pub %s\n", partition);
    }

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "sub";
    const char* partition = (argc > 2) ? argv[2] : "A";

    int is_publisher = (strcmp(mode, "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Partition Filter Demo\n");
    printf("QoS: PARTITION - logical data filtering by namespace\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("PartitionDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (is_publisher) {
        run_publisher(participant, partition);
    } else {
        run_subscriber(participant, partition);
    }

    hdds_participant_destroy(participant);
    return 0;
}
