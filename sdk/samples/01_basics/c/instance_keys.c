// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Instance Keys (C)
 *
 * Demonstrates keyed instances in DDS.
 *
 * Usage:
 *     ./instance_keys        # Subscriber
 *     ./instance_keys pub    # Publisher
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/KeyedData.h"

#define NUM_INSTANCES 3

static void run_publisher(HddsParticipant* participant) {
    HddsDataWriter* writer = hdds_writer_create(participant, "SensorTopic");
    printf("Publishing updates for %d sensor instances...\n\n", NUM_INSTANCES);

    for (int seq = 0; seq < 5; seq++) {
        for (int sensor_id = 0; sensor_id < NUM_INSTANCES; sensor_id++) {
            KeyedData msg;
            KeyedData_init(&msg);
            msg.id = sensor_id;
            snprintf(msg.data, sizeof(msg.data), "Sensor-%d reading", sensor_id);
            msg.sequence_num = seq;

            uint8_t buffer[512];
            size_t len = KeyedData_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writer, buffer, len);

            printf("  [Sensor %d] seq=%d -> '%s'\n", sensor_id, seq, msg.data);
        }
        usleep(500000);
    }

    printf("\nDone publishing.\n");
    hdds_writer_destroy(writer);
}

static void run_subscriber(HddsParticipant* participant) {
    HddsDataReader* reader = hdds_reader_create(participant, "SensorTopic");
    HddsWaitSet* waitset = hdds_waitset_create();
    hdds_waitset_attach_status_condition(waitset, hdds_reader_get_status_condition(reader));

    // Track state per instance
    int instance_state[NUM_INSTANCES];
    for (int i = 0; i < NUM_INSTANCES; i++) {
        instance_state[i] = -1;
    }

    printf("Subscribing to %d sensor instances...\n\n", NUM_INSTANCES);
    int total_expected = NUM_INSTANCES * 5;
    int received = 0;

    while (received < total_expected) {
        const void* triggered[1];
        size_t count;

        if (hdds_waitset_wait(waitset, 3000000000LL, triggered, 1, &count) == HDDS_OK && count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                KeyedData msg;
                KeyedData_deserialize(&msg, buffer, len);

                int prev_seq = instance_state[msg.id];
                instance_state[msg.id] = msg.sequence_num;

                printf("  [Sensor %d] seq=%u (prev=%d) -> '%s'\n",
                       msg.id, msg.sequence_num, prev_seq, msg.data);
                received++;
            }
        } else {
            printf("  (timeout)\n");
        }
    }

    printf("\nFinal instance states:\n");
    for (int i = 0; i < NUM_INSTANCES; i++) {
        printf("  Sensor %d: last_seq=%d\n", i, instance_state[i]);
    }

    printf("Done.\n");
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(3);

    printf("============================================================\n");
    printf("Instance Keys Demo\n");
    printf("Simulating %d sensor instances with keyed data\n", NUM_INSTANCES);
    printf("============================================================\n");

    HddsParticipant* participant = hdds_participant_create("InstanceKeysDemo");
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
