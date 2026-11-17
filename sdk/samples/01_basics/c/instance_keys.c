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
#include "../../common/sample_decode.h"

SAMPLE_DEFINE_DECODE(decode_checked, hdds_samples_KeyedData, hdds_samples_keyeddata_decode_cdr2_le_alloc)

#define NUM_INSTANCES 3

static void run_publisher(HddsParticipant* participant) {
    HddsDataWriter* writer = hdds_samples_keyeddata_create_keyed_writer(participant, "SensorTopic", NULL);
    /* A sample written before discovery completes is never delivered,
     * so wait until a subscriber has matched. */
    printf("Waiting for a subscriber...\n");
    if (hdds_writer_wait_for_matched_readers(writer, 1, 10000u) != HDDS_OK) {
        fprintf(stderr, "No subscriber matched within 10 s; start the subscriber first\n");
        hdds_writer_destroy(writer);
        return;
    }
    printf("Publishing updates for %d sensor instances...\n\n", NUM_INSTANCES);

    for (int seq = 0; seq < 5; seq++) {
        for (int sensor_id = 0; sensor_id < NUM_INSTANCES; sensor_id++) {
            char data_str[256];
            snprintf(data_str, sizeof(data_str), "Sensor-%d reading", sensor_id);

            hdds_samples_KeyedData msg;
            msg.id = sensor_id;
            msg.data = data_str;
            msg.sequence_num = seq;

            /* A keyed writer takes the typed write, which carries the key. */
            HddsError rc = hdds_samples_keyeddata_write(writer, &msg);
            if (rc != HDDS_OK) {
                fprintf(stderr, "  write failed (error %d)\n", (int)rc);
                continue;
            }

            printf("  [Sensor %d] seq=%d -> '%s'\n", sensor_id, seq, msg.data);
        }
        usleep(500000);
    }

    printf("\nDone publishing.\n");
    hdds_writer_destroy(writer);
}

static void run_subscriber(HddsParticipant* participant) {
    HddsDataReader* reader = hdds_reader_create_with_type(participant, "SensorTopic", hdds_samples_keyed_data_type_name(), NULL);
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
                hdds_samples_KeyedData msg;
                char data_buf[256];
                msg.data = data_buf;
                if (decode_checked(&msg, buffer, len) <= 0) continue;

                if (msg.id < 0 || msg.id >= NUM_INSTANCES) continue;
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
