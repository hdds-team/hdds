// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Ownership Exclusive (C)
 *
 * Demonstrates EXCLUSIVE ownership with strength-based arbitration.
 * Only the writer with highest strength publishes to a topic.
 *
 * Usage:
 *     ./ownership_exclusive             # Subscriber
 *     ./ownership_exclusive pub 100     # Publisher with strength 100
 *     ./ownership_exclusive pub 200     # Publisher with strength 200 (wins)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "generated/HelloWorld.h"

volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

void run_publisher(struct HddsParticipant* participant, int strength) {
    /* Create writer with EXCLUSIVE ownership */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_ownership_exclusive(qos, strength);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "OwnershipTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing with EXCLUSIVE ownership (strength: %d)\n", strength);
    printf("Higher strength wins ownership. Start another publisher with different strength.\n\n");

    signal(SIGINT, signal_handler);

    int seq = 0;
    while (running) {
        char text[64];
        snprintf(text, sizeof(text), "Writer[%d] seq=%d", strength, seq);

        HelloWorld msg = {.id = strength};  /* Use strength as ID */
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);
        printf("  [PUBLISHED strength=%d] seq=%d\n", strength, seq);

        seq++;
        usleep(500000);  /* 500ms */
    }

    printf("\nPublisher (strength=%d) shutting down.\n", strength);
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create reader with EXCLUSIVE ownership */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_ownership_exclusive(qos, 0);  /* Strength doesn't matter for reader */

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "OwnershipTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Subscribing with EXCLUSIVE ownership...\n");
    printf("Only data from the highest-strength writer will be received.\n\n");

    signal(SIGINT, signal_handler);

    int last_owner = -1;

    while (running) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 1000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    if (msg.id != last_owner) {
                        printf("\n  ** OWNERSHIP CHANGED to writer with strength=%d **\n\n", msg.id);
                        last_owner = msg.id;
                    }
                    printf("  [RECV from strength=%d] %s\n", msg.id, msg.message);
                }
            }
        }
    }

    printf("\nSubscriber shutting down.\n");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);
    int strength = 100;  /* Default strength */

    if (is_publisher && argc > 2) {
        strength = atoi(argv[2]);
    }

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Ownership Exclusive Demo\n");
    printf("QoS: EXCLUSIVE ownership - highest strength writer wins\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("OwnershipDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (is_publisher) {
        run_publisher(participant, strength);
    } else {
        run_subscriber(participant);
    }

    hdds_participant_destroy(participant);
    return 0;
}
