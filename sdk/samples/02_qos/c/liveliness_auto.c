// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Liveliness Automatic (C)
 *
 * Demonstrates AUTOMATIC liveliness - system automatically asserts
 * liveliness via heartbeats. Reader detects when writer goes offline.
 *
 * Usage:
 *     ./liveliness_auto        # Subscriber (monitors liveliness)
 *     ./liveliness_auto pub    # Publisher (sends periodic data)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define LEASE_DURATION_MS 1000  /* 1 second lease */
#define NUM_MESSAGES 8

void run_publisher(struct HddsParticipant* participant) {
    /* Create writer with AUTOMATIC liveliness */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_liveliness_automatic_ns(qos, LEASE_DURATION_MS * 1000000ULL);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "LivelinessTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing with AUTOMATIC liveliness (lease: %dms)\n", LEASE_DURATION_MS);
    printf("System automatically sends heartbeats to maintain liveliness.\n\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Heartbeat #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("  [%ld.%03ld] Published id=%d - writer is ALIVE\n",
               ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);

        usleep(400000);  /* 400ms - faster than lease */
    }

    printf("\nPublisher going offline. Subscriber should detect liveliness lost.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create reader with AUTOMATIC liveliness */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_liveliness_automatic_ns(qos, LEASE_DURATION_MS * 1000000ULL);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "LivelinessTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Monitoring AUTOMATIC liveliness (lease: %dms)...\n", LEASE_DURATION_MS);
    printf("Will detect if writer goes offline.\n\n");

    int received = 0;
    int liveliness_lost_count = 0;
    struct timespec last_msg;
    clock_gettime(CLOCK_MONOTONIC, &last_msg);

    while (received < NUM_MESSAGES + 2) {  /* Wait for a couple extra timeouts */
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, LEASE_DURATION_MS * 2 * 1000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);

                    printf("  [%ld.%03ld] Received id=%d - writer ALIVE\n",
                           now.tv_sec % 100, now.tv_nsec / 1000000, msg.id);

                    last_msg = now;
                    received++;
                }
            }
        } else {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);

            long since_last_ms = (now.tv_sec - last_msg.tv_sec) * 1000 +
                                  (now.tv_nsec - last_msg.tv_nsec) / 1000000;

            if (since_last_ms > LEASE_DURATION_MS) {
                printf("  [%ld.%03ld] LIVELINESS LOST - no heartbeat for %ldms!\n",
                       now.tv_sec % 100, now.tv_nsec / 1000000, since_last_ms);
                liveliness_lost_count++;

                if (liveliness_lost_count >= 2) {
                    break;  /* Exit after detecting lost liveliness */
                }
            }
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Summary: %d messages, liveliness lost %d times\n",
           received, liveliness_lost_count);
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Liveliness Automatic Demo\n");
    printf("QoS: AUTOMATIC liveliness - system heartbeats\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("LivelinessAutoDemo");
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
