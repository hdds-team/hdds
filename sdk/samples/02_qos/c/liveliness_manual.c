// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Liveliness Manual (C)
 *
 * Demonstrates MANUAL_BY_PARTICIPANT liveliness - application must
 * explicitly assert liveliness. Useful for detecting app-level failures.
 *
 * Usage:
 *     ./liveliness_manual        # Subscriber (monitors liveliness)
 *     ./liveliness_manual pub    # Publisher (with manual assertion)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define LEASE_DURATION_MS 2000  /* 2 second lease */
#define NUM_MESSAGES 6

void run_publisher(struct HddsParticipant* participant) {
    /* Create writer with MANUAL_BY_PARTICIPANT liveliness */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_liveliness_manual_participant_ns(qos, LEASE_DURATION_MS * 1000000ULL);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "ManualLivenessTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing with MANUAL_BY_PARTICIPANT liveliness (lease: %dms)\n", LEASE_DURATION_MS);
    printf("Application must explicitly assert liveliness.\n\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Manual update #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        /* Writing data implicitly asserts liveliness */
        hdds_writer_write(writer, buffer, len);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("  [%ld.%03ld] Published id=%d (liveliness asserted via write)\n",
               ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);

        /* First 3 messages: normal rate
         * Last 3 messages: slow rate (will miss liveliness) */
        if (i < 3) {
            usleep(500000);  /* 500ms - OK */
        } else {
            printf("  (simulating slow processing...)\n");
            usleep(2500000);  /* 2.5s - exceeds lease! */
        }
    }

    printf("\nPublisher done. Some liveliness violations occurred.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create reader with MANUAL_BY_PARTICIPANT liveliness */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_liveliness_manual_participant_ns(qos, LEASE_DURATION_MS * 1000000ULL);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "ManualLivenessTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Monitoring MANUAL_BY_PARTICIPANT liveliness (lease: %dms)...\n", LEASE_DURATION_MS);
    printf("Writer must assert liveliness explicitly (by writing).\n\n");

    int received = 0;
    int liveliness_changed = 0;
    struct timespec last_msg;
    clock_gettime(CLOCK_MONOTONIC, &last_msg);

    while (received < NUM_MESSAGES || liveliness_changed < 3) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, LEASE_DURATION_MS * 1000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);

                    long delta_ms = (now.tv_sec - last_msg.tv_sec) * 1000 +
                                    (now.tv_nsec - last_msg.tv_nsec) / 1000000;

                    const char* status = (delta_ms > LEASE_DURATION_MS && received > 0)
                        ? " [LIVELINESS WAS LOST]" : "";

                    printf("  [%ld.%03ld] Received id=%d (delta=%ldms)%s\n",
                           now.tv_sec % 100, now.tv_nsec / 1000000,
                           msg.id, delta_ms, status);

                    last_msg = now;
                    received++;
                }
            }
        } else {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);

            long since_last_ms = (now.tv_sec - last_msg.tv_sec) * 1000 +
                                  (now.tv_nsec - last_msg.tv_nsec) / 1000000;

            if (since_last_ms > LEASE_DURATION_MS && received > 0) {
                printf("  [%ld.%03ld] LIVELINESS LOST! (no assertion for %ldms)\n",
                       now.tv_sec % 100, now.tv_nsec / 1000000, since_last_ms);
                liveliness_changed++;
            }

            if (liveliness_changed >= 3) {
                break;
            }
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Summary: %d messages, %d liveliness events detected\n",
           received, liveliness_changed);
    printf("MANUAL liveliness requires explicit app-level assertion.\n");
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Liveliness Manual Demo\n");
    printf("QoS: MANUAL_BY_PARTICIPANT - app must assert liveliness\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("LivelinessManualDemo");
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
