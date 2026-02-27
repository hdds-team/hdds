// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Deadline Monitor (C)
 *
 * Demonstrates DEADLINE QoS for monitoring update rates.
 * Publisher must send data within deadline or violation is reported.
 *
 * Usage:
 *     ./deadline_monitor        # Subscriber (monitors deadline)
 *     ./deadline_monitor pub    # Publisher (normal rate)
 *     ./deadline_monitor slow   # Publisher (misses deadlines)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define DEADLINE_MS 500  /* 500ms deadline period */
#define NUM_MESSAGES 10

void run_publisher(struct HddsParticipant* participant, int slow_mode) {
    /* Create writer with deadline QoS */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_deadline_ns(qos, DEADLINE_MS * 1000000ULL);

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "DeadlineTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    int interval_ms = slow_mode ? 800 : 300;  /* 800ms violates, 300ms is OK */

    printf("Publishing with %dms interval (deadline: %dms)\n", interval_ms, DEADLINE_MS);
    if (slow_mode) {
        printf("WARNING: This will MISS deadlines!\n");
    } else {
        printf("This should meet all deadlines.\n");
    }
    printf("\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Update #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("  [%ld.%03ld] Sent id=%d\n",
               ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);

        usleep(interval_ms * 1000);
    }

    printf("\nDone publishing.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create reader with deadline QoS */
    struct HddsQoS* qos = hdds_qos_reliable();
    hdds_qos_set_deadline_ns(qos, DEADLINE_MS * 1000000ULL);

    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "DeadlineTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Monitoring for deadline violations (deadline: %dms)...\n\n", DEADLINE_MS);

    int received = 0;
    int deadline_violations = 0;
    struct timespec last_recv;
    clock_gettime(CLOCK_MONOTONIC, &last_recv);

    while (received < NUM_MESSAGES) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, DEADLINE_MS * 2 * 1000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec now;
                    clock_gettime(CLOCK_MONOTONIC, &now);

                    long delta_ms = (now.tv_sec - last_recv.tv_sec) * 1000 +
                                    (now.tv_nsec - last_recv.tv_nsec) / 1000000;

                    const char* status = (delta_ms > DEADLINE_MS && received > 0)
                                         ? "DEADLINE MISSED!" : "OK";

                    if (delta_ms > DEADLINE_MS && received > 0) {
                        deadline_violations++;
                    }

                    printf("  [%ld.%03ld] Received id=%d (delta=%ldms) %s\n",
                           now.tv_sec % 100, now.tv_nsec / 1000000,
                           msg.id, delta_ms, status);

                    last_recv = now;
                    received++;
                }
            }
        } else {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            printf("  [%ld.%03ld] DEADLINE VIOLATION - no data received!\n",
                   now.tv_sec % 100, now.tv_nsec / 1000000);
            deadline_violations++;
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Summary: %d messages received, %d deadline violations\n",
           received, deadline_violations);
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);
    int slow_mode = (argc > 1 && strcmp(argv[1], "slow") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Deadline Monitor Demo\n");
    printf("QoS: DEADLINE - monitor update rate violations\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("DeadlineDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (is_publisher || slow_mode) {
        run_publisher(participant, slow_mode);
    } else {
        run_subscriber(participant);
    }

    hdds_participant_destroy(participant);
    return 0;
}
