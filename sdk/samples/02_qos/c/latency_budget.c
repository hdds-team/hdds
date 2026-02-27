// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Latency Budget (C)
 *
 * Demonstrates LATENCY_BUDGET QoS for hinting acceptable delivery latency.
 * Two writers publish on different topics with different latency budgets:
 * one with zero latency (real-time) and one with 100ms budget (batching hint).
 *
 * Note: The actual effect of latency budget depends on the middleware
 * implementation. This sample demonstrates the API usage pattern.
 *
 * Usage:
 *     ./latency_budget        # Subscriber (reads from both topics)
 *     ./latency_budget pub    # Publisher (writes to both topics)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES    5
#define SEND_INTERVAL_MS 200
#define BUDGET_REALTIME_NS  0ULL
#define BUDGET_BATCHED_NS   100000000ULL  /* 100ms */

void run_publisher(struct HddsParticipant* participant) {
    /* Create low-latency writer (budget = 0) */
    struct HddsQoS* qos_rt = hdds_qos_reliable();
    hdds_qos_set_latency_budget_ns(qos_rt, BUDGET_REALTIME_NS);

    struct HddsDataWriter* writer_rt = hdds_writer_create_with_qos(participant, "LowLatencyTopic", qos_rt);
    hdds_qos_destroy(qos_rt);

    if (!writer_rt) {
        fprintf(stderr, "Failed to create low-latency writer\n");
        return;
    }

    /* Create batched writer (budget = 100ms) */
    struct HddsQoS* qos_batch = hdds_qos_reliable();
    hdds_qos_set_latency_budget_ns(qos_batch, BUDGET_BATCHED_NS);

    struct HddsDataWriter* writer_batch = hdds_writer_create_with_qos(participant, "BatchedTopic", qos_batch);
    hdds_qos_destroy(qos_batch);

    if (!writer_batch) {
        fprintf(stderr, "Failed to create batched writer\n");
        hdds_writer_destroy(writer_rt);
        return;
    }

    printf("Publishing %d messages on each topic alternately:\n", NUM_MESSAGES);
    printf("  LowLatencyTopic  -> budget = 0ns (real-time)\n");
    printf("  BatchedTopic      -> budget = 100ms (batching hint)\n\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        struct timespec ts;

        /* Send low-latency message */
        {
            char text[64];
            snprintf(text, sizeof(text), "RealTime #%d", i + 1);

            HelloWorld msg = {.id = i + 1};
            strncpy(msg.message, text, sizeof(msg.message) - 1);

            uint8_t buffer[256];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writer_rt, buffer, len);

            clock_gettime(CLOCK_MONOTONIC, &ts);
            printf("  [%ld.%03ld] Sent LowLatency  id=%d\n",
                   ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);
        }

        usleep(50 * 1000);  /* 50ms gap between the two writes */

        /* Send batched message */
        {
            char text[64];
            snprintf(text, sizeof(text), "Batched #%d", i + 1);

            HelloWorld msg = {.id = i + 1};
            strncpy(msg.message, text, sizeof(msg.message) - 1);

            uint8_t buffer[256];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writer_batch, buffer, len);

            clock_gettime(CLOCK_MONOTONIC, &ts);
            printf("  [%ld.%03ld] Sent Batched     id=%d\n",
                   ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);
        }

        usleep(SEND_INTERVAL_MS * 1000);
    }

    printf("\nDone publishing.\n");
    hdds_writer_destroy(writer_rt);
    hdds_writer_destroy(writer_batch);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create low-latency reader (budget = 0) */
    struct HddsQoS* qos_rt = hdds_qos_reliable();
    hdds_qos_set_latency_budget_ns(qos_rt, BUDGET_REALTIME_NS);

    struct HddsDataReader* reader_rt = hdds_reader_create_with_qos(participant, "LowLatencyTopic", qos_rt);
    hdds_qos_destroy(qos_rt);

    if (!reader_rt) {
        fprintf(stderr, "Failed to create low-latency reader\n");
        return;
    }

    /* Create batched reader (budget = 100ms) */
    struct HddsQoS* qos_batch = hdds_qos_reliable();
    hdds_qos_set_latency_budget_ns(qos_batch, BUDGET_BATCHED_NS);

    struct HddsDataReader* reader_batch = hdds_reader_create_with_qos(participant, "BatchedTopic", qos_batch);
    hdds_qos_destroy(qos_batch);

    if (!reader_batch) {
        fprintf(stderr, "Failed to create batched reader\n");
        hdds_reader_destroy(reader_rt);
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond_rt = hdds_reader_get_status_condition(reader_rt);
    const struct HddsStatusCondition* cond_batch = hdds_reader_get_status_condition(reader_batch);
    hdds_waitset_attach_status_condition(waitset, cond_rt);
    hdds_waitset_attach_status_condition(waitset, cond_batch);

    printf("Listening on both topics...\n\n");

    int received_rt = 0;
    int received_batch = 0;
    int total_expected = NUM_MESSAGES * 2;

    while (received_rt + received_batch < total_expected) {
        const void* triggered[2];
        size_t triggered_count;

        if (hdds_waitset_wait(waitset, 5000000000LL, triggered, 2, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            /* Check low-latency reader */
            while (hdds_reader_take(reader_rt, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    printf("  [%ld.%03ld] LowLatency  received id=%d: \"%s\"\n",
                           ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, msg.message);
                    received_rt++;
                }
            }

            /* Check batched reader */
            while (hdds_reader_take(reader_batch, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    printf("  [%ld.%03ld] Batched     received id=%d: \"%s\"\n",
                           ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, msg.message);
                    received_batch++;
                }
            }
        } else {
            printf("  Timeout waiting for data.\n");
            break;
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Summary: LowLatency=%d, Batched=%d messages received\n",
           received_rt, received_batch);
    printf("Note: Actual latency difference depends on middleware internals.\n");
    printf("The latency budget is a hint, not a guarantee.\n");
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader_rt);
    hdds_reader_destroy(reader_batch);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Latency Budget Demo\n");
    printf("QoS: LATENCY_BUDGET - hint acceptable delivery latency\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("LatencyBudgetDemo");
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
