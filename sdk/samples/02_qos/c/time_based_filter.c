// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Time-Based Filter (C)
 *
 * Demonstrates TIME_BASED_FILTER QoS for reader-side sample filtering.
 * A minimum separation is enforced between accepted samples. Samples
 * arriving faster than the filter interval are silently dropped.
 *
 * This sample runs as a single process: publishes data, then reads
 * from two readers with different filter settings.
 *
 * Usage:
 *     ./time_based_filter        # Run full demo (single process)
 *     ./time_based_filter pub    # Publisher only
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES        20
#define SEND_INTERVAL_MS    100       /* 100ms between messages */
#define FILTER_NS           500000000ULL  /* 500ms minimum separation */

void run_publisher(struct HddsParticipant* participant) {
    struct HddsQoS* qos = hdds_qos_best_effort();

    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "FilteredTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("Publishing %d messages at %dms intervals...\n\n", NUM_MESSAGES, SEND_INTERVAL_MS);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        char text[64];
        snprintf(text, sizeof(text), "Msg #%d", i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        printf("  [%ld.%03ld] Sent id=%d\n",
               ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);

        usleep(SEND_INTERVAL_MS * 1000);
    }

    printf("\nDone publishing.\n");
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Reader A: no time-based filter (receives all samples) */
    struct HddsQoS* qos_all = hdds_qos_best_effort();

    struct HddsDataReader* reader_all = hdds_reader_create_with_qos(participant, "FilteredTopic", qos_all);
    hdds_qos_destroy(qos_all);

    if (!reader_all) {
        fprintf(stderr, "Failed to create unfiltered reader\n");
        return;
    }

    /* Reader B: 500ms time-based filter */
    struct HddsQoS* qos_filtered = hdds_qos_best_effort();
    hdds_qos_set_time_based_filter_ns(qos_filtered, FILTER_NS);

    struct HddsDataReader* reader_filtered = hdds_reader_create_with_qos(participant, "FilteredTopic", qos_filtered);
    hdds_qos_destroy(qos_filtered);

    if (!reader_filtered) {
        fprintf(stderr, "Failed to create filtered reader\n");
        hdds_reader_destroy(reader_all);
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond_all = hdds_reader_get_status_condition(reader_all);
    const struct HddsStatusCondition* cond_filt = hdds_reader_get_status_condition(reader_filtered);
    hdds_waitset_attach_status_condition(waitset, cond_all);
    hdds_waitset_attach_status_condition(waitset, cond_filt);

    printf("Listening with two readers:\n");
    printf("  Reader A: no filter (should receive all %d messages)\n", NUM_MESSAGES);
    printf("  Reader B: 500ms filter (should receive ~%d messages)\n\n",
           (int)(NUM_MESSAGES * SEND_INTERVAL_MS / (FILTER_NS / 1000000ULL)));

    int count_all = 0;
    int count_filtered = 0;
    int idle_rounds = 0;

    while (idle_rounds < 3) {
        const void* triggered[2];
        size_t triggered_count;
        int got_data = 0;

        if (hdds_waitset_wait(waitset, 1000000000LL, triggered, 2, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            /* Drain unfiltered reader */
            while (hdds_reader_take(reader_all, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    printf("  [%ld.%03ld] Reader A (all)      received id=%d\n",
                           ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);
                    count_all++;
                    got_data = 1;
                }
            }

            /* Drain filtered reader */
            while (hdds_reader_take(reader_filtered, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    printf("  [%ld.%03ld] Reader B (filtered) received id=%d\n",
                           ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);
                    count_filtered++;
                    got_data = 1;
                }
            }
        }

        if (!got_data) {
            idle_rounds++;
        } else {
            idle_rounds = 0;
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Results:\n");
    printf("  Reader A (no filter):    %d messages received\n", count_all);
    printf("  Reader B (500ms filter): %d messages received\n", count_filtered);
    printf("  Filter ratio: %.1f%% of messages passed through\n",
           count_all > 0 ? (100.0 * count_filtered / count_all) : 0.0);
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader_all);
    hdds_reader_destroy(reader_filtered);
}

int main(int argc, char** argv) {
    int pub_only = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Time-Based Filter Demo\n");
    printf("QoS: TIME_BASED_FILTER - reader-side minimum separation\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("TimeBasedFilterDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    if (pub_only) {
        run_publisher(participant);
    } else {
        /* Single-process mode: publish then subscribe */
        printf("Running single-process demo (publisher + 2 readers)...\n\n");

        /* Create readers first so they are ready when data arrives */
        struct HddsQoS* qos_all = hdds_qos_best_effort();
        struct HddsDataReader* reader_all = hdds_reader_create_with_qos(participant, "FilteredTopic", qos_all);
        hdds_qos_destroy(qos_all);

        struct HddsQoS* qos_filt = hdds_qos_best_effort();
        hdds_qos_set_time_based_filter_ns(qos_filt, FILTER_NS);
        struct HddsDataReader* reader_filtered = hdds_reader_create_with_qos(participant, "FilteredTopic", qos_filt);
        hdds_qos_destroy(qos_filt);

        if (!reader_all || !reader_filtered) {
            fprintf(stderr, "Failed to create readers\n");
            if (reader_all) hdds_reader_destroy(reader_all);
            if (reader_filtered) hdds_reader_destroy(reader_filtered);
            hdds_participant_destroy(participant);
            return 1;
        }

        /* Publish all data */
        struct HddsQoS* qos_wr = hdds_qos_best_effort();
        struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "FilteredTopic", qos_wr);
        hdds_qos_destroy(qos_wr);

        if (!writer) {
            fprintf(stderr, "Failed to create writer\n");
            hdds_reader_destroy(reader_all);
            hdds_reader_destroy(reader_filtered);
            hdds_participant_destroy(participant);
            return 1;
        }

        printf("Publishing %d messages at %dms intervals...\n\n", NUM_MESSAGES, SEND_INTERVAL_MS);

        for (int i = 0; i < NUM_MESSAGES; i++) {
            char text[64];
            snprintf(text, sizeof(text), "Msg #%d", i + 1);

            HelloWorld msg = {.id = i + 1};
            strncpy(msg.message, text, sizeof(msg.message) - 1);

            uint8_t buffer[256];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writer, buffer, len);

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            printf("  [%ld.%03ld] Sent id=%d\n",
                   ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id);

            usleep(SEND_INTERVAL_MS * 1000);
        }

        hdds_writer_destroy(writer);
        printf("\nPublishing complete. Reading results...\n\n");

        /* Brief pause to let delivery complete */
        usleep(200 * 1000);

        /* Read from both readers */
        int count_all = 0;
        int count_filtered = 0;
        uint8_t buffer[512];
        size_t len;

        while (hdds_reader_take(reader_all, buffer, sizeof(buffer), &len) == HDDS_OK) {
            HelloWorld msg;
            if (HelloWorld_deserialize(&msg, buffer, len)) {
                printf("  Reader A (all)      : id=%d \"%s\"\n", msg.id, msg.message);
                count_all++;
            }
        }

        while (hdds_reader_take(reader_filtered, buffer, sizeof(buffer), &len) == HDDS_OK) {
            HelloWorld msg;
            if (HelloWorld_deserialize(&msg, buffer, len)) {
                printf("  Reader B (filtered) : id=%d \"%s\"\n", msg.id, msg.message);
                count_filtered++;
            }
        }

        printf("\n%s\n", "------------------------------------------------------------");
        printf("Results:\n");
        printf("  Reader A (no filter):    %d messages received\n", count_all);
        printf("  Reader B (500ms filter): %d messages received\n", count_filtered);
        printf("  Filter ratio: %.1f%% of messages passed through\n",
               count_all > 0 ? (100.0 * count_filtered / count_all) : 0.0);
        printf("%s\n", "------------------------------------------------------------");

        hdds_reader_destroy(reader_all);
        hdds_reader_destroy(reader_filtered);
    }

    hdds_participant_destroy(participant);
    return 0;
}
