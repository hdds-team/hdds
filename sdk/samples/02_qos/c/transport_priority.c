// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Transport Priority (C)
 *
 * Demonstrates TRANSPORT_PRIORITY QoS for assigning network priorities
 * to data flows. Higher-priority data can be mapped to DSCP values
 * for differentiated handling at the network level.
 *
 * Note: Actual network prioritization depends on OS configuration and
 * network infrastructure (DSCP/TOS support). This sample shows API usage.
 *
 * Usage:
 *     ./transport_priority        # Subscriber (reads both topics)
 *     ./transport_priority pub    # Publisher (sends alarms + telemetry)
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES    5
#define PRIORITY_HIGH   10
#define PRIORITY_LOW    0

void run_publisher(struct HddsParticipant* participant) {
    /* Create high-priority writer for alarms */
    struct HddsQoS* qos_alarm = hdds_qos_reliable();
    hdds_qos_set_transport_priority(qos_alarm, PRIORITY_HIGH);

    struct HddsDataWriter* writer_alarm = hdds_writer_create_with_qos(participant, "AlarmTopic", qos_alarm);
    hdds_qos_destroy(qos_alarm);

    if (!writer_alarm) {
        fprintf(stderr, "Failed to create alarm writer\n");
        return;
    }

    /* Create low-priority writer for telemetry */
    struct HddsQoS* qos_telem = hdds_qos_reliable();
    hdds_qos_set_transport_priority(qos_telem, PRIORITY_LOW);

    struct HddsDataWriter* writer_telem = hdds_writer_create_with_qos(participant, "TelemetryTopic", qos_telem);
    hdds_qos_destroy(qos_telem);

    if (!writer_telem) {
        fprintf(stderr, "Failed to create telemetry writer\n");
        hdds_writer_destroy(writer_alarm);
        return;
    }

    printf("Publishing bursts on two topics:\n");
    printf("  AlarmTopic     -> priority=%d (high)\n", PRIORITY_HIGH);
    printf("  TelemetryTopic -> priority=%d (low)\n\n", PRIORITY_LOW);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        struct timespec ts;

        /* Send alarm burst */
        {
            char text[64];
            snprintf(text, sizeof(text), "ALARM level=%d sensor=%d", (i % 3) + 1, i + 1);

            HelloWorld msg = {.id = i + 1};
            strncpy(msg.message, text, sizeof(msg.message) - 1);

            uint8_t buffer[256];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writer_alarm, buffer, len);

            clock_gettime(CLOCK_MONOTONIC, &ts);
            printf("  [%ld.%03ld] Sent ALARM     id=%d priority=%d\n",
                   ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, PRIORITY_HIGH);
        }

        /* Send telemetry data */
        {
            char text[64];
            snprintf(text, sizeof(text), "temp=%.1f pressure=%.2f", 20.0 + i * 0.5, 1013.25 + i);

            HelloWorld msg = {.id = i + 1};
            strncpy(msg.message, text, sizeof(msg.message) - 1);

            uint8_t buffer[256];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
            hdds_writer_write(writer_telem, buffer, len);

            clock_gettime(CLOCK_MONOTONIC, &ts);
            printf("  [%ld.%03ld] Sent TELEMETRY id=%d priority=%d\n",
                   ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, PRIORITY_LOW);
        }

        usleep(300 * 1000);  /* 300ms between bursts */
    }

    printf("\nDone publishing.\n");
    hdds_writer_destroy(writer_alarm);
    hdds_writer_destroy(writer_telem);
}

void run_subscriber(struct HddsParticipant* participant) {
    /* Create reader for alarms (high priority) */
    struct HddsQoS* qos_alarm = hdds_qos_reliable();
    hdds_qos_set_transport_priority(qos_alarm, PRIORITY_HIGH);

    struct HddsDataReader* reader_alarm = hdds_reader_create_with_qos(participant, "AlarmTopic", qos_alarm);
    hdds_qos_destroy(qos_alarm);

    if (!reader_alarm) {
        fprintf(stderr, "Failed to create alarm reader\n");
        return;
    }

    /* Create reader for telemetry (low priority) */
    struct HddsQoS* qos_telem = hdds_qos_reliable();
    hdds_qos_set_transport_priority(qos_telem, PRIORITY_LOW);

    struct HddsDataReader* reader_telem = hdds_reader_create_with_qos(participant, "TelemetryTopic", qos_telem);
    hdds_qos_destroy(qos_telem);

    if (!reader_telem) {
        fprintf(stderr, "Failed to create telemetry reader\n");
        hdds_reader_destroy(reader_alarm);
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond_alarm = hdds_reader_get_status_condition(reader_alarm);
    const struct HddsStatusCondition* cond_telem = hdds_reader_get_status_condition(reader_telem);
    hdds_waitset_attach_status_condition(waitset, cond_alarm);
    hdds_waitset_attach_status_condition(waitset, cond_telem);

    printf("Listening for alarms (priority=%d) and telemetry (priority=%d)...\n\n",
           PRIORITY_HIGH, PRIORITY_LOW);

    int alarm_count = 0;
    int telem_count = 0;
    int total_expected = NUM_MESSAGES * 2;

    while (alarm_count + telem_count < total_expected) {
        const void* triggered[2];
        size_t triggered_count;

        if (hdds_waitset_wait(waitset, 5000000000LL, triggered, 2, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[512];
            size_t len;

            /* Check alarm reader */
            while (hdds_reader_take(reader_alarm, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    printf("  [%ld.%03ld] ALARM     id=%d: \"%s\"\n",
                           ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, msg.message);
                    alarm_count++;
                }
            }

            /* Check telemetry reader */
            while (hdds_reader_take(reader_telem, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                if (HelloWorld_deserialize(&msg, buffer, len)) {
                    struct timespec ts;
                    clock_gettime(CLOCK_MONOTONIC, &ts);
                    printf("  [%ld.%03ld] TELEMETRY id=%d: \"%s\"\n",
                           ts.tv_sec % 100, ts.tv_nsec / 1000000, msg.id, msg.message);
                    telem_count++;
                }
            }
        } else {
            printf("  Timeout waiting for data.\n");
            break;
        }
    }

    printf("\n%s\n", "------------------------------------------------------------");
    printf("Summary: Alarms=%d, Telemetry=%d messages received\n",
           alarm_count, telem_count);
    printf("\nNote: Actual network prioritization depends on:\n");
    printf("  - OS socket options (SO_PRIORITY / IP_TOS)\n");
    printf("  - Network infrastructure DSCP support\n");
    printf("  - Middleware transport-priority-to-DSCP mapping\n");
    printf("%s\n", "------------------------------------------------------------");

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader_alarm);
    hdds_reader_destroy(reader_telem);
}

int main(int argc, char** argv) {
    int is_publisher = (argc > 1 && strcmp(argv[1], "pub") == 0);

    hdds_logging_init(HDDS_LOG_INFO);

    printf("%s\n", "============================================================");
    printf("Transport Priority Demo\n");
    printf("QoS: TRANSPORT_PRIORITY - assign network priorities to data flows\n");
    printf("%s\n", "============================================================");

    struct HddsParticipant* participant = hdds_participant_create("TransportPriorityDemo");
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
