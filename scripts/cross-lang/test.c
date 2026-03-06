// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Cross-language test helper: C pub/sub.
//
// Usage:
//     ./xtest_c pub <topic> <count>
//     ./xtest_c sub <topic> <count>
//
// Build:
//     gcc -o xtest_c test.c -I../../sdk/c/include -L../../target/release -lhdds_c -lpthread -ldl -lm

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

// Forward-declare ROS2 type used in hdds.h (not needed by our code)
typedef struct rosidl_message_type_support_t rosidl_message_type_support_t;
#include <hdds.h>

#define PAYLOAD_PREFIX "XTEST-"
#define MAX_BUF 4096

static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int run_pub(const char *topic, int count) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("xtest_c_pub", HDDS_TRANSPORT_UDP_MULTICAST);
    if (!p) { fprintf(stderr, "Failed to create participant\n"); return 1; }

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, (uint32_t)(count + 5));

    struct HddsDataWriter *w = hdds_writer_create_with_type(p, topic, "RawBytes", qos);
    hdds_qos_destroy(qos);
    if (!w) { fprintf(stderr, "Failed to create writer\n"); hdds_participant_destroy(p); return 1; }

    // Let discovery happen
    msleep(300);

    for (int i = 0; i < count; i++) {
        char buf[256];
        int len = snprintf(buf, sizeof(buf), "%s%d", PAYLOAD_PREFIX, i);
        enum HddsError err = hdds_writer_write(w, (const uint8_t *)buf, (size_t)len);
        if (err != HDDS_OK) {
            fprintf(stderr, "Write failed: %d\n", err);
            hdds_writer_destroy(w);
            hdds_participant_destroy(p);
            return 1;
        }
    }

    // Keep alive for late joiners
    msleep(2000);

    hdds_writer_destroy(w);
    hdds_participant_destroy(p);
    return 0;
}

static int run_sub(const char *topic, int count) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("xtest_c_sub", HDDS_TRANSPORT_UDP_MULTICAST);
    if (!p) { fprintf(stderr, "Failed to create participant\n"); return 1; }

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, (uint32_t)(count + 5));

    struct HddsDataReader *r = hdds_reader_create_with_type(p, topic, "RawBytes", qos);
    hdds_qos_destroy(qos);
    if (!r) { fprintf(stderr, "Failed to create reader\n"); hdds_participant_destroy(p); return 1; }

    struct HddsWaitSet *ws = hdds_waitset_create();
    const struct HddsStatusCondition *cond = hdds_reader_get_status_condition(r);
    hdds_waitset_attach_status_condition(ws, cond);

    int received = 0;
    uint8_t buf[MAX_BUF];
    size_t buf_len;
    char expected[256];

    // 10 second deadline
    for (int attempt = 0; attempt < 100 && received < count; attempt++) {
        const void *triggered[4];
        size_t trig_count = 0;
        enum HddsError err = hdds_waitset_wait(ws, 100000000LL, triggered, 4, &trig_count);

        if (err == HDDS_OK && trig_count > 0) {
            while (hdds_reader_take(r, buf, sizeof(buf), &buf_len) == HDDS_OK) {
                int idx = received;
                int elen = snprintf(expected, sizeof(expected), "%s%d", PAYLOAD_PREFIX, idx);

                if ((size_t)elen != buf_len || memcmp(buf, expected, buf_len) != 0) {
                    buf[buf_len < sizeof(buf) - 1 ? buf_len : sizeof(buf) - 1] = '\0';
                    fprintf(stderr, "MISMATCH at %d: got '%s', want '%s'\n",
                            idx, (char *)buf, expected);
                    hdds_waitset_destroy(ws);
                    hdds_reader_destroy(r);
                    hdds_participant_destroy(p);
                    return 1;
                }
                received++;
            }
        }
    }

    hdds_waitset_detach_condition(ws, (const void *)cond);
    hdds_status_condition_release(cond);
    hdds_waitset_destroy(ws);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);

    if (received == count) {
        printf("OK: received %d/%d samples\n", count, count);
        return 0;
    } else {
        fprintf(stderr, "FAIL: received %d/%d samples\n", received, count);
        return 1;
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s pub|sub <topic> <count>\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *topic = argv[2];
    int count = atoi(argv[3]);

    if (strcmp(mode, "pub") == 0) return run_pub(topic, count);
    if (strcmp(mode, "sub") == 0) return run_sub(topic, count);

    fprintf(stderr, "Unknown mode: %s\n", mode);
    return 1;
}
