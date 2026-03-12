// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Typed cross-language test: C pub/sub with generated CDR2 types.
//
// Usage:
//     ./typed_test_c pub <topic> <count>
//     ./typed_test_c sub <topic> <count>
//
// Build:
//     gcc -std=c11 -O2 -o typed_test_c typed_test.c \
//         -I../../sdk/c/include -I$WORK \
//         -L../../target/release -lhdds_c -lpthread -ldl -lm

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <math.h>
#include <time.h>

#include <hdds.h>
#include "interop_types.h"

#define MAX_BUF 8192

// CDR2 LE encapsulation header
static const uint8_t ENCAP_CDR2_LE[4] = {0x00, 0x01, 0x00, 0x00};

static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void fill_test_message(SensorReading* msg, float* hist,
                              char* label_buf) {
    memset(msg, 0, sizeof(*msg));
    msg->sensor_id = 42;
    msg->kind = SENSORKIND_PRESSURE;
    msg->value = 3.15f;
    strcpy(label_buf, "test-sensor");
    msg->label = label_buf;
    msg->timestamp_ns = 1700000000000000000LL;
    hist[0] = 1.0f; hist[1] = 2.0f; hist[2] = 3.0f;
    msg->history.data = hist;
    msg->history.len = 3;
    msg->has_error_code = 1;
    msg->error_code = 7;
    msg->location.latitude = 48.8566;
    msg->location.longitude = 2.3522;
}

static int validate_message(const SensorReading* msg) {
    int errs = 0;
    if (msg->sensor_id != 42) {
        fprintf(stderr, "FAIL: sensor_id = %u, want 42\n", msg->sensor_id);
        errs++;
    }
    if (msg->kind != SENSORKIND_PRESSURE) {
        fprintf(stderr, "FAIL: kind = %d, want PRESSURE(1)\n", msg->kind);
        errs++;
    }
    if (msg->value != 3.15f) {
        fprintf(stderr, "FAIL: value = %f, want 3.15\n", (double)msg->value);
        errs++;
    }
    if (strcmp(msg->label, "test-sensor") != 0) {
        fprintf(stderr, "FAIL: label = '%s', want 'test-sensor'\n", msg->label);
        errs++;
    }
    if (msg->timestamp_ns != 1700000000000000000LL) {
        fprintf(stderr, "FAIL: timestamp_ns mismatch\n");
        errs++;
    }
    if (msg->history.len != 3) {
        fprintf(stderr, "FAIL: history.len = %u, want 3\n", msg->history.len);
        errs++;
    } else {
        if (msg->history.data[0] != 1.0f) { fprintf(stderr, "FAIL: history[0]\n"); errs++; }
        if (msg->history.data[1] != 2.0f) { fprintf(stderr, "FAIL: history[1]\n"); errs++; }
        if (msg->history.data[2] != 3.0f) { fprintf(stderr, "FAIL: history[2]\n"); errs++; }
    }
    if (!msg->has_error_code) {
        fprintf(stderr, "FAIL: has_error_code = 0, want 1\n");
        errs++;
    }
    if (msg->error_code != 7) {
        fprintf(stderr, "FAIL: error_code = %d, want 7\n", msg->error_code);
        errs++;
    }
    if (fabs(msg->location.latitude - 48.8566) > 1e-10) {
        fprintf(stderr, "FAIL: latitude = %f\n", msg->location.latitude);
        errs++;
    }
    if (fabs(msg->location.longitude - 2.3522) > 1e-10) {
        fprintf(stderr, "FAIL: longitude = %f\n", msg->location.longitude);
        errs++;
    }
    return errs;
}

static int is_keyed_topic(const char *topic) {
    return strncmp(topic, "Keyed", 5) == 0;
}

static void fill_keyed_message(KeyedSample* msg, char* name_buf) {
    memset(msg, 0, sizeof(*msg));
    msg->id = 99;
    msg->active = 1;
    msg->kind = SENSORKIND_HUMIDITY;
    strcpy(name_buf, "device-alpha");
    msg->name = name_buf;
    msg->origin.latitude = 37.7749;
    msg->origin.longitude = -122.4194;
    msg->reading = 1.618f;
}

static int validate_keyed_message(const KeyedSample* msg) {
    int errs = 0;
    if (msg->id != 99) {
        fprintf(stderr, "FAIL: id = %u, want 99\n", msg->id);
        errs++;
    }
    if (!msg->active) {
        fprintf(stderr, "FAIL: active = 0, want 1\n");
        errs++;
    }
    if (msg->kind != SENSORKIND_HUMIDITY) {
        fprintf(stderr, "FAIL: kind = %d, want HUMIDITY(2)\n", msg->kind);
        errs++;
    }
    if (strcmp(msg->name, "device-alpha") != 0) {
        fprintf(stderr, "FAIL: name = '%s', want 'device-alpha'\n", msg->name);
        errs++;
    }
    if (fabs(msg->origin.latitude - 37.7749) > 1e-10) {
        fprintf(stderr, "FAIL: origin.latitude = %f\n", msg->origin.latitude);
        errs++;
    }
    if (fabs(msg->origin.longitude - (-122.4194)) > 1e-10) {
        fprintf(stderr, "FAIL: origin.longitude = %f\n", msg->origin.longitude);
        errs++;
    }
    if (msg->reading != 1.618f) {
        fprintf(stderr, "FAIL: reading = %f, want 1.618\n", (double)msg->reading);
        errs++;
    }
    return errs;
}

static int run_pub(const char *topic, int count) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("typed_c_pub", HDDS_TRANSPORT_UDP_MULTICAST);
    if (!p) { fprintf(stderr, "Failed to create participant\n"); return 1; }

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, (uint32_t)(count + 5));

    struct HddsDataWriter *w = hdds_writer_create_with_type(p, topic, "RawBytes", qos);
    hdds_qos_destroy(qos);
    if (!w) { fprintf(stderr, "Failed to create writer\n"); hdds_participant_destroy(p); return 1; }

    msleep(300);

    int keyed = is_keyed_topic(topic);
    for (int i = 0; i < count; i++) {
        uint8_t cdr2_buf[4096];
        int enc;

        if (keyed) {
            KeyedSample kmsg;
            char name_buf[64];
            fill_keyed_message(&kmsg, name_buf);
            enc = keyedsample_encode_cdr2_le(&kmsg, cdr2_buf, sizeof(cdr2_buf));
        } else {
            SensorReading msg;
            float hist[3];
            char label_buf[64];
            fill_test_message(&msg, hist, label_buf);
            enc = sensorreading_encode_cdr2_le(&msg, cdr2_buf, sizeof(cdr2_buf));
        }
        if (enc < 0) {
            fprintf(stderr, "encode failed: %d\n", enc);
            hdds_writer_destroy(w);
            hdds_participant_destroy(p);
            return 1;
        }

        // Build payload: encap header + CDR2 bytes
        uint8_t payload[4096 + 4];
        memcpy(payload, ENCAP_CDR2_LE, 4);
        memcpy(payload + 4, cdr2_buf, (size_t)enc);

        enum HddsError err = hdds_writer_write(w, payload, (size_t)(4 + enc));
        if (err != HDDS_OK) {
            fprintf(stderr, "write failed: %d\n", err);
            hdds_writer_destroy(w);
            hdds_participant_destroy(p);
            return 1;
        }
    }

    msleep(2000);
    hdds_writer_destroy(w);
    hdds_participant_destroy(p);
    return 0;
}

static int run_sub(const char *topic, int count) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("typed_c_sub", HDDS_TRANSPORT_UDP_MULTICAST);
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
    bool ok = true;

    for (int attempt = 0; attempt < 100 && received < count; attempt++) {
        const void *triggered[4];
        size_t trig_count = 0;
        enum HddsError err = hdds_waitset_wait(ws, 100000000LL, triggered, 4, &trig_count);

        if (err == HDDS_OK && trig_count > 0) {
            while (hdds_reader_take(r, buf, sizeof(buf), &buf_len) == HDDS_OK) {
                if (buf_len < 4) {
                    fprintf(stderr, "FAIL: sample %d too short (%zu bytes)\n", received, buf_len);
                    ok = false;
                    received++;
                    continue;
                }

                // Strip 4-byte encap header, decode CDR2
                const uint8_t *cdr2_data = buf + 4;
                size_t cdr2_len = buf_len - 4;

                int dec;
                int verr;
                if (is_keyed_topic(topic)) {
                    KeyedSample kout;
                    memset(&kout, 0, sizeof(kout));
                    char name_out[256];
                    kout.name = name_out;
                    dec = keyedsample_decode_cdr2_le(&kout, cdr2_data, cdr2_len);
                    if (dec < 0) {
                        fprintf(stderr, "FAIL: decode error at sample %d: %d\n", received, dec);
                        ok = false;
                        received++;
                        continue;
                    }
                    verr = validate_keyed_message(&kout);
                } else {
                    SensorReading out;
                    memset(&out, 0, sizeof(out));
                    char label_out[256];
                    out.label = label_out;
                    float hist_out[64];
                    out.history.data = hist_out;
                    dec = sensorreading_decode_cdr2_le(&out, cdr2_data, cdr2_len);
                    if (dec < 0) {
                        fprintf(stderr, "FAIL: decode error at sample %d: %d\n", received, dec);
                        ok = false;
                        received++;
                        continue;
                    }
                    verr = validate_message(&out);
                }

                if (verr != 0) {
                    ok = false;
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

    if (ok && received == count) {
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
