// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Typed cross-language test: C pub/sub with generated CDR2 types.
//
// Usage:
//     ./typed_test_c pub <topic> <count>
//     ./typed_test_c sub <topic> <count>
//     ./typed_test_c pub-default <topic> <count>
//     ./typed_test_c sub-default <topic> <count>
//     ./typed_test_c sub-legacy <topic> <count>
//     ./typed_test_c pub-ext <ExtFinal*|ExtAppendable*|ExtMutable*> <count>
//     ./typed_test_c sub-ext <ExtFinal*|ExtAppendable*|ExtMutable*> <count>
//
// pub/sub carry a 4-byte encapsulation header inside the payload (the
// convention of this suite's byte-vector lanes). The -default modes are the
// SDK as an application uses it: the bytes are the body, the writer labels
// them (D_CDR2_LE: the IDL types are APPENDABLE), the reader requests what
// the generated decoders read ([XCDR, XCDR2] when HDDSGEN_C_DECODES_XCDR1)
// and decodes by the identifier hdds_reader_take_ex reports. sub-legacy is a
// reader whose code decodes XCDR2 only: it requests XCDR2, receives nothing
// from a writer that offers XCDR, and reports REQUESTED_INCOMPATIBLE_QOS.
// pub-ext / sub-ext write and read FinalProbe, SensorReading (APPENDABLE)
// or MutableProbe, by topic prefix; the writer is created with the natural
// per-type helper hddsgen generates (`<name>_create_writer(participant,
// topic, qos)`), which labels every sample with the type's extensibility
// (`<name>_extensibility()`) without the caller naming it.
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

// Bump allocator for the generated _alloc decoders, which allocate every
// string and sequence they decode; reset before each sample.
static uint8_t arena_mem[1 << 16];
static size_t arena_used;
static void *arena_alloc(void *ctx, size_t size) {
    (void)ctx;
    size_t at = (arena_used + 15u) & ~(size_t)15u;
    if (at > sizeof(arena_mem) || size > sizeof(arena_mem) - at) return NULL;
    arena_used = at + size;
    return arena_mem + at;
}

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

static int run_vector(const char *topic) {
    uint8_t buf[4096];
    int len;
    if (is_keyed_topic(topic)) {
        KeyedSample msg;
        char name_buf[64];
        fill_keyed_message(&msg, name_buf);
        len = keyedsample_encode_cdr2_le(&msg, buf, sizeof(buf));
    } else {
        SensorReading msg;
        float hist[3];
        char label_buf[64];
        fill_test_message(&msg, hist, label_buf);
        len = sensorreading_encode_cdr2_le(&msg, buf, sizeof(buf));
    }
    if (len < 0) return 1;
    for (int i = 0; i < len; i++) printf("%02x", buf[i]);
    putchar('\n');
    return 0;
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
                    arena_used = 0;
                    dec = keyedsample_decode_cdr2_le_alloc(&kout, cdr2_data, cdr2_len,
                                                           arena_alloc, NULL);
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
                    arena_used = 0;
                    dec = sensorreading_decode_cdr2_le_alloc(&out, cdr2_data, cdr2_len,
                                                             arena_alloc, NULL);
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

// ---------------------------------------------------------------------------
// The SDK as an application uses it (no header inside the payload)
// ---------------------------------------------------------------------------

/// The IDL type name the Rust writer and reader of this suite announce.
#define TYPE_NAME "SensorReading"

static int run_pub_default(const char *topic, int count) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("typed_c_pub_default", HDDS_TRANSPORT_UDP_MULTICAST);
    if (!p) { fprintf(stderr, "Failed to create participant\n"); return 1; }

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, (uint32_t)(count + 5));
    // No DATA_REPRESENTATION: the writer offers XCDR2, what the generated
    // encoders write; the type is APPENDABLE, so D_CDR2_LE, which the
    // generated code says (hddsgen 2.0 and later).
    struct HddsDataWriter *w = hdds_writer_create_with_extensibility(
        p, topic, TYPE_NAME, qos, SENSORREADING_EXTENSIBILITY);
    hdds_qos_destroy(qos);
    if (!w) { fprintf(stderr, "Failed to create writer\n"); hdds_participant_destroy(p); return 1; }

    msleep(300);
    for (int i = 0; i < count; i++) {
        uint8_t body[4096];
        SensorReading msg;
        float hist[3];
        char label_buf[64];
        fill_test_message(&msg, hist, label_buf);
        int enc = sensorreading_encode_cdr2_le(&msg, body, sizeof(body));
        if (enc < 0 || hdds_writer_write(w, body, (size_t)enc) != HDDS_OK) {
            fprintf(stderr, "encode/write failed: %d\n", enc);
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

static void on_incompatible(const struct HddsIncompatibleQosStatus *status, void *user) {
    *(volatile uint32_t *)user = status->LAST_POLICY_ID;
}

static int run_sub_default(const char *topic, int count, bool legacy) {
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("typed_c_sub_default", HDDS_TRANSPORT_UDP_MULTICAST);
    if (!p) { fprintf(stderr, "Failed to create participant\n"); return 1; }

    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, (uint32_t)(count + 5));
#ifdef HDDSGEN_C_DECODES_XCDR1
    if (!legacy) {
        // The generated decoders read XCDR1 too: request it as well.
        const int16_t both[2] = {HDDS_XCDR_DATA_REPRESENTATION, HDDS_XCDR2_DATA_REPRESENTATION};
        hdds_qos_set_data_representation(qos, both, 2);
    }
#else
    (void)legacy;
#endif
    struct HddsDataReader *r = hdds_reader_create_with_type(p, topic, TYPE_NAME, qos);
    hdds_qos_destroy(qos);
    if (!r) { fprintf(stderr, "Failed to create reader\n"); hdds_participant_destroy(p); return 1; }

    volatile uint32_t incompatible_policy = 0;
    struct HddsReaderListener listener;
    memset(&listener, 0, sizeof(listener));
    listener.ON_INCOMPATIBLE_QOS = on_incompatible;
    listener.USER_DATA = (void *)&incompatible_policy;
    hdds_reader_set_listener(r, &listener);

    int received = 0;
    bool ok = true;
    uint16_t seen_id = 0;
    uint8_t buf[MAX_BUF];
    for (int attempt = 0; attempt < 100 && received < count; attempt++) {
        size_t len = 0;
        uint16_t id = 0;
        if (hdds_reader_take_ex(r, buf, sizeof(buf), &len, &id) != HDDS_OK) {
            msleep(100);
            continue;
        }
        SensorReading out;
        memset(&out, 0, sizeof(out));
        arena_used = 0;
#ifdef HDDSGEN_C_DECODES_XCDR1
        int dec = sensorreading_decode_by_encapsulation_alloc(&out, id, buf, len, arena_alloc, NULL);
#else
        int dec = id == 0x0007 ? sensorreading_decode_cdr2_le_alloc(&out, buf, len, arena_alloc, NULL) : -1;
#endif
        if (dec < 0 || validate_message(&out) != 0) {
            fprintf(stderr, "FAIL: sample %d (encapsulation 0x%04x) decode %d\n", received, id, dec);
            ok = false;
        }
        seen_id = id;
        received++;
    }
    hdds_reader_clear_listener(r);
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);

    if (legacy) {
        // A reader whose code reads XCDR2 only, facing a writer that offers
        // XCDR: refused at matching (policy 23, DATA_REPRESENTATION), never
        // handed bytes it would misread.
        if (received == 0 && incompatible_policy == 23) {
            printf("OK: legacy reader received nothing, REQUESTED_INCOMPATIBLE_QOS policy 23\n");
            return 0;
        }
        fprintf(stderr, "FAIL: legacy reader received %d, incompatible policy %u\n",
                received, (unsigned)incompatible_policy);
        return 1;
    }
    if (ok && received == count) {
        printf("OK: received %d/%d samples encap=0x%04x\n", count, count, seen_id);
        return 0;
    }
    fprintf(stderr, "FAIL: received %d/%d samples\n", received, count);
    return 1;
}

// ---------------------------------------------------------------------------
// Extensibility lanes: FinalProbe, SensorReading (APPENDABLE), MutableProbe
// ---------------------------------------------------------------------------

enum ext_lane { EXT_NONE, EXT_FINAL, EXT_APPENDABLE, EXT_MUTABLE };

static enum ext_lane ext_lane_of(const char *topic) {
    if (strncmp(topic, "ExtFinal", 8) == 0) return EXT_FINAL;
    if (strncmp(topic, "ExtAppendable", 13) == 0) return EXT_APPENDABLE;
    if (strncmp(topic, "ExtMutable", 10) == 0) return EXT_MUTABLE;
    return EXT_NONE;
}

#define PROBE_ID 7u
#define PROBE_LABEL "ext-probe"

static int run_pub_ext(const char *topic, int count) {
    enum ext_lane lane = ext_lane_of(topic);
    if (lane == EXT_NONE) { fprintf(stderr, "pub-ext: not an Ext* topic\n"); return 1; }
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("typed_c_pub_ext", HDDS_TRANSPORT_UDP_MULTICAST);
    if (!p) { fprintf(stderr, "Failed to create participant\n"); return 1; }
    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, (uint32_t)(count + 5));
    // The natural way: the per-type helper hddsgen generates
    // (<name>_create_writer), not the caller computing <name>_extensibility()
    // and calling hdds_writer_create_with_extensibility() itself.
    struct HddsDataWriter *w = lane == EXT_FINAL ? finalprobe_create_writer(p, topic, qos)
                              : lane == EXT_MUTABLE ? mutableprobe_create_writer(p, topic, qos)
                              : sensorreading_create_writer(p, topic, qos);
    hdds_qos_destroy(qos);
    if (!w) { fprintf(stderr, "Failed to create writer\n"); hdds_participant_destroy(p); return 1; }
    msleep(300);
    for (int i = 0; i < count; i++) {
        uint8_t body[4096];
        int enc;
        if (lane == EXT_APPENDABLE) {
            SensorReading msg;
            float hist[3];
            char label_buf[64];
            fill_test_message(&msg, hist, label_buf);
            enc = sensorreading_encode_cdr2_le(&msg, body, sizeof(body));
        } else if (lane == EXT_FINAL) {
            FinalProbe msg;
            memset(&msg, 0, sizeof(msg));
            msg.id = PROBE_ID;
            msg.label = (char *)PROBE_LABEL;
            enc = finalprobe_encode_cdr2_le(&msg, body, sizeof(body));
        } else {
            MutableProbe msg;
            memset(&msg, 0, sizeof(msg));
            msg.id = PROBE_ID;
            msg.label = (char *)PROBE_LABEL;
            enc = mutableprobe_encode_cdr2_le(&msg, body, sizeof(body));
        }
        if (enc < 0 || hdds_writer_write(w, body, (size_t)enc) != HDDS_OK) {
            fprintf(stderr, "encode/write failed: %d\n", enc);
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

static int run_sub_ext(const char *topic, int count) {
    enum ext_lane lane = ext_lane_of(topic);
    if (lane == EXT_NONE) { fprintf(stderr, "sub-ext: not an Ext* topic\n"); return 1; }
    struct HddsParticipant *p =
        hdds_participant_create_with_transport("typed_c_sub_ext", HDDS_TRANSPORT_UDP_MULTICAST);
    if (!p) { fprintf(stderr, "Failed to create participant\n"); return 1; }
    struct HddsQoS *qos = hdds_qos_reliable();
    hdds_qos_set_transient_local(qos);
    hdds_qos_set_history_depth(qos, (uint32_t)(count + 5));
    struct HddsDataReader *r = hdds_reader_create_with_type(p, topic, NULL, qos);
    hdds_qos_destroy(qos);
    if (!r) { fprintf(stderr, "Failed to create reader\n"); hdds_participant_destroy(p); return 1; }
    int received = 0;
    bool ok = true;
    uint8_t buf[MAX_BUF];
    for (int attempt = 0; attempt < 100 && received < count; attempt++) {
        size_t len = 0;
        uint16_t id = 0;
        if (hdds_reader_take_ex(r, buf, sizeof(buf), &len, &id) != HDDS_OK) {
            msleep(100);
            continue;
        }
        arena_used = 0;
        int dec;
        bool good;
        if (lane == EXT_APPENDABLE) {
            SensorReading out;
            memset(&out, 0, sizeof(out));
            dec = sensorreading_decode_by_encapsulation_alloc(&out, id, buf, len, arena_alloc, NULL);
            good = dec >= 0 && validate_message(&out) == 0;
        } else if (lane == EXT_FINAL) {
            FinalProbe out;
            memset(&out, 0, sizeof(out));
            dec = finalprobe_decode_by_encapsulation_alloc(&out, id, buf, len, arena_alloc, NULL);
            good = dec >= 0 && out.id == PROBE_ID && out.label && strcmp(out.label, PROBE_LABEL) == 0;
        } else {
            MutableProbe out;
            memset(&out, 0, sizeof(out));
            dec = mutableprobe_decode_by_encapsulation_alloc(&out, id, buf, len, arena_alloc, NULL);
            good = dec >= 0 && out.id == PROBE_ID && out.label && strcmp(out.label, PROBE_LABEL) == 0;
        }
        if (!good) {
            fprintf(stderr, "FAIL: sample %d (encapsulation 0x%04x) decode %d\n", received, id, dec);
            ok = false;
        }
        received++;
    }
    hdds_reader_destroy(r);
    hdds_participant_destroy(p);
    if (ok && received == count) {
        printf("OK: received %d/%d samples\n", count, count);
        return 0;
    }
    fprintf(stderr, "FAIL: received %d/%d samples\n", received, count);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s pub|sub|vector <topic> <count>\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *topic = argv[2];
    int count = atoi(argv[3]);

    if (strcmp(mode, "pub") == 0) return run_pub(topic, count);
    if (strcmp(mode, "sub") == 0) return run_sub(topic, count);
    if (strcmp(mode, "vector") == 0) return run_vector(topic);
    if (strcmp(mode, "pub-default") == 0) return run_pub_default(topic, count);
    if (strcmp(mode, "sub-default") == 0) return run_sub_default(topic, count, false);
    if (strcmp(mode, "sub-legacy") == 0) return run_sub_default(topic, count, true);
    if (strcmp(mode, "pub-ext") == 0) return run_pub_ext(topic, count);
    if (strcmp(mode, "sub-ext") == 0) return run_sub_ext(topic, count);

    fprintf(stderr, "Unknown mode: %s\n", mode);
    return 1;
}
