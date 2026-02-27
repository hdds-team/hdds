// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Primitives.idl
 * Demonstrates all DDS primitive types
 */
#ifndef HDDS_SAMPLES_PRIMITIVES_H
#define HDDS_SAMPLES_PRIMITIVES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef struct Primitives {
    bool bool_val;
    uint8_t octet_val;
    char char_val;
    int16_t short_val;
    uint16_t ushort_val;
    int32_t long_val;
    uint32_t ulong_val;
    int64_t llong_val;
    uint64_t ullong_val;
    float float_val;
    double double_val;
} Primitives;

static inline size_t Primitives_serialize(const Primitives* msg, uint8_t* buf, size_t max_len) {
    if (max_len < 43) return 0;  /* Fixed size: 1+1+1+2+2+4+4+8+8+4+8 = 43 bytes */
    size_t pos = 0;

    buf[pos++] = msg->bool_val ? 1 : 0;
    buf[pos++] = msg->octet_val;
    buf[pos++] = (uint8_t)msg->char_val;

    memcpy(&buf[pos], &msg->short_val, 2); pos += 2;
    memcpy(&buf[pos], &msg->ushort_val, 2); pos += 2;
    memcpy(&buf[pos], &msg->long_val, 4); pos += 4;
    memcpy(&buf[pos], &msg->ulong_val, 4); pos += 4;
    memcpy(&buf[pos], &msg->llong_val, 8); pos += 8;
    memcpy(&buf[pos], &msg->ullong_val, 8); pos += 8;
    memcpy(&buf[pos], &msg->float_val, 4); pos += 4;
    memcpy(&buf[pos], &msg->double_val, 8); pos += 8;

    return pos;
}

static inline bool Primitives_deserialize(Primitives* msg, const uint8_t* buf, size_t len) {
    if (len < 43) return false;
    size_t pos = 0;

    msg->bool_val = buf[pos++] != 0;
    msg->octet_val = buf[pos++];
    msg->char_val = (char)buf[pos++];

    memcpy(&msg->short_val, &buf[pos], 2); pos += 2;
    memcpy(&msg->ushort_val, &buf[pos], 2); pos += 2;
    memcpy(&msg->long_val, &buf[pos], 4); pos += 4;
    memcpy(&msg->ulong_val, &buf[pos], 4); pos += 4;
    memcpy(&msg->llong_val, &buf[pos], 8); pos += 8;
    memcpy(&msg->ullong_val, &buf[pos], 8); pos += 8;
    memcpy(&msg->float_val, &buf[pos], 4); pos += 4;
    memcpy(&msg->double_val, &buf[pos], 8); pos += 8;

    return true;
}

#endif /* HDDS_SAMPLES_PRIMITIVES_H */
