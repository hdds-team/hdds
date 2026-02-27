// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * KeyedData.h - Generated from KeyedData.idl
 *
 * Keyed data type for instance management samples.
 */

#ifndef HDDS_SAMPLES_KEYEDDATA_H
#define HDDS_SAMPLES_KEYEDDATA_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * KeyedData - Data with instance key
 * @key id - Instance identifier
 */
typedef struct KeyedData {
    int32_t id;           // @key
    char data[256];
    uint32_t sequence_num;
} KeyedData;

static inline void KeyedData_init(KeyedData* msg) {
    msg->id = 0;
    memset(msg->data, 0, sizeof(msg->data));
    msg->sequence_num = 0;
}

static inline size_t KeyedData_serialize(const KeyedData* msg, uint8_t* buffer, size_t capacity) {
    if (capacity < 268) return 0;
    size_t offset = 0;

    // Write key (id)
    memcpy(buffer + offset, &msg->id, 4);
    offset += 4;

    // Write string length + data
    size_t str_len = strlen(msg->data) + 1;
    memcpy(buffer + offset, &str_len, 4);
    offset += 4;
    memcpy(buffer + offset, msg->data, str_len);
    offset += str_len;

    // Align to 4 bytes
    while (offset % 4 != 0) buffer[offset++] = 0;

    // Write sequence_num
    memcpy(buffer + offset, &msg->sequence_num, 4);
    offset += 4;

    return offset;
}

static inline size_t KeyedData_deserialize(KeyedData* msg, const uint8_t* buffer, size_t len) {
    if (len < 12) return 0;
    size_t offset = 0;

    // Read key (id)
    memcpy(&msg->id, buffer + offset, 4);
    offset += 4;

    // Read string
    uint32_t str_len;
    memcpy(&str_len, buffer + offset, 4);
    offset += 4;
    if (str_len > 256 || offset + str_len > len) return 0;
    memcpy(msg->data, buffer + offset, str_len);
    offset += str_len;

    // Align
    while (offset % 4 != 0) offset++;

    // Read sequence_num
    if (offset + 4 > len) return 0;
    memcpy(&msg->sequence_num, buffer + offset, 4);
    offset += 4;

    return offset;
}

#ifdef __cplusplus
}
#endif

#endif /* HDDS_SAMPLES_KEYEDDATA_H */
