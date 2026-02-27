// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HelloWorld.h - Generated from HelloWorld.idl
 *
 * Simple message type for pub/sub samples.
 */

#ifndef HDDS_SAMPLES_HELLOWORLD_H
#define HDDS_SAMPLES_HELLOWORLD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HelloWorld message structure
 */
typedef struct HelloWorld {
    int32_t id;
    char message[256];
} HelloWorld;

/**
 * Initialize a HelloWorld message with default values
 */
static inline void HelloWorld_init(HelloWorld* msg) {
    msg->id = 0;
    memset(msg->message, 0, sizeof(msg->message));
}

/**
 * Serialize HelloWorld to CDR buffer
 * Returns number of bytes written, or 0 on error
 */
static inline size_t HelloWorld_serialize(const HelloWorld* msg, uint8_t* buffer, size_t capacity) {
    if (capacity < 264) return 0;  // 4 (id) + 4 (strlen) + 256 (string) minimum

    size_t offset = 0;

    // Write id
    memcpy(buffer + offset, &msg->id, 4);
    offset += 4;

    // Write string length (including null terminator)
    uint32_t str_len = (uint32_t)strlen(msg->message) + 1;
    memcpy(buffer + offset, &str_len, 4);
    offset += 4;

    // Write string data
    memcpy(buffer + offset, msg->message, str_len);
    offset += str_len;

    // Align to 4 bytes
    while (offset % 4 != 0) {
        buffer[offset++] = 0;
    }

    return offset;
}

/**
 * Deserialize HelloWorld from CDR buffer
 * Returns true on success, false on error
 */
static inline bool HelloWorld_deserialize(HelloWorld* msg, const uint8_t* buffer, size_t len) {
    if (len < 12) return false;  // 4 (id) + 4 (strlen) + at least 4 bytes

    size_t offset = 0;

    // Read id
    memcpy(&msg->id, buffer + offset, 4);
    offset += 4;

    // Read string length
    uint32_t str_len;
    memcpy(&str_len, buffer + offset, 4);
    offset += 4;

    if (str_len > 256 || offset + str_len > len) return false;

    // Read string data
    memcpy(msg->message, buffer + offset, str_len);
    offset += str_len;

    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* HDDS_SAMPLES_HELLOWORLD_H */
