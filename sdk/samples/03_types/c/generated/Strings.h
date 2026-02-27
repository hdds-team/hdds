// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Strings.idl
 * Demonstrates string types
 */
#ifndef HDDS_SAMPLES_STRINGS_H
#define HDDS_SAMPLES_STRINGS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define STRINGS_MAX_UNBOUNDED 1024
#define STRINGS_MAX_BOUNDED 256
#define STRINGS_MAX_WIDE 512

typedef struct Strings {
    char unbounded_str[STRINGS_MAX_UNBOUNDED];
    char bounded_str[STRINGS_MAX_BOUNDED];
    char wide_str[STRINGS_MAX_WIDE];  /* wstring stored as UTF-8 */
} Strings;

static inline size_t Strings_serialize(const Strings* msg, uint8_t* buf, size_t max_len) {
    size_t pos = 0;

    /* Unbounded string: 4-byte length + data */
    uint32_t len1 = (uint32_t)strlen(msg->unbounded_str);
    if (pos + 4 + len1 + 1 > max_len) return 0;
    memcpy(&buf[pos], &len1, 4); pos += 4;
    memcpy(&buf[pos], msg->unbounded_str, len1 + 1); pos += len1 + 1;

    /* Bounded string */
    uint32_t len2 = (uint32_t)strlen(msg->bounded_str);
    if (pos + 4 + len2 + 1 > max_len) return 0;
    memcpy(&buf[pos], &len2, 4); pos += 4;
    memcpy(&buf[pos], msg->bounded_str, len2 + 1); pos += len2 + 1;

    /* Wide string (stored as UTF-8) */
    uint32_t len3 = (uint32_t)strlen(msg->wide_str);
    if (pos + 4 + len3 + 1 > max_len) return 0;
    memcpy(&buf[pos], &len3, 4); pos += 4;
    memcpy(&buf[pos], msg->wide_str, len3 + 1); pos += len3 + 1;

    return pos;
}

static inline bool Strings_deserialize(Strings* msg, const uint8_t* buf, size_t len) {
    size_t pos = 0;

    if (pos + 4 > len) return false;
    uint32_t len1;
    memcpy(&len1, &buf[pos], 4); pos += 4;
    if (pos + len1 + 1 > len || len1 >= STRINGS_MAX_UNBOUNDED) return false;
    memcpy(msg->unbounded_str, &buf[pos], len1 + 1); pos += len1 + 1;

    if (pos + 4 > len) return false;
    uint32_t len2;
    memcpy(&len2, &buf[pos], 4); pos += 4;
    if (pos + len2 + 1 > len || len2 >= STRINGS_MAX_BOUNDED) return false;
    memcpy(msg->bounded_str, &buf[pos], len2 + 1); pos += len2 + 1;

    if (pos + 4 > len) return false;
    uint32_t len3;
    memcpy(&len3, &buf[pos], 4); pos += 4;
    if (pos + len3 + 1 > len || len3 >= STRINGS_MAX_WIDE) return false;
    memcpy(msg->wide_str, &buf[pos], len3 + 1); pos += len3 + 1;

    return true;
}

#endif /* HDDS_SAMPLES_STRINGS_H */
