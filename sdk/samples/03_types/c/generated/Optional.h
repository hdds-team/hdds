// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Optional.idl
 * Demonstrates optional field types
 */
#ifndef HDDS_SAMPLES_OPTIONAL_H
#define HDDS_SAMPLES_OPTIONAL_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define OPTIONAL_FIELDS_MAX_NAME_LEN 256

/* Presence flag bits */
#define OPT_HAS_NAME  (1 << 0)
#define OPT_HAS_VALUE (1 << 1)
#define OPT_HAS_COUNT (1 << 2)

typedef struct OptionalFields {
    uint32_t required_id;
    uint8_t presence_flags;
    char optional_name[OPTIONAL_FIELDS_MAX_NAME_LEN];
    double optional_value;
    int32_t optional_count;
} OptionalFields;

static inline void OptionalFields_init(OptionalFields* of, uint32_t required_id) {
    memset(of, 0, sizeof(OptionalFields));
    of->required_id = required_id;
}

static inline void OptionalFields_set_name(OptionalFields* of, const char* name) {
    of->presence_flags |= OPT_HAS_NAME;
    strncpy(of->optional_name, name, OPTIONAL_FIELDS_MAX_NAME_LEN - 1);
    of->optional_name[OPTIONAL_FIELDS_MAX_NAME_LEN - 1] = '\0';
}

static inline void OptionalFields_set_value(OptionalFields* of, double value) {
    of->presence_flags |= OPT_HAS_VALUE;
    of->optional_value = value;
}

static inline void OptionalFields_set_count(OptionalFields* of, int32_t count) {
    of->presence_flags |= OPT_HAS_COUNT;
    of->optional_count = count;
}

static inline bool OptionalFields_has_name(const OptionalFields* of) {
    return (of->presence_flags & OPT_HAS_NAME) != 0;
}

static inline bool OptionalFields_has_value(const OptionalFields* of) {
    return (of->presence_flags & OPT_HAS_VALUE) != 0;
}

static inline bool OptionalFields_has_count(const OptionalFields* of) {
    return (of->presence_flags & OPT_HAS_COUNT) != 0;
}

static inline size_t OptionalFields_serialize(const OptionalFields* of, uint8_t* buf, size_t max_len) {
    size_t pos = 0;

    /* Required ID */
    if (pos + 4 > max_len) return 0;
    memcpy(&buf[pos], &of->required_id, 4);
    pos += 4;

    /* Presence flags */
    if (pos + 1 > max_len) return 0;
    buf[pos++] = of->presence_flags;

    /* Optional name */
    if (OptionalFields_has_name(of)) {
        uint32_t name_len = (uint32_t)strlen(of->optional_name);
        if (pos + 4 + name_len + 1 > max_len) return 0;
        memcpy(&buf[pos], &name_len, 4);
        pos += 4;
        memcpy(&buf[pos], of->optional_name, name_len + 1);
        pos += name_len + 1;
    }

    /* Optional value */
    if (OptionalFields_has_value(of)) {
        if (pos + 8 > max_len) return 0;
        memcpy(&buf[pos], &of->optional_value, 8);
        pos += 8;
    }

    /* Optional count */
    if (OptionalFields_has_count(of)) {
        if (pos + 4 > max_len) return 0;
        memcpy(&buf[pos], &of->optional_count, 4);
        pos += 4;
    }

    return pos;
}

static inline bool OptionalFields_deserialize(OptionalFields* of, const uint8_t* buf, size_t len) {
    size_t pos = 0;
    memset(of, 0, sizeof(OptionalFields));

    /* Required ID */
    if (pos + 4 > len) return false;
    memcpy(&of->required_id, &buf[pos], 4);
    pos += 4;

    /* Presence flags */
    if (pos >= len) return false;
    of->presence_flags = buf[pos++];

    /* Optional name */
    if (OptionalFields_has_name(of)) {
        if (pos + 4 > len) return false;
        uint32_t name_len;
        memcpy(&name_len, &buf[pos], 4);
        pos += 4;
        if (name_len >= OPTIONAL_FIELDS_MAX_NAME_LEN) return false;
        if (pos + name_len + 1 > len) return false;
        memcpy(of->optional_name, &buf[pos], name_len + 1);
        pos += name_len + 1;
    }

    /* Optional value */
    if (OptionalFields_has_value(of)) {
        if (pos + 8 > len) return false;
        memcpy(&of->optional_value, &buf[pos], 8);
        pos += 8;
    }

    /* Optional count */
    if (OptionalFields_has_count(of)) {
        if (pos + 4 > len) return false;
        memcpy(&of->optional_count, &buf[pos], 4);
        pos += 4;
    }

    return true;
}

#endif /* HDDS_SAMPLES_OPTIONAL_H */
