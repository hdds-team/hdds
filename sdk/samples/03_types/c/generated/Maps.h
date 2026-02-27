// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Maps.idl
 * Demonstrates map types
 */
#ifndef HDDS_SAMPLES_MAPS_H
#define HDDS_SAMPLES_MAPS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define STRING_LONG_MAP_MAX_ENTRIES 64
#define STRING_LONG_MAP_MAX_KEY_LEN 128
#define LONG_STRING_MAP_MAX_ENTRIES 64
#define LONG_STRING_MAP_MAX_VAL_LEN 256

typedef struct StringLongMapEntry {
    char key[STRING_LONG_MAP_MAX_KEY_LEN];
    int32_t value;
} StringLongMapEntry;

typedef struct StringLongMap {
    StringLongMapEntry entries[STRING_LONG_MAP_MAX_ENTRIES];
    uint32_t count;
} StringLongMap;

typedef struct LongStringMapEntry {
    int32_t key;
    char value[LONG_STRING_MAP_MAX_VAL_LEN];
} LongStringMapEntry;

typedef struct LongStringMap {
    LongStringMapEntry entries[LONG_STRING_MAP_MAX_ENTRIES];
    uint32_t count;
} LongStringMap;

static inline size_t StringLongMap_serialize(const StringLongMap* m, uint8_t* buf, size_t max_len) {
    size_t pos = 0;

    if (pos + 4 > max_len) return 0;
    memcpy(&buf[pos], &m->count, 4);
    pos += 4;

    for (uint32_t i = 0; i < m->count; ++i) {
        uint32_t key_len = (uint32_t)strlen(m->entries[i].key);
        if (pos + 4 + key_len + 1 + 4 > max_len) return 0;

        memcpy(&buf[pos], &key_len, 4);
        pos += 4;
        memcpy(&buf[pos], m->entries[i].key, key_len + 1);
        pos += key_len + 1;
        memcpy(&buf[pos], &m->entries[i].value, 4);
        pos += 4;
    }
    return pos;
}

static inline bool StringLongMap_deserialize(StringLongMap* m, const uint8_t* buf, size_t len) {
    size_t pos = 0;

    if (pos + 4 > len) return false;
    memcpy(&m->count, &buf[pos], 4);
    pos += 4;

    if (m->count > STRING_LONG_MAP_MAX_ENTRIES) return false;

    for (uint32_t i = 0; i < m->count; ++i) {
        if (pos + 4 > len) return false;
        uint32_t key_len;
        memcpy(&key_len, &buf[pos], 4);
        pos += 4;

        if (key_len >= STRING_LONG_MAP_MAX_KEY_LEN) return false;
        if (pos + key_len + 1 + 4 > len) return false;

        memcpy(m->entries[i].key, &buf[pos], key_len + 1);
        pos += key_len + 1;
        memcpy(&m->entries[i].value, &buf[pos], 4);
        pos += 4;
    }
    return true;
}

static inline size_t LongStringMap_serialize(const LongStringMap* m, uint8_t* buf, size_t max_len) {
    size_t pos = 0;

    if (pos + 4 > max_len) return 0;
    memcpy(&buf[pos], &m->count, 4);
    pos += 4;

    for (uint32_t i = 0; i < m->count; ++i) {
        if (pos + 4 > max_len) return 0;
        memcpy(&buf[pos], &m->entries[i].key, 4);
        pos += 4;

        uint32_t val_len = (uint32_t)strlen(m->entries[i].value);
        if (pos + 4 + val_len + 1 > max_len) return 0;

        memcpy(&buf[pos], &val_len, 4);
        pos += 4;
        memcpy(&buf[pos], m->entries[i].value, val_len + 1);
        pos += val_len + 1;
    }
    return pos;
}

static inline bool LongStringMap_deserialize(LongStringMap* m, const uint8_t* buf, size_t len) {
    size_t pos = 0;

    if (pos + 4 > len) return false;
    memcpy(&m->count, &buf[pos], 4);
    pos += 4;

    if (m->count > LONG_STRING_MAP_MAX_ENTRIES) return false;

    for (uint32_t i = 0; i < m->count; ++i) {
        if (pos + 4 > len) return false;
        memcpy(&m->entries[i].key, &buf[pos], 4);
        pos += 4;

        if (pos + 4 > len) return false;
        uint32_t val_len;
        memcpy(&val_len, &buf[pos], 4);
        pos += 4;

        if (val_len >= LONG_STRING_MAP_MAX_VAL_LEN) return false;
        if (pos + val_len + 1 > len) return false;

        memcpy(m->entries[i].value, &buf[pos], val_len + 1);
        pos += val_len + 1;
    }
    return true;
}

#endif /* HDDS_SAMPLES_MAPS_H */
