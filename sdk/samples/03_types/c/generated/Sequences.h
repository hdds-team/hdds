// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Sequences.idl
 * Demonstrates sequence types
 */
#ifndef HDDS_SAMPLES_SEQUENCES_H
#define HDDS_SAMPLES_SEQUENCES_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define LONG_SEQ_MAX_SIZE 1024
#define STRING_SEQ_MAX_SIZE 64
#define STRING_SEQ_MAX_STR_LEN 256
#define BOUNDED_LONG_SEQ_MAX_SIZE 10

typedef struct LongSeq {
    int32_t values[LONG_SEQ_MAX_SIZE];
    uint32_t count;
} LongSeq;

typedef struct StringSeq {
    char values[STRING_SEQ_MAX_SIZE][STRING_SEQ_MAX_STR_LEN];
    uint32_t count;
} StringSeq;

typedef struct BoundedLongSeq {
    int32_t values[BOUNDED_LONG_SEQ_MAX_SIZE];
    uint32_t count;
} BoundedLongSeq;

static inline size_t LongSeq_serialize(const LongSeq* seq, uint8_t* buf, size_t max_len) {
    size_t needed = 4 + seq->count * 4;
    if (needed > max_len) return 0;

    memcpy(buf, &seq->count, 4);
    size_t pos = 4;
    for (uint32_t i = 0; i < seq->count; ++i) {
        memcpy(&buf[pos], &seq->values[i], 4);
        pos += 4;
    }
    return pos;
}

static inline bool LongSeq_deserialize(LongSeq* seq, const uint8_t* buf, size_t len) {
    if (len < 4) return false;

    memcpy(&seq->count, buf, 4);
    if (seq->count > LONG_SEQ_MAX_SIZE) return false;

    size_t pos = 4;
    if (pos + seq->count * 4 > len) return false;

    for (uint32_t i = 0; i < seq->count; ++i) {
        memcpy(&seq->values[i], &buf[pos], 4);
        pos += 4;
    }
    return true;
}

static inline size_t StringSeq_serialize(const StringSeq* seq, uint8_t* buf, size_t max_len) {
    size_t pos = 0;

    if (pos + 4 > max_len) return 0;
    memcpy(&buf[pos], &seq->count, 4);
    pos += 4;

    for (uint32_t i = 0; i < seq->count; ++i) {
        uint32_t slen = (uint32_t)strlen(seq->values[i]);
        if (pos + 4 + slen + 1 > max_len) return 0;
        memcpy(&buf[pos], &slen, 4);
        pos += 4;
        memcpy(&buf[pos], seq->values[i], slen + 1);
        pos += slen + 1;
    }
    return pos;
}

static inline bool StringSeq_deserialize(StringSeq* seq, const uint8_t* buf, size_t len) {
    if (len < 4) return false;

    memcpy(&seq->count, buf, 4);
    if (seq->count > STRING_SEQ_MAX_SIZE) return false;

    size_t pos = 4;
    for (uint32_t i = 0; i < seq->count; ++i) {
        if (pos + 4 > len) return false;
        uint32_t slen;
        memcpy(&slen, &buf[pos], 4);
        pos += 4;
        if (slen >= STRING_SEQ_MAX_STR_LEN) return false;
        if (pos + slen + 1 > len) return false;
        memcpy(seq->values[i], &buf[pos], slen + 1);
        pos += slen + 1;
    }
    return true;
}

static inline size_t BoundedLongSeq_serialize(const BoundedLongSeq* seq, uint8_t* buf, size_t max_len) {
    if (seq->count > BOUNDED_LONG_SEQ_MAX_SIZE) return 0;
    size_t needed = 4 + seq->count * 4;
    if (needed > max_len) return 0;

    memcpy(buf, &seq->count, 4);
    size_t pos = 4;
    for (uint32_t i = 0; i < seq->count; ++i) {
        memcpy(&buf[pos], &seq->values[i], 4);
        pos += 4;
    }
    return pos;
}

static inline bool BoundedLongSeq_deserialize(BoundedLongSeq* seq, const uint8_t* buf, size_t len) {
    if (len < 4) return false;

    memcpy(&seq->count, buf, 4);
    if (seq->count > BOUNDED_LONG_SEQ_MAX_SIZE) return false;

    size_t pos = 4;
    if (pos + seq->count * 4 > len) return false;

    for (uint32_t i = 0; i < seq->count; ++i) {
        memcpy(&seq->values[i], &buf[pos], 4);
        pos += 4;
    }
    return true;
}

#endif /* HDDS_SAMPLES_SEQUENCES_H */
