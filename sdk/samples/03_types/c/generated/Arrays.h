// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Arrays.idl
 * Demonstrates array types
 */
#ifndef HDDS_SAMPLES_ARRAYS_H
#define HDDS_SAMPLES_ARRAYS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define LONG_ARRAY_SIZE 10
#define STRING_ARRAY_SIZE 5
#define STRING_ARRAY_MAX_STR_LEN 256
#define MATRIX_ROWS 3
#define MATRIX_COLS 3

typedef struct LongArray {
    int32_t values[LONG_ARRAY_SIZE];
} LongArray;

typedef struct StringArray {
    char values[STRING_ARRAY_SIZE][STRING_ARRAY_MAX_STR_LEN];
} StringArray;

typedef struct Matrix {
    double values[MATRIX_ROWS][MATRIX_COLS];
} Matrix;

static inline size_t LongArray_serialize(const LongArray* arr, uint8_t* buf, size_t max_len) {
    if (max_len < LONG_ARRAY_SIZE * 4) return 0;
    memcpy(buf, arr->values, LONG_ARRAY_SIZE * 4);
    return LONG_ARRAY_SIZE * 4;
}

static inline bool LongArray_deserialize(LongArray* arr, const uint8_t* buf, size_t len) {
    if (len < LONG_ARRAY_SIZE * 4) return false;
    memcpy(arr->values, buf, LONG_ARRAY_SIZE * 4);
    return true;
}

static inline size_t StringArray_serialize(const StringArray* arr, uint8_t* buf, size_t max_len) {
    size_t pos = 0;
    for (int i = 0; i < STRING_ARRAY_SIZE; ++i) {
        uint32_t slen = (uint32_t)strlen(arr->values[i]);
        if (pos + 4 + slen + 1 > max_len) return 0;
        memcpy(&buf[pos], &slen, 4);
        pos += 4;
        memcpy(&buf[pos], arr->values[i], slen + 1);
        pos += slen + 1;
    }
    return pos;
}

static inline bool StringArray_deserialize(StringArray* arr, const uint8_t* buf, size_t len) {
    size_t pos = 0;
    for (int i = 0; i < STRING_ARRAY_SIZE; ++i) {
        if (pos + 4 > len) return false;
        uint32_t slen;
        memcpy(&slen, &buf[pos], 4);
        pos += 4;
        if (slen >= STRING_ARRAY_MAX_STR_LEN) return false;
        if (pos + slen + 1 > len) return false;
        memcpy(arr->values[i], &buf[pos], slen + 1);
        pos += slen + 1;
    }
    return true;
}

static inline size_t Matrix_serialize(const Matrix* m, uint8_t* buf, size_t max_len) {
    size_t size = MATRIX_ROWS * MATRIX_COLS * sizeof(double);
    if (max_len < size) return 0;
    memcpy(buf, m->values, size);
    return size;
}

static inline bool Matrix_deserialize(Matrix* m, const uint8_t* buf, size_t len) {
    size_t size = MATRIX_ROWS * MATRIX_COLS * sizeof(double);
    if (len < size) return false;
    memcpy(m->values, buf, size);
    return true;
}

static inline void Matrix_identity(Matrix* m) {
    memset(m->values, 0, sizeof(m->values));
    m->values[0][0] = 1.0;
    m->values[1][1] = 1.0;
    m->values[2][2] = 1.0;
}

#endif /* HDDS_SAMPLES_ARRAYS_H */
