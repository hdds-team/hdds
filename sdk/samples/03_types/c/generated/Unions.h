// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Unions.idl
 * Demonstrates union types
 */
#ifndef HDDS_SAMPLES_UNIONS_H
#define HDDS_SAMPLES_UNIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define DATA_VALUE_MAX_TEXT_LEN 256

typedef enum DataKind {
    DATA_KIND_INTEGER = 0,
    DATA_KIND_FLOAT = 1,
    DATA_KIND_TEXT = 2,
} DataKind;

typedef struct DataValue {
    DataKind kind;
    union {
        int32_t integer_val;
        double float_val;
        char text_val[DATA_VALUE_MAX_TEXT_LEN];
    } value;
} DataValue;

static inline void DataValue_set_integer(DataValue* dv, int32_t v) {
    dv->kind = DATA_KIND_INTEGER;
    dv->value.integer_val = v;
}

static inline void DataValue_set_float(DataValue* dv, double v) {
    dv->kind = DATA_KIND_FLOAT;
    dv->value.float_val = v;
}

static inline void DataValue_set_text(DataValue* dv, const char* v) {
    dv->kind = DATA_KIND_TEXT;
    strncpy(dv->value.text_val, v, DATA_VALUE_MAX_TEXT_LEN - 1);
    dv->value.text_val[DATA_VALUE_MAX_TEXT_LEN - 1] = '\0';
}

static inline size_t DataValue_serialize(const DataValue* dv, uint8_t* buf, size_t max_len) {
    size_t pos = 0;

    if (pos + 4 > max_len) return 0;
    uint32_t k = (uint32_t)dv->kind;
    memcpy(&buf[pos], &k, 4);
    pos += 4;

    switch (dv->kind) {
        case DATA_KIND_INTEGER:
            if (pos + 4 > max_len) return 0;
            memcpy(&buf[pos], &dv->value.integer_val, 4);
            pos += 4;
            break;

        case DATA_KIND_FLOAT:
            if (pos + 8 > max_len) return 0;
            memcpy(&buf[pos], &dv->value.float_val, 8);
            pos += 8;
            break;

        case DATA_KIND_TEXT: {
            uint32_t len = (uint32_t)strlen(dv->value.text_val);
            if (pos + 4 + len + 1 > max_len) return 0;
            memcpy(&buf[pos], &len, 4);
            pos += 4;
            memcpy(&buf[pos], dv->value.text_val, len + 1);
            pos += len + 1;
            break;
        }
    }
    return pos;
}

static inline bool DataValue_deserialize(DataValue* dv, const uint8_t* buf, size_t len) {
    size_t pos = 0;

    if (pos + 4 > len) return false;
    uint32_t k;
    memcpy(&k, &buf[pos], 4);
    pos += 4;
    dv->kind = (DataKind)k;

    switch (dv->kind) {
        case DATA_KIND_INTEGER:
            if (pos + 4 > len) return false;
            memcpy(&dv->value.integer_val, &buf[pos], 4);
            break;

        case DATA_KIND_FLOAT:
            if (pos + 8 > len) return false;
            memcpy(&dv->value.float_val, &buf[pos], 8);
            break;

        case DATA_KIND_TEXT: {
            if (pos + 4 > len) return false;
            uint32_t slen;
            memcpy(&slen, &buf[pos], 4);
            pos += 4;
            if (slen >= DATA_VALUE_MAX_TEXT_LEN) return false;
            if (pos + slen + 1 > len) return false;
            memcpy(dv->value.text_val, &buf[pos], slen + 1);
            break;
        }

        default:
            return false;
    }
    return true;
}

static inline const char* DataKind_to_string(DataKind k) {
    switch (k) {
        case DATA_KIND_INTEGER: return "Integer";
        case DATA_KIND_FLOAT: return "Float";
        case DATA_KIND_TEXT: return "Text";
        default: return "Unknown";
    }
}

#endif /* HDDS_SAMPLES_UNIONS_H */
