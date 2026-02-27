// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Enums.idl
 * Demonstrates enum types
 */
#ifndef HDDS_SAMPLES_ENUMS_H
#define HDDS_SAMPLES_ENUMS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef enum Color {
    COLOR_RED = 0,
    COLOR_GREEN = 1,
    COLOR_BLUE = 2,
} Color;

typedef enum Status {
    STATUS_UNKNOWN = 0,
    STATUS_PENDING = 10,
    STATUS_ACTIVE = 20,
    STATUS_COMPLETED = 30,
    STATUS_FAILED = 100,
} Status;

typedef struct EnumDemo {
    Color color;
    Status status;
} EnumDemo;

static inline size_t EnumDemo_serialize(const EnumDemo* e, uint8_t* buf, size_t max_len) {
    if (max_len < 8) return 0;
    uint32_t c = (uint32_t)e->color;
    uint32_t s = (uint32_t)e->status;
    memcpy(&buf[0], &c, 4);
    memcpy(&buf[4], &s, 4);
    return 8;
}

static inline bool EnumDemo_deserialize(EnumDemo* e, const uint8_t* buf, size_t len) {
    if (len < 8) return false;
    uint32_t c, s;
    memcpy(&c, &buf[0], 4);
    memcpy(&s, &buf[4], 4);
    e->color = (Color)c;
    e->status = (Status)s;
    return true;
}

static inline const char* Color_to_string(Color c) {
    switch (c) {
        case COLOR_RED: return "Red";
        case COLOR_GREEN: return "Green";
        case COLOR_BLUE: return "Blue";
        default: return "Unknown";
    }
}

static inline const char* Status_to_string(Status s) {
    switch (s) {
        case STATUS_UNKNOWN: return "Unknown";
        case STATUS_PENDING: return "Pending";
        case STATUS_ACTIVE: return "Active";
        case STATUS_COMPLETED: return "Completed";
        case STATUS_FAILED: return "Failed";
        default: return "Unknown";
    }
}

#endif /* HDDS_SAMPLES_ENUMS_H */
