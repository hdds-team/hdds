// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Bits.idl
 * Demonstrates bitmask and bitset types
 */
#ifndef HDDS_SAMPLES_BITS_H
#define HDDS_SAMPLES_BITS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Permission bitmask values */
#define PERM_NONE    0
#define PERM_READ    (1 << 0)
#define PERM_WRITE   (1 << 1)
#define PERM_EXECUTE (1 << 2)
#define PERM_DELETE  (1 << 3)

typedef uint32_t Permissions;

/* StatusFlags bitmask values */
#define STATUS_ENABLED  (1 << 0)
#define STATUS_VISIBLE  (1 << 1)
#define STATUS_SELECTED (1 << 2)
#define STATUS_FOCUSED  (1 << 3)
#define STATUS_ERROR    (1 << 4)
#define STATUS_WARNING  (1 << 5)

typedef uint8_t StatusFlags;

typedef struct BitsDemo {
    Permissions permissions;
    StatusFlags status;
} BitsDemo;

static inline bool Permissions_has(Permissions p, uint32_t flag) {
    return (p & flag) != 0;
}

static inline bool Permissions_can_read(Permissions p) { return Permissions_has(p, PERM_READ); }
static inline bool Permissions_can_write(Permissions p) { return Permissions_has(p, PERM_WRITE); }
static inline bool Permissions_can_execute(Permissions p) { return Permissions_has(p, PERM_EXECUTE); }
static inline bool Permissions_can_delete(Permissions p) { return Permissions_has(p, PERM_DELETE); }

static inline bool StatusFlags_has(StatusFlags s, uint8_t flag) {
    return (s & flag) != 0;
}

static inline bool StatusFlags_is_enabled(StatusFlags s) { return StatusFlags_has(s, STATUS_ENABLED); }
static inline bool StatusFlags_is_visible(StatusFlags s) { return StatusFlags_has(s, STATUS_VISIBLE); }
static inline bool StatusFlags_is_selected(StatusFlags s) { return StatusFlags_has(s, STATUS_SELECTED); }
static inline bool StatusFlags_is_focused(StatusFlags s) { return StatusFlags_has(s, STATUS_FOCUSED); }
static inline bool StatusFlags_has_error(StatusFlags s) { return StatusFlags_has(s, STATUS_ERROR); }
static inline bool StatusFlags_has_warning(StatusFlags s) { return StatusFlags_has(s, STATUS_WARNING); }

static inline size_t BitsDemo_serialize(const BitsDemo* b, uint8_t* buf, size_t max_len) {
    if (max_len < 5) return 0;
    memcpy(&buf[0], &b->permissions, 4);
    buf[4] = b->status;
    return 5;
}

static inline bool BitsDemo_deserialize(BitsDemo* b, const uint8_t* buf, size_t len) {
    if (len < 5) return false;
    memcpy(&b->permissions, &buf[0], 4);
    b->status = buf[4];
    return true;
}

#endif /* HDDS_SAMPLES_BITS_H */
