// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Nested.idl
 * Demonstrates nested struct types
 */
#ifndef HDDS_SAMPLES_NESTED_H
#define HDDS_SAMPLES_NESTED_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define ROBOT_MAX_NAME_LEN 128
#define ROBOT_MAX_WAYPOINTS 64

typedef struct Point {
    double x;
    double y;
} Point;

typedef struct Pose {
    Point position;
    double orientation;  /* radians */
} Pose;

typedef struct Robot {
    uint32_t id;
    char name[ROBOT_MAX_NAME_LEN];
    Pose pose;
    Point waypoints[ROBOT_MAX_WAYPOINTS];
    uint32_t waypoint_count;
} Robot;

static inline size_t Point_serialize(const Point* p, uint8_t* buf, size_t max_len) {
    if (max_len < 16) return 0;
    memcpy(&buf[0], &p->x, 8);
    memcpy(&buf[8], &p->y, 8);
    return 16;
}

static inline bool Point_deserialize(Point* p, const uint8_t* buf, size_t len) {
    if (len < 16) return false;
    memcpy(&p->x, &buf[0], 8);
    memcpy(&p->y, &buf[8], 8);
    return true;
}

static inline size_t Pose_serialize(const Pose* p, uint8_t* buf, size_t max_len) {
    if (max_len < 24) return 0;
    Point_serialize(&p->position, buf, 16);
    memcpy(&buf[16], &p->orientation, 8);
    return 24;
}

static inline bool Pose_deserialize(Pose* p, const uint8_t* buf, size_t len) {
    if (len < 24) return false;
    Point_deserialize(&p->position, buf, 16);
    memcpy(&p->orientation, &buf[16], 8);
    return true;
}

static inline size_t Robot_serialize(const Robot* r, uint8_t* buf, size_t max_len) {
    size_t pos = 0;

    /* ID */
    if (pos + 4 > max_len) return 0;
    memcpy(&buf[pos], &r->id, 4);
    pos += 4;

    /* Name */
    uint32_t name_len = (uint32_t)strlen(r->name);
    if (pos + 4 + name_len + 1 > max_len) return 0;
    memcpy(&buf[pos], &name_len, 4);
    pos += 4;
    memcpy(&buf[pos], r->name, name_len + 1);
    pos += name_len + 1;

    /* Pose */
    if (pos + 24 > max_len) return 0;
    Pose_serialize(&r->pose, &buf[pos], 24);
    pos += 24;

    /* Waypoints */
    if (pos + 4 > max_len) return 0;
    memcpy(&buf[pos], &r->waypoint_count, 4);
    pos += 4;

    for (uint32_t i = 0; i < r->waypoint_count; ++i) {
        if (pos + 16 > max_len) return 0;
        Point_serialize(&r->waypoints[i], &buf[pos], 16);
        pos += 16;
    }

    return pos;
}

static inline bool Robot_deserialize(Robot* r, const uint8_t* buf, size_t len) {
    size_t pos = 0;

    /* ID */
    if (pos + 4 > len) return false;
    memcpy(&r->id, &buf[pos], 4);
    pos += 4;

    /* Name */
    if (pos + 4 > len) return false;
    uint32_t name_len;
    memcpy(&name_len, &buf[pos], 4);
    pos += 4;
    if (name_len >= ROBOT_MAX_NAME_LEN) return false;
    if (pos + name_len + 1 > len) return false;
    memcpy(r->name, &buf[pos], name_len + 1);
    pos += name_len + 1;

    /* Pose */
    if (pos + 24 > len) return false;
    Pose_deserialize(&r->pose, &buf[pos], 24);
    pos += 24;

    /* Waypoints */
    if (pos + 4 > len) return false;
    memcpy(&r->waypoint_count, &buf[pos], 4);
    pos += 4;

    if (r->waypoint_count > ROBOT_MAX_WAYPOINTS) return false;

    for (uint32_t i = 0; i < r->waypoint_count; ++i) {
        if (pos + 16 > len) return false;
        Point_deserialize(&r->waypoints[i], &buf[pos], 16);
        pos += 16;
    }

    return true;
}

#endif /* HDDS_SAMPLES_NESTED_H */
