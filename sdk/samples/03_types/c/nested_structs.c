// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Nested Structs Sample - Demonstrates nested/composite DDS types
 *
 * This sample shows how to work with nested types:
 * - Point (x, y coordinates)
 * - Pose (position + orientation)
 * - Robot (complex type with nested structs and sequences)
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "generated/Nested.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

int main(void) {
    printf("=== HDDS Nested Struct Types Sample ===\n\n");

    uint8_t buffer[4096];

    /* Point - simple nested struct */
    printf("--- Point ---\n");
    Point point = {.x = 10.5, .y = 20.3};

    printf("Original: Point(%.1f, %.1f)\n", point.x, point.y);

    size_t size = Point_serialize(&point, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes (2 × f64)\n", size);

    Point point_deser;
    Point_deserialize(&point_deser, buffer, size);
    printf("Deserialized: Point(%.1f, %.1f)\n", point_deser.x, point_deser.y);

    if (point.x == point_deser.x && point.y == point_deser.y) {
        printf("[OK] Point round-trip successful\n\n");
    }

    /* Pose - struct containing another struct */
    printf("--- Pose ---\n");
    Pose pose = {
        .position = {.x = 100.0, .y = 200.0},
        .orientation = M_PI / 4.0  /* 45 degrees */
    };

    printf("Original Pose:\n");
    printf("  position: (%.1f, %.1f)\n", pose.position.x, pose.position.y);
    printf("  orientation: %.4f rad (%.1f°)\n",
           pose.orientation, pose.orientation * 180.0 / M_PI);

    size = Pose_serialize(&pose, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes (3 × f64)\n", size);

    Pose pose_deser;
    Pose_deserialize(&pose_deser, buffer, size);
    printf("Deserialized Pose:\n");
    printf("  position: (%.1f, %.1f)\n", pose_deser.position.x, pose_deser.position.y);
    printf("  orientation: %.4f rad\n", pose_deser.orientation);

    if (pose.orientation == pose_deser.orientation) {
        printf("[OK] Pose round-trip successful\n\n");
    }

    /* Robot - complex type with nested structs and sequences */
    printf("--- Robot ---\n");
    Robot robot;
    robot.id = 42;
    strcpy(robot.name, "RobotOne");
    robot.pose.position.x = 0.0;
    robot.pose.position.y = 0.0;
    robot.pose.orientation = 0.0;
    robot.waypoint_count = 4;
    robot.waypoints[0] = (Point){10.0, 0.0};
    robot.waypoints[1] = (Point){10.0, 10.0};
    robot.waypoints[2] = (Point){0.0, 10.0};
    robot.waypoints[3] = (Point){0.0, 0.0};

    printf("Original Robot:\n");
    printf("  id: %u\n", robot.id);
    printf("  name: \"%s\"\n", robot.name);
    printf("  pose: (%.1f, %.1f) @ %.1f°\n",
           robot.pose.position.x, robot.pose.position.y,
           robot.pose.orientation * 180.0 / M_PI);
    printf("  waypoints (%u):\n", robot.waypoint_count);
    for (uint32_t i = 0; i < robot.waypoint_count; ++i) {
        printf("    [%u] (%.1f, %.1f)\n", i,
               robot.waypoints[i].x, robot.waypoints[i].y);
    }

    size = Robot_serialize(&robot, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    Robot robot_deser;
    Robot_deserialize(&robot_deser, buffer, size);
    printf("Deserialized Robot:\n");
    printf("  id: %u\n", robot_deser.id);
    printf("  name: \"%s\"\n", robot_deser.name);
    printf("  pose: (%.1f, %.1f)\n",
           robot_deser.pose.position.x, robot_deser.pose.position.y);
    printf("  waypoints: %u\n", robot_deser.waypoint_count);

    if (robot.id == robot_deser.id && strcmp(robot.name, robot_deser.name) == 0) {
        printf("[OK] Robot round-trip successful\n\n");
    }

    /* Robot with no waypoints */
    printf("--- Robot with empty waypoints ---\n");
    Robot simple_robot;
    simple_robot.id = 1;
    strcpy(simple_robot.name, "SimpleBot");
    simple_robot.pose.position.x = 5.0;
    simple_robot.pose.position.y = 5.0;
    simple_robot.pose.orientation = M_PI;
    simple_robot.waypoint_count = 0;

    size = Robot_serialize(&simple_robot, buffer, sizeof(buffer));
    Robot simple_deser;
    Robot_deserialize(&simple_deser, buffer, size);

    printf("Robot \"%s\" with %u waypoints\n",
           simple_deser.name, simple_deser.waypoint_count);
    if (simple_robot.waypoint_count == simple_deser.waypoint_count) {
        printf("[OK] Empty waypoints handled correctly\n\n");
    }

    /* Test default/zero values */
    printf("--- Default Values ---\n");
    Point default_point = {0};
    Pose default_pose = {0};
    Robot default_robot = {0};

    printf("Default Point: (%.0f, %.0f)\n", default_point.x, default_point.y);
    printf("Default Pose orientation: %.0f\n", default_pose.orientation);
    printf("Default Robot id: %u\n", default_robot.id);

    printf("\n=== Sample Complete ===\n");
    return 0;
}
