// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Nested Structs Sample - Demonstrates nested/composite DDS types
 *
 * This sample shows how to work with nested types:
 * - Point (x, y, z coordinates)
 * - Pose (position + orientation as Points)
 * - Robot (name, pose, trajectory sequence of Points)
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

    /* Point - simple nested struct (now has x, y, z) */
    printf("--- Point ---\n");
    Point point = {.x = 10.5, .y = 20.3, .z = 0.0};

    printf("Original: Point(%.1f, %.1f, %.1f)\n", point.x, point.y, point.z);

    int size = point_encode_cdr2_le(&point, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes (3 x f64)\n", size);

    Point point_deser;
    memset(&point_deser, 0, sizeof(point_deser));
    point_decode_cdr2_le(&point_deser, buffer, (size_t)size);
    printf("Deserialized: Point(%.1f, %.1f, %.1f)\n",
           point_deser.x, point_deser.y, point_deser.z);

    if (point.x == point_deser.x && point.y == point_deser.y && point.z == point_deser.z) {
        printf("[OK] Point round-trip successful\n\n");
    }

    /* Pose - struct containing two Points (position + orientation) */
    printf("--- Pose ---\n");
    Pose pose = {
        .position = {.x = 100.0, .y = 200.0, .z = 0.0},
        .orientation = {.x = 0.0, .y = 0.0, .z = M_PI / 4.0}  /* 45 degrees around Z */
    };

    printf("Original Pose:\n");
    printf("  position: (%.1f, %.1f, %.1f)\n",
           pose.position.x, pose.position.y, pose.position.z);
    printf("  orientation: (%.4f, %.4f, %.4f)\n",
           pose.orientation.x, pose.orientation.y, pose.orientation.z);

    size = pose_encode_cdr2_le(&pose, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes (6 x f64)\n", size);

    Pose pose_deser;
    memset(&pose_deser, 0, sizeof(pose_deser));
    pose_decode_cdr2_le(&pose_deser, buffer, (size_t)size);
    printf("Deserialized Pose:\n");
    printf("  position: (%.1f, %.1f, %.1f)\n",
           pose_deser.position.x, pose_deser.position.y, pose_deser.position.z);
    printf("  orientation: (%.4f, %.4f, %.4f)\n",
           pose_deser.orientation.x, pose_deser.orientation.y, pose_deser.orientation.z);

    if (pose.orientation.z == pose_deser.orientation.z) {
        printf("[OK] Pose round-trip successful\n\n");
    }

    /* Robot - complex type with name (char*), pose, trajectory (sequence<Point>) */
    printf("--- Robot ---\n");
    Robot robot;
    memset(&robot, 0, sizeof(robot));

    robot.name = "RobotOne";
    robot.pose.position = (Point){0.0, 0.0, 0.0};
    robot.pose.orientation = (Point){0.0, 0.0, 0.0};

    Point waypoints[] = {
        {10.0, 0.0, 0.0},
        {10.0, 10.0, 0.0},
        {0.0, 10.0, 0.0},
        {0.0, 0.0, 0.0}
    };
    robot.trajectory.data = waypoints;
    robot.trajectory.len = 4;

    printf("Original Robot:\n");
    printf("  name: \"%s\"\n", robot.name);
    printf("  pose: (%.1f, %.1f, %.1f)\n",
           robot.pose.position.x, robot.pose.position.y, robot.pose.position.z);
    printf("  trajectory (%u):\n", robot.trajectory.len);
    for (uint32_t i = 0; i < robot.trajectory.len; ++i) {
        printf("    [%u] (%.1f, %.1f, %.1f)\n", i,
               robot.trajectory.data[i].x, robot.trajectory.data[i].y,
               robot.trajectory.data[i].z);
    }

    size = robot_encode_cdr2_le(&robot, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Robot robot_deser;
    memset(&robot_deser, 0, sizeof(robot_deser));
    char name_buf[256] = {0};
    robot_deser.name = name_buf;
    Point deser_waypoints[8] = {{0}};
    robot_deser.trajectory.data = deser_waypoints;
    robot_deser.trajectory.len = 0;

    robot_decode_cdr2_le(&robot_deser, buffer, (size_t)size);
    printf("Deserialized Robot:\n");
    printf("  name: \"%s\"\n", robot_deser.name);
    printf("  pose: (%.1f, %.1f, %.1f)\n",
           robot_deser.pose.position.x, robot_deser.pose.position.y,
           robot_deser.pose.position.z);
    printf("  trajectory: %u\n", robot_deser.trajectory.len);

    if (strcmp(robot.name, robot_deser.name) == 0 &&
        robot.trajectory.len == robot_deser.trajectory.len) {
        printf("[OK] Robot round-trip successful\n\n");
    }

    /* Robot with no trajectory */
    printf("--- Robot with empty trajectory ---\n");
    Robot simple_robot;
    memset(&simple_robot, 0, sizeof(simple_robot));
    simple_robot.name = "SimpleBot";
    simple_robot.pose.position = (Point){5.0, 5.0, 0.0};
    simple_robot.pose.orientation = (Point){0.0, 0.0, M_PI};
    simple_robot.trajectory.data = NULL;
    simple_robot.trajectory.len = 0;

    size = robot_encode_cdr2_le(&simple_robot, buffer, sizeof(buffer));
    Robot simple_deser;
    memset(&simple_deser, 0, sizeof(simple_deser));
    char simple_name_buf[256] = {0};
    simple_deser.name = simple_name_buf;
    simple_deser.trajectory.data = NULL;
    simple_deser.trajectory.len = 0;

    robot_decode_cdr2_le(&simple_deser, buffer, (size_t)size);

    printf("Robot \"%s\" with %u trajectory points\n",
           simple_deser.name, simple_deser.trajectory.len);
    if (simple_robot.trajectory.len == simple_deser.trajectory.len) {
        printf("[OK] Empty trajectory handled correctly\n\n");
    }

    /* Test default/zero values */
    printf("--- Default Values ---\n");
    Point default_point = {0};
    Pose default_pose = {0};
    Robot default_robot = {0};

    printf("Default Point: (%.0f, %.0f, %.0f)\n",
           default_point.x, default_point.y, default_point.z);
    printf("Default Pose position: (%.0f, %.0f, %.0f)\n",
           default_pose.position.x, default_pose.position.y, default_pose.position.z);
    printf("Default Robot name: %s\n",
           default_robot.name ? default_robot.name : "(null)");

    printf("\n=== Sample Complete ===\n");
    return 0;
}
