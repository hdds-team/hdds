// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Nested Structs Sample - Demonstrates nested/composite DDS types
 *
 * This sample shows how to work with nested types:
 * - Point (x, y, z coordinates)
 * - Pose (position + orientation as Points)
 * - Robot (name, pose, trajectory of Points)
 */

#include <iostream>
#include <iomanip>
#include <cstdint>
#include "generated/Nested.hpp"

using namespace hdds_samples;

int main() {
    std::cout << "=== HDDS Nested Struct Types Sample ===\n\n";

    // Point - simple nested struct with 3 doubles
    std::cout << "--- Point ---\n";
    Point point(10.5, 20.3, 0.0);

    std::cout << std::fixed << std::setprecision(1);
    std::cout << "Original: Point(" << point.x << ", " << point.y
              << ", " << point.z << ")\n";

    std::uint8_t buf[4096];
    int len = point.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes (3 x f64)\n";

    Point deser;
    deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized: Point(" << deser.x << ", " << deser.y
              << ", " << deser.z << ")\n";

    if (point.x == deser.x && point.y == deser.y && point.z == deser.z) {
        std::cout << "[OK] Point round-trip successful\n\n";
    }

    // Pose - struct containing two Points (position + orientation)
    std::cout << "--- Pose ---\n";
    Pose pose(Point(100.0, 200.0, 0.0), Point(0.0, 0.0, 0.7854));

    std::cout << "Original Pose:\n";
    std::cout << "  position: (" << pose.position.x << ", "
              << pose.position.y << ", " << pose.position.z << ")\n";
    std::cout << std::setprecision(4);
    std::cout << "  orientation: (" << pose.orientation.x << ", "
              << pose.orientation.y << ", " << pose.orientation.z << ")\n";

    len = pose.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes (6 x f64)\n";

    Pose pose_deser;
    pose_deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized Pose:\n";
    std::cout << std::setprecision(1);
    std::cout << "  position: (" << pose_deser.position.x << ", "
              << pose_deser.position.y << ", " << pose_deser.position.z << ")\n";
    std::cout << std::setprecision(4);
    std::cout << "  orientation: (" << pose_deser.orientation.x << ", "
              << pose_deser.orientation.y << ", " << pose_deser.orientation.z << ")\n";

    if (pose.orientation.z == pose_deser.orientation.z) {
        std::cout << "[OK] Pose round-trip successful\n\n";
    }

    // Robot - complex type with nested structs and sequence of Points
    std::cout << "--- Robot ---\n";
    Robot robot(
        "RobotOne",
        Pose(Point(0.0, 0.0, 0.0), Point(0.0, 0.0, 0.0)),
        {
            Point(10.0, 0.0, 0.0),
            Point(10.0, 10.0, 0.0),
            Point(0.0, 10.0, 0.0),
            Point(0.0, 0.0, 0.0),
        }
    );

    std::cout << std::setprecision(1);
    std::cout << "Original Robot:\n";
    std::cout << "  name: \"" << robot.name << "\"\n";
    std::cout << "  pose position: (" << robot.pose.position.x << ", "
              << robot.pose.position.y << ", " << robot.pose.position.z << ")\n";
    std::cout << "  trajectory (" << robot.trajectory.size() << "):\n";
    for (size_t i = 0; i < robot.trajectory.size(); ++i) {
        std::cout << "    [" << i << "] (" << robot.trajectory[i].x
                  << ", " << robot.trajectory[i].y
                  << ", " << robot.trajectory[i].z << ")\n";
    }

    len = robot.encode_cdr2_le(buf, sizeof(buf));
    std::cout << "Serialized size: " << len << " bytes\n";

    Robot robot_deser;
    robot_deser.decode_cdr2_le(buf, (std::size_t)len);
    std::cout << "Deserialized Robot:\n";
    std::cout << "  name: \"" << robot_deser.name << "\"\n";
    std::cout << "  pose position: (" << robot_deser.pose.position.x << ", "
              << robot_deser.pose.position.y << ")\n";
    std::cout << "  trajectory: " << robot_deser.trajectory.size() << " points\n";

    if (robot.name == robot_deser.name &&
        robot.trajectory.size() == robot_deser.trajectory.size()) {
        std::cout << "[OK] Robot round-trip successful\n\n";
    }

    // Robot with no trajectory
    std::cout << "--- Robot with empty trajectory ---\n";
    Robot simple_robot(
        "SimpleBot",
        Pose(Point(5.0, 5.0, 0.0), Point(0.0, 0.0, 3.14159)),
        {}
    );

    std::uint8_t simple_buf[4096];
    int simple_len = simple_robot.encode_cdr2_le(simple_buf, sizeof(simple_buf));
    Robot simple_deser;
    simple_deser.decode_cdr2_le(simple_buf, (std::size_t)simple_len);

    std::cout << "Robot \"" << simple_deser.name << "\" with "
              << simple_deser.trajectory.size() << " trajectory points\n";
    if (simple_robot.trajectory.size() == simple_deser.trajectory.size()) {
        std::cout << "[OK] Empty trajectory handled correctly\n\n";
    }

    // Test default values
    std::cout << "--- Default Values ---\n";
    Point default_point;
    Pose default_pose;
    Robot default_robot;

    std::cout << "Default Point: (" << default_point.x << ", "
              << default_point.y << ", " << default_point.z << ")\n";
    std::cout << "Default Pose position: (" << default_pose.position.x << ", "
              << default_pose.position.y << ")\n";
    std::cout << "Default Robot name: \"" << default_robot.name << "\"\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
