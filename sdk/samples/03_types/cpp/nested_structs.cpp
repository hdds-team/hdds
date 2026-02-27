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

#include <iostream>
#include <iomanip>
#include <cmath>
#include "generated/Nested.hpp"

using namespace hdds_samples;

constexpr double PI = 3.14159265358979323846;

int main() {
    std::cout << "=== HDDS Nested Struct Types Sample ===\n\n";

    // Point - simple nested struct
    std::cout << "--- Point ---\n";
    Point point(10.5, 20.3);

    std::cout << std::fixed << std::setprecision(1);
    std::cout << "Original: Point(" << point.x << ", " << point.y << ")\n";

    auto bytes = point.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes (2 × f64)\n";

    auto deser = Point::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized: Point(" << deser.x << ", " << deser.y << ")\n";

    if (point.x == deser.x && point.y == deser.y) {
        std::cout << "[OK] Point round-trip successful\n\n";
    }

    // Pose - struct containing another struct
    std::cout << "--- Pose ---\n";
    Pose pose(Point(100.0, 200.0), PI / 4.0);  // 45 degrees

    std::cout << "Original Pose:\n";
    std::cout << "  position: (" << pose.position.x << ", " << pose.position.y << ")\n";
    std::cout << std::setprecision(4);
    std::cout << "  orientation: " << pose.orientation << " rad ("
              << std::setprecision(1) << (pose.orientation * 180.0 / PI) << "°)\n";

    bytes = pose.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes (3 × f64)\n";

    auto pose_deser = Pose::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized Pose:\n";
    std::cout << "  position: (" << pose_deser.position.x << ", "
              << pose_deser.position.y << ")\n";
    std::cout << std::setprecision(4);
    std::cout << "  orientation: " << pose_deser.orientation << " rad\n";

    if (pose.orientation == pose_deser.orientation) {
        std::cout << "[OK] Pose round-trip successful\n\n";
    }

    // Robot - complex type with nested structs and sequences
    std::cout << "--- Robot ---\n";
    Robot robot(
        42,
        "RobotOne",
        Pose(Point(0.0, 0.0), 0.0),
        {
            Point(10.0, 0.0),
            Point(10.0, 10.0),
            Point(0.0, 10.0),
            Point(0.0, 0.0),
        }
    );

    std::cout << std::setprecision(1);
    std::cout << "Original Robot:\n";
    std::cout << "  id: " << robot.id << "\n";
    std::cout << "  name: \"" << robot.name << "\"\n";
    std::cout << "  pose: (" << robot.pose.position.x << ", "
              << robot.pose.position.y << ") @ "
              << (robot.pose.orientation * 180.0 / PI) << "°\n";
    std::cout << "  waypoints (" << robot.waypoints.size() << "):\n";
    for (size_t i = 0; i < robot.waypoints.size(); ++i) {
        std::cout << "    [" << i << "] (" << robot.waypoints[i].x
                  << ", " << robot.waypoints[i].y << ")\n";
    }

    bytes = robot.serialize();
    std::cout << "Serialized size: " << bytes.size() << " bytes\n";

    auto robot_deser = Robot::deserialize(bytes.data(), bytes.size());
    std::cout << "Deserialized Robot:\n";
    std::cout << "  id: " << robot_deser.id << "\n";
    std::cout << "  name: \"" << robot_deser.name << "\"\n";
    std::cout << "  pose: (" << robot_deser.pose.position.x << ", "
              << robot_deser.pose.position.y << ")\n";
    std::cout << "  waypoints: " << robot_deser.waypoints.size() << "\n";

    if (robot.id == robot_deser.id && robot.name == robot_deser.name) {
        std::cout << "[OK] Robot round-trip successful\n\n";
    }

    // Robot with no waypoints
    std::cout << "--- Robot with empty waypoints ---\n";
    Robot simple_robot(1, "SimpleBot", Pose(Point(5.0, 5.0), PI), {});

    auto simple_bytes = simple_robot.serialize();
    auto simple_deser = Robot::deserialize(simple_bytes.data(), simple_bytes.size());

    std::cout << "Robot \"" << simple_deser.name << "\" with "
              << simple_deser.waypoints.size() << " waypoints\n";
    if (simple_robot.waypoints.size() == simple_deser.waypoints.size()) {
        std::cout << "[OK] Empty waypoints handled correctly\n\n";
    }

    // Test default values
    std::cout << "--- Default Values ---\n";
    Point default_point;
    Pose default_pose;
    Robot default_robot;

    std::cout << "Default Point: (" << default_point.x << ", " << default_point.y << ")\n";
    std::cout << "Default Pose orientation: " << default_pose.orientation << "\n";
    std::cout << "Default Robot id: " << default_robot.id << "\n";

    std::cout << "\n=== Sample Complete ===\n";
    return 0;
}
