// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Generated from Nested.idl
 * Demonstrates nested struct types
 */
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hdds_samples {

/// 2D Point
struct Point {
    double x = 0.0;
    double y = 0.0;

    Point() = default;
    Point(double x_, double y_) : x(x_), y(y_) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(16);
        std::memcpy(&buf[0], &x, 8);
        std::memcpy(&buf[8], &y, 8);
        return buf;
    }

    static Point deserialize(const uint8_t* data, size_t len) {
        if (len < 16) throw std::runtime_error("Buffer too small for Point");
        Point p;
        std::memcpy(&p.x, &data[0], 8);
        std::memcpy(&p.y, &data[8], 8);
        return p;
    }
};

/// Position and orientation
struct Pose {
    Point position;
    double orientation = 0.0;  // radians

    Pose() = default;
    Pose(Point pos, double orient) : position(pos), orientation(orient) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf(24);
        auto pos_buf = position.serialize();
        std::memcpy(&buf[0], pos_buf.data(), 16);
        std::memcpy(&buf[16], &orientation, 8);
        return buf;
    }

    static Pose deserialize(const uint8_t* data, size_t len) {
        if (len < 24) throw std::runtime_error("Buffer too small for Pose");
        Pose p;
        p.position = Point::deserialize(data, 16);
        std::memcpy(&p.orientation, &data[16], 8);
        return p;
    }
};

/// Robot with nested types
struct Robot {
    uint32_t id = 0;
    std::string name;
    Pose pose;
    std::vector<Point> waypoints;

    Robot() = default;
    Robot(uint32_t id_, std::string name_, Pose pose_, std::vector<Point> wps)
        : id(id_), name(std::move(name_)), pose(pose_), waypoints(std::move(wps)) {}

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buf;

        // ID
        buf.insert(buf.end(), reinterpret_cast<const uint8_t*>(&id),
                   reinterpret_cast<const uint8_t*>(&id) + 4);

        // Name
        uint32_t name_len = static_cast<uint32_t>(name.size());
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&name_len),
                   reinterpret_cast<uint8_t*>(&name_len) + 4);
        buf.insert(buf.end(), name.begin(), name.end());
        buf.push_back(0);

        // Pose
        auto pose_buf = pose.serialize();
        buf.insert(buf.end(), pose_buf.begin(), pose_buf.end());

        // Waypoints
        uint32_t wp_count = static_cast<uint32_t>(waypoints.size());
        buf.insert(buf.end(), reinterpret_cast<uint8_t*>(&wp_count),
                   reinterpret_cast<uint8_t*>(&wp_count) + 4);
        for (const auto& wp : waypoints) {
            auto wp_buf = wp.serialize();
            buf.insert(buf.end(), wp_buf.begin(), wp_buf.end());
        }

        return buf;
    }

    static Robot deserialize(const uint8_t* data, size_t len) {
        Robot r;
        size_t pos = 0;

        // ID
        if (pos + 4 > len) throw std::runtime_error("Buffer too small for robot id");
        std::memcpy(&r.id, &data[pos], 4);
        pos += 4;

        // Name
        if (pos + 4 > len) throw std::runtime_error("Buffer too small for name length");
        uint32_t name_len;
        std::memcpy(&name_len, &data[pos], 4);
        pos += 4;
        if (pos + name_len + 1 > len) throw std::runtime_error("Buffer too small for name");
        r.name.assign(reinterpret_cast<const char*>(&data[pos]), name_len);
        pos += name_len + 1;

        // Pose
        if (pos + 24 > len) throw std::runtime_error("Buffer too small for pose");
        r.pose = Pose::deserialize(&data[pos], 24);
        pos += 24;

        // Waypoints
        if (pos + 4 > len) throw std::runtime_error("Buffer too small for waypoint count");
        uint32_t wp_count;
        std::memcpy(&wp_count, &data[pos], 4);
        pos += 4;

        r.waypoints.reserve(wp_count);
        for (uint32_t i = 0; i < wp_count; ++i) {
            if (pos + 16 > len) throw std::runtime_error("Buffer too small for waypoint");
            r.waypoints.push_back(Point::deserialize(&data[pos], 16));
            pos += 16;
        }

        return r;
    }
};

} // namespace hdds_samples
