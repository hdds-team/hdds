// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Typed cross-language test: C++ pub/sub with generated CDR2 types.
//
// Usage:
//     ./typed_test_cpp pub <topic> <count>
//     ./typed_test_cpp sub <topic> <count>
//
// Build:
//     g++ -std=c++17 -O2 -o typed_test_cpp typed_test.cpp \
//         ../../sdk/cxx/src/*.cpp \
//         -I../../sdk/cxx/include -I../../sdk/c/include -I$WORK \
//         -L../../target/release -lhdds_c -lpthread -ldl -lm

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <vector>
#include <optional>
#include "interop_types.hpp"

// CDR2 LE encapsulation header
static const uint8_t ENCAP_CDR2_LE[4] = {0x00, 0x01, 0x00, 0x00};

static bool is_keyed_topic(const std::string &topic) {
    return topic.rfind("Keyed", 0) == 0;
}

static KeyedSample create_keyed_message() {
    KeyedSample msg;
    msg.id = 99;
    msg.active = true;
    msg.kind = SensorKind::HUMIDITY;
    msg.name = "device-alpha";
    msg.origin.latitude = 37.7749;
    msg.origin.longitude = -122.4194;
    msg.reading = 1.618f;
    return msg;
}

static int validate_keyed_message(const KeyedSample &msg) {
    int errs = 0;
    if (msg.id != 99) {
        std::fprintf(stderr, "FAIL: id = %u, want 99\n", msg.id);
        errs++;
    }
    if (!msg.active) {
        std::fprintf(stderr, "FAIL: active = false, want true\n");
        errs++;
    }
    if (msg.kind != SensorKind::HUMIDITY) {
        std::fprintf(stderr, "FAIL: kind mismatch\n");
        errs++;
    }
    if (msg.name != "device-alpha") {
        std::fprintf(stderr, "FAIL: name = '%s', want 'device-alpha'\n", msg.name.c_str());
        errs++;
    }
    if (std::fabs(msg.origin.latitude - 37.7749) > 1e-10) {
        std::fprintf(stderr, "FAIL: origin.latitude = %f\n", msg.origin.latitude);
        errs++;
    }
    if (std::fabs(msg.origin.longitude - (-122.4194)) > 1e-10) {
        std::fprintf(stderr, "FAIL: origin.longitude = %f\n", msg.origin.longitude);
        errs++;
    }
    if (msg.reading != 1.618f) {
        std::fprintf(stderr, "FAIL: reading = %f, want 1.618\n", static_cast<double>(msg.reading));
        errs++;
    }
    return errs;
}

static SensorReading create_test_message() {
    SensorReading msg;
    msg.sensor_id = 42;
    msg.kind = SensorKind::PRESSURE;
    msg.value = 3.15f;
    msg.label = "test-sensor";
    msg.timestamp_ns = 1700000000000000000LL;
    msg.history = {1.0f, 2.0f, 3.0f};
    msg.error_code = 7;
    msg.location.latitude = 48.8566;
    msg.location.longitude = 2.3522;
    return msg;
}

static int validate_message(const SensorReading &msg) {
    int errs = 0;
    if (msg.sensor_id != 42) {
        std::fprintf(stderr, "FAIL: sensor_id = %u, want 42\n", msg.sensor_id);
        errs++;
    }
    if (msg.kind != SensorKind::PRESSURE) {
        std::fprintf(stderr, "FAIL: kind mismatch\n");
        errs++;
    }
    if (msg.value != 3.15f) {
        std::fprintf(stderr, "FAIL: value = %f, want 3.15\n", static_cast<double>(msg.value));
        errs++;
    }
    if (msg.label != "test-sensor") {
        std::fprintf(stderr, "FAIL: label = '%s', want 'test-sensor'\n", msg.label.c_str());
        errs++;
    }
    if (msg.timestamp_ns != 1700000000000000000LL) {
        std::fprintf(stderr, "FAIL: timestamp_ns mismatch\n");
        errs++;
    }
    if (msg.history.size() != 3) {
        std::fprintf(stderr, "FAIL: history.size = %zu, want 3\n", msg.history.size());
        errs++;
    } else {
        if (msg.history[0] != 1.0f) { std::fprintf(stderr, "FAIL: history[0]\n"); errs++; }
        if (msg.history[1] != 2.0f) { std::fprintf(stderr, "FAIL: history[1]\n"); errs++; }
        if (msg.history[2] != 3.0f) { std::fprintf(stderr, "FAIL: history[2]\n"); errs++; }
    }
    if (!msg.error_code.has_value() || *msg.error_code != 7) {
        std::fprintf(stderr, "FAIL: error_code mismatch\n");
        errs++;
    }
    if (std::fabs(msg.location.latitude - 48.8566) > 1e-10) {
        std::fprintf(stderr, "FAIL: latitude = %f\n", msg.location.latitude);
        errs++;
    }
    if (std::fabs(msg.location.longitude - 2.3522) > 1e-10) {
        std::fprintf(stderr, "FAIL: longitude = %f\n", msg.location.longitude);
        errs++;
    }
    return errs;
}

static int run_pub(const std::string &topic, int count) {
    hdds::Participant p("typed_cpp_pub", hdds::TransportMode::UdpMulticast);

    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(count + 5);

    auto writer = p.create_writer_raw(topic, qos);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    bool keyed = is_keyed_topic(topic);
    for (int i = 0; i < count; i++) {
        uint8_t cdr2_buf[4096];
        int enc;
        if (keyed) {
            auto msg = create_keyed_message();
            enc = msg.encode_cdr2_le(cdr2_buf, sizeof(cdr2_buf));
        } else {
            auto msg = create_test_message();
            enc = msg.encode_cdr2_le(cdr2_buf, sizeof(cdr2_buf));
        }
        if (enc < 0) {
            std::fprintf(stderr, "encode failed: %d\n", enc);
            return 1;
        }

        // Build payload: encap header + CDR2 bytes
        std::vector<uint8_t> payload(4 + static_cast<size_t>(enc));
        std::memcpy(payload.data(), ENCAP_CDR2_LE, 4);
        std::memcpy(payload.data() + 4, cdr2_buf, static_cast<size_t>(enc));

        writer->write_raw(payload.data(), payload.size());
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

static int run_sub(const std::string &topic, int count) {
    hdds::Participant p("typed_cpp_sub", hdds::TransportMode::UdpMulticast);

    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(count + 5);

    auto reader = p.create_reader_raw(topic, qos);

    hdds::WaitSet ws;
    ws.attach(reader->get_status_condition());

    std::vector<std::vector<uint8_t>> received;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    while (static_cast<int>(received.size()) < count &&
           std::chrono::steady_clock::now() < deadline) {
        if (ws.wait(std::chrono::seconds(1))) {
            while (auto data = reader->take_raw()) {
                received.emplace_back(data->begin(), data->end());
            }
        }
    }

    // Validate
    bool ok = true;
    for (int i = 0; i < static_cast<int>(received.size()); i++) {
        const auto &raw = received[static_cast<size_t>(i)];
        if (raw.size() < 4) {
            std::fprintf(stderr, "FAIL: sample %d too short (%zu bytes)\n", i, raw.size());
            ok = false;
            continue;
        }

        // Strip 4-byte encap header, decode CDR2
        if (is_keyed_topic(topic)) {
            KeyedSample kout;
            int dec = kout.decode_cdr2_le(raw.data() + 4, raw.size() - 4);
            if (dec < 0) {
                std::fprintf(stderr, "FAIL: decode error at sample %d: %d\n", i, dec);
                ok = false;
                continue;
            }
            if (validate_keyed_message(kout) != 0) {
                ok = false;
            }
        } else {
            SensorReading out;
            int dec = out.decode_cdr2_le(raw.data() + 4, raw.size() - 4);
            if (dec < 0) {
                std::fprintf(stderr, "FAIL: decode error at sample %d: %d\n", i, dec);
                ok = false;
                continue;
            }
            if (validate_message(out) != 0) {
                ok = false;
            }
        }
    }

    if (ok && static_cast<int>(received.size()) == count) {
        std::cout << "OK: received " << count << "/" << count << " samples\n";
        return 0;
    } else {
        std::cerr << "FAIL: received " << received.size()
                  << "/" << count << " samples\n";
        return 1;
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " pub|sub <topic> <count>\n";
        return 1;
    }

    std::string mode = argv[1];
    std::string topic = argv[2];
    int count = std::atoi(argv[3]);

    try {
        if (mode == "pub") return run_pub(topic, count);
        if (mode == "sub") return run_sub(topic, count);
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    } catch (const hdds::Error &e) {
        std::cerr << "HDDS error: " << e.what() << "\n";
        return 1;
    }
}
