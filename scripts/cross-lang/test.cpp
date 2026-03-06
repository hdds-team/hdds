// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Cross-language test helper: C++ pub/sub.
//
// Usage:
//     ./xtest_cpp pub <topic> <count>
//     ./xtest_cpp sub <topic> <count>
//
// Build:
//     g++ -std=c++17 -o xtest_cpp test.cpp \
//         -I../../sdk/cxx/include -I../../sdk/c/include \
//         ../../sdk/cxx/src/*.cpp \
//         -L../../target/release -lhdds_c -lpthread -ldl -lm

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <cstring>

static const std::string PAYLOAD_PREFIX = "XTEST-";

static int run_pub(const std::string &topic, int count) {
    hdds::Participant p("xtest_cpp_pub", hdds::TransportMode::UdpMulticast);

    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(count + 5);

    auto writer = p.create_writer_raw(topic, qos);

    // Let discovery happen
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    for (int i = 0; i < count; i++) {
        std::string payload = PAYLOAD_PREFIX + std::to_string(i);
        writer->write_raw(
            reinterpret_cast<const uint8_t *>(payload.data()),
            payload.size());
    }

    // Keep alive for late joiners
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

static int run_sub(const std::string &topic, int count) {
    hdds::Participant p("xtest_cpp_sub", hdds::TransportMode::UdpMulticast);

    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(count + 5);

    auto reader = p.create_reader_raw(topic, qos);

    hdds::WaitSet ws;
    ws.attach(reader->get_status_condition());

    std::vector<std::string> received;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

    while ((int)received.size() < count &&
           std::chrono::steady_clock::now() < deadline) {
        if (ws.wait(std::chrono::seconds(1))) {
            while (auto data = reader->take_raw()) {
                received.emplace_back(data->begin(), data->end());
            }
        }
    }

    // Validate
    bool ok = true;
    for (int i = 0; i < count; i++) {
        std::string expected = PAYLOAD_PREFIX + std::to_string(i);
        if (i < (int)received.size()) {
            if (received[i] != expected) {
                std::cerr << "MISMATCH at " << i
                          << ": got '" << received[i]
                          << "', want '" << expected << "'\n";
                ok = false;
            }
        } else {
            std::cerr << "MISSING sample " << i << "\n";
            ok = false;
        }
    }

    if (ok && (int)received.size() == count) {
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
