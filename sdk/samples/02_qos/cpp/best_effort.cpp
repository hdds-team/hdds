// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Best Effort (C++)
 *
 * Demonstrates BEST_EFFORT QoS for fire-and-forget messaging.
 * Lower latency than RELIABLE, but no delivery guarantees.
 *
 * Usage:
 *     ./best_effort        # Subscriber
 *     ./best_effort pub    # Publisher
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

constexpr int NUM_MESSAGES = 20;

void run_publisher(hdds::Participant& participant) {
    /* Create BEST_EFFORT writer */
    auto qos = hdds::QoS::best_effort();
    auto writer = participant.create_writer<HelloWorld>("BestEffortTopic", qos);

    std::cout << "Publishing " << NUM_MESSAGES << " messages with BEST_EFFORT QoS...\n";
    std::cout << "(Some messages may be lost - fire-and-forget)\n\n";

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "BestEffort #" + std::to_string(i + 1));
        writer.write(msg);

        std::cout << "  [SENT] id=" << msg.id << " msg='" << msg.message << "'\n";
        std::this_thread::sleep_for(50ms);  /* Fast publishing */
    }

    std::cout << "\nDone publishing. Some messages may have been dropped.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create BEST_EFFORT reader */
    auto qos = hdds::QoS::best_effort();
    auto reader = participant.create_reader<HelloWorld>("BestEffortTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Waiting for BEST_EFFORT messages...\n";
    std::cout << "(Lower latency, but delivery not guaranteed)\n\n";

    int received = 0;
    int timeouts = 0;
    constexpr int max_timeouts = 3;

    while (timeouts < max_timeouts) {
        if (waitset.wait(2s)) {
            while (auto msg = reader.take()) {
                std::cout << "  [RECV] id=" << msg->id << " msg='" << msg->message << "'\n";
                received++;
            }
            timeouts = 0;  /* Reset on data */
        } else {
            timeouts++;
            std::cout << "  (timeout " << timeouts << "/" << max_timeouts << ")\n";
        }
    }

    std::cout << "\nReceived " << received << "/" << NUM_MESSAGES
              << " messages. BEST_EFFORT trades reliability for speed.\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Best Effort Demo\n";
        std::cout << "QoS: BEST_EFFORT - fire-and-forget, lowest latency\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("BestEffortDemo");

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
