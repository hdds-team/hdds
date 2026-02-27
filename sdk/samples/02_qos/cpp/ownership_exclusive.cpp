// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Ownership Exclusive (C++)
 *
 * Demonstrates EXCLUSIVE ownership with strength-based arbitration.
 * Only the writer with highest strength publishes to a topic.
 *
 * Usage:
 *     ./ownership_exclusive             # Subscriber
 *     ./ownership_exclusive pub 100     # Publisher with strength 100
 *     ./ownership_exclusive pub 200     # Publisher with strength 200 (wins)
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <csignal>
#include <atomic>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

std::atomic<bool> running{true};

void signal_handler(int) { running = false; }

void run_publisher(hdds::Participant& participant, int strength) {
    /* Create writer with EXCLUSIVE ownership */
    auto qos = hdds::QoS::reliable().ownership_exclusive(strength);
    auto writer = participant.create_writer<HelloWorld>("OwnershipTopic", qos);

    std::cout << "Publishing with EXCLUSIVE ownership (strength: " << strength << ")\n";
    std::cout << "Higher strength wins ownership. Start another publisher with different strength.\n\n";

    std::signal(SIGINT, signal_handler);

    int seq = 0;
    while (running) {
        HelloWorld msg(strength, "Writer[" + std::to_string(strength) + "] seq=" + std::to_string(seq));
        writer.write(msg);

        std::cout << "  [PUBLISHED strength=" << strength << "] seq=" << seq << "\n";

        seq++;
        std::this_thread::sleep_for(500ms);
    }

    std::cout << "\nPublisher (strength=" << strength << ") shutting down.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create reader with EXCLUSIVE ownership */
    auto qos = hdds::QoS::reliable().ownership_exclusive(0);  /* Strength doesn't matter for reader */
    auto reader = participant.create_reader<HelloWorld>("OwnershipTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Subscribing with EXCLUSIVE ownership...\n";
    std::cout << "Only data from the highest-strength writer will be received.\n\n";

    std::signal(SIGINT, signal_handler);

    int last_owner = -1;

    while (running) {
        if (waitset.wait(1s)) {
            while (auto msg = reader.take()) {
                if (msg->id != last_owner) {
                    std::cout << "\n  ** OWNERSHIP CHANGED to writer with strength="
                              << msg->id << " **\n\n";
                    last_owner = msg->id;
                }
                std::cout << "  [RECV from strength=" << msg->id << "] " << msg->message << "\n";
            }
        }
    }

    std::cout << "\nSubscriber shutting down.\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);
    int strength = 100;  /* Default strength */

    if (is_publisher && argc > 2) {
        strength = std::atoi(argv[2]);
    }

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Ownership Exclusive Demo\n";
        std::cout << "QoS: EXCLUSIVE ownership - highest strength writer wins\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("OwnershipDemo");

        if (is_publisher) {
            run_publisher(participant, strength);
        } else {
            run_subscriber(participant);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
