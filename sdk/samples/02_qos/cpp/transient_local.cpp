// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Transient Local (C++)
 *
 * Demonstrates TRANSIENT_LOCAL durability QoS policy.
 *
 * KNOWN LIMITATION: Late-joiner delivery is not yet fully implemented.
 * A subscriber joining after the publisher has written will NOT receive
 * historical data. Both pub and sub must be running simultaneously for
 * RELIABLE + TRANSIENT_LOCAL to ensure no message loss.
 *
 * Usage:
 *     ./transient_local        # Subscriber
 *     ./transient_local pub    # Publisher
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

constexpr int NUM_MESSAGES = 5;
std::atomic<bool> running{true};

void signal_handler(int) { running = false; }

void run_publisher(hdds::Participant& participant) {
    /* Create TRANSIENT_LOCAL writer - caches data for late joiners */
    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(NUM_MESSAGES);

    auto writer = participant.create_writer<HelloWorld>("TransientTopic", qos);

    std::cout << "Publishing " << NUM_MESSAGES << " messages with TRANSIENT_LOCAL QoS...\n\n";

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Historical data #" + std::to_string(i + 1));
        writer.write(msg);

        std::cout << "  [CACHED] id=" << msg.id << " msg='" << msg.message << "'\n";
    }

    std::cout << "\nAll messages cached. Waiting for late-joining subscribers...\n";
    std::cout << "(Run './transient_local' in another terminal to see late-join)\n";
    std::cout << "Press Ctrl+C to exit.\n";

    std::signal(SIGINT, signal_handler);
    while (running) {
        std::this_thread::sleep_for(1s);
    }
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "Creating TRANSIENT_LOCAL subscriber (late-joiner)...\n";
    std::cout << "If publisher ran first, we should receive cached historical data.\n\n";

    /* Create TRANSIENT_LOCAL reader */
    auto qos = hdds::QoS::reliable().transient_local();
    auto reader = participant.create_reader<HelloWorld>("TransientTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Waiting for historical data...\n\n";

    int received = 0;
    int timeouts = 0;

    while (timeouts < 2) {
        if (waitset.wait(3s)) {
            while (auto msg = reader.take()) {
                std::cout << "  [HISTORICAL] id=" << msg->id << " msg='" << msg->message << "'\n";
                received++;
            }
            timeouts = 0;
        } else {
            timeouts++;
        }
    }

    if (received > 0) {
        std::cout << "\nReceived " << received << " historical messages via TRANSIENT_LOCAL!\n";
        std::cout << "Late-joiners automatically get cached data.\n";
    } else {
        std::cout << "\nNo historical data received. Start publisher first:\n";
        std::cout << "  ./transient_local pub\n";
    }
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Transient Local Demo\n";
        std::cout << "QoS: TRANSIENT_LOCAL - late-joiners receive historical data\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("TransientLocalDemo");

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
