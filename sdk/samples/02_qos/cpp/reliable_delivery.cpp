// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Reliable Delivery (C++)
 *
 * Demonstrates RELIABLE QoS for guaranteed message delivery.
 * Messages are retransmitted if lost (NACK-based recovery).
 *
 * Usage:
 *     ./reliable_delivery        # Subscriber
 *     ./reliable_delivery pub    # Publisher
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

constexpr int NUM_MESSAGES = 10;

void run_publisher(hdds::Participant& participant) {
    /* Create RELIABLE writer */
    auto qos = hdds::QoS::reliable();
    auto writer = participant.create_writer<HelloWorld>("ReliableTopic", qos);

    std::cout << "Publishing " << NUM_MESSAGES << " messages with RELIABLE QoS...\n\n";

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Reliable message #" + std::to_string(i + 1));
        writer.write(msg);

        std::cout << "  [SENT] id=" << msg.id << " msg='" << msg.message << "'\n";
        std::this_thread::sleep_for(100ms);
    }

    std::cout << "\nDone publishing. RELIABLE ensures all messages delivered.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create RELIABLE reader */
    auto qos = hdds::QoS::reliable();
    auto reader = participant.create_reader<HelloWorld>("ReliableTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Waiting for RELIABLE messages...\n\n";

    int received = 0;
    while (received < NUM_MESSAGES) {
        if (waitset.wait(5s)) {
            while (auto msg = reader.take()) {
                std::cout << "  [RECV] id=" << msg->id << " msg='" << msg->message << "'\n";
                received++;
            }
        } else {
            std::cout << "  (timeout waiting for messages)\n";
        }
    }

    std::cout << "\nReceived all " << received << " messages. RELIABLE QoS guarantees delivery!\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Reliable Delivery Demo\n";
        std::cout << "QoS: RELIABLE - guaranteed delivery via NACK retransmission\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("ReliableDemo");

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
