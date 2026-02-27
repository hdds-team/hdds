// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Partition Filter (C++)
 *
 * Demonstrates PARTITION QoS for logical data filtering.
 * Writers and readers only communicate when partitions match.
 *
 * Usage:
 *     ./partition_filter                # Subscriber (partition A)
 *     ./partition_filter pub            # Publisher (partition A)
 *     ./partition_filter pub B          # Publisher (partition B - no match)
 *     ./partition_filter sub B          # Subscriber (partition B)
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

constexpr int NUM_MESSAGES = 5;

void run_publisher(hdds::Participant& participant, const std::string& partition) {
    /* Create writer with partition */
    auto qos = hdds::QoS::reliable().partition(partition);
    auto writer = participant.create_writer<HelloWorld>("PartitionTopic", qos);

    std::cout << "Publishing to partition '" << partition << "'...\n\n";

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "[" + partition + "] Message #" + std::to_string(i + 1));
        writer.write(msg);

        std::cout << "  [SENT:" << partition << "] id=" << msg.id
                  << " msg='" << msg.message << "'\n";

        std::this_thread::sleep_for(200ms);
    }

    std::cout << "\nDone publishing to partition '" << partition << "'.\n";
    std::cout << "Only readers in matching partition will receive data.\n";
}

void run_subscriber(hdds::Participant& participant, const std::string& partition) {
    /* Create reader with partition */
    auto qos = hdds::QoS::reliable().partition(partition);
    auto reader = participant.create_reader<HelloWorld>("PartitionTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Subscribing to partition '" << partition << "'...\n";
    std::cout << "Only publishers in matching partition will be received.\n\n";

    int received = 0;
    int timeouts = 0;

    while (timeouts < 3) {
        if (waitset.wait(2s)) {
            while (auto msg = reader.take()) {
                std::cout << "  [RECV:" << partition << "] id=" << msg->id
                          << " msg='" << msg->message << "'\n";
                received++;
            }
            timeouts = 0;
        } else {
            timeouts++;
            std::cout << "  (waiting for partition '" << partition << "'...)\n";
        }
    }

    if (received > 0) {
        std::cout << "\nReceived " << received << " messages in partition '"
                  << partition << "'.\n";
    } else {
        std::cout << "\nNo messages received. Is there a publisher in partition '"
                  << partition << "'?\n";
        std::cout << "Try: ./partition_filter pub " << partition << "\n";
    }
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "sub";
    std::string partition = (argc > 2) ? argv[2] : "A";

    bool is_publisher = (mode == "pub");

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Partition Filter Demo\n";
        std::cout << "QoS: PARTITION - logical data filtering by namespace\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("PartitionDemo");

        if (is_publisher) {
            run_publisher(participant, partition);
        } else {
            run_subscriber(participant, partition);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
