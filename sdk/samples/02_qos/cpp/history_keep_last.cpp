// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: History Keep Last (C++)
 *
 * Demonstrates KEEP_LAST history QoS with configurable depth.
 * Only the N most recent samples are retained per instance.
 *
 * Usage:
 *     ./history_keep_last        # Subscriber (default depth=3)
 *     ./history_keep_last pub    # Publisher (burst of 10 messages)
 *     ./history_keep_last sub 5  # Subscriber with depth=5
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
    /* Create writer with KEEP_LAST history */
    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(NUM_MESSAGES);  /* Keep all on writer side */

    auto writer = participant.create_writer<HelloWorld>("HistoryTopic", qos);

    std::cout << "Publishing " << NUM_MESSAGES << " messages in rapid succession...\n\n";

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Message #" + std::to_string(i + 1));
        writer.write(msg);

        std::cout << "  [SENT] id=" << msg.id << " msg='" << msg.message << "'\n";
    }

    std::cout << "\nAll " << NUM_MESSAGES << " messages published.\n";
    std::cout << "Subscriber with history depth < " << NUM_MESSAGES
              << " will only see most recent.\n";
    std::cout << "Press Enter to exit (keep writer alive for late-join test)...\n";
    std::cin.get();
}

void run_subscriber(hdds::Participant& participant, int history_depth) {
    /* Create reader with KEEP_LAST history */
    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(history_depth);

    auto reader = participant.create_reader<HelloWorld>("HistoryTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Subscribing with KEEP_LAST history (depth=" << history_depth << ")...\n";
    std::cout << "Will only retain the " << history_depth << " most recent samples.\n\n";

    int received = 0;
    int timeouts = 0;

    while (timeouts < 2) {
        if (waitset.wait(2s)) {
            while (auto msg = reader.take()) {
                std::cout << "  [RECV] id=" << msg->id << " msg='" << msg->message << "'\n";
                received++;
            }
            timeouts = 0;
        } else {
            timeouts++;
        }
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary: Received " << received << " messages (history depth was "
              << history_depth << ")\n";

    if (received <= history_depth) {
        std::cout << "All received messages fit within history depth.\n";
    } else {
        std::cout << "Note: If publisher sent more than " << history_depth << " messages,\n";
        std::cout << "only the most recent " << history_depth << " were retained in history.\n";
    }
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);
    int history_depth = 3;  /* Default history depth */

    if (argc > 2) {
        history_depth = std::atoi(argv[2]);
        if (history_depth < 1) history_depth = 1;
    }

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "History Keep Last Demo\n";
        std::cout << "QoS: KEEP_LAST - retain N most recent samples per instance\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("HistoryDemo");

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant, history_depth);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
