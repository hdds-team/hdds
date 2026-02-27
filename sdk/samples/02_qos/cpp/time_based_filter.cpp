// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Time-Based Filter (C++)
 *
 * Demonstrates TIME_BASED_FILTER QoS for reader-side rate limiting.
 * The filter sets a minimum separation between delivered samples,
 * reducing bandwidth for readers that do not need every update.
 *
 * This sample runs in single-process mode (two readers in one process)
 * to compare filtered vs unfiltered reception side by side.
 *
 * Usage:
 *     ./time_based_filter        # Single-process demo (pub + 2 readers)
 *     ./time_based_filter pub    # Publisher only
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <iomanip>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

constexpr int NUM_MESSAGES = 20;
constexpr int PUBLISH_INTERVAL_MS = 100;
constexpr int FILTER_INTERVAL_MS = 500;

void run_publisher(hdds::Participant& participant) {
    /* Create writer - best effort for high-rate data */
    auto qos = hdds::QoS::best_effort();
    auto writer = participant.create_writer<HelloWorld>("FilteredTopic", qos);

    std::cout << "Publishing " << NUM_MESSAGES << " messages at "
              << PUBLISH_INTERVAL_MS << "ms intervals...\n\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Sample #" + std::to_string(i + 1));
        writer.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << elapsed << "ms] Sent id="
                  << msg.id << "\n";

        std::this_thread::sleep_for(std::chrono::milliseconds(PUBLISH_INTERVAL_MS));
    }

    auto total = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();
    std::cout << "\nDone publishing " << NUM_MESSAGES << " messages over "
              << total << "ms.\n";
}

void run_demo(hdds::Participant& participant) {
    /* Reader A: no filter - receives all messages */
    auto qos_all = hdds::QoS::best_effort();
    auto reader_all = participant.create_reader<HelloWorld>("FilteredTopic", qos_all);

    /* Reader B: time-based filter - minimum 500ms between deliveries */
    auto qos_filtered = hdds::QoS::best_effort()
        .time_based_filter(std::chrono::milliseconds(FILTER_INTERVAL_MS));
    auto reader_filtered = participant.create_reader<HelloWorld>("FilteredTopic", qos_filtered);

    /* Publisher in the same process */
    auto writer_qos = hdds::QoS::best_effort();
    auto writer = participant.create_writer<HelloWorld>("FilteredTopic", writer_qos);

    std::cout << "Single-process demo with two readers:\n";
    std::cout << "  Reader A: No filter (receives all)\n";
    std::cout << "  Reader B: Time-based filter (min " << FILTER_INTERVAL_MS
              << "ms separation)\n\n";
    std::cout << "Publishing " << NUM_MESSAGES << " messages at "
              << PUBLISH_INTERVAL_MS << "ms intervals...\n\n";

    /* Publish all messages */
    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Sample #" + std::to_string(i + 1));
        writer.write(msg);

        std::this_thread::sleep_for(std::chrono::milliseconds(PUBLISH_INTERVAL_MS));
    }

    auto pub_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();
    std::cout << "Published " << NUM_MESSAGES << " messages in "
              << pub_elapsed << "ms.\n\n";

    /* Allow some time for delivery */
    std::this_thread::sleep_for(500ms);

    /* Drain Reader A */
    int recv_all = 0;
    std::cout << "Reader A (no filter) received:\n";
    while (auto msg = reader_all.take()) {
        std::cout << "  [ALL]      id=" << msg->id << "\n";
        recv_all++;
    }

    std::cout << "\n";

    /* Drain Reader B */
    int recv_filtered = 0;
    std::cout << "Reader B (filter=" << FILTER_INTERVAL_MS << "ms) received:\n";
    while (auto msg = reader_filtered.take()) {
        std::cout << "  [FILTERED] id=" << msg->id << "\n";
        recv_filtered++;
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary:\n";
    std::cout << "  Reader A (no filter):      " << recv_all
              << " messages received\n";
    std::cout << "  Reader B (filter="
              << FILTER_INTERVAL_MS << "ms): " << recv_filtered
              << " messages received\n";

    int expected_filtered = (NUM_MESSAGES * PUBLISH_INTERVAL_MS) / FILTER_INTERVAL_MS;
    std::cout << "\nWith " << NUM_MESSAGES << " messages at "
              << PUBLISH_INTERVAL_MS << "ms intervals and "
              << FILTER_INTERVAL_MS << "ms filter,\n";
    std::cout << "Reader B should receive approximately " << expected_filtered
              << " messages.\n";
    std::cout << "TIME_BASED_FILTER reduces reader-side bandwidth.\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool pub_only = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Time-Based Filter Demo\n";
        std::cout << "QoS: TIME_BASED_FILTER - reader-side minimum separation\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("TimeFilterDemo");

        if (pub_only) {
            run_publisher(participant);
        } else {
            run_demo(participant);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
