// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Resource Limits (C++)
 *
 * Demonstrates RESOURCE_LIMITS QoS for bounding memory usage.
 * Limits the maximum number of samples, instances, and samples
 * per instance that a reader will store.
 *
 * This sample runs in single-process mode (two readers in one process)
 * to compare limited vs unlimited reception side by side.
 *
 * Usage:
 *     ./resource_limits        # Single-process demo (pub + 2 readers)
 *     ./resource_limits pub    # Publisher only
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
constexpr int MAX_SAMPLES = 5;
constexpr int MAX_INSTANCES = 1;
constexpr int MAX_SAMPLES_PER_INSTANCE = 5;

void run_publisher(hdds::Participant& participant) {
    /* Create TRANSIENT_LOCAL writer with deep history */
    auto qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(100);
    auto writer = participant.create_writer<HelloWorld>("ResourceTopic", qos);

    std::cout << "Publishing " << NUM_MESSAGES
              << " messages with TRANSIENT_LOCAL durability...\n\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Data #" + std::to_string(i + 1));
        writer.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << elapsed << "ms] Sent id="
                  << msg.id << "\n";

        std::this_thread::sleep_for(50ms);
    }

    std::cout << "\nAll " << NUM_MESSAGES << " messages published.\n";
    std::cout << "Waiting for subscribers to connect...\n";
    std::cout << "(Run './resource_limits' in another terminal)\n";

    std::this_thread::sleep_for(10s);
    std::cout << "\nPublisher exiting.\n";
}

void run_demo(hdds::Participant& participant) {
    /* Publisher in the same process */
    auto writer_qos = hdds::QoS::reliable()
        .transient_local()
        .history_depth(100);
    auto writer = participant.create_writer<HelloWorld>("ResourceTopic", writer_qos);

    std::cout << "Publishing " << NUM_MESSAGES << " messages first...\n\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Data #" + std::to_string(i + 1));
        writer.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << elapsed << "ms] Sent id="
                  << msg.id << "\n";

        std::this_thread::sleep_for(50ms);
    }

    std::cout << "\nAll " << NUM_MESSAGES << " messages published. "
              << "Creating readers...\n\n";

    /* Allow writer cache to settle */
    std::this_thread::sleep_for(500ms);

    /* Reader A: resource-limited (max 5 samples) */
    auto qos_limited = hdds::QoS::reliable()
        .transient_local()
        .resource_limits(MAX_SAMPLES, MAX_INSTANCES, MAX_SAMPLES_PER_INSTANCE);
    auto reader_limited = participant.create_reader<HelloWorld>("ResourceTopic", qos_limited);

    /* Reader B: unlimited (receives everything available) */
    auto qos_unlimited = hdds::QoS::reliable()
        .transient_local()
        .history_depth(100);
    auto reader_unlimited = participant.create_reader<HelloWorld>("ResourceTopic", qos_unlimited);

    std::cout << "Reader A: resource_limits(max_samples=" << MAX_SAMPLES
              << ", max_instances=" << MAX_INSTANCES
              << ", max_per_instance=" << MAX_SAMPLES_PER_INSTANCE << ")\n";
    std::cout << "Reader B: unlimited (history_depth=100)\n\n";

    /* Allow time for historical data delivery */
    std::this_thread::sleep_for(2s);

    /* Drain Reader A (limited) */
    int recv_limited = 0;
    std::cout << "Reader A (limited to " << MAX_SAMPLES << " samples) received:\n";
    while (auto msg = reader_limited.take()) {
        std::cout << "  [LIMITED]   id=" << msg->id
                  << " msg='" << msg->message << "'\n";
        recv_limited++;
    }

    std::cout << "\n";

    /* Drain Reader B (unlimited) */
    int recv_unlimited = 0;
    std::cout << "Reader B (unlimited) received:\n";
    while (auto msg = reader_unlimited.take()) {
        std::cout << "  [UNLIMITED] id=" << msg->id
                  << " msg='" << msg->message << "'\n";
        recv_unlimited++;
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary:\n";
    std::cout << "  Published:              " << NUM_MESSAGES << " messages\n";
    std::cout << "  Reader A (limited):     " << recv_limited
              << " messages (max_samples=" << MAX_SAMPLES << ")\n";
    std::cout << "  Reader B (unlimited):   " << recv_unlimited
              << " messages\n";
    std::cout << "\nRESOURCE_LIMITS caps the reader's internal storage.\n";
    std::cout << "When the limit is reached, new samples are rejected or\n";
    std::cout << "oldest samples are dropped (depending on history QoS).\n";
    std::cout << "Use this to bound memory in resource-constrained systems.\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool pub_only = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Resource Limits Demo\n";
        std::cout << "QoS: RESOURCE_LIMITS - bound memory for samples/instances\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("ResourceLimitsDemo");

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
