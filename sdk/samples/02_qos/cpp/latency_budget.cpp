// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Latency Budget (C++)
 *
 * Demonstrates LATENCY_BUDGET QoS for delivery timing hints.
 * A low budget signals time-critical data; a higher budget allows
 * the middleware to batch or defer delivery for efficiency.
 *
 * Usage:
 *     ./latency_budget        # Subscriber (measures arrival times)
 *     ./latency_budget pub    # Publisher (two topics, different budgets)
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

constexpr int NUM_MESSAGES = 5;

void run_publisher(hdds::Participant& participant) {
    /* Low latency writer - budget = 0ms (deliver immediately) */
    auto qos_low = hdds::QoS::reliable()
        .latency_budget(std::chrono::milliseconds(0));
    auto writer_low = participant.create_writer<HelloWorld>("LowLatencyTopic", qos_low);

    /* Batched writer - budget = 100ms (middleware may defer delivery) */
    auto qos_batched = hdds::QoS::reliable()
        .latency_budget(std::chrono::milliseconds(100));
    auto writer_batched = participant.create_writer<HelloWorld>("BatchedTopic", qos_batched);

    std::cout << "Publishing " << NUM_MESSAGES << " messages on each topic:\n";
    std::cout << "  - LowLatencyTopic:  budget=0ms   (immediate delivery)\n";
    std::cout << "  - BatchedTopic:     budget=100ms  (deferred delivery OK)\n\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg_low(i + 1, "LowLatency #" + std::to_string(i + 1));
        writer_low.write(msg_low);

        auto t1 = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << t1
                  << "ms] Sent LowLatency  id=" << msg_low.id << "\n";

        HelloWorld msg_batched(i + 1, "Batched #" + std::to_string(i + 1));
        writer_batched.write(msg_batched);

        auto t2 = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << t2
                  << "ms] Sent Batched     id=" << msg_batched.id << "\n";

        std::this_thread::sleep_for(200ms);
    }

    std::cout << "\nDone publishing.\n";
    std::cout << "Compare arrival times on the subscriber side.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create readers matching the publisher QoS */
    auto qos_low = hdds::QoS::reliable()
        .latency_budget(std::chrono::milliseconds(0));
    auto reader_low = participant.create_reader<HelloWorld>("LowLatencyTopic", qos_low);

    auto qos_batched = hdds::QoS::reliable()
        .latency_budget(std::chrono::milliseconds(100));
    auto reader_batched = participant.create_reader<HelloWorld>("BatchedTopic", qos_batched);

    hdds::WaitSet waitset;
    waitset.attach(reader_low.get_status_condition());
    waitset.attach(reader_batched.get_status_condition());

    std::cout << "Subscribing to both topics...\n";
    std::cout << "  - LowLatencyTopic:  budget=0ms\n";
    std::cout << "  - BatchedTopic:     budget=100ms\n\n";

    int recv_low = 0;
    int recv_batched = 0;
    int total_expected = NUM_MESSAGES * 2;
    int timeouts = 0;
    auto start = Clock::now();

    while ((recv_low + recv_batched) < total_expected && timeouts < 3) {
        if (waitset.wait(2s)) {
            while (auto msg = reader_low.take()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - start).count();
                std::cout << "  [" << std::setw(5) << elapsed
                          << "ms] LowLatency  RECV id=" << msg->id
                          << " (budget=0ms)\n";
                recv_low++;
            }
            while (auto msg = reader_batched.take()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - start).count();
                std::cout << "  [" << std::setw(5) << elapsed
                          << "ms] Batched     RECV id=" << msg->id
                          << " (budget=100ms)\n";
                recv_batched++;
            }
            timeouts = 0;
        } else {
            timeouts++;
        }
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary:\n";
    std::cout << "  LowLatency (budget=0ms):   " << recv_low
              << " messages received\n";
    std::cout << "  Batched    (budget=100ms):  " << recv_batched
              << " messages received\n";
    std::cout << "\nNote: LATENCY_BUDGET is a hint to the middleware.\n";
    std::cout << "Low budget = prioritize immediate delivery.\n";
    std::cout << "High budget = middleware may batch for efficiency.\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Latency Budget Demo\n";
        std::cout << "QoS: LATENCY_BUDGET - delivery timing hints\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("LatencyBudgetDemo");

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
