// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Deadline Monitor (C++)
 *
 * Demonstrates DEADLINE QoS for monitoring update rates.
 * Publisher must send data within deadline or violation is reported.
 *
 * Usage:
 *     ./deadline_monitor        # Subscriber (monitors deadline)
 *     ./deadline_monitor pub    # Publisher (normal rate)
 *     ./deadline_monitor slow   # Publisher (misses deadlines)
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

constexpr int DEADLINE_MS = 500;  /* 500ms deadline period */
constexpr int NUM_MESSAGES = 10;

void run_publisher(hdds::Participant& participant, bool slow_mode) {
    /* Create writer with deadline QoS */
    auto qos = hdds::QoS::reliable().deadline(std::chrono::milliseconds(DEADLINE_MS));
    auto writer = participant.create_writer<HelloWorld>("DeadlineTopic", qos);

    auto interval = slow_mode ? 800ms : 300ms;

    std::cout << "Publishing with " << interval.count() << "ms interval (deadline: "
              << DEADLINE_MS << "ms)\n";
    if (slow_mode) {
        std::cout << "WARNING: This will MISS deadlines!\n";
    } else {
        std::cout << "This should meet all deadlines.\n";
    }
    std::cout << "\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Update #" + std::to_string(i + 1));
        writer.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << elapsed << "ms] Sent id=" << msg.id << "\n";

        std::this_thread::sleep_for(interval);
    }

    std::cout << "\nDone publishing.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create reader with deadline QoS */
    auto qos = hdds::QoS::reliable().deadline(std::chrono::milliseconds(DEADLINE_MS));
    auto reader = participant.create_reader<HelloWorld>("DeadlineTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Monitoring for deadline violations (deadline: " << DEADLINE_MS << "ms)...\n\n";

    int received = 0;
    int deadline_violations = 0;
    auto start = Clock::now();
    auto last_recv = start;

    while (received < NUM_MESSAGES) {
        if (waitset.wait(std::chrono::milliseconds(DEADLINE_MS * 2))) {
            while (auto msg = reader.take()) {
                auto now = Clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - start).count();
                auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - last_recv).count();

                std::string status = (delta > DEADLINE_MS && received > 0)
                    ? "DEADLINE MISSED!" : "OK";

                if (delta > DEADLINE_MS && received > 0) {
                    deadline_violations++;
                }

                std::cout << "  [" << std::setw(5) << elapsed << "ms] Received id="
                          << msg->id << " (delta=" << delta << "ms) " << status << "\n";

                last_recv = now;
                received++;
            }
        } else {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - start).count();
            std::cout << "  [" << std::setw(5) << elapsed
                      << "ms] DEADLINE VIOLATION - no data received!\n";
            deadline_violations++;
        }
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary: " << received << " messages received, "
              << deadline_violations << " deadline violations\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);
    bool slow_mode = (argc > 1 && std::strcmp(argv[1], "slow") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Deadline Monitor Demo\n";
        std::cout << "QoS: DEADLINE - monitor update rate violations\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("DeadlineDemo");

        if (is_publisher || slow_mode) {
            run_publisher(participant, slow_mode);
        } else {
            run_subscriber(participant);
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
