// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Liveliness Automatic (C++)
 *
 * Demonstrates AUTOMATIC liveliness - system automatically asserts
 * liveliness via heartbeats. Reader detects when writer goes offline.
 *
 * Usage:
 *     ./liveliness_auto        # Subscriber (monitors liveliness)
 *     ./liveliness_auto pub    # Publisher (sends periodic data)
 */

#include <hdds.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

constexpr auto LEASE_DURATION = 1000ms;  /* 1 second lease */
constexpr int NUM_MESSAGES = 8;

void run_publisher(hdds::Participant& participant) {
    /* Create writer with AUTOMATIC liveliness */
    auto qos = hdds::QoS::reliable()
        .liveliness_automatic(LEASE_DURATION);

    auto writer = participant.create_writer<HelloWorld>("LivelinessTopic", qos);

    std::cout << "Publishing with AUTOMATIC liveliness (lease: "
              << LEASE_DURATION.count() << "ms)\n";
    std::cout << "System automatically sends heartbeats to maintain liveliness.\n\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Heartbeat #" + std::to_string(i + 1));
        writer.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << elapsed << "ms] Published id=" << msg.id
                  << " - writer is ALIVE\n";

        std::this_thread::sleep_for(400ms);  /* Faster than lease */
    }

    std::cout << "\nPublisher going offline. Subscriber should detect liveliness lost.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create reader with AUTOMATIC liveliness */
    auto qos = hdds::QoS::reliable()
        .liveliness_automatic(LEASE_DURATION);

    auto reader = participant.create_reader<HelloWorld>("LivelinessTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Monitoring AUTOMATIC liveliness (lease: "
              << LEASE_DURATION.count() << "ms)...\n";
    std::cout << "Will detect if writer goes offline.\n\n";

    int received = 0;
    int liveliness_lost_count = 0;
    auto start = Clock::now();
    auto last_msg = start;

    while (received < NUM_MESSAGES + 2) {
        if (waitset.wait(LEASE_DURATION * 2)) {
            while (auto msg = reader.take()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - start).count();
                std::cout << "  [" << elapsed << "ms] Received id=" << msg->id
                          << " - writer ALIVE\n";

                last_msg = Clock::now();
                received++;
            }
        } else {
            auto now = Clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - start).count();
            auto since_last = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_msg).count();

            if (since_last > LEASE_DURATION.count()) {
                std::cout << "  [" << elapsed << "ms] LIVELINESS LOST - no heartbeat for "
                          << since_last << "ms!\n";
                liveliness_lost_count++;

                if (liveliness_lost_count >= 2) {
                    break;
                }
            }
        }
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary: " << received << " messages, liveliness lost "
              << liveliness_lost_count << " times\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Liveliness Automatic Demo\n";
        std::cout << "QoS: AUTOMATIC liveliness - system heartbeats\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("LivelinessAutoDemo");

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
