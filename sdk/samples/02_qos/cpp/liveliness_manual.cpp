// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Liveliness Manual (C++)
 *
 * Demonstrates MANUAL_BY_PARTICIPANT liveliness - application must
 * explicitly assert liveliness. Useful for detecting app-level failures.
 *
 * Usage:
 *     ./liveliness_manual        # Subscriber (monitors liveliness)
 *     ./liveliness_manual pub    # Publisher (with manual assertion)
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

constexpr auto LEASE_DURATION = 2000ms;  /* 2 second lease */
constexpr int NUM_MESSAGES = 6;

void run_publisher(hdds::Participant& participant) {
    /* Create writer with MANUAL_BY_PARTICIPANT liveliness */
    auto qos = hdds::QoS::reliable()
        .liveliness_manual_participant(LEASE_DURATION);

    auto writer = participant.create_writer<HelloWorld>("ManualLivenessTopic", qos);

    std::cout << "Publishing with MANUAL_BY_PARTICIPANT liveliness (lease: "
              << LEASE_DURATION.count() << "ms)\n";
    std::cout << "Application must explicitly assert liveliness.\n\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Manual update #" + std::to_string(i + 1));
        /* Writing data implicitly asserts liveliness */
        writer.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << elapsed << "ms] Published id=" << msg.id
                  << " (liveliness asserted via write)\n";

        /* First 3 messages: normal rate
         * Last 3 messages: slow rate (will miss liveliness) */
        if (i < 3) {
            std::this_thread::sleep_for(500ms);  /* OK */
        } else {
            std::cout << "  (simulating slow processing...)\n";
            std::this_thread::sleep_for(2500ms);  /* Exceeds lease! */
        }
    }

    std::cout << "\nPublisher done. Some liveliness violations occurred.\n";
}

void run_subscriber(hdds::Participant& participant) {
    /* Create reader with MANUAL_BY_PARTICIPANT liveliness */
    auto qos = hdds::QoS::reliable()
        .liveliness_manual_participant(LEASE_DURATION);

    auto reader = participant.create_reader<HelloWorld>("ManualLivenessTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Monitoring MANUAL_BY_PARTICIPANT liveliness (lease: "
              << LEASE_DURATION.count() << "ms)...\n";
    std::cout << "Writer must assert liveliness explicitly (by writing).\n\n";

    int received = 0;
    int liveliness_changed = 0;
    auto start = Clock::now();
    auto last_msg = start;

    while (received < NUM_MESSAGES || liveliness_changed < 3) {
        if (waitset.wait(LEASE_DURATION)) {
            while (auto msg = reader.take()) {
                auto now = Clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - start).count();
                auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - last_msg).count();

                std::string status = (delta > LEASE_DURATION.count() && received > 0)
                    ? " [LIVELINESS WAS LOST]" : "";

                std::cout << "  [" << elapsed << "ms] Received id=" << msg->id
                          << " (delta=" << delta << "ms)" << status << "\n";

                last_msg = now;
                received++;
            }
        } else {
            auto now = Clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - start).count();
            auto since_last = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_msg).count();

            if (since_last > LEASE_DURATION.count() && received > 0) {
                std::cout << "  [" << elapsed << "ms] LIVELINESS LOST! (no assertion for "
                          << since_last << "ms)\n";
                liveliness_changed++;
            }

            if (liveliness_changed >= 3) {
                break;
            }
        }
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary: " << received << " messages, "
              << liveliness_changed << " liveliness events detected\n";
    std::cout << "MANUAL liveliness requires explicit app-level assertion.\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Liveliness Manual Demo\n";
        std::cout << "QoS: MANUAL_BY_PARTICIPANT - app must assert liveliness\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("LivelinessManualDemo");

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
