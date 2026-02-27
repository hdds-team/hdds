// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Lifespan (C++)
 *
 * Demonstrates LIFESPAN QoS for automatic data expiration.
 * Messages that exceed their lifespan duration are discarded
 * and will not be delivered to late-joining subscribers.
 *
 * Usage:
 *     ./lifespan        # Subscriber (joins after delay)
 *     ./lifespan pub    # Publisher (sends with 2s lifespan)
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

constexpr int NUM_MESSAGES = 10;
constexpr int LIFESPAN_SEC = 2;
constexpr int SUBSCRIBER_DELAY_SEC = 3;
constexpr int PUBLISH_INTERVAL_MS = 500;

void run_publisher(hdds::Participant& participant) {
    /* Create TRANSIENT_LOCAL writer with lifespan - data expires after 2s */
    auto qos = hdds::QoS::reliable()
        .transient_local()
        .lifespan(std::chrono::seconds(LIFESPAN_SEC))
        .history_depth(NUM_MESSAGES);

    auto writer = participant.create_writer<HelloWorld>("LifespanTopic", qos);

    std::cout << "Publishing " << NUM_MESSAGES << " messages with "
              << LIFESPAN_SEC << "s lifespan...\n";
    std::cout << "Messages expire " << LIFESPAN_SEC
              << "s after publication.\n\n";

    auto start = Clock::now();

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg(i + 1, "Data #" + std::to_string(i + 1));
        writer.write(msg);

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - start).count();
        std::cout << "  [" << std::setw(5) << elapsed << "ms] Sent id="
                  << msg.id << " (expires at ~"
                  << (elapsed + LIFESPAN_SEC * 1000) << "ms)\n";

        std::this_thread::sleep_for(std::chrono::milliseconds(PUBLISH_INTERVAL_MS));
    }

    auto total = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start).count();

    std::cout << "\nAll " << NUM_MESSAGES << " messages published over "
              << total << "ms.\n";
    std::cout << "Early messages will have expired by the time a late subscriber joins.\n";
    std::cout << "Waiting for late-joining subscribers...\n";
    std::cout << "(Run './lifespan' in another terminal within a few seconds)\n";

    /* Keep writer alive long enough for subscriber to join */
    std::this_thread::sleep_for(10s);
    std::cout << "\nPublisher exiting.\n";
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "Delaying subscriber startup by " << SUBSCRIBER_DELAY_SEC
              << "s to let some messages expire...\n\n";

    std::this_thread::sleep_for(std::chrono::seconds(SUBSCRIBER_DELAY_SEC));

    /* Create TRANSIENT_LOCAL reader to receive cached data */
    auto qos = hdds::QoS::reliable().transient_local();
    auto reader = participant.create_reader<HelloWorld>("LifespanTopic", qos);

    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "Subscriber joined after " << SUBSCRIBER_DELAY_SEC
              << "s delay.\n";
    std::cout << "Messages older than " << LIFESPAN_SEC
              << "s should have expired.\n\n";

    int received = 0;
    int timeouts = 0;
    auto start = Clock::now();

    while (timeouts < 2) {
        if (waitset.wait(2s)) {
            while (auto msg = reader.take()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - start).count();

                std::cout << "  [" << std::setw(5) << elapsed
                          << "ms] Received id=" << msg->id
                          << " msg='" << msg->message << "'\n";
                received++;
            }
            timeouts = 0;
        } else {
            timeouts++;
        }
    }

    std::cout << "\n" << std::string(60, '-') << "\n";
    std::cout << "Summary: Received " << received << " of " << NUM_MESSAGES
              << " messages\n";
    std::cout << "Messages published more than " << LIFESPAN_SEC
              << "s ago were expired by LIFESPAN QoS.\n";

    int expected_expired = SUBSCRIBER_DELAY_SEC * 1000 / PUBLISH_INTERVAL_MS;
    if (expected_expired > NUM_MESSAGES) expected_expired = NUM_MESSAGES;

    std::cout << "Expected ~" << (NUM_MESSAGES - expected_expired)
              << " surviving messages (first ~" << expected_expired
              << " expired).\n";
    std::cout << std::string(60, '-') << "\n";
}

int main(int argc, char** argv) {
    bool is_publisher = (argc > 1 && std::strcmp(argv[1], "pub") == 0);

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        std::cout << std::string(60, '=') << "\n";
        std::cout << "Lifespan Demo\n";
        std::cout << "QoS: LIFESPAN - automatic data expiration after duration\n";
        std::cout << std::string(60, '=') << "\n";

        hdds::Participant participant("LifespanDemo");

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
