// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * WaitSets Sample - Demonstrates condition-based event handling
 *
 * WaitSets allow efficient waiting on multiple conditions:
 * - ReadConditions: data available on readers
 * - StatusConditions: entity status changes
 * - GuardConditions: application-triggered events
 *
 * Key concepts:
 * - WaitSet creation and condition attachment
 * - Blocking vs timeout-based waiting
 * - Condition dispatching
 *
 * Uses the real HDDS C++ API for WaitSet operations.
 */

#include <hdds.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <cstring>
#include <atomic>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

void print_waitset_overview() {
    std::cout << "--- WaitSet Overview ---\n\n";
    std::cout << "WaitSet Architecture:\n\n";
    std::cout << "  +------------------------------------------+\n";
    std::cout << "  |               WaitSet                    |\n";
    std::cout << "  |  +-------------+ +-------------+         |\n";
    std::cout << "  |  | StatusCond  | | StatusCond  |         |\n";
    std::cout << "  |  | (Reader A)  | | (Reader B)  |         |\n";
    std::cout << "  |  +-------------+ +-------------+         |\n";
    std::cout << "  |  +-------------+                         |\n";
    std::cout << "  |  | GuardCond   |                         |\n";
    std::cout << "  |  | (Shutdown)  |                         |\n";
    std::cout << "  |  +-------------+                         |\n";
    std::cout << "  +------------------------------------------+\n";
    std::cout << "                    |\n";
    std::cout << "                    v\n";
    std::cout << "              wait(timeout)\n";
    std::cout << "                    |\n";
    std::cout << "                    v\n";
    std::cout << "         Condition triggered!\n";
    std::cout << "\n";
    std::cout << "Condition Types:\n";
    std::cout << "  - StatusCondition: Data available / entity status\n";
    std::cout << "  - GuardCondition: Application-triggered signal\n";
    std::cout << "\n";
}

void run_publisher(hdds::Participant& participant) {
    std::cout << "--- Publisher Mode ---\n\n";

    // Create writers for multiple topics
    auto sensor_writer = participant.create_writer_raw("SensorTopic", hdds::QoS::reliable());
    auto command_writer = participant.create_writer_raw("CommandTopic", hdds::QoS::reliable());

    std::cout << "[OK] Writers created for SensorTopic and CommandTopic\n\n";

    // Publish sensor data
    std::cout << "Publishing sensor data...\n";
    for (int i = 0; i < 5; i++) {
        HelloWorld msg(i, "Sensor reading");
        auto data = msg.serialize();
        sensor_writer->write_raw(data);
        std::cout << "  Published sensor data: id=" << i << "\n";
        std::this_thread::sleep_for(300ms);
    }

    // Publish commands
    std::cout << "\nPublishing commands...\n";
    for (int i = 0; i < 3; i++) {
        HelloWorld msg(i, "Command");
        auto data = msg.serialize();
        command_writer->write_raw(data);
        std::cout << "  Published command: id=" << i << "\n";
        std::this_thread::sleep_for(300ms);
    }

    // More sensor data
    std::cout << "\nPublishing more sensor data...\n";
    for (int i = 5; i < 8; i++) {
        HelloWorld msg(i, "Sensor reading");
        auto data = msg.serialize();
        sensor_writer->write_raw(data);
        std::cout << "  Published sensor data: id=" << i << "\n";
        std::this_thread::sleep_for(300ms);
    }

    std::cout << "\nDone publishing.\n";
}

void run_subscriber(hdds::Participant& participant) {
    std::cout << "--- Subscriber Mode ---\n\n";

    // Create readers for multiple topics
    auto sensor_reader = participant.create_reader_raw("SensorTopic", hdds::QoS::reliable());
    auto command_reader = participant.create_reader_raw("CommandTopic", hdds::QoS::reliable());

    std::cout << "[OK] Readers created for SensorTopic and CommandTopic\n";

    // Create WaitSet
    hdds::WaitSet waitset;
    std::cout << "[OK] WaitSet created\n";

    // Attach conditions
    auto sensor_cond = sensor_reader->get_status_condition();
    auto command_cond = command_reader->get_status_condition();

    waitset.attach(sensor_cond);
    std::cout << "[OK] StatusCondition for SensorTopic attached\n";

    waitset.attach(command_cond);
    std::cout << "[OK] StatusCondition for CommandTopic attached\n";

    // Create guard condition for shutdown
    hdds::GuardCondition shutdown_guard;
    waitset.attach(shutdown_guard);
    std::cout << "[OK] GuardCondition 'shutdown' attached\n\n";

    // Demonstrate waiting
    std::cout << "--- WaitSet Event Loop ---\n\n";
    std::cout << "Waiting for data (Ctrl+C to exit)...\n\n";

    int sensor_count = 0;
    int command_count = 0;
    int timeout_count = 0;
    int max_timeouts = 5;

    while (timeout_count < max_timeouts) {
        // Wait with timeout
        if (waitset.wait(2s)) {
            // Check sensor reader
            while (auto sample = sensor_reader->take_raw()) {
                auto msg = HelloWorld::deserialize(sample->data(), sample->size());
                std::cout << "[SENSOR] Received: " << msg.message
                          << " (id=" << msg.id << ")\n";
                sensor_count++;
            }

            // Check command reader
            while (auto sample = command_reader->take_raw()) {
                auto msg = HelloWorld::deserialize(sample->data(), sample->size());
                std::cout << "[COMMAND] Received: " << msg.message
                          << " (id=" << msg.id << ")\n";
                command_count++;
            }

            timeout_count = 0; // Reset timeout counter on activity
        } else {
            timeout_count++;
            std::cout << "[TIMEOUT] No data (" << timeout_count << "/" << max_timeouts << ")\n";
        }
    }

    // Summary
    std::cout << "\n--- Summary ---\n\n";
    std::cout << "Sensor messages received: " << sensor_count << "\n";
    std::cout << "Command messages received: " << command_count << "\n";

    // Cleanup - detach conditions
    std::cout << "\n--- Cleanup ---\n\n";
    waitset.detach(sensor_cond);
    std::cout << "[OK] Detached sensor condition\n";
    waitset.detach(command_cond);
    std::cout << "[OK] Detached command condition\n";
    waitset.detach(shutdown_guard);
    std::cout << "[OK] Detached shutdown guard\n";
}

void demonstrate_guard_condition() {
    std::cout << "\n--- GuardCondition Demo ---\n\n";
    std::cout << "GuardConditions are manually triggered by the application:\n\n";

    hdds::GuardCondition guard;
    hdds::WaitSet waitset;
    waitset.attach(guard);

    std::cout << "  Created GuardCondition and attached to WaitSet\n";

    // Trigger from another thread
    std::thread trigger_thread([&guard]() {
        std::this_thread::sleep_for(500ms);
        std::cout << "  [Thread] Triggering guard condition...\n";
        guard.trigger();
    });

    std::cout << "  Waiting for guard condition...\n";

    if (waitset.wait(2s)) {
        std::cout << "  [WaitSet] Guard condition triggered!\n";
    } else {
        std::cout << "  [WaitSet] Timeout\n";
    }

    trigger_thread.join();
    std::cout << "  Done.\n";
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS WaitSets Sample ===\n\n";

    bool is_publisher = (argc > 1) &&
        (std::strcmp(argv[1], "pub") == 0 ||
         std::strcmp(argv[1], "publisher") == 0 ||
         std::strcmp(argv[1], "-p") == 0);

    print_waitset_overview();

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating participant..." << std::endl;
        hdds::Participant participant("WaitSetDemo");
        std::cout << "[OK] Participant created\n\n";

        if (is_publisher) {
            run_publisher(participant);
        } else {
            run_subscriber(participant);
        }

        // Demonstrate guard condition
        demonstrate_guard_condition();

        // Event loop pattern
        std::cout << "\n--- Event Loop Pattern ---\n\n";
        std::cout << "Typical WaitSet event loop (C++):\n\n";
        std::cout << "  while (running) {\n";
        std::cout << "      if (waitset.wait(timeout)) {\n";
        std::cout << "          // Check each reader for data\n";
        std::cout << "          while (auto sample = reader->take_raw()) {\n";
        std::cout << "              process(sample);\n";
        std::cout << "          }\n";
        std::cout << "      }\n";
        std::cout << "  }\n\n";

        // Best practices
        std::cout << "--- WaitSet Best Practices ---\n\n";
        std::cout << "1. Use one WaitSet per processing thread\n";
        std::cout << "2. Prefer WaitSets over polling for efficiency\n";
        std::cout << "3. Use GuardConditions for inter-thread signaling\n";
        std::cout << "4. Set appropriate timeouts for responsiveness\n";
        std::cout << "5. Process all available data before waiting again\n";
        std::cout << "6. Detach conditions before destroying readers\n";

        std::cout << "\n=== Sample Complete ===\n";

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
