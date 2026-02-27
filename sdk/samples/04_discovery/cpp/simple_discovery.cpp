// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Simple Discovery Sample - Demonstrates automatic multicast discovery
 *
 * This sample shows how DDS participants automatically discover each other
 * using SPDP (Simple Participant Discovery Protocol) over multicast.
 *
 * Run multiple instances to see them discover each other:
 *   Terminal 1: ./simple_discovery
 *   Terminal 2: ./simple_discovery
 *
 * Key concepts:
 * - Automatic peer discovery via multicast
 * - No manual configuration required
 * - Domain ID for logical separation
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <unistd.h>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Simple Discovery Sample ===\n\n";

    // Get instance ID from args or use PID
    uint32_t instance_id = (argc > 1) ? std::atoi(argv[1]) : getpid();

    std::cout << "Instance ID: " << instance_id << "\n";
    std::cout << "Domain ID: 0 (default)\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant with default discovery settings
        // Multicast discovery is enabled by default
        std::cout << "Creating Participant...\n";
        hdds::Participant participant("SimpleDiscovery_" + std::to_string(instance_id));

        std::cout << "[OK] Participant created: " << participant.name() << "\n";
        std::cout << "     Domain ID: " << participant.domain_id() << "\n";
        std::cout << "     Participant ID: " << static_cast<int>(participant.participant_id()) << "\n";

        // Create writer and reader for demonstration
        auto qos = hdds::QoS::reliable().history_depth(10);

        std::cout << "\nCreating DataWriter on topic 'DiscoveryDemo'...\n";
        auto writer = participant.create_writer<HelloWorld>("DiscoveryDemo", qos);
        std::cout << "[OK] DataWriter created\n";

        std::cout << "Creating DataReader on topic 'DiscoveryDemo'...\n";
        auto reader = participant.create_reader<HelloWorld>("DiscoveryDemo", qos);
        std::cout << "[OK] DataReader created\n";

        // Create WaitSet for efficient waiting
        hdds::WaitSet waitset;
        waitset.attach(reader.get_status_condition());

        std::cout << "\n--- Discovery in Progress ---\n";
        std::cout << "Waiting for other participants to join...\n";
        std::cout << "(Run another instance of this sample to see discovery)\n\n";

        // Announce ourselves periodically
        int announce_count = 0;

        while (announce_count < 10) {
            announce_count++;

            // Create and send announcement message
            HelloWorld msg(announce_count, "Hello from instance " + std::to_string(instance_id));
            writer.write(msg);
            std::cout << "[SENT] " << msg.message << " (id=" << msg.id << ")\n";

            // Wait for messages with timeout
            if (waitset.wait(500ms)) {
                // Check for received messages
                while (auto received_msg = reader.take()) {
                    std::cout << "[RECV] " << received_msg->message
                              << " (id=" << received_msg->id << ")\n";
                }
            }

            // Wait before next announcement
            std::this_thread::sleep_for(2s);
        }

        std::cout << "\n--- Sample Complete (10 announcements sent) ---\n";
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
