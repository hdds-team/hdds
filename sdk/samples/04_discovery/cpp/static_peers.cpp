// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Static Peers Sample - Demonstrates peer-to-peer communication
 *
 * This sample shows how to use HDDS for communication between
 * specific peers. While HDDS uses automatic multicast discovery
 * by default, this sample demonstrates point-to-point messaging
 * patterns useful in scenarios where:
 * - Networks without multicast support
 * - Cloud/container environments
 * - Explicit peer-to-peer connections
 *
 * Run with different modes:
 *   Terminal 1: ./static_peers --sender
 *   Terminal 2: ./static_peers --receiver
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstring>
#include <unistd.h>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -s, --sender      Run as sender (publisher)\n";
    std::cout << "  -r, --receiver    Run as receiver (subscriber)\n";
    std::cout << "  -d, --domain ID   Use specified domain ID (default: 0)\n";
    std::cout << "  -h, --help        Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  Terminal 1: " << prog << " --receiver\n";
    std::cout << "  Terminal 2: " << prog << " --sender\n";
}

void run_sender(hdds::Participant& participant) {
    std::cout << "\n--- Running as SENDER ---\n";

    // Create writer with reliable QoS for guaranteed delivery
    auto qos = hdds::QoS::reliable().history_depth(10);
    auto writer = participant.create_writer<HelloWorld>("StaticPeersTopic", qos);
    std::cout << "[OK] DataWriter created on topic 'StaticPeersTopic'\n";

    // Give time for discovery
    std::cout << "Waiting for discovery...\n";
    std::this_thread::sleep_for(2s);

    uint32_t instance_id = getpid();
    int msg_count = 0;

    std::cout << "\n--- Sending Messages ---\n";

    while (msg_count < 10) {
        msg_count++;

        std::string msg_text = "Static peer " + std::to_string(instance_id) + " says hello";
        HelloWorld msg(msg_count, msg_text);
        writer.write(msg);
        std::cout << "[SENT] " << msg.message << " #" << msg.id << "\n";

        std::this_thread::sleep_for(2s);
    }

    std::cout << "\n--- Sender Complete ---\n";
}

void run_receiver(hdds::Participant& participant) {
    std::cout << "\n--- Running as RECEIVER ---\n";

    // Create reader with reliable QoS
    auto qos = hdds::QoS::reliable().history_depth(10);
    auto reader = participant.create_reader<HelloWorld>("StaticPeersTopic", qos);
    std::cout << "[OK] DataReader created on topic 'StaticPeersTopic'\n";

    // Create WaitSet for efficient waiting
    hdds::WaitSet waitset;
    waitset.attach(reader.get_status_condition());

    std::cout << "\n--- Waiting for Messages ---\n";
    std::cout << "Run sender in another terminal.\n\n";

    int received_count = 0;
    auto start_time = std::chrono::steady_clock::now();
    auto timeout = 60s;

    while (received_count < 10) {
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed > timeout) {
            std::cout << "\n--- Timeout waiting for messages ---\n";
            break;
        }

        if (waitset.wait(5s)) {
            while (auto msg = reader.take()) {
                std::cout << "[RECV] " << msg->message << " #" << msg->id << "\n";
                received_count++;
            }
        } else {
            std::cout << "[TIMEOUT] No messages, waiting...\n";
        }
    }

    std::cout << "\n--- Receiver Complete ---\n";
    std::cout << "Total messages received: " << received_count << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Static Peers Sample ===\n\n";

    bool is_sender = false;
    bool is_receiver = false;
    uint32_t domain_id = 0;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--sender" || arg == "-s") {
            is_sender = true;
        } else if (arg == "--receiver" || arg == "-r") {
            is_receiver = true;
        } else if (arg == "--domain" || arg == "-d") {
            if (++i < argc) domain_id = std::stoi(argv[i]);
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Default to receiver if nothing specified
    if (!is_sender && !is_receiver) {
        std::cout << "No mode specified. Run with --sender or --receiver.\n";
        std::cout << "Defaulting to receiver mode.\n";
        is_receiver = true;
    }

    std::cout << "Configuration:\n";
    std::cout << "  Mode: " << (is_sender ? "SENDER" : "RECEIVER") << "\n";
    std::cout << "  Domain ID: " << domain_id << "\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating Participant...\n";
        std::string name = is_sender ? "StaticPeersSender" : "StaticPeersReceiver";
        hdds::Participant participant(name, domain_id);

        std::cout << "[OK] Participant created: " << participant.name() << "\n";
        std::cout << "     Domain ID: " << participant.domain_id() << "\n";

        if (is_sender) {
            run_sender(participant);
        } else {
            run_receiver(participant);
        }

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
