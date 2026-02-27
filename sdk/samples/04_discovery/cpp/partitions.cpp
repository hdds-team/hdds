// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Partitions Sample - Demonstrates logical data separation with partitions
 *
 * Partitions provide a way to logically separate data within a domain.
 * Only endpoints with matching partitions will communicate.
 *
 * Key concepts:
 * - QoS partition configuration
 * - Partition-based filtering
 * - Multiple partition membership
 *
 * Run multiple instances with different partitions:
 *   ./partitions --partition "SensorA"
 *   ./partitions --partition "SensorB"
 *   ./partitions --partition "SensorA" --partition "SensorB"  (receives from both)
 */

#include <hdds.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <thread>
#include <unistd.h>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -p, --partition NAME   Add partition (can be repeated)\n";
    std::cout << "  -s, --sender           Run as sender only\n";
    std::cout << "  -r, --receiver         Run as receiver only\n";
    std::cout << "  -h, --help             Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog << " --partition SensorA\n";
    std::cout << "  " << prog << " --partition SensorA --partition SensorB\n";
    std::cout << "  " << prog << " --partition SensorA --sender\n";
}

std::string partitions_to_string(const std::vector<std::string>& partitions) {
    std::string result = "[";
    for (size_t i = 0; i < partitions.size(); ++i) {
        if (i > 0) result += ", ";
        result += "\"" + partitions[i] + "\"";
    }
    result += "]";
    return result;
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Partitions Sample ===\n\n";

    std::vector<std::string> partitions;
    bool sender_only = false;
    bool receiver_only = false;

    // Simple argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-p" || arg == "--partition") {
            if (i + 1 < argc) {
                partitions.push_back(argv[++i]);
            }
        } else if (arg == "-s" || arg == "--sender") {
            sender_only = true;
        } else if (arg == "-r" || arg == "--receiver") {
            receiver_only = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Default partition if none specified
    if (partitions.empty()) {
        partitions.push_back("DefaultPartition");
    }

    std::cout << "Configuration:\n";
    std::cout << "  Partitions: " << partitions_to_string(partitions) << "\n";
    std::cout << "  Mode: " << (sender_only ? "SENDER" : (receiver_only ? "RECEIVER" : "BOTH")) << "\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        std::cout << "Creating Participant...\n";
        hdds::Participant participant("Partitions");
        std::cout << "[OK] Participant created: " << participant.name() << "\n";

        // Build QoS with partition(s)
        // The partition() method adds a partition to the QoS
        auto writer_qos = hdds::QoS::reliable().history_depth(10);
        auto reader_qos = hdds::QoS::reliable().history_depth(10);

        for (const auto& partition : partitions) {
            writer_qos.partition(partition);
            reader_qos.partition(partition);
        }

        std::optional<hdds::TypedDataWriter<HelloWorld>> writer;
        std::optional<hdds::TypedDataReader<HelloWorld>> reader;

        // Create writer if not receiver-only
        if (!receiver_only) {
            std::cout << "\nCreating DataWriter with partitions "
                      << partitions_to_string(partitions) << "...\n";
            writer.emplace(participant.create_writer<HelloWorld>("PartitionDemo", writer_qos));
            std::cout << "[OK] DataWriter created\n";
        }

        // Create reader if not sender-only
        if (!sender_only) {
            std::cout << "Creating DataReader with partitions "
                      << partitions_to_string(partitions) << "...\n";
            reader.emplace(participant.create_reader<HelloWorld>("PartitionDemo", reader_qos));
            std::cout << "[OK] DataReader created\n";
        }

        std::cout << "\n--- Partition Matching Rules ---\n";
        std::cout << "Two endpoints match if they share at least one partition.\n";
        std::cout << "Empty partition list means 'default' partition.\n\n";

        std::cout << "--- Communication Loop ---\n";
        std::cout << "Only endpoints in matching partitions will communicate.\n\n";

        // Create WaitSet if we have a reader
        std::optional<hdds::WaitSet> waitset;
        if (reader) {
            waitset.emplace();
            waitset->attach(reader->get_status_condition());
        }

        uint32_t instance_id = getpid();

        for (int msg_count = 1; msg_count <= 10; ++msg_count) {
            // Send message if we have a writer
            if (writer) {
                std::string msg_text = "Message from partition " + partitions_to_string(partitions);
                HelloWorld msg(msg_count, msg_text);
                writer->write(msg);
                std::cout << "[SEND] " << msg.message << " #" << msg.id << "\n";
            }

            // Receive messages if we have a reader
            if (reader && waitset) {
                if (waitset->wait(500ms)) {
                    while (auto msg = reader->take()) {
                        std::cout << "[RECV] " << msg->message << " #" << msg->id << "\n";
                    }
                }
            }

            std::this_thread::sleep_for(2s);
        }

        // Summary
        std::cout << "\n--- Partition Summary ---\n";
        std::cout << "Configured partitions: " << partitions_to_string(partitions) << "\n";
        std::cout << "Messages sent: " << (writer ? 10 : 0) << "\n";

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
