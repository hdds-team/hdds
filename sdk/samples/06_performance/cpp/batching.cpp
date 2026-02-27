// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Batching Demonstration (C++)
 *
 * Shows how batching improves throughput:
 * - Batch multiple messages into single network packet
 * - Reduce per-message overhead
 * - Trade latency for throughput
 *
 * Key concepts:
 * - history_depth: Queue depth for batching
 * - Comparing batched vs unbatched performance
 * - Network efficiency metrics
 *
 * Usage:
 *     ./batching
 */

#include <hdds.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <cstring>
#include <iomanip>

#include "generated/HelloWorld.hpp"

using namespace std::chrono_literals;

constexpr int MESSAGE_SIZE = 64;
constexpr int NUM_MESSAGES = 10000;

// Batch statistics
struct BatchStats {
    uint64_t messages_sent = 0;
    uint64_t batches_sent = 0;
    uint64_t bytes_sent = 0;
    double duration_sec = 0;
    double avg_batch_size = 0;
    double msg_per_sec = 0;
};

void print_comparison(const std::string& label, const BatchStats& stats) {
    std::cout << std::left << std::setw(20) << label
              << std::right << std::setw(8) << stats.messages_sent << " msgs, "
              << std::setw(6) << stats.batches_sent << " batches, "
              << std::fixed << std::setprecision(0)
              << std::setw(8) << stats.msg_per_sec << " msg/s, avg batch: "
              << std::setprecision(1) << stats.avg_batch_size << " msgs\n";
}

BatchStats run_batched_test(hdds::Participant& participant,
                            const std::string& topic_suffix,
                            int batch_size,
                            int num_messages) {
    BatchStats stats;

    // Create writer with history depth to simulate batching behavior
    auto qos = hdds::QoS::best_effort().history_depth(batch_size > 0 ? batch_size : 1);
    auto writer = participant.create_writer_raw("BatchTopic" + topic_suffix, qos);

    // Prepare message
    std::vector<uint8_t> msg_data(MESSAGE_SIZE, 'X');

    auto start = std::chrono::high_resolution_clock::now();

    if (batch_size > 0) {
        // Batched sending: accumulate messages before implicit flush
        int current_batch = 0;

        for (int i = 0; i < num_messages; i++) {
            // Update sequence in message
            uint32_t seq = i;
            std::memcpy(msg_data.data(), &seq, sizeof(seq));

            writer->write_raw(msg_data);
            stats.messages_sent++;
            stats.bytes_sent += MESSAGE_SIZE;
            current_batch++;

            // Simulate batch boundary
            if (current_batch >= batch_size) {
                stats.batches_sent++;
                current_batch = 0;
                // Small delay to simulate batch transmission
                std::this_thread::sleep_for(std::chrono::microseconds(1));
            }
        }

        // Count remaining partial batch
        if (current_batch > 0) {
            stats.batches_sent++;
        }
    } else {
        // Non-batched: each message is its own batch
        for (int i = 0; i < num_messages; i++) {
            uint32_t seq = i;
            std::memcpy(msg_data.data(), &seq, sizeof(seq));

            writer->write_raw(msg_data);
            stats.messages_sent++;
            stats.bytes_sent += MESSAGE_SIZE;
            stats.batches_sent++;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    stats.duration_sec = std::chrono::duration<double>(end - start).count();
    stats.msg_per_sec = stats.messages_sent / stats.duration_sec;
    stats.avg_batch_size = static_cast<double>(stats.messages_sent) / stats.batches_sent;

    return stats;
}

int main() {
    std::cout << "=== HDDS Batching Sample ===\n\n";

    std::cout << "--- Batching Overview ---\n\n";
    std::cout << "Batching combines multiple messages into fewer network packets:\n";
    std::cout << "  - Reduces per-message overhead (headers, syscalls)\n";
    std::cout << "  - Improves throughput significantly\n";
    std::cout << "  - Adds slight latency (batch accumulation time)\n\n";

    std::cout << "Configuration Parameters:\n";
    std::cout << "  history_depth:    Queue depth affects batching behavior\n";
    std::cout << "  QoS settings:     Reliability affects batching efficiency\n";
    std::cout << "  Message size:     Larger messages benefit less from batching\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        hdds::Participant participant("BatchingSample");
        std::cout << "[OK] Participant created\n\n";

        std::cout << "--- Running Batching Comparison ---\n";
        std::cout << "Sending " << NUM_MESSAGES << " messages of " << MESSAGE_SIZE << " bytes each...\n\n";

        // Test configurations: batch sizes (0 = no batching)
        std::vector<int> batch_sizes = {0, 16, 64, 128, 256, 1024};
        std::vector<std::string> labels = {
            "No batching:",
            "Batch 16:",
            "Batch 64:",
            "Batch 128:",
            "Batch 256:",
            "Batch 1024:",
        };

        std::vector<BatchStats> results;

        for (size_t i = 0; i < batch_sizes.size(); i++) {
            auto stats = run_batched_test(participant, std::to_string(i), batch_sizes[i], NUM_MESSAGES);
            results.push_back(stats);
            print_comparison(labels[i], stats);
        }

        // Calculate improvement
        std::cout << "\n--- Performance Improvement ---\n\n";

        double baseline = results[0].msg_per_sec;
        for (size_t i = 1; i < results.size(); i++) {
            double improvement = ((results[i].msg_per_sec / baseline) - 1.0) * 100;
            std::cout << labels[i] << " " << std::fixed << std::setprecision(0)
                      << improvement << "% faster than no batching\n";
        }

        // Network efficiency
        std::cout << "\n--- Network Efficiency ---\n\n";
        std::cout << "| Configuration | Messages | Packets | Efficiency |\n";
        std::cout << "|---------------|----------|---------|------------|\n";

        for (size_t i = 0; i < results.size(); i++) {
            double efficiency = static_cast<double>(results[i].messages_sent) / results[i].batches_sent;
            std::cout << "| " << std::left << std::setw(13) << labels[i]
                      << " | " << std::right << std::setw(8) << results[i].messages_sent
                      << " | " << std::setw(7) << results[i].batches_sent
                      << " | " << std::fixed << std::setprecision(1) << std::setw(5) << efficiency << "x     |\n";
        }

        // Best practices
        std::cout << "\n--- Batching Best Practices ---\n\n";
        std::cout << "1. Choose batch size based on network MTU (typically 1500 bytes)\n";
        std::cout << "2. For low-latency: smaller batches or disable batching\n";
        std::cout << "3. For high-throughput: larger batches (8KB-64KB)\n";
        std::cout << "4. Use reliable QoS for guaranteed delivery with batching\n";
        std::cout << "5. Consider history_depth to control queue behavior\n";

        // Latency trade-off
        std::cout << "\n--- Latency vs Throughput Trade-off ---\n\n";
        std::cout << "| Batch Size | Throughput | Added Latency    |\n";
        std::cout << "|------------|------------|------------------|\n";
        std::cout << "| None       | Baseline   | ~0 us            |\n";
        std::cout << "| 16 msgs    | ~2x        | ~10-50 us        |\n";
        std::cout << "| 128 msgs   | ~5x        | ~50-200 us       |\n";
        std::cout << "| 1024 msgs  | ~10x       | ~100-500 us      |\n";

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
