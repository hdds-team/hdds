// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Throughput Benchmark (C++)
 *
 * Measures maximum message throughput:
 * - Publisher sends messages as fast as possible
 * - Subscriber counts received messages
 * - Calculate messages/sec and MB/sec
 *
 * Key concepts:
 * - Sustained throughput measurement
 * - Variable payload sizes
 * - Publisher and subscriber modes
 *
 * Usage:
 *     # Terminal 1 - Subscriber
 *     ./throughput --sub
 *
 *     # Terminal 2 - Publisher
 *     ./throughput --pub -d 10 -z 256
 */

#include <hdds.hpp>
#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>
#include <iomanip>

#include "generated/HelloWorld.hpp"

using namespace std::chrono_literals;

constexpr int DEFAULT_PAYLOAD_SIZE = 256;
constexpr int DEFAULT_DURATION_SEC = 10;
constexpr int MAX_PAYLOAD_SIZE = 64 * 1024;

// Throughput statistics
struct ThroughputStats {
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    double duration_sec = 0;
    double msg_per_sec = 0;
    double mb_per_sec = 0;
};

static std::atomic<bool> running{true};

void signal_handler(int) {
    running = false;
}

uint64_t get_time_ns() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();
}

void calculate_stats(ThroughputStats& stats, bool is_publisher) {
    if (stats.duration_sec <= 0) return;

    if (is_publisher) {
        stats.msg_per_sec = stats.messages_sent / stats.duration_sec;
        stats.mb_per_sec = (stats.bytes_sent / (1024.0 * 1024.0)) / stats.duration_sec;
    } else {
        stats.msg_per_sec = stats.messages_received / stats.duration_sec;
        stats.mb_per_sec = (stats.bytes_received / (1024.0 * 1024.0)) / stats.duration_sec;
    }
}

void print_progress(const ThroughputStats& stats, int elapsed_sec, bool is_publisher) {
    double current_msg_sec = is_publisher ?
        (stats.messages_sent / static_cast<double>(elapsed_sec)) :
        (stats.messages_received / static_cast<double>(elapsed_sec));

    double current_mb_sec = is_publisher ?
        ((stats.bytes_sent / (1024.0 * 1024.0)) / elapsed_sec) :
        ((stats.bytes_received / (1024.0 * 1024.0)) / elapsed_sec);

    std::cout << "  [" << std::setw(2) << elapsed_sec << " sec] "
              << std::fixed << std::setprecision(0) << current_msg_sec << " msg/s, "
              << std::setprecision(2) << current_mb_sec << " MB/s\n";
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -p, --pub          Run as publisher (default)\n";
    std::cout << "  -s, --sub          Run as subscriber\n";
    std::cout << "  -d, --duration N   Test duration in seconds (default: " << DEFAULT_DURATION_SEC << ")\n";
    std::cout << "  -z, --size N       Payload size in bytes (default: " << DEFAULT_PAYLOAD_SIZE << ")\n";
    std::cout << "  -h, --help         Show this help\n";
}

void run_publisher(hdds::Participant& participant, int duration_sec, uint32_t payload_size) {
    std::cout << "Creating DataWriter..." << std::endl;

    // Use best-effort QoS for maximum throughput
    auto writer = participant.create_writer_raw("ThroughputTopic", hdds::QoS::best_effort());
    std::cout << "[OK] DataWriter created\n";

    // Prepare message buffer
    std::vector<uint8_t> msg_buffer(payload_size + sizeof(uint64_t) * 2);
    size_t total_msg_size = msg_buffer.size();

    std::cout << "\n--- Running Throughput Test ---\n";
    std::cout << "Press Ctrl+C to stop early.\n\n";
    std::cout << "Publishing messages...\n\n";

    ThroughputStats stats;
    auto start_time = std::chrono::steady_clock::now();
    int last_progress_sec = 0;

    while (running) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - start_time).count();

        if (elapsed >= duration_sec) break;

        // Prepare and send message
        uint64_t seq = stats.messages_sent;
        uint64_t timestamp = get_time_ns();
        std::memcpy(msg_buffer.data(), &seq, sizeof(seq));
        std::memcpy(msg_buffer.data() + sizeof(uint64_t), &timestamp, sizeof(timestamp));

        writer->write_raw(msg_buffer);

        stats.messages_sent++;
        stats.bytes_sent += total_msg_size;

        // Progress update every second
        int current_sec = static_cast<int>(elapsed);
        if (current_sec > last_progress_sec) {
            print_progress(stats, current_sec, true);
            last_progress_sec = current_sec;
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    stats.duration_sec = std::chrono::duration<double>(end_time - start_time).count();

    calculate_stats(stats, true);

    // Print results
    std::cout << "\n--- Throughput Results ---\n\n";
    std::cout << std::fixed;
    std::cout << "Messages sent:     " << stats.messages_sent << "\n";
    std::cout << "Bytes sent:        " << stats.bytes_sent << " ("
              << std::setprecision(2) << (stats.bytes_sent / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "Duration:          " << std::setprecision(2) << stats.duration_sec << " seconds\n\n";

    std::cout << "Throughput:\n";
    std::cout << "  Messages/sec:    " << std::setprecision(0) << stats.msg_per_sec << "\n";
    std::cout << "  MB/sec:          " << std::setprecision(2) << stats.mb_per_sec << "\n";
    std::cout << "  Gbps:            " << std::setprecision(2) << (stats.mb_per_sec * 8 / 1024) << "\n";
}

void run_subscriber(hdds::Participant& participant, int duration_sec, uint32_t payload_size) {
    std::cout << "Creating DataReader..." << std::endl;

    auto reader = participant.create_reader_raw("ThroughputTopic", hdds::QoS::best_effort());
    std::cout << "[OK] DataReader created\n";

    hdds::WaitSet waitset;
    waitset.attach(reader->get_status_condition());

    size_t total_msg_size = payload_size + sizeof(uint64_t) * 2;

    std::cout << "\n--- Running Throughput Test ---\n";
    std::cout << "Press Ctrl+C to stop early.\n\n";
    std::cout << "Receiving messages...\n\n";

    ThroughputStats stats;
    auto start_time = std::chrono::steady_clock::now();
    int last_progress_sec = 0;

    while (running) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - start_time).count();

        if (elapsed >= duration_sec) break;

        // Wait for data with short timeout
        if (waitset.wait(100ms)) {
            while (auto data = reader->take_raw()) {
                stats.messages_received++;
                stats.bytes_received += data->size();
            }
        }

        // Progress update every second
        int current_sec = static_cast<int>(elapsed);
        if (current_sec > last_progress_sec && current_sec > 0) {
            print_progress(stats, current_sec, false);
            last_progress_sec = current_sec;
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    stats.duration_sec = std::chrono::duration<double>(end_time - start_time).count();

    calculate_stats(stats, false);

    // Print results
    std::cout << "\n--- Throughput Results ---\n\n";
    std::cout << std::fixed;
    std::cout << "Messages received: " << stats.messages_received << "\n";
    std::cout << "Bytes received:    " << stats.bytes_received << " ("
              << std::setprecision(2) << (stats.bytes_received / (1024.0 * 1024.0)) << " MB)\n";
    std::cout << "Duration:          " << std::setprecision(2) << stats.duration_sec << " seconds\n\n";

    std::cout << "Throughput:\n";
    std::cout << "  Messages/sec:    " << std::setprecision(0) << stats.msg_per_sec << "\n";
    std::cout << "  MB/sec:          " << std::setprecision(2) << stats.mb_per_sec << "\n";
    std::cout << "  Gbps:            " << std::setprecision(2) << (stats.mb_per_sec * 8 / 1024) << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Throughput Benchmark ===\n\n";

    // Parse arguments
    bool is_publisher = true;
    int duration_sec = DEFAULT_DURATION_SEC;
    uint32_t payload_size = DEFAULT_PAYLOAD_SIZE;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" || arg == "--pub") {
            is_publisher = true;
        } else if (arg == "-s" || arg == "--sub") {
            is_publisher = false;
        } else if ((arg == "-d" || arg == "--duration") && i + 1 < argc) {
            duration_sec = std::atoi(argv[++i]);
        } else if ((arg == "-z" || arg == "--size") && i + 1 < argc) {
            payload_size = std::atoi(argv[++i]);
            if (payload_size > MAX_PAYLOAD_SIZE) payload_size = MAX_PAYLOAD_SIZE;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
    }

    size_t total_msg_size = payload_size + sizeof(uint64_t) * 2;

    std::cout << "Configuration:\n";
    std::cout << "  Mode: " << (is_publisher ? "PUBLISHER" : "SUBSCRIBER") << "\n";
    std::cout << "  Duration: " << duration_sec << " seconds\n";
    std::cout << "  Payload size: " << payload_size << " bytes\n";
    std::cout << "  Message size: " << total_msg_size << " bytes (with header)\n\n";

    // Setup signal handler
    std::signal(SIGINT, signal_handler);

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        hdds::Participant participant("ThroughputBenchmark");
        std::cout << "[OK] Participant created\n";

        if (is_publisher) {
            run_publisher(participant, duration_sec, payload_size);
        } else {
            run_subscriber(participant, duration_sec, payload_size);
        }

        std::cout << "\n=== Benchmark Complete ===\n";

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
