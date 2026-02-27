// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Latency Benchmark (C++)
 *
 * Measures round-trip latency using ping-pong pattern:
 * - Publisher sends timestamped message
 * - Subscriber echoes back
 * - Publisher calculates round-trip time
 *
 * Key concepts:
 * - High-resolution timestamps
 * - Latency percentiles (p50, p99, p99.9)
 * - Histogram analysis
 *
 * Usage:
 *     # Terminal 1 - Pong (responder)
 *     ./latency --pong
 *
 *     # Terminal 2 - Ping (initiator)
 *     ./latency 1000
 */

#include <hdds.hpp>
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <chrono>
#include <thread>
#include <cstring>
#include <iomanip>

#include "generated/HelloWorld.hpp"

using namespace std::chrono_literals;

constexpr int MAX_SAMPLES = 10000;
constexpr int WARMUP_SAMPLES = 100;
constexpr int PAYLOAD_SIZE = 64;

// Latency statistics
struct LatencyStats {
    std::vector<double> samples;
    double min = 0;
    double max = 0;
    double mean = 0;
    double std_dev = 0;
    double p50 = 0;
    double p90 = 0;
    double p99 = 0;
    double p999 = 0;
};

// Get current time in nanoseconds
uint64_t get_time_ns() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();
}

// Calculate percentile
double percentile(const std::vector<double>& sorted, double p) {
    if (sorted.empty()) return 0.0;
    double idx = (p / 100.0) * (sorted.size() - 1);
    size_t lo = static_cast<size_t>(idx);
    size_t hi = lo + 1;
    if (hi >= sorted.size()) hi = sorted.size() - 1;
    double frac = idx - lo;
    return sorted[lo] * (1 - frac) + sorted[hi] * frac;
}

// Calculate latency statistics
void calculate_stats(LatencyStats& stats) {
    if (stats.samples.empty()) return;

    // Sort for percentiles
    std::sort(stats.samples.begin(), stats.samples.end());

    // Min/Max
    stats.min = stats.samples.front();
    stats.max = stats.samples.back();

    // Mean
    stats.mean = std::accumulate(stats.samples.begin(), stats.samples.end(), 0.0)
                 / stats.samples.size();

    // Standard deviation
    double sq_sum = 0;
    for (double s : stats.samples) {
        double diff = s - stats.mean;
        sq_sum += diff * diff;
    }
    stats.std_dev = std::sqrt(sq_sum / stats.samples.size());

    // Percentiles
    stats.p50 = percentile(stats.samples, 50);
    stats.p90 = percentile(stats.samples, 90);
    stats.p99 = percentile(stats.samples, 99);
    stats.p999 = percentile(stats.samples, 99.9);
}

// Print histogram
void print_histogram(const std::vector<double>& samples) {
    if (samples.empty()) return;

    std::vector<int> buckets(20, 0);
    double min_val = samples.front();
    double max_val = samples.back();
    double range = max_val - min_val;
    if (range == 0) range = 1;

    for (double s : samples) {
        int bucket = static_cast<int>((s - min_val) / range * 19);
        if (bucket >= 20) bucket = 19;
        buckets[bucket]++;
    }

    int max_count = *std::max_element(buckets.begin(), buckets.end());

    std::cout << "\nLatency Distribution:\n";
    for (int i = 0; i < 20; i++) {
        double bucket_min = min_val + (range * i / 20);
        double bucket_max = min_val + (range * (i + 1) / 20);
        int bar_len = (max_count > 0) ? (buckets[i] * 40 / max_count) : 0;

        std::cout << std::fixed << std::setprecision(1);
        std::cout << std::setw(7) << bucket_min << "-" << std::setw(7) << bucket_max << " us |";
        std::cout << std::string(bar_len, '#') << " " << buckets[i] << "\n";
    }
}

// Serialize timestamp to bytes
std::vector<uint8_t> serialize_ping(uint64_t seq, uint64_t timestamp_ns) {
    std::vector<uint8_t> data(sizeof(uint64_t) * 2 + PAYLOAD_SIZE);
    std::memcpy(data.data(), &seq, sizeof(seq));
    std::memcpy(data.data() + sizeof(uint64_t), &timestamp_ns, sizeof(timestamp_ns));
    return data;
}

// Deserialize timestamp from bytes
void deserialize_ping(const uint8_t* data, size_t len, uint64_t& seq, uint64_t& timestamp_ns) {
    if (len >= sizeof(uint64_t) * 2) {
        std::memcpy(&seq, data, sizeof(seq));
        std::memcpy(&timestamp_ns, data + sizeof(uint64_t), sizeof(timestamp_ns));
    }
}

void run_ping(hdds::Participant& participant, int num_samples) {
    std::cout << "Creating ping writer and reader..." << std::endl;

    // Create writer for ping topic, reader for pong topic
    auto ping_writer = participant.create_writer_raw("LatencyPing", hdds::QoS::reliable());
    auto pong_reader = participant.create_reader_raw("LatencyPong", hdds::QoS::reliable());

    // Wait for subscriber
    hdds::WaitSet waitset;
    waitset.attach(pong_reader->get_status_condition());

    std::cout << "[OK] Endpoints created\n";
    std::cout << "\n--- Running Latency Test ---\n";
    std::cout << "Waiting for pong responder...\n\n";

    // Allow time for discovery
    std::this_thread::sleep_for(1s);

    // Latency statistics
    LatencyStats stats;
    stats.samples.reserve(num_samples);

    // Warmup
    std::cout << "Running warmup (" << WARMUP_SAMPLES << " samples)...\n";

    for (int i = 0; i < WARMUP_SAMPLES; i++) {
        auto data = serialize_ping(i, get_time_ns());
        ping_writer->write_raw(data);

        // Wait for pong response
        if (waitset.wait(1s)) {
            pong_reader->take_raw();
        }
        std::this_thread::sleep_for(1ms);
    }

    // Measurement
    std::cout << "Running measurement (" << num_samples << " samples)...\n\n";

    for (int i = 0; i < num_samples; i++) {
        uint64_t send_time = get_time_ns();
        auto data = serialize_ping(WARMUP_SAMPLES + i, send_time);

        ping_writer->write_raw(data);

        // Wait for pong response
        if (waitset.wait(1s)) {
            auto response = pong_reader->take_raw();
            if (response) {
                uint64_t recv_time = get_time_ns();
                double rtt_us = (recv_time - send_time) / 1000.0;
                stats.samples.push_back(rtt_us);
            }
        }

        if ((i + 1) % (num_samples / 10) == 0) {
            std::cout << "  Progress: " << (i + 1) << "/" << num_samples << " samples\n";
        }
    }

    // Calculate statistics
    calculate_stats(stats);

    // Print results
    std::cout << "\n--- Latency Results ---\n\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Round-trip latency (microseconds):\n";
    std::cout << "  Min:    " << std::setw(8) << stats.min << " us\n";
    std::cout << "  Max:    " << std::setw(8) << stats.max << " us\n";
    std::cout << "  Mean:   " << std::setw(8) << stats.mean << " us\n";
    std::cout << "  StdDev: " << std::setw(8) << stats.std_dev << " us\n";
    std::cout << "\n";
    std::cout << "Percentiles:\n";
    std::cout << "  p50:    " << std::setw(8) << stats.p50 << " us (median)\n";
    std::cout << "  p90:    " << std::setw(8) << stats.p90 << " us\n";
    std::cout << "  p99:    " << std::setw(8) << stats.p99 << " us\n";
    std::cout << "  p99.9:  " << std::setw(8) << stats.p999 << " us\n";

    // Print histogram
    print_histogram(stats.samples);

    // One-way latency estimate
    std::cout << "\n--- One-Way Latency Estimate ---\n";
    std::cout << "  Estimated: " << (stats.p50 / 2) << " us (RTT/2)\n";
}

void run_pong(hdds::Participant& participant) {
    std::cout << "Creating pong reader and writer..." << std::endl;

    // Create reader for ping topic, writer for pong topic
    auto ping_reader = participant.create_reader_raw("LatencyPing", hdds::QoS::reliable());
    auto pong_writer = participant.create_writer_raw("LatencyPong", hdds::QoS::reliable());

    hdds::WaitSet waitset;
    waitset.attach(ping_reader->get_status_condition());

    std::cout << "[OK] Endpoints created\n";
    std::cout << "\n--- Running as Pong Responder ---\n";
    std::cout << "Waiting for ping messages (Ctrl+C to exit)...\n\n";

    uint64_t messages_echoed = 0;

    while (true) {
        if (waitset.wait(5s)) {
            while (auto data = ping_reader->take_raw()) {
                // Echo back immediately
                pong_writer->write_raw(*data);
                messages_echoed++;

                if (messages_echoed % 1000 == 0) {
                    std::cout << "  Echoed " << messages_echoed << " messages\n";
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    std::cout << "=== HDDS Latency Benchmark ===\n\n";

    int num_samples = (argc > 1 && std::string(argv[1]) != "--pong") ? std::atoi(argv[1]) : 1000;
    if (num_samples > MAX_SAMPLES) num_samples = MAX_SAMPLES;

    bool is_pong = (argc > 1 && std::string(argv[argc - 1]) == "--pong");

    std::cout << "Configuration:\n";
    std::cout << "  Samples: " << num_samples << " (+ " << WARMUP_SAMPLES << " warmup)\n";
    std::cout << "  Payload: " << PAYLOAD_SIZE << " bytes\n";
    std::cout << "  Mode: " << (is_pong ? "PONG (responder)" : "PING (initiator)") << "\n\n";

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        hdds::Participant participant("LatencyBenchmark");
        std::cout << "[OK] Participant created\n";

        if (is_pong) {
            run_pong(participant);
        } else {
            run_ping(participant, num_samples);
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
