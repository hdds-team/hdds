// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Telemetry Dashboard - Monitor DDS performance metrics in real-time (C++)
 *
 * Demonstrates HDDS telemetry with RAII: initializes metrics, creates
 * pub/sub, records latency for each write/read cycle, takes periodic
 * snapshots, and starts a Prometheus-compatible exporter.
 *
 * Build:
 *     cd build && cmake .. && make telemetry_dashboard
 *
 * Usage:
 *     ./telemetry_dashboard
 *
 * Expected output:
 *     --- Snapshot #1 ---
 *     Messages sent: 10 | received: 10
 *     Latency p50: 0.12 ms | p99: 0.45 ms
 *     ...
 */

#include <hdds.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <cstring>
#include <vector>

#include "generated/HelloWorld.hpp"

using namespace hdds_samples;
using namespace std::chrono_literals;

static constexpr int BATCH_SIZE = 10;
static constexpr int NUM_BATCHES = 5;
static constexpr uint16_t EXPORTER_PORT = 4242;

static uint64_t now_ns() {
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(t).count();
}

static void print_snapshot(const hdds::MetricsSnapshot& snap, int idx) {
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "--- Snapshot #" << idx << " ---\n";
    std::cout << "  Messages sent:     " << snap.messages_sent
              << "   | received: " << snap.messages_received << "\n";
    std::cout << "  Messages dropped:  " << snap.messages_dropped << "\n";
    std::cout << "  Bytes sent:        " << snap.bytes_sent << "\n";
    std::cout << "  Latency p50: " << snap.latency_p50_ms()
              << " ms | p99: " << snap.latency_p99_ms()
              << " ms | p999: " << snap.latency_p999_ms() << " ms\n";
    std::cout << "  Backpressure: merge_full=" << snap.merge_full_count
              << ", would_block=" << snap.would_block_count << "\n\n";
}

int main() {
    std::cout << "============================================================\n";
    std::cout << "HDDS Telemetry Dashboard (C++)\n";
    std::cout << "============================================================\n\n";

    try {
        hdds::logging::init(hdds::LogLevel::Warn);

        // Initialize telemetry (RAII - auto-releases)
        auto metrics = hdds::telemetry::init();
        std::cout << "[OK] Telemetry initialized\n";

        // Create participant and endpoints
        hdds::Participant participant("TelemetryDashboard");
        auto writer = participant.create_writer_raw("TelemetryTopic",
                                                     hdds::QoS::reliable());
        auto reader = participant.create_reader_raw("TelemetryTopic",
                                                     hdds::QoS::reliable());
        std::cout << "[OK] Pub/Sub created on 'TelemetryTopic'\n";

        // Start exporter
        auto exporter = hdds::telemetry::start_exporter("0.0.0.0", EXPORTER_PORT);
        std::cout << "[OK] Exporter running on 0.0.0.0:" << EXPORTER_PORT << "\n\n";

        // Write/read cycles with latency measurement
        for (int batch = 0; batch < NUM_BATCHES; batch++) {
            for (int i = 0; i < BATCH_SIZE; i++) {
                // Serialize a simple payload
                int32_t id = batch * BATCH_SIZE + i;
                std::vector<uint8_t> payload(4);
                std::memcpy(payload.data(), &id, 4);

                uint64_t start = now_ns();
                writer->write_raw(payload);

                // Try to read back
                auto sample = reader->take_raw();
                uint64_t end = now_ns();

                metrics.record_latency(start, end);
            }

            // Snapshot after each batch
            auto snap = metrics.snapshot();
            print_snapshot(snap, batch + 1);
        }

        // Final summary
        std::cout << "=== Dashboard Summary ===\n";
        auto final_snap = metrics.snapshot();
        std::cout << "Total messages sent: " << final_snap.messages_sent << "\n";
        std::cout << "Total bytes sent:    " << final_snap.bytes_sent << "\n";
        std::cout << "Final p99 latency:   " << final_snap.latency_p99_ms()
                  << " ms\n\n";

        // RAII: exporter, metrics, participant all cleaned up automatically
        exporter.stop();

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "=== Telemetry Dashboard Complete ===\n";
    return 0;
}
