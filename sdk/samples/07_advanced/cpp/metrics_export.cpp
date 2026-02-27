// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Metrics Export - Focused telemetry exporter example (C++)
 *
 * Initializes telemetry, starts a TCP exporter on port 9090,
 * records 1000 latency samples, takes a final snapshot, and stops.
 * Uses RAII for automatic resource cleanup.
 *
 * Build:
 *     cd build && cmake .. && make metrics_export
 *
 * Usage:
 *     ./metrics_export
 *
 * Expected output:
 *     [OK] Exporter listening on 127.0.0.1:9090
 *     Recording 1000 latency samples...
 *     --- Final Metrics ---
 *     Latency p50: 0.001 ms | p99: 0.003 ms
 */

#include <hdds.hpp>
#include <iostream>
#include <iomanip>
#include <chrono>

static constexpr int NUM_SAMPLES = 1000;
static constexpr uint16_t EXPORTER_PORT = 9090;

static uint64_t now_ns() {
    auto t = std::chrono::high_resolution_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(t).count();
}

/* Simulate work with a busy loop */
static void simulate_work() {
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
    (void)x;
}

int main() {
    std::cout << "============================================================\n";
    std::cout << "HDDS Metrics Export Sample (C++)\n";
    std::cout << "============================================================\n\n";

    try {
        // Initialize telemetry
        auto metrics = hdds::telemetry::init();
        std::cout << "[OK] Telemetry initialized\n";

        // Start exporter (RAII - stops on destruction)
        auto exporter = hdds::telemetry::start_exporter("127.0.0.1", EXPORTER_PORT);
        std::cout << "[OK] Exporter listening on 127.0.0.1:" << EXPORTER_PORT << "\n\n";

        // Record latency samples
        std::cout << "Recording " << NUM_SAMPLES << " latency samples...\n";

        for (int i = 0; i < NUM_SAMPLES; i++) {
            uint64_t start = now_ns();
            simulate_work();
            uint64_t end = now_ns();

            metrics.record_latency(start, end);

            if ((i + 1) % 250 == 0) {
                std::cout << "  ... " << (i + 1) << "/" << NUM_SAMPLES << "\n";
            }
        }

        // Final snapshot
        std::cout << std::fixed << std::setprecision(4);
        std::cout << "\n--- Final Metrics ---\n";

        auto snap = metrics.snapshot();
        std::cout << "  Latency p50:  " << snap.latency_p50_ms() << " ms\n";
        std::cout << "  Latency p99:  " << snap.latency_p99_ms() << " ms\n";
        std::cout << "  Latency p999: " << snap.latency_p999_ms() << " ms\n";
        std::cout << "  Messages sent: " << snap.messages_sent
                  << " | received: " << snap.messages_received << "\n";

        std::cout << "\nStopping exporter...\n";
        exporter.stop();

    } catch (const hdds::Error& e) {
        std::cerr << "HDDS Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\n=== Metrics Export Complete ===\n";
    return 0;
}
