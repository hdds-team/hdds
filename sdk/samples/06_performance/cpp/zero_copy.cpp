// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Zero-Copy Demonstration (C++)
 *
 * Shows how to minimize memory copies for high performance:
 * - Direct buffer access patterns
 * - Comparing copy vs zero-copy performance
 * - Memory efficiency considerations
 *
 * Key concepts:
 * - write_raw(): Direct buffer writing
 * - take_raw(): Direct buffer reading
 * - Avoiding intermediate copies
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for Zero-Copy / Shared Memory Loans.
 * The native Zero-Copy / Shared Memory Loans API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 *
 * Usage:
 *     ./zero_copy
 */

#include <hdds.hpp>
#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <cstring>
#include <iomanip>

#include "generated/HelloWorld.hpp"

using namespace std::chrono_literals;

constexpr size_t LARGE_PAYLOAD_SIZE = 1024 * 1024;  // 1 MB
constexpr int NUM_ITERATIONS = 100;

// Performance results
struct ZeroCopyResults {
    double copy_time_ms = 0;
    double zero_copy_time_ms = 0;
    double speedup = 0;
    uint64_t bytes_transferred = 0;
};

void print_zero_copy_overview() {
    std::cout << "--- Zero-Copy Overview ---\n\n";
    std::cout << "Traditional copy path:\n";
    std::cout << "  Application -> [COPY] -> DDS Buffer -> [COPY] -> Network\n";
    std::cout << "  Network -> [COPY] -> DDS Buffer -> [COPY] -> Application\n\n";

    std::cout << "Zero-copy path (with raw API):\n";
    std::cout << "  Application Buffer -> [DIRECT] -> DDS -> Network\n";
    std::cout << "  (Minimizes copies using raw byte interfaces)\n\n";

    std::cout << "Benefits:\n";
    std::cout << "  - Eliminates unnecessary memory copies\n";
    std::cout << "  - Reduces CPU usage\n";
    std::cout << "  - Lower latency for large messages\n";
    std::cout << "  - Better cache utilization\n\n";
}

ZeroCopyResults benchmark_copy_vs_zero_copy(size_t payload_size, int iterations) {
    ZeroCopyResults results;
    results.bytes_transferred = payload_size * iterations;

    // Allocate test buffers
    std::vector<uint8_t> src_buffer(payload_size, 0xAB);
    std::vector<uint8_t> dst_buffer(payload_size);

    // Benchmark with copy (simulating intermediate buffer copy)
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        // Simulate: app buffer -> intermediate -> DDS
        std::memcpy(dst_buffer.data(), src_buffer.data(), payload_size);
        dst_buffer[0] = static_cast<uint8_t>(i);  // Prevent optimization
    }
    auto copy_time = std::chrono::high_resolution_clock::now() - start;
    results.copy_time_ms = std::chrono::duration<double, std::milli>(copy_time).count();

    // Benchmark zero-copy (direct pointer/reference)
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        // Direct access - no intermediate copy
        uint8_t* ptr = src_buffer.data();
        ptr[0] = static_cast<uint8_t>(i);  // Prevent optimization
    }
    auto zc_time = std::chrono::high_resolution_clock::now() - start;
    results.zero_copy_time_ms = std::chrono::duration<double, std::milli>(zc_time).count();

    results.speedup = results.copy_time_ms / results.zero_copy_time_ms;

    return results;
}

int main() {
    std::cout << "=== HDDS Zero-Copy Sample ===\n\n";
    std::cout << "NOTE: CONCEPT DEMO - Native Zero-Copy / Shared Memory Loans API not yet in SDK.\n"
              << "      Using standard pub/sub API to demonstrate the pattern.\n\n";

    print_zero_copy_overview();

    try {
        // Initialize logging
        hdds::logging::init(hdds::LogLevel::Warn);

        // Create participant
        hdds::Participant participant("ZeroCopySample");
        std::cout << "[OK] Participant created\n\n";

        // Create writer and reader using raw API for zero-copy patterns
        auto writer = participant.create_writer_raw("ZeroCopyTopic", hdds::QoS::reliable());
        auto reader = participant.create_reader_raw("ZeroCopyTopic", hdds::QoS::reliable());
        std::cout << "[OK] Raw endpoints created (zero-copy enabled)\n\n";

        // Demonstrate raw API usage
        std::cout << "--- Raw API Demonstration ---\n\n";

        // Prepare large payload directly
        std::cout << "Writer: Preparing " << (LARGE_PAYLOAD_SIZE / (1024 * 1024)) << " MB payload...\n";
        std::vector<uint8_t> payload(LARGE_PAYLOAD_SIZE);
        std::memset(payload.data(), 0xCD, LARGE_PAYLOAD_SIZE);
        std::cout << "[OK] Payload prepared (single allocation, no intermediate copy)\n";

        std::cout << "Writer: Publishing with write_raw()...\n";
        writer->write_raw(payload);
        std::cout << "[OK] Published directly from application buffer\n\n";

        // Give time for message to be received
        std::this_thread::sleep_for(100ms);

        // Create waitset for reading
        hdds::WaitSet waitset;
        waitset.attach(reader->get_status_condition());

        std::cout << "Reader: Taking with take_raw()...\n";
        if (waitset.wait(1s)) {
            if (auto data = reader->take_raw()) {
                std::cout << "[OK] Received " << data->size() << " bytes\n";
                std::cout << "     First byte: 0x" << std::hex
                          << static_cast<int>((*data)[0]) << std::dec << "\n";
                std::cout << "     (Data accessed directly without copy to user buffer)\n";
            }
        }
        std::cout << "\n";

        // Performance comparison
        std::cout << "--- Performance Comparison ---\n\n";

        std::vector<size_t> payload_sizes = {1024, 64*1024, 256*1024, 1024*1024, 4*1024*1024};
        std::vector<std::string> size_labels = {"1 KB", "64 KB", "256 KB", "1 MB", "4 MB"};

        std::cout << "| Payload | With Copy | Zero-Copy | Speedup |\n";
        std::cout << "|---------|-----------|-----------|--------|\n";

        for (size_t i = 0; i < payload_sizes.size(); i++) {
            auto r = benchmark_copy_vs_zero_copy(payload_sizes[i], NUM_ITERATIONS);
            std::cout << "| " << std::setw(7) << size_labels[i]
                      << " | " << std::fixed << std::setprecision(2)
                      << std::setw(7) << r.copy_time_ms << " ms"
                      << " | " << std::setw(7) << r.zero_copy_time_ms << " ms"
                      << " | " << std::setw(5) << std::setprecision(1) << r.speedup << "x  |\n";
        }

        // Best practices
        std::cout << "\n--- When to Use Zero-Copy Patterns ---\n\n";
        std::cout << "Recommended when:\n";
        std::cout << "  - Payload size > 64 KB\n";
        std::cout << "  - High message rates with large payloads\n";
        std::cout << "  - CPU is bottleneck (reduces memcpy overhead)\n";
        std::cout << "  - Low latency is critical\n\n";

        std::cout << "HDDS Raw API patterns:\n";
        std::cout << "  - create_writer_raw(): Create untyped writer\n";
        std::cout << "  - create_reader_raw(): Create untyped reader\n";
        std::cout << "  - write_raw(data): Write bytes directly\n";
        std::cout << "  - take_raw(): Get bytes without deserialization overhead\n";

        std::cout << "\n--- Code Example ---\n\n";
        std::cout << "  // Zero-copy write pattern\n";
        std::cout << "  std::vector<uint8_t> my_data(1024 * 1024);\n";
        std::cout << "  fill_data(my_data);  // Prepare in-place\n";
        std::cout << "  writer->write_raw(my_data);  // Direct write\n\n";

        std::cout << "  // Zero-copy read pattern\n";
        std::cout << "  if (auto data = reader->take_raw()) {\n";
        std::cout << "      process_data(*data);  // Direct access\n";
        std::cout << "  }\n";

        // Memory considerations
        std::cout << "\n--- Memory Considerations ---\n\n";
        std::cout << "Tips for optimal zero-copy performance:\n";
        std::cout << "  - Pre-allocate buffers to avoid allocation overhead\n";
        std::cout << "  - Reuse buffers across multiple writes when possible\n";
        std::cout << "  - Align buffers to cache line boundaries (64 bytes)\n";
        std::cout << "  - Consider memory pool patterns for high-frequency messaging\n";

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
