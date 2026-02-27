// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Zero Copy (C)
 *
 * Demonstrates zero-copy data sharing concepts.
 * Shows how to minimize data copies for large payloads.
 *
 * Usage:
 *     ./zero_copy
 *
 * Key concepts:
 * - Intra-process: Direct pointer sharing
 * - Inter-process: Shared memory segments
 * - Loan API: Borrow buffers from middleware
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for Zero-Copy / Shared Memory Loans.
 * The native Zero-Copy / Shared Memory Loans API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define LARGE_PAYLOAD_SIZE (1024 * 1024)  /* 1 MB */
#define NUM_ITERATIONS 100

uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void print_zero_copy_overview(void) {
    printf("--- Zero-Copy Overview ---\n\n");
    printf("Traditional copy path:\n");
    printf("  App -> [COPY] -> DDS Buffer -> [COPY] -> Network\n");
    printf("  Network -> [COPY] -> DDS Buffer -> [COPY] -> App\n\n");

    printf("Zero-copy path:\n");
    printf("  App -> [SHARED MEMORY] -> App\n");
    printf("  (No copies for intra-host communication)\n\n");

    printf("Benefits:\n");
    printf("  - Eliminates memory copies for large payloads\n");
    printf("  - Reduces CPU usage\n");
    printf("  - Lower latency for large messages\n");
    printf("  - Better cache utilization\n\n");
}

typedef struct {
    double copy_time_ms;
    double zero_copy_time_ms;
    double speedup;
    uint64_t bytes_transferred;
} benchmark_result_t;

benchmark_result_t benchmark_copy_vs_zerocopy(size_t payload_size, int iterations) {
    benchmark_result_t result = {0};
    result.bytes_transferred = payload_size * iterations;

    void* src_buffer = malloc(payload_size);
    void* dst_buffer = malloc(payload_size);
    memset(src_buffer, 0xAB, payload_size);

    /* Benchmark with copy */
    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        memcpy(dst_buffer, src_buffer, payload_size);
        ((char*)dst_buffer)[0] = (char)i;  /* Prevent optimization */
    }
    uint64_t copy_time = get_time_ns() - start;
    result.copy_time_ms = copy_time / 1e6;

    /* Benchmark zero-copy (pointer assignment only) */
    start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        void* ptr = src_buffer;  /* Just pointer assignment */
        ((char*)ptr)[0] = (char)i;  /* Prevent optimization */
    }
    uint64_t zc_time = get_time_ns() - start;
    result.zero_copy_time_ms = zc_time / 1e6;

    result.speedup = result.copy_time_ms / (result.zero_copy_time_ms > 0 ? result.zero_copy_time_ms : 0.001);

    free(src_buffer);
    free(dst_buffer);

    return result;
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("Zero-Copy Demo\n");
    printf("Eliminating memory copies for large payloads\n");
    printf("============================================================\n\n");
    printf("NOTE: CONCEPT DEMO - Native Zero-Copy / Shared Memory Loans API not yet in SDK.\n");
    printf("      Using standard pub/sub API to demonstrate the pattern.\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    print_zero_copy_overview();

    printf("--- Zero-Copy Configuration ---\n");
    printf("  Shared Memory: Conceptually enabled\n");
    printf("  Loan API: Conceptually enabled\n");
    printf("  (Full implementation via future HDDS features)\n\n");

    struct HddsParticipant* participant = hdds_participant_create("ZeroCopyDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n\n", hdds_participant_name(participant));

    /* Create endpoints */
    struct HddsDataWriter* writer = hdds_writer_create(participant, "LargeData");
    struct HddsDataReader* reader = hdds_reader_create(participant, "LargeData");

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] Endpoints created for 'LargeData' topic\n\n");

    /* Demonstrate loan API concept */
    printf("--- Loan API Concept ---\n\n");

    printf("Writer loan pattern:\n");
    printf("  1. void* buffer = hdds_writer_loan_sample(writer, size);\n");
    printf("  2. Fill buffer with data (no copy needed)\n");
    printf("  3. hdds_writer_write_loaned(writer, buffer, size);\n");
    printf("  4. Ownership transferred to middleware\n\n");

    printf("Reader loan pattern:\n");
    printf("  1. sample_t* sample = hdds_reader_take_loan(reader);\n");
    printf("  2. Access sample->data directly (no copy)\n");
    printf("  3. hdds_reader_return_loan(reader, sample);\n\n");

    /* Simulate large data send */
    printf("Simulating large data transfer...\n");

    void* large_buffer = malloc(LARGE_PAYLOAD_SIZE);
    memset(large_buffer, 0xCD, LARGE_PAYLOAD_SIZE);

    /* Can only write the standard way for now */
    HelloWorld msg = {.id = 1};
    strncpy(msg.message, "Large data reference", sizeof(msg.message) - 1);

    uint8_t buffer[256];
    size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
    hdds_writer_write(writer, buffer, len);

    printf("[OK] Reference message sent (actual large data would use loan API)\n\n");
    free(large_buffer);

    /* Performance comparison */
    printf("--- Performance Comparison ---\n\n");

    size_t sizes[] = {1024, 64*1024, 256*1024, 1024*1024, 4*1024*1024};
    const char* labels[] = {"1 KB", "64 KB", "256 KB", "1 MB", "4 MB"};

    printf("| Payload | With Copy | Zero-Copy | Speedup |\n");
    printf("|---------|-----------|-----------|--------|\n");

    for (int i = 0; i < 5; i++) {
        benchmark_result_t r = benchmark_copy_vs_zerocopy(sizes[i], NUM_ITERATIONS);
        printf("| %7s | %7.2f ms | %7.3f ms | %5.0fx  |\n",
               labels[i], r.copy_time_ms, r.zero_copy_time_ms, r.speedup);
    }

    /* When to use zero-copy */
    printf("\n--- When to Use Zero-Copy ---\n\n");
    printf("Recommended when:\n");
    printf("  - Payload size > 64 KB\n");
    printf("  - Same-host communication\n");
    printf("  - High message rates with large payloads\n");
    printf("  - CPU is bottleneck\n\n");

    printf("Not recommended when:\n");
    printf("  - Small payloads (< 1 KB)\n");
    printf("  - Cross-network communication\n");
    printf("  - Security isolation required\n");

    /* Memory considerations */
    printf("\n--- Memory Considerations ---\n\n");
    printf("For shared memory (when available):\n");
    printf("  - /dev/shm size (Linux): check with 'df -h /dev/shm'\n");
    printf("  - Segment size: must fit all loaned samples\n");
    printf("  - Cleanup: segments persist until removed\n");

    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Zero-Copy Demo Complete ===\n");
    return 0;
}
