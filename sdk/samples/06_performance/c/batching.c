// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Batching (C)
 *
 * Demonstrates message batching for improved throughput.
 * Batching combines multiple messages into fewer network packets.
 *
 * Usage:
 *     ./batching
 *
 * Key concepts:
 * - Batch multiple messages per network send
 * - Reduce per-message overhead
 * - Trade-off between latency and throughput
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 1000
#define MESSAGE_SIZE 64

uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

typedef struct {
    uint64_t messages;
    uint64_t batches;
    double duration_ms;
    double msg_per_sec;
    double avg_batch_size;
} batch_result_t;

batch_result_t run_batch_test(struct HddsParticipant* participant, int batch_size) {
    batch_result_t result = {0};

    struct HddsQoS* qos = hdds_qos_best_effort();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "BatchTest", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return result;
    }

    uint64_t start = get_time_ns();

    int current_batch = 0;
    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg = {.id = i};
        snprintf(msg.message, sizeof(msg.message), "Msg %d batch %d", i, (int)result.batches);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        hdds_writer_write(writer, buffer, len);
        result.messages++;
        current_batch += len;

        /* Simulate batch boundary */
        if (batch_size > 0 && current_batch >= batch_size) {
            result.batches++;
            current_batch = 0;
            usleep(10);  /* Small delay between batches */
        } else if (batch_size == 0) {
            result.batches++;
            usleep(10);  /* No batching - one message per "batch" */
        }
    }

    /* Final partial batch */
    if (current_batch > 0) {
        result.batches++;
    }

    uint64_t end = get_time_ns();
    result.duration_ms = (end - start) / 1e6;
    result.msg_per_sec = result.messages / (result.duration_ms / 1000.0);
    result.avg_batch_size = (double)result.messages / result.batches;

    hdds_writer_destroy(writer);
    return result;
}

void print_comparison(const char* label, batch_result_t* r) {
    printf("%-16s %6lu msgs, %5lu batches, %8.0f msg/s, avg: %.1f msg/batch\n",
           label, r->messages, r->batches, r->msg_per_sec, r->avg_batch_size);
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("Batching Demo\n");
    printf("Message batching for improved throughput\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    printf("--- Batching Overview ---\n\n");
    printf("Batching combines multiple messages into fewer packets:\n");
    printf("  - Reduces per-message overhead (headers, syscalls)\n");
    printf("  - Improves throughput significantly\n");
    printf("  - Adds slight latency (batch accumulation time)\n\n");

    struct HddsParticipant* participant = hdds_participant_create("BatchingDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n\n", hdds_participant_name(participant));

    printf("--- Running Batching Comparison ---\n");
    printf("Sending %d messages of ~%d bytes each...\n\n", NUM_MESSAGES, MESSAGE_SIZE);

    /* Test different batch sizes */
    struct {
        const char* label;
        int batch_size;
    } configs[] = {
        {"No batching:", 0},
        {"Batch 512B:", 512},
        {"Batch 1KB:", 1024},
        {"Batch 4KB:", 4096},
        {"Batch 8KB:", 8192},
        {"Batch 16KB:", 16384}
    };

    batch_result_t results[6];

    for (int i = 0; i < 6; i++) {
        results[i] = run_batch_test(participant, configs[i].batch_size);
        print_comparison(configs[i].label, &results[i]);
    }

    /* Performance improvement */
    printf("\n--- Performance Improvement ---\n\n");

    double baseline = results[0].msg_per_sec;
    for (int i = 1; i < 6; i++) {
        double improvement = ((results[i].msg_per_sec / baseline) - 1.0) * 100;
        printf("%s %.0f%% faster than no batching\n", configs[i].label, improvement);
    }

    /* Network efficiency */
    printf("\n--- Network Efficiency ---\n\n");
    printf("| Configuration | Messages | Packets | Efficiency |\n");
    printf("|---------------|----------|---------|------------|\n");

    for (int i = 0; i < 6; i++) {
        double efficiency = results[i].avg_batch_size;
        printf("| %-13s | %8lu | %7lu | %5.1fx     |\n",
               configs[i].label, results[i].messages, results[i].batches, efficiency);
    }

    /* Best practices */
    printf("\n--- Batching Best Practices ---\n\n");
    printf("1. Choose batch size based on network MTU (typically 1500 bytes)\n");
    printf("2. For low-latency: smaller batches or disable batching\n");
    printf("3. For high-throughput: larger batches (8KB-64KB)\n");
    printf("4. Use flush() for time-sensitive messages\n");
    printf("5. Set batch_timeout to prevent stale messages\n");

    /* Latency trade-off */
    printf("\n--- Latency vs Throughput Trade-off ---\n\n");
    printf("| Batch Size | Throughput | Added Latency |\n");
    printf("|------------|------------|---------------|\n");
    printf("| None       | Baseline   | ~0 us         |\n");
    printf("| 1 KB       | ~2x        | ~10-50 us     |\n");
    printf("| 8 KB       | ~5x        | ~50-200 us    |\n");
    printf("| 64 KB      | ~10x       | ~100-500 us   |\n");

    hdds_participant_destroy(participant);

    printf("\n=== Batching Demo Complete ===\n");
    return 0;
}
