// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Throughput (C)
 *
 * Measures maximum message throughput.
 * Publisher sends as fast as possible, subscriber counts received.
 *
 * Usage:
 *     ./throughput              # Run as publisher
 *     ./throughput sub          # Run as subscriber
 *     ./throughput pub 256      # Publisher with 256-byte payload
 *
 * Key concepts:
 * - Sustained throughput measurement
 * - Messages/sec and MB/sec metrics
 * - Variable payload sizes
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define DEFAULT_DURATION_SEC 10
#define DEFAULT_PAYLOAD_SIZE 256
#define MAX_PAYLOAD_SIZE 65536

volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void run_publisher(struct HddsParticipant* participant, int duration_sec, int payload_size) {
    struct HddsQoS* qos = hdds_qos_best_effort();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "ThroughputTopic", qos);
    hdds_qos_destroy(qos);

    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        return;
    }

    printf("[OK] DataWriter created\n");
    printf("Publishing for %d seconds...\n\n", duration_sec);

    /* Allocate message buffer */
    uint8_t* buffer = malloc(payload_size);
    memset(buffer, 0xAB, payload_size);

    uint64_t messages_sent = 0;
    uint64_t bytes_sent = 0;
    uint64_t start_time = get_time_ns();
    int last_sec = 0;

    while (running) {
        uint64_t now = get_time_ns();
        double elapsed = (now - start_time) / 1e9;
        if (elapsed >= duration_sec) break;

        /* Send message */
        hdds_writer_write(writer, buffer, payload_size);
        messages_sent++;
        bytes_sent += payload_size;

        /* Progress every second */
        int current_sec = (int)elapsed;
        if (current_sec > last_sec) {
            double msg_per_sec = messages_sent / elapsed;
            double mb_per_sec = (bytes_sent / (1024.0 * 1024.0)) / elapsed;
            printf("  [%2d sec] %.0f msg/s, %.2f MB/s\n", current_sec, msg_per_sec, mb_per_sec);
            last_sec = current_sec;
        }
    }

    double duration = (get_time_ns() - start_time) / 1e9;
    double msg_per_sec = messages_sent / duration;
    double mb_per_sec = (bytes_sent / (1024.0 * 1024.0)) / duration;

    printf("\n--- Publisher Results ---\n\n");
    printf("Messages sent:     %lu\n", messages_sent);
    printf("Bytes sent:        %lu (%.2f MB)\n", bytes_sent, bytes_sent / (1024.0 * 1024.0));
    printf("Duration:          %.2f seconds\n\n", duration);
    printf("Throughput:\n");
    printf("  Messages/sec:    %.0f\n", msg_per_sec);
    printf("  MB/sec:          %.2f\n", mb_per_sec);
    printf("  Gbps:            %.2f\n", mb_per_sec * 8 / 1024);

    free(buffer);
    hdds_writer_destroy(writer);
}

void run_subscriber(struct HddsParticipant* participant, int duration_sec, int payload_size) {
    struct HddsQoS* qos = hdds_qos_best_effort();
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "ThroughputTopic", qos);
    hdds_qos_destroy(qos);

    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        return;
    }

    printf("[OK] DataReader created\n");

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Receiving for %d seconds...\n\n", duration_sec);

    uint8_t* buffer = malloc(payload_size + 1024);
    uint64_t messages_recv = 0;
    uint64_t bytes_recv = 0;
    uint64_t start_time = get_time_ns();
    int last_sec = 0;

    while (running) {
        uint64_t now = get_time_ns();
        double elapsed = (now - start_time) / 1e9;
        if (elapsed >= duration_sec) break;

        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 100000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            size_t len;
            while (hdds_reader_take(reader, buffer, payload_size + 1024, &len) == HDDS_OK) {
                messages_recv++;
                bytes_recv += len;
            }
        }

        int current_sec = (int)elapsed;
        if (current_sec > last_sec && messages_recv > 0) {
            double msg_per_sec = messages_recv / elapsed;
            double mb_per_sec = (bytes_recv / (1024.0 * 1024.0)) / elapsed;
            printf("  [%2d sec] %.0f msg/s, %.2f MB/s\n", current_sec, msg_per_sec, mb_per_sec);
            last_sec = current_sec;
        }
    }

    double duration = (get_time_ns() - start_time) / 1e9;
    double msg_per_sec = messages_recv / duration;
    double mb_per_sec = (bytes_recv / (1024.0 * 1024.0)) / duration;

    printf("\n--- Subscriber Results ---\n\n");
    printf("Messages received: %lu\n", messages_recv);
    printf("Bytes received:    %lu (%.2f MB)\n", bytes_recv, bytes_recv / (1024.0 * 1024.0));
    printf("Duration:          %.2f seconds\n\n", duration);
    printf("Throughput:\n");
    printf("  Messages/sec:    %.0f\n", msg_per_sec);
    printf("  MB/sec:          %.2f\n", mb_per_sec);
    printf("  Gbps:            %.2f\n", mb_per_sec * 8 / 1024);

    free(buffer);
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
}

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Throughput Benchmark\n");
    printf("Maximum message throughput measurement\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    signal(SIGINT, signal_handler);

    int is_subscriber = 0;
    int duration_sec = DEFAULT_DURATION_SEC;
    int payload_size = DEFAULT_PAYLOAD_SIZE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "sub") == 0) {
            is_subscriber = 1;
        } else if (strcmp(argv[i], "pub") == 0) {
            is_subscriber = 0;
        } else {
            int n = atoi(argv[i]);
            if (n > 0 && n <= MAX_PAYLOAD_SIZE) payload_size = n;
        }
    }

    printf("Configuration:\n");
    printf("  Mode: %s\n", is_subscriber ? "SUBSCRIBER" : "PUBLISHER");
    printf("  Duration: %d seconds\n", duration_sec);
    printf("  Payload: %d bytes\n\n", payload_size);

    struct HddsParticipant* participant = hdds_participant_create("ThroughputBench");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));

    if (is_subscriber) {
        run_subscriber(participant, duration_sec, payload_size);
    } else {
        run_publisher(participant, duration_sec, payload_size);
    }

    hdds_participant_destroy(participant);

    printf("\n=== Benchmark Complete ===\n");
    return 0;
}
