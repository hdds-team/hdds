// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Latency (C)
 *
 * Measures round-trip latency using ping-pong pattern.
 * Publisher sends timestamped messages, measures echo time.
 *
 * Usage:
 *     ./latency              # Run ping mode (publisher)
 *     ./latency pong         # Run pong mode (echo back)
 *     ./latency 1000         # Run with 1000 samples
 *
 * Key concepts:
 * - High-resolution timestamps
 * - Latency percentiles (p50, p99, p99.9)
 * - Warmup period to avoid cold-start effects
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#include "generated/HelloWorld.h"

#define MAX_SAMPLES 10000
#define WARMUP_SAMPLES 100

/* Get current time in nanoseconds */
uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Compare function for qsort */
int compare_double(const void* a, const void* b) {
    double da = *(const double*)a;
    double db = *(const double*)b;
    return (da > db) - (da < db);
}

/* Calculate percentile from sorted array */
double percentile(double* sorted, int count, double p) {
    if (count == 0) return 0.0;
    double idx = (p / 100.0) * (count - 1);
    int lo = (int)idx;
    int hi = lo + 1;
    if (hi >= count) hi = count - 1;
    double frac = idx - lo;
    return sorted[lo] * (1 - frac) + sorted[hi] * frac;
}

void run_ping(struct HddsParticipant* participant, int num_samples) {
    struct HddsQoS* qos = hdds_qos_best_effort();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "LatencyPing", qos);
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "LatencyPong", qos);
    hdds_qos_destroy(qos);

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Running latency test (ping mode)...\n");
    printf("Waiting for pong endpoint...\n\n");

    /* Allocate samples array */
    double* samples = malloc(sizeof(double) * num_samples);
    int sample_count = 0;

    /* Warmup */
    printf("Warmup (%d samples)...\n", WARMUP_SAMPLES);
    for (int i = 0; i < WARMUP_SAMPLES; i++) {
        HelloWorld msg = {.id = i};
        snprintf(msg.message, sizeof(msg.message), "%lu", get_time_ns());

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
        hdds_writer_write(writer, buffer, len);
        usleep(1000);
    }

    /* Measurement */
    printf("Measuring (%d samples)...\n\n", num_samples);
    for (int i = 0; i < num_samples && sample_count < num_samples; i++) {
        uint64_t send_time = get_time_ns();

        HelloWorld msg = {.id = WARMUP_SAMPLES + i};
        snprintf(msg.message, sizeof(msg.message), "%lu", send_time);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
        hdds_writer_write(writer, buffer, len);

        /* Wait for echo */
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 100000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t recv_buf[256];
            size_t recv_len;
            if (hdds_reader_take(reader, recv_buf, sizeof(recv_buf), &recv_len) == HDDS_OK) {
                uint64_t recv_time = get_time_ns();
                double rtt_us = (recv_time - send_time) / 1000.0;
                samples[sample_count++] = rtt_us;
            }
        }

        if ((i + 1) % (num_samples / 10) == 0) {
            printf("  Progress: %d/%d samples\n", i + 1, num_samples);
        }
    }

    if (sample_count > 0) {
        /* Sort for percentiles */
        qsort(samples, sample_count, sizeof(double), compare_double);

        /* Calculate stats */
        double sum = 0, min = samples[0], max = samples[sample_count - 1];
        for (int i = 0; i < sample_count; i++) sum += samples[i];
        double mean = sum / sample_count;

        double sq_sum = 0;
        for (int i = 0; i < sample_count; i++) {
            double diff = samples[i] - mean;
            sq_sum += diff * diff;
        }
        double std_dev = sqrt(sq_sum / sample_count);

        printf("\n--- Latency Results ---\n\n");
        printf("Round-trip latency (microseconds):\n");
        printf("  Min:    %8.2f us\n", min);
        printf("  Max:    %8.2f us\n", max);
        printf("  Mean:   %8.2f us\n", mean);
        printf("  StdDev: %8.2f us\n\n", std_dev);

        printf("Percentiles:\n");
        printf("  p50:    %8.2f us (median)\n", percentile(samples, sample_count, 50));
        printf("  p90:    %8.2f us\n", percentile(samples, sample_count, 90));
        printf("  p99:    %8.2f us\n", percentile(samples, sample_count, 99));
        printf("  p99.9:  %8.2f us\n", percentile(samples, sample_count, 99.9));

        printf("\n--- One-Way Latency Estimate ---\n");
        printf("  Estimated: %.2f us (RTT/2)\n", percentile(samples, sample_count, 50) / 2);
    } else {
        printf("No samples collected. Ensure pong endpoint is running.\n");
    }

    free(samples);
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
}

void run_pong(struct HddsParticipant* participant) {
    struct HddsQoS* qos = hdds_qos_best_effort();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "LatencyPong", qos);
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "LatencyPing", qos);
    hdds_qos_destroy(qos);

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        return;
    }

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("Running latency test (pong mode)...\n");
    printf("Echoing messages back to ping endpoint.\n");
    printf("Press Ctrl+C to exit.\n\n");

    int echoed = 0;
    while (1) {
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 1000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t buffer[256];
            size_t len;
            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                /* Echo back immediately */
                hdds_writer_write(writer, buffer, len);
                echoed++;
                if (echoed % 100 == 0) {
                    printf("Echoed %d messages\n", echoed);
                }
            }
        }
    }

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
}

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Latency Benchmark\n");
    printf("Round-trip latency measurement using ping-pong pattern\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    int num_samples = 1000;
    int is_pong = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "pong") == 0) {
            is_pong = 1;
        } else {
            int n = atoi(argv[i]);
            if (n > 0 && n <= MAX_SAMPLES) num_samples = n;
        }
    }

    printf("Mode: %s\n", is_pong ? "PONG (echo)" : "PING (measure)");
    if (!is_pong) {
        printf("Samples: %d (+ %d warmup)\n", num_samples, WARMUP_SAMPLES);
    }
    printf("\n");

    struct HddsParticipant* participant = hdds_participant_create("LatencyBench");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n\n", hdds_participant_name(participant));

    if (is_pong) {
        run_pong(participant);
    } else {
        run_ping(participant, num_samples);
    }

    hdds_participant_destroy(participant);

    printf("\n=== Benchmark Complete ===\n");
    return 0;
}
