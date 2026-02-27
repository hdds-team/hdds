// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Telemetry Dashboard - Monitor DDS performance metrics in real-time
 *
 * Demonstrates HDDS telemetry: initializes metrics, creates pub/sub,
 * records latency for each write/read cycle, takes periodic snapshots,
 * and starts a Prometheus-compatible exporter.
 *
 * Build:
 *     cd build && cmake .. && make telemetry_dashboard
 *
 * Usage:
 *     ./telemetry_dashboard
 *
 * Expected output:
 *     --- Snapshot #1 ---
 *     Messages sent:     10   | received: 10
 *     Latency p50: 0.12 ms   | p99: 0.45 ms
 *     Bytes sent: 1280
 *     ...
 *     Exporter running on 0.0.0.0:4242
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define BATCH_SIZE    10
#define NUM_BATCHES   5
#define EXPORTER_PORT 4242

/* Get monotonic timestamp in nanoseconds */
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void print_snapshot(const struct HddsMetricsSnapshot *snap, int idx)
{
    printf("--- Snapshot #%d ---\n", idx);
    printf("  Messages sent:     %lu   | received: %lu\n",
           (unsigned long)snap->MESSAGES_SENT,
           (unsigned long)snap->MESSAGES_RECEIVED);
    printf("  Messages dropped:  %lu\n", (unsigned long)snap->MESSAGES_DROPPED);
    printf("  Bytes sent:        %lu\n", (unsigned long)snap->BYTES_SENT);
    printf("  Latency p50: %.3f ms | p99: %.3f ms | p999: %.3f ms\n",
           snap->LATENCY_P50_NS / 1e6,
           snap->LATENCY_P99_NS / 1e6,
           snap->LATENCY_P999_NS / 1e6);
    printf("  Backpressure: merge_full=%lu, would_block=%lu\n\n",
           (unsigned long)snap->MERGE_FULL_COUNT,
           (unsigned long)snap->WOULD_BLOCK_COUNT);
}

int main(void)
{
    printf("============================================================\n");
    printf("HDDS Telemetry Dashboard\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    /* Initialize telemetry */
    struct HddsMetrics *metrics = hdds_telemetry_init();
    if (!metrics) {
        fprintf(stderr, "Failed to initialize telemetry\n");
        return 1;
    }
    printf("[OK] Telemetry initialized\n");

    /* Create participant + endpoints */
    struct HddsParticipant *participant = hdds_participant_create("TelemetryDashboard");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        hdds_telemetry_release(metrics);
        return 1;
    }

    struct HddsDataWriter *writer = hdds_writer_create(participant, "TelemetryTopic");
    struct HddsDataReader *reader = hdds_reader_create(participant, "TelemetryTopic");

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        hdds_telemetry_release(metrics);
        return 1;
    }
    printf("[OK] Pub/Sub created on 'TelemetryTopic'\n");

    /* Start exporter */
    struct HddsTelemetryExporter *exporter =
        hdds_telemetry_start_exporter("0.0.0.0", EXPORTER_PORT);
    if (exporter) {
        printf("[OK] Exporter running on 0.0.0.0:%d\n\n", EXPORTER_PORT);
    } else {
        printf("[WARN] Exporter failed to start (continuing without)\n\n");
    }

    /* Write/read cycles with latency measurement */
    for (int batch = 0; batch < NUM_BATCHES; batch++) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            HelloWorld msg = {.id = batch * BATCH_SIZE + i};
            snprintf(msg.message, sizeof(msg.message), "sample_%d", msg.id);

            uint8_t buf[256];
            size_t len = HelloWorld_serialize(&msg, buf, sizeof(buf));

            uint64_t start = now_ns();
            hdds_writer_write(writer, buf, len);

            /* Read back (best-effort, may not always get data) */
            uint8_t rbuf[256];
            size_t rlen = 0;
            hdds_reader_take(reader, rbuf, sizeof(rbuf), &rlen);
            uint64_t end = now_ns();

            hdds_telemetry_record_latency(metrics, start, end);
        }

        /* Take snapshot after each batch */
        struct HddsMetricsSnapshot snap;
        if (hdds_telemetry_snapshot(metrics, &snap) == HDDS_OK) {
            print_snapshot(&snap, batch + 1);
        }
    }

    /* Final summary */
    printf("=== Dashboard Summary ===\n");
    struct HddsMetricsSnapshot final_snap;
    if (hdds_telemetry_snapshot(metrics, &final_snap) == HDDS_OK) {
        printf("Total messages sent: %lu\n",
               (unsigned long)final_snap.MESSAGES_SENT);
        printf("Total bytes sent:    %lu\n",
               (unsigned long)final_snap.BYTES_SENT);
        printf("Final p99 latency:   %.3f ms\n\n",
               final_snap.LATENCY_P99_NS / 1e6);
    }

    /* Cleanup */
    if (exporter) hdds_telemetry_stop_exporter(exporter);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    hdds_telemetry_release(metrics);

    printf("=== Telemetry Dashboard Complete ===\n");
    return 0;
}
