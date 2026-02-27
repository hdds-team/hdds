// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Metrics Export - Focused telemetry exporter example
 *
 * Initializes telemetry, starts a TCP exporter on port 9090,
 * records 1000 latency samples, takes a final snapshot, and stops.
 * Connect HDDS Viewer or curl to http://localhost:9090 for metrics.
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
 *     Latency p50: 0.001 ms | p99: 0.003 ms | p999: 0.005 ms
 */

#include <hdds.h>
#include <stdio.h>
#include <time.h>

#define NUM_SAMPLES   1000
#define EXPORTER_PORT 9090

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Simulate work with a busy loop */
static void simulate_work(void)
{
    volatile int x = 0;
    for (int i = 0; i < 100; i++) x += i;
    (void)x;
}

int main(void)
{
    printf("============================================================\n");
    printf("HDDS Metrics Export Sample\n");
    printf("============================================================\n\n");

    /* Initialize telemetry */
    struct HddsMetrics *metrics = hdds_telemetry_init();
    if (!metrics) {
        fprintf(stderr, "Failed to initialize telemetry\n");
        return 1;
    }
    printf("[OK] Telemetry initialized\n");

    /* Start exporter on port 9090 */
    struct HddsTelemetryExporter *exporter =
        hdds_telemetry_start_exporter("127.0.0.1", EXPORTER_PORT);
    if (!exporter) {
        fprintf(stderr, "Failed to start exporter on port %d\n", EXPORTER_PORT);
        hdds_telemetry_release(metrics);
        return 1;
    }
    printf("[OK] Exporter listening on 127.0.0.1:%d\n\n", EXPORTER_PORT);

    /* Record latency samples */
    printf("Recording %d latency samples...\n", NUM_SAMPLES);

    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint64_t start = now_ns();
        simulate_work();
        uint64_t end = now_ns();

        hdds_telemetry_record_latency(metrics, start, end);

        /* Progress indicator every 250 samples */
        if ((i + 1) % 250 == 0) {
            printf("  ... %d/%d\n", i + 1, NUM_SAMPLES);
        }
    }

    /* Take final snapshot */
    printf("\n--- Final Metrics ---\n");
    struct HddsMetricsSnapshot snap;
    if (hdds_telemetry_snapshot(metrics, &snap) == HDDS_OK) {
        printf("  Latency p50:  %.4f ms\n", snap.LATENCY_P50_NS / 1e6);
        printf("  Latency p99:  %.4f ms\n", snap.LATENCY_P99_NS / 1e6);
        printf("  Latency p999: %.4f ms\n", snap.LATENCY_P999_NS / 1e6);
        printf("  Messages sent: %lu | received: %lu\n",
               (unsigned long)snap.MESSAGES_SENT,
               (unsigned long)snap.MESSAGES_RECEIVED);
    }

    /* Cleanup */
    printf("\nStopping exporter...\n");
    hdds_telemetry_stop_exporter(exporter);
    hdds_telemetry_release(metrics);

    printf("\n=== Metrics Export Complete ===\n");
    return 0;
}
