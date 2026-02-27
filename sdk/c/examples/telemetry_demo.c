// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Example: Telemetry Demo (C)
 *
 * Demonstrates the HDDS telemetry / metrics API:
 *   - Initialize the metrics collector
 *   - Record custom latency samples
 *   - Take a metrics snapshot and print counters
 *   - Start and stop the telemetry exporter
 *
 * Usage:
 *     ./telemetry_demo
 *
 * Expected output:
 *     Telemetry initialized.
 *     Recorded 10 latency samples.
 *     --- Metrics Snapshot ---
 *     ...
 *     Exporter stopped.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdint.h>

int main(void) {
    /* Initialize the global metrics collector */
    struct HddsMetrics *metrics = hdds_telemetry_init();
    if (!metrics) {
        fprintf(stderr, "Failed to initialize telemetry\n");
        return 1;
    }
    printf("Telemetry initialized.\n");

    /* Verify hdds_telemetry_get returns the same instance */
    struct HddsMetrics *metrics2 = hdds_telemetry_get();
    if (metrics2) {
        printf("hdds_telemetry_get() returned a valid handle.\n");
        hdds_telemetry_release(metrics2);
    }

    /* Record some synthetic latency samples (simulating 1-10 us latencies) */
    for (int i = 0; i < 10; i++) {
        uint64_t start_ns = (uint64_t)i * 1000;         /* start time */
        uint64_t end_ns   = start_ns + (uint64_t)(i + 1) * 1000; /* end time */
        hdds_telemetry_record_latency(metrics, start_ns, end_ns);
    }
    printf("Recorded 10 latency samples.\n");

    /* Take a snapshot of current metrics */
    struct HddsMetricsSnapshot snap;
    enum HddsError err = hdds_telemetry_snapshot(metrics, &snap);
    if (err == HDDS_OK) {
        printf("\n--- Metrics Snapshot ---\n");
        printf("timestamp_ns:     %lu\n", (unsigned long)snap.TIMESTAMP_NS);
        printf("messages_sent:    %lu\n", (unsigned long)snap.MESSAGES_SENT);
        printf("messages_received:%lu\n", (unsigned long)snap.MESSAGES_RECEIVED);
        printf("messages_dropped: %lu\n", (unsigned long)snap.MESSAGES_DROPPED);
        printf("bytes_sent:       %lu\n", (unsigned long)snap.BYTES_SENT);
        printf("latency_p50:      %lu ns\n", (unsigned long)snap.LATENCY_P50_NS);
        printf("latency_p99:      %lu ns\n", (unsigned long)snap.LATENCY_P99_NS);
        printf("latency_p999:     %lu ns\n", (unsigned long)snap.LATENCY_P999_NS);
        printf("merge_full:       %lu\n", (unsigned long)snap.MERGE_FULL_COUNT);
        printf("would_block:      %lu\n", (unsigned long)snap.WOULD_BLOCK_COUNT);
        printf("------------------------\n");
    } else {
        fprintf(stderr, "Failed to take snapshot: error %d\n", err);
    }

    /* Start the telemetry exporter on localhost:4242 */
    printf("\nStarting telemetry exporter on 127.0.0.1:4242...\n");
    struct HddsTelemetryExporter *exporter =
        hdds_telemetry_start_exporter("127.0.0.1", 4242);
    if (exporter) {
        printf("Exporter running.\n");

        /* In a real application you would keep the exporter alive.
         * Here we just stop it immediately for demonstration. */
        hdds_telemetry_stop_exporter(exporter);
        printf("Exporter stopped.\n");
    } else {
        printf("Exporter failed to start (port may be in use).\n");
    }

    /* Release the metrics handle */
    hdds_telemetry_release(metrics);
    printf("\nTelemetry demo complete.\n");

    return 0;
}
