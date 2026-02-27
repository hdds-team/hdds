// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Micro Publisher - Sensor node using hdds-micro-c API
 *
 * Publishes counter (u32), temperature (f32), and label (string) readings
 * using the lightweight hdds-micro API designed for embedded targets.
 * Uses null transport for local testing; replace with serial transport
 * for real UART-based deployments (e.g., RS-485 bus).
 *
 * Target: ARM Cortex-M/A, ESP32, or any POSIX host
 * Build (host): gcc -o micro_publisher micro_publisher.c -lhdds_micro
 * Build (ARM64): aarch64-linux-gnu-gcc -o micro_publisher micro_publisher.c -lhdds_micro
 */

#include <hdds_micro.h>
#include <stdio.h>
#include <string.h>

#define BUF_SIZE    128
#define NUM_SAMPLES 20

static float read_temperature(int tick)
{
    return 22.0f + (float)(tick % 10) * 0.25f;
}

int main(void)
{
    printf("=== HDDS Micro Publisher (Sensor Node) ===\n");
    printf("hdds-micro version: %s\n\n", hdds_micro_version());

    /* Create null transport for testing (no network I/O) */
    HddsMicroTransport *transport = hdds_micro_transport_create_null();
    if (!transport) { fprintf(stderr, "Transport failed\n"); return 1; }

    HddsMicroParticipant *p = hdds_micro_participant_create(42, transport);
    if (!p) { hdds_micro_transport_destroy(transport); return 1; }
    printf("[OK] Participant created (domain=%u)\n",
           hdds_micro_participant_domain_id(p));

    HddsMicroWriter *writer = hdds_micro_writer_create(p, "sensor/readings", NULL);
    if (!writer) { hdds_micro_participant_destroy(p); return 1; }
    printf("[OK] Writer on 'sensor/readings'\n\n");

    for (int i = 0; i < NUM_SAMPLES; i++) {
        uint8_t buf[BUF_SIZE];
        int off = 0, n;
        uint32_t counter = (uint32_t)i;
        float temp = read_temperature(i);
        char label[32];
        snprintf(label, sizeof(label), "sensor_%d", i % 4);

        /* Encode: u32 counter + f32 temperature + string label */
        n = hdds_micro_encode_u32(buf, BUF_SIZE, counter);
        if (n < 0) { fprintf(stderr, "Encode error\n"); break; }
        off += n;
        n = hdds_micro_encode_f32(buf + off, BUF_SIZE - off, temp);
        if (n < 0) { fprintf(stderr, "Encode error\n"); break; }
        off += n;
        n = hdds_micro_encode_string(buf + off, BUF_SIZE - off, label);
        if (n < 0) { fprintf(stderr, "Encode error\n"); break; }
        off += n;

        HddsMicroError err = hdds_micro_write(writer, buf, (size_t)off);
        if (err != HDDS_MICRO_OK) {
            fprintf(stderr, "Write: %s\n", hdds_micro_error_str(err));
            break;
        }
        printf("  [Sensor] counter=%u temp=%.2f label=\"%s\"\n",
               counter, temp, label);
    }

    printf("\nPublished %d samples.\n", NUM_SAMPLES);
    hdds_micro_writer_destroy(writer);
    hdds_micro_participant_destroy(p);
    return 0;
}
