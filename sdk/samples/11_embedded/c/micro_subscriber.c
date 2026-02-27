// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Micro Subscriber - Gateway node using hdds-micro-c API
 *
 * Receives sensor readings (counter u32 + temperature f32 + label string)
 * from the micro publisher, decodes the CDR payload, and prints values.
 * Uses null transport for local testing.
 *
 * Target: ARM Cortex-M/A, ESP32, or any POSIX host
 * Build (host): gcc -o micro_subscriber micro_subscriber.c -lhdds_micro
 * Build (ARM64): aarch64-linux-gnu-gcc -o micro_subscriber micro_subscriber.c -lhdds_micro
 */

#include <hdds_micro.h>
#include <stdio.h>
#include <string.h>

#define BUF_SIZE    256
#define MAX_READS   100
#define POLL_ROUNDS 50

int main(void)
{
    printf("=== HDDS Micro Subscriber (Gateway Node) ===\n");
    printf("hdds-micro version: %s\n\n", hdds_micro_version());

    HddsMicroTransport *transport = hdds_micro_transport_create_null();
    if (!transport) { fprintf(stderr, "Transport failed\n"); return 1; }

    HddsMicroParticipant *p = hdds_micro_participant_create(42, transport);
    if (!p) { hdds_micro_transport_destroy(transport); return 1; }
    printf("[OK] Participant created (domain=%u)\n",
           hdds_micro_participant_domain_id(p));

    HddsMicroReader *reader = hdds_micro_reader_create(p, "sensor/readings", NULL);
    if (!reader) { hdds_micro_participant_destroy(p); return 1; }

    char topic_name[64];
    hdds_micro_reader_topic_name(reader, topic_name, sizeof(topic_name));
    printf("[OK] Reader on '%s'\nPolling for data...\n\n", topic_name);

    int received = 0;
    for (int round = 0; round < POLL_ROUNDS && received < MAX_READS; round++) {
        uint8_t buf[BUF_SIZE];
        size_t len = 0;
        HddsMicroSampleInfo info;

        HddsMicroError err = hdds_micro_take(reader, buf, BUF_SIZE, &len, &info);
        if (err == HDDS_MICRO_OK && len > 0) {
            /* Decode: u32 counter + f32 temperature + string label */
            uint32_t counter = 0;
            int off = hdds_micro_decode_u32(buf, len, &counter);
            if (off < 0) { fprintf(stderr, "Decode error\n"); continue; }

            float temp = 0.0f;
            int n = hdds_micro_decode_f32(buf + off, len - off, &temp);
            if (n < 0) { fprintf(stderr, "Decode error\n"); continue; }
            off += n;

            char label[64] = {0};
            n = hdds_micro_decode_string(buf + off, len - off, label, sizeof(label));
            if (n < 0) { fprintf(stderr, "Decode string error\n"); continue; }

            printf("  [Gateway] counter=%u temp=%.2f label=\"%s\"\n",
                   counter, temp, label);
            received++;
        }
    }

    if (received == 0)
        printf("  (no data - run micro_publisher in another terminal)\n");

    printf("\nGateway finished. Received %d samples.\n", received);
    hdds_micro_reader_destroy(reader);
    hdds_micro_participant_destroy(p);
    return 0;
}
