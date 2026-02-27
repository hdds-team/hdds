// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * rti_interop.c — HDDS subscriber with RTI Connext-compatible QoS
 *
 * Subscribes on "InteropTest" using hdds_qos_rti_defaults() which
 * configures RTPS wire-format parameters to match RTI Connext defaults.
 * Run an RTI Connext publisher on the same domain/topic to send data.
 *
 * Build:
 *   gcc -o rti_interop rti_interop.c -I../../../c/include -lhdds
 *
 * Run:
 *   ./rti_interop
 *
 * RTI Connext peer: see peer_commands.md
 *
 * Expected:
 *   Received 64 bytes: id=1, msg="Hello from RTI #1"
 */

#include <hdds.h>
#include <stdio.h>
#include <string.h>

/* Deserialize StringMsg {id: u32, message: string} from CDR LE. */
static int deser(const uint8_t *buf, size_t len, uint32_t *id, char *msg, size_t cap) {
    if (len < 8) return -1;
    memcpy(id, buf, 4);
    uint32_t sl; memcpy(&sl, buf + 4, 4);
    if (sl == 0 || 8 + sl > len) return -1;
    size_t n = (sl < cap) ? sl : cap - 1;
    memcpy(msg, buf + 8, n);
    msg[n] = '\0';
    return 0;
}

int main(void) {
    hdds_logging_init(3);

    HddsParticipant *p = hdds_participant_create("RTI_Interop");
    if (!p) { fprintf(stderr, "Participant creation failed\n"); return 1; }

    HddsQoS *qos = hdds_qos_rti_defaults();
    HddsDataReader *reader = hdds_reader_create_with_qos(p, "InteropTest", qos);
    if (!reader) { fprintf(stderr, "Reader creation failed\n"); return 1; }

    HddsWaitSet *ws = hdds_waitset_create();
    hdds_waitset_attach_status_condition(ws, hdds_reader_get_status_condition(reader));

    printf("[HDDS] Subscribing on 'InteropTest' (RTI-compatible QoS)...\n");
    printf("[HDDS] Start an RTI Connext publisher on the same topic.\n\n");

    int received = 0;
    for (int attempt = 0; attempt < 60; attempt++) {
        const void *trig[1]; size_t tc = 0;
        if (hdds_waitset_wait(ws, 1000000000LL, trig, 1, &tc) == HDDS_OK && tc > 0) {
            uint8_t buf[4096]; size_t len = 0;
            while (hdds_reader_take(reader, buf, sizeof(buf), &len) == HDDS_OK) {
                uint32_t id; char msg[256];
                if (deser(buf, len, &id, msg, sizeof(msg)) == 0)
                    printf("Received %zu bytes: id=%u, msg=\"%s\"\n", len, id, msg);
                else
                    printf("Received %zu bytes (unable to decode)\n", len);
                received++;
            }
        }
    }

    printf("\nReceived %d total messages.\n", received);
    hdds_waitset_destroy(ws);
    hdds_reader_destroy(reader);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
    return 0;
}
