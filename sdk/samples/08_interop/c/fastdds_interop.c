// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * fastdds_interop.c — HDDS publisher interop with FastDDS subscriber
 *
 * Publishes CDR messages on "InteropTest" using standard RTPS QoS.
 * Run a FastDDS subscriber on the same domain/topic to receive.
 *
 * Build:  gcc -o fastdds_interop fastdds_interop.c -I../../../c/include -lhdds
 * Run:    ./fastdds_interop
 * FastDDS peer: see peer_commands.md
 *
 * Expected:
 *   Published 1/20: "Hello from HDDS C #1"
 *   ...
 */

#include <hdds.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

/* Serialize StringMsg {id: u32, message: string} to CDR LE. */
static size_t ser(uint8_t *buf, size_t cap, uint32_t id, const char *msg) {
    size_t slen = strlen(msg) + 1, pad = (4 - (slen % 4)) % 4;
    if (4 + 4 + slen + pad > cap) return 0;
    memcpy(buf, &id, 4);
    uint32_t sl = (uint32_t)slen;
    memcpy(buf + 4, &sl, 4);
    memcpy(buf + 8, msg, slen);
    memset(buf + 8 + slen, 0, pad);
    return 8 + slen + pad;
}

int main(void) {
    hdds_logging_init(3);

    HddsParticipant *p = hdds_participant_create("FastDDS_Interop");
    if (!p) { fprintf(stderr, "Participant creation failed\n"); return 1; }

    HddsQoS *qos = hdds_qos_reliable();
    HddsDataWriter *w = hdds_writer_create_with_qos(p, "InteropTest", qos);
    if (!w) { fprintf(stderr, "Writer creation failed\n"); return 1; }

    printf("[HDDS] Publishing 20 messages on 'InteropTest' (domain 0)...\n");
    printf("[HDDS] Start a FastDDS subscriber on the same topic.\n\n");

    for (uint32_t i = 1; i <= 20; i++) {
        char text[128]; uint8_t buf[256];
        snprintf(text, sizeof(text), "Hello from HDDS C #%u", i);
        size_t len = ser(buf, sizeof(buf), i, text);
        if (len > 0 && hdds_writer_write(w, buf, len) == HDDS_OK)
            printf("Published %u/20: \"%s\"\n", i, text);
        sleep_ms(500);
    }

    printf("\nDone.\n");
    hdds_writer_destroy(w);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
    return 0;
}
