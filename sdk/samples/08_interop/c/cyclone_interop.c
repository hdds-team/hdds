// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * cyclone_interop.c — HDDS bidirectional pub+sub for CycloneDDS interop
 *
 * Publishes and subscribes on "InteropTest" simultaneously.  Run a
 * CycloneDDS peer that does the same and both sides will exchange data.
 *
 * Build:
 *   gcc -o cyclone_interop cyclone_interop.c -I../../../c/include -lhdds -lpthread
 *
 * Run:
 *   ./cyclone_interop
 *
 * CycloneDDS peer: see peer_commands.md
 *
 * Expected:
 *   [PUB] Sent #1: "HDDS ping #1"
 *   [SUB] Got 48 bytes: id=1, msg="CycloneDDS pong #1"
 */

#include <hdds.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#include <pthread.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

/* CDR LE serialize/deserialize for StringMsg {id: u32, message: string}. */
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

static void *subscriber_thread(void *arg) {
    HddsDataReader *reader = (HddsDataReader *)arg;
    HddsWaitSet *ws = hdds_waitset_create();
    hdds_waitset_attach_status_condition(ws, hdds_reader_get_status_condition(reader));

    for (int i = 0; i < 60; i++) {
        const void *trig[1]; size_t tc = 0;
        if (hdds_waitset_wait(ws, 500000000LL, trig, 1, &tc) == HDDS_OK && tc > 0) {
            uint8_t buf[4096]; size_t len = 0;
            while (hdds_reader_take(reader, buf, sizeof(buf), &len) == HDDS_OK) {
                uint32_t id; char msg[256];
                if (deser(buf, len, &id, msg, sizeof(msg)) == 0)
                    printf("[SUB] Got %zu bytes: id=%u, msg=\"%s\"\n", len, id, msg);
            }
        }
    }
    hdds_waitset_destroy(ws);
    return NULL;
}

int main(void) {
    hdds_logging_init(3);

    HddsParticipant *p = hdds_participant_create("Cyclone_Interop");
    if (!p) { fprintf(stderr, "Participant creation failed\n"); return 1; }

    HddsQoS *qos = hdds_qos_reliable();
    HddsDataWriter *w = hdds_writer_create_with_qos(p, "InteropTest", qos);
    HddsDataReader *r = hdds_reader_create_with_qos(p, "InteropTest", qos);
    if (!w || !r) { fprintf(stderr, "Endpoint creation failed\n"); return 1; }

    printf("[HDDS] Bidirectional interop on 'InteropTest' (domain 0).\n");
    printf("[HDDS] Start a CycloneDDS peer on the same topic.\n\n");

    pthread_t tid;
    pthread_create(&tid, NULL, subscriber_thread, r);

    for (uint32_t i = 1; i <= 20; i++) {
        char text[128]; uint8_t buf[256];
        snprintf(text, sizeof(text), "HDDS ping #%u", i);
        size_t len = ser(buf, sizeof(buf), i, text);
        if (len > 0 && hdds_writer_write(w, buf, len) == HDDS_OK)
            printf("[PUB] Sent #%u: \"%s\"\n", i, text);
        sleep_ms(500);
    }

    pthread_join(tid, NULL);
    printf("\nDone.\n");

    hdds_writer_destroy(w);
    hdds_reader_destroy(r);
    hdds_qos_destroy(qos);
    hdds_participant_destroy(p);
    return 0;
}
