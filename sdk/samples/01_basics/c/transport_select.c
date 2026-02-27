// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Transport Selection (C)
 *
 * Demonstrates creating participants with explicit transport selection.
 * Shows UDP (default), TCP, and how to switch between transports.
 *
 * Build:
 *     cd build && cmake .. && make transport_select
 *
 * Usage:
 *     ./transport_select              # Default UDP transport
 *     ./transport_select tcp          # TCP transport
 *     ./transport_select udp          # Explicit UDP transport
 *
 * Expected output:
 *     [OK] Participant created with UDP transport
 *     [SENT] Transport test message #1
 *     ...
 *
 * Key concepts:
 * - Default transport is UDP multicast
 * - TCP transport for NAT traversal / WAN
 * - Transport selected at participant creation
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 5

int main(int argc, char **argv)
{
    const char *transport = "udp";
    if (argc > 1) {
        transport = argv[1];
    }

    printf("============================================================\n");
    printf("Transport Selection Demo\n");
    printf("Selected transport: %s\n", transport);
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    printf("--- Available Transports ---\n");
    printf("  udp  - UDP multicast (default, LAN discovery)\n");
    printf("  tcp  - TCP point-to-point (NAT traversal, WAN)\n");
    printf("\n");

    /* Create participant with selected transport */
    struct HddsParticipant *participant = NULL;

    if (strcmp(transport, "tcp") == 0) {
        participant = hdds_participant_create_with_transport("TransportDemo", HDDS_TRANSPORT_INTRA_PROCESS);
        if (participant) {
            printf("[OK] Participant created with TCP transport\n");
        }
    } else {
        participant = hdds_participant_create_with_transport("TransportDemo", HDDS_TRANSPORT_UDP_MULTICAST);
        if (participant) {
            printf("[OK] Participant created with UDP transport\n");
        }
    }

    if (!participant) {
        fprintf(stderr, "Failed to create participant with %s transport\n", transport);
        return 1;
    }

    /* Create writer */
    struct HddsDataWriter *writer = hdds_writer_create(participant, "TransportTopic");
    if (!writer) {
        fprintf(stderr, "Failed to create writer\n");
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] DataWriter created on 'TransportTopic'\n\n");

    /* Create reader */
    struct HddsDataReader *reader = hdds_reader_create(participant, "TransportTopic");
    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] DataReader created on 'TransportTopic'\n\n");

    /* Send messages */
    printf("--- Sending %d messages via %s ---\n\n", NUM_MESSAGES, transport);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg = {.id = i + 1};
        snprintf(msg.message, sizeof(msg.message),
                 "Transport test #%d (%s)", i + 1, transport);

        uint8_t buf[256];
        size_t len = HelloWorld_serialize(&msg, buf, sizeof(buf));

        if (hdds_writer_write(writer, buf, len) == HDDS_OK) {
            printf("[SENT] id=%d msg='%s'\n", msg.id, msg.message);
        } else {
            printf("[FAIL] id=%d\n", msg.id);
        }

        usleep(200000); /* 200ms */
    }

    /* Read back */
    printf("\n--- Reading messages ---\n\n");

    struct HddsWaitSet *waitset = hdds_waitset_create();
    const struct HddsStatusCondition *cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    const void *triggered[1];
    size_t triggered_count;
    if (hdds_waitset_wait(waitset, 2000000000LL, triggered, 1, &triggered_count) == HDDS_OK) {
        uint8_t rbuf[512];
        size_t rlen;
        while (hdds_reader_take(reader, rbuf, sizeof(rbuf), &rlen) == HDDS_OK) {
            HelloWorld rmsg;
            if (HelloWorld_deserialize(&rmsg, rbuf, rlen)) {
                printf("[RECV] id=%d msg='%s'\n", rmsg.id, rmsg.message);
            }
        }
    } else {
        printf("[TIMEOUT] No messages received (run two instances to test)\n");
    }

    /* Cleanup */
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Transport Selection Complete ===\n");
    return 0;
}
