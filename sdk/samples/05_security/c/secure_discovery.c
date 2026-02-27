// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Secure Discovery (C)
 *
 * Demonstrates authenticated discovery concepts for DDS Security.
 * Shows how SPDP/SEDP can be protected with authentication.
 *
 * Usage:
 *     ./secure_discovery
 *     ./secure_discovery SecureSensor2
 *
 * Key concepts:
 * - Authenticated SPDP (Simple Participant Discovery Protocol)
 * - Discovery protection settings
 * - Secure endpoint matching
 * - Rejection of unauthenticated participants
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Secure Discovery.
 * The native DDS Security Secure Discovery API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "generated/HelloWorld.h"

volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

void print_secure_discovery_info(void) {
    printf("--- Secure Discovery Overview ---\n\n");
    printf("Standard SPDP sends participant info in plaintext.\n");
    printf("Secure SPDP adds:\n");
    printf("  1. Authentication of participant announcements\n");
    printf("  2. Encryption of discovery metadata\n");
    printf("  3. Rejection of unauthenticated participants\n");
    printf("  4. Secure liveliness assertions\n\n");

    printf("Governance Settings (when security enabled):\n");
    printf("  <enable_discovery_protection>true</..>\n");
    printf("  <enable_liveliness_protection>true</..>\n");
    printf("  <allow_unauthenticated_participants>false</..>\n\n");
}

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Secure Discovery Demo\n");
    printf("Authenticated participant discovery concepts\n");
    printf("============================================================\n\n");
    printf("NOTE: CONCEPT DEMO - Native DDS Security Secure Discovery API not yet in SDK.\n");
    printf("      Using standard pub/sub API to demonstrate the pattern.\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    signal(SIGINT, signal_handler);

    const char* participant_name = (argc > 1) ? argv[1] : "SecureDiscovery";

    print_secure_discovery_info();

    printf("--- Simulated Secure Discovery Config ---\n");
    printf("  Discovery Protection:  ENABLED\n");
    printf("  Liveliness Protection: ENABLED\n");
    printf("  Allow Unauthenticated: NO\n\n");

    /* Create participant */
    char name_buf[64];
    snprintf(name_buf, sizeof(name_buf), "SecDisc_%s", participant_name);

    struct HddsParticipant* participant = hdds_participant_create(name_buf);
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));
    printf("     Participant ID: %u\n", hdds_participant_id(participant));
    printf("     (Secure discovery via security plugins)\n\n");

    /* Get graph guard condition for discovery events */
    const struct HddsGuardCondition* graph_cond = hdds_participant_graph_guard_condition(participant);

    /* Create endpoints */
    struct HddsDataWriter* writer = hdds_writer_create(participant, "SecureDiscoveryTopic");
    struct HddsDataReader* reader = hdds_reader_create(participant, "SecureDiscoveryTopic");

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] Secure endpoints created\n\n");

    /* Set up waitset */
    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* data_cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, data_cond);
    if (graph_cond) {
        hdds_waitset_attach_guard_condition(waitset, graph_cond);
    }

    printf("--- Secure Discovery Process ---\n\n");
    printf("1. Send authenticated SPDP announcement\n");
    printf("2. Receive and verify peer announcements\n");
    printf("3. Perform mutual authentication handshake\n");
    printf("4. Exchange encrypted endpoint info (SEDP)\n");
    printf("5. Establish secure data channels\n\n");

    printf("--- Discovering Peers ---\n");
    printf("Run another instance to see discovery:\n");
    printf("  %s SecureSensor2\n", argv[0]);
    printf("Press Ctrl+C to exit.\n\n");

    int msg_count = 0;
    int discovery_events = 0;

    while (running && msg_count < 10) {
        /* Send periodic announcement */
        HelloWorld msg = {.id = msg_count + 1};
        snprintf(msg.message, sizeof(msg.message),
                 "Authenticated msg from %s #%d", participant_name, msg_count + 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
            printf("[SENT] %s\n", msg.message);
        }
        msg_count++;

        /* Wait for events */
        const void* triggered[4];
        size_t triggered_count;

        if (hdds_waitset_wait(waitset, 2000000000LL, triggered, 4, &triggered_count) == HDDS_OK && triggered_count > 0) {
            for (size_t i = 0; i < triggered_count; i++) {
                if (graph_cond && triggered[i] == graph_cond) {
                    discovery_events++;
                    printf("[DISCOVERY] Authenticated peer detected! (event #%d)\n", discovery_events);
                } else if (triggered[i] == data_cond) {
                    uint8_t recv_buf[512];
                    size_t recv_len;

                    while (hdds_reader_take(reader, recv_buf, sizeof(recv_buf), &recv_len) == HDDS_OK) {
                        HelloWorld recv_msg;
                        if (HelloWorld_deserialize(&recv_msg, recv_buf, recv_len)) {
                            printf("[RECV] id=%d msg='%s'\n", recv_msg.id, recv_msg.message);
                        }
                    }
                }
            }
        }
    }

    /* Summary */
    printf("\n--- Secure Discovery Summary ---\n\n");
    printf("Participant: %s\n", participant_name);
    printf("Messages sent: %d\n", msg_count);
    printf("Discovery events: %d\n\n", discovery_events);

    printf("Security Benefits (when enabled):\n");
    printf("  - Only trusted participants can join\n");
    printf("  - Discovery metadata is encrypted\n");
    printf("  - Prevents rogue participant injection\n");
    printf("  - Protects endpoint information\n");

    /* Cleanup */
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Secure Discovery Demo Complete ===\n");
    return 0;
}
