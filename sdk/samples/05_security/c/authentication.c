// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Authentication (C)
 *
 * Demonstrates PKI-based authentication concepts for DDS Security.
 * This sample shows the authentication patterns - actual security
 * plugins will be enabled in a future HDDS release.
 *
 * Usage:
 *     ./authentication             # Run as Participant1
 *     ./authentication Participant2  # Run as Participant2
 *
 * Key concepts:
 * - Identity Certificate and Private Key (X.509)
 * - Certificate Authority (CA) for trust
 * - Mutual authentication between participants
 *
 * Prerequisites (when security is enabled):
 *   Generate certificates using: ../scripts/generate_certs.sh
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Authentication.
 * The native DDS Security Authentication API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 5

void print_auth_concepts(void) {
    printf("--- DDS Security Authentication Concepts ---\n\n");
    printf("Authentication uses X.509 PKI:\n");
    printf("1. Each participant has an identity certificate\n");
    printf("2. Certificates are signed by a trusted CA\n");
    printf("3. Participants validate each other's certificates\n");
    printf("4. Only authenticated participants can communicate\n\n");

    printf("Required Files (when security enabled):\n");
    printf("  - ca_cert.pem         : CA certificate for validating peers\n");
    printf("  - participant_cert.pem: This participant's certificate\n");
    printf("  - participant_key.pem : This participant's private key\n\n");
}

int main(int argc, char* argv[]) {
    printf("============================================================\n");
    printf("Authentication Demo\n");
    printf("PKI-based participant authentication concepts\n");
    printf("============================================================\n\n");
    printf("NOTE: CONCEPT DEMO - Native DDS Security Authentication API not yet in SDK.\n");
    printf("      Using standard pub/sub API to demonstrate the pattern.\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    const char* participant_name = (argc > 1) ? argv[1] : "Participant1";

    print_auth_concepts();

    printf("--- Simulated Authentication ---\n");
    printf("Participant: %s\n", participant_name);
    printf("Identity: CN=%s,O=HDDS,C=US\n\n", participant_name);

    /* Create participant (without security for now) */
    char name_buf[64];
    snprintf(name_buf, sizeof(name_buf), "Auth_%s", participant_name);

    struct HddsParticipant* participant = hdds_participant_create(name_buf);
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));
    printf("     (Security plugins not yet enabled)\n");

    /* Create endpoints */
    struct HddsQoS* qos = hdds_qos_reliable();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "SecureData", qos);
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "SecureData", qos);
    hdds_qos_destroy(qos);

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] DataWriter and DataReader created\n\n");

    struct HddsWaitSet* waitset = hdds_waitset_create();
    const struct HddsStatusCondition* cond = hdds_reader_get_status_condition(reader);
    hdds_waitset_attach_status_condition(waitset, cond);

    printf("--- Waiting for Peers ---\n");
    printf("Run another instance to see communication:\n");
    printf("  %s Participant2\n\n", argv[0]);

    /* Communication loop */
    for (int i = 0; i < NUM_MESSAGES; i++) {
        /* Send message */
        char text[64];
        snprintf(text, sizeof(text), "Message from %s #%d", participant_name, i + 1);

        HelloWorld msg = {.id = i + 1};
        strncpy(msg.message, text, sizeof(msg.message) - 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
            printf("[SENT] %s\n", text);
        }

        /* Check for received messages */
        const void* triggered[1];
        size_t triggered_count;
        if (hdds_waitset_wait(waitset, 1000000000LL, triggered, 1, &triggered_count) == HDDS_OK && triggered_count > 0) {
            uint8_t recv_buf[512];
            size_t recv_len;

            while (hdds_reader_take(reader, recv_buf, sizeof(recv_buf), &recv_len) == HDDS_OK) {
                HelloWorld recv_msg;
                if (HelloWorld_deserialize(&recv_msg, recv_buf, recv_len)) {
                    printf("[RECV] id=%d msg='%s'\n", recv_msg.id, recv_msg.message);
                }
            }
        }

        sleep(2);
    }

    /* Summary */
    printf("\n--- Authentication Summary ---\n");
    printf("This participant: %s\n", participant_name);
    printf("Status: Communication established\n\n");
    printf("Note: When DDS Security is enabled:\n");
    printf("  - Unauthenticated participants are rejected\n");
    printf("  - Only peers with valid certificates can join\n");
    printf("  - All data is cryptographically protected\n");

    /* Cleanup */
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Authentication Demo Complete ===\n");
    return 0;
}
