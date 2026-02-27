// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Encryption (C)
 *
 * Demonstrates DDS Security encryption concepts.
 * Shows how data is protected with AES-GCM encryption.
 *
 * Usage:
 *     ./encryption
 *
 * Key concepts:
 * - Data encryption (AES-GCM)
 * - Message authentication (GMAC)
 * - Protection levels (RTPS, metadata, data)
 * - Key exchange protocols
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Encryption.
 * The native DDS Security Encryption API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

#define NUM_MESSAGES 5

void print_crypto_info(void) {
    printf("--- DDS Security Cryptography ---\n\n");
    printf("Encryption Algorithms:\n");
    printf("  - AES-128-GCM: Fast, hardware-accelerated encryption\n");
    printf("  - AES-256-GCM: Stronger encryption for sensitive data\n");
    printf("  - GMAC: Message authentication without encryption\n\n");

    printf("Protection Levels:\n");
    printf("  - RTPS Protection: Protects entire RTPS messages\n");
    printf("  - Metadata Protection: Protects discovery information\n");
    printf("  - Data Protection: Protects user data payload\n\n");

    printf("Key Exchange:\n");
    printf("  - Diffie-Hellman for shared secrets\n");
    printf("  - Per-endpoint session keys\n");
    printf("  - Automatic key rotation\n\n");
}

void print_protection_levels(void) {
    printf("--- Protection Level Comparison ---\n\n");
    printf("| Level          | Confidentiality | Integrity | Overhead |\n");
    printf("|----------------|-----------------|-----------|----------|\n");
    printf("| NONE           | No              | No        | 0 bytes  |\n");
    printf("| SIGN (GMAC)    | No              | Yes       | 16 bytes |\n");
    printf("| ENCRYPT (GCM)  | Yes             | Yes       | 16 bytes |\n");
    printf("| SIGN+ENCRYPT   | Yes             | Yes       | 32 bytes |\n\n");
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("Encryption Demo\n");
    printf("DDS Security cryptographic protection concepts\n");
    printf("============================================================\n\n");
    printf("NOTE: CONCEPT DEMO - Native DDS Security Encryption API not yet in SDK.\n");
    printf("      Using standard pub/sub API to demonstrate the pattern.\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    print_crypto_info();

    printf("--- Simulated Crypto Configuration ---\n");
    printf("  RTPS Protection:     ENCRYPT (AES-GCM)\n");
    printf("  Metadata Protection: SIGN (GMAC)\n");
    printf("  Data Protection:     ENCRYPT (AES-GCM)\n\n");

    /* Create participant */
    struct HddsParticipant* participant = hdds_participant_create("EncryptionDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));
    printf("     (Encryption would be enabled with security plugins)\n\n");

    /* Create endpoints */
    struct HddsQoS* qos = hdds_qos_reliable();
    struct HddsDataWriter* writer = hdds_writer_create_with_qos(participant, "EncryptedData", qos);
    struct HddsDataReader* reader = hdds_reader_create_with_qos(participant, "EncryptedData", qos);
    hdds_qos_destroy(qos);

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] DataWriter created (data would be encrypted)\n");
    printf("[OK] DataReader created (data would be decrypted)\n\n");

    printf("--- Encrypted Communication Demo ---\n\n");

    /* Simulate encrypted communication */
    const char* sensitive_data[] = {
        "credit_card=4111-XXXX-XXXX-1111",
        "password=EXAMPLE_DO_NOT_USE",
        "api_key=sk_test_EXAMPLE_DO_NOT_USE",
        "ssn=000-00-0000",
        "medical_record_id=MR-00000"
    };

    printf("Sending sensitive data (would be encrypted on wire):\n\n");

    for (int i = 0; i < NUM_MESSAGES; i++) {
        HelloWorld msg = {.id = i + 1};
        snprintf(msg.message, sizeof(msg.message), "%s", sensitive_data[i]);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

        printf("Plaintext:  \"%s\"\n", sensitive_data[i]);
        printf("Wire format: [AES-GCM encrypted + 16-byte auth tag]\n");

        if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
            printf("[SENT] Message %d transmitted securely\n\n", i + 1);
        }

        usleep(500000);
    }

    /* Show statistics */
    printf("--- Encryption Statistics (Simulated) ---\n\n");
    printf("Bytes encrypted:     %d\n", NUM_MESSAGES * 64);
    printf("Bytes decrypted:     0\n");
    printf("Messages sent:       %d\n", NUM_MESSAGES);
    printf("Messages received:   0\n");
    printf("Auth tag failures:   0\n\n");

    print_protection_levels();

    printf("Recommendations:\n");
    printf("  - Use ENCRYPT for sensitive user data\n");
    printf("  - Use SIGN for discovery metadata (performance)\n");
    printf("  - Use NONE only in fully trusted networks\n");

    /* Cleanup */
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Encryption Demo Complete ===\n");
    return 0;
}
