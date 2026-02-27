// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Access Control (C)
 *
 * Demonstrates DDS Security access control concepts.
 * Shows how governance and permissions documents control access.
 *
 * Usage:
 *     ./access_control
 *
 * Key concepts:
 * - Governance document (domain-level rules)
 * - Permissions document (participant-level rules)
 * - Topic read/write permissions
 * - Domain and partition access
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Access Control.
 * The native DDS Security Access Control API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

void print_sample_governance(void) {
    printf("Sample Governance Document:\n");
    printf("  <domain_access_rules>\n");
    printf("    <domain_rule>\n");
    printf("      <domains><id>0</id></domains>\n");
    printf("      <allow_unauthenticated_participants>false</..>\n");
    printf("      <enable_discovery_protection>true</..>\n");
    printf("      <topic_access_rules>\n");
    printf("        <topic_rule>\n");
    printf("          <topic_expression>*</topic_expression>\n");
    printf("          <enable_data_protection>true</..>\n");
    printf("        </topic_rule>\n");
    printf("      </topic_access_rules>\n");
    printf("    </domain_rule>\n");
    printf("  </domain_access_rules>\n\n");
}

void print_sample_permissions(const char* subject) {
    printf("Sample Permissions Document:\n");
    printf("  <permissions>\n");
    printf("    <grant name=\"SensorGrant\">\n");
    printf("      <subject_name>%s</subject_name>\n", subject);
    printf("      <allow_rule>\n");
    printf("        <domains><id>0</id></domains>\n");
    printf("        <publish><topics><topic>SensorData</topic></topics></publish>\n");
    printf("        <subscribe><topics><topic>*</topic></topics></subscribe>\n");
    printf("      </allow_rule>\n");
    printf("      <deny_rule>\n");
    printf("        <publish><topics><topic>AdminTopic</topic></topics></publish>\n");
    printf("      </deny_rule>\n");
    printf("    </grant>\n");
    printf("  </permissions>\n\n");
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("Access Control Demo\n");
    printf("DDS Security permissions and governance concepts\n");
    printf("============================================================\n\n");
    printf("NOTE: CONCEPT DEMO - Native DDS Security Access Control API not yet in SDK.\n");
    printf("      Using standard pub/sub API to demonstrate the pattern.\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    const char* participant_name = "SensorNode";
    const char* subject_name = "CN=SensorNode,O=HDDS,C=US";

    printf("--- DDS Security Access Control ---\n");
    printf("Access control uses two XML documents:\n");
    printf("1. Governance: Domain-wide security policies\n");
    printf("2. Permissions: Per-participant access rights\n\n");

    print_sample_governance();
    print_sample_permissions(subject_name);

    /* Create participant */
    struct HddsParticipant* participant = hdds_participant_create("AccessControlDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));
    printf("     Subject: %s\n\n", subject_name);

    printf("--- Testing Topic Permissions (Simulated) ---\n\n");

    /* Simulate permission checks */
    struct {
        const char* topic;
        int can_pub;
        int can_sub;
    } test_topics[] = {
        {"SensorData", 1, 1},
        {"CommandTopic", 0, 1},
        {"AdminTopic", 0, 0},
        {"LogData", 1, 1}
    };

    for (int i = 0; i < 4; i++) {
        printf("Topic '%s':\n", test_topics[i].topic);
        printf("  Publish:   %s\n", test_topics[i].can_pub ? "ALLOWED" : "DENIED");
        printf("  Subscribe: %s\n\n", test_topics[i].can_sub ? "ALLOWED" : "DENIED");
    }

    /* Create allowed endpoints */
    printf("--- Creating Endpoints ---\n\n");

    struct HddsDataWriter* writer = hdds_writer_create(participant, "SensorData");
    if (writer) {
        printf("[OK] Writer created for 'SensorData' (allowed)\n");
    }

    struct HddsDataReader* reader = hdds_reader_create(participant, "CommandTopic");
    if (reader) {
        printf("[OK] Reader created for 'CommandTopic' (allowed)\n");
    }

    printf("[INFO] Writer for 'AdminTopic' would be DENIED\n\n");

    /* Send some data */
    if (writer) {
        printf("--- Sending Permitted Data ---\n\n");

        for (int i = 0; i < 3; i++) {
            HelloWorld msg = {.id = i + 1};
            snprintf(msg.message, sizeof(msg.message), "Sensor reading #%d", i + 1);

            uint8_t buffer[256];
            size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));

            if (hdds_writer_write(writer, buffer, len) == HDDS_OK) {
                printf("[SENT] id=%d msg='%s'\n", msg.id, msg.message);
            }

            usleep(500000);
        }
    }

    /* Summary */
    printf("\n--- Access Control Summary ---\n");
    printf("Participant: %s\n", participant_name);
    printf("Subject DN: %s\n\n", subject_name);
    printf("Configured Permissions:\n");
    printf("  - Can publish to: SensorData, LogData\n");
    printf("  - Cannot publish to: AdminTopic, CommandTopic\n");
    printf("  - Can subscribe to: all topics\n\n");
    printf("Note: When DDS Security is enabled, permissions are enforced\n");
    printf("      at endpoint creation time. Access violations are rejected.\n");

    /* Cleanup */
    if (writer) hdds_writer_destroy(writer);
    if (reader) hdds_reader_destroy(reader);
    hdds_participant_destroy(participant);

    printf("\n=== Access Control Demo Complete ===\n");
    return 0;
}
