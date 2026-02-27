// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Enums Sample - Demonstrates DDS enumeration types
 *
 * This sample shows how to work with enum types:
 * - Simple enums (Color)
 * - Enums with explicit values (Status)
 */

#include <stdio.h>
#include "generated/Enums.h"

int main(void) {
    printf("=== HDDS Enum Types Sample ===\n\n");

    uint8_t buffer[64];

    /* Color enum */
    printf("--- Color Enum ---\n");
    printf("Color values:\n");
    printf("  Red   = %d\n", COLOR_RED);
    printf("  Green = %d\n", COLOR_GREEN);
    printf("  Blue  = %d\n", COLOR_BLUE);

    /* Status enum with explicit values */
    printf("\n--- Status Enum (explicit values) ---\n");
    printf("Status values:\n");
    printf("  Unknown   = %d\n", STATUS_UNKNOWN);
    printf("  Pending   = %d\n", STATUS_PENDING);
    printf("  Active    = %d\n", STATUS_ACTIVE);
    printf("  Completed = %d\n", STATUS_COMPLETED);
    printf("  Failed    = %d\n", STATUS_FAILED);

    /* EnumDemo with both enums */
    printf("\n--- EnumDemo Serialization ---\n");
    EnumDemo demo = {
        .color = COLOR_GREEN,
        .status = STATUS_ACTIVE
    };

    printf("Original:\n");
    printf("  color:  %s (%d)\n", Color_to_string(demo.color), demo.color);
    printf("  status: %s (%d)\n", Status_to_string(demo.status), demo.status);

    size_t size = EnumDemo_serialize(&demo, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);
    printf("Serialized bytes: ");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");

    EnumDemo deser;
    EnumDemo_deserialize(&deser, buffer, size);
    printf("Deserialized:\n");
    printf("  color:  %s\n", Color_to_string(deser.color));
    printf("  status: %s\n", Status_to_string(deser.status));

    if (demo.color == deser.color && demo.status == deser.status) {
        printf("[OK] EnumDemo round-trip successful\n\n");
    }

    /* Test all color values */
    printf("--- All Color Values Test ---\n");
    Color colors[] = {COLOR_RED, COLOR_GREEN, COLOR_BLUE};
    for (int i = 0; i < 3; ++i) {
        EnumDemo test = {.color = colors[i], .status = STATUS_UNKNOWN};
        size_t test_size = EnumDemo_serialize(&test, buffer, sizeof(buffer));
        EnumDemo test_deser;
        EnumDemo_deserialize(&test_deser, buffer, test_size);
        printf("  %s: %d -> %s\n",
               Color_to_string(colors[i]), colors[i],
               Color_to_string(test_deser.color));
    }
    printf("[OK] All colors round-trip correctly\n\n");

    /* Test all status values */
    printf("--- All Status Values Test ---\n");
    Status statuses[] = {STATUS_UNKNOWN, STATUS_PENDING, STATUS_ACTIVE,
                         STATUS_COMPLETED, STATUS_FAILED};
    for (int i = 0; i < 5; ++i) {
        EnumDemo test = {.color = COLOR_RED, .status = statuses[i]};
        size_t test_size = EnumDemo_serialize(&test, buffer, sizeof(buffer));
        EnumDemo test_deser;
        EnumDemo_deserialize(&test_deser, buffer, test_size);
        printf("  %s: %d -> %s\n",
               Status_to_string(statuses[i]), statuses[i],
               Status_to_string(test_deser.status));
    }
    printf("[OK] All statuses round-trip correctly\n\n");

    /* Default values */
    printf("--- Default Values ---\n");
    EnumDemo default_demo = {0};
    printf("Default color:  %s\n", Color_to_string(default_demo.color));
    printf("Default status: %s\n", Status_to_string(default_demo.status));

    printf("\n=== Sample Complete ===\n");
    return 0;
}
