// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Enums Sample - Demonstrates DDS enumeration types
 *
 * This sample shows how to work with the Enums struct:
 * - Color enum (Red=0, Green=1, Blue=2)
 * - Status enum (Unknown=0, Active=10, Inactive=20, Error=100)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Enums.h"

/* Helper: Color to string */
static const char* color_to_string(Color c) {
    switch (c) {
        case COLOR_RED:   return "Red";
        case COLOR_GREEN: return "Green";
        case COLOR_BLUE:  return "Blue";
        default:          return "Unknown";
    }
}

/* Helper: Status to string */
static const char* status_to_string(Status s) {
    switch (s) {
        case STATUS_UNKNOWN:  return "Unknown";
        case STATUS_ACTIVE:   return "Active";
        case STATUS_INACTIVE: return "Inactive";
        case STATUS_ERROR:    return "Error";
        default:              return "?";
    }
}

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
    printf("  Unknown  = %d\n", STATUS_UNKNOWN);
    printf("  Active   = %d\n", STATUS_ACTIVE);
    printf("  Inactive = %d\n", STATUS_INACTIVE);
    printf("  Error    = %d\n", STATUS_ERROR);

    /* Enums struct with both enums */
    printf("\n--- Enums Serialization ---\n");
    Enums demo = {
        .color = COLOR_GREEN,
        .status = STATUS_ACTIVE
    };

    printf("Original:\n");
    printf("  color:  %s (%d)\n", color_to_string(demo.color), demo.color);
    printf("  status: %s (%d)\n", status_to_string(demo.status), demo.status);

    int size = enums_encode_cdr2_le(&demo, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);
    printf("Serialized bytes: ");
    for (int i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");

    Enums deser;
    memset(&deser, 0, sizeof(deser));
    enums_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Deserialized:\n");
    printf("  color:  %s\n", color_to_string(deser.color));
    printf("  status: %s\n", status_to_string(deser.status));

    if (demo.color == deser.color && demo.status == deser.status) {
        printf("[OK] Enums round-trip successful\n\n");
    }

    /* Test all color values */
    printf("--- All Color Values Test ---\n");
    Color colors[] = {COLOR_RED, COLOR_GREEN, COLOR_BLUE};
    for (int i = 0; i < 3; ++i) {
        Enums test = {.color = colors[i], .status = STATUS_UNKNOWN};
        int test_size = enums_encode_cdr2_le(&test, buffer, sizeof(buffer));
        Enums test_deser;
        memset(&test_deser, 0, sizeof(test_deser));
        enums_decode_cdr2_le(&test_deser, buffer, (size_t)test_size);
        printf("  %s: %d -> %s\n",
               color_to_string(colors[i]), colors[i],
               color_to_string(test_deser.color));
    }
    printf("[OK] All colors round-trip correctly\n\n");

    /* Test all status values */
    printf("--- All Status Values Test ---\n");
    Status statuses[] = {STATUS_UNKNOWN, STATUS_ACTIVE, STATUS_INACTIVE, STATUS_ERROR};
    for (int i = 0; i < 4; ++i) {
        Enums test = {.color = COLOR_RED, .status = statuses[i]};
        int test_size = enums_encode_cdr2_le(&test, buffer, sizeof(buffer));
        Enums test_deser;
        memset(&test_deser, 0, sizeof(test_deser));
        enums_decode_cdr2_le(&test_deser, buffer, (size_t)test_size);
        printf("  %s: %d -> %s\n",
               status_to_string(statuses[i]), statuses[i],
               status_to_string(test_deser.status));
    }
    printf("[OK] All statuses round-trip correctly\n\n");

    /* Default values */
    printf("--- Default Values ---\n");
    Enums default_demo = {0};
    printf("Default color:  %s\n", color_to_string(default_demo.color));
    printf("Default status: %s\n", status_to_string(default_demo.status));

    printf("\n=== Sample Complete ===\n");
    return 0;
}
