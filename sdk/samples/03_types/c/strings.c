// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Strings Sample - Demonstrates DDS string types
 *
 * This sample shows how to work with string types:
 * - Unbounded strings
 * - Bounded strings (with length limit)
 * - Wide strings (wstring)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Strings.h"

int main(void) {
    printf("=== HDDS String Types Sample ===\n\n");

    /* Create a Strings instance */
    Strings original;
    strncpy(original.unbounded_str, "This is an unbounded string (up to buffer limit)",
            STRINGS_MAX_UNBOUNDED - 1);
    strncpy(original.bounded_str, "Bounded to 256 chars",
            STRINGS_MAX_BOUNDED - 1);
    strncpy(original.wide_str, "Wide string with UTF-8: Hello World!",
            STRINGS_MAX_WIDE - 1);

    printf("Original Strings:\n");
    printf("  unbounded_str: \"%s\"\n", original.unbounded_str);
    printf("  bounded_str:   \"%s\" (max 256 chars)\n", original.bounded_str);
    printf("  wide_str:      \"%s\"\n", original.wide_str);

    /* Serialize */
    uint8_t buffer[4096];
    size_t serialized_size = Strings_serialize(&original, buffer, sizeof(buffer));
    printf("\nSerialized size: %zu bytes\n", serialized_size);

    if (serialized_size == 0) {
        printf("[ERROR] Serialization failed!\n");
        return 1;
    }

    /* Deserialize */
    Strings deserialized;
    if (!Strings_deserialize(&deserialized, buffer, serialized_size)) {
        printf("[ERROR] Deserialization failed!\n");
        return 1;
    }

    printf("\nDeserialized:\n");
    printf("  unbounded_str: \"%s\"\n", deserialized.unbounded_str);
    printf("  bounded_str:   \"%s\"\n", deserialized.bounded_str);
    printf("  wide_str:      \"%s\"\n", deserialized.wide_str);

    /* Verify round-trip */
    if (strcmp(original.unbounded_str, deserialized.unbounded_str) == 0 &&
        strcmp(original.bounded_str, deserialized.bounded_str) == 0 &&
        strcmp(original.wide_str, deserialized.wide_str) == 0) {
        printf("\n[OK] Round-trip serialization successful!\n");
    } else {
        printf("\n[ERROR] Round-trip verification failed!\n");
        return 1;
    }

    /* Test empty strings */
    printf("\n--- Empty String Test ---\n");
    Strings empty;
    memset(&empty, 0, sizeof(empty));

    size_t empty_size = Strings_serialize(&empty, buffer, sizeof(buffer));
    Strings empty_deser;
    Strings_deserialize(&empty_deser, buffer, empty_size);

    if (strlen(empty_deser.unbounded_str) == 0) {
        printf("[OK] Empty strings handled correctly\n");
    }

    /* Test different length strings */
    printf("\n--- Various Length Test ---\n");
    Strings varied;
    strcpy(varied.unbounded_str, "Short");
    memset(varied.bounded_str, 'X', 200);
    varied.bounded_str[200] = '\0';
    strcpy(varied.wide_str, "Medium length string here");

    size_t varied_size = Strings_serialize(&varied, buffer, sizeof(buffer));
    Strings varied_deser;
    Strings_deserialize(&varied_deser, buffer, varied_size);

    printf("String lengths:\n");
    printf("  unbounded_str: %zu chars\n", strlen(varied_deser.unbounded_str));
    printf("  bounded_str:   %zu chars\n", strlen(varied_deser.bounded_str));
    printf("  wide_str:      %zu chars\n", strlen(varied_deser.wide_str));

    if (strcmp(varied.bounded_str, varied_deser.bounded_str) == 0) {
        printf("[OK] Various length strings handled correctly\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
