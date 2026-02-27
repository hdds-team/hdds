// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Primitives Sample - Demonstrates all DDS primitive types
 *
 * This sample shows how to work with all basic DDS primitive types:
 * - bool, octet (uint8_t), char
 * - short (int16_t), unsigned short (uint16_t)
 * - long (int32_t), unsigned long (uint32_t)
 * - long long (int64_t), unsigned long long (uint64_t)
 * - float, double
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <float.h>
#include "generated/Primitives.h"

int main(void) {
    printf("=== HDDS Primitives Type Sample ===\n\n");

    /* Create a Primitives instance with all types */
    Primitives original = {
        .bool_val = true,
        .octet_val = 0xAB,
        .char_val = 'X',
        .short_val = -1234,
        .ushort_val = 5678,
        .long_val = -123456,
        .ulong_val = 789012,
        .llong_val = -9876543210LL,
        .ullong_val = 12345678901ULL,
        .float_val = 3.14159f,
        .double_val = 2.718281828,
    };

    printf("Original Primitives:\n");
    printf("  bool_val:   %s\n", original.bool_val ? "true" : "false");
    printf("  octet_val:  0x%02X (%u)\n", original.octet_val, original.octet_val);
    printf("  char_val:   '%c'\n", original.char_val);
    printf("  short_val:  %d\n", original.short_val);
    printf("  ushort_val: %u\n", original.ushort_val);
    printf("  long_val:   %d\n", original.long_val);
    printf("  ulong_val:  %u\n", original.ulong_val);
    printf("  llong_val:  %lld\n", (long long)original.llong_val);
    printf("  ullong_val: %llu\n", (unsigned long long)original.ullong_val);
    printf("  float_val:  %.5f\n", original.float_val);
    printf("  double_val: %.9f\n", original.double_val);

    /* Serialize */
    uint8_t buffer[256];
    size_t serialized_size = Primitives_serialize(&original, buffer, sizeof(buffer));
    printf("\nSerialized size: %zu bytes\n", serialized_size);
    printf("Serialized bytes (hex):\n");
    for (size_t i = 0; i < serialized_size; i += 16) {
        printf("  %04zX: ", i);
        for (size_t j = i; j < i + 16 && j < serialized_size; ++j) {
            printf("%02X ", buffer[j]);
        }
        printf("\n");
    }

    /* Deserialize */
    Primitives deserialized;
    if (!Primitives_deserialize(&deserialized, buffer, serialized_size)) {
        printf("\n[ERROR] Deserialization failed!\n");
        return 1;
    }

    printf("\nDeserialized:\n");
    printf("  bool_val:   %s\n", deserialized.bool_val ? "true" : "false");
    printf("  octet_val:  0x%02X\n", deserialized.octet_val);
    printf("  char_val:   '%c'\n", deserialized.char_val);
    printf("  short_val:  %d\n", deserialized.short_val);
    printf("  ushort_val: %u\n", deserialized.ushort_val);
    printf("  long_val:   %d\n", deserialized.long_val);
    printf("  ulong_val:  %u\n", deserialized.ulong_val);
    printf("  llong_val:  %lld\n", (long long)deserialized.llong_val);
    printf("  ullong_val: %llu\n", (unsigned long long)deserialized.ullong_val);
    printf("  float_val:  %.5f\n", deserialized.float_val);
    printf("  double_val: %.9f\n", deserialized.double_val);

    /* Verify round-trip */
    bool match = (original.bool_val == deserialized.bool_val &&
                  original.octet_val == deserialized.octet_val &&
                  original.char_val == deserialized.char_val &&
                  original.short_val == deserialized.short_val &&
                  original.ushort_val == deserialized.ushort_val &&
                  original.long_val == deserialized.long_val &&
                  original.ulong_val == deserialized.ulong_val &&
                  original.llong_val == deserialized.llong_val &&
                  original.ullong_val == deserialized.ullong_val);

    if (match) {
        printf("\n[OK] Round-trip serialization successful!\n");
    } else {
        printf("\n[ERROR] Round-trip verification failed!\n");
        return 1;
    }

    /* Test edge cases */
    printf("\n--- Edge Case Tests ---\n");

    Primitives edge_cases = {
        .bool_val = false,
        .octet_val = 0,
        .char_val = '\0',
        .short_val = SHRT_MIN,
        .ushort_val = USHRT_MAX,
        .long_val = INT_MIN,
        .ulong_val = UINT_MAX,
        .llong_val = LLONG_MIN,
        .ullong_val = ULLONG_MAX,
        .float_val = FLT_MIN,
        .double_val = DBL_MAX,
    };

    size_t edge_size = Primitives_serialize(&edge_cases, buffer, sizeof(buffer));
    Primitives edge_deserialized;
    Primitives_deserialize(&edge_deserialized, buffer, edge_size);

    printf("Edge case values:\n");
    printf("  i16 min = %d\n", edge_deserialized.short_val);
    printf("  u16 max = %u\n", edge_deserialized.ushort_val);
    printf("  i32 min = %d\n", edge_deserialized.long_val);
    printf("  u32 max = %u\n", edge_deserialized.ulong_val);
    printf("  i64 min = %lld\n", (long long)edge_deserialized.llong_val);
    printf("  u64 max = %llu\n", (unsigned long long)edge_deserialized.ullong_val);

    printf("\n[OK] Edge case round-trip successful!\n");

    printf("\n=== Sample Complete ===\n");
    return 0;
}
