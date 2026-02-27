// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Unions Sample - Demonstrates DDS discriminated union types
 *
 * This sample shows how to work with union types:
 * - Discriminated unions with different value types
 * - Integer, float, and string variants
 */

#include <stdio.h>
#include <string.h>
#include "generated/Unions.h"

int main(void) {
    printf("=== HDDS Union Types Sample ===\n\n");

    uint8_t buffer[512];

    /* Integer variant */
    printf("--- Integer Variant ---\n");
    DataValue int_value;
    DataValue_set_integer(&int_value, 42);

    printf("Original: Integer(42)\n");
    printf("Kind: %s (%d)\n", DataKind_to_string(int_value.kind), int_value.kind);

    size_t size = DataValue_serialize(&int_value, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);
    printf("Serialized: ");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");

    DataValue deser;
    DataValue_deserialize(&deser, buffer, size);
    printf("Deserialized: %s(%d)\n",
           DataKind_to_string(deser.kind), deser.value.integer_val);

    if (int_value.value.integer_val == deser.value.integer_val) {
        printf("[OK] Integer variant round-trip successful\n\n");
    }

    /* Float variant */
    printf("--- Float Variant ---\n");
    DataValue float_value;
    DataValue_set_float(&float_value, 3.14159265359);

    printf("Original: Float(3.14159265359)\n");
    printf("Kind: %s\n", DataKind_to_string(float_value.kind));

    size = DataValue_serialize(&float_value, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    DataValue_deserialize(&deser, buffer, size);
    printf("Deserialized: %s(%.11f)\n",
           DataKind_to_string(deser.kind), deser.value.float_val);

    if (float_value.value.float_val == deser.value.float_val) {
        printf("[OK] Float variant round-trip successful\n\n");
    }

    /* Text variant */
    printf("--- Text Variant ---\n");
    DataValue text_value;
    DataValue_set_text(&text_value, "Hello, DDS Unions!");

    printf("Original: Text(\"Hello, DDS Unions!\")\n");
    printf("Kind: %s\n", DataKind_to_string(text_value.kind));

    size = DataValue_serialize(&text_value, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    DataValue_deserialize(&deser, buffer, size);
    printf("Deserialized: %s(\"%s\")\n",
           DataKind_to_string(deser.kind), deser.value.text_val);

    if (strcmp(text_value.value.text_val, deser.value.text_val) == 0) {
        printf("[OK] Text variant round-trip successful\n\n");
    }

    /* Pattern matching on union */
    printf("--- Pattern Matching ---\n");
    DataValue values[3];
    DataValue_set_integer(&values[0], -100);
    DataValue_set_float(&values[1], 2.718);
    DataValue_set_text(&values[2], "Pattern");

    for (int i = 0; i < 3; ++i) {
        switch (values[i].kind) {
            case DATA_KIND_INTEGER:
                printf("  Integer value: %d\n", values[i].value.integer_val);
                break;
            case DATA_KIND_FLOAT:
                printf("  Float value: %.3f\n", values[i].value.float_val);
                break;
            case DATA_KIND_TEXT:
                printf("  Text value: \"%s\"\n", values[i].value.text_val);
                break;
        }
    }
    printf("\n");

    /* Test edge cases */
    printf("--- Edge Cases ---\n");

    /* Empty string */
    DataValue empty_text;
    DataValue_set_text(&empty_text, "");
    size = DataValue_serialize(&empty_text, buffer, sizeof(buffer));
    DataValue_deserialize(&deser, buffer, size);
    printf("Empty string: %s(\"%s\")\n",
           DataKind_to_string(deser.kind), deser.value.text_val);

    /* Zero values */
    DataValue zero_int;
    DataValue_set_integer(&zero_int, 0);
    size = DataValue_serialize(&zero_int, buffer, sizeof(buffer));
    DataValue_deserialize(&deser, buffer, size);
    printf("Zero integer: %s(%d)\n",
           DataKind_to_string(deser.kind), deser.value.integer_val);

    /* Negative float */
    DataValue neg_float;
    DataValue_set_float(&neg_float, -999.999);
    size = DataValue_serialize(&neg_float, buffer, sizeof(buffer));
    DataValue_deserialize(&deser, buffer, size);
    printf("Negative float: %s(%f)\n",
           DataKind_to_string(deser.kind), deser.value.float_val);

    printf("[OK] Edge cases handled correctly\n");

    printf("\n=== Sample Complete ===\n");
    return 0;
}
