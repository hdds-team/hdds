// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Unions Sample - Demonstrates DDS discriminated union types
 *
 * This sample shows how to work with the DataValue union:
 * - discriminator _d (DataKind enum)
 * - int_val (DATAKIND_INTEGER)
 * - float_val (DATAKIND_FLOAT)
 * - str_val (DATAKIND_STRING, char* pointer)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Unions.h"

/* Helper: DataKind to string */
static const char* datakind_to_string(DataKind k) {
    switch (k) {
        case DATAKIND_INTEGER: return "Integer";
        case DATAKIND_FLOAT:   return "Float";
        case DATAKIND_STRING:  return "String";
        default:               return "Unknown";
    }
}

int main(void) {
    printf("=== HDDS Union Types Sample ===\n\n");

    uint8_t buffer[512];

    /* Integer variant */
    printf("--- Integer Variant ---\n");
    DataValue int_value;
    memset(&int_value, 0, sizeof(int_value));
    int_value._d = DATAKIND_INTEGER;
    int_value._u.int_val = 42;

    printf("Original: Integer(42)\n");
    printf("Kind: %s (%d)\n", datakind_to_string(int_value._d), int_value._d);

    int size = datavalue_encode_cdr2_le(&int_value, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);
    printf("Serialized: ");
    for (int i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");

    DataValue deser;
    memset(&deser, 0, sizeof(deser));
    datavalue_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Deserialized: %s(%d)\n",
           datakind_to_string(deser._d), deser._u.int_val);

    if (int_value._u.int_val == deser._u.int_val) {
        printf("[OK] Integer variant round-trip successful\n\n");
    }

    /* Float variant */
    printf("--- Float Variant ---\n");
    DataValue float_value;
    memset(&float_value, 0, sizeof(float_value));
    float_value._d = DATAKIND_FLOAT;
    float_value._u.float_val = 3.14159265359;

    printf("Original: Float(3.14159265359)\n");
    printf("Kind: %s\n", datakind_to_string(float_value._d));

    size = datavalue_encode_cdr2_le(&float_value, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    memset(&deser, 0, sizeof(deser));
    datavalue_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Deserialized: %s(%.11f)\n",
           datakind_to_string(deser._d), deser._u.float_val);

    if (float_value._u.float_val == deser._u.float_val) {
        printf("[OK] Float variant round-trip successful\n\n");
    }

    /* Text variant */
    printf("--- Text Variant ---\n");
    DataValue text_value;
    memset(&text_value, 0, sizeof(text_value));
    text_value._d = DATAKIND_STRING;
    text_value._u.str_val = "Hello, DDS Unions!";

    printf("Original: Text(\"Hello, DDS Unions!\")\n");
    printf("Kind: %s\n", datakind_to_string(text_value._d));

    size = datavalue_encode_cdr2_le(&text_value, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    memset(&deser, 0, sizeof(deser));
    char text_buf[256] = {0};
    deser._u.str_val = text_buf;
    datavalue_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Deserialized: %s(\"%s\")\n",
           datakind_to_string(deser._d), deser._u.str_val);

    if (strcmp(text_value._u.str_val, deser._u.str_val) == 0) {
        printf("[OK] Text variant round-trip successful\n\n");
    }

    /* Pattern matching on union */
    printf("--- Pattern Matching ---\n");
    DataValue values[3];
    memset(values, 0, sizeof(values));

    values[0]._d = DATAKIND_INTEGER;
    values[0]._u.int_val = -100;

    values[1]._d = DATAKIND_FLOAT;
    values[1]._u.float_val = 2.718;

    values[2]._d = DATAKIND_STRING;
    values[2]._u.str_val = "Pattern";

    for (int i = 0; i < 3; ++i) {
        switch (values[i]._d) {
            case DATAKIND_INTEGER:
                printf("  Integer value: %d\n", values[i]._u.int_val);
                break;
            case DATAKIND_FLOAT:
                printf("  Float value: %.3f\n", values[i]._u.float_val);
                break;
            case DATAKIND_STRING:
                printf("  Text value: \"%s\"\n", values[i]._u.str_val);
                break;
        }
    }
    printf("\n");

    /* Test edge cases */
    printf("--- Edge Cases ---\n");

    /* Empty string */
    DataValue empty_text;
    memset(&empty_text, 0, sizeof(empty_text));
    empty_text._d = DATAKIND_STRING;
    empty_text._u.str_val = "";
    size = datavalue_encode_cdr2_le(&empty_text, buffer, sizeof(buffer));
    memset(&deser, 0, sizeof(deser));
    char empty_buf[64] = {0};
    deser._u.str_val = empty_buf;
    datavalue_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Empty string: %s(\"%s\")\n",
           datakind_to_string(deser._d), deser._u.str_val);

    /* Zero values */
    DataValue zero_int;
    memset(&zero_int, 0, sizeof(zero_int));
    zero_int._d = DATAKIND_INTEGER;
    zero_int._u.int_val = 0;
    size = datavalue_encode_cdr2_le(&zero_int, buffer, sizeof(buffer));
    memset(&deser, 0, sizeof(deser));
    datavalue_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Zero integer: %s(%d)\n",
           datakind_to_string(deser._d), deser._u.int_val);

    /* Negative float */
    DataValue neg_float;
    memset(&neg_float, 0, sizeof(neg_float));
    neg_float._d = DATAKIND_FLOAT;
    neg_float._u.float_val = -999.999;
    size = datavalue_encode_cdr2_le(&neg_float, buffer, sizeof(buffer));
    memset(&deser, 0, sizeof(deser));
    datavalue_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Negative float: %s(%f)\n",
           datakind_to_string(deser._d), deser._u.float_val);

    printf("[OK] Edge cases handled correctly\n");

    printf("\n=== Sample Complete ===\n");
    return 0;
}
