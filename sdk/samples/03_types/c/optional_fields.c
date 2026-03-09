// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Optional Fields Sample - Demonstrates DDS optional field types
 *
 * This sample shows how to work with optional fields:
 * - required_id (always present)
 * - optional_name (has_optional_name flag + char* pointer)
 * - optional_value (has_optional_value flag + double)
 * - optional_data (has_optional_data flag + sequence<long>)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Optional.h"

int main(void) {
    printf("=== HDDS Optional Fields Sample ===\n\n");

    uint8_t buffer[1024];

    /* All fields present */
    printf("--- All Fields Present ---\n");
    OptionalFields full;
    memset(&full, 0, sizeof(full));
    full.required_id = 42;
    full.has_optional_name = 1;
    full.optional_name = "Complete";
    full.has_optional_value = 1;
    full.optional_value = 3.14159;
    full.has_optional_data = 1;
    int32_t data_buf[] = {10, 20, 30};
    full.optional_data.data = data_buf;
    full.optional_data.len = 3;

    printf("Original:\n");
    printf("  required_id:    %d\n", full.required_id);
    printf("  optional_name:  %s\n",
           full.has_optional_name ? full.optional_name : "(none)");
    printf("  optional_value: ");
    if (full.has_optional_value) {
        printf("%f\n", full.optional_value);
    } else {
        printf("(none)\n");
    }
    printf("  optional_data:  ");
    if (full.has_optional_data) {
        printf("[");
        for (uint32_t i = 0; i < full.optional_data.len; ++i) {
            if (i > 0) printf(", ");
            printf("%d", full.optional_data.data[i]);
        }
        printf("]\n");
    } else {
        printf("(none)\n");
    }

    int size = optionalfields_encode_cdr2_le(&full, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    OptionalFields deser;
    memset(&deser, 0, sizeof(deser));
    char name_deser_buf[256] = {0};
    deser.optional_name = name_deser_buf;
    int32_t data_deser_buf[64] = {0};
    deser.optional_data.data = data_deser_buf;
    deser.optional_data.len = 0;

    optionalfields_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Deserialized:\n");
    printf("  required_id:    %d\n", deser.required_id);
    printf("  optional_name:  %s\n",
           deser.has_optional_name ? deser.optional_name : "(none)");

    if (full.required_id == deser.required_id) {
        printf("[OK] Full struct round-trip successful\n\n");
    }

    /* Only required field */
    printf("--- Only Required Field ---\n");
    OptionalFields minimal;
    memset(&minimal, 0, sizeof(minimal));
    minimal.required_id = 1;
    minimal.has_optional_name = 0;
    minimal.optional_name = NULL;
    minimal.has_optional_value = 0;
    minimal.has_optional_data = 0;
    minimal.optional_data.data = NULL;
    minimal.optional_data.len = 0;

    printf("Original:\n");
    printf("  required_id:    %d\n", minimal.required_id);
    printf("  optional_name:  %s\n", minimal.has_optional_name ? "(set)" : "(none)");
    printf("  optional_value: %s\n", minimal.has_optional_value ? "(set)" : "(none)");
    printf("  optional_data:  %s\n", minimal.has_optional_data ? "(set)" : "(none)");

    size = optionalfields_encode_cdr2_le(&minimal, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes (minimal)\n", size);

    memset(&deser, 0, sizeof(deser));
    deser.optional_name = name_deser_buf;
    deser.optional_data.data = data_deser_buf;
    deser.optional_data.len = 0;

    optionalfields_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Deserialized:\n");
    bool all_empty = !deser.has_optional_name &&
                     !deser.has_optional_value &&
                     !deser.has_optional_data;
    printf("  all optionals are None: %s\n", all_empty ? "true" : "false");

    if (minimal.required_id == deser.required_id && all_empty) {
        printf("[OK] Minimal struct round-trip successful\n\n");
    }

    /* Partial fields */
    printf("--- Partial Fields ---\n");
    OptionalFields partial;
    memset(&partial, 0, sizeof(partial));
    partial.required_id = 99;
    partial.has_optional_name = 1;
    partial.optional_name = "Partial";
    partial.has_optional_value = 0;
    partial.has_optional_data = 0;
    partial.optional_data.data = NULL;
    partial.optional_data.len = 0;

    printf("Original:\n");
    printf("  required_id:    %d\n", partial.required_id);
    printf("  optional_name:  \"%s\"\n", partial.optional_name);
    printf("  optional_value: %s\n", partial.has_optional_value ? "(set)" : "(none)");
    printf("  optional_data:  %s\n", partial.has_optional_data ? "(set)" : "(none)");

    size = optionalfields_encode_cdr2_le(&partial, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    memset(&deser, 0, sizeof(deser));
    memset(name_deser_buf, 0, sizeof(name_deser_buf));
    deser.optional_name = name_deser_buf;
    deser.optional_data.data = data_deser_buf;
    deser.optional_data.len = 0;

    optionalfields_decode_cdr2_le(&deser, buffer, (size_t)size);

    if (deser.has_optional_name &&
        strcmp(partial.optional_name, deser.optional_name) == 0) {
        printf("[OK] Partial struct round-trip successful\n\n");
    }

    /* Various combinations */
    printf("--- Various Combinations ---\n");

    OptionalFields s1, s2, s3, s4, s5;

    memset(&s1, 0, sizeof(s1));
    s1.required_id = 1;

    memset(&s2, 0, sizeof(s2));
    s2.required_id = 2;
    s2.has_optional_name = 1;
    s2.optional_name = "Named";

    memset(&s3, 0, sizeof(s3));
    s3.required_id = 3;
    s3.has_optional_value = 1;
    s3.optional_value = 2.718;

    memset(&s4, 0, sizeof(s4));
    s4.required_id = 4;
    s4.has_optional_data = 1;
    int32_t s4_data[] = {1, 2, 3};
    s4.optional_data.data = s4_data;
    s4.optional_data.len = 3;

    memset(&s5, 0, sizeof(s5));
    s5.required_id = 5;
    s5.has_optional_name = 1;
    s5.optional_name = "All";
    s5.has_optional_value = 1;
    s5.optional_value = 1.0;
    s5.has_optional_data = 1;
    int32_t s5_data[] = {99};
    s5.optional_data.data = s5_data;
    s5.optional_data.len = 1;

    OptionalFields* structs[] = {&s1, &s2, &s3, &s4, &s5};
    for (int i = 0; i < 5; ++i) {
        OptionalFields* s = structs[i];
        printf("  ID %d: ", s->required_id);

        bool has_name = s->has_optional_name;
        bool has_value = s->has_optional_value;
        bool has_data = s->has_optional_data;

        if (!has_name && !has_value && !has_data) {
            printf("(no optional fields)\n");
        } else {
            printf("has ");
            bool first = true;
            if (has_name) {
                printf("name");
                first = false;
            }
            if (has_value) {
                printf("%svalue", first ? "" : ", ");
                first = false;
            }
            if (has_data) {
                printf("%sdata", first ? "" : ", ");
            }
            printf("\n");
        }
    }
    printf("\n");

    /* Size comparison */
    printf("--- Size Comparison ---\n");
    OptionalFields min_struct, full_struct;

    memset(&min_struct, 0, sizeof(min_struct));
    min_struct.required_id = 1;

    memset(&full_struct, 0, sizeof(full_struct));
    full_struct.required_id = 1;
    full_struct.has_optional_name = 1;
    full_struct.optional_name = "Test Name";
    full_struct.has_optional_value = 1;
    full_struct.optional_value = 123.456;
    full_struct.has_optional_data = 1;
    int32_t full_data[] = {42};
    full_struct.optional_data.data = full_data;
    full_struct.optional_data.len = 1;

    int min_size = optionalfields_encode_cdr2_le(&min_struct, buffer, sizeof(buffer));
    int full_size = optionalfields_encode_cdr2_le(&full_struct, buffer, sizeof(buffer));

    printf("Minimal (required only): %d bytes\n", min_size);
    printf("Full (all fields):       %d bytes\n", full_size);
    printf("Space saved when optional fields absent: %d bytes\n",
           full_size - min_size);

    printf("\n=== Sample Complete ===\n");
    return 0;
}
