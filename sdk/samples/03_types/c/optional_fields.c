// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Optional Fields Sample - Demonstrates DDS optional field types
 *
 * This sample shows how to work with optional fields:
 * - Required fields (always present)
 * - Optional fields (may be absent)
 * - Presence checking
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
    OptionalFields_init(&full, 42);
    OptionalFields_set_name(&full, "Complete");
    OptionalFields_set_value(&full, 3.14159);
    OptionalFields_set_count(&full, 100);

    printf("Original:\n");
    printf("  required_id:    %u\n", full.required_id);
    printf("  optional_name:  %s\n",
           OptionalFields_has_name(&full) ? full.optional_name : "(none)");
    printf("  optional_value: ");
    if (OptionalFields_has_value(&full)) {
        printf("%f\n", full.optional_value);
    } else {
        printf("(none)\n");
    }
    printf("  optional_count: ");
    if (OptionalFields_has_count(&full)) {
        printf("%d\n", full.optional_count);
    } else {
        printf("(none)\n");
    }

    size_t size = OptionalFields_serialize(&full, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    OptionalFields deser;
    OptionalFields_deserialize(&deser, buffer, size);
    printf("Deserialized:\n");
    printf("  required_id:    %u\n", deser.required_id);
    printf("  optional_name:  %s\n",
           OptionalFields_has_name(&deser) ? deser.optional_name : "(none)");

    if (full.required_id == deser.required_id) {
        printf("[OK] Full struct round-trip successful\n\n");
    }

    /* Only required field */
    printf("--- Only Required Field ---\n");
    OptionalFields minimal;
    OptionalFields_init(&minimal, 1);

    printf("Original:\n");
    printf("  required_id:    %u\n", minimal.required_id);
    printf("  optional_name:  %s\n",
           OptionalFields_has_name(&minimal) ? "(set)" : "(none)");
    printf("  optional_value: %s\n",
           OptionalFields_has_value(&minimal) ? "(set)" : "(none)");
    printf("  optional_count: %s\n",
           OptionalFields_has_count(&minimal) ? "(set)" : "(none)");

    size = OptionalFields_serialize(&minimal, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes (minimal)\n", size);

    OptionalFields_deserialize(&deser, buffer, size);
    printf("Deserialized:\n");
    bool all_empty = !OptionalFields_has_name(&deser) &&
                     !OptionalFields_has_value(&deser) &&
                     !OptionalFields_has_count(&deser);
    printf("  all optionals are None: %s\n", all_empty ? "true" : "false");

    if (minimal.required_id == deser.required_id && all_empty) {
        printf("[OK] Minimal struct round-trip successful\n\n");
    }

    /* Partial fields */
    printf("--- Partial Fields ---\n");
    OptionalFields partial;
    OptionalFields_init(&partial, 99);
    OptionalFields_set_name(&partial, "Partial");
    /* value and count not set */

    printf("Original:\n");
    printf("  required_id:    %u\n", partial.required_id);
    printf("  optional_name:  \"%s\"\n", partial.optional_name);
    printf("  optional_value: %s\n",
           OptionalFields_has_value(&partial) ? "(set)" : "(none)");
    printf("  optional_count: %s\n",
           OptionalFields_has_count(&partial) ? "(set)" : "(none)");

    size = OptionalFields_serialize(&partial, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    OptionalFields_deserialize(&deser, buffer, size);

    if (strcmp(partial.optional_name, deser.optional_name) == 0) {
        printf("[OK] Partial struct round-trip successful\n\n");
    }

    /* Various combinations */
    printf("--- Various Combinations ---\n");

    OptionalFields s1, s2, s3, s4, s5;
    OptionalFields_init(&s1, 1);
    OptionalFields_init(&s2, 2);
    OptionalFields_set_name(&s2, "Named");
    OptionalFields_init(&s3, 3);
    OptionalFields_set_value(&s3, 2.718);
    OptionalFields_init(&s4, 4);
    OptionalFields_set_count(&s4, -50);
    OptionalFields_init(&s5, 5);
    OptionalFields_set_name(&s5, "All");
    OptionalFields_set_value(&s5, 1.0);
    OptionalFields_set_count(&s5, 999);

    OptionalFields* structs[] = {&s1, &s2, &s3, &s4, &s5};
    for (int i = 0; i < 5; ++i) {
        OptionalFields* s = structs[i];
        printf("  ID %u: ", s->required_id);

        bool has_name = OptionalFields_has_name(s);
        bool has_value = OptionalFields_has_value(s);
        bool has_count = OptionalFields_has_count(s);

        if (!has_name && !has_value && !has_count) {
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
            if (has_count) {
                printf("%scount", first ? "" : ", ");
            }
            printf("\n");
        }
    }
    printf("\n");

    /* Size comparison */
    printf("--- Size Comparison ---\n");
    OptionalFields min_struct, full_struct;
    OptionalFields_init(&min_struct, 1);
    OptionalFields_init(&full_struct, 1);
    OptionalFields_set_name(&full_struct, "Test Name");
    OptionalFields_set_value(&full_struct, 123.456);
    OptionalFields_set_count(&full_struct, 42);

    size_t min_size = OptionalFields_serialize(&min_struct, buffer, sizeof(buffer));
    size_t full_size = OptionalFields_serialize(&full_struct, buffer, sizeof(buffer));

    printf("Minimal (required only): %zu bytes\n", min_size);
    printf("Full (all fields):       %zu bytes\n", full_size);
    printf("Space saved when optional fields absent: %zu bytes\n",
           full_size - min_size);

    printf("\n=== Sample Complete ===\n");
    return 0;
}
