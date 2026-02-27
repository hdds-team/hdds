// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Sequences Sample - Demonstrates DDS sequence types
 *
 * This sample shows how to work with sequence types:
 * - Unbounded sequences (variable length)
 * - Bounded sequences (with max length)
 * - Sequences of primitives and strings
 */

#include <stdio.h>
#include <string.h>
#include "generated/Sequences.h"

static void print_long_array(const int32_t* arr, uint32_t count) {
    printf("[");
    for (uint32_t i = 0; i < count; ++i) {
        if (i > 0) printf(", ");
        printf("%d", arr[i]);
    }
    printf("]");
}

int main(void) {
    printf("=== HDDS Sequence Types Sample ===\n\n");

    uint8_t buffer[8192];

    /* LongSeq - unbounded sequence of integers */
    printf("--- LongSeq (unbounded) ---\n");
    LongSeq long_seq;
    long_seq.count = 8;
    int32_t long_values[] = {1, 2, 3, 4, 5, -10, 100, 1000};
    memcpy(long_seq.values, long_values, sizeof(long_values));

    printf("Original: ");
    print_long_array(long_seq.values, long_seq.count);
    printf("\nLength: %u\n", long_seq.count);

    size_t size = LongSeq_serialize(&long_seq, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    LongSeq long_deser;
    LongSeq_deserialize(&long_deser, buffer, size);
    printf("Deserialized: ");
    print_long_array(long_deser.values, long_deser.count);
    printf("\n");

    if (long_seq.count == long_deser.count &&
        memcmp(long_seq.values, long_deser.values, long_seq.count * sizeof(int32_t)) == 0) {
        printf("[OK] LongSeq round-trip successful\n\n");
    }

    /* StringSeq - sequence of strings */
    printf("--- StringSeq (unbounded) ---\n");
    StringSeq string_seq;
    string_seq.count = 4;
    strcpy(string_seq.values[0], "Hello");
    strcpy(string_seq.values[1], "World");
    strcpy(string_seq.values[2], "DDS");
    strcpy(string_seq.values[3], "Sequences");

    printf("Original: [");
    for (uint32_t i = 0; i < string_seq.count; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", string_seq.values[i]);
    }
    printf("]\nLength: %u\n", string_seq.count);

    size = StringSeq_serialize(&string_seq, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    StringSeq str_deser;
    StringSeq_deserialize(&str_deser, buffer, size);
    printf("Deserialized: [");
    for (uint32_t i = 0; i < str_deser.count; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", str_deser.values[i]);
    }
    printf("]\n");

    bool str_match = (string_seq.count == str_deser.count);
    for (uint32_t i = 0; str_match && i < string_seq.count; ++i) {
        str_match = (strcmp(string_seq.values[i], str_deser.values[i]) == 0);
    }
    if (str_match) {
        printf("[OK] StringSeq round-trip successful\n\n");
    }

    /* BoundedLongSeq - bounded sequence (max 10 elements) */
    printf("--- BoundedLongSeq (max 10) ---\n");
    BoundedLongSeq bounded_seq;
    bounded_seq.count = 5;
    int32_t bounded_values[] = {10, 20, 30, 40, 50};
    memcpy(bounded_seq.values, bounded_values, sizeof(bounded_values));

    printf("Original: ");
    print_long_array(bounded_seq.values, bounded_seq.count);
    printf("\nLength: %u (max: %d)\n", bounded_seq.count, BOUNDED_LONG_SEQ_MAX_SIZE);

    size = BoundedLongSeq_serialize(&bounded_seq, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    BoundedLongSeq bounded_deser;
    BoundedLongSeq_deserialize(&bounded_deser, buffer, size);
    printf("Deserialized: ");
    print_long_array(bounded_deser.values, bounded_deser.count);
    printf("\n");

    if (bounded_seq.count == bounded_deser.count) {
        printf("[OK] BoundedLongSeq round-trip successful\n\n");
    }

    /* Test empty sequences */
    printf("--- Empty Sequence Test ---\n");
    LongSeq empty_long;
    empty_long.count = 0;

    size = LongSeq_serialize(&empty_long, buffer, sizeof(buffer));
    LongSeq empty_deser;
    LongSeq_deserialize(&empty_deser, buffer, size);

    printf("Empty sequence length: %u\n", empty_deser.count);
    if (empty_deser.count == 0) {
        printf("[OK] Empty sequence handled correctly\n");
    }

    /* Test sequence with max elements */
    printf("\n--- Max Bounded Sequence Test ---\n");
    BoundedLongSeq max_seq;
    max_seq.count = BOUNDED_LONG_SEQ_MAX_SIZE;
    for (int i = 0; i < BOUNDED_LONG_SEQ_MAX_SIZE; ++i) {
        max_seq.values[i] = i * 10;
    }

    size = BoundedLongSeq_serialize(&max_seq, buffer, sizeof(buffer));
    printf("Max bounded sequence size: %zu bytes\n", size);

    BoundedLongSeq max_deser;
    BoundedLongSeq_deserialize(&max_deser, buffer, size);
    if (max_seq.count == max_deser.count) {
        printf("[OK] Max bounded sequence handled correctly\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
