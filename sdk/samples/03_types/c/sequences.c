// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Sequences Sample - Demonstrates DDS sequence types
 *
 * This sample shows how to work with the Sequences struct:
 * - numbers: LongSeq (unbounded integer sequence)
 * - names: StringSeq (unbounded string sequence)
 * - bounded_numbers: BoundedLongSeq (bounded integer sequence)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Sequences.h"

static void print_long_seq(const int32_t* data, uint32_t count) {
    printf("[");
    for (uint32_t i = 0; i < count; ++i) {
        if (i > 0) printf(", ");
        printf("%d", data[i]);
    }
    printf("]");
}

int main(void) {
    printf("=== HDDS Sequence Types Sample ===\n\n");

    uint8_t buffer[8192];

    /* Sequences struct with numbers (LongSeq) */
    printf("--- LongSeq (unbounded) ---\n");
    Sequences seq;
    memset(&seq, 0, sizeof(seq));

    int32_t long_values[] = {1, 2, 3, 4, 5, -10, 100, 1000};
    seq.numbers.data = long_values;
    seq.numbers.len = 8;

    /* Leave names and bounded_numbers empty for this test */
    seq.names.data = NULL;
    seq.names.len = 0;
    seq.bounded_numbers.data = NULL;
    seq.bounded_numbers.len = 0;

    printf("Original: ");
    print_long_seq(seq.numbers.data, seq.numbers.len);
    printf("\nLength: %u\n", seq.numbers.len);

    int size = sequences_encode_cdr2_le(&seq, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Sequences seq_deser;
    memset(&seq_deser, 0, sizeof(seq_deser));
    int32_t deser_long_buf[64] = {0};
    seq_deser.numbers.data = deser_long_buf;
    seq_deser.numbers.len = 0;
    seq_deser.names.data = NULL;
    seq_deser.names.len = 0;
    seq_deser.bounded_numbers.data = NULL;
    seq_deser.bounded_numbers.len = 0;

    sequences_decode_cdr2_le(&seq_deser, buffer, (size_t)size);
    printf("Deserialized: ");
    print_long_seq(seq_deser.numbers.data, seq_deser.numbers.len);
    printf("\n");

    if (seq.numbers.len == seq_deser.numbers.len &&
        memcmp(seq.numbers.data, seq_deser.numbers.data,
               seq.numbers.len * sizeof(int32_t)) == 0) {
        printf("[OK] LongSeq round-trip successful\n\n");
    }

    /* StringSeq - sequence of strings */
    printf("--- StringSeq (unbounded) ---\n");
    Sequences str_seq;
    memset(&str_seq, 0, sizeof(str_seq));

    str_seq.numbers.data = NULL;
    str_seq.numbers.len = 0;

    char* str_ptrs[4] = {"Hello", "World", "DDS", "Sequences"};
    str_seq.names.data = str_ptrs;
    str_seq.names.len = 4;

    str_seq.bounded_numbers.data = NULL;
    str_seq.bounded_numbers.len = 0;

    printf("Original: [");
    for (uint32_t i = 0; i < str_seq.names.len; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", str_seq.names.data[i]);
    }
    printf("]\nLength: %u\n", str_seq.names.len);

    size = sequences_encode_cdr2_le(&str_seq, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Sequences str_deser;
    memset(&str_deser, 0, sizeof(str_deser));
    str_deser.numbers.data = NULL;
    str_deser.numbers.len = 0;

    char sbuf0[256] = {0}, sbuf1[256] = {0}, sbuf2[256] = {0}, sbuf3[256] = {0};
    char* deser_str_ptrs[4] = {sbuf0, sbuf1, sbuf2, sbuf3};
    str_deser.names.data = deser_str_ptrs;
    str_deser.names.len = 0;

    str_deser.bounded_numbers.data = NULL;
    str_deser.bounded_numbers.len = 0;

    sequences_decode_cdr2_le(&str_deser, buffer, (size_t)size);
    printf("Deserialized: [");
    for (uint32_t i = 0; i < str_deser.names.len; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", str_deser.names.data[i]);
    }
    printf("]\n");

    bool str_match = (str_seq.names.len == str_deser.names.len);
    for (uint32_t i = 0; str_match && i < str_seq.names.len; ++i) {
        str_match = (strcmp(str_seq.names.data[i], str_deser.names.data[i]) == 0);
    }
    if (str_match) {
        printf("[OK] StringSeq round-trip successful\n\n");
    }

    /* BoundedLongSeq - bounded sequence */
    printf("--- BoundedLongSeq (bounded) ---\n");
    Sequences bounded_seq;
    memset(&bounded_seq, 0, sizeof(bounded_seq));

    bounded_seq.numbers.data = NULL;
    bounded_seq.numbers.len = 0;
    bounded_seq.names.data = NULL;
    bounded_seq.names.len = 0;

    int32_t bounded_values[] = {10, 20, 30, 40, 50};
    bounded_seq.bounded_numbers.data = bounded_values;
    bounded_seq.bounded_numbers.len = 5;

    printf("Original: ");
    print_long_seq(bounded_seq.bounded_numbers.data, bounded_seq.bounded_numbers.len);
    printf("\nLength: %u\n", bounded_seq.bounded_numbers.len);

    size = sequences_encode_cdr2_le(&bounded_seq, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Sequences bounded_deser;
    memset(&bounded_deser, 0, sizeof(bounded_deser));
    bounded_deser.numbers.data = NULL;
    bounded_deser.numbers.len = 0;
    bounded_deser.names.data = NULL;
    bounded_deser.names.len = 0;
    int32_t deser_bounded_buf[10] = {0};
    bounded_deser.bounded_numbers.data = deser_bounded_buf;
    bounded_deser.bounded_numbers.len = 0;

    sequences_decode_cdr2_le(&bounded_deser, buffer, (size_t)size);
    printf("Deserialized: ");
    print_long_seq(bounded_deser.bounded_numbers.data, bounded_deser.bounded_numbers.len);
    printf("\n");

    if (bounded_seq.bounded_numbers.len == bounded_deser.bounded_numbers.len) {
        printf("[OK] BoundedLongSeq round-trip successful\n\n");
    }

    /* Test empty sequences */
    printf("--- Empty Sequence Test ---\n");
    Sequences empty_seq;
    memset(&empty_seq, 0, sizeof(empty_seq));
    empty_seq.numbers.data = NULL;
    empty_seq.numbers.len = 0;
    empty_seq.names.data = NULL;
    empty_seq.names.len = 0;
    empty_seq.bounded_numbers.data = NULL;
    empty_seq.bounded_numbers.len = 0;

    size = sequences_encode_cdr2_le(&empty_seq, buffer, sizeof(buffer));
    Sequences empty_deser;
    memset(&empty_deser, 0, sizeof(empty_deser));
    empty_deser.numbers.data = NULL;
    empty_deser.numbers.len = 0;
    empty_deser.names.data = NULL;
    empty_deser.names.len = 0;
    empty_deser.bounded_numbers.data = NULL;
    empty_deser.bounded_numbers.len = 0;

    sequences_decode_cdr2_le(&empty_deser, buffer, (size_t)size);

    printf("Empty sequence length: %u\n", empty_deser.numbers.len);
    if (empty_deser.numbers.len == 0) {
        printf("[OK] Empty sequence handled correctly\n");
    }

    /* Test sequence with max bounded elements */
    printf("\n--- Max Bounded Sequence Test ---\n");
    Sequences max_seq;
    memset(&max_seq, 0, sizeof(max_seq));
    max_seq.numbers.data = NULL;
    max_seq.numbers.len = 0;
    max_seq.names.data = NULL;
    max_seq.names.len = 0;

    int32_t max_values[10];
    for (int i = 0; i < 10; ++i) {
        max_values[i] = i * 10;
    }
    max_seq.bounded_numbers.data = max_values;
    max_seq.bounded_numbers.len = 10;

    size = sequences_encode_cdr2_le(&max_seq, buffer, sizeof(buffer));
    printf("Max bounded sequence size: %d bytes\n", size);

    Sequences max_deser;
    memset(&max_deser, 0, sizeof(max_deser));
    max_deser.numbers.data = NULL;
    max_deser.numbers.len = 0;
    max_deser.names.data = NULL;
    max_deser.names.len = 0;
    int32_t max_deser_buf[10] = {0};
    max_deser.bounded_numbers.data = max_deser_buf;
    max_deser.bounded_numbers.len = 0;

    sequences_decode_cdr2_le(&max_deser, buffer, (size_t)size);
    if (max_seq.bounded_numbers.len == max_deser.bounded_numbers.len) {
        printf("[OK] Max bounded sequence handled correctly\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
