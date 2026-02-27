// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Arrays Sample - Demonstrates DDS fixed-size array types
 *
 * This sample shows how to work with array types:
 * - Fixed-size integer arrays
 * - Fixed-size string arrays
 * - Multi-dimensional arrays (matrices)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Arrays.h"

int main(void) {
    printf("=== HDDS Array Types Sample ===\n\n");

    uint8_t buffer[1024];

    /* LongArray - fixed 10-element array */
    printf("--- LongArray (10 elements) ---\n");
    LongArray long_arr;
    for (int i = 0; i < LONG_ARRAY_SIZE; ++i) {
        long_arr.values[i] = i + 1;
    }

    printf("Original: [");
    for (int i = 0; i < LONG_ARRAY_SIZE; ++i) {
        if (i > 0) printf(", ");
        printf("%d", long_arr.values[i]);
    }
    printf("]\n");

    size_t size = LongArray_serialize(&long_arr, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes (10 × 4 = 40)\n", size);

    LongArray long_deser;
    LongArray_deserialize(&long_deser, buffer, size);
    printf("Deserialized: [");
    for (int i = 0; i < LONG_ARRAY_SIZE; ++i) {
        if (i > 0) printf(", ");
        printf("%d", long_deser.values[i]);
    }
    printf("]\n");

    if (memcmp(long_arr.values, long_deser.values, sizeof(long_arr.values)) == 0) {
        printf("[OK] LongArray round-trip successful\n\n");
    }

    /* StringArray - fixed 5-element string array */
    printf("--- StringArray (5 elements) ---\n");
    StringArray str_arr;
    strcpy(str_arr.values[0], "Alpha");
    strcpy(str_arr.values[1], "Beta");
    strcpy(str_arr.values[2], "Gamma");
    strcpy(str_arr.values[3], "Delta");
    strcpy(str_arr.values[4], "Epsilon");

    printf("Original: [");
    for (int i = 0; i < STRING_ARRAY_SIZE; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", str_arr.values[i]);
    }
    printf("]\n");

    size = StringArray_serialize(&str_arr, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    StringArray str_deser;
    StringArray_deserialize(&str_deser, buffer, size);
    printf("Deserialized: [");
    for (int i = 0; i < STRING_ARRAY_SIZE; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", str_deser.values[i]);
    }
    printf("]\n");

    bool str_match = true;
    for (int i = 0; i < STRING_ARRAY_SIZE; ++i) {
        if (strcmp(str_arr.values[i], str_deser.values[i]) != 0) {
            str_match = false;
            break;
        }
    }
    if (str_match) {
        printf("[OK] StringArray round-trip successful\n\n");
    }

    /* Matrix - 3x3 double array */
    printf("--- Matrix (3x3) ---\n");
    Matrix matrix;
    double m_values[3][3] = {
        {1.0, 2.0, 3.0},
        {4.0, 5.0, 6.0},
        {7.0, 8.0, 9.0}
    };
    memcpy(matrix.values, m_values, sizeof(m_values));

    printf("Original matrix:\n");
    for (int i = 0; i < MATRIX_ROWS; ++i) {
        printf("  Row %d: [", i);
        for (int j = 0; j < MATRIX_COLS; ++j) {
            if (j > 0) printf(", ");
            printf("%.1f", matrix.values[i][j]);
        }
        printf("]\n");
    }

    size = Matrix_serialize(&matrix, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes (9 × 8 = 72)\n", size);

    Matrix mat_deser;
    Matrix_deserialize(&mat_deser, buffer, size);
    printf("Deserialized matrix:\n");
    for (int i = 0; i < MATRIX_ROWS; ++i) {
        printf("  Row %d: [", i);
        for (int j = 0; j < MATRIX_COLS; ++j) {
            if (j > 0) printf(", ");
            printf("%.1f", mat_deser.values[i][j]);
        }
        printf("]\n");
    }

    if (memcmp(matrix.values, mat_deser.values, sizeof(matrix.values)) == 0) {
        printf("[OK] Matrix round-trip successful\n\n");
    }

    /* Identity matrix */
    printf("--- Identity Matrix ---\n");
    Matrix identity;
    Matrix_identity(&identity);
    printf("Identity matrix:\n");
    for (int i = 0; i < MATRIX_ROWS; ++i) {
        printf("  [");
        for (int j = 0; j < MATRIX_COLS; ++j) {
            if (j > 0) printf(", ");
            printf("%.1f", identity.values[i][j]);
        }
        printf("]\n");
    }

    size = Matrix_serialize(&identity, buffer, sizeof(buffer));
    Matrix id_deser;
    Matrix_deserialize(&id_deser, buffer, size);
    if (memcmp(identity.values, id_deser.values, sizeof(identity.values)) == 0) {
        printf("[OK] Identity matrix round-trip successful\n\n");
    }

    /* Test with zeros */
    printf("--- Zero-initialized Arrays ---\n");
    LongArray zero_arr;
    memset(&zero_arr, 0, sizeof(zero_arr));
    printf("Zero LongArray: all zeros\n");

    size = LongArray_serialize(&zero_arr, buffer, sizeof(buffer));
    LongArray zero_deser;
    LongArray_deserialize(&zero_deser, buffer, size);
    if (memcmp(zero_arr.values, zero_deser.values, sizeof(zero_arr.values)) == 0) {
        printf("[OK] Zero array round-trip successful\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
