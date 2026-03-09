// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Arrays Sample - Demonstrates DDS array/sequence types
 *
 * This sample shows how to work with the Arrays struct:
 * - numbers: sequence<long> (integer sequence)
 * - names: sequence<string> (string sequence)
 * - transform: sequence<sequence<float>> (nested sequences / matrix)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Arrays.h"

int main(void) {
    printf("=== HDDS Array Types Sample ===\n\n");

    uint8_t buffer[2048];

    /* numbers - integer sequence (replaces old LongArray) */
    printf("--- Numbers (integer sequence, 10 elements) ---\n");
    Arrays arr;
    memset(&arr, 0, sizeof(arr));

    int32_t numbers_buf[10];
    for (int i = 0; i < 10; ++i) {
        numbers_buf[i] = i + 1;
    }
    arr.numbers.data = numbers_buf;
    arr.numbers.len = 10;

    /* Leave names and transform empty for this test */
    arr.names.data = NULL;
    arr.names.len = 0;
    arr.transform.data = NULL;
    arr.transform.len = 0;

    printf("Original: [");
    for (uint32_t i = 0; i < arr.numbers.len; ++i) {
        if (i > 0) printf(", ");
        printf("%d", arr.numbers.data[i]);
    }
    printf("]\n");

    int size = arrays_encode_cdr2_le(&arr, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Arrays arr_deser;
    memset(&arr_deser, 0, sizeof(arr_deser));
    int32_t deser_numbers[10] = {0};
    arr_deser.numbers.data = deser_numbers;
    arr_deser.numbers.len = 0;
    arr_deser.names.data = NULL;
    arr_deser.names.len = 0;
    arr_deser.transform.data = NULL;
    arr_deser.transform.len = 0;

    arrays_decode_cdr2_le(&arr_deser, buffer, (size_t)size);
    printf("Deserialized: [");
    for (uint32_t i = 0; i < arr_deser.numbers.len; ++i) {
        if (i > 0) printf(", ");
        printf("%d", arr_deser.numbers.data[i]);
    }
    printf("]\n");

    if (arr.numbers.len == arr_deser.numbers.len &&
        memcmp(arr.numbers.data, arr_deser.numbers.data,
               arr.numbers.len * sizeof(int32_t)) == 0) {
        printf("[OK] Numbers round-trip successful\n\n");
    }

    /* names - string sequence (replaces old StringArray) */
    printf("--- Names (string sequence, 5 elements) ---\n");
    Arrays str_arr;
    memset(&str_arr, 0, sizeof(str_arr));

    str_arr.numbers.data = NULL;
    str_arr.numbers.len = 0;

    char* name_ptrs[5] = {"Alpha", "Beta", "Gamma", "Delta", "Epsilon"};
    str_arr.names.data = name_ptrs;
    str_arr.names.len = 5;

    str_arr.transform.data = NULL;
    str_arr.transform.len = 0;

    printf("Original: [");
    for (uint32_t i = 0; i < str_arr.names.len; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", str_arr.names.data[i]);
    }
    printf("]\n");

    size = arrays_encode_cdr2_le(&str_arr, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Arrays str_deser;
    memset(&str_deser, 0, sizeof(str_deser));
    str_deser.numbers.data = NULL;
    str_deser.numbers.len = 0;

    /* Pre-allocate string buffers for decode */
    char name_buf0[256] = {0}, name_buf1[256] = {0}, name_buf2[256] = {0};
    char name_buf3[256] = {0}, name_buf4[256] = {0};
    char* deser_name_ptrs[5] = {name_buf0, name_buf1, name_buf2, name_buf3, name_buf4};
    str_deser.names.data = deser_name_ptrs;
    str_deser.names.len = 0;

    str_deser.transform.data = NULL;
    str_deser.transform.len = 0;

    arrays_decode_cdr2_le(&str_deser, buffer, (size_t)size);
    printf("Deserialized: [");
    for (uint32_t i = 0; i < str_deser.names.len; ++i) {
        if (i > 0) printf(", ");
        printf("\"%s\"", str_deser.names.data[i]);
    }
    printf("]\n");

    bool str_match = (str_arr.names.len == str_deser.names.len);
    for (uint32_t i = 0; str_match && i < str_arr.names.len; ++i) {
        str_match = (strcmp(str_arr.names.data[i], str_deser.names.data[i]) == 0);
    }
    if (str_match) {
        printf("[OK] Names round-trip successful\n\n");
    }

    /* transform - nested sequences (replaces old Matrix) */
    printf("--- Transform (3x3 matrix as nested sequences) ---\n");
    Arrays matrix;
    memset(&matrix, 0, sizeof(matrix));

    matrix.numbers.data = NULL;
    matrix.numbers.len = 0;
    matrix.names.data = NULL;
    matrix.names.len = 0;

    /* Build 3 rows of 3 floats each */
    float row0[] = {1.0f, 2.0f, 3.0f};
    float row1[] = {4.0f, 5.0f, 6.0f};
    float row2[] = {7.0f, 8.0f, 9.0f};

    struct { float* data; uint32_t len; } rows[3];
    rows[0].data = row0; rows[0].len = 3;
    rows[1].data = row1; rows[1].len = 3;
    rows[2].data = row2; rows[2].len = 3;

    { void* p = rows; matrix.transform.data = p; }
    matrix.transform.len = 3;

    printf("Original matrix:\n");
    for (uint32_t i = 0; i < matrix.transform.len; ++i) {
        printf("  Row %u: [", i);
        for (uint32_t j = 0; j < matrix.transform.data[i].len; ++j) {
            if (j > 0) printf(", ");
            printf("%.1f", matrix.transform.data[i].data[j]);
        }
        printf("]\n");
    }

    size = arrays_encode_cdr2_le(&matrix, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Matrix serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    /* Deserialize the matrix */
    Arrays mat_deser;
    memset(&mat_deser, 0, sizeof(mat_deser));
    mat_deser.numbers.data = NULL;
    mat_deser.numbers.len = 0;
    mat_deser.names.data = NULL;
    mat_deser.names.len = 0;

    float drow0[3] = {0}, drow1[3] = {0}, drow2[3] = {0};
    struct { float* data; uint32_t len; } drows[3];
    drows[0].data = drow0; drows[0].len = 0;
    drows[1].data = drow1; drows[1].len = 0;
    drows[2].data = drow2; drows[2].len = 0;

    { void* p = drows; mat_deser.transform.data = p; }
    mat_deser.transform.len = 0;

    arrays_decode_cdr2_le(&mat_deser, buffer, (size_t)size);
    printf("Deserialized matrix:\n");
    for (uint32_t i = 0; i < mat_deser.transform.len; ++i) {
        printf("  Row %u: [", i);
        for (uint32_t j = 0; j < mat_deser.transform.data[i].len; ++j) {
            if (j > 0) printf(", ");
            printf("%.1f", mat_deser.transform.data[i].data[j]);
        }
        printf("]\n");
    }

    if (matrix.transform.len == mat_deser.transform.len) {
        printf("[OK] Matrix round-trip successful\n\n");
    }

    /* Test with zeros */
    printf("--- Zero-initialized Arrays ---\n");
    Arrays zero_arr;
    memset(&zero_arr, 0, sizeof(zero_arr));

    int32_t zero_nums[10] = {0};
    zero_arr.numbers.data = zero_nums;
    zero_arr.numbers.len = 10;
    zero_arr.names.data = NULL;
    zero_arr.names.len = 0;
    zero_arr.transform.data = NULL;
    zero_arr.transform.len = 0;

    printf("Zero array: all zeros\n");

    size = arrays_encode_cdr2_le(&zero_arr, buffer, sizeof(buffer));
    Arrays zero_deser;
    memset(&zero_deser, 0, sizeof(zero_deser));
    int32_t zero_deser_nums[10] = {0};
    zero_deser.numbers.data = zero_deser_nums;
    zero_deser.numbers.len = 0;
    zero_deser.names.data = NULL;
    zero_deser.names.len = 0;
    zero_deser.transform.data = NULL;
    zero_deser.transform.len = 0;

    arrays_decode_cdr2_le(&zero_deser, buffer, (size_t)size);
    if (zero_deser.numbers.len == 10 &&
        memcmp(zero_arr.numbers.data, zero_deser.numbers.data, 10 * sizeof(int32_t)) == 0) {
        printf("[OK] Zero array round-trip successful\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
