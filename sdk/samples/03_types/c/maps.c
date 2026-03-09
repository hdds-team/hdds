// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Maps Sample - Demonstrates DDS map types
 *
 * This sample shows how to work with the Maps struct:
 * - scores: StringLongMap (string keys, long values)
 * - labels: LongStringMap (long keys, string values)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Maps.h"

int main(void) {
    printf("=== HDDS Map Types Sample ===\n\n");

    uint8_t buffer[4096];

    /* StringLongMap (scores) */
    printf("--- StringLongMap (scores) ---\n");
    Maps maps;
    memset(&maps, 0, sizeof(maps));

    /* Set up scores: string -> long map */
    char* score_keys[] = {"alpha", "beta", "gamma", "delta"};
    int32_t score_values[] = {1, 2, 3, 4};
    maps.scores.keys = score_keys;
    maps.scores.values = score_values;
    maps.scores.len = 4;

    /* Leave labels empty for this test */
    maps.labels.keys = NULL;
    maps.labels.values = NULL;
    maps.labels.len = 0;

    printf("Original map:\n");
    for (uint32_t i = 0; i < maps.scores.len; ++i) {
        printf("  \"%s\" => %d\n", maps.scores.keys[i], maps.scores.values[i]);
    }

    int size = maps_encode_cdr2_le(&maps, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Maps sl_deser;
    memset(&sl_deser, 0, sizeof(sl_deser));

    /* Pre-allocate buffers for decode */
    char sk_buf0[256] = {0}, sk_buf1[256] = {0}, sk_buf2[256] = {0}, sk_buf3[256] = {0};
    char* deser_score_keys[] = {sk_buf0, sk_buf1, sk_buf2, sk_buf3};
    int32_t deser_score_values[4] = {0};
    sl_deser.scores.keys = deser_score_keys;
    sl_deser.scores.values = deser_score_values;
    sl_deser.scores.len = 0;
    sl_deser.labels.keys = NULL;
    sl_deser.labels.values = NULL;
    sl_deser.labels.len = 0;

    maps_decode_cdr2_le(&sl_deser, buffer, (size_t)size);
    printf("Deserialized map:\n");
    for (uint32_t i = 0; i < sl_deser.scores.len; ++i) {
        printf("  \"%s\" => %d\n", sl_deser.scores.keys[i], sl_deser.scores.values[i]);
    }

    if (maps.scores.len == sl_deser.scores.len) {
        printf("[OK] StringLongMap round-trip successful\n\n");
    }

    /* LongStringMap (labels) */
    printf("--- LongStringMap (labels) ---\n");
    Maps label_maps;
    memset(&label_maps, 0, sizeof(label_maps));

    /* Leave scores empty */
    label_maps.scores.keys = NULL;
    label_maps.scores.values = NULL;
    label_maps.scores.len = 0;

    int32_t label_keys[] = {100, 200, 300};
    char* label_values[] = {"one hundred", "two hundred", "three hundred"};
    label_maps.labels.keys = label_keys;
    label_maps.labels.values = label_values;
    label_maps.labels.len = 3;

    printf("Original map:\n");
    for (uint32_t i = 0; i < label_maps.labels.len; ++i) {
        printf("  %d => \"%s\"\n", label_maps.labels.keys[i], label_maps.labels.values[i]);
    }

    size = maps_encode_cdr2_le(&label_maps, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);

    Maps ls_deser;
    memset(&ls_deser, 0, sizeof(ls_deser));
    ls_deser.scores.keys = NULL;
    ls_deser.scores.values = NULL;
    ls_deser.scores.len = 0;

    int32_t deser_label_keys[3] = {0};
    char lv_buf0[256] = {0}, lv_buf1[256] = {0}, lv_buf2[256] = {0};
    char* deser_label_values[] = {lv_buf0, lv_buf1, lv_buf2};
    ls_deser.labels.keys = deser_label_keys;
    ls_deser.labels.values = deser_label_values;
    ls_deser.labels.len = 0;

    maps_decode_cdr2_le(&ls_deser, buffer, (size_t)size);
    printf("Deserialized map:\n");
    for (uint32_t i = 0; i < ls_deser.labels.len; ++i) {
        printf("  %d => \"%s\"\n", ls_deser.labels.keys[i], ls_deser.labels.values[i]);
    }

    if (label_maps.labels.len == ls_deser.labels.len) {
        printf("[OK] LongStringMap round-trip successful\n\n");
    }

    /* Empty map */
    printf("--- Empty Map Test ---\n");
    Maps empty_maps;
    memset(&empty_maps, 0, sizeof(empty_maps));
    empty_maps.scores.keys = NULL;
    empty_maps.scores.values = NULL;
    empty_maps.scores.len = 0;
    empty_maps.labels.keys = NULL;
    empty_maps.labels.values = NULL;
    empty_maps.labels.len = 0;

    size = maps_encode_cdr2_le(&empty_maps, buffer, sizeof(buffer));
    Maps empty_deser;
    memset(&empty_deser, 0, sizeof(empty_deser));
    empty_deser.scores.keys = NULL;
    empty_deser.scores.values = NULL;
    empty_deser.scores.len = 0;
    empty_deser.labels.keys = NULL;
    empty_deser.labels.values = NULL;
    empty_deser.labels.len = 0;

    maps_decode_cdr2_le(&empty_deser, buffer, (size_t)size);

    printf("Empty map size: %u\n", empty_deser.scores.len);
    if (empty_deser.scores.len == 0) {
        printf("[OK] Empty map handled correctly\n\n");
    }

    /* Single entry map */
    printf("--- Single Entry Map ---\n");
    Maps single_maps;
    memset(&single_maps, 0, sizeof(single_maps));

    char* single_keys[] = {"only_key"};
    int32_t single_values[] = {42};
    single_maps.scores.keys = single_keys;
    single_maps.scores.values = single_values;
    single_maps.scores.len = 1;
    single_maps.labels.keys = NULL;
    single_maps.labels.values = NULL;
    single_maps.labels.len = 0;

    size = maps_encode_cdr2_le(&single_maps, buffer, sizeof(buffer));
    Maps single_deser;
    memset(&single_deser, 0, sizeof(single_deser));

    char single_key_buf[256] = {0};
    char* single_key_ptrs[] = {single_key_buf};
    int32_t single_deser_vals[1] = {0};
    single_deser.scores.keys = single_key_ptrs;
    single_deser.scores.values = single_deser_vals;
    single_deser.scores.len = 0;
    single_deser.labels.keys = NULL;
    single_deser.labels.values = NULL;
    single_deser.labels.len = 0;

    maps_decode_cdr2_le(&single_deser, buffer, (size_t)size);

    printf("Single entry: \"%s\" => %d\n",
           single_deser.scores.keys[0], single_deser.scores.values[0]);
    if (single_deser.scores.len == 1) {
        printf("[OK] Single entry map handled correctly\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
