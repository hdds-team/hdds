// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Maps Sample - Demonstrates DDS map types
 *
 * This sample shows how to work with map types:
 * - String to long maps
 * - Long to string maps
 */

#include <stdio.h>
#include <string.h>
#include "generated/Maps.h"

int main(void) {
    printf("=== HDDS Map Types Sample ===\n\n");

    uint8_t buffer[4096];

    /* StringLongMap */
    printf("--- StringLongMap ---\n");
    StringLongMap str_long_map;
    str_long_map.count = 4;
    strcpy(str_long_map.entries[0].key, "alpha");
    str_long_map.entries[0].value = 1;
    strcpy(str_long_map.entries[1].key, "beta");
    str_long_map.entries[1].value = 2;
    strcpy(str_long_map.entries[2].key, "gamma");
    str_long_map.entries[2].value = 3;
    strcpy(str_long_map.entries[3].key, "delta");
    str_long_map.entries[3].value = 4;

    printf("Original map:\n");
    for (uint32_t i = 0; i < str_long_map.count; ++i) {
        printf("  \"%s\" => %d\n", str_long_map.entries[i].key,
               str_long_map.entries[i].value);
    }

    size_t size = StringLongMap_serialize(&str_long_map, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    StringLongMap sl_deser;
    StringLongMap_deserialize(&sl_deser, buffer, size);
    printf("Deserialized map:\n");
    for (uint32_t i = 0; i < sl_deser.count; ++i) {
        printf("  \"%s\" => %d\n", sl_deser.entries[i].key,
               sl_deser.entries[i].value);
    }

    if (str_long_map.count == sl_deser.count) {
        printf("[OK] StringLongMap round-trip successful\n\n");
    }

    /* LongStringMap */
    printf("--- LongStringMap ---\n");
    LongStringMap long_str_map;
    long_str_map.count = 3;
    long_str_map.entries[0].key = 100;
    strcpy(long_str_map.entries[0].value, "one hundred");
    long_str_map.entries[1].key = 200;
    strcpy(long_str_map.entries[1].value, "two hundred");
    long_str_map.entries[2].key = 300;
    strcpy(long_str_map.entries[2].value, "three hundred");

    printf("Original map:\n");
    for (uint32_t i = 0; i < long_str_map.count; ++i) {
        printf("  %d => \"%s\"\n", long_str_map.entries[i].key,
               long_str_map.entries[i].value);
    }

    size = LongStringMap_serialize(&long_str_map, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);

    LongStringMap ls_deser;
    LongStringMap_deserialize(&ls_deser, buffer, size);
    printf("Deserialized map:\n");
    for (uint32_t i = 0; i < ls_deser.count; ++i) {
        printf("  %d => \"%s\"\n", ls_deser.entries[i].key,
               ls_deser.entries[i].value);
    }

    if (long_str_map.count == ls_deser.count) {
        printf("[OK] LongStringMap round-trip successful\n\n");
    }

    /* Empty map */
    printf("--- Empty Map Test ---\n");
    StringLongMap empty_map;
    empty_map.count = 0;

    size = StringLongMap_serialize(&empty_map, buffer, sizeof(buffer));
    StringLongMap empty_deser;
    StringLongMap_deserialize(&empty_deser, buffer, size);

    printf("Empty map size: %u\n", empty_deser.count);
    if (empty_deser.count == 0) {
        printf("[OK] Empty map handled correctly\n\n");
    }

    /* Single entry map */
    printf("--- Single Entry Map ---\n");
    StringLongMap single_map;
    single_map.count = 1;
    strcpy(single_map.entries[0].key, "only_key");
    single_map.entries[0].value = 42;

    size = StringLongMap_serialize(&single_map, buffer, sizeof(buffer));
    StringLongMap single_deser;
    StringLongMap_deserialize(&single_deser, buffer, size);

    printf("Single entry: \"%s\" => %d\n",
           single_deser.entries[0].key, single_deser.entries[0].value);
    if (single_deser.count == 1) {
        printf("[OK] Single entry map handled correctly\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
