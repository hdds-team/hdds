// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Strings Sample - Demonstrates DDS string types
 *
 * This sample shows how to work with string types:
 * - Unbounded strings (char* pointer)
 * - Bounded strings (sequence<char> with .data/.len)
 * - Wide strings (wchar_t* pointer)
 */

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "generated/Strings.h"

int main(void) {
    printf("=== HDDS String Types Sample ===\n\n");

    /* Create a Strings instance - new API uses char* pointers */
    Strings original;
    memset(&original, 0, sizeof(original));

    /* unbounded_str: char* pointer, assign string literal for encode */
    original.unbounded_str = "This is an unbounded string (up to buffer limit)";

    /* bounded_str: sequence<char> with .data and .len */
    char bounded_buf[] = "Bounded to 256 chars";
    original.bounded_str.data = bounded_buf;
    original.bounded_str.len = (uint32_t)strlen(bounded_buf);

    /* wide_str: wchar_t* pointer */
    wchar_t wide_buf[] = L"Wide string with UTF-8: Hello World!";
    original.wide_str = wide_buf;

    printf("Original Strings:\n");
    printf("  unbounded_str: \"%s\"\n", original.unbounded_str);
    printf("  bounded_str:   \"%.*s\" (max 256 chars)\n",
           (int)original.bounded_str.len, original.bounded_str.data);
    printf("  wide_str:      \"%ls\"\n", original.wide_str);

    /* Serialize */
    uint8_t buffer[4096];
    int serialized_size = strings_encode_cdr2_le(&original, buffer, sizeof(buffer));
    if (serialized_size <= 0) {
        printf("[ERROR] Serialization failed! (%d)\n", serialized_size);
        return 1;
    }
    printf("\nSerialized size: %d bytes\n", serialized_size);

    /* Deserialize - must pre-allocate buffers for char* fields */
    Strings deserialized;
    memset(&deserialized, 0, sizeof(deserialized));

    char deser_unbounded[512] = {0};
    deserialized.unbounded_str = deser_unbounded;

    char deser_bounded[256] = {0};
    deserialized.bounded_str.data = deser_bounded;
    deserialized.bounded_str.len = 0;

    wchar_t deser_wide[512] = {0};
    deserialized.wide_str = deser_wide;

    int deser_size = strings_decode_cdr2_le(&deserialized, buffer, (size_t)serialized_size);
    if (deser_size < 0) {
        printf("[ERROR] Deserialization failed! (%d)\n", deser_size);
        return 1;
    }

    printf("\nDeserialized:\n");
    printf("  unbounded_str: \"%s\"\n", deserialized.unbounded_str);
    printf("  bounded_str:   \"%.*s\"\n",
           (int)deserialized.bounded_str.len, deserialized.bounded_str.data);
    printf("  wide_str:      \"%ls\"\n", deserialized.wide_str);

    /* Verify round-trip */
    if (strcmp(original.unbounded_str, deserialized.unbounded_str) == 0 &&
        original.bounded_str.len == deserialized.bounded_str.len &&
        memcmp(original.bounded_str.data, deserialized.bounded_str.data,
               original.bounded_str.len) == 0 &&
        wcscmp(original.wide_str, deserialized.wide_str) == 0) {
        printf("\n[OK] Round-trip serialization successful!\n");
    } else {
        printf("\n[ERROR] Round-trip verification failed!\n");
        return 1;
    }

    /* Test empty strings */
    printf("\n--- Empty String Test ---\n");
    Strings empty;
    memset(&empty, 0, sizeof(empty));
    empty.unbounded_str = "";
    empty.bounded_str.data = NULL;
    empty.bounded_str.len = 0;
    wchar_t empty_wide[] = L"";
    empty.wide_str = empty_wide;

    int empty_size = strings_encode_cdr2_le(&empty, buffer, sizeof(buffer));

    Strings empty_deser;
    memset(&empty_deser, 0, sizeof(empty_deser));
    char empty_unbounded_buf[64] = {0};
    empty_deser.unbounded_str = empty_unbounded_buf;
    empty_deser.bounded_str.data = NULL;
    empty_deser.bounded_str.len = 0;
    wchar_t empty_wide_buf[64] = {0};
    empty_deser.wide_str = empty_wide_buf;

    strings_decode_cdr2_le(&empty_deser, buffer, (size_t)empty_size);

    if (strlen(empty_deser.unbounded_str) == 0) {
        printf("[OK] Empty strings handled correctly\n");
    }

    /* Test different length strings */
    printf("\n--- Various Length Test ---\n");
    Strings varied;
    memset(&varied, 0, sizeof(varied));
    varied.unbounded_str = "Short";

    char varied_bounded[256];
    memset(varied_bounded, 'X', 200);
    varied_bounded[200] = '\0';
    varied.bounded_str.data = varied_bounded;
    varied.bounded_str.len = 200;

    wchar_t varied_wide[] = L"Medium length string here";
    varied.wide_str = varied_wide;

    int varied_size = strings_encode_cdr2_le(&varied, buffer, sizeof(buffer));

    Strings varied_deser;
    memset(&varied_deser, 0, sizeof(varied_deser));
    char varied_deser_unbounded[512] = {0};
    varied_deser.unbounded_str = varied_deser_unbounded;
    char varied_deser_bounded[256] = {0};
    varied_deser.bounded_str.data = varied_deser_bounded;
    varied_deser.bounded_str.len = 0;
    wchar_t varied_deser_wide[512] = {0};
    varied_deser.wide_str = varied_deser_wide;

    strings_decode_cdr2_le(&varied_deser, buffer, (size_t)varied_size);

    printf("String lengths:\n");
    printf("  unbounded_str: %zu chars\n", strlen(varied_deser.unbounded_str));
    printf("  bounded_str:   %u chars\n", varied_deser.bounded_str.len);
    printf("  wide_str:      %zu chars\n", wcslen(varied_deser.wide_str));

    if (varied.bounded_str.len == varied_deser.bounded_str.len) {
        printf("[OK] Various length strings handled correctly\n");
    }

    printf("\n=== Sample Complete ===\n");
    return 0;
}
