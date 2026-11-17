// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include "hdds.h"
#include <stdio.h>
#include <string.h>

/* These checks stay enabled in release builds (unlike assert with NDEBUG). */
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
    return 1; \
} } while (0)

static int dynamic_roundtrip(void) {
    struct HddsTypeBuilder *builder = hdds_type_builder_new("Sensor");
    CHECK(builder != NULL);
    CHECK(hdds_type_builder_add_field(builder, "bad", UINT32_MAX) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_type_builder_add_sequence_field(builder, "bad", 12) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_type_builder_add_array_field(builder, "bad", 12, 2) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_type_builder_add_array_field(builder, "bad", HDDS_PRIM_U8, SIZE_MAX) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_type_builder_add_array_field(builder, "bad", HDDS_PRIM_U8, 0) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_type_builder_add_field(builder, "id", HDDS_PRIM_U32) == HDDS_OK);
    CHECK(hdds_type_builder_add_field(builder, "id", HDDS_PRIM_F64) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_type_builder_add_string_field(builder, "") == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_type_builder_add_string_field(builder, "label") == HDDS_OK);
    struct HddsTypeDescriptor *desc = hdds_type_builder_build(builder);
    CHECK(desc != NULL);
    CHECK(hdds_type_descriptor_get_field_count(desc) == 2);
    struct HddsDynamicData *data = hdds_dynamic_data_new(desc);
    CHECK(data != NULL);
    CHECK(hdds_dynamic_data_set_u32(data, "id", 42) == HDDS_OK);
    CHECK(hdds_dynamic_data_set_string(data, "label", "room") == HDDS_OK);
    /* A type mismatch must leave the valid value in place. */
    CHECK(hdds_dynamic_data_set_f64(data, "id", 1.5) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_dynamic_data_set_string(data, "id", "bad") == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_dynamic_data_set_u32(data, "absent", 1) == HDDS_INVALID_ARGUMENT);
    uint32_t id = 0;
    CHECK(hdds_dynamic_data_get_u32(data, "id", &id) == HDDS_OK && id == 42);
    double wrong = 12.0;
    CHECK(hdds_dynamic_data_get_f64(data, "id", &wrong) == HDDS_INVALID_ARGUMENT);
    CHECK(wrong == 12.0);

    uint8_t bytes[128];
    size_t len = 0;
    CHECK(hdds_dynamic_data_encode(data, NULL, 0, &len) == HDDS_BUFFER_TOO_SMALL);
    CHECK(len > 0 && len <= sizeof(bytes));
    CHECK(hdds_dynamic_data_encode(data, bytes, sizeof(bytes), &len) == HDDS_OK);
    CHECK(len > 0 && len <= sizeof(bytes));
    CHECK(hdds_dynamic_data_decode(desc, bytes, 1) == NULL);
    struct HddsDynamicData *decoded = hdds_dynamic_data_decode(desc, bytes, len);
    CHECK(decoded != NULL);
    /* Data owns a descriptor reference independently of the C handle. */
    hdds_type_descriptor_destroy(desc);
    hdds_dynamic_data_destroy(data);
    id = 0;
    CHECK(hdds_dynamic_data_get_u32(decoded, "id", &id) == HDDS_OK && id == 42);
    CHECK(hdds_dynamic_data_get_string(decoded, "label", NULL, 0) == 4);
    char label[3] = {'?', '?', '?'};
    CHECK(hdds_dynamic_data_get_string(decoded, "label", label, sizeof(label)) == 4);
    CHECK(strcmp(label, "ro") == 0);
    hdds_dynamic_data_destroy(decoded);
    return 0;
}

static int filter_parameters(void) {
    const char *params[] = {"40", "60"};
    struct HddsFilter *filter = hdds_filter_create_with_params(
        "value > %0 AND value < %1", params, 2);
    CHECK(filter != NULL);
    struct HddsFieldMap *fields = hdds_field_map_create();
    CHECK(fields != NULL);
    CHECK(hdds_field_map_set_i64(fields, "value", 50) == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 1);

    const char *missing[] = {NULL, "60"};
    const char invalid_utf8[] = {(char)0xff, 0};
    const char *invalid[] = {invalid_utf8, "60"};
    CHECK(hdds_filter_set_parameters(filter, missing, 2) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_filter_evaluate(filter, fields) == 1);
    CHECK(hdds_filter_set_parameters(filter, invalid, 2) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_filter_evaluate(filter, fields) == 1);
    CHECK(hdds_filter_set_parameters(filter, NULL, 2) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_filter_evaluate(filter, fields) == 1);
    CHECK(hdds_filter_create_with_params("value > %0", missing, 2) == NULL);
    CHECK(hdds_filter_create_with_params("value > %0", invalid, 2) == NULL);
    CHECK(hdds_filter_create_with_params("value > %0", NULL, 2) == NULL);

    const char *changed[] = {"55", "60"};
    CHECK(hdds_filter_set_parameters(filter, changed, 2) == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 0);
    CHECK(hdds_filter_set_parameters(filter, NULL, 0) == HDDS_INVALID_ARGUMENT);
    CHECK(hdds_filter_evaluate(filter, fields) == 0);
    hdds_field_map_destroy(fields);
    hdds_filter_destroy(filter);
    return 0;
}

static int filter_literal_validation(void) {
    /* Beyond the integer range a digit series is a FLOATVALUE (Annex B makes
     * the point and the exponent optional); a hexadecimal literal has no
     * such derivation and must fit 64 bits. */
    struct HddsFilter *wide = hdds_filter_create("value = 18446744073709551616");
    CHECK(wide != NULL);
    hdds_filter_destroy(wide);
    CHECK(hdds_filter_create("value = 0x1FFFFFFFFFFFFFFFF") == NULL);
    CHECK(hdds_filter_create("value = 1e400") == NULL);
    /* '!' alone is nothing; '!=' is the alias of '<>' (see filter_annex_b_grammar). */
    CHECK(hdds_filter_create("value ! 1") == NULL);
    CHECK(hdds_filter_create("value = 1 garbage") == NULL);
    CHECK(hdds_filter_create("value") == NULL);
    struct HddsFilter *filter = hdds_filter_create(
        "value = 18446744073709551615 AND enabled = TRUE");
    struct HddsFieldMap *fields = hdds_field_map_create();
    CHECK(filter != NULL && fields != NULL);
    CHECK(hdds_field_map_set_u64(fields, "value", UINT64_MAX) == HDDS_OK);
    CHECK(hdds_field_map_set_bool(fields, "enabled", true) == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 1);
    CHECK(hdds_field_map_set_u64(fields, "value", UINT64_MAX - 1) == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 0);
    hdds_filter_destroy(filter);
    hdds_field_map_destroy(fields);
    return 0;
}

/* DDS 1.4 Annex B forms beyond the historical subset: dotted FIELDNAME,
 * hexadecimal INTEGERVALUE, FLOATVALUE exponent, BETWEEN / NOT BETWEEN with
 * parameters, like, and the boolean field coercions. */
static int filter_annex_b_grammar(void) {
    struct HddsFilter *filter = hdds_filter_create("value = 1e3 AND enabled = 1");
    CHECK(filter != NULL);
    hdds_filter_destroy(filter);

    const char *params[] = {"0x0A", "'sen%'"};
    filter = hdds_filter_create_with_params(
        "pos.x BETWEEN %0 AND 1e1 AND name LIKE %1 AND pos.y NOT BETWEEN -0x1 AND +1",
        params, 2);
    CHECK(filter != NULL);
    struct HddsFieldMap *fields = hdds_field_map_create();
    CHECK(fields != NULL);
    CHECK(hdds_field_map_set_i64(fields, "pos.x", 10) == HDDS_OK);
    CHECK(hdds_field_map_set_i64(fields, "pos.y", 2) == HDDS_OK);
    CHECK(hdds_field_map_set_string(fields, "name", "sensor") == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 1);
    CHECK(hdds_field_map_set_i64(fields, "pos.y", 1) == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 0);
    CHECK(hdds_field_map_set_i64(fields, "pos.y", 2) == HDDS_OK);
    CHECK(hdds_field_map_set_i64(fields, "pos.x", 11) == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 0);
    hdds_filter_destroy(filter);

    filter = hdds_filter_create("enabled = 'TRUE' AND ch = 'A'");
    CHECK(filter != NULL);
    CHECK(hdds_field_map_set_bool(fields, "enabled", true) == HDDS_OK);
    CHECK(hdds_field_map_set_u64(fields, "ch", 65) == HDDS_OK);
    CHECK(hdds_filter_evaluate(filter, fields) == 1);
    hdds_filter_destroy(filter);

    /* '!=' and '==' are local aliases. The expression getter returns the
     * source text (DDS 1.4 2.2.2.3.3.2); the canonical getter returns the
     * Annex B text. Both checked byte for byte. */
    filter = hdds_filter_create("value != 1 and enabled == TRUE");
    CHECK(filter != NULL);
    char text[64];
    size_t needed = hdds_filter_get_expression(filter, text, sizeof(text));
    CHECK(needed == strlen("value != 1 and enabled == TRUE"));
    CHECK(strcmp(text, "value != 1 and enabled == TRUE") == 0);
    needed = hdds_filter_get_canonical_expression(filter, text, sizeof(text));
    CHECK(needed == strlen("value <> 1 AND enabled = TRUE"));
    CHECK(strcmp(text, "value <> 1 AND enabled = TRUE") == 0);
    hdds_filter_destroy(filter);

    CHECK(hdds_filter_create("1 = 1") == NULL);
    CHECK(hdds_filter_create("value = %100") == NULL);
    CHECK(hdds_filter_create("name = \"double\"") == NULL);
    CHECK(hdds_filter_create("a[0] = 1") == NULL);
    hdds_field_map_destroy(fields);
    return 0;
}

static int dynamic_wire_contract(void) {
    struct HddsTypeBuilder *builder = hdds_type_builder_new("Aligned");
    CHECK(builder != NULL);
    CHECK(hdds_type_builder_add_field(builder, "b", HDDS_PRIM_U8) == HDDS_OK);
    CHECK(hdds_type_builder_add_field(builder, "d", HDDS_PRIM_F64) == HDDS_OK);
    struct HddsTypeDescriptor *desc = hdds_type_builder_build(builder);
    struct HddsDynamicData *data = hdds_dynamic_data_new(desc);
    CHECK(data != NULL);
    CHECK(hdds_dynamic_data_set_f64(data, "d", 1.0) == HDDS_OK);
    uint8_t bytes[16];
    size_t len = 0;
    CHECK(hdds_dynamic_data_encode(data, bytes, sizeof(bytes), &len) == HDDS_OK);
    /* XCDR2 body of an APPENDABLE struct, with no encapsulation header:
     * DHEADER (12), u8, f64 aligned at four. XCDR1 would align it at eight. */
    const uint8_t expected[16] = {12, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0xf0, 0x3f};
    CHECK(len == sizeof(expected) && memcmp(bytes, expected, len) == 0);
    hdds_dynamic_data_destroy(data);
    hdds_type_descriptor_destroy(desc);

    /* An empty APPENDABLE struct is its DHEADER alone under XCDR2. */
    builder = hdds_type_builder_new("Empty");
    desc = hdds_type_builder_build(builder);
    CHECK(hdds_dynamic_data_decode(desc, NULL, 0) == NULL);
    const uint8_t empty[] = {0, 0, 0, 0};
    data = hdds_dynamic_data_decode(desc, empty, sizeof(empty));
    CHECK(data != NULL);
    CHECK(hdds_dynamic_data_encode(data, NULL, 0, &len) == HDDS_BUFFER_TOO_SMALL);
    CHECK(len == sizeof(empty));
    CHECK(hdds_dynamic_data_encode(data, bytes, sizeof(bytes), &len) == HDDS_OK);
    CHECK(len == sizeof(empty) && memcmp(bytes, empty, len) == 0);
    hdds_dynamic_data_destroy(data);
    hdds_type_descriptor_destroy(desc);

    builder = hdds_type_builder_new("Sequence");
    CHECK(hdds_type_builder_add_sequence_field(builder, "s", HDDS_PRIM_U8) == HDDS_OK);
    desc = hdds_type_builder_build(builder);
    /* DHEADER (4), then a sequence length past the end of the body. */
    const uint8_t oversized[] = {4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};
    CHECK(hdds_dynamic_data_decode(desc, oversized, sizeof(oversized)) == NULL);
    /* DHEADER (6), sequence length 2, two elements. */
    const uint8_t valid[] = {6, 0, 0, 0, 2, 0, 0, 0, 1, 2};
    data = hdds_dynamic_data_decode(desc, valid, sizeof(valid));
    CHECK(data != NULL);
    CHECK(hdds_dynamic_data_encode(data, bytes, sizeof(bytes), &len) == HDDS_OK);
    CHECK(len == sizeof(valid) && memcmp(bytes, valid, len) == 0);
    hdds_dynamic_data_destroy(data);
    hdds_type_descriptor_destroy(desc);
    return 0;
}

int main(void) {
    CHECK(dynamic_roundtrip() == 0);
    CHECK(filter_parameters() == 0);
    CHECK(filter_literal_validation() == 0);
    CHECK(filter_annex_b_grammar() == 0);
    CHECK(dynamic_wire_contract() == 0);
    puts("Dynamic CDR roundtrip and transactional filter parameters: PASS");
    return 0;
}
