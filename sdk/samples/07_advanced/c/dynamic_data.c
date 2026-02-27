// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Dynamic Data (C)
 *
 * Demonstrates runtime type manipulation concepts.
 * Dynamic Data allows working with types at runtime without
 * compile-time type definitions.
 *
 * Usage:
 *     ./dynamic_data
 *
 * Key concepts:
 * - DynamicType: runtime type definition
 * - DynamicData: runtime data manipulation
 * - Type introspection
 * - Integration with DDS pub/sub
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DynamicData/DynamicType.
 * The native DynamicData/DynamicType API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "generated/HelloWorld.h"

#define MAX_MEMBERS 32
#define MAX_NAME_LEN 64

/* Type kinds */
typedef enum {
    TYPE_INT32,
    TYPE_UINT32,
    TYPE_INT64,
    TYPE_FLOAT32,
    TYPE_FLOAT64,
    TYPE_BOOL,
    TYPE_STRING,
    TYPE_STRUCT
} type_kind_t;

/* Member descriptor */
typedef struct {
    char name[MAX_NAME_LEN];
    type_kind_t type;
    uint32_t id;
    bool is_key;
} member_descriptor_t;

/* Dynamic type */
typedef struct {
    char name[MAX_NAME_LEN];
    type_kind_t kind;
    member_descriptor_t members[MAX_MEMBERS];
    int member_count;
} dynamic_type_t;

/* Dynamic data value union */
typedef union {
    int32_t int32_val;
    uint32_t uint32_val;
    int64_t int64_val;
    float float32_val;
    double float64_val;
    bool bool_val;
    char* string_val;
} data_value_t;

/* Dynamic data member */
typedef struct {
    char name[MAX_NAME_LEN];
    type_kind_t type;
    data_value_t value;
    bool is_set;
} data_member_t;

/* Dynamic data */
typedef struct {
    dynamic_type_t* type;
    data_member_t members[MAX_MEMBERS];
    int member_count;
} dynamic_data_t;

/* Create struct type */
dynamic_type_t* dynamic_type_create_struct(const char* name) {
    dynamic_type_t* type = (dynamic_type_t*)calloc(1, sizeof(dynamic_type_t));
    strncpy(type->name, name, MAX_NAME_LEN - 1);
    type->kind = TYPE_STRUCT;
    type->member_count = 0;
    return type;
}

/* Add member to type */
void dynamic_type_add_member(dynamic_type_t* type, const char* name, type_kind_t member_type, bool is_key) {
    if (type->member_count >= MAX_MEMBERS) return;

    member_descriptor_t* member = &type->members[type->member_count];
    strncpy(member->name, name, MAX_NAME_LEN - 1);
    member->type = member_type;
    member->id = (uint32_t)type->member_count;
    member->is_key = is_key;
    type->member_count++;
}

/* Create dynamic data from type */
dynamic_data_t* dynamic_data_create(dynamic_type_t* type) {
    dynamic_data_t* data = (dynamic_data_t*)calloc(1, sizeof(dynamic_data_t));
    data->type = type;
    data->member_count = type->member_count;

    for (int i = 0; i < type->member_count; i++) {
        strncpy(data->members[i].name, type->members[i].name, MAX_NAME_LEN - 1);
        data->members[i].type = type->members[i].type;
        data->members[i].is_set = false;
    }

    return data;
}

/* Set member values */
void dynamic_data_set_int32(dynamic_data_t* data, const char* name, int32_t value) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            data->members[i].value.int32_val = value;
            data->members[i].is_set = true;
            return;
        }
    }
}

void dynamic_data_set_float64(dynamic_data_t* data, const char* name, double value) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            data->members[i].value.float64_val = value;
            data->members[i].is_set = true;
            return;
        }
    }
}

void dynamic_data_set_string(dynamic_data_t* data, const char* name, const char* value) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            if (data->members[i].value.string_val) {
                free(data->members[i].value.string_val);
            }
            data->members[i].value.string_val = strdup(value);
            data->members[i].is_set = true;
            return;
        }
    }
}

void dynamic_data_set_bool(dynamic_data_t* data, const char* name, bool value) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            data->members[i].value.bool_val = value;
            data->members[i].is_set = true;
            return;
        }
    }
}

/* Get member values */
int32_t dynamic_data_get_int32(dynamic_data_t* data, const char* name) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            return data->members[i].value.int32_val;
        }
    }
    return 0;
}

double dynamic_data_get_float64(dynamic_data_t* data, const char* name) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            return data->members[i].value.float64_val;
        }
    }
    return 0.0;
}

const char* dynamic_data_get_string(dynamic_data_t* data, const char* name) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            return data->members[i].value.string_val;
        }
    }
    return NULL;
}

bool dynamic_data_get_bool(dynamic_data_t* data, const char* name) {
    for (int i = 0; i < data->member_count; i++) {
        if (strcmp(data->members[i].name, name) == 0) {
            return data->members[i].value.bool_val;
        }
    }
    return false;
}

/* Serialize dynamic data to string for transport */
size_t dynamic_data_serialize(dynamic_data_t* data, char* buffer, size_t buffer_size) {
    size_t pos = 0;
    pos += (size_t)snprintf(buffer + pos, buffer_size - pos, "%s|", data->type->name);

    for (int i = 0; i < data->member_count && pos < buffer_size; i++) {
        data_member_t* m = &data->members[i];
        if (!m->is_set) continue;

        switch (m->type) {
            case TYPE_INT32:
                pos += (size_t)snprintf(buffer + pos, buffer_size - pos, "%s:i:%d;", m->name, m->value.int32_val);
                break;
            case TYPE_FLOAT64:
                pos += (size_t)snprintf(buffer + pos, buffer_size - pos, "%s:f:%.2f;", m->name, m->value.float64_val);
                break;
            case TYPE_STRING:
                pos += (size_t)snprintf(buffer + pos, buffer_size - pos, "%s:s:%s;", m->name,
                       m->value.string_val ? m->value.string_val : "");
                break;
            case TYPE_BOOL:
                pos += (size_t)snprintf(buffer + pos, buffer_size - pos, "%s:b:%d;", m->name, m->value.bool_val ? 1 : 0);
                break;
            default:
                break;
        }
    }

    return pos;
}

/* Free dynamic data */
void dynamic_data_destroy(dynamic_data_t* data) {
    for (int i = 0; i < data->member_count; i++) {
        if (data->members[i].type == TYPE_STRING && data->members[i].value.string_val) {
            free(data->members[i].value.string_val);
        }
    }
    free(data);
}

const char* type_kind_str(type_kind_t kind) {
    switch (kind) {
        case TYPE_INT32: return "int32";
        case TYPE_UINT32: return "uint32";
        case TYPE_INT64: return "int64";
        case TYPE_FLOAT32: return "float32";
        case TYPE_FLOAT64: return "float64";
        case TYPE_BOOL: return "bool";
        case TYPE_STRING: return "string";
        case TYPE_STRUCT: return "struct";
        default: return "unknown";
    }
}

void print_type(dynamic_type_t* type) {
    printf("  Type: %s (%s)\n", type->name, type_kind_str(type->kind));
    printf("  Members (%d):\n", type->member_count);
    for (int i = 0; i < type->member_count; i++) {
        member_descriptor_t* m = &type->members[i];
        printf("    [%d] %s: %s", m->id, m->name, type_kind_str(m->type));
        if (m->is_key) printf(" @key");
        printf("\n");
    }
}

void print_data(dynamic_data_t* data) {
    printf("  Data of type '%s':\n", data->type->name);
    for (int i = 0; i < data->member_count; i++) {
        data_member_t* m = &data->members[i];
        printf("    %s = ", m->name);
        if (!m->is_set) {
            printf("<unset>\n");
            continue;
        }
        switch (m->type) {
            case TYPE_INT32: printf("%d\n", m->value.int32_val); break;
            case TYPE_FLOAT64: printf("%.2f\n", m->value.float64_val); break;
            case TYPE_STRING: printf("\"%s\"\n", m->value.string_val ? m->value.string_val : ""); break;
            case TYPE_BOOL: printf("%s\n", m->value.bool_val ? "true" : "false"); break;
            default: printf("<complex>\n"); break;
        }
    }
}

void print_dynamic_data_overview(void) {
    printf("--- Dynamic Data Overview ---\n\n");
    printf("Dynamic Data allows working with types at runtime:\n\n");
    printf("  TypeFactory -> DynamicType -> DynamicData\n");
    printf("       |              |              |\n");
    printf("  Creates         Describes       Holds\n");
    printf("  types           structure       values\n");
    printf("\n");
    printf("Use Cases:\n");
    printf("  - Generic data recording/replay tools\n");
    printf("  - Protocol bridges (DDS <-> REST/MQTT)\n");
    printf("  - Data visualization without type knowledge\n");
    printf("  - Testing and debugging utilities\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("Dynamic Data Demo\n");
    printf("Runtime type manipulation and introspection\n");
    printf("============================================================\n\n");
    printf("NOTE: CONCEPT DEMO - Native DynamicData/DynamicType API not yet in SDK.\n");
    printf("      Using standard pub/sub API to demonstrate the pattern.\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    print_dynamic_data_overview();

    /* Create DDS participant */
    struct HddsParticipant* participant = hdds_participant_create("DynamicDataDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n\n", hdds_participant_name(participant));

    /* Create endpoints for transport */
    struct HddsDataWriter* writer = hdds_writer_create(participant, "DynamicDataTopic");
    struct HddsDataReader* reader = hdds_reader_create(participant, "DynamicDataTopic");

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] DDS endpoints created for transport\n\n");

    /* Define a SensorReading type at runtime */
    printf("--- Creating Dynamic Type ---\n\n");

    dynamic_type_t* sensor_type = dynamic_type_create_struct("SensorReading");
    dynamic_type_add_member(sensor_type, "sensor_id", TYPE_INT32, true);
    dynamic_type_add_member(sensor_type, "location", TYPE_STRING, false);
    dynamic_type_add_member(sensor_type, "temperature", TYPE_FLOAT64, false);
    dynamic_type_add_member(sensor_type, "humidity", TYPE_FLOAT64, false);
    dynamic_type_add_member(sensor_type, "is_valid", TYPE_BOOL, false);

    printf("[OK] Type 'SensorReading' created dynamically\n\n");
    print_type(sensor_type);
    printf("\n");

    /* Create and populate dynamic data */
    printf("--- Creating Dynamic Data ---\n\n");

    dynamic_data_t* reading1 = dynamic_data_create(sensor_type);
    dynamic_data_set_int32(reading1, "sensor_id", 101);
    dynamic_data_set_string(reading1, "location", "Building-A/Room-1");
    dynamic_data_set_float64(reading1, "temperature", 23.5);
    dynamic_data_set_float64(reading1, "humidity", 45.2);
    dynamic_data_set_bool(reading1, "is_valid", true);

    printf("[OK] DynamicData instance created\n\n");
    print_data(reading1);
    printf("\n");

    /* Serialize and send via DDS */
    printf("--- Publishing Dynamic Data via DDS ---\n\n");

    char serialized[512];
    size_t ser_len = dynamic_data_serialize(reading1, serialized, sizeof(serialized));

    HelloWorld msg = {.id = 1};
    strncpy(msg.message, serialized, sizeof(msg.message) - 1);

    uint8_t buffer[512];
    size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
    hdds_writer_write(writer, buffer, len);

    printf("[OK] Published: %s\n\n", serialized);

    /* Read values back */
    printf("--- Reading Dynamic Data ---\n\n");

    int32_t id = dynamic_data_get_int32(reading1, "sensor_id");
    const char* loc = dynamic_data_get_string(reading1, "location");
    double temp = dynamic_data_get_float64(reading1, "temperature");
    double hum = dynamic_data_get_float64(reading1, "humidity");
    bool valid = dynamic_data_get_bool(reading1, "is_valid");

    printf("Read values:\n");
    printf("  sensor_id: %d\n", id);
    printf("  location: %s\n", loc);
    printf("  temperature: %.2f\n", temp);
    printf("  humidity: %.2f\n", hum);
    printf("  is_valid: %s\n\n", valid ? "true" : "false");

    /* Type introspection */
    printf("--- Type Introspection ---\n\n");

    printf("Iterating over type members:\n");
    for (int i = 0; i < sensor_type->member_count; i++) {
        member_descriptor_t* m = &sensor_type->members[i];
        printf("  Member '%s':\n", m->name);
        printf("    - Type: %s\n", type_kind_str(m->type));
        printf("    - ID: %d\n", m->id);
        printf("    - Is key: %s\n", m->is_key ? "yes" : "no");
    }
    printf("\n");

    /* Create another type */
    printf("--- Creating Additional Type ---\n\n");

    dynamic_type_t* alarm_type = dynamic_type_create_struct("AlarmEvent");
    dynamic_type_add_member(alarm_type, "alarm_id", TYPE_INT32, true);
    dynamic_type_add_member(alarm_type, "severity", TYPE_INT32, false);
    dynamic_type_add_member(alarm_type, "message", TYPE_STRING, false);
    dynamic_type_add_member(alarm_type, "acknowledged", TYPE_BOOL, false);

    print_type(alarm_type);
    printf("\n");

    dynamic_data_t* alarm = dynamic_data_create(alarm_type);
    dynamic_data_set_int32(alarm, "alarm_id", 5001);
    dynamic_data_set_int32(alarm, "severity", 3);
    dynamic_data_set_string(alarm, "message", "High temperature warning");
    dynamic_data_set_bool(alarm, "acknowledged", false);

    print_data(alarm);
    printf("\n");

    /* Publish alarm via DDS */
    char alarm_ser[512];
    dynamic_data_serialize(alarm, alarm_ser, sizeof(alarm_ser));

    HelloWorld alarm_msg = {.id = 2};
    strncpy(alarm_msg.message, alarm_ser, sizeof(alarm_msg.message) - 1);

    len = HelloWorld_serialize(&alarm_msg, buffer, sizeof(buffer));
    hdds_writer_write(writer, buffer, len);

    printf("[OK] Published alarm: %s\n\n", alarm_ser);

    /* Best practices */
    printf("--- Dynamic Data Best Practices ---\n\n");
    printf("1. Cache type lookups for performance-critical paths\n");
    printf("2. Use member IDs instead of names for faster access\n");
    printf("3. Validate type compatibility before operations\n");
    printf("4. Consider memory management for string members\n");
    printf("5. Use typed APIs when types are known at compile time\n");
    printf("6. Leverage type introspection for generic tooling\n");

    /* Cleanup */
    dynamic_data_destroy(reading1);
    dynamic_data_destroy(alarm);
    free(sensor_type);
    free(alarm_type);

    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Dynamic Data Demo Complete ===\n");
    return 0;
}
