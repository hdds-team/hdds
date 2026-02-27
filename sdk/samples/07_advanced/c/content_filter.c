// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Content Filter (C)
 *
 * Demonstrates content-filtered topic concepts.
 * Content filters allow subscribers to receive only data matching
 * SQL-like filter expressions, reducing network and CPU overhead.
 *
 * Usage:
 *     ./content_filter
 *
 * Key concepts:
 * - ContentFilteredTopic creation
 * - SQL filter expressions
 * - Filter parameters
 * - Application-side filtering demo
 *
 * NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for ContentFilteredTopic.
 * The native ContentFilteredTopic API is not yet exported to the C/C++/Python SDK.
 * This sample uses standard participant/writer/reader API to show the concept.
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "generated/HelloWorld.h"

#define NUM_SENSORS 10

/* Sensor data with extended fields */
typedef struct {
    uint32_t sensor_id;
    char location[32];
    float temperature;
    float humidity;
} sensor_data_t;

/* Simple filter structure */
typedef struct {
    float temp_threshold;
    float humidity_threshold;
    const char* location_filter;
} content_filter_t;

/* Check if data matches filter (application-side demo) */
int matches_filter(const sensor_data_t* data, const content_filter_t* filter) {
    if (filter->temp_threshold > 0 && data->temperature <= filter->temp_threshold) {
        return 0;
    }
    if (filter->humidity_threshold > 0 && data->humidity <= filter->humidity_threshold) {
        return 0;
    }
    if (filter->location_filter && strlen(filter->location_filter) > 0) {
        if (strcmp(data->location, filter->location_filter) != 0) {
            return 0;
        }
    }
    return 1;
}

void print_filter_info(void) {
    printf("--- Content Filter Overview ---\n\n");
    printf("Content filters use SQL-like WHERE clause syntax:\n\n");
    printf("  Filter Expression          | Description\n");
    printf("  ---------------------------|---------------------------\n");
    printf("  temperature > 25.0         | High temperature readings\n");
    printf("  location = 'Room1'         | Specific location only\n");
    printf("  sensor_id BETWEEN 1 AND 10 | Sensor ID range\n");
    printf("  humidity > %%0              | Parameterized threshold\n");
    printf("  location LIKE 'Building%%'  | Pattern matching\n");
    printf("\n");
    printf("Note: Full content filter implementation via HDDS extensions.\n");
    printf("This sample demonstrates the filtering concept.\n\n");
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("Content Filter Demo\n");
    printf("SQL-like filtering for DDS topics\n");
    printf("============================================================\n\n");
    printf("NOTE: CONCEPT DEMO - Native ContentFilteredTopic API not yet in SDK.\n");
    printf("      Using standard pub/sub API to demonstrate the pattern.\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    print_filter_info();

    /* Create participant */
    struct HddsParticipant* participant = hdds_participant_create("ContentFilterDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));

    /* Create endpoints */
    struct HddsDataWriter* writer = hdds_writer_create(participant, "SensorData");
    struct HddsDataReader* reader = hdds_reader_create(participant, "SensorData");

    if (!writer || !reader) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader) hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] DataWriter and DataReader created for 'SensorData' topic\n\n");

    /* Define filters */
    printf("--- Defining Content Filters ---\n\n");

    content_filter_t high_temp_filter = {
        .temp_threshold = 30.0f,
        .humidity_threshold = 0,
        .location_filter = NULL
    };
    printf("[OK] Filter 1: temperature > 30.0 (high temperature alerts)\n");

    content_filter_t server_room_filter = {
        .temp_threshold = 0,
        .humidity_threshold = 0,
        .location_filter = "ServerRoom"
    };
    printf("[OK] Filter 2: location = 'ServerRoom'\n");

    content_filter_t combined_filter = {
        .temp_threshold = 25.0f,
        .humidity_threshold = 60.0f,
        .location_filter = NULL
    };
    printf("[OK] Filter 3: temperature > 25.0 AND humidity > 60.0\n\n");

    /* Generate and publish sensor data */
    printf("--- Publishing Sensor Data ---\n\n");

    const char* locations[] = {"ServerRoom", "Office1", "Lobby", "DataCenter"};
    sensor_data_t samples[NUM_SENSORS];
    srand((unsigned int)time(NULL));

    for (int i = 0; i < NUM_SENSORS; i++) {
        samples[i].sensor_id = (uint32_t)(i + 1);
        strncpy(samples[i].location, locations[i % 4], sizeof(samples[i].location) - 1);
        samples[i].temperature = 20.0f + (float)(rand() % 200) / 10.0f;  /* 20-40 */
        samples[i].humidity = 40.0f + (float)(rand() % 400) / 10.0f;      /* 40-80 */

        printf("Publishing: sensor=%u, loc=%s, temp=%.1f, hum=%.1f\n",
               samples[i].sensor_id, samples[i].location,
               samples[i].temperature, samples[i].humidity);

        /* Publish via real HDDS (using HelloWorld as carrier) */
        HelloWorld msg = {.id = (int32_t)samples[i].sensor_id};
        snprintf(msg.message, sizeof(msg.message), "%s:%.1f:%.1f",
                 samples[i].location, samples[i].temperature, samples[i].humidity);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
        hdds_writer_write(writer, buffer, len);
    }

    /* Show which samples match each filter */
    printf("\n--- Filter Results (Application-Side) ---\n\n");

    printf("High Temperature Filter (temp > 30.0):\n");
    int match_count = 0;
    for (int i = 0; i < NUM_SENSORS; i++) {
        if (matches_filter(&samples[i], &high_temp_filter)) {
            printf("  [MATCH] sensor=%u, temp=%.1f\n",
                   samples[i].sensor_id, samples[i].temperature);
            match_count++;
        }
    }
    if (match_count == 0) printf("  (no matches)\n");

    printf("\nServerRoom Filter (location = 'ServerRoom'):\n");
    match_count = 0;
    for (int i = 0; i < NUM_SENSORS; i++) {
        if (matches_filter(&samples[i], &server_room_filter)) {
            printf("  [MATCH] sensor=%u, loc=%s\n",
                   samples[i].sensor_id, samples[i].location);
            match_count++;
        }
    }
    if (match_count == 0) printf("  (no matches)\n");

    printf("\nEnvironment Alert Filter (temp > 25 AND hum > 60):\n");
    match_count = 0;
    for (int i = 0; i < NUM_SENSORS; i++) {
        if (matches_filter(&samples[i], &combined_filter)) {
            printf("  [MATCH] sensor=%u, temp=%.1f, hum=%.1f\n",
                   samples[i].sensor_id, samples[i].temperature, samples[i].humidity);
            match_count++;
        }
    }
    if (match_count == 0) printf("  (no matches)\n");

    /* Demonstrate dynamic filter update */
    printf("\n--- Dynamic Filter Update ---\n\n");
    printf("Changing high temperature threshold from 30.0 to 35.0...\n");

    high_temp_filter.temp_threshold = 35.0f;
    printf("[OK] Filter updated dynamically\n");

    printf("\nNew matches (temp > 35.0):\n");
    match_count = 0;
    for (int i = 0; i < NUM_SENSORS; i++) {
        if (matches_filter(&samples[i], &high_temp_filter)) {
            printf("  [MATCH] sensor=%u, temp=%.1f\n",
                   samples[i].sensor_id, samples[i].temperature);
            match_count++;
        }
    }
    if (match_count == 0) printf("  (no matches)\n");

    /* Benefits summary */
    printf("\n--- Content Filter Benefits ---\n\n");
    printf("1. Network Efficiency: Filtering at source reduces traffic\n");
    printf("2. CPU Efficiency: Subscriber processes only relevant data\n");
    printf("3. Flexibility: SQL-like expressions for complex filters\n");
    printf("4. Dynamic Updates: Change filters without recreating readers\n");
    printf("5. Parameterization: Use %%0, %%1 for runtime values\n");

    /* Cleanup */
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== Content Filter Demo Complete ===\n");
    return 0;
}
