// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * Basic Publish-Subscribe Example using HDDS C FFI
 *
 * This example demonstrates:
 * - Creating a DDS participant
 * - Creating a writer and reader on the same topic
 * - Writing data through the FFI interface
 * - Reading data through the FFI interface
 * - Proper cleanup
 *
 * Build:
 *   gcc -o basic_pubsub basic_pubsub.c -L../../target/debug -lhdds_c -lpthread -ldl -lm
 *
 * Run:
 *   LD_LIBRARY_PATH=../../target/debug ./basic_pubsub
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include "../hdds.h"

/*
 * Minimal rosidl introspection stubs used to demonstrate
 * hdds_participant_register_type_support(). In a real ROS 2
 * deployment these definitions would come from the generated
 * type support of a message package.
 */
static const rosidl_type_hash_t EXAMPLE_TYPE_HASH = {
    .version = 1,
    .value = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    },
};

static const rosidl_type_hash_t *example_get_hash(
    const rosidl_message_type_support_t *type_support) {
    (void)type_support;
    return &EXAMPLE_TYPE_HASH;
}

static const rosidl_typesupport_introspection_c__MessageMember EXAMPLE_MEMBERS[] = {
    {
        .name_ = "x",
        .type_id_ = 1, /* float */
        .string_upper_bound_ = 0,
        .members_ = NULL,
        .is_key_ = false,
        .is_array_ = false,
        .array_size_ = 0,
        .is_upper_bound_ = false,
        .offset_ = 0,
        .default_value_ = NULL,
        .size_function = NULL,
        .get_const_function = NULL,
        .get_function = NULL,
        .fetch_function = NULL,
        .assign_function = NULL,
        .resize_function = NULL,
    },
    {
        .name_ = "label",
        .type_id_ = 16, /* string */
        .string_upper_bound_ = 0,
        .members_ = NULL,
        .is_key_ = false,
        .is_array_ = false,
        .array_size_ = 0,
        .is_upper_bound_ = false,
        .offset_ = 0,
        .default_value_ = NULL,
        .size_function = NULL,
        .get_const_function = NULL,
        .get_function = NULL,
        .fetch_function = NULL,
        .assign_function = NULL,
        .resize_function = NULL,
    },
};

static const rosidl_typesupport_introspection_c__MessageMembers EXAMPLE_MESSAGE_MEMBERS = {
    .message_namespace_ = "demo_msgs__msg",
    .message_name_ = "Example",
    .member_count_ = sizeof(EXAMPLE_MEMBERS) / sizeof(EXAMPLE_MEMBERS[0]),
    .size_of_ = 0,
    .has_any_key_member_ = false,
    .members_ = EXAMPLE_MEMBERS,
    .init_function = NULL,
    .fini_function = NULL,
};

static const rosidl_message_type_support_t EXAMPLE_TYPE_SUPPORT = {
    .typesupport_identifier = "rosidl_typesupport_introspection_c",
    .data = &EXAMPLE_MESSAGE_MEMBERS,
    .func = NULL,
    .get_type_hash_func = example_get_hash,
    .get_type_description_func = NULL,
    .get_type_description_sources_func = NULL,
};

static void print_hash(const uint8_t *hash) {
    for (size_t i = 0; i < ROSIDL_TYPE_HASH_SIZE; ++i) {
        printf("%02" PRIx8, hash[i]);
        if ((i + 1) % 8 == 0 && i + 1 < ROSIDL_TYPE_HASH_SIZE) {
            printf(" ");
        }
    }
    printf("\n");
}

int main(void) {
    printf("HDDS C FFI Basic Pub/Sub Example\n");
    printf("=================================\n\n");

    // Get library version
    const char *version = hdds_version();
    printf("HDDS Version: %s\n\n", version);

    // Create participant
    printf("Creating participant...\n");
    struct HddsParticipant *participant = hdds_participant_create("example_participant");
    if (participant == NULL) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }
    printf("Participant created successfully\n\n");

    // Register ROS 2 type support and obtain a TypeObject handle
    printf("Registering type support for demo_msgs::msg::Example...\n");
    const struct HddsTypeObject *type_object = NULL;
    enum HddsError result = hdds_participant_register_type_support(
        participant,
        0, /* Humble */
        &EXAMPLE_TYPE_SUPPORT,
        &type_object);
    if (result != OK || type_object == NULL) {
        fprintf(stderr, "Failed to register type support (error code: %d)\n", result);
        hdds_participant_destroy(participant);
        return 1;
    }

    uint8_t hash_version = 0;
    uint8_t hash_value[ROSIDL_TYPE_HASH_SIZE] = {0};
    result = hdds_type_object_hash(type_object, &hash_version, hash_value, sizeof(hash_value));
    if (result != OK) {
        fprintf(stderr, "Failed to query TypeObject hash (error code: %d)\n", result);
        hdds_type_object_release(type_object);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("Obtained TypeObject hash (version %u):\n", hash_version);
    print_hash(hash_value);
    printf("\n");

    // TypeObject handle can be cached or released when no longer needed
    hdds_type_object_release(type_object);

    // Create writer
    printf("Creating writer for topic 'example_topic'...\n");
    struct HddsDataWriter *writer = hdds_writer_create(participant, "example_topic");
    if (writer == NULL) {
        fprintf(stderr, "Failed to create writer\n");
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("Writer created successfully\n\n");

    // Create reader
    printf("Creating reader for topic 'example_topic'...\n");
    struct HddsDataReader *reader = hdds_reader_create(participant, "example_topic");
    if (reader == NULL) {
        fprintf(stderr, "Failed to create reader\n");
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("Reader created successfully\n\n");

    printf("Setting up waitset...\n");
    struct HddsWaitSet *waitset = hdds_waitset_create();
    if (waitset == NULL) {
        fprintf(stderr, "Failed to create waitset\n");
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    const struct HddsGuardCondition *graph_guard =
        hdds_participant_graph_guard_condition(participant);
    if (graph_guard == NULL) {
        fprintf(stderr, "Failed to get participant graph guard\n");
        hdds_waitset_destroy(waitset);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    result = hdds_waitset_attach_guard_condition(waitset, graph_guard);
    if (result != OK) {
        fprintf(stderr, "Failed to attach graph guard (error %d)\n", result);
        hdds_guard_condition_release(graph_guard);
        hdds_waitset_destroy(waitset);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    const struct HddsStatusCondition *reader_status =
        hdds_reader_get_status_condition(reader);
    if (reader_status == NULL) {
        fprintf(stderr, "Failed to get reader status condition\n");
        hdds_waitset_detach_condition(waitset, graph_guard);
        hdds_guard_condition_release(graph_guard);
        hdds_waitset_destroy(waitset);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    result = hdds_waitset_attach_status_condition(waitset, reader_status);
    if (result != OK) {
        fprintf(stderr, "Failed to attach reader status condition (error %d)\n", result);
        hdds_status_condition_release(reader_status);
        hdds_waitset_detach_condition(waitset, graph_guard);
        hdds_guard_condition_release(graph_guard);
        hdds_waitset_destroy(waitset);
        hdds_reader_destroy(reader);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("Waiting for discovery via waitset (2s timeout)...\n");
    const void *triggered[4] = {0};
    size_t triggered_len = 0;
    result = hdds_waitset_wait(
        waitset,
        2LL * 1000 * 1000 * 1000,
        triggered,
        4,
        &triggered_len);
    if (result != OK) {
        fprintf(stderr, "Waitset wait failed (error %d)\n", result);
    } else {
        printf("Waitset triggered by %zu condition(s)\n", triggered_len);
    }

    hdds_waitset_detach_condition(waitset, reader_status);
    hdds_status_condition_release(reader_status);

    // Write some data
    const char *message = "Hello from C FFI!";
    printf("Writing message: '%s'\n", message);
    result = hdds_writer_write(writer, message, strlen(message));

    if (result == OK) {
        printf("Message written successfully\n\n");
    } else {
        fprintf(stderr, "Failed to write message (error code: %d)\n", result);
        fprintf(stderr, "Note: This may happen if discovery hasn't completed yet\n\n");
    }

    hdds_waitset_detach_condition(waitset, graph_guard);
    hdds_guard_condition_release(graph_guard);
    hdds_waitset_destroy(waitset);

    // Try to read data
    printf("Attempting to read data...\n");
    char buffer[256];
    size_t len_read = 0;
    result = hdds_reader_take(reader, buffer, sizeof(buffer), &len_read);

    if (result == OK) {
        buffer[len_read] = '\0';  // Null-terminate for printing
        printf("Received message: '%s' (%zu bytes)\n\n", buffer, len_read);
    } else if (result == NOT_FOUND) {
        printf("No data available (this is expected in this simple example)\n");
        printf("Note: Reader may not have received data yet due to discovery timing\n\n");
    } else {
        fprintf(stderr, "Failed to read (error code: %d)\n\n", result);
    }

    // Cleanup
    printf("Cleaning up...\n");
    hdds_reader_destroy(reader);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    printf("Cleanup complete\n\n");

    printf("Example completed successfully!\n");
    return 0;
}
