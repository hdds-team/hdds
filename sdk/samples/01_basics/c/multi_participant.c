// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Multi-Participant (C)
 *
 * Demonstrates multiple DDS participants in the same process.
 *
 * Usage:
 *     ./multi_participant
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "generated/HelloWorld.h"

typedef struct {
    const char* name;
    const char* topic;
    int is_publisher;
} ThreadArgs;

static void* publisher_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;

    printf("[%s] Creating participant...\n", args->name);
    HddsParticipant* participant = hdds_participant_create(args->name);
    if (!participant) {
        fprintf(stderr, "[%s] Failed to create participant\n", args->name);
        return NULL;
    }

    HddsDataWriter* writer = hdds_writer_create(participant, args->topic);
    printf("[%s] Publishing to '%s'...\n", args->name, args->topic);

    HelloWorld msg;
    HelloWorld_init(&msg);
    snprintf(msg.message, sizeof(msg.message), "From %s", args->name);

    for (int i = 0; i < 5; i++) {
        msg.id = i;
        uint8_t buffer[512];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
        hdds_writer_write(writer, buffer, len);
        printf("[%s] Sent: %s #%d\n", args->name, msg.message, msg.id);
        usleep(300000);
    }

    printf("[%s] Done.\n", args->name);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);
    return NULL;
}

static void* subscriber_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;

    printf("[%s] Creating participant...\n", args->name);
    HddsParticipant* participant = hdds_participant_create(args->name);
    if (!participant) {
        fprintf(stderr, "[%s] Failed to create participant\n", args->name);
        return NULL;
    }

    HddsDataReader* reader = hdds_reader_create(participant, args->topic);
    HddsWaitSet* waitset = hdds_waitset_create();
    hdds_waitset_attach_status_condition(waitset, hdds_reader_get_status_condition(reader));

    printf("[%s] Subscribing to '%s'...\n", args->name, args->topic);
    int received = 0;

    while (received < 10) {
        const void* triggered[1];
        size_t count;

        if (hdds_waitset_wait(waitset, 2000000000LL, triggered, 1, &count) == HDDS_OK && count > 0) {
            uint8_t buffer[512];
            size_t len;

            while (hdds_reader_take(reader, buffer, sizeof(buffer), &len) == HDDS_OK) {
                HelloWorld msg;
                HelloWorld_deserialize(&msg, buffer, len);
                printf("[%s] Received: %s #%d\n", args->name, msg.message, msg.id);
                received++;
            }
        }
    }

    printf("[%s] Done.\n", args->name);
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_participant_destroy(participant);
    return NULL;
}

int main(void) {
    hdds_logging_init(3);

    printf("============================================================\n");
    printf("Multi-Participant Demo\n");
    printf("Creating 3 participants: 2 publishers + 1 subscriber\n");
    printf("============================================================\n");

    const char* topic = "MultiParticipantTopic";

    ThreadArgs sub_args = {"Subscriber", topic, 0};
    ThreadArgs pub_a_args = {"Publisher-A", topic, 1};
    ThreadArgs pub_b_args = {"Publisher-B", topic, 1};

    pthread_t threads[3];

    // Start subscriber first
    pthread_create(&threads[0], NULL, subscriber_thread, &sub_args);
    usleep(200000);
    pthread_create(&threads[1], NULL, publisher_thread, &pub_a_args);
    pthread_create(&threads[2], NULL, publisher_thread, &pub_b_args);

    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("============================================================\n");
    printf("All participants finished.\n");
    printf("============================================================\n");

    return 0;
}
