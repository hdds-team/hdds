// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: WaitSets (C)
 *
 * Demonstrates condition-based event handling with WaitSets.
 * WaitSets allow efficient waiting on multiple conditions.
 *
 * Usage:
 *     ./waitsets
 *
 * Key concepts:
 * - WaitSet creation and condition attachment
 * - StatusConditions for data availability
 * - GuardConditions for application-triggered events
 * - Blocking vs timeout-based waiting
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include "generated/HelloWorld.h"

#define MAX_CONDITIONS 16

volatile int running = 1;
volatile int trigger_shutdown = 0;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

void print_waitset_overview(void) {
    printf("--- WaitSet Overview ---\n\n");
    printf("WaitSet Architecture:\n\n");
    printf("  +----------------------------------------+\n");
    printf("  |               WaitSet                  |\n");
    printf("  |  +-----------+ +-----------+           |\n");
    printf("  |  |StatusCond | |StatusCond |           |\n");
    printf("  |  | (Reader1) | | (Reader2) |           |\n");
    printf("  |  +-----------+ +-----------+           |\n");
    printf("  |  +-----------+ +-----------+           |\n");
    printf("  |  |GuardCond  | |Graph Cond |           |\n");
    printf("  |  |(Shutdown) | |(Discovery)|           |\n");
    printf("  |  +-----------+ +-----------+           |\n");
    printf("  +----------------------------------------+\n");
    printf("                    |\n");
    printf("                    v\n");
    printf("              wait(timeout)\n");
    printf("                    |\n");
    printf("                    v\n");
    printf("         Active Conditions List\n");
    printf("\n");
    printf("Condition Types:\n");
    printf("  - StatusCondition: Entity status changed (data available)\n");
    printf("  - GuardCondition: Application-triggered signal\n");
    printf("  - GraphGuardCondition: Discovery events\n");
    printf("\n");
}

/* Thread to trigger guard condition after delay */
void* trigger_thread(void* arg) {
    const struct HddsGuardCondition* guard = (const struct HddsGuardCondition*)arg;
    sleep(3);  /* Wait 3 seconds */
    if (running) {
        printf("\n[TRIGGER] Application requesting shutdown via GuardCondition\n");
        hdds_guard_condition_set_trigger(guard, true);
        trigger_shutdown = 1;
    }
    return NULL;
}

/* Thread to publish data periodically */
void* publisher_thread(void* arg) {
    struct HddsDataWriter* writer = (struct HddsDataWriter*)arg;
    int count = 0;

    while (running && count < 5) {
        sleep(1);

        HelloWorld msg = {.id = count + 1};
        snprintf(msg.message, sizeof(msg.message), "Message #%d", count + 1);

        uint8_t buffer[256];
        size_t len = HelloWorld_serialize(&msg, buffer, sizeof(buffer));
        hdds_writer_write(writer, buffer, len);

        printf("[PUBLISH] Sent message %d\n", count + 1);
        count++;
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("============================================================\n");
    printf("WaitSets Demo\n");
    printf("Condition-based event handling\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    signal(SIGINT, signal_handler);

    print_waitset_overview();

    /* Create participant */
    struct HddsParticipant* participant = hdds_participant_create("WaitSetsDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    printf("[OK] Participant created: %s\n", hdds_participant_name(participant));

    /* Create endpoints */
    struct HddsDataWriter* writer = hdds_writer_create(participant, "WaitSetTopic");
    struct HddsDataReader* reader1 = hdds_reader_create(participant, "WaitSetTopic");
    struct HddsDataReader* reader2 = hdds_reader_create(participant, "AnotherTopic");

    if (!writer || !reader1 || !reader2) {
        fprintf(stderr, "Failed to create endpoints\n");
        if (writer) hdds_writer_destroy(writer);
        if (reader1) hdds_reader_destroy(reader1);
        if (reader2) hdds_reader_destroy(reader2);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] DataWriter and DataReaders created\n\n");

    /* Create WaitSet */
    struct HddsWaitSet* waitset = hdds_waitset_create();
    if (!waitset) {
        fprintf(stderr, "Failed to create waitset\n");
        hdds_reader_destroy(reader1);
        hdds_reader_destroy(reader2);
        hdds_writer_destroy(writer);
        hdds_participant_destroy(participant);
        return 1;
    }

    printf("[OK] WaitSet created\n\n");

    /* Create and attach conditions */
    printf("--- Creating and Attaching Conditions ---\n\n");

    /* Status condition for reader1 (data available) */
    const struct HddsStatusCondition* reader1_cond = hdds_reader_get_status_condition(reader1);
    hdds_waitset_attach_status_condition(waitset, reader1_cond);
    printf("[OK] StatusCondition attached for Reader1 (WaitSetTopic)\n");

    /* Status condition for reader2 */
    const struct HddsStatusCondition* reader2_cond = hdds_reader_get_status_condition(reader2);
    hdds_waitset_attach_status_condition(waitset, reader2_cond);
    printf("[OK] StatusCondition attached for Reader2 (AnotherTopic)\n");

    /* Guard condition for shutdown */
    const struct HddsGuardCondition* shutdown_guard = hdds_guard_condition_create();
    if (shutdown_guard) {
        hdds_waitset_attach_guard_condition(waitset, shutdown_guard);
        printf("[OK] GuardCondition attached for shutdown signal\n");
    }

    /* Graph guard condition for discovery events */
    const struct HddsGuardCondition* graph_cond = hdds_participant_graph_guard_condition(participant);
    if (graph_cond) {
        hdds_waitset_attach_guard_condition(waitset, graph_cond);
        printf("[OK] GraphGuardCondition attached for discovery events\n");
    }

    printf("\n");

    /* Start publisher thread */
    pthread_t pub_thread;
    pthread_create(&pub_thread, NULL, publisher_thread, writer);

    /* Start trigger thread (will trigger shutdown after delay) */
    pthread_t trig_thread;
    if (shutdown_guard) {
        pthread_create(&trig_thread, NULL, trigger_thread, shutdown_guard);
    }

    /* Main event loop */
    printf("--- Event Loop (waiting for conditions) ---\n\n");
    printf("Events will occur over the next few seconds...\n\n");

    int loop_count = 0;
    int data_events = 0;
    int discovery_events = 0;

    while (running && !trigger_shutdown && loop_count < 10) {
        const void* triggered[MAX_CONDITIONS];
        size_t triggered_count = 0;

        enum HddsError result = hdds_waitset_wait(waitset, 1000000000LL, triggered, MAX_CONDITIONS, &triggered_count);

        if (result == HDDS_OK && triggered_count > 0) {
            printf("[WAKE] %zu condition(s) triggered:\n", triggered_count);

            for (size_t i = 0; i < triggered_count; i++) {
                if (triggered[i] == reader1_cond) {
                    printf("  - StatusCondition: Reader1 has data\n");
                    data_events++;

                    /* Read the data */
                    uint8_t buffer[512];
                    size_t len;
                    while (hdds_reader_take(reader1, buffer, sizeof(buffer), &len) == HDDS_OK) {
                        HelloWorld msg;
                        if (HelloWorld_deserialize(&msg, buffer, len)) {
                            printf("    [DATA] id=%d msg='%s'\n", msg.id, msg.message);
                        }
                    }
                } else if (triggered[i] == reader2_cond) {
                    printf("  - StatusCondition: Reader2 has data\n");
                    data_events++;
                } else if (shutdown_guard && triggered[i] == shutdown_guard) {
                    printf("  - GuardCondition: Shutdown requested!\n");
                    trigger_shutdown = 1;
                } else if (graph_cond && triggered[i] == graph_cond) {
                    printf("  - GraphGuardCondition: Discovery event\n");
                    discovery_events++;
                }
            }
            printf("\n");
        } else if (result == HDDS_OK && triggered_count == 0) {
            printf("[TIMEOUT] No events in 1 second\n\n");
        }

        loop_count++;
    }

    /* Wait for threads */
    running = 0;
    pthread_join(pub_thread, NULL);
    if (shutdown_guard) {
        pthread_join(trig_thread, NULL);
    }

    /* Summary */
    printf("--- WaitSet Summary ---\n\n");
    printf("Total event loop iterations: %d\n", loop_count);
    printf("Data events received: %d\n", data_events);
    printf("Discovery events: %d\n", discovery_events);
    printf("Shutdown via guard: %s\n\n", trigger_shutdown ? "yes" : "no");

    /* Event loop pattern */
    printf("--- Event Loop Pattern ---\n\n");
    printf("Typical WaitSet event loop:\n\n");
    printf("  while (running) {\n");
    printf("      triggered = waitset_wait(ws, timeout);\n");
    printf("      \n");
    printf("      for (cond in triggered) {\n");
    printf("          if (cond == shutdown_guard) {\n");
    printf("              running = false;\n");
    printf("          } else if (cond == data_ready) {\n");
    printf("              process_data(reader);\n");
    printf("          } else if (cond == status_changed) {\n");
    printf("              handle_status(entity);\n");
    printf("          }\n");
    printf("      }\n");
    printf("  }\n\n");

    /* Best practices */
    printf("--- WaitSet Best Practices ---\n\n");
    printf("1. Use one WaitSet per processing thread\n");
    printf("2. Prefer WaitSets over polling for efficiency\n");
    printf("3. Use GuardConditions for inter-thread signaling\n");
    printf("4. Set appropriate timeouts for responsiveness\n");
    printf("5. Process all triggered conditions before waiting again\n");
    printf("6. Detach conditions before destroying entities\n");

    /* Cleanup */
    printf("\n--- Cleanup ---\n\n");

    hdds_waitset_detach_condition(waitset, reader1_cond);
    printf("[OK] Detached Reader1 condition\n");
    hdds_waitset_detach_condition(waitset, reader2_cond);
    printf("[OK] Detached Reader2 condition\n");
    if (shutdown_guard) {
        hdds_waitset_detach_condition(waitset, shutdown_guard);
        printf("[OK] Detached shutdown guard\n");
        hdds_guard_condition_release(shutdown_guard);
    }
    if (graph_cond) {
        hdds_waitset_detach_condition(waitset, graph_cond);
        printf("[OK] Detached graph guard\n");
    }

    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader1);
    hdds_reader_destroy(reader2);
    hdds_writer_destroy(writer);
    hdds_participant_destroy(participant);

    printf("\n=== WaitSets Demo Complete ===\n");
    return 0;
}
