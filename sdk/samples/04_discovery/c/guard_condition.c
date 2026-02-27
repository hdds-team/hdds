// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Sample: Guard Condition (C)
 *
 * Demonstrates manual event signaling with GuardConditions.
 * A background thread triggers a guard condition after a delay,
 * waking the main thread's WaitSet.
 *
 * Build:
 *     cd build && cmake .. && make guard_condition
 *
 * Usage:
 *     ./guard_condition
 *
 * Expected output:
 *     [OK] GuardCondition created
 *     [OK] Attached to WaitSet
 *     Waiting for trigger (background thread will fire in 2s)...
 *     [TRIGGER] Guard condition triggered from background thread
 *     [WAKE] GuardCondition fired!
 *
 * Key concepts:
 * - GuardCondition for application-level signaling
 * - Attach/detach conditions on a WaitSet
 * - Cross-thread triggering
 */

#include <hdds.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define TRIGGER_DELAY_SEC 2

/* Background thread: triggers the guard condition after a delay */
static void *trigger_thread(void *arg)
{
    const struct HddsGuardCondition *guard = (const struct HddsGuardCondition *)arg;

    printf("[THREAD] Sleeping %d seconds before triggering...\n", TRIGGER_DELAY_SEC);
    sleep(TRIGGER_DELAY_SEC);

    printf("[TRIGGER] Guard condition triggered from background thread\n");
    hdds_guard_condition_set_trigger(guard, true);

    return NULL;
}

int main(void)
{
    printf("============================================================\n");
    printf("Guard Condition Demo\n");
    printf("Manual event signaling via GuardCondition\n");
    printf("============================================================\n\n");

    hdds_logging_init(HDDS_LOG_INFO);

    /* Create participant (needed for context, not strictly for guard) */
    struct HddsParticipant *participant = hdds_participant_create("GuardCondDemo");
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }
    printf("[OK] Participant created\n");

    /* Create guard condition */
    const struct HddsGuardCondition *guard = hdds_guard_condition_create();
    if (!guard) {
        fprintf(stderr, "Failed to create guard condition\n");
        hdds_participant_destroy(participant);
        return 1;
    }
    printf("[OK] GuardCondition created (trigger_value=false)\n");

    /* Create WaitSet and attach guard condition */
    struct HddsWaitSet *waitset = hdds_waitset_create();
    if (!waitset) {
        fprintf(stderr, "Failed to create waitset\n");
        hdds_guard_condition_release(guard);
        hdds_participant_destroy(participant);
        return 1;
    }

    hdds_waitset_attach_guard_condition(waitset, guard);
    printf("[OK] GuardCondition attached to WaitSet\n\n");

    /* Spawn background trigger thread */
    pthread_t tid;
    pthread_create(&tid, NULL, trigger_thread, (void *)guard);

    /* Wait on the WaitSet - will block until guard is triggered */
    printf("Waiting for trigger (background thread will fire in %ds)...\n\n",
           TRIGGER_DELAY_SEC);

    const void *triggered[1];
    size_t triggered_count = 0;

    /* 5 second timeout as safety net */
    enum HddsError result = hdds_waitset_wait(
        waitset, 5000000000LL, triggered, 1, &triggered_count);

    if (result == HDDS_OK && triggered_count > 0) {
        if (triggered[0] == guard) {
            printf("[WAKE] GuardCondition fired!\n");
        }
    } else {
        printf("[TIMEOUT] Guard condition was not triggered in time\n");
    }

    /* Reset the guard condition */
    hdds_guard_condition_set_trigger(guard, false);
    printf("[OK] GuardCondition reset to false\n");

    /* Demonstrate a second trigger cycle */
    printf("\n--- Second trigger (immediate) ---\n\n");

    hdds_guard_condition_set_trigger(guard, true);
    printf("[TRIGGER] Guard condition set to true (immediate)\n");

    result = hdds_waitset_wait(waitset, 1000000000LL, triggered, 1, &triggered_count);
    if (result == HDDS_OK && triggered_count > 0) {
        printf("[WAKE] Immediate trigger detected!\n");
    }

    /* Wait for background thread */
    pthread_join(tid, NULL);

    /* Cleanup */
    printf("\n--- Cleanup ---\n");
    hdds_waitset_detach_condition(waitset, guard);
    printf("[OK] GuardCondition detached\n");
    hdds_guard_condition_release(guard);
    hdds_waitset_destroy(waitset);
    hdds_participant_destroy(participant);

    printf("\n=== Guard Condition Demo Complete ===\n");
    return 0;
}
