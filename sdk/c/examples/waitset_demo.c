// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Example: WaitSet Demo (C)
 *
 * Demonstrates event-driven reception with WaitSet:
 *   - Create a waitset
 *   - Attach a guard condition and a status condition
 *   - Wait with timeout
 *   - Trigger guard condition manually
 *   - Detach conditions and cleanup
 *
 * Usage:
 *     ./waitset_demo
 *
 * Expected output:
 *     Wait timed out (expected — no data yet)
 *     Guard condition triggered!
 *     ...
 *     Cleanup complete.
 */

#include <hdds.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    hdds_logging_init(HDDS_LOG_INFO);

    /* Create participant and reader (needed for status condition) */
    struct HddsParticipant *participant =
        hdds_participant_create_with_transport("WaitSetDemo", HDDS_TRANSPORT_INTRA_PROCESS);
    if (!participant) {
        fprintf(stderr, "Failed to create participant\n");
        return 1;
    }

    struct HddsDataReader *reader = hdds_reader_create(participant, "WaitSetTopic");
    if (!reader) {
        fprintf(stderr, "Failed to create reader\n");
        hdds_participant_destroy(participant);
        return 1;
    }

    /* Create waitset */
    struct HddsWaitSet *waitset = hdds_waitset_create();
    if (!waitset) {
        fprintf(stderr, "Failed to create waitset\n");
        hdds_reader_destroy(reader);
        hdds_participant_destroy(participant);
        return 1;
    }

    /* Create and attach a guard condition */
    const struct HddsGuardCondition *guard = hdds_guard_condition_create();
    enum HddsError err = hdds_waitset_attach_guard_condition(waitset, guard);
    if (err != HDDS_OK) {
        fprintf(stderr, "Failed to attach guard condition: %d\n", err);
    }

    /* Attach a reader status condition */
    const struct HddsStatusCondition *status_cond =
        hdds_reader_get_status_condition(reader);
    err = hdds_waitset_attach_status_condition(waitset, status_cond);
    if (err != HDDS_OK) {
        fprintf(stderr, "Failed to attach status condition: %d\n", err);
    }

    printf("WaitSet created with guard condition + status condition.\n\n");

    /* ---- 1. Wait with timeout (nothing triggered) ---- */
    printf("1) Waiting 500ms (nothing triggered)...\n");
    {
        const void *triggered[4];
        size_t count = 0;
        /* 500 ms = 500_000_000 ns */
        err = hdds_waitset_wait(waitset, 500000000LL, triggered, 4, &count);
        if (count == 0) {
            printf("   Wait timed out (expected — no data yet)\n");
        } else {
            printf("   Unexpected: %zu conditions triggered\n", count);
        }
    }

    /* ---- 2. Trigger guard condition, then wait ---- */
    printf("\n2) Triggering guard condition...\n");
    hdds_guard_condition_set_trigger(guard, true);

    {
        const void *triggered[4];
        size_t count = 0;
        err = hdds_waitset_wait(waitset, 1000000000LL, triggered, 4, &count);
        printf("   Wait returned: %zu condition(s) triggered\n", count);
        for (size_t i = 0; i < count; i++) {
            if (triggered[i] == (const void *)guard) {
                printf("   -> Guard condition triggered!\n");
            } else if (triggered[i] == (const void *)status_cond) {
                printf("   -> Status condition triggered!\n");
            } else {
                printf("   -> Unknown condition %p\n", triggered[i]);
            }
        }
    }

    /* Reset the guard condition */
    hdds_guard_condition_set_trigger(guard, false);

    /* ---- 3. Write data, then wait for status condition ---- */
    printf("\n3) Writing data to trigger status condition...\n");
    {
        struct HddsDataWriter *writer =
            hdds_writer_create(participant, "WaitSetTopic");
        if (writer) {
            const char *msg = "wake up!";
            hdds_writer_write(writer, msg, strlen(msg) + 1);
            hdds_writer_destroy(writer);
        }

        const void *triggered[4];
        size_t count = 0;
        err = hdds_waitset_wait(waitset, 1000000000LL, triggered, 4, &count);
        printf("   Wait returned: %zu condition(s) triggered\n", count);

        /* Drain the reader */
        uint8_t buf[256];
        size_t len;
        while (hdds_reader_take(reader, buf, sizeof(buf), &len) == HDDS_OK) {
            printf("   Read: '%s'\n", (char *)buf);
        }
    }

    /* ---- 4. Detach conditions ---- */
    printf("\n4) Detaching conditions...\n");
    hdds_waitset_detach_condition(waitset, (const void *)guard);
    hdds_waitset_detach_condition(waitset, (const void *)status_cond);
    printf("   Conditions detached.\n");

    /* ---- Cleanup ---- */
    hdds_status_condition_release(status_cond);
    hdds_guard_condition_release(guard);
    hdds_waitset_destroy(waitset);
    hdds_reader_destroy(reader);
    hdds_participant_destroy(participant);

    printf("\nCleanup complete.\n");
    return 0;
}
