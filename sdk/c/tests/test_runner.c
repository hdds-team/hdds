// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Test Runner
 *
 * Runs all HDDS C SDK test suites and prints a PASS/FAIL summary.
 * Each test suite is a separate executable invoked as a subprocess.
 *
 * Build: cmake --build . --target test_runner
 * Usage: ./test_runner
 *
 * Returns non-zero exit code if any test suite fails.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* List of test executables to run (must be in the same directory) */
static const char *test_suites[] = {
    "./test_participant",
    "./test_qos",
    "./test_waitset",
};

#define NUM_SUITES (sizeof(test_suites) / sizeof(test_suites[0]))

int main(void) {
    int total_passed = 0;
    int total_failed = 0;
    int suite_results[NUM_SUITES];

    printf("========================================\n");
    printf("  HDDS C SDK Test Runner\n");
    printf("========================================\n\n");

    for (size_t i = 0; i < NUM_SUITES; i++) {
        printf("--- Running: %s ---\n", test_suites[i]);
        int rc = system(test_suites[i]);

        if (rc == 0) {
            suite_results[i] = 0;
            total_passed++;
            printf("--- %s: PASS ---\n\n", test_suites[i]);
        } else {
            suite_results[i] = 1;
            total_failed++;
            printf("--- %s: FAIL (exit code %d) ---\n\n", test_suites[i], rc);
        }
    }

    /* Summary */
    printf("========================================\n");
    printf("  Summary: %d/%zu suites passed\n",
           total_passed, NUM_SUITES);
    printf("========================================\n");

    for (size_t i = 0; i < NUM_SUITES; i++) {
        printf("  %-30s [%s]\n", test_suites[i],
               suite_results[i] == 0 ? "PASS" : "FAIL");
    }
    printf("\n");

    if (total_failed > 0) {
        printf("RESULT: FAIL (%d suite(s) failed)\n", total_failed);
        return 1;
    }

    printf("RESULT: ALL PASS\n");
    return 0;
}
