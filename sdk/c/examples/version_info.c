// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * HDDS Example: Version Info (C)
 *
 * Minimal HDDS program — prints the library version string.
 *
 * Usage:
 *     ./version_info
 *
 * Expected output:
 *     HDDS version: x.y.z
 */

#include <hdds.h>
#include <stdio.h>

int main(void) {
    printf("HDDS version: %s\n", hdds_version());
    return 0;
}
