// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Bitsets and Bitmasks Sample - Demonstrates DDS bit types
 *
 * This sample shows how to work with bit types:
 * - Bitmask types (Permissions)
 * - Bitset types (StatusFlags)
 */

#include <stdio.h>
#include "generated/Bits.h"

int main(void) {
    printf("=== HDDS Bitsets and Bitmasks Sample ===\n\n");

    uint8_t buffer[64];

    /* Permissions bitmask */
    printf("--- Permissions Bitmask ---\n");
    printf("Permission flags:\n");
    printf("  READ    = 0x%02X (%u)\n", PERM_READ, PERM_READ);
    printf("  WRITE   = 0x%02X (%u)\n", PERM_WRITE, PERM_WRITE);
    printf("  EXECUTE = 0x%02X (%u)\n", PERM_EXECUTE, PERM_EXECUTE);
    printf("  DELETE  = 0x%02X (%u)\n", PERM_DELETE, PERM_DELETE);

    /* Create permissions with multiple flags */
    Permissions perms = PERM_READ | PERM_WRITE;

    printf("\nPermissions with READ | WRITE:\n");
    printf("  bits: 0x%02X\n", perms);
    printf("  can_read:    %s\n", Permissions_can_read(perms) ? "true" : "false");
    printf("  can_write:   %s\n", Permissions_can_write(perms) ? "true" : "false");
    printf("  can_execute: %s\n", Permissions_can_execute(perms) ? "true" : "false");
    printf("  can_delete:  %s\n", Permissions_can_delete(perms) ? "true" : "false");

    /* StatusFlags bitset */
    printf("\n--- StatusFlags Bitset ---\n");
    printf("Status flags:\n");
    printf("  ENABLED  = 0x%02X\n", STATUS_ENABLED);
    printf("  VISIBLE  = 0x%02X\n", STATUS_VISIBLE);
    printf("  SELECTED = 0x%02X\n", STATUS_SELECTED);
    printf("  FOCUSED  = 0x%02X\n", STATUS_FOCUSED);
    printf("  ERROR    = 0x%02X\n", STATUS_ERROR);
    printf("  WARNING  = 0x%02X\n", STATUS_WARNING);

    StatusFlags status = STATUS_ENABLED | STATUS_VISIBLE | STATUS_WARNING;

    printf("\nStatus with ENABLED | VISIBLE | WARNING:\n");
    printf("  bits: 0x%02X\n", status);
    printf("  is_enabled:  %s\n", StatusFlags_is_enabled(status) ? "true" : "false");
    printf("  is_visible:  %s\n", StatusFlags_is_visible(status) ? "true" : "false");
    printf("  has_error:   %s\n", StatusFlags_has_error(status) ? "true" : "false");
    printf("  has_warning: %s\n", StatusFlags_has_warning(status) ? "true" : "false");

    /* BitsDemo serialization */
    printf("\n--- BitsDemo Serialization ---\n");
    BitsDemo demo = {
        .permissions = PERM_READ | PERM_EXECUTE,
        .status = STATUS_ENABLED | STATUS_FOCUSED
    };

    printf("Original:\n");
    printf("  permissions: 0x%02X\n", demo.permissions);
    printf("  status:      0x%02X\n", demo.status);

    size_t size = BitsDemo_serialize(&demo, buffer, sizeof(buffer));
    printf("Serialized size: %zu bytes\n", size);
    printf("Serialized: ");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");

    BitsDemo deser;
    BitsDemo_deserialize(&deser, buffer, size);
    printf("Deserialized:\n");
    printf("  permissions: 0x%02X\n", deser.permissions);
    printf("  status:      0x%02X\n", deser.status);

    if (demo.permissions == deser.permissions && demo.status == deser.status) {
        printf("[OK] BitsDemo round-trip successful\n\n");
    }

    /* Test flag operations */
    printf("--- Flag Operations ---\n");

    Permissions flags = PERM_NONE;
    printf("Initial:      0x%02X\n", flags);

    flags |= PERM_READ;
    printf("After +READ:  0x%02X\n", flags);

    flags |= PERM_WRITE;
    printf("After +WRITE: 0x%02X\n", flags);

    flags ^= PERM_EXECUTE;
    printf("After ^EXEC:  0x%02X\n", flags);

    flags &= ~PERM_READ;
    printf("After -READ:  0x%02X\n", flags);

    /* All permissions */
    printf("\n--- All Permissions ---\n");
    Permissions all_perms = PERM_READ | PERM_WRITE | PERM_EXECUTE | PERM_DELETE;
    printf("All permissions: 0x%02X\n", all_perms);

    BitsDemo all_demo = {.permissions = all_perms, .status = 0};
    size = BitsDemo_serialize(&all_demo, buffer, sizeof(buffer));
    BitsDemo all_deser;
    BitsDemo_deserialize(&all_deser, buffer, size);
    printf("Round-trip:      0x%02X\n", all_deser.permissions);

    printf("\n=== Sample Complete ===\n");
    return 0;
}
