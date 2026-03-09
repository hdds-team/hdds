// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/**
 * Bitsets and Bitmasks Sample - Demonstrates DDS bit types
 *
 * This sample shows how to work with the Bits struct:
 * - Permissions bitmask (uint64_t with READ/WRITE/EXECUTE/DELETE flags)
 * - StatusFlags bitset (struct with .bits field, getter/setter accessors)
 */

#include <stdio.h>
#include <string.h>
#include "generated/Bits.h"

int main(void) {
    printf("=== HDDS Bitsets and Bitmasks Sample ===\n\n");

    uint8_t buffer[64];

    /* Permissions bitmask */
    printf("--- Permissions Bitmask ---\n");
    printf("Permission flags:\n");
    printf("  READ    = 0x%02llX (%llu)\n",
           (unsigned long long)PERMISSIONS_READ, (unsigned long long)PERMISSIONS_READ);
    printf("  WRITE   = 0x%02llX (%llu)\n",
           (unsigned long long)PERMISSIONS_WRITE, (unsigned long long)PERMISSIONS_WRITE);
    printf("  EXECUTE = 0x%02llX (%llu)\n",
           (unsigned long long)PERMISSIONS_EXECUTE, (unsigned long long)PERMISSIONS_EXECUTE);
    printf("  DELETE  = 0x%02llX (%llu)\n",
           (unsigned long long)PERMISSIONS_DELETE, (unsigned long long)PERMISSIONS_DELETE);

    /* Create permissions with multiple flags */
    Permissions perms = PERMISSIONS_READ | PERMISSIONS_WRITE;

    printf("\nPermissions with READ | WRITE:\n");
    printf("  bits: 0x%02llX\n", (unsigned long long)perms);
    printf("  can_read:    %s\n", (perms & PERMISSIONS_READ)    ? "true" : "false");
    printf("  can_write:   %s\n", (perms & PERMISSIONS_WRITE)   ? "true" : "false");
    printf("  can_execute: %s\n", (perms & PERMISSIONS_EXECUTE) ? "true" : "false");
    printf("  can_delete:  %s\n", (perms & PERMISSIONS_DELETE)  ? "true" : "false");

    /* StatusFlags bitset */
    printf("\n--- StatusFlags Bitset ---\n");
    StatusFlags status = {0};
    StatusFlags_set_priority(&status, 5);
    StatusFlags_set_active(&status, 1);
    StatusFlags_set_warning(&status, 1);

    printf("Status with priority=5, active=1, warning=1:\n");
    printf("  bits: 0x%02llX\n", (unsigned long long)status.bits);
    printf("  priority: %llu\n", (unsigned long long)StatusFlags_get_priority(&status));
    printf("  active:   %llu\n", (unsigned long long)StatusFlags_get_active(&status));
    printf("  error:    %llu\n", (unsigned long long)StatusFlags_get_error(&status));
    printf("  warning:  %llu\n", (unsigned long long)StatusFlags_get_warning(&status));

    /* Bits struct serialization */
    printf("\n--- Bits Serialization ---\n");
    Bits demo = {
        .perms = PERMISSIONS_READ | PERMISSIONS_EXECUTE,
        .flags = {0}
    };
    StatusFlags_set_active(&demo.flags, 1);
    StatusFlags_set_priority(&demo.flags, 8);

    printf("Original:\n");
    printf("  perms: 0x%02llX\n", (unsigned long long)demo.perms);
    printf("  flags: 0x%02llX\n", (unsigned long long)demo.flags.bits);

    int size = bits_encode_cdr2_le(&demo, buffer, sizeof(buffer));
    if (size < 0) {
        printf("[ERROR] Serialization failed! (%d)\n", size);
        return 1;
    }
    printf("Serialized size: %d bytes\n", size);
    printf("Serialized: ");
    for (int i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");

    Bits deser;
    memset(&deser, 0, sizeof(deser));
    bits_decode_cdr2_le(&deser, buffer, (size_t)size);
    printf("Deserialized:\n");
    printf("  perms: 0x%02llX\n", (unsigned long long)deser.perms);
    printf("  flags: 0x%02llX\n", (unsigned long long)deser.flags.bits);

    if (demo.perms == deser.perms && demo.flags.bits == deser.flags.bits) {
        printf("[OK] Bits round-trip successful\n\n");
    }

    /* Test flag operations */
    printf("--- Flag Operations ---\n");

    Permissions flags = 0;
    printf("Initial:      0x%02llX\n", (unsigned long long)flags);

    flags |= PERMISSIONS_READ;
    printf("After +READ:  0x%02llX\n", (unsigned long long)flags);

    flags |= PERMISSIONS_WRITE;
    printf("After +WRITE: 0x%02llX\n", (unsigned long long)flags);

    flags ^= PERMISSIONS_EXECUTE;
    printf("After ^EXEC:  0x%02llX\n", (unsigned long long)flags);

    flags &= ~PERMISSIONS_READ;
    printf("After -READ:  0x%02llX\n", (unsigned long long)flags);

    /* All permissions */
    printf("\n--- All Permissions ---\n");
    Permissions all_perms = PERMISSIONS_READ | PERMISSIONS_WRITE |
                            PERMISSIONS_EXECUTE | PERMISSIONS_DELETE;
    printf("All permissions: 0x%02llX\n", (unsigned long long)all_perms);

    Bits all_demo = {.perms = all_perms, .flags = {0}};
    size = bits_encode_cdr2_le(&all_demo, buffer, sizeof(buffer));
    Bits all_deser;
    memset(&all_deser, 0, sizeof(all_deser));
    bits_decode_cdr2_le(&all_deser, buffer, (size_t)size);
    printf("Round-trip:      0x%02llX\n", (unsigned long long)all_deser.perms);

    printf("\n=== Sample Complete ===\n");
    return 0;
}
