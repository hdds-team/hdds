// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/*
 * Checked decoding for the C samples.
 *
 * The generated decoders take no allocator (the generator's design, kept
 * for embedded targets), so a decoder called without one cannot store a
 * string field: it fails with CDR_OUT_OF_MEMORY and leaves the field as it
 * was. The samples decode through an arena instead, a fixed buffer owned by
 * the sample: decoded strings point into it and stay valid until the next
 * decode.
 *
 * Usage, after the include of the generated header of the type:
 *
 *     SAMPLE_DEFINE_DECODE(decode_checked, hdds_samples_HelloWorld,
 *                          hdds_samples_helloworld_decode_cdr2_le_alloc)
 *
 * The defined function returns what the generated decoder returns: the
 * number of bytes consumed on success (> 0), a negative error otherwise.
 * A failure is printed here; the caller must skip the sample then.
 */

#ifndef HDDS_SAMPLE_DECODE_H
#define HDDS_SAMPLE_DECODE_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#define SAMPLE_DECODE_ARENA_SIZE 4096

#define SAMPLE_DEFINE_DECODE(NAME, TYPE, DECODE_ALLOC)                       \
    static uint8_t sample_decode_arena[SAMPLE_DECODE_ARENA_SIZE];            \
    static int NAME(TYPE* out, const uint8_t* src, size_t len) {             \
        hdds_x2c_arena arena;                                                \
        int rc;                                                              \
        hdds_x2c_arena_init(&arena, sample_decode_arena,                     \
                            sizeof sample_decode_arena);                     \
        rc = DECODE_ALLOC(out, src, len, hdds_x2c_arena_alloc, &arena);      \
        if (rc < 0) {                                                        \
            fprintf(stderr, "decode failed (error %d), sample skipped\n", rc); \
        }                                                                    \
        return rc;                                                           \
    }

#endif /* HDDS_SAMPLE_DECODE_H */
