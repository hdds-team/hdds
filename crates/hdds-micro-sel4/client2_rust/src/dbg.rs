// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Thin Rust wrapper around `hdds_dbg_puts` - the C trampoline over
//! `microkit_dbg_puts` exposed by `client2_rust_wrapper.c`.
//!
//! The kernel debug UART (`microkit_dbg_puts`) is the cheapest serial
//! sink available to a Microkit PD: no serial-PD wiring, no shared
//! memory regions, no sDDF channel - just a syscall the kernel
//! forwards to the platform UART. Only present in debug builds
//! (`CONFIG_PRINTING` in seL4), which matches `MICROKIT_CONFIG=debug`
//! used by all hdds-micro-sel4 scripts.
//!
//! We expose `dbg_str` (raw string, no formatting) and `dbg_u64_line`
//! (one decimal u64 + label). Both are no-alloc: callers pass `&str`
//! slices and stack buffers; we copy into a fixed-size local buffer
//! and append a NUL terminator before crossing the FFI boundary.

extern "C" {
    fn hdds_dbg_puts(s: *const u8);
}

/// Max stack buffer for one debug line, including trailing NUL.
const DBG_BUF_LEN: usize = 128;

/// Print `s` followed by a newline. Truncates silently if the message
/// would exceed `DBG_BUF_LEN - 2` bytes (one byte for `\n`, one for the
/// terminating NUL).
pub(crate) fn dbg_line(s: &str) {
    let mut buf = [0u8; DBG_BUF_LEN];
    let max_payload = DBG_BUF_LEN - 2;
    let n = core::cmp::min(s.len(), max_payload);
    buf[..n].copy_from_slice(&s.as_bytes()[..n]);
    buf[n] = b'\n';
    // buf[n+1] stays at 0 - that's our NUL terminator.
    // SAFETY: the buffer is fully initialised (zero-filled then partly
    // overwritten), NUL-terminated, and lives for the duration of the
    // FFI call. `hdds_dbg_puts` is a C-side trampoline that only reads
    // up to (and including) the first NUL.
    unsafe { hdds_dbg_puts(buf.as_ptr()) };
}

/// Emit `label=<value>\n` as a single debug line. No-alloc - we
/// format the u64 into a small stack buffer using a manual decimal
/// conversion (avoids pulling `core::fmt::Write` into the no_std PD).
//
// Used by `subscriber` mode only; `#[allow(dead_code)]` so the
// publisher feature build (which only calls `dbg_line`) does not
// trip dead-code lints.
#[allow(dead_code)]
pub(crate) fn dbg_label_u64(prefix: &str, label: &str, value: u64) {
    let mut buf = [0u8; DBG_BUF_LEN];
    let mut pos = 0;

    pos = copy_into(&mut buf, pos, prefix.as_bytes());
    pos = copy_into(&mut buf, pos, label.as_bytes());
    pos = copy_into(&mut buf, pos, b"=");

    pos = copy_u64(&mut buf, pos, value);

    if pos < DBG_BUF_LEN - 1 {
        buf[pos] = b'\n';
        pos += 1;
    }
    // buf[pos] stays NUL.
    let _ = pos;
    // SAFETY: same as `dbg_line` - buffer fully initialised + NUL-
    // terminated; FFI callee reads up to the first NUL.
    unsafe { hdds_dbg_puts(buf.as_ptr()) };
}

/// Emit `prefix` followed by ` label=value` for each field, as one line.
/// Used by the `stats` build only.
#[cfg(feature = "stats")]
pub(crate) fn dbg_fields(prefix: &str, fields: &[(&str, u64)]) {
    let mut buf = [0u8; DBG_BUF_LEN];
    let mut pos = copy_into(&mut buf, 0, prefix.as_bytes());
    for (label, value) in fields {
        pos = copy_into(&mut buf, pos, b" ");
        pos = copy_into(&mut buf, pos, label.as_bytes());
        pos = copy_into(&mut buf, pos, b"=");
        pos = copy_u64(&mut buf, pos, *value);
    }
    if pos < DBG_BUF_LEN - 1 {
        buf[pos] = b'\n';
    }
    // SAFETY: same as `dbg_line` - buffer fully initialised + NUL-
    // terminated; FFI callee reads up to the first NUL.
    unsafe { hdds_dbg_puts(buf.as_ptr()) };
}

#[allow(dead_code)]
fn copy_into(buf: &mut [u8; DBG_BUF_LEN], mut pos: usize, src: &[u8]) -> usize {
    for &b in src {
        if pos >= DBG_BUF_LEN - 1 {
            break;
        }
        buf[pos] = b;
        pos += 1;
    }
    pos
}

/// Append `value` in decimal, stopping at the payload limit of the buffer.
#[allow(dead_code)]
fn copy_u64(buf: &mut [u8; DBG_BUF_LEN], mut pos: usize, value: u64) -> usize {
    // Manual u64 -> decimal ASCII. Worst case 20 digits.
    let mut digits = [0u8; 20];
    let mut d = 0;
    let mut v = value;
    if v == 0 {
        digits[d] = b'0';
        d += 1;
    } else {
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
    }
    while d > 0 {
        d -= 1;
        if pos < DBG_BUF_LEN - 2 {
            buf[pos] = digits[d];
            pos += 1;
        }
    }
    pos
}
