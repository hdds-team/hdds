#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Measures what the no_std DDS-XRCE client actually costs on a 32-bit MCU
# target, so the "<20KB RAM" line on the website has a number behind it.
#
# It prints, and fails if any of them cannot be produced:
#   - .text / .data / .bss of hdds-xrce-client built for thumbv7em-none-eabihf
#   - CLIENT_STATE_BYTES (size_of::<XrceClient>) from the crate itself
#   - the named test that asserts state + a 512-byte MTU buffer stays under 20 KB
#
# Requires: rustup target thumbv7em-none-eabihf, and `size` (GNU binutils).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET=thumbv7em-none-eabihf
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "FAIL: rust target $TARGET is not installed (rustup target add $TARGET)" >&2
    exit 1
fi
if ! command -v size >/dev/null 2>&1; then
    echo "FAIL: 'size' (GNU binutils) is required to measure the artefact" >&2
    exit 1
fi

echo "=== hdds-xrce-client, target $TARGET, release ==="
cargo build -p hdds-xrce-client --release --target "$TARGET"

RLIB="$TARGET_DIR/$TARGET/release/libhdds_xrce_client.rlib"
if [ ! -f "$RLIB" ]; then
    echo "FAIL: $RLIB not produced" >&2
    exit 1
fi

SIZE_OUT="$(size -t "$RLIB")"
echo "$SIZE_OUT"
TOTALS="$(echo "$SIZE_OUT" | awk '/TOTALS/ {print $1" "$2" "$3}')"
TEXT="$(echo "$TOTALS" | cut -d' ' -f1)"
DATA="$(echo "$TOTALS" | cut -d' ' -f2)"
BSS="$(echo "$TOTALS" | cut -d' ' -f3)"
if [ -z "$TEXT" ]; then
    echo "FAIL: could not read the section totals out of size(1)" >&2
    exit 1
fi
echo "flash (.text) = ${TEXT} bytes ; .data = ${DATA} ; .bss = ${BSS}"

echo
echo "=== session state and the announced RAM budget ==="
# The crate's own named test carries the assertion; --nocapture prints the
# measured bytes when it fails, and the exit code is the gate.
#
# `--exact` plus the "1 passed" check, because a filter that matches NOTHING
# exits 0: without this the gate stays green if the named assertion is
# renamed or deleted.
ASSERTION_OUT="$(cargo test -p hdds-xrce-client --release -- --nocapture --exact \
    tests::client_state_fits_the_announced_ram_budget 2>&1)"
ASSERTION_RC=$?
echo "$ASSERTION_OUT"
if [ $ASSERTION_RC -ne 0 ]; then
    echo "FAIL: the RAM-budget assertion did not pass" >&2
    exit 1
fi
if ! echo "$ASSERTION_OUT" | grep -q "1 passed"; then
    echo "FAIL: client_state_fits_the_announced_ram_budget did not run (renamed or removed?)" >&2
    exit 1
fi

cargo test -p hdds-xrce-client
echo "xrce-size-gate: PASSED (flash ${TEXT} B, data ${DATA} B, bss ${BSS} B on ${TARGET})"
