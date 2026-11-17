#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Measure the compiled code size of the hdds-micro core for a Cortex-M target.
#
# What this measures, and what it does not: the .text of the objects inside the
# produced rlib, which is the library's compiled code. It is NOT a linked firmware
# image: a final link applies garbage collection, and an application pulls only the
# subset it calls. Published figures must carry that distinction.
#
# Usage:
#   crates/hdds-micro/scripts/footprint.sh [TARGET]
#
# Default TARGET is thumbv7em-none-eabihf (Cortex-M4F). The target must be
# installed: rustup target add <TARGET>.
set -u

TARGET=${1:-thumbv7em-none-eabihf}
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
OUT=${CARGO_TARGET_DIR:-$REPO/target/footprint-$TARGET}

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "target $TARGET is not installed: rustup target add $TARGET" >&2
    exit 2
fi

SIZE=$(find "$(rustc --print sysroot)" -name llvm-size -type f 2>/dev/null | head -1)
if [ -z "$SIZE" ]; then
    echo "llvm-size not found in the Rust sysroot; install the llvm-tools component" >&2
    exit 2
fi

echo "target:    $TARGET"
echo "revision:  $(git -C "$REPO" rev-parse --short=9 HEAD 2>/dev/null || echo unknown)"

cargo build --release -p hdds-micro --target "$TARGET" --no-default-features \
      --target-dir "$OUT" >/dev/null 2>&1 || {
    echo "build failed" >&2; exit 1; }

RLIB=$OUT/$TARGET/release/libhdds_micro.rlib
[ -f "$RLIB" ] || { echo "rlib not produced at $RLIB" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$WORK" && ar x "$RLIB" && "$SIZE" -t ./*.o | tail -1) | awk '
    {printf "text:      %s bytes\ndata:      %s bytes\nbss:       %s bytes\n", $1, $2, $3}'
echo
echo "Reported as: the no_std core compiles to the .text above on $TARGET in release"
echo "with no default features. Not a linked firmware image."
