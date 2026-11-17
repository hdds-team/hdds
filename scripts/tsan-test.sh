#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# ThreadSanitizer runner for the hdds crate (quality TODO 6.2).
#
# Builds std + hdds with -Zsanitizer=thread (nightly + -Zbuild-std) and
# fails if any "WARNING: ThreadSanitizer" report appears in the output.
# TSan-instrumented artifacts land in a dedicated target dir so they
# never pollute the shared normal build cache.
#
# Usage:
#   scripts/tsan-test.sh [FILTER]                # hdds lib unit tests
#   scripts/tsan-test.sh --test NAME [FILTER]    # one integration test target
#
# Examples:
#   scripts/tsan-test.sh merger
#   scripts/tsan-test.sh slabpool
#   scripts/tsan-test.sh --test concurrency_stress
#
# Notes:
#   - TSan runs are 10-20x slower than plain cargo test; keep filters tight.
#   - Requires: nightly toolchain with the rust-src component.
#   - halt_on_error=0 so a single race does not hide later ones; the
#     script itself exits nonzero when any warning was emitted.

set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_TRIPLE="x86_64-unknown-linux-gnu"
TSAN_TARGET_DIR="${TSAN_TARGET_DIR:-${REPO_ROOT}/.target-tsan}"

TEST_TARGET=""
if [ "${1:-}" = "--test" ]; then
    if [ $# -lt 2 ]; then
        echo "error: --test requires an integration test target name" >&2
        exit 2
    fi
    TEST_TARGET="$2"
    shift 2
fi
FILTER="${1:-}"

LOG_FILE="$(mktemp /tmp/hdds-tsan-XXXXXX.log)"

CMD=(cargo +nightly test -Zbuild-std --target "$TARGET_TRIPLE" -p hdds)
if [ -n "$TEST_TARGET" ]; then
    CMD+=(--test "$TEST_TARGET")
else
    CMD+=(--lib)
fi
if [ -n "$FILTER" ]; then
    CMD+=("$FILTER")
fi
# Bounded harness parallelism keeps interleaved TSan reports readable.
CMD+=(-- --test-threads=4)

echo "[tsan] repo       : $REPO_ROOT"
echo "[tsan] target dir : $TSAN_TARGET_DIR"
echo "[tsan] command    : ${CMD[*]}"
echo "[tsan] log        : $LOG_FILE"

(
    cd "$REPO_ROOT" &&
        RUSTFLAGS="-Zsanitizer=thread" \
        TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1" \
        CARGO_TARGET_DIR="$TSAN_TARGET_DIR" \
        "${CMD[@]}"
) 2>&1 | tee "$LOG_FILE"
CARGO_STATUS=${PIPESTATUS[0]}

WARN_COUNT=$(grep -c "WARNING: ThreadSanitizer" "$LOG_FILE" || true)

echo
echo "==================== TSAN SUMMARY ===================="
if [ "$WARN_COUNT" -gt 0 ]; then
    echo "[tsan] RACES FOUND: $WARN_COUNT ThreadSanitizer warning(s)"
    grep -n "WARNING: ThreadSanitizer" "$LOG_FILE" | sed 's/^/[tsan]   /'
    echo "[tsan] full report: $LOG_FILE"
    echo "======================================================="
    exit 1
fi
if [ "$CARGO_STATUS" -ne 0 ]; then
    echo "[tsan] cargo exited nonzero ($CARGO_STATUS) with no TSan warnings"
    echo "[tsan] (build or test-assertion failure; see $LOG_FILE)"
    echo "======================================================="
    exit "$CARGO_STATUS"
fi
echo "[tsan] CLEAN: no ThreadSanitizer warnings"
echo "======================================================="
