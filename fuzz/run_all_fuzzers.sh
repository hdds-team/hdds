#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Run all HDDS fuzz targets in parallel
# Usage: ./run_all_fuzzers.sh [duration_seconds]

DURATION=${1:-3600}  # 1 hour default
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "═══════════════════════════════════════════════════════════════"
echo "  HDDS Fuzzing Campaign - All Targets"
echo "═══════════════════════════════════════════════════════════════"
echo "  Duration: ${DURATION}s ($((DURATION/60)) minutes)"
echo "  Log dir:  $LOG_DIR"
echo

TARGETS=$(cargo +nightly fuzz list 2>/dev/null)
PIDS=""

for target in $TARGETS; do
    LOG="${LOG_DIR}/${target}_${TIMESTAMP}.log"
    echo "[START] $target -> $LOG"

    cargo +nightly fuzz run "$target" -- \
        -max_total_time="$DURATION" \
        -jobs=2 \
        > "$LOG" 2>&1 &

    PIDS="$PIDS $!"
done

echo
echo "Fuzzers running in background. PIDs: $PIDS"
echo "Monitor with: tail -f $LOG_DIR/*.log"
echo
echo "Waiting for completion..."

# Wait for all fuzzers
for pid in $PIDS; do
    wait $pid 2>/dev/null
done

echo
echo "═══════════════════════════════════════════════════════════════"
echo "  Fuzzing Complete - Checking Results"
echo "═══════════════════════════════════════════════════════════════"

# Check for crashes
CRASH_COUNT=0
for target in $TARGETS; do
    ARTIFACT_DIR="$SCRIPT_DIR/artifacts/$target"
    if [[ -d "$ARTIFACT_DIR" ]] && [[ -n "$(ls -A "$ARTIFACT_DIR" 2>/dev/null)" ]]; then
        echo "❌ CRASH in $target:"
        ls -la "$ARTIFACT_DIR"
        CRASH_COUNT=$((CRASH_COUNT + 1))
    else
        CORPUS_DIR="$SCRIPT_DIR/corpus/$target"
        CORPUS_COUNT=$(ls "$CORPUS_DIR" 2>/dev/null | wc -l)
        echo "✅ $target - OK (corpus: $CORPUS_COUNT entries)"
    fi
done

echo
if [[ $CRASH_COUNT -gt 0 ]]; then
    echo "⚠️  Found $CRASH_COUNT crash(es)! Check artifacts/ directory."
else
    echo "✅ All fuzzers completed without crashes!"
fi
