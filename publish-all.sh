#!/usr/bin/env bash
# HDDS — Publish all workspace crates to crates.io in dependency order
# Usage: ./publish-all.sh [--dry-run]
#
# Handles crates.io rate limit (max ~4 new crates per hour for new accounts)
# by publishing in batches of 4 with a 1h cooldown between batches.
# Safe to re-run: already-published crates are skipped.

set -euo pipefail

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo "=== DRY RUN MODE ==="
fi

BATCH_SIZE=4
BATCH_COOLDOWN=3660  # 61 minutes (safe margin over 1h rate limit window)

# Topologically sorted: dependencies before dependents
CRATES=(
    # Tier 0: no internal deps
    "tools/hdds-admin"
    "crates/hdds-codegen"
    "tools/hdds-debugger"
    "crates/hdds-gateway"
    "crates/hdds-micro"
    "tools/hdds-shm-viewer"
    "crates/hdds-telemetry-otlp"

    # Tier 1: depends on hdds-codegen or hdds-micro
    "crates/hdds"
    "crates/hdds-micro-c"

    # Tier 2: depends on hdds
    "crates/hdds-discovery-server"
    "crates/hdds-persistence"
    "crates/hdds-recording"
    "crates/hdds-router"
    "crates/hdds-logger"
    "tools/hdds-gen"
    "tools/hddsctl"
    "tools/hdds-convert-qos"
    "tools/hdds-ws"
    "tools/hdds-topic-echo"
    "tools/hdds-latency-probe"
    "tools/hdds-stress"
    "tools/hdds-discovery-dump"
    "crates/hdds-c"
    "sdk/rust"
    "sdk/samples/01_basics/rust"
    "sdk/samples/02_qos/rust"
    "sdk/samples/03_types/rust"
    "sdk/samples/04_discovery/rust"
    "sdk/samples/05_security/rust"
    "sdk/samples/06_performance/rust"
    "sdk/samples/07_advanced/rust"
    "sdk/samples/08_interop/rust"
    "sdk/samples/09_ros2/rust"
    "sdk/samples/10_usecases/rust"
    "sdk/samples/11_embedded/rust"

    # Tier 3: depends on hdds + hdds-c
    "crates/rmw-hdds"
)

TOTAL=${#CRATES[@]}
PUBLISHED=0
SKIPPED=0
FAILED=()
BATCH_COUNT=0

echo ""
echo "Publishing $TOTAL crates to crates.io (batches of $BATCH_SIZE, ${BATCH_COOLDOWN}s cooldown)..."
echo "Started at: $(date)"
echo ""

for i in "${!CRATES[@]}"; do
    dir="${CRATES[$i]}"
    num=$((i + 1))
    name=$(grep '^name' "$dir/Cargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')

    echo "[$num/$TOTAL] Publishing $name from $dir..."

    OUTPUT=$(cargo publish -p "$name" --no-verify $DRY_RUN 2>&1) && {
        echo "  OK: $name"
        PUBLISHED=$((PUBLISHED + 1))
        BATCH_COUNT=$((BATCH_COUNT + 1))
    } || {
        if echo "$OUTPUT" | grep -q "already"; then
            echo "  SKIP: $name (already published)"
            SKIPPED=$((SKIPPED + 1))
        elif echo "$OUTPUT" | grep -q "429\|Too Many Requests\|rate limit"; then
            echo "  RATE LIMITED on $name — waiting ${BATCH_COOLDOWN}s..."
            sleep "$BATCH_COOLDOWN"
            # Retry once after cooldown
            OUTPUT2=$(cargo publish -p "$name" --no-verify $DRY_RUN 2>&1) && {
                echo "  OK (retry): $name"
                PUBLISHED=$((PUBLISHED + 1))
                BATCH_COUNT=$((BATCH_COUNT + 1))
            } || {
                echo "$OUTPUT2"
                echo "  FAILED (after retry): $name"
                FAILED+=("$name")
            }
        else
            echo "$OUTPUT"
            echo "  FAILED: $name"
            FAILED+=("$name")
        fi
    }

    # Wait 30s for crates.io index to update between crates
    if [[ $num -lt $TOTAL ]] && [[ -z "$DRY_RUN" ]]; then
        # Every BATCH_SIZE new publishes, take a long cooldown
        if [[ $BATCH_COUNT -ge $BATCH_SIZE ]]; then
            echo ""
            echo "  === Batch of $BATCH_SIZE done. Cooling down ${BATCH_COOLDOWN}s (~1h) ==="
            echo "  Resume at: $(date -d "+${BATCH_COOLDOWN} seconds" 2>/dev/null || date -v+${BATCH_COOLDOWN}S 2>/dev/null || echo "~1h from now")"
            echo ""
            sleep "$BATCH_COOLDOWN"
            BATCH_COUNT=0
        else
            echo "  Waiting 30s for index..."
            sleep 30
        fi
    fi

    echo ""
done

echo "==========================================="
echo "DONE at: $(date)"
echo "Published: $PUBLISHED | Skipped: $SKIPPED | Failed: ${#FAILED[@]} | Total: $TOTAL"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "Failed crates: ${FAILED[*]}"
    exit 1
else
    echo "All crates published successfully!"
fi
