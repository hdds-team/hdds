#!/usr/bin/env bash
# HDDS — Publish all workspace crates to crates.io in dependency order
# Usage: ./publish-all.sh [--dry-run]
#
# Publishes 36 crates with a 30s delay between each to let the crates.io
# index update (otherwise dependent crates fail to resolve).

set -euo pipefail

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="--dry-run"
    echo "=== DRY RUN MODE ==="
fi

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
FAILED=()

echo ""
echo "Publishing $TOTAL crates to crates.io..."
echo ""

for i in "${!CRATES[@]}"; do
    dir="${CRATES[$i]}"
    num=$((i + 1))
    name=$(grep '^name' "$dir/Cargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')
    version=$(cd "$dir" && cargo pkgid 2>/dev/null | sed 's/.*#//' || echo "?")

    echo "[$num/$TOTAL] Publishing $name ($version) from $dir..."

    OUTPUT=$(cargo publish -p "$name" --no-verify $DRY_RUN 2>&1) && {
        echo "  OK: $name"
    } || {
        if echo "$OUTPUT" | grep -q "already"; then
            echo "  SKIP: $name (already published)"
        else
            echo "$OUTPUT"
            echo "  FAILED: $name"
            FAILED+=("$name")
        fi
    }

    # Wait for crates.io index to update (skip on last crate and dry-run)
    if [[ $num -lt $TOTAL ]] && [[ -z "$DRY_RUN" ]]; then
        echo "  Waiting 30s for crates.io index..."
        sleep 30
    fi

    echo ""
done

echo "=== DONE ==="
echo "Published: $((TOTAL - ${#FAILED[@]}))/$TOTAL"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo "Failed: ${FAILED[*]}"
    exit 1
fi
