#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Intra-process latency benchmark for HDDS.
# Runs the latency_benchmark example N times and computes statistics.
#
# Usage:
#   ./scripts/bench-intra-process.sh              # 100 runs, build first
#   ./scripts/bench-intra-process.sh 50            # 50 runs
#   ./scripts/bench-intra-process.sh 100 --no-build  # skip cargo build
#
# Tips:
#   - Copy the binary to /tmp for best results (avoids NFS/network FS overhead)
#   - Set CPU governor to 'performance' for stable results:
#       sudo cpupower frequency-set -g performance
#   - Close other workloads for clean measurements

set -euo pipefail

RUNS="${1:-100}"
SKIP_BUILD=false
for arg in "$@"; do
    [ "$arg" = "--no-build" ] && SKIP_BUILD=true
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_DIR/target/release/examples/latency_benchmark"

# --- Build ---
if [ "$SKIP_BUILD" = false ]; then
    echo "Building latency_benchmark (release)..."
    cargo build --release --example latency_benchmark --manifest-path "$PROJECT_DIR/Cargo.toml" 2>&1 \
        | grep -v "^warning:" || true
fi

if [ ! -x "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    echo "       Run: cargo build --release --example latency_benchmark"
    exit 1
fi

# Copy to /tmp to avoid filesystem overhead (NFS, network mounts, etc.)
BENCH_BIN="/tmp/hdds_latency_benchmark_$$"
cp "$BINARY" "$BENCH_BIN"
trap 'rm -f "$BENCH_BIN"' EXIT

# --- Collect ---
echo ""
echo "=== HDDS Intra-Process Latency Benchmark ==="
echo "Host:    $(hostname)"
cpu_model=$(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | sed 's/.*: //')
echo "CPU:     ${cpu_model:-unknown}"
echo "Kernel:  $(uname -r)"
echo "Date:    $(date -Iseconds)"
echo "Runs:    $RUNS"
echo ""

declare -a p50_values=()
declare -a p99_values=()
declare -a min_values=()
declare -a tput_values=()

for i in $(seq 1 "$RUNS"); do
    output=$("$BENCH_BIN" 2>/dev/null)

    min=$(echo "$output"  | grep "^Min latency:"  | sed 's/[^0-9]//g')
    p50=$(echo "$output"  | grep "^p50 latency:"  | sed 's/[^0-9]//g')
    p99=$(echo "$output"  | grep "^p99 latency:"  | sed 's/[^0-9]//g')
    tput=$(echo "$output" | grep "^Throughput:"    | sed 's/.*: *//' | tr -d ' kmsg/s')

    min_values+=("$min")
    p50_values+=("$p50")
    p99_values+=("$p99")
    tput_values+=("$tput")

    printf "\r  Run %3d/%d - p50: %s ns" "$i" "$RUNS" "$p50" >&2
done
echo "" >&2

# --- Statistics ---
calc_stats() {
    local label="$1"
    shift
    local arr=("$@")
    local n=${#arr[@]}

    # Sort numerically
    IFS=$'\n' sorted=($(printf '%s\n' "${arr[@]}" | sort -n)); unset IFS

    local sum=0
    for v in "${sorted[@]}"; do sum=$((sum + v)); done

    local s_min=${sorted[0]}
    local s_max=${sorted[$((n - 1))]}
    local s_avg=$((sum / n))
    local s_med=${sorted[$((n / 2))]}
    local s_p10=${sorted[$((n * 10 / 100))]}
    local s_p90=${sorted[$((n * 90 / 100))]}

    printf "| %-10s | %6d ns | %6d ns | %6d ns | %6d ns | %6d ns | %6d ns |\n" \
        "$label" "$s_min" "$s_p10" "$s_med" "$s_avg" "$s_p90" "$s_max"
}

echo ""
echo "| Metric     |    Min    |    p10    |  Median  |    Avg   |    p90   |    Max   |"
echo "|------------|----------|----------|----------|----------|----------|----------|"
calc_stats "Min"  "${min_values[@]}"
calc_stats "p50"  "${p50_values[@]}"
calc_stats "p99"  "${p99_values[@]}"

# Count sub-257ns p50 runs
sub257=0
for v in "${p50_values[@]}"; do
    [ "$v" -le 257 ] 2>/dev/null && sub257=$((sub257 + 1))
done

echo ""
echo "Runs with p50 <= 257ns: $sub257 / $RUNS"
echo ""

# Best run
IFS=$'\n' sorted_p50=($(printf '%s\n' "${p50_values[@]}" | sort -n)); unset IFS
echo "Best p50:  ${sorted_p50[0]} ns"
echo "Worst p50: ${sorted_p50[$((${#sorted_p50[@]} - 1))]} ns"
