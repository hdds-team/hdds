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
#   - The CPU governor is CHECKED, not merely advised: the script refuses to
#     run unless it is 'performance' (override with --allow-any-governor).
#     The governor it ran under is printed in the report.
#   - Close other workloads for clean measurements

set -euo pipefail

RUNS="${1:-100}"
SKIP_BUILD=false
ALLOW_ANY_GOVERNOR=false
for arg in "$@"; do
    [ "$arg" = "--no-build" ] && SKIP_BUILD=true
    [ "$arg" = "--allow-any-governor" ] && ALLOW_ANY_GOVERNOR=true
done

# --- Regime guard -----------------------------------------------------------
#
# A benchmark that cannot detect its own invalid regime produces confident
# garbage. The governor is therefore checked, not left as ADVICE in the header
# comment: nobody reads a header before running a script, and the number that
# comes out looks exactly like a good one.
#
# The cost is real: a non-performance governor can inflate medians by a large
# factor, and some governors stay at their minimum frequency under sustained
# load instead of ramping up -- so "it will clock up when it needs to" is not
# something to assume.
#
# NO RATIO IS QUOTED HERE, DELIBERATELY. Throughput does not track frequency
# one-for-one: how far it falls short depends on how much of the workload is
# waiting on memory rather than on the CPU, which is a property of the workload
# and not of the machine. Printing a factor invites the reader to rescue a bad
# number by multiplying it back up, which is exactly the thing that does not
# work. There is no correction. Re-measure.
#
# `--allow-any-governor` exists for someone who deliberately wants a
# non-performance regime. It prints the governor into the report either way, so
# a result can always be read back with the regime it came from.
check_governor() {
    local govs
    govs=$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u | paste -sd, -)
    if [ -z "$govs" ]; then
        GOVERNOR="unknown (no cpufreq on this host)"
        return 0
    fi
    GOVERNOR="$govs"
    [ "$govs" = "performance" ] && return 0
    if [ "$ALLOW_ANY_GOVERNOR" = true ]; then
        echo "WARNING: governor is '$govs', not 'performance'. Continuing because" >&2
        echo "         --allow-any-governor was given. The numbers below describe" >&2
        echo "         THAT regime and are not comparable to published figures." >&2
        return 0
    fi
    cat >&2 <<GOVERR
ERROR: CPU governor is '$govs', not 'performance'.

  Refusing to measure. A wrong governor can inflate the result by a large
  factor and the resulting number looks perfectly plausible. Some governors
  also stay at their minimum frequency under sustained load rather than
  clocking up.

  There is no correction factor. Do not scale a number back up: throughput does
  not track frequency one-for-one, and the shortfall depends on the workload.
  Set the governor and measure again.

  Fix it:
      for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
          echo performance | sudo tee "\$c" >/dev/null
      done
  or, if it is deliberate:
      $0 $RUNS --allow-any-governor

  Governors are usually NOT persistent across a reboot: re-check after one.
GOVERR
    exit 1
}
check_governor

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
# awk with an explicit `exit`, NOT `grep | head -1`. Under `set -o pipefail`
# the pipeline form kills this script on any machine whose /proc/cpuinfo is
# larger than a pipe buffer (many-core hosts): head closes after one line, grep
# is still writing, takes SIGPIPE, and the pipeline reports 141.
cpu_model=$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || true)
echo "CPU:     ${cpu_model:-unknown}"
echo "Kernel:  $(uname -r)"
echo "Governor: ${GOVERNOR}"
echo "Date:    $(date -Iseconds)"
echo "Runs:    $RUNS"
echo ""

declare -a p50_values=()
declare -a p99_values=()
declare -a min_values=()
declare -a tput_values=()

for i in $(seq 1 "$RUNS"); do
    output=$("$BENCH_BIN" 2>/dev/null)

    # Take the FIELD, never `sed 's/[^0-9]//g'` on the whole line. Stripping
    # non-digits keeps the digits in the LABEL too: "p50 latency: 190 ns"
    # became 50190 and "p99 latency: 231 ns" became 99231, the label's own
    # digits glued in front of the value. "Min latency:" has no digit in its
    # name, so min alone was right, which is what made the other two look like
    # a plausible engine result rather than a parsing bug.
    #
    # The damage was not cosmetic: this harness is what an outsider runs to
    # reproduce our published latency. It reported a p50 of ~50200 ns against a
    # true ~195 ns, a factor of 265, and its own summary line then announced
    # "Runs with p50 <= 257ns: 0 / N" -- telling every reader we miss our own
    # published figure, on every run, when the real numbers meet it 8 times
    # out of 8.
    min=$(echo "$output"  | awk '/^Min latency:/ {print $3; exit}')
    p50=$(echo "$output"  | awk '/^p50 latency:/ {print $3; exit}')
    p99=$(echo "$output"  | awk '/^p99 latency:/ {print $3; exit}')
    # Same rule as above: the FIELD, not a character filter. `tr -d ' kmsg/s'`
    # deletes those letters wherever they appear, so it happens to work while
    # the unit is a lowercase "k" and silently yields "4207.8M" the day the
    # example prints "M msg/s". Nothing here is wrong today; it is one unit
    # change away from being wrong, and the p50 bug above was exactly that
    # kind of latent parse.
    tput=$(echo "$output" | awk '/^Throughput:/ {print $2; exit}')

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
