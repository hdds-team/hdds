#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# HDDS Reproducible Latency Benchmark Harness
# ============================================
# Single source of truth for HDDS intra-process latency numbers: every
# published figure must be regenerable by anyone running this script.
#
# What it measures: intra-process end-to-end roundtrip latency of the
# tracked example crates/hdds/examples/latency_benchmark.rs -- a wall-clock
# timestamp is taken immediately before writer.write(&msg), and the latency
# is (now - that timestamp) right after reader.take() returns the sample,
# on a single thread, with a 16-byte payload (2x u64). Warmup is performed
# by the benchmark binary itself before measurement starts.
#
# Build pinning: the benchmark is ALWAYS built with thin-LTO and
# codegen-units=1 on the release profile, enforced through cargo
# environment overrides (CARGO_PROFILE_RELEASE_LTO=thin,
# CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1) so that manifest edits or local
# cargo config cannot silently change the flags. Ambient RUSTFLAGS is
# cleared unless explicitly re-injected via HDDS_BENCH_RUSTFLAGS. Mixed
# build flags have been observed to produce phantom deltas in the tens of
# nanoseconds; this script exists so that can never happen unnoticed.
#
# Usage:
#   ./scripts/bench-repro.sh                 # 5 rounds, pinned to core 3
#   HDDS_BENCH_CORE=5 HDDS_BENCH_ROUNDS=9 ./scripts/bench-repro.sh
#
# Environment overrides:
#   HDDS_BENCH_CORE       CPU core to pin the benchmark to (default: 3)
#   HDDS_BENCH_ROUNDS     Number of benchmark rounds (default: 5)
#   HDDS_BENCH_EXAMPLE    latency_benchmark (default, 10k msgs/round) or
#                         latency_benchmark_prof (10M msgs/round)
#   HDDS_BENCH_OUT_DIR    Result directory (default: <repo>/target/bench-repro)
#   HDDS_BENCH_RUSTFLAGS  Extra RUSTFLAGS, e.g. "-C target-cpu=native".
#                         Default: empty (portable baseline). Whatever is
#                         used is recorded in the results stamp.
#   CARGO_TARGET_DIR      Respected as usual by cargo.
#
# Dependencies:
#   required: bash, cargo/rustc (workspace toolchain), coreutils, awk, sed
#   optional: taskset (util-linux; without it the run is NOT core-pinned),
#             git (stamp falls back to "unknown" outside a checkout),
#             jq or python3 (only for JSON self-validation of the output)
#
# Output:
#   - human-readable per-round summary + median-of-rounds on stdout
#   - machine-readable JSON: <out-dir>/bench-results-<sha>-<host>.json
#   - raw benchmark output:  <same basename>.rounds.log
#
# Exit codes:
#   0 = benchmark completed and results written (warnings possible)
#   1 = configuration, build, run, or parse failure

set -euo pipefail

################################################################################
# Configuration
################################################################################

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

readonly HDDS_BENCH_CORE="${HDDS_BENCH_CORE:-3}"
readonly HDDS_BENCH_ROUNDS="${HDDS_BENCH_ROUNDS:-5}"
readonly HDDS_BENCH_EXAMPLE="${HDDS_BENCH_EXAMPLE:-latency_benchmark}"
readonly HDDS_BENCH_OUT_DIR="${HDDS_BENCH_OUT_DIR:-${PROJECT_ROOT}/target/bench-repro}"

# Colors (suppressed when stdout is not a terminal)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

usage() {
    sed -n '/^# Usage:/,/^# Exit codes:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}
[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && usage

die() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo -e "${GREEN}[OK]${NC} $*"; }

################################################################################
# Validate configuration
################################################################################

[[ "$HDDS_BENCH_CORE" =~ ^[0-9]+$ ]] \
    || die "HDDS_BENCH_CORE must be a non-negative integer (got '$HDDS_BENCH_CORE')"
[[ "$HDDS_BENCH_ROUNDS" =~ ^[1-9][0-9]*$ ]] \
    || die "HDDS_BENCH_ROUNDS must be a positive integer (got '$HDDS_BENCH_ROUNDS')"

case "$HDDS_BENCH_EXAMPLE" in
    latency_benchmark)      EXPECTED_MSGS=10000;    EXPECTED_WARMUP=1000 ;;
    latency_benchmark_prof) EXPECTED_MSGS=10000000; EXPECTED_WARMUP=100000 ;;
    *) die "HDDS_BENCH_EXAMPLE must be 'latency_benchmark' or 'latency_benchmark_prof' (got '$HDDS_BENCH_EXAMPLE')" ;;
esac
readonly EXPECTED_MSGS EXPECTED_WARMUP

command -v cargo >/dev/null 2>&1 || die "cargo not found in PATH"
command -v rustc >/dev/null 2>&1 || die "rustc not found in PATH"

NUM_CORES="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)"
[[ "$NUM_CORES" =~ ^[0-9]+$ ]] || NUM_CORES=0
if [[ "$NUM_CORES" -gt 0 && "$HDDS_BENCH_CORE" -ge "$NUM_CORES" ]]; then
    die "HDDS_BENCH_CORE=$HDDS_BENCH_CORE but only $NUM_CORES cores are online (valid: 0..$((NUM_CORES - 1)))"
fi

TASKSET_AVAILABLE=0
if command -v taskset >/dev/null 2>&1; then
    TASKSET_AVAILABLE=1
else
    warn "taskset not found (util-linux): the benchmark will NOT be core-pinned."
    warn "Results without pinning are noisier and are stamped pinned=false."
fi

################################################################################
# Environment stamp
################################################################################

cd "$PROJECT_ROOT"

DATE_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST_RAW="$(hostname -s 2>/dev/null || uname -n 2>/dev/null || echo unknown)"
HOST="${HOST_RAW//[^A-Za-z0-9._-]/_}"
KERNEL="$(uname -sr 2>/dev/null || echo unknown)"
RUSTC_VERSION="$(rustc --version 2>/dev/null || echo unknown)"
CARGO_VERSION="$(cargo --version 2>/dev/null || echo unknown)"
CPU_MODEL="$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
[[ -n "$CPU_MODEL" ]] || CPU_MODEL="unknown"
HDDS_VERSION="$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/' || echo unknown)"

GIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_SHA_SHORT="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY=false
if [[ "$GIT_SHA" != "unknown" ]] && [[ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]]; then
    GIT_DIRTY=true
fi

# Scaling governor of the pinned core (best effort; absent in most VMs).
GOVERNOR_PATH="/sys/devices/system/cpu/cpu${HDDS_BENCH_CORE}/cpufreq/scaling_governor"
if [[ -r "$GOVERNOR_PATH" ]]; then
    GOVERNOR="$(cat "$GOVERNOR_PATH" 2>/dev/null || echo unknown)"
else
    GOVERNOR="unavailable"
fi

governor_warning() {
    if [[ "$GOVERNOR" != "performance" ]]; then
        echo ""
        echo -e "${YELLOW}${BOLD}==================================================================${NC}"
        echo -e "${YELLOW}${BOLD} WARNING: scaling governor on core ${HDDS_BENCH_CORE} is '${GOVERNOR}'${NC}"
        echo -e "${YELLOW}${BOLD} (want 'performance'). Frequency scaling adds noise and latency.${NC}"
        echo -e "${YELLOW} To fix (as root):${NC}"
        echo -e "${YELLOW}   echo performance > ${GOVERNOR_PATH}${NC}"
        echo -e "${YELLOW}${BOLD} Numbers from this run are NOT reference-grade.${NC}"
        echo -e "${YELLOW}${BOLD}==================================================================${NC}"
        echo ""
    fi
}

################################################################################
# Pinned build
################################################################################

# RUSTFLAGS is pinned: ambient values are dropped so that user-level cargo
# config or shell exports cannot skew the build. Opt back in explicitly via
# HDDS_BENCH_RUSTFLAGS; whatever is used ends up in the stamp.
if [[ -n "${RUSTFLAGS:-}" && -z "${HDDS_BENCH_RUSTFLAGS+x}" ]]; then
    warn "Ambient RUSTFLAGS='$RUSTFLAGS' is IGNORED for the pinned build."
    warn "Set HDDS_BENCH_RUSTFLAGS to inject flags deliberately (they get stamped)."
fi
export RUSTFLAGS="${HDDS_BENCH_RUSTFLAGS-}"

# Profile pinning via environment overrides: these beat both Cargo.toml and
# any .cargo/config.toml, so the build flags below are exact by construction.
export CARGO_PROFILE_RELEASE_LTO="thin"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1"

CARGO_CMD=(cargo build --locked
    --manifest-path "${PROJECT_ROOT}/Cargo.toml"
    --release -p hdds --example "$HDDS_BENCH_EXAMPLE")

echo ""
echo -e "${BOLD}=== HDDS Reproducible Latency Benchmark ===${NC}"
echo ""
echo "Pinned build invocation (exact):"
echo "  CARGO_PROFILE_RELEASE_LTO=thin \\"
echo "  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \\"
echo "  RUSTFLAGS='${RUSTFLAGS}' \\"
echo "  ${CARGO_CMD[*]}"
echo ""

BUILD_LOG="$(mktemp)"
trap 'rm -f "$BUILD_LOG"' EXIT
if ! "${CARGO_CMD[@]}" >"$BUILD_LOG" 2>&1; then
    tail -30 "$BUILD_LOG" >&2
    die "cargo build failed (full log: $BUILD_LOG preserved on failure)"
fi
trap - EXIT
rm -f "$BUILD_LOG"
info "Build complete (release profile, lto=thin, codegen-units=1, --locked)"

BENCH_BIN="${CARGO_TARGET_DIR:-${PROJECT_ROOT}/target}/release/examples/${HDDS_BENCH_EXAMPLE}"
[[ -x "$BENCH_BIN" ]] || die "benchmark binary not found at $BENCH_BIN"

################################################################################
# Stamp banner
################################################################################

echo ""
echo -e "${BLUE}--- Environment stamp ---${NC}"
echo "Date (UTC):     $DATE_UTC"
echo "Host:           $HOST"
echo "CPU model:      $CPU_MODEL"
echo "CPU cores:      $NUM_CORES"
echo "Pinned core:    $HDDS_BENCH_CORE (taskset available: $TASKSET_AVAILABLE)"
echo "Governor:       $GOVERNOR"
echo "Kernel:         $KERNEL"
echo "rustc:          $RUSTC_VERSION"
echo "cargo:          $CARGO_VERSION"
echo "HDDS version:   $HDDS_VERSION"
echo "Git commit:     $GIT_SHA (dirty: $GIT_DIRTY)"
echo "Build flags:    profile=release lto=thin codegen-units=1 locked=true RUSTFLAGS='${RUSTFLAGS}'"
echo "Benchmark:      $HDDS_BENCH_EXAMPLE ($EXPECTED_MSGS msgs/round, $EXPECTED_WARMUP warmup, 16-byte payload)"
echo "Rounds:         $HDDS_BENCH_ROUNDS"

governor_warning

################################################################################
# Run rounds
################################################################################

mkdir -p "$HDDS_BENCH_OUT_DIR"

DIRTY_SUFFIX=""
if [[ "$GIT_DIRTY" == "true" ]]; then DIRTY_SUFFIX="-dirty"; fi
RESULT_BASE="bench-results-${GIT_SHA_SHORT}${DIRTY_SUFFIX}-${HOST}"
RESULT_JSON="${HDDS_BENCH_OUT_DIR}/${RESULT_BASE}.json"
if [[ -e "$RESULT_JSON" ]]; then
    STAMP_SUFFIX="$(date -u +%Y%m%d-%H%M%S)"
    RESULT_JSON="${HDDS_BENCH_OUT_DIR}/${RESULT_BASE}-${STAMP_SUFFIX}.json"
fi
RESULT_LOG="${RESULT_JSON%.json}.rounds.log"
: > "$RESULT_LOG"

ROUND_TMP="$(mktemp)"
trap 'rm -f "$ROUND_TMP"' EXIT

# Extract "<value>" from lines like "p50 latency:   104 ns"
parse_ns() { # $1=field prefix, $2=log file
    awk -v key="$1" 'index($0, key" latency:") == 1 {print $3; exit}' "$2"
}

require_uint() { # $1=name, $2=value
    [[ "$2" =~ ^[0-9]+$ ]] || die "could not parse $1 from benchmark output (got '$2'); raw output: $RESULT_LOG"
}

R_MSGS=() R_MIN=() R_MEAN=() R_P50=() R_P95=() R_P99=() R_MAX=() R_THRPT=()

for ((round = 1; round <= HDDS_BENCH_ROUNDS; round++)); do
    echo -e "${BLUE}--- Round ${round}/${HDDS_BENCH_ROUNDS} ---${NC}"
    if [[ "$TASKSET_AVAILABLE" -eq 1 ]]; then
        taskset -c "$HDDS_BENCH_CORE" "$BENCH_BIN" > "$ROUND_TMP" 2>&1 \
            || { cat "$ROUND_TMP" >&2; die "benchmark run failed in round $round"; }
    else
        "$BENCH_BIN" > "$ROUND_TMP" 2>&1 \
            || { cat "$ROUND_TMP" >&2; die "benchmark run failed in round $round"; }
    fi

    { echo "===== round $round ====="; cat "$ROUND_TMP"; echo ""; } >> "$RESULT_LOG"

    msgs="$(awk '/^Messages:/ {print $2; exit}' "$ROUND_TMP")"
    min="$(parse_ns "Min" "$ROUND_TMP")"
    mean="$(parse_ns "Mean" "$ROUND_TMP")"
    p50="$(parse_ns "p50" "$ROUND_TMP")"
    p95="$(parse_ns "p95" "$ROUND_TMP")"
    p99="$(parse_ns "p99" "$ROUND_TMP")"
    max="$(parse_ns "Max" "$ROUND_TMP")"
    thrpt="$(awk '/^Throughput:/ {print $2; exit}' "$ROUND_TMP")"

    require_uint "Messages" "$msgs"
    require_uint "min latency" "$min"
    require_uint "mean latency" "$mean"
    require_uint "p50 latency" "$p50"
    require_uint "p95 latency" "$p95"
    require_uint "p99 latency" "$p99"
    require_uint "max latency" "$max"
    [[ "$thrpt" =~ ^[0-9]+(\.[0-9]+)?$ ]] \
        || die "could not parse throughput from benchmark output (got '$thrpt'); raw output: $RESULT_LOG"

    if [[ "$msgs" -ne "$EXPECTED_MSGS" ]]; then
        warn "round $round measured $msgs samples (expected $EXPECTED_MSGS): some take() calls returned no data"
    fi

    R_MSGS+=("$msgs"); R_MIN+=("$min"); R_MEAN+=("$mean"); R_P50+=("$p50")
    R_P95+=("$p95"); R_P99+=("$p99"); R_MAX+=("$max"); R_THRPT+=("$thrpt")

    printf '  p50 %6s ns | min %6s ns | p99 %6s ns | max %8s ns | %s k msg/s\n' \
        "$p50" "$min" "$p99" "$max" "$thrpt"
done

################################################################################
# Aggregate
################################################################################

median_of() { # numbers on stdin, one per line
    sort -n | awk '{ a[NR] = $1 }
        END {
            if (NR == 0) { print "null"; exit }
            if (NR % 2 == 1) { print a[(NR + 1) / 2] }
            else { printf "%g\n", (a[NR / 2] + a[NR / 2 + 1]) / 2 }
        }'
}

P50_MEDIAN="$(printf '%s\n' "${R_P50[@]}" | median_of)"
P99_MEDIAN="$(printf '%s\n' "${R_P99[@]}" | median_of)"
MEAN_MEDIAN="$(printf '%s\n' "${R_MEAN[@]}" | median_of)"
THRPT_MEDIAN="$(printf '%s\n' "${R_THRPT[@]}" | median_of)"
MIN_BEST="$(printf '%s\n' "${R_MIN[@]}" | sort -n | head -1)"

echo ""
echo -e "${BOLD}--- Summary ($HDDS_BENCH_ROUNDS rounds x $EXPECTED_MSGS messages) ---${NC}"
printf '%-7s %10s %10s %10s %10s %12s %14s\n' \
    "round" "p50(ns)" "min(ns)" "p99(ns)" "mean(ns)" "max(ns)" "thrpt(k/s)"
for ((i = 0; i < HDDS_BENCH_ROUNDS; i++)); do
    printf '%-7s %10s %10s %10s %10s %12s %14s\n' \
        "$((i + 1))" "${R_P50[$i]}" "${R_MIN[$i]}" "${R_P99[$i]}" \
        "${R_MEAN[$i]}" "${R_MAX[$i]}" "${R_THRPT[$i]}"
done
echo ""
echo -e "${GREEN}${BOLD}Median-of-rounds p50:  ${P50_MEDIAN} ns${NC}"
echo -e "Median-of-rounds p99:  ${P99_MEDIAN} ns"
echo -e "Median-of-rounds mean: ${MEAN_MEDIAN} ns"
echo -e "Best min across rounds: ${MIN_BEST} ns"
echo -e "Median throughput:     ${THRPT_MEDIAN} k msg/s"

################################################################################
# JSON output
################################################################################

json_escape() { # minimal escaping for the strings we stamp
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\r\n'
}

{
    printf '{\n'
    printf '  "schema": "hdds-bench-repro/1",\n'
    printf '  "benchmark": {\n'
    printf '    "name": "%s",\n' "$(json_escape "$HDDS_BENCH_EXAMPLE")"
    printf '    "kind": "intra-process end-to-end roundtrip latency, single thread",\n'
    printf '    "definition": "wall-clock stamp taken before writer.write(); latency = now - stamp after reader.take() returns, same thread, best-effort KeepLast(1)",\n'
    printf '    "source": "crates/hdds/examples/%s.rs",\n' "$(json_escape "$HDDS_BENCH_EXAMPLE")"
    printf '    "message_bytes": 16,\n'
    printf '    "messages_per_round": %s,\n' "$EXPECTED_MSGS"
    printf '    "warmup_messages": %s,\n' "$EXPECTED_WARMUP"
    printf '    "rounds": %s\n' "$HDDS_BENCH_ROUNDS"
    printf '  },\n'
    printf '  "environment": {\n'
    printf '    "date_utc": "%s",\n' "$(json_escape "$DATE_UTC")"
    printf '    "host": "%s",\n' "$(json_escape "$HOST")"
    printf '    "cpu_model": "%s",\n' "$(json_escape "$CPU_MODEL")"
    printf '    "cpu_cores": %s,\n' "${NUM_CORES:-0}"
    printf '    "pinned_core": %s,\n' "$HDDS_BENCH_CORE"
    printf '    "core_pinned": %s,\n' "$([[ "$TASKSET_AVAILABLE" -eq 1 ]] && echo true || echo false)"
    printf '    "scaling_governor": "%s",\n' "$(json_escape "$GOVERNOR")"
    printf '    "governor_is_performance": %s,\n' "$([[ "$GOVERNOR" == "performance" ]] && echo true || echo false)"
    printf '    "kernel": "%s",\n' "$(json_escape "$KERNEL")"
    printf '    "rustc": "%s",\n' "$(json_escape "$RUSTC_VERSION")"
    printf '    "cargo": "%s"\n' "$(json_escape "$CARGO_VERSION")"
    printf '  },\n'
    printf '  "build": {\n'
    printf '    "hdds_version": "%s",\n' "$(json_escape "$HDDS_VERSION")"
    printf '    "git_sha": "%s",\n' "$(json_escape "$GIT_SHA")"
    printf '    "git_dirty": %s,\n' "$GIT_DIRTY"
    printf '    "cargo_profile": "release",\n'
    printf '    "lto": "thin",\n'
    printf '    "codegen_units": 1,\n'
    printf '    "locked": true,\n'
    printf '    "rustflags": "%s",\n' "$(json_escape "$RUSTFLAGS")"
    printf '    "invocation": "CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 RUSTFLAGS='"'"'%s'"'"' %s"\n' \
        "$(json_escape "$RUSTFLAGS")" "$(json_escape "${CARGO_CMD[*]}")"
    printf '  },\n'
    printf '  "rounds": [\n'
    for ((i = 0; i < HDDS_BENCH_ROUNDS; i++)); do
        printf '    {"round": %s, "messages": %s, "min_ns": %s, "mean_ns": %s, "p50_ns": %s, "p95_ns": %s, "p99_ns": %s, "max_ns": %s, "throughput_kmsg_per_s": %s}%s\n' \
            "$((i + 1))" "${R_MSGS[$i]}" "${R_MIN[$i]}" "${R_MEAN[$i]}" "${R_P50[$i]}" \
            "${R_P95[$i]}" "${R_P99[$i]}" "${R_MAX[$i]}" "${R_THRPT[$i]}" \
            "$([[ $((i + 1)) -lt $HDDS_BENCH_ROUNDS ]] && echo ',')"
    done
    printf '  ],\n'
    printf '  "summary": {\n'
    printf '    "p50_ns_median_of_rounds": %s,\n' "$P50_MEDIAN"
    printf '    "p99_ns_median_of_rounds": %s,\n' "$P99_MEDIAN"
    printf '    "mean_ns_median_of_rounds": %s,\n' "$MEAN_MEDIAN"
    printf '    "min_ns_best_of_rounds": %s,\n' "$MIN_BEST"
    printf '    "throughput_kmsg_per_s_median_of_rounds": %s\n' "$THRPT_MEDIAN"
    printf '  }\n'
    printf '}\n'
} > "$RESULT_JSON"

# Self-check the JSON if a validator is available (harness bug guard).
if command -v jq >/dev/null 2>&1; then
    jq empty "$RESULT_JSON" || die "generated JSON failed validation: $RESULT_JSON"
elif command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "$RESULT_JSON" >/dev/null || die "generated JSON failed validation: $RESULT_JSON"
fi

echo ""
info "Machine-readable results: $RESULT_JSON"
info "Raw benchmark output:     $RESULT_LOG"

governor_warning

exit 0
