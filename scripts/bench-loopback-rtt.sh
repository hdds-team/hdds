#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# HDDS same-device loopback round-trip latency, reproducible harness
# ==================================================================
# Companion to scripts/bench-repro.sh, which covers the INTRA-PROCESS path
# (one process, writer and reader in the same thread). This script covers a
# different regime: two processes on ONE machine exchanging over the loopback
# interface, measured as a round trip.
#
# What it measures: wall-clock round-trip time of a ping/pong exchange between
# two hdds-latency-probe processes on the same host, over the loopback
# interface, with RELIABLE QoS and a 64-byte payload. Per sample the ping side
# timestamps the write, the pong side echoes the sample back, and the ping side
# records the delta when the echo is taken. So the number covers two full DDS
# writes, two takes, two UDP traversals of the kernel loopback path, and the
# scheduling delay of waking the other process.
#
# What it does NOT measure: one-way latency (halving a round trip is not a
# one-way measurement), a real network, cross-machine traffic, or the
# intra-process path (use scripts/bench-repro.sh for that one).
#
# Hardware dependence: the result belongs to the machine it ran on. Running
# this harness on a different host does not reproduce another host's published
# figure; it produces this host's figure under the same regime. Every published
# figure from this harness names its hardware for that reason.
#
# Usage:
#   ./scripts/bench-loopback-rtt.sh
#   HDDS_RTT_RUNS=8 HDDS_RTT_SAMPLES=2000 ./scripts/bench-loopback-rtt.sh
#
# Environment overrides:
#   HDDS_RTT_RUNS       Number of runs, one pong process per run (default: 4)
#   HDDS_RTT_SAMPLES    Samples measured per run (default: 2000)
#   HDDS_RTT_SIZE       Payload size in bytes (default: 64)
#   HDDS_RTT_WARMUP     Warmup samples per run, not measured (default: 100)
#   HDDS_RTT_INTERVAL   Microseconds between pings (default: 1000)
#   HDDS_RTT_DOMAIN     DDS domain id (default: 39)
#   HDDS_RTT_OUT_DIR    Result directory (default: <repo>/target/bench-loopback)
#   HDDS_RTT_PROBE      Use an existing probe binary instead of building one
#   CARGO_TARGET_DIR    Respected as usual by cargo.
#
# Cross-compiling for an embedded target: build the probe for the target,
# copy it over, and run this script there with HDDS_RTT_PROBE pointing at it:
#   cargo build --release --locked -p hdds-latency-probe \
#       --target aarch64-unknown-linux-gnu
# A statically linked musl build of the probe has been measured slower than
# the glibc build on the same hardware, which is the cost of that libc and not
# a property of HDDS: state which build any published figure came from.
#
# Dependencies: bash, cargo/rustc (unless HDDS_RTT_PROBE is given), coreutils,
# awk. Optional: python3 (nicer percentile handling), git (stamp only).

set -u
set -o pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd -- "$SCRIPT_DIR/.." && pwd)

RUNS=${HDDS_RTT_RUNS:-4}
SAMPLES=${HDDS_RTT_SAMPLES:-2000}
SIZE=${HDDS_RTT_SIZE:-64}
WARMUP=${HDDS_RTT_WARMUP:-100}
INTERVAL=${HDDS_RTT_INTERVAL:-1000}
DOMAIN=${HDDS_RTT_DOMAIN:-39}
OUT_DIR=${HDDS_RTT_OUT_DIR:-$REPO/target/bench-loopback}

PONG_PID=""

# The pong process is killed BY PID, never by name. The kernel truncates a
# process name to 15 characters, so `hdds-latency-probe` appears as
# `hdds-latency-pr` and a name-based kill silently matches nothing: a leftover
# responder then keeps burning a core and every later run of a series reads
# slower than the one before it. A measurement that drifts run after run is
# measuring the harness, so the cleanup here is exact and verified.
cleanup_pong() {
    [ -n "$PONG_PID" ] || return 0
    kill -TERM "$PONG_PID" 2>/dev/null
    # A killed child becomes a zombie until it is reaped, and /proc/<pid> still
    # exists while it is one: testing for that directory would wait for nothing.
    # Read the real state instead, cutting past the comm field (which is
    # parenthesised and can contain spaces), and escalate past a deadline.
    local deadline=$((SECONDS + 10)) state=
    while :; do
        state=$(sed 's/.*) //' "/proc/$PONG_PID/stat" 2>/dev/null | cut -d' ' -f1)
        [ -z "$state" ] && break
        [ "$state" = "Z" ] && break
        [ "$SECONDS" -ge "$deadline" ] && kill -KILL "$PONG_PID" 2>/dev/null
        sleep 0.2
    done
    wait "$PONG_PID" 2>/dev/null
    PONG_PID=""
    return 0
}

trap 'cleanup_pong; exit 130' INT TERM
trap 'cleanup_pong' EXIT

# --- the probe binary -------------------------------------------------------
if [ -n "${HDDS_RTT_PROBE:-}" ]; then
    PROBE=$HDDS_RTT_PROBE
    if [ ! -x "$PROBE" ]; then
        echo "HDDS_RTT_PROBE is not an executable file: $PROBE" >&2
        exit 2
    fi
    BUILD_NOTE="supplied via HDDS_RTT_PROBE (not built by this script)"
else
    command -v cargo >/dev/null 2>&1 || { echo "cargo not found and HDDS_RTT_PROBE not set" >&2; exit 2; }
    echo ">>> Building hdds-latency-probe (release, --locked)"
    # No profile overrides here on purpose: this harness must build the probe
    # the way a user building the released tree gets it. bench-repro.sh pins
    # LTO and codegen-units because it measures nanoseconds; this regime is
    # dominated by two kernel traversals and a process wake-up, so the honest
    # default is the stock release profile, recorded in the stamp.
    ( cd "$REPO" && cargo build --release --locked -p hdds-latency-probe ) || exit 1
    PROBE=${CARGO_TARGET_DIR:-$REPO/target}/release/hdds-latency-probe
    BUILD_NOTE="cargo build --release --locked -p hdds-latency-probe (stock release profile)"
    if [ ! -x "$PROBE" ]; then
        echo "build reported success but $PROBE is missing" >&2
        exit 1
    fi
fi

mkdir -p "$OUT_DIR" || exit 1

# --- stamp ------------------------------------------------------------------
STAMP=$OUT_DIR/stamp.txt
{
    echo "harness: bench-loopback-rtt.sh"
    echo "regime: same-device loopback round trip, two processes, RELIABLE QoS"
    echo "probe: $PROBE"
    echo "build: $BUILD_NOTE"
    echo "runs: $RUNS"
    echo "samples_per_run: $SAMPLES"
    echo "payload_bytes: $SIZE"
    echo "warmup_samples: $WARMUP"
    echo "ping_interval_us: $INTERVAL"
    echo "domain: $DOMAIN"
    echo "interface: lo (HDDS_INTERFACE=lo)"
    echo "kernel: $(uname -sr)"
    echo "arch: $(uname -m)"
    echo "cores: $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
    if [ -r /proc/meminfo ]; then
        echo "mem_total_kb: $(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
    fi
    if command -v ldd >/dev/null 2>&1; then
        echo "libc: $(ldd --version 2>&1 | head -1)"
    fi
    if command -v git >/dev/null 2>&1 && git -C "$REPO" rev-parse --git-dir >/dev/null 2>&1; then
        echo "git_head: $(git -C "$REPO" rev-parse --short=9 HEAD)"
        echo "git_dirty: $([ -n "$(git -C "$REPO" status --porcelain)" ] && echo yes || echo no)"
    fi
    echo "load_before: $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown)"
    echo "started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "$STAMP"

echo
echo "=== HDDS loopback round-trip latency ==="
sed 's/^/  /' "$STAMP"
echo

# --- the series -------------------------------------------------------------
RESULTS=$OUT_DIR/runs.tsv
printf 'run\tmin_us\tmean_us\tp50_us\tp90_us\tp99_us\tlost\tsamples\n' > "$RESULTS"

run=1
while [ "$run" -le "$RUNS" ]; do
    echo ">>> run $run/$RUNS"
    HDDS_INTERFACE=lo "$PROBE" --domain "$DOMAIN" --qos reliable pong --quiet \
        > "$OUT_DIR/pong-$run.log" 2>&1 &
    PONG_PID=$!

    # Give the responder time to join the domain. The ping side waits for a
    # responder on its own, so this is a floor, not a timeout.
    sleep 2
    if [ ! -d "/proc/$PONG_PID" ]; then
        echo "ERROR: responder exited immediately; see $OUT_DIR/pong-$run.log" >&2
        PONG_PID=""
        exit 1
    fi

    JSON=$OUT_DIR/run-$run.json
    if ! HDDS_INTERFACE=lo "$PROBE" --domain "$DOMAIN" --qos reliable ping \
            -s "$SIZE" -n "$SAMPLES" -w "$WARMUP" -i "$INTERVAL" --json \
            > "$JSON" 2> "$OUT_DIR/ping-$run.log"; then
        echo "ERROR: ping run $run failed; see $OUT_DIR/ping-$run.log" >&2
        cleanup_pong
        exit 1
    fi

    cleanup_pong || exit 1

    # One line per run, parsed from the probe's own JSON.
    awk -v run="$run" '
        {
            min = extract($0, "\"min\":");  mean = extract($0, "\"mean\":")
            p50 = extract($0, "\"p50\":");  p90  = extract($0, "\"p90\":")
            p99 = extract($0, "\"p99\":")
            lost = extract($0, "\"lost\":"); samples = extract($0, "\"samples\":")
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", run, min, mean, p50, p90, p99, lost, samples
        }
        function extract(s, key,   p, rest, v) {
            p = index(s, key)
            if (p == 0) return "NA"
            rest = substr(s, p + length(key))
            if (match(rest, /^-?[0-9]+(\.[0-9]+)?/) == 0) return "NA"
            return substr(rest, RSTART, RLENGTH)
        }
    ' "$JSON" >> "$RESULTS"

    tail -1 "$RESULTS" | awk -F'\t' '{printf "    min %s  mean %s  p50 %s  lost %s of %s\n", $2, $3, $4, $7, $8}'

    # Let the machine settle before the next run: a run started on the tail of
    # the previous one reads the previous one's heat.
    if [ "$run" -lt "$RUNS" ]; then sleep 3; fi
    run=$((run + 1))
done

echo "load_after: $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown)" >> "$STAMP"
echo "finished: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$STAMP"

# --- verdict ----------------------------------------------------------------
echo
echo "=== results ($RESULTS) ==="
column -t -s $'\t' "$RESULTS" 2>/dev/null || cat "$RESULTS"
echo

awk -F'\t' -v size="$SIZE" -v samples="$SAMPLES" '
    NR > 1 {
        n++; p[n] = $4 + 0; lost += $7; total += $8
        if (min_p50 == "" || p[n] < min_p50) min_p50 = p[n]
        if (max_p50 == "" || p[n] > max_p50) max_p50 = p[n]
    }
    END {
        if (n == 0) { print "no run produced a figure"; exit 1 }
        for (i = 1; i <= n; i++)
            for (j = i + 1; j <= n; j++)
                if (p[j] < p[i]) { t = p[i]; p[i] = p[j]; p[j] = t }
        median = (n % 2) ? p[(n + 1) / 2] : (p[n / 2] + p[n / 2 + 1]) / 2
        # The denominator of a spread has to be stated or the same series reads
        # as two different numbers: this one divides by the median.
        spread = (median > 0) ? (max_p50 - min_p50) / median * 100 : 0
        printf "  p50 median over %d runs : %.2f us  (published form: %d us)\n", n, median, int(median + 0.5)
        printf "  p50 spread             : %.2f to %.2f us (%.1f %% of the median)\n", min_p50, max_p50, spread
        printf "  lost                   : %d of %d samples\n", lost, total
        print ""
        print "  A published figure is the median ROUNDED to the microsecond, so a"
        print "  reproduction that prints 367.50 here matches a published 368 us."
        print "  Publish this as: <median> us p50, same-device loopback, RELIABLE,"
        printf "  %s-byte payload, %s samples per run, median of %d runs, %d of %d lost,\n", size, samples, n, lost, total
        print "  naming the hardware it ran on. A figure without its regime is not a figure."
        if (lost > 0)
            print "  WARNING: samples were lost; a RELIABLE run that loses samples needs explaining before publication."
    }
' "$RESULTS"
