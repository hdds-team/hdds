#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Proves that the C samples in sdk/samples compile without a warning against
# the current hdds-c library and the current generated sample headers, so a
# sample can never silently rot again.
#
# Steps:
#   1. Build libhdds_c.a (cargo build --release -p hdds-c).
#   2. Regenerate the sample headers from the IDLs (sdk/samples/scripts/generate.sh).
#   3. make -k -C sdk/samples c with CC="gcc -Werror": any warning fails its sample.
#   4. Count the C sample binaries built. The expectation is derived from the
#      C sample sources, with the Makefile's selection (*/c/*.c minus 03_types
#      and 11_embedded).
#   5. Smoke test: one hello_world publisher and subscriber on domain 210 with
#      HDDS_INTERFACE=lo, each bounded by timeout. The subscriber must receive
#      all 10 messages. Skipped when CS_SKIP_RUN=1.
#
# Environment:
#   HDDSGEN           hddsgen to use. Default: <HDDS_GEN_DIR>/target/release/hddsgen
#                     when it exists, else hddsgen from PATH.
#   HDDS_GEN_DIR      hdds_gen checkout. Default: <repo>/../hdds_gen (sibling checkout).
#   CARGO_TARGET_DIR  cargo output directory (a relative value is taken from the
#                     repo root). Default: <repo>/target.
#   CS_SKIP_RUN=1     skip step 5.
#
# Exit codes:
#   0  every step passed
#   1  step 1 failed (hdds-c library build)
#   2  step 2 failed (sample header generation)
#   3  step 3 failed (a C sample does not compile, or emits a warning)
#   4  step 4 failed (fewer C sample binaries than expected)
#   5  step 5 failed (pub/sub smoke test)
#   6  missing prerequisite (cargo, gcc, make, hddsgen)
#
# Usage: scripts/check-c-samples.sh   (from anywhere in the repo)
#
# Cargo runs here without a lock: a caller that shares the machine can wrap
# the whole script in its own lock (for example flock).

# No -e: every step checks its own status and maps it to an exit code.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd) || exit 6
SAMPLES="$ROOT/sdk/samples"
DOMAIN=210
WORK=$(mktemp -d "${TMPDIR:-/tmp}/check-c-samples.XXXXXX") || exit 6
trap 'rm -rf "$WORK"' EXIT

step() {
    printf '\n=== %s ===\n' "$*"
}

fail() {
    local code=$1
    shift
    printf 'check-c-samples: FAIL (exit %d): %s\n' "$code" "$*" >&2
    exit "$code"
}

# -- prerequisites ------------------------------------------------------------
for tool in cargo gcc make; do
    command -v "$tool" >/dev/null 2>&1 || fail 6 "$tool not found on PATH"
done

HDDS_GEN_DIR="${HDDS_GEN_DIR:-$ROOT/../hdds_gen}"
if [ -z "${HDDSGEN:-}" ]; then
    if [ -x "$HDDS_GEN_DIR/target/release/hddsgen" ]; then
        HDDSGEN="$HDDS_GEN_DIR/target/release/hddsgen"
    else
        HDDSGEN=$(command -v hddsgen 2>/dev/null) ||
            fail 6 "no hddsgen: set HDDSGEN, build the hdds_gen checkout (HDDS_GEN_DIR=$HDDS_GEN_DIR), or put hddsgen on PATH"
    fi
fi
[ -x "$HDDSGEN" ] || fail 6 "HDDSGEN=$HDDSGEN is not executable"
export HDDSGEN

# Absolute cargo target dir, shared by cargo (step 1) and make (step 3).
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
case "$TARGET_DIR" in
    /*) ;;
    *) TARGET_DIR="$ROOT/$TARGET_DIR" ;;
esac
export CARGO_TARGET_DIR="$TARGET_DIR"
LIB="$TARGET_DIR/release/libhdds_c.a"

echo "repo:        $ROOT"
echo "hddsgen:     $HDDSGEN"
echo "target dir:  $TARGET_DIR"

# -- 1. hdds-c library --------------------------------------------------------
step "1/5 build hdds-c ($LIB)"
cd "$ROOT" || fail 1 "cannot enter $ROOT"
cargo build --release -p hdds-c || fail 1 "cargo build --release -p hdds-c failed"
[ -f "$LIB" ] || fail 1 "$LIB missing after the build"
echo "library ok"

# -- 2. sample headers from the IDLs ------------------------------------------
step "2/5 generate sample headers from IDL"
bash "$SAMPLES/scripts/generate.sh" || fail 2 "sdk/samples/scripts/generate.sh failed"

# -- 3. compile every C sample with -Werror -----------------------------------
step "3/5 compile C samples (make -k -C sdk/samples c, CC=gcc -Werror)"
# Remove stale binaries first: a sample that no longer builds must not be
# counted from an old run.
rm -rf "$SAMPLES/build"
make -k -C "$SAMPLES" c CC="gcc -Werror" 2>&1 | tee "$WORK/make.log"
make_rc=${PIPESTATUS[0]}
if [ "$make_rc" -ne 0 ]; then
    echo "--- compiler diagnostics ---" >&2
    grep -E 'error|warning' "$WORK/make.log" | head -60 >&2
    fail 3 "make exited $make_rc: a C sample fails to compile or emits a warning (-Werror)"
fi
echo "all C samples compiled with no warning"

# -- 4. count the binaries ----------------------------------------------------
step "4/5 count C sample binaries"
expected=()
for src in "$SAMPLES"/*/c/*.c; do
    [ -f "$src" ] || continue
    rel=${src#"$SAMPLES"/}
    case "$rel" in
        03_types/*|11_embedded/*) continue ;;
    esac
    expected+=("${rel%.c}")
done
n_expected=${#expected[@]}
[ "$n_expected" -gt 0 ] || fail 4 "no C sample sources found under $SAMPLES"

n_built=0
for rel in "${expected[@]}"; do
    if [ -x "$SAMPLES/build/$rel" ]; then
        n_built=$((n_built + 1))
    else
        echo "  not built: build/$rel" >&2
    fi
done
echo "C sample binaries built: $n_built of $n_expected expected"
[ "$n_built" -ge "$n_expected" ] ||
    fail 4 "$((n_expected - n_built)) C sample binary(ies) missing ($n_built of $n_expected built)"

# -- 5. hello_world pub/sub smoke test ----------------------------------------
if [ "${CS_SKIP_RUN:-0}" = 1 ]; then
    step "5/5 pub/sub smoke test skipped (CS_SKIP_RUN=1)"
else
    step "5/5 hello_world pub/sub on domain $DOMAIN (HDDS_INTERFACE=lo)"
    HW="$SAMPLES/build/01_basics/c/hello_world"
    # Subscriber first; the publisher waits for it to match (up to 30 s).
    HDDS_DOMAIN_ID=$DOMAIN HDDS_INTERFACE=lo timeout 60 "$HW" >"$WORK/sub.log" 2>&1 &
    sub_pid=$!
    HDDS_DOMAIN_ID=$DOMAIN HDDS_INTERFACE=lo timeout 60 "$HW" pub >"$WORK/pub.log" 2>&1 &
    pub_pid=$!
    wait "$pub_pid"
    pub_rc=$?
    wait "$sub_pid"
    sub_rc=$?

    cat "$WORK/pub.log"
    echo "--- subscriber ---"
    cat "$WORK/sub.log"
    if [ "$pub_rc" -ne 0 ] || [ "$sub_rc" -ne 0 ]; then
        fail 5 "pub/sub exited with publisher=$pub_rc subscriber=$sub_rc"
    fi
    grep -q 'Received 10 of 10 messages' "$WORK/sub.log" ||
        fail 5 "subscriber did not receive all 10 samples"
    echo "subscriber received 10 of 10 samples"
fi

echo ""
echo "check-c-samples: PASS ($n_built C sample binaries built, $n_expected expected)"
exit 0
