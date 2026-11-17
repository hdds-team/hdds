#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

################################################################################
# HDDS TYPED CROSS-LANGUAGE TEST SUITE
#
# Full pipeline test: IDL -> hdds_gen -> types -> CDR2 -> HDDS pub/sub
#
# Tests 5 languages (Python, Rust, C, C++, TypeScript) in same-language and
# cross-language combinations. Validates that generated CDR2 serialization is
# interoperable across all backends, and that every SDK writer labels its
# samples with the type's extensibility (phase 7, which also builds a
# test-support hdds-c under $CARGO_TARGET_DIR/wire-capture).
#
# Usage:
#   HDDSGEN=/path/to/hddsgen ./scripts/test-sdk-typed.sh
#
# Environment:
#   HDDSGEN   Path to hddsgen binary. When unset: hddsgen on PATH, then
#             ../hdds_gen/target/release/hddsgen (sibling checkout).
#             The resolved binary's version is printed into the log so the
#             evidence says which generator produced the vectors.
#
# Exit codes:
#   0   = All tests passed
#   1+  = Number of test failures
################################################################################

set -euo pipefail

# Terminal colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly CROSS_DIR="$SCRIPT_DIR/cross-lang"
readonly SDK_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
readonly LIB_PATH="$SDK_TARGET_DIR/release"
readonly IDL="$CROSS_DIR/interop_test.idl"
export CARGO_TARGET_DIR="$SDK_TARGET_DIR"

# Test config
readonly NUM_SAMPLES=3
readonly TOPIC_BASE="TypedTest"
readonly SUB_TIMEOUT=15

# Counters
PASS=0
FAIL=0
SKIP=0

# Logging
log_pass() { echo -e "[${GREEN}PASS${NC}] $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "[${RED}FAIL${NC}] $1"; FAIL=$((FAIL + 1)); }
log_skip() { echo -e "[${YELLOW}SKIP${NC}] $1"; SKIP=$((SKIP + 1)); }
log_info() { echo -e "[${CYAN}INFO${NC}] $1"; }
log_section() { echo -e "\n${BOLD}=== $1 ===${NC}"; }

################################################################################
# Phase 0: Prerequisites
################################################################################

phase_prereqs() {
    log_section "PHASE 0: PREREQUISITES"

    # Locate hddsgen: HDDSGEN (explicit) > hddsgen on PATH > sibling checkout
    if [ -z "${HDDSGEN:-}" ]; then
        HDDSGEN="$(command -v hddsgen 2>/dev/null || true)"
    fi
    if [ -z "${HDDSGEN:-}" ]; then
        HDDSGEN="$ROOT/../hdds_gen/target/release/hddsgen"
    fi
    if [ ! -x "$HDDSGEN" ]; then
        echo "ERROR: hddsgen not found at $HDDSGEN" >&2
        echo "  Tried: HDDSGEN, hddsgen on PATH, $ROOT/../hdds_gen/target/release/hddsgen" >&2
        echo "  Set HDDSGEN=/path/to/hddsgen or build hdds_gen first." >&2
        exit 99
    fi
    export HDDSGEN
    log_info "hddsgen: $HDDSGEN ($("$HDDSGEN" --version 2>/dev/null || echo 'version unknown'))"

    # Verify libhdds_c.so
    if [ ! -f "$LIB_PATH/libhdds_c.so" ]; then
        log_info "Building libhdds_c.so..."
        cargo build --release -p hdds-c --manifest-path="$ROOT/Cargo.toml" --quiet
    fi

    if [ ! -f "$LIB_PATH/libhdds_c.so" ]; then
        echo "ERROR: libhdds_c.so not found at $LIB_PATH" >&2
        exit 99
    fi
    log_info "libhdds_c: $LIB_PATH/libhdds_c.so"

    # Create work directory
    WORK="$SDK_TARGET_DIR/typed-test"
    mkdir -p "$WORK"
    log_info "Work dir: $WORK"
}

################################################################################
# Phase 1: Code generation
################################################################################

phase_codegen() {
    log_section "PHASE 1: CODE GENERATION"

    "$HDDSGEN" gen python "$IDL" -o "$WORK/interop_types.py"
    "$HDDSGEN" gen rust   "$IDL" -o "$WORK/interop_types.rs"
    "$HDDSGEN" gen c      "$IDL" -o "$WORK/interop_types.h"
    "$HDDSGEN" gen cpp    "$IDL" -o "$WORK/interop_types.hpp"
    log_pass "Code generation (Python, Rust, C, C++)"

    # The TypeScript backend is the newest one and is not present in every
    # hddsgen build. Guarded on its own so swapping HDDSGEN for a binary
    # without it reports one failure instead of killing every later phase;
    # $WORK/interop_types.ts then stays absent and the TypeScript lane
    # reports unavailable, which is what phase 2 is written to expect.
    if "$HDDSGEN" gen typescript "$IDL" -o "$WORK/interop_types.ts" 2>>"$WORK/codegen.err"; then
        log_pass "Code generation (TypeScript)"
    else
        rm -f "$WORK/interop_types.ts"
        log_fail "Code generation (TypeScript backend missing or failed in $HDDSGEN)"
        tail -5 "$WORK/codegen.err" 2>/dev/null | sed 's/^/      /' >&2 || true
    fi
}

################################################################################
# Phase 2: Build
################################################################################

# Track which languages are available
RUST_BIN=""
C_BIN=""
CPP_BIN=""
PY_CMD=""
TS_CMD=""

phase_build() {
    log_section "PHASE 2: BUILD"

    # --- Rust ---
    log_info "Building Rust typed test..."
    if cargo build --release --example typed_cross_lang_test \
        --features typed-test \
        --manifest-path="$ROOT/Cargo.toml" --quiet 2>/dev/null; then
        RUST_BIN="$SDK_TARGET_DIR/release/examples/typed_cross_lang_test"
        log_pass "Rust build"
    else
        log_fail "Rust build"
    fi

    # --- C ---
    CC=""
    for cc_candidate in clang gcc; do
        if command -v "$cc_candidate" > /dev/null 2>&1; then
            CC="$cc_candidate"
            break
        fi
    done

    if [ -n "$CC" ]; then
        log_info "Building C typed test with $CC..."
        C_BIN="$WORK/typed_test_c"
        if "$CC" -std=c11 -O2 -Wall -Wno-unused-function \
            -I"$ROOT/sdk/c/include" -I"$WORK" \
            "$CROSS_DIR/typed_test.c" \
            -o "$C_BIN" \
            -L"$LIB_PATH" -lhdds_c -lpthread -ldl -lm 2>"$WORK/c_build.err"; then
            log_pass "C build"
        else
            log_fail "C build"
            cat "$WORK/c_build.err" >&2
            C_BIN=""
        fi
    else
        log_skip "C build (no compiler)"
    fi

    # --- C++ ---
    CXX=""
    for cxx_candidate in clang++ g++; do
        if command -v "$cxx_candidate" > /dev/null 2>&1; then
            CXX="$cxx_candidate"
            break
        fi
    done

    if [ -n "$CXX" ]; then
        log_info "Building C++ typed test with $CXX..."
        CPP_BIN="$WORK/typed_test_cpp"
        if "$CXX" -std=c++17 -O2 -Wall -Wno-unused-function \
            -I"$ROOT/sdk/cxx/include" -I"$ROOT/sdk/c/include" -I"$WORK" \
            "$CROSS_DIR/typed_test.cpp" \
            "$ROOT"/sdk/cxx/src/*.cpp \
            -o "$CPP_BIN" \
            -L"$LIB_PATH" -lhdds_c -lpthread -ldl -lm 2>"$WORK/cpp_build.err"; then
            log_pass "C++ build"
        else
            log_fail "C++ build"
            cat "$WORK/cpp_build.err" >&2
            CPP_BIN=""
        fi
    else
        log_skip "C++ build (no compiler)"
    fi

    # --- Python ---
    if command -v python3 > /dev/null 2>&1; then
        PY_CMD="python3 $CROSS_DIR/typed_test.py"
        log_pass "Python (no build needed)"
    else
        log_skip "Python (python3 not found)"
    fi

    # --- TypeScript ---
    build_typescript_typed
}

# Compile the generated TypeScript module together with the driver into
# $WORK/ts. "@hdds/client" resolves through a node_modules/@hdds/client
# symlink placed next to the emitted JS, so the driver reaches the SDK's own
# exports map without any path rewriting and nothing is written into the
# worktree except sdk/typescript/dist (gitignored, and the package needs it).
build_typescript_typed() {
    TS_CMD=""
    local ts_sdk="$ROOT/sdk/typescript"

    if ! command -v node > /dev/null 2>&1 || ! command -v npm > /dev/null 2>&1; then
        log_fail "TypeScript build (node/npm not found)"
        return
    fi

    log_info "Building TypeScript typed test (node $(node --version))..."
    local log="$WORK/ts_build.err"
    : > "$log"

    if [ ! -d "$ts_sdk/node_modules" ]; then
        if ! (cd "$ts_sdk" && npm ci --offline --no-audit --no-fund) >> "$log" 2>&1; then
            if ! (cd "$ts_sdk" && npm ci --no-audit --no-fund) >> "$log" 2>&1; then
                log_fail "TypeScript build (npm ci failed)"
                tail -5 "$log" >&2
                return
            fi
            log_info "npm dependency restore path: online"
        else
            log_info "npm dependency restore path: offline"
        fi
    fi
    if ! (cd "$ts_sdk" && npm run build) >> "$log" 2>&1; then
        log_fail "TypeScript build (tsc failed on the SDK)"
        tail -10 "$log" >&2
        return
    fi

    if [ ! -f "$WORK/interop_types.ts" ]; then
        log_fail "TypeScript build (phase 1 produced no interop_types.ts)"
        return
    fi

    rm -rf "$WORK/ts"
    mkdir -p "$WORK/ts/src" "$WORK/ts/node_modules/@hdds"
    ln -sfn "$ts_sdk" "$WORK/ts/node_modules/@hdds/client"
    cp "$WORK/interop_types.ts" "$WORK/ts/src/"
    cp "$CROSS_DIR/typed_test.ts" "$WORK/ts/src/"

    if (cd "$ts_sdk" && npx tsc --target ES2022 --module CommonJS \
            --moduleResolution Node --strict --esModuleInterop --skipLibCheck \
            --noEmitOnError --outDir "$WORK/ts" \
            "$WORK/ts/src/interop_types.ts" "$WORK/ts/src/typed_test.ts") >> "$log" 2>&1 \
        && [ -f "$WORK/ts/typed_test.js" ]; then
        TS_CMD="node $WORK/ts/typed_test.js"
        log_pass "TypeScript build"
    else
        log_fail "TypeScript build (tsc rejected the generated module or the driver)"
        echo "    The generated TypeScript must compile before it can be a" >&2
        echo "    byte-vector reference. tsc output:" >&2
        # `|| true`: a tsc failure with no "error TS####" line (npx missing,
        # OOM, a tsconfig error) must still leave phases 3-5 to run.
        { grep -E "error TS[0-9]+" "$log" | head -10 | sed 's/^/      /' >&2; } || true
    fi
}

################################################################################
# Pub/Sub test helpers
################################################################################

lang_cmd() {
    local lang="$1" mode="$2" topic="$3" count="$4"
    case "$lang" in
        rust)   echo "$RUST_BIN $mode $topic $count" ;;
        c)      echo "$C_BIN $mode $topic $count" ;;
        cpp)    echo "$CPP_BIN $mode $topic $count" ;;
        python) echo "$PY_CMD $mode $topic $count" ;;
        typescript) echo "$TS_CMD $mode $topic $count" ;;
    esac
}

lang_available() {
    case "$1" in
        rust)   [ -n "$RUST_BIN" ] && [ -f "$RUST_BIN" ] ;;
        c)      [ -n "$C_BIN" ] && [ -f "$C_BIN" ] ;;
        cpp)    [ -n "$CPP_BIN" ] && [ -f "$CPP_BIN" ] ;;
        python) [ -n "$PY_CMD" ] ;;
        typescript) [ -n "$TS_CMD" ] ;;
    esac
}

lang_label() {
    case "$1" in
        rust)   echo "Rust" ;;
        c)      echo "C" ;;
        cpp)    echo "C++" ;;
        python) echo "Python" ;;
        typescript) echo "TypeScript" ;;
    esac
}

# Run a single typed pub/sub test pair
run_typed_test() {
    local pub_lang="$1" sub_lang="$2"
    local topic_base="${3:-$TOPIC_BASE}"
    local pub_label sub_label
    pub_label="$(lang_label "$pub_lang")"
    sub_label="$(lang_label "$sub_lang")"
    local suffix="typed"
    if [ "$topic_base" = "KeyedTest" ]; then suffix="keyed"; fi
    run_pair "$pub_lang" pub "$sub_lang" sub \
        "${topic_base}_${pub_lang}_${sub_lang}_$$" \
        "${pub_label} pub -> ${sub_label} sub (${suffix})" "^OK:"
}

# Run one publisher mode against one subscriber mode on a fresh topic. The
# verdict is the publisher's exit status, the subscriber's, and a line of the
# subscriber's output matching `sub_pattern`.
run_pair() {
    local pub_lang="$1" pub_mode="$2" sub_lang="$3" sub_mode="$4"
    local topic="$5" test_name="$6" sub_pattern="$7"

    if ! lang_available "$pub_lang"; then
        log_skip "$test_name ($(lang_label "$pub_lang") not available)"
        return
    fi
    if ! lang_available "$sub_lang"; then
        log_skip "$test_name ($(lang_label "$sub_lang") not available)"
        return
    fi

    local pub_cmd sub_cmd
    pub_cmd="$(lang_cmd "$pub_lang" "$pub_mode" "$topic" "$NUM_SAMPLES")"
    sub_cmd="$(lang_cmd "$sub_lang" "$sub_mode" "$topic" "$NUM_SAMPLES")"

    local sub_log="$WORK/sub_${pub_lang}_${sub_lang}.log"
    local pub_log="$WORK/pub_${pub_lang}_${sub_lang}.log"

    # Start subscriber first. HDDS_LIB_PATH is how the Python and TypeScript
    # SDK loaders find the library; LD_LIBRARY_PATH is for the -lhdds_c binaries.
    LD_LIBRARY_PATH="$LIB_PATH" HDDS_LIB_PATH="$LIB_PATH" TYPED_TEST_TYPES="$WORK" \
        $sub_cmd > "$sub_log" 2>&1 &
    local sub_pid=$!

    # Give subscriber time for discovery
    sleep 1

    # Start publisher
    LD_LIBRARY_PATH="$LIB_PATH" HDDS_LIB_PATH="$LIB_PATH" TYPED_TEST_TYPES="$WORK" \
        $pub_cmd > "$pub_log" 2>&1 &
    local pub_pid=$!

    # Wait for publisher
    local pub_ok=true
    if ! wait "$pub_pid" 2>/dev/null; then
        pub_ok=false
    fi

    # Wait for subscriber (with timeout)
    local sub_ok=true
    local waited=0
    while kill -0 "$sub_pid" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if [ $waited -ge $SUB_TIMEOUT ]; then
            kill -9 "$sub_pid" 2>/dev/null || true
            wait "$sub_pid" 2>/dev/null || true
            sub_ok=false
            break
        fi
    done

    if $sub_ok; then
        if ! wait "$sub_pid" 2>/dev/null; then
            sub_ok=false
        fi
    fi

    # Verdict
    if $pub_ok && $sub_ok && grep -q "$sub_pattern" "$sub_log" 2>/dev/null; then
        log_pass "$test_name"
    else
        log_fail "$test_name"
        if ! $pub_ok; then
            echo "    Publisher failed:"
            head -5 "$pub_log" 2>/dev/null | sed 's/^/      /'
        fi
        if ! $sub_ok || ! grep -q "$sub_pattern" "$sub_log" 2>/dev/null; then
            echo "    Subscriber failed, timed out, or did not print '$sub_pattern':"
            head -5 "$sub_log" 2>/dev/null | sed 's/^/      /'
        fi
    fi

    rm -f "$sub_log" "$pub_log"
}

################################################################################
# Phase 3: Generated CDR2 byte-vector parity
################################################################################

phase_vectors() {
    log_section "PHASE 3: GENERATED CDR2 BYTE-VECTOR PARITY"

    local langs=(rust python cpp c typescript)

    # An unavailable language is ITS OWN skip line, never a reason to throw
    # away the comparison between the languages that ARE available: returning
    # on the first gap turned a real multi-language PASS into a single SKIP,
    # and the release certificate counts both.
    local avail=() lang
    for lang in "${langs[@]}"; do
        if lang_available "$lang"; then
            avail+=("$lang")
        else
            log_skip "Generated byte-vector parity ($(lang_label "$lang") unavailable)"
        fi
    done
    if [ "${#avail[@]}" -lt 2 ]; then
        log_skip "Generated byte-vector parity (fewer than two languages available)"
        return
    fi

    local reference=""
    local reference_lang=""
    local labels=""
    local cmd vector
    for lang in "${avail[@]}"; do
        cmd="$(lang_cmd "$lang" vector "KeyedVector" 1)"
        if ! vector=$(LD_LIBRARY_PATH="$LIB_PATH" HDDS_LIB_PATH="$LIB_PATH" TYPED_TEST_TYPES="$WORK" $cmd); then
            log_fail "Generated byte-vector parity ($(lang_label "$lang") encoder failed)"
            return
        fi
        if [ -z "$reference" ]; then
            reference="$vector"
            reference_lang="$lang"
        elif [ "$vector" != "$reference" ]; then
            log_fail "Generated byte-vector parity ($(lang_label "$lang") differs from $(lang_label "$reference_lang"))"
            return
        fi
        labels="${labels:+$labels, }$(lang_label "$lang")"
    done

    # The label lists exactly the languages that were compared, so no surface
    # can read a five-language parity claim off a four-language run.
    log_pass "Generated byte-vector parity ($labels)"
}

################################################################################
# Phase 4: Same-language typed pub/sub
################################################################################

phase_same_lang() {
    log_section "PHASE 4: SAME-LANGUAGE TYPED PUB/SUB"

    local LANGS=(rust python cpp c typescript)
    for lang in "${LANGS[@]}"; do
        run_typed_test "$lang" "$lang"
    done

    # Keyed types: same tests but with @key edge cases (bool, enum, typedef string)
    log_info "Running same-language tests with KeyedSample..."
    for lang in "${LANGS[@]}"; do
        run_typed_test "$lang" "$lang" "KeyedTest"
    done
}

################################################################################
# Phase 5: Cross-language matrix
################################################################################

phase_cross_lang() {
    log_section "PHASE 5: CROSS-LANGUAGE TYPED PUB/SUB"

    local LANGS=(rust python cpp c typescript)
    for pub_lang in "${LANGS[@]}"; do
        for sub_lang in "${LANGS[@]}"; do
            if [ "$pub_lang" != "$sub_lang" ]; then
                run_typed_test "$pub_lang" "$sub_lang"
            fi
        done
    done

    # Keyed types: cross-language with @key edge cases
    log_info "Running cross-language tests with KeyedSample..."
    for pub_lang in "${LANGS[@]}"; do
        for sub_lang in "${LANGS[@]}"; do
            if [ "$pub_lang" != "$sub_lang" ]; then
                run_typed_test "$pub_lang" "$sub_lang" "KeyedTest"
            fi
        done
    done
}

################################################################################
# Phase 6: Default DATA_REPRESENTATION, as applications create endpoints
################################################################################

# No header inside the payload, no DATA_REPRESENTATION set by hand. A default
# Rust writer of the generated type offers XCDR (DDS-XTypes 1.3 7.6.3.1.1)
# and encodes XCDR1; every SDK reader told its generated decoders (which
# read XCDR1 since hddsgen 2.0) requests XCDR and XCDR2 and must receive the
# right values. The reverse: an SDK writer offers XCDR2, labelled with the
# type's extensibility, and a default Rust reader decodes it. And a reader
# whose code reads XCDR2 only stays at XCDR2: refused at matching (policy
# 23), never handed XCDR1 bytes.
phase_default_representation() {
    log_section "PHASE 6: DEFAULT DATA_REPRESENTATION (XCDR1 writer, XCDR1-aware readers)"

    local lang label
    for lang in c cpp python typescript; do
        label="$(lang_label "$lang")"
        local pattern="^OK:"
        # The C reader prints the identifier it decoded by: XCDR1 (CDR_LE).
        if [ "$lang" = "c" ]; then pattern="^OK:.*encap=0x0001"; fi
        run_pair rust pub-default "$lang" sub-default "DefRep_rust_${lang}_$$" \
            "Rust default writer (XCDR1) -> ${label} default reader" "$pattern"
    done
    for lang in c cpp python typescript; do
        label="$(lang_label "$lang")"
        run_pair "$lang" pub-default rust sub-default "DefRep_${lang}_rust_$$" \
            "${label} default writer (XCDR2) -> Rust default reader" "^OK:"
    done
    run_pair rust pub-default c sub-legacy "DefRep_rust_legacy_$$" \
        "Rust default writer (XCDR1) -> C reader decoding XCDR2 only: incompatible" \
        "^OK: legacy reader received nothing"
}

################################################################################
# Phase 7: Writer extensibility, on the wire
################################################################################

# DDS-XTypes 1.3 7.6.3.1.2, Table 60: the encapsulation identifier of a
# sample names its type's extensibility. Every SDK writer is created the way
# an application creates it, told the type only (C <name>_extensibility(),
# C++ create_writer<T>, Python msg_type=T, TypeScript extensibility<Name>),
# for a FINAL (FinalProbe), an APPENDABLE (SensorReading) and a MUTABLE
# (MutableProbe) type. Wire lane: the writer runs against an hdds-c built
# with `test-support`, which sends its DATA to the Rust probe instead of its
# readers (HDDS_TEST_CAPTURE_DATA); the probe decodes the datagrams
# (test_support::wire), checks the identifier (0x0007, 0x0009, 0x000b) and
# decodes the body as the type. Reader lanes: a Rust typed reader and the
# same SDK's typed reader receive and decode the samples.

CAPTURE_LIB_PATH=""

build_capture_lib() {
    local dir="$SDK_TARGET_DIR/wire-capture"
    log_info "Building the test-support hdds-c (wire capture) into $dir..."
    if CARGO_TARGET_DIR="$dir" cargo build -p hdds-c --features test-support \
            --manifest-path="$ROOT/Cargo.toml" --quiet 2>"$WORK/capture_build.err" \
        && [ -f "$dir/debug/libhdds_c.so" ]; then
        CAPTURE_LIB_PATH="$dir/debug"
        log_pass "Wire-capture hdds-c build"
    else
        log_fail "Wire-capture hdds-c build"
        tail -10 "$WORK/capture_build.err" >&2 || true
    fi
}

# One SDK writer of one lane, its DATA captured and decoded by the probe.
run_wire_probe() {
    local lang="$1" lane="$2" want="$3"
    local label topic test_name
    label="$(lang_label "$lang")"
    topic="Ext${lane}_wire_${lang}_$$"
    test_name="${label} writer of the ${lane} type: DATA on the wire carries ${want}"
    if ! lang_available "$lang" || [ -z "$RUST_BIN" ] || [ -z "$CAPTURE_LIB_PATH" ]; then
        log_skip "$test_name (writer, probe or capture library not available)"
        return
    fi
    local probe_log="$WORK/probe_${lang}_${lane}.log" pub_log="$WORK/probe_pub_${lang}_${lane}.log"
    "$RUST_BIN" probe "$topic" 1 > "$probe_log" 2>&1 &
    local probe_pid=$!
    local port="" waited=0
    while [ -z "$port" ] && [ $waited -lt 50 ]; do
        port="$(sed -n 's/^PORT \([0-9][0-9]*\)$/\1/p' "$probe_log" 2>/dev/null | head -1)"
        [ -n "$port" ] || { sleep 0.1; waited=$((waited + 1)); }
    done
    if [ -z "$port" ]; then
        kill -9 "$probe_pid" 2>/dev/null || true
        wait "$probe_pid" 2>/dev/null || true
        log_fail "$test_name (the probe printed no port)"
        return
    fi
    local pub_ok=true probe_ok=true
    LD_LIBRARY_PATH="$CAPTURE_LIB_PATH" HDDS_LIB_PATH="$CAPTURE_LIB_PATH" \
        TYPED_TEST_TYPES="$WORK" HDDS_TEST_CAPTURE_DATA="127.0.0.1:$port" \
        $(lang_cmd "$lang" pub-ext "$topic" 1) > "$pub_log" 2>&1 || pub_ok=false
    wait "$probe_pid" 2>/dev/null || probe_ok=false
    if $pub_ok && $probe_ok && grep -q "^OK:.*encap=${want}" "$probe_log"; then
        log_pass "$test_name"
    else
        log_fail "$test_name"
        head -5 "$probe_log" | sed 's/^/      probe: /'
        head -5 "$pub_log" | sed 's/^/      writer: /'
    fi
    rm -f "$probe_log" "$pub_log"
}

phase_extensibility() {
    log_section "PHASE 7: WRITER EXTENSIBILITY (encapsulation identifier on the wire)"

    build_capture_lib
    local lang lane label
    for lang in c cpp python typescript; do
        run_wire_probe "$lang" Final 0x0007
        run_wire_probe "$lang" Appendable 0x0009
        run_wire_probe "$lang" Mutable 0x000b
    done
    for lang in c cpp python typescript; do
        label="$(lang_label "$lang")"
        for lane in Final Appendable Mutable; do
            run_pair "$lang" pub-ext rust sub-ext "Ext${lane}_${lang}_rust_$$" \
                "${label} writer of the ${lane} type -> Rust typed reader" "^OK:"
            run_pair "$lang" pub-ext "$lang" sub-ext "Ext${lane}_${lang}_${lang}_$$" \
                "${label} writer of the ${lane} type -> ${label} typed reader" "^OK:"
        done
    done
}

################################################################################
# Phase 8: Summary
################################################################################

phase_summary() {
    echo ""
    echo "========================================="
    echo "  Typed cross-language test summary"
    echo "========================================="
    echo -e "  ${GREEN}PASS${NC}: $PASS"
    echo -e "  ${RED}FAIL${NC}: $FAIL"
    echo -e "  ${YELLOW}SKIP${NC}: $SKIP"
    echo "========================================="
}

################################################################################
# Main
################################################################################

main() {
    phase_prereqs
    phase_codegen
    phase_build
    phase_vectors
    phase_same_lang
    phase_cross_lang
    phase_default_representation
    phase_extensibility
    phase_summary
    exit "$FAIL"
}

main "$@"
