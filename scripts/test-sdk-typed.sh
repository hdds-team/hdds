#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

################################################################################
# HDDS TYPED CROSS-LANGUAGE TEST SUITE
#
# Full pipeline test: IDL -> hdds_gen -> types -> CDR2 -> HDDS pub/sub
#
# Tests 4 languages (Python, Rust, C, C++) in same-language and cross-language
# combinations. Validates that generated CDR2 serialization is interoperable
# across all backends.
#
# Usage:
#   HDDSGEN=/path/to/hddsgen ./scripts/test-sdk-typed.sh
#
# Environment:
#   HDDSGEN   Path to hddsgen binary (default: ../hdds_gen/target/release/hddsgen)
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
readonly LIB_PATH="$ROOT/target/release"
readonly IDL="$CROSS_DIR/interop_test.idl"

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

    # Locate hddsgen
    HDDSGEN="${HDDSGEN:-$ROOT/../hdds_gen/target/release/hddsgen}"
    if [ ! -x "$HDDSGEN" ]; then
        echo "ERROR: hddsgen not found at $HDDSGEN" >&2
        echo "  Set HDDSGEN=/path/to/hddsgen or build hdds_gen first." >&2
        exit 99
    fi
    log_info "hddsgen: $HDDSGEN"

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
    WORK="$ROOT/target/typed-test"
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
}

################################################################################
# Phase 2: Build
################################################################################

# Track which languages are available
RUST_BIN=""
C_BIN=""
CPP_BIN=""
PY_CMD=""

phase_build() {
    log_section "PHASE 2: BUILD"

    # --- Rust ---
    log_info "Building Rust typed test..."
    if cargo build --release --example typed_cross_lang_test \
        --manifest-path="$ROOT/Cargo.toml" --quiet 2>/dev/null; then
        RUST_BIN="$ROOT/target/release/examples/typed_cross_lang_test"
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
            -include "$CROSS_DIR/ros2_fwd.h" \
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
    esac
}

lang_available() {
    case "$1" in
        rust)   [ -n "$RUST_BIN" ] && [ -f "$RUST_BIN" ] ;;
        c)      [ -n "$C_BIN" ] && [ -f "$C_BIN" ] ;;
        cpp)    [ -n "$CPP_BIN" ] && [ -f "$CPP_BIN" ] ;;
        python) [ -n "$PY_CMD" ] ;;
    esac
}

lang_label() {
    case "$1" in
        rust)   echo "Rust" ;;
        c)      echo "C" ;;
        cpp)    echo "C++" ;;
        python) echo "Python" ;;
    esac
}

# Run a single typed pub/sub test pair
run_typed_test() {
    local pub_lang="$1" sub_lang="$2"
    local pub_label sub_label
    pub_label="$(lang_label "$pub_lang")"
    sub_label="$(lang_label "$sub_lang")"
    local test_name="${pub_label} pub -> ${sub_label} sub (typed)"

    if ! lang_available "$pub_lang"; then
        log_skip "$test_name (${pub_label} not available)"
        return
    fi
    if ! lang_available "$sub_lang"; then
        log_skip "$test_name (${sub_label} not available)"
        return
    fi

    local topic="${TOPIC_BASE}_${pub_lang}_${sub_lang}_$$"

    local pub_cmd sub_cmd
    pub_cmd="$(lang_cmd "$pub_lang" pub "$topic" "$NUM_SAMPLES")"
    sub_cmd="$(lang_cmd "$sub_lang" sub "$topic" "$NUM_SAMPLES")"

    local sub_log="$WORK/sub_${pub_lang}_${sub_lang}.log"
    local pub_log="$WORK/pub_${pub_lang}_${sub_lang}.log"

    # Start subscriber first
    LD_LIBRARY_PATH="$LIB_PATH" TYPED_TEST_TYPES="$WORK" \
        $sub_cmd > "$sub_log" 2>&1 &
    local sub_pid=$!

    # Give subscriber time for discovery
    sleep 1

    # Start publisher
    LD_LIBRARY_PATH="$LIB_PATH" TYPED_TEST_TYPES="$WORK" \
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
    if $pub_ok && $sub_ok && grep -q "^OK:" "$sub_log" 2>/dev/null; then
        log_pass "$test_name"
    else
        log_fail "$test_name"
        if ! $pub_ok; then
            echo "    Publisher failed:"
            head -5 "$pub_log" 2>/dev/null | sed 's/^/      /'
        fi
        if ! $sub_ok; then
            echo "    Subscriber failed or timed out:"
            head -5 "$sub_log" 2>/dev/null | sed 's/^/      /'
        fi
    fi

    rm -f "$sub_log" "$pub_log"
}

################################################################################
# Phase 3: Same-language typed pub/sub
################################################################################

phase_same_lang() {
    log_section "PHASE 3: SAME-LANGUAGE TYPED PUB/SUB"

    local LANGS=(rust python cpp c)
    for lang in "${LANGS[@]}"; do
        run_typed_test "$lang" "$lang"
    done
}

################################################################################
# Phase 4: Cross-language matrix
################################################################################

phase_cross_lang() {
    log_section "PHASE 4: CROSS-LANGUAGE TYPED PUB/SUB"

    local LANGS=(rust python cpp c)
    for pub_lang in "${LANGS[@]}"; do
        for sub_lang in "${LANGS[@]}"; do
            if [ "$pub_lang" != "$sub_lang" ]; then
                run_typed_test "$pub_lang" "$sub_lang"
            fi
        done
    done
}

################################################################################
# Phase 5: Summary
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
    phase_same_lang
    phase_cross_lang
    phase_summary
    exit "$FAIL"
}

main "$@"
