#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

################################################################################
# HDDS SDK VERIFICATION GATE - Mechanical Cross-Language Test Suite
# Version: 2.0.0
#
# Runs automated verification for all SDK language bindings:
#   Layer 0: Build verification (compile all targets, hash binaries)
#   Layer 1: Python unit + integration tests (pytest)
#   Layer 2: Same-language pub/sub (Rust/Rust, C/C, C++/C++, Python/Python)
#   Layer 3: Cross-language pub/sub (all 12 combinations)
#
# This is a CI-quality gate. It produces machine-parseable reports
# and exits with the number of failures (0 = all green).
#
# Usage:
#   ./scripts/test-sdk.sh              # Full matrix (build + test)
#   ./scripts/test-sdk.sh --no-build   # Skip build, run tests only
#   ./scripts/test-sdk.sh --quick      # Same-language only (skip Layer 3)
#   ./scripts/test-sdk.sh --lang rust  # Only combos involving rust
#   ./scripts/test-sdk.sh --python     # Python unit + integration tests only
#   ./scripts/test-sdk.sh --report     # Write report to target/sdk-reports/
#
# Exit codes:
#   0   = All tests passed (gate OPEN)
#   1+  = Number of test failures (gate CLOSED)
################################################################################

set -euo pipefail

# Terminal colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly CROSS_DIR="$SCRIPT_DIR/cross-lang"
readonly LIB_PATH="$ROOT/target/release"
readonly REPORT_DIR="$ROOT/target/sdk-reports"

# Binaries
RUST_BIN="$ROOT/target/release/examples/cross_lang_test"
C_BIN="/tmp/hdds_xtest_c"
CPP_BIN="/tmp/hdds_xtest_cpp"
PY_CMD="python3 $CROSS_DIR/test.py"

# Test config
readonly NUM_SAMPLES=5
readonly TOPIC_BASE="XLangTest"
readonly SUB_TIMEOUT=15       # seconds before killing a stuck subscriber
readonly PUB_SETTLE_MS=1000   # ms for subscriber to start before publisher

# Counters
LAYER_PASS=0
LAYER_FAIL=0
LAYER_SKIP=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
TOTAL_TESTS=0
BUILD_FAILURES=0

# Report buffer
REPORT_LINES=()

# Options
DO_BUILD=true
QUICK=false
FILTER_LANG=""
PYTHON_ONLY=false
WRITE_REPORT=false

################################################################################
# Argument parsing
################################################################################

parse_args() {
    local i=1
    while [[ $i -le $# ]]; do
        local arg="${!i}"
        case "$arg" in
            --no-build)  DO_BUILD=false ;;
            --quick)     QUICK=true ;;
            --python)    PYTHON_ONLY=true ;;
            --report)    WRITE_REPORT=true ;;
            --lang)
                i=$((i + 1))
                if [[ $i -le $# ]]; then
                    FILTER_LANG="${!i}"
                else
                    echo "Error: --lang requires a value" >&2
                    exit 1
                fi
                ;;
            -h|--help)
                sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
                exit 0
                ;;
            *)
                echo "Unknown option: $arg" >&2
                exit 1
                ;;
        esac
        i=$((i + 1))
    done
}

################################################################################
# Logging (terminal + report buffer)
################################################################################

report() {
    REPORT_LINES+=("$*")
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    report "[PASS] $*"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    report "[FAIL] $*"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
    report "[SKIP] $*"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    report "[INFO] $*"
}

log_section() {
    echo ""
    echo -e "${BLUE}--------------------------------------------------------------${NC}"
    echo -e "${BLUE}${BOLD}> $*${NC}"
    echo -e "${BLUE}--------------------------------------------------------------${NC}"
    report ""
    report "--------------------------------------------------------------"
    report "> $*"
    report "--------------------------------------------------------------"
}

reset_layer_counters() {
    LAYER_PASS=0
    LAYER_FAIL=0
    LAYER_SKIP=0
}

layer_summary() {
    local layer_name="$1"
    local layer_total=$((LAYER_PASS + LAYER_FAIL + LAYER_SKIP))
    TOTAL_PASS=$((TOTAL_PASS + LAYER_PASS))
    TOTAL_FAIL=$((TOTAL_FAIL + LAYER_FAIL))
    TOTAL_SKIP=$((TOTAL_SKIP + LAYER_SKIP))
    TOTAL_TESTS=$((TOTAL_TESTS + LAYER_PASS + LAYER_FAIL))

    echo ""
    echo -e "  ${layer_name}: ${GREEN}${LAYER_PASS} passed${NC}, ${RED}${LAYER_FAIL} failed${NC}, ${YELLOW}${LAYER_SKIP} skipped${NC} (${layer_total} total)"
    report "  ${layer_name}: ${LAYER_PASS} passed, ${LAYER_FAIL} failed, ${LAYER_SKIP} skipped (${layer_total} total)"
}

################################################################################
# Environment fingerprint
################################################################################

print_environment() {
    log_section "ENVIRONMENT"

    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    log_info "Timestamp:  $timestamp"
    log_info "Hostname:   $(hostname)"
    log_info "Kernel:     $(uname -sr)"
    log_info "Arch:       $(uname -m)"

    # Compiler versions
    if command -v rustc &>/dev/null; then
        log_info "rustc:      $(rustc --version 2>/dev/null || echo 'n/a')"
    fi
    if command -v gcc &>/dev/null; then
        log_info "gcc:        $(gcc --version 2>/dev/null | head -1)"
    fi
    if command -v g++ &>/dev/null; then
        log_info "g++:        $(g++ --version 2>/dev/null | head -1)"
    fi
    if command -v python3 &>/dev/null; then
        log_info "python3:    $(python3 --version 2>/dev/null)"
    fi

    # Git state
    local git_hash
    git_hash="$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo 'n/a')"
    local git_dirty=""
    if [[ -n "$(cd "$ROOT" && git status --porcelain 2>/dev/null)" ]]; then
        git_dirty=" (dirty)"
    fi
    log_info "Git commit: ${git_hash}${git_dirty}"
    log_info "Branch:     $(cd "$ROOT" && git branch --show-current 2>/dev/null || echo 'n/a')"

    # Options
    log_info "Options:    build=$DO_BUILD quick=$QUICK filter='$FILTER_LANG' python_only=$PYTHON_ONLY"
}

################################################################################
# Binary hash verification
################################################################################

hash_binaries() {
    log_section "BINARY FINGERPRINTS"

    local lib="$LIB_PATH/libhdds_c.so"
    if [[ -f "$lib" ]]; then
        local hash size
        hash="$(sha256sum "$lib" | cut -d' ' -f1)"
        size="$(stat -c%s "$lib" 2>/dev/null || stat -f%z "$lib" 2>/dev/null || echo '?')"
        log_info "libhdds_c.so  sha256:${hash:0:16}...  size:${size}"
    else
        log_info "libhdds_c.so  NOT FOUND"
    fi

    for bin_path in "$RUST_BIN" "$C_BIN" "$CPP_BIN"; do
        local bin_name
        bin_name="$(basename "$bin_path")"
        if [[ -f "$bin_path" ]]; then
            local hash size
            hash="$(sha256sum "$bin_path" | cut -d' ' -f1)"
            size="$(stat -c%s "$bin_path" 2>/dev/null || stat -f%z "$bin_path" 2>/dev/null || echo '?')"
            log_info "${bin_name}  sha256:${hash:0:16}...  size:${size}"
        else
            log_info "${bin_name}  NOT BUILT"
        fi
    done
}

################################################################################
# LAYER 0: BUILD VERIFICATION
################################################################################

layer_build() {
    log_section "LAYER 0: BUILD VERIFICATION"
    reset_layer_counters

    if ! $DO_BUILD; then
        log_info "Build skipped (--no-build)"
        # Still verify binaries exist
        verify_binaries
        layer_summary "Layer 0 (Build)"
        return
    fi

    # 0a: Shared library
    log_info "Building hdds-c shared library (release)..."
    if cargo build --release -p hdds-c --manifest-path="$ROOT/Cargo.toml" 2>&1 | tail -3; then
        if [[ -f "$LIB_PATH/libhdds_c.so" ]]; then
            log_pass "libhdds_c.so built"
            LAYER_PASS=$((LAYER_PASS + 1))
        else
            log_fail "libhdds_c.so not found after build"
            LAYER_FAIL=$((LAYER_FAIL + 1))
            BUILD_FAILURES=$((BUILD_FAILURES + 1))
        fi
    else
        log_fail "cargo build hdds-c failed"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
    fi

    # 0b: Rust test binary
    log_info "Building Rust cross_lang_test example..."
    if cargo build --release --example cross_lang_test --manifest-path="$ROOT/Cargo.toml" 2>&1 | tail -3; then
        if [[ -f "$RUST_BIN" ]]; then
            log_pass "cross_lang_test (Rust) built"
            LAYER_PASS=$((LAYER_PASS + 1))
        else
            log_fail "Rust binary not found at $RUST_BIN"
            LAYER_FAIL=$((LAYER_FAIL + 1))
            BUILD_FAILURES=$((BUILD_FAILURES + 1))
        fi
    else
        log_fail "cargo build cross_lang_test failed"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
    fi

    # 0c: C test binary
    log_info "Compiling C test program..."
    if gcc -O2 -o "$C_BIN" "$CROSS_DIR/test.c" \
        -include "$CROSS_DIR/ros2_fwd.h" \
        -I"$ROOT/sdk/c/include" \
        -L"$LIB_PATH" -lhdds_c -lpthread -ldl -lm 2>&1; then
        log_pass "xtest_c (C) compiled"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "C compilation failed"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
        C_BIN=""
    fi

    # 0d: C++ test binary
    log_info "Compiling C++ test program..."
    if g++ -std=c++17 -O2 -o "$CPP_BIN" "$CROSS_DIR/test.cpp" \
        "$ROOT"/sdk/cxx/src/*.cpp \
        -include "$CROSS_DIR/ros2_fwd.h" \
        -I"$ROOT/sdk/cxx/include" \
        -I"$ROOT/sdk/c/include" \
        -L"$LIB_PATH" -lhdds_c -lpthread -ldl -lm 2>&1; then
        log_pass "xtest_cpp (C++) compiled"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "C++ compilation failed"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
        CPP_BIN=""
    fi

    # 0e: Python availability
    if command -v python3 &>/dev/null; then
        log_pass "python3 available"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "python3 not found"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
    fi

    layer_summary "Layer 0 (Build)"
}

verify_binaries() {
    [[ -f "$LIB_PATH/libhdds_c.so" ]] && log_pass "libhdds_c.so present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_fail "libhdds_c.so missing"; LAYER_FAIL=$((LAYER_FAIL + 1)); BUILD_FAILURES=$((BUILD_FAILURES + 1)); }
    [[ -f "$RUST_BIN" ]] && log_pass "Rust binary present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_skip "Rust binary missing"; LAYER_SKIP=$((LAYER_SKIP + 1)); }
    [[ -n "$C_BIN" && -f "$C_BIN" ]] && log_pass "C binary present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_skip "C binary missing"; LAYER_SKIP=$((LAYER_SKIP + 1)); C_BIN=""; }
    [[ -n "$CPP_BIN" && -f "$CPP_BIN" ]] && log_pass "C++ binary present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_skip "C++ binary missing"; LAYER_SKIP=$((LAYER_SKIP + 1)); CPP_BIN=""; }
    command -v python3 &>/dev/null && log_pass "python3 available" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_fail "python3 not found"; LAYER_FAIL=$((LAYER_FAIL + 1)); }
}

################################################################################
# LAYER 1: PYTHON UNIT + INTEGRATION TESTS
################################################################################

layer_python() {
    log_section "LAYER 1: PYTHON UNIT + INTEGRATION TESTS"
    reset_layer_counters

    if ! command -v python3 &>/dev/null; then
        log_fail "python3 not available -- cannot run pytest"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1 (Python)"
        return
    fi

    local pytest_log="/tmp/hdds_pytest_$$.log"
    log_info "Running pytest in sdk/python/tests/..."

    local pytest_exit=0
    (
        cd "$ROOT/sdk/python"
        LD_LIBRARY_PATH="$LIB_PATH" python3 -m pytest tests/ -v --tb=short 2>&1
    ) > "$pytest_log" 2>&1 || pytest_exit=$?

    # Parse pytest output for individual test results
    local pytest_passed pytest_failed pytest_total
    pytest_passed=$(grep -cE '::.*PASSED' "$pytest_log" 2>/dev/null) || pytest_passed=0
    pytest_failed=$(grep -cE '::.*FAILED' "$pytest_log" 2>/dev/null) || pytest_failed=0
    pytest_total=$((pytest_passed + pytest_failed))

    if [[ $pytest_exit -eq 0 ]]; then
        log_pass "pytest: ${pytest_passed}/${pytest_total} tests passed"
        LAYER_PASS=$((LAYER_PASS + pytest_passed))
    else
        log_fail "pytest: ${pytest_failed}/${pytest_total} tests failed (exit code $pytest_exit)"
        # Show failure details
        grep -E '(FAILED|ERROR|assert)' "$pytest_log" 2>/dev/null | head -10 | while IFS= read -r line; do
            echo "    $line"
            report "    $line"
        done
        LAYER_PASS=$((LAYER_PASS + pytest_passed))
        LAYER_FAIL=$((LAYER_FAIL + pytest_failed))
    fi

    # If no tests found at all, that's a failure
    if [[ $pytest_total -eq 0 ]]; then
        log_fail "pytest: no tests found"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    rm -f "$pytest_log"
    layer_summary "Layer 1 (Python)"
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
        rust)   [[ -f "$RUST_BIN" ]] ;;
        c)      [[ -n "$C_BIN" && -f "$C_BIN" ]] ;;
        cpp)    [[ -n "$CPP_BIN" && -f "$CPP_BIN" ]] ;;
        python) command -v python3 &>/dev/null ;;
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

# Run a single pub/sub test pair and update counters
run_pubsub_test() {
    local pub_lang="$1" sub_lang="$2"
    local pub_label sub_label
    pub_label="$(lang_label "$pub_lang")"
    sub_label="$(lang_label "$sub_lang")"
    local test_name="${pub_label} pub -> ${sub_label} sub"

    # Filter check
    if [[ -n "$FILTER_LANG" ]]; then
        if [[ "$pub_lang" != "$FILTER_LANG" && "$sub_lang" != "$FILTER_LANG" ]]; then
            LAYER_SKIP=$((LAYER_SKIP + 1))
            return
        fi
    fi

    # Availability check
    if ! lang_available "$pub_lang"; then
        log_skip "$test_name (${pub_label} not available)"
        LAYER_SKIP=$((LAYER_SKIP + 1))
        return
    fi
    if ! lang_available "$sub_lang"; then
        log_skip "$test_name (${sub_label} not available)"
        LAYER_SKIP=$((LAYER_SKIP + 1))
        return
    fi

    # Unique topic per test to avoid crosstalk
    local topic="${TOPIC_BASE}_${pub_lang}_${sub_lang}_$$"

    local pub_cmd sub_cmd
    pub_cmd="$(lang_cmd "$pub_lang" pub "$topic" "$NUM_SAMPLES")"
    sub_cmd="$(lang_cmd "$sub_lang" sub "$topic" "$NUM_SAMPLES")"

    # Log files
    local sub_log="/tmp/hdds_xtest_sub_${pub_lang}_${sub_lang}_$$.log"
    local pub_log="/tmp/hdds_xtest_pub_${pub_lang}_${sub_lang}_$$.log"

    # Start subscriber first (background)
    LD_LIBRARY_PATH="$LIB_PATH" $sub_cmd > "$sub_log" 2>&1 &
    local sub_pid=$!

    # Give subscriber time to start and begin discovery
    sleep 1

    # Start publisher
    LD_LIBRARY_PATH="$LIB_PATH" $pub_cmd > "$pub_log" 2>&1 &
    local pub_pid=$!

    # Wait for publisher (should finish in ~3s)
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
        if [[ $waited -ge $SUB_TIMEOUT ]]; then
            kill -9 "$sub_pid" 2>/dev/null || true
            wait "$sub_pid" 2>/dev/null || true
            sub_ok=false
            break
        fi
    done

    if $sub_ok; then
        wait "$sub_pid" 2>/dev/null
        sub_ok=$([[ $? -eq 0 ]] && echo true || echo false)
    fi

    # Verdict
    if $pub_ok && [[ "$sub_ok" == "true" ]] && grep -q "^OK:" "$sub_log" 2>/dev/null; then
        log_pass "$test_name"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "$test_name"
        if ! $pub_ok; then
            echo "    Publisher exit=non-zero:"
            head -5 "$pub_log" 2>/dev/null | sed 's/^/      /'
            report "    Publisher failed (see log)"
        fi
        if [[ "$sub_ok" != "true" ]]; then
            echo "    Subscriber exit=non-zero or timeout:"
            head -5 "$sub_log" 2>/dev/null | sed 's/^/      /'
            report "    Subscriber failed (see log)"
        fi
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # Cleanup temp logs
    rm -f "$sub_log" "$pub_log"
}

################################################################################
# LAYER 2: SAME-LANGUAGE TESTS
################################################################################

layer_same_lang() {
    log_section "LAYER 2: SAME-LANGUAGE PUB/SUB"
    reset_layer_counters

    local LANGS=(rust c cpp python)

    for lang in "${LANGS[@]}"; do
        run_pubsub_test "$lang" "$lang"
    done

    layer_summary "Layer 2 (Same-Language)"
}

################################################################################
# LAYER 3: CROSS-LANGUAGE TESTS
################################################################################

layer_cross_lang() {
    log_section "LAYER 3: CROSS-LANGUAGE PUB/SUB"
    reset_layer_counters

    if $QUICK; then
        log_info "Skipped (--quick mode)"
        report "  Skipped (--quick mode)"
        return
    fi

    local LANGS=(rust c cpp python)

    for pub_lang in "${LANGS[@]}"; do
        for sub_lang in "${LANGS[@]}"; do
            if [[ "$pub_lang" != "$sub_lang" ]]; then
                run_pubsub_test "$pub_lang" "$sub_lang"
            fi
        done
    done

    layer_summary "Layer 3 (Cross-Language)"
}

################################################################################
# Report writer
################################################################################

write_report() {
    if ! $WRITE_REPORT; then
        return
    fi

    mkdir -p "$REPORT_DIR"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%d_%H%M%S')"
    local report_file="$REPORT_DIR/sdk-test-${timestamp}.txt"

    {
        echo "============================================================"
        echo "HDDS SDK VERIFICATION REPORT"
        echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "Git:       $(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo 'n/a')"
        echo "============================================================"
        echo ""
        for line in "${REPORT_LINES[@]}"; do
            echo "$line"
        done
    } > "$report_file"

    log_info "Report written to: $report_file"
}

################################################################################
# Final summary
################################################################################

print_summary() {
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BOLD}SDK VERIFICATION SUMMARY${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $TOTAL_PASS"
    echo -e "  ${RED}Failed:${NC}  $TOTAL_FAIL"
    echo -e "  ${YELLOW}Skipped:${NC} $TOTAL_SKIP"
    echo -e "  ${BOLD}Total:${NC}   $TOTAL_TESTS (executed)"
    echo ""

    report ""
    report "================================================================"
    report "SDK VERIFICATION SUMMARY"
    report "================================================================"
    report ""
    report "  Passed:  $TOTAL_PASS"
    report "  Failed:  $TOTAL_FAIL"
    report "  Skipped: $TOTAL_SKIP"
    report "  Total:   $TOTAL_TESTS (executed)"
    report ""

    if [[ $TOTAL_FAIL -eq 0 ]] && [[ $BUILD_FAILURES -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}[OK] ALL TESTS PASSED - SDK verification gate OPEN${NC}"
        report "[OK] ALL TESTS PASSED - SDK verification gate OPEN"
    elif [[ $BUILD_FAILURES -gt 0 ]]; then
        echo -e "${RED}${BOLD}[X] BUILD FAILED - SDK verification gate CLOSED${NC}"
        echo -e "${RED}   ${BUILD_FAILURES} build target(s) failed. Fix builds first.${NC}"
        report "[X] BUILD FAILED - SDK verification gate CLOSED"
    else
        echo -e "${RED}${BOLD}[X] ${TOTAL_FAIL} TEST(S) FAILED - SDK verification gate CLOSED${NC}"
        echo ""
        echo "  Recommended actions:"
        echo "    1. Check failed test output above for details"
        echo "    2. Run individual language: ./scripts/test-sdk.sh --lang <lang>"
        echo "    3. Run Python only:        ./scripts/test-sdk.sh --python"
        report "[X] ${TOTAL_FAIL} TEST(S) FAILED - SDK verification gate CLOSED"
    fi
    echo ""
}

################################################################################
# Python-only fast path
################################################################################

run_python_only() {
    log_section "PYTHON-ONLY MODE"

    if $DO_BUILD; then
        log_info "Building hdds-c (release)..."
        cargo build --release -p hdds-c --manifest-path="$ROOT/Cargo.toml" 2>&1 | tail -1
    fi

    log_info "Running pytest..."
    cd "$ROOT/sdk/python"
    LD_LIBRARY_PATH="$LIB_PATH" python3 -m pytest tests/ -v --tb=short
    exit $?
}

################################################################################
# Main
################################################################################

main() {
    parse_args "$@"

    echo -e "${BOLD}HDDS SDK Verification Gate v2.0.0${NC}"
    echo -e "${BOLD}$(date -u '+%Y-%m-%dT%H:%M:%SZ')${NC}"
    echo ""

    report "HDDS SDK Verification Gate v2.0.0"
    report "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Python-only fast path
    if $PYTHON_ONLY; then
        run_python_only
        # run_python_only exits directly
    fi

    # Full verification pipeline
    print_environment
    layer_build
    hash_binaries
    layer_python
    layer_same_lang
    layer_cross_lang

    # Summary + report
    print_summary
    write_report

    # Exit code = number of failures
    exit $((TOTAL_FAIL + BUILD_FAILURES))
}

main "$@"
