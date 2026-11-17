#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

################################################################################
# HDDS SDK VERIFICATION GATE - Mechanical Cross-Language Test Suite
# Version: 2.1.0
#
# Runs automated verification for all SDK language bindings:
#   Layer 0: Build verification (compile all targets, hash binaries)
#   Layer 1: Python source-tree tests (pytest), package version == workspace
#            version, Python docs consistency (scripts/check-python-docs.sh)
#   Layer 1b: Python installable wheel: offline wheel build from a copy under
#            the cargo target dir -> bare venv per claimed interpreter ->
#            pip install --no-index -> installed smoke (cwd=/) -> fail-closed
#            check with HDDS_LIB_PATH on an empty directory (loading is lazy:
#            "import hdds" succeeds, the FIRST NATIVE CALL raises ImportError)
#   Layer 1c: TypeScript SDK: package version == workspace version, vitest
#            (logic + native FFI against libhdds_c.so + every advertised sample
#            spawned and asserted). 0 tests found = FAIL.
#   Layer 1d: TypeScript installable tarball: npm pack -> scratch project ->
#            npm install --no-save of the tarball -> installed smoke from
#            site-like node_modules, plus a fail-closed check with
#            HDDS_LIB_PATH on an empty directory.
#   Layer 1e: C and C++ listener tests (sdk/c/tests/test_listener.c,
#            sdk/cxx/tests/test_listener.cpp): compiled against the release
#            libhdds_c and run; each binary is one pass or one failure
#   Layer 2: Same-language pub/sub (Rust/Rust, C/C, C++/C++, Python/Python,
#            TypeScript/TypeScript)
#   Layer 3: Cross-language pub/sub (all 20 combinations)
#
# The Python layers pass HDDS_LIB_PATH (strict override of the SDK loader),
# never LD_LIBRARY_PATH; C/C++/Rust binaries linked with -lhdds_c keep
# LD_LIBRARY_PATH. Host prerequisites for Layer 1b: python3 with venv and
# ensurepip, setuptools >= 77 importable by every claimed interpreter
# (no network is used: --no-build-isolation --no-index).
#
# This is a CI-quality gate. It produces machine-parseable reports
# and exits with the number of failures (0 = all green).
#
# Usage:
#   ./scripts/test-sdk.sh              # Full matrix (build + test)
#   ./scripts/test-sdk.sh --no-build   # Skip build, run tests only
#   ./scripts/test-sdk.sh --quick      # Same-language only (skip Layer 3)
#   ./scripts/test-sdk.sh --lang rust  # Only combos involving rust
#   ./scripts/test-sdk.sh --python     # Layers 0a + 1 + 1b only (Python gate)
#   ./scripts/test-sdk.sh --typescript # Layers 0a + 0f + 1c + 1d (TypeScript gate)
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
readonly SDK_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
readonly LIB_PATH="$SDK_TARGET_DIR/release"
readonly REPORT_DIR="$SDK_TARGET_DIR/sdk-reports"
readonly PY_SDK_DIR="$ROOT/sdk/python"
readonly PY_WHEEL_DIR="$SDK_TARGET_DIR/python-wheel"
readonly PY_MIN_SETUPTOOLS=77
readonly TS_SDK_DIR="$ROOT/sdk/typescript"
readonly TS_XLANG_DIR="$SDK_TARGET_DIR/ts-xlang"
readonly TS_PACK_DIR="$SDK_TARGET_DIR/ts-pack"
export CARGO_TARGET_DIR="$SDK_TARGET_DIR"

# Binaries
RUST_BIN="$SDK_TARGET_DIR/release/examples/cross_lang_test"
C_BIN="/tmp/hdds_xtest_c"
CPP_BIN="/tmp/hdds_xtest_cpp"
PY_CMD="python3 $CROSS_DIR/test.py"
TS_CMD=""            # set by build_typescript_sdk once the driver compiles
TS_NPM_CI_MODE=""    # "offline" or "online": recorded in the report

# Network: ensure HDDS binds to the right interface (avoid docker bridges)
if [[ -z "${HDDS_INTERFACE:-}" ]]; then
    HDDS_INTERFACE=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+' || true)
    export HDDS_INTERFACE
fi

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
TYPESCRIPT_ONLY=false
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
            --typescript) TYPESCRIPT_ONLY=true ;;
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
# Layer 1e: native listener tests (C, C++)
################################################################################

# Build and run one listener test binary; one pass or one failure.
run_native_listener_test() {
    local label="$1" bin="$2"
    shift 2
    if ! "$@" > "/tmp/hdds_listener_build_$$.log" 2>&1; then
        log_fail "$label listener test: compilation failed"
        sed 's/^/    /' "/tmp/hdds_listener_build_$$.log" | head -10
        LAYER_FAIL=$((LAYER_FAIL + 1))
        return
    fi
    if LD_LIBRARY_PATH="$LIB_PATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        timeout 120 "$bin" > "/tmp/hdds_listener_run_$$.log" 2>&1; then
        log_pass "$label listener test: $(grep -E 'tests passed' "/tmp/hdds_listener_run_$$.log" | tail -1)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "$label listener test failed"
        tail -5 "/tmp/hdds_listener_run_$$.log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi
}

layer_native_listeners() {
    log_section "LAYER 1e: C / C++ LISTENER TESTS"
    reset_layer_counters

    run_native_listener_test "C" "/tmp/hdds_listener_c_$$" \
        gcc -std=c11 -O1 -g -o "/tmp/hdds_listener_c_$$" \
        "$ROOT/sdk/c/tests/test_listener.c" \
        -I"$ROOT/sdk/c/include" -L"$LIB_PATH" -lhdds_c -lpthread -ldl -lm
    run_native_listener_test "C++" "/tmp/hdds_listener_cpp_$$" \
        g++ -std=c++17 -O1 -g -o "/tmp/hdds_listener_cpp_$$" \
        "$ROOT/sdk/cxx/tests/test_listener.cpp" "$ROOT"/sdk/cxx/src/*.cpp \
        -I"$ROOT/sdk/cxx/include" -I"$ROOT/sdk/c/include" \
        -L"$LIB_PATH" -lhdds_c -lpthread -ldl -lm

    rm -f "/tmp/hdds_listener_c_$$" "/tmp/hdds_listener_cpp_$$" \
        "/tmp/hdds_listener_build_$$.log" "/tmp/hdds_listener_run_$$.log"
    layer_summary "Layer 1e (C/C++ listeners)"
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
    log_info "Options:    build=$DO_BUILD quick=$QUICK filter='$FILTER_LANG' python_only=$PYTHON_ONLY typescript_only=$TYPESCRIPT_ONLY"
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

    # koffi ships one prebuilt per <platform>_<arch>; hardcoding linux_x64
    # would record "NOT BUILT" on any other box while the lane runs green.
    local koffi_node=""
    if [[ -d "$TS_SDK_DIR/node_modules/koffi/build/koffi" ]]; then
        koffi_node="$(find "$TS_SDK_DIR/node_modules/koffi/build/koffi" \
            -name koffi.node -type f 2>/dev/null | head -1 || true)"
    fi
    for bin_path in "$RUST_BIN" "$C_BIN" "$CPP_BIN" \
                    "$TS_SDK_DIR/dist/index.js" \
                    "${koffi_node:-$TS_SDK_DIR/node_modules/koffi/build/koffi/koffi.node}"; do
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

    # 0c: Header standalone parse (no ROS2)
    log_info "Verifying hdds.h parses without ROS2..."
    if echo '#include "hdds.h"' | gcc -fsyntax-only -x c -I"$ROOT/sdk/c/include" - 2>&1; then
        log_pass "hdds.h standalone parse (no ROS2)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "hdds.h fails to parse without ROS2"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
    fi

    # 0d: C test binary
    log_info "Compiling C test program..."
    if gcc -O2 -o "$C_BIN" "$CROSS_DIR/test.c" \
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

    # 0f: TypeScript SDK (npm restore + tsc for the SDK, the samples and the
    # cross-language driver). Fail-closed: no TypeScript lane without a build.
    build_typescript_sdk

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

# Restore node_modules, build dist/, dist-samples/ and the cross-language
# driver. Sets TS_CMD when the driver is runnable; leaves it empty otherwise so
# every TypeScript pair reports as unavailable instead of silently passing.
#
# npm restore tries the local cache first and falls back to the network. Which
# path ran is printed and lands in the report: an "offline" line means the run
# was hermetic, an "online" line means it was not.
build_typescript_sdk() {
    TS_CMD=""
    TS_NPM_CI_MODE=""

    if ! command -v npm &>/dev/null || ! command -v node &>/dev/null; then
        log_fail "node/npm not found -- the TypeScript SDK cannot be built"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
        return
    fi
    log_info "node $(node --version), npm $(npm --version)"

    local npm_log="$SDK_TARGET_DIR/ts-npm-ci.log"
    mkdir -p "$SDK_TARGET_DIR"
    if (cd "$TS_SDK_DIR" && npm ci --offline --no-audit --no-fund) > "$npm_log" 2>&1; then
        TS_NPM_CI_MODE="offline"
    elif (cd "$TS_SDK_DIR" && npm ci --no-audit --no-fund) >> "$npm_log" 2>&1; then
        TS_NPM_CI_MODE="online"
    else
        log_fail "npm ci failed for sdk/typescript (see $npm_log)"
        tail -5 "$npm_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
        return
    fi
    log_pass "npm ci ($TS_NPM_CI_MODE) restored sdk/typescript/node_modules"
    LAYER_PASS=$((LAYER_PASS + 1))

    # tsc: the SDK itself, then the samples (which resolve "@hdds/client" by
    # package self-reference and therefore need dist/ to exist first).
    local tsc_log="$SDK_TARGET_DIR/ts-build.log"
    if (cd "$TS_SDK_DIR" && npm run build && npm run build:samples) > "$tsc_log" 2>&1; then
        log_pass "tsc built sdk/typescript dist/ and dist-samples/"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "tsc failed for sdk/typescript (see $tsc_log)"
        tail -10 "$tsc_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
        return
    fi

    # The cross-language driver is a build artefact: compiled into the cargo
    # target dir, never into the worktree. A node_modules/@hdds/client symlink
    # next to it makes "@hdds/client" resolve through the package exports map
    # for both tsc and node, with no path rewriting.
    rm -rf "$TS_XLANG_DIR"
    mkdir -p "$TS_XLANG_DIR/src" "$TS_XLANG_DIR/node_modules/@hdds"
    ln -sfn "$TS_SDK_DIR" "$TS_XLANG_DIR/node_modules/@hdds/client"
    cp "$CROSS_DIR/test.ts" "$TS_XLANG_DIR/src/"
    local drv_log="$SDK_TARGET_DIR/ts-xlang-build.log"
    if (cd "$TS_SDK_DIR" && npx tsc --target ES2022 --module CommonJS \
            --moduleResolution Node --strict --esModuleInterop --skipLibCheck \
            --noEmitOnError --outDir "$TS_XLANG_DIR" \
            "$TS_XLANG_DIR/src/test.ts") > "$drv_log" 2>&1 \
        && [[ -f "$TS_XLANG_DIR/test.js" ]]; then
        TS_CMD="node $TS_XLANG_DIR/test.js"
        log_pass "xtest_ts (TypeScript) compiled"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "TypeScript cross-language driver failed to compile (see $drv_log)"
        tail -10 "$drv_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
    fi
}

verify_binaries() {
    [[ -f "$LIB_PATH/libhdds_c.so" ]] && log_pass "libhdds_c.so present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_fail "libhdds_c.so missing"; LAYER_FAIL=$((LAYER_FAIL + 1)); BUILD_FAILURES=$((BUILD_FAILURES + 1)); }
    [[ -f "$RUST_BIN" ]] && log_pass "Rust binary present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_skip "Rust binary missing"; LAYER_SKIP=$((LAYER_SKIP + 1)); }
    [[ -n "$C_BIN" && -f "$C_BIN" ]] && log_pass "C binary present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_skip "C binary missing"; LAYER_SKIP=$((LAYER_SKIP + 1)); C_BIN=""; }
    [[ -n "$CPP_BIN" && -f "$CPP_BIN" ]] && log_pass "C++ binary present" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_skip "C++ binary missing"; LAYER_SKIP=$((LAYER_SKIP + 1)); CPP_BIN=""; }
    command -v python3 &>/dev/null && log_pass "python3 available" && LAYER_PASS=$((LAYER_PASS + 1)) || { log_fail "python3 not found"; LAYER_FAIL=$((LAYER_FAIL + 1)); }
    if [[ -f "$TS_XLANG_DIR/test.js" ]]; then
        TS_CMD="node $TS_XLANG_DIR/test.js"
        log_pass "TypeScript driver present"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_skip "TypeScript driver missing (run without --no-build)"
        LAYER_SKIP=$((LAYER_SKIP + 1))
        TS_CMD=""
    fi
}

################################################################################
# LAYER 1: PYTHON SOURCE-TREE TESTS + VERSION + DOCS CONSISTENCY
################################################################################

# Workspace version from the root Cargo.toml ([workspace.package] version).
workspace_version() {
    awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *= */{sub(/^[^"]*"/,""); sub(/".*$/,""); print; exit}' "$ROOT/Cargo.toml"
}

# Python package version from sdk/python/hdds/__init__.py (__version__).
python_package_version() {
    sed -n 's/^__version__ = "\([^"]*\)".*/\1/p' "$PY_SDK_DIR/hdds/__init__.py" | head -1
}

# Every SDK carries the workspace version; this is the
# one check that enforces it for Python. pyproject.toml reads __version__
# dynamically, so __init__.py is the only place to compare.
check_python_version_matches_workspace() {
    local ws py
    ws="$(workspace_version)"
    py="$(python_package_version)"
    if [[ -z "$ws" || -z "$py" ]]; then
        log_fail "python version check: could not read workspace ('$ws') or package ('$py') version"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    elif [[ "$ws" == "$py" ]]; then
        log_pass "python package version == workspace version ($py)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "python package version $py != workspace version $ws (fix sdk/python/hdds/__init__.py; scripts/bump-version.sh rewrites both)"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi
}

check_python_docs() {
    local checker="$SCRIPT_DIR/check-python-docs.sh"
    if [[ ! -x "$checker" ]]; then
        log_fail "python docs check: $checker missing or not executable"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        return
    fi
    local out
    if out="$("$checker" 2>&1)"; then
        log_pass "python docs consistent (no foreign build-backend words, README discovery order == _native.py)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "python docs check failed"
        echo "$out" | sed 's/^/    /' | head -20
        report "    $(echo "$out" | head -5 | tr '\n' ' ')"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi
}

# scripts/bump-version.sh keeps sdk/python/hdds/__init__.py in step with the
# workspace Cargo.toml. Named proof for that behaviour, run against a scratch
# tree under the cargo target dir (never this worktree): both directions must
# hold -- the nominal path rewrites BOTH files, and a drifted SDK file exits 1
# with Cargo.toml UNTOUCHED (no half-bumped tree).
check_bump_version_script() {
    local bumper="$SCRIPT_DIR/bump-version.sh"
    if [[ ! -x "$bumper" ]]; then
        log_fail "bump-version check: $bumper missing or not executable"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        return
    fi
    local scratch="$SDK_TARGET_DIR/bump-version-check"
    local init_rel="sdk/python/hdds/__init__.py"
    local pkg_rel="sdk/typescript/package.json"
    local lock_rel="sdk/typescript/package-lock.json"
    rm -rf "$scratch"
    mkdir -p "$scratch/sdk/python/hdds" "$scratch/sdk/typescript"
    printf '[workspace.package]\nversion = "9.9.7"\n' > "$scratch/Cargo.toml"
    printf '__version__ = "9.9.7"\n' > "$scratch/$init_rel"
    # Minimal but shape-accurate fixtures: the lock carries the version TWICE
    # (top level and packages[""]) plus a dependency that must NOT move.
    cat > "$scratch/$pkg_rel" <<'PKGJSON'
{
  "name": "@hdds/client",
  "version": "9.9.7",
  "private": true
}
PKGJSON
    cat > "$scratch/$lock_rel" <<'LOCKJSON'
{
  "name": "@hdds/client",
  "version": "9.9.7",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "@hdds/client",
      "version": "9.9.7"
    },
    "node_modules/koffi": {
      "version": "9.9.7"
    }
  }
}
LOCKJSON

    # 1. nominal: all three SDK files move with Cargo.toml, and the dependency
    # version inside the lock does not (the lock must keep exactly two 9.9.8
    # lines: its own two, never koffi's).
    local lock_moved=0
    if "$bumper" "$scratch/Cargo.toml" >/dev/null 2>&1 \
        && grep -q '^version = "9.9.8"' "$scratch/Cargo.toml" \
        && grep -q '^__version__ = "9.9.8"' "$scratch/$init_rel" \
        && grep -q '^  "version": "9.9.8",$' "$scratch/$pkg_rel" \
        && grep -q '^  "version": "9.9.8",$' "$scratch/$lock_rel" \
        && grep -q '^      "version": "9.9.8"' "$scratch/$lock_rel"; then
        lock_moved="$(grep -c '"version": "9.9.8"' "$scratch/$lock_rel" || true)"
    fi
    if [[ "$lock_moved" == "2" ]]; then
        log_pass "bump-version.sh rewrites Cargo.toml, $init_rel, $pkg_rel and $lock_rel in step (9.9.7 -> 9.9.8), leaving dependency versions alone"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "bump-version.sh did not bump all four files (Cargo.toml: $(grep -m1 '^version' "$scratch/Cargo.toml" 2>/dev/null), $init_rel: $(grep -m1 '^__version__' "$scratch/$init_rel" 2>/dev/null), $pkg_rel: $(grep -m1 '"version"' "$scratch/$pkg_rel" 2>/dev/null), lock 9.9.8 lines: $lock_moved (want 2))"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # 2. drift: an SDK file carries a different version -> refuse, change
    # nothing. Run once per SDK file so a missing arm cannot hide.
    local drifted
    for drifted in "$init_rel" "$pkg_rel" "$lock_rel"; do
        local saved="$scratch/$drifted.saved"
        cp "$scratch/$drifted" "$saved"
        sed -i 's/9\.9\.8/0.0.1/' "$scratch/$drifted"
        local rc=0
        "$bumper" "$scratch/Cargo.toml" >/dev/null 2>&1 || rc=$?
        if [[ $rc -ne 0 ]] && grep -q '^version = "9.9.8"' "$scratch/Cargo.toml"; then
            log_pass "bump-version.sh refuses a drifted $drifted (exit $rc) and leaves Cargo.toml untouched"
            LAYER_PASS=$((LAYER_PASS + 1))
        else
            log_fail "bump-version.sh half-bumped a tree with a drifted $drifted (exit $rc, Cargo.toml: $(grep -m1 '^version' "$scratch/Cargo.toml" 2>/dev/null))"
            LAYER_FAIL=$((LAYER_FAIL + 1))
        fi
        mv "$saved" "$scratch/$drifted"
    done
    printf '__version__ = "0.0.1"\n' > "$scratch/$init_rel"
    local drift_rc=0
    "$bumper" "$scratch/Cargo.toml" >/dev/null 2>&1 || drift_rc=$?
    if [[ $drift_rc -ne 0 ]] \
        && grep -q '^version = "9.9.8"' "$scratch/Cargo.toml" \
        && grep -q '^__version__ = "0.0.1"' "$scratch/$init_rel"; then
        log_pass "bump-version.sh refuses a drifted SDK version (exit $drift_rc) and leaves Cargo.toml untouched"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "bump-version.sh half-bumped a drifted tree (exit $drift_rc, Cargo.toml: $(grep -m1 '^version' "$scratch/Cargo.toml" 2>/dev/null))"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi
    rm -rf "$scratch"
}

layer_python() {
    log_section "LAYER 1: PYTHON SOURCE-TREE TESTS"
    reset_layer_counters

    if ! command -v python3 &>/dev/null; then
        log_fail "python3 not available -- cannot run pytest"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1 (Python)"
        return
    fi

    check_python_version_matches_workspace
    check_python_docs
    check_bump_version_script

    # Required tool, like cargo: tests/test_native_surface.py derives the
    # library symbol table with nm. Without it the binding-vs-library parity
    # proof cannot run, and a proof that cannot run must close the gate.
    if command -v nm &>/dev/null; then
        log_pass "nm present (binding-vs-library parity proof can run)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "nm (binutils) missing -- tests/test_native_surface.py cannot derive the library symbol table"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # The wheel is built ONCE per gate run: here, so test_wheel_contents.py
    # inspects the same artefact Layer 1b installs (HDDS_PY_WHEEL). When the
    # build fails the variable stays empty, pytest builds its own copy and
    # reports the error, and Layer 1b fails on the build again.
    build_python_wheel || true

    local pytest_log="/tmp/hdds_pytest_$$.log"
    log_info "Running pytest in sdk/python/tests/ (HDDS_LIB_PATH=$LIB_PATH, HDDS_PY_WHEEL=${PY_WHEEL_FILE:-<unset>})..."

    # HDDS_LIB_PATH is the loader's strict override: a library that does not
    # load FAILS the native tests (conftest.py), it never skips them.
    local pytest_exit=0
    (
        cd "$PY_SDK_DIR"
        env -u LD_LIBRARY_PATH HDDS_LIB_PATH="$LIB_PATH" HDDS_PY_WHEEL="${PY_WHEEL_FILE:-}" PYTHONDONTWRITEBYTECODE=1 \
            python3 -m pytest tests/ -v --tb=short -p no:cacheprovider -rxX 2>&1
    ) > "$pytest_log" 2>&1 || pytest_exit=$?

    # Parse pytest output for individual test results. Only the -v progress
    # lines count ("tests/<file>::<test> <OUTCOME>", one per test, anchored
    # at column 0): the -rxX summary lines start with the outcome word and
    # quote the xfail reason, so a reason mentioning XPASS/FAILED must never
    # reach the tally. XFAIL is a known, documented gap and counts as
    # neither; XPASS(strict) is a failure.
    local pytest_passed pytest_failed pytest_xfail pytest_xpass pytest_skipped pytest_total
    local progress='^tests/[^ ]+::[^ ]+ '
    pytest_passed=$(grep -cE "${progress}PASSED" "$pytest_log" 2>/dev/null) || pytest_passed=0
    pytest_failed=$(grep -cE "${progress}(FAILED|ERROR)" "$pytest_log" 2>/dev/null) || pytest_failed=0
    pytest_xfail=$(grep -cE "${progress}XFAIL" "$pytest_log" 2>/dev/null) || pytest_xfail=0
    pytest_xpass=$(grep -cE "${progress}XPASS" "$pytest_log" 2>/dev/null) || pytest_xpass=0
    pytest_skipped=$(grep -cE "${progress}SKIPPED" "$pytest_log" 2>/dev/null) || pytest_skipped=0
    pytest_failed=$((pytest_failed + pytest_xpass))
    pytest_total=$((pytest_passed + pytest_failed + pytest_skipped))
    # A skipped test is evidence that did NOT run: the release certificate
    # requires 0 failures AND 0 skips, so it must reach the tally instead of
    # being erased into a green line.
    LAYER_SKIP=$((LAYER_SKIP + pytest_skipped))

    if [[ $pytest_exit -eq 0 ]]; then
        log_pass "pytest: ${pytest_passed}/${pytest_total} tests passed (${pytest_xfail} documented xfail, ${pytest_skipped} skipped)"
        LAYER_PASS=$((LAYER_PASS + pytest_passed))
    else
        log_fail "pytest: ${pytest_failed}/${pytest_total} tests failed, ${pytest_skipped} skipped (exit code $pytest_exit)"
        # Show failure details
        { grep -E '(FAILED|ERROR|XPASS|assert)' "$pytest_log" 2>/dev/null | head -10 | while IFS= read -r line; do
            echo "    $line"
            report "    $line"
        done; } || true
        LAYER_PASS=$((LAYER_PASS + pytest_passed))
        LAYER_FAIL=$((LAYER_FAIL + pytest_failed))
        # A non-zero exit with no parsed failure (collection error, usage
        # error) must still close the gate.
        if [[ $pytest_failed -eq 0 ]]; then
            LAYER_FAIL=$((LAYER_FAIL + 1))
        fi
    fi

    # If no tests found at all, that's a failure
    if [[ $pytest_skipped -gt 0 ]]; then
        log_skip "pytest: ${pytest_skipped} test(s) skipped (they are not evidence)"
        { grep -E "${progress}SKIPPED" "$pytest_log" 2>/dev/null | head -5 | sed 's/^/    /'; } || true
    fi

    if [[ $pytest_total -eq 0 ]]; then
        log_fail "pytest: no tests found"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    rm -f "$pytest_log"
    layer_summary "Layer 1 (Python)"
}

################################################################################
# LAYER 1b: PYTHON INSTALLABLE WHEEL (build -> bare venv -> install -> smoke)
################################################################################

# Build the pure-Python wheel from a COPY of sdk/python under
# $PY_WHEEL_DIR (setuptools writes build/ and *.egg-info next to the
# sources, and the gate must leave the worktree clean). Idempotent: a
# second call returns the wheel already built in this run. Sets
# PY_WHEEL_FILE on success; returns 1 (PY_WHEEL_FILE empty) on failure,
# with the log at $PY_WHEEL_DIR/build.log.
PY_WHEEL_FILE=""
build_python_wheel() {
    if [[ -n "$PY_WHEEL_FILE" && -f "$PY_WHEEL_FILE" ]]; then
        return 0
    fi
    PY_WHEEL_FILE=""
    command -v python3 &>/dev/null || return 1
    local src="$PY_WHEEL_DIR/src" dist="$PY_WHEEL_DIR/dist"
    rm -rf "$PY_WHEEL_DIR"
    mkdir -p "$src" "$dist"
    cp -r "$PY_SDK_DIR/hdds" "$src/hdds"
    # pyproject.toml declares license-files; the wheel must carry both texts.
    cp "$PY_SDK_DIR/pyproject.toml" "$PY_SDK_DIR/README.md" \
       "$PY_SDK_DIR/LICENSE-APACHE" "$PY_SDK_DIR/LICENSE-MIT" "$src/"
    find "$src" -name '__pycache__' -type d -prune -exec rm -rf {} +
    local build_log="$PY_WHEEL_DIR/build.log"
    local wheel
    if python3 -m pip wheel --no-build-isolation --no-deps --no-index -w "$dist" "$src" > "$build_log" 2>&1 \
        && wheel="$(ls "$dist"/hdds-*-py3-none-any.whl 2>/dev/null | head -1)" && [[ -n "$wheel" ]]; then
        PY_WHEEL_FILE="$wheel"
        return 0
    fi
    return 1
}

# Interpreters the package CLAIMS (pyproject.toml classifiers
# "Programming Language :: Python :: 3.N"). Each claimed version must be
# on PATH as python3.N and pass the installed smoke; a claim the gate cannot
# run is a failure (ZERO BULLSHIT applies to metadata).
claimed_python_versions() {
    grep -oE 'Programming Language :: Python :: 3\.[0-9]+' "$PY_SDK_DIR/pyproject.toml" \
        | sed 's/.*:: //' | sort -uV
}

# Run one interpreter through venv -> install -> smoke -> fail-closed.
python_wheel_for_interpreter() {
    local py="$1" wheel="$2"
    local tag venv
    tag="$("$py" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    venv="$PY_WHEEL_DIR/venv-$tag"
    rm -rf "$venv"

    log_info "Interpreter $py ($("$py" --version 2>&1))"

    if ! "$py" -m venv "$venv" >/dev/null 2>&1; then
        log_fail "python $tag: venv creation failed (python3-venv / ensurepip missing?)"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        return
    fi
    local vpy="$venv/bin/python"

    local install_log="$PY_WHEEL_DIR/install-$tag.log"
    if "$vpy" -m pip install --no-index --no-deps "$wheel" > "$install_log" 2>&1; then
        log_pass "python $tag: wheel installed in bare venv"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "python $tag: wheel install failed (see $install_log)"
        tail -5 "$install_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
        return
    fi

    # Positive smoke: cwd=/ so the source tree cannot leak into sys.path;
    # HDDS_LIB_PATH is the only way the installed package finds the library.
    local smoke_log="$PY_WHEEL_DIR/smoke-$tag.log"
    if (cd / && env -u LD_LIBRARY_PATH -u PYTHONPATH HDDS_LIB_PATH="$LIB_PATH" PYTHONDONTWRITEBYTECODE=1 \
            "$vpy" "$PY_SDK_DIR/tests/smoke_installed.py") > "$smoke_log" 2>&1; then
        log_pass "python $tag: installed smoke: site-packages import + version + intra-process roundtrip"
        LAYER_PASS=$((LAYER_PASS + 1))
        grep '^SMOKE OK' "$smoke_log" | sed 's/^/    /'
    else
        log_fail "python $tag: installed smoke failed (see $smoke_log)"
        tail -8 "$smoke_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # Fail-closed: HDDS_LIB_PATH on an empty directory is the ONLY candidate
    # (strict override), so this is hermetic even on a host that has
    # libhdds_c.so in /usr/lib or on the linker path. Loading is LAZY:
    # "import hdds" itself succeeds, and smoke_installed.py --expect-import-error
    # asserts that the first native call raises.
    local empty="$PY_WHEEL_DIR/empty-lib-dir"
    mkdir -p "$empty"
    local closed_log="$PY_WHEEL_DIR/fail-closed-$tag.log"
    if (cd / && env -u LD_LIBRARY_PATH -u PYTHONPATH HDDS_LIB_PATH="$empty" PYTHONDONTWRITEBYTECODE=1 \
            "$vpy" "$PY_SDK_DIR/tests/smoke_installed.py" --expect-import-error) > "$closed_log" 2>&1; then
        log_pass "python $tag: first native call fails closed without library (HDDS_LIB_PATH=empty dir)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "python $tag: the first native call did NOT fail closed (see $closed_log)"
        tail -5 "$closed_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi
}

layer_python_wheel() {
    log_section "LAYER 1b: PYTHON INSTALLABLE WHEEL"
    reset_layer_counters

    if ! command -v python3 &>/dev/null; then
        log_fail "python3 not available -- cannot build the wheel"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1b (Python wheel)"
        return
    fi

    if [[ ! -f "$LIB_PATH/libhdds_c.so" ]]; then
        log_fail "libhdds_c.so missing at $LIB_PATH (build it: cargo build --release -p hdds-c)"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1b (Python wheel)"
        return
    fi

    # Host prerequisite, stated explicitly (same class as needing cargo):
    # --no-build-isolation uses the host's setuptools.
    local st_version
    if ! st_version="$(python3 -c 'import setuptools; print(setuptools.__version__)' 2>/dev/null)"; then
        log_fail "setuptools not importable by python3; install python3-setuptools (>= $PY_MIN_SETUPTOOLS) to build the wheel offline"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1b (Python wheel)"
        return
    fi
    if [[ "${st_version%%.*}" -lt "$PY_MIN_SETUPTOOLS" ]]; then
        log_fail "setuptools $st_version too old (need >= $PY_MIN_SETUPTOOLS for SPDX licence metadata)"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1b (Python wheel)"
        return
    fi
    log_info "setuptools $st_version (host), pip $(python3 -m pip --version 2>/dev/null | awk '{print $2}')"

    # One wheel per gate run (built in Layer 1 when it ran, else here).
    local wheel
    if build_python_wheel; then
        wheel="$PY_WHEEL_FILE"
        log_pass "wheel built: $(basename "$wheel") ($PY_WHEEL_DIR/dist)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "wheel build failed (see $PY_WHEEL_DIR/build.log)"
        tail -5 "$PY_WHEEL_DIR/build.log" 2>/dev/null | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1b (Python wheel)"
        return
    fi

    # The wheel file name carries the package version; it must be the
    # workspace version (Layer 1 checks __init__.py, this checks the artefact).
    local ws
    ws="$(workspace_version)"
    if [[ "$(basename "$wheel")" == "hdds-${ws}-py3-none-any.whl" ]]; then
        log_pass "wheel version is the workspace version ($ws)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "wheel $(basename "$wheel") does not carry the workspace version $ws"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # No classifier at all must reach the log_fail below, not abort the run
    # under `set -e` (the report would never be written).
    local claimed
    claimed="$(claimed_python_versions || true)"
    if [[ -z "$claimed" ]]; then
        log_fail "pyproject.toml claims no 'Programming Language :: Python :: 3.N' classifier"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi
    local ver py
    for ver in $claimed; do
        py="$(command -v "python${ver}" || true)"
        if [[ -z "$py" ]]; then
            log_fail "python $ver is claimed by pyproject.toml classifiers but python${ver} is not on PATH (provision it or drop the claim)"
            LAYER_FAIL=$((LAYER_FAIL + 1))
            continue
        fi
        python_wheel_for_interpreter "$py" "$wheel"
    done

    layer_summary "Layer 1b (Python wheel)"
}

################################################################################
# LAYER 1c: TYPESCRIPT SDK (version + vitest: logic, native FFI, samples)
################################################################################

# package.json version from sdk/typescript.
typescript_package_version() {
    node -e 'process.stdout.write(require(process.argv[1]).version)' \
        "$TS_SDK_DIR/package.json" 2>/dev/null
}

# Every SDK carries the workspace version. Layer 1 enforces
# it for Python, this is the same check for TypeScript.
check_typescript_version_matches_workspace() {
    local ws ts
    # Both helpers are documented to yield an empty string on failure; the
    # `|| true` is what makes that true under set -e.
    ws="$(workspace_version || true)"
    ts="$(typescript_package_version || true)"
    if [[ -z "$ws" || -z "$ts" ]]; then
        log_fail "typescript version check: could not read workspace ('$ws') or package ('$ts') version"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    elif [[ "$ws" == "$ts" ]]; then
        log_pass "typescript package version == workspace version ($ts)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "typescript package version $ts != workspace version $ws (run scripts/bump-version.sh, which rewrites package.json and package-lock.json with Cargo.toml)"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi
}

layer_typescript() {
    log_section "LAYER 1c: TYPESCRIPT SDK TESTS"
    reset_layer_counters

    if ! command -v node &>/dev/null || ! command -v npm &>/dev/null; then
        log_fail "node/npm not available -- cannot run the TypeScript suite"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1c (TypeScript)"
        return
    fi
    if [[ ! -d "$TS_SDK_DIR/node_modules" ]]; then
        log_fail "sdk/typescript/node_modules missing -- Layer 0f did not run or failed"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1c (TypeScript)"
        return
    fi
    if [[ -n "$TS_NPM_CI_MODE" ]]; then
        log_info "npm dependency restore path: $TS_NPM_CI_MODE"
    fi

    check_typescript_version_matches_workspace

    # hdds-ws drives the announced WebSocket-bridge sample. It is a workspace
    # member, so a missing binary is a build failure, not a reason to skip.
    local ws_bin="$LIB_PATH/hdds-ws"
    if [[ ! -x "$ws_bin" ]]; then
        log_info "Building hdds-ws (samples/ws_bridge.ts drives it)..."
        # Guarded like every other cargo call in this file: an unguarded
        # pipeline aborts the gate under set -e and the log_fail below, which
        # is the real verdict, would never be reached.
        if ! cargo build --release -p hdds-ws --manifest-path="$ROOT/Cargo.toml" 2>&1 | tail -2; then
            log_info "hdds-ws build failed (see the two lines above)"
        fi
    fi
    if [[ -x "$ws_bin" ]]; then
        log_pass "hdds-ws present (ws_bridge sample can run)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "hdds-ws not built at $ws_bin -- the ws_bridge sample cannot be proven"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # HDDS_LIB_PATH is the loader's explicit override: tests/native.test.ts
    # THROWS when it is set and holds no libhdds_c.so, so a broken library
    # fails the layer instead of skipping it.
    local vitest_log="/tmp/hdds_vitest_$$.log"
    log_info "Running vitest in sdk/typescript/tests (HDDS_LIB_PATH=$LIB_PATH)..."
    local vitest_exit=0
    (
        cd "$TS_SDK_DIR"
        env -u LD_LIBRARY_PATH HDDS_LIB_PATH="$LIB_PATH" HDDS_WS_BIN="$ws_bin" \
            npx vitest run --reporter=verbose 2>&1
    ) > "$vitest_log" 2>&1 || vitest_exit=$?

    # vitest's trailing tally is authoritative. The line is the LAST one that
    # starts with "Tests" and lists the outcomes in whatever order they
    # occurred: "Tests  36 passed (36)", "Tests  3 failed | 10 passed (13)",
    # "Tests  17 passed | 17 skipped (34)". Read <count> <outcome> pairs off
    # that one line instead of matching a fixed order.
    local ts_line ts_passed ts_failed ts_skipped ts_total
    # `|| true`: no match is a REAL outcome (vitest prints no "Tests" line
    # when it finds no test files), and pipefail would otherwise abort the
    # whole gate here, before the `ts_total -eq 0` check written for it.
    ts_line="$(grep -E '^[[:space:]]*Tests[[:space:]]+[0-9]' "$vitest_log" | tail -1 || true)"
    ts_tally() {
        awk -v want="$1" '{for (i = 2; i <= NF; i++) if ($i == want) { print $(i - 1); exit } } END { }' <<< "$ts_line"
    }
    ts_passed="$(ts_tally passed)"
    ts_failed="$(ts_tally failed)"
    ts_skipped="$(ts_tally skipped)"
    ts_passed=${ts_passed:-0}
    ts_failed=${ts_failed:-0}
    ts_skipped=${ts_skipped:-0}
    ts_total=$((ts_passed + ts_failed + ts_skipped))

    # A skipped test is evidence that did NOT run (the certificate wants 0
    # skips), so it reaches the tally rather than being erased into a pass.
    LAYER_SKIP=$((LAYER_SKIP + ts_skipped))
    LAYER_PASS=$((LAYER_PASS + ts_passed))

    if [[ $vitest_exit -eq 0 ]]; then
        log_pass "vitest: ${ts_passed}/${ts_total} tests passed (${ts_skipped} skipped)"
    else
        log_fail "vitest: ${ts_failed} failed, ${ts_skipped} skipped (exit code $vitest_exit)"
        # `|| true`: a failure whose message shape does not match (worker
        # crash, timeout kill) must not abort the layer before the tally below.
        { grep -E '^\s+.\s+.*>|AssertionError|Error:' "$vitest_log" 2>/dev/null | head -12 \
            | while IFS= read -r line; do
                echo "    $line"
                report "    $line"
            done; } || true
        LAYER_FAIL=$((LAYER_FAIL + ts_failed))
        # A non-zero exit with no parsed failure must still close the gate.
        # Written as `if` and not `A && B`: as the last command of this branch
        # `A && B` returns 1 whenever ts_failed != 0 and set -e kills the run.
        if [[ $ts_failed -eq 0 ]]; then
            LAYER_FAIL=$((LAYER_FAIL + 1))
        fi
    fi

    if [[ $ts_skipped -gt 0 ]]; then
        log_skip "vitest: ${ts_skipped} test(s) skipped (they are not evidence)"
    fi

    # The shipped SDK could not load at all before 1.5.0 and no test noticed,
    # because the only suite ran without the library. An empty run must fail.
    if [[ $ts_total -eq 0 ]]; then
        log_fail "vitest: no tests found"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    rm -f "$vitest_log"
    layer_summary "Layer 1c (TypeScript)"
}

################################################################################
# LAYER 1d: TYPESCRIPT INSTALLABLE TARBALL (npm pack -> install -> smoke)
################################################################################

# @hdds/client is not published to npm yet. The artefact is still BUILT and gated here, so publishing later is one
# manual command and not a leap of faith.
layer_typescript_pack() {
    log_section "LAYER 1d: TYPESCRIPT INSTALLABLE TARBALL"
    reset_layer_counters

    if ! command -v npm &>/dev/null; then
        log_fail "npm not available -- cannot build the tarball"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1d (TypeScript pack)"
        return
    fi
    if [[ ! -f "$TS_SDK_DIR/dist/index.js" ]]; then
        log_fail "sdk/typescript/dist/index.js missing -- Layer 0f did not build the SDK"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1d (TypeScript pack)"
        return
    fi

    rm -rf "$TS_PACK_DIR"
    mkdir -p "$TS_PACK_DIR/dist" "$TS_PACK_DIR/app"

    local pack_log="$TS_PACK_DIR/pack.log" tarball=""
    if (cd "$TS_SDK_DIR" && npm pack --pack-destination "$TS_PACK_DIR/dist") > "$pack_log" 2>&1; then
        tarball="$(ls "$TS_PACK_DIR"/dist/*.tgz 2>/dev/null | head -1)"
    fi
    if [[ -z "$tarball" ]]; then
        log_fail "npm pack produced no tarball (see $pack_log)"
        tail -5 "$pack_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1d (TypeScript pack)"
        return
    fi
    log_pass "npm pack: $(basename "$tarball")"
    LAYER_PASS=$((LAYER_PASS + 1))

    # The file name carries the package version; it must be the workspace one.
    local ws
    ws="$(workspace_version)"
    if [[ "$(basename "$tarball")" == "hdds-client-${ws}.tgz" ]]; then
        log_pass "tarball version is the workspace version ($ws)"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "tarball $(basename "$tarball") does not carry the workspace version $ws"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # package.json "files" claims dist + README + both licence texts. A claim
    # nobody checks is how the LICENSE entry survived pointing at a file that
    # did not exist.
    local listing missing=""
    listing="$(tar -tzf "$tarball")"
    local entry
    for entry in package/dist/index.js package/dist/index.d.ts package/README.md \
                 package/LICENSE-APACHE package/LICENSE-MIT; do
        grep -qx "$entry" <<< "$listing" || missing="$missing $entry"
    done
    if [[ -z "$missing" ]]; then
        log_pass "tarball carries dist/, README.md and both licence texts"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "tarball is missing:$missing"
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # Install into a scratch project OUTSIDE the worktree and run the package
    # the way a consumer would: resolved from node_modules, not from src/.
    local app="$TS_PACK_DIR/app"
    printf '{"name":"hdds-pack-smoke","version":"1.0.0","private":true}\n' > "$app/package.json"
    local install_log="$TS_PACK_DIR/install.log"
    if (cd "$app" && npm install --no-save --no-audit --no-fund --offline "$tarball") > "$install_log" 2>&1 \
        || (cd "$app" && npm install --no-save --no-audit --no-fund "$tarball") >> "$install_log" 2>&1; then
        log_pass "tarball installed into a scratch project"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "npm install of the tarball failed (see $install_log)"
        tail -5 "$install_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
        layer_summary "Layer 1d (TypeScript pack)"
        return
    fi

    cat > "$app/smoke.js" <<'SMOKE'
// Consumer view of the package: resolved from node_modules through the
// exports map, never from sdk/typescript/src.
const hdds = require("@hdds/client");
const path = require("path");
const resolved = require.resolve("@hdds/client");
if (!resolved.includes(path.join("node_modules", "@hdds", "client"))) {
  console.error(`FAIL: resolved outside node_modules: ${resolved}`);
  process.exit(1);
}
if (process.argv[2] === "--expect-load-error") {
  try {
    hdds.version();
  } catch (e) {
    console.log(`SMOKE OK: fail-closed (${e.constructor.name})`);
    process.exit(0);
  }
  console.error("FAIL: version() succeeded without a library");
  process.exit(1);
}
const p = hdds.Participant.create("pack_smoke", {
  transport: hdds.TransportMode.INTRA_PROCESS,
});
const qos = hdds.QoS.reliable().transientLocal().historyDepth(4);
const w = p.createWriter("PackSmoke", qos);
const r = p.createReader("PackSmoke", qos);
const ws = new hdds.WaitSet();
ws.attachReader(r);
w.write(Buffer.from("pack-smoke"));
if (!ws.wait(5.0)) {
  console.error("FAIL: waitset timed out");
  process.exit(1);
}
const got = r.take();
if (got === null || got.toString() !== "pack-smoke") {
  console.error(`FAIL: got ${got}`);
  process.exit(1);
}
ws.dispose();
p.dispose();
console.log(`SMOKE OK: ${hdds.version()} round trip from ${resolved}`);
SMOKE

    local smoke_log="$TS_PACK_DIR/smoke.log"
    if (cd "$app" && env -u LD_LIBRARY_PATH HDDS_LIB_PATH="$LIB_PATH" \
            node smoke.js) > "$smoke_log" 2>&1; then
        log_pass "installed smoke: node_modules resolution + intra-process round trip"
        LAYER_PASS=$((LAYER_PASS + 1))
        grep '^SMOKE OK' "$smoke_log" | sed 's/^/    /'
    else
        log_fail "installed smoke failed (see $smoke_log)"
        tail -8 "$smoke_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    # Fail-closed: HDDS_LIB_PATH pointing at an empty directory is only the
    # FIRST candidate for the TypeScript loader (unlike Python's strict
    # override), so the check also clears LD_LIBRARY_PATH and runs from a
    # scratch directory with no target/ above it.
    local empty="$TS_PACK_DIR/empty-lib-dir"
    mkdir -p "$empty"
    local closed_log="$TS_PACK_DIR/fail-closed.log"
    if (cd "$app" && env -u LD_LIBRARY_PATH HDDS_LIB_PATH="$empty" \
            node smoke.js --expect-load-error) > "$closed_log" 2>&1; then
        log_pass "package fails closed without libhdds_c.so"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "the package did NOT fail closed without a library (see $closed_log)"
        tail -5 "$closed_log" | sed 's/^/    /'
        LAYER_FAIL=$((LAYER_FAIL + 1))
    fi

    layer_summary "Layer 1d (TypeScript pack)"
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
        rust)   [[ -f "$RUST_BIN" ]] ;;
        c)      [[ -n "$C_BIN" && -f "$C_BIN" ]] ;;
        cpp)    [[ -n "$CPP_BIN" && -f "$CPP_BIN" ]] ;;
        python) command -v python3 &>/dev/null ;;
        typescript) [[ -n "$TS_CMD" && -f "$TS_XLANG_DIR/test.js" ]] ;;
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

    # Start subscriber first (background). HDDS_LIB_PATH for the Python SDK
    # loader (strict override), LD_LIBRARY_PATH for binaries linked -lhdds_c.
    HDDS_LIB_PATH="$LIB_PATH" LD_LIBRARY_PATH="$LIB_PATH" $sub_cmd > "$sub_log" 2>&1 &
    local sub_pid=$!

    # Give subscriber time to start and begin discovery
    sleep 1

    # Start publisher
    HDDS_LIB_PATH="$LIB_PATH" LD_LIBRARY_PATH="$LIB_PATH" $pub_cmd > "$pub_log" 2>&1 &
    local pub_pid=$!

    # Wait for publisher (with timeout -- should finish in ~3s)
    local pub_ok=true
    local pub_waited=0
    while kill -0 "$pub_pid" 2>/dev/null; do
        sleep 1
        pub_waited=$((pub_waited + 1))
        if [[ $pub_waited -ge $SUB_TIMEOUT ]]; then
            kill -9 "$pub_pid" 2>/dev/null || true
            wait "$pub_pid" 2>/dev/null || true
            pub_ok=false
            break
        fi
    done
    if $pub_ok && ! wait "$pub_pid" 2>/dev/null; then
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

    if $sub_ok && ! wait "$sub_pid" 2>/dev/null; then
        sub_ok=false
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

    local LANGS=(rust c cpp python typescript)

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

    local LANGS=(rust c cpp python typescript)

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
# Python-only fast path (Layer 0a + Layer 1 + Layer 1b through the same helpers)
################################################################################

run_python_only() {
    log_section "LAYER 0: BUILD VERIFICATION (python-only: hdds-c)"
    reset_layer_counters

    if $DO_BUILD; then
        log_info "Building hdds-c shared library (release)..."
        if ! cargo build --release -p hdds-c --manifest-path="$ROOT/Cargo.toml" 2>&1 | tail -1; then
            log_fail "cargo build hdds-c failed"
            LAYER_FAIL=$((LAYER_FAIL + 1))
            BUILD_FAILURES=$((BUILD_FAILURES + 1))
        fi
    fi
    if [[ -f "$LIB_PATH/libhdds_c.so" ]]; then
        log_pass "libhdds_c.so present at $LIB_PATH"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "libhdds_c.so missing at $LIB_PATH"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
    fi
    layer_summary "Layer 0 (Build)"

    hash_binaries
    layer_python
    layer_python_wheel

    print_summary
    write_report
    exit $((TOTAL_FAIL + BUILD_FAILURES))
}

################################################################################
# TypeScript-only fast path (Layer 0a + 0f + Layer 1c + Layer 1d)
################################################################################

run_typescript_only() {
    log_section "LAYER 0: BUILD VERIFICATION (typescript-only: hdds-c + SDK)"
    reset_layer_counters

    if $DO_BUILD; then
        log_info "Building hdds-c shared library (release)..."
        if ! cargo build --release -p hdds-c --manifest-path="$ROOT/Cargo.toml" 2>&1 | tail -1; then
            log_fail "cargo build hdds-c failed"
            LAYER_FAIL=$((LAYER_FAIL + 1))
            BUILD_FAILURES=$((BUILD_FAILURES + 1))
        fi
    fi
    if [[ -f "$LIB_PATH/libhdds_c.so" ]]; then
        log_pass "libhdds_c.so present at $LIB_PATH"
        LAYER_PASS=$((LAYER_PASS + 1))
    else
        log_fail "libhdds_c.so missing at $LIB_PATH"
        LAYER_FAIL=$((LAYER_FAIL + 1))
        BUILD_FAILURES=$((BUILD_FAILURES + 1))
    fi
    build_typescript_sdk
    layer_summary "Layer 0 (Build)"

    hash_binaries
    layer_typescript
    layer_typescript_pack

    print_summary
    write_report
    exit $((TOTAL_FAIL + BUILD_FAILURES))
}

################################################################################
# Main
################################################################################

main() {
    parse_args "$@"

    echo -e "${BOLD}HDDS SDK Verification Gate v2.1.0${NC}"
    echo -e "${BOLD}$(date -u '+%Y-%m-%dT%H:%M:%SZ')${NC}"
    echo ""

    report "HDDS SDK Verification Gate v2.1.0"
    report "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    print_environment

    # Python-only fast path (exits with the failure count)
    if $PYTHON_ONLY; then
        run_python_only
    fi

    # TypeScript-only fast path (exits with the failure count)
    if $TYPESCRIPT_ONLY; then
        run_typescript_only
    fi

    # Full verification pipeline
    layer_build
    hash_binaries
    layer_python
    layer_python_wheel
    layer_native_listeners
    layer_typescript
    layer_typescript_pack
    layer_same_lang
    layer_cross_lang

    # Summary + report
    print_summary
    write_report

    # Exit code = number of failures
    exit $((TOTAL_FAIL + BUILD_FAILURES))
}

main "$@"
