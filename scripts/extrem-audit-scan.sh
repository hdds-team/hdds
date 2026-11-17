#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com


################################################################################
# HDDS EXTREME AUDIT SCANNER - Military Grade Code Quality
# Version: 1.1.0-ULTRA-HARDENED
#
# ZERO TOLERANCE POLICY - This script blocks EVERYTHING suspicious
#
# Compliance targets:
# - ANSSI/IGI-1300 (French military certification)
# - Common Criteria EAL4+
# - MISRA-C++ 2008
# - OMG DDS/RTPS v2.5
# - DO-178C Level B
# - ISO 26262 ASIL-D
#
# New in v1.1.0:
# - Ultra-hardened Clippy with ALL lints (indexing_slicing, empty_drop, etc.)
# - cargo-geiger unsafe budget monitoring
# - Swallowed results detection (_ = expr; patterns)
# - cargo-udeps unused dependencies detection
# - Secrets scanning (passwords, tokens, API keys)
#
# Exit codes:
#  0 = Passed (perfect, or within the acceptance policy)
#  1 = Violations above the acceptance policy
#  2 = Degraded scan: a required tool was missing, so some check groups never
#      ran. Never treat this as a pass.
#
# Note: the exit status deliberately does NOT carry the violation count any
# more. Shell exit codes wrap modulo 256, so a count of exactly 256 was
# reported to the caller as success. Counts are in the summary output.
################################################################################

set -euo pipefail

# Terminal colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly SRC_DIR="${PROJECT_ROOT}/crates/hdds/src"
readonly TOOLS_DIR="${PROJECT_ROOT}/tools"
# Service crates scanned in addition to the engine (SRC_DIR), so a FIXME or an
# unsafe block without a SAFETY comment cannot sit in them unseen. Directories
# that do not exist are skipped, so the scanner still runs on a partial
# checkout.
readonly SERVICE_CRATE_DIRS=(
    "${PROJECT_ROOT}/crates/hdds-wasm/src"
    "${PROJECT_ROOT}/crates/hdds-xrce/src"
    "${PROJECT_ROOT}/crates/hdds-xrce-client/src"
    "${PROJECT_ROOT}/crates/hdds-schema-registry/src"
    "${PROJECT_ROOT}/crates/hdds-influx-sink/src"
)
readonly REPORT_DIR="${PROJECT_ROOT}/target/audit-reports"
export PATH="${PROJECT_ROOT}/tools/bin:${PATH}"

# cargo's target directory. CARGO_TARGET_DIR (or build.target-dir in a cargo
# config) moves cargo's output away from ${PROJECT_ROOT}/target, so every path
# this audit reads from cargo's output goes through here. Prints the resolved
# absolute path. Falls back to CARGO_TARGET_DIR, then to ${PROJECT_ROOT}/target.
audit_target_dir() {
    local meta dir=""
    meta=$(cd "$PROJECT_ROOT" && cargo metadata --format-version 1 --no-deps 2>/dev/null) || meta=""
    if [[ -n "$meta" ]] && command -v jq >/dev/null 2>&1; then
        dir=$(printf '%s' "$meta" | jq -r '.target_directory // empty' 2>/dev/null) || dir=""
    fi
    [[ -n "$dir" ]] || dir="${CARGO_TARGET_DIR:-${PROJECT_ROOT}/target}"
    case "$dir" in
        /*) ;;
        *) dir="${PROJECT_ROOT}/${dir}" ;;
    esac
    printf '%s\n' "$dir"
}

# Scan target (set by main() based on --file flag)
SCAN_TARGET=""
SINGLE_FILE_MODE=0
# In full project mode, we scan multiple directories
SCAN_TARGETS=("$SRC_DIR")

# Counters
TOTAL_VIOLATIONS=0
CRITICAL_VIOLATIONS=0
HIGH_VIOLATIONS=0
MEDIUM_VIOLATIONS=0
LOW_VIOLATIONS=0
SUPPRESSED_COUNT=0

# Configuration
readonly MAX_COMPLEXITY=20  # McCabe cyclomatic complexity
readonly MAX_COGNITIVE=30   # Cognitive complexity (nested conditionals)
# HDDS is a zero-copy DDS/RTPS implementation requiring unsafe for:
# - Lock-free ring buffers (SPSC/MPSC)
# - Custom memory pools (SlabPool)
# - Raw socket multicast operations
# - CDR2 serialization with alignment
# Every unsafe block must carry a SAFETY justification (enforced by Layer 3);
# the ceiling below bounds the audited population, it is not an aspiration.
# Reference point for the ceiling: `rg -c 'unsafe\s*\{' crates/hdds/src`.
readonly MAX_UNSAFE_BLOCKS=250  # Realistic for FFI (C/ROS2) + transport (SHM/TSN/sockets)
readonly MAX_FUNCTION_LINES=100  # Allow complex protocol handlers
# Counted in CODE lines: the file's own test module, its comments and its blank
# lines are all excluded (see LAYER 4). The threshold is set for code lines
# only: keeping a threshold calibrated for raw lines would loosen the gate in
# silence.
readonly MAX_FILE_LINES=600
readonly MIN_TEST_COVERAGE=90  # Minimum 90% coverage
readonly MAX_DUPLICATION_PERCENT=8.0  # Allow test code similarity + constants re-export
# Acceptance policy. The MEDIUM ceiling is set to the currently measured value
# (mostly function complexity): it may only go down, and any run above it
# FAILS. Reducing it is planned work.
readonly MAX_MEDIUM_ACCEPTED=240
readonly MAX_LOW_ACCEPTED=49      # Acceptance policy: strictly < 50

# Optional switches (can also be set via env)
SKIP_VALIDATION_GATES="${AUDIT_SKIP_VALIDATION_GATES:-0}"
VERBOSE="${AUDIT_VERBOSE:-0}"

# Integrity of the audit run itself.
# A check that could not execute is NOT a check that passed. Any missing tool
# is recorded here and downgrades the final verdict, so that a degraded scan can
# never be mistaken for a clean one.
SKIPPED_CHECKS=0
SKIPPED_TOOLS=""

# Timing
SCAN_START_TIME=""
LAYER_START_TIME=""

################################################################################
# Helper Functions
################################################################################

# Files the crate reaches ONLY through a test-gated module declaration are not
# compiled into the shipped library, so a finding inside one is not a finding
# about the product. Reporting them as production defects is how an audit stops
# being listened to (for example a `panic!()` "in production code" inside a
# `#[cfg(test)] mod probes;`).
#
# Decided from the DECLARATION, never from the file name:
#   #[cfg(test)] mod x;                     -> test only
#   #[cfg(all(test, feature = "f"))] mod x; -> test only, `test` is required
#   #[cfg(any(test, feature = "f"))] mod x; -> NOT test only, the feature ships it
# `#[path = "..."]` between the attribute and the declaration is honoured, and a
# directory module makes every file beneath it test-only as well.
#
# Nothing is dropped silently: what this filters is counted and printed.
TEST_ONLY_PATHS=""
TEST_ONLY_FILTERED=0

# The other half of the same idea, at LINE granularity.
#
# A `#[cfg(test)] mod tests { ... }` block inside an otherwise production file
# is not compiled into the shipped library either, but the path index above
# works per FILE and cannot see it. Findings inside such a block were still
# reported as product defects.
#
# Each entry is `file|start|end`, covering the attribute line through the
# block's closing brace. The brace counter deliberately fails SAFE: a block
# whose end cannot be determined (unbalanced at end of file) is DROPPED from
# the index, so an undecidable case filters nothing rather than hiding a real
# finding. Strings, char literals and comments are stripped before counting,
# because a `"{"` in a message would otherwise push the end of the block past
# the real one and start hiding production code.
TEST_ONLY_RANGES=""


build_test_only_index() {
    local root ranges
    TEST_ONLY_PATHS=""
    TEST_ONLY_RANGES=""

    # The pre-commit hook runs this scanner ONCE PER STAGED FILE, and this
    # index is whole-tree whatever single file is being scanned: two `awk`
    # forks for every `.rs` file in the project, paid again in full for each
    # file of the commit. Scanning scope and classification scope are two
    # different things -- that is stated above and it is right -- but the COST
    # followed the classification scope while the loop followed the scanning
    # one, so a thirteen-file commit built the same index thirteen times.
    #
    # When the caller hands us a cache directory, the index is computed for
    # the first file and read back for the rest. There is deliberately NO
    # invalidation: the cache lives for one run of the hook, during which the
    # tree does not change. It is a way of not asking the same question
    # thirteen times in one second, never a way of remembering an answer.
    #
    # Round-trip safety: both variables are consumed with `<<<` by
    # `is_test_only_path` / `is_test_only_line`, which skip empty lines, so
    # the trailing newline that `$(cat)` strips carries no meaning. A cache
    # that fails to WRITE simply costs the next file a rebuild; a cache that
    # reads back EMPTY yields an empty index, which reports test code as
    # production code -- noisy and visible, never a silent clearance.
    local cache_paths="" cache_ranges=""
    if [[ -n "${HDDS_AUDIT_CACHE:-}" ]]; then
        cache_paths="$HDDS_AUDIT_CACHE/test-only-paths"
        cache_ranges="$HDDS_AUDIT_CACHE/test-only-ranges"
        if [[ -f "$cache_paths" ]] && [[ -f "$cache_ranges" ]]; then
            TEST_ONLY_PATHS="$(cat "$cache_paths")"
            TEST_ONLY_RANGES="$(cat "$cache_ranges")"
            return 0
        fi
    fi

    for root in "$@"; do
        [[ -d "$root" ]] || continue
        # ONE awk for the whole root, not one per file: forking two awk
        # processes and a `dirname` subshell for every `.rs` in the project is
        # far too slow, especially from the pre-commit hook.
        #
        # `FNR==1` resets the per-file state, and the file name now travels in
        # the record rather than in the loop, so the shell does the `dirname`
        # with a parameter expansion instead of a subshell.
        while IFS='|' read -r decl_file modname pathattr; do
            [[ -n "$modname" ]] || continue
            local dir="${decl_file%/*}"
            local target=""
            if [[ -n "$pathattr" ]]; then
                target="$dir/$pathattr"
            elif [[ -f "$dir/$modname.rs" ]]; then
                target="$dir/$modname.rs"
            elif [[ -d "$dir/$modname" ]]; then
                target="$dir/$modname/"
            fi
            [[ -n "$target" ]] && TEST_ONLY_PATHS+="$target"$'\n'
        done < <(find "$root" -name '*.rs' -type f -print0 2>/dev/null | xargs -0 -r awk '
                FNR==1 { armed=0; path="" }
                /^[[:space:]]*#\[cfg\(test\)\]/                      { armed=1; path=""; next }
                /^[[:space:]]*#\[cfg\(all\(/ && /[^a-z_]test[^a-z_]/ { armed=1; path=""; next }
                armed && match($0, /^[[:space:]]*#\[path[[:space:]]*=[[:space:]]*"([^"]+)"\]/, p) {
                    path=p[1]; next
                }
                armed && /^[[:space:]]*#\[/ { next }
                armed && match($0, /^[[:space:]]*(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?mod[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;/, m) {
                    print FILENAME "|" m[3] "|" path; armed=0; path=""; next
                }
                { armed=0; path="" }
            ')

        # Second pass over the same files: inline test blocks, by line range.
        # Also one awk for the whole root. Two things make that safe and both
        # are load-bearing:
        #
        #   * `FNR==1` resets `armed` AND the two string states of `strip()`.
        #     An unterminated raw string must not leak its state into the next
        #     file, which with one awk per file was free and here is not.
        #   * `getline` inside the brace counter can cross INTO the next file.
        #     With one awk per file that was simply end-of-input and the block
        #     was correctly not claimed; here the guard `FILENAME == startfile`
        #     reproduces that exactly. The residual difference is that lines of
        #     the following file get consumed by a runaway block, which can
        #     only happen on a `mod x {` that never closes - and such a file
        #     does not compile. Stated rather than hidden.
        #
        # The output was compared record for record against the previous
        # implementation before this replaced it: 53 paths and 382 ranges,
        # identical.
        ranges=$(find "$root" -name '*.rs' -type f -print0 2>/dev/null | xargs -0 -r awk '
                # Strings that SPAN LINES must be handled: a raw string
                # (r#"..."#) holding a JSON body in a test would otherwise
                # close the range early, and the panics in the rest of that
                # test module would be reported as production CRITICALs. Raw
                # strings are cut out first, across lines; then an ordinary
                # literal left open at the end of a line keeps swallowing
                # lines until its close.
                function strip(line,   out, i, j, rest) {
                    out = line
                    while (1) {
                        if (in_raw) {
                            j = index(out, "\"#")
                            if (j == 0) return ""
                            out = substr(out, j + 2); in_raw = 0
                        }
                        i = index(out, "r#\"")
                        if (i == 0) break
                        rest = substr(out, i + 3)
                        j = index(rest, "\"#")
                        if (j == 0) { in_raw = 1; return substr(out, 1, i - 1) }
                        out = substr(out, 1, i - 1) substr(rest, j + 2)
                    }
                    gsub(/\\./, "", out)                 # escaped chars first
                    if (in_str) {
                        j = index(out, "\"")
                        if (j == 0) return ""
                        out = substr(out, j + 1); in_str = 0
                    }
                    gsub(/"[^"]*"/, "\"\"", out)          # then string literals
                    j = index(out, "\"")
                    if (j > 0 && out !~ /"[^"]*"$/) {     # a literal left open
                        # only when an odd quote remains after pairing
                        n_q = gsub(/"/, "\"", out)
                        if (n_q % 2 == 1) { in_str = 1; out = substr(out, 1, index(out, "\"") - 1) }
                    }
                    gsub(/'"'"'[^'"'"']*'"'"'/, "", out)   # then char literals
                    gsub(/\/\*.*\*\//, "", out)         # single-line block comments
                    sub(/\/\/.*$/, "", out)              # then line comments
                    return out
                }
                # Per-file state, reset at every file boundary: the arm, and
                # both string states of strip().
                FNR==1 { armed=0; in_raw=0; in_str=0 }
                # Arm on a test-gated attribute, remember where it started.
                /^[[:space:]]*#\[cfg\(test\)\]/                      { armed=1; astart=FNR; next }
                /^[[:space:]]*#\[cfg\(all\(/ && /[^a-z_]test[^a-z_]/ { armed=1; astart=FNR; next }
                armed && /^[[:space:]]*#\[/ { next }
                # An inline block: `mod x {` rather than `mod x;`. The `;` form
                # is a separate FILE and the path index above owns it.
                armed && /^[[:space:]]*(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/ {
                    depth = 0
                    start = astart
                    startfile = FILENAME
                    line = strip($0)
                    n = gsub(/\{/, "{", line); depth += n
                    n = gsub(/\}/, "}", line); depth -= n
                    while (depth > 0 && (getline nextline) > 0) {
                        line = strip(nextline)
                        n = gsub(/\{/, "{", line); depth += n
                        n = gsub(/\}/, "}", line); depth -= n
                    }
                    # depth == 0 means the block closed; anything else means we
                    # ran off the end of the file and must NOT claim a range.
                    if (depth == 0 && FILENAME == startfile) {
                        print startfile "|" start "|" FNR
                    }
                    armed = 0; next
                }
                { armed = 0 }
            ')
        [[ -n "$ranges" ]] && TEST_ONLY_RANGES+="$ranges"$'\n'
    done

    if [[ -n "$cache_paths" ]]; then
        mkdir -p "$HDDS_AUDIT_CACHE" 2>/dev/null || true
        printf '%s' "$TEST_ONLY_PATHS" > "$cache_paths" 2>/dev/null || true
        printf '%s' "$TEST_ONLY_RANGES" > "$cache_ranges" 2>/dev/null || true
    fi
}

# True when `file:line` falls inside an inline `#[cfg(test)]` block.
is_test_only_line() {
    local candidate="$1" line="$2" entry rfile rstart rend
    [[ -n "$TEST_ONLY_RANGES" ]] || return 1
    [[ "$line" =~ ^[0-9]+$ ]] || return 1
    while IFS='|' read -r rfile rstart rend; do
        [[ -n "$rfile" ]] || continue
        [[ "$candidate" == "$rfile" ]] || continue
        if (( line >= rstart && line <= rend )); then
            return 0
        fi
    done <<< "$TEST_ONLY_RANGES"
    return 1
}

# True when `path` is a file the shipped library never compiles.
is_test_only_path() {
    local candidate="$1" entry
    [[ -n "$TEST_ONLY_PATHS" ]] || return 1
    while IFS= read -r entry; do
        [[ -n "$entry" ]] || continue
        if [[ "$entry" == */ ]]; then
            [[ "$candidate" == "$entry"* ]] && return 0
        else
            [[ "$candidate" == "$entry" ]] && return 0
        fi
    done <<< "$TEST_ONLY_PATHS"
    return 1
}

# A violation message starts with `<file>:<line> - ...` when it has a location.
# Messages without one (gate failures, tool problems) are never filtered.
violation_is_test_only() {
    # Two statements on purpose: in a single `local a=.. b=$a`, `a` is not yet
    # visible when `b` expands, and `set -u` turns that into a hard error.
    local first="${1%% *}"
    local file="${first%%:*}"
    local rest="${first#*:}"
    local line="${rest%%:*}"
    [[ "$file" == /* || "$file" == *".rs" ]] || return 1
    [[ -f "$file" ]] || return 1
    # Either the whole file is test-only (path index), or the finding sits
    # inside an inline `#[cfg(test)]` block in a production file (line index).
    if is_test_only_path "$file"; then
        ((TEST_ONLY_FILTERED++)) || true
        return 0
    fi
    if is_test_only_line "$file" "$line"; then
        ((TEST_ONLY_FILTERED++)) || true
        return 0
    fi
    return 1
}

log_critical() {
    violation_is_test_only "$*" && return
    echo -e "${RED}${BOLD}[CRITICAL]${NC} $*" >&2
    ((CRITICAL_VIOLATIONS++)) || true
    ((TOTAL_VIOLATIONS++)) || true
}

log_high() {
    violation_is_test_only "$*" && return
    echo -e "${RED}[HIGH]${NC} $*" >&2
    ((HIGH_VIOLATIONS++)) || true
    ((TOTAL_VIOLATIONS++)) || true
}

log_medium() {
    violation_is_test_only "$*" && return
    echo -e "${YELLOW}[MEDIUM]${NC} $*" >&2
    ((MEDIUM_VIOLATIONS++)) || true
    ((TOTAL_VIOLATIONS++)) || true
}

log_low() {
    violation_is_test_only "$*" && return
    echo -e "${CYAN}[LOW]${NC} $*" >&2
    ((LOW_VIOLATIONS++)) || true
    ((TOTAL_VIOLATIONS++)) || true
}

log_pass() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_section() {
    # Print elapsed time of previous layer (if any)
    if [[ -n "$LAYER_START_TIME" ]]; then
        local now elapsed
        now=$(date +%s)
        elapsed=$((now - LAYER_START_TIME))
        echo -e "  ${BLUE}(${elapsed}s)${NC}"
    fi
    LAYER_START_TIME=$(date +%s)

    echo ""
    echo -e "${BLUE}--------------------------------------------------------------${NC}"
    echo -e "${BLUE}${BOLD}> $*${NC}"
    echo -e "${BLUE}--------------------------------------------------------------${NC}"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_medium "Tool '$1' not installed. Some checks skipped."
        ((SKIPPED_CHECKS++)) || true
        SKIPPED_TOOLS="${SKIPPED_TOOLS:+$SKIPPED_TOOLS, }$1"
        return 1
    fi
    return 0
}

# Check if a line has @audit-ok suppression marker
# Usage: if is_suppressed "$file" "$line_num"; then skip; fi
# Checks the line itself and up to 6 lines above for // @audit-ok: <reason>
# (six, not three: see the comment inside)
is_suppressed() {
    local file="$1"
    local line_num="$2"

    if [[ ! -f "$file" ]] || [[ ! "$line_num" =~ ^[0-9]+$ ]]; then
        return 1  # Not suppressed (invalid input)
    fi

    # Six lines, not three. A suppression is only trustworthy when it carries
    # a REASON, and a reason is usually two or three lines of comment; with a
    # three-line window that explanation pushed the @audit-ok marker out of
    # range, the finding fired anyway, and the author's remaining options were
    # to delete their own explanation or skip the hook. One of those happened.
    local start=$((line_num > 6 ? line_num - 6 : 1))
    local context
    context=$(sed -n "${start},${line_num}p" "$file" 2>/dev/null || echo "")

    if echo "$context" | grep -qE '@audit-ok:|@audit-ignore:'; then
        ((SUPPRESSED_COUNT++)) || true
        return 0  # Suppressed
    fi
    return 1  # Not suppressed
}

# Get list of Rust files to audit (single file or directory scan)
get_target_files() {
    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        echo "$SCAN_TARGET"
    else
        # Scan multiple directories in full project mode
        find "$SRC_DIR" -name "*.rs" -type f -not -path "*/target/*"
        # Also scan tools/ directory for Rust code
        if [[ -d "$TOOLS_DIR" ]]; then
            find "$TOOLS_DIR" -name "*.rs" -type f -not -path "*/target/*"
        fi
        # And the announced service crates.
        local service_dir
        for service_dir in "${SERVICE_CRATE_DIRS[@]}"; do
            if [[ -d "$service_dir" ]]; then
                find "$service_dir" -name "*.rs" -type f -not -path "*/target/*"
            fi
        done
    fi
}

# Skip audit layer if in single-file mode and layer requires full project context
should_skip_project_layer() {
    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        log_info "Skipping (requires full project context in single-file mode)"
        return 0
    fi
    return 1
}

# Directory roots the test-only index is built from.
#
# Deliberately NOT `get_rg_targets`, which collapses to a single FILE in
# `--file` mode. `build_test_only_index` skips anything that is not a
# directory, so passing it a file left the index EMPTY and every single-file
# audit reported test-module findings as production defects. That is the mode
# the pre-commit hook runs in, so the hook blocked every commit touching a
# test-only file -- `transport/shm/ring_test.rs` produced 4 CRITICAL and 4
# HIGH that a full-project run correctly filters.
#
# It also could not have worked any other way: the declaration that makes a
# file test-only (`#[cfg(test)] #[path = "ring_test.rs"] mod tests;`) lives in
# a SIBLING file, so deciding test-ness requires the tree even when only one
# file is being scanned. Scanning scope and classification scope are two
# different things.
get_test_only_roots() {
    echo "$SRC_DIR"
    if [[ -d "$TOOLS_DIR" ]]; then
        echo "$TOOLS_DIR"
    fi
    local service_dir
    for service_dir in "${SERVICE_CRATE_DIRS[@]}"; do
        if [[ -d "$service_dir" ]]; then
            echo "$service_dir"
        fi
    done
}

# Get ripgrep target paths (supports both single-file and multi-directory mode)
get_rg_targets() {
    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        echo "$SCAN_TARGET"
    else
        # Full project mode: main source, tools and the service crates
        echo "$SRC_DIR"
        if [[ -d "$TOOLS_DIR" ]]; then
            echo "$TOOLS_DIR"
        fi
        local service_dir
        for service_dir in "${SERVICE_CRATE_DIRS[@]}"; do
            if [[ -d "$service_dir" ]]; then
                echo "$service_dir"
            fi
        done
    fi
}

################################################################################
# LAYER 0: CORE VALIDATION GATES
################################################################################

audit_validation_gates() {
    log_section "LAYER 0: CORE VALIDATION GATES"

    # Formatting is the one gate in this layer that is genuinely PER FILE, so
    # single-file mode runs it instead of skipping the layer wholesale.
    #
    # Skipping the layer in `--file` mode would mean the pre-commit hook never
    # checked formatting at all, and the failure would only surface in a full
    # audit, as one HIGH with no indication of which file. A gate that only
    # fires far from the keystroke that broke it is a gate nobody acts on.
    #
    # `rustfmt` directly rather than `cargo fmt`, which has no per-file form.
    # The edition must be passed explicitly: rustfmt defaults to 2015 and would
    # otherwise reformat 2021 code wrongly. Kept to .rs files, since the hook
    # also hands this script nothing else.
    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        if [[ "$SCAN_TARGET" == *.rs ]] && command -v rustfmt >/dev/null 2>&1; then
            if rustfmt --edition 2021 --check "$SCAN_TARGET" >/dev/null 2>&1; then
                log_pass "rustfmt --check"
            else
                log_high "Formatting gate failed (rustfmt --edition 2021 --check)"
            fi
        fi
        log_info "Remaining gates skipped (require full project context in single-file mode)"
        return
    fi

    if should_skip_project_layer; then
        return
    fi

    if [[ "${SKIP_VALIDATION_GATES}" == "1" ]]; then
        log_info "Skipped by flag/environment (--skip-validation-gates or AUDIT_SKIP_VALIDATION_GATES=1)"
        return
    fi

    cd "$PROJECT_ROOT"

    local validation_failed=0
    local gate_output

    # Helper: run a gate command, capture or stream based on verbose mode
    # A blocking gate has to say WHERE. Filtering the output to lines matching
    # "error:"/"warning:" drops rustc's `-->` location lines, so this layer
    # failed a release with
    #
    #     [HIGH] Global clippy gate failed
    #
    # naming no file, no line and no lint - the only way to act on it was to
    # re-run the command by hand and rediscover what it had already found.
    run_gate() {
        local label="$1" fail_label="$2"
        shift 2
        echo "  Running $label..."
        if [[ "$VERBOSE" == "1" ]]; then
            if "$@" 2>&1 | sed 's/^/    /'; then
                log_pass "$label"
                return 0
            else
                log_high "$fail_label"
                return 1
            fi
        else
            if gate_output=$("$@" 2>&1); then
                log_pass "$label"
                return 0
            else
                echo "$gate_output" \
                    | grep -E "^(error|warning)(\[|:)|^ *--> " \
                    | head -40 \
                    || echo "$gate_output" | tail -10
                local first_site
                first_site=$(echo "$gate_output" | grep -m1 -E "^ *--> " | sed 's/^ *--> //')
                if [[ -n "$first_site" ]]; then
                    log_high "${fail_label} (first: ${first_site})"
                else
                    log_high "$fail_label"
                fi
                return 1
            fi
        fi
    }

    run_gate "cargo fmt --all -- --check" \
             "Formatting gate failed (cargo fmt --all -- --check)" \
             cargo fmt --all -- --check || validation_failed=1

    run_gate "cargo clippy --all-targets --all-features -- -D warnings" \
             "Global clippy gate failed" \
             cargo clippy --all-targets --all-features -- -D warnings || validation_failed=1

    # Sequential tests: DDS participants bind multicast on the same domain,
    # parallel tests cause port contention and discovery cross-talk.
    run_gate "cargo test --all-features" \
             "Global test gate failed" \
             cargo test --all-features -- --test-threads=1 || validation_failed=1

    # Cross-compilation gate: catch platform-specific type mismatches
    # (e.g. libc::msg_controllen is usize on glibc-x86_64 but u32 on musl/arm)
    local CROSS_TARGETS=(
        "x86_64-unknown-linux-musl"
        "aarch64-unknown-linux-gnu"
        "aarch64-unknown-linux-musl"
    )
    for target in "${CROSS_TARGETS[@]}"; do
        if ! rustup target list --installed | grep -q "^${target}$"; then
            log_medium "Cross-compile skip: ${target} (not installed, run: rustup target add ${target})"
            continue
        fi

        # A missing C cross-compiler is an ENVIRONMENT gap, not a code defect,
        # and reporting it as HIGH makes this gate unusable as a release door:
        # it fails on a machine that has never installed the toolchain, while
        # the code is fine. `--examples` pulls `ring`, which builds C, so the
        # target's `gcc` has to be on PATH.
        #
        # Probe first, then run. The probe is what the rustup check above
        # already does for the Rust half; this is the same idea for the C half.
        # Without it a missing cross compiler would be reported as a HIGH
        # "Cross-compile check failed" although the code is fine.
        local cross_cc=""
        case "${target}" in
            *-linux-musl)  cross_cc="${target%%-unknown*}-linux-musl-gcc" ;;
            *-linux-gnu)   cross_cc="${target%%-unknown*}-linux-gnu-gcc" ;;
            *-windows-gnu) cross_cc="${target%%-pc*}-w64-mingw32-gcc" ;;
        esac
        if [[ -n "${cross_cc}" ]] && ! command -v "${cross_cc}" >/dev/null 2>&1; then
            log_medium "Cross-compile skip: ${target} (C toolchain '${cross_cc}' not on PATH; the Rust target is installed, so this is an environment gap and NOT a code defect)"
            continue
        fi

        run_gate "cargo check -p hdds --lib --examples --target ${target}" \
                 "Cross-compile check failed: ${target}" \
                 cargo check -p hdds --lib --examples --target "${target}" || validation_failed=1
    done

    if [[ $validation_failed -eq 0 ]]; then
        log_pass "All core validation gates passed"
    fi
}

################################################################################
# LAYER 1: ANTI-STUB ENFORCEMENT (NO TODO/FIXME/HACK/XXX/UNIMPLEMENTED)
################################################################################

audit_stubs() {
    log_section "LAYER 1: ANTI-STUB ENFORCEMENT"

    local violations=0
    local -a rg_targets
    mapfile -t rg_targets < <(get_rg_targets)

    # Common excludes: skip documentation, examples in git-hooks, and non-Rust files
    local rg_excludes=("--glob=!*.md" "--glob=!tools/git-hooks/**")

    # Check for todo!() and unimplemented!()
    if rg -q 'todo!\(|unimplemented!\(' "${rg_excludes[@]}" --type rust "${rg_targets[@]}"; then
        while IFS=: read -r file line content; do
            log_critical "$file:$line - Found stub macro: $content"
            ((violations++)) || true
        done < <(rg -H -n 'todo!\(|unimplemented!\(' "${rg_excludes[@]}" --type rust "${rg_targets[@]}")
    fi

    # Check for TODO/FIXME/HACK/XXX comments
    if rg -q '//\s*(TODO|FIXME|HACK|TEMPO|FUTURE|XXX|BUG|KLUDGE|REFACTOR|OPTIMIZE)' "${rg_excludes[@]}" --type rust "${rg_targets[@]}"; then
        while IFS=: read -r file line content; do
            # Skip if suppressed with @audit-ok
            if is_suppressed "$file" "$line"; then
                continue
            fi
            log_high "$file:$line - Found marker comment: $content"
            ((violations++)) || true
        done < <(rg -H -n '//\s*(TODO|FIXME|HACK|TEMPO|FUTURE|XXX|BUG|KLUDGE|REFACTOR|OPTIMIZE)' "${rg_excludes[@]}" --type rust "${rg_targets[@]}")
    fi

    # Check for empty function bodies
    if rg -q 'fn\s+\w+\([^)]*\)\s*(->\s*[^{]+)?\s*\{\s*\}' "${rg_excludes[@]}" --type rust "${rg_targets[@]}"; then
        while IFS=: read -r file line content; do
            # An empty body is a SMELL, not a defect: a trait impl that
            # deliberately ignores an event (a null sink) is correct, idiomatic
            # Rust, and rewriting it to satisfy a grep makes the code worse.
            # So this HIGH is suppressible with @audit-ok, exactly like the
            # marker-comment check above it. todo!() and unimplemented!() stay
            # UNSUPPRESSIBLE on purpose: those are unfinished code, not a
            # deliberate no-op.
            if is_suppressed "$file" "$line"; then
                continue
            fi
            log_high "$file:$line - Empty function body: $content"
            ((violations++)) || true
        done < <(rg -H -n 'fn\s+\w+\([^)]*\)\s*(->\s*[^{]+)?\s*\{\s*\}' "${rg_excludes[@]}" --type rust "${rg_targets[@]}")
    fi

    # Check for dbg!() macro (should not be in production)
    if rg -q 'dbg!\(' "${rg_excludes[@]}" --type rust "${rg_targets[@]}"; then
        while IFS=: read -r file line content; do
            log_critical "$file:$line - Debug macro in production: $content"
            ((violations++)) || true
        done < <(rg -H -n 'dbg!\(' "${rg_excludes[@]}" --type rust "${rg_targets[@]}" | head -10)
    fi

    if [[ $violations -eq 0 ]]; then
        log_pass "No stubs or debug artifacts found"
    fi
}

################################################################################
# LAYER 2: TYPE SAFETY AUDIT (DANGEROUS CASTS)
################################################################################

# ---------------------------------------------------------------------------
# Cast truncation oracle: ask the COMPILER, not a regex.
#
# The cast scan in LAYER 2 matches source text, so it cannot know the SOURCE
# type of a cast. It judged `PORT_BASE as u32` (u16 -> u32, which cannot lose a
# bit) exactly as harshly as `bytes.len() as u8` (usize -> u8, which silently
# truncates a DNS label). Provably-safe widenings (the RTPS port formula, a
# `port <= u16::MAX as u32` bounds check) would land in the HIGH column.
#
# clippy knows the types. `clippy::cast_possible_truncation` fires only when
# the target type is narrower than the source. Run it once, use it as an
# oracle: a cast the regex flags is a HIGH only if the compiler agrees it can
# lose information.
#
# The oracle has to be COMPLETE or it is worse than the regex. A file clippy
# never compiled produces no lint, and "no lint" is indistinguishable from
# "safe". A narrow run (`-p hdds --lib`) hides casts behind feature gates and
# would declare them safe, so `--all-features` is used. Coverage comes from cargo's own
# dep-info (every file it actually compiled), a flagged cast outside that set
# is reported as a GAP rather than dropped, and the oracle refuses to be used
# at all if it cannot account for every file clippy linted.
# ---------------------------------------------------------------------------
CAST_ORACLE_STATE="unavailable"
CAST_ORACLE_HITS=""
CAST_ORACLE_FILES=""

build_cast_truncation_oracle() {
    CAST_ORACLE_STATE="unavailable"
    command -v cargo >/dev/null 2>&1 || { echo "  Cast oracle: cargo not on PATH"; return 0; }
    command -v python3 >/dev/null 2>&1 || { echo "  Cast oracle: python3 not on PATH"; return 0; }
    [[ -f "${PROJECT_ROOT}/Cargo.toml" ]] || { echo "  Cast oracle: no workspace at ${PROJECT_ROOT}"; return 0; }

    local work
    work="$(mktemp -d)" || return 0
    CAST_ORACLE_HITS="${work}/hits"
    CAST_ORACLE_FILES="${work}/files"
    local raw="${work}/clippy.json"
    local marker="${work}/marker"
    : > "$marker"

    echo "  Cast oracle: asking clippy for the real types (all features)..."
    if ! (cd "$PROJECT_ROOT" && cargo clippy -q -p hdds --lib --all-features \
            --message-format=json -- \
            -W clippy::cast_possible_truncation -A clippy::all) >"$raw" 2>/dev/null; then
        echo "  Cast oracle UNAVAILABLE: clippy did not complete - casts fall back to regex judgement"
        # A scan whose oracle did not run is a DEGRADED scan, and the summary
        # must say so: without this the run printed a perfect score on text
        # judgement alone.
        ((SKIPPED_CHECKS++)) || true
        return 0
    fi

    # PROJECT_ROOT is readonly, so it cannot be passed as an env prefix
    # (`VAR=x python3` on a readonly VAR is a bash error). It goes in argv.
    if ! python3 - \
            "$PROJECT_ROOT" "$raw" "$marker" "$(audit_target_dir)" \
            "$SCAN_TARGET" "$CAST_ORACLE_HITS" "$CAST_ORACLE_FILES" <<'ORACLE_PY'
import json, os, sys

root, raw, marker, target_dir, scan_root, hits_path, files_path = sys.argv[1:8]
since = os.path.getmtime(marker)


def abspath(name):
    return name if os.path.isabs(name) else os.path.normpath(os.path.join(root, name))


# Files clippy emitted a diagnostic for. This is a SUBSET of what it compiled:
# a clean file says nothing. Used only to validate the coverage set below.
linted, hits = set(), set()
for line in open(raw, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        msg = json.loads(line).get("message") or {}
    except ValueError:
        continue
    spans = msg.get("spans") or []
    if not spans or not spans[0].get("file_name"):
        continue
    path = abspath(spans[0]["file_name"])
    linted.add(path)
    if "cast_possible_truncation" in (msg.get("code") or {}).get("code", ""):
        # EVERY line of the span, not its first one. The text scan finds the
        # `as u32` on the line it is written on; for a method chain broken
        # over several lines clippy's span STARTS at the receiver, lines
        # above. Keyed on line_start alone, such a hit never met its text
        # match, the cast was "not in the oracle" and therefore cleared as
        # widening.
        start = int(spans[0].get("line_start", 0))
        end = int(spans[0].get("line_end", start))
        for ln in range(start, max(start, end) + 1):
            hits.add("%s:%d" % (path, ln))

# Coverage: cargo writes a dep-info file listing every source of a compiled
# unit. Take the ones this run touched.
covered = set()
deps = os.path.join(target_dir, "debug", "deps")
for entry in os.listdir(deps) if os.path.isdir(deps) else []:
    if not entry.endswith(".d"):
        continue
    full = os.path.join(deps, entry)
    try:
        if os.path.getmtime(full) < since:
            continue
        text = open(full, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    for token in text.replace(":", " ").split():
        if token.endswith(".rs"):
            covered.add(abspath(token))

# Self-check: every linted file INSIDE the scanned tree must be inside the
# coverage set, or the coverage set is not measuring what we think it is and
# the oracle is unsafe to consult.
#
# Scoped to the scanned tree on purpose. clippy also lints workspace crates
# that hdds depends on (hdds-codegen), and on a warm cache cargo does not
# rewrite their dep-info, so they are legitimately absent from coverage. They
# are also outside what this layer scans, so they cannot produce a finding. An
# unscoped check failed on exactly that and silently cost us the oracle.
scan_root = os.path.normpath(scan_root)
missing = {f for f in linted if f.startswith(scan_root + os.sep)} - covered
if not covered or missing:
    sys.stderr.write("oracle coverage incomplete: %d scanned file(s) linted but not accounted for\n"
                     % len(missing))
    for f in sorted(missing)[:5]:
        sys.stderr.write("  %s\n" % f)
    raise SystemExit(1)

with open(hits_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(sorted(hits)) + "\n")
with open(files_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(sorted(covered)) + "\n")
ORACLE_PY
    then
        echo "  Cast oracle UNAVAILABLE: could not establish compile coverage - casts fall back to regex judgement"
        ((SKIPPED_CHECKS++)) || true
        return 0
    fi

    CAST_ORACLE_STATE="ready"
    echo "  Cast oracle ready: $(grep -c . "$CAST_ORACLE_HITS") truncating cast(s) known across $(grep -c . "$CAST_ORACLE_FILES") type-checked file(s)"
}

audit_type_safety() {
    log_section "LAYER 2: TYPE SAFETY AUDIT"

    local violations=0
    local widening_dropped=0

    if [[ $SINGLE_FILE_MODE -eq 0 ]]; then
        build_cast_truncation_oracle
    fi

    # Strategy: Use ripgrep's inverse matching to exclude safe patterns
    # This is MUCH faster than post-processing in bash

    echo "  Scanning for potentially unsafe casts..."

    # Numeric casts - exclude:
    # - Test files and test sections (glob)
    # - Doc comments (///  //!)
    # - Inline SAFETY comments
    # - Enum discriminants (self as u8)
    # - RTPS sequence high bits (>> 32)
    # - Constants (UPPER_CASE as)

    # Use rg with negative lookahead via PCRE2
    local cast_pattern=' as (u8|u16|u32|i8|i16|i32)\b'

    # First pass: get all casts, then filter
    local all_casts
    all_casts=$(rg -H -n "$cast_pattern" "$SCAN_TARGET" --type rust \
        --glob '!**/tests/**' \
        --glob '!**/*_test.rs' \
        --glob '!**/benches/**' \
        2>/dev/null || true)

    while IFS=: read -r file line_num content; do
        [[ -z "$file" ]] && continue

        # Quick filters (fastest first)

        # Skip comment lines, doc or plain: a cast QUOTED in a comment is not
        # a cast.
        [[ "$content" =~ ^[[:space:]]*// ]] && continue

        # Skip inline SAFETY comment or @audit-ok marker. COUNTED, so the
        # `Suppressed (@audit-ok)` line at the end of a run reports every
        # suppression this layer performed.
        [[ "$content" =~ SAFETY ]] && continue
        if [[ "$content" =~ @audit-ok|@audit-ignore ]]; then
            ((SUPPRESSED_COUNT++)) || true
            continue
        fi

        # PROVABLE WIDENINGS, decided without the compiler.
        #
        # A widening is not a finding, and the oracle says so in full-project
        # mode - but `--file` mode has no oracle, so the pre-commit hook used
        # to report `PORT_BASE as u32` and `u16::MAX as u32` as HIGH while the
        # full audit cleared them, and the only way past it was a dozen
        # @audit-ok markers on lossless conversions. A tool with two modes has
        # two scopes; these are the two cases the text CAN prove, so the two
        # modes agree wherever proof is available.
        #
        #   1. `<int>::MAX as <wider int>` - both widths are in the text.
        #   2. `NAME as uN` where THIS FILE declares `const NAME: uM`, M < N.
        #
        # Anything else still goes to the oracle, or to the text fallback.
        if [[ "$content" =~ (u8|u16|u32|i8|i16|i32)::(MAX|MIN)[[:space:]]+as[[:space:]]+(u16|u32|u64|u128|i16|i32|i64|i128) ]]; then
            src_w=${BASH_REMATCH[1]}; dst_w=${BASH_REMATCH[3]}
            if [[ ${src_w:1} -lt ${dst_w:1} && ${src_w:0:1} == "${dst_w:0:1}" ]]; then
                ((widening_dropped++)) || true
                continue
            fi
        fi
        if [[ "$content" =~ ([A-Z][A-Z0-9_]+)[[:space:]]+as[[:space:]]+(u16|u32|u64|u128) ]]; then
            const_name=${BASH_REMATCH[1]}; dst_w=${BASH_REMATCH[2]}
            # `|| true`: under `set -euo pipefail` a grep with no match exits 1
            # and would KILL THE WHOLE AUDIT at the assignment (see the panic
            # and expect layers for the same trap).
            const_decl=$(grep -oE "const[[:space:]]+${const_name}[[:space:]]*:[[:space:]]*u(8|16|32|64)" "$file" 2>/dev/null | head -1 || true)
            if [[ -n "$const_decl" ]]; then
                src_w=${const_decl##*: }
                if [[ ${src_w:1} -lt ${dst_w:1} ]]; then
                    ((widening_dropped++)) || true
                    continue
                fi
            fi
        fi

        # The text skips below are a FALLBACK, used only when the compiler
        # cannot be asked. When the cast oracle is ready every cast goes to it,
        # because these patterns decide by SPELLING: a rule such as
        # `[a-z_]+_len.*as u` waves `padded_len as u16` through unread while
        # the identical cast on a variable named `padded` is flagged. The
        # oracle knows the types and does not care about the names.
        if [[ "$CAST_ORACLE_STATE" != "ready" ]]; then
            # Skip enum discriminant (self as u8)
            [[ "$content" =~ self[[:space:]]as[[:space:]]u8 ]] && continue

            # Skip RTPS sequence high bits (>> 32) as i32
            [[ "$content" =~ \>\>[[:space:]]*32 ]] && continue

            # Skip RTPS sequence low bits: sn_low, start_low, base_low, first_low, last_low, list_low
            [[ "$content" =~ _low[[:space:]]*=[[:space:]].*as[[:space:]]u32 ]] && continue

            # Skip port casts (ports are always 0-65535)
            [[ "$content" =~ \.port\(\)[[:space:]]*as[[:space:]]u ]] && continue
            [[ "$content" =~ \.port[[:space:]]as[[:space:]]u ]] && continue
            [[ "$content" =~ _port[[:space:]]as[[:space:]]u ]] && continue

            # Skip submessage length (RTPS protocol limit)
            [[ "$content" =~ submsg_len[[:space:]]as[[:space:]]u16 ]] && continue

            # Skip .len() as u32 (CDR/serialization - rarely overflows)
            [[ "$content" =~ \.len\(\)[[:space:]]*[\+\-\*]?[[:space:]]*[0-9]*\)?[[:space:]]*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ _len[[:space:]]as[[:space:]]u32 ]] && continue

            # Skip float calculations: (x as f32 * y) as u32 (rate calculations)
            [[ "$content" =~ as[[:space:]]f32.*\)[[:space:]]*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ as[[:space:]]f64.*\)[[:space:]]*as[[:space:]]u32 ]] && continue

            # Skip bounded values with .min() or .max()
            [[ "$content" =~ \.min\(.*\)[[:space:]]*as[[:space:]]u ]] && continue
            [[ "$content" =~ \.max\(.*\)[[:space:]]*as[[:space:]]u ]] && continue

            # Skip domain_id/participant_id (validated at entry point in ports.rs)
            [[ "$content" =~ domain_id[[:space:]]as[[:space:]]u16 ]] && continue
            [[ "$content" =~ participant_id[[:space:]]as[[:space:]]u16 ]] && continue

            # Skip confidence scores (percentage 0-100)
            [[ "$content" =~ \*[[:space:]]*100\.0\)[[:space:]]*as[[:space:]]u8 ]] && continue

            # Skip TOS/DSCP values (network byte, always fits)
            [[ "$content" =~ tos.*as[[:space:]]i32 ]] && continue
            [[ "$content" =~ dscp.*as[[:space:]]i32 ]] && continue

            # Skip bytes[0] as i8 (single byte conversion)
            [[ "$content" =~ bytes\[0\][[:space:]]*as[[:space:]]i8 ]] && continue

            # Skip Atomic loads (already the right type internally)
            [[ "$content" =~ \.load\(Ordering:: ]] && continue

            # Skip properties_size (serialization bounded)
            [[ "$content" =~ properties_size[[:space:]]as[[:space:]]u16 ]] && continue

            # Skip byte extraction from larger integers: (x >> N) as u8
            [[ "$content" =~ \>\>[[:space:]]*[0-9]+\)[[:space:]]*as[[:space:]]u8 ]] && continue

            # Skip bit mask operations: (x & MASK) as uXX
            [[ "$content" =~ \&[[:space:]]*[A-Z0-9x_]+\)[[:space:]]*as[[:space:]]u ]] && continue

            # Skip .abs() calculations (absolute values)
            [[ "$content" =~ \.abs\(\) ]] && continue

            # Skip bit index calculations: (idx as u32 * 32)
            [[ "$content" =~ idx[[:space:]]as[[:space:]]u32[[:space:]]*\*[[:space:]]*32 ]] && continue

            # Skip highest_bit calculations
            [[ "$content" =~ highest_bit ]] && continue

            # Skip kind/type enum casts
            [[ "$content" =~ kind[[:space:]]as[[:space:]]u ]] && continue
            [[ "$content" =~ kind_val[[:space:]]as[[:space:]]u ]] && continue
            [[ "$content" =~ \(kind_val[[:space:]]*\>\> ]] && continue

            # Skip timestamp/time casts
            [[ "$content" =~ seconds[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ fraction[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ timestamp[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ nanos.*as[[:space:]]u32 ]] && continue

            # Skip depth/count/index casts (typically bounded by protocol)
            [[ "$content" =~ depth[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ count[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ frag_num[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ frag_.*as[[:space:]]u ]] && continue

            # Skip aligned_payload_len (serialization)
            [[ "$content" =~ aligned_.*as[[:space:]]u ]] && continue
            [[ "$content" =~ param_len[[:space:]]as[[:space:]]u ]] && continue
            [[ "$content" =~ str_len.*as[[:space:]]u ]] && continue
            [[ "$content" =~ len_with_null[[:space:]]as[[:space:]]u ]] && continue

            # Skip *val as u32 (dereferenced value, typically bounded)
            [[ "$content" =~ \*val[[:space:]]as[[:space:]]u ]] && continue
            [[ "$content" =~ \*v[[:space:]]as[[:space:]]u8 ]] && continue

            # Skip durability/qos enum casts
            [[ "$content" =~ durability.*as[[:space:]]u8 ]] && continue

            # Skip num_bits calculations (RTPS ACK/NACK)
            [[ "$content" =~ num_bits ]] && continue
            [[ "$content" =~ max_seq.*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ max_sn.*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ base_sn.*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ seq_base.*as[[:space:]]u32 ]] && continue

            # Skip pid/now byte extraction for GUIDs
            [[ "$content" =~ pid[[:space:]]as[[:space:]]u8 ]] && continue
            [[ "$content" =~ \(pid[[:space:]]*\>\> ]] && continue
            [[ "$content" =~ now[[:space:]]as[[:space:]]u8 ]] && continue
            [[ "$content" =~ \(now[[:space:]]*\>\> ]] && continue

            # Skip detected/expected difference calculations
            [[ "$content" =~ detected[[:space:]]as[[:space:]]i32 ]] && continue
            [[ "$content" =~ expected[[:space:]]as[[:space:]]i32 ]] && continue

            # Skip size_of::<T>() as uXX (compile-time known)
            [[ "$content" =~ size_of::\<.*\>\(\)[[:space:]]*as[[:space:]]u ]] && continue
            [[ "$content" =~ mem::size_of ]] && continue

            # Skip CMSG_SPACE/CMSG_LEN (libc macros)
            [[ "$content" =~ CMSG_SPACE ]] && continue
            [[ "$content" =~ CMSG_LEN ]] && continue

            # Skip libc constants casts (AF_*, etc.)
            [[ "$content" =~ libc::[A-Z_]+[[:space:]]as[[:space:]] ]] && continue

            # Skip socket family casts
            [[ "$content" =~ sa_family[[:space:]]as[[:space:]]i32 ]] && continue
            [[ "$content" =~ nl_family.*as[[:space:]]u16 ]] && continue
            [[ "$content" =~ family[[:space:]]as[[:space:]]i32 ]] && continue
            [[ "$content" =~ family[[:space:]]==.*as[[:space:]]u8 ]] && continue

            # Skip interface index casts
            [[ "$content" =~ if_index[[:space:]]as[[:space:]]i32 ]] && continue
            [[ "$content" =~ ifindex[[:space:]]as[[:space:]] ]] && continue

            # Skip CRC byte extraction
            [[ "$content" =~ crc[[:space:]]as[[:space:]]u8 ]] && continue

            # Skip priority casts (bounded 0-7 or similar)
            [[ "$content" =~ priority[[:space:]]as[[:space:]]u8 ]] && continue
            [[ "$content" =~ prio[[:space:]]as[[:space:]]u8 ]] && continue

            # Skip TTL/TOS values (network bounded 0-255)
            [[ "$content" =~ ttl_val[[:space:]]as[[:space:]]u8 ]] && continue
            [[ "$content" =~ tos_val[[:space:]]as[[:space:]]u8 ]] && continue

            # Skip payload/data length casts
            [[ "$content" =~ payload\.len\(\)[[:space:]]*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ data\.len\(\)[[:space:]]*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ orig_len.*as[[:space:]]u32 ]] && continue

            # Skip dialect enum casts
            [[ "$content" =~ dialect[[:space:]]as[[:space:]]u8 ]] && continue

            # Skip varint decoded values (bounded by encoding)
            [[ "$content" =~ value[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ value[[:space:]]as[[:space:]]u16 ]] && continue

            # Skip sequence number casts in lowbw
            [[ "$content" =~ _seq[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ last_seq[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ full_seq[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ patch_seq[[:space:]]as[[:space:]]u32 ]] && continue

            # Skip field_id casts (protocol bounded)
            [[ "$content" =~ field_id[[:space:]]as[[:space:]]u32 ]] && continue

            # Skip group_id casts
            [[ "$content" =~ group_id[[:space:]]as[[:space:]]u32 ]] && continue

            # Skip size/len casts for serialization
            [[ "$content" =~ size[[:space:]]as[[:space:]]u16 ]] && continue
            [[ "$content" =~ [a-z_]+_len.*as[[:space:]]u ]] && continue

            # Skip window/stats casts
            [[ "$content" =~ window_used.*as[[:space:]]u32 ]] && continue

            # Skip diff/wrapping calculations
            [[ "$content" =~ wrapping_sub.*as[[:space:]]i32 ]] && continue
            [[ "$content" =~ diff.*as[[:space:]]i32 ]] && continue

            # Skip hash output truncation
            [[ "$content" =~ \.finish\(\)[[:space:]]*as[[:space:]]u32 ]] && continue

            # Skip encoded_size/length casts
            [[ "$content" =~ encoded_size\(\)[[:space:]]*as[[:space:]]u ]] && continue
            [[ "$content" =~ length.*as[[:space:]]u16 ]] && continue

            # Skip expects/inline_qos booleans as u32
            [[ "$content" =~ expects.*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ expect_inline_qos[[:space:]]as[[:space:]]u32 ]] && continue

            # Skip futex syscall return
            [[ "$content" =~ \)[[:space:]]*as[[:space:]]i32$ ]] && continue

            # Skip enum self as u16/u32 (discriminant)
            [[ "$content" =~ \(self[[:space:]]as[[:space:]]u ]] && continue

            # Skip domain_id calculations for multicast
            [[ "$content" =~ domain_id[[:space:]]\/.*as[[:space:]]u8 ]] && continue
            [[ "$content" =~ domain_id[[:space:]]%.*as[[:space:]]u8 ]] && continue

            # Skip mask/prefix calculations
            [[ "$content" =~ count_ones\(\)[[:space:]]*as[[:space:]]u8 ]] && continue
            [[ "$content" =~ prefix_len ]] && continue
            [[ "$content" =~ mask_bits ]] && continue

            # Skip i (loop index) as u16/u32 (typically small loops)
            [[ "$content" =~ \(i[[:space:]]as[[:space:]]u ]] && continue

            # Skip byte extraction patterns
            [[ "$content" =~ byte[[:space:]]as[[:space:]]u8 ]] && continue
            [[ "$content" =~ DATA_MASK\)\)[[:space:]]*as[[:space:]]u8 ]] && continue

            # Skip generic .len() as u32 (any variable.len())
            [[ "$content" =~ [a-z_]+\.len\(\)[[:space:]]*as[[:space:]]u32 ]] && continue
            [[ "$content" =~ [a-z_]+\.len\(\)[[:space:]]*\+[[:space:]]*[0-9]+\)[[:space:]]*as[[:space:]]u32 ]] && continue

            # Skip Atomic fetch_add counter patterns
            [[ "$content" =~ fetch_add.*as[[:space:]]u32 ]] && continue

            # Skip capacity/size constants
            [[ "$content" =~ capacity[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ CAPACITY[[:space:]]as[[:space:]]u32 ]] && continue
            [[ "$content" =~ SIZE[[:space:]]as[[:space:]]u32 ]] && continue

            # Skip generic port casts (not caught by .port() pattern)
            [[ "$content" =~ [^a-z]port[[:space:]]as[[:space:]]u ]] && continue

            # Skip self as u32 (enum discriminant)
            [[ "$content" =~ ^[[:space:]]*self[[:space:]]as[[:space:]]u ]] && continue

        fi

        # Skip casts inside an inline test block, by RANGE. A rule of the form
        # "line > first #[cfg(test)] in file" would hide every production
        # line after the first test module to the end of the file.
        if is_test_only_line "$file" "$line_num"; then
            continue
        fi

        # The compiler has the last word. A widening cast is not a finding.
        if [[ "$CAST_ORACLE_STATE" == "ready" ]]; then
            if ! grep -qxF "$file" "$CAST_ORACLE_FILES"; then
                log_medium "$file:$line_num - Cast NOT type-checked (file outside the compiled unit): $content"
                ((violations++)) || true
                continue
            fi
            if ! grep -qxF "$file:$line_num" "$CAST_ORACLE_HITS"; then
                ((widening_dropped++)) || true
                continue
            fi
        fi

        log_high "$file:$line_num - Unchecked cast: $content"
        ((violations++)) || true
    done <<< "$all_casts"

    # No silent caps: say how many the compiler cleared, so a reader can tell
    # "nothing flagged" from "everything suppressed".
    if [[ "$CAST_ORACLE_STATE" == "ready" ]]; then
        echo "  Cast oracle cleared $widening_dropped widening cast(s) the text scan had flagged"
    else
        log_medium "Cast truncation oracle unavailable - cast findings are text-matched, not type-checked"
    fi

    # Pointer casts - ALL must have SAFETY justification (checked in Layer 3)
    # Just count them here for awareness
    echo "  Scanning for pointer casts..."
    local ptr_count
    ptr_count=$(rg -c 'as \*(?:mut|const)' "$SCAN_TARGET" --type rust \
        --glob '!**/tests/**' 2>/dev/null | \
        awk -F: '{s+=$2} END {print s+0}' || true)
    echo "  Found $ptr_count pointer casts (verified by Layer 3 SAFETY check)"

    # Check for wrong integer types in RTPS (should be u64 for sequences)
    while IFS=: read -r file line content; do
        [[ -z "$file" ]] && continue
        log_critical "$file:$line - Wrong type for sequence_number (must be u64): $content"
        ((violations++)) || true
    done < <(rg -H -n 'sequence_number.*:\s*u32' "$SCAN_TARGET" --type rust 2>/dev/null || true)

    # Check for transmute (extremely dangerous)
    while IFS=: read -r file line content; do
        [[ -z "$file" ]] && continue
        log_critical "$file:$line - transmute() detected (forbidden): $content"
        ((violations++)) || true
    done < <(rg -H -n 'std::mem::transmute|core::mem::transmute' "$SCAN_TARGET" --type rust 2>/dev/null || true)

    if [[ $violations -eq 0 ]]; then
        log_pass "Type safety audit passed"
    fi
}

################################################################################
# LAYER 3: UNSAFE CODE AUDIT (ANSSI/IGI-1300)
################################################################################

audit_unsafe() {
    log_section "LAYER 3: UNSAFE CODE AUDIT (ANSSI/IGI-1300)"

    local unsafe_count=0
    local unjustified=0

    # Count unsafe blocks
    # Force rg to always show filename with -H
    while IFS=: read -r file line content; do
        # Verify line is a number before doing arithmetic
        if [[ "$line" =~ ^[0-9]+$ ]]; then
            ((unsafe_count++)) || true

            # Check for SAFETY comment within 15 lines before
            # Multi-line SAFETY justifications with extensive invariant documentation
            # can span 10+ lines before the unsafe block
            local start=$((line > 15 ? line - 15 : 1))
            local context=$(sed -n "${start},${line}p" "$file" 2>/dev/null || echo "")

            if ! echo "$context" | grep -qE '(SAFETY|Safety|# Safety).*:'; then
                # Count it only if it was actually REPORTED. `log_critical`
                # drops findings in test-only files (the line-level test
                # index), and the aggregate "Found N unsafe blocks without
                # SAFETY comments" must not count what was dropped.
                local filtered_before=$TEST_ONLY_FILTERED
                log_critical "$file:$line - Unsafe block without SAFETY justification"
                if [[ "$TEST_ONLY_FILTERED" -eq "$filtered_before" ]]; then
                    ((unjustified++)) || true
                fi
            fi
        fi
    done < <(rg -H -n 'unsafe\s*\{' "$SCAN_TARGET" 2>/dev/null)

    echo "  Total unsafe blocks: $unsafe_count"
    echo "  Unjustified unsafe: $unjustified"

    if [[ $unsafe_count -gt $MAX_UNSAFE_BLOCKS ]] && [[ $SINGLE_FILE_MODE -eq 0 ]]; then
        log_high "Too many unsafe blocks: $unsafe_count (max: $MAX_UNSAFE_BLOCKS)"
    fi

    if [[ $unjustified -gt 0 ]]; then
        log_critical "Found $unjustified unsafe blocks without SAFETY comments"
    elif [[ $unsafe_count -eq 0 ]]; then
        log_pass "No unsafe code (excellent!)"
    else
        log_pass "All unsafe blocks properly justified"
    fi
}

################################################################################
# LAYER 4: COMPLEXITY ANALYSIS
################################################################################

audit_complexity() {
    log_section "LAYER 4: COMPLEXITY ANALYSIS"

    local violations=0

    # Check function length
    while IFS= read -r file; do
        local in_function=0
        local function_start=0
        local function_name=""
        local line_num=0

        while IFS= read -r line; do
            ((line_num++)) || true

            if [[ "$line" =~ ^[[:space:]]*(pub[[:space:]]+)?fn[[:space:]]+([a-z_][a-z0-9_]*) ]]; then
                in_function=1
                function_start=$line_num
                function_name="${BASH_REMATCH[2]}"
            elif [[ $in_function -eq 1 ]] && [[ "$line" =~ ^[[:space:]]*\}[[:space:]]*$ ]]; then
                local function_length=$((line_num - function_start))
                if [[ $function_length -gt $MAX_FUNCTION_LINES ]]; then
                    log_medium "$file:$function_start - Function '$function_name' too long: $function_length lines (max: $MAX_FUNCTION_LINES)"
                    ((violations++)) || true
                fi
                in_function=0
            fi
        done < "$file"
    done < <(get_target_files)

    # Check file length -- of the PRODUCTION half only.
    #
    # `wc -l` would count a file's own `#[cfg(test)]` block against it, so the
    # metric would read "this module is well tested" as "this module is too
    # big", and the only way to improve the score would be to move tests away
    # from the code they cover. Production lines alone are counted.
    # Files that are long in production, remembered so the complexity pass can
    # tell "merely long" from "long AND branching", which is the only one of
    # the two that names a refactor candidate.
    local long_files
    long_files="$(mktemp)"

    while IFS= read -r file; do
        local total code
        total=$(wc -l < "$file")
        # Count the CODE: stop at the file's own test module, and skip blank
        # and comment lines: comments are written on purpose - the traps in
        # this codebase are explained in full sentences.
        # Charging a module for explaining itself, on top of charging it for
        # testing itself, made the metric punish the two practices the project
        # leans on hardest.
        code=$(awk '
            /#\[cfg\(test\)\]/ { exit }
            {
                line = $0
                sub(/^[ \t]+/, "", line)
                if (in_block) { if (line ~ /\*\//) in_block = 0; next }
                if (line == "") next
                if (line ~ /^\/\//) next
                if (line ~ /^\/\*/) { if (line !~ /\*\//) in_block = 1; next }
                n++
            }
            END { print n + 0 }
        ' "$file")
        if [[ "$code" -gt "$MAX_FILE_LINES" ]]; then
            if [[ "$code" != "$total" ]]; then
                log_low "$file - File too long: $code code lines of $total (max: $MAX_FILE_LINES)"
            else
                log_low "$file - File too long: $code lines (max: $MAX_FILE_LINES)"
            fi
            ((violations++)) || true
            echo "${file} ${code}" >> "$long_files"
        fi
    done < <(get_target_files)

    # Check cyclomatic/cognitive complexity (if rust-code-analysis-cli is available)
    if check_command rust-code-analysis-cli; then
        while IFS= read -r file; do
            # Skip test files and generated code
            [[ "$file" =~ /tests/ ]] && continue
            [[ "$file" =~ /benches/ ]] && continue
            [[ "$file" =~ cdr2_serde\.rs$ ]] && continue  # Generated serialization code
            [[ "$file" =~ type_kind\.rs$ ]] && continue   # Generated type definitions

            # Analyze file and extract high-complexity functions
            local result
            result=$(rust-code-analysis-cli -p "$file" -l rust -m -O json 2>/dev/null | \
                jq -r --arg file "$file" \
                   --argjson cyc "$MAX_COMPLEXITY" \
                   --argjson cog "$MAX_COGNITIVE" \
                '[.. | select(.kind? == "function") |
                 {name: .name, line: .start_line,
                  cyclomatic: (.metrics.cyclomatic.sum | floor),
                  cognitive: (.metrics.cognitive.sum | floor)}] |
                 .[] |
                 select(.cyclomatic > $cyc or .cognitive > $cog) |
                 "\($file):\(.line) - \(.name) (cyclomatic: \(.cyclomatic), cognitive: \(.cognitive))"' 2>/dev/null || true)

            if [[ -n "$result" ]]; then
                while IFS= read -r violation; do
                    # Extract file:line from violation string
                    local vfile vline
                    vfile=$(echo "$violation" | cut -d: -f1)
                    vline=$(echo "$violation" | cut -d: -f2 | cut -d' ' -f1)
                    # Skip if suppressed with @audit-ok
                    if is_suppressed "$vfile" "$vline"; then
                        continue
                    fi
                    log_medium "$violation"
                    ((violations++)) || true
                    echo "$violation" >> "${long_files}.cc"
                done <<< "$result"
            fi
        done < <(get_target_files)
    fi

    # ---------------------------------------------------------------------
    # Refactor candidates: the intersection, ranked.
    #
    # "File too long" on its own is a weak signal: a file whose only fault is
    # size is not a defect. The files worth a person's afternoon are the ones
    # that are long in shipped code AND hold a branching function.
    #
    # Printed, not logged: these are already counted once as a long file and
    # once as a complex function. Counting them a third time would make the
    # totals say more work exists than does. The list is here to be ACTED on,
    # so it is ranked worst-first.
    if [[ -s "$long_files" ]] && [[ -s "${long_files}.cc" ]]; then
        local candidates
        # `if`, not `[[ ... ]] && printf`. A long file with no complex function
        # leaves `worst` empty, the `&&` chain then returns 1 as the LAST
        # command of the loop body, pipefail carries that out of the pipeline,
        # and `set -e` kills the run silently at the end of this layer. Test
        # this block with the same `set -euo pipefail` the real script carries.
        candidates=$(
            {
                while read -r lf lines; do
                    local worst
                    worst=$(grep -F "$lf:" "${long_files}.cc" 2>/dev/null \
                            | sed 's/.*cyclomatic: \([0-9]*\).*/\1/' \
                            | sort -rn | head -1 || true)
                    if [[ -n "$worst" ]]; then
                        printf '%s %s %s\n' "$worst" "$lines" "$lf"
                    fi
                done < "$long_files"
            } | sort -rn || true
        )
        if [[ -n "$candidates" ]]; then
            echo ""
            echo "  Refactor candidates (large in CODE and holding a branching function):"
            echo "$candidates" | head -12 | while read -r worst lines lf; do
                printf '    cyclomatic %-4s %-5s code lines  %s\n' "$worst" "$lines" "${lf#"${PROJECT_ROOT}/"}"
            done
            echo "    ($(echo "$candidates" | wc -l) in total; a long file with no branching function is not one)"
        fi
    fi
    rm -f "$long_files" "${long_files}.cc"

    if [[ $violations -eq 0 ]]; then
        log_pass "Complexity metrics within limits"
    fi
}

################################################################################
# LAYER 5: PANIC/UNWRAP AUDIT
################################################################################

audit_panics() {
    # `local -` scopes every shell option to this function: bash restores them
    # on return, by ANY path. The `set +o pipefail` below and its matching
    # `set -o pipefail` at the bottom sit ninety lines apart, and the day
    # someone adds an early `return` between them, pipefail stays off for every
    # layer that runs afterwards - silently, since a pipeline would then report
    # the exit status of its LAST command.
    local -
    log_section "LAYER 5: PANIC/UNWRAP AUDIT"
    # Temporarily disable pipefail to avoid hanging on process substitutions
    set +o pipefail

    local violations=0

    # Check for panic!() outside tests
    while IFS=: read -r file line content; do
        # Skip if in test module (directory or filename pattern)
        local dir=$(dirname "$file")
        if [[ "$dir" =~ tests ]] || [[ "$file" =~ test ]]; then
            continue
        fi

        # Skip if suppressed with @audit-ok
        #
        # Its SIBLING loop below - the unwrap check, same layer - honours
        # `@audit-ok`, and so does this one, so the documented escape hatch
        # works for both checks. A
        # const-context `panic!` (a compile-time assertion that no binary can
        # execute) had no way to be marked, and it was reported as a CRITICAL
        # blocking the release.
        if is_suppressed "$file" "$line"; then
            continue
        fi

        # Skip doc comments (//! and ///), for the same reason the unwrap loop
        # does: a `panic!` named in prose is not a `panic!` in code.
        if [[ "$content" =~ ^[[:space:]]*//[!/] ]]; then
            continue
        fi

        # Skip if in inline #[cfg(test)] module (common Rust pattern)
        # Find line number of first #[cfg(test)] in the file
        #
        # `|| true` is LOad-BEARING, here and at the two sibling sites (the
        # other panic/unwrap loop and the concurrency layer). This script runs
        # under `set -euo pipefail`: `grep` exits 1 when the file contains no
        # `#[cfg(test)]` at all, `pipefail` promotes that to the pipeline's
        # status, and `set -e` then kills the WHOLE AUDIT at the assignment -
        # no summary, no verdict, and every later layer silently skipped, with
        # exit status 1 that reads exactly like an honest "violations found".
        # It was intermittent because the hits come from `rg | head -10` and
        # ripgrep's walk order varies, so it only fired when one of the first
        # ten hits landed in a file with no inline test module.
        # By RANGE, not "after the first #[cfg(test)]": see the cast layer.
        if is_test_only_line "$file" "$line"; then
            continue
        fi

        log_critical "$file:$line - panic!() in production code: $content"
        ((violations++)) || true
    # No cap. `-m 20` capped this at twenty hits per file BEFORE the filters
    # ran, so on a file with more than twenty the CRITICAL count was not a
    # measurement; filter first, report everything that survives.
    done < <(rg -H -n 'panic!\(' "$SCAN_TARGET" --type rust --glob '!**/tests/**' --glob '!**/*test*' 2>/dev/null || true)

    # Check for unwrap() - should use expect() or proper error handling
    while IFS=: read -r file line content; do
        # Skip if in test module (directory or filename pattern)
        local dir=$(dirname "$file")
        if [[ "$dir" =~ tests ]] || [[ "$file" =~ test ]]; then
            continue
        fi

        # Skip if suppressed with @audit-ok
        if is_suppressed "$file" "$line"; then
            continue
        fi

        # Skip if in an inline #[cfg(test)] block, by RANGE (see the cast layer).
        if is_test_only_line "$file" "$line"; then
            continue
        fi

        # Skip doc comments (//! and ///)
        if [[ "$content" =~ ^[[:space:]]*//[!/] ]]; then
            continue
        fi

        log_high "$file:$line - unwrap() detected (use expect() or ? operator): $content"
        ((violations++)) || true
    # TRUNCATE-THEN-FILTER, removed. This read `-m 20 ... | head -20`, so the
    # loop above considered TWENTY of the 1252 `.unwrap()` occurrences in the
    # tree and then filtered those twenty down to nothing. The layer reported
    # ZERO unwrap violations, and it reported zero the same way a closed
    # notebook reports zero: 890 of those 1252 are inside `#[cfg(test)]`
    # modules and 288 in test files, which the filters below would have
    # dropped anyway - but NINE are in shipped code and had never once been
    # printed.
    #
    # Worse than the undercount: `rg` walks in parallel, so WHICH twenty
    # survive the cap changes between identical runs. That is why the
    # `Suppressed (@audit-ok)` line read 16 on one run and 13 on the next with
    # no change to the tree, and it means the headline HIGH count was not a
    # measurement of anything. Filter first, report everything that survives.
    done < <(rg -H -n '\.unwrap\(\)' "$SCAN_TARGET" --type rust --glob '!**/tests/**' 2>/dev/null)

    # Check for .expect("") with empty message. No cap (it was `-m 20`), and
    # inline test blocks are skipped by range like the two detectors above.
    while IFS=: read -r file line content; do
        if is_test_only_line "$file" "$line"; then
            continue
        fi
        log_medium "$file:$line - Empty expect message: $content"
        ((violations++)) || true
    done < <(rg -H -n '\.expect\(""\)' "$SCAN_TARGET" --type rust 2>/dev/null || true)

    if [[ $violations -eq 0 ]]; then
        log_pass "No panics or unwraps in production code"
    fi
    # Re-enable pipefail
    set -o pipefail
}

################################################################################
# LAYER 6: MEMORY PATTERNS AUDIT
################################################################################

audit_memory_patterns() {
    log_section "LAYER 6: MEMORY PATTERNS AUDIT"

    local violations=0

    # Check for Box::leak (memory leak) - skip if SAFETY comment nearby
    if rg -q 'Box::leak' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            # A comment that NAMES `Box::leak` is not a call to it. Prose that
            # explains why some other module was forced into one was being
            # reported as a CRITICAL memory leak (security/cms.rs:68).
            if [[ "$content" =~ ^[[:space:]]*(///|//!|//|\*) ]]; then
                continue
            fi
            # Check if there's a SAFETY comment within 10 lines before
            local has_safety
            has_safety=$(head -n "$line" "$file" 2>/dev/null | tail -n 10 | grep -ciE "SAFETY|intentionally|acceptable|KNOWN LIMITATION" 2>/dev/null || true)
            if [[ -n "$has_safety" ]] && [[ "$has_safety" -gt 0 ]]; then
                log_low "$file:$line - Box::leak with SAFETY justification (acceptable)"
            else
                log_critical "$file:$line - Box::leak detected (memory leak): $content"
                ((violations++)) || true
            fi
        done < <(rg -H -n 'Box::leak' "$SCAN_TARGET")
    fi

    # Check for forget() (can cause leaks)
    if rg -q 'std::mem::forget|core::mem::forget' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            log_high "$file:$line - mem::forget detected: $content"
            ((violations++)) || true
        done < <(rg -H -n 'std::mem::forget|core::mem::forget' "$SCAN_TARGET")
    fi

    # Check for ManuallyDrop misuse
    if rg -q 'ManuallyDrop' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            log_medium "$file:$line - ManuallyDrop usage (verify correctness): $content"
            ((violations++)) || true
        done < <(rg -H -n 'ManuallyDrop' "$SCAN_TARGET")
    fi

    # Check for static mut (global mutable state)
    if rg -q 'static\s+mut\s+' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            log_critical "$file:$line - static mut detected (forbidden): $content"
            ((violations++)) || true
        done < <(rg -H -n 'static\s+mut\s+' "$SCAN_TARGET")
    fi

    if [[ $violations -eq 0 ]]; then
        log_pass "Memory patterns audit passed"
    fi
}

################################################################################
# LAYER 7: DEPENDENCY AUDIT
################################################################################

audit_dependencies() {
    log_section "LAYER 7: DEPENDENCY AUDIT"

    if should_skip_project_layer; then
        return
    fi

    cd "$PROJECT_ROOT"

    # Check for security vulnerabilities
    if check_command cargo-audit; then
        echo "  Running cargo-audit..."
        local audit_output audit_rc=0 audit_stale=0 audit_reported=0
        # THE EXIT STATUS CARRIES THE VERDICT, the output only explains it.
        # cargo-audit exits 0 when the audit completed and found nothing it
        # treats as a failure (allowed warnings included), and non-zero both
        # when it finds vulnerabilities AND when it fails to run. Reading only
        # the text meant that any failure shape the patterns did not cover --
        # a database that fails to load after a successful fetch, an output in
        # JSON because the user configured it, any unanticipated error -- fell
        # through to "No known vulnerabilities", i.e. a silent false clearance
        # on a security audit. So: PASS requires a completed audit, and an
        # unrecognised failure is reported, never swallowed.
        audit_output=$(cargo audit 2>&1) || audit_rc=$?
        # A fetch failure is not a verdict either: retry on the local copy, say
        # so, and never pass when no database could be consulted.
        if echo "$audit_output" | grep -qE "couldn't fetch advisory database|failed to fetch advisory database"; then
            audit_stale=1
            audit_rc=0
            audit_output=$(cargo audit -n 2>&1) || audit_rc=$?
            if echo "$audit_output" | grep -qE "error loading advisory database|no advisory database|couldn't open advisory database"; then
                log_high "cargo-audit could not consult any advisory database (fetch failed and no local copy): dependencies NOT audited"
                audit_reported=1
            else
                log_medium "cargo-audit ran on the LOCAL advisory database (fetch failed, database may be stale)"
            fi
        fi
        if echo "$audit_output" | grep -q "unsupported CVSS version"; then
            log_low "cargo-audit database uses CVSS 4.0 (not yet supported by cargo-audit)"
        fi
        if [[ $audit_reported -eq 0 ]]; then
            if echo "$audit_output" | grep -qE "^Vulnerability|[0-9]+ vulnerabilit(y|ies) found"; then
                log_critical "Security vulnerabilities found in dependencies"
            elif [[ $audit_rc -ne 0 ]]; then
                # Non-zero, and not a shape we recognise: do NOT clear the tree.
                log_high "cargo-audit exited $audit_rc with an output this scan does not recognise: dependencies NOT audited"
            elif [[ $audit_stale -ne 0 ]]; then
                : # already reported as MEDIUM above; a stale database cannot clear
            else
                log_pass "No known vulnerabilities"
            fi
        fi
        # Advisories that are not vulnerabilities (unmaintained, unsound, yanked)
        # are counted by cargo-audit as "allowed warnings" and exit 0 with them,
        # so a scan that only looks for vulnerabilities clears them in silence.
        local audit_warnings
        audit_warnings=$(echo "$audit_output" | sed -n 's/^warning: \([0-9]\+\) allowed warnings\? found$/\1/p' | tail -1)
        if [[ -n "$audit_warnings" && "$audit_warnings" != "0" ]]; then
            local audit_unsound
            audit_unsound=$(echo "$audit_output" | grep -c "^Warning:[[:space:]]*unsound" || true)
            if [[ "$audit_unsound" -gt 0 ]]; then
                log_medium "cargo-audit reports $audit_warnings advisory warnings on dependencies, $audit_unsound of them unsound"
            else
                log_low "cargo-audit reports $audit_warnings advisory warnings on dependencies (unmaintained or yanked, no vulnerability)"
            fi
        fi
    fi

    # Check for outdated dependencies
    if check_command cargo-outdated; then
        echo "  Checking for outdated dependencies..."
        local outdated=$(cargo outdated --exit-code 1 2>&1 | grep -c "out of date" || true)
        if [[ $outdated -gt 5 ]]; then
            log_medium "Found $outdated outdated dependencies"
        fi
    fi

    # Check number of dependencies (less is better for security)
    local dep_count=$(cargo tree --prefix none --no-dedupe 2>/dev/null | wc -l)
    echo "  Total dependencies: $dep_count"
    if [[ $dep_count -gt 100 ]]; then
        log_low "High number of dependencies: $dep_count (consider reducing)"
    fi

    # Check for duplicate dependencies with different versions
    local duplicates=$(cargo tree --prefix none --no-dedupe 2>/dev/null | \
                       grep -oE '^[a-z0-9_-]+ v[0-9.]+' | \
                       cut -d' ' -f1 | sort | uniq -c | grep -v '^ *1 ' | wc -l)
    if [[ $duplicates -gt 0 ]]; then
        log_low "Found $duplicates duplicate dependencies with different versions"
    fi
}

################################################################################
# LAYER 8: CLIPPY ULTRA-HARDENED MODE
################################################################################

audit_clippy() {
    log_section "LAYER 8: CLIPPY ULTRA-HARDENED MODE"

    if should_skip_project_layer; then
        return
    fi

    cd "$PROJECT_ROOT"

    echo "  Running clippy SAFETY gate (blocking)..."

    # Pass 1 (blocking): safety-critical lints only.
    # This keeps HIGH reserved for patterns that can hide runtime failures.
    local safety_output
    if safety_output=$(
        cargo clippy -p hdds --lib --all-features --no-deps -- \
            -D warnings \
            -D clippy::unwrap_used \
            -D clippy::expect_used \
            -D clippy::panic \
            -D clippy::unimplemented \
            -D clippy::todo \
            2>&1
    ); then
        log_pass "Clippy safety gate passed"
    else
        # Keep the `-->` location lines. Filtering to "error:"/"warning:" alone
        # produced a release-blocking HIGH that named no file and no line, so
        # the only way to act on it was to re-run clippy by hand.
        echo "$safety_output" | grep -E "^(error|warning)(\[|:)|^ *--> " | head -40 || true
        local first_site
        first_site=$(echo "$safety_output" | grep -m1 -E "^ *--> " | sed 's/^ *--> //')
        if [[ -n "$first_site" ]]; then
            log_high "Clippy safety violations found (first: ${first_site})"
        else
            log_high "Clippy safety violations found"
        fi
        return
    fi

    echo "  Running clippy ULTRA-HARDENED style pass (non-blocking)..."

    # Pass 2 (non-blocking): ultra-hardened quality profile.
    # Failing this pass is tracked as MEDIUM to keep quality pressure without
    # blocking releases on broad style churn.
    local clippy_output
    if clippy_output=$(
        cargo clippy -p hdds --lib --all-features --no-deps -- \
            -D warnings \
            -W clippy::pedantic \
            -W clippy::nursery \
            -W clippy::cargo \
            -A clippy::multiple-crate-versions \
            -D clippy::indexing_slicing \
            -D clippy::empty_drop \
            -D clippy::inefficient_to_string \
            2>&1
    ); then
        log_pass "Clippy ultra-hardened mode passed"
    else
        echo "$clippy_output" | grep -E "(error|warning):" | head -20 || true
        log_medium "Clippy ultra-hardened style violations found (non-blocking)"
    fi
}

################################################################################
# LAYER 9: DOCUMENTATION COVERAGE
################################################################################

audit_documentation() {
    log_section "LAYER 9: DOCUMENTATION COVERAGE"

    local violations=0

    # Check for missing docs on public items
    # Force rg to always show filename with -H
    if rg -q '^pub (fn|struct|enum|trait|type|const|static|mod) \w+' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            # Check if previous line(s) have doc comment (skip attributes and blank lines)
            if [[ "$line" =~ ^[0-9]+$ ]]; then
                local check_line=$((line - 1))
                local found_doc=0

                # Walk backwards up to 10 lines to find documentation
                # Skip: attributes (#[...]), blank lines, closing braces
                while [[ $check_line -gt 0 ]] && [[ $((line - check_line)) -lt 10 ]]; do
                    local prev_content=$(sed -n "${check_line}p" "$file" 2>/dev/null || echo "")

                    # Found doc comment -> OK
                    if [[ "$prev_content" =~ ^[[:space:]]*/// ]]; then
                        found_doc=1
                        break
                    fi

                    # Skip attributes, blank lines, closing braces
                    if [[ "$prev_content" =~ ^[[:space:]]*#\[ ]] || \
                       [[ "$prev_content" =~ ^[[:space:]]*$ ]] || \
                       [[ "$prev_content" =~ ^[[:space:]]*\}[[:space:]]*$ ]]; then
                        ((check_line--)) || true
                        continue
                    fi

                    # Hit non-doc, non-attribute line -> missing doc
                    break
                done

                if [[ $found_doc -eq 0 ]]; then
                    log_medium "$file:$line - Missing documentation: $content"
                    ((violations++)) || true
                fi
            fi
        done < <(rg -H -n '^pub (fn|struct|enum|trait|type|const|static|mod) \w+' "$SCAN_TARGET" | head -30)
    fi

    # Check for # Safety sections in unsafe functions
    if rg -q 'pub unsafe fn' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            # Look for # Safety section in preceding comments
            if [[ "$line" =~ ^[0-9]+$ ]]; then
                local start=$((line > 10 ? line - 10 : 1))
                local context=$(sed -n "${start},${line}p" "$file" 2>/dev/null || echo "")

                if ! echo "$context" | grep -q '# Safety'; then
                    log_critical "$file:$line - Unsafe function without # Safety docs: $content"
                    ((violations++)) || true
                fi
            fi
        done < <(rg -H -n 'pub unsafe fn' "$SCAN_TARGET")
    fi

    if [[ $violations -eq 0 ]]; then
        log_pass "Documentation coverage adequate"
    fi
}

################################################################################
# LAYER 10: CONCURRENCY AUDIT
################################################################################

audit_concurrency() {
    log_section "LAYER 10: CONCURRENCY AUDIT"

    local violations=0

    # Check for std::thread::spawn without proper join handling
    if rg -q 'thread::spawn' "$SCAN_TARGET"; then
        log_low "Found thread::spawn usage - ensure JoinHandle is properly joined or detached"
    fi

    # Check for Mutex without poisoning handling
    if rg -q '\.lock\(\)\.unwrap\(\)' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            # Skip if in inline #[cfg(test)] module
            local test_start
            test_start=$(grep -n '#\[cfg(test)\]' "$file" 2>/dev/null | head -1 | cut -d: -f1) || true
            if [[ -n "$test_start" ]] && [[ "$line" -gt "$test_start" ]]; then
                continue
            fi

            log_high "$file:$line - Mutex lock without poison handling: $content"
            ((violations++)) || true
        done < <(rg -H -n '\.lock\(\)\.unwrap\(\)' "$SCAN_TARGET" | head -10)
    fi

    # Check for potential race conditions (static with interior mutability)
    # Note: OnceLock<...> is safe lazy initialization and excluded from this check
    # Pattern: "static NAME:" to match declarations, not return types like "&'static Mutex"
    if rg -q 'static\s+[A-Z_][A-Z0-9_]*\s*:.*(RefCell|Mutex|RwLock)' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            # Skip OnceLock patterns (safe lazy static initialization)
            if [[ "$content" =~ OnceLock ]]; then
                continue
            fi
            # Skip if suppressed with @audit-ok
            if is_suppressed "$file" "$line"; then
                continue
            fi

            log_high "$file:$line - Global state with interior mutability: $content"
            ((violations++)) || true
        done < <(rg -H -n 'static\s+[A-Z_][A-Z0-9_]*\s*:.*(RefCell|Mutex|RwLock)' "$SCAN_TARGET")
    fi

    if [[ $violations -eq 0 ]]; then
        log_pass "Concurrency patterns look safe"
    fi
}

################################################################################
# LAYER 11: LICENSE AND COPYRIGHT
################################################################################

audit_license() {
    log_section "LAYER 11: LICENSE AND COPYRIGHT"

    local violations=0

    # Check for license headers in source files
    local files_without_header=0
    while IFS= read -r file; do
        if ! head -n 5 "$file" | grep -qE '(Copyright|License|SPDX)'; then
            ((files_without_header++)) || true
        fi
    done < <(get_target_files)

    if [[ $files_without_header -gt 0 ]]; then
        log_low "Found $files_without_header files without license headers"
        ((violations++)) || true
    fi

    # Check for GPL contamination (if not intended) - only in full project mode
    if [[ $SINGLE_FILE_MODE -eq 0 ]]; then
        if grep -q "GPL" "$PROJECT_ROOT/Cargo.toml" 2>/dev/null; then
            log_medium "GPL license detected - verify compatibility"
            ((violations++)) || true
        fi
    fi

    if [[ $violations -eq 0 ]]; then
        log_pass "License compliance OK"
    fi
}

################################################################################
# LAYER 12: PERFORMANCE ANTIPATTERNS
################################################################################

audit_performance() {
    log_section "LAYER 12: PERFORMANCE ANTIPATTERNS"

    local violations=0

    # Check for collect() followed by len() (use count() instead)
    if rg -q '\.collect::<.*>\(\)\.len\(\)' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            log_medium "$file:$line - Inefficient collect().len() (use count()): $content"
            ((violations++)) || true
        done < <(rg -H -n '\.collect::<.*>\(\)\.len\(\)' "$SCAN_TARGET")
    fi

    # Check for String allocation in loops
    if rg -q 'for.*\{.*String::new\(\)' "$SCAN_TARGET"; then
        log_medium "String allocation in loop detected (move outside loop)"
        ((violations++)) || true
    fi

    # Check for format! in hot paths (only core/rt directory, exclude tests)
    # Only check if we're scanning core/rt or in full project mode
    if [[ "$SCAN_TARGET" =~ core/rt ]] || [[ $SINGLE_FILE_MODE -eq 0 ]]; then
        # Determine the target: either the specific file/dir or force core/rt in full mode
        local rt_target
        if [[ "$SCAN_TARGET" =~ core/rt ]]; then
            rt_target="$SCAN_TARGET"
        else
            rt_target="$SRC_DIR/core/rt"
        fi

        # Find format!() outside of #[cfg(test)] sections in core/rt only
        # Strategy: Search for format!() then verify it appears before any #[cfg(test)] in the file
        local has_format_in_prod=0
        if [[ -d "$rt_target" ]] || [[ -f "$rt_target" ]]; then
            while IFS=: read -r file line_no _content; do
                # Production unless the line sits inside an inline test block
                # (by range; "before the first #[cfg(test)]" hid everything
                # after the first test module).
                if ! is_test_only_line "$file" "$line_no"; then
                    has_format_in_prod=1
                    break
                fi
            done < <(rg -H -n 'format!\(' --type rust "$rt_target" 2>/dev/null || true)
        fi

        if [[ $has_format_in_prod -eq 1 ]]; then
            log_medium "format!() in runtime core production code (allocates, avoid in hot path)"
            ((violations++)) || true
        fi
    fi

    if [[ $violations -eq 0 ]]; then
        log_pass "No obvious performance antipatterns"
    fi
}

################################################################################
# LAYER 13: RTPS/DDS COMPLIANCE
################################################################################

audit_rtps_compliance() {
    log_section "LAYER 13: RTPS/DDS COMPLIANCE"

    local violations=0

    # Check for proper endianness handling (skip in single-file mode if not a serialization file)
    if [[ $SINGLE_FILE_MODE -eq 0 ]] || [[ "$SCAN_TARGET" =~ /ser/ ]]; then
        local ser_check_target="$SCAN_TARGET"
        if [[ $SINGLE_FILE_MODE -eq 0 ]]; then
            ser_check_target="$SRC_DIR/core/ser"
        fi

        if ! rg -q 'ByteOrder|to_be_bytes|to_le_bytes|from_be_bytes|from_le_bytes' "$ser_check_target" 2>/dev/null; then
            log_high "No explicit endianness handling in serialization"
            ((violations++)) || true
        fi
    fi

    # Check for proper CDR2 alignment (intelligent check)
    # HEURISTIC: Distinguish CDR data structures from tools
    # - Encoder/Decoder/Builder/Factory/Handler = TOOLS (no #[repr(C)] needed)
    # - Msg/Data/Guid/Header/EntityId = WIRE DATA (MUST have #[repr(C)])

    local cdr_violations=0
    local tool_structs=0

    # Pattern 1: Find structs in the CDR2 serializer that are NOT tools
    # (core/ser/cdr2.rs was split; pl_cdr2.rs is the surviving wire-side file)
    local cdr2_file="$SRC_DIR/core/ser/pl_cdr2.rs"
    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        [[ "$SCAN_TARGET" =~ cdr2\.rs$ ]] && cdr2_file="$SCAN_TARGET" || cdr2_file=""
    fi

    if [[ -n "$cdr2_file" ]] && [[ -f "$cdr2_file" ]]; then
        while IFS=: read -r line struct_name; do
            # Skip tool structs (Encoder/Decoder/Builder/etc)
            if [[ "$struct_name" =~ (Encoder|Decoder|Builder|Factory|Handler|Context|Config|Cursor) ]]; then
                ((tool_structs++)) || true
            else
                # This is potentially a wire-data struct, check for #[repr(C)]
                local linenum=$(echo "$line" | cut -d: -f1)
                local check_start=$((linenum > 3 ? linenum - 3 : 1))
                if ! sed -n "${check_start},${linenum}p" "$cdr2_file" | grep -q '#\[repr(C)\]'; then
                    log_high "$cdr2_file:$linenum - Wire struct '$struct_name' missing #[repr(C)]"
                    ((cdr_violations++)) || true
                fi
            fi
        done < <(rg -H -n '^pub struct (\w+)' "$cdr2_file" -r '$1' --only-matching 2>/dev/null | awk '{print NR":"$0}')

        if [[ $tool_structs -gt 0 ]]; then
            log_pass "Skipped $tool_structs tool structs in cdr2.rs (no #[repr(C)] needed)"
        fi
    fi

    # Pattern 2: Check wire-data structs in reliability/ (Msg/Header/Data types)
    # (formerly qos/reliable/, renamed during the reliability rework)
    local reliable_dir="$SRC_DIR/reliability/"
    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        [[ "$SCAN_TARGET" =~ /reliability/ ]] && reliable_dir="$SCAN_TARGET" || reliable_dir=""
    fi

    if [[ -n "$reliable_dir" ]]; then
        while IFS=: read -r file line struct_name; do
            if [[ "$struct_name" =~ (Msg|Header|Data|Guid|EntityId|SequenceNumber)$ ]]; then
                local linenum="$line"
                local check_start=$((linenum > 3 ? linenum - 3 : 1))
                if ! sed -n "${check_start},${linenum}p" "$file" | grep -q '#\[repr(C)\]'; then
                    # Only warn if struct has fields (not just type alias)
                    if sed -n "${linenum}p" "$file" | grep -q '{'; then
                        log_medium "$file:$linenum - Wire struct '$struct_name' possibly missing #[repr(C)] (verify manual serialization)"
                        ((cdr_violations++)) || true
                    fi
                fi
            fi
        done < <(rg -H -n '^pub struct (\w+)' "$reliable_dir" -r '$1' 2>/dev/null | awk -F: '{print $1":"$2":"$3}')
    fi

    if [[ $cdr_violations -gt 0 ]]; then
        ((violations += cdr_violations)) || true
    fi

    # Check for magic numbers (should use constants)
    # Skip: comments (//!, ///, //), const declarations,
    #       well-known algorithm constants (FNV-1a / SHA-256 tables)
    # Skip: lines with @audit-ok suppression
    # Skip: test code (test globs below, inline #[cfg(test)] blocks by range)
    #
    # No `| head -20` here: a cap applied BEFORE the filters would judge twenty
    # raw matches picked in parallel-walk order, differing between identical
    # runs. Filter first, count everything that survives.
    if rg -q '0x52545053|0x[0-9a-fA-F]{8}' "$SCAN_TARGET"; then
        while IFS=: read -r file line content; do
            # Skip test-only code (inline #[cfg(test)] block)
            if is_test_only_line "$file" "$line"; then
                continue
            fi
            # Skip if suppressed with @audit-ok
            if is_suppressed "$file" "$line"; then
                continue
            fi
            # Skip documentation comments and regular comments
            if echo "$content" | grep -qE '^\s*(//!|///|//)'; then
                continue
            fi
            # Skip const declarations
            if echo "$content" | grep -q "const"; then
                continue
            fi
            # Skip well-known algorithm constants (FNV-1a: 0x811c9dc5, 0x01000193)
            if echo "$content" | grep -qE '0x811c9dc5|0x01000193'; then
                continue
            fi
            # Skip known cryptographic constant tables (SHA-256 implementations)
            if echo "$file" | grep -qE 'sha256\.rs$'; then
                continue
            fi
            log_medium "$file:$line - Magic number without const: $content"
            ((violations++)) || true
        done < <(rg -H -n '0x52545053|0x[0-9a-fA-F]{8}' "$SCAN_TARGET" \
            --glob '!**/tests/**' --glob '!**/*_test.rs' 2>/dev/null || true)
    fi

    if [[ $violations -eq 0 ]]; then
        log_pass "RTPS compliance checks passed"
    fi
}

################################################################################
# LAYER 14: TEST COVERAGE
################################################################################

audit_test_coverage() {
    log_section "LAYER 14: TEST COVERAGE"

    if should_skip_project_layer; then
        return
    fi

    cd "$PROJECT_ROOT"

    if check_command cargo-tarpaulin; then
        echo "  Calculating test coverage..."
        local coverage=$(cargo tarpaulin --print-summary 2>/dev/null | grep "Coverage" | grep -oE '[0-9.]+%' | tr -d '%')

        if [[ -n "$coverage" ]]; then
            echo "  Test coverage: ${coverage}%"
            # awk instead of bc: bc is not guaranteed installed, and a missing
            # bc must not silently skip the coverage floor (fail-open).
            if awk -v c="$coverage" -v m="$MIN_TEST_COVERAGE" 'BEGIN { exit !(c < m) }'; then
                log_high "Test coverage ${coverage}% below minimum ${MIN_TEST_COVERAGE}%"
            else
                log_pass "Test coverage meets requirements"
            fi
        fi
    else
        echo "  (Install cargo-tarpaulin for coverage analysis)"
    fi

    # Count test functions
    local test_count=$(rg -c '#\[test\]|#\[tokio::test\]' "$SRC_DIR" 2>/dev/null | awk -F: '{s+=$2} END {print s}' || true)
    echo "  Test functions: ${test_count:-0}"

    if [[ ${test_count:-0} -lt 100 ]]; then
        log_medium "Low test count: ${test_count:-0} (recommend >100)"
    fi
}

################################################################################
# LAYER 15: UNSAFE CODE BUDGET (cargo-geiger)
################################################################################

audit_geiger() {
    log_section "LAYER 15: UNSAFE CODE BUDGET (cargo-geiger)"

    if should_skip_project_layer; then
        return
    fi

    cd "$PROJECT_ROOT"

    if ! check_command cargo-geiger; then
        echo "  [!]  cargo-geiger not installed (cargo install cargo-geiger)"
        echo "  Skipping unsafe budget analysis..."
        return 0
    fi

    # Create report directory
    mkdir -p "$REPORT_DIR"

    echo "  Running cargo-geiger (unsafe detection)..."
    local geiger_rc=0
    cargo geiger -q --manifest-path "$PROJECT_ROOT/crates/hdds/Cargo.toml" --all-features --output-format Json > "$REPORT_DIR/geiger.json" 2>"$REPORT_DIR/geiger.err" || geiger_rc=$?

    # The budget is MEASURED only when geiger exited 0 and its output is a JSON
    # report with a non-empty package list. Anything else is NOT MEASURED, which
    # is a HIGH process error, never "Unsafe budget OK" (a swallowed jq error
    # on an empty geiger.json must not read as "no unsafe").
    local not_measured=""
    if [[ $geiger_rc -ne 0 ]]; then
        not_measured="cargo-geiger exited ${geiger_rc} (see geiger.err)"
    elif ! check_command jq; then
        not_measured="jq not installed, geiger.json cannot be read"
    elif [[ ! -s "$REPORT_DIR/geiger.json" ]] \
         || ! jq -e '(.packages | type == "array") and ((.packages | length) > 0)' "$REPORT_DIR/geiger.json" >/dev/null 2>&1; then
        not_measured="geiger.json is empty or not a geiger report with a package list"
    fi

    if [[ -n "$not_measured" ]]; then
        echo "  [!]  Unsafe budget NOT MEASURED: ${not_measured}"
        log_high "Unsafe budget NOT MEASURED: ${not_measured}"
        return 0
    fi

    local unsafe_packages
    if ! unsafe_packages=$(jq -r '.packages[] | select(.unsafety.used.unsafe > 0) | "\(.package.name): \(.unsafety.used.unsafe) unsafe"' "$REPORT_DIR/geiger.json"); then
        log_high "Unsafe budget NOT MEASURED: jq could not read geiger.json"
        return 0
    fi

    if [[ -n "$unsafe_packages" ]]; then
        echo ""
        echo "  Unsafe usage detected:"
        echo "$unsafe_packages" | while read -r line; do
            echo "    $line"
        done
        log_high "Unsafe code detected (see geiger.json for details)"
    else
        log_pass "Unsafe budget OK (minimal unsafe usage)"
    fi
}

################################################################################
# LAYER 16: SWALLOWED RESULTS DETECTION
################################################################################

detect_swallowed_results() {
    log_section "LAYER 16: SWALLOWED RESULTS DETECTION"

    local violations=0

    if ! check_command rg; then
        echo "  [!]  ripgrep (rg) not installed"
        return 0
    fi

    echo "  Scanning for '_ = expr;' patterns (swallowed results)..."

    # Create report directory
    mkdir -p "$REPORT_DIR"

    # Use null-delimited file list for safety
    local matches
    matches=$(find "$SRC_DIR" -name '*.rs' -type f -print0 2>/dev/null | \
              xargs -0 rg -n -H --no-heading --hidden --glob '!target' \
              --regexp '^[[:space:]]*_\s*=\s*[^;]+;' 2>/dev/null || true)

    if [[ -n "$matches" ]]; then
        printf '%s\n' "$matches" > "$REPORT_DIR/swallowed_results.txt"
        local count=$(echo "$matches" | wc -l)
        echo "  Found $count swallowed-result patterns"
        echo "  Details saved to: $REPORT_DIR/swallowed_results.txt"

        # Show first 5 violations
        echo ""
        echo "  First violations:"
        echo "$matches" | head -5 | while IFS=: read -r file line content; do
            log_high "$file:$line - Swallowed result: $content"
            ((violations++)) || true
        done
    else
        log_pass "No suspicious '_ =' patterns found"
    fi
}

################################################################################
# LAYER 17: UNUSED DEPENDENCIES (cargo-udeps)
################################################################################

audit_udeps() {
    log_section "LAYER 17: UNUSED DEPENDENCIES (cargo-udeps)"

    if should_skip_project_layer; then
        return
    fi

    cd "$PROJECT_ROOT"

    if ! check_command cargo-udeps; then
        echo "  [!]  cargo-udeps not installed (cargo install cargo-udeps)"
        echo "  Skipping unused dependency detection..."
        return 0
    fi

    echo "  Running cargo-udeps (unused deps detection)..."

    local udeps_output
    udeps_output=$(cargo +nightly udeps --all-targets 2>&1) || true
    if echo "$udeps_output" | grep -q "unused crate"; then
        # Downgrade to MEDIUM - udeps often has false positives with feature flags
        log_medium "Unused dependencies detected (review manually - may be feature-gated)"
        echo "$udeps_output" | grep "unused crate" | head -5
    else
        log_pass "No unused dependencies"
    fi
}

################################################################################
# LAYER 18: SECRETS DETECTION
################################################################################

check_secrets() {
    log_section "LAYER 18: SECRETS DETECTION"

    local violations=0

    if ! check_command rg; then
        log_medium "ripgrep (rg) not installed. Secrets scan skipped."
        return 0
    fi

    # Create report directory
    if ! mkdir -p "$REPORT_DIR"; then
        log_high "Cannot create report directory: $REPORT_DIR"
        return 0
    fi

    echo "  Scanning for hardcoded secrets..."

    # Look for actual hardcoded secrets (assignments with string literals)
    # Patterns: password = "...", secret: "...", token = String::from("...")
    local patterns='(password|secret|api_key)\s*[=:]\s*"[^"]+"|String::from\("[^"]*secret|String::from\("[^"]*password'
    local secrets_report="$REPORT_DIR/secrets.txt"
    local scan_status=0

    # Validate report path is writable before running scan; otherwise rg exit code
    # may be mistaken for "no matches".
    if ! : 2>/dev/null > "$secrets_report"; then
        log_high "Cannot write secrets report: $secrets_report"
        return 0
    fi

    # Honour single-file mode: scanning $SRC_DIR unconditionally made a
    # `--file` run inherit findings from the whole project, so an isolated file
    # could never come back clean.
    local -a rg_targets
    mapfile -t rg_targets < <(get_rg_targets)

    # -H is NOT optional. ripgrep prints the filename only when it searches more
    # than one path, so with a SINGLE target -- exactly what the pre-commit hook
    # passes -- every line came back as "LINE:content" instead of
    # "FILE:LINE:content". The reader below then bound file=<line number> and
    # line=<start of the code>, so is_suppressed() received a non-numeric line
    # and returned false for everything: @audit-ok could never suppress a secret
    # finding in the one mode the hook ever runs. Forcing the filename makes the
    # three-field read correct in both modes; with several targets rg already
    # prints it, so this changes nothing there.
    if rg -i -n -H --no-heading --hidden --glob '!target' --glob '!*.md' --glob '!**/tests/**' \
       "$patterns" "${rg_targets[@]}" > "$secrets_report" 2>/dev/null; then
        scan_status=0
    else
        scan_status=$?
    fi

    if [[ $scan_status -eq 1 ]]; then
        log_pass "No hardcoded secrets detected"
        return 0
    fi

    if [[ $scan_status -ne 0 ]]; then
        log_high "Secrets scan failed (rg exit code: $scan_status)"
        return 0
    fi

    if [[ -s "$secrets_report" ]]; then
        local count
        count=$(wc -l < "$secrets_report")
        local shown=0
        local header_printed=0

        while IFS=: read -r file line content; do
            # Skip explicit audit suppressions
            if is_suppressed "$file" "$line"; then
                continue
            fi

            # Skip doc comments
            if [[ "$content" =~ ^[[:space:]]*//[!/] ]]; then
                continue
            fi

            # Skip well-known placeholder credentials from official docs/examples.
            if echo "$content" | grep -qE 'EXAMPLE(KEY|SECRET)|AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'; then
                continue
            fi

            if [[ $header_printed -eq 0 ]]; then
                echo "  Found $count potential hardcoded secrets"
                echo "  Details saved to: $secrets_report"
                echo ""
                echo "  First matches:"
                header_printed=1
            fi

            log_high "$file:$line - Potential hardcoded secret: $content"
            ((violations++)) || true
            ((shown++)) || true

            if [[ $shown -ge 3 ]]; then
                break
            fi
        done < "$secrets_report"

        if [[ $violations -eq 0 ]]; then
            log_pass "No hardcoded secrets detected (all matches suppressed)"
        fi
    else
        # Defensive fallback in case rg returned 0 with no persisted lines.
        log_medium "Secrets scan produced no persisted matches; verify scan output manually"
    fi
}

################################################################################
# LAYER 19: CODE DUPLICATION ANALYSIS
################################################################################

audit_duplication() {
  log_section "LAYER 19: CODE DUPLICATION ANALYSIS"

  local violations=0

  # Check if jscpd is installed
  if ! check_command jscpd; then
      echo "  [!]  jscpd not installed (npm install -g jscpd)"
      echo "  Skipping duplication analysis..."
      return 0
  fi

  # Create temp output directory
  local report_dir="${PROJECT_ROOT}/target/duplication-report"
  mkdir -p "$report_dir"

  # Run jscpd scan
  echo "  Running token-based duplication detection..."
  jscpd \
      --min-lines 8 \
      --min-tokens 40 \
      --threshold "${MAX_DUPLICATION_PERCENT}" \
      --format rust \
      --reporters "json" \
      --output "$report_dir" \
      --ignore "**/target/**,**/tests/**,**/benches/**,**/generated/**,**/build.rs" \
      "$SCAN_TARGET" 2>/dev/null || true

  # Parse results
  local report="${report_dir}/jscpd-report.json"
  if [[ -f "$report" ]]; then
      # Extract metrics using jq (safer than parsing JSON in bash)
      if check_command jq; then
          local percentage=$(jq -r '.statistics.total.percentage // 0' "$report" 2>/dev/null || echo "0")
          local duplicates=$(jq -r '.statistics.total.duplicates // 0' "$report" 2>/dev/null || echo "0")
          local total_clones=$(jq -r '.duplicates | length // 0' "$report" 2>/dev/null || echo "0")

          # Filter clones: skip if either file has @audit-ok in first 20 lines
          local suppressed_clones=0
          local active_clones=0

          while IFS= read -r clone_json; do
              local file1=$(echo "$clone_json" | jq -r '.firstFile.name')
              local file2=$(echo "$clone_json" | jq -r '.secondFile.name')

              # Check if either file has @audit-ok marker
              local file1_suppressed=0
              local file2_suppressed=0

              if [[ -f "$file1" ]] && head -20 "$file1" 2>/dev/null | grep -q '@audit-ok'; then
                  file1_suppressed=1
              fi
              if [[ -f "$file2" ]] && head -20 "$file2" 2>/dev/null | grep -q '@audit-ok'; then
                  file2_suppressed=1
              fi

              if [[ $file1_suppressed -eq 1 ]] || [[ $file2_suppressed -eq 1 ]]; then
                  ((suppressed_clones++)) || true
                  ((SUPPRESSED_COUNT++)) || true
              else
                  ((active_clones++)) || true
              fi
          done < <(jq -c '.duplicates[]' "$report" 2>/dev/null)

          echo "  Total duplicates: $duplicates"
          echo "  Duplication rate: ${percentage}%"
          echo "  Clone pairs: $total_clones (suppressed: $suppressed_clones, active: $active_clones)"

          # Check threshold (only count active clones)
          # awk instead of bc: a missing bc must not fail-open the threshold.
          if [[ $active_clones -gt 0 ]] && awk -v p="$percentage" -v t="$MAX_DUPLICATION_PERCENT" 'BEGIN { exit !(p > t) }'; then
              log_medium "Code duplication rate ${percentage}% exceeds threshold ${MAX_DUPLICATION_PERCENT}%"

              # List top 5 non-suppressed duplicates
              echo ""
              echo "  Top active duplicates (not suppressed):"
              local shown=0
              while IFS= read -r clone_json && [[ $shown -lt 5 ]]; do
                  local f1=$(echo "$clone_json" | jq -r '.firstFile.name')
                  local f2=$(echo "$clone_json" | jq -r '.secondFile.name')

                  # Skip if either file has @audit-ok
                  if [[ -f "$f1" ]] && head -20 "$f1" 2>/dev/null | grep -q '@audit-ok'; then
                      continue
                  fi
                  if [[ -f "$f2" ]] && head -20 "$f2" 2>/dev/null | grep -q '@audit-ok'; then
                      continue
                  fi

                  local start1=$(echo "$clone_json" | jq -r '.firstFile.start')
                  local start2=$(echo "$clone_json" | jq -r '.secondFile.start')
                  local lines=$(echo "$clone_json" | jq -r '.lines')
                  echo "    $f1:$start1 <-> $f2:$start2 ($lines lines)"
                  ((shown++)) || true
              done < <(jq -c '.duplicates[]' "$report" 2>/dev/null)

              ((violations++)) || true
          else
              if [[ $suppressed_clones -gt 0 ]]; then
                  log_pass "Duplication OK ($suppressed_clones clone pairs suppressed via @audit-ok)"
              else
                  log_pass "Duplication rate within acceptable range"
              fi
          fi
      else
          echo "  [!]  jq not installed, cannot parse duplication metrics"
      fi
  else
      echo "  [!]  No duplication report generated"
  fi

  # Cleanup old reports (keep last 3)
  find "${PROJECT_ROOT}/target" -maxdepth 1 -name "duplication-report-*" -type d 2>/dev/null | \
      sort -r | tail -n +4 | xargs rm -rf 2>/dev/null || true
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Parse command-line arguments
    local target_file=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --file|-f)
                if [[ -z "${2:-}" ]]; then
                    echo "Error: --file requires a file path argument"
                    exit 1
                fi
                target_file="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --file, -f <path>    Audit a single file instead of full project"
                echo "  --skip-validation-gates  Skip layer 0 (fmt/clippy/test global gates)"
                echo "  --verbose, -v        Show timing per layer and cargo output"
                echo "  --help, -h           Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                              # Full project audit"
                echo "  $0 --file src/admin/api.rs     # Single file audit"
                echo ""
                echo "Suppression:"
                echo "  Use // @audit-ok: <reason> to suppress a violation."
                echo "  The comment must be on the same line or up to 3 lines above."
                echo ""
                echo "  Example:"
                echo "    // @audit-ok: intentional dialect-specific implementation"
                echo "    let magic = 0xDEADBEEF;"
                echo ""
                echo "  Suppressed items are counted but not reported as violations."
                exit 0
                ;;
            --skip-validation-gates)
                SKIP_VALIDATION_GATES=1
                shift
                ;;
            --verbose|-v)
                VERBOSE=1
                shift
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Configure scan target
    if [[ -n "$target_file" ]]; then
        # Single file mode
        if [[ ! -f "$target_file" ]]; then
            echo "Error: File not found: $target_file"
            exit 1
        fi
        SCAN_TARGET="$(realpath "$target_file")"
        SINGLE_FILE_MODE=1
        # Judge a file only if a FULL run would have scanned it. `crates/hdds/
        # examples/` is outside every root in `get_test_only_roots`, so the
        # project has no audited standard for it -- and an example legitimately
        # uses `unwrap()` for brevity where the library may not. Without this,
        # `--file` mode applied library rules to files the project never audits,
        # and the pre-commit hook blocked a pure `cargo fmt` commit on 40
        # pre-existing findings in `examples/shape_main.rs` that no full run has
        # ever reported. Same family as the test-only index bug above: the
        # hook's scope was WIDER than the audit's own.
        local in_scope=0 root
        while IFS= read -r root; do
            [[ "$SCAN_TARGET" == "$root"/* ]] && in_scope=1
        done < <(get_test_only_roots)
        if [[ $in_scope -eq 0 ]]; then
            echo "Not audited: $SCAN_TARGET is outside the audit's scan roots"
            echo "  (a full run scans crates/hdds/src, tools/ and the service crates)"
            exit 0
        fi
    else
        # Full project mode
        SCAN_TARGET="$SRC_DIR"
        SINGLE_FILE_MODE=0
    fi

    echo ""
    echo -e "${MAGENTA}${BOLD}+==============================================================+${NC}"
    echo -e "${MAGENTA}${BOLD}|       HDDS EXTREME AUDIT SCAN v1.1.0-ULTRA-HARDENED         |${NC}"
    echo -e "${MAGENTA}${BOLD}|                   MILITARY GRADE QUALITY               |${NC}"
    echo -e "${MAGENTA}${BOLD}+==============================================================+${NC}"
    echo ""
    echo -e "${BOLD}Target Standards:${NC} ANSSI/IGI-1300, Common Criteria EAL4+, DO-178C"

    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        echo -e "${BOLD}Mode:${NC} Single file audit"
        echo -e "${BOLD}File:${NC} ${SCAN_TARGET}"
        echo -e "${CYAN}Note: Project-wide checks (dependencies, clippy, test coverage) skipped${NC}"
    else
        echo -e "${BOLD}Mode:${NC} Full project audit"
        echo -e "${BOLD}Scanning:${NC} ${SCAN_TARGET}"
    fi
    echo ""

    SCAN_START_TIME=$(date +%s)

    # Check required tools
    echo "Checking tools..."
    # ripgrep is NOT optional: most audit layers are written as
    # `if rg -q '<pattern>'; then <violation>; fi`. Without rg those calls exit
    # 127, the condition reads false, and every one of those layers silently
    # reports zero violations. A scan without rg does not weaken the audit, it
    # inverts it. Abort like we do for cargo.
    check_command rg || { echo "  [X] ripgrep (rg) not found - aborting (most checks depend on it)"; exit 1; }
    check_command cargo || { echo "  [X] cargo not found - aborting"; exit 1; }

    # Which files does the shipped library never compile? Answered once, from
    # the module declarations, before any layer reports anything. Always from
    # the directory roots, never from the scan target -- see
    # `get_test_only_roots` for why a single-file run needs the whole tree.
    build_test_only_index $(get_test_only_roots)
    echo ""

    # Reachability, before the quality layers: a file the compiler never sees
    # is not low-quality code, it is absent code that looks present, and every
    # layer below would report zero findings for it. One implementation
    # (scripts/audit-wiring.py), called from here and from gates.sh.
    log_section "LAYER 0: WIRING (is every file in the build graph?)"
    wiring_log="${TMPDIR:-/tmp}/hdds-wiring-$$.log"
    # Two modes, two scopes: per file the question is about THAT file, so a
    # pre-commit hook cannot be failed by orphans its author never touched.
    wiring_args=()
    if [[ $SINGLE_FILE_MODE -eq 1 ]]; then
        wiring_args=(--file "$SCAN_TARGET")
    fi
    if CARGO_TARGET_DIR="$(audit_target_dir)" python3 "$(dirname "${BASH_SOURCE[0]}")/audit-wiring.py" "${wiring_args[@]}" >"$wiring_log" 2>&1; then
        sed 's/^/  /' "$wiring_log"
        log_pass "Every source file is in the build graph"
    else
        rc_wiring=$?
        sed 's/^/  /' "$wiring_log"
        if [[ $rc_wiring -eq 2 ]]; then
            log_medium "Wiring check SKIPPED: no dep-info under target/ (nothing built)"
            ((SKIPPED_CHECKS++)) || true
        else
            while IFS= read -r orphan_line; do
                log_high "${orphan_line#*: }"
            done < <(grep -E 'NOT IN THE BUILD GRAPH|STALE EXEMPTION' "$wiring_log" || true)
        fi
    fi
    rm -f "$wiring_log"
    echo ""

    # Run all audit layers
    audit_validation_gates
    audit_stubs
    audit_type_safety
    audit_unsafe
    audit_complexity
    audit_panics
    audit_memory_patterns
    audit_dependencies
    audit_clippy
    audit_documentation
    audit_concurrency
    audit_license
    audit_performance
    audit_rtps_compliance
    audit_test_coverage
    audit_geiger
    detect_swallowed_results
    audit_udeps
    check_secrets
    audit_duplication

    # Print elapsed time of last layer
    if [[ -n "$LAYER_START_TIME" ]]; then
        local now elapsed
        now=$(date +%s)
        elapsed=$((now - LAYER_START_TIME))
        echo -e "  ${BLUE}(${elapsed}s)${NC}"
    fi

    # Total elapsed
    local total_elapsed=$(( $(date +%s) - SCAN_START_TIME ))
    local mins=$((total_elapsed / 60))
    local secs=$((total_elapsed % 60))

    # Final summary
    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BOLD}AUDIT SUMMARY${NC}  (${mins}m${secs}s)"
    echo -e "${BLUE}================================================================${NC}"
    echo ""
    echo -e "  ${RED}CRITICAL violations: ${CRITICAL_VIOLATIONS}${NC}"
    echo -e "  ${RED}HIGH violations:     ${HIGH_VIOLATIONS}${NC}"
    echo -e "  ${YELLOW}MEDIUM violations:   ${MEDIUM_VIOLATIONS}${NC}"
    echo -e "  ${CYAN}LOW violations:      ${LOW_VIOLATIONS}${NC}"
    echo "  -----------------------------"
    echo -e "  ${BOLD}TOTAL VIOLATIONS:    ${TOTAL_VIOLATIONS}${NC}"
    echo ""
    if [[ $SUPPRESSED_COUNT -gt 0 ]]; then
        echo -e "  ${GREEN}Suppressed (@audit-ok): ${SUPPRESSED_COUNT}${NC}"
        echo ""
    fi
    if [[ $TEST_ONLY_FILTERED -gt 0 ]]; then
        echo -e "  ${GREEN}Not counted, test-only modules: ${TEST_ONLY_FILTERED}${NC}"
        echo -e "  ${GREEN}   (files the shipped library never compiles; run with"
        echo -e "  ${GREEN}    AUDIT_VERBOSE=1 to see which paths were indexed)${NC}"
        echo ""
    fi

    # Exit codes are taken modulo 256 by the shell, so `exit $TOTAL_VIOLATIONS`
    # reports SUCCESS at exactly 256, 512, ... violations. The acceptance policy
    # alone already allows 199 MEDIUM + 49 LOW = 248, so that wrap point is well
    # within reach. The detailed counts are printed above; the exit status only
    # has to carry pass/fail.
    #   0 = audit passed
    #   1 = violations above policy
    #   2 = audit could not run completely (degraded scan)
    if [[ $SKIPPED_CHECKS -gt 0 ]]; then
        echo -e "${RED}${BOLD}[X] DEGRADED SCAN - ${SKIPPED_CHECKS} check group(s) could not run${NC}"
        echo -e "${RED}   Missing tool(s): ${SKIPPED_TOOLS}${NC}"
        echo -e "${RED}   A check that did not execute is not a check that passed.${NC}"
        echo -e "${RED}   Install the tool(s) and re-run before qualifying a release.${NC}"
        echo ""
        exit 2
    fi

    if [[ $TOTAL_VIOLATIONS -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}[OK] PERFECT SCORE! Code is military-grade certified!${NC}"
        echo -e "${GREEN}   Ready for deployment in nuclear submarines [*]${NC}"
        echo ""
        exit 0
    elif [[ $CRITICAL_VIOLATIONS -eq 0 ]] && [[ $HIGH_VIOLATIONS -eq 0 ]]; then
        # Acceptance criteria: MEDIUM <= MAX_MEDIUM_ACCEPTED, LOW <= MAX_LOW_ACCEPTED
        if [[ $MEDIUM_VIOLATIONS -le $MAX_MEDIUM_ACCEPTED ]] && [[ $LOW_VIOLATIONS -le $MAX_LOW_ACCEPTED ]]; then
            echo -e "${GREEN}[OK] Within acceptance criteria (MEDIUM ${MEDIUM_VIOLATIONS}/${MAX_MEDIUM_ACCEPTED}, LOW ${LOW_VIOLATIONS}/${MAX_LOW_ACCEPTED})${NC}"
            echo -e "${YELLOW}   Fix remaining medium/low issues for perfect score${NC}"
            echo ""
            exit 0
        else
            echo -e "${RED}${BOLD}[X] AUDIT FAILED - acceptance threshold exceeded: MEDIUM ${MEDIUM_VIOLATIONS} (max ${MAX_MEDIUM_ACCEPTED}), LOW ${LOW_VIOLATIONS} (max ${MAX_LOW_ACCEPTED})${NC}"
            echo -e "${RED}   TOTAL: ${TOTAL_VIOLATIONS}${NC}"
            echo ""
            exit 1
        fi
    else
        # Name what actually failed. Announcing "critical issues" on a run whose
        # CRITICAL count is zero is the same class of untruth as a green scan
        # that never ran a check.
        if [[ $CRITICAL_VIOLATIONS -gt 0 ]]; then
            echo -e "${RED}${BOLD}[X] AUDIT FAILED - ${CRITICAL_VIOLATIONS} CRITICAL and ${HIGH_VIOLATIONS} HIGH must be fixed${NC}"
        else
            echo -e "${RED}${BOLD}[X] AUDIT FAILED - no CRITICAL, but ${HIGH_VIOLATIONS} HIGH must be fixed${NC}"
        fi
        if [[ $MEDIUM_VIOLATIONS -gt $MAX_MEDIUM_ACCEPTED ]] || [[ $LOW_VIOLATIONS -gt $MAX_LOW_ACCEPTED ]]; then
            echo -e "${RED}${BOLD}[X] ALSO: acceptance threshold exceeded: MEDIUM ${MEDIUM_VIOLATIONS} (max ${MAX_MEDIUM_ACCEPTED}), LOW ${LOW_VIOLATIONS} (max ${MAX_LOW_ACCEPTED})${NC}"
        fi
        echo -e "${RED}   Not ready for production deployment${NC}"
        echo -e "${RED}   TOTAL: ${TOTAL_VIOLATIONS}${NC}"
        echo ""
        echo "Recommended actions:"
        echo "  1. Fix all CRITICAL violations immediately"
        echo "  2. Address HIGH violations before release"
        echo "  3. Plan to fix MEDIUM violations in the next release cycle"
        echo "  4. Track LOW violations in backlog"
        echo ""
        exit 1
    fi
}

# Run the audit
main "$@"
