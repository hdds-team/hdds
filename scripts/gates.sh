#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

################################################################################
# HDDS QUALITY GATES - the executable form of CONTRIBUTING.md "Quality Gates"
#
# WHY THIS SCRIPT EXISTS
#
# A rule that exists only as prose decays. Two classes of defect are the
# reason for a script:
#
#   1. Code that compiles for Linux ONLY: macOS and Windows targets can go red
#      from a single cause while the Linux host stays green. The remedy is a
#      gate that runs the cross-target checks.
#
#   2. Code behind a NON-DEFAULT feature, for example
#      crates/hdds-c/src/rmw.rs behind #[cfg(feature = "rmw")]: the command
#      people type, `cargo check -p hdds-c`, only ever compiles the default
#      feature set, so a removed API breaks it silently.
#
# DESIGN RULES
#
#   EVERY GATE RUNS, even after one fails. A script that stops at the first
#   failure tells you one thing per run. This one gives the whole picture,
#   then prints a summary table.
#
#   THE EXIT STATUS IS A VERDICT, NEVER A COUNT. An exit status is 8 bits, so
#   `exit $TOTAL_VIOLATIONS` would PASS a tree with exactly 256 violations.
#   Here: 1 on any failure, 0 on none.
#
#   NEVER JUDGE A GATE THROUGH A PIPE. `cargo test | grep` reports grep's
#   status, not the test's. Every gate is redirected to its own log file, $? is captured
#   immediately on the next line, and the log is grepped afterwards.
#
#   A SKIP IS NOT A PASS. A cross target whose toolchain is absent is
#   reported as a loud, explicitly labelled SKIP, and the final verdict says
#   how many gates were skipped. --strict-skip turns skips into failures.
#
#   REPORT THE ACTUAL NUMBERS. Test counts passed/failed/ignored, error
#   counts, per-target results -- not a bare OK/FAIL.
#
# USAGE
#   bash scripts/gates.sh                 full gate set (before a merge)
#   bash scripts/gates.sh --quick         skip the slow lanes (before a commit)
#   bash scripts/gates.sh --hermeticity   additionally A/B the test suite with
#                                         and without HDDS_INTERFACE
#   bash scripts/gates.sh --strict-skip   any SKIP counts as a failure
#   bash scripts/gates.sh --list          print the gate set and exit
#
# Logs land in target/gate-logs/<timestamp>/ (gitignored with the rest of
# target/). The path is printed at the end of every run.
################################################################################

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 2

# ------------------------------------------------------------------ options --
QUICK=0
HERMETICITY=0
STRICT_SKIP=0
LIST_ONLY=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)       QUICK=1 ;;
        --hermeticity) HERMETICITY=1 ;;
        --strict-skip) STRICT_SKIP=1 ;;
        --list)        LIST_ONLY=1 ;;
        -h|--help)
            sed -n '/^# USAGE/,/^####/p' "${BASH_SOURCE[0]}" \
                | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "gates.sh: unknown option '$1' (try --help)" >&2
            exit 2
            ;;
    esac
    shift
done

# ------------------------------------------------------------------- colours --
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

# The four targets the release must compile for (defect (1) above).
CROSS_TARGETS=(
    x86_64-apple-darwin
    aarch64-apple-darwin
    x86_64-pc-windows-gnu
    aarch64-unknown-linux-gnu
)

if [[ $LIST_ONLY -eq 1 ]]; then
    cat <<'EOF'
HDDS gate set (in order):

  fmt            cargo fmt --all -- --check
  punctuation    tracked *.rs free of em/en dash, Unicode arrow, ellipsis,
                 guillemets and accented letters
  clippy         cargo clippy --all-targets --all-features -- -D warnings
  test           cargo test --all-features
  audit          bash scripts/extrem-audit-scan.sh                    [slow]
  check-ws       cargo check --workspace --all-targets
  hdds-c-rmw     cargo check -p hdds-c --features rmw
  cross:<T>      cargo check -p hdds --lib --target <T>               [slow]
                 for x86_64-apple-darwin, aarch64-apple-darwin,
                 x86_64-pc-windows-gnu, aarch64-unknown-linux-gnu

  [slow] lanes are skipped by --quick.
EOF
    exit 0
fi

RUN_DIR="$REPO_ROOT/target/gate-logs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR" || exit 2

# ------------------------------------------------------------------ results --
# Parallel arrays, appended by record(). Bash 4 associative arrays would do,
# but ordering matters for the summary table and plain arrays keep it.
G_NAME=(); G_STATUS=(); G_DETAIL=(); G_LOG=()

record() {  # record NAME STATUS DETAIL LOGFILE
    G_NAME+=("$1"); G_STATUS+=("$2"); G_DETAIL+=("$3"); G_LOG+=("$4")
    local colour="$NC"
    case "$2" in
        OK)   colour="$GREEN" ;;
        FAIL) colour="$RED" ;;
        SKIP) colour="$YELLOW" ;;
        NOTE) colour="$BLUE" ;;
    esac
    printf '  %s%-6s%s %-32s %s\n' "$colour" "$2" "$NC" "$1" "$3"
}

banner() {
    echo ""
    echo "${BOLD}=== $* ===${NC}"
}

# ------------------------------------------------------- sample classifier --
#
# The sdk/samples/*/rust crates include! files under sdk/samples/**/generated/
# which are GITIGNORED and produced by sdk/samples/scripts/gen_rust_types.sh
# using the `hddsgen` binary from the SEPARATE hdds_gen repository. On a tree
# where that step has not run, those crates cannot compile.
#
# WHICH GATES SEE THEM: only the ones that say --workspace. Cargo.toml sets
# `default-members` to the engine/tools/SDK set precisely so a clean-checkout
# `cargo clippy` / `cargo test` at the root stays off the samples. On a tree
# with no generated types, clippy and the test suite pass and only
# `cargo check --workspace --all-targets` reports sample errors.
#
# THE ERROR COUNT IS NOT STABLE BETWEEN RUNS OF THE SAME TREE. A crate stops
# emitting diagnostics once it fails and the parallel build front differs run
# to run, so the raw count measures nothing and must never be reported as if
# it did.
#
# Classification rule:
#   any error OUTSIDE sdk/samples/  -> FAILURE
#   errors inside sdk/samples/      -> labelled, non-fatal NOTE naming the
#                                      generation step
#
# CAVEAT, printed with the note: a crate that fails to compile stops emitting
# diagnostics, so sample failures can MASK later diagnostics in those same
# sample crates. Only a tree where gen_rust_types.sh has run gives a complete
# check of the sample crates themselves.

SAMPLE_ERRORS=0   # set by classify_json
REAL_ERRORS=0

classify_json() {  # classify_json JSONLOG  -> sets SAMPLE_ERRORS / REAL_ERRORS,
                   # writes JSONLOG.rendered
    local json="$1"
    SAMPLE_ERRORS=0
    REAL_ERRORS=0

    [[ -s "$json" ]] || return 0

    # Human-readable rendering of the same diagnostics, so the log is usable.
    jq -r 'select(.reason=="compiler-message") | .message.rendered // empty' \
        <"$json" >"${json}.rendered" 2>/dev/null

    # One line per error: primary span files, then the message text. Both are
    # inspected, because "couldn't read <path>: No such file or directory"
    # carries the path in the message even when the span points at include!.
    local tsv="${json}.errors.tsv"
    jq -r '
        select(.reason=="compiler-message")
        | .message
        | select(.level=="error")
        | [ ([.spans[]? | select(.is_primary==true) | .file_name] | join(" ")),
            (.message | gsub("\t"; " ") | gsub("\n"; " ")) ]
        | @tsv
    ' <"$json" >"$tsv" 2>/dev/null

    [[ -s "$tsv" ]] || return 0

    SAMPLE_ERRORS=$(grep -c 'sdk/samples/' "$tsv" || true)
    REAL_ERRORS=$(grep -vc 'sdk/samples/' "$tsv" || true)
    grep -v 'sdk/samples/' "$tsv" >"${json}.real-errors.tsv" 2>/dev/null || true
    return 0
}

sample_note() {  # sample_note  -> the labelled non-fatal note, or nothing
    if [[ $SAMPLE_ERRORS -gt 0 ]]; then
        echo ""
        echo "${BLUE}  NOTE (non-fatal, sdk/samples generation step not run):${NC}"
        echo "    ${SAMPLE_ERRORS} error(s) are in sdk/samples/*/rust, whose include! files"
        echo "    under sdk/samples/**/generated/ are gitignored and produced by:"
        echo "      bash sdk/samples/scripts/gen_rust_types.sh"
        echo "    That step needs the 'hddsgen' binary from the SEPARATE hdds_gen"
        echo "    repository (cargo install --path /path/to/hdds_gen --force, or"
        echo "    export HDDSGEN=/abs/path/to/hddsgen)."
        echo "    The count above is NOT a measurement: it is unstable between runs"
        echo "    of the same tree, and sample failures can mask later diagnostics"
        echo "    in those same sample crates."
    fi
}

# --------------------------------------------------------------- gate runner --
#
# The shape every gate uses, and the reason it looks like this:
#   cmd >log 2>&1
#   rc=$?            <- captured on the very next line, from the command
#                       itself, NEVER from a pipeline whose last stage is grep
#   ...grep the FILE afterwards...

run_logged() {  # run_logged LOGFILE cmd...  -> echoes rc
    local log="$1"; shift
    "$@" >"$log" 2>&1
    echo $?
}

# ============================================================================
#                                  GATES
# ============================================================================

echo "${BOLD}HDDS quality gates${NC}"
echo "  repo    : $REPO_ROOT"
echo "  branch  : $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
echo "  head    : $(git log --oneline -1 2>/dev/null || echo '?')"
echo "  logs    : $RUN_DIR"
echo "  mode    : $( [[ $QUICK -eq 1 ]] && echo 'quick (slow lanes skipped)' || echo 'full' )"
echo "  date    : $(date -Is)"

# ------------------------------------------------------- environment probes --
banner "environment"

# The sdk/samples generation step: detected, never run. A gate does not mutate
# the tree it is judging.
# Look specifically at the RUST generated dirs the include!() paths name.
# A bare `-name generated` also matches the C and C++ ones, several of which
# are symlinks that exist in a clean checkout -- it would report "present" on
# a tree where no Rust type has been generated at all.
GEN_DIRS=(sdk/samples/*/rust/generated)
GEN_COUNT=0
for d in "${GEN_DIRS[@]}"; do [[ -d "$d" ]] && GEN_COUNT=$((GEN_COUNT+1)); done
if [[ "$GEN_COUNT" -eq 0 ]]; then
    echo "  ${YELLOW}sdk/samples generated types: ABSENT${NC} (gen_rust_types.sh has not run here)"
    echo "    -> sample crates will fail to compile; those errors are classified"
    echo "       as a non-fatal note, not as a gate failure. See the note below."
else
    echo "  sdk/samples generated types: present ($GEN_COUNT dir(s))"
fi

# Multicast routed into a VPN tunnel silently breaks SPDP discovery. One
# command names the cause, so the gate runs it and prints the answer rather
# than leaving a future reader to rediscover it.
MCAST_ROUTE="$(ip route get 239.255.0.2 2>&1 | head -1)"
echo "  ip route get 239.255.0.2: $MCAST_ROUTE"
if grep -qiE 'dev (warp|cloudflarewarp|wg[0-9]|tun[0-9]|tailscale|utun)' <<<"$MCAST_ROUTE"; then
    echo "  ${YELLOW}This host routes DDS multicast into a tunnel interface.${NC}"
    echo "    The suite pins itself to loopback via"
    echo "    crates/hdds/src/test_support/network.rs, so a plain 'cargo test'"
    echo "    should still be hermetic. Run --hermeticity to PROVE that here."
    echo "    If a test dies at 'SPDP discovery never completed', the pin has a"
    echo "    hole: re-run with HDDS_INTERFACE=lo and report the difference."
fi
echo "  HDDS_INTERFACE in env: ${HDDS_INTERFACE:-<unset>}"

# ------------------------------------------------------------------ 1. fmt --
banner "gate: fmt"
LOG="$RUN_DIR/fmt.log"
RC=$(run_logged "$LOG" cargo fmt --all -- --check)
if [[ "$RC" -eq 0 ]]; then
    record "fmt" OK "no formatting diffs" "$LOG"
else
    NDIFF=$(grep -c '^Diff in ' "$LOG" || true)
    NFILES=$(grep '^Diff in ' "$LOG" | awk '{print $3}' | sort -u | wc -l)
    record "fmt" FAIL "$NDIFF hunk(s) in $NFILES file(s)" "$LOG"
fi

# --------------------------------------------------------- 2. punctuation --
#
# "Source is pure ASCII, English only" is a coding rule in CONTRIBUTING.md that
# named its offenders (em dash, Unicode arrow, ellipsis, guillemets, accents)
# and then decayed like every other rule kept only as prose.
#
# DELIBERATELY NARROW. This does NOT gate on all non-ASCII: failing on other
# characters (for example box-drawing glyphs or a section sign) is a
# different decision and it is not this gate's to take. The set below is the
# prose-punctuation subset plus accented Latin letters, nothing more:
#
#   U+2014 EM DASH        U+2013 EN DASH       U+2192 RIGHTWARDS ARROW
#   U+2026 ELLIPSIS       U+00AB / U+00BB GUILLEMETS
#   accented Latin letters: U+00C0-U+00D6, U+00D8-U+00F6, U+00F8-U+00FF,
#   U+0100-U+017F  (the two holes skip U+00D7 MULTIPLICATION and U+00F7
#   DIVISION, and the ranges deliberately exclude U+00B0 DEGREE, U+00B1
#   PLUS-MINUS, U+00B5 MICRO and U+00A7 SECTION, which are not letters)
#
# Write '-' for a dash and '->' for an arrow. Every offending file:line is
# listed so the fix is mechanical.
banner "gate: source punctuation (tracked *.rs)"
LOG="$RUN_DIR/punctuation.log"
PUNCT_CLASS='[\x{2014}\x{2013}\x{2192}\x{2026}\x{00AB}\x{00BB}\x{00C0}-\x{00D6}\x{00D8}-\x{00F6}\x{00F8}-\x{00FF}\x{0100}-\x{017F}]'
if ! echo x | grep -qP 'x' 2>/dev/null; then
    echo "${YELLOW}${BOLD}  !! grep has no -P (PCRE) support on this host.${NC}"
    echo "${YELLOW}     The punctuation rule is UNCHECKED here, not satisfied.${NC}"
    record "punctuation" SKIP "grep -P unavailable" "-"
else
    git ls-files -z '*.rs' \
        | xargs -0 --no-run-if-empty grep -noP "$PUNCT_CLASS" >"$LOG" 2>/dev/null
    # grep exits 1 for "no match", which is this gate PASSING. The verdict
    # comes from the line count of the FILE, never from the pipeline status.
    P_HITS=$(wc -l <"$LOG")
    P_FILES=$(cut -d: -f1 "$LOG" | sort -u | wc -l)
    if [[ "$P_HITS" -eq 0 ]]; then
        record "punctuation" OK "0 offending character in tracked *.rs" "$LOG"
    else
        echo "${RED}  first offending lines (full list in $LOG):${NC}"
        head -5 "$LOG" | sed 's/^/    /'
        record "punctuation" FAIL "$P_HITS occurrence(s) in $P_FILES file(s)" "$LOG"
    fi
fi

# --------------------------------------------------------------- 3. clippy --
# --all-features is the point: defect (2) lived behind a non-default feature.
banner "gate: clippy (--all-targets --all-features -D warnings)"
LOG="$RUN_DIR/clippy.log"
JSON="$RUN_DIR/clippy.json"
cargo clippy --all-targets --all-features --message-format=json -- -D warnings \
    >"$JSON" 2>"$LOG"
RC=$?
classify_json "$JSON"
CLIPPY_SAMPLE=$SAMPLE_ERRORS
cat "${JSON}.rendered" >>"$LOG" 2>/dev/null || true
NWARN=$(jq -r 'select(.reason=="compiler-message") | .message | select(.level=="warning") | .message' \
        <"$JSON" 2>/dev/null | wc -l)
if [[ $REAL_ERRORS -gt 0 ]]; then
    record "clippy" FAIL "$REAL_ERRORS error(s) outside sdk/samples, $NWARN warning(s)" "$LOG"
elif [[ "$RC" -ne 0 && $SAMPLE_ERRORS -eq 0 ]]; then
    # Non-zero with nothing attributable: cargo itself failed (resolver,
    # manifest, network). Never read that as a pass.
    record "clippy" FAIL "exit $RC with no classified diagnostic (see log)" "$LOG"
elif [[ $SAMPLE_ERRORS -gt 0 ]]; then
    record "clippy" NOTE "0 error outside sdk/samples; $SAMPLE_ERRORS sample error(s), see note" "$LOG"
else
    record "clippy" OK "0 error, $NWARN warning(s)" "$LOG"
fi

# ---------------------------------------------------------------- 4. tests --
run_test_gate() {  # run_test_gate LOGFILE  -> echoes "rc passed failed ignored"
    local log="$1"
    cargo test --all-features >"$log" 2>&1
    local rc=$?
    # Parse the FILE, never the pipe. One "test result:" line per test binary.
    local p f i
    p=$(grep '^test result:' "$log" | awk '{s+=$4} END {print s+0}')
    f=$(grep '^test result:' "$log" | awk '{s+=$6} END {print s+0}')
    i=$(grep '^test result:' "$log" | awk '{s+=$8} END {print s+0}')
    echo "$rc $p $f $i"
}

banner "gate: test (--all-features)"
LOG="$RUN_DIR/test.log"
read -r RC T_PASS T_FAIL T_IGN <<<"$(run_test_gate "$LOG")"
T_BINS=$(grep -c '^test result:' "$LOG" || true)
TEST_DETAIL="$T_PASS passed / $T_FAIL failed / $T_IGN ignored over $T_BINS binaries"
if [[ "$RC" -eq 0 ]]; then
    record "test" OK "$TEST_DETAIL" "$LOG"
elif grep -q 'error: could not compile\|^error\[' "$LOG" && [[ "$T_BINS" -eq 0 ]]; then
    # Did not even build. If the only broken crates are the samples, say so
    # with the label rather than pretending the suite failed.
    if grep -q 'sdk/samples/' "$LOG" && ! grep -E '^\s+--> (crates|tools|sdk/rust)/' "$LOG" >/dev/null; then
        SAMPLE_ERRORS=$(grep -c 'sdk/samples/' "$LOG" || true)
        record "test" NOTE "build stopped in sdk/samples; 0 test executed, see note" "$LOG"
    else
        record "test" FAIL "build failed before any test ran" "$LOG"
    fi
else
    record "test" FAIL "$TEST_DETAIL" "$LOG"
fi

# Hermeticity A/B. The suite CLAIMS to pin itself to loopback
# (crates/hdds/src/test_support/network.rs); this MEASURES the claim instead of
# repeating it. Slow -- it runs the suite twice -- so it is opt-in.
#
# WHAT ONE A/B CAN AND CANNOT CONCLUDE. This gate compares two single runs. If
# they differ, that is evidence of NON-DETERMINISM, and non-determinism has two
# possible causes which one sample each cannot tell apart:
#   (a) the interface pin has a hole, so the ambient route really does decide;
#   (b) a flaky test that happened to land on one side of the A/B.
# Claiming (a) from one differing pair is exactly the false attribution this
# repository keeps paying for, so the gate reports the DIFFERING TEST NAMES and
# says which question is still open, rather than announcing a verdict it has
# not earned. Resolve it by re-running the named tests in isolation, both ways,
# enough times to see a rate -- that is what distinguishes a flake from a hole.
if [[ $HERMETICITY -eq 1 && $QUICK -eq 0 ]]; then
    banner "gate: test hermeticity A/B (HDDS_INTERFACE=lo)"
    LOG2="$RUN_DIR/test-iface-lo.log"
    HDDS_INTERFACE=lo cargo test --all-features >"$LOG2" 2>&1
    RC2=$?
    P2=$(grep '^test result:' "$LOG2" | awk '{s+=$4} END {print s+0}')
    F2=$(grep '^test result:' "$LOG2" | awk '{s+=$6} END {print s+0}')
    I2=$(grep '^test result:' "$LOG2" | awk '{s+=$8} END {print s+0}')
    echo "  without HDDS_INTERFACE : $T_PASS passed / $T_FAIL failed / $T_IGN ignored (exit $RC)"
    echo "  with HDDS_INTERFACE=lo : $P2 passed / $F2 failed / $I2 ignored (exit $RC2)"
    # Names, not only counts: a count says "something moved", a name says what.
    grep -oP '^test \K\S+(?= \.\.\. FAILED)' "$LOG"  | sort -u >"$RUN_DIR/failed-plain.txt"
    grep -oP '^test \K\S+(?= \.\.\. FAILED)' "$LOG2" | sort -u >"$RUN_DIR/failed-iface-lo.txt"
    if [[ "$T_PASS" == "$P2" && "$T_FAIL" == "$F2" ]]; then
        record "hermeticity" OK "identical both ways ($T_PASS passed / $T_FAIL failed)" "$LOG2"
    else
        echo "${YELLOW}  tests that failed WITHOUT the variable:${NC}"
        sed 's/^/    /' "$RUN_DIR/failed-plain.txt"
        echo "${YELLOW}  tests that failed WITH HDDS_INTERFACE=lo:${NC}"
        sed 's/^/    /' "$RUN_DIR/failed-iface-lo.txt"
        echo "${YELLOW}  The two runs disagree, so the suite is NOT DETERMINISTIC here.${NC}"
        echo "    That is NOT yet proof the interface pin has a hole: a flaky test"
        echo "    landing on one side produces the same signature. Re-run each name"
        echo "    above in isolation, both ways, ~12 times, and compare the RATES"
        echo "    before blaming the pin."
        record "hermeticity" FAIL \
            "runs disagree ($T_PASS/$T_FAIL vs $P2/$F2): flake or pin hole, not distinguished" "$LOG2"
    fi
fi

# --------------------------------------------- 4b. tests, DEFAULT features --
#
# `--all-features` is not "every configuration", it is ONE configuration, and
# it is not the one most users build. Every test written `#[cfg(not(feature =
# "x"))]` - the ones that pin what a build WITHOUT a capability must refuse -
# is invisible to the lane above: the --all-features harness never registers
# them.
banner "gate: test (default features)"
LOG_DEF="$RUN_DIR/test-default.log"
cargo test --lib >"$LOG_DEF" 2>&1
RC_DEF=$?
D_PASS=$(grep '^test result:' "$LOG_DEF" | awk '{s+=$4} END {print s+0}')
D_FAIL=$(grep '^test result:' "$LOG_DEF" | awk '{s+=$6} END {print s+0}')
if [[ $RC_DEF -eq 0 && "${D_FAIL:-1}" == "0" ]]; then
    record "test:default" OK "$D_PASS passed / $D_FAIL failed" "$LOG_DEF"
else
    record "test:default" FAIL "$D_PASS passed / $D_FAIL failed (rc $RC_DEF)" "$LOG_DEF"
fi

# ------------------------------------------------------------- 4c. wiring --
#
# Is every source file in the build graph? A `.rs` no `mod` names compiles in
# NO configuration, so fmt, clippy and both test lanes above are silent about
# it - it is not dead code, it is absent code that looks present. The oracle
# is cargo's own dep-info, so this costs a diff, not a build.
#
# It found 20 files on the day it was written: 2432 lines of production code
# (a STUN/NAT subsystem, a dynamic-permissions subsystem) and 164 tests that
# had never executed. One such directory had been found the week before by
# reading code; this finds the class in two seconds.
banner "gate: wiring (every file in the build graph)"
LOG_WIRE="$RUN_DIR/wiring.log"
python3 "$SCRIPT_DIR/audit-wiring.py" >"$LOG_WIRE" 2>&1
RC_WIRE=$?
WIRE_ORPHANS=$(grep -c 'NOT IN THE BUILD GRAPH' "$LOG_WIRE" || true)
WIRE_STALE=$(grep -c 'STALE EXEMPTION' "$LOG_WIRE" || true)
sed 's/^/  /' "$LOG_WIRE"
if [[ $RC_WIRE -eq 0 ]]; then
    record "wiring" OK "every source file is in the build graph" "$LOG_WIRE"
elif [[ $RC_WIRE -eq 2 ]]; then
    record "wiring" SKIP "no dep-info under target/ (nothing was built)" "$LOG_WIRE"
else
    record "wiring" FAIL \
        "$WIRE_ORPHANS file(s) outside the build graph, $WIRE_STALE stale exemption(s)" \
        "$LOG_WIRE"
fi

# ----------------------------------------------------------------- 5. audit --
banner "gate: audit scan"
if [[ $QUICK -eq 1 ]]; then
    record "audit" SKIP "--quick (slow lane)" "-"
else
    LOG="$RUN_DIR/audit.log"
    RC=$(run_logged "$LOG" bash scripts/extrem-audit-scan.sh)
    # The scan's own exit convention: 0 within policy, 1 above policy, 2
    # degraded (a check group could not run -- which is NOT a pass).
    # The scan writes its summary with ANSI colour codes embedded, e.g.
    # "\033[0;31mCRITICAL violations: 0\033[0m", so strip them before
    # reading the numbers -- a pattern that matches nothing would print "?"
    # and quietly stop reporting the severities.
    PLAIN="$LOG.plain"
    sed -e 's/\x1b\[[0-9;]*m//g' "$LOG" >"$PLAIN"
    audit_count() { grep -oE "^ *$1 violations: *[0-9]+" "$PLAIN" | tail -1 | grep -oE '[0-9]+$' || true; }
    CRIT=$(audit_count CRITICAL)
    HIGHC=$(audit_count HIGH)
    MED=$(audit_count MEDIUM)
    LOWC=$(audit_count LOW)
    AUDIT_DETAIL="CRITICAL=${CRIT:-?} HIGH=${HIGHC:-?} MEDIUM=${MED:-?} LOW=${LOWC:-?}"
    case "$RC" in
        0) record "audit" OK   "$AUDIT_DETAIL (within policy)" "$LOG" ;;
        2) record "audit" FAIL "DEGRADED SCAN - a check group could not run" "$LOG" ;;
        *) record "audit" FAIL "$AUDIT_DETAIL (above policy, exit $RC)" "$LOG" ;;
    esac
fi

# ------------------------------------------------------- 6. workspace check --
banner "gate: check --workspace --all-targets"
LOG="$RUN_DIR/check-workspace.log"
JSON="$RUN_DIR/check-workspace.json"
cargo check --workspace --all-targets --message-format=json >"$JSON" 2>"$LOG"
RC=$?
classify_json "$JSON"
WS_SAMPLE=$SAMPLE_ERRORS
cat "${JSON}.rendered" >>"$LOG" 2>/dev/null || true
if [[ $REAL_ERRORS -gt 0 ]]; then
    record "check-ws" FAIL "$REAL_ERRORS error(s) OUTSIDE sdk/samples" "$LOG"
elif [[ "$RC" -ne 0 && $SAMPLE_ERRORS -eq 0 ]]; then
    record "check-ws" FAIL "exit $RC with no classified diagnostic (see log)" "$LOG"
elif [[ $SAMPLE_ERRORS -gt 0 ]]; then
    record "check-ws" NOTE "0 error outside sdk/samples; $SAMPLE_ERRORS sample error(s), see note" "$LOG"
else
    record "check-ws" OK "0 error" "$LOG"
fi

# ------------------------------------------------------- 7. hdds-c rmw lane --
#
# NAMED SEPARATELY ON PURPOSE, even though --all-features above subsumes it.
#
# This is the exact blindness that bit: crates/hdds-c/src/rmw.rs sits behind
# #[cfg(feature = "rmw")], a non-default feature, and the command in people's
# fingers was `cargo check -p hdds-c` -- default features only -- so a removed
# API broke it silently. Giving the lane its own row makes that regression
# visible ON ITS OWN LINE in the summary instead of buried inside a feature
# union where it reads as "clippy failed, somewhere".
banner "gate: hdds-c --features rmw"
LOG="$RUN_DIR/hdds-c-rmw.log"
JSON="$RUN_DIR/hdds-c-rmw.json"
cargo check -p hdds-c --features rmw --message-format=json >"$JSON" 2>"$LOG"
RC=$?
classify_json "$JSON"
cat "${JSON}.rendered" >>"$LOG" 2>/dev/null || true
if [[ $REAL_ERRORS -gt 0 ]]; then
    record "hdds-c-rmw" FAIL "$REAL_ERRORS error(s) behind --features rmw" "$LOG"
elif [[ "$RC" -ne 0 ]]; then
    record "hdds-c-rmw" FAIL "exit $RC with no classified diagnostic (see log)" "$LOG"
else
    record "hdds-c-rmw" OK "0 error" "$LOG"
fi

# ------------------------------------------------------ 8. cross-target lane --
#
# Defect (1): targets can be red while the host check is green, because the
# host check is the only thing anyone runs.
banner "gate: cross-target check (cargo check -p hdds --lib --target ...)"
if [[ $QUICK -eq 1 ]]; then
    for T in "${CROSS_TARGETS[@]}"; do
        record "cross:$T" SKIP "--quick (slow lane)" "-"
    done
else
    INSTALLED="$RUN_DIR/rustup-targets.txt"
    if rustup target list --installed >"$INSTALLED" 2>&1; then
        :
    else
        echo "${RED}  rustup unavailable; cannot tell an absent target from a pass.${NC}"
    fi
    for T in "${CROSS_TARGETS[@]}"; do
        if ! grep -qx "$T" "$INSTALLED" 2>/dev/null; then
            # LOUD: an uninstalled target must never read as a pass.
            echo "${YELLOW}${BOLD}  !! TARGET NOT INSTALLED: $T${NC}"
            echo "${YELLOW}     install it with:  rustup target add $T${NC}"
            echo "${YELLOW}     this target is UNPROVEN on this host, not green.${NC}"
            record "cross:$T" SKIP "toolchain absent (rustup target add $T)" "-"
            continue
        fi
        LOG="$RUN_DIR/cross-$T.log"
        JSON="$RUN_DIR/cross-$T.json"
        cargo check -p hdds --lib --target "$T" --message-format=json >"$JSON" 2>"$LOG"
        RC=$?
        classify_json "$JSON"
        cat "${JSON}.rendered" >>"$LOG" 2>/dev/null || true
        if [[ $REAL_ERRORS -gt 0 ]]; then
            record "cross:$T" FAIL "$REAL_ERRORS error(s)" "$LOG"
        elif [[ "$RC" -ne 0 ]]; then
            record "cross:$T" FAIL "exit $RC with no classified diagnostic (see log)" "$LOG"
        else
            record "cross:$T" OK "0 error" "$LOG"
        fi
    done
fi

# ============================================================================
#                                  SUMMARY
# ============================================================================

banner "summary"

N_OK=0; N_FAIL=0; N_SKIP=0; N_NOTE=0
TBL_RULE="+----------------------------------+--------+--------------------------------------------------------+"
printf '%s\n' "$TBL_RULE"
printf '| %-32s | %-6s | %-54s |\n' "GATE" "STATUS" "DETAIL"
printf '%s\n' "$TBL_RULE"
for i in "${!G_NAME[@]}"; do
    printf '| %-32s | %-6s | %-54s |\n' \
        "${G_NAME[$i]:0:32}" "${G_STATUS[$i]}" "${G_DETAIL[$i]:0:54}"
    case "${G_STATUS[$i]}" in
        OK)   N_OK=$((N_OK+1)) ;;
        FAIL) N_FAIL=$((N_FAIL+1)) ;;
        SKIP) N_SKIP=$((N_SKIP+1)) ;;
        NOTE) N_NOTE=$((N_NOTE+1)) ;;
    esac
done
printf '%s\n' "$TBL_RULE"
echo "  OK=$N_OK  FAIL=$N_FAIL  NOTE=$N_NOTE  SKIP=$N_SKIP"

# The sdk/samples note, printed once, at the end, where it will be read.
if [[ ${CLIPPY_SAMPLE:-0} -gt 0 || ${WS_SAMPLE:-0} -gt 0 ]]; then
    SAMPLE_ERRORS=$(( ${CLIPPY_SAMPLE:-0} > ${WS_SAMPLE:-0} ? ${CLIPPY_SAMPLE:-0} : ${WS_SAMPLE:-0} ))
    sample_note
fi

echo ""
echo "  logs: $RUN_DIR"

# ------------------------------------------------------------------ verdict --
#
# A VERDICT, NOT A COUNT. `exit $N_FAIL` would wrap to 0 at 256 and would make
# a single failure indistinguishable from a specific error code. One bit of
# meaning, one exit status.
echo ""
if [[ $N_FAIL -gt 0 ]]; then
    echo "${RED}${BOLD}VERDICT: FAIL${NC} - $N_FAIL gate(s) failed. Named above; read their logs."
    exit 1
fi
if [[ $N_SKIP -gt 0 ]]; then
    if [[ $STRICT_SKIP -eq 1 ]]; then
        echo "${RED}${BOLD}VERDICT: FAIL${NC} - 0 gate failed but $N_SKIP was SKIPPED (--strict-skip)."
        exit 1
    fi
    echo "${YELLOW}${BOLD}VERDICT: PASS WITH $N_SKIP SKIPPED GATE(S) - NOT A FULL PROOF.${NC}"
    echo "  A skipped gate is not a passing gate. Re-run without --quick, or"
    echo "  install the missing toolchains, before calling a tree merge-ready."
    exit 0
fi
if [[ $N_NOTE -gt 0 ]]; then
    echo "${GREEN}${BOLD}VERDICT: PASS${NC} ($N_NOTE gate(s) carry a labelled non-fatal note)."
    exit 0
fi
echo "${GREEN}${BOLD}VERDICT: PASS${NC} - all $N_OK gates green."
exit 0
