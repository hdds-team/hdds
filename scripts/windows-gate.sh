#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

################################################################################
# HDDS WINDOWS GATE - cross-build + wine tests for the Windows targets
#
# Backs the "Windows" line of the platform table with a gate the release
# process runs on a Linux box, with no network and no credentials. Everything
# the box cannot prove is reported as SKIP with a reason, never as a pass.
#
# Lanes (each has a hard pass/fail; SKIP only for an absent tool):
#   W0  toolchain probe: rustup targets, mingw-w64 gcc, wine (versions pinned
#       in the report; wine's socket emulation differs across major versions)
#   W1  x86_64-pc-windows-gnu: cargo check, workspace, all targets, all
#       features (+ cbindgen headers must stay target-invariant)
#   W1R x86_64-pc-windows-gnu: hdds-c `rmw` feature + rmw-hdds (the ROS 2
#       shim), named separately because it carries the Linux-only SHM shim
#   W2  x86_64-pc-windows-gnu: cargo clippy -D warnings, same shapes as W1
#   W2H HOST clippy on the feature shapes the universal --all-features gate
#       cannot see: `-p hdds --lib --tests` at DEFAULT features and at
#       --features security. Needs no Windows toolchain, so it never SKIPs
#       for an absent target, and it FAILS rather than merely reporting
#   W3  x86_64-pc-windows-gnu tests under wine: hdds --lib AT --all-features
#       (so security / tcp-tls / quic / dynamic-types / rpc / cloud-discovery
#       are EXECUTED, not merely compiled), hdds-micro and a named integration
#       list at default features; 0 failed and a passing-count floor each
#   W4  x86_64-pc-windows-gnu release artefacts: hdds_c.dll + import/static
#       libs, hdds-gen.exe --version, hddsctl.exe (banner + controlled
#       connection failure), hdds-shm-viewer.exe (Linux-only tool: exit 2)
#   W5  x86_64-pc-windows-msvc: cargo check + clippy on the crate set that
#       needs no Windows CRT (hdds-persistence, i.e. libsqlite3-sys, the
#       ring-backed features and rmw-hdds are NOT in this set and are named
#       as unproven). TWO hard shapes, because cargo builds every
#       dev-dependency unconditionally and dev-dependencies cannot be
#       feature-gated ("error: dev-dependencies are not allowed to be
#       optional"):
#         W5a  --lib --bins over the whole MSVC subset  (SHIPPED code)
#         W5b  --lib --bins --tests over the packages whose DEV-dependency
#              closure is CRT-free                       (TEST targets)
#       The test targets of the packages in MSVC_NO_TEST_TARGETS are reported
#       INCOMPLETE BY NAME with the reason, never silently dropped
#       and never worked around by changing a product manifest; they are
#       compiled --all-targets --all-features for the GNU target by W1 and
#       EXECUTED under wine by W3, and W6 is the only lane that could prove
#       them on MSVC. clippy is A/B'd against the host under identical flags.
#       Outcomes: an MSVC-ONLY clippy finding = FAIL, otherwise SKIP
#       (INCOMPLETE) while any sub-claim above is unproven - never PASS
#   W6  x86_64-pc-windows-msvc full workspace check + clippy: opt-in via
#       --msvc-full and HDDS_XWIN_DIR (xwin-splatted CRT + SDK, clang-cl,
#       llvm-lib, lld-link). Without it: SKIP "Windows SDK not available".
#   W7  report: $REPORT_DIR/report.md (toolchain versions, per-lane result,
#       test totals, lanes INCOMPLETE by name)
#
# What this gate proves: the GNU target builds, is clippy-clean, its unit
# suite passes under wine at --all-features and a NAMED subset of its
# integration targets passes there at default features; the MSVC target
# type-checks on the C-free crate set. What it does NOT prove (named in the
# report): anything on a real Windows host (native run, MSVC link + run,
# DDS-Security on MSVC, multicast on real adapters, MSI, vcpkg), and any
# integration target outside the named list.
#
# Run conditions: lane W3 runs the suite in wine processes that bind fixed
# ports (7401/7403 in the discovery listener tests, 17400 in udp_test), with no
# network namespace. Run it on an otherwise idle box; a second HDDS suite or
# another process holding those ports makes W3 flake. That is why W3 asserts
# 0 failed plus a passing-count FLOOR, never an exact count.
#
# In particular: do NOT run a HOST `cargo test -p hdds` at the same time as
# W3. The wine processes bind the SAME fixed ports as the host suite, and the
# collision surfaces on the host side as "Address already in use (os error 98)"
# in the security e2e tests - i.e. the concurrent run poisons the OTHER suite,
# not this one.
#
# Wine note: wine 10 pins a socket bound to a specific interface address with
# SO_BINDTODEVICE (strace: setsockopt(SOL_SOCKET, SO_BINDTODEVICE, "<iface>")),
# and a SO_BINDTODEVICE socket cannot reach 127.0.0.1 on the Linux kernel.
# That is an emulation artefact, not Windows behaviour, so lane W3 exports
# HDDS_INTERFACE=127.0.0.1 (loopback-pinned) instead of changing product code.
#
# Usage:
#   ./scripts/windows-gate.sh                 # all lanes
#   ./scripts/windows-gate.sh --lane W0       # one lane (comma list accepted)
#   ./scripts/windows-gate.sh --lane W1,W2
#   ./scripts/windows-gate.sh --msvc-full     # enable W6 (needs HDDS_XWIN_DIR)
#   ./scripts/windows-gate.sh --report DIR    # report.md location
#
# Environment:
#   CARGO_TARGET_DIR   honoured (default: <repo>/target)
#   HDDS_XWIN_DIR      xwin splat root for W6 (crt/, sdk/)
#   WINDOWS_GATE_ONLINE=1  drop --offline (default: --locked --offline)
#
# Exit codes:
#   0 = every selected lane PASS
#   1 = at least one lane FAIL
#   3 = no FAIL but at least one lane SKIP (toolchain absent / opt-in lane):
#       the release certificate must report INCOMPLETE, never APPROVED
################################################################################

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

GNU_TARGET="x86_64-pc-windows-gnu"
MSVC_TARGET="x86_64-pc-windows-msvc"
MINGW_CC="x86_64-w64-mingw32-gcc"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
REPORT_DIR="$CARGO_TARGET_DIR/windows-gate"
FULL_LANES="W0,W1,W1R,W2,W2H,W3,W4,W5,W6,W7"
LANES="$FULL_LANES"
MSVC_FULL=0

# Passing-count floors for W3 (guards against a silently filtered test run;
# recomputed when the suite grows, never lowered to hide a failure).
# Set just below the counts observed under wine 10.0 (hdds --lib
# --all-features, hdds-micro, and the named integration set); raise them when
# the suite grows.
LIB_FLOOR="${WINDOWS_GATE_LIB_FLOOR:-3000}"
MICRO_FLOOR="${WINDOWS_GATE_MICRO_FLOOR:-140}"
INTEG_FLOOR="${WINDOWS_GATE_INTEG_FLOOR:-130}"

# Integration targets of crates/hdds that run under wine (network-local,
# no Linux-only fixture). tests/mobility_e2e.rs is cfg(target_os = "linux").
INTEG_TARGETS=(
  golden_vectors
  serialization_roundtrip
  publisher_subscriber
  rtps_port_mapping
  qos_partition
  transient_local_late_joiner
  reliable_repair
  intra_tier_roundtrip
  local_delivery_scope
)

# MSVC crate set that needs no Windows CRT to type-check (no C build script).
# rmw-hdds is out: it forces hdds-c/rmw, the Linux-only SHM shim named by W1R.
MSVC_SUBSET=(
  hdds hdds-micro hdds-gen hddsctl hdds-logger hdds-router hdds-gateway
  hdds-recording hdds-discovery-server hdds-c hdds-micro-c
)
MSVC_EXCLUDED_REASON="hdds-persistence (libsqlite3-sys bundled C) and every ring-backed dependency - the security / tcp-tls / quic FEATURES and, through dev-dependencies, the in-process TLS test PKI - need the Windows CRT/SDK; rmw-hdds / hdds-c rmw carry the Linux-only SHM shim (see W1R): not proven on MSVC by this lane"

# Packages of MSVC_SUBSET whose DEV-dependency closure reaches a crate that
# needs the Windows CRT, so their TEST targets cannot be type-checked for MSVC
# on this box. Their LIB and BIN targets still are, by the shape above.
#
# Found with:
#   cargo tree -i ring --target x86_64-pc-windows-msvc -e normal,build,dev -p <pkg>
# which reports ring <- rcgen [dev-dependencies] for hdds and for hdds-c, and
# no other package of the subset. rcgen backs the in-process TLS test PKI of
# the mTLS tests; it is a legitimate dev-dependency and is NOT removed or
# feature-gated to make this lane green: `cargo test -p hdds --lib
# --features tcp-tls transport::tcp` must keep running at that exact feature
# set.
MSVC_NO_TEST_TARGETS=(hdds hdds-c)
MSVC_NO_TEST_REASON="test targets of ${MSVC_NO_TEST_TARGETS[*]} are NOT type-checked for $MSVC_TARGET on this box: cargo builds every dev-dependency unconditionally and dev-dependencies cannot be feature-gated ('error: dev-dependencies are not allowed to be optional'), and their in-process TLS test PKI pulls rcgen 0.13 -> ring 0.17.14, whose build script needs the Windows CRT (cl.exe/lib.exe are absent; substituting clang-cl-19 + llvm-lib-19 gets past lib.exe and then dies on \"fatal error: 'assert.h' file not found\"), which this lane does not provide. The SAME test targets ARE compiled --all-targets --all-features for $GNU_TARGET by W1 and EXECUTED under wine by W3; W6 (--msvc-full + HDDS_XWIN_DIR) is the only lane that could prove them on MSVC. Known gap: a future dev-dependency that fails to build for MSVC and enters only through these two packages will not be caught here"

CARGO_FLAGS=(--locked)
if [[ "${WINDOWS_GATE_ONLINE:-0}" != "1" ]]; then
  CARGO_FLAGS+=(--offline)
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lane) LANES="$2"; shift 2 ;;
    --lane=*) LANES="${1#--lane=}"; shift ;;
    --msvc-full) MSVC_FULL=1; shift ;;
    --report) REPORT_DIR="$2"; shift 2 ;;
    --report=*) REPORT_DIR="${1#--report=}"; shift ;;
    -h|--help) sed -n '5,83p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Reject an unknown lane name and an empty selection: a run that proves
# nothing must not be able to write a report that says PASS.
KNOWN_LANES=(W0 W1 W1R W2 W2H W3 W4 W5 W6 W7)
PROVING_LANES=(W0 W1 W1R W2 W2H W3 W4 W5 W6)
if [[ "$LANES" != "all" ]]; then
  IFS=',' read -r -a REQUESTED <<< "$LANES"
  for want in "${REQUESTED[@]}"; do
    [[ -z "$want" ]] && continue
    ok=0
    for k in "${KNOWN_LANES[@]}"; do [[ "$want" == "$k" ]] && ok=1; done
    if [[ $ok -eq 0 ]]; then
      echo "[windows-gate] unknown lane: $want (known: ${KNOWN_LANES[*]}, or all)" >&2
      exit 2
    fi
  done
  any_proving=0
  for want in "${REQUESTED[@]}"; do
    for k in "${PROVING_LANES[@]}"; do [[ "$want" == "$k" ]] && any_proving=1; done
  done
  if [[ $any_proving -eq 0 ]]; then
    echo "[windows-gate] lane selection '$LANES' proves nothing (no lane in ${PROVING_LANES[*]})" >&2
    exit 2
  fi
fi

mkdir -p "$REPORT_DIR"
LOG_DIR="$REPORT_DIR/logs"
mkdir -p "$LOG_DIR"
# A partial run gets its OWN report file: a `--lane W1` run must never
# overwrite the full-run report.md that a certificate may quote.
if [[ "$LANES" == "$FULL_LANES" || "$LANES" == "all" ]]; then
  REPORT="$REPORT_DIR/report.md"
else
  REPORT="$REPORT_DIR/report-$(echo "$LANES" | tr ',' '-').md"
fi

# ----------------------------------------------------------------------------
# Result bookkeeping
# ----------------------------------------------------------------------------
declare -A LANE_RESULT LANE_NOTE
LANE_ORDER=()
FAILS=0
SKIPS=0

join_with() {
  # join_with <separator> <items...>
  local sep="$1"; shift
  local out="" item
  for item in "$@"; do
    if [[ -z "$out" ]]; then out="$item"; else out="$out$sep$item"; fi
  done
  echo "$out"
}

record() {
  local lane="$1" result="$2" note="${3:-}"
  LANE_ORDER+=("$lane")
  LANE_RESULT["$lane"]="$result"
  LANE_NOTE["$lane"]="$note"
  case "$result" in
    PASS) echo "[windows-gate] $lane PASS ${note:+- $note}" ;;
    FAIL) FAILS=$((FAILS + 1)); echo "[windows-gate] $lane FAIL - $note" >&2 ;;
    SKIP) SKIPS=$((SKIPS + 1)); echo "[windows-gate] $lane SKIP - $note" ;;
  esac
}

selected() {
  case ",$LANES," in
    *",$1,"*) return 0 ;;
    *",all,"*) return 0 ;;
    *) return 1 ;;
  esac
}

run_logged() {
  # run_logged <logname> <cmd...> ; returns the command's exit code
  local name="$1"; shift
  echo "[windows-gate] \$ $*"
  "$@" > "$LOG_DIR/$name.log" 2>&1
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "[windows-gate] --- tail of $LOG_DIR/$name.log ---" >&2
    tail -n 40 "$LOG_DIR/$name.log" >&2
  fi
  return $rc
}

clippy_sites() {
  # clippy_sites <log...> -> sorted unique "file:line:col :: diagnostic" of
  # every finding across the given logs. The MESSAGE is part of the key on
  # purpose: two different lints that happen to point at the same span must
  # not cancel out in the A/B. Several logs are accepted because a lane may
  # need more than one cargo shape (see W5).
  awk '
    /^(error|warning)(\[[^]]*\])?: / { msg = $0; next }
    /^[[:space:]]+--> / {
      loc = $0; sub(/^[[:space:]]+--> /, "", loc);
      print loc " :: " msg
    }
  ' "$@" | sort -u
}

# ----------------------------------------------------------------------------
# cbindgen header guard
#
# The hdds-c / hdds-micro-c build scripts rewrite tracked headers into the
# source tree. A cross build must leave them byte-identical (target-invariant
# ABI), and the gate must not leave the checkout dirty when it does not.
#
# The comparison baseline is a COPY taken before any lane runs, not the git
# index and not HEAD: a pre-existing local edit is then part of the baseline
# instead of being reported as "the cross build rewrote a header".
# ----------------------------------------------------------------------------
HEADER_FILES=(crates/hdds-c/hdds.h sdk/c/include/hdds.h crates/hdds-micro-c/hdds_micro.h)
HEADER_BASELINE="$REPORT_DIR/headers-baseline"

snapshot_headers() {
  mkdir -p "$HEADER_BASELINE"
  local f
  for f in "${HEADER_FILES[@]}"; do
    [[ -f "$f" ]] && cp -f "$f" "$HEADER_BASELINE/$(echo "$f" | tr '/' '_')"
  done
}

headers_unchanged() {
  local f b
  for f in "${HEADER_FILES[@]}"; do
    b="$HEADER_BASELINE/$(echo "$f" | tr '/' '_')"
    [[ -f "$b" ]] || continue
    cmp -s "$f" "$b" || return 1
  done
  return 0
}

restore_headers() {
  # Put the pre-lane bytes back so a FAIL does not leave the tree dirty.
  local f b
  for f in "${HEADER_FILES[@]}"; do
    b="$HEADER_BASELINE/$(echo "$f" | tr '/' '_')"
    [[ -f "$b" ]] || continue
    cmp -s "$f" "$b" || cp -f "$b" "$f"
  done
}

snapshot_headers

# ----------------------------------------------------------------------------
# W0 toolchain probe
# ----------------------------------------------------------------------------
HAVE_GNU_TARGET=0; HAVE_MSVC_TARGET=0; HAVE_MINGW=0; HAVE_WINE=0
RUSTC_VERSION="$(rustc --version 2>/dev/null || echo 'rustc absent')"
CARGO_VERSION="$(cargo --version 2>/dev/null || echo 'cargo absent')"
MINGW_VERSION="absent"
WINE_VERSION="absent"
CLANG_CL_VERSION="absent"
MISSING=()

if rustup target list --installed 2>/dev/null | grep -qx "$GNU_TARGET"; then
  HAVE_GNU_TARGET=1
else
  MISSING+=("rustup target $GNU_TARGET")
fi
if rustup target list --installed 2>/dev/null | grep -qx "$MSVC_TARGET"; then
  HAVE_MSVC_TARGET=1
else
  MISSING+=("rustup target $MSVC_TARGET")
fi
if command -v "$MINGW_CC" >/dev/null 2>&1; then
  HAVE_MINGW=1
  MINGW_VERSION="$("$MINGW_CC" --version 2>/dev/null | head -n 1)"
else
  MISSING+=("$MINGW_CC")
fi
if command -v wine >/dev/null 2>&1; then
  HAVE_WINE=1
  WINE_VERSION="$(wine --version 2>/dev/null | head -n 1)"
else
  MISSING+=("wine")
fi
for cl in clang-cl-19 clang-cl; do
  if command -v "$cl" >/dev/null 2>&1; then
    CLANG_CL_VERSION="$("$cl" --version 2>/dev/null | head -n 1)"
    break
  fi
done

if selected W0; then
  if [[ ${#MISSING[@]} -eq 0 ]]; then
    record W0 PASS "rustc=$RUSTC_VERSION; mingw=$MINGW_VERSION; wine=$WINE_VERSION"
  else
    record W0 SKIP "toolchain absent: $(join_with ', ' "${MISSING[@]}")"
  fi
fi

gnu_ready() { [[ $HAVE_GNU_TARGET -eq 1 && $HAVE_MINGW -eq 1 ]]; }
gnu_missing_note() {
  local m=()
  [[ $HAVE_GNU_TARGET -eq 1 ]] || m+=("rustup target $GNU_TARGET")
  [[ $HAVE_MINGW -eq 1 ]] || m+=("$MINGW_CC")
  echo "toolchain absent: $(join_with ', ' "${m[@]}")"
}

# ----------------------------------------------------------------------------
# W1 GNU check / W2 GNU clippy: the same three shapes
#
#  (a) workspace, all targets, all features, minus: the samples (need generated
#      code), hdds-persistence (its rocksdb-backend feature builds librocksdb-sys,
#      a C++ library that needs a posix-threads mingw g++; Debian ships the
#      win32 thread model), hdds-c and rmw-hdds (the `rmw` feature carries the
#      Linux-only SHM shim, checked separately as lane W1R so the failure is
#      named, not hidden).
#  (b) hdds-persistence with its sqlite feature (rocksdb-backend: NOT proven).
#  (c) hdds-c with every feature but rmw (xtypes, qos-loaders, security).
# ----------------------------------------------------------------------------
GNU_NOT_PROVEN="hdds-persistence/rocksdb-backend (librocksdb-sys needs a posix-threads mingw g++; this box has the win32 thread model)"

gnu_shapes() {
  # gnu_shapes <cargo subcommand> <log prefix> [trailing args...]
  local sub="$1" prefix="$2"; shift 2
  run_logged "$prefix-a-workspace" cargo "$sub" "${CARGO_FLAGS[@]}" --workspace --all-targets \
      --all-features --target "$GNU_TARGET" --exclude 'hdds-samples-*' \
      --exclude hdds-persistence --exclude hdds-c --exclude rmw-hdds "$@" || return 1
  run_logged "$prefix-b-persistence" cargo "$sub" "${CARGO_FLAGS[@]}" -p hdds-persistence \
      --all-targets --features sqlite --target "$GNU_TARGET" "$@" || return 1
  run_logged "$prefix-c-hdds-c" cargo "$sub" "${CARGO_FLAGS[@]}" -p hdds-c --all-targets \
      --features xtypes,qos-loaders,security --target "$GNU_TARGET" "$@" || return 1
  return 0
}

if selected W1; then
  if ! gnu_ready; then
    record W1 SKIP "$(gnu_missing_note)"
  elif gnu_shapes check w1; then
    if headers_unchanged; then
      record W1 PASS "cargo check $GNU_TARGET: workspace --all-targets --all-features (minus samples, hdds-persistence, hdds-c, rmw-hdds) + hdds-persistence/sqlite + hdds-c xtypes,qos-loaders,security; cbindgen headers target-invariant; NOT proven: $GNU_NOT_PROVEN"
    else
      record W1 FAIL "cross build rewrote a tracked cbindgen header (baseline: $HEADER_BASELINE)"
    fi
  else
    record W1 FAIL "cargo check $GNU_TARGET failed (logs/w1-*.log)"
  fi
  restore_headers
fi

# ----------------------------------------------------------------------------
# W1R hdds-c `rmw` feature + rmw-hdds (ROS 2 shim) on the GNU target
# ----------------------------------------------------------------------------
if selected W1R; then
  if ! gnu_ready; then
    record W1R SKIP "$(gnu_missing_note)"
  elif run_logged w1r-check cargo check "${CARGO_FLAGS[@]}" -p hdds-c -p rmw-hdds --all-targets \
         --features hdds-c/rmw --target "$GNU_TARGET" \
       && run_logged w1r-clippy cargo clippy "${CARGO_FLAGS[@]}" -p hdds-c -p rmw-hdds --all-targets \
         --features hdds-c/rmw --target "$GNU_TARGET" -- -D warnings \
       && headers_unchanged; then
    record W1R PASS "hdds-c --features rmw + rmw-hdds: check + clippy -D warnings on $GNU_TARGET"
  else
    # Do NOT print a root cause we did not read: the lane is expected-red
    # today, so a FUTURE unrelated breakage would inherit the old diagnosis
    # and nobody would open the log. Only claim the known cause when the
    # known signature is actually in the log.
    if grep -qE 'shm_open|crates/hdds-c/src/rmw\.rs' "$LOG_DIR/w1r-check.log" 2>/dev/null; then
      record W1R FAIL "hdds-c --features rmw does not build on $GNU_TARGET: crates/hdds-c/src/rmw.rs uses the Linux-only SHM shim without a cfg gate (signature found in logs/w1r-check.log). Named, tracked, and owned by the ROS 2 workstream that owns that file; this gate reports it red rather than excluding it, so the release certificate cannot read APPROVED while the ROS 2 shim has no Windows build"
    else
      record W1R FAIL "UNEXPECTED W1R failure on $GNU_TARGET: the known rmw.rs SHM-shim signature is NOT in the log, so the root cause is something else - read logs/w1r-check.log and logs/w1r-clippy.log before quoting this lane"
    fi
  fi
  restore_headers
fi

# ----------------------------------------------------------------------------
# W2 GNU strict clippy (same shapes as W1)
# ----------------------------------------------------------------------------
if selected W2; then
  if ! gnu_ready; then
    record W2 SKIP "$(gnu_missing_note)"
  elif gnu_shapes clippy w2 -- -D warnings; then
    record W2 PASS "cargo clippy -D warnings $GNU_TARGET on the W1 shapes"
  else
    record W2 FAIL "clippy -D warnings $GNU_TARGET failed (logs/w2-*.log)"
  fi
fi

# ----------------------------------------------------------------------------
# W2H host clippy on the feature shapes --all-features cannot see
#
# The repository's universal clippy gate runs --all-features. That shape is
# BLIND to a lint that only fires on the default set or on one feature: every
# consumer of a gated item is compiled in, so an item wrongly declared ungated
# still resolves and nothing warns. The hole reached the release candidate
# more than once (for example a type_complexity lint on the not(security) arm
# of a function). W5 could only REPORT it, because no lane owned the feature
# set. This one owns it. It runs on the HOST, so it needs no Windows toolchain and never
# SKIPs for an absent target, and it FAILS instead of noting.
#
# --tests COMPILES the test targets; it does not RUN them, so this lane has no
# port collision with W3 and the two may run in either order.
# ----------------------------------------------------------------------------
if selected W2H; then
  w2h_ok=1; w2h_notes=()
  if run_logged w2h-clippy-default \
       cargo clippy -p hdds --lib --tests -- -D warnings; then
    w2h_notes+=("DEFAULT features clean")
  else
    w2h_ok=0
    w2h_notes+=("clippy -D warnings FAILED at DEFAULT features (logs/w2h-clippy-default.log)")
  fi
  if run_logged w2h-clippy-security \
       cargo clippy -p hdds --lib --tests --features security -- -D warnings; then
    w2h_notes+=("--features security clean")
  else
    w2h_ok=0
    w2h_notes+=("clippy -D warnings FAILED at --features security (logs/w2h-clippy-security.log)")
  fi
  if [[ $w2h_ok -eq 1 ]]; then
    record W2H PASS "host cargo clippy -p hdds --lib --tests -D warnings: $(join_with '; ' "${w2h_notes[@]}")"
  else
    record W2H FAIL "$(join_with '; ' "${w2h_notes[@]}")"
  fi
fi

# ----------------------------------------------------------------------------
# wine hygiene
#
# WINEDLLOVERRIDES disables the wine-mono / wine-gecko installer dialogs: on a
# box without those packages a fresh prefix would otherwise BLOCK on a GUI
# prompt, and a release gate must fail, never hang. Every wine invocation is
# wrapped in `timeout` for the same reason. The prefix lives under REPORT_DIR
# so that two runs told to use different --report directories cannot delete
# each other's prefix.
# ----------------------------------------------------------------------------
WINE_TIMEOUT="${WINDOWS_GATE_WINE_TIMEOUT:-120}"
WINE_SUITE_TIMEOUT="${WINDOWS_GATE_SUITE_TIMEOUT:-2400}"

wine_env() {
  export WINEPREFIX="$REPORT_DIR/wineprefix"
  export WINEDEBUG=-all
  export WINEDLLOVERRIDES="mscoree,mshtml="
}

wine_boot() {
  # Initialise the prefix once, under a timeout, before anything depends on it.
  mkdir -p "$WINEPREFIX"
  timeout "$WINE_TIMEOUT" wineboot -u > "$LOG_DIR/wineboot.log" 2>&1 || true
}

# ----------------------------------------------------------------------------
# W3 GNU tests under wine
# ----------------------------------------------------------------------------
W3_LIB_PASSED=0; W3_LIB_FAILED=0; W3_MICRO_PASSED=0; W3_MICRO_FAILED=0
W3_INTEG_PASSED=0; W3_INTEG_FAILED=0

sum_results() {
  # sum_results <log> -> "passed failed" summed over every "test result:" line
  awk '/^test result:/ {
         for (i = 1; i <= NF; i++) {
           if ($(i+1) == "passed;") p += $i;
           if ($(i+1) == "failed;") f += $i;
         }
       } END { printf "%d %d\n", p + 0, f + 0 }' "$1"
}

if selected W3; then
  if ! gnu_ready || [[ $HAVE_WINE -eq 0 ]]; then
    note="$(gnu_missing_note)"
    [[ $HAVE_WINE -eq 1 ]] || note="${note}, wine"
    record W3 SKIP "${note/toolchain absent: , /toolchain absent: }"
  else
    export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine
    wine_env
    # Emulation artefact, not Windows: see the header note (SO_BINDTODEVICE).
    export HDDS_INTERFACE=127.0.0.1
    rm -rf "$WINEPREFIX"
    wine_boot

    w3_ok=1
    if run_logged w3-lib timeout "$WINE_SUITE_TIMEOUT" cargo test "${CARGO_FLAGS[@]}" \
         --target "$GNU_TARGET" -p hdds --lib --all-features -- --test-threads=4; then :; else w3_ok=0; fi
    read -r W3_LIB_PASSED W3_LIB_FAILED < <(sum_results "$LOG_DIR/w3-lib.log")

    if run_logged w3-micro timeout "$WINE_SUITE_TIMEOUT" cargo test "${CARGO_FLAGS[@]}" \
         --target "$GNU_TARGET" -p hdds-micro -- --test-threads=4; then :; else w3_ok=0; fi
    read -r W3_MICRO_PASSED W3_MICRO_FAILED < <(sum_results "$LOG_DIR/w3-micro.log")

    integ_args=()
    for t in "${INTEG_TARGETS[@]}"; do integ_args+=(--test "$t"); done
    if run_logged w3-integ timeout "$WINE_SUITE_TIMEOUT" cargo test "${CARGO_FLAGS[@]}" \
         --target "$GNU_TARGET" -p hdds --no-fail-fast "${integ_args[@]}" -- --test-threads=1; then :; else w3_ok=0; fi
    read -r W3_INTEG_PASSED W3_INTEG_FAILED < <(sum_results "$LOG_DIR/w3-integ.log")

    unset CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER HDDS_INTERFACE
    totals="lib --all-features $W3_LIB_PASSED passed/$W3_LIB_FAILED failed (floor $LIB_FLOOR); hdds-micro $W3_MICRO_PASSED/$W3_MICRO_FAILED (floor $MICRO_FLOOR); integration $W3_INTEG_PASSED/$W3_INTEG_FAILED (floor $INTEG_FLOOR)"
    if [[ $w3_ok -eq 1 && $W3_LIB_FAILED -eq 0 && $W3_MICRO_FAILED -eq 0 && $W3_INTEG_FAILED -eq 0 \
          && $W3_LIB_PASSED -ge $LIB_FLOOR && $W3_MICRO_PASSED -ge $MICRO_FLOOR \
          && $W3_INTEG_PASSED -ge $INTEG_FLOOR ]]; then
      record W3 PASS "$totals; runner=$WINE_VERSION, HDDS_INTERFACE=127.0.0.1; unit tests run at --all-features (security, tcp-tls, quic, dynamic-types, rpc, cloud-discovery EXECUTED here); the ${#INTEG_TARGETS[@]} named integration targets run at DEFAULT features"
    else
      record W3 FAIL "$totals (logs/w3-*.log)"
    fi
  fi
fi

# ----------------------------------------------------------------------------
# W4 GNU release artefacts
# ----------------------------------------------------------------------------
if selected W4; then
  if ! gnu_ready || [[ $HAVE_WINE -eq 0 ]]; then
    note="$(gnu_missing_note)"
    [[ $HAVE_WINE -eq 1 ]] || note="${note}, wine"
    record W4 SKIP "${note/toolchain absent: , /toolchain absent: }"
  else
    wine_env
    wine_boot
    REL="$CARGO_TARGET_DIR/$GNU_TARGET/release"
    w4_notes=()
    w4_ok=1
    if run_logged w4-build cargo build "${CARGO_FLAGS[@]}" --release --target "$GNU_TARGET" \
         -p hdds-c -p hdds-gen -p hddsctl -p hdds-shm-viewer; then
      for f in hdds_c.dll libhdds_c.dll.a libhdds_c.a hdds-gen.exe hddsctl.exe hdds-shm-viewer.exe; do
        if [[ -f "$REL/$f" ]]; then w4_notes+=("$f ok"); else w4_notes+=("$f MISSING"); w4_ok=0; fi
      done
      if ! headers_unchanged; then w4_notes+=("cbindgen header REWRITTEN"); w4_ok=0; fi
      if run_logged w4-hdds-gen-version timeout "$WINE_TIMEOUT" wine "$REL/hdds-gen.exe" --version \
         && grep -q '^hdds-gen ' "$LOG_DIR/w4-hdds-gen-version.log"; then
        w4_notes+=("wine hdds-gen.exe --version: $(grep '^hdds-gen ' "$LOG_DIR/w4-hdds-gen-version.log" | head -n 1)")
      else
        w4_notes+=("wine hdds-gen.exe --version FAILED"); w4_ok=0
      fi
      # hddsctl takes <host:port> (no --help flag exists); point it at a closed
      # loopback port: the banner must print and the connection failure must
      # be the controlled exit 1, not a loader or runtime crash.
      timeout "$WINE_TIMEOUT" wine "$REL/hddsctl.exe" 127.0.0.1:1 > "$LOG_DIR/w4-hddsctl.log" 2>&1
      rc=$?
      if [[ $rc -eq 1 ]] && grep -q '^hddsctl: HDDS CLI Metrics Viewer' "$LOG_DIR/w4-hddsctl.log" \
         && grep -q 'Connection failed' "$LOG_DIR/w4-hddsctl.log"; then
        w4_notes+=("wine hddsctl.exe 127.0.0.1:1: banner + controlled connection failure (exit 1)")
      else
        w4_notes+=("wine hddsctl.exe 127.0.0.1:1 expected banner + exit 1, got exit $rc"); w4_ok=0
      fi
      # Linux-only tool: must say so and exit 2, never crash or pretend.
      timeout "$WINE_TIMEOUT" wine "$REL/hdds-shm-viewer.exe" > "$LOG_DIR/w4-shm-viewer.log" 2>&1
      rc=$?
      if [[ $rc -eq 2 ]] && grep -q 'Linux-only' "$LOG_DIR/w4-shm-viewer.log"; then
        w4_notes+=("wine hdds-shm-viewer.exe exit 2 with Linux-only notice")
      else
        w4_notes+=("wine hdds-shm-viewer.exe expected exit 2 + notice, got exit $rc"); w4_ok=0
      fi
    else
      w4_ok=0; w4_notes+=("cargo build --release $GNU_TARGET failed (logs/w4-build.log)")
    fi
    if [[ $w4_ok -eq 1 ]]; then
      record W4 PASS "$(join_with '; ' "${w4_notes[@]}") (GNU ABI artefacts; MSVC .lib/.dll are not produced here)"
    else
      record W4 FAIL "$(join_with '; ' "${w4_notes[@]}")"
    fi
    restore_headers
  fi
fi

# ----------------------------------------------------------------------------
# W5 MSVC check + clippy on the CRT-free crate set
# ----------------------------------------------------------------------------
if selected W5; then
  if [[ $HAVE_MSVC_TARGET -eq 0 ]]; then
    record W5 SKIP "toolchain absent: rustup target $MSVC_TARGET"
  else
    # W5a: every package of the subset at --lib --bins (the SHIPPED code).
    # W5b: the packages whose dev-dependency closure is CRT-free, additionally
    # at --tests. Both are hard; the difference between the two sets is named
    # by MSVC_NO_TEST_REASON and forces the lane to INCOMPLETE below.
    pk=(); pk_tests=()
    for c in "${MSVC_SUBSET[@]}"; do
      pk+=(-p "$c")
      skip_tests=0
      for n in "${MSVC_NO_TEST_TARGETS[@]}"; do [[ "$c" == "$n" ]] && skip_tests=1; done
      [[ $skip_tests -eq 0 ]] && pk_tests+=(-p "$c")
    done

    w5_shapes() {
      # w5_shapes <log-prefix> <check|clippy> <target-or-empty>
      # Runs BOTH shapes and returns 0 only if BOTH succeed. Logs land in
      # <log-prefix>-libs.log and <log-prefix>-tests.log.
      local prefix="$1" sub="$2" tgt="$3"
      local -a tflag=() lint=()
      [[ -n "$tgt" ]] && tflag=(--target "$tgt")
      [[ "$sub" == "clippy" ]] && lint=(-- -D warnings)
      local rc=0
      run_logged "$prefix-libs" cargo "$sub" "${CARGO_FLAGS[@]}" "${tflag[@]}" \
        --lib --bins "${pk[@]}" "${lint[@]}" || rc=1
      run_logged "$prefix-tests" cargo "$sub" "${CARGO_FLAGS[@]}" "${tflag[@]}" \
        --lib --bins --tests "${pk_tests[@]}" "${lint[@]}" || rc=1
      return $rc
    }

    w5_ok=1; w5_unowned=0; w5_notes=()
    if w5_shapes w5-check check "$MSVC_TARGET"; then
      w5_notes+=("check ok (--lib --bins on ${#MSVC_SUBSET[@]} package(s), + --tests on $((${#pk_tests[@]} / 2)))")
    else
      w5_ok=0; w5_notes+=("check FAILED (logs/w5-check-libs.log, logs/w5-check-tests.log)")
    fi
    if [[ $w5_ok -eq 1 ]]; then
      # Default features (no security/tcp-tls/quic, so no ring) are what this
      # lane can compile. `clippy -D warnings` is RED on that feature set on
      # the Linux host too. Lane W2H now OWNS that feature set and FAILS on
      # it (the universal --all-features gate never saw those sites). So this
      # lane A/Bs MSVC against the host under identical flags and reports
      # three distinct outcomes: green both sides = PASS; an MSVC-ONLY finding
      # = FAIL; red on BOTH sides at the same sites = SKIP (INCOMPLETE), never
      # PASS, because nothing proves that set clean.
      if w5_shapes w5-clippy clippy "$MSVC_TARGET"; then
        w5_notes+=("clippy -D warnings ok")
      elif w5_shapes w5-clippy-host clippy ""; then
        w5_ok=0; w5_notes+=("clippy -D warnings FAILED on $MSVC_TARGET only (host passes with identical flags and identical package shapes; logs/w5-clippy-*.log)")
      else
        # Compare the finding LOCATIONS (--> file:line:col), not a line
        # count: under -D warnings clippy prints findings as "error:" and
        # build scripts print unrelated "warning:" lines. Both shapes of a
        # side are folded into one site list.
        clippy_sites "$LOG_DIR/w5-clippy-libs.log" "$LOG_DIR/w5-clippy-tests.log" \
          > "$LOG_DIR/w5-sites-msvc.txt"
        clippy_sites "$LOG_DIR/w5-clippy-host-libs.log" "$LOG_DIR/w5-clippy-host-tests.log" \
          > "$LOG_DIR/w5-sites-host.txt"
        msvc_only="$(comm -23 "$LOG_DIR/w5-sites-msvc.txt" "$LOG_DIR/w5-sites-host.txt")"
        msvc_n="$(wc -l < "$LOG_DIR/w5-sites-msvc.txt")"
        if [[ -z "$msvc_only" ]]; then
          w5_unowned=1
          w5_notes+=("clippy -D warnings is RED on the default-feature crate set on $MSVC_TARGET AND on the Linux host at the SAME $msvc_n finding site(s), so nothing here is Windows-specific - lane W2H owns that feature set and reports it as a hard failure (the universal --all-features gate does not see these sites). Sites: $(head -n 4 "$LOG_DIR/w5-sites-msvc.txt" | sed -E 's/ :: .*//' | tr '\n' ' ')(full list in logs/w5-sites-msvc.txt)")
        else
          w5_ok=0; w5_notes+=("clippy -D warnings: $(echo "$msvc_only" | wc -l) finding site(s) on $MSVC_TARGET only: $(echo "$msvc_only" | tr '\n' ' ')(logs/w5-clippy-*.log)")
        fi
      fi
    fi
    headers_unchanged || { w5_ok=0; w5_notes+=("cbindgen header REWRITTEN"); }
    # A named sub-claim this box cannot prove keeps the lane INCOMPLETE for as
    # long as it stands, even once the clippy set is clean: MSVC_NO_TEST_REASON
    # is a gap, not a pass.
    w5_incomplete=$w5_unowned
    [[ ${#MSVC_NO_TEST_TARGETS[@]} -gt 0 ]] && w5_incomplete=1
    if [[ $w5_ok -eq 1 && $w5_incomplete -eq 1 ]]; then
      record W5 SKIP "$MSVC_TARGET check PASSED and there is no MSVC-ONLY clippy finding, but the lane cannot be called clean: $(join_with '; ' "${w5_notes[@]}") on ${MSVC_SUBSET[*]}; INCOMPLETE BY NAME: $MSVC_NO_TEST_REASON; NOT proven: $MSVC_EXCLUDED_REASON"
    elif [[ $w5_ok -eq 1 ]]; then
      record W5 PASS "$(join_with '; ' "${w5_notes[@]}") on ${MSVC_SUBSET[*]}; NOT proven: $MSVC_EXCLUDED_REASON"
    else
      record W5 FAIL "$(join_with '; ' "${w5_notes[@]}"); INCOMPLETE BY NAME: $MSVC_NO_TEST_REASON"
    fi
    restore_headers
  fi
fi

# ----------------------------------------------------------------------------
# W6 MSVC full (opt-in: --msvc-full + HDDS_XWIN_DIR)
# ----------------------------------------------------------------------------
if selected W6; then
  if [[ $MSVC_FULL -eq 0 ]]; then
    record W6 SKIP "MSVC full workspace lane is opt-in (--msvc-full + HDDS_XWIN_DIR): Windows SDK not available"
  elif [[ -z "${HDDS_XWIN_DIR:-}" || ! -d "${HDDS_XWIN_DIR:-/nonexistent}/crt/include" ]]; then
    record W6 SKIP "HDDS_XWIN_DIR unset or has no crt/include: Windows SDK not available"
  elif [[ $HAVE_MSVC_TARGET -eq 0 ]]; then
    record W6 SKIP "toolchain absent: rustup target $MSVC_TARGET"
  else
    CL="$(command -v clang-cl-19 || command -v clang-cl || true)"
    LIBTOOL="$(command -v llvm-lib-19 || command -v llvm-lib || true)"
    LINKER="$(command -v lld-link || true)"
    if [[ -z "$CL" || -z "$LIBTOOL" || -z "$LINKER" ]]; then
      record W6 SKIP "toolchain absent: clang-cl / llvm-lib / lld-link"
    else
      X="$HDDS_XWIN_DIR"
      export CC_x86_64_pc_windows_msvc="$CL"
      export CXX_x86_64_pc_windows_msvc="$CL"
      export AR_x86_64_pc_windows_msvc="$LIBTOOL"
      export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="$LINKER"
      export CFLAGS_x86_64_pc_windows_msvc="/imsvc $X/crt/include /imsvc $X/sdk/include/ucrt /imsvc $X/sdk/include/um /imsvc $X/sdk/include/shared"
      export CXXFLAGS_x86_64_pc_windows_msvc="$CFLAGS_x86_64_pc_windows_msvc"
      export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-Lnative=$X/crt/lib/x86_64 -Lnative=$X/sdk/lib/um/x86_64 -Lnative=$X/sdk/lib/ucrt/x86_64"
      if run_logged w6-check cargo check "${CARGO_FLAGS[@]}" --workspace --all-targets \
           --all-features --target "$MSVC_TARGET" --exclude 'hdds-samples-*' \
         && run_logged w6-clippy cargo clippy "${CARGO_FLAGS[@]}" --workspace --all-targets \
           --all-features --target "$MSVC_TARGET" --exclude 'hdds-samples-*' -- -D warnings \
         && headers_unchanged; then
        record W6 PASS "check + clippy -D warnings $MSVC_TARGET workspace --all-features with HDDS_XWIN_DIR=$X"
      else
        record W6 FAIL "MSVC full check/clippy failed (logs/w6-*.log)"
      fi
      restore_headers
    fi
  fi
fi

# ----------------------------------------------------------------------------
# W7 report
# ----------------------------------------------------------------------------
if ! selected W7; then
  echo "[windows-gate] W7 not selected: no report written (lanes: $LANES)"
  if [[ $FAILS -gt 0 ]]; then
    echo "[windows-gate] RESULT: FAIL ($FAILS failed, $SKIPS skipped; lanes: $LANES)" >&2
    exit 1
  elif [[ $SKIPS -gt 0 ]]; then
    echo "[windows-gate] RESULT: INCOMPLETE (0 failed, $SKIPS skipped; lanes: $LANES)"
    exit 3
  fi
  echo "[windows-gate] RESULT: PASS (lanes: $LANES)"
  exit 0
fi

# Recorded here, before the table is generated, so the report can contain its
# own row instead of always missing it.
record W7 PASS "report written to $REPORT"

{
  echo "# HDDS Windows gate report"
  echo
  echo "- date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- tree: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)$(git diff --quiet 2>/dev/null || echo ' (dirty)')"
  echo "- lanes selected: $LANES"
  echo "- cargo flags: ${CARGO_FLAGS[*]}"
  echo
  echo "## Toolchain"
  echo
  echo "| tool | version |"
  echo "|------|---------|"
  echo "| rustc | $RUSTC_VERSION |"
  echo "| cargo | $CARGO_VERSION |"
  echo "| rustup target $GNU_TARGET | $([[ $HAVE_GNU_TARGET -eq 1 ]] && echo installed || echo absent) |"
  echo "| rustup target $MSVC_TARGET | $([[ $HAVE_MSVC_TARGET -eq 1 ]] && echo installed || echo absent) |"
  echo "| $MINGW_CC | $MINGW_VERSION |"
  echo "| wine | $WINE_VERSION |"
  echo "| clang-cl (W6 only) | $CLANG_CL_VERSION |"
  echo "| HDDS_XWIN_DIR (W6 only) | ${HDDS_XWIN_DIR:-unset} |"
  echo
  echo "## Lanes"
  echo
  echo "| lane | result | note |"
  echo "|------|--------|------|"
  for lane in "${LANE_ORDER[@]}"; do
    echo "| $lane | ${LANE_RESULT[$lane]} | ${LANE_NOTE[$lane]} |"
  done
  echo
  if selected W3 && [[ "${LANE_RESULT[W3]:-}" != "SKIP" ]]; then
    echo "## W3 test totals (wine, $WINE_VERSION, HDDS_INTERFACE=127.0.0.1)"
    echo
    echo "| suite | passed | failed | floor |"
    echo "|-------|--------|--------|-------|"
    echo "| hdds --lib (--all-features, --test-threads=4) | $W3_LIB_PASSED | $W3_LIB_FAILED | $LIB_FLOOR |"
    echo "| hdds-micro (default features) | $W3_MICRO_PASSED | $W3_MICRO_FAILED | $MICRO_FLOOR |"
    echo "| hdds integration, ${#INTEG_TARGETS[@]} named targets (default features, --test-threads=1) | $W3_INTEG_PASSED | $W3_INTEG_FAILED | $INTEG_FLOOR |"
    echo
  fi
  echo "## What this run proves (derived from the lane results above, nothing else)"
  echo
  lane_state() { echo "${LANE_RESULT[$1]:-not selected}"; }
  echo "- $GNU_TARGET cargo check (W1): $(lane_state W1)"
  echo "- $GNU_TARGET clippy -D warnings (W2): $(lane_state W2)"
  echo "- $GNU_TARGET unit + integration tests under wine, not on Windows (W3): $(lane_state W3)"
  echo "- $GNU_TARGET release artefacts + wine smoke (W4): $(lane_state W4)"
  echo "- $GNU_TARGET hdds-c rmw + rmw-hdds (W1R): $(lane_state W1R)"
  echo "- $MSVC_TARGET type-check + clippy of the CRT-free crate set, --lib --bins (W5): $(lane_state W5)"
  echo "- $MSVC_TARGET type-check + clippy of the TEST targets of that set MINUS"
  echo "  ${MSVC_NO_TEST_TARGETS[*]} (W5): $(lane_state W5)"
  echo "- $MSVC_TARGET full workspace check + clippy (W6): $(lane_state W6)"
  echo
  echo "## INCOMPLETE by name (needs a real Windows host or the Windows SDK)"
  echo
  echo "- W6 MSVC full workspace (ring, libsqlite3-sys): $([[ "${LANE_RESULT[W6]:-SKIP}" == PASS ]] && echo proven || echo 'not proven')"
  echo "- $MSVC_NO_TEST_REASON"
  echo "- $GNU_TARGET $GNU_NOT_PROVEN: not proven"
  echo "- Native run on Windows 10/11 (no emulation): not proven"
  echo "- MSVC link + run, DDS-Security on MSVC: not proven"
  echo "- Multicast on real Windows adapters (WSAEADDRNOTAVAIL 10049 path): not proven"
  echo "- MSI installer, vcpkg port, MSVC-ABI hdds_c.lib: not built here"
  echo "- sdk/c/CMakeLists.txt and sdk/cxx/CMakeLists.txt have no WIN32/MSVC branch: the"
  echo "  Visual Studio / vcpkg consumption path of the installation page is unproven"
  echo "- \`hdds self-test\` / \`hdds interfaces\`: no such binary exists in this workspace"
  echo "- MSVC-side clippy on the DEFAULT feature set is A/B'd against the host by W5, but"
  echo "  the OWNER of that feature set is lane W2H, which runs on the HOST only: a finding"
  echo "  that fires at default features on $MSVC_TARGET and NOT on the host is still only"
  echo "  detectable through W5's site comparison, not through a lane of its own."
  echo "- W3 scope: the hdds unit suite runs at --all-features, but hdds-micro and the"
  echo "  ${#INTEG_TARGETS[@]} named integration targets run at DEFAULT features, and the integration list is"
  echo "  a named subset of crates/hdds/tests, not all of it."
  echo "- transport/ttl.rs cfg(windows) setters: executed by one tolerant round-trip test"
  echo "  under wine; the policy tests that hard-assert success stay cfg(unix), so a"
  echo "  Windows stack REFUSING IP_MULTICAST_TTL / IP_TTL would not fail this gate."
  echo "- IP mobility detection is inert outside unix: PollIpDetector's address lookup"
  echo "  returns an empty set on non-unix, so its unit tests pass vacuously under wine."
  echo
  echo "## Run conditions"
  echo
  echo "- W3 binds fixed ports (7401, 7403, 17400) in wine with no netns: run on an idle box."
  echo "- W3 asserts 0 failed plus a passing-count floor, never an exact count."
  echo "- Do NOT run a host \`cargo test -p hdds\` while W3 runs: the wine processes bind the"
  echo "  same fixed ports, and the collision fails the HOST suite (security e2e, os error 98)."
  echo
  echo "## Verdict"
  echo
  if [[ $FAILS -gt 0 ]]; then
    echo "FAIL ($FAILS lane(s) failed, $SKIPS skipped; lanes run: $LANES)"
  elif [[ $SKIPS -gt 0 ]]; then
    echo "INCOMPLETE (0 failed, $SKIPS lane(s) skipped; lanes run: $LANES)"
  else
    echo "PASS (every selected lane passed; lanes run: $LANES)"
  fi
  if [[ "$LANES" != "$FULL_LANES" && "$LANES" != "all" ]]; then
    echo
    echo "This is a PARTIAL run. The verdict covers ONLY the lanes listed above."
  fi
} > "$REPORT"
echo "[windows-gate] report: $REPORT"

if [[ $FAILS -gt 0 ]]; then
  echo "[windows-gate] RESULT: FAIL ($FAILS failed, $SKIPS skipped; lanes: $LANES)" >&2
  exit 1
elif [[ $SKIPS -gt 0 ]]; then
  echo "[windows-gate] RESULT: INCOMPLETE (0 failed, $SKIPS skipped; lanes: $LANES)"
  exit 3
fi
echo "[windows-gate] RESULT: PASS (lanes: $LANES)"
exit 0
