#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# The ROS 2 gate for rmw_hdds, end to end, for one distro or all three.
#
#   1. build rmw_hdds against THIS tree inside the pinned per-distro image
#   2. check the exported symbol set against the committed required list
#   3. run the inter-process cases on a private bridge
#   4. render the status table from what was measured
#
# Exit code: 0 all green, 1 something failed, 77 SKIP (docker or an image
# absent). A skip always prints its reason; there is no silent pass.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SKIP_CODE=77

DISTROS=()
EVIDENCE_DIR="${HDDS_ROS2_EVIDENCE_DIR:-}"
CASES=""
PREPARE=0
BUILD_ONLY=0

usage() {
    cat <<'EOF'
Usage: scripts/ros2/gate-ros2.sh [--distro NAME]... [options]

Options:
  --distro NAME       humble | iron | jazzy (repeatable; default: all three)
  --cases LIST        forwarded to gate-ros2-pubsub.sh
  --prepare           re-vendor the Cargo dependencies (the only network step)
  --build-only        stop after the build and symbol gate
  --evidence-dir DIR  where logs, result.json and the status table are written
  -h, --help          this text

First run on a box:
  tools/docker-ros2/build-image.sh --distro humble
  scripts/ros2/gate-ros2.sh --distro humble --prepare
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro) DISTROS+=("$2"); shift 2 ;;
        --cases) CASES="$2"; shift 2 ;;
        --prepare) PREPARE=1; shift ;;
        --build-only) BUILD_ONLY=1; shift ;;
        --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ ${#DISTROS[@]} -gt 0 ]] || DISTROS=(humble iron jazzy)
[[ -n "$EVIDENCE_DIR" ]] || EVIDENCE_DIR=$(mktemp -d -t hdds-ros2-gate-XXXXXX)
mkdir -p "$EVIDENCE_DIR"

FAILED=0
SKIPPED=0
RAN=0        # distros whose BUILD + SYMBOLS stage completed
RAN_CASES=0  # distros whose BEHAVIOURAL stage actually executed

for distro in "${DISTROS[@]}"; do
    echo "=============================================================="
    echo "[gate-ros2] ${distro}"
    echo "=============================================================="

    build_args=(--distro "$distro")
    [[ "$PREPARE" == "1" ]] && build_args+=(--prepare)
    "$HERE/gate-ros2-build.sh" "${build_args[@]}"
    rc=$?
    if [[ $rc -eq $SKIP_CODE ]]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    if [[ $rc -ne 0 ]]; then
        echo "[gate-ros2] ${distro}: BUILD/SYMBOLS FAILED"
        FAILED=$((FAILED + 1))
        continue
    fi
    RAN=$((RAN + 1))

    [[ "$BUILD_ONLY" == "1" ]] && continue

    pubsub_args=(--distro "$distro" --evidence-dir "$EVIDENCE_DIR")
    [[ -n "$CASES" ]] && pubsub_args+=(--cases "$CASES")
    "$HERE/gate-ros2-pubsub.sh" "${pubsub_args[@]}"
    rc=$?
    if [[ $rc -eq $SKIP_CODE ]]; then
        SKIPPED=$((SKIPPED + 1))
    elif [[ $rc -ne 0 ]]; then
        echo "[gate-ros2] ${distro}: ${rc} case(s) failed"
        FAILED=$((FAILED + 1))
        RAN_CASES=$((RAN_CASES + 1))
    else
        RAN_CASES=$((RAN_CASES + 1))
    fi
done

if [[ "$BUILD_ONLY" != "1" ]]; then
    echo
    echo "[gate-ros2] status table (from the measurements above):"
    python3 "$REPO_ROOT/tools/docker-ros2/render-status.py" "$EVIDENCE_DIR" || true
    python3 "$REPO_ROOT/tools/docker-ros2/render-status.py" "$EVIDENCE_DIR" --format json \
        > "${EVIDENCE_DIR}/status.json" 2>/dev/null || true
fi

echo "[gate-ros2] evidence: ${EVIDENCE_DIR}"
if [[ $FAILED -gt 0 ]]; then
    echo "[gate-ros2] RESULT: FAIL (${FAILED} distro(s) failed, ${SKIPPED} skipped, ${RAN} built, ${RAN_CASES} measured)"
    exit 1
fi
if [[ $RAN -eq 0 ]]; then
    echo "[gate-ros2] RESULT: SKIP (no distro could run; ${SKIPPED} skipped)"
    exit "$SKIP_CODE"
fi
# RAN counts BUILDS. A run where every pub/sub stage returned 77 (image or
# build volume gone between the two stages, bridge subnet already in use) used
# to leave FAILED at 0 with RAN non-zero and print PASS having executed no
# behavioural case at all - the exact failure mode this gate exists to remove.
if [[ "$BUILD_ONLY" != "1" && $RAN_CASES -eq 0 ]]; then
    echo "[gate-ros2] RESULT: SKIP (${RAN} distro(s) built, but no behavioural case ran; ${SKIPPED} skipped)"
    exit "$SKIP_CODE"
fi
if [[ "$BUILD_ONLY" == "1" ]]; then
    echo "[gate-ros2] RESULT: PASS (build only: ${RAN} distro(s), ${SKIPPED} skipped)"
else
    echo "[gate-ros2] RESULT: PASS (${RAN} distro(s) built, ${RAN_CASES} measured, ${SKIPPED} skipped)"
fi
exit 0
