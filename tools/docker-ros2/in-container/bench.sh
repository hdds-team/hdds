#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# One performance_test round inside a pinned image. The host runner
# (scripts/ros2/bench-rmw.sh) calls this once per (rmw, round, role).
#
# usage: bench.sh <rmw> <msg> <rate> <seconds> <role>
#   role: intra | pub | sub
# Writes the CSV performance_test produces to /out/<name>.csv and prints a
# one-line verdict the summariser parses. A round that produces no usable row
# says so; it is never silently dropped.
set -uo pipefail

RMW="${1:?rmw required}"
MSG="${2:-Array1k}"
RATE="${3:-1000}"
SECS="${4:-10}"
ROLE="${5:-intra}"
TAG="${BENCH_TAG:-round}"
DISTRO="${ROS_DISTRO:?ROS_DISTRO not set}"

set +u
# shellcheck disable=SC1090
source "/opt/ros/${DISTRO}/setup.bash"
if [[ -d /opt/perf_ws/install ]]; then
    # shellcheck disable=SC1091
    source /opt/perf_ws/install/setup.bash
fi
# shellcheck disable=SC1091
source /build/ws/install/setup.bash
set -u

if ! command -v perf_test >/dev/null 2>&1; then
    echo "ROUND ${TAG} ${RMW} ${ROLE} SKIP performance_test is not in this image (built with --no-perf-test)"
    exit 0
fi

export RMW_IMPLEMENTATION="$RMW"
mkdir -p /out
OUT="/out/${TAG}.csv"

ARGS=(-c ROS2 -t "$MSG" --max-runtime "$SECS" --rate "$RATE" -l "/out/${TAG}")
case "$ROLE" in
    intra) ARGS+=(-p 1 -s 1) ;;
    pub)   ARGS+=(-p 1 -s 0) ;;
    sub)   ARGS+=(-p 0 -s 1) ;;
    *) echo "unknown role: $ROLE" >&2; exit 2 ;;
esac

echo "[bench] RMW_IMPLEMENTATION=${RMW} perf_test ${ARGS[*]}"
timeout -s KILL $((SECS + 30)) perf_test "${ARGS[@]}" > "/out/${TAG}.stdout" 2> "/out/${TAG}.stderr"
rc=$?

# perf_test writes <prefix>_<timestamp>.csv; normalise the name.
found=$(ls -1 /out/${TAG}*.csv 2>/dev/null | head -1 || true)
if [[ -n "$found" && "$found" != "$OUT" ]]; then
    mv "$found" "$OUT"
fi

if [[ $rc -ne 0 ]]; then
    echo "ROUND ${TAG} ${RMW} ${ROLE} FAILED perf_test exited ${rc}"
    exit 0
fi
if [[ ! -s "$OUT" ]]; then
    echo "ROUND ${TAG} ${RMW} ${ROLE} FAILED no CSV produced"
    exit 0
fi
echo "ROUND ${TAG} ${RMW} ${ROLE} OK ${OUT}"
