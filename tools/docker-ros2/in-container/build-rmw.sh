#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Build rmw_hdds inside a pinned ROS 2 image, then check the exported symbol
# set against the committed per-distro required list.
#
# Contract with the host wrapper (scripts/ros2/gate-ros2-build.sh):
#   /hdds    HDDS tree, bind-mounted READ ONLY
#   /build   writable scratch (docker volume): cargo target dir + colcon ws
#   /cargo   writable CARGO_HOME holding the vendored crates
# Nothing is ever written into /hdds. Cargo runs --locked --offline: the
# lockfile cannot be refreshed against a read-only tree, and the container has
# no route out of the private bridge anyway.
set -euo pipefail

DISTRO="${ROS_DISTRO:?ROS_DISTRO not set}"
PROFILE="${HDDS_RUST_PROFILE:-release}"
SYMBOL_LIST="/hdds/tools/docker-ros2/symbols/${DISTRO}.txt"

# ROS setup.bash reads unset variables; -u must be off while it runs.
set +u
# shellcheck disable=SC1090
source "/opt/ros/${DISTRO}/setup.bash"
set -u

export CARGO_HOME=/cargo
export CARGO_TARGET_DIR=/build/target
export HDDS_PROJECT_ROOT=/hdds
mkdir -p /build/target /build/ws

CARGO_FLAGS=(--locked --offline)
[[ "$PROFILE" == "release" ]] && CARGO_FLAGS+=(--release)

echo "[build-rmw] rustc: $(rustc --version)"
# Both static libraries in ONE invocation: rmw_hdds/CMakeLists.txt links
# librmw_hdds.a (whole-archive, so rmw_implementation can dlsym every entry
# point) plus libhdds_c.a. One invocation also means Cargo feature unification
# gives hdds-c the `rmw` feature exactly as rmw-hdds declares it.
echo "[build-rmw] cargo build -p rmw-hdds -p hdds-c ${CARGO_FLAGS[*]}"
cargo build --manifest-path /hdds/Cargo.toml -p rmw-hdds -p hdds-c "${CARGO_FLAGS[@]}"

CMAKE_BUILD_TYPE=Release
[[ "$PROFILE" == "debug" ]] && CMAKE_BUILD_TYPE=Debug

echo "[build-rmw] colcon build --packages-select rmw_hdds"
cd /build/ws
colcon build \
    --packages-select rmw_hdds \
    --base-paths /hdds/rmw_hdds \
    --build-base /build/ws/build \
    --install-base /build/ws/install \
    --cmake-args \
        "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}" \
        "-DHDDS_CARGO_TARGET_ROOT=/build/target" \
        "-DRMW_HDDS_CARGO_LOCKED=ON" \
        "-DRMW_HDDS_CARGO_OFFLINE=ON"

# Gate-only probe package, built into the SAME workspace but a SEPARATE
# package: it drives rmw entry points no stock ROS 2 node calls
# (rmw_take_sequence), and it is never installed beside rmw_hdds nor shipped.
# A probe that fails to build must fail the gate, not disappear from it.
echo "[build-rmw] colcon build --packages-select hdds_ros2_probe"
colcon build \
    --packages-select hdds_ros2_probe \
    --base-paths /hdds/tools/docker-ros2/probe \
    --build-base /build/ws/build \
    --install-base /build/ws/install \
    --cmake-args "-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"

PROBE=/build/ws/install/hdds_ros2_probe/lib/hdds_ros2_probe/take_sequence_probe
if [[ ! -x "$PROBE" ]]; then
    echo "[build-rmw] FAIL: the take_sequence probe was not built" >&2
    exit 1
fi
echo "PROBES ${DISTRO} OK"

SO=/build/ws/install/rmw_hdds/lib/librmw_hdds.so
if [[ ! -f "$SO" ]]; then
    echo "[build-rmw] FAIL: $SO was not produced" >&2
    exit 1
fi
echo "BUILD ${DISTRO} OK"

# ---------------------------------------------------------------------------
# Symbol gate. rmw_implementation dlopen()s this .so and resolves every entry
# point by name (its GET_SYMBOL list); a missing one is a nullptr that only
# explodes when something calls it, so "the talker works" is not proof. The
# required list is committed per distro and the gate is a set difference.
# ---------------------------------------------------------------------------
if [[ ! -f "$SYMBOL_LIST" ]]; then
    echo "[build-rmw] FAIL: no committed symbol list at $SYMBOL_LIST" >&2
    exit 1
fi

DEFINED=$(mktemp)
REQUIRED=$(mktemp)
nm -D --defined-only "$SO" | awk '{print $NF}' | sort -u > "$DEFINED"
grep -vE '^\s*(#|$)' "$SYMBOL_LIST" | sort -u > "$REQUIRED"

MISSING=$(comm -23 "$REQUIRED" "$DEFINED" || true)
TOTAL=$(wc -l < "$REQUIRED")
MISSING_COUNT=0
[[ -n "$MISSING" ]] && MISSING_COUNT=$(printf '%s\n' "$MISSING" | wc -l)
PRESENT=$((TOTAL - MISSING_COUNT))

echo "SYMBOLS ${DISTRO} ${PRESENT}/${TOTAL}"
if [[ -n "$MISSING" ]]; then
    echo "[build-rmw] FAIL: rmw entry points missing from librmw_hdds.so:" >&2
    printf '  %s\n' $MISSING >&2
fi

# The --whole-archive link exports everything in librmw_hdds.a, including the
# crate's own hdds_* / rmw_hdds_* helpers. That is not a failure (rmw only
# looks up rmw_*), but it is worth reporting so a leak is never a surprise.
LEAKED=$(grep -cE '^(hdds_|rmw_hdds_)' "$DEFINED" || true)
echo "INTERNAL-SYMBOLS ${DISTRO} ${LEAKED} (informational: whole-archive link)"

rm -f "$DEFINED" "$REQUIRED"
[[ -z "$MISSING" ]]
