#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Gate: rmw_hdds builds against THIS tree inside a pinned ROS 2 image, and the
# resulting librmw_hdds.so defines every rmw entry point rmw_implementation
# resolves on that distro.
#
# Nothing here writes into the worktree: the tree is bind-mounted read only and
# every artefact lands in a per-distro docker volume. Cargo runs
# --locked --offline against a vendored source tree prepared once by
# `--prepare` (the only step that needs the network).
#
# Exit codes: 0 pass, 1 fail, 77 skip (docker or image absent). A skip is
# always printed with its reason and is never a silent pass.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SKIP_CODE=77

DISTRO=""
PROFILE="release"
PREPARE=0
STATE_DIR="${HDDS_ROS2_STATE_DIR:-${REPO_ROOT}/target/ros2-gate}"

usage() {
    cat <<'EOF'
Usage: scripts/ros2/gate-ros2-build.sh --distro {humble|iron|jazzy} [options]

Options:
  --distro NAME     ROS 2 distro (required)
  --profile NAME    release (default) or debug
  --prepare         (re)vendor the Cargo dependencies into the state dir.
                    This is the ONLY step that touches the network; the gate
                    itself runs --offline.
  --state-dir DIR   where the vendored crates live
                    (default: target/ros2-gate, override HDDS_ROS2_STATE_DIR)
  -h, --help        this text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro) DISTRO="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --prepare) PREPARE=1; shift ;;
        --state-dir) STATE_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$DISTRO" ]] || { echo "error: --distro is required" >&2; exit 2; }

IMAGE="hdds-ros2:${DISTRO}"
VOLUME="hdds-ros2-build-${DISTRO}"
CARGO_DIR="${STATE_DIR}/cargo-home"
VENDOR_DIR="${STATE_DIR}/vendor"

# --------------------------------------------------------------------------
# Preconditions -> SKIP, never a silent pass (same contract as gate 18).
# --------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not installed"
    exit "$SKIP_CODE"
fi
if ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker daemon not reachable"
    exit "$SKIP_CODE"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "SKIP: image ${IMAGE} absent (build it with tools/docker-ros2/build-image.sh --distro ${DISTRO})"
    exit "$SKIP_CODE"
fi

# --------------------------------------------------------------------------
# Cargo vendoring. `cargo vendor` writes ONLY into the output directory and
# reads the committed lockfile, so the worktree stays clean.
# --------------------------------------------------------------------------
prepare_vendor() {
    echo "[gate-ros2-build] vendoring Cargo dependencies into ${VENDOR_DIR} (needs network)"
    mkdir -p "$STATE_DIR" "$CARGO_DIR"
    ( cd "$REPO_ROOT" && cargo vendor --locked --versioned-dirs "$VENDOR_DIR" >/dev/null ) || return 1
    cat > "${CARGO_DIR}/config.toml" <<'CFG'
# Written by scripts/ros2/gate-ros2-build.sh --prepare.
# Redirects crates.io to the vendored tree so the in-container build needs no
# network and no writable registry cache.
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "/vendor"
CFG
    return 0
}

if [[ "$PREPARE" == "1" || ! -f "${CARGO_DIR}/config.toml" || ! -d "$VENDOR_DIR" ]]; then
    if ! prepare_vendor; then
        echo "FAIL: cargo vendor failed (see output above)"
        exit 1
    fi
fi

docker volume create "$VOLUME" >/dev/null

echo "[gate-ros2-build] distro=${DISTRO} image=${IMAGE} profile=${PROFILE}"
docker run --rm \
    --network none \
    -v "${REPO_ROOT}:/hdds:ro" \
    -v "${VOLUME}:/build" \
    -v "${CARGO_DIR}:/cargo" \
    -v "${VENDOR_DIR}:/vendor:ro" \
    -e "ROS_DISTRO=${DISTRO}" \
    -e "HDDS_RUST_PROFILE=${PROFILE}" \
    "$IMAGE" \
    bash /hdds/tools/docker-ros2/in-container/build-rmw.sh
rc=$?

if [[ $rc -ne 0 ]]; then
    echo "FAIL: rmw_hdds build or symbol gate failed on ${DISTRO} (exit ${rc})"
    exit 1
fi
exit 0
