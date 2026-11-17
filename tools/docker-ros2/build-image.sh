#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Build the per-distro ROS 2 gate image (hdds-ros2:<distro>).
#
# The base image is pinned BY DIGEST, not by tag: osrf rebuilds the -desktop
# tags and a tag-only FROM would silently change the toolchain under a gate
# that is supposed to be reproducible. The digests below are the ones present
# on the box that first built these images; re-pin deliberately, never by
# accident, and record the change in the commit message.
set -euo pipefail

DISTRO=""
WITH_PERF_TEST=1
NO_CACHE=0

usage() {
    cat <<'EOF'
Usage: tools/docker-ros2/build-image.sh --distro {humble|iron|jazzy} [options]

Options:
  --distro NAME        ROS 2 distro to build (required)
  --no-perf-test       skip the performance_test build (image builds much
                       faster; the bench runner then reports SKIP by name)
  --no-cache           docker build --no-cache
  -h, --help           this text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro) DISTRO="$2"; shift 2 ;;
        --no-perf-test) WITH_PERF_TEST=0; shift ;;
        --no-cache) NO_CACHE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

# Pinned base digests, one per ROS distro.
case "$DISTRO" in
    humble)
        BASE_REPO="osrf/ros"
        BASE_TAG="humble-desktop"
        BASE_DIGEST="sha256:b2b520a8b42d868ed498a8c062ae8d555d3fa671e698641d4a53558badb8fc0c"
        ;;
    iron)
        BASE_REPO="osrf/ros"
        BASE_TAG="iron-desktop"
        BASE_DIGEST="sha256:c82d8b91b11291a2c86fad704534d15662ae1a8ad80a84346c54f756a48f5d40"
        ;;
    jazzy)
        BASE_REPO="osrf/ros"
        BASE_TAG="jazzy-desktop"
        BASE_DIGEST="sha256:e1c05248ece3bc328386d0509a041a97a5de872a5606418118748875c539c66f"
        ;;
    "")
        echo "error: --distro is required" >&2; usage; exit 2 ;;
    *)
        echo "error: unknown distro '$DISTRO' (humble|iron|jazzy)" >&2; exit 2 ;;
esac

if [[ "$BASE_DIGEST" == __*__ ]]; then
    echo "error: no digest pinned for '$DISTRO' in $0" >&2
    echo "       pull the base once and record its RepoDigest here" >&2
    exit 2
fi

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE_IMAGE="${BASE_REPO}@${BASE_DIGEST}"
IMAGE="hdds-ros2:${DISTRO}"

echo "[build-image] distro=${DISTRO}"
echo "[build-image] base  =${BASE_IMAGE}"
echo "[build-image] (tag at pin time: ${BASE_REPO}:${BASE_TAG})"
echo "[build-image] image =${IMAGE}"

# Only pull if the digest is not already local: the whole point of the pin is
# that a rebuilt upstream tag cannot change what this gate measures.
if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
    echo "[build-image] base digest not local, pulling (needs network)"
    docker pull "$BASE_IMAGE"
fi

ARGS=(--build-arg "BASE_IMAGE=${BASE_IMAGE}"
      --build-arg "ROS_DISTRO=${DISTRO}"
      --build-arg "BASE_DIGEST=${BASE_DIGEST}"
      --build-arg "WITH_PERF_TEST=${WITH_PERF_TEST}")
[[ "$NO_CACHE" == "1" ]] && ARGS+=(--no-cache)

docker build "${ARGS[@]}" -t "$IMAGE" -f "$HERE/Dockerfile" "$HERE"

echo "[build-image] OK: $IMAGE"
docker run --rm --network none "$IMAGE" cat /etc/hdds-ros2-image.env
