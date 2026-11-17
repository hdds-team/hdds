#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Pinned performance_test runner for rmw_hdds.
#
# The quick runner rmw_hdds/scripts/bench_rmw.sh is the one the performance
# page names. Its inputs are not pinned: it pulls an image tag without a
# digest, runs a live rustup and apt, shallow-clones the performance_test
# default branch, and stamps no HDDS tree SHA in its summary, so a run of it
# cannot be tied to one tree.
#
# What this runner guarantees:
#   * every round is accounted for: rounds_total / rounds_failed /
#     rounds_zero_recv are in the summary, always
#   * min, median and max, never a single figure
#   * NO headline at all when rmw_hdds had a failed or zero-receive round
#   * the topology is asserted, not assumed (--topology intra|inter)
#   * the summary carries the tree SHA, the image digest, rustc, the
#     performance_test commit, the cpuset and the CPU governor
#
# The measured latency includes the rmw layer's own per-take allocation. It is
# NOT comparable with the engine's intra-process write latency, and the
# summary says so in the headline note.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SKIP_CODE=77

DISTRO=""
ROUNDS=10
SECONDS_PER_ROUND=10
RATE=1000
MSG="Array1k"
TOPOLOGY="intra"
RMWS="rmw_hdds,rmw_cyclonedds_cpp,rmw_fastrtps_cpp"
CPUSET="${HDDS_ROS2_BENCH_CPUSET:-}"
OUT_DIR="${HDDS_ROS2_BENCH_DIR:-}"

usage() {
    cat <<'EOF'
Usage: scripts/ros2/bench-rmw.sh --distro {humble|iron|jazzy} [options]

Options:
  --distro NAME       ROS 2 distro (required)
  --rounds N          rounds per middleware (default 10)
  --seconds N         seconds per round (default 10)
  --rate N            publish rate in Hz (default 1000)
  --msg NAME          performance_test message (default Array1k)
  --topology KIND     intra (one process) or inter (two containers). Asserted,
                      not assumed: the two are not comparable
  --rmws LIST         comma-separated middlewares
  --cpuset LIST       docker --cpuset-cpus for every container
  --out DIR           where rounds and summary.json are written
  --quick             2 rounds of 3 seconds
  -h, --help          this text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro) DISTRO="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        --seconds) SECONDS_PER_ROUND="$2"; shift 2 ;;
        --rate) RATE="$2"; shift 2 ;;
        --msg) MSG="$2"; shift 2 ;;
        --topology) TOPOLOGY="$2"; shift 2 ;;
        --rmws) RMWS="$2"; shift 2 ;;
        --cpuset) CPUSET="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --quick) ROUNDS=2; SECONDS_PER_ROUND=3; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$DISTRO" ]] || { echo "error: --distro is required" >&2; exit 2; }
case "$TOPOLOGY" in intra|inter) ;; *) echo "error: --topology must be intra or inter" >&2; exit 2 ;; esac

IMAGE="hdds-ros2:${DISTRO}"
VOLUME="hdds-ros2-build-${DISTRO}"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker not available"; exit "$SKIP_CODE"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "SKIP: image ${IMAGE} absent"; exit "$SKIP_CODE"
fi
if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    echo "SKIP: build volume ${VOLUME} absent (run scripts/ros2/gate-ros2-build.sh first)"
    exit "$SKIP_CODE"
fi
if ! docker run --rm --network none "$IMAGE" test -d /opt/perf_ws/install >/dev/null 2>&1; then
    echo "SKIP: performance_test is not in ${IMAGE} (built with --no-perf-test); rebuild the image without that flag to bench"
    exit "$SKIP_CODE"
fi

[[ -n "$OUT_DIR" ]] || OUT_DIR=$(mktemp -d -t hdds-ros2-bench-XXXXXX)
mkdir -p "$OUT_DIR"
ROUNDS_TXT="${OUT_DIR}/rounds.txt"
: > "$ROUNDS_TXT"

NET="hdds-ros2-bench-${DISTRO}-$$"

# Every round below MUST share one domain across its containers, but the
# number itself must not be a literal: a fixed ROS_DOMAIN_ID would let a
# bench run collide with another gate, the TypeScript SDK suite, or a Rust
# test suite on the same host. Leased instead, from the SAME
# kernel-arbitrated token table crates/hdds/src/test_support/domains.rs's
# Rust tests and the TypeScript SDK's tests use. See scripts/domain-lease.sh
# for the protocol. Acquired right before the cleanup trap is installed, so
# there is no window where a SKIP exit above could leak a held lease.
# shellcheck source=../domain-lease.sh
source "${REPO_ROOT}/scripts/domain-lease.sh"
if ! hdds_domain_lease_acquire; then
    echo "SKIP: could not lease a DDS test domain (see stderr above)"
    exit "$SKIP_CODE"
fi
ROS_DOMAIN="$HDDS_LEASED_DOMAIN"

CONTAINERS=()
cleanup() {
    for c in "${CONTAINERS[@]:-}"; do [[ -n "$c" ]] && docker rm -f "$c" >/dev/null 2>&1; done
    docker network rm "$NET" >/dev/null 2>&1
    hdds_domain_lease_release
}
trap cleanup EXIT
docker network create --driver bridge "$NET" >/dev/null

# --------------------------------------------------------------------------
# Provenance stamp. A number without this is not evidence.
# --------------------------------------------------------------------------
GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)
IMAGE_ENV=$(docker run --rm --network none "$IMAGE" cat /etc/hdds-ros2-image.env 2>/dev/null || true)
get_env() { printf '%s\n' "$IMAGE_ENV" | sed -n "s/^$1=//p" | head -1; }

cat > "${OUT_DIR}/stamp.json" <<JSON
{
  "tree_sha": "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)",
  "tree_dirty": $(if [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then echo true; else echo false; fi),
  "ros_distro": "${DISTRO}",
  "image": "${IMAGE}",
  "base_digest": "$(get_env base_digest)",
  "rust_version": "$(get_env rust_version)",
  "perf_test_commit": "$(get_env perf_test_commit)",
  "topology": "${TOPOLOGY}",
  "message": "${MSG}",
  "rate_hz": ${RATE},
  "seconds_per_round": ${SECONDS_PER_ROUND},
  "rounds_requested": ${ROUNDS},
  "cpuset": "${CPUSET:-unpinned}",
  "cpu_governor": "${GOVERNOR}",
  "date_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "caveat": "latency includes the rmw layer's own per-take allocation; not comparable with the engine's intra-process write latency"
}
JSON

if [[ "$GOVERNOR" != "performance" ]]; then
    echo "[bench-rmw] WARNING: cpu governor is '${GOVERNOR}', not 'performance'. Numbers from this run are indicative only."
fi

run_bench() {
    # run_bench <name> <rmw> <role> ; detached, returns the container name
    local name="$1" rmw="$2" role="$3"
    local cpuset_arg=()
    [[ -n "$CPUSET" ]] && cpuset_arg=(--cpuset-cpus "$CPUSET")
    CONTAINERS+=("$name")
    docker run -d --name "$name" --network "$NET" "${cpuset_arg[@]}" \
        -v "${REPO_ROOT}:/hdds:ro" \
        -v "${VOLUME}:/build:ro" \
        -v "${OUT_DIR}:/out" \
        -e "ROS_DISTRO=${DISTRO}" \
        -e "ROS_DOMAIN_ID=${ROS_DOMAIN}" \
        -e "BENCH_TAG=${name#hdds-bench-}" \
        "$IMAGE" \
        bash /hdds/tools/docker-ros2/in-container/bench.sh \
            "$rmw" "$MSG" "$RATE" "$SECONDS_PER_ROUND" "$role" >/dev/null
    echo "$name"
}

IFS=',' read -r -a RMW_LIST <<< "$RMWS"
for rmw in "${RMW_LIST[@]}"; do
    for (( r = 1; r <= ROUNDS; r++ )); do
        tag="${rmw}-r${r}"
        echo "[bench-rmw] ${DISTRO} ${TOPOLOGY} ${rmw} round ${r}/${ROUNDS}"
        if [[ "$TOPOLOGY" == "intra" ]]; then
            c=$(run_bench "hdds-bench-${tag}-$$" "$rmw" intra)
            docker wait "$c" >/dev/null 2>&1
            docker logs "$c" 2>&1 | grep '^ROUND ' >> "$ROUNDS_TXT" || true
            docker rm -f "$c" >/dev/null 2>&1
        else
            cs=$(run_bench "hdds-bench-${tag}-sub-$$" "$rmw" sub)
            sleep 2
            cp_=$(run_bench "hdds-bench-${tag}-pub-$$" "$rmw" pub)
            docker wait "$cs" >/dev/null 2>&1
            docker logs "$cs" 2>&1 | grep '^ROUND ' >> "$ROUNDS_TXT" || true
            docker rm -f "$cs" "$cp_" >/dev/null 2>&1
        fi
    done
done

docker run --rm --network none -v "${OUT_DIR}:/out" -v "${REPO_ROOT}:/hdds:ro" "$IMAGE" \
    python3 /hdds/tools/docker-ros2/in-container/summarize.py /out /out/stamp.json \
    --measured-rmw rmw_hdds

echo "[bench-rmw] summary: ${OUT_DIR}/summary.json"
