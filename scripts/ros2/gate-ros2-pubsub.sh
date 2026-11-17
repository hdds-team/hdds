#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Gate: two ROS 2 nodes in SEPARATE containers, on a private bridge, talk to
# each other through rmw_hdds.
#
# Cases (each has a name, a hard pass/fail and its own log):
#   reader_first  rclpy listener up first, rclpy talker joins later
#   writer_first  rclpy talker up first, rclpy listener joins later
#                 -- the two orderings are separate cases ON PURPOSE: they do
#                 not behave the same today, and a gate that only ran the
#                 favourable one would be measuring its own setup
#   writer_first_peers
#                 the writer_first ordering again, with HDDS_DISCOVERY_PEERS
#                 pointing each container at the other's metatraffic unicast
#                 port: unicast SPDP instead of multicast SPDP
#   cli           `ros2 topic pub` -> `ros2 topic echo`
#   graph         the late container's graph cache carries the REMOTE node and
#                 topic (proof SEDP crossed the bridge); records two case
#                 names, graph_topics and graph_nodes
#   rclcpp        demo_nodes_cpp talker -> rclpy listener (C++ message path)
#   service       add_two_ints server + `ros2 service call` across containers
#   security_enforce    ROS_SECURITY_STRATEGY=Enforce must REFUSE to start
#   security_permissive ... and Permissive must still start
#   domain_env    HDDS_DOMAIN_ID must beat ROS_DOMAIN_ID
#   rust_log      RUST_LOG must reach the engine from inside a ROS 2 node
#   take_sequence rmw_take_sequence short-reads and refuses both undersized
#                 sequences (no stock ROS 2 node ever calls it)
#
# Isolation: one freshly created bridge per run (named after the pid), so two
# gates on different distros never collide; ROS_DOMAIN_ID is LEASED per run
# (scripts/domain-lease.sh), not hardcoded, so this gate no longer collides
# with another gate, the TypeScript SDK suite, or a Rust test suite on the
# same host; the tree is bind-mounted read only; the build volume is
# mounted read only.
#
# Exit code = number of failed cases (0 = all passed), or 77 for SKIP.
set -uo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SKIP_CODE=77

DISTRO=""
# The full expected set, in one place. `graph` records TWO case names
# (graph_topics, graph_nodes); both are accepted as selectors so the names in
# the results table are the names you can ask for.
ALL_CASES=(reader_first writer_first writer_first_peers cli graph rclcpp service
           security_enforce security_permissive domain_env rust_log take_sequence)
CASE_ALIASES=(graph_topics graph_nodes)
CASES=$(IFS=,; echo "${ALL_CASES[*]}")
SETTLE=5           # seconds the first side gets before the second starts
WINDOW=25          # seconds the second side runs
MIN_SAMPLES=5      # a case passes on at least this many received samples
EVIDENCE_DIR="${HDDS_ROS2_EVIDENCE_DIR:-}"

usage() {
    cat <<'EOF'
Usage: scripts/ros2/gate-ros2-pubsub.sh --distro {humble|iron|jazzy} [options]

Options:
  --distro NAME      ROS 2 distro (required)
  --cases LIST       comma-separated subset of reader_first,writer_first,
                     writer_first_peers,cli,graph,rclcpp,service,
                     security_enforce,security_permissive,domain_env,rust_log,
                     take_sequence
                     (graph_topics and graph_nodes are accepted for graph)
  --settle SECONDS   how long the first side runs alone (default 5)
  --window SECONDS   how long the second side runs (default 25)
  --min-samples N    samples needed to pass a pub/sub case (default 5)
  --evidence-dir DIR where per-case logs and result.json are written
                     (default: a temp dir, printed at the end)
  -h, --help         this text
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --distro) DISTRO="$2"; shift 2 ;;
        --cases) CASES="$2"; shift 2 ;;
        --settle) SETTLE="$2"; shift 2 ;;
        --window) WINDOW="$2"; shift 2 ;;
        --min-samples) MIN_SAMPLES="$2"; shift 2 ;;
        --evidence-dir) EVIDENCE_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$DISTRO" ]] || { echo "error: --distro is required" >&2; exit 2; }

# An unknown case name used to select nothing at all: RESULTS stayed empty,
# FAILED stayed 0 and the script exited 0 having measured NOTHING. In a gate
# whose header promises "never a silent pass", a typo in --cases was a green
# run. Refuse the name instead.
KNOWN_CASES=("${ALL_CASES[@]}" "${CASE_ALIASES[@]}")
IFS=',' read -r -a REQUESTED_CASES <<< "$CASES"
for requested in "${REQUESTED_CASES[@]}"; do
    requested=$(echo "$requested" | tr -d '[:space:]')
    [[ -n "$requested" ]] || continue
    found=no
    for known in "${KNOWN_CASES[@]}"; do
        [[ "$requested" == "$known" ]] && { found=yes; break; }
    done
    if [[ "$found" != yes ]]; then
        echo "error: unknown case '${requested}'. Known: ${KNOWN_CASES[*]}" >&2
        exit 2
    fi
done

IMAGE="hdds-ros2:${DISTRO}"
VOLUME="hdds-ros2-build-${DISTRO}"
NET="hdds-ros2-${DISTRO}-$$"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "SKIP: docker not available"
    exit "$SKIP_CODE"
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "SKIP: image ${IMAGE} absent (tools/docker-ros2/build-image.sh --distro ${DISTRO})"
    exit "$SKIP_CODE"
fi
if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    echo "SKIP: build volume ${VOLUME} absent (run scripts/ros2/gate-ros2-build.sh --distro ${DISTRO} first)"
    exit "$SKIP_CODE"
fi

if [[ -z "$EVIDENCE_DIR" ]]; then
    EVIDENCE_DIR=$(mktemp -d -t hdds-ros2-gate-XXXXXX)
fi
mkdir -p "$EVIDENCE_DIR"
LOG_DIR="${EVIDENCE_DIR}/${DISTRO}"
mkdir -p "$LOG_DIR"

# The two containers below MUST share one domain to talk to each other, but
# the number itself must not be a literal: with a fixed domain, two gates for
# different distros running at once -- or this gate running alongside the
# TypeScript SDK suite or a Rust test suite on the same host -- would pick
# the same number. Leased instead, from the SAME kernel-arbitrated token table
# crates/hdds/src/test_support/domains.rs's Rust tests and the TypeScript
# SDK's tests use. See scripts/domain-lease.sh for the protocol. Acquired
# right before the cleanup trap is installed, so there is no window where a
# SKIP exit could leak a held lease.
# shellcheck source=../domain-lease.sh
source "${REPO_ROOT}/scripts/domain-lease.sh"
if ! hdds_domain_lease_acquire; then
    echo "SKIP: could not lease a DDS test domain (see stderr above)"
    exit "$SKIP_CODE"
fi
ROS_DOMAIN="$HDDS_LEASED_DOMAIN"

CONTAINERS=()
cleanup() {
    for c in "${CONTAINERS[@]:-}"; do
        [[ -n "$c" ]] && docker rm -f "$c" >/dev/null 2>&1
    done
    docker network rm "$NET" >/dev/null 2>&1
    hdds_domain_lease_release
}
trap cleanup EXIT

# A fixed /24 per run: the static-peer case has to be able to NAME the two
# addresses before the containers exist. The third octet is derived from the
# pid so two gates never pick the same subnet.
SUBNET_OCTET=$(( ($$ % 200) + 30 ))
SUBNET="172.31.${SUBNET_OCTET}.0/24"
IP_A="172.31.${SUBNET_OCTET}.10"
IP_B="172.31.${SUBNET_OCTET}.11"
METATRAFFIC_PORT=$(( 7400 + 250 * ROS_DOMAIN + 10 ))   # RTPS: PB + DG*domain + d1 + PG*0

docker network rm "$NET" >/dev/null 2>&1
if ! docker network create --driver bridge --subnet "$SUBNET" "$NET" >/dev/null 2>&1; then
    echo "SKIP: could not create a private bridge on ${SUBNET} (address range already in use?)"
    exit "$SKIP_CODE"
fi

# start_side <container-name> <role> <seconds> <ip> [peer-ip]
# A peer-ip sets HDDS_DISCOVERY_PEERS, i.e. unicast SPDP instead of multicast.
start_side() {
    local name="$1" role="$2" secs="$3" ip="$4" peer="${5:-}"
    local peers_env=()
    [[ -n "$peer" ]] && peers_env=(-e "HDDS_DISCOVERY_PEERS=${peer}:${METATRAFFIC_PORT}")
    # CASE_EXTRA_ENV is how a case asks for a REGIME, not just a value: the
    # static-peer case sets HDDS_MULTICAST_DISABLE=1 through it, because
    # setting the peer list while the bridge still carries multicast proves
    # nothing - every peer would have been found anyway, which is why that case
    # passed at the base commit where the variable was inert.
    local extra_env=()
    if [[ -n "${CASE_EXTRA_ENV:-}" ]]; then
        # shellcheck disable=SC2206
        local kv=(${CASE_EXTRA_ENV})
        for entry in "${kv[@]}"; do extra_env+=(-e "$entry"); done
    fi
    CONTAINERS+=("$name")
    # No --rm: the container must survive its process so `docker logs` can
    # still read it. The EXIT trap removes every container it started.
    docker run -d --name "$name" --network "$NET" --ip "$ip" \
        -v "${REPO_ROOT}:/hdds:ro" \
        -v "${VOLUME}:/build:ro" \
        -e "ROS_DISTRO=${DISTRO}" \
        -e "ROS_DOMAIN_ID=${ROS_DOMAIN}" \
        -e "RMW_IMPLEMENTATION=rmw_hdds" \
        "${peers_env[@]}" \
        "${extra_env[@]}" \
        "$IMAGE" \
        bash /hdds/tools/docker-ros2/in-container/run-case.sh "$role" "$secs" >/dev/null
}

stop_side() {
    local name="$1"
    docker rm -f "$name" >/dev/null 2>&1 || true
}

RESULTS=()
FAILED=0

record() {
    local case_name="$1" verdict="$2" detail="$3"
    RESULTS+=("${case_name}|${verdict}|${detail}")
    printf '[gate-ros2-pubsub] %-13s %-4s %s\n' "$case_name" "$verdict" "$detail"
    [[ "$verdict" == "FAIL" ]] && FAILED=$((FAILED + 1))
    return 0
}

selected() {
    [[ ",${CASES}," == *",$1,"* ]] && return 0
    # graph_topics / graph_nodes are the names the results table and
    # result.json use; accept either as a request for the graph case.
    if [[ "$1" == graph ]]; then
        [[ ",${CASES}," == *",graph_topics,"* || ",${CASES}," == *",graph_nodes,"* ]]
        return
    fi
    return 1
}

# ---------------------------------------------------------------------------
# A pub/sub case: <name> <first-role> <second-role> <grep pattern> <which side
# is measured: first|second>
# ---------------------------------------------------------------------------
pubsub_case() {
    local name="$1" first_role="$2" second_role="$3" pattern="$4" measured="$5"
    local use_peers="${6:-no}"
    local first="hdds-${DISTRO}-${name}-a-$$" second="hdds-${DISTRO}-${name}-b-$$"
    local total=$((SETTLE + WINDOW + 10))
    local peer_a="" peer_b=""
    local saved_extra_env="${CASE_EXTRA_ENV:-}"
    if [[ "$use_peers" == "peers" ]]; then
        peer_a="$IP_B"; peer_b="$IP_A"
        CASE_EXTRA_ENV="${saved_extra_env} HDDS_MULTICAST_DISABLE=1"
    fi

    start_side "$first" "$first_role" "$total" "$IP_A" "$peer_a"
    sleep "$SETTLE"
    start_side "$second" "$second_role" "$WINDOW" "$IP_B" "$peer_b"
    CASE_EXTRA_ENV="$saved_extra_env"
    sleep $((WINDOW + 2))

    docker logs "$first"  > "${LOG_DIR}/${name}-a.log" 2>&1 || true
    docker logs "$second" > "${LOG_DIR}/${name}-b.log" 2>&1 || true
    stop_side "$first"; stop_side "$second"

    local measured_log="${LOG_DIR}/${name}-b.log"
    [[ "$measured" == "first" ]] && measured_log="${LOG_DIR}/${name}-a.log"

    local got
    got=$(grep -c -- "$pattern" "$measured_log" 2>/dev/null || true)
    got=${got:-0}
    if [[ "$got" -ge "$MIN_SAMPLES" ]]; then
        record "$name" PASS "${got} samples received (>= ${MIN_SAMPLES}) in ${WINDOW}s"
    else
        record "$name" FAIL "${got} samples received (< ${MIN_SAMPLES}) in ${WINDOW}s; see ${measured_log}"
    fi
}

if selected reader_first; then
    # The reader is already up when the writer joins.
    pubsub_case reader_first listener_py talker_py "I heard" first
fi

if selected writer_first; then
    # The writer is already up when the reader joins - the late-joining reader.
    pubsub_case writer_first talker_py listener_py "I heard" second
fi

if selected writer_first_peers; then
    # Same ordering, unicast SPDP ONLY: HDDS_DISCOVERY_PEERS points each
    # container at the other's metatraffic unicast port AND
    # HDDS_MULTICAST_DISABLE=1 removes the multicast path, so the only way the
    # two sides can find each other is the peer list. With multicast left on,
    # this case passes whether or not the list reaches the participant.
    pubsub_case writer_first_peers talker_py listener_py "I heard" second peers
fi

if selected cli; then
    pubsub_case cli cli_echo cli_pub "data:" first
fi

if selected rclcpp; then
    # C++ publisher, Python subscriber: proves the rclcpp message path puts the
    # same CDR on the wire the rclpy path reads.
    pubsub_case rclcpp listener_py talker_cpp "I heard" first
fi

if selected graph; then
    graph_first="hdds-${DISTRO}-graph-a-$$"
    graph_second="hdds-${DISTRO}-graph-b-$$"
    start_side "$graph_first" talker_py $((SETTLE + 30)) "$IP_A" "$IP_B"
    sleep "$SETTLE"
    start_side "$graph_second" graph_probe 25 "$IP_B" "$IP_A"
    sleep 27
    docker logs "$graph_second" > "${LOG_DIR}/graph-b.log" 2>&1 || true
    docker logs "$graph_first"  > "${LOG_DIR}/graph-a.log" 2>&1 || true
    stop_side "$graph_first"; stop_side "$graph_second"
    # Two separate claims, because they do not hold equally today.
    if grep -q '^/chatter$' "${LOG_DIR}/graph-b.log" \
       && grep -q 'std_msgs/msg/String' "${LOG_DIR}/graph-b.log"; then
        record graph_topics PASS "the remote /chatter topic and its type reached the other container's graph cache (SEDP crossed the bridge)"
    else
        record graph_topics FAIL "the remote /chatter topic or its type is missing from the graph cache; see ${LOG_DIR}/graph-b.log"
    fi
    if grep -q '^/talker$' "${LOG_DIR}/graph-b.log"; then
        record graph_nodes PASS "the remote /talker node is in \`ros2 node list\`"
    else
        record graph_nodes FAIL "\`ros2 node list\` does not show the remote /talker node: rmw_get_node_names reports local nodes only, remote participants never reach the node side of the graph cache; see ${LOG_DIR}/graph-b.log"
    fi
fi

if selected service; then
    svc_first="hdds-${DISTRO}-service-a-$$"
    svc_second="hdds-${DISTRO}-service-b-$$"
    start_side "$svc_first" service_server $((SETTLE + 40)) "$IP_A" "$IP_B"
    sleep "$SETTLE"
    start_side "$svc_second" service_call 35 "$IP_B" "$IP_A"
    sleep 37
    docker logs "$svc_second" > "${LOG_DIR}/service-b.log" 2>&1 || true
    docker logs "$svc_first"  > "${LOG_DIR}/service-a.log" 2>&1 || true
    stop_side "$svc_first"; stop_side "$svc_second"
    if grep -q 'sum=5' "${LOG_DIR}/service-b.log"; then
        record service PASS "add_two_ints(2,3) answered 5 across containers"
    else
        record service FAIL "no answer from add_two_ints across containers; see ${LOG_DIR}/service-b.log"
    fi
fi

# ---------------------------------------------------------------------------
# Single-container cases. These need no peer: they measure what ONE node does
# with an environment, which is exactly the class of claim that had no gate at
# all before (a start-refusal, a resolved domain, a logger).
#
# solo_case <case-name> <role> <seconds> <env "K=V K=V"> <expect-exit ok|fail>
#           <grep pattern> <detail-on-pass>
# ---------------------------------------------------------------------------
solo_case() {
    local name="$1" role="$2" secs="$3" env_kv="$4" expect="$5" pattern="$6" detail="$7"
    local cname="hdds-${DISTRO}-${name}-$$"
    local saved_extra_env="${CASE_EXTRA_ENV:-}"
    CASE_EXTRA_ENV="${saved_extra_env} ${env_kv}"
    start_side "$cname" "$role" "$secs" "$IP_A" ""
    CASE_EXTRA_ENV="$saved_extra_env"
    # The container is started detached; wait for the process rather than
    # sleeping past it, so a refusal is measured the moment it happens.
    local rc
    rc=$(docker wait "$cname" 2>/dev/null || echo 255)
    docker logs "$cname" > "${LOG_DIR}/${name}.log" 2>&1 || true
    stop_side "$cname"

    local exit_ok=no
    if [[ "$expect" == ok && "$rc" == 0 ]]; then exit_ok=yes; fi
    # `timeout -s KILL` reports 137 for a node that ran its full window: that
    # is the normal end of a healthy long-running role.
    if [[ "$expect" == ok && ( "$rc" == 124 || "$rc" == 137 ) ]]; then exit_ok=yes; fi
    if [[ "$expect" == fail && "$rc" != 0 && "$rc" != 124 && "$rc" != 137 ]]; then exit_ok=yes; fi

    if [[ "$exit_ok" == yes ]] && grep -q -- "$pattern" "${LOG_DIR}/${name}.log"; then
        record "$name" PASS "$detail (exit ${rc})"
    else
        record "$name" FAIL "expected exit ${expect} and /${pattern}/ in the log; got exit ${rc}; see ${LOG_DIR}/${name}.log"
    fi
}

if selected security_enforce; then
    # rmw_hdds implements no ROS 2 security keystore. A node started with
    # ROS_SECURITY_STRATEGY=Enforce used to come up UNSECURED while believing
    # it was protected. It must refuse instead - and a start-refusal is the
    # highest-blast-radius behaviour on this branch, so it gets a case.
    solo_case security_enforce talker_py 25 \
        "ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Enforce ROS_SECURITY_KEYSTORE=/tmp/ks" \
        fail "refusing to start unsecured" \
        "ROS_SECURITY_STRATEGY=Enforce is refused instead of starting a node that is not secured"
fi

if selected security_permissive; then
    # Permissive is exactly the mode that says "start without security if you
    # have to". It must still start, and it must SAY it is unsecured.
    solo_case security_permissive talker_py 15 \
        "ROS_SECURITY_ENABLE=true ROS_SECURITY_STRATEGY=Permissive ROS_SECURITY_KEYSTORE=/tmp/ks" \
        ok "runs WITHOUT DDS-Security" \
        "ROS_SECURITY_STRATEGY=Permissive starts the node and says plainly that it is unsecured"
fi

if selected domain_env; then
    # HDDS_DOMAIN_ID was documented, parsed, unit-tested and applied to
    # nothing; ROS_DOMAIN_ID is CLEARED below (not just left at its leased
    # value), so a log line naming 88 can only come from HDDS_DOMAIN_ID being
    # honoured, never from whatever domain this run happened to lease.
    # ROS_DOMAIN_ID has to be CLEARED: rcl resolves it itself and passes an
    # explicit domain down, which is the caller's and must win. HDDS_DOMAIN_ID
    # acts where ROS_DOMAIN_ID acts - when rcl passed no domain of its own.
    # 88 itself is a literal by the same logic as domains.rs's
    # TEST_PINNED_DOMAINS: it is the value under test, not an arbitrary pick,
    # so it stays hardcoded here on purpose.
    solo_case domain_env talker_py 15 \
        "ROS_DOMAIN_ID= HDDS_DOMAIN_ID=88" \
        ok "RMW HDDS initialized (domain 88)" \
        "HDDS_DOMAIN_ID=88 reached the participant (base: domain 0, the variable was inert)"
fi

if selected take_sequence; then
    # rmw_take_sequence: a short read, and BOTH capacity refusals. Its only
    # proof used to be the symbol gate, which by build-rmw.sh's own comment
    # proves presence, not behaviour.
    #
    # Two containers, like every other data case: a publisher and a subscriber
    # on the SAME participant crash inside rcl_wait on this stack (the shm
    # shim in rmw_wait.c), which is a separate pre-existing defect named in
    # docs/deltas/ros2.md and not what this case is measuring.
    ts_first="hdds-${DISTRO}-take_sequence-a-$$"
    ts_second="hdds-${DISTRO}-take_sequence-b-$$"
    start_side "$ts_first" talker_py $((SETTLE + 45)) "$IP_A" ""
    sleep "$SETTLE"
    start_side "$ts_second" take_sequence 40 "$IP_B" ""
    sleep 42
    docker logs "$ts_second" > "${LOG_DIR}/take_sequence.log" 2>&1 || true
    docker logs "$ts_first"  > "${LOG_DIR}/take_sequence-a.log" 2>&1 || true
    stop_side "$ts_first"; stop_side "$ts_second"
    if grep -q "PROBE take_sequence done: 0 failure(s)" "${LOG_DIR}/take_sequence.log"; then
        record take_sequence PASS "$(grep -c '^PROBE .* PASS' "${LOG_DIR}/take_sequence.log") probe assertion(s) passed: short read, payloads, and BOTH capacity refusals"
    else
        record take_sequence FAIL "the take_sequence probe did not report a clean run; see ${LOG_DIR}/take_sequence.log"
    fi
fi

if selected rust_log; then
    # RUST_LOG did nothing inside a ROS 2 process: no rmw entry point ever
    # brought env_logger up. An `hdds::` line in the container log is the
    # engine's own logger talking, not rcutils.
    solo_case rust_log talker_py 15 \
        "RUST_LOG=debug" \
        ok "hdds::" \
        "RUST_LOG reaches the engine from inside a ROS 2 node (an hdds:: line is in the log)"
fi

# ---------------------------------------------------------------------------
# result.json - what render-status.py and the release gate read
# ---------------------------------------------------------------------------
{
    printf '{\n'
    printf '  "distro": "%s",\n' "$DISTRO"
    printf '  "image": "%s",\n' "$IMAGE"
    printf '  "tree_sha": "%s",\n' "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    printf '  "ros_domain_id": %s,\n' "$ROS_DOMAIN"
    printf '  "subnet": "%s",\n' "$SUBNET"
    printf '  "min_samples": %s,\n' "$MIN_SAMPLES"
    printf '  "window_s": %s,\n' "$WINDOW"
    printf '  "date_utc": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # The renderer cannot tell a clean sweep from a one-case run without
    # these: a `--cases reader_first` run that passes used to render
    # "Full support | 1/1 gate cases".
    printf '  "cases_expected": [%s],\n' "$(printf '"%s",' "${ALL_CASES[@]}" | sed 's/,$//')"
    printf '  "cases_requested": [%s],\n' "$(printf '"%s",' "${REQUESTED_CASES[@]}" | tr -d '[:space:]' | sed 's/,$//')"
    printf '  "cases": [\n'
    for i in "${!RESULTS[@]}"; do
        IFS='|' read -r n v d <<< "${RESULTS[$i]}"
        printf '    {"name": "%s", "verdict": "%s", "detail": "%s"}' "$n" "$v" "${d//\"/\\\"}"
        [[ $i -lt $(( ${#RESULTS[@]} - 1 )) ]] && printf ','
        printf '\n'
    done
    printf '  ],\n'
    printf '  "failed": %s\n' "$FAILED"
    printf '}\n'
} > "${LOG_DIR}/result.json"

echo "[gate-ros2-pubsub] ${DISTRO}: $(( ${#RESULTS[@]} - FAILED ))/${#RESULTS[@]} cases passed"
echo "[gate-ros2-pubsub] evidence: ${LOG_DIR}"

# A run that measured nothing is not a pass. Unknown case names are already
# refused above, but a --cases list that selects no case at all (all aliases of
# a case that did not run, say) would still land here.
if [[ ${#RESULTS[@]} -eq 0 ]]; then
    echo "[gate-ros2-pubsub] no case ran: refusing to report a pass" >&2
    exit 2
fi

exit "$FAILED"
