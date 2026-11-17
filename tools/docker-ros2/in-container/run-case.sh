#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# One side of one gate case, inside a container. The host wrapper
# (scripts/ros2/gate-ros2-pubsub.sh) starts two of these on a private bridge.
#
# usage: run-case.sh <role> [seconds]
#   roles: talker_py listener_py talker_cpp listener_cpp
#          cli_pub cli_echo graph_probe take_sequence
#          service_server service_call param_get
set -uo pipefail

ROLE="${1:?role required}"
SECONDS_LIMIT="${2:-25}"
DISTRO="${ROS_DISTRO:?ROS_DISTRO not set}"

set +u
# shellcheck disable=SC1090
source "/opt/ros/${DISTRO}/setup.bash"
# shellcheck disable=SC1091
source /build/ws/install/setup.bash
set -u

export RMW_IMPLEMENTATION="${RMW_IMPLEMENTATION:-rmw_hdds}"

# rcl refuses to hand the middleware anything at all when ROS security is on
# and it cannot find an enclave directory, so the security cases would never
# reach rmw_init and would be measuring rcl instead. An empty keystore is
# enough for rcl: it resolves the enclave and passes the strategy down, and
# what rmw_hdds does with it is then the thing under test.
if [[ -n "${ROS_SECURITY_KEYSTORE:-}" ]]; then
    mkdir -p "${ROS_SECURITY_KEYSTORE}/enclaves"
fi

run() { timeout -s KILL "$SECONDS_LIMIT" "$@"; }

case "$ROLE" in
    talker_py)      run ros2 run demo_nodes_py talker ;;
    listener_py)    run ros2 run demo_nodes_py listener ;;
    talker_cpp)     run ros2 run demo_nodes_cpp talker ;;
    listener_cpp)   run ros2 run demo_nodes_cpp listener ;;
    cli_pub)        run ros2 topic pub -r 5 /gate_chatter std_msgs/msg/String '{data: "gate"}' ;;
    cli_echo)       run ros2 topic echo /gate_chatter std_msgs/msg/String ;;
    graph_probe)
        # The graph cache must carry the REMOTE node and topic, not just the
        # local ones: that is what proves SEDP crossed the bridge.
        #
        # --spin-time is what these commands give discovery before they answer.
        # The default is 1 second, which is shorter than an SPDP period (3 s),
        # so the default is a measurement of the CLI's patience, not of the
        # middleware.
        SPIN="${HDDS_GATE_SPIN_TIME:-10}"
        echo "--- ros2 node list"
        run ros2 node list --spin-time "$SPIN" || true
        echo "--- ros2 topic list"
        run ros2 topic list --spin-time "$SPIN" || true
        echo "--- ros2 topic info /chatter"
        run ros2 topic info /chatter || true
        ;;
    service_server) run ros2 run demo_nodes_py add_two_ints_server ;;
    service_call)
        run ros2 service call /add_two_ints example_interfaces/srv/AddTwoInts '{a: 2, b: 3}'
        ;;
    param_get)      run ros2 param get /talker use_sim_time ;;
    take_sequence)
        # rmw_take_sequence has no stock caller: rclpy has no binding and
        # rclcpp's executors take one message at a time. The probe drives it
        # directly, so the entry point is measured and not just present.
        run ros2 run hdds_ros2_probe take_sequence_probe
        ;;
    *)
        echo "unknown role: $ROLE" >&2
        exit 2
        ;;
esac
