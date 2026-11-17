#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Build rmw_hdds by hand against an installed ROS 2 tree and run
# serialized_probe.c on it: serialized publish/take, rmw_serialize,
# rmw_deserialize, empty messages and rmw_publisher_wait_for_all_acked
# (a stopped remote reader must time out, a resumed one must acknowledge).
#
# This is for a host that has a ROS 2 install but no working ament/colcon
# (the container gate, scripts/ros2/gate-ros2-build.sh, is the reference
# build). Nothing is installed and nothing is written outside WORK.
#
# Environment:
#   ROS_PREFIX  installed ROS 2 tree (one directory per package), default /opt/ros2/install
#   ROS_SRC     optional source tree whose headers stand in for dangling
#               symlinks of a symlink-install, default /opt/ros2/src/ros2
#   WORK        scratch directory, default a new directory under /tmp
#   DOMAIN      DDS domain for the probe, default 214
# Every cargo command takes HDDS_CARGO_LOCK when it is set (flock).
# Exit code: 0 when the probe reports no failure.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
ROS_PREFIX=${ROS_PREFIX:-/opt/ros2/install}
ROS_SRC=${ROS_SRC:-/opt/ros2/src/ros2}
WORK=${WORK:-$(mktemp -d /tmp/rmw-host-probe.XXXXXX)}
DOMAIN=${DOMAIN:-214}
LOCK=()
[[ -n "${HDDS_CARGO_LOCK:-}" ]] && LOCK=(flock "$HDDS_CARGO_LOCK")

mkdir -p "$WORK/obj"
cd "$REPO"

PKGS="rmw rcutils rosidl_runtime_c rosidl_typesupport_interface rosidl_typesupport_introspection_c
      rcl_interfaces builtin_interfaces rcl_logging_interface rosgraph_msgs std_msgs
      rosidl_runtime_cpp rosidl_typesupport_introspection_cpp rosidl_typesupport_cpp
      rosidl_typesupport_c rosidl_generator_c"
INC=()
for p in $PKGS; do
  INC+=("-I$ROS_PREFIX/$p/include/$p" "-I$ROS_PREFIX/$p/include")
done
if [[ -d "$ROS_SRC" ]]; then
  # After the install, so a symlink that dangles falls through to the source.
  for d in rmw/rmw/include rcutils/include rosidl/rosidl_runtime_c/include \
           rosidl/rosidl_typesupport_interface/include \
           rosidl/rosidl_typesupport_introspection_c/include \
           rosidl/rosidl_runtime_cpp/include rosidl/rosidl_typesupport_introspection_cpp/include; do
    INC+=("-I$ROS_SRC/$d")
  done
fi

echo "[probe] cargo build -p rmw-hdds -p hdds-c"
"${LOCK[@]}" cargo build -p rmw-hdds -p hdds-c
TARGET=${CARGO_TARGET_DIR:-$REPO/target}/debug

echo "[probe] compiling rmw_hdds"
CFLAGS=(-g -fPIC -DHDDS_WITH_ROS2 -DHDDS_HAVE_ROSLOG_FAST
        -I"$REPO/rmw_hdds/include" -I"$REPO/rmw_hdds/include/hdds_cpp" -I"$REPO/crates/hdds-c")
for f in "$REPO"/rmw_hdds/src/*.c; do
  gcc -std=gnu11 -Wall -Wextra "${CFLAGS[@]}" "${INC[@]}" -c "$f" -o "$WORK/obj/$(basename "$f").o"
done
for f in "$REPO"/rmw_hdds/src/codec_parameter_event.cpp "$REPO"/rmw_hdds/src/codec_log.cpp \
         "$REPO"/rmw_hdds/src/cpp/bridge.cpp; do
  g++ -std=gnu++17 "${CFLAGS[@]}" "${INC[@]}" -c "$f" -o "$WORK/obj/$(basename "$f").o"
done

LIBDIRS=()
for p in $PKGS; do LIBDIRS+=("-L$ROS_PREFIX/$p/lib"); done
RPATH=$(for p in $PKGS; do printf '%s:' "$ROS_PREFIX/$p/lib"; done)

echo "[probe] linking librmw_hdds.so"
g++ -shared -o "$WORK/librmw_hdds.so" "$WORK"/obj/*.o \
  -Wl,--whole-archive "$TARGET/librmw_hdds.a" -Wl,--no-whole-archive "$TARGET/libhdds_c.a" \
  "${LIBDIRS[@]}" -lrmw -lrcutils -lrosidl_runtime_c -lrcl_interfaces__rosidl_generator_c \
  -lrosidl_typesupport_introspection_c -lgcc_s -lutil -lrt -lpthread -lm -ldl

echo "[probe] building the probe"
gcc -std=gnu11 -g -Wall "${INC[@]}" "$REPO/scripts/ros2/rmw-host-probe/serialized_probe.c" \
  -o "$WORK/serialized_probe" "${LIBDIRS[@]}" -L"$WORK" \
  -lrmw_hdds -lrmw -lrcutils -lrosidl_runtime_c \
  -lstd_msgs__rosidl_generator_c -lstd_msgs__rosidl_typesupport_introspection_c \
  -Wl,-rpath,"$WORK" -Wl,-rpath,"$RPATH"

echo "[probe] running (domain $DOMAIN, loopback)"
cd "$WORK"
LD_LIBRARY_PATH="$RPATH" HDDS_INTERFACE=lo HDDS_DOMAIN_ID="$DOMAIN" \
  timeout 180 "$WORK/serialized_probe" 2>&1 | tee "$WORK/probe.log" | grep -E '^(ok|FAIL|PASSED|FAILED)|^     '
grep -q '^PASSED' "$WORK/probe.log"
