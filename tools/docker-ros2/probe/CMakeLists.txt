# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Gate-only probe package. It is NOT part of rmw_hdds and is never installed
# next to it: build-rmw.sh builds it into the gate's own workspace so a case
# can drive rmw entry points that no stock ROS 2 node ever calls.
cmake_minimum_required(VERSION 3.16)
project(hdds_ros2_probe C)

if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 99)
endif()
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(ament_cmake REQUIRED)
find_package(rcl REQUIRED)
find_package(rmw REQUIRED)
find_package(rcutils REQUIRED)
find_package(rosidl_runtime_c REQUIRED)
find_package(std_msgs REQUIRED)

add_executable(take_sequence_probe src/take_sequence_probe.c)
target_link_options(take_sequence_probe PRIVATE -rdynamic)
ament_target_dependencies(take_sequence_probe rcl rmw rcutils rosidl_runtime_c std_msgs)

install(TARGETS take_sequence_probe DESTINATION lib/${PROJECT_NAME})

ament_package()
