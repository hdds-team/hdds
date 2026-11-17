# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
#
# Per-distro ROS 2 image for the rmw_hdds gate (scripts/ros2/gate-ros2.sh).
#
# Everything that needs the network - apt, rustup, the performance_test
# checkout - happens HERE, at image build time. At gate time the containers run
# on a private bridge with no route out, the HDDS tree is bind-mounted read
# only, and cargo runs --locked --offline against a vendored source tree. No
# HDDS source enters the image, so the image is tree-independent and cacheable
# across branches.
#
# BASE_IMAGE must be pinned by digest by build-image.sh: `FROM osrf/ros:<tag>`
# alone silently follows upstream rebuilds (osrf rebuilt humble-desktop and
# jazzy-desktop in September 2026).
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# ARGs consumed by FROM are out of scope afterwards: re-declare the ones the
# provenance stamp needs.
ARG BASE_IMAGE
ARG ROS_DISTRO
ARG RUST_VERSION=1.92.0
ARG PERF_TEST_COMMIT=6e24680edd
ARG WITH_PERF_TEST=1

ENV DEBIAN_FRONTEND=noninteractive
ENV ROS_DISTRO=${ROS_DISTRO}
ENV RUSTUP_HOME=/opt/rust/rustup
ENV CARGO_HOME_IMAGE=/opt/rust/cargo
ENV PATH=/opt/rust/cargo/bin:${PATH}

# Comparator middlewares (bench only, never part of the pass/fail gate), the
# demo nodes both gate cases drive, and the build tooling.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      curl \
      ca-certificates \
      git \
      python3-colcon-common-extensions \
      python3-vcstool \
      ros-${ROS_DISTRO}-demo-nodes-cpp \
      ros-${ROS_DISTRO}-demo-nodes-py \
      ros-${ROS_DISTRO}-example-interfaces \
      ros-${ROS_DISTRO}-rmw-cyclonedds-cpp \
      ros-${ROS_DISTRO}-rmw-fastrtps-cpp \
      ros-${ROS_DISTRO}-rosidl-typesupport-introspection-cpp \
    && rm -rf /var/lib/apt/lists/*

# Pinned Rust toolchain (the same version the host builds with, so the gate
# and the workspace gates cannot disagree about the compiler).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | env CARGO_HOME=/opt/rust/cargo sh -s -- \
        -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} \
    && /opt/rust/cargo/bin/rustc --version

# Apex.AI performance_test, pinned by commit. Bench comparator only: nothing
# in the pass/fail gate depends on it, and the bench runner reports SKIP by
# name when it is absent.
RUN if [ "${WITH_PERF_TEST}" = "1" ]; then \
      mkdir -p /opt/perf_ws/src && cd /opt/perf_ws/src \
      && git clone https://gitlab.com/ApexAI/performance_test.git \
      && cd performance_test && git checkout ${PERF_TEST_COMMIT} && cd /opt/perf_ws \
      && . /opt/ros/${ROS_DISTRO}/setup.sh \
      && colcon build --packages-select performance_test \
           --cmake-args -DPERFORMANCE_TEST_PLUGIN=ROS2 -DCMAKE_BUILD_TYPE=Release \
      && rm -rf /opt/perf_ws/build /opt/perf_ws/src ; \
    else \
      echo "performance_test not built into this image (WITH_PERF_TEST=${WITH_PERF_TEST})" \
        > /opt/perf_ws_absent ; \
    fi

# Stamped into every gate and bench result so a number can always be traced
# back to the exact image it was measured in.
ARG BASE_DIGEST=unknown
RUN printf 'ros_distro=%s\nbase_image=%s\nbase_digest=%s\nrust_version=%s\nperf_test_commit=%s\nwith_perf_test=%s\n' \
      "${ROS_DISTRO}" "${BASE_IMAGE}" "${BASE_DIGEST}" "${RUST_VERSION}" \
      "${PERF_TEST_COMMIT}" "${WITH_PERF_TEST}" > /etc/hdds-ros2-image.env \
    && cat /etc/hdds-ros2-image.env

WORKDIR /hdds
