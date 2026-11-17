# HDDS interop smoke test -- OpenDDS peer.
#
# Builds OpenDDS from upstream source at a pinned tag, then builds the
# InteropPing pub/sub app (opendds_app.cpp) against it using OpenDDS's
# own CMake integration (find_package(OpenDDS) + opendds_target_sources,
# which drives opendds_idl + tao_idl for code generation). Final stage is
# a slim runtime image carrying just the app binary and the shared
# libraries it needs.
#
# ACE_TAO dependency note: OpenDDS v3.34.0 does not carry ACE_TAO as a
# git submodule in this release (only tools/rapidjson and
# tests/googletest are submodules there). ACE_TAO and MPC are fetched
# as pinned commits on their respective branches (ACE_TAO ace6tao2,
# MPC master -- the branch OpenDDS's own CI checks out), each resolved
# via `git ls-remote` ahead of time rather than left to track the
# branch tip, so rebuilding this image later does not silently pick up
# a different ACE_TAO or MPC.

ARG OPENDDS_TAG=v3.34.0
ARG ACE_TAO_COMMIT=614ef0d23b7bba3c8490bc436344f294a8e0aa8e
ARG MPC_COMMIT=420e24790d349057e6463890ae993eb61eecc273

# ---- Stage 1: build ACE_TAO + OpenDDS from upstream source ----
FROM debian:12-slim AS opendds-builder
ARG OPENDDS_TAG
ARG ACE_TAO_COMMIT
ARG MPC_COMMIT

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential perl git ca-certificates make cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --branch "${OPENDDS_TAG}" --depth 1 \
        https://github.com/OpenDDS/OpenDDS.git OpenDDS
RUN git -C OpenDDS rev-parse HEAD > /opt_opendds_commit.txt

# Pinned, independent shallow fetches: a `--branch` shallow clone would
# track the branch tip, not a frozen commit, so each is a plain init +
# fetch of the exact commit.
RUN git init -q ACE_TAO \
    && cd ACE_TAO \
    && git remote add origin https://github.com/DOCGroup/ACE_TAO.git \
    && git fetch --depth 1 origin "${ACE_TAO_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${ACE_TAO_COMMIT}"

RUN git init -q MPC \
    && cd MPC \
    && git remote add origin https://github.com/DOCGroup/MPC.git \
    && git fetch --depth 1 origin "${MPC_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${MPC_COMMIT}"

ENV ACE_ROOT=/src/ACE_TAO/ACE
ENV TAO_ROOT=/src/ACE_TAO/TAO
ENV MPC_ROOT=/src/MPC

WORKDIR /src/OpenDDS

# No --ace/--ace-github-latest flag: configure auto-detects ACE/TAO/MPC
# from the ACE_ROOT/TAO_ROOT/MPC_ROOT env vars above, the same way
# OpenDDS's own CI (ci_opendds.yml) does. --verbose makes it log which
# ACE_ROOT/TAO_ROOT it picked up, so the build log shows the pinned
# checkout was used rather than some other ACE_TAO it found on its own.
# --optimize --no-debug matches a release build; --no-tests skips
# building OpenDDS's own test suite and examples, which this image
# does not need.
RUN perl ./configure --verbose --optimize --no-debug --no-tests 2>&1 \
        | tee /tmp/configure.log \
    && grep -q "Using ace_src: /src/ACE_TAO/ACE" /tmp/configure.log

# This is the heavy step: ACE, TAO, and OpenDDS from source. Expect
# 30-60+ minutes on a modest multi-core box.
RUN bash -c "source setenv.sh && make -j\$(nproc)"

# ---- Stage 2: build the interop smoke app against that build tree ----
FROM opendds-builder AS app-builder
ARG OPENDDS_TAG

WORKDIR /app
COPY CMakeLists.txt ./CMakeLists.txt
COPY idl/InteropPing.idl ./idl/InteropPing.idl
COPY src/opendds_app.cpp ./src/opendds_app.cpp

RUN bash -c " \
    source /src/OpenDDS/setenv.sh && \
    cmake -S /app -B /app/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /app/build --parallel \$(nproc) \
    "

RUN mkdir -p /opt/interop && cp /app/build/opendds_app /opt/interop/opendds_app

# Provenance file: the resolved OpenDDS commit (from the pinned tag),
# the pinned ACE_TAO and MPC commits actually checked out above, and
# the sha256 of the shipped binary.
# Shell variable names deliberately differ from the build ARG names so
# the recorded commits come from the checkouts themselves, never from
# build-arg substitution.
RUN odds_sha="$(cat /opt_opendds_commit.txt)" \
    && ace_sha="$(git -C /src/ACE_TAO rev-parse HEAD)" \
    && mpc_sha="$(git -C /src/MPC rev-parse HEAD)" \
    && bin_sha="$(sha256sum /opt/interop/opendds_app | awk '{print $1}')" \
    && printf '{\n  "opendds_tag": "%s",\n  "opendds_commit": "%s",\n  "ace_tao_commit": "%s",\n  "mpc_commit": "%s",\n  "binary_sha256": "%s"\n}\n' \
         "${OPENDDS_TAG}" "$odds_sha" "$ace_sha" "$mpc_sha" "$bin_sha" \
         > /opt/interop/BUILD_INFO \
    && cat /opt/interop/BUILD_INFO

# Collect exactly the ACE/TAO/OpenDDS shared libraries the binary links
# against. The lib/ directories of the build tree hold relative symlinks
# into the source tree, so each library is copied dereferenced (cp -L)
# under the name the dynamic linker asks for, plus an unversioned
# libX.so link: in a shared-library build OpenDDS loads the rtps_udp
# transport through the ACE service configurator by its unversioned
# library name. The build fails here if any dependency is unresolved.
# ACE_TAO now lives as a sibling of OpenDDS (/src/ACE_TAO, pinned
# above), not inside it, so both prefixes are matched here.
RUN bash -c ' \
    set -eo pipefail; \
    source /src/OpenDDS/setenv.sh; \
    set -u; \
    mkdir -p /opt/opendds-libs; \
    if ldd /opt/interop/opendds_app | grep -q "not found"; then \
        ldd /opt/interop/opendds_app; exit 1; \
    fi; \
    ldd /opt/interop/opendds_app \
        | awk "\$3 ~ /^\/src\/(OpenDDS|ACE_TAO)\// {print \$1, \$3}" \
        | while read -r name path; do \
            cp -L "$path" "/opt/opendds-libs/$name"; \
            ln -sf "$name" "/opt/opendds-libs/${name%%.so.*}.so"; \
          done; \
    ls -la /opt/opendds-libs \
    '

# ---- Stage 3: slim runtime image ----
FROM debian:12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/opendds/lib /opt/interop

COPY --from=app-builder /opt/opendds-libs/ /opt/opendds/lib/
COPY --from=app-builder /opt/interop/opendds_app /opt/interop/opendds_app
COPY --from=app-builder /opt/interop/BUILD_INFO /opt/interop/BUILD_INFO

ENV LD_LIBRARY_PATH=/opt/opendds/lib

ENTRYPOINT ["/opt/interop/opendds_app"]
