# HDDS interop-smoke image for eProsima Fast DDS.
#
# Builds from upstream source at pinned tags:
#   - foonathan_memory_vendor v1.4.1 (version pinned by Fast-DDS v3.6.2's own
#     fastdds.repos, read from the tagged source tree rather than guessed)
#   - Fast-CDR v2.4.0
#   - Fast-DDS v3.6.2
#   - Fast-DDS-Gen v4.3.0 (same version pinned by Fast-DDS v3.6.2's
#     fastdds.repos; used only to generate TypeSupport code from the shared
#     InteropPing IDL, not shipped in the final binary)
#
# Final image exposes the smoke-test CLI at /opt/interop/fastdds_app,
# implementing the pub/sub contract in scripts/interop-smoke/CONTRACT.md.

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --yes --no-install-recommends \
        build-essential \
        cmake \
        git \
        ca-certificates \
        wget \
        libssl-dev \
        libasio-dev \
        libtinyxml2-dev \
        openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV INSTALL_PREFIX=/opt/install
RUN mkdir -p ${INSTALL_PREFIX} /opt/build_info

WORKDIR /opt/src

# --- foonathan_memory_vendor v1.4.1 (dependency pinned by Fast-DDS v3.6.2's
# own fastdds.repos file, read from the tagged Fast-DDS source tree) --------
RUN git clone --depth 1 --branch v1.4.1 \
        https://github.com/eProsima/foonathan_memory_vendor.git foonathan_memory_vendor \
    && git -C foonathan_memory_vendor rev-parse HEAD > /opt/build_info/foonathan_memory_vendor.commit
RUN cmake -S foonathan_memory_vendor -B foonathan_memory_vendor/build \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
        -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake --build foonathan_memory_vendor/build --target install -- -j"$(nproc)"

# --- Fast-CDR v2.4.0 --------------------------------------------------------
RUN git clone --depth 1 --branch v2.4.0 \
        https://github.com/eProsima/Fast-CDR.git Fast-CDR \
    && git -C Fast-CDR rev-parse HEAD > /opt/build_info/fastcdr.commit
RUN cmake -S Fast-CDR -B Fast-CDR/build \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
        -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} \
        -DCMAKE_BUILD_TYPE=Release \
    && cmake --build Fast-CDR/build --target install -- -j"$(nproc)"

# --- Fast-DDS v3.6.2 ---------------------------------------------------------
RUN git clone --depth 1 --branch v3.6.2 \
        https://github.com/eProsima/Fast-DDS.git Fast-DDS \
    && git -C Fast-DDS rev-parse HEAD > /opt/build_info/fastdds.commit
RUN cmake -S Fast-DDS -B Fast-DDS/build \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
        -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} \
        -DCMAKE_BUILD_TYPE=Release \
        -DSECURITY=OFF \
        -DCOMPILE_EXAMPLES=OFF \
        -DBUILD_TESTING=OFF \
    && cmake --build Fast-DDS/build --target install -- -j"$(nproc)"

# --- Fast-DDS-Gen v4.3.0 (code generator only, not shipped) -----------------
RUN git clone --depth 1 --branch v4.3.0 \
        https://github.com/eProsima/Fast-DDS-Gen.git Fast-DDS-Gen \
    && git -C Fast-DDS-Gen rev-parse HEAD > /opt/build_info/fastddsgen.commit
WORKDIR /opt/src/Fast-DDS-Gen
RUN git submodule update --init
RUN ./gradlew assemble --no-daemon

# --- Generate TypeSupport code from the shared InteropPing IDL -------------
# idl/InteropPing.idl here is a verbatim copy of
# scripts/interop-smoke/idl/InteropPing.idl, needed because the Docker
# build context is restricted to this vendor subdirectory.
COPY idl/InteropPing.idl /opt/src/idl/InteropPing.idl

RUN mkdir -p /opt/src/app/generated && \
    java -jar /opt/src/Fast-DDS-Gen/share/fastddsgen/java/fastddsgen.jar \
        -replace -d /opt/src/app/generated /opt/src/idl/InteropPing.idl

# --- Build the smoke-test app -----------------------------------------------
WORKDIR /opt/src/app
COPY CMakeLists.txt /opt/src/app/CMakeLists.txt
COPY src/fastdds_app.cpp /opt/src/app/src/fastdds_app.cpp

RUN cmake -S /opt/src/app -B /opt/src/app/build \
        -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} \
        -DCMAKE_BUILD_TYPE=Release \
        -DGENERATED_DIR=/opt/src/app/generated \
    && cmake --build /opt/src/app/build -- -j"$(nproc)"

# --- Provenance record ------------------------------------------------------
# Resolved commits for every upstream source tree pulled by tag above, plus a
# sha256 of the final binary, so the exact build inputs can be checked later
# without re-cloning anything:
#   docker run --rm --entrypoint cat <image> /opt/interop/BUILD_INFO
RUN sha256sum /opt/src/app/build/fastdds_app | awk '{print $1}' > /opt/build_info/binary.sha256
RUN { \
        echo "{"; \
        echo "  \"foonathan_memory_vendor\": {\"tag\": \"v1.4.1\", \"commit\": \"$(cat /opt/build_info/foonathan_memory_vendor.commit)\"},"; \
        echo "  \"fastcdr\": {\"tag\": \"v2.4.0\", \"commit\": \"$(cat /opt/build_info/fastcdr.commit)\"},"; \
        echo "  \"fastdds\": {\"tag\": \"v3.6.2\", \"commit\": \"$(cat /opt/build_info/fastdds.commit)\"},"; \
        echo "  \"fastddsgen\": {\"tag\": \"v4.3.0\", \"commit\": \"$(cat /opt/build_info/fastddsgen.commit)\"},"; \
        echo "  \"binary_sha256\": \"$(cat /opt/build_info/binary.sha256)\""; \
        echo "}"; \
    } > /opt/build_info/BUILD_INFO

# --- Runtime stage -----------------------------------------------------------
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install --yes --no-install-recommends \
        libtinyxml2-dev \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/install/lib/ /opt/install/lib/
COPY --from=builder /opt/src/app/build/fastdds_app /opt/interop/fastdds_app
COPY --from=builder /opt/build_info/BUILD_INFO /opt/interop/BUILD_INFO

ENV LD_LIBRARY_PATH=/opt/install/lib

ENTRYPOINT ["/opt/interop/fastdds_app"]
