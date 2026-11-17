# HDDS interop smoke test -- CycloneDDS peer.
#
# Builds CycloneDDS from upstream source at a pinned tag, then builds
# the InteropPing pub/sub app (interop_app.c) against it via CycloneDDS's
# own CMake package and idlc code generator. Final stage is a slim
# runtime image carrying just the app binary and the CycloneDDS shared
# libraries it needs.

ARG CYCLONEDDS_TAG=11.0.1

# ---- Stage 1: build CycloneDDS from upstream source ----
FROM debian:12-slim AS cyclonedds-builder
ARG CYCLONEDDS_TAG

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --branch "${CYCLONEDDS_TAG}" --depth 1 \
        https://github.com/eclipse-cyclonedds/cyclonedds.git cyclonedds \
    && git -C cyclonedds rev-parse HEAD > /opt-cyclonedds-commit.txt

RUN cmake -S cyclonedds -B cyclonedds/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/cyclonedds \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TESTING=OFF \
        -DBUILD_DDSPERF=OFF \
        -DENABLE_SECURITY=OFF \
        -DENABLE_SHM=OFF \
    && cmake --build cyclonedds/build --parallel "$(nproc)" \
    && cmake --install cyclonedds/build

# ---- Stage 2: build the interop smoke app against that install ----
FROM cyclonedds-builder AS app-builder
ARG CYCLONEDDS_TAG

WORKDIR /app
COPY CMakeLists.txt ./CMakeLists.txt
COPY idl/InteropPing.idl ./idl/InteropPing.idl
COPY src/interop_app.c ./src/interop_app.c

RUN cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH=/opt/cyclonedds \
    && cmake --build build --parallel "$(nproc)"

RUN mkdir -p /opt/interop && cp build/cyclonedds_app /opt/interop/cyclonedds_app

# Provenance file: resolved upstream commit for the pinned tag (captured
# right after the clone, before build) plus the sha256 of the final
# binary. Read with: docker run --rm --entrypoint cat <image> /opt/interop/BUILD_INFO
RUN COMMIT="$(cat /opt-cyclonedds-commit.txt)" \
    && SHA256="$(sha256sum /opt/interop/cyclonedds_app | awk '{print $1}')" \
    && printf '{\n  "vendor": "cyclonedds",\n  "tag": "%s",\n  "commit": "%s",\n  "binary": "cyclonedds_app",\n  "binary_sha256": "%s"\n}\n' \
        "${CYCLONEDDS_TAG}" "${COMMIT}" "${SHA256}" > /opt/interop/BUILD_INFO \
    && cat /opt/interop/BUILD_INFO

# ---- Stage 3: slim runtime image ----
FROM debian:12-slim AS runtime

RUN mkdir -p /opt/cyclonedds/lib /opt/interop

COPY --from=cyclonedds-builder /opt/cyclonedds/lib/ /opt/cyclonedds/lib/
COPY --from=app-builder /opt/interop/cyclonedds_app /opt/interop/cyclonedds_app
COPY --from=app-builder /opt/interop/BUILD_INFO /opt/interop/BUILD_INFO

ENV LD_LIBRARY_PATH=/opt/cyclonedds/lib

ENTRYPOINT ["/opt/interop/cyclonedds_app"]
