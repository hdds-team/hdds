#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${HDDSGEN:?set HDDSGEN to the hddsgen binary}"
export HDDS_KEYED_WORK=${HDDS_KEYED_WORK:-$(mktemp -d)}
export HDDS_KEYED_CODEC="$HDDS_KEYED_WORK/generated"
mkdir -p "$HDDS_KEYED_CODEC"
"$HDDSGEN" --version
"$HDDSGEN" gen python "$ROOT/crates/hdds-c/tests/fixtures/sdk_keyed.idl" > "$HDDS_KEYED_CODEC/sdk_keyed.py"
"$HDDSGEN" gen cpp "$ROOT/crates/hdds-c/tests/fixtures/sdk_keyed.idl" > "$HDDS_KEYED_CODEC/sdk_keyed.hpp"
"$HDDSGEN" gen c "$ROOT/crates/hdds-c/tests/fixtures/sdk_keyed.idl" > "$HDDS_KEYED_CODEC/sdk_keyed.h"
# Optional: HDDS_CARGO_LOCK=/path/to/lockfile serializes the cargo steps with
# other builds on a shared machine. Unset, cargo runs directly.
LOCK=()
if [ -n "${HDDS_CARGO_LOCK:-}" ]; then LOCK=(flock "$HDDS_CARGO_LOCK"); fi
cd "$ROOT"
${LOCK[@]+"${LOCK[@]}"} cargo build -p hdds-c --features security
export HDDS_LIB_PATH="${CARGO_TARGET_DIR:-$ROOT/target}/debug"
export HDDS_KEYED_CPP="$HDDS_KEYED_WORK/sdk-keyed-cpp"
export HDDS_KEYED_C="$HDDS_KEYED_WORK/sdk-keyed-c"
gcc -std=c99 -Wall -Wextra -Werror -I"$ROOT/sdk/c/include" -I"$HDDS_KEYED_CODEC" \
    "$ROOT/crates/hdds-c/tests/fixtures/sdk_keyed_writer.c" \
    -L"$HDDS_LIB_PATH" -lhdds_c -Wl,-rpath,"$HDDS_LIB_PATH" -o "$HDDS_KEYED_C"
g++ -std=c++17 -Wall -Wextra -Werror \
    -I"$ROOT/sdk/cxx/include" -I"$ROOT/sdk/c/include" -I"$HDDS_KEYED_CODEC" \
    "$ROOT/crates/hdds-c/tests/fixtures/sdk_keyed_writer.cpp" \
    "$ROOT"/sdk/cxx/src/{logging,participant,pubsub,qos,reader,telemetry,waitset,writer}.cpp \
    -L"$HDDS_LIB_PATH" -lhdds_c -Wl,-rpath,"$HDDS_LIB_PATH" -o "$HDDS_KEYED_CPP"
export HDDS_INTERFACE=lo
${LOCK[@]+"${LOCK[@]}"} cargo test -p hdds-c --features security --test sdk_keyed -- --ignored --nocapture
