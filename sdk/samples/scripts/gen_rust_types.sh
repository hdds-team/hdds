#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Generate Rust types from IDL files using hddsgen
#
# Usage:
#   ./gen_rust_types.sh
#   ./gen_rust_types.sh --clean  # remove prior Rust outputs first
#
# Prerequisites:
#   - hddsgen must be built and available in PATH
#     (cargo install --path <hdds_gen_repo> --force)
#   - Or set HDDSGEN=/absolute/path/to/hddsgen to override PATH lookup,
#     or HDDS_GEN_DIR=/path/to/hdds_gen (a checkout built with cargo build
#     --release; default: the sibling checkout ../hdds_gen)
#
# Coverage:
#   - 20 IDLs in sdk/samples/idl/ (HelloWorld, KeyedData, Primitives, Strings,
#     Sequences, Arrays, Maps, Enums, Unions, Nested, Bits, Optional,
#     Benchmark, Interop, ROS2Types, Usecases, RequestReply, SecurityTypes,
#     SensorData, WaitsetTypes)
#   - 5 of those land in 2 sample sub-dirs (HelloWorld, KeyedData, Interop,
#     ROS2Types, Usecases) -> 25 type files plus one aggregator mod.rs

set -e

CLEAN=0
if [ "${1:-}" = "--clean" ]; then
    CLEAN=1
    shift
fi
if [ "$#" -ne 0 ]; then
    echo "Usage: $0 [--clean]" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLES_DIR="$(dirname "$SCRIPT_DIR")"
IDL_DIR="$SAMPLES_DIR/idl"
PROJECT_ROOT="$(cd "$SAMPLES_DIR/../.." && pwd)"
# HDDS_GEN_DIR points at an hdds_gen checkout (default: the sibling checkout
# ../hdds_gen next to this repository).
HDDS_GEN_DIR="${HDDS_GEN_DIR:-$PROJECT_ROOT/../hdds_gen}"
SIBLING_HDDSGEN="$HDDS_GEN_DIR/target/release/hddsgen"
if [ -n "${HDDSGEN:-}" ]; then
    : # Explicit override wins.
elif command -v hddsgen >/dev/null 2>&1; then
    HDDSGEN="$(command -v hddsgen)"
elif [ -x "$SIBLING_HDDSGEN" ]; then
    HDDSGEN="$SIBLING_HDDSGEN"
else
    HDDSGEN=""
fi

if [ -z "$HDDSGEN" ] || [ ! -x "$HDDSGEN" ]; then
    echo "ERROR: hddsgen not found in PATH"
    echo "Build + install from hdds_gen source:"
    echo "    cargo install --path /path/to/hdds_gen --force"
    echo "A checkout at \$HDDS_GEN_DIR (default ../hdds_gen) is also detected, via"
    echo "\$HDDS_GEN_DIR/target/release/hddsgen."
    echo "Or export HDDSGEN=/absolute/path/to/hddsgen"
    exit 1
fi

echo "=== Generating Rust types from IDL ($("$HDDSGEN" --version)) ==="

gen() {
    # gen <IDL_NAME> <PRIMARY_OUT> [EXTRA_OUT ...]
    local idl="$1"; shift
    local primary="$1"; shift
    "$HDDSGEN" gen rust "$IDL_DIR/$idl" > "$primary"
    for extra in "$@"; do
        cp "$primary" "$extra"
    done
}

GENERATED_DIRS=(
    "$SAMPLES_DIR/01_basics/rust/generated"
    "$SAMPLES_DIR/03_types/rust/generated"
    "$SAMPLES_DIR/05_security/rust/generated"
    "$SAMPLES_DIR/07_advanced/rust/generated"
    "$SAMPLES_DIR/08_interop/rust/generated"
    "$SAMPLES_DIR/09_ros2/rust/generated"
    "$SAMPLES_DIR/10_usecases/rust/generated"
)

if [ "$CLEAN" -eq 1 ]; then
    for dir in "${GENERATED_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            find "$dir" -maxdepth 1 -type f -name '*.rs' -delete
        fi
    done
fi

mkdir -p "${GENERATED_DIRS[@]}"

# 01_basics + 03_types duplicates
gen HelloWorld.idl \
    "$SAMPLES_DIR/01_basics/rust/generated/helloworld.rs" \
    "$SAMPLES_DIR/03_types/rust/generated/helloworld.rs"
gen KeyedData.idl \
    "$SAMPLES_DIR/01_basics/rust/generated/keyeddata.rs" \
    "$SAMPLES_DIR/03_types/rust/generated/keyeddata.rs"

# 03_types unique
gen Primitives.idl "$SAMPLES_DIR/03_types/rust/generated/primitives.rs"
gen Strings.idl    "$SAMPLES_DIR/03_types/rust/generated/strings.rs"
gen Sequences.idl  "$SAMPLES_DIR/03_types/rust/generated/sequences.rs"
gen Arrays.idl     "$SAMPLES_DIR/03_types/rust/generated/arrays.rs"
gen Maps.idl       "$SAMPLES_DIR/03_types/rust/generated/maps.rs"
gen Enums.idl      "$SAMPLES_DIR/03_types/rust/generated/enums.rs"
gen Unions.idl     "$SAMPLES_DIR/03_types/rust/generated/unions.rs"
gen Nested.idl     "$SAMPLES_DIR/03_types/rust/generated/nested.rs"
gen Bits.idl       "$SAMPLES_DIR/03_types/rust/generated/bits.rs"
gen Optional.idl   "$SAMPLES_DIR/03_types/rust/generated/optional.rs"
gen Benchmark.idl  "$SAMPLES_DIR/03_types/rust/generated/benchmark.rs"

# 03_types + sub-dir duplicates
gen Interop.idl \
    "$SAMPLES_DIR/03_types/rust/generated/interop.rs" \
    "$SAMPLES_DIR/08_interop/rust/generated/interop.rs"
gen ROS2Types.idl \
    "$SAMPLES_DIR/03_types/rust/generated/ros2types.rs" \
    "$SAMPLES_DIR/09_ros2/rust/generated/ros2types.rs"
gen Usecases.idl \
    "$SAMPLES_DIR/03_types/rust/generated/usecases.rs" \
    "$SAMPLES_DIR/10_usecases/rust/generated/usecases.rs"

# Security and advanced samples
gen SecurityTypes.idl "$SAMPLES_DIR/05_security/rust/generated/security_types.rs"
gen SensorData.idl "$SAMPLES_DIR/07_advanced/rust/generated/sensor_data.rs"
gen RequestReply.idl "$SAMPLES_DIR/07_advanced/rust/generated/rpc_types.rs"
gen WaitsetTypes.idl "$SAMPLES_DIR/07_advanced/rust/generated/waitset_types.rs"

# Aggregator mod.rs for 03_types
cat > "$SAMPLES_DIR/03_types/rust/generated/mod.rs" << 'EOF'
// Generated by gen_rust_types.sh - DO NOT EDIT
pub mod arrays;
pub mod bits;
pub mod enums;
pub mod maps;
pub mod nested;
pub mod optional;
pub mod primitives;
pub mod sequences;
pub mod strings;
pub mod unions;
pub mod benchmark;
pub mod helloworld;
pub mod interop;
pub mod keyeddata;
pub mod ros2types;
pub mod usecases;
EOF

echo "=== Done ==="
echo "Generated 26 Rust files across 7 sample sub-dirs from 20 IDLs."
