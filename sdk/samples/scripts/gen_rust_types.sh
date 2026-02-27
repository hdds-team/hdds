#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Generate Rust types from IDL files using hdds_gen
#
# Usage: ./gen_rust_types.sh
#
# Prerequisites:
#   - hdds_gen must be built and idl-gen available in PATH or set HDDS_GEN env var

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLES_DIR="$(dirname "$SCRIPT_DIR")"
IDL_DIR="$SAMPLES_DIR/idl"
HDDS_GEN="${HDDS_GEN:-$(command -v idl-gen 2>/dev/null || echo "")}"

# Check hdds_gen exists
if [ -z "$HDDS_GEN" ] || [ ! -x "$HDDS_GEN" ]; then
    echo "ERROR: idl-gen not found in PATH"
    echo "Either add it to PATH or set HDDS_GEN=/path/to/idl-gen"
    exit 1
fi

echo "=== Generating Rust types from IDL ==="

# 01_basics
echo "Generating 01_basics types..."
mkdir -p "$SAMPLES_DIR/01_basics/rust/generated"
$HDDS_GEN gen rust "$IDL_DIR/HelloWorld.idl" > "$SAMPLES_DIR/01_basics/rust/generated/hello_world.rs"
$HDDS_GEN gen rust "$IDL_DIR/KeyedData.idl" > "$SAMPLES_DIR/01_basics/rust/generated/keyed_data.rs"

# 03_types
echo "Generating 03_types types..."
mkdir -p "$SAMPLES_DIR/03_types/rust/generated"
$HDDS_GEN gen rust "$IDL_DIR/Primitives.idl" > "$SAMPLES_DIR/03_types/rust/generated/primitives.rs"
$HDDS_GEN gen rust "$IDL_DIR/Strings.idl" > "$SAMPLES_DIR/03_types/rust/generated/strings.rs"
$HDDS_GEN gen rust "$IDL_DIR/Sequences.idl" > "$SAMPLES_DIR/03_types/rust/generated/sequences.rs"
$HDDS_GEN gen rust "$IDL_DIR/Arrays.idl" > "$SAMPLES_DIR/03_types/rust/generated/arrays.rs"
$HDDS_GEN gen rust "$IDL_DIR/Maps.idl" > "$SAMPLES_DIR/03_types/rust/generated/maps.rs"
$HDDS_GEN gen rust "$IDL_DIR/Enums.idl" > "$SAMPLES_DIR/03_types/rust/generated/enums.rs"
$HDDS_GEN gen rust "$IDL_DIR/Unions.idl" > "$SAMPLES_DIR/03_types/rust/generated/unions.rs"
$HDDS_GEN gen rust "$IDL_DIR/Nested.idl" > "$SAMPLES_DIR/03_types/rust/generated/nested.rs"
$HDDS_GEN gen rust "$IDL_DIR/Bits.idl" > "$SAMPLES_DIR/03_types/rust/generated/bits.rs"
$HDDS_GEN gen rust "$IDL_DIR/Optional.idl" > "$SAMPLES_DIR/03_types/rust/generated/optional.rs"

# Generate mod.rs for 03_types
cat > "$SAMPLES_DIR/03_types/rust/generated/mod.rs" << 'EOF'
// Generated module index - DO NOT EDIT
pub mod primitives;
pub mod strings;
pub mod sequences;
pub mod arrays;
pub mod maps;
pub mod enums;
pub mod unions;
pub mod nested;
pub mod bits;
pub mod optional;
EOF

echo "=== Done ==="
echo "Generated files in:"
echo "  - $SAMPLES_DIR/01_basics/rust/generated/"
echo "  - $SAMPLES_DIR/03_types/rust/generated/"
