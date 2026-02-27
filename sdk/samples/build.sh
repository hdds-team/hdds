#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

#
# HDDS SDK Samples - Build Script
#
# Usage:
#   ./build.sh           # Build all C samples
#   ./build.sh --cpp     # Build C++ samples
#   ./build.sh --clean   # Clean build artifacts
#   ./build.sh --help    # Show help
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HDDS_ROOT="${HDDS_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
HDDS_INC="$HDDS_ROOT/sdk/c/include"
HDDS_CXX_INC="$HDDS_ROOT/sdk/cxx/include"
HDDS_CXX_LIB="$HDDS_ROOT/sdk/cxx/build/libhdds_cxx.a"
HDDS_LIB="$HDDS_ROOT/target/release"
BUILD_DIR="$SCRIPT_DIR/build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

show_help() {
    echo "HDDS SDK Samples - Build Script"
    echo ""
    echo "Usage:"
    echo "  ./build.sh           Build all C samples"
    echo "  ./build.sh --cpp     Build C++ samples"
    echo "  ./build.sh --all     Build C and C++ samples"
    echo "  ./build.sh --clean   Clean build artifacts"
    echo "  ./build.sh --help    Show this help"
    echo ""
    echo "Environment:"
    echo "  HDDS_ROOT=$HDDS_ROOT"
    echo ""
    echo "Prerequisites:"
    echo "  1. Build HDDS first: cd $HDDS_ROOT && cargo build --release"
    echo "  2. Run this script"
}

check_prerequisites() {
    if [ ! -f "$HDDS_LIB/libhdds_c.so" ]; then
        echo -e "${RED}Error: libhdds_c.so not found at $HDDS_LIB${NC}"
        echo "Build HDDS first: cd $HDDS_ROOT && cargo build --release"
        exit 1
    fi

    if [ ! -f "$HDDS_INC/hdds.h" ]; then
        echo -e "${RED}Error: hdds.h not found at $HDDS_INC${NC}"
        exit 1
    fi
}

check_cpp_prerequisites() {
    check_prerequisites
    if [ ! -f "$HDDS_CXX_LIB" ]; then
        echo -e "${RED}Error: libhdds_cxx.a not found at $HDDS_CXX_LIB${NC}"
        echo "Build C++ SDK: cd $HDDS_ROOT/sdk/cxx/build && cmake .. && make"
        exit 1
    fi
}

build_c_samples() {
    echo -e "${YELLOW}Building C samples...${NC}"

    local success=0
    local failed=0

    # Categories included in standard build:
    #   01_basics 02_qos 04_discovery 05_security 06_performance 07_advanced 08_interop 10_usecases
    #
    # Categories excluded (separate build requirements):
    #   03_types     - codegen-generated types, standalone build via hdds-gen
    #   09_ros2      - requires ROS2 SDK (Python/Rust only)
    #   11_embedded  - requires embedded toolchain (arm-none-eabi-gcc)
    #   12_typescript - requires Node.js/TypeScript, see typescript/README.md
    for sample_dir in 01_basics 02_qos 04_discovery 05_security 06_performance 07_advanced 08_interop 10_usecases; do
        for src in "$SCRIPT_DIR/$sample_dir/c"/*.c; do
            [ -f "$src" ] || continue

            local name=$(basename "$src" .c)
            local out_dir="$BUILD_DIR/$sample_dir/c"
            local out="$out_dir/$name"

            mkdir -p "$out_dir"

            echo -n "  $sample_dir/c/$name... "
            if gcc -Wall -O2 -I"$HDDS_INC" -I"$(dirname "$src")" "$src" \
                   -L"$HDDS_LIB" -lhdds_c -lpthread -lm -Wl,-rpath,"$HDDS_LIB" \
                   -o "$out" 2>/dev/null; then
                echo -e "${GREEN}OK${NC}"
                success=$((success + 1))
            else
                echo -e "${RED}FAILED${NC}"
                failed=$((failed + 1))
            fi
        done
    done

    echo ""
    echo -e "C samples: ${GREEN}$success OK${NC}, ${RED}$failed failed${NC}"
}

build_cpp_samples() {
    echo -e "${YELLOW}Building C++ samples...${NC}"

    local success=0
    local failed=0

    # Same categories as C build (see build_c_samples for excluded list)
    for sample_dir in 01_basics 02_qos 04_discovery 05_security 06_performance 07_advanced 08_interop 10_usecases; do
        for src in "$SCRIPT_DIR/$sample_dir/cpp"/*.cpp; do
            [ -f "$src" ] || continue

            local name=$(basename "$src" .cpp)
            local out_dir="$BUILD_DIR/$sample_dir/cpp"
            local out="$out_dir/$name"

            mkdir -p "$out_dir"

            echo -n "  $sample_dir/cpp/$name... "
            if g++ -Wall -O2 -std=c++17 -I"$HDDS_CXX_INC" -I"$HDDS_INC" -I"$(dirname "$src")" "$src" \
                   "$HDDS_CXX_LIB" -L"$HDDS_LIB" -lhdds_c -lpthread -lm -Wl,-rpath,"$HDDS_LIB" \
                   -o "$out" 2>/dev/null; then
                echo -e "${GREEN}OK${NC}"
                success=$((success + 1))
            else
                echo -e "${RED}FAILED${NC}"
                failed=$((failed + 1))
            fi
        done
    done

    echo ""
    echo -e "C++ samples: ${GREEN}$success OK${NC}, ${RED}$failed failed${NC}"
}

clean() {
    echo "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    echo -e "${GREEN}Done${NC}"
}

# Main
cd "$SCRIPT_DIR"

case "${1:-}" in
    --help|-h)
        show_help
        ;;
    --clean)
        clean
        ;;
    --cpp)
        check_cpp_prerequisites
        build_cpp_samples
        ;;
    --all)
        check_cpp_prerequisites
        build_c_samples
        build_cpp_samples
        ;;
    *)
        check_prerequisites
        build_c_samples
        ;;
esac
