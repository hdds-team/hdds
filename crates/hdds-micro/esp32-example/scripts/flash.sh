#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Flash ESP32 firmware
# Usage: ./flash.sh [PORT] [BINARY]
#   ./flash.sh                          # Flash main.rs to /dev/ttyUSB0
#   ./flash.sh /dev/ttyUSB1             # Flash to specific port
#   ./flash.sh /dev/ttyUSB0 hc12_test   # Flash specific binary

set -e
cd "$(dirname "$0")/.."
source scripts/export-esp.sh

PORT="${1:-/dev/ttyUSB0}"
BINARY="${2:-hdds-micro-esp32}"

echo "Building $BINARY..."
cargo build --release --bin "$BINARY"

echo "Flashing to $PORT..."
espflash flash --port "$PORT" "target/xtensa-esp32-espidf/release/$BINARY"

echo "Done!"
