#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Get ESP32 board info for all connected devices
# Usage: ./board_info.sh

source "$(dirname "$0")/export-esp.sh"

for port in /dev/ttyUSB*; do
    if [ -e "$port" ]; then
        echo "=== $port ==="
        espflash board-info --port "$port" 2>&1 | grep -E "Chip|Flash|Features|MAC|Crystal"
        echo ""
    fi
done
