#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

# Test PC -> ESP32 communication
# Usage: ./test_pc_to_esp32.sh [ESP32_IP]

ESP32_IP="${1:-192.168.0.71}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== PC -> ESP32 Test ==="
echo "ESP32 IP: $ESP32_IP"
echo ""

# Reset ESP32 and wait for WiFi
python3 -c "
import serial
import time
ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)
ser.dtr = False
ser.rts = True
time.sleep(0.1)
ser.rts = False
ser.close()
"
echo "ESP32 reset, waiting 10s for WiFi..."
sleep 10

# Start publisher in background
python3 "$SCRIPT_DIR/esp32_publisher.py" "$ESP32_IP" 10 &
PUB_PID=$!

# Monitor ESP32 for RX messages
sleep 2
python3 -c "
import serial
import time

ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)
start = time.time()
rx_count = 0
while time.time() - start < 15:
    if ser.in_waiting:
        line = ser.readline().decode('utf-8', errors='replace').strip()
        if 'RX' in line:
            print(line)
            rx_count += 1
ser.close()
print(f'\n=== Result: {rx_count}/10 messages received ===')
"

wait $PUB_PID 2>/dev/null
