#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
ESP32 serial monitor for viewing output.

Usage:
    python3 esp32_monitor.py [PORT] [DURATION]

Example:
    python3 esp32_monitor.py /dev/ttyUSB0 30
"""
import serial
import sys
import time

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 30
BAUD = 115200

ser = serial.Serial(PORT, BAUD, timeout=1)

# Reset ESP32
ser.dtr = False
ser.rts = True
time.sleep(0.1)
ser.rts = False

print(f"=== ESP32 Monitor ({PORT}) - {DURATION}s ===")
start = time.time()
while time.time() - start < DURATION:
    if ser.in_waiting:
        try:
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if line:
                print(line)
        except Exception as e:
            print(f"Error: {e}")

ser.close()
print("=== End ===")
