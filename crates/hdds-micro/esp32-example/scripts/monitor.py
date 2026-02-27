#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
ESP32 serial monitor with optional reset.

Usage:
    ./monitor.py [PORT] [DURATION] [--no-reset]

Examples:
    ./monitor.py                      # Monitor ttyUSB0 for 30s with reset
    ./monitor.py /dev/ttyUSB1 60      # Monitor ttyUSB1 for 60s
    ./monitor.py /dev/ttyUSB0 30 --no-reset  # No reset before monitoring
"""
import serial
import sys
import time

PORT = "/dev/ttyUSB0"
DURATION = 30
RESET = True

# Parse args
args = [a for a in sys.argv[1:] if not a.startswith('-')]
flags = [a for a in sys.argv[1:] if a.startswith('-')]

if len(args) >= 1:
    PORT = args[0]
if len(args) >= 2:
    DURATION = int(args[1])
if '--no-reset' in flags:
    RESET = False

ser = serial.Serial(PORT, 115200, timeout=1)

if RESET:
    print(f"Resetting {PORT}...")
    ser.dtr = False
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False

print(f"=== Monitoring {PORT} for {DURATION}s ===\n")
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
print("\n=== Done ===")
