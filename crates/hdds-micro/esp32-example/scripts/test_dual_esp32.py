#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Test communication between two ESP32s.
Monitors both serial ports simultaneously.

Usage:
    ./test_dual_esp32.py [PORT1] [PORT2] [DURATION]

Examples:
    ./test_dual_esp32.py                           # Default ports, 30s
    ./test_dual_esp32.py /dev/ttyUSB0 /dev/ttyUSB1 60
"""
import serial
import sys
import time
import threading

PORT1 = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
PORT2 = sys.argv[2] if len(sys.argv) > 2 else "/dev/ttyUSB1"
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 30

results = {'port1': 0, 'port2': 0}

def reset_esp32(port):
    ser = serial.Serial(port, 115200)
    ser.dtr = False
    ser.rts = True
    time.sleep(0.1)
    ser.rts = False
    ser.close()

def monitor(port, name, key):
    ser = serial.Serial(port, 115200, timeout=1)
    start = time.time()
    while time.time() - start < DURATION:
        if ser.in_waiting:
            try:
                line = ser.readline().decode('utf-8', errors='replace').strip()
                if 'TX' in line or 'RX' in line:
                    results[key] += 1
                    print(f"[{name}] {line}")
                elif 'IP:' in line or 'Starting' in line or 'Mode' in line:
                    print(f"[{name}] {line}")
            except:
                pass
    ser.close()

# Reset both
print("Resetting both ESP32s...")
reset_esp32(PORT1)
reset_esp32(PORT2)
print("Waiting 10s for boot/WiFi...")
time.sleep(10)

print(f"\n=== Dual ESP32 Test ===")
print(f"Port 1: {PORT1}")
print(f"Port 2: {PORT2}")
print(f"Duration: {DURATION}s\n")

t1 = threading.Thread(target=monitor, args=(PORT1, 'ESP1', 'port1'))
t2 = threading.Thread(target=monitor, args=(PORT2, 'ESP2', 'port2'))
t1.start()
t2.start()
t1.join()
t2.join()

print(f"\n=== Results: ESP1={results['port1']}, ESP2={results['port2']} ===")
