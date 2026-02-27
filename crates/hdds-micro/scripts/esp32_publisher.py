#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Temperature publisher for ESP32 subscriber testing.
Works on any platform (PC, Pi Zero, etc.)

Usage:
    python3 esp32_publisher.py [ESP32_IP] [COUNT]

Example:
    python3 esp32_publisher.py 192.168.0.71 10
"""
import socket
import struct
import sys
import time

DEST_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.71"
DEST_PORT = 17401
COUNT = int(sys.argv[2]) if len(sys.argv) > 2 else 10

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"Sending {COUNT} temperature samples to {DEST_IP}:{DEST_PORT}")

for seq in range(COUNT):
    temp_value = 20.0 + (seq * 0.5)

    # Build RTPS-like packet
    buf = bytearray(128)

    # RTPS header
    buf[0:4] = b"RTPS"
    buf[4] = 2  # version major
    buf[5] = 3  # version minor
    buf[6] = 0x01  # vendor
    buf[7] = 0x0F

    # CDR payload at offset 20 (little-endian)
    struct.pack_into('<I', buf, 20, 0xE532)  # sensor_id
    struct.pack_into('<f', buf, 24, temp_value)  # value
    struct.pack_into('<Q', buf, 32, seq * 1000)  # timestamp

    sock.sendto(buf[:40], (DEST_IP, DEST_PORT))
    print(f"TX #{seq+1}: temp={temp_value:.1f}C")
    time.sleep(1)

print(f"Done - {COUNT} samples sent!")
sock.close()
