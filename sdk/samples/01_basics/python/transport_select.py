#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: Transport Selection (Python)

Demonstrates creating participants with explicit transport selection.
Shows UDP (default), TCP, and how to switch between transports.

Usage:
    python transport_select.py              # Default UDP transport
    python transport_select.py tcp          # TCP transport
    python transport_select.py udp          # Explicit UDP transport

Expected output:
    [OK] Participant created with UDP transport
    [SENT] Transport test message #1
    ...

Key concepts:
- Default transport is UDP multicast
- TCP transport for NAT traversal / WAN
- Transport selected at participant creation
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds

NUM_MESSAGES: int = 5


def main() -> int:
    transport = "udp"
    if len(sys.argv) > 1:
        transport = sys.argv[1].lower()

    print("=" * 60)
    print("Transport Selection Demo")
    print(f"Selected transport: {transport}")
    print("=" * 60)
    print()

    hdds.logging.init(hdds.LogLevel.INFO)

    print("--- Available Transports ---")
    print("  udp  - UDP multicast (default, LAN discovery)")
    print("  tcp  - TCP point-to-point (NAT traversal, WAN)")
    print()

    # Create participant with selected transport
    if transport == "tcp":
        kind = hdds.TransportKind.TCP
    else:
        kind = hdds.TransportKind.UDP

    participant = hdds.Participant("TransportDemo", transport=kind)
    print(f"[OK] Participant created with {transport.upper()} transport")

    # Create endpoints
    writer = participant.create_writer("TransportTopic")
    print("[OK] DataWriter created on 'TransportTopic'")

    reader = participant.create_reader("TransportTopic")
    print("[OK] DataReader created on 'TransportTopic'\n")

    # Send messages
    print(f"--- Sending {NUM_MESSAGES} messages via {transport} ---\n")

    for i in range(NUM_MESSAGES):
        msg_id = i + 1
        payload = f"Transport test #{msg_id} ({transport})".encode('utf-8')
        writer.write(payload)
        print(f"[SENT] id={msg_id} msg='Transport test #{msg_id} ({transport})'")
        time.sleep(0.2)

    # Read back
    print("\n--- Reading messages ---\n")

    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    if waitset.wait(timeout=2.0):
        while True:
            data = reader.take()
            if data is None:
                break
            print(f"[RECV] {data.decode('utf-8')}")
    else:
        print("[TIMEOUT] No messages received (run two instances to test)")

    participant.close()

    print("\n=== Transport Selection Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
