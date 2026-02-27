#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Static Peers Sample - Demonstrates manual peer configuration

This sample shows how to configure static peers for discovery
when multicast is not available or when you want explicit control.

Use cases:
- Networks without multicast support
- Cloud/container environments
- Explicit peer-to-peer connections

Run with peer addresses:
  Terminal 1: python3 static_peers.py --listen 7400
  Terminal 2: python3 static_peers.py --peer 127.0.0.1:7400

Note: Static peer configuration is typically done via HDDS configuration
files or environment variables. This sample demonstrates the concept
using the standard HDDS API with multicast discovery.
"""

import argparse
import os
import sys
import time

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


def main():
    print("=== HDDS Static Peers Discovery Sample ===\n")

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Static Peers Discovery Sample')
    parser.add_argument('-l', '--listen', type=int, help='Listen on specified port')
    parser.add_argument('-p', '--peer', action='append', default=[],
                       help='Add static peer (host:port)')

    args = parser.parse_args()

    listen_port = args.listen
    peers = args.peer

    # Default configuration if nothing specified
    if listen_port is None and not peers:
        print("No configuration specified. Using defaults:")
        print("  Listen port: 7400")
        print("  Static peer: 127.0.0.1:7401")
        print()
        listen_port = 7400
        peers = ["127.0.0.1:7401"]

    print("Configuration:")
    if listen_port:
        print(f"  Listen port: {listen_port}")
    print(f"  Static peers: {peers}")
    print()

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Build participant
    # Note: In a real deployment, static peers would be configured via
    # HDDS configuration files or environment variables
    print("Creating DomainParticipant...")
    participant = hdds.Participant("StaticPeers")

    print(f"[OK] Participant created: {participant.name}")
    print(f"     Domain ID: {participant.domain_id}")

    # Create writer and reader
    print("\nCreating endpoints...")
    writer = participant.create_writer("StaticPeersDemo")
    reader = participant.create_reader("StaticPeersDemo")
    print("[OK] DataWriter and DataReader created")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    print("\n--- Waiting for Peers ---")
    print("Configured peers will be contacted directly.")
    print("In production, configure HDDS_PEERS environment variable.\n")

    # Communication loop
    instance_id = os.getpid()
    msg_count = 0

    try:
        while msg_count < 10:
            msg_count += 1

            # Send message
            message = f"Static peer {instance_id} says hello #{msg_count}"
            try:
                writer.write(message.encode('utf-8'))
                print(f"[SENT] {message}")
            except Exception as e:
                print(f"[WARN] Send failed (peer may not be connected): {e}")

            # Receive messages using waitset
            if waitset.wait(timeout=0.1):
                while True:
                    data = reader.take()
                    if data is None:
                        break
                    print(f"[RECV] {data.decode('utf-8')}")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n--- Interrupted ---")

    # Show connection status
    print("\n--- Connection Status ---")
    print(f"Messages sent: {msg_count}")

    # Cleanup
    waitset.close()
    participant.close()

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
