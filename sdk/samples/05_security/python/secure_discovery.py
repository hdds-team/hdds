#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Secure Discovery Sample - Demonstrates authenticated discovery concepts

This sample shows how secure participant discovery works in DDS Security:
- Authenticated SPDP (Simple Participant Discovery Protocol)
- Discovery protection settings
- Liveliness with authentication
- Secure endpoint matching

Key concepts:
- Discovery protection in governance
- Authenticated participant announcements
- Secure builtin endpoints

Note: Security features are not yet fully implemented in HDDS.
      This sample demonstrates the concepts while using the basic API.

NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Secure Discovery.
The native DDS Security Secure Discovery API is not yet exported to the C/C++/Python SDK.
This sample uses standard participant/writer/reader API to show the concept.
"""

import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


@dataclass
class SecureDiscoveryConfig:
    """Secure discovery configuration"""
    enable_discovery_protection: bool = True
    enable_liveliness_protection: bool = True
    allow_unauthenticated: bool = False
    identity_ca: str = ""
    identity_cert: str = ""
    private_key: str = ""


@dataclass
class DiscoveredParticipant:
    """Discovered participant info (simulated)"""
    guid: str
    name: str
    subject_name: str
    authenticated: bool
    discovered_at: float


def get_certs_dir() -> Path:
    """Get path to certificates directory"""
    return Path(__file__).parent.parent / "certs"


def print_discovery_security_info():
    print("--- Secure Discovery Overview ---\n")
    print("Standard SPDP sends participant info in plaintext.")
    print("Secure SPDP adds:")
    print("  1. Authentication of participant announcements")
    print("  2. Encryption of discovery metadata")
    print("  3. Rejection of unauthenticated participants")
    print("  4. Secure liveliness assertions\n")

    print("Governance Settings:")
    print("  <enable_discovery_protection>true</enable_discovery_protection>")
    print("  <enable_liveliness_protection>true</enable_liveliness_protection>")
    print("  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\n")


def run_announcer(participant, participant_name):
    """Run participant that announces itself and discovers peers."""
    print("Creating writer for discovery announcements...")
    writer = participant.create_writer("ParticipantAnnouncement")

    print("Creating reader for peer announcements...")
    reader = participant.create_reader("ParticipantAnnouncement")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    cond = reader.get_status_condition()
    waitset.attach(cond)

    print("\n--- Secure Discovery Active ---\n")

    # Simulated discovered participants
    discovered: List[DiscoveredParticipant] = []

    for iteration in range(10):
        # Send authenticated announcement
        announcement = f"SPDP:{participant_name}:iteration={iteration}"
        writer.write(announcement.encode('utf-8'))
        print(f"[ANNOUNCE] Sent authenticated SPDP for {participant_name}")

        # Check for peer announcements
        if waitset.wait(timeout=2.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                message = data.decode('utf-8')
                if message.startswith("SPDP:"):
                    parts = message.split(":")
                    peer_name = parts[1] if len(parts) > 1 else "Unknown"

                    # Check if already discovered
                    if not any(p.name == peer_name for p in discovered):
                        new_peer = DiscoveredParticipant(
                            guid=f"01.0f.ab.cd.00.00.00.{len(discovered)+1:02x}",
                            name=peer_name,
                            subject_name=f"CN={peer_name},O=HDDS,C=US",
                            authenticated=True,
                            discovered_at=time.time()
                        )
                        discovered.append(new_peer)

                        print(f"\n[DISCOVERED] Authenticated Participant")
                        print(f"  GUID:    {new_peer.guid}")
                        print(f"  Name:    {new_peer.name}")
                        print(f"  Subject: {new_peer.subject_name}")
                        print(f"  Status:  AUTHENTICATED\n")
        else:
            print("  (waiting for authenticated peers...)")

        time.sleep(1)

    return discovered


def main():
    print("=== HDDS Secure Discovery Sample ===\n")
    print("NOTE: CONCEPT DEMO - Native DDS Security Secure Discovery API not yet in SDK.")
    print("      Using standard pub/sub API to demonstrate the pattern.\n")

    participant_name = sys.argv[1] if len(sys.argv) > 1 else "SecureDiscovery"
    certs_dir = get_certs_dir()

    print_discovery_security_info()

    # Configure secure discovery (conceptual)
    config = SecureDiscoveryConfig(
        enable_discovery_protection=True,
        enable_liveliness_protection=True,
        allow_unauthenticated=False,
        identity_ca=str(certs_dir / "ca_cert.pem"),
        identity_cert=str(certs_dir / f"{participant_name}_cert.pem"),
        private_key=str(certs_dir / f"{participant_name}_key.pem")
    )

    print("Secure Discovery Configuration:")
    print(f"  Discovery Protection:  {'ENABLED' if config.enable_discovery_protection else 'DISABLED'}")
    print(f"  Liveliness Protection: {'ENABLED' if config.enable_liveliness_protection else 'DISABLED'}")
    print(f"  Allow Unauthenticated: {'YES' if config.allow_unauthenticated else 'NO'}\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating DomainParticipant with secure discovery...")
    participant = hdds.Participant(participant_name)
    print(f"[OK] Participant created: {participant_name}")
    print("[OK] Secure discovery enabled (conceptual)")
    print("[OK] Builtin endpoints protected (conceptual)\n")

    print("--- Secure Discovery Process ---\n")
    print("1. Send authenticated SPDP announcement")
    print("2. Receive and verify peer announcements")
    print("3. Perform mutual authentication handshake")
    print("4. Exchange encrypted endpoint info (SEDP)")
    print("5. Establish secure data channels\n")

    print("--- Discovering Authenticated Peers ---")
    print("Run another instance with different identity:")
    print(f"  python {sys.argv[0]} Participant2\n")

    try:
        discovered = run_announcer(participant, participant_name)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        discovered = []

    # Show discovery summary
    print("\n--- Secure Discovery Summary ---\n")
    print(f"Total authenticated participants: {len(discovered)}\n")

    for i, p in enumerate(discovered, 1):
        print(f"Participant {i}:")
        print(f"  Name: {p.name}")
        print(f"  Subject: {p.subject_name}")
        print(f"  Authenticated: {'YES' if p.authenticated else 'NO'}\n")

    print("Security Benefits:")
    print("  - Only trusted participants can join")
    print("  - Discovery metadata is encrypted")
    print("  - Prevents rogue participant injection")
    print("  - Protects endpoint information")

    print("\nNote: Full security features are not yet implemented.")
    print("      This sample demonstrates secure discovery concepts")
    print("      while using the basic HDDS API.")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
