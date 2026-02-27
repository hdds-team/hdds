#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Authentication Sample - Demonstrates PKI-based participant authentication concepts

This sample shows DDS Security authentication concepts:
- Certificate-based identity (X.509)
- CA trust chain validation
- Mutual authentication between participants

Key concepts:
- Identity Certificate and Private Key
- Certificate Authority (CA) for trust
- Authentication plugin configuration

Note: Security features are not yet fully implemented in HDDS.
      This sample demonstrates the concepts while using the basic API.

Prerequisites:
  Generate certificates using: ../certs/generate_certs.sh

NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Authentication.
The native DDS Security Authentication API is not yet exported to the C/C++/Python SDK.
This sample uses standard participant/writer/reader API to show the concept.
"""

import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


@dataclass
class AuthenticationConfig:
    """Authentication configuration for DDS Security"""
    identity_ca: str       # CA certificate path
    identity_cert: str     # Participant certificate path
    private_key: str       # Private key path
    password: str = ""     # Private key password (optional)


def get_certs_dir() -> Path:
    """Get path to certificates directory"""
    return Path(__file__).parent.parent / "certs"


def print_cert_info(label: str, path: Path):
    """Print certificate file info"""
    status = "[OK]" if path.exists() else "[NOT FOUND]"
    print(f"  {label}: {path} {status}")


def run_publisher(participant, participant_name):
    """Run publisher sending authenticated messages."""
    print("Creating writer for SecureData topic...")
    writer = participant.create_writer("SecureData")

    print("\n--- Sending Authenticated Messages ---\n")

    for msg_count in range(1, 6):
        message = f"Authenticated message #{msg_count} from {participant_name}"
        print(f"[SEND] {message}")
        writer.write(message.encode('utf-8'))
        print("       (message signed with participant identity)")
        time.sleep(2)

    print("\nDone sending.")


def run_subscriber(participant):
    """Run subscriber receiving authenticated messages."""
    print("Creating reader for SecureData topic...")
    reader = participant.create_reader("SecureData")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    cond = reader.get_status_condition()
    waitset.attach(cond)

    print("\n--- Waiting for Authenticated Messages ---\n")
    print("Run a publisher with:")
    print("  python authentication.py pub [ParticipantName]\n")

    received = 0
    max_receive = 10

    while received < max_receive:
        if waitset.wait(timeout=5.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                message = data.decode('utf-8')
                print(f"[RECV] {message}")
                print("       (sender identity verified)")
                received += 1
        else:
            print("  (waiting for authenticated peers...)")

    print("\nDone receiving.")


def main():
    print("=== HDDS Authentication Sample ===\n")
    print("NOTE: CONCEPT DEMO - Native DDS Security Authentication API not yet in SDK.")
    print("      Using standard pub/sub API to demonstrate the pattern.\n")

    # Parse arguments
    is_publisher = len(sys.argv) > 1 and sys.argv[1].lower() in ('pub', 'publisher', '-p')
    participant_name = sys.argv[2] if len(sys.argv) > 2 else "Participant1"

    certs_dir = get_certs_dir()

    # Configure authentication (conceptual - security not yet implemented)
    auth_config = AuthenticationConfig(
        identity_ca=str(certs_dir / "ca_cert.pem"),
        identity_cert=str(certs_dir / f"{participant_name}_cert.pem"),
        private_key=str(certs_dir / f"{participant_name}_key.pem"),
        password=""
    )

    print("Security Configuration:")
    print_cert_info("CA Certificate", Path(auth_config.identity_ca))
    print_cert_info("Identity Cert ", Path(auth_config.identity_cert))
    print_cert_info("Private Key   ", Path(auth_config.private_key))
    print()

    print("--- DDS Security Authentication ---")
    print("Authentication uses X.509 PKI:")
    print("1. Each participant has an identity certificate")
    print("2. Certificates are signed by a trusted CA")
    print("3. Participants validate each other's certificates")
    print("4. Only authenticated participants can communicate\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print(f"Creating DomainParticipant '{participant_name}'...")
    participant = hdds.Participant(participant_name)
    print("[OK] Participant created")

    # Display authentication status (conceptual)
    print("\nAuthentication Status (conceptual):")
    print(f"  Authenticated: YES")
    print(f"  Local Identity: CN={participant_name},O=HDDS,C=US")
    print(f"  Status: AUTHENTICATED\n")

    try:
        if is_publisher:
            run_publisher(participant, participant_name)
        else:
            run_subscriber(participant)
    except KeyboardInterrupt:
        print("\nInterrupted.")

    # Show authentication summary
    print("\n--- Authentication Summary ---")
    print(f"This participant: {participant_name}")
    print("Authentication: SUCCESS (conceptual)")
    print("\nNote: Full security features are not yet implemented.")
    print("      This sample demonstrates authentication concepts")
    print("      while using the basic HDDS API for communication.")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
