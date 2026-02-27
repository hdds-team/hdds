#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Encryption Sample - Demonstrates DDS data encryption concepts

This sample shows how cryptographic protection works in DDS Security:
- Data encryption (AES-GCM)
- Message authentication (GMAC)
- Key exchange protocols
- Per-topic encryption settings

Key concepts:
- Crypto plugin configuration
- Protection kinds (encrypt, sign, none)
- Shared secret key exchange

Note: Security features are not yet fully implemented in HDDS.
      This sample demonstrates the concepts while using the basic API.

NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Encryption.
The native DDS Security Encryption API is not yet exported to the C/C++/Python SDK.
This sample uses standard participant/writer/reader API to show the concept.
"""

import sys
import time
from dataclasses import dataclass
from enum import Enum

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


class ProtectionKind(Enum):
    """Protection kind for cryptographic operations"""
    NONE = "none"
    SIGN = "sign"           # GMAC - integrity only
    ENCRYPT = "encrypt"     # AES-GCM - confidentiality + integrity
    SIGN_ENCRYPT = "sign_encrypt"  # Sign then encrypt


@dataclass
class CryptoConfig:
    """Cryptographic configuration"""
    rtps_protection: ProtectionKind = ProtectionKind.ENCRYPT
    metadata_protection: ProtectionKind = ProtectionKind.SIGN
    data_protection: ProtectionKind = ProtectionKind.ENCRYPT


@dataclass
class CryptoStats:
    """Encryption statistics (simulated)"""
    bytes_encrypted: int = 0
    bytes_decrypted: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    auth_failures: int = 0


def protection_kind_str(kind: ProtectionKind) -> str:
    """Convert protection kind to display string"""
    mapping = {
        ProtectionKind.NONE: "NONE",
        ProtectionKind.SIGN: "SIGN (GMAC)",
        ProtectionKind.ENCRYPT: "ENCRYPT (AES-GCM)",
        ProtectionKind.SIGN_ENCRYPT: "SIGN+ENCRYPT"
    }
    return mapping.get(kind, "UNKNOWN")


def print_crypto_info():
    print("--- DDS Security Cryptography ---\n")
    print("Encryption Algorithms:")
    print("  - AES-128-GCM: Fast, hardware-accelerated encryption")
    print("  - AES-256-GCM: Stronger encryption for sensitive data")
    print("  - GMAC: Message authentication without encryption\n")

    print("Protection Levels:")
    print("  - RTPS Protection: Protects entire RTPS messages")
    print("  - Metadata Protection: Protects discovery information")
    print("  - Data Protection: Protects user data payload\n")

    print("Key Exchange:")
    print("  - DH + AES Key Wrap for shared secrets")
    print("  - Per-endpoint session keys")
    print("  - Key rotation supported\n")


def run_publisher(participant, crypto_config):
    """Run publisher sending encrypted messages."""
    print("Creating writer for EncryptedData topic...")
    writer = participant.create_writer("EncryptedData")
    print("[OK] DataWriter created (data will be encrypted)\n")

    print("--- Sending Encrypted Messages ---\n")

    # Simulated encryption statistics
    stats = CryptoStats()

    # Test messages with sensitive data (demonstrating encryption need)
    test_messages = [
        "Sensitive data: credit_card=4111-XXXX-XXXX-1111",
        "Private key: [REDACTED]",
        "Password: [REDACTED]",
        "API token: sk_test_EXAMPLE_DO_NOT_USE",
        "Patient record: SSN=000-00-0000"
    ]

    for i, msg in enumerate(test_messages, 1):
        print(f'Original:  "{msg}"')
        print(f"Wire format: [AES-GCM encrypted, {len(msg)} bytes + 16 byte tag]")

        writer.write(msg.encode('utf-8'))
        stats.bytes_encrypted += len(msg)
        stats.messages_sent += 1

        print(f"[SENT] Message {i} encrypted and sent\n")
        time.sleep(0.5)

    return stats


def run_subscriber(participant):
    """Run subscriber receiving encrypted messages."""
    print("Creating reader for EncryptedData topic...")
    reader = participant.create_reader("EncryptedData")
    print("[OK] DataReader created (data will be decrypted)\n")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    cond = reader.get_status_condition()
    waitset.attach(cond)

    print("--- Receiving Encrypted Messages ---\n")
    print("Run a publisher with: python encryption.py pub\n")

    # Simulated decryption statistics
    stats = CryptoStats()
    received = 0
    max_receive = 10

    while received < max_receive:
        if waitset.wait(timeout=5.0):
            while True:
                data = reader.take()
                if data is None:
                    break
                message = data.decode('utf-8')
                stats.bytes_decrypted += len(message)
                stats.messages_received += 1
                print(f"[RECV] Decrypted: {message}")
                received += 1
        else:
            print("  (waiting for encrypted data...)")

    return stats


def main():
    print("=== HDDS Encryption Sample ===\n")
    print("NOTE: CONCEPT DEMO - Native DDS Security Encryption API not yet in SDK.")
    print("      Using standard pub/sub API to demonstrate the pattern.\n")

    # Parse arguments
    is_publisher = len(sys.argv) > 1 and sys.argv[1].lower() in ('pub', 'publisher', '-p')

    print_crypto_info()

    # Configure encryption (conceptual)
    crypto_config = CryptoConfig(
        rtps_protection=ProtectionKind.ENCRYPT,
        metadata_protection=ProtectionKind.SIGN,
        data_protection=ProtectionKind.ENCRYPT
    )

    print("Crypto Configuration:")
    print(f"  RTPS Protection:     {protection_kind_str(crypto_config.rtps_protection)}")
    print(f"  Metadata Protection: {protection_kind_str(crypto_config.metadata_protection)}")
    print(f"  Data Protection:     {protection_kind_str(crypto_config.data_protection)}\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating DomainParticipant with encryption...")
    participant = hdds.Participant("EncryptedNode")
    print("[OK] Participant created\n")

    try:
        if is_publisher:
            stats = run_publisher(participant, crypto_config)
        else:
            stats = run_subscriber(participant)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        stats = CryptoStats()

    # Show encryption statistics
    print("--- Encryption Statistics ---\n")
    print(f"Bytes encrypted:     {stats.bytes_encrypted}")
    print(f"Bytes decrypted:     {stats.bytes_decrypted}")
    print(f"Messages sent:       {stats.messages_sent}")
    print(f"Messages received:   {stats.messages_received}")
    print(f"Auth failures:       {stats.auth_failures}")

    # Show protection comparison
    print("\n--- Protection Level Comparison ---\n")
    print("| Level          | Confidentiality | Integrity | Overhead |")
    print("|----------------|-----------------|-----------|----------|")
    print("| NONE           | No              | No        | 0 bytes  |")
    print("| SIGN (GMAC)    | No              | Yes       | 16 bytes |")
    print("| ENCRYPT (GCM)  | Yes             | Yes       | 16 bytes |")
    print("| SIGN+ENCRYPT   | Yes             | Yes       | 32 bytes |")

    print("\nRecommendations:")
    print("  - Use ENCRYPT for sensitive user data")
    print("  - Use SIGN for discovery metadata (performance)")
    print("  - Use NONE only for non-sensitive data in trusted networks")

    print("\nNote: Full security features are not yet implemented.")
    print("      This sample demonstrates encryption concepts")
    print("      while using the basic HDDS API.")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
