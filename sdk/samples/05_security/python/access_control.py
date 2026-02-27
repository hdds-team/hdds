#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Access Control Sample - Demonstrates DDS Security permissions concepts

This sample shows how access control works in DDS Security:
- Governance document (domain-level rules)
- Permissions document (participant-level rules)
- Topic read/write permissions
- Domain and partition access

Key concepts:
- Governance XML defines domain security policies
- Permissions XML defines per-participant access rights
- Signed permissions for tamper protection

Note: Security features are not yet fully implemented in HDDS.
      This sample demonstrates the concepts while using the basic API.

NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DDS Security Access Control.
The native DDS Security Access Control API is not yet exported to the C/C++/Python SDK.
This sample uses standard participant/writer/reader API to show the concept.
"""

import sys
import time
from dataclasses import dataclass, field
from typing import List

# Add SDK to path
sys.path.insert(0, '../../../python')

import hdds


@dataclass
class AccessControlConfig:
    """Access control configuration"""
    governance_file: str
    permissions_file: str
    permissions_ca: str


@dataclass
class TopicPermission:
    """Topic permission rule"""
    topic_pattern: str
    can_publish: bool = False
    can_subscribe: bool = False


@dataclass
class AccessControlPolicy:
    """Participant access control policy (simulated)"""
    subject_name: str
    allowed_domains: List[int] = field(default_factory=list)
    topic_rules: List[TopicPermission] = field(default_factory=list)

    def check_permission(self, topic: str, publish: bool) -> bool:
        """Check if operation is allowed on topic (simulated)"""
        # Simulated permission check for demonstration
        if topic == "RestrictedTopic" and publish:
            return False
        return True


def print_sample_governance():
    print("Sample Governance Document:")
    print("  <domain_access_rules>")
    print("    <domain_rule>")
    print("      <domains><id>0</id></domains>")
    print("      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>")
    print("      <enable_discovery_protection>true</enable_discovery_protection>")
    print("      <topic_access_rules>")
    print("        <topic_rule>")
    print("          <topic_expression>*</topic_expression>")
    print("          <enable_data_protection>true</enable_data_protection>")
    print("        </topic_rule>")
    print("      </topic_access_rules>")
    print("    </domain_rule>")
    print("  </domain_access_rules>\n")


def print_sample_permissions(subject: str):
    print(f"Sample Permissions Document for {subject}:")
    print("  <permissions>")
    print("    <grant name=\"ParticipantGrant\">")
    print(f"      <subject_name>{subject}</subject_name>")
    print("      <validity><not_before>2024-01-01</not_before></validity>")
    print("      <allow_rule>")
    print("        <domains><id>0</id></domains>")
    print("        <publish><topics><topic>SensorData</topic></topics></publish>")
    print("        <subscribe><topics><topic>*</topic></topics></subscribe>")
    print("      </allow_rule>")
    print("      <deny_rule>")
    print("        <domains><id>0</id></domains>")
    print("        <publish><topics><topic>RestrictedTopic</topic></topics></publish>")
    print("      </deny_rule>")
    print("    </grant>")
    print("  </permissions>\n")


def main():
    print("=== HDDS Access Control Sample ===\n")
    print("NOTE: CONCEPT DEMO - Native DDS Security Access Control API not yet in SDK.")
    print("      Using standard pub/sub API to demonstrate the pattern.\n")

    participant_name = sys.argv[1] if len(sys.argv) > 1 else "SensorNode"
    subject_name = "CN=SensorNode,O=HDDS,C=US"

    print("--- DDS Security Access Control ---")
    print("Access control uses two XML documents:")
    print("1. Governance: Domain-wide security policies")
    print("2. Permissions: Per-participant access rights\n")

    # Show example documents
    print_sample_governance()
    print_sample_permissions(subject_name)

    # Configure access control (conceptual)
    ac_config = AccessControlConfig(
        governance_file="../certs/governance.xml",
        permissions_file="../certs/permissions.xml",
        permissions_ca="../certs/permissions_ca.pem"
    )

    print("Access Control Configuration:")
    print(f"  Governance:   {ac_config.governance_file}")
    print(f"  Permissions:  {ac_config.permissions_file}")
    print(f"  Permissions CA: {ac_config.permissions_ca}\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating DomainParticipant with access control...")
    participant = hdds.Participant(participant_name)
    print(f"[OK] Participant created: {participant_name}")
    print(f"     Subject: {subject_name}\n")

    # Create simulated access control policy for demonstration
    policy = AccessControlPolicy(subject_name=subject_name)

    # Test topic permissions (simulated)
    print("--- Testing Topic Permissions ---\n")

    test_topics = [
        "SensorData",
        "CommandTopic",
        "RestrictedTopic",
        "LogData"
    ]

    for topic in test_topics:
        can_pub = policy.check_permission(topic, publish=True)
        can_sub = policy.check_permission(topic, publish=False)

        print(f"Topic '{topic}':")
        print(f"  Publish:   {'ALLOWED' if can_pub else 'DENIED'}")
        print(f"  Subscribe: {'ALLOWED' if can_sub else 'DENIED'}\n")

    # Create endpoints for allowed topics
    print("--- Creating Endpoints ---\n")

    print("Creating writer for 'SensorData'...")
    if policy.check_permission("SensorData", publish=True):
        writer = participant.create_writer("SensorData")
        print("[OK] DataWriter created\n")

        # Write some sample data
        print("Publishing sensor data...")
        for i in range(3):
            data = f"Sensor reading {i}: temperature=22.{i}C"
            writer.write(data.encode('utf-8'))
            print(f"  [SENT] {data}")
            time.sleep(0.5)
        print()
    else:
        print("[DENIED] No publish permission\n")

    print("Creating writer for 'RestrictedTopic'...")
    if policy.check_permission("RestrictedTopic", publish=True):
        writer = participant.create_writer("RestrictedTopic")
        print("[OK] DataWriter created\n")
    else:
        print("[DENIED] No publish permission for this topic")
        print("         (Access control would prevent this endpoint creation)\n")

    # Summary
    print("--- Access Control Summary ---")
    print(f"Participant: {participant_name}")
    print(f"Subject DN: {subject_name}")
    print("\nPermissions (simulated):")
    print("  - Can publish to: SensorData, CommandTopic, LogData")
    print("  - Cannot publish to: RestrictedTopic")
    print("  - Can subscribe to: all topics")
    print("\nNote: Full security features are not yet implemented.")
    print("      This sample demonstrates access control concepts")
    print("      while using the basic HDDS API.")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
