#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Sample: XML QoS Loading (Python)

Demonstrates loading QoS profiles from XML files, including
standard OMG DDS XML and FastDDS-compatible XML formats.

Usage:
    python xml_loading.py

Expected output:
    [OK] Loaded QoS from XML profile 'reliable_profile'
    [OK] Writer created with XML QoS
    [OK] Reader created with XML QoS

Key concepts:
- Loading QoS from standard OMG DDS XML
- Loading FastDDS-compatible XML profiles
- Applying loaded QoS to writers and readers
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds

NUM_MESSAGES: int = 5
XML_PATH: str = os.path.join(os.path.dirname(__file__), '..', 'qos_profile.xml')


def main() -> int:
    print("=" * 60)
    print("XML QoS Loading Demo")
    print("Load QoS profiles from XML files")
    print("=" * 60)
    print()

    hdds.logging.init(hdds.LogLevel.INFO)

    participant = hdds.Participant("XmlQosDemo")
    print("[OK] Participant created\n")

    # --- Load QoS from standard OMG DDS XML ---
    print("--- Standard OMG DDS XML ---\n")

    writer_qos = hdds.QoS.from_xml(XML_PATH, "reliable_profile")
    if writer_qos:
        print("[OK] Loaded writer QoS from 'reliable_profile'")
    else:
        print("[WARN] XML loading failed, falling back to defaults")
        writer_qos = hdds.QoS.reliable()

    reader_qos = hdds.QoS.from_xml(XML_PATH, "reliable_profile")
    if reader_qos:
        print("[OK] Loaded reader QoS from 'reliable_profile'")
    else:
        print("[WARN] XML loading failed, falling back to defaults")
        reader_qos = hdds.QoS.reliable()

    writer = participant.create_writer("XmlQosTopic", qos=writer_qos)
    reader = participant.create_reader("XmlQosTopic", qos=reader_qos)
    print("[OK] Writer and Reader created with XML QoS\n")

    # --- Load FastDDS-compatible XML ---
    print("--- FastDDS-Compatible XML ---\n")

    fastdds_qos = hdds.QoS.from_fastdds_xml(XML_PATH, "reliable_profile")
    if fastdds_qos:
        print("[OK] Loaded FastDDS-compatible XML profile")
    else:
        print("[INFO] FastDDS XML not available (expected with OMG format)")

    # --- Send/receive test ---
    print("\n--- Pub/Sub Test with XML QoS ---\n")

    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    for i in range(NUM_MESSAGES):
        msg_id = i + 1
        payload = f"XML QoS message #{msg_id}".encode('utf-8')
        writer.write(payload)
        print(f"[SENT] id={msg_id} msg='XML QoS message #{msg_id}'")

    if waitset.wait(timeout=2.0):
        while True:
            data = reader.take()
            if data is None:
                break
            print(f"[RECV] {data.decode('utf-8')}")

    participant.close()

    print("\n=== XML QoS Loading Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
