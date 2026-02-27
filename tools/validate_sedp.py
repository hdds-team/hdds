#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
SEDP Packet Validator - Analyze and validate RTPS SEDP packets for DDS interop debugging

This tool parses RTPS packets from pcap files and performs deep validation of SEDP
(Simple Endpoint Discovery Protocol) announcements to ensure compliance with the
RTPS specification and compatibility with FastDDS/RTI Connext.

Features:
- Decode EntityID to classify packet types (SPDP/SEDP_PUB/SEDP_SUB/USER)
- Parse CDR-encoded parameter lists (PIDs)
- Validate required SEDP parameters
- Check QoS parameter encoding
- Compare against spec requirements

Usage:
    python3 validate_sedp.py /tmp/hdds_capture.pcap
    python3 validate_sedp.py /tmp/hdds_capture.pcap --verbose
    python3 validate_sedp.py /tmp/hdds_capture.pcap --dump-pids
"""

import struct
import sys
from pathlib import Path

# ================================
# RTPS Constants
# ================================

# Submessage IDs (RTPS v2.3 Table 8.18)
RTPS_SUBMSG_PAD = 0x01
RTPS_SUBMSG_ACKNACK = 0x06
RTPS_SUBMSG_HEARTBEAT = 0x07
RTPS_SUBMSG_GAP = 0x08
RTPS_SUBMSG_INFO_TS = 0x09
RTPS_SUBMSG_INFO_SRC = 0x0C
RTPS_SUBMSG_INFO_REPLY_IP4 = 0x0D
RTPS_SUBMSG_INFO_DST = 0x0E
RTPS_SUBMSG_INFO_REPLY = 0x0F
RTPS_SUBMSG_NACK_FRAG = 0x12
RTPS_SUBMSG_HEARTBEAT_FRAG = 0x13
RTPS_SUBMSG_DATA = 0x15
RTPS_SUBMSG_DATA_FRAG = 0x16

# EntityID classification (RTPS v2.3 Table 9.1)
ENTITY_IDS = {
    0x000000C0: "ENTITYID_UNKNOWN",
    0x000100C2: "ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER",
    0x000001C1: "ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER",
    0x000003C2: "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER",
    0x000004C2: "ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER",
    0x000003C7: "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER",
    0x000004C7: "ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_READER",
    0x000200C2: "ENTITYID_SEDP_BUILTIN_TOPIC_WRITER",
    0x000201C2: "ENTITYID_SEDP_BUILTIN_TOPIC_READER",
}

# Parameter IDs (RTPS v2.3 Table 8.76, DDS-XTypes v1.3)
PID_MAP = {
    0x0001: "PID_SENTINEL",
    0x0002: "PID_USER_DATA",
    0x0003: "PID_TOPIC_NAME",  # Correct per RTPS v2.3 Table 8.76
    0x0004: "PID_TYPE_NAME",   # Correct per RTPS v2.3 Table 8.76
    0x0005: "PID_GROUP_DATA",
    0x0006: "PID_TOPIC_DATA",
    0x0007: "PID_DURABILITY",
    0x000B: "PID_DEADLINE",
    0x000D: "PID_LATENCY_BUDGET",
    0x000F: "PID_LIVELINESS",
    0x0011: "PID_RELIABILITY",
    0x0016: "PID_LIFESPAN",
    0x001A: "PID_DESTINATION_ORDER",
    0x001D: "PID_PRESENTATION",
    0x001F: "PID_PARTITION",
    0x0023: "PID_TIME_BASED_FILTER",
    0x0025: "PID_OWNERSHIP",
    0x0029: "PID_OWNERSHIP_STRENGTH",
    0x002B: "PID_DESTINATION_ORDER",
    0x002F: "PID_METATRAFFIC_UNICAST_LOCATOR",
    0x0030: "PID_METATRAFFIC_MULTICAST_LOCATOR",
    0x0031: "PID_DEFAULT_UNICAST_LOCATOR",
    0x0032: "PID_DEFAULT_MULTICAST_LOCATOR",
    0x0033: "PID_METATRAFFIC_UNICAST_IPADDRESS",
    0x0034: "PID_METATRAFFIC_MULTICAST_IPADDRESS",
    0x0035: "PID_DEFAULT_UNICAST_IPADDRESS",
    0x0040: "PID_PROTOCOL_VERSION",
    0x0041: "PID_VENDOR_ID",
    0x0043: "PID_MULTICAST_IPADDRESS",
    0x0044: "PID_DEFAULT_UNICAST_PORT",
    0x0045: "PID_METATRAFFIC_UNICAST_PORT",
    0x0046: "PID_METATRAFFIC_MULTICAST_PORT",
    0x0048: "PID_UNICAST_LOCATOR",
    0x0050: "PID_EXPECTS_INLINE_QOS",
    0x0058: "PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT",
    0x0059: "PID_PARTICIPANT_BUILTIN_ENDPOINTS",
    0x005A: "PID_ENDPOINT_GUID",
    0x005B: "PID_PARTICIPANT_GUID",
    0x005C: "PID_PARTICIPANT_LEASE_DURATION",
    0x005D: "PID_CONTENT_FILTER_PROPERTY",
    0x005E: "PID_PARTICIPANT_ENTITY_ID",
    0x0060: "PID_GROUP_GUID",
    0x0061: "PID_GROUP_ENTITYID",
    0x0062: "PID_BUILTIN_ENDPOINT_SET",
    0x0063: "PID_PROPERTY_LIST",
    0x0071: "PID_TYPE_MAX_SIZE_SERIALIZED",
    0x0072: "PID_ENTITY_NAME",
    0x0073: "PID_KEY_HASH",
    0x0074: "PID_STATUS_INFO",
    0x0075: "PID_CONTENT_FILTER_INFO",
    0x8000: "PID_RELATED_SAMPLE_IDENTITY",
    0x8001: "PID_TOPIC_QUERY_GUID",
    0x8002: "PID_DATA_REPRESENTATION",
    0x8003: "PID_TYPE_CONSISTENCY_ENFORCEMENT",
    0x8004: "PID_TYPE_INFORMATION",
    0x8005: "PID_TYPE_OBJECT",
    0x8007: "PID_DATA_TAGS",
    0x8014: "PID_EXTENDED_BUILTIN_ENDPOINTS",
    0x8016: "PID_PRODUCT_VERSION",
    0x8017: "PID_PLUGIN_PROMISCUITY_KIND",
    0x8018: "PID_ENTITY_VIRTUAL_GUID",
    0x8019: "PID_SERVICE_INSTANCE_NAME",
}

# Required PIDs for SEDP Publications Writer announcement
REQUIRED_SEDP_WRITER_PIDS = {
    0x005A: "PID_ENDPOINT_GUID",
    0x0003: "PID_TOPIC_NAME",  # Fixed: was 0x0005 (wrong!)
    0x0004: "PID_TYPE_NAME",   # Fixed: was 0x0007 (wrong!)
    0x001A: "PID_RELIABILITY",
    0x001D: "PID_DURABILITY",
}

# Required PIDs for SEDP Subscriptions Reader announcement
REQUIRED_SEDP_READER_PIDS = {
    0x005A: "PID_ENDPOINT_GUID",
    0x0003: "PID_TOPIC_NAME",  # Fixed: was 0x0005 (wrong!)
    0x0004: "PID_TYPE_NAME",   # Fixed: was 0x0007 (wrong!)
    0x001A: "PID_RELIABILITY",
    0x001D: "PID_DURABILITY",
}

# ================================
# PCAP Parsing
# ================================

def read_pcap(filepath):
    """Read pcap file and extract UDP packets"""
    with open(filepath, 'rb') as f:
        # Read global header (24 bytes)
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("Invalid pcap file: header too short")

        magic = struct.unpack('<I', header[:4])[0]
        if magic == 0xa1b2c3d4:
            endian = '<'  # Little-endian
        elif magic == 0xd4c3b2a1:
            endian = '>'  # Big-endian
        else:
            raise ValueError(f"Invalid pcap magic: {magic:08x}")

        packets = []
        packet_num = 0

        while True:
            # Read packet header (16 bytes)
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break

            packet_num += 1

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_header)

            # Read packet data
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                print(f"Warning: Packet {packet_num} truncated")
                break

            packets.append({
                'num': packet_num,
                'timestamp': ts_sec + ts_usec / 1_000_000.0,
                'data': pkt_data,
                'size': incl_len
            })

        return packets

def parse_ethernet(data):
    """Parse Ethernet frame and extract IP packet"""
    if len(data) < 14:
        return None

    # Ethernet header: 6 bytes dst MAC + 6 bytes src MAC + 2 bytes EtherType
    ethertype = struct.unpack('>H', data[12:14])[0]

    if ethertype != 0x0800:  # Not IPv4
        return None

    return data[14:]  # Return IP packet

def parse_ip(data):
    """Parse IPv4 packet and extract UDP datagram"""
    if len(data) < 20:
        return None

    # IP header
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4  # Header length in bytes

    if version != 4:
        return None

    protocol = data[9]
    if protocol != 17:  # Not UDP
        return None

    src_ip = '.'.join(str(b) for b in data[12:16])
    dst_ip = '.'.join(str(b) for b in data[16:20])

    # Extract UDP datagram
    udp_data = data[ihl:]
    if len(udp_data) < 8:
        return None

    src_port = struct.unpack('>H', udp_data[0:2])[0]
    dst_port = struct.unpack('>H', udp_data[2:4])[0]
    udp_length = struct.unpack('>H', udp_data[4:6])[0]

    payload = udp_data[8:]

    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'payload': payload
    }

# ================================
# RTPS Parsing
# ================================

def parse_rtps_header(data):
    """Parse RTPS header (20 bytes)"""
    if len(data) < 20:
        return None

    magic = data[0:4]
    if magic != b'RTPS':
        return None

    protocol_version = f"{data[4]}.{data[5]}"
    vendor_id = struct.unpack('>H', data[6:8])[0]
    guid_prefix = data[8:20].hex()

    return {
        'protocol_version': protocol_version,
        'vendor_id': vendor_id,
        'guid_prefix': guid_prefix,
        'submessages_offset': 20
    }

def parse_submessages(data, offset):
    """Parse all submessages in RTPS packet"""
    submessages = []

    while offset < len(data):
        if offset + 4 > len(data):
            break

        submsg_id = data[offset]
        flags = data[offset + 1]
        octets_to_next = struct.unpack('<H', data[offset + 2:offset + 4])[0]

        submsg_data = data[offset + 4:offset + 4 + octets_to_next] if octets_to_next > 0 else b''

        submsg = {
            'id': submsg_id,
            'flags': flags,
            'length': octets_to_next,
            'data': submsg_data,
            'offset': offset
        }

        # Parse DATA submessage further
        if submsg_id == RTPS_SUBMSG_DATA and len(submsg_data) >= 20:
            submsg['extra_flags'] = struct.unpack('<H', submsg_data[0:2])[0]
            submsg['octets_to_inline_qos'] = struct.unpack('<H', submsg_data[2:4])[0]
            submsg['reader_id'] = struct.unpack('>I', submsg_data[4:8])[0]
            submsg['writer_id'] = struct.unpack('>I', submsg_data[8:12])[0]
            submsg['sequence_number'] = struct.unpack('<Q', submsg_data[12:20])[0]

            # Classify based on writer entity ID
            submsg['entity_type'] = classify_entity_id(submsg['writer_id'])

            # Extract serialized payload (after inline QoS if present)
            qos_offset = submsg['octets_to_inline_qos']
            if qos_offset >= 20:
                payload_start = qos_offset
                submsg['payload'] = submsg_data[payload_start:]
            else:
                submsg['payload'] = submsg_data[20:]

        submessages.append(submsg)

        if octets_to_next == 0:
            break

        offset += 4 + octets_to_next

    return submessages

def classify_entity_id(entity_id):
    """Classify entity ID into SPDP/SEDP/USER"""
    if entity_id in ENTITY_IDS:
        name = ENTITY_IDS[entity_id]
        if 'SPDP' in name:
            return 'SPDP'
        elif 'PUBLICATIONS' in name:
            return 'SEDP_PUB'
        elif 'SUBSCRIPTIONS' in name:
            return 'SEDP_SUB'
        return 'BUILTIN'
    return 'USER'

# ================================
# CDR Parameter List Parsing
# ================================

def parse_cdr_parameter_list(data):
    """Parse CDR-encoded parameter list (PID format)"""
    if len(data) < 4:
        return []

    # Check CDR encapsulation header (first 4 bytes)
    encapsulation = struct.unpack('<H', data[0:2])[0]

    params = []
    offset = 4  # Skip encapsulation header

    while offset + 4 <= len(data):
        pid = struct.unpack('<H', data[offset:offset + 2])[0]
        length = struct.unpack('<H', data[offset + 2:offset + 4])[0]

        if pid == 0x0001:  # PID_SENTINEL
            break

        # Extract parameter value
        param_value = data[offset + 4:offset + 4 + length] if offset + 4 + length <= len(data) else b''

        param = {
            'pid': pid,
            'name': PID_MAP.get(pid, f"UNKNOWN_0x{pid:04X}"),
            'length': length,
            'value': param_value,
            'offset': offset
        }

        # Try to decode common parameter types
        if pid == 0x0003:  # PID_TOPIC_NAME (correct per RTPS v2.3 Table 8.76)
            try:
                # String: 4-byte length + null-terminated string
                str_len = struct.unpack('<I', param_value[:4])[0]
                param['decoded'] = param_value[4:4 + str_len - 1].decode('utf-8', errors='ignore')
            except:
                param['decoded'] = '<decode error>'

        elif pid == 0x0004:  # PID_TYPE_NAME (correct per RTPS v2.3 Table 8.76)
            try:
                str_len = struct.unpack('<I', param_value[:4])[0]
                param['decoded'] = param_value[4:4 + str_len - 1].decode('utf-8', errors='ignore')
            except:
                param['decoded'] = '<decode error>'

        elif pid == 0x005A:  # PID_ENDPOINT_GUID
            if len(param_value) >= 16:
                param['decoded'] = param_value[:16].hex()

        elif pid == 0x001A:  # PID_RELIABILITY (ReliabilityQosPolicy)
            if len(param_value) >= 12:
                kind = struct.unpack('<I', param_value[0:4])[0]
                param['decoded'] = 'RELIABLE' if kind == 1 else 'BEST_EFFORT'

        elif pid == 0x001D:  # PID_DURABILITY (DurabilityQosPolicy)
            if len(param_value) >= 4:
                kind = struct.unpack('<I', param_value[0:4])[0]
                durability_map = {0: 'VOLATILE', 1: 'TRANSIENT_LOCAL', 2: 'TRANSIENT', 3: 'PERSISTENT'}
                param['decoded'] = durability_map.get(kind, f'UNKNOWN({kind})')

        params.append(param)

        # Move to next parameter (align to 4-byte boundary)
        padded_length = (length + 3) & ~3
        offset += 4 + padded_length

    return params

# ================================
# Validation
# ================================

def validate_sedp_packet(submsg, params):
    """Validate SEDP packet against spec requirements"""
    issues = []
    warnings = []

    entity_type = submsg.get('entity_type')

    if entity_type == 'SEDP_PUB':
        required = REQUIRED_SEDP_WRITER_PIDS
    elif entity_type == 'SEDP_SUB':
        required = REQUIRED_SEDP_READER_PIDS
    else:
        return issues, warnings  # Not a SEDP packet

    # Check required PIDs
    found_pids = {p['pid'] for p in params}

    for req_pid, req_name in required.items():
        if req_pid not in found_pids:
            issues.append(f"Missing required PID: {req_name} (0x{req_pid:04X})")

    # Check for empty topic/type names
    for param in params:
        if param['pid'] == 0x0003:  # PID_TOPIC_NAME (correct per RTPS v2.3)
            decoded = param.get('decoded', '')
            if not decoded or decoded == '<decode error>':
                issues.append("Empty or invalid TOPIC_NAME")

        if param['pid'] == 0x0004:  # PID_TYPE_NAME (correct per RTPS v2.3)
            decoded = param.get('decoded', '')
            if not decoded or decoded == '<decode error>':
                issues.append("Empty or invalid TYPE_NAME")

    # Check sequence number
    seq_num = submsg.get('sequence_number', 0)
    if seq_num == 0:
        warnings.append("Sequence number is 0 (should start from 1 for Reliable QoS)")

    return issues, warnings

# ================================
# Main Analysis
# ================================

def analyze_pcap(filepath, verbose=False, dump_pids=False):
    """Analyze RTPS packets in pcap file"""
    print(f"Reading: {filepath}")

    packets = read_pcap(filepath)
    print(f"Total packets: {len(packets)}\n")

    rtps_count = 0
    sedp_count = 0
    spdp_count = 0

    for pkt in packets:
        # Extract IP/UDP
        ip_pkt = parse_ethernet(pkt['data'])
        if not ip_pkt:
            continue

        udp = parse_ip(ip_pkt)
        if not udp:
            continue

        # Parse RTPS
        rtps = parse_rtps_header(udp['payload'])
        if not rtps:
            continue

        rtps_count += 1

        # Parse submessages
        submessages = parse_submessages(udp['payload'], rtps['submessages_offset'])

        # Find DATA submessages
        for submsg in submessages:
            if submsg['id'] != RTPS_SUBMSG_DATA:
                continue

            entity_type = submsg.get('entity_type', 'UNKNOWN')

            if entity_type == 'SPDP':
                spdp_count += 1
            elif entity_type in ('SEDP_PUB', 'SEDP_SUB'):
                sedp_count += 1

                print(f"{'='*70}")
                print(f"Packet #{pkt['num']} - {entity_type} Announcement")
                print(f"{'='*70}")
                print(f"Source: {udp['src_ip']}:{udp['src_port']} -> {udp['dst_ip']}:{udp['dst_port']}")
                print(f"Size: {pkt['size']} bytes")
                print(f"RTPS GUID Prefix: {rtps['guid_prefix']}")
                print(f"Writer EntityID: 0x{submsg['writer_id']:08X} ({ENTITY_IDS.get(submsg['writer_id'], 'UNKNOWN')})")
                print(f"Reader EntityID: 0x{submsg['reader_id']:08X} ({ENTITY_IDS.get(submsg['reader_id'], 'UNKNOWN')})")
                print(f"Sequence Number: {submsg['sequence_number']}")
                print()

                # Parse CDR parameters
                params = parse_cdr_parameter_list(submsg.get('payload', b''))

                print(f"Parameters: {len(params)} PIDs found")

                if dump_pids or verbose:
                    for param in params:
                        decoded_str = f" = {param['decoded']}" if 'decoded' in param else ""
                        print(f"  [0x{param['pid']:04X}] {param['name']} (len={param['length']}){decoded_str}")

                print()

                # Validate
                issues, warnings = validate_sedp_packet(submsg, params)

                if issues:
                    print("[X] VALIDATION ISSUES:")
                    for issue in issues:
                        print(f"  - {issue}")
                    print()

                if warnings:
                    print("[!]  WARNINGS:")
                    for warning in warnings:
                        print(f"  - {warning}")
                    print()

                if not issues and not warnings:
                    print("[OK] Packet validation PASSED")
                    print()

    print(f"{'='*70}")
    print(f"Summary:")
    print(f"  RTPS packets: {rtps_count}")
    print(f"  SPDP packets: {spdp_count}")
    print(f"  SEDP packets: {sedp_count}")
    print(f"{'='*70}")

# ================================
# Entry Point
# ================================

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: validate_sedp.py <pcap_file> [--verbose] [--dump-pids]")
        sys.exit(1)

    filepath = sys.argv[1]
    verbose = '--verbose' in sys.argv
    dump_pids = '--dump-pids' in sys.argv

    if not Path(filepath).exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    analyze_pcap(filepath, verbose=verbose, dump_pids=dump_pids)
