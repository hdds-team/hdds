#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Dynamic Data Sample - Demonstrates runtime type manipulation

Dynamic Data allows working with types at runtime without
compile-time type definitions. Useful for:
- Generic tools and data bridges
- Type discovery and introspection
- Protocol adapters and gateways

Key concepts:
- DynamicType: runtime type definition
- DynamicData: runtime data manipulation
- Type introspection
- Publishing and receiving dynamic data via HDDS

NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for DynamicData/DynamicType.
The native DynamicData/DynamicType API is not yet exported to the C/C++/Python SDK.
This sample uses standard participant/writer/reader API to show the concept.
"""

import os
import sys
import struct
import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional
from copy import deepcopy

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


class TypeKind(Enum):
    """Type kinds"""
    INT32 = auto()
    UINT32 = auto()
    INT64 = auto()
    FLOAT32 = auto()
    FLOAT64 = auto()
    BOOL = auto()
    STRING = auto()
    SEQUENCE = auto()
    ARRAY = auto()
    STRUCT = auto()
    UNION = auto()
    ENUM = auto()


def type_kind_str(kind: TypeKind) -> str:
    """Convert type kind to string"""
    return {
        TypeKind.INT32: "int32",
        TypeKind.UINT32: "uint32",
        TypeKind.INT64: "int64",
        TypeKind.FLOAT32: "float32",
        TypeKind.FLOAT64: "float64",
        TypeKind.BOOL: "bool",
        TypeKind.STRING: "string",
        TypeKind.SEQUENCE: "sequence",
        TypeKind.ARRAY: "array",
        TypeKind.STRUCT: "struct",
        TypeKind.UNION: "union",
        TypeKind.ENUM: "enum",
    }.get(kind, "unknown")


@dataclass
class MemberDescriptor:
    """Member descriptor"""
    name: str
    type: TypeKind
    id: int = 0
    is_key: bool = False
    is_optional: bool = False


class DynamicType:
    """Dynamic type definition"""

    def __init__(self, name: str, kind: TypeKind):
        self._name = name
        self._kind = kind
        self._members: List[MemberDescriptor] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def kind(self) -> TypeKind:
        return self._kind

    @property
    def members(self) -> List[MemberDescriptor]:
        return self._members

    def add_member(self, name: str, member_type: TypeKind,
                   is_key: bool = False, is_optional: bool = False):
        """Add a member to the type"""
        member = MemberDescriptor(
            name=name,
            type=member_type,
            id=len(self._members),
            is_key=is_key,
            is_optional=is_optional
        )
        self._members.append(member)

    def get_member(self, name: str) -> Optional[MemberDescriptor]:
        """Get member by name"""
        for m in self._members:
            if m.name == name:
                return m
        return None


@dataclass
class DataMember:
    """Dynamic data member"""
    name: str
    type: TypeKind
    value: Any = None
    is_set: bool = False


class DynamicData:
    """Dynamic data instance"""

    def __init__(self, dtype: DynamicType):
        self._type = dtype
        self._members: Dict[str, DataMember] = {}
        for m in dtype.members:
            self._members[m.name] = DataMember(
                name=m.name,
                type=m.type,
                value=None,
                is_set=False
            )

    @property
    def type(self) -> DynamicType:
        return self._type

    @property
    def members(self) -> Dict[str, DataMember]:
        return self._members

    # Setters
    def set_int32(self, name: str, value: int):
        if name in self._members:
            self._members[name].value = value
            self._members[name].is_set = True

    def set_float64(self, name: str, value: float):
        if name in self._members:
            self._members[name].value = value
            self._members[name].is_set = True

    def set_string(self, name: str, value: str):
        if name in self._members:
            self._members[name].value = value
            self._members[name].is_set = True

    def set_bool(self, name: str, value: bool):
        if name in self._members:
            self._members[name].value = value
            self._members[name].is_set = True

    # Getters
    def get_int32(self, name: str) -> int:
        if name in self._members and self._members[name].is_set:
            return self._members[name].value
        return 0

    def get_float64(self, name: str) -> float:
        if name in self._members and self._members[name].is_set:
            return self._members[name].value
        return 0.0

    def get_string(self, name: str) -> str:
        if name in self._members and self._members[name].is_set:
            return self._members[name].value
        return ""

    def get_bool(self, name: str) -> bool:
        if name in self._members and self._members[name].is_set:
            return self._members[name].value
        return False

    def clone(self) -> 'DynamicData':
        """Clone this dynamic data"""
        copy = DynamicData(self._type)
        copy._members = deepcopy(self._members)
        return copy

    def serialize(self) -> bytes:
        """Serialize to bytes using JSON encoding."""
        data = {
            "type": self._type.name,
            "members": {}
        }
        for name, member in self._members.items():
            if member.is_set:
                data["members"][name] = {
                    "type": type_kind_str(member.type),
                    "value": member.value
                }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def deserialize(cls, data: bytes, dtype: DynamicType) -> 'DynamicData':
        """Deserialize from bytes."""
        parsed = json.loads(data.decode('utf-8'))
        result = cls(dtype)
        for name, member_data in parsed.get("members", {}).items():
            if name in result._members:
                result._members[name].value = member_data["value"]
                result._members[name].is_set = True
        return result


class TypeFactory:
    """Factory for creating dynamic types"""

    def __init__(self):
        self._types: Dict[str, DynamicType] = {}

    def create_struct(self, name: str) -> DynamicType:
        """Create a struct type"""
        dtype = DynamicType(name, TypeKind.STRUCT)
        self._types[name] = dtype
        return dtype

    def get_type(self, name: str) -> Optional[DynamicType]:
        """Get a type by name"""
        return self._types.get(name)


def print_type(dtype: DynamicType):
    """Print type information"""
    print(f"  Type: {dtype.name} ({type_kind_str(dtype.kind)})")
    print(f"  Members ({len(dtype.members)}):")
    for m in dtype.members:
        flags = ""
        if m.is_key:
            flags += " @key"
        if m.is_optional:
            flags += " @optional"
        print(f"    [{m.id}] {m.name}: {type_kind_str(m.type)}{flags}")


def print_data(data: DynamicData):
    """Print dynamic data"""
    print(f"  Data of type '{data.type.name}':")
    for name, member in data.members.items():
        if not member.is_set:
            print(f"    {name} = <unset>")
        elif member.type == TypeKind.STRING:
            print(f"    {name} = \"{member.value}\"")
        elif member.type == TypeKind.BOOL:
            print(f"    {name} = {'true' if member.value else 'false'}")
        else:
            print(f"    {name} = {member.value}")


def print_dynamic_data_overview():
    print("--- Dynamic Data Overview ---\n")
    print("Dynamic Data Architecture:\n")
    print("  +-----------------+      +-----------------+")
    print("  |  TypeFactory    |----->|  DynamicType    |")
    print("  |                 |      |  - name         |")
    print("  | create_struct() |      |  - kind         |")
    print("  | create_enum()   |      |  - members[]    |")
    print("  +-----------------+      +--------+--------+")
    print("                                    |")
    print("                                    v")
    print("                           +-----------------+")
    print("                           |  DynamicData    |")
    print("                           |  - type         |")
    print("                           |  - values[]     |")
    print("                           |  - get/set()    |")
    print("                           +-----------------+")
    print()
    print("Use Cases:")
    print("  - Generic data recording/replay tools")
    print("  - Protocol bridges (DDS <-> REST/MQTT)")
    print("  - Data visualization without type knowledge")
    print("  - Testing and debugging utilities")
    print()


def main():
    print("=== HDDS Dynamic Data Sample ===\n")
    print("NOTE: CONCEPT DEMO - Native DynamicData/DynamicType API not yet in SDK.")
    print("      Using standard pub/sub API to demonstrate the pattern.\n")

    print_dynamic_data_overview()

    # Initialize HDDS logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create type factory
    factory = TypeFactory()
    print("[OK] TypeFactory created\n")

    # Define a SensorReading type at runtime
    print("--- Creating Dynamic Type ---\n")

    sensor_type = factory.create_struct("SensorReading")
    sensor_type.add_member("sensor_id", TypeKind.INT32, is_key=True)
    sensor_type.add_member("location", TypeKind.STRING)
    sensor_type.add_member("temperature", TypeKind.FLOAT64)
    sensor_type.add_member("humidity", TypeKind.FLOAT64)
    sensor_type.add_member("is_valid", TypeKind.BOOL)

    print("[OK] Type 'SensorReading' created dynamically\n")
    print_type(sensor_type)
    print()

    # Create and populate dynamic data
    print("--- Creating Dynamic Data ---\n")

    reading1 = DynamicData(sensor_type)
    reading1.set_int32("sensor_id", 101)
    reading1.set_string("location", "Building-A/Room-1")
    reading1.set_float64("temperature", 23.5)
    reading1.set_float64("humidity", 45.2)
    reading1.set_bool("is_valid", True)

    print("[OK] DynamicData instance created\n")
    print_data(reading1)
    print()

    # Read values back
    print("--- Reading Dynamic Data ---\n")

    id_val = reading1.get_int32("sensor_id")
    loc = reading1.get_string("location")
    temp = reading1.get_float64("temperature")
    hum = reading1.get_float64("humidity")
    valid = reading1.get_bool("is_valid")

    print("Read values:")
    print(f"  sensor_id: {id_val}")
    print(f"  location: {loc}")
    print(f"  temperature: {temp}")
    print(f"  humidity: {hum}")
    print(f"  is_valid: {'true' if valid else 'false'}\n")

    # Publish dynamic data via HDDS
    print("--- Publishing Dynamic Data via HDDS ---\n")

    participant = hdds.Participant("DynamicDataDemo")
    writer = participant.create_writer("DynamicSensorTopic", qos=hdds.QoS.reliable())
    reader = participant.create_reader("DynamicSensorTopic", qos=hdds.QoS.reliable())

    print("[OK] Created participant, writer, and reader")

    # Serialize and publish
    serialized = reading1.serialize()
    writer.write(serialized)
    print(f"[OK] Published dynamic data ({len(serialized)} bytes)")

    # Wait briefly for data to arrive
    import time
    time.sleep(0.1)

    # Read and deserialize
    received_data = reader.take()
    if received_data:
        received = DynamicData.deserialize(received_data, sensor_type)
        print("[OK] Received and deserialized dynamic data\n")
        print_data(received)
    else:
        print("[INFO] No data received (this is normal in single-process demo)")
    print()

    # Clone data
    print("--- Cloning Dynamic Data ---\n")

    reading2 = reading1.clone()
    reading2.set_int32("sensor_id", 102)
    reading2.set_string("location", "Building-B/Room-3")
    reading2.set_float64("temperature", 25.0)

    print("[OK] Cloned and modified:\n")
    print_data(reading2)
    print()

    # Type introspection
    print("--- Type Introspection ---\n")

    print("Iterating over type members:")
    for m in sensor_type.members:
        print(f"  Member '{m.name}':")
        print(f"    - Type: {type_kind_str(m.type)}")
        print(f"    - ID: {m.id}")
        print(f"    - Is key: {'yes' if m.is_key else 'no'}")
        print(f"    - Optional: {'yes' if m.is_optional else 'no'}")
    print()

    # Create another type
    print("--- Creating Additional Type ---\n")

    alarm_type = factory.create_struct("AlarmEvent")
    alarm_type.add_member("alarm_id", TypeKind.INT32, is_key=True)
    alarm_type.add_member("severity", TypeKind.INT32)
    alarm_type.add_member("message", TypeKind.STRING)
    alarm_type.add_member("acknowledged", TypeKind.BOOL)

    print_type(alarm_type)
    print()

    alarm = DynamicData(alarm_type)
    alarm.set_int32("alarm_id", 5001)
    alarm.set_int32("severity", 3)
    alarm.set_string("message", "High temperature warning")
    alarm.set_bool("acknowledged", False)

    print_data(alarm)
    print()

    # Publish alarm via HDDS
    alarm_writer = participant.create_writer("AlarmTopic", qos=hdds.QoS.reliable())
    alarm_writer.write(alarm.serialize())
    print("[OK] Published alarm event via HDDS\n")

    # Best practices
    print("--- Dynamic Data Best Practices ---\n")
    print("1. Cache type lookups for performance-critical paths")
    print("2. Use member IDs instead of names for faster access")
    print("3. Validate type compatibility before operations")
    print("4. Consider memory management for string members")
    print("5. Use typed APIs when types are known at compile time")
    print("6. Leverage type introspection for generic tooling")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
