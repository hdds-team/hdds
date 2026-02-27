# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Generated types for HDDS type samples

This module contains all the generated types from IDL files:
- Primitives: Basic DDS primitive types
- Strings: Bounded and unbounded strings
- Sequences: Bounded and unbounded sequences
- Arrays: Fixed-size arrays and matrices
- Maps: Key-value map types
- Enums: Enumeration types with explicit values
- Unions: Discriminated union types
- Nested: Nested struct types
- Bits: Bitmask and bitset types
- Optional: Optional field types
"""

from .Primitives import Primitives
from .Strings import Strings
from .Sequences import LongSeq, StringSeq, BoundedLongSeq
from .Arrays import LongArray, StringArray, Matrix
from .Maps import StringLongMap, LongStringMap
from .Enums import Color, Status, EnumDemo
from .Unions import DataKind, DataValue
from .Nested import Point, Pose, Robot
from .Bits import Permissions, StatusFlags, BitsDemo
from .Optional import OptionalFields

__all__ = [
    'Primitives',
    'Strings',
    'LongSeq', 'StringSeq', 'BoundedLongSeq',
    'LongArray', 'StringArray', 'Matrix',
    'StringLongMap', 'LongStringMap',
    'Color', 'Status', 'EnumDemo',
    'DataKind', 'DataValue',
    'Point', 'Pose', 'Robot',
    'Permissions', 'StatusFlags', 'BitsDemo',
    'OptionalFields',
]
