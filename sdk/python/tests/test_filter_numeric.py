# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Check numeric C filter results against Python's independent comparisons.

Python compares an integer with a float without first rounding the integer to
binary64. This makes its operators a useful independent oracle at 2**53 and the
64-bit limits; implementing the Rust comparison algorithm again here would not.
"""

import ctypes as ct
import operator
import random
import struct

import pytest


OPERATORS = [
    ("=", operator.eq), ("<>", operator.ne),
    ("<", operator.lt), ("<=", operator.le),
    (">", operator.gt), (">=", operator.ge),
]


@pytest.fixture
def numeric_filter(native_lib):
    lib = native_lib
    for name, result, args in [
        ("hdds_filter_create", ct.c_void_p, [ct.c_char_p]),
        ("hdds_filter_destroy", None, [ct.c_void_p]),
        ("hdds_field_map_create", ct.c_void_p, []),
        ("hdds_field_map_destroy", None, [ct.c_void_p]),
        ("hdds_filter_evaluate", ct.c_int, [ct.c_void_p, ct.c_void_p]),
        ("hdds_field_map_set_i64", ct.c_int, [ct.c_void_p, ct.c_char_p, ct.c_int64]),
        ("hdds_field_map_set_u64", ct.c_int, [ct.c_void_p, ct.c_char_p, ct.c_uint64]),
        ("hdds_field_map_set_f64", ct.c_int, [ct.c_void_p, ct.c_char_p, ct.c_double]),
    ]:
        function = getattr(lib, name)
        function.restype, function.argtypes = result, args
    filters = []
    fields = lib.hdds_field_map_create()
    assert fields
    try:
        for symbol, expected in OPERATORS:
            handle = lib.hdds_filter_create(("lhs " + symbol + " rhs").encode())
            assert handle
            filters.append((symbol, expected, handle))

        def check(lhs, rhs):
            for name, (kind, value) in [(b"lhs", lhs), (b"rhs", rhs)]:
                assert getattr(lib, "hdds_field_map_set_" + kind)(fields, name, value) == 0
            for symbol, expected, handle in filters:
                actual = lib.hdds_filter_evaluate(handle, fields)
                assert actual == int(expected(lhs[1], rhs[1])), (lhs, symbol, rhs, actual)

        yield check
    finally:
        for _, _, handle in filters:
            lib.hdds_filter_destroy(handle)
        lib.hdds_field_map_destroy(fields)


@pytest.mark.native
def test_numeric_boundaries_and_nonfinite(numeric_filter):
    values = [
        ("i64", -(2**63)), ("i64", -(2**63) + 1),
        ("i64", -(2**53) - 1), ("i64", -1), ("i64", 0),
        ("i64", 2**53 + 1), ("i64", 2**63 - 1),
        ("u64", 0), ("u64", 1), ("u64", 2**53 + 1),
        ("u64", 2**63), ("u64", 2**64 - 1),
        ("f64", float("-inf")), ("f64", float("inf")), ("f64", float("nan")),
        ("f64", -(2.0**64)), ("f64", -(2.0**63)), ("f64", -(2.0**53)),
        ("f64", -1.5), ("f64", -5e-10), ("f64", -0.0), ("f64", 0.0),
        ("f64", 5e-324), ("f64", -5e-324), ("f64", 5e-10),
        ("f64", 1.5), ("f64", 2.0**53), ("f64", 2.0**63), ("f64", 2.0**64),
    ]
    for lhs in values:
        for rhs in values:
            numeric_filter(lhs, rhs)


@pytest.mark.native
def test_seeded_numeric_bit_patterns(numeric_filter):
    rng = random.Random(0x48444453)

    def value():
        kind = rng.randrange(3)
        bits = rng.getrandbits(64)
        if kind == 0:
            return "i64", bits - 2**63
        if kind == 1:
            return "u64", bits
        return "f64", struct.unpack("<d", bits.to_bytes(8, "little"))[0]

    for _ in range(2000):
        numeric_filter(value(), value())
