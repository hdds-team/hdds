# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Configuration errors must be observable before samples are evaluated."""

import ctypes as ct

import pytest


@pytest.mark.native
def test_filter_configuration_rejects_errors_transactionally(native_lib):
    lib = native_lib
    functions = [
        ("hdds_filter_create_with_params", ct.c_void_p, [ct.c_char_p, ct.POINTER(ct.c_char_p), ct.c_size_t]),
        ("hdds_filter_set_parameters", ct.c_int, [ct.c_void_p, ct.POINTER(ct.c_char_p), ct.c_size_t]),
        ("hdds_filter_destroy", None, [ct.c_void_p]),
        ("hdds_field_map_create", ct.c_void_p, []),
        ("hdds_field_map_destroy", None, [ct.c_void_p]),
        ("hdds_field_map_set_i64", ct.c_int, [ct.c_void_p, ct.c_char_p, ct.c_int64]),
        ("hdds_filter_evaluate", ct.c_int, [ct.c_void_p, ct.c_void_p]),
    ]
    for name, result, arguments in functions:
        function = getattr(lib, name)
        function.restype, function.argtypes = result, arguments
    params = (ct.c_char_p * 2)(b"40", b"60")
    handle = lib.hdds_filter_create_with_params(b"value > %0 AND value < %1", params, 2)
    fields = lib.hdds_field_map_create()
    assert handle and fields
    try:
        assert lib.hdds_field_map_set_i64(fields, b"value", 50) == 0
        for values in [[], [b"40"], [b"1e400", b"60"], [b"18446744073709551616", b"60"]]:
            candidate = (ct.c_char_p * len(values))(*values)
            assert lib.hdds_filter_set_parameters(handle, candidate, len(values)) == 1
            assert lib.hdds_filter_evaluate(handle, fields) == 1
        # Validate every branch, including a parameter hidden by short-circuiting.
        candidate = lib.hdds_filter_create_with_params(b"value > %0 OR value > %1", params, 1)
        if candidate:
            lib.hdds_filter_destroy(candidate)
        assert not candidate
        candidate = lib.hdds_filter_create_with_params(b"value > %0", (ct.c_char_p * 1)(b"1e400"), 1)
        if candidate:
            lib.hdds_filter_destroy(candidate)
        assert not candidate
    finally:
        lib.hdds_filter_destroy(handle)
        lib.hdds_field_map_destroy(fields)
