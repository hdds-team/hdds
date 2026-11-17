# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Use the dynamic-data and field-map C API via ctypes (HDDS 1.5.0).

Run with PYTHONPATH=sdk/python and HDDS_LIB_PATH pointing to libhdds_c.
These are local serialization and evaluation APIs, not filtered DDS readers.
"""

import ctypes as ct

from hdds import library_path


def main():
    # A separate CDLL keeps these example signatures local to this consumer.
    lib = ct.CDLL(library_path())
    signatures = {
        "hdds_type_builder_new": (ct.c_void_p, [ct.c_char_p]),
        "hdds_type_builder_add_field": (ct.c_int, [ct.c_void_p, ct.c_char_p, ct.c_uint32]),
        "hdds_type_builder_build": (ct.c_void_p, [ct.c_void_p]),
        "hdds_type_builder_destroy": (None, [ct.c_void_p]),
        "hdds_type_descriptor_destroy": (None, [ct.c_void_p]),
        "hdds_dynamic_data_new": (ct.c_void_p, [ct.c_void_p]),
        "hdds_dynamic_data_destroy": (None, [ct.c_void_p]),
        "hdds_dynamic_data_set_u32": (ct.c_int, [ct.c_void_p, ct.c_char_p, ct.c_uint32]),
        "hdds_dynamic_data_get_u32": (
            ct.c_int, [ct.c_void_p, ct.c_char_p, ct.POINTER(ct.c_uint32)]),
        "hdds_dynamic_data_encode": (
            ct.c_int, [ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_size_t)]),
        "hdds_dynamic_data_decode": (ct.c_void_p, [ct.c_void_p, ct.c_void_p, ct.c_size_t]),
        "hdds_filter_create": (ct.c_void_p, [ct.c_char_p]),
        "hdds_filter_destroy": (None, [ct.c_void_p]),
        "hdds_field_map_create": (ct.c_void_p, []),
        "hdds_field_map_destroy": (None, [ct.c_void_p]),
        "hdds_field_map_set_u64": (ct.c_int, [ct.c_void_p, ct.c_char_p, ct.c_uint64]),
        "hdds_filter_evaluate": (ct.c_int, [ct.c_void_p, ct.c_void_p]),
    }
    for name, (result, args) in signatures.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, args

    def check(ok):
        if not ok:
            raise RuntimeError("HDDS dynamic/filter example failed")

    builder = desc = data = decoded = filter_handle = fields = None
    try:
        builder = lib.hdds_type_builder_new(b"Sensor")
        check(builder)
        check(lib.hdds_type_builder_add_field(builder, b"id", 3) == 0)  # HDDS_PRIM_U32
        desc = lib.hdds_type_builder_build(builder)
        builder = None  # build consumes the builder
        check(desc)
        data = lib.hdds_dynamic_data_new(desc)
        check(data)
        check(lib.hdds_dynamic_data_set_u32(data, b"id", 42) == 0)
        buffer = (ct.c_uint8 * 128)()
        length = ct.c_size_t()
        check(lib.hdds_dynamic_data_encode(data, buffer, len(buffer), ct.byref(length)) == 0)
        decoded = lib.hdds_dynamic_data_decode(desc, buffer, length.value)
        check(decoded)
        value = ct.c_uint32()
        check(lib.hdds_dynamic_data_get_u32(decoded, b"id", ct.byref(value)) == 0)
        check(value.value == 42)

        filter_handle = lib.hdds_filter_create(b"id > 40")
        fields = lib.hdds_field_map_create()
        check(filter_handle and fields)
        check(lib.hdds_field_map_set_u64(fields, b"id", value.value) == 0)
        check(lib.hdds_filter_evaluate(filter_handle, fields) == 1)
        check(lib.hdds_field_map_set_u64(fields, b"id", 10) == 0)
        check(lib.hdds_filter_evaluate(filter_handle, fields) == 0)
    finally:
        lib.hdds_field_map_destroy(fields)
        lib.hdds_filter_destroy(filter_handle)
        lib.hdds_dynamic_data_destroy(decoded)
        lib.hdds_dynamic_data_destroy(data)
        lib.hdds_type_descriptor_destroy(desc)
        lib.hdds_type_builder_destroy(builder)
    print("Dynamic CDR roundtrip and field-map evaluation: PASS")


if __name__ == "__main__":
    main()
