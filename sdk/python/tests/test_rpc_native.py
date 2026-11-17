# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Exercise the optional RPC ABI with a callback entered from a Rust worker."""

import ctypes as ct
import os
import queue

import pytest


@pytest.mark.native
def test_rpc_python_callback_and_shutdown(native_lib, intra_participant):
    lib = native_lib
    if not hasattr(lib, "hdds_rpc_client_create"):
        if os.environ.get("HDDS_REQUIRE_RPC") == "1":
            pytest.fail("HDDS_REQUIRE_RPC=1 but the library has no RPC feature")
        pytest.skip("Optional RPC feature is not enabled")
    callback_type = ct.CFUNCTYPE(
        ct.c_int32, ct.c_void_p, ct.c_size_t,
        ct.POINTER(ct.c_void_p), ct.POINTER(ct.c_size_t), ct.c_void_p,
    )
    signatures = [
        ("hdds_rpc_client_create", ct.c_void_p, [ct.c_void_p, ct.c_char_p, ct.c_uint64]),
        ("hdds_rpc_client_destroy", None, [ct.c_void_p]),
        ("hdds_rpc_client_shutdown", None, [ct.c_void_p]),
        ("hdds_rpc_client_call_default", ct.c_int, [ct.c_void_p, ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_void_p), ct.POINTER(ct.c_size_t)]),
        ("hdds_rpc_server_create", ct.c_void_p, [ct.c_void_p, ct.c_char_p, callback_type, ct.c_void_p]),
        ("hdds_rpc_server_destroy", None, [ct.c_void_p]),
        ("hdds_rpc_server_spin_background", ct.c_int, [ct.c_void_p]),
    ]
    for name, result, arguments in signatures:
        function = getattr(lib, name)
        function.restype, function.argtypes = result, arguments
    received = queue.Queue()

    @callback_type
    def handler(request, length, out_reply, out_length, context):
        # Empty reply needs no cross-runtime allocation. Keep this callback
        # object alive until server destruction has joined the worker.
        received.put(ct.string_at(request, length) if length else b"")
        out_reply[0], out_length[0] = None, 0
        return 0

    server = lib.hdds_rpc_server_create(intra_participant._handle, b"python_rpc", handler, None)
    assert server
    client = None
    try:
        assert lib.hdds_rpc_server_spin_background(server) == 0
        client = lib.hdds_rpc_client_create(intra_participant._handle, b"python_rpc", 2000)
        assert client
        for payload in [b"\0\xffpython\0", b""]:
            reply, length = ct.c_void_p(), ct.c_size_t()
            assert lib.hdds_rpc_client_call_default(client, payload, len(payload), ct.byref(reply), ct.byref(length)) == 0
            assert reply.value is None and length.value == 0
            assert received.get(timeout=2) == payload
        lib.hdds_rpc_client_shutdown(client)
        assert lib.hdds_rpc_client_call_default(client, None, 0, ct.byref(reply), ct.byref(length)) == 14
    finally:
        if client:
            lib.hdds_rpc_client_destroy(client)
        lib.hdds_rpc_server_destroy(server)
