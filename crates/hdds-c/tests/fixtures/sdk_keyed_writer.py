# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Generated Python samples cross a process boundary through the real SDK."""
import ctypes as C
import os
import sys

sys.path.insert(0, os.environ["HDDS_KEYED_CODEC"])
from sdk_keyed import Keyed, m_T
from hdds import Participant, QoS
from hdds._native import get_lib, check_error

lib = get_lib()

def ffi(name, result, types, *args):
    f = getattr(lib, name)
    f.restype, f.argtypes = result, types
    return f(*args)

def ok(name, types, *args):
    check_error(ffi(name, C.c_int, types, *args))

P, S, U = C.c_void_p, C.c_char_p, C.c_uint32
config = ffi("hdds_config_create", P, [S], b"generated_python_writer")
ok("hdds_config_set_domain_id", [P, U], config, int(sys.argv[1]))
if sys.argv[2] == "encrypt":
    security = ffi("hdds_security_config_create", P, [])
    for setter, filename in [("identity_cert", "id.pem"), ("private_key", "key.pem"), ("ca_cert", "ca.pem")]:
        path = os.path.join(os.environ["HDDS_KEYED_PKI"], filename).encode()
        ok("hdds_security_config_set_" + setter, [P, S], security, path)
    ok("hdds_security_config_enable_encryption", [P, C.c_bool], security, True)
    ok("hdds_config_set_security", [P, P], config, security)
participant = ffi("hdds_config_build", P, [P], config)
assert participant
qos = QoS.reliable().history_depth(32)
# The security-capable config supplies the Participant handle; writer
# construction and dispatch go through the public SDK factories.
parent = Participant.__new__(Participant)
parent._handle = participant
parent._writers, parent._readers, parent._publishers, parent._subscribers = [], [], [], []
mode = sys.argv[3] if len(sys.argv) > 3 else "typed"
message_type = m_T if mode == "scoped" else Keyed
class OldCodec:
    HDDS_EXTENSIBILITY = "final"
    @staticmethod
    def has_key(): return True
    def __init__(self, **fields): self.value = Keyed(**fields)
    def encode_cdr2_le(self): return self.value.encode_cdr2_le()
if mode == "oldcodec": message_type = OldCodec
wire_name = "m::T" if mode == "scoped" else "Keyed"
writer = parent.create_writer("sdk_key_identity", None if mode == "legacy" else message_type,
                              qos=qos, type_name=wire_name)
assert writer.wait_for_readers(1, timeout=20)
for value in [10, 20]:
    for id in [1, 2, 3]:
        message = message_type(tag=1, id=id, value=value)
        if mode == "bytes": writer.write(message.encode_cdr2_le())
        else: writer.write_typed(message)
assert writer.wait_for_acknowledgments(timeout=20)
print("WRITTEN", flush=True)
if mode in ("legacy", "oldcodec"):
    assert input() == "quit"
    parent.close()
    sys.exit(0)
assert input() == "dispose"
writer.dispose(message_type(tag=1, id=2, value=0))
assert writer.wait_for_acknowledgments(timeout=20)
print("DISPOSED", flush=True)
assert input() == "unregister"
writer.unregister_instance(message_type(tag=1, id=3, value=0))
assert writer.wait_for_acknowledgments(timeout=20)
print("UNREGISTERED", flush=True)
assert input() == "quit"
parent.close()
