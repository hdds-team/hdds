# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Typed instance operations preserve all three codec representations.

RTPS 2.5 9.6.4.8 uses the normal hash, DDS-Security 1.1 7.3.4 the
protected digest, and RTPS 2.5 9.4.5.3 the key-only payload.
"""
import ctypes
import pytest
from hdds.entities import DataWriter, _SerializedKey


@pytest.fixture(autouse=True)
def require_native_double(monkeypatch):
    def refuse():
        raise AssertionError("a fake handle requires a native test double")
    monkeypatch.setattr("hdds._native.get_lib", refuse)


class Keyed:
    HDDS_EXTENSIBILITY = "final"
    HDDS_KEY_SUPPORTED = True

    @staticmethod
    def has_key():
        return True

    @staticmethod
    def decode_cdr2_le(data):
        assert data == Keyed().encode_cdr2_le()
        return Keyed(), len(data)

    def encode_cdr2_le(self):
        return b"\x01\x00\x00\x00\x09\x00\x00\x00"

    def encode_key_cdr2_le(self):
        return b"\x01\x00\x00\x00"

    def compute_key(self, protected_key=False):
        # MD5 of 00000001 when protected, zero-padded BE otherwise.
        return bytes.fromhex("f1450306517624a57eafbbf8ed995985" if protected_key else
                             "00000001000000000000000000000000")


@pytest.mark.parametrize("operation", ["write", "write_w_timestamp", "dispose", "dispose_w_timestamp",
                                        "unregister_instance", "unregister_instance_w_timestamp",
                                        "register_instance", "register_instance_w_timestamp"])
def test_typed_operations_pass_the_codec_identity(monkeypatch, operation):
    seen = []

    class Function:
        def __call__(self, handle, data, length, key_ptr, *tail):
            key = ctypes.cast(key_ptr, ctypes.POINTER(_SerializedKey)).contents
            seen.append((bytes(data[:length]), bytes(key.hash), bytes(key.protected_hash),
                         ctypes.string_at(key.payload, key.payload_len), key.representation))
            if operation.startswith("register_instance"):
                ctypes.memmove(tail[-1], key.hash, 16)
            return 0

    class Lib:
        pass

    lib = Lib()
    setattr(lib, "hdds_writer_" + operation + "_keyed", Function())
    monkeypatch.setattr("hdds.entities._require", lambda symbol, api: lib)
    writer = DataWriter._from_handle("keys", 1, None, extensibility_known=True, keyed_type=Keyed)
    value = Keyed()
    args = [value] + ([123] if operation.endswith("_w_timestamp") else [])
    if operation == "write":
        writer.write_typed(value)
    elif operation == "write_w_timestamp":
        writer.write_typed_w_timestamp(*args)
    else:
        result = getattr(writer, operation)(*args)
        if operation.startswith("register_instance"):
            assert result == value.compute_key()
    assert seen == [(value.encode_cdr2_le() if operation.startswith("write") else b"", value.compute_key(), value.compute_key(True),
                     value.encode_key_cdr2_le(), 2)]


def test_unsupported_key_is_refused_before_any_ffi_call():
    value = Keyed()
    value.HDDS_KEY_SUPPORTED = False
    writer = DataWriter._from_handle("keys", 1, None, extensibility_known=True, keyed_type=Keyed)
    with pytest.raises(NotImplementedError, match="current hddsgen codec"):
        writer.write_typed(value)


def test_lifecycle_never_serializes_non_key_fields(monkeypatch):
    value = Keyed()
    value.encode_cdr2_le = lambda: (_ for _ in ()).throw(AssertionError("non-key data read"))
    class Function:
        def __call__(self, *_args):
            return 0
    class Lib:
        hdds_writer_dispose_keyed = Function()
    monkeypatch.setattr("hdds.entities._require", lambda *_args: Lib())
    writer = DataWriter._from_handle("keys", 1, None, extensibility_known=True, keyed_type=Keyed)
    writer.dispose(value)


@pytest.mark.parametrize("owner", ["participant", "publisher"])
@pytest.mark.parametrize("decoder", [True, False])
def test_keyed_creation_passes_idl_name(monkeypatch, owner, decoder):
    from types import SimpleNamespace
    from hdds import Participant
    from hdds.entities import Publisher

    class Function:
        def __call__(self, *args):
            self.args = args
            return 2

    if not decoder:
        monkeypatch.setattr(Keyed, "decode_cdr2_le", None)
    constructor = Function()
    symbol = "hdds_writer_create_keyed" if owner == "participant" else "hdds_publisher_create_writer_keyed"
    lib = SimpleNamespace(**{symbol: constructor})
    monkeypatch.setattr("hdds._native.get_lib", lambda: lib)
    if owner == "participant":
        parent = Participant.__new__(Participant)
        parent._handle = 1
        parent._writers = []
    else:
        parent = Publisher._from_handle(1, None)
    # Supply a QoS double so this constructor test needs no native library.
    qos = SimpleNamespace(_c_handle=3)
    writer = parent.create_writer("keys", Keyed, qos=qos, type_name="module::Keyed")
    assert constructor.args == (1, b"keys", b"module::Keyed", 3, 0)
    writer._handle = None
    parent._handle = None

@pytest.mark.parametrize("operation", ["write", "write_w_timestamp", "dispose", "unregister_instance", "register_instance"])
def test_old_writer_and_old_codec_keep_legacy_dispatch(monkeypatch, operation):
    calls = []
    class OldCodec:
        HDDS_EXTENSIBILITY = "final"
        @staticmethod
        def has_key(): return True
        def encode_cdr2_le(self): return b"old codec bytes"
    class Function:
        def __call__(self, *args):
            calls.append(args)
            return 0
    from types import SimpleNamespace
    lib = SimpleNamespace(**{"hdds_writer_" + operation: Function()})
    monkeypatch.setattr("hdds._native.get_lib", lambda: lib)
    monkeypatch.setattr("hdds.entities._require", lambda *_: lib)
    writer = DataWriter._from_handle("legacy", 1, None)
    if operation == "write": writer.write_typed(OldCodec())
    elif operation == "write_w_timestamp": writer.write_typed_w_timestamp(OldCodec(), 123)
    else: getattr(writer, operation)(OldCodec())
    assert len(calls) == 1
    assert bytes(calls[0][1][:calls[0][2]]) == b"old codec bytes"
    writer._handle = None


def test_encoded_bytes_keep_the_typed_writers_key(monkeypatch):
    seen = []
    class Versioned(Keyed):
        @staticmethod
        def decode_cdr2_le(data):
            assert data == b"original wire body"
            return Versioned(), len(data)
    class Function:
        def __call__(self, _handle, _data, _length, key_ptr):
            assert bytes(_data[:_length]) == b"original wire body"
            key = ctypes.cast(key_ptr, ctypes.POINTER(_SerializedKey)).contents
            seen.append(bytes(key.hash))
            return 0
    from types import SimpleNamespace
    monkeypatch.setattr("hdds.entities._require", lambda *_: SimpleNamespace(hdds_writer_write_keyed=Function()))
    def refuse_legacy(*_args): raise AssertionError("key metadata was lost")
    monkeypatch.setattr("hdds._native.get_lib", lambda: SimpleNamespace(hdds_writer_write=refuse_legacy))
    writer = DataWriter._from_handle("keys", 1, None, keyed_type=Versioned)
    writer.write(b"original wire body")
    assert seen == [Keyed().compute_key()]
    writer._handle = None

@pytest.mark.parametrize("owner", ["participant", "publisher"])
def test_old_codec_constructor_is_not_keyed(monkeypatch, owner):
    from types import SimpleNamespace
    from hdds import Participant
    from hdds.entities import Publisher
    class OldCodec:
        HDDS_EXTENSIBILITY = "final"
        @staticmethod
        def has_key(): return True
        def encode_cdr2_le(self): return b"old codec bytes"
    class Function:
        def __call__(self, *args): return 2
    symbol = "hdds_writer_create_with_extensibility" if owner == "participant" else "hdds_publisher_create_writer_with_type"
    monkeypatch.setattr("hdds._native.get_lib", lambda: SimpleNamespace(**{symbol: Function()}))
    if owner == "participant":
        parent = Participant.__new__(Participant)
        parent._handle, parent._writers = 1, []
    else: parent = Publisher._from_handle(1, None)
    writer = parent.create_writer("old", OldCodec, qos=SimpleNamespace(_c_handle=3))
    assert writer._keyed_type is None
    writer._handle, parent._handle = None, None


def test_encoder_only_keyed_codec_refuses_only_preencoded_operations(monkeypatch):
    class EncoderOnly(Keyed):
        decode_cdr2_le = None
    from hdds.entities import _has_key_codec
    assert _has_key_codec(EncoderOnly)
    writer = DataWriter._from_handle("keys", 1, None, keyed_type=EncoderOnly)
    with pytest.raises(NotImplementedError, match="decoding codec"):
        writer.write(EncoderOnly().encode_cdr2_le())
    writer._handle = None
