#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
"""Hand-built RSASSA-PSS encoded messages, signed raw with openssl, for the
negative tests of the any-salt verifier (security/handshake/pss.rs).

Each vector is a well-formed EMSA-PSS encoding (RFC 8017 9.1.1, SHA-256,
MGF1-SHA-256) of `pss/msg` under `rsa_identity_key.pem` with ONE defect, so
that a verifier missing the matching check accepts it: its hash H still
covers the salt it carries. Run from crates/hdds/src/security/fixtures:

    python3 ../../../../../scripts/security/gen-pss-fixtures.py

Needs python3 and openssl (to read the key's n and d; the raw RSA operation
is done here, by pow).
The test never runs this; regenerate by hand and commit the result.
"""
import hashlib
import re
import subprocess

KEY = "rsa_identity_key.pem"
EM_LEN = 256  # 2048-bit modulus: emBits 2047, emLen 256, one unused top bit
H_LEN = 32


def mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def encode(msg, salt, separator=0x01, trailer=0xBC, top_bit=False):
    m_hash = hashlib.sha256(msg).digest()
    h = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    ps = b"\x00" * (EM_LEN - len(salt) - H_LEN - 2)
    db = ps + bytes([separator]) + salt
    masked = bytearray(a ^ b for a, b in zip(db, mgf1(h, len(db))))
    masked[0] &= 0x7F
    if top_bit:
        masked[0] |= 0x80
    return bytes(masked) + h + bytes([trailer])


def key_numbers():
    text = subprocess.run(
        ["openssl", "pkey", "-in", KEY, "-noout", "-text"],
        check=True, capture_output=True, text=True,
    ).stdout

    def field(name):
        block = re.search(name + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", text).group(1)
        return int(re.sub(r"[\s:]", "", block), 16)

    return field("modulus"), field("privateExponent")


def raw_sign(em, out):
    n, d = key_numbers()
    m = int.from_bytes(em, "big")
    assert m < n
    with open(out, "wb") as f:
        f.write(pow(m, d, n).to_bytes(EM_LEN, "big"))


def main():
    msg = open("pss/msg", "rb").read()
    salt = bytes(range(1, 21))  # 20 octets, no zero octet
    raw_sign(encode(msg, salt), "pss/raw_ok.sig")
    raw_sign(encode(msg, salt, trailer=0xBD), "pss/raw_bad_trailer.sig")
    raw_sign(encode(msg, salt, separator=0x02), "pss/raw_bad_separator.sig")
    raw_sign(encode(msg, salt, top_bit=True), "pss/raw_top_bit.sig")


if __name__ == "__main__":
    main()
