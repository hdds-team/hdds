#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com
"""Differential vectors for the any-salt RSASSA-PSS verifier
(security/handshake/pss.rs), against OpenSSL as the oracle.

For RSA keys of awkward sizes (modulus bits not a multiple of 8, so emLen
and the unused top bits vary, plus sizes outside 2048..=8192) and exponents
65537 and 3, it signs random messages with random salt lengths and applies
at most one defect per case: an EMSA-PSS field (separator, padding string,
salt, all-zero DB, unused top bit, hash, trailer), the signature (a bit
flipped, s >= n, s + n, one octet short or long, random), the message, the
hash or MGF (MGF1-SHA1, SHA-384), or a raw m^d of a random m. A defect that
cannot apply to its case (no padding string at the maximum salt, no salt to
alter, no unused top bit) leaves the case valid. The expected
verdict is what python-cryptography (OpenSSL) says with
`salt_length=PSS.AUTO`, and 0 for a key outside 2048..=8192 bits, which the
verifier refuses whatever the signature. One deliberate divergence: a
signature one octet short (its leading octet was zero) OpenSSL accepts, by
left-padding it, and RFC 8017 8.1.2 step 1 refuses, as the verifier does;
such a case is expected 0 and labelled `short-openssl-accepts`.

Output (stdout), one record per line:
    K <modulus hex> <exponent hex>     a key, for the cases below it
    C <0|1> <defect> <message hex> <signature hex>
An empty message is written as "-".

The test reads the committed file through include_str!; it never runs this
script. Regenerate by hand (needs python3 and python-cryptography):

    python3 scripts/security/gen-pss-differential.py \
        > crates/hdds/src/security/fixtures/pss/differential.txt

Keys are fresh on every run, so the file changes as a whole.
"""
import hashlib
import os
import random
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

rng = random.Random(20261020)
CASES_PER_KEY = 24
SIZES = [2048, 2049, 2050, 2055, 2056, 2057, 2063, 2064, 2065, 3072, 3073,
         4097, 2047, 1024]
DEFECTS = [None, None, None, "sep", "ps", "salt", "allzero", "topbit",
           "hash", "trailer", "flip", "s_ge_n", "s_plus_n", "short", "long",
           "wrongmsg", "mgf1sha1", "sha384", "random", "raw_m"]


def randbytes(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def mgf1(seed, length, h):
    out = b""
    counter = 0
    while len(out) < length:
        out += h(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def encode(msg, mod_bits, salt_len, defect=None, h=hashlib.sha256, mgf_h=hashlib.sha256):
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    h_len = h().digest_size
    salt = randbytes(salt_len)
    big_h = h(b"\0" * 8 + h(msg).digest() + salt).digest()
    db_len = em_len - h_len - 1
    ps = bytearray(db_len - salt_len - 1)
    sep = 1
    if defect == "sep":
        sep = rng.choice([0, 2, 3, 0x81, 0xFF])
    if defect == "ps" and ps:
        ps[rng.randrange(len(ps))] = rng.randrange(1, 256)
    db = bytearray(bytes(ps) + bytes([sep]) + salt)
    if defect == "salt" and salt_len > 0:
        db[-1 - rng.randrange(salt_len)] ^= 1 << rng.randrange(8)
    if defect == "allzero":
        db = bytearray(db_len)
    masked = bytearray(a ^ b for a, b in zip(db, mgf1(big_h, db_len, mgf_h)))
    unused = 8 * em_len - em_bits
    masked[0] &= 0xFF >> unused
    if defect == "topbit" and unused > 0:
        masked[0] |= 0x80 >> rng.randrange(unused)
    if defect == "hash":
        big_h = bytearray(big_h)
        big_h[rng.randrange(h_len)] ^= 1 << rng.randrange(8)
        big_h = bytes(big_h)
    trailer = rng.choice([0xBD, 0xCC, 0x00, 0x01, 0xBB]) if defect == "trailer" else 0xBC
    return bytes(masked) + big_h + bytes([trailer])


def oracle(public_key, msg, sig):
    try:
        public_key.verify(
            sig,
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
            hashes.SHA256(),
        )
        return 1
    except InvalidSignature:
        return 0
    except ValueError:
        return 0


def main():
    out = sys.stdout
    for bits in SIZES:
        key = rsa.generate_private_key(public_exponent=rng.choice([65537, 65537, 3]), key_size=bits)
        numbers = key.public_key().public_numbers()
        n, e, d = numbers.n, numbers.e, key.private_numbers().d
        k = (n.bit_length() + 7) // 8
        em_len = (n.bit_length() - 1 + 7) // 8
        max_salt = em_len - 32 - 2
        n_bytes = n.to_bytes(k, "big")
        if rng.random() < 0.5:
            n_bytes = b"\0" + n_bytes  # DER INTEGER with its leading zero
        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")
        out.write(f"K {n_bytes.hex()} {e_bytes.hex()}\n")
        in_bounds = 2048 <= n.bit_length() <= 8192
        for _ in range(CASES_PER_KEY):
            msg = randbytes(rng.randrange(0, 64))
            salt_len = rng.choice([0, 1, 20, 32, 48, max_salt, max_salt - 1, rng.randrange(0, max_salt + 1)])
            defect = rng.choice(DEFECTS)
            if defect == "mgf1sha1":
                em = encode(msg, n.bit_length(), salt_len, mgf_h=hashlib.sha1)
            elif defect == "sha384":
                em = encode(msg, n.bit_length(), min(salt_len, em_len - 48 - 2), h=hashlib.sha384)
            elif defect in ("sep", "ps", "salt", "allzero", "topbit", "hash", "trailer"):
                em = encode(msg, n.bit_length(), salt_len, defect)
            else:
                em = encode(msg, n.bit_length(), salt_len)
            m = int.from_bytes(em, "big")
            if defect == "raw_m":
                m = rng.randrange(n)
            s = pow(m % n, d, n)
            sig = s.to_bytes(k, "big")
            if defect == "flip":
                sig = bytearray(sig)
                sig[rng.randrange(k)] ^= 1 << rng.randrange(8)
                sig = bytes(sig)
            elif defect == "s_ge_n":
                sig = rng.randrange(n, 256 ** k).to_bytes(k, "big")
            elif defect == "s_plus_n":
                if s + n < 256 ** k:
                    sig = (s + n).to_bytes(k, "big")
                else:
                    defect = None  # s + n needs one octet more: no defect
            elif defect == "short":
                sig = sig[1:]
            elif defect == "long":
                sig = b"\0" + sig
            elif defect == "random":
                sig = randbytes(k)
            verified = msg + b"x" if defect == "wrongmsg" else msg
            expected = oracle(key.public_key(), verified, sig) if in_bounds else 0
            label = defect or "none"
            if len(sig) != k and expected:
                # RFC 8017 8.1.2 step 1 refuses a signature that is not k
                # octets; OpenSSL left-pads a shorter one. The RFC wins.
                expected = 0
                label += "-openssl-accepts"
            out.write(f"C {expected} {label} {verified.hex() or '-'} {sig.hex()}\n")


if __name__ == "__main__":
    main()
