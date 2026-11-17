// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Instance KeyHash, as DDSI-RTPS 2.5 9.6.4.8 and DDS-XTypes 1.3 7.6.8
//! define it.
//!
//! # The algorithm
//!
//! The KeyHash of a sample of an aggregated type `Foo` is computed from a
//! derived type, the KeyHolder of `Foo` (XTypes 7.2.2.4.7):
//!
//! 1. The KeyHolder has extensibility FINAL whatever `Foo` declares. If `Foo`
//!    has key members, the non-key members are removed; if it has none, every
//!    member is kept. The members are put in ascending member-id order, which
//!    is not declaration order when `@id` reorders them.
//! 2. The KeyHolder object takes its values from the sample.
//! 3. Steps 1 and 2 apply recursively to members that are themselves
//!    aggregated types. A nested structure with no key member therefore
//!    contributes ALL its members. A union whose discriminator is not a key
//!    contributes the whole union; one whose discriminator is a key
//!    contributes the discriminator alone.
//! 4. The KeyHolder object is serialized as PLAIN_CDR2, BIG endian, with no
//!    encapsulation header, no DHEADER and no member header, in a buffer
//!    aligned to 4 at its start. PLAIN_CDR2 aligns a primitive to its size
//!    capped at 4: an 8-byte member sits at a 4-byte boundary. Padding bytes
//!    are zero.
//! 5. If the KeyHolder's MAXIMUM serialized size is at most 16 bytes, the
//!    KeyHash is the serialization extended with zeros to 16 bytes. Otherwise
//!    it is the MD5 of the serialization. The choice depends on the TYPE, not
//!    on the value: the string "BLUE" in a `string<8>` key is padded, the same
//!    string in an unbounded `string` key is hashed.
//!
//! [`KeyHolderWriter`] performs step 4 one member at a time and step 5 in
//! [`KeyHolderWriter::finish`]. Steps 1 to 3, which members to write and in
//! what order, are the caller's: code generated from IDL knows them at
//! generation time, the dynamic-type walker reads them from the descriptor.
//!
//! # The contract for generated code
//!
//! A keyed type implements one hook of [`crate::dds::DDS`]:
//! `write_key_holder(&self, w: &mut KeyHolderWriter) -> Option<KeyMaxSize>`
//! writes the KeyHolder members in member-id order and returns
//! `Some(max)`, the KeyHolder's maximum serialized size, computed with the
//! same alignment rule (capped at 4, buffer starting aligned). The size is a
//! property of the type, so every sample returns the same value; it travels
//! with the members so that a type cannot provide one without the other.
//! `compute_key` then needs no override. The mapping from IDL to writer
//! calls is:
//!
//! | IDL                                 | call                                  |
//! |-------------------------------------|---------------------------------------|
//! | `boolean`                           | [`KeyHolderWriter::write_bool`]       |
//! | `octet`, `uint8`, `char`            | [`KeyHolderWriter::write_u8`]         |
//! | `int8`                              | [`KeyHolderWriter::write_i8`]         |
//! | `short`/`int16`, `unsigned short`   | `write_i16` / `write_u16`             |
//! | `wchar`                             | `write_u16` of the UTF-16 code unit   |
//! | `long`/`int32`, `unsigned long`     | `write_i32` / `write_u32`             |
//! | `long long`, `unsigned long long`   | `write_i64` / `write_u64`             |
//! | `float`, `double`                   | `write_f32` / `write_f64`             |
//! | `string`, `string<N>`               | [`KeyHolderWriter::write_string`]     |
//! | `wstring`, `wstring<N>`             | [`KeyHolderWriter::write_wstring`]    |
//! | enum, `@bit_bound` 1-8 / 9-16 / 17-32 | `write_i8` / `write_i16` / `write_i32` |
//! | bitmask, `@bit_bound` 1-8 / 9-16 / 17-32 / 33-64 | `write_u8` / `write_u16` / `write_u32` / `write_u64` |
//! | `sequence<P>` of a primitive `P`    | `write_u32(len)`, then each element   |
//! | `sequence<octet>`                   | `write_u32(len)`, then [`KeyHolderWriter::write_octets`] |
//! | `P[N]` of a primitive `P`           | each element, no length               |
//! | nested struct or union              | its own KeyHolder, recursively        |
//!
//! Collections whose element type is NOT primitive (`sequence<string>`,
//! arrays of structures) carry a DHEADER in XCDR2 (XTypes 7.4.3.5.3 rules 9
//! and 12), while the KeyHash note says the serialization holds no "type
//! header". Which reading peers implement is not established, so this
//! module offers no call for that DHEADER and such keys are not covered.
//!
//! # Maximum serialized size
//!
//! [`KeyMaxSize::Bounded`] carries the maximum, in bytes, under the same
//! alignment rule, of every value the KeyHolder can hold. Strings count their
//! 4-byte length, their bound in bytes and the NUL. Any unbounded string or
//! sequence in the KeyHolder makes it [`KeyMaxSize::Unbounded`]. Spec Example
//! 2: `@key string<12> label; @key long long id` is 4 + 12 + 1 = 17, three
//! bytes of padding to reach a 4-byte boundary, then 8: 28 bytes.
//!
//! # Known foreign divergence
//!
//! Eclipse Cyclone DDS 0.11 aligns 8-byte members at 8 when it computes the
//! KeyHash of a `@final` type, where PLAIN_CDR2 aligns them at 4. Observed
//! with a probe linked against `libddsc` 0.11.0 (`ddsi_serdata_get_keyhash`
//! on samples of `idlc` 0.11.0 types):
//!
//! - `@final struct { @key octet t; @key long long v; }`, 1, 2: Cyclone gives
//!   `01000000000000000000000000000002` (the `long long` at offset 8), the
//!   specification `01000000000000000000000200000000` (offset 4).
//! - Spec Example 2 declared `@final`: Cyclone gives
//!   `b5a5ff394886de362bf4911c4115f1c1`, the MD5 of the 24-byte serialization
//!   with the `long long` at offset 16; the specification prints
//!   `f91a59e32e4535d9a69cd5d9f5b6e36e` (offset 12, 20 bytes).
//!
//! The same probe agrees with the specification on the other twelve golden
//! types, including spec Example 3, which is `@mutable`. That is a divergence
//! of that implementation, not an expected value: this module follows the
//! specification, and the golden vectors pin the 4-byte alignment.

#[cfg(test)]
mod golden_tests;
mod payload;

pub use payload::{KeyPayloadMember, KeyPayloadParameter, KeyPayloadReader};

/// Length of a KeyHash (RTPS 2.5 9.3.2 `KeyHash_t`).
const KEY_HASH_LEN: usize = 16;

/// PLAIN_CDR2 caps alignment at 4 bytes (XTypes 1.3 7.4.2).
const PLAIN_CDR2_MAX_ALIGN: usize = 4;

/// Log, once per process, that a type declares a key and writes no
/// KeyHolder, so its samples all share the all-zero KeyHash.
#[doc(hidden)]
pub fn warn_keyed_type_without_key_holder(type_name: &str) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        log::warn!(
            "type {type_name} declares a key (has_key) but implements no write_key_holder: \
             every sample gets the all-zero KeyHash, so all its samples are one instance"
        );
    }
}

/// Maximum serialized size of a type's KeyHolder (RTPS 2.5 9.6.4.8 step 5).
///
/// It decides the KeyHash form: a bound of at most 16 bytes selects the
/// zero-padded serialization, anything larger or unbounded selects MD5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMaxSize {
    /// The KeyHolder never serializes to more than this many bytes.
    Bounded(usize),
    /// The KeyHolder holds an unbounded string or sequence.
    Unbounded,
}

/// Bytes a KeyHolder keeps on the stack before it spills to the heap. The
/// padded form needs at most 16; the short keys most MD5-form types carry
/// (a string of a few characters, a few integers) fit as well.
const INLINE_CAPACITY: usize = 32;

/// Serializes a KeyHolder object as PLAIN_CDR2 big endian, then reduces it to
/// a 16-byte KeyHash (RTPS 2.5 9.6.4.8 steps 4 and 5).
///
/// Every `write_*` call aligns the value to its size capped at 4, relative to
/// the first byte written, and fills the padding with zeros. The first 32
/// bytes live inside the writer, so a KeyHolder that fits allocates nothing.
#[derive(Debug, Clone, Default)]
pub struct KeyHolderWriter {
    /// The serialization while it fits.
    inline: [u8; INLINE_CAPACITY],
    /// Bytes used in `inline`; meaningless once `spill` holds the bytes.
    len: usize,
    /// The whole serialization once it outgrew `inline`; empty (and not
    /// allocated) until then. Never empty once used: it spills only to grow.
    spill: Vec<u8>,
    /// Zero selects PLAIN_CDR2; security hashing uses CDR alignment.
    max_align: usize,
}

impl KeyHolderWriter {
    /// An empty writer, aligned to 4 at its start.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// CDR big endian key fields for DDS-Security 1.1 Sec.7.3.4.
    /// Finish with `KeyMaxSize::Unbounded` to force MD5 regardless of size.
    #[must_use]
    pub fn for_security() -> Self {
        Self {
            max_align: 8,
            ..Self::default()
        }
    }

    #[inline]
    fn len(&self) -> usize {
        if self.spill.is_empty() {
            self.len
        } else {
            self.spill.len()
        }
    }

    #[inline]
    fn extend(&mut self, bytes: &[u8]) {
        if self.spill.is_empty() {
            let end = self.len + bytes.len();
            if let Some(dst) = self.inline.get_mut(self.len..end) {
                dst.copy_from_slice(bytes);
                self.len = end;
                return;
            }
            let mut spill = Vec::with_capacity(end.max(2 * INLINE_CAPACITY));
            spill.extend_from_slice(&self.inline[..self.len]);
            self.spill = spill;
        }
        self.spill.extend_from_slice(bytes);
    }

    #[inline]
    fn align(&mut self, size: usize) {
        let align = size.min(if self.max_align == 0 {
            PLAIN_CDR2_MAX_ALIGN
        } else {
            self.max_align
        });
        let pad = (align - self.len() % align) % align;
        self.extend(&[0u8; 8][..pad]);
    }

    #[inline]
    fn put<const N: usize>(&mut self, bytes: [u8; N]) {
        self.align(N);
        self.extend(&bytes);
    }

    /// `boolean`: one byte, 0 or 1.
    #[inline]
    pub fn write_bool(&mut self, v: bool) {
        self.extend(&[u8::from(v)]);
    }

    /// `octet`, `uint8`, or `char`.
    #[inline]
    pub fn write_u8(&mut self, v: u8) {
        self.extend(&[v]);
    }

    /// `int8`, or an enum whose `@bit_bound` is at most 8.
    #[inline]
    pub fn write_i8(&mut self, v: i8) {
        self.put(v.to_be_bytes());
    }

    /// `unsigned short`, or a `wchar` as its UTF-16 code unit.
    #[inline]
    pub fn write_u16(&mut self, v: u16) {
        self.put(v.to_be_bytes());
    }

    /// `short`.
    #[inline]
    pub fn write_i16(&mut self, v: i16) {
        self.put(v.to_be_bytes());
    }

    /// `unsigned long`, or a sequence length.
    #[inline]
    pub fn write_u32(&mut self, v: u32) {
        self.put(v.to_be_bytes());
    }

    /// `long`, or an enum with the default `@bit_bound` of 32.
    #[inline]
    pub fn write_i32(&mut self, v: i32) {
        self.put(v.to_be_bytes());
    }

    /// `unsigned long long`, aligned at 4 as PLAIN_CDR2 requires.
    #[inline]
    pub fn write_u64(&mut self, v: u64) {
        self.put(v.to_be_bytes());
    }

    /// `long long`, aligned at 4 as PLAIN_CDR2 requires.
    #[inline]
    pub fn write_i64(&mut self, v: i64) {
        self.put(v.to_be_bytes());
    }

    /// `float`, its IEEE 754 bits as written.
    #[inline]
    pub fn write_f32(&mut self, v: f32) {
        self.put(v.to_be_bytes());
    }

    /// `double`, its IEEE 754 bits as written, aligned at 4.
    #[inline]
    pub fn write_f64(&mut self, v: f64) {
        self.put(v.to_be_bytes());
    }

    /// Raw octets with no length and no alignment: the body of a
    /// `sequence<octet>` (after its `write_u32` length) or an `octet[N]`.
    #[inline]
    pub fn write_octets(&mut self, v: &[u8]) {
        self.extend(v);
    }

    /// `string`: a 4-byte length counting the terminating NUL, the bytes, the
    /// NUL (XTypes 1.3 7.4.3.5.3 rule 3).
    #[inline]
    pub fn write_string(&mut self, v: &str) {
        let len = u32::try_from(v.len().saturating_add(1)).unwrap_or(u32::MAX);
        self.write_u32(len);
        self.extend(v.as_bytes());
        self.extend(&[0]);
    }

    /// `wstring`: a 4-byte length counting BYTES of UTF-16 payload, then the
    /// code units, with no terminating NUL (XTypes 1.3 7.4.3.5.3 rule 4).
    #[inline]
    pub fn write_wstring(&mut self, v: &str) {
        let units = v.encode_utf16().count();
        let len = u32::try_from(units.saturating_mul(2)).unwrap_or(u32::MAX);
        self.write_u32(len);
        for unit in v.encode_utf16() {
            self.extend(&unit.to_be_bytes());
        }
    }

    /// The serialization written so far (RTPS 2.5 9.6.4.8 step 4).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        if self.spill.is_empty() {
            &self.inline[..self.len]
        } else {
            &self.spill
        }
    }

    /// The KeyHash (RTPS 2.5 9.6.4.8 step 5).
    ///
    /// `max` is the KeyHolder's maximum serialized size, a property of the
    /// type. With `Bounded(n)` and `n <= 16` the result is the serialization
    /// followed by zeros; otherwise it is the MD5 of the serialization.
    ///
    /// The MD5 of a serialization is remembered per thread for the last
    /// eight short serializations (32 bytes or less): a writer repeats its
    /// instances, and comparing a few bytes costs far less than a digest.
    /// The digest depends on the bytes alone, so the cache serves every type
    /// and every writer or reader on the thread.
    ///
    /// # A value beyond its type's bounds
    ///
    /// A serialization longer than a declared `Bounded(n)` with `n <= 16`
    /// means the value breaks its type's bounds (a string longer than its
    /// `string<N>`), or the declared maximum is wrong. This is a contract
    /// violation, and a debug build panics on it so that a generator or a
    /// hand-written hook that miscounts is caught by its tests. A release
    /// build hashes the bytes rather than truncating them: this method has no
    /// error channel (`compute_key` cannot fail), and truncation would give
    /// two distinct instances one KeyHash, while the MD5 keeps them apart. No
    /// conforming peer computes a KeyHash for such a value. With `n > 16` the
    /// form is MD5 either way, so there is nothing to catch.
    #[inline]
    #[must_use]
    pub fn finish(self, max: KeyMaxSize) -> [u8; KEY_HASH_LEN] {
        let bytes = self.as_bytes();
        if let KeyMaxSize::Bounded(n) = max {
            debug_assert!(
                n > KEY_HASH_LEN || bytes.len() <= n,
                "KeyHolder serialization of {} bytes exceeds its declared maximum of {n}",
                bytes.len()
            );
        }
        match max {
            KeyMaxSize::Bounded(n) if n <= KEY_HASH_LEN && bytes.len() <= n => {
                let mut out = [0u8; KEY_HASH_LEN];
                out[..bytes.len()].copy_from_slice(bytes);
                out
            }
            _ => md5_cache::digest(bytes),
        }
    }
}

/// A per-thread memory of recent MD5-form KeyHashes.
mod md5_cache {
    use super::{INLINE_CAPACITY, KEY_HASH_LEN};
    use md5::{Digest, Md5};
    use std::cell::RefCell;

    /// Entries kept per thread; replaced in turn once full.
    const ENTRIES: usize = 8;

    #[derive(Clone, Copy)]
    struct Entry {
        used: bool,
        len: usize,
        bytes: [u8; INLINE_CAPACITY],
        hash: [u8; KEY_HASH_LEN],
    }

    const EMPTY: Entry = Entry {
        used: false,
        len: 0,
        bytes: [0; INLINE_CAPACITY],
        hash: [0; KEY_HASH_LEN],
    };

    struct Cache {
        entries: [Entry; ENTRIES],
        next: usize,
        #[cfg(test)]
        hits: u64,
    }

    // @audit-ok: per-thread memo of a pure function (MD5 of the bytes), never
    // shared across threads; a stale or evicted entry only costs a recompute.
    thread_local! {
        static CACHE: RefCell<Cache> = const {
            RefCell::new(Cache {
                entries: [EMPTY; ENTRIES],
                next: 0,
                #[cfg(test)]
                hits: 0,
            })
        };
    }

    /// The MD5 of `bytes`, computed without the cache.
    pub(super) fn uncached(bytes: &[u8]) -> [u8; KEY_HASH_LEN] {
        let mut out = [0u8; KEY_HASH_LEN];
        out.copy_from_slice(&Md5::digest(bytes));
        out
    }

    /// The MD5 of `bytes`, from the cache when this thread computed it
    /// recently. A serialization longer than an entry holds is not cached.
    pub(super) fn digest(bytes: &[u8]) -> [u8; KEY_HASH_LEN] {
        if bytes.len() > INLINE_CAPACITY {
            return uncached(bytes);
        }
        CACHE
            .try_with(|cache| {
                let Ok(mut cache) = cache.try_borrow_mut() else {
                    return uncached(bytes);
                };
                if let Some(hit) = cache
                    .entries
                    .iter()
                    .find(|e| e.used && e.len == bytes.len() && &e.bytes[..e.len] == bytes)
                {
                    let hash = hit.hash;
                    #[cfg(test)]
                    {
                        cache.hits += 1;
                    }
                    return hash;
                }
                let hash = uncached(bytes);
                let slot = cache.next;
                cache.next = (slot + 1) % ENTRIES;
                let entry = &mut cache.entries[slot];
                entry.used = true;
                entry.len = bytes.len();
                entry.bytes[..bytes.len()].copy_from_slice(bytes);
                entry.hash = hash;
                hash
            })
            .unwrap_or_else(|_| uncached(bytes))
    }

    /// Cache hits on this thread so far.
    #[cfg(test)]
    pub(super) fn hits() -> u64 {
        CACHE.with(|cache| cache.borrow().hits)
    }
}
