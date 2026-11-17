// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reusable encode buffer for the two per-sample encodes of the UDP path:
//! the wire leg of `DataWriter::write`, and the re-encode a network reader
//! does before handing a received sample to its ring.
//!
//! Encoding every sample into a fresh `vec![0u8; 65_536]` would cost one
//! 64 KiB allocation and a 64 KiB memset per sample, whatever its size. The
//! scratch here is instead allocated once per endpoint and kept **all zero at
//! rest**: the bytes an encode touched are zeroed again when the encoded
//! sample is dropped, so every encode starts from the same all-zero buffer a
//! fresh allocation would have given it. An encoder that skips padding bytes
//! instead of writing them therefore still puts zeros on the wire, never the
//! bytes of a previous sample. The zeroing costs the encoded length, not the
//! 64 KiB capacity.
//!
//! Contract relied on: an encoder that returns `Ok(len)` wrote nothing past
//! `len`; an encoder that fails may have written anywhere in the slice it was
//! given, so a failed attempt zeroes that whole slice. An encoder that writes
//! past the length it returns (scratch space at the tail, a rewound
//! speculative member) breaks the contract: the bytes past `len` stay in the
//! scratch, and a later encoder that skips padding there would emit them.
//! A fresh zeroed buffer per sample was immune to that, at 64 KiB per sample.

use crate::dds::{CdrVersion, Error, Result, DDS};
use std::sync::{Mutex, MutexGuard, TryLockError};

/// Initial encode window, as the per-write allocation it replaces.
const INITIAL_SIZE: usize = 65_536;
/// Largest buffer an encode is given, prefix included (a DATA_FRAG
/// payload is reassembled up to this size).
pub(crate) const MAX_SERIALIZED_SIZE: usize = 16 * 1024 * 1024;

enum Slot<'a> {
    /// The writer's retained scratch, all zero outside an encoded sample.
    Shared(MutexGuard<'a, Vec<u8>>),
    /// A one-off buffer, used when the scratch is held by an enclosing
    /// `write()` on the same writer (a re-entrant write from a callback).
    Owned(Vec<u8>),
}

impl Slot<'_> {
    fn buf(&mut self) -> &mut Vec<u8> {
        match self {
            Slot::Shared(g) => g,
            Slot::Owned(v) => v,
        }
    }
}

/// One encoded sample in an endpoint's scratch. Dropping it restores the
/// all-zero invariant (and releases the scratch for the next sample).
pub(crate) struct EncodedSample<'a> {
    slot: Slot<'a>,
    /// Prefix bytes reserved before the sample, plus the sample's length.
    len: usize,
    prefix: usize,
}

impl EncodedSample<'_> {
    /// The prefix followed by the serialized sample, exactly `len` bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        match &self.slot {
            Slot::Shared(g) => &g[..self.len],
            Slot::Owned(v) => &v[..self.len],
        }
    }

    /// The prefix bytes reserved before the sample (zero until written).
    pub(crate) fn prefix_mut(&mut self) -> &mut [u8] {
        let prefix = self.prefix;
        &mut self.slot.buf()[..prefix]
    }
}

impl Drop for EncodedSample<'_> {
    fn drop(&mut self) {
        if let Slot::Shared(g) = &mut self.slot {
            let n = self.len.min(g.len());
            g[..n].fill(0);
        }
    }
}

/// Encode `msg` at `version` into `scratch` (or into a one-off buffer when
/// the scratch is already held, e.g. by an enclosing write on the same
/// writer), growing geometrically on `BufferTooSmall` up to
/// [`MAX_SERIALIZED_SIZE`].
pub(crate) fn encode_into<'a, T: DDS>(
    scratch: &'a Mutex<Vec<u8>>,
    msg: &T,
    version: CdrVersion,
) -> Result<EncodedSample<'a>> {
    encode_into_after(scratch, 0, msg, version)
}

/// [`encode_into`] after `prefix` bytes left zero for the caller to fill
/// (see [`EncodedSample::prefix_mut`]); `bytes()` then covers the prefix
/// and the sample.
pub(crate) fn encode_into_after<'a, T: DDS>(
    scratch: &'a Mutex<Vec<u8>>,
    prefix: usize,
    msg: &T,
    version: CdrVersion,
) -> Result<EncodedSample<'a>> {
    let mut slot = match scratch.try_lock() {
        Ok(g) => Slot::Shared(g),
        // A panic while the scratch was held may have left encoded bytes in
        // it: forget them (`clear` keeps the capacity; `resize` below zeroes
        // whatever it hands out again).
        Err(TryLockError::Poisoned(p)) => {
            let mut g = p.into_inner();
            g.clear();
            // Cleared: the invariant holds again, so the next sample need
            // not re-zero 64 KiB through this branch.
            scratch.clear_poison();
            Slot::Shared(g)
        }
        Err(TryLockError::WouldBlock) => Slot::Owned(Vec::new()),
    };
    let buf = slot.buf();
    // An opaque reader's retained key header must not reduce the payload
    // size accepted before capture. The header is not serialized user data.
    let max_size = MAX_SERIALIZED_SIZE + if T::captures_wire_identity() { 16 } else { 0 };
    let mut size = buf.len().clamp(INITIAL_SIZE, max_size);
    let len = loop {
        if buf.len() < size {
            buf.resize(size, 0);
        }
        match msg.encode(&mut buf[prefix..size], version) {
            // An encoder claiming more bytes than it was given is broken:
            // refuse the sample rather than ship a truncated one.
            Ok(len) if len > size - prefix => {
                buf[..size].fill(0);
                return Err(Error::SerializationError);
            }
            Ok(len) => break prefix + len,
            Err(e) => {
                buf[..size].fill(0);
                match e {
                    Error::BufferTooSmall if size < max_size => {
                        size = (size * 2).min(max_size);
                    }
                    e => return Err(e),
                }
            }
        }
    };
    Ok(EncodedSample { slot, len, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `n` bytes of 0xAB at the start, skips `gap` bytes WITHOUT
    /// writing them (an encoder that relies on a zeroed buffer for
    /// padding), then writes one 0xCD byte.
    struct Gappy {
        n: usize,
        gap: usize,
    }

    impl DDS for Gappy {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            unimplemented!("not used by encode_into")
        }
        fn encode(&self, buf: &mut [u8], _v: CdrVersion) -> Result<usize> {
            let total = self.n + self.gap + 1;
            if buf.len() < total {
                // Scribble before failing, as a partial encode would.
                buf.fill(0xEE);
                return Err(Error::BufferTooSmall);
            }
            buf[..self.n].fill(0xAB);
            buf[self.n + self.gap] = 0xCD;
            Ok(total)
        }
        fn decode(_buf: &[u8], _v: CdrVersion) -> Result<Self> {
            unimplemented!("not used by encode_into")
        }
    }

    #[test]
    fn skipped_bytes_are_zero_not_the_previous_sample() {
        let scratch = Mutex::new(Vec::new());
        {
            let s = encode_into(&scratch, &Gappy { n: 40, gap: 0 }, CdrVersion::Xcdr2).unwrap();
            assert_eq!(s.bytes().len(), 41);
        }
        let s = encode_into(&scratch, &Gappy { n: 4, gap: 30 }, CdrVersion::Xcdr2).unwrap();
        let b = s.bytes();
        assert_eq!(b.len(), 35);
        assert!(b[..4].iter().all(|&x| x == 0xAB));
        assert!(
            b[4..34].iter().all(|&x| x == 0),
            "stale bytes leaked: {:?}",
            &b[4..34]
        );
        assert_eq!(b[34], 0xCD);
    }

    #[test]
    fn scratch_is_all_zero_after_each_sample_including_growth_failures() {
        let scratch = Mutex::new(Vec::new());
        // Needs two doublings: the failed attempts scribble 0xEE everywhere.
        let big = Gappy { n: 200_000, gap: 0 };
        {
            let s = encode_into(&scratch, &big, CdrVersion::Xcdr2).unwrap();
            assert_eq!(s.bytes().len(), 200_001);
        }
        let g = scratch.lock().unwrap();
        assert_eq!(g.len(), 4 * INITIAL_SIZE);
        assert!(g.iter().all(|&x| x == 0));
    }

    #[test]
    fn a_held_scratch_falls_back_to_a_one_off_buffer() {
        let scratch = Mutex::new(Vec::new());
        let outer = encode_into(&scratch, &Gappy { n: 8, gap: 0 }, CdrVersion::Xcdr2).unwrap();
        let inner = encode_into(&scratch, &Gappy { n: 2, gap: 3 }, CdrVersion::Xcdr2).unwrap();
        assert_eq!(inner.bytes(), &[0xAB, 0xAB, 0, 0, 0, 0xCD]);
        assert_eq!(outer.bytes().len(), 9);
    }

    #[test]
    fn a_prefix_is_zero_writable_and_cleared_with_the_sample() {
        let scratch = Mutex::new(Vec::new());
        {
            let mut s = encode_into_after(&scratch, 16, &Gappy { n: 3, gap: 1 }, CdrVersion::Xcdr2)
                .unwrap();
            assert!(s.prefix_mut().iter().all(|&x| x == 0));
            s.prefix_mut().fill(0x11);
            assert_eq!(s.bytes().len(), 16 + 5);
            assert!(s.bytes()[..16].iter().all(|&x| x == 0x11));
            assert_eq!(&s.bytes()[16..], &[0xAB, 0xAB, 0xAB, 0, 0xCD]);
        }
        let g = scratch.lock().unwrap();
        assert!(g.iter().all(|&x| x == 0));
    }

    /// Claims one byte more than the slice it was given.
    struct Liar;

    impl DDS for Liar {
        fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
            unimplemented!("not used by encode_into")
        }
        fn encode(&self, buf: &mut [u8], _v: CdrVersion) -> Result<usize> {
            buf[..4].fill(0x77);
            Ok(buf.len() + 1)
        }
        fn decode(_buf: &[u8], _v: CdrVersion) -> Result<Self> {
            unimplemented!("not used by encode_into")
        }
    }

    #[test]
    fn an_encoder_claiming_more_than_its_slice_is_refused() {
        let scratch = Mutex::new(Vec::new());
        let r = encode_into(&scratch, &Liar, CdrVersion::Xcdr2);
        assert!(matches!(r, Err(Error::SerializationError)));
        assert!(scratch.lock().unwrap().iter().all(|&x| x == 0));
    }

    #[test]
    fn a_poisoned_scratch_is_cleared_and_unpoisoned() {
        let scratch = Mutex::new(vec![0x5Au8; 8]);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = scratch.lock().unwrap();
            panic!("poison it");
        }));
        assert!(scratch.is_poisoned());
        {
            let s = encode_into(&scratch, &Gappy { n: 2, gap: 6 }, CdrVersion::Xcdr2).unwrap();
            assert_eq!(s.bytes(), &[0xAB, 0xAB, 0, 0, 0, 0, 0, 0, 0xCD]);
        }
        assert!(!scratch.is_poisoned());
    }

    #[test]
    fn an_oversized_sample_is_refused_and_leaves_the_scratch_zero() {
        let scratch = Mutex::new(Vec::new());
        let r = encode_into(
            &scratch,
            &Gappy {
                n: MAX_SERIALIZED_SIZE,
                gap: 0,
            },
            CdrVersion::Xcdr2,
        );
        assert!(matches!(r, Err(Error::BufferTooSmall)));
        let g = scratch.lock().unwrap();
        assert!(g.iter().all(|&x| x == 0));
    }
}
