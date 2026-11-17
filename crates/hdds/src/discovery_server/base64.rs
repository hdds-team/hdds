// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Base64 (RFC 4648 section 4, standard alphabet, padded) for the Discovery
//! Server relay frame.
//!
//! # Why this exists rather than the `base64` crate
//!
//! `discovery_server` is in the DEFAULT build of this crate, while the
//! `base64` dependency is gated behind the `security` feature. Making it
//! unconditional would add a permanent dependency to the core library for one
//! field of one message, which is a cost the certification surface pays
//! forever. The server side of the protocol does use the real crate, so every
//! byte this module produces is checked against a reference implementation
//! (see the conformance tests at the bottom of this file) rather than against
//! our own idea of base64.
//!
//! # Why base64 and not the alternative encodings
//!
//! The relay payload is a whole RTPS message, and the protocol carries it in
//! JSON. Measured on a 1400-byte payload:
//!
//! | encoding                     | random data | RTPS-like data |
//! |------------------------------|-------------|----------------|
//! | `Vec<u8>` as a JSON array    | x3.62       | x2.43          |
//! | serde's `serialize_bytes`    | x3.57       | x2.38          |
//! | hex string                   | x2.00       | x2.00          |
//! | base64 string                | x1.33       | x1.33          |
//!
//! `serialize_bytes` (what `serde_bytes` gives you) is NOT a fix: `serde_json`
//! writes bytes as an array of decimal numbers whichever way you ask, so the
//! gain is 1.3%.
//!
//! Size is not even the main argument. A decimal array expands by an amount
//! that depends on the DATA, so the frame size cannot be derived from the
//! payload size and `max_message_size` bounds an unknowable payload. Base64
//! expands by a constant, so the frame size is a pure function of the payload
//! size.
//!
//! # Strictness
//!
//! Decoding rejects a non-canonical encoding: a wrong length, padding
//! anywhere but at the end, and a final quantum whose unused bits are not
//! zero. Accepting those would mean two different strings decode to the same
//! bytes, and a relay is exactly the place where a byte sequence with two
//! spellings is worth refusing. The reference implementation makes the same
//! choice, which is what lets the conformance tests compare the two directly.

use std::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

/// Encode bytes as standard, padded base64.
pub(super) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let quantum = (b0 << 16) | (b1 << 8) | b2;

        out.push(char::from(ALPHABET[(quantum >> 18) as usize & 0x3f]));
        out.push(char::from(ALPHABET[(quantum >> 12) as usize & 0x3f]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(quantum >> 6) as usize & 0x3f])
        } else {
            char::from(PAD)
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[quantum as usize & 0x3f])
        } else {
            char::from(PAD)
        });
    }

    out
}

/// Decode standard, padded base64. Rejects any non-canonical spelling.
pub(super) fn decode(text: &str) -> Result<Vec<u8>, Base64Error> {
    let input = text.as_bytes();

    if !input.len().is_multiple_of(4) {
        return Err(Base64Error::Length {
            length: input.len(),
        });
    }
    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Padding lives in the last quantum only, and only at its end. A pad in
    // either of the first two symbols is a padding fault, not an alphabet
    // fault: saying "'=' is outside the alphabet" would be true and useless.
    let last = &input[input.len() - 4..];
    if last[0] == PAD || last[1] == PAD {
        return Err(Base64Error::Padding);
    }
    let padding = match (last[2] == PAD, last[3] == PAD) {
        (false, false) => 0,
        (false, true) => 1,
        (true, true) => 2,
        // "=X": a pad is never followed by data.
        (true, false) => return Err(Base64Error::Padding),
    };
    if input[..input.len() - 4].contains(&PAD) {
        return Err(Base64Error::Padding);
    }

    let quanta = input.len() / 4;
    let mut out = Vec::with_capacity(quanta * 3 - padding);

    for (index, quantum) in input.chunks(4).enumerate() {
        let significant = if index == quanta - 1 { 4 - padding } else { 4 };

        let mut accumulator = 0u32;
        for &symbol in &quantum[..significant] {
            let value = value_of(symbol).ok_or(Base64Error::Symbol {
                symbol: char::from(symbol),
            })?;
            accumulator = (accumulator << 6) | u32::from(value);
        }
        // Left-align to 24 bits, so a padded quantum sits where an unpadded
        // one would and the bits the encoder never wrote end up at the
        // bottom.
        accumulator <<= 6 * (4 - significant);

        // `significant` symbols carry `significant - 1` whole bytes; the
        // 24 - 8 * (significant - 1) low bits are the ones a canonical
        // encoder leaves at zero. A non-zero value there means these bytes
        // have a second spelling, which is the one thing a relay must not
        // accept.
        let emitted = significant - 1;
        let unused = 24 - 8 * emitted;
        if unused > 0 && accumulator & ((1u32 << unused) - 1) != 0 {
            return Err(Base64Error::NonCanonical);
        }

        // The quantum is 24 bits by construction (four 6-bit symbols), so
        // the top byte of the u32 is always zero and the three we want are
        // its big-endian tail. Naming them beats three shift-and-truncate
        // casts: the truncation WAS the operation, but nothing in `as u8`
        // says so, and a reader has to re-derive the widths to be sure.
        let [_always_zero, first, second, third] = accumulator.to_be_bytes();
        out.push(first);
        if emitted > 1 {
            out.push(second);
        }
        if emitted > 2 {
            out.push(third);
        }
    }

    Ok(out)
}

fn value_of(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Why a base64 string was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Base64Error {
    /// Not a whole number of 4-symbol quanta.
    Length { length: usize },
    /// Padding somewhere other than the end of the last quantum.
    Padding,
    /// A symbol outside the standard alphabet.
    Symbol { symbol: char },
    /// A final quantum whose unused bits are not zero: the same bytes would
    /// have more than one spelling.
    NonCanonical,
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { length } => {
                write!(f, "base64 length {} is not a multiple of 4", length)
            }
            Self::Padding => write!(f, "base64 padding is not at the end"),
            Self::Symbol { symbol } => {
                write!(f, "base64 symbol {:?} is outside the alphabet", symbol)
            }
            Self::NonCanonical => write!(f, "base64 final quantum has non-zero unused bits"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic byte source, so a failure is reproducible.
    fn pseudo_random(length: usize) -> Vec<u8> {
        let mut state = 0x12345678u32;
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1103515245).wrapping_add(12345);
                (state >> 16) as u8
            })
            .collect()
    }

    #[test]
    fn rfc4648_test_vectors() {
        // RFC 4648 section 10, verbatim. A fixture from the SPEC, not from
        // our own encoder.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encoding {:?}", plain);
            assert_eq!(
                decode(encoded).expect("decode a spec vector"),
                plain.as_bytes(),
                "decoding {:?}",
                encoded
            );
        }
    }

    #[test]
    fn round_trips_at_every_length_modulo_three() {
        for length in 0..=96 {
            let original = pseudo_random(length);
            let encoded = encode(&original);
            assert!(
                encoded.len().is_multiple_of(4),
                "length {} encoded to {} symbols",
                length,
                encoded.len()
            );
            assert_eq!(
                decode(&encoded).expect("decode our own output"),
                original,
                "round trip at length {}",
                length
            );
        }
    }

    #[test]
    fn a_full_relay_payload_round_trips() {
        let original = pseudo_random(1400);
        let encoded = encode(&original);
        // The constant expansion is the reason this encoding was chosen:
        // frame size must be a function of payload size alone.
        assert_eq!(encoded.len(), 1400usize.div_ceil(3) * 4);
        assert_eq!(decode(&encoded).expect("decode 1400 bytes"), original);
    }

    /// Conformance against a reference implementation.
    ///
    /// A round trip through our own code only proves this module agrees with
    /// itself, which is the cheapest kind of agreement. The `base64` crate is
    /// a dev-dependency for exactly this: a foreign oracle that decides what
    /// the bytes on the wire are. The server side of this protocol uses that
    /// crate in production, so this is also the test that keeps the two ends
    /// of the relay speaking the same language.
    #[test]
    fn agrees_with_the_reference_implementation() {
        use ::base64::Engine as _;
        let reference = ::base64::engine::general_purpose::STANDARD;

        for length in 0..=256 {
            let original = pseudo_random(length);
            let theirs = reference.encode(&original);

            assert_eq!(
                encode(&original),
                theirs,
                "our encoding differs from the reference at length {}",
                length
            );
            assert_eq!(
                decode(&theirs).expect("decode the reference output"),
                original,
                "our decoder disagrees with the reference at length {}",
                length
            );
        }
    }

    /// Strictness is not our invention: the reference refuses the same
    /// second spellings. If this ever fails, the disagreement is a wire
    /// incompatibility between the two ends of the relay, not a style
    /// difference.
    #[test]
    fn the_reference_also_refuses_a_non_canonical_quantum() {
        use ::base64::Engine as _;
        let reference = ::base64::engine::general_purpose::STANDARD;

        // Each of these decodes to the same bytes as a canonical form:
        // "Zg==" is b"f" and "Zm9vYmE=" is b"fooba". The unused bits of the
        // final quantum are the difference, and nothing else.
        for second_spelling in ["Zh==", "Zi==", "Zx==", "Zm9vYmF=", "Zm9vYmH="] {
            assert!(
                reference.decode(second_spelling).is_err(),
                "the reference accepts {:?}, so our refusal would break the wire",
                second_spelling
            );
            assert!(
                decode(second_spelling).is_err(),
                "we accept {:?} while the reference refuses it",
                second_spelling
            );
        }
    }

    #[test]
    fn a_wrong_length_is_refused() {
        for bad in ["Z", "Zg", "Zm9", "Zm9vY"] {
            assert!(
                matches!(decode(bad), Err(Base64Error::Length { .. })),
                "{:?} must be refused for its length",
                bad
            );
        }
    }

    #[test]
    fn a_symbol_outside_the_alphabet_is_refused() {
        // '-' and '_' are the URL-safe alphabet: a near miss, which is
        // exactly the kind that gets accepted by accident.
        for bad in ["Zm9-", "Zm9_", "Zm9 ", "Zm9\n"] {
            assert!(
                matches!(decode(bad), Err(Base64Error::Symbol { .. })),
                "{:?} must be refused for its alphabet",
                bad
            );
        }
    }

    #[test]
    fn padding_away_from_the_end_is_refused() {
        for bad in ["Zg==Zg==", "Z=g=", "===="] {
            assert!(
                matches!(decode(bad), Err(Base64Error::Padding)),
                "{:?} must be refused for its padding",
                bad
            );
        }
    }

    #[test]
    fn a_non_canonical_final_quantum_is_refused() {
        // "Zg==" is `b"f"`. The last symbol carries 4 unused bits; any other
        // value for it decodes to the same byte, so it is a second spelling
        // of the same payload and must not be accepted.
        assert_eq!(decode("Zg==").expect("the canonical form"), b"f");
        for second_spelling in ["Zh==", "Zi==", "Zj==", "Zx=="] {
            assert_eq!(
                decode(second_spelling),
                Err(Base64Error::NonCanonical),
                "{:?} decodes to the same byte as the canonical Zg== and must be refused",
                second_spelling
            );
        }
    }
}
