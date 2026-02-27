// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Header

use super::types::{GuidPrefix, ProtocolVersion, VendorId};
use crate::error::{Error, Result};

/// RTPS magic number "RTPS"
pub const RTPS_MAGIC: [u8; 4] = *b"RTPS";

/// RTPS Header (20 bytes)
///
/// ```text
/// 0...3: Magic "RTPS"
/// 4...5: Protocol version (2.5)
/// 6...7: Vendor ID
/// 8..19: GUID Prefix
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtpsHeader {
    /// Protocol version
    pub protocol_version: ProtocolVersion,
    /// Vendor ID
    pub vendor_id: VendorId,
    /// GUID prefix of sender
    pub guid_prefix: GuidPrefix,
}

impl RtpsHeader {
    /// Size of RTPS header in bytes
    pub const SIZE: usize = 20;

    /// Create a new RTPS header
    pub const fn new(
        protocol_version: ProtocolVersion,
        vendor_id: VendorId,
        guid_prefix: GuidPrefix,
    ) -> Self {
        Self {
            protocol_version,
            vendor_id,
            guid_prefix,
        }
    }

    /// Encode header to bytes (fixed 20 bytes)
    ///
    /// # Arguments
    ///
    /// * `buf` - Output buffer (must be at least 20 bytes)
    ///
    /// # Returns
    ///
    /// Number of bytes written (always 20)
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Magic "RTPS"
        buf[0..4].copy_from_slice(&RTPS_MAGIC);

        // Protocol version
        buf[4] = self.protocol_version.major;
        buf[5] = self.protocol_version.minor;

        // Vendor ID
        buf[6..8].copy_from_slice(&self.vendor_id.0);

        // GUID Prefix
        buf[8..20].copy_from_slice(self.guid_prefix.as_bytes());

        Ok(Self::SIZE)
    }

    /// Decode header from bytes
    ///
    /// # Arguments
    ///
    /// * `buf` - Input buffer (must be at least 20 bytes)
    ///
    /// # Returns
    ///
    /// Decoded header
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Verify magic
        if buf[0..4] != RTPS_MAGIC {
            return Err(Error::InvalidHeader);
        }

        // Protocol version
        let protocol_version = ProtocolVersion::new(buf[4], buf[5]);

        // Vendor ID
        let vendor_id = VendorId::new([buf[6], buf[7]]);

        // GUID Prefix
        let mut guid_prefix_bytes = [0u8; 12];
        guid_prefix_bytes.copy_from_slice(&buf[8..20]);
        let guid_prefix = GuidPrefix::new(guid_prefix_bytes);

        Ok(Self {
            protocol_version,
            vendor_id,
            guid_prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtps_header_encode_decode() {
        let header = RtpsHeader::new(
            ProtocolVersion::RTPS_2_5,
            VendorId::HDDS,
            GuidPrefix::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        );

        let mut buf = [0u8; 64];
        let written = header.encode(&mut buf).unwrap();
        assert_eq!(written, RtpsHeader::SIZE);

        // Verify magic
        assert_eq!(&buf[0..4], b"RTPS");

        // Decode
        let decoded = RtpsHeader::decode(&buf).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn test_rtps_header_invalid_magic() {
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(b"XXXX"); // Invalid magic

        let result = RtpsHeader::decode(&buf);
        assert_eq!(result, Err(Error::InvalidHeader));
    }

    #[test]
    fn test_rtps_header_buffer_too_small() {
        let header = RtpsHeader::default();
        let mut buf = [0u8; 10]; // Too small

        let result = header.encode(&mut buf);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }
}
