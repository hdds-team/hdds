// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MicroParticipant - DDS Participant for embedded

use crate::error::Result;
use crate::rtps::{EntityId, GuidPrefix, Locator, VendorId, GUID};
use crate::transport::Transport;

/// MicroParticipant - DDS Participant
///
/// Represents a DDS participant on an embedded device.
///
/// # Design
///
/// - Single-threaded (no async, no locks)
/// - Fixed number of readers/writers (compile-time limit)
/// - BEST_EFFORT QoS only (no reliability, no history)
///
/// # GUID prefix
///
/// RTPS 2.5 9.3.1.5: the first two octets of the prefix are the vendor id
/// (HDDS, `0x011A`), and the prefix must be unique in the domain
/// (8.2.4.2). The other ten octets are:
///
/// ```text
/// [0..2]   vendor id          0x01 0x1A
/// [2..6]   host               last four octets of the transport's local
///                             locator address (the IPv4 address, or a
///                             radio node id)
/// [6..8]   port               low 16 bits of the local locator port,
///                             big endian
/// [8..12]  instance           the caller's per-boot value, big endian
/// ```
///
/// This crate has no source of entropy or time of its own: it is `no_std`
/// with no dependency, and the targets it serves differ in what they have
/// (a hardware RNG on ESP32 and STM32, the ring oscillator on RP2040, a
/// boot counter in flash, an RTC). The value that makes a restarted device
/// differ from its previous life therefore comes from the caller, through
/// [`MicroParticipant::with_instance`]. Without it a device that reboots
/// comes back under the GUID of its predecessor, and a peer that still
/// remembers that GUID takes the new sequence numbers for duplicates.
///
/// # Example
///
/// ```ignore
/// let mut transport = NullTransport::default();
/// let participant = MicroParticipant::with_instance(0, transport, boot_entropy)?;
/// ```
pub struct MicroParticipant<T: Transport> {
    /// Domain ID
    domain_id: u32,

    /// GUID prefix
    guid_prefix: GuidPrefix,

    /// Transport
    transport: T,

    /// Next entity ID counter (for creating readers/writers)
    next_entity_id: u32,
}

impl<T: Transport> MicroParticipant<T> {
    /// Create a new participant with instance value 0
    ///
    /// The GUID prefix is the same at every boot of a device (see the type
    /// documentation). Use [`MicroParticipant::with_instance`] with a value
    /// that differs from one boot to the next.
    ///
    /// # Arguments
    ///
    /// * `domain_id` - DDS domain ID (0-232)
    /// * `transport` - Transport implementation
    #[deprecated(
        note = "the GUID prefix repeats across reboots; use `with_instance` with a per-boot value"
    )]
    pub fn new(domain_id: u32, transport: T) -> Result<Self> {
        Self::with_instance(domain_id, transport, 0)
    }

    /// Create a new participant
    ///
    /// # Arguments
    ///
    /// * `domain_id` - DDS domain ID (0-232)
    /// * `transport` - Transport implementation
    /// * `instance` - A value that differs from one boot of the device to
    ///   the next: a hardware random number, a boot counter kept in
    ///   non-volatile memory, or a clock reading. It fills the last four
    ///   octets of the GUID prefix.
    pub fn with_instance(domain_id: u32, mut transport: T, instance: u32) -> Result<Self> {
        // Initialize transport
        transport.init()?;

        let local_locator = transport.local_locator();
        let guid_prefix = Self::generate_guid_prefix(&local_locator, instance);

        Ok(Self {
            domain_id,
            guid_prefix,
            transport,
            next_entity_id: 1, // Start at 1 (0 is reserved)
        })
    }

    /// Get domain ID
    pub const fn domain_id(&self) -> u32 {
        self.domain_id
    }

    /// Get GUID prefix
    pub const fn guid_prefix(&self) -> GuidPrefix {
        self.guid_prefix
    }

    /// Get GUID
    pub const fn guid(&self) -> GUID {
        GUID::new(self.guid_prefix, EntityId::PARTICIPANT)
    }

    /// Get local locator
    pub fn local_locator(&self) -> Locator {
        self.transport.local_locator()
    }

    /// Allocate next entity ID
    pub fn allocate_entity_id(&mut self, is_writer: bool) -> EntityId {
        let entity_key = self.next_entity_id;
        self.next_entity_id += 1;

        // Build entity ID (simplified)
        let kind = if is_writer { 0xc2 } else { 0xc7 }; // Writer or Reader

        EntityId::new([
            ((entity_key >> 16) & 0xff) as u8,
            ((entity_key >> 8) & 0xff) as u8,
            (entity_key & 0xff) as u8,
            kind,
        ])
    }

    /// Get transport (mutable)
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Get transport (immutable)
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Shutdown participant
    pub fn shutdown(mut self) -> Result<()> {
        self.transport.shutdown()
    }

    /// The GUID prefix: vendor id, host, port, instance (see the type
    /// documentation).
    fn generate_guid_prefix(locator: &Locator, instance: u32) -> GuidPrefix {
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&VendorId::HDDS.0);
        bytes[2..6].copy_from_slice(&locator.address[12..16]);
        bytes[6..8].copy_from_slice(&locator.port.to_be_bytes()[2..4]);
        bytes[8..12].copy_from_slice(&instance.to_be_bytes());
        GuidPrefix::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::NullTransport;

    #[test]
    fn test_participant_creation() {
        let transport = NullTransport::default();
        let participant = MicroParticipant::with_instance(0, transport, 1).unwrap();

        assert_eq!(participant.domain_id(), 0);
        assert_ne!(participant.guid_prefix(), GuidPrefix::UNKNOWN);
    }

    #[test]
    fn test_entity_id_allocation() {
        let transport = NullTransport::default();
        let mut participant = MicroParticipant::with_instance(0, transport, 1).unwrap();

        let writer_id = participant.allocate_entity_id(true);
        let reader_id = participant.allocate_entity_id(false);

        assert!(writer_id.is_writer());
        assert!(reader_id.is_reader());
        assert_ne!(writer_id, reader_id);
    }

    fn prefix_of(address: [u8; 4], port: u16, instance: u32) -> [u8; 12] {
        let transport = NullTransport::new(Locator::udpv4(address, port));
        MicroParticipant::with_instance(0, transport, instance)
            .unwrap()
            .guid_prefix()
            .0
    }

    /// RTPS 2.5 9.3.1.5: "guidPrefix[0] = vendorId[0] guidPrefix[1] =
    /// vendorId[1]". The rest is host, port and instance, in that order.
    #[test]
    fn the_prefix_starts_with_the_hdds_vendor_id() {
        let prefix = prefix_of([192, 168, 1, 50], 7410, 0xA1B2_C3D4);
        assert_eq!(
            prefix,
            [0x01, 0x1A, 192, 168, 1, 50, 0x1C, 0xF2, 0xA1, 0xB2, 0xC3, 0xD4]
        );
        assert_eq!(&prefix[0..2], &VendorId::HDDS.0);
    }

    /// The same device on the same address and port differs from one boot
    /// to the next by its instance value; two devices differ by host, two
    /// participants of one device by port.
    #[test]
    fn each_input_reaches_its_own_octets() {
        let base = prefix_of([10, 0, 0, 1], 7400, 1);
        assert_ne!(base, prefix_of([10, 0, 0, 1], 7400, 2));
        assert_ne!(base, prefix_of([10, 0, 0, 2], 7400, 1));
        assert_ne!(base, prefix_of([10, 0, 0, 1], 7401, 1));
    }

    #[test]
    #[allow(deprecated)]
    fn new_is_with_instance_zero() {
        let a = MicroParticipant::new(0, NullTransport::default()).unwrap();
        let b = MicroParticipant::with_instance(0, NullTransport::default(), 0).unwrap();
        assert_eq!(a.guid_prefix(), b.guid_prefix());
        assert_eq!(&a.guid_prefix().0[0..2], &[0x01, 0x1A]);
    }
}
