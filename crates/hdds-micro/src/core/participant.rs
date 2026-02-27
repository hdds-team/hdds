// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! MicroParticipant - DDS Participant for embedded

use crate::error::Result;
use crate::rtps::{EntityId, GuidPrefix, Locator, GUID};
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
/// # Example
///
/// ```ignore
/// let mut transport = NullTransport::default();
/// let participant = MicroParticipant::new(0, transport)?;
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
    /// Create a new participant
    ///
    /// # Arguments
    ///
    /// * `domain_id` - DDS domain ID (0-232)
    /// * `transport` - Transport implementation
    pub fn new(domain_id: u32, mut transport: T) -> Result<Self> {
        // Initialize transport
        transport.init()?;

        // Generate GUID prefix from local locator
        let local_locator = transport.local_locator();
        let guid_prefix = Self::generate_guid_prefix(&local_locator);

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

    /// Generate GUID prefix from locator
    ///
    /// Uses last 12 bytes of locator (address + port) for uniqueness.
    fn generate_guid_prefix(locator: &Locator) -> GuidPrefix {
        let mut bytes = [0u8; 12];

        // Use address (16 bytes) -> take last 8 bytes
        bytes[0..8].copy_from_slice(&locator.address[8..16]);

        // Use port (4 bytes)
        let port_bytes = locator.port.to_be_bytes();
        bytes[8..12].copy_from_slice(&port_bytes);

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
        let participant = MicroParticipant::new(0, transport).unwrap();

        assert_eq!(participant.domain_id(), 0);
        assert_ne!(participant.guid_prefix(), GuidPrefix::UNKNOWN);
    }

    #[test]
    fn test_entity_id_allocation() {
        let transport = NullTransport::default();
        let mut participant = MicroParticipant::new(0, transport).unwrap();

        let writer_id = participant.allocate_entity_id(true);
        let reader_id = participant.allocate_entity_id(false);

        assert!(writer_id.is_writer());
        assert!(reader_id.is_reader());
        assert_ne!(writer_id, reader_id);
    }
}
