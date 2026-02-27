// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// ProxyBridge trait - bridges XRCE agent to an actual DDS implementation.
//
// This is intentionally DDS-agnostic: any DDS library can implement it.

use crate::protocol::XrceError;

/// Bridge between the XRCE agent and an actual DDS implementation.
///
/// Each method maps to an XRCE operation that the agent needs to
/// forward to the DDS layer. Implementations can target hdds, Cyclone DDS,
/// Fast-DDS, or any other compliant DDS middleware.
pub trait ProxyBridge: Send + Sync {
    /// Create a DDS DomainParticipant.
    /// Returns a unique entity handle.
    fn create_participant(&self, domain_id: u16) -> Result<u32, XrceError>;

    /// Create a DDS Topic under the given participant.
    fn create_topic(
        &self,
        participant_id: u32,
        name: &str,
        type_name: &str,
    ) -> Result<u32, XrceError>;

    /// Create a DDS DataWriter under the given participant for a topic.
    fn create_writer(
        &self,
        participant_id: u32,
        topic_id: u32,
    ) -> Result<u32, XrceError>;

    /// Create a DDS DataReader under the given participant for a topic.
    fn create_reader(
        &self,
        participant_id: u32,
        topic_id: u32,
    ) -> Result<u32, XrceError>;

    /// Write serialized data through the given writer.
    fn write_data(&self, writer_id: u32, data: &[u8]) -> Result<(), XrceError>;

    /// Read one sample from the given reader.
    /// Returns `None` if no data is available.
    fn read_data(&self, reader_id: u32) -> Result<Option<Vec<u8>>, XrceError>;

    /// Delete a DDS entity by handle.
    fn delete_entity(&self, entity_id: u32) -> Result<(), XrceError>;
}

// ---------------------------------------------------------------------------
// Null bridge (for testing)
// ---------------------------------------------------------------------------

/// A no-op bridge that always succeeds. Useful for protocol-level testing
/// without a real DDS stack.
pub struct NullBridge;

impl ProxyBridge for NullBridge {
    fn create_participant(&self, _domain_id: u16) -> Result<u32, XrceError> {
        Ok(1)
    }

    fn create_topic(
        &self,
        _participant_id: u32,
        _name: &str,
        _type_name: &str,
    ) -> Result<u32, XrceError> {
        Ok(2)
    }

    fn create_writer(
        &self,
        _participant_id: u32,
        _topic_id: u32,
    ) -> Result<u32, XrceError> {
        Ok(3)
    }

    fn create_reader(
        &self,
        _participant_id: u32,
        _topic_id: u32,
    ) -> Result<u32, XrceError> {
        Ok(4)
    }

    fn write_data(&self, _writer_id: u32, _data: &[u8]) -> Result<(), XrceError> {
        Ok(())
    }

    fn read_data(&self, _reader_id: u32) -> Result<Option<Vec<u8>>, XrceError> {
        Ok(None)
    }

    fn delete_entity(&self, _entity_id: u32) -> Result<(), XrceError> {
        Ok(())
    }
}
