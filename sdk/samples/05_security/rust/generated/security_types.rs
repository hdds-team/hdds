// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Security Sample Types - Generated types for security samples
//
// Message types used by authentication, access control, encryption,
// and secure discovery samples.

/// Secure message with authentication metadata
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecureMessage {
    pub sender_id: String,
    pub payload: String,
    pub sequence: u32,
}

impl SecureMessage {
    /// Create a new SecureMessage
    pub fn new(sender_id: impl Into<String>, payload: impl Into<String>, sequence: u32) -> Self {
        Self {
            sender_id: sender_id.into(),
            payload: payload.into(),
            sequence,
        }
    }

    /// Serialize to CDR buffer
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(128);

        // Write sender_id string
        let str_bytes = self.sender_id.as_bytes();
        let str_len = (str_bytes.len() + 1) as u32;
        buffer.extend_from_slice(&str_len.to_le_bytes());
        buffer.extend_from_slice(str_bytes);
        buffer.push(0);

        // Align to 4 bytes
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }

        // Write payload string
        let payload_bytes = self.payload.as_bytes();
        let payload_len = (payload_bytes.len() + 1) as u32;
        buffer.extend_from_slice(&payload_len.to_le_bytes());
        buffer.extend_from_slice(payload_bytes);
        buffer.push(0);

        // Align to 4 bytes
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }

        // Write sequence
        buffer.extend_from_slice(&self.sequence.to_le_bytes());

        buffer
    }

    /// Deserialize from CDR buffer
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 12 {
            return Err("Buffer too small");
        }

        let mut offset = 0;

        // Read sender_id
        let str_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + str_len > data.len() {
            return Err("Invalid sender_id length");
        }

        let sender_id = String::from_utf8_lossy(&data[offset..offset + str_len - 1]).into_owned();
        offset += str_len;

        // Align to 4 bytes
        while offset % 4 != 0 {
            offset += 1;
        }

        // Read payload
        if offset + 4 > data.len() {
            return Err("Buffer too small for payload length");
        }
        let payload_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + payload_len > data.len() {
            return Err("Invalid payload length");
        }

        let payload = String::from_utf8_lossy(&data[offset..offset + payload_len - 1]).into_owned();
        offset += payload_len;

        // Align to 4 bytes
        while offset % 4 != 0 {
            offset += 1;
        }

        // Read sequence
        if offset + 4 > data.len() {
            return Err("Buffer too small for sequence");
        }
        let sequence = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        Ok((Self { sender_id, payload, sequence }, offset))
    }
}

/// Sensor data message for access control samples
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SensorData {
    pub sensor_id: String,
    pub value: f64,
    pub timestamp: u64,
}

impl SensorData {
    /// Create new SensorData
    pub fn new(sensor_id: impl Into<String>, value: f64, timestamp: u64) -> Self {
        Self {
            sensor_id: sensor_id.into(),
            value,
            timestamp,
        }
    }

    /// Serialize to CDR buffer
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(64);

        // Write sensor_id string
        let str_bytes = self.sensor_id.as_bytes();
        let str_len = (str_bytes.len() + 1) as u32;
        buffer.extend_from_slice(&str_len.to_le_bytes());
        buffer.extend_from_slice(str_bytes);
        buffer.push(0);

        // Align to 8 bytes for f64
        while buffer.len() % 8 != 0 {
            buffer.push(0);
        }

        // Write value (f64)
        buffer.extend_from_slice(&self.value.to_le_bytes());

        // Write timestamp (u64)
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());

        buffer
    }

    /// Deserialize from CDR buffer
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 20 {
            return Err("Buffer too small");
        }

        let mut offset = 0;

        // Read sensor_id
        let str_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + str_len > data.len() {
            return Err("Invalid sensor_id length");
        }

        let sensor_id = String::from_utf8_lossy(&data[offset..offset + str_len - 1]).into_owned();
        offset += str_len;

        // Align to 8 bytes
        while offset % 8 != 0 {
            offset += 1;
        }

        if offset + 16 > data.len() {
            return Err("Buffer too small for value and timestamp");
        }

        // Read value (f64)
        let value = f64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        // Read timestamp (u64)
        let timestamp = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);
        offset += 8;

        Ok((Self { sensor_id, value, timestamp }, offset))
    }
}

/// Discovery announcement message
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiscoveryAnnouncement {
    pub participant_name: String,
    pub domain_id: u32,
    pub capabilities: String,
}

impl DiscoveryAnnouncement {
    /// Create new DiscoveryAnnouncement
    pub fn new(participant_name: impl Into<String>, domain_id: u32, capabilities: impl Into<String>) -> Self {
        Self {
            participant_name: participant_name.into(),
            domain_id,
            capabilities: capabilities.into(),
        }
    }

    /// Serialize to CDR buffer
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(128);

        // Write participant_name string
        let str_bytes = self.participant_name.as_bytes();
        let str_len = (str_bytes.len() + 1) as u32;
        buffer.extend_from_slice(&str_len.to_le_bytes());
        buffer.extend_from_slice(str_bytes);
        buffer.push(0);

        // Align to 4 bytes
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }

        // Write domain_id
        buffer.extend_from_slice(&self.domain_id.to_le_bytes());

        // Write capabilities string
        let cap_bytes = self.capabilities.as_bytes();
        let cap_len = (cap_bytes.len() + 1) as u32;
        buffer.extend_from_slice(&cap_len.to_le_bytes());
        buffer.extend_from_slice(cap_bytes);
        buffer.push(0);

        // Align to 4 bytes
        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }

        buffer
    }

    /// Deserialize from CDR buffer
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 16 {
            return Err("Buffer too small");
        }

        let mut offset = 0;

        // Read participant_name
        let str_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + str_len > data.len() {
            return Err("Invalid participant_name length");
        }

        let participant_name = String::from_utf8_lossy(&data[offset..offset + str_len - 1]).into_owned();
        offset += str_len;

        // Align to 4 bytes
        while offset % 4 != 0 {
            offset += 1;
        }

        if offset + 4 > data.len() {
            return Err("Buffer too small for domain_id");
        }

        // Read domain_id
        let domain_id = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]);
        offset += 4;

        // Read capabilities
        if offset + 4 > data.len() {
            return Err("Buffer too small for capabilities length");
        }
        let cap_len = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
        ]) as usize;
        offset += 4;

        if offset + cap_len > data.len() {
            return Err("Invalid capabilities length");
        }

        let capabilities = String::from_utf8_lossy(&data[offset..offset + cap_len - 1]).into_owned();
        offset += cap_len;

        // Align to 4 bytes
        while offset % 4 != 0 {
            offset += 1;
        }

        Ok((Self { participant_name, domain_id, capabilities }, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_message_roundtrip() {
        let original = SecureMessage::new("sender1", "Hello secure world!", 42);
        let serialized = original.serialize();
        let (deserialized, _) = SecureMessage::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_sensor_data_roundtrip() {
        let original = SensorData::new("temp_sensor_01", 23.5, 1234567890);
        let serialized = original.serialize();
        let (deserialized, _) = SensorData::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_discovery_announcement_roundtrip() {
        let original = DiscoveryAnnouncement::new("SecureNode", 0, "auth,encrypt");
        let serialized = original.serialize();
        let (deserialized, _) = DiscoveryAnnouncement::deserialize(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}
