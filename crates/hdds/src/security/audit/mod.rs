// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Logging Plugin for DDS Security v1.1
//!
//! Provides audit trail for security events per DDS Security spec Sec.8.6.

use crate::security::SecurityError;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Security event types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEvent {
    Authentication {
        participant_guid: [u8; 16],
        outcome: AuthenticationOutcome,
        timestamp: u64,
    },
    AccessControl {
        participant_guid: [u8; 16],
        action: String,
        resource: String,
        outcome: AccessOutcome,
        timestamp: u64,
    },
    Crypto {
        key_id: u64,
        operation: String,
        outcome: CryptoOutcome,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationOutcome {
    Success,
    Failed,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOutcome {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOutcome {
    Success,
    Failed,
}

/// Logging Plugin implementing DDS Security v1.1 Sec.8.6
pub struct LoggingPlugin {
    file: Option<File>,
    previous_hash: [u8; 32],
}

impl LoggingPlugin {
    /// Create logging plugin with file backend
    pub fn with_file<P: AsRef<Path>>(path: P) -> Result<Self, SecurityError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                SecurityError::ConfigError(format!("Failed to open audit log file: {}", e))
            })?;

        Ok(Self {
            file: Some(file),
            previous_hash: [0u8; 32],
        })
    }

    /// Create logging plugin without file (in-memory only)
    pub fn new() -> Self {
        Self {
            file: None,
            previous_hash: [0u8; 32],
        }
    }

    /// Log a security event
    pub fn log_event(&mut self, event: &SecurityEvent) -> Result<(), SecurityError> {
        let json = format!("{:?}\n", event);

        // Compute hash-chain (ANSSI compliance)
        let current_hash = self.compute_hash(&json);
        self.previous_hash = current_hash;

        if let Some(ref mut file) = self.file {
            file.write_all(json.as_bytes()).map_err(|e| {
                SecurityError::ConfigError(format!("Failed to write audit log: {}", e))
            })?;
            file.sync_all().map_err(|e| {
                SecurityError::ConfigError(format!("Failed to sync audit log: {}", e))
            })?;
        }

        Ok(())
    }

    /// Compute SHA-256 hash for hash-chain
    fn compute_hash(&self, data: &str) -> [u8; 32] {
        use ring::digest::{digest, SHA256};

        let mut input = Vec::new();
        input.extend_from_slice(&self.previous_hash);
        input.extend_from_slice(data.as_bytes());

        let hash = digest(&SHA256, &input);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_ref());
        result
    }

    /// Get previous hash (for tamper detection)
    pub fn get_previous_hash(&self) -> [u8; 32] {
        self.previous_hash
    }
}

impl Default for LoggingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_log_authentication_event() {
        let mut plugin = LoggingPlugin::new();

        let event = SecurityEvent::Authentication {
            participant_guid: [0x42; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 1234567890,
        };

        assert!(plugin.log_event(&event).is_ok());
    }

    #[test]
    fn test_log_access_control_event() {
        let mut plugin = LoggingPlugin::new();

        let event = SecurityEvent::AccessControl {
            participant_guid: [0x42; 16],
            action: "create_writer".to_string(),
            resource: "sensor/temperature".to_string(),
            outcome: AccessOutcome::Allowed,
            timestamp: 1234567890,
        };

        assert!(plugin.log_event(&event).is_ok());
    }

    #[test]
    fn test_log_crypto_event() {
        let mut plugin = LoggingPlugin::new();

        let event = SecurityEvent::Crypto {
            key_id: 42,
            operation: "encrypt".to_string(),
            outcome: CryptoOutcome::Success,
            timestamp: 1234567890,
        };

        assert!(plugin.log_event(&event).is_ok());
    }

    #[test]
    fn test_log_to_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let mut plugin = LoggingPlugin::with_file(&path).unwrap();

        let event = SecurityEvent::Authentication {
            participant_guid: [0x42; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 1234567890,
        };

        plugin.log_event(&event).unwrap();

        // Verify file was written
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("Authentication"));
        assert!(contents.contains("Success"));
    }

    #[test]
    fn test_hash_chain() {
        let mut plugin = LoggingPlugin::new();

        let event1 = SecurityEvent::Authentication {
            participant_guid: [0x01; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 1,
        };

        let event2 = SecurityEvent::Authentication {
            participant_guid: [0x02; 16],
            outcome: AuthenticationOutcome::Success,
            timestamp: 2,
        };

        let hash_before = plugin.get_previous_hash();
        plugin.log_event(&event1).unwrap();
        let hash_after_1 = plugin.get_previous_hash();
        plugin.log_event(&event2).unwrap();
        let hash_after_2 = plugin.get_previous_hash();

        // Hashes should change
        assert_ne!(hash_before, hash_after_1);
        assert_ne!(hash_after_1, hash_after_2);
    }

    #[test]
    fn test_multiple_events_to_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        let mut plugin = LoggingPlugin::with_file(&path).unwrap();

        for i in 0..10 {
            let event = SecurityEvent::Crypto {
                key_id: i,
                operation: "encrypt".to_string(),
                outcome: CryptoOutcome::Success,
                timestamp: i,
            };
            plugin.log_event(&event).unwrap();
        }

        let contents = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 10);
    }
}
