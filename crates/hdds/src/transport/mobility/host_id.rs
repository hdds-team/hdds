// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Stable host identification for IP mobility.
//!
//! Generates a stable host ID that persists across IP address changes,
//! reboots, and interface changes. This allows remote participants to
//! recognize us even after roaming.

use std::collections::hash_map::DefaultHasher;
#[cfg(target_os = "linux")]
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Generate a stable host ID.
///
/// Uses the following sources in order of preference:
/// 1. `/etc/machine-id` (systemd machine ID)
/// 2. `/var/lib/dbus/machine-id` (D-Bus machine ID)
/// 3. Hostname + first MAC address
/// 4. Random (fallback)
pub fn generate_host_id() -> u64 {
    // Try machine-id files
    if let Some(id) = read_machine_id() {
        return id;
    }

    // Try hostname + MAC
    if let Some(id) = generate_from_hostname_mac() {
        return id;
    }

    // Fallback to random
    random_host_id()
}

/// Read machine ID from standard locations.
#[cfg(target_os = "linux")]
fn read_machine_id() -> Option<u64> {
    // Try systemd machine-id first
    if let Ok(content) = fs::read_to_string("/etc/machine-id") {
        let trimmed = content.trim();
        if !trimmed.is_empty() && trimmed.len() >= 16 {
            return Some(hash_string(trimmed));
        }
    }

    // Try D-Bus machine-id
    if let Ok(content) = fs::read_to_string("/var/lib/dbus/machine-id") {
        let trimmed = content.trim();
        if !trimmed.is_empty() && trimmed.len() >= 16 {
            return Some(hash_string(trimmed));
        }
    }

    None
}

/// Read machine ID -- not available on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
fn read_machine_id() -> Option<u64> {
    None
}

/// Generate ID from hostname and MAC address.
fn generate_from_hostname_mac() -> Option<u64> {
    let hostname = get_hostname().unwrap_or_default();
    let mac = get_first_mac().unwrap_or_default();

    if hostname.is_empty() && mac.is_empty() {
        return None;
    }

    Some(hash_string(&format!("{}{}", hostname, mac)))
}

/// Get system hostname (Unix/Linux).
#[cfg(unix)]
fn get_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY:
    // - buf is a valid mutable buffer with known size (256 bytes)
    // - gethostname writes at most buf.len() bytes including NUL terminator
    // - On success, the buffer contains a NUL-terminated hostname string
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };

    if ret != 0 {
        return None;
    }

    // SAFETY:
    // - gethostname succeeded (ret == 0), so buf contains valid NUL-terminated string
    // - buf is valid for the duration of this block
    // - We immediately convert to owned String, so no lifetime issues
    let hostname = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .into_owned();

    if hostname.is_empty() || hostname == "localhost" {
        None
    } else {
        Some(hostname)
    }
}

/// Get system hostname (Windows).
#[cfg(windows)]
fn get_hostname() -> Option<String> {
    let hostname = std::env::var("COMPUTERNAME").ok()?;

    if hostname.is_empty() || hostname == "localhost" {
        None
    } else {
        Some(hostname)
    }
}

/// Get first non-zero MAC address (Linux).
#[cfg(target_os = "linux")]
fn get_first_mac() -> Option<String> {
    // Read from /sys/class/net/*/address
    let net_dir = Path::new("/sys/class/net");

    if !net_dir.exists() {
        return None;
    }

    let entries = fs::read_dir(net_dir).ok()?;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip loopback
        if name == "lo" {
            continue;
        }

        let addr_path = entry.path().join("address");
        if let Ok(mac) = fs::read_to_string(&addr_path) {
            let mac = mac.trim();

            // Skip zero MAC and empty
            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                return Some(mac.to_string());
            }
        }
    }

    None
}

/// Get first non-zero MAC address (non-Linux).
///
/// MAC address retrieval via /sys/class/net is Linux-specific.
/// On other platforms, we skip this source.
#[cfg(not(target_os = "linux"))]
fn get_first_mac() -> Option<String> {
    None
}

/// Generate random host ID.
fn random_host_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    hasher.finish()
}

/// Hash a string to u64.
fn hash_string(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Host identification info.
#[derive(Clone, Debug)]
pub struct HostInfo {
    /// Stable host ID.
    pub id: u64,

    /// Source of the ID.
    pub source: HostIdSource,

    /// Hostname (if available).
    pub hostname: Option<String>,

    /// Primary MAC address (if available).
    pub mac_address: Option<String>,
}

impl HostInfo {
    /// Gather host information.
    pub fn gather() -> Self {
        let hostname = get_hostname();
        let mac_address = get_first_mac();

        let (id, source) = if let Some(machine_id) = read_machine_id() {
            (machine_id, HostIdSource::MachineId)
        } else if let Some(hmac_id) = generate_from_hostname_mac() {
            (hmac_id, HostIdSource::HostnameMac)
        } else {
            (random_host_id(), HostIdSource::Random)
        };

        Self {
            id,
            source,
            hostname,
            mac_address,
        }
    }

    /// Get the host ID as bytes (for embedding in RTPS).
    pub fn id_bytes(&self) -> [u8; 8] {
        self.id.to_be_bytes()
    }

    /// Get lower 32 bits (for RTPS host_id field).
    pub fn id_lower32(&self) -> u32 {
        (self.id & 0xFFFF_FFFF) as u32
    }

    /// Get upper 32 bits.
    pub fn id_upper32(&self) -> u32 {
        (self.id >> 32) as u32
    }
}

impl Default for HostInfo {
    fn default() -> Self {
        Self::gather()
    }
}

/// Source of host ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostIdSource {
    /// From /etc/machine-id or /var/lib/dbus/machine-id.
    MachineId,

    /// From hostname + MAC address.
    HostnameMac,

    /// Randomly generated.
    Random,
}

impl HostIdSource {
    /// Check if source is stable across reboots.
    pub fn is_persistent(&self) -> bool {
        matches!(self, HostIdSource::MachineId | HostIdSource::HostnameMac)
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            HostIdSource::MachineId => "machine-id",
            HostIdSource::HostnameMac => "hostname+mac",
            HostIdSource::Random => "random",
        }
    }
}

/// Validate that a host ID can be regenerated consistently.
///
/// Useful for testing that the ID is truly stable.
pub fn validate_host_id_stability() -> io::Result<bool> {
    let id1 = generate_host_id();
    let id2 = generate_host_id();
    Ok(id1 == id2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_host_id() {
        let id = generate_host_id();
        assert_ne!(id, 0);
    }

    #[test]
    fn test_generate_host_id_stable() {
        let id1 = generate_host_id();
        let id2 = generate_host_id();
        // Should be the same (unless falling back to random)
        // Note: May differ if system has no machine-id and random is used
        let info = HostInfo::gather();
        if info.source.is_persistent() {
            assert_eq!(id1, id2);
        }
    }

    #[test]
    fn test_host_info_gather() {
        let info = HostInfo::gather();
        assert_ne!(info.id, 0);
    }

    #[test]
    fn test_host_info_id_bytes() {
        let info = HostInfo::gather();
        let bytes = info.id_bytes();
        assert_eq!(bytes.len(), 8);

        // Reconstruct from bytes
        let reconstructed = u64::from_be_bytes(bytes);
        assert_eq!(reconstructed, info.id);
    }

    #[test]
    fn test_host_info_id_parts() {
        let info = HostInfo {
            id: 0x1234_5678_9ABC_DEF0,
            source: HostIdSource::Random,
            hostname: None,
            mac_address: None,
        };

        assert_eq!(info.id_upper32(), 0x1234_5678);
        assert_eq!(info.id_lower32(), 0x9ABC_DEF0);
    }

    #[test]
    fn test_host_id_source_is_persistent() {
        assert!(HostIdSource::MachineId.is_persistent());
        assert!(HostIdSource::HostnameMac.is_persistent());
        assert!(!HostIdSource::Random.is_persistent());
    }

    #[test]
    fn test_host_id_source_description() {
        assert_eq!(HostIdSource::MachineId.description(), "machine-id");
        assert_eq!(HostIdSource::HostnameMac.description(), "hostname+mac");
        assert_eq!(HostIdSource::Random.description(), "random");
    }

    #[test]
    fn test_hash_string() {
        let h1 = hash_string("test");
        let h2 = hash_string("test");
        let h3 = hash_string("other");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_get_hostname() {
        // Should return something on most systems
        let hostname = get_hostname();
        // May be None in minimal containers
        if let Some(h) = hostname {
            assert!(!h.is_empty());
        }
    }

    #[test]
    fn test_get_first_mac() {
        // May return None in minimal environments
        let mac = get_first_mac();
        if let Some(m) = mac {
            assert!(!m.is_empty());
            assert_ne!(m, "00:00:00:00:00:00");
        }
    }

    #[test]
    fn test_validate_host_id_stability() {
        let result = validate_host_id_stability();
        assert!(result.is_ok());
        // Should be stable if we have machine-id or hostname+mac
        let info = HostInfo::gather();
        if info.source.is_persistent() {
            assert!(result.expect("should validate"));
        }
    }

    #[test]
    fn test_host_info_default() {
        let info = HostInfo::default();
        assert_ne!(info.id, 0);
    }

    #[test]
    fn test_random_host_id_varies() {
        // Random IDs should vary between processes
        // But within the same process, they should be consistent
        // because they're based on process ID and time
        let id1 = random_host_id();
        let id2 = random_host_id();
        // These might be the same or different depending on timing
        // Just verify they're not zero
        assert_ne!(id1, 0);
        assert_ne!(id2, 0);
    }
}
