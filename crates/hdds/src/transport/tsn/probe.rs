// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN capability probing.

use std::io;
use std::path::PathBuf;

/// TSN capabilities detected at runtime.
#[derive(Clone, Debug, Default)]
pub struct TsnCapabilities {
    /// Support SO_TXTIME.
    pub so_txtime: SupportLevel,

    /// qdisc ETF configuree.
    pub etf_configured: bool,

    /// qdisc TAPRIO configuree.
    pub taprio_configured: bool,

    /// qdisc mqprio configuree.
    pub mqprio_configured: bool,

    /// qdisc CBS configuree.
    pub cbs_configured: bool,

    /// Hardware timestamping disponible.
    pub hw_timestamping: SupportLevel,

    /// Device PHC (ex: "/dev/ptp0").
    pub phc_device: Option<PathBuf>,

    /// Version kernel detectee.
    pub kernel_version: Option<(u32, u32)>,

    /// Notes diagnostiques.
    pub notes: Vec<String>,
}

impl TsnCapabilities {
    /// Check if basic TSN features are available.
    pub fn is_tsn_ready(&self) -> bool {
        self.so_txtime != SupportLevel::Unsupported
    }

    /// Check if scheduled transmission is fully configured.
    pub fn is_scheduled_tx_ready(&self) -> bool {
        self.so_txtime != SupportLevel::Unsupported && self.etf_configured
    }

    /// Check if priority tagging via mqprio is available.
    pub fn has_priority_queues(&self) -> bool {
        self.mqprio_configured
    }

    /// Add a diagnostic note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

/// Support level for a TSN feature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SupportLevel {
    /// Feature not supported.
    #[default]
    Unsupported,

    /// Feature supported in software.
    Supported,

    /// Feature supported with hardware offload.
    SupportedWithOffload,
}

impl SupportLevel {
    /// Check if feature is available (software or hardware).
    pub fn is_available(&self) -> bool {
        *self != SupportLevel::Unsupported
    }

    /// Check if hardware offload is available.
    pub fn has_offload(&self) -> bool {
        *self == SupportLevel::SupportedWithOffload
    }
}

/// TSN capability prober.
pub struct TsnProbe;

impl TsnProbe {
    /// Probe TSN capabilities for an interface.
    ///
    /// This is a convenience wrapper that uses the default backend.
    pub fn probe(iface: &str) -> io::Result<TsnCapabilities> {
        #[cfg(target_os = "linux")]
        {
            super::linux::LinuxTsnBackend::new().probe_capabilities(iface)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = iface;
            Ok(TsnCapabilities {
                so_txtime: SupportLevel::Unsupported,
                notes: vec!["TSN not supported on this platform".to_string()],
                ..Default::default()
            })
        }
    }

    /// Probe SO_TXTIME support without interface-specific checks.
    pub fn probe_txtime_support() -> SupportLevel {
        #[cfg(target_os = "linux")]
        {
            if let Ok((major, minor)) = super::linux::LinuxTsnBackend::kernel_version() {
                // SO_TXTIME requires kernel >= 4.19
                if major > 4 || (major == 4 && minor >= 19) {
                    return SupportLevel::Supported;
                }
            }
            SupportLevel::Unsupported
        }
        #[cfg(not(target_os = "linux"))]
        {
            SupportLevel::Unsupported
        }
    }

    /// Quick check: is TSN likely available on this system?
    pub fn quick_check() -> bool {
        Self::probe_txtime_support().is_available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_support_level_default() {
        let level = SupportLevel::default();
        assert_eq!(level, SupportLevel::Unsupported);
        assert!(!level.is_available());
        assert!(!level.has_offload());
    }

    #[test]
    fn test_support_level_supported() {
        let level = SupportLevel::Supported;
        assert!(level.is_available());
        assert!(!level.has_offload());
    }

    #[test]
    fn test_support_level_offload() {
        let level = SupportLevel::SupportedWithOffload;
        assert!(level.is_available());
        assert!(level.has_offload());
    }

    #[test]
    fn test_capabilities_default() {
        let caps = TsnCapabilities::default();
        assert!(!caps.is_tsn_ready());
        assert!(!caps.is_scheduled_tx_ready());
        assert!(!caps.has_priority_queues());
    }

    #[test]
    fn test_capabilities_with_txtime() {
        let caps = TsnCapabilities {
            so_txtime: SupportLevel::Supported,
            ..Default::default()
        };
        assert!(caps.is_tsn_ready());
        assert!(!caps.is_scheduled_tx_ready()); // No ETF
    }

    #[test]
    fn test_capabilities_with_etf() {
        let caps = TsnCapabilities {
            so_txtime: SupportLevel::Supported,
            etf_configured: true,
            ..Default::default()
        };
        assert!(caps.is_tsn_ready());
        assert!(caps.is_scheduled_tx_ready());
    }

    #[test]
    fn test_capabilities_with_mqprio() {
        let caps = TsnCapabilities {
            mqprio_configured: true,
            ..Default::default()
        };
        assert!(caps.has_priority_queues());
    }

    #[test]
    fn test_capabilities_add_note() {
        let mut caps = TsnCapabilities::default();
        caps.add_note("Test note");
        caps.add_note(String::from("Another note"));
        assert_eq!(caps.notes.len(), 2);
        assert_eq!(caps.notes[0], "Test note");
    }

    #[test]
    fn test_tsn_probe_quick_check() {
        // Should not panic, result depends on platform
        let _result = TsnProbe::quick_check();
    }

    #[test]
    fn test_tsn_probe_txtime_support() {
        let level = TsnProbe::probe_txtime_support();
        // On Linux with kernel >= 4.19, should be Supported
        // On other platforms, should be Unsupported
        #[cfg(target_os = "linux")]
        {
            // Most modern Linux systems have kernel >= 4.19
            // This test may fail on very old kernels
            println!("SO_TXTIME support level: {:?}", level);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(level, SupportLevel::Unsupported);
        }
    }
}
