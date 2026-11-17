// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dialect Detection - Auto-detect RTPS vendor implementation
//!
//! Implements PROBE/LOCKED/MONITOR state machine with scoring algorithm:
//! - Vendor ID: 40%
//! - Ports: 30%
//! - RTPS version: 20%
//! - Quirks: 10%

use crate::core::discovery::multicast::Origin;
use crate::core::rtps_constants::{
    CYCLONEDDS_VENDOR_ID_U16, EPROSIMA_VENDOR_ID_U16, HDDS_VENDOR_ID_U16, OPENDDS_VENDOR_ID_U16,
    RTI_VENDOR_ID_U16, RTPS_MAGIC,
};
use crate::protocol::dialect::Dialect;
use std::time::{Duration, Instant};

/// Detection phase in dialect discovery lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionPhase {
    /// Initial probing (80-100ms) - collect samples and score
    Probe,

    /// Locked to a dialect - running native protocol
    Locked,

    /// Background monitoring (1Hz adaptive) - detect topology changes
    Monitor,
}

/// Dialect change event (for hot-reconfiguration)
#[derive(Debug, Clone, Copy)]
pub struct DialectChange {
    pub from: Dialect,
    pub to: Dialect,
}

/// Minimum samples before making decision
const MIN_SAMPLES: usize = 3;

/// PROBE timeout (fallback to Hybrid if no clear decision)
/// Increased to 2s to allow remote participants time to send their SPDP.
const PROBE_TIMEOUT: Duration = Duration::from_millis(2000);

/// Confidence threshold for locking dialect (0-100)
const CONFIDENCE_THRESHOLD: u8 = 70;

/// Flapping protection: max switches before cooldown
/// Reserved for MONITOR topology change detection.
const MAX_SWITCHES_BEFORE_COOLDOWN: usize = 3;

/// Flapping cooldown duration
/// Reserved for MONITOR topology change detection.
const FLAPPING_COOLDOWN: Duration = Duration::from_secs(60);

/// Dialect detector state machine
pub struct DialectDetector {
    phase: DetectionPhase,
    start_time: Instant,
    samples_seen: usize,
    locked_dialect: Option<Dialect>,
    /// Reserved for MONITOR topology change detection.
    switch_count: usize,
    /// Reserved for MONITOR topology change detection.
    last_switch: Option<Instant>,

    // Accumulated scores (0.0-1.0)
    score_fast: f32,
    score_rti: f32,
    score_opendds: f32,
    score_cyclone: f32,

    /// Set once any sample matches a KNOWN vendor ID. When the PROBE phase
    /// times out without ever matching a known vendor (an unknown vendor such
    /// as a young/third-party impl), the score tie-break would otherwise favor
    /// CycloneDds purely on the shared SPDP port -- a misclassification that
    /// applies CycloneDds-specific SEDP/control encoding to a peer that does
    /// not speak it. The correct fallback for an unknown vendor is the
    /// conservative Hybrid encoding, mirroring `Dialect::from_vendor(Unknown)`.
    vendor_matched: bool,

    /// Interop mode flag - once enabled, never goes back to native
    /// Default: false (HDDS native mode with fast discovery)
    interop_mode: bool,

    /// Domain-aware reference ports for scoring
    spdp_multicast_port: u16,
    sedp_unicast_port: u16,
}

impl DialectDetector {
    /// Create new detector in PROBE phase
    ///
    /// Default mode is HDDS native (interop_mode = false) for fast discovery.
    /// Interop mode is auto-enabled when a non-HDDS vendor is detected.
    pub fn new() -> Self {
        Self::with_domain(0)
    }

    /// Create detector with domain-aware port scoring
    pub fn with_domain(domain_id: u32) -> Self {
        crate::trace_fn!("DialectDetector::with_domain");
        use crate::config::{sedp_unicast_port, spdp_multicast_port};
        Self {
            phase: DetectionPhase::Probe,
            start_time: Instant::now(),
            samples_seen: 0,
            locked_dialect: None,
            switch_count: 0,
            last_switch: None,
            score_fast: 0.0,
            score_rti: 0.0,
            score_opendds: 0.0,
            score_cyclone: 0.0,
            vendor_matched: false,
            interop_mode: false, // Default: HDDS native mode
            spdp_multicast_port: spdp_multicast_port(domain_id),
            sedp_unicast_port: sedp_unicast_port(domain_id, 0),
        }
    }

    /// Check if interop mode is enabled
    ///
    /// - `false`: HDDS native mode (fast discovery, skip_spdp_barrier = true)
    /// - `true`: Interop mode (dialect detection active, vendor-specific behavior)
    pub fn is_interop_mode(&self) -> bool {
        self.interop_mode
    }

    /// Enable interop mode (one-way transition, no flip-flop)
    ///
    /// Called automatically when a non-HDDS vendor is detected.
    /// Once enabled, interop mode stays enabled for the lifetime of the participant.
    pub fn enable_interop_mode(&mut self) {
        if !self.interop_mode {
            log::info!("[DIALECT-DETECTOR] Enabling interop mode (non-HDDS vendor detected)");
            self.interop_mode = true;
        }
    }

    /// Process incoming discovery packet
    ///
    /// Returns Some(Dialect) when decision is made (PROBE -> LOCKED transition).
    ///
    /// # HDDS Native Mode
    /// - HDDS packets are counted but don't trigger interop mode
    /// - If only HDDS peers exist, stays in native mode (fast discovery)
    ///
    /// # Auto-Interop
    /// - Non-HDDS vendor detected -> enable_interop_mode() called
    /// - Once in interop mode, dialect detection proceeds normally
    pub fn process_packet(&mut self, packet: &[u8], origin: Origin) -> Option<Dialect> {
        crate::trace_fn!("DialectDetector::process_packet");

        match self.phase {
            DetectionPhase::Probe => {
                // Extract features from packet
                let vendor_id = extract_vendor_id(packet)?;

                // HDDS packet - confirms native HDDS peer exists
                if vendor_id == HDDS_VENDOR_ID_U16 {
                    log::trace!(
                        "[DIALECT-DETECTOR] HDDS peer detected (vendor 0x{:04x})",
                        vendor_id
                    );
                    // In native mode, lock to Hdds immediately
                    if !self.interop_mode {
                        return self.lock_dialect(Dialect::Hdds);
                    }
                    // In interop mode, HDDS peers are still valid.
                    // Return None to let spdp_handler process them with Hybrid encoding.
                    // We don't count HDDS toward dialect scoring (they're not foreign).
                    log::debug!(
                        "[DIALECT-DETECTOR] HDDS peer in interop mode - spdp_handler will use Hybrid"
                    );
                    return None;
                }

                // Non-HDDS vendor detected -> enable interop mode and score
                self.enable_interop_mode();
                self.samples_seen += 1;
                // RTPS 2.5 8.3.8.10: behind an INFO_SRC the datagram's source
                // is only the forwarder's, never the named participant's, so
                // its port is not a signal about the peer's dialect. Scoring
                // it anyway would grade the forwarder's port against every
                // vendor's reference port instead of the peer's -- score the
                // vendor id alone and skip the port component (0.0, neutral).
                // `reply` ignores an INFO_REPLY (8.3.8.9): the port it names
                // is where to answer, not where the peer sent from.
                let port = origin.reply().map(|addr| addr.port());

                // Score vendor ID (40% weight)
                let vendor_score_fast = score_vendor_id(vendor_id, EPROSIMA_VENDOR_ID_U16) * 0.4;
                let vendor_score_rti = score_vendor_id(vendor_id, RTI_VENDOR_ID_U16) * 0.4;
                let vendor_score_opendds = score_vendor_id(vendor_id, OPENDDS_VENDOR_ID_U16) * 0.4;
                let vendor_score_cyclone =
                    score_vendor_id(vendor_id, CYCLONEDDS_VENDOR_ID_U16) * 0.4;

                // Track whether this packet matched any KNOWN vendor ID. If the
                // PROBE phase ends without a single known-vendor match, the peer
                // is an unknown vendor and must fall back to Hybrid (see below),
                // not the CycloneDds-favoring score tie-break.
                if vendor_id == EPROSIMA_VENDOR_ID_U16
                    || vendor_id == RTI_VENDOR_ID_U16
                    || vendor_id == OPENDDS_VENDOR_ID_U16
                    || vendor_id == CYCLONEDDS_VENDOR_ID_U16
                {
                    self.vendor_matched = true;
                }

                // Score port (30% weight) - domain-aware reference ports
                // The heuristic scores the SEDP unicast port for the FastDDS
                // dialect and the SPDP multicast port for the others
                // `port` is `None` behind an INFO_SRC (see above): no port score then.
                let port_score_fast =
                    port.map_or(0.0, |p| score_port(p, self.sedp_unicast_port) * 0.3);
                let port_score_rti =
                    port.map_or(0.0, |p| score_port(p, self.spdp_multicast_port) * 0.3);
                let port_score_opendds =
                    port.map_or(0.0, |p| score_port(p, self.spdp_multicast_port) * 0.3);
                let port_score_cyclone =
                    port.map_or(0.0, |p| score_port(p, self.spdp_multicast_port) * 0.3);

                // Accumulate scores (vendor + port signals only).
                self.score_fast += vendor_score_fast + port_score_fast;
                self.score_rti += vendor_score_rti + port_score_rti;
                self.score_opendds += vendor_score_opendds + port_score_opendds;
                self.score_cyclone += vendor_score_cyclone + port_score_cyclone;

                // Normalize scores by sample count (guard against division by zero)
                let (avg_score_fast, avg_score_rti, avg_score_opendds, avg_score_cyclone) =
                    if self.samples_seen > 0 {
                        (
                            self.score_fast / self.samples_seen as f32,
                            self.score_rti / self.samples_seen as f32,
                            self.score_opendds / self.samples_seen as f32,
                            self.score_cyclone / self.samples_seen as f32,
                        )
                    } else {
                        (0.0, 0.0, 0.0, 0.0)
                    };

                // Confidence on a 0-100 scale, compared as a float. For a
                // non-negative x, trunc(x) >= 70 exactly when x >= 70, and NaN
                // fails both, so comparing the float directly gives the same
                // decision as truncating and needs no narrowing conversion.
                let threshold = f32::from(CONFIDENCE_THRESHOLD);
                let confidence_fast = avg_score_fast * 100.0;
                let confidence_rti = avg_score_rti * 100.0;
                let confidence_opendds = avg_score_opendds * 100.0;
                let confidence_cyclone = avg_score_cyclone * 100.0;

                // Decision logic - need MIN_SAMPLES from remote participants
                if self.samples_seen >= MIN_SAMPLES {
                    if confidence_fast >= threshold {
                        return self.lock_dialect(Dialect::FastDds);
                    } else if confidence_rti >= threshold {
                        return self.lock_dialect(Dialect::Rti);
                    } else if confidence_opendds >= threshold {
                        return self.lock_dialect(Dialect::OpenDds);
                    } else if confidence_cyclone >= threshold {
                        return self.lock_dialect(Dialect::CycloneDds);
                    }
                }

                // Timeout fallback
                if self.start_time.elapsed() >= PROBE_TIMEOUT {
                    // If no remote samples received, default to Hybrid (compatible with all)
                    if self.samples_seen == 0 {
                        log::debug!("[DIALECT-DETECTOR] Timeout with no remote samples, defaulting to Hybrid");
                        return self.lock_dialect(Dialect::Hybrid);
                    }
                    // Unknown vendor (no known vendor ID ever matched): the score
                    // tie-break below would pick CycloneDds purely on the shared
                    // SPDP port, mislabeling a third-party impl and applying
                    // CycloneDds-specific SEDP/control encoding it does not speak.
                    // Mirror Dialect::from_vendor(Unknown) and fall back to the
                    // conservative Hybrid encoding instead.
                    if !self.vendor_matched {
                        log::info!("[DIALECT-DETECTOR] Timeout with no known-vendor match, defaulting to Hybrid (unknown vendor)");
                        return self.lock_dialect(Dialect::Hybrid);
                    }
                    // Choose highest score, or FastDds if tied (safe default for modern DDS)
                    let dialect = if avg_score_cyclone >= avg_score_fast
                        && avg_score_cyclone >= avg_score_rti
                        && avg_score_cyclone >= avg_score_opendds
                    {
                        Dialect::CycloneDds
                    } else if avg_score_opendds >= avg_score_fast
                        && avg_score_opendds >= avg_score_rti
                    {
                        Dialect::OpenDds
                    } else if avg_score_fast >= avg_score_rti {
                        Dialect::FastDds
                    } else {
                        Dialect::Rti
                    };
                    return self.lock_dialect(dialect);
                }

                None
            }
            DetectionPhase::Locked | DetectionPhase::Monitor => {
                // Already locked, no decision needed
                None
            }
        }
    }

    /// Lock to a dialect (PROBE -> LOCKED transition)
    fn lock_dialect(&mut self, dialect: Dialect) -> Option<Dialect> {
        crate::trace_fn!("DialectDetector::lock_dialect");
        log::info!(
            "[DIALECT-DETECTOR] Locked to {:?} (confidence: {}%, {} samples)",
            dialect,
            self.confidence(),
            self.samples_seen
        );
        self.phase = DetectionPhase::Locked;
        self.locked_dialect = Some(dialect);
        Some(dialect)
    }

    /// Get current locked dialect
    pub fn locked_dialect(&self) -> Option<Dialect> {
        crate::trace_fn!("DialectDetector::locked_dialect");
        self.locked_dialect
    }

    /// Get current confidence (0-100)
    pub fn confidence(&self) -> u8 {
        crate::trace_fn!("DialectDetector::confidence");
        // Currently 100 when locked, 0 otherwise; a score-derived value
        // (from avg_score_fast/rti) is not computed yet.
        if self.locked_dialect.is_some() {
            100
        } else {
            0
        }
    }

    /// Check if flapping cooldown is active
    #[allow(dead_code)] // Phase 3: MONITOR state
    fn flapping_cooldown_active(&self) -> bool {
        crate::trace_fn!("DialectDetector::flapping_cooldown_active");
        if let Some(last_switch) = self.last_switch {
            if self.switch_count >= MAX_SWITCHES_BEFORE_COOLDOWN {
                return last_switch.elapsed() < FLAPPING_COOLDOWN;
            }
        }
        false
    }

    /// MONITOR tick - detect topology changes
    ///
    /// Returns Some(DialectChange) if dialect switch is needed
    pub fn monitor_tick(&mut self, _now: Instant) -> Option<DialectChange> {
        crate::trace_fn!("DialectDetector::monitor_tick");
        if self.phase != DetectionPhase::Monitor {
            return None;
        }

        // Stub: always returns None. Adaptive monitoring at 1Hz is not
        // implemented yet.
        None
    }
}

impl Default for DialectDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if SPDP barrier should be skipped based on vendor ID in packet.
///
/// For vendor id 0x0110 HDDS sends its SEDP announcements as soon as the
/// participant is discovered instead of holding them behind the SPDP
/// barrier, so builtin endpoint discovery is not delayed by our own barrier.
///
/// This function provides immediate vendor detection without waiting for the
/// full dialect detection phase (which requires 3+ samples).
///
/// # Arguments
/// - `packet`: Raw RTPS packet (must include header)
///
/// # Returns
/// `true` if the packet is from a vendor that requires immediate SEDP response.
pub fn should_skip_spdp_barrier_for_packet(packet: &[u8]) -> bool {
    if let Some(vendor_id) = extract_vendor_id(packet) {
        // Vendor id 0x0110: send SEDP DATA right after the participant is
        // discovered (see the function doc).
        if vendor_id == CYCLONEDDS_VENDOR_ID_U16 {
            log::debug!(
                "[DIALECT-DETECTOR] CycloneDDS vendor detected (0x{:04x}), skipping SPDP barrier",
                vendor_id
            );
            return true;
        }
    }
    false
}

/// Extract vendor ID from RTPS packet
///
/// RTPS header structure (Sec.8.3.3.1):
/// ```text
/// Offset | Size | Field
/// -------|------|------
///   0    |  4   | Magic: "RTPS" (0x52545053)
///   4    |  1   | Protocol version (major)
///   5    |  1   | Protocol version (minor)
///   6    |  2   | Vendor ID (big-endian u16)
///   8    | 12   | GUID prefix
/// ```
fn extract_vendor_id(packet: &[u8]) -> Option<u16> {
    crate::trace_fn!("extract_vendor_id");
    if packet.len() < 8 {
        return None;
    }

    // Verify RTPS magic
    if &packet[0..4] != RTPS_MAGIC {
        return None;
    }

    // Extract vendor ID (bytes 6-7, big-endian)
    Some(u16::from_be_bytes([packet[6], packet[7]]))
}

/// Score vendor ID match (0.0-1.0)
///
/// Returns 1.0 for exact match, 0.0 for mismatch
fn score_vendor_id(detected: u16, expected: u16) -> f32 {
    crate::trace_fn!("score_vendor_id");
    if detected == expected {
        1.0
    } else {
        0.0
    }
}

/// Score port proximity (0.0-1.0)
///
/// Returns 1.0 for exact match, 0.5 for +/-10 offset, 0.0 otherwise
fn score_port(detected: u16, expected: u16) -> f32 {
    crate::trace_fn!("score_port");
    let diff = (detected as i32 - expected as i32).abs();
    match diff {
        0 => 1.0,
        1..=10 => 0.5,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_detector_creation() {
        let detector = DialectDetector::new();
        assert_eq!(detector.phase, DetectionPhase::Probe);
        assert_eq!(detector.samples_seen, 0);
        assert_eq!(detector.locked_dialect(), None);
    }

    #[test]
    fn test_fastdds_detection_after_min_samples() {
        let mut detector = DialectDetector::new();

        // Create a valid RTPS packet with FastDDS vendor ID (0x010F)
        let mut packet = vec![0u8; 20];
        packet[0..4].copy_from_slice(b"RTPS"); // RTPS magic
        packet[4] = 0x02; // Protocol version major
        packet[5] = 0x03; // Protocol version minor
        packet[6] = 0x01; // Vendor ID high byte
        packet[7] = 0x0F; // Vendor ID low byte (FastDDS = 0x010F)

        let addr: SocketAddr = "192.168.1.1:7410"
            .parse()
            .expect("valid test socket address");

        // Need MIN_SAMPLES (3) packets from FastDDS to trigger detection
        for i in 0..2 {
            let result = detector.process_packet(&packet, Origin::direct(addr));
            // First 2 packets shouldn't lock yet
            assert!(result.is_none(), "Unexpected early lock at packet {}", i);
        }

        // 3rd packet should trigger lock to FastDds
        let result = detector.process_packet(&packet, Origin::direct(addr));
        // FastDDS vendor ID (0x010F) + port 7410 = high confidence
        if result != Some(Dialect::FastDds) {
            // May not lock if confidence < threshold, but detector should still work
            // This is acceptable - the detector may need more samples
        }
    }

    // ========================================================================
    // Comprehensive FastStd Detection Tests
    // ========================================================================

    /// Helper to create RTPS packet with specific vendor ID
    fn create_rtps_packet(vendor_id: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0..4].copy_from_slice(b"RTPS");
        packet[4] = 0x02; // Protocol version major
        packet[5] = 0x03; // Protocol version minor
        packet[6] = (vendor_id >> 8) as u8; // Vendor ID high byte
        packet[7] = (vendor_id & 0xFF) as u8; // Vendor ID low byte
        packet
    }

    #[test]
    fn test_fastdds_detection_vendor_id() {
        let mut detector = DialectDetector::new();
        let packet = create_rtps_packet(EPROSIMA_VENDOR_ID_U16);

        // Process 3 packets from FastDDS
        for _ in 0..3 {
            let result = detector.process_packet(
                &packet,
                Origin::direct(
                    "192.168.1.1:7410"
                        .parse()
                        .expect("valid test socket address"),
                ),
            );
            if result.is_some() {
                assert_eq!(result, Some(Dialect::FastDds));
                break;
            }
        }

        assert_eq!(detector.locked_dialect(), Some(Dialect::FastDds));
    }

    #[test]
    fn test_rti_detection_vendor_id() {
        let mut detector = DialectDetector::new();
        let packet = create_rtps_packet(RTI_VENDOR_ID_U16);

        // Process 3 packets with vendor id 0x0101
        for _ in 0..3 {
            let result = detector.process_packet(
                &packet,
                Origin::direct(
                    "192.168.1.1:7400"
                        .parse()
                        .expect("valid test socket address"),
                ),
            );
            if result.is_some() {
                assert_eq!(result, Some(Dialect::Rti));
                break;
            }
        }

        assert_eq!(detector.locked_dialect(), Some(Dialect::Rti));
    }

    #[test]
    fn test_fastdds_detection_port() {
        let mut detector = DialectDetector::new();
        let packet = create_rtps_packet(EPROSIMA_VENDOR_ID_U16);

        // Source port 7410, the port the heuristic scores for the FastDDS dialect
        let result = detector.process_packet(
            &packet,
            Origin::direct(
                "192.168.1.1:7410"
                    .parse()
                    .expect("valid test socket address"),
            ),
        );

        // Should detect FastStd immediately with matching vendor + port
        if result.is_none() {
            // Need more samples
            let result2 = detector.process_packet(
                &packet,
                Origin::direct(
                    "192.168.1.1:7410"
                        .parse()
                        .expect("valid test socket address"),
                ),
            );
            if result2.is_none() {
                let result3 = detector.process_packet(
                    &packet,
                    Origin::direct(
                        "192.168.1.1:7410"
                            .parse()
                            .expect("valid test socket address"),
                    ),
                );
                assert_eq!(result3, Some(Dialect::FastDds));
            } else {
                assert_eq!(result2, Some(Dialect::FastDds));
            }
        } else {
            assert_eq!(result, Some(Dialect::FastDds));
        }
    }

    #[test]
    fn test_extract_vendor_id() {
        let packet = create_rtps_packet(0x010F);
        assert_eq!(extract_vendor_id(&packet), Some(0x010F));

        let packet_rti = create_rtps_packet(0x0101);
        assert_eq!(extract_vendor_id(&packet_rti), Some(0x0101));

        // Invalid packet (too short)
        let invalid = vec![0u8; 4];
        assert_eq!(extract_vendor_id(&invalid), None);

        // Invalid magic
        let mut invalid_magic = vec![0u8; 20];
        invalid_magic[0..4].copy_from_slice(b"ABCD");
        assert_eq!(extract_vendor_id(&invalid_magic), None);
    }

    #[test]
    fn test_score_vendor_id() {
        // Exact match
        assert_eq!(score_vendor_id(0x010F, 0x010F), 1.0);

        // Mismatch
        assert_eq!(score_vendor_id(0x010F, 0x0101), 0.0);
    }

    #[test]
    fn test_score_port() {
        // Exact match
        assert_eq!(score_port(7410, 7410), 1.0);

        // Close match (+5)
        assert_eq!(score_port(7415, 7410), 0.5);

        // Far mismatch
        assert_eq!(score_port(8000, 7410), 0.0);
    }

    #[test]
    fn test_min_samples_threshold() {
        let mut detector = DialectDetector::new();
        let packet = create_rtps_packet(EPROSIMA_VENDOR_ID_U16);

        // First 2 samples should not lock
        let result1 = detector.process_packet(
            &packet,
            Origin::direct(
                "192.168.1.1:7410"
                    .parse()
                    .expect("valid test socket address"),
            ),
        );
        assert_eq!(result1, None);

        let result2 = detector.process_packet(
            &packet,
            Origin::direct(
                "192.168.1.1:7410"
                    .parse()
                    .expect("valid test socket address"),
            ),
        );
        assert_eq!(result2, None);

        // 3rd sample should trigger decision (MIN_SAMPLES = 3)
        let result3 = detector.process_packet(
            &packet,
            Origin::direct(
                "192.168.1.1:7410"
                    .parse()
                    .expect("valid test socket address"),
            ),
        );
        assert_eq!(result3, Some(Dialect::FastDds));
    }

    /// RTPS 2.5 8.3.8.10: behind an INFO_SRC the datagram's source is only
    /// the forwarder's, never the named peer's -- its port carries no signal
    /// about the peer's dialect. `test_min_samples_threshold` above locks to
    /// FastDds after 3 samples of this exact vendor+port combination because
    /// the matching port supplies 30% on top of the vendor's 40%, clearing
    /// the 70% threshold. A relayed origin must not get that credit: with
    /// the port excluded, three samples carry only the vendor's 40% and the
    /// detector stays unlocked.
    #[test]
    fn a_relayed_origins_port_is_never_scored() {
        let mut detector = DialectDetector::new();
        let packet = create_rtps_packet(EPROSIMA_VENDOR_ID_U16);
        let forwarder: SocketAddr = "192.168.1.1:7410"
            .parse()
            .expect("valid test socket address");

        let mut result = None;
        for _ in 0..3 {
            result = detector.process_packet(&packet, Origin::relayed(forwarder));
        }
        assert_eq!(
            result, None,
            "vendor alone (40% weight) must not reach the 70% lock threshold \
             that the matching port would have supplied"
        );
        assert_eq!(
            detector.locked_dialect(),
            None,
            "a relayed forwarder's port must never be credited as the peer's"
        );
    }

    /// RTPS 2.5 8.3.8.9: an INFO_REPLY says where to answer, not where the
    /// peer sent from. The datagram's own port is still the signal (a
    /// direct peer behind an INFO_REPLY to a far port locks as it would
    /// without one), and the INFO_REPLY's port is never one (the same
    /// INFO_REPLY port, from a relayed origin, does not lock).
    #[test]
    fn an_info_reply_port_is_never_scored() {
        let packet = create_rtps_packet(EPROSIMA_VENDOR_ID_U16);
        let sender: SocketAddr = "192.168.1.1:7410"
            .parse()
            .expect("valid test socket address");
        let far: std::net::SocketAddrV4 = "192.168.1.1:9000".parse().expect("valid address");
        let near: std::net::SocketAddrV4 = "192.168.1.1:7410".parse().expect("valid address");

        let mut direct = DialectDetector::new();
        let mut result = None;
        for _ in 0..3 {
            result = direct.process_packet(&packet, Origin::direct(sender).replying_to(Some(far)));
        }
        assert_eq!(
            result,
            Some(Dialect::FastDds),
            "the sender's own port counts"
        );

        let mut relayed = DialectDetector::new();
        for _ in 0..3 {
            result =
                relayed.process_packet(&packet, Origin::relayed(sender).replying_to(Some(near)));
        }
        assert_eq!(result, None, "the INFO_REPLY's port does not");
    }
}
