// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TxTime calculation and management for scheduled transmission.
//!
//! # SO_TXTIME Socket Option
//!
//! Linux kernel's SO_TXTIME (socket option level SOL_SOCKET, option 61) enables
//! scheduled packet transmission. The sockopt encoding uses a 16-byte struct:
//!
//! ```text
//! struct sock_txtime {
//!     clockid_t clockid;  // 4 bytes: clock source (CLOCK_TAI, CLOCK_MONOTONIC, etc.)
//!     u32 flags;          // 4 bytes: SOF_TXTIME_* flags
//! };
//! ```
//!
//! # Deadline Mode vs Delivery Mode
//!
//! The `flags` field controls transmission behavior:
//!
//! - **Delivery mode** (flags = 0): The NIC attempts to transmit the packet at
//!   the specified txtime. If the deadline is missed, the packet is still sent
//!   (late delivery is acceptable).
//!
//! - **Deadline mode** (flags = SOF_TXTIME_DEADLINE_MODE = 0x1): The NIC will
//!   drop the packet if it cannot be transmitted by the specified txtime.
//!   This provides strict timing guarantees - late packets are never sent.
//!
//! # Flags Field Interpretation
//!
//! ```text
//! SOF_TXTIME_DEADLINE_MODE (0x1): Enable deadline semantics (drop if late)
//! SOF_TXTIME_REPORT_ERRORS (0x2): Report errors via socket error queue (SO_EE_CODE_TXTIME_*)
//! ```
//!
//! When REPORT_ERRORS is set, missed deadlines generate SCM_TXTIME errors on the
//! error queue with codes:
//! - `SO_EE_CODE_TXTIME_INVALID_PARAM`: Invalid txtime value
//! - `SO_EE_CODE_TXTIME_MISSED`: Transmission deadline was missed
//!
//! # Struct-to-SCM Conversion
//!
//! To actually transmit with txtime, the timestamp is passed via SCM_TXTIME
//! ancillary message (cmsg) on each sendmsg() call:
//!
//! ```text
//! struct cmsghdr {
//!     size_t cmsg_len;    // sizeof(cmsghdr) + sizeof(u64)
//!     int cmsg_level;     // SOL_SOCKET
//!     int cmsg_type;      // SCM_TXTIME (61)
//!     // followed by:
//!     u64 txtime;         // Absolute timestamp in nanoseconds (clock-specific)
//! };
//! ```
//!
//! The txtime value is an absolute timestamp in nanoseconds, interpreted according
//! to the clockid configured via SO_TXTIME. For CLOCK_TAI, this is nanoseconds
//! since the TAI epoch; for CLOCK_MONOTONIC, nanoseconds since boot.
//!
//! # Usage Flow
//!
//! 1. Configure socket: `setsockopt(fd, SOL_SOCKET, SO_TXTIME, &sock_txtime, 16)`
//! 2. For each packet: build cmsg with SCM_TXTIME containing the u64 timestamp
//! 3. Send via `sendmsg()` with the ancillary data attached
//! 4. If REPORT_ERRORS enabled, poll error queue for missed deadline notifications

use std::io;
use std::time::Duration;

use super::clock::ClockSource;
use super::config::{TsnConfig, TsnTxtime, TxTimePolicy};
use super::metrics::TsnMetrics;

/// TxTime calculator for automatic txtime computation.
///
/// This calculator abstracts the complexity of computing appropriate txtime
/// values for SO_TXTIME-enabled sockets. It handles:
/// - Clock source selection (maps to `sock_txtime.clockid`)
/// - Lead time calculation to ensure packets reach the NIC before their scheduled time
/// - Policy enforcement (disabled, opportunistic, mandatory)
/// - Strict deadline mode (maps to `SOF_TXTIME_DEADLINE_MODE` flag)
#[derive(Debug)]
pub struct TxTimeCalculator {
    /// Clock source for timestamp generation.
    /// This must match the clockid configured via SO_TXTIME on the socket.
    /// Mismatch between calculator clock and socket clock causes timing errors.
    clock: ClockSource,

    /// Minimum time (in nanoseconds) between "now" and the scheduled txtime.
    /// This lead time accounts for:
    /// - Kernel processing delay
    /// - Qdisc (ETF/TAPRIO) scheduling overhead
    /// - NIC DMA and transmission latency
    ///
    /// Typical values: 100µs - 1ms depending on hardware.
    lead_time_ns: u64,

    /// Policy controlling when txtime is applied.
    /// - Disabled: Never use SO_TXTIME, send immediately
    /// - Opportunistic: Use txtime when available, fallback to regular send
    /// - Mandatory: Always use txtime, fail if not possible
    policy: TxTimePolicy,

    /// When true, enables deadline semantics (SOF_TXTIME_DEADLINE_MODE).
    /// Late packets will be dropped rather than sent. This maps directly
    /// to the flags field in the SO_TXTIME sockopt struct.
    strict_deadline: bool,
}

impl TxTimeCalculator {
    /// Create a new TxTime calculator from config.
    pub fn from_config(config: &TsnConfig) -> io::Result<Self> {
        let clock = ClockSource::new(config.clock_id.clone())?;
        Ok(Self {
            clock,
            lead_time_ns: config.lead_time_ns,
            policy: config.tx_time,
            strict_deadline: config.strict_deadline,
        })
    }

    /// Create with explicit parameters.
    pub fn new(
        clock: ClockSource,
        lead_time_ns: u64,
        policy: TxTimePolicy,
        strict_deadline: bool,
    ) -> Self {
        Self {
            clock,
            lead_time_ns,
            policy,
            strict_deadline,
        }
    }

    /// Calculate txtime for immediate send (now + lead_time).
    ///
    /// Returns an absolute timestamp in nanoseconds suitable for use in
    /// SCM_TXTIME ancillary messages. The returned value is:
    /// `current_clock_time + lead_time_ns`
    ///
    /// The timestamp format depends on the clock source:
    /// - CLOCK_TAI: nanoseconds since TAI epoch (1970-01-01 without leap seconds)
    /// - CLOCK_MONOTONIC: nanoseconds since system boot
    /// - CLOCK_REALTIME: nanoseconds since Unix epoch (with leap seconds)
    ///
    /// This value will be encoded as a u64 in the cmsg data for sendmsg().
    pub fn calculate_txtime(&self) -> io::Result<u64> {
        let now = self.clock.now_ns()?;
        Ok(now.saturating_add(self.lead_time_ns))
    }

    /// Resolve a TsnTxtime to absolute nanoseconds.
    pub fn resolve_txtime(&self, txtime: TsnTxtime) -> io::Result<u64> {
        match txtime {
            TsnTxtime::AbsoluteNs(ns) => Ok(ns),
            TsnTxtime::After(duration) => {
                let now = self.clock.now_ns()?;
                Ok(now.saturating_add(duration.as_nanos() as u64))
            }
        }
    }

    /// Get txtime for a send operation.
    ///
    /// - If override is provided, use it
    /// - Otherwise, auto-calculate based on policy
    /// - Returns None if txtime is disabled
    pub fn get_txtime(&self, override_txtime: Option<TsnTxtime>) -> io::Result<Option<u64>> {
        match self.policy {
            TxTimePolicy::Disabled => Ok(None),
            TxTimePolicy::Opportunistic | TxTimePolicy::Mandatory => {
                let txtime = match override_txtime {
                    Some(t) => self.resolve_txtime(t)?,
                    None => self.calculate_txtime()?,
                };
                Ok(Some(txtime))
            }
        }
    }

    /// Check if a txtime is late (past current time).
    pub fn is_late(&self, txtime: u64) -> io::Result<bool> {
        let now = self.clock.now_ns()?;
        Ok(txtime < now)
    }

    /// Get lateness in nanoseconds (0 if not late).
    pub fn lateness_ns(&self, txtime: u64) -> io::Result<u64> {
        let now = self.clock.now_ns()?;
        Ok(now.saturating_sub(txtime))
    }

    /// Check if should drop a late packet based on config.
    ///
    /// This implements application-level deadline enforcement that mirrors
    /// the kernel's SOF_TXTIME_DEADLINE_MODE behavior. When `strict_deadline`
    /// is enabled, this method returns true for packets whose txtime has
    /// already passed, allowing the application to drop them before sendmsg().
    ///
    /// This provides two benefits:
    /// 1. Avoids wasting syscall overhead on packets the kernel would drop anyway
    /// 2. Allows accurate metrics collection for dropped packets (kernel drops
    ///    are only visible via the error queue with SOF_TXTIME_REPORT_ERRORS)
    pub fn should_drop_late(&self, txtime: u64) -> io::Result<bool> {
        if !self.strict_deadline {
            return Ok(false);
        }
        self.is_late(txtime)
    }

    /// Get the policy.
    pub fn policy(&self) -> TxTimePolicy {
        self.policy
    }

    /// Get lead time in nanoseconds.
    pub fn lead_time_ns(&self) -> u64 {
        self.lead_time_ns
    }

    /// Get a reference to the clock source.
    pub fn clock(&self) -> &ClockSource {
        &self.clock
    }
}

/// Result of a txtime send operation.
///
/// Tracks the outcome of sendmsg() calls for metrics and diagnostics.
/// Maps to different kernel code paths:
///
/// - `SentWithTxtime`: sendmsg() succeeded with SCM_TXTIME cmsg attached.
///   Packet entered the ETF/TAPRIO qdisc for scheduled transmission.
/// - `SentRegular`: sendmsg() succeeded without txtime (immediate queueing).
/// - `DroppedLate`: Packet dropped before sendmsg() due to application-level
///   deadline check (mirrors SOF_TXTIME_DEADLINE_MODE behavior).
/// - `Failed`: sendmsg() returned an error (EINVAL, ENOBUFS, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxTimeSendResult {
    /// Sent successfully with txtime (SCM_TXTIME cmsg attached).
    /// The kernel has queued the packet for transmission at the specified time.
    SentWithTxtime,
    /// Sent without txtime (fallback or disabled).
    /// Packet was queued for immediate transmission via standard path.
    SentRegular,
    /// Dropped because late (strict_deadline mode).
    /// Application-level drop to avoid wasting resources on packets
    /// that would be rejected by SOF_TXTIME_DEADLINE_MODE anyway.
    DroppedLate,
    /// Failed to send. Check errno for details:
    /// - EINVAL: Invalid txtime (in the past, or invalid clock)
    /// - ENOBUFS: Qdisc queue full
    /// - ENETDOWN: Interface down
    Failed,
}

/// TxTime send helper with metrics integration.
pub struct TxTimeSender<'a> {
    calculator: &'a TxTimeCalculator,
    metrics: &'a TsnMetrics,
}

impl<'a> TxTimeSender<'a> {
    /// Create a new sender.
    pub fn new(calculator: &'a TxTimeCalculator, metrics: &'a TsnMetrics) -> Self {
        Self {
            calculator,
            metrics,
        }
    }

    /// Prepare a send operation.
    ///
    /// Returns the txtime to use (if any) and whether to proceed.
    pub fn prepare_send(&self, override_txtime: Option<TsnTxtime>) -> io::Result<PreparedSend> {
        let txtime = self.calculator.get_txtime(override_txtime)?;

        match txtime {
            None => Ok(PreparedSend::Regular),
            Some(t) => {
                // Check if late and should drop
                if self.calculator.should_drop_late(t)? {
                    self.metrics.record_dropped_late(1);
                    Ok(PreparedSend::DropLate)
                } else {
                    Ok(PreparedSend::WithTxtime(t))
                }
            }
        }
    }

    /// Record send result.
    pub fn record_result(&self, result: TxTimeSendResult) {
        match result {
            TxTimeSendResult::SentWithTxtime => {
                self.metrics.record_txtime_send();
            }
            TxTimeSendResult::SentRegular => {
                self.metrics.record_regular_send();
            }
            TxTimeSendResult::DroppedLate => {
                self.metrics.record_dropped_late(1);
            }
            TxTimeSendResult::Failed => {
                // Failure is recorded elsewhere
            }
        }
    }
}

/// Prepared send operation.
///
/// Represents the outcome of txtime preparation, determining how the
/// subsequent sendmsg() call should be structured:
///
/// - `WithTxtime(u64)`: Attach SCM_TXTIME cmsg with the u64 timestamp
/// - `Regular`: No ancillary data needed, send immediately
/// - `DropLate`: Do not call sendmsg(), packet deadline already missed
#[derive(Clone, Copy, Debug)]
pub enum PreparedSend {
    /// Send with txtime. The u64 value should be encoded as an 8-byte
    /// payload in an SCM_TXTIME cmsg (cmsg_level=SOL_SOCKET, cmsg_type=61).
    WithTxtime(u64),
    /// Send without txtime (no ancillary message required).
    /// Used when TxTimePolicy is Disabled or as a fallback.
    Regular,
    /// Drop the packet (strict deadline mode and txtime already passed).
    /// The kernel would drop it anyway with SOF_TXTIME_DEADLINE_MODE,
    /// but dropping here saves the syscall overhead.
    DropLate,
}

impl PreparedSend {
    /// Get txtime if present.
    pub fn txtime(&self) -> Option<u64> {
        match self {
            PreparedSend::WithTxtime(t) => Some(*t),
            _ => None,
        }
    }

    /// Check if should proceed with send.
    pub fn should_send(&self) -> bool {
        !matches!(self, PreparedSend::DropLate)
    }
}

/// WriteOptions for advanced write operations.
#[derive(Clone, Debug, Default)]
pub struct WriteOptions {
    /// Override txtime (otherwise auto-calculated).
    pub txtime: Option<TsnTxtime>,

    /// Override source timestamp.
    pub source_timestamp: Option<Duration>,

    /// Force immediate send (bypass batching).
    pub force_immediate: bool,
}

impl WriteOptions {
    /// Create default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set explicit txtime.
    pub fn with_txtime(mut self, txtime: TsnTxtime) -> Self {
        self.txtime = Some(txtime);
        self
    }

    /// Set txtime as duration after now.
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.txtime = Some(TsnTxtime::After(delay));
        self
    }

    /// Set absolute txtime in nanoseconds.
    pub fn with_absolute_txtime(mut self, ns: u64) -> Self {
        self.txtime = Some(TsnTxtime::AbsoluteNs(ns));
        self
    }

    /// Set source timestamp.
    pub fn with_timestamp(mut self, ts: Duration) -> Self {
        self.source_timestamp = Some(ts);
        self
    }

    /// Force immediate send.
    pub fn immediate(mut self) -> Self {
        self.force_immediate = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tsn::config::TsnClockId;

    fn test_calculator() -> TxTimeCalculator {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        TxTimeCalculator::new(clock, 500_000, TxTimePolicy::Mandatory, false)
    }

    #[test]
    fn test_calculator_calculate_txtime() {
        let calc = test_calculator();
        let txtime = calc.calculate_txtime().expect("should calculate");

        // Should be in the future
        let now = calc.clock.now_ns().expect("should get time");
        assert!(txtime >= now);
        assert!(txtime <= now + 1_000_000); // Within 1ms
    }

    #[test]
    fn test_calculator_resolve_absolute() {
        let calc = test_calculator();
        let txtime = calc
            .resolve_txtime(TsnTxtime::AbsoluteNs(12345))
            .expect("should resolve");
        assert_eq!(txtime, 12345);
    }

    #[test]
    fn test_calculator_resolve_after() {
        let calc = test_calculator();
        let now = calc.clock.now_ns().expect("should get time");

        let txtime = calc
            .resolve_txtime(TsnTxtime::After(Duration::from_millis(10)))
            .expect("should resolve");

        assert!(txtime >= now + 9_000_000); // At least 9ms ahead
        assert!(txtime <= now + 11_000_000); // At most 11ms ahead
    }

    #[test]
    fn test_calculator_get_txtime_disabled() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        let calc = TxTimeCalculator::new(clock, 500_000, TxTimePolicy::Disabled, false);

        let txtime = calc.get_txtime(None).expect("should work");
        assert!(txtime.is_none());
    }

    #[test]
    fn test_calculator_get_txtime_mandatory() {
        let calc = test_calculator();
        let txtime = calc.get_txtime(None).expect("should work");
        assert!(txtime.is_some());
    }

    #[test]
    fn test_calculator_get_txtime_with_override() {
        let calc = test_calculator();
        let txtime = calc
            .get_txtime(Some(TsnTxtime::AbsoluteNs(999)))
            .expect("should work");
        assert_eq!(txtime, Some(999));
    }

    #[test]
    fn test_calculator_is_late() {
        let calc = test_calculator();
        let now = calc.clock.now_ns().expect("should get time");

        // Past time is late
        assert!(calc.is_late(now - 1_000_000).expect("should check"));

        // Future time is not late
        assert!(!calc.is_late(now + 1_000_000_000).expect("should check"));
    }

    #[test]
    fn test_calculator_should_drop_late() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        let now = clock.now_ns().expect("should get time");

        // Non-strict: never drops
        let calc_non_strict = TxTimeCalculator::new(
            ClockSource::new(TsnClockId::Monotonic).expect("clock"),
            500_000,
            TxTimePolicy::Mandatory,
            false,
        );
        assert!(!calc_non_strict
            .should_drop_late(now - 1_000_000)
            .expect("should check"));

        // Strict: drops late packets
        let calc_strict = TxTimeCalculator::new(
            ClockSource::new(TsnClockId::Monotonic).expect("clock"),
            500_000,
            TxTimePolicy::Mandatory,
            true,
        );
        assert!(calc_strict
            .should_drop_late(now - 1_000_000)
            .expect("should check"));
    }

    #[test]
    fn test_prepared_send_variants() {
        let with_txtime = PreparedSend::WithTxtime(12345);
        assert_eq!(with_txtime.txtime(), Some(12345));
        assert!(with_txtime.should_send());

        let regular = PreparedSend::Regular;
        assert!(regular.txtime().is_none());
        assert!(regular.should_send());

        let drop = PreparedSend::DropLate;
        assert!(drop.txtime().is_none());
        assert!(!drop.should_send());
    }

    #[test]
    fn test_write_options_default() {
        let opts = WriteOptions::default();
        assert!(opts.txtime.is_none());
        assert!(opts.source_timestamp.is_none());
        assert!(!opts.force_immediate);
    }

    #[test]
    fn test_write_options_builder() {
        let opts = WriteOptions::new()
            .with_delay(Duration::from_millis(5))
            .with_timestamp(Duration::from_secs(1))
            .immediate();

        assert!(opts.txtime.is_some());
        assert!(opts.source_timestamp.is_some());
        assert!(opts.force_immediate);
    }

    #[test]
    fn test_write_options_absolute_txtime() {
        let opts = WriteOptions::new().with_absolute_txtime(1_000_000_000);

        match opts.txtime {
            Some(TsnTxtime::AbsoluteNs(ns)) => assert_eq!(ns, 1_000_000_000),
            _ => panic!("Expected AbsoluteNs"),
        }
    }

    #[test]
    fn test_txtime_sender_prepare_regular() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        let calc = TxTimeCalculator::new(clock, 500_000, TxTimePolicy::Disabled, false);
        let metrics = TsnMetrics::new();
        let sender = TxTimeSender::new(&calc, &metrics);

        let prepared = sender.prepare_send(None).expect("should prepare");
        assert!(matches!(prepared, PreparedSend::Regular));
    }

    #[test]
    fn test_txtime_sender_prepare_with_txtime() {
        let calc = test_calculator();
        let metrics = TsnMetrics::new();
        let sender = TxTimeSender::new(&calc, &metrics);

        let prepared = sender.prepare_send(None).expect("should prepare");
        assert!(matches!(prepared, PreparedSend::WithTxtime(_)));
    }

    #[test]
    fn test_txtime_send_result() {
        assert_eq!(
            TxTimeSendResult::SentWithTxtime,
            TxTimeSendResult::SentWithTxtime
        );
        assert_ne!(
            TxTimeSendResult::SentWithTxtime,
            TxTimeSendResult::SentRegular
        );
    }

    #[test]
    fn test_calculator_lateness() {
        let calc = test_calculator();
        let now = calc.clock.now_ns().expect("should get time");

        // Future has 0 lateness
        assert_eq!(calc.lateness_ns(now + 1_000_000).expect("should calc"), 0);

        // Past has positive lateness
        let lateness = calc.lateness_ns(now - 100_000).expect("should calc");
        assert!(lateness > 0);
    }
}
