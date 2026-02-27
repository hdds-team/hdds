// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Clock utilities for TSN txtime calculations.

use std::io;
use std::path::Path;

use super::config::TsnClockId;

// Linux-specific constants
#[cfg(target_os = "linux")]
mod linux_consts {
    pub const CLOCK_TAI: libc::clockid_t = 11;
}

/// Get current time from a clock in nanoseconds.
#[cfg(target_os = "linux")]
pub fn clock_gettime_ns(clock_id: &TsnClockId) -> io::Result<u64> {
    let clockid = match clock_id {
        TsnClockId::Monotonic => libc::CLOCK_MONOTONIC,
        TsnClockId::Tai => linux_consts::CLOCK_TAI,
        TsnClockId::Realtime => libc::CLOCK_REALTIME,
        TsnClockId::Phc(path) => {
            let fd = open_phc(path)?;
            let clockid = fd_to_clockid(fd);
            // Note: fd is leaked here for simplicity; in production,
            // PHC fds should be cached
            return clock_gettime_raw(clockid);
        }
    };
    clock_gettime_raw(clockid)
}

#[cfg(not(target_os = "linux"))]
pub fn clock_gettime_ns(_clock_id: &TsnClockId) -> io::Result<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(now.as_nanos() as u64)
}

/// Raw clock_gettime call.
#[cfg(target_os = "linux")]
fn clock_gettime_raw(clockid: libc::clockid_t) -> io::Result<u64> {
    // SAFETY:
    // - timespec is a POD type that can be safely zero-initialized
    // - tv_sec and tv_nsec have no invalid bit patterns
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY:
    // - clockid is a valid clock ID (standard clock or PHC-derived via fd_to_clockid)
    // - &mut ts is a valid pointer to a properly sized timespec struct
    // - clock_gettime() will write valid time data on success
    let ret = unsafe { libc::clock_gettime(clockid, &mut ts) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

/// Open a PHC device.
#[cfg(target_os = "linux")]
pub fn open_phc(path: &Path) -> io::Result<i32> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new().read(true).open(path)?;
    Ok(file.as_raw_fd())
}

#[cfg(not(target_os = "linux"))]
pub fn open_phc(_path: &Path) -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "PHC not supported on this platform",
    ))
}

/// Convert PHC file descriptor to clockid_t.
///
/// Linux-specific: clockid = ~(fd << 3) | 3
#[cfg(target_os = "linux")]
pub fn fd_to_clockid(fd: i32) -> libc::clockid_t {
    (!(fd << 3) | 3) as libc::clockid_t
}

#[cfg(not(target_os = "linux"))]
pub fn fd_to_clockid(_fd: i32) -> i32 {
    -1
}

/// Convert TsnClockId to libc clockid_t (Linux only).
#[cfg(target_os = "linux")]
pub fn to_clockid(clock: &TsnClockId) -> Option<libc::clockid_t> {
    match clock {
        TsnClockId::Monotonic => Some(libc::CLOCK_MONOTONIC),
        TsnClockId::Tai => Some(linux_consts::CLOCK_TAI),
        TsnClockId::Realtime => Some(libc::CLOCK_REALTIME),
        TsnClockId::Phc(_) => None, // Requires fd conversion
    }
}

/// Clock time source for txtime calculations.
#[derive(Clone, Debug)]
pub struct ClockSource {
    clock_id: TsnClockId,
    #[cfg(target_os = "linux")]
    phc_fd: Option<i32>,
}

impl ClockSource {
    /// Create a new clock source.
    pub fn new(clock_id: TsnClockId) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let phc_fd = if let TsnClockId::Phc(path) = &clock_id {
                Some(open_phc(path)?)
            } else {
                None
            };
            Ok(Self { clock_id, phc_fd })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self { clock_id })
        }
    }

    /// Get current time in nanoseconds.
    pub fn now_ns(&self) -> io::Result<u64> {
        #[cfg(target_os = "linux")]
        {
            if let Some(fd) = self.phc_fd {
                let clockid = fd_to_clockid(fd);
                return clock_gettime_raw(clockid);
            }
        }
        clock_gettime_ns(&self.clock_id)
    }

    /// Get the clock ID.
    pub fn clock_id(&self) -> &TsnClockId {
        &self.clock_id
    }

    /// Check if this is a hardware clock (PHC).
    pub fn is_hardware_clock(&self) -> bool {
        matches!(self.clock_id, TsnClockId::Phc(_))
    }

    /// Check if this clock is PTP-synchronized (TAI or PHC).
    pub fn is_ptp_synced(&self) -> bool {
        matches!(self.clock_id, TsnClockId::Tai | TsnClockId::Phc(_))
    }
}

impl Default for ClockSource {
    fn default() -> Self {
        Self {
            clock_id: TsnClockId::Tai,
            #[cfg(target_os = "linux")]
            phc_fd: None,
        }
    }
}

/// Calculate txtime from current time and lead time.
pub fn calculate_txtime(clock: &ClockSource, lead_time_ns: u64) -> io::Result<u64> {
    let now = clock.now_ns()?;
    Ok(now.saturating_add(lead_time_ns))
}

/// Validate that a txtime is in the future.
pub fn validate_txtime(clock: &ClockSource, txtime: u64) -> io::Result<bool> {
    let now = clock.now_ns()?;
    Ok(txtime > now)
}

/// Calculate how late a txtime is (0 if not late).
pub fn txtime_lateness(clock: &ClockSource, txtime: u64) -> io::Result<u64> {
    let now = clock.now_ns()?;
    Ok(now.saturating_sub(txtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_source_default() {
        let clock = ClockSource::default();
        assert_eq!(*clock.clock_id(), TsnClockId::Tai);
        assert!(!clock.is_hardware_clock());
        assert!(clock.is_ptp_synced());
    }

    #[test]
    fn test_clock_source_monotonic() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        assert!(!clock.is_hardware_clock());
        assert!(!clock.is_ptp_synced());

        let time = clock.now_ns().expect("should get time");
        assert!(time > 0);
    }

    #[test]
    fn test_clock_source_realtime() {
        let clock = ClockSource::new(TsnClockId::Realtime).expect("should create clock");
        let time = clock.now_ns().expect("should get time");
        // Realtime should be after year 2020 in nanoseconds
        assert!(time > 1_577_836_800_000_000_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_clock_source_tai() {
        let clock = ClockSource::new(TsnClockId::Tai).expect("should create clock");
        assert!(clock.is_ptp_synced());

        // TAI may fail on systems without proper time sync
        let result = clock.now_ns();
        if let Ok(time) = result {
            assert!(time > 0);
        }
    }

    #[test]
    fn test_clock_gettime_ns_monotonic() {
        let time1 = clock_gettime_ns(&TsnClockId::Monotonic).expect("should get time");
        let time2 = clock_gettime_ns(&TsnClockId::Monotonic).expect("should get time");
        assert!(time2 >= time1);
    }

    #[test]
    fn test_calculate_txtime() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        let lead_time = 1_000_000; // 1ms

        let txtime = calculate_txtime(&clock, lead_time).expect("should calculate txtime");
        let now = clock.now_ns().expect("should get time");

        // txtime should be approximately now + lead_time (within 10ms tolerance)
        assert!(txtime >= now);
        assert!(txtime < now + 10_000_000);
    }

    #[test]
    fn test_validate_txtime() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        let now = clock.now_ns().expect("should get time");

        // Future txtime should be valid
        let future = now + 1_000_000_000; // 1 second ahead
        assert!(validate_txtime(&clock, future).expect("should validate"));

        // Past txtime should be invalid
        let past = now.saturating_sub(1_000_000_000);
        assert!(!validate_txtime(&clock, past).expect("should validate"));
    }

    #[test]
    fn test_txtime_lateness() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");
        let now = clock.now_ns().expect("should get time");

        // Future txtime has 0 lateness
        let future = now + 1_000_000_000;
        assert_eq!(txtime_lateness(&clock, future).expect("should calc"), 0);

        // Past txtime has positive lateness
        let past = now.saturating_sub(100_000_000); // 100ms ago
        let lateness = txtime_lateness(&clock, past).expect("should calc");
        assert!(lateness > 0);
        assert!(lateness < 200_000_000); // Less than 200ms
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_fd_to_clockid() {
        // Test the formula: clockid = ~(fd << 3) | 3
        let fd = 5;
        let clockid = fd_to_clockid(fd);
        // ~(5 << 3) | 3 = ~40 | 3 = -41 | 3 = -41
        assert!(clockid < 0); // Should be negative for dynamic clocks
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_to_clockid() {
        assert_eq!(
            to_clockid(&TsnClockId::Monotonic),
            Some(libc::CLOCK_MONOTONIC)
        );
        assert_eq!(to_clockid(&TsnClockId::Tai), Some(linux_consts::CLOCK_TAI));
        assert_eq!(
            to_clockid(&TsnClockId::Realtime),
            Some(libc::CLOCK_REALTIME)
        );
        assert!(to_clockid(&TsnClockId::Phc("/dev/ptp0".into())).is_none());
    }

    #[test]
    fn test_clock_source_time_advances() {
        let clock = ClockSource::new(TsnClockId::Monotonic).expect("should create clock");

        let times: Vec<u64> = (0..10)
            .map(|_| clock.now_ns().expect("should get time"))
            .collect();

        // Times should be monotonically increasing (or equal)
        for i in 1..times.len() {
            assert!(times[i] >= times[i - 1]);
        }
    }
}
