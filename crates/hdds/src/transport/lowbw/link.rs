// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Link abstraction for LBW transport.
//!
//! The LBW protocol operates on "frames" which can be transmitted over:
//! - **Datagrams** (UDP, radio packets) - frame boundaries preserved
//! - **Streams** (serial, TCP tunnel) - use frame_len + sync for resync
//!
//! # Link Trait
//!
//! ```ignore
//! pub trait LowBwLink: Send + Sync {
//!     fn send(&self, frame: &[u8]) -> io::Result<()>;
//!     fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
//! }
//! ```
//!
//! # Implementations
//!
//! - `UdpLink` - UDP socket for development/testing
//! - `SimLink` - Simulated link with loss/delay/corruption

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum frame size for LBW links.
pub const MAX_FRAME_SIZE: usize = 2048;

/// Link statistics.
#[derive(Debug, Default, Clone)]
pub struct LinkStats {
    /// Total frames sent.
    pub frames_sent: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total frames received.
    pub frames_received: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Frames dropped (simulated loss).
    pub frames_dropped: u64,
    /// Frames corrupted (simulated).
    pub frames_corrupted: u64,
    /// Send errors.
    pub send_errors: u64,
    /// Receive errors.
    pub recv_errors: u64,
}

/// Trait for LBW link implementations.
///
/// Links provide frame-based send/receive operations.
/// Frame boundaries are preserved (datagram semantics).
pub trait LowBwLink: Send + Sync {
    /// Send a frame.
    ///
    /// # Arguments
    /// * `frame` - Complete frame bytes to send
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` on send failure
    fn send(&self, frame: &[u8]) -> io::Result<()>;

    /// Receive a frame.
    ///
    /// # Arguments
    /// * `buf` - Buffer to receive frame into (should be at least MAX_FRAME_SIZE)
    ///
    /// # Returns
    /// * `Ok(n)` where n is the number of bytes received
    /// * `Err` on receive failure or timeout
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Receive with timeout.
    ///
    /// Default implementation sets socket timeout and calls recv.
    fn recv_timeout(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        // Default: just call recv (implementations should override for proper timeout)
        let _ = timeout;
        self.recv(buf)
    }

    /// Get link statistics.
    ///
    /// Default implementation returns empty statistics.
    /// Implementations that track statistics should override this.
    fn stats(&self) -> LinkStats {
        LinkStats::default()
    }

    /// Reset link statistics.
    ///
    /// Default implementation is a no-op.
    /// Implementations that track statistics should override this to reset counters.
    fn reset_stats(&self) {
        // Intentionally empty - default for implementations that don't track statistics.
    }
}

// ============================================================================
// UdpLink - UDP socket link for development
// ============================================================================

/// UDP-based link for development and testing.
///
/// Wraps a UDP socket with peer address for send/recv.
pub struct UdpLink {
    socket: UdpSocket,
    peer: SocketAddr,
    stats: Arc<UdpLinkStats>,
}

struct UdpLinkStats {
    frames_sent: AtomicU64,
    bytes_sent: AtomicU64,
    frames_received: AtomicU64,
    bytes_received: AtomicU64,
    send_errors: AtomicU64,
    recv_errors: AtomicU64,
}

impl Default for UdpLinkStats {
    fn default() -> Self {
        Self {
            frames_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
        }
    }
}

impl UdpLink {
    /// Create a new UDP link.
    ///
    /// # Arguments
    /// * `local_addr` - Local address to bind to
    /// * `peer_addr` - Remote peer address
    pub fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local_addr)?;
        socket.set_nonblocking(false)?;
        Ok(Self {
            socket,
            peer: peer_addr,
            stats: Arc::new(UdpLinkStats::default()),
        })
    }

    /// Create from existing socket.
    pub fn from_socket(socket: UdpSocket, peer_addr: SocketAddr) -> Self {
        Self {
            socket,
            peer: peer_addr,
            stats: Arc::new(UdpLinkStats::default()),
        }
    }

    /// Set read timeout.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// Get the local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Get the peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

impl LowBwLink for UdpLink {
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        match self.socket.send_to(frame, self.peer) {
            Ok(n) => {
                self.stats.frames_sent.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.socket.recv(buf) {
            Ok(n) => {
                self.stats.frames_received.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_received
                    .fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                self.stats.recv_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    fn recv_timeout(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(timeout))?;
        let result = self.recv(buf);
        self.socket.set_read_timeout(None)?;
        result
    }

    fn stats(&self) -> LinkStats {
        LinkStats {
            frames_sent: self.stats.frames_sent.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            frames_received: self.stats.frames_received.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            recv_errors: self.stats.recv_errors.load(Ordering::Relaxed),
            ..Default::default()
        }
    }

    fn reset_stats(&self) {
        self.stats.frames_sent.store(0, Ordering::Relaxed);
        self.stats.bytes_sent.store(0, Ordering::Relaxed);
        self.stats.frames_received.store(0, Ordering::Relaxed);
        self.stats.bytes_received.store(0, Ordering::Relaxed);
        self.stats.send_errors.store(0, Ordering::Relaxed);
        self.stats.recv_errors.store(0, Ordering::Relaxed);
    }
}

// ============================================================================
// SimLink - Simulated link with impairments
// ============================================================================

/// Configuration for simulated link impairments.
#[derive(Debug, Clone)]
pub struct SimLinkConfig {
    /// Packet loss probability (0.0 - 1.0).
    pub loss_rate: f64,
    /// Fixed delay in milliseconds.
    pub delay_ms: u64,
    /// Delay jitter in milliseconds (uniform random +/- jitter).
    pub jitter_ms: u64,
    /// Bit corruption probability per byte (0.0 - 1.0).
    pub corruption_rate: f64,
    /// Maximum bandwidth in bytes per second (0 = unlimited).
    pub bandwidth_bps: u64,
    /// Queue capacity (frames).
    pub queue_capacity: usize,
}

impl Default for SimLinkConfig {
    fn default() -> Self {
        Self {
            loss_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
            corruption_rate: 0.0,
            bandwidth_bps: 0,
            queue_capacity: 100,
        }
    }
}

impl SimLinkConfig {
    /// Create a config for a lossy link.
    pub fn lossy(loss_rate: f64) -> Self {
        Self {
            loss_rate,
            ..Default::default()
        }
    }

    /// Create a config for a slow link (like 9600 bps serial).
    pub fn slow_serial() -> Self {
        Self {
            loss_rate: 0.05,
            delay_ms: 100,
            jitter_ms: 50,
            corruption_rate: 0.001,
            bandwidth_bps: 1200, // 9600 bps / 8
            queue_capacity: 10,
        }
    }

    /// Create a config for satellite link.
    pub fn satellite() -> Self {
        Self {
            loss_rate: 0.10,
            delay_ms: 500,
            jitter_ms: 100,
            corruption_rate: 0.0005,
            bandwidth_bps: 50_000, // 400 kbps / 8
            queue_capacity: 50,
        }
    }

    /// Create a config for tactical radio.
    pub fn tactical_radio() -> Self {
        Self {
            loss_rate: 0.20,
            delay_ms: 200,
            jitter_ms: 150,
            corruption_rate: 0.002,
            bandwidth_bps: 2400, // 19.2 kbps / 8
            queue_capacity: 20,
        }
    }
}

/// Queued frame with delivery time.
struct QueuedFrame {
    data: Vec<u8>,
    deliver_at: Instant,
}

/// Simulated link with configurable impairments.
///
/// Useful for testing LBW behavior under adverse conditions:
/// - Packet loss
/// - Delay and jitter
/// - Bit corruption
/// - Bandwidth limiting
pub struct SimLink {
    config: SimLinkConfig,
    /// Frames in transit (delayed).
    queue: Mutex<Vec<QueuedFrame>>,
    /// Simple PRNG state.
    rng_state: AtomicU64,
    /// Statistics.
    stats: Mutex<SimLinkStats>,
    /// Last send time for bandwidth limiting.
    last_send: Mutex<Instant>,
}

#[derive(Debug, Default, Clone)]
struct SimLinkStats {
    frames_sent: u64,
    bytes_sent: u64,
    frames_received: u64,
    bytes_received: u64,
    frames_dropped: u64,
    frames_corrupted: u64,
}

impl SimLink {
    /// Create a new simulated link.
    pub fn new(config: SimLinkConfig) -> Self {
        Self {
            config,
            queue: Mutex::new(Vec::new()),
            rng_state: AtomicU64::new(0x12345678_9ABCDEF0),
            stats: Mutex::new(SimLinkStats::default()),
            last_send: Mutex::new(Instant::now()),
        }
    }

    /// Create with default config (no impairments).
    pub fn perfect() -> Self {
        Self::new(SimLinkConfig::default())
    }

    /// Get a random f64 in [0, 1).
    fn rand_f64(&self) -> f64 {
        let mut state = self.rng_state.load(Ordering::Relaxed);
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.rng_state.store(state, Ordering::Relaxed);
        (state as f64) / (u64::MAX as f64)
    }

    /// Get a random u64.
    fn rand_u64(&self) -> u64 {
        let mut state = self.rng_state.load(Ordering::Relaxed);
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.rng_state.store(state, Ordering::Relaxed);
        state
    }

    /// Calculate delivery delay.
    fn calculate_delay(&self) -> Duration {
        let base_delay = self.config.delay_ms;
        let jitter = if self.config.jitter_ms > 0 {
            let j = (self.rand_u64() % (self.config.jitter_ms * 2)) as i64
                - self.config.jitter_ms as i64;
            j.max(-(base_delay as i64)) as u64
        } else {
            0
        };
        Duration::from_millis(base_delay.saturating_add_signed(jitter as i64))
    }

    /// Maybe corrupt a frame.
    fn maybe_corrupt(&self, data: &mut [u8]) -> bool {
        if self.config.corruption_rate <= 0.0 {
            return false;
        }

        let mut corrupted = false;
        for byte in data.iter_mut() {
            if self.rand_f64() < self.config.corruption_rate {
                let bit = 1u8 << (self.rand_u64() % 8);
                *byte ^= bit;
                corrupted = true;
            }
        }
        corrupted
    }

    /// Enforce bandwidth limit.
    fn enforce_bandwidth(&self, frame_size: usize) {
        if self.config.bandwidth_bps == 0 {
            return;
        }

        let transmission_time_us = (frame_size as u64 * 1_000_000) / self.config.bandwidth_bps;

        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let mut last_send = self.last_send.lock().expect("lock");
        let now = Instant::now();
        let elapsed = now.duration_since(*last_send);
        let required = Duration::from_micros(transmission_time_us);

        if elapsed < required {
            std::thread::sleep(required - elapsed);
        }

        *last_send = Instant::now();
    }

    /// Deliver ready frames to output queue.
    fn deliver_ready(&self) -> Option<Vec<u8>> {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let mut queue = self.queue.lock().expect("lock");
        let now = Instant::now();

        // Find first ready frame
        if let Some(idx) = queue.iter().position(|f| f.deliver_at <= now) {
            let frame = queue.remove(idx);
            return Some(frame.data);
        }

        None
    }

    /// Get the next frame delivery time.
    fn next_delivery_time(&self) -> Option<Instant> {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let queue = self.queue.lock().expect("lock");
        queue.iter().map(|f| f.deliver_at).min()
    }

    /// Set the random seed for reproducible testing.
    pub fn set_seed(&self, seed: u64) {
        self.rng_state.store(seed, Ordering::Relaxed);
    }

    /// Get current configuration.
    pub fn config(&self) -> &SimLinkConfig {
        &self.config
    }

    /// Update configuration.
    pub fn set_config(&mut self, config: SimLinkConfig) {
        self.config = config;
    }

    /// Get queue depth.
    pub fn queue_depth(&self) -> usize {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        {
            self.queue.lock().expect("lock").len()
        }
    }
}

impl LowBwLink for SimLink {
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        // Enforce bandwidth limit
        self.enforce_bandwidth(frame.len());

        // Check for loss
        if self.rand_f64() < self.config.loss_rate {
            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let mut stats = self.stats.lock().expect("lock");
            stats.frames_dropped += 1;
            return Ok(()); // Silently drop
        }

        // Check queue capacity
        {
            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let queue = self.queue.lock().expect("lock");
            if queue.len() >= self.config.queue_capacity {
                #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
                let mut stats = self.stats.lock().expect("lock");
                stats.frames_dropped += 1;
                return Ok(()); // Drop due to congestion
            }
        }

        // Prepare frame (maybe corrupt)
        let mut data = frame.to_vec();
        let corrupted = self.maybe_corrupt(&mut data);

        // Calculate delivery time
        let delay = self.calculate_delay();
        let deliver_at = Instant::now() + delay;

        // Queue for delivery
        {
            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let mut queue = self.queue.lock().expect("lock");
            queue.push(QueuedFrame { data, deliver_at });
        }

        // Update stats
        {
            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let mut stats = self.stats.lock().expect("lock");
            stats.frames_sent += 1;
            stats.bytes_sent += frame.len() as u64;
            if corrupted {
                stats.frames_corrupted += 1;
            }
        }

        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to deliver a ready frame
        if let Some(data) = self.deliver_ready() {
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);

            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let mut stats = self.stats.lock().expect("lock");
            stats.frames_received += 1;
            stats.bytes_received += len as u64;

            return Ok(len);
        }

        // No frame ready
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "no frame available",
        ))
    }

    fn recv_timeout(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let deadline = Instant::now() + timeout;

        loop {
            // Try to receive
            match self.recv(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Check timeout
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "receive timeout"));
                    }

                    // Sleep until next delivery or timeout
                    let sleep_until = self
                        .next_delivery_time()
                        .map(|t| t.min(deadline))
                        .unwrap_or(deadline);

                    if sleep_until > now {
                        std::thread::sleep(sleep_until - now);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn stats(&self) -> LinkStats {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let stats = self.stats.lock().expect("lock");
        LinkStats {
            frames_sent: stats.frames_sent,
            bytes_sent: stats.bytes_sent,
            frames_received: stats.frames_received,
            bytes_received: stats.bytes_received,
            frames_dropped: stats.frames_dropped,
            frames_corrupted: stats.frames_corrupted,
            ..Default::default()
        }
    }

    fn reset_stats(&self) {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let mut stats = self.stats.lock().expect("lock");
        *stats = SimLinkStats::default();
    }
}

// ============================================================================
// LoopbackLink - Direct loopback for unit tests
// ============================================================================

/// Simple loopback link for unit testing.
///
/// Frames sent are immediately available for receive.
pub struct LoopbackLink {
    queue: Mutex<Vec<Vec<u8>>>,
    stats: Mutex<LinkStats>,
}

impl LoopbackLink {
    /// Create a new loopback link.
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(Vec::new()),
            stats: Mutex::new(LinkStats::default()),
        }
    }
}

impl Default for LoopbackLink {
    fn default() -> Self {
        Self::new()
    }
}

impl LowBwLink for LoopbackLink {
    fn send(&self, frame: &[u8]) -> io::Result<()> {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let mut queue = self.queue.lock().expect("lock");
        queue.push(frame.to_vec());

        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let mut stats = self.stats.lock().expect("lock");
        stats.frames_sent += 1;
        stats.bytes_sent += frame.len() as u64;

        Ok(())
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let mut queue = self.queue.lock().expect("lock");

        if let Some(data) = queue.pop() {
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);

            #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
            let mut stats = self.stats.lock().expect("lock");
            stats.frames_received += 1;
            stats.bytes_received += len as u64;

            Ok(len)
        } else {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "no frame available",
            ))
        }
    }

    fn stats(&self) -> LinkStats {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let stats = self.stats.lock().expect("lock");
        stats.clone()
    }

    fn reset_stats(&self) {
        #[allow(clippy::expect_used)] // mutex poisoning is unrecoverable
        let mut stats = self.stats.lock().expect("lock");
        *stats = LinkStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::lowbw::crc::crc16_ccitt;

    #[test]
    fn test_loopback_link_basic() {
        let link = LoopbackLink::new();

        // Send frame
        let frame = b"Hello, LBW!";
        link.send(frame).expect("send");

        // Receive frame
        let mut buf = [0u8; 64];
        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], frame);

        // Stats
        let stats = link.stats();
        assert_eq!(stats.frames_sent, 1);
        assert_eq!(stats.frames_received, 1);
    }

    #[test]
    fn test_loopback_link_empty() {
        let link = LoopbackLink::new();
        let mut buf = [0u8; 64];

        let result = link.recv(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_loopback_link_multiple() {
        let link = LoopbackLink::new();

        // Send multiple frames
        link.send(b"Frame 1").expect("send");
        link.send(b"Frame 2").expect("send");
        link.send(b"Frame 3").expect("send");

        let mut buf = [0u8; 64];

        // Receive in LIFO order (stack)
        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"Frame 3");

        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"Frame 2");

        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], b"Frame 1");
    }

    #[test]
    fn test_simlink_perfect() {
        let link = SimLink::perfect();

        // Send frame
        let frame = b"Test frame";
        link.send(frame).expect("send");

        // Should be immediately available (no delay)
        let mut buf = [0u8; 64];
        let n = link.recv(&mut buf).expect("recv");
        assert_eq!(&buf[..n], frame);
    }

    #[test]
    fn test_simlink_loss() {
        let config = SimLinkConfig {
            loss_rate: 1.0, // 100% loss
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Send frame
        link.send(b"Lost frame").expect("send");

        // Should be dropped
        let mut buf = [0u8; 64];
        let result = link.recv(&mut buf);
        assert!(result.is_err());

        let stats = link.stats();
        assert_eq!(stats.frames_dropped, 1);
    }

    #[test]
    fn test_simlink_partial_loss() {
        let config = SimLinkConfig {
            loss_rate: 0.5, // 50% loss
            ..Default::default()
        };
        let link = SimLink::new(config);
        link.set_seed(12345); // Reproducible

        // Send many frames
        let mut sent = 0;
        for _ in 0..100 {
            link.send(b"Test").expect("send");
            sent += 1;
        }

        // Receive all available
        let mut received = 0;
        let mut buf = [0u8; 64];
        while link.recv(&mut buf).is_ok() {
            received += 1;
        }

        let stats = link.stats();
        assert_eq!(stats.frames_sent + stats.frames_dropped, sent);
        // With 50% loss, expect roughly half received
        assert!(
            received > 20 && received < 80,
            "received {} frames",
            received
        );
    }

    #[test]
    fn test_simlink_delay() {
        let config = SimLinkConfig {
            delay_ms: 50,
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Send frame
        let start = Instant::now();
        link.send(b"Delayed").expect("send");

        // Should not be immediately available
        let mut buf = [0u8; 64];
        let result = link.recv(&mut buf);
        assert!(result.is_err());

        // Wait for delivery
        std::thread::sleep(Duration::from_millis(60));
        let n = link.recv(&mut buf).expect("recv after delay");
        assert_eq!(&buf[..n], b"Delayed");

        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
    }

    #[test]
    fn test_simlink_recv_timeout() {
        let config = SimLinkConfig {
            delay_ms: 100,
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Send frame
        link.send(b"Delayed").expect("send");

        let mut buf = [0u8; 64];

        // Timeout too short
        let result = link.recv_timeout(&mut buf, Duration::from_millis(20));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);

        // Timeout long enough
        let n = link
            .recv_timeout(&mut buf, Duration::from_millis(150))
            .expect("recv with timeout");
        assert_eq!(&buf[..n], b"Delayed");
    }

    #[test]
    fn test_simlink_corruption() {
        let config = SimLinkConfig {
            corruption_rate: 1.0, // Corrupt every byte
            ..Default::default()
        };
        let link = SimLink::new(config);
        link.set_seed(99999);

        // Send frame with known CRC
        let original = b"Test data for corruption";
        let original_crc = crc16_ccitt(original);

        link.send(original).expect("send");

        let mut buf = [0u8; 64];
        let n = link.recv(&mut buf).expect("recv");

        // Frame should be corrupted
        let received_crc = crc16_ccitt(&buf[..n]);
        assert_ne!(
            received_crc, original_crc,
            "CRC should differ after corruption"
        );

        let stats = link.stats();
        assert!(stats.frames_corrupted > 0);
    }

    #[test]
    fn test_simlink_queue_overflow() {
        let config = SimLinkConfig {
            queue_capacity: 3,
            delay_ms: 1000, // Long delay to fill queue
            ..Default::default()
        };
        let link = SimLink::new(config);

        // Fill queue
        for i in 0..5 {
            link.send(format!("Frame {}", i).as_bytes()).expect("send");
        }

        let stats = link.stats();
        assert_eq!(stats.frames_sent, 3); // Only 3 fit
        assert_eq!(stats.frames_dropped, 2); // 2 dropped due to overflow
    }

    #[test]
    fn test_simlink_presets() {
        // Just verify presets don't panic
        let _slow = SimLink::new(SimLinkConfig::slow_serial());
        let _sat = SimLink::new(SimLinkConfig::satellite());
        let _tac = SimLink::new(SimLinkConfig::tactical_radio());
    }

    #[test]
    fn test_link_stats_reset() {
        let link = LoopbackLink::new();

        link.send(b"Test").expect("send");
        let mut buf = [0u8; 64];
        let _ = link.recv(&mut buf);

        let stats = link.stats();
        assert_eq!(stats.frames_sent, 1);
        assert_eq!(stats.frames_received, 1);

        link.reset_stats();

        let stats = link.stats();
        assert_eq!(stats.frames_sent, 0);
        assert_eq!(stats.frames_received, 0);
    }
}
