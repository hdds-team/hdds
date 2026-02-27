// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Gateway statistics and rate limiting

// Use AtomicU64 on 64-bit, AtomicU32 on 32-bit (ESP32, etc.)
#[cfg(not(target_pointer_width = "64"))]
use std::sync::atomic::AtomicU32 as AtomicCounter;
#[cfg(target_pointer_width = "64")]
use std::sync::atomic::AtomicU64 as AtomicCounter;

#[cfg(target_pointer_width = "64")]
type CounterValue = u64;
#[cfg(not(target_pointer_width = "64"))]
type CounterValue = u32;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// Gateway statistics
#[derive(Debug)]
pub struct GatewayStats {
    /// Messages received from LoRa
    pub lora_rx_count: AtomicCounter,
    /// Messages sent to LoRa
    pub lora_tx_count: AtomicCounter,
    /// Messages received from WiFi/UDP
    pub wifi_rx_count: AtomicCounter,
    /// Messages sent to WiFi/UDP
    pub wifi_tx_count: AtomicCounter,
    /// Messages dropped (rate limited)
    pub dropped_rate_limit: AtomicCounter,
    /// Messages dropped (filter)
    pub dropped_filter: AtomicCounter,
    /// Bytes received from LoRa
    pub lora_rx_bytes: AtomicCounter,
    /// Bytes sent to LoRa
    pub lora_tx_bytes: AtomicCounter,
    /// Bytes received from WiFi
    pub wifi_rx_bytes: AtomicCounter,
    /// Bytes sent to WiFi
    pub wifi_tx_bytes: AtomicCounter,
    /// Parse errors
    pub parse_errors: AtomicCounter,
    /// Start time
    start_time: Instant,
}

impl GatewayStats {
    /// Create new statistics tracker
    pub fn new() -> Self {
        Self {
            lora_rx_count: AtomicCounter::new(0),
            lora_tx_count: AtomicCounter::new(0),
            wifi_rx_count: AtomicCounter::new(0),
            wifi_tx_count: AtomicCounter::new(0),
            dropped_rate_limit: AtomicCounter::new(0),
            dropped_filter: AtomicCounter::new(0),
            lora_rx_bytes: AtomicCounter::new(0),
            lora_tx_bytes: AtomicCounter::new(0),
            wifi_rx_bytes: AtomicCounter::new(0),
            wifi_tx_bytes: AtomicCounter::new(0),
            parse_errors: AtomicCounter::new(0),
            start_time: Instant::now(),
        }
    }

    /// Record LoRa receive
    pub fn record_lora_rx(&self, bytes: usize) {
        self.lora_rx_count.fetch_add(1, Ordering::Relaxed);
        self.lora_rx_bytes
            .fetch_add(bytes as CounterValue, Ordering::Relaxed);
    }

    /// Record LoRa transmit
    pub fn record_lora_tx(&self, bytes: usize) {
        self.lora_tx_count.fetch_add(1, Ordering::Relaxed);
        self.lora_tx_bytes
            .fetch_add(bytes as CounterValue, Ordering::Relaxed);
    }

    /// Record WiFi receive
    pub fn record_wifi_rx(&self, bytes: usize) {
        self.wifi_rx_count.fetch_add(1, Ordering::Relaxed);
        self.wifi_rx_bytes
            .fetch_add(bytes as CounterValue, Ordering::Relaxed);
    }

    /// Record WiFi transmit
    pub fn record_wifi_tx(&self, bytes: usize) {
        self.wifi_tx_count.fetch_add(1, Ordering::Relaxed);
        self.wifi_tx_bytes
            .fetch_add(bytes as CounterValue, Ordering::Relaxed);
    }

    /// Record rate-limited drop
    pub fn record_rate_limit_drop(&self) {
        self.dropped_rate_limit.fetch_add(1, Ordering::Relaxed);
    }

    /// Record filter drop
    pub fn record_filter_drop(&self) {
        self.dropped_filter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record parse error
    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get snapshot of all stats
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            lora_rx_count: self.lora_rx_count.load(Ordering::Relaxed),
            lora_tx_count: self.lora_tx_count.load(Ordering::Relaxed),
            wifi_rx_count: self.wifi_rx_count.load(Ordering::Relaxed),
            wifi_tx_count: self.wifi_tx_count.load(Ordering::Relaxed),
            dropped_rate_limit: self.dropped_rate_limit.load(Ordering::Relaxed),
            dropped_filter: self.dropped_filter.load(Ordering::Relaxed),
            lora_rx_bytes: self.lora_rx_bytes.load(Ordering::Relaxed),
            lora_tx_bytes: self.lora_tx_bytes.load(Ordering::Relaxed),
            wifi_rx_bytes: self.wifi_rx_bytes.load(Ordering::Relaxed),
            wifi_tx_bytes: self.wifi_tx_bytes.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Format stats as string
    pub fn format_summary(&self) -> String {
        let snap = self.snapshot();
        format!(
            "Gateway Stats (uptime: {}s)\n\
             LoRa:  RX {} msgs ({} bytes), TX {} msgs ({} bytes)\n\
             WiFi:  RX {} msgs ({} bytes), TX {} msgs ({} bytes)\n\
             Drops: rate_limit={}, filter={}, errors={}",
            snap.uptime_secs,
            snap.lora_rx_count,
            snap.lora_rx_bytes,
            snap.lora_tx_count,
            snap.lora_tx_bytes,
            snap.wifi_rx_count,
            snap.wifi_rx_bytes,
            snap.wifi_tx_count,
            snap.wifi_tx_bytes,
            snap.dropped_rate_limit,
            snap.dropped_filter,
            snap.parse_errors
        )
    }
}

impl Default for GatewayStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics snapshot (immutable copy of current stats)
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    /// Messages received from LoRa
    pub lora_rx_count: CounterValue,
    /// Messages sent to LoRa
    pub lora_tx_count: CounterValue,
    /// Messages received from WiFi/UDP
    pub wifi_rx_count: CounterValue,
    /// Messages sent to WiFi/UDP
    pub wifi_tx_count: CounterValue,
    /// Messages dropped (rate limited)
    pub dropped_rate_limit: CounterValue,
    /// Messages dropped (filter)
    pub dropped_filter: CounterValue,
    /// Bytes received from LoRa
    pub lora_rx_bytes: CounterValue,
    /// Bytes sent to LoRa
    pub lora_tx_bytes: CounterValue,
    /// Bytes received from WiFi
    pub wifi_rx_bytes: CounterValue,
    /// Bytes sent to WiFi
    pub wifi_tx_bytes: CounterValue,
    /// Parse errors
    pub parse_errors: CounterValue,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

/// Token bucket rate limiter
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum tokens (burst capacity)
    capacity: u32,
    /// Current tokens available
    tokens: f64,
    /// Tokens added per second
    rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `rate` - Messages per second
    /// * `burst` - Maximum burst size (0 = same as rate)
    pub fn new(rate: u32, burst: u32) -> Self {
        let capacity = if burst == 0 { rate } else { burst };
        Self {
            capacity,
            tokens: capacity as f64,
            rate: rate as f64,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token
    ///
    /// Returns true if message is allowed, false if rate limited
    pub fn try_acquire(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Try to consume multiple tokens
    pub fn try_acquire_n(&mut self, n: u32) -> bool {
        self.refill();

        let needed = n as f64;
        if self.tokens >= needed {
            self.tokens -= needed;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        self.last_refill = now;

        let add = elapsed.as_secs_f64() * self.rate;
        self.tokens = (self.tokens + add).min(self.capacity as f64);
    }

    /// Get current available tokens
    pub fn available(&mut self) -> u32 {
        self.refill();
        self.tokens as u32
    }

    /// Reset to full capacity
    pub fn reset(&mut self) {
        self.tokens = self.capacity as f64;
        self.last_refill = Instant::now();
    }
}

/// Per-topic rate limiter
pub struct TopicRateLimiter {
    /// Default rate limit per topic
    default_rate: u32,
    /// Per-topic limiters
    limiters: std::collections::HashMap<String, RateLimiter>,
    /// Global limiter
    global: RateLimiter,
}

impl TopicRateLimiter {
    /// Create a new topic rate limiter
    pub fn new(global_rate: u32, default_topic_rate: u32) -> Self {
        Self {
            default_rate: default_topic_rate,
            limiters: std::collections::HashMap::new(),
            global: RateLimiter::new(global_rate, global_rate * 2),
        }
    }

    /// Try to send a message for a topic
    pub fn try_acquire(&mut self, topic: Option<&str>) -> bool {
        // Check global limit first
        if !self.global.try_acquire() {
            return false;
        }

        // Check topic-specific limit if topic known
        if let Some(t) = topic {
            let rate = self.default_rate;
            let limiter = self
                .limiters
                .entry(t.to_string())
                .or_insert_with(|| RateLimiter::new(rate, rate * 2));
            limiter.try_acquire()
        } else {
            true
        }
    }

    /// Set custom rate for a specific topic
    pub fn set_topic_rate(&mut self, topic: &str, rate: u32) {
        self.limiters
            .insert(topic.to_string(), RateLimiter::new(rate, rate * 2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_stats_recording() {
        let stats = GatewayStats::new();

        stats.record_lora_rx(100);
        stats.record_lora_rx(50);
        stats.record_wifi_tx(200);

        let snap = stats.snapshot();
        assert_eq!(snap.lora_rx_count, 2);
        assert_eq!(snap.lora_rx_bytes, 150);
        assert_eq!(snap.wifi_tx_count, 1);
        assert_eq!(snap.wifi_tx_bytes, 200);
    }

    #[test]
    fn test_rate_limiter_basic() {
        let mut limiter = RateLimiter::new(10, 10);

        // Should be able to acquire initial burst
        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }

        // Should be rate limited now
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_refill() {
        let mut limiter = RateLimiter::new(100, 10);

        // Exhaust tokens
        for _ in 0..10 {
            limiter.try_acquire();
        }
        assert!(!limiter.try_acquire());

        // Wait for refill (100/sec = 1 token per 10ms)
        thread::sleep(Duration::from_millis(50));

        // Should have some tokens now
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_topic_rate_limiter() {
        let mut limiter = TopicRateLimiter::new(100, 10);

        // Should work for unknown topic
        assert!(limiter.try_acquire(None));

        // Should work for known topic
        assert!(limiter.try_acquire(Some("Temperature")));

        // Exhaust topic limit (burst = rate * 2 = 20)
        // Already consumed 1, so need 19 more to exhaust
        for _ in 0..19 {
            limiter.try_acquire(Some("Temperature"));
        }

        // Temperature should be limited, but other topics ok
        assert!(!limiter.try_acquire(Some("Temperature")));
        assert!(limiter.try_acquire(Some("Humidity")));
    }

    #[test]
    fn test_stats_format() {
        let stats = GatewayStats::new();
        stats.record_lora_rx(100);
        stats.record_wifi_tx(200);

        let summary = stats.format_summary();
        assert!(summary.contains("LoRa:"));
        assert!(summary.contains("WiFi:"));
    }
}
