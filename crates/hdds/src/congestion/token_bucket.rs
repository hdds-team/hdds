// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Token bucket rate limiter.
//!
//! Provides a classic token bucket algorithm for rate limiting with:
//! - Configurable rate (tokens per second)
//! - Configurable burst capacity
//! - Automatic refill based on elapsed time

use std::time::{Duration, Instant};

/// Token bucket rate limiter.
///
/// Tokens are added at a fixed rate up to a maximum capacity (burst size).
/// Each send consumes tokens equal to the packet size.
#[derive(Debug)]
pub struct TokenBucket {
    /// Current token count (in bytes).
    tokens: u64,

    /// Maximum token capacity (burst size in bytes).
    capacity: u64,

    /// Token refill rate (bytes per second).
    rate_bps: u32,

    /// Last refill timestamp.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// # Arguments
    ///
    /// * `rate_bps` - Token refill rate in bytes per second
    /// * `capacity` - Maximum token capacity (burst size) in bytes
    pub fn new(rate_bps: u32, capacity: u64) -> Self {
        Self {
            tokens: capacity, // Start full
            capacity,
            rate_bps,
            last_refill: Instant::now(),
        }
    }

    /// Create a token bucket starting empty.
    pub fn new_empty(rate_bps: u32, capacity: u64) -> Self {
        Self {
            tokens: 0,
            capacity,
            rate_bps,
            last_refill: Instant::now(),
        }
    }

    /// Create a token bucket with initial tokens.
    pub fn with_initial(rate_bps: u32, capacity: u64, initial: u64) -> Self {
        Self {
            tokens: initial.min(capacity),
            capacity,
            rate_bps,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume tokens for a packet.
    ///
    /// Returns `true` if tokens were available and consumed.
    /// Returns `false` if insufficient tokens (no tokens consumed).
    pub fn try_consume(&mut self, bytes: u64) -> bool {
        self.refill();

        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    /// Consume tokens, returning actual amount consumed.
    ///
    /// This is useful for partial sends or when you want to send
    /// whatever is available.
    pub fn consume_available(&mut self, bytes: u64) -> u64 {
        self.refill();

        let consumed = self.tokens.min(bytes);
        self.tokens -= consumed;
        consumed
    }

    /// Force consume tokens (can go negative conceptually, but we clamp to 0).
    ///
    /// Use this when you must send regardless of tokens (e.g., P0 critical).
    pub fn force_consume(&mut self, bytes: u64) {
        self.refill();
        self.tokens = self.tokens.saturating_sub(bytes);
    }

    /// Check if tokens are available without consuming.
    pub fn has_tokens(&mut self, bytes: u64) -> bool {
        self.refill();
        self.tokens >= bytes
    }

    /// Get current token count.
    pub fn tokens(&mut self) -> u64 {
        self.refill();
        self.tokens
    }

    /// Get current token count without refilling.
    pub fn tokens_snapshot(&self) -> u64 {
        self.tokens
    }

    /// Get the capacity (burst size).
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Get the current rate in bytes per second.
    pub fn rate(&self) -> u32 {
        self.rate_bps
    }

    /// Update the rate.
    ///
    /// This is called when the congestion controller adjusts the rate.
    pub fn set_rate(&mut self, rate_bps: u32) {
        self.refill(); // Refill at old rate first
        self.rate_bps = rate_bps;
    }

    /// Update the capacity.
    pub fn set_capacity(&mut self, capacity: u64) {
        self.capacity = capacity;
        self.tokens = self.tokens.min(capacity);
    }

    /// Time until `bytes` tokens will be available.
    ///
    /// Returns `Duration::ZERO` if already available.
    pub fn time_until_available(&mut self, bytes: u64) -> Duration {
        self.refill();

        if self.tokens >= bytes {
            return Duration::ZERO;
        }

        let needed = bytes - self.tokens;
        let seconds = needed as f64 / self.rate_bps as f64;
        Duration::from_secs_f64(seconds)
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed.is_zero() {
            return;
        }

        // Calculate tokens to add
        let add = (elapsed.as_secs_f64() * self.rate_bps as f64) as u64;

        if add > 0 {
            self.tokens = (self.tokens + add).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Reset the bucket to full capacity.
    pub fn reset(&mut self) {
        self.tokens = self.capacity;
        self.last_refill = Instant::now();
    }

    /// Reset the bucket to empty.
    pub fn drain(&mut self) {
        self.tokens = 0;
        self.last_refill = Instant::now();
    }

    /// Get fill ratio (0.0 to 1.0).
    pub fn fill_ratio(&mut self) -> f32 {
        self.refill();
        if self.capacity == 0 {
            return 1.0;
        }
        self.tokens as f32 / self.capacity as f32
    }
}

impl Clone for TokenBucket {
    fn clone(&self) -> Self {
        Self {
            tokens: self.tokens,
            capacity: self.capacity,
            rate_bps: self.rate_bps,
            last_refill: Instant::now(), // Reset time on clone
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_starts_full() {
        let mut bucket = TokenBucket::new(1000, 500);
        assert_eq!(bucket.tokens(), 500);
    }

    #[test]
    fn test_new_empty_starts_empty() {
        let mut bucket = TokenBucket::new_empty(1000, 500);
        assert_eq!(bucket.tokens(), 0);
    }

    #[test]
    fn test_with_initial() {
        let mut bucket = TokenBucket::with_initial(1000, 500, 200);
        assert_eq!(bucket.tokens(), 200);

        // Initial capped to capacity
        let mut bucket2 = TokenBucket::with_initial(1000, 500, 1000);
        assert_eq!(bucket2.tokens(), 500);
    }

    #[test]
    fn test_try_consume_success() {
        let mut bucket = TokenBucket::new(1000, 500);
        assert!(bucket.try_consume(100));
        assert_eq!(bucket.tokens(), 400);
    }

    #[test]
    fn test_try_consume_failure() {
        let mut bucket = TokenBucket::new(1000, 100);
        assert!(!bucket.try_consume(200));
        assert_eq!(bucket.tokens(), 100); // Unchanged
    }

    #[test]
    fn test_consume_available() {
        let mut bucket = TokenBucket::new(1000, 100);
        let consumed = bucket.consume_available(150);
        assert_eq!(consumed, 100);
        assert_eq!(bucket.tokens_snapshot(), 0);
    }

    #[test]
    fn test_force_consume() {
        let mut bucket = TokenBucket::new(1000, 100);
        bucket.force_consume(150);
        assert_eq!(bucket.tokens(), 0); // Clamped to 0
    }

    #[test]
    fn test_has_tokens() {
        let mut bucket = TokenBucket::new(1000, 100);
        assert!(bucket.has_tokens(50));
        assert!(bucket.has_tokens(100));
        assert!(!bucket.has_tokens(101));
    }

    #[test]
    fn test_refill() {
        let mut bucket = TokenBucket::new_empty(10_000, 1000); // 10KB/s

        // Wait 50ms -> should add ~500 bytes
        thread::sleep(Duration::from_millis(50));

        let tokens = bucket.tokens();
        assert!((400..=600).contains(&tokens), "tokens={}", tokens);
    }

    #[test]
    fn test_refill_capped_at_capacity() {
        let mut bucket = TokenBucket::new(10_000, 100); // Full

        thread::sleep(Duration::from_millis(50));

        // Should still be at capacity
        assert_eq!(bucket.tokens(), 100);
    }

    #[test]
    fn test_set_rate() {
        let mut bucket = TokenBucket::new_empty(1000, 1000);

        // Wait a bit
        thread::sleep(Duration::from_millis(50));

        // Change rate
        bucket.set_rate(2000);
        assert_eq!(bucket.rate(), 2000);

        // Tokens should have been added at old rate before change
        let tokens = bucket.tokens_snapshot();
        assert!(tokens > 0, "should have refilled before rate change");
    }

    #[test]
    fn test_set_capacity() {
        let mut bucket = TokenBucket::new(1000, 500);
        assert_eq!(bucket.capacity(), 500);

        bucket.set_capacity(200);
        assert_eq!(bucket.capacity(), 200);
        assert_eq!(bucket.tokens(), 200); // Clamped
    }

    #[test]
    fn test_time_until_available() {
        let mut bucket = TokenBucket::new(1000, 100); // 1KB/s, 100B capacity

        // Already have 100 tokens
        assert_eq!(bucket.time_until_available(50), Duration::ZERO);
        assert_eq!(bucket.time_until_available(100), Duration::ZERO);

        // Need to wait for 150 tokens (have 100, need 50 more)
        let wait = bucket.time_until_available(150);
        assert!(wait.as_millis() >= 45 && wait.as_millis() <= 55);
    }

    #[test]
    fn test_reset() {
        let mut bucket = TokenBucket::new(1000, 100);
        bucket.try_consume(80);
        assert_eq!(bucket.tokens(), 20);

        bucket.reset();
        assert_eq!(bucket.tokens(), 100);
    }

    #[test]
    fn test_drain() {
        let mut bucket = TokenBucket::new(1000, 100);
        bucket.drain();
        assert_eq!(bucket.tokens(), 0);
    }

    #[test]
    fn test_fill_ratio() {
        let mut bucket = TokenBucket::new(1000, 100);
        assert!((bucket.fill_ratio() - 1.0).abs() < 0.01);

        bucket.try_consume(50);
        assert!((bucket.fill_ratio() - 0.5).abs() < 0.01);

        bucket.drain();
        assert!((bucket.fill_ratio() - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_clone() {
        let bucket = TokenBucket::new(1000, 100);
        let mut clone = bucket.clone();

        // Clone should have same tokens and capacity
        assert_eq!(clone.tokens(), 100);
        assert_eq!(clone.capacity(), 100);
        assert_eq!(clone.rate(), 1000);
    }

    #[test]
    fn test_zero_rate() {
        let mut bucket = TokenBucket::new_empty(0, 100);

        thread::sleep(Duration::from_millis(10));

        // No tokens should be added with zero rate
        assert_eq!(bucket.tokens(), 0);
    }

    #[test]
    fn test_large_capacity() {
        let mut bucket = TokenBucket::new(1_000_000_000, 10_000_000_000); // 1GB/s, 10GB capacity
        assert!(bucket.try_consume(1_000_000_000)); // 1GB
                                                    // Allow some tokens to have been added due to timing
        let tokens = bucket.tokens();
        assert!(
            tokens >= 9_000_000_000,
            "tokens should be at least 9GB, got {}",
            tokens
        );
        assert!(
            tokens <= 10_000_000_000,
            "tokens should be at most 10GB, got {}",
            tokens
        );
    }

    #[test]
    fn test_consume_exact_amount() {
        let mut bucket = TokenBucket::new(1000, 100);
        assert!(bucket.try_consume(100));
        assert_eq!(bucket.tokens(), 0);
        assert!(!bucket.try_consume(1));
    }
}
