// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Compression for low-bandwidth transport.
//!
//! This module provides optional compression with:
//! - **Threshold**: Skip compression for small payloads (overhead > benefit)
//! - **Ratio gate**: Only use compressed output if it's actually smaller
//!
//! # Compression Algorithms
//!
//! - **LZ4** (feature `lowbw-lz4`): Fast compression, good for real-time
//! - **Deflate** (always available via flate2): Better ratio, slower
//!
//! # Wire Format
//!
//! Compressed payload is prefixed with original length (varint) for decompression:
//! ```text
//! compressed_payload = orig_len(varint) | compressed_bytes
//! ```
//!
//! The COMPRESSED flag in record flags indicates compression is applied.

use super::varint::{decode_varint, encode_varint, varint_len};

/// Compression algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionAlgo {
    /// No compression.
    #[default]
    None,
    /// LZ4 compression (requires `lowbw-lz4` feature).
    #[cfg(feature = "lowbw-lz4")]
    Lz4,
    /// Deflate compression (always available via flate2).
    Deflate,
}

/// Compression configuration.
#[derive(Debug, Clone)]
pub struct CompressConfig {
    /// Algorithm to use.
    pub algo: CompressionAlgo,
    /// Minimum payload size to attempt compression (default: 64 bytes).
    pub threshold: usize,
    /// Minimum compression ratio to accept (default: 0.9 = 10% savings).
    /// If compressed_size > original_size * ratio_gate, skip compression.
    pub ratio_gate: f32,
    /// Deflate compression level (1-9, default: 6).
    pub deflate_level: u32,
}

impl Default for CompressConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "lowbw-lz4")]
            algo: CompressionAlgo::Lz4,
            #[cfg(not(feature = "lowbw-lz4"))]
            algo: CompressionAlgo::None,
            threshold: 64,
            ratio_gate: 0.9,
            deflate_level: 6,
        }
    }
}

/// Error type for compression operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressError {
    /// Buffer too small for output.
    BufferTooSmall,
    /// Decompression failed.
    DecompressFailed,
    /// Invalid compressed data.
    InvalidData,
    /// Original length mismatch after decompression.
    LengthMismatch { expected: usize, actual: usize },
    /// Compression algorithm not available.
    AlgoNotAvailable,
}

impl std::fmt::Display for CompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::DecompressFailed => write!(f, "decompression failed"),
            Self::InvalidData => write!(f, "invalid compressed data"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "length mismatch: expected {}, got {}", expected, actual)
            }
            Self::AlgoNotAvailable => write!(f, "compression algorithm not available"),
        }
    }
}

impl std::error::Error for CompressError {}

/// Compression statistics.
#[derive(Debug, Clone, Default)]
pub struct CompressStats {
    /// Number of payloads compressed.
    pub compressed_count: u64,
    /// Number of payloads skipped (below threshold).
    pub skipped_threshold: u64,
    /// Number of payloads skipped (ratio gate).
    pub skipped_ratio: u64,
    /// Total bytes before compression.
    pub bytes_in: u64,
    /// Total bytes after compression.
    pub bytes_out: u64,
    /// Number of decompressions.
    pub decompressed_count: u64,
}

impl CompressStats {
    /// Calculate overall compression ratio (0.0 = perfect, 1.0 = no compression).
    pub fn ratio(&self) -> f32 {
        if self.bytes_in == 0 {
            1.0
        } else {
            self.bytes_out as f32 / self.bytes_in as f32
        }
    }

    /// Calculate bytes saved.
    pub fn bytes_saved(&self) -> u64 {
        self.bytes_in.saturating_sub(self.bytes_out)
    }
}

/// Result of compression attempt.
#[derive(Debug)]
pub enum CompressResult {
    /// Compression applied, use this data.
    Compressed(Vec<u8>),
    /// Compression skipped (threshold or ratio), use original.
    Skipped,
}

/// Compressor for outgoing data.
#[derive(Debug)]
pub struct Compressor {
    config: CompressConfig,
    /// Statistics.
    pub stats: CompressStats,
}

impl Compressor {
    /// Create a new compressor with the given configuration.
    pub fn new(config: CompressConfig) -> Self {
        Self {
            config,
            stats: CompressStats::default(),
        }
    }

    /// Create a compressor with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CompressConfig::default())
    }

    /// Attempt to compress the payload.
    ///
    /// Returns `CompressResult::Compressed` if compression was beneficial,
    /// or `CompressResult::Skipped` if the original should be used.
    pub fn compress(&mut self, payload: &[u8]) -> Result<CompressResult, CompressError> {
        // Check threshold
        if payload.len() < self.config.threshold {
            self.stats.skipped_threshold += 1;
            return Ok(CompressResult::Skipped);
        }

        // Skip if no compression algorithm
        if self.config.algo == CompressionAlgo::None {
            self.stats.skipped_threshold += 1;
            return Ok(CompressResult::Skipped);
        }

        // Compress
        let compressed = self.compress_raw(payload)?;

        // Calculate wire size (with orig_len prefix)
        let wire_size = varint_len(payload.len() as u64) + compressed.len();

        // Check ratio gate
        let ratio = wire_size as f32 / payload.len() as f32;
        if ratio > self.config.ratio_gate {
            self.stats.skipped_ratio += 1;
            return Ok(CompressResult::Skipped);
        }

        // Build output: orig_len(varint) | compressed_bytes
        let mut output = Vec::with_capacity(wire_size);
        let mut tmp = [0u8; 10];
        let n = encode_varint(payload.len() as u64, &mut tmp);
        output.extend_from_slice(&tmp[..n]);
        output.extend_from_slice(&compressed);

        self.stats.compressed_count += 1;
        self.stats.bytes_in += payload.len() as u64;
        self.stats.bytes_out += output.len() as u64;

        Ok(CompressResult::Compressed(output))
    }

    fn compress_raw(&self, payload: &[u8]) -> Result<Vec<u8>, CompressError> {
        match self.config.algo {
            CompressionAlgo::None => Ok(payload.to_vec()),

            #[cfg(feature = "lowbw-lz4")]
            CompressionAlgo::Lz4 => Ok(lz4_flex::compress_prepend_size(payload)),

            CompressionAlgo::Deflate => {
                use flate2::write::DeflateEncoder;
                use flate2::Compression;
                use std::io::Write;

                let mut encoder =
                    DeflateEncoder::new(Vec::new(), Compression::new(self.config.deflate_level));
                encoder
                    .write_all(payload)
                    .map_err(|_| CompressError::DecompressFailed)?;
                encoder
                    .finish()
                    .map_err(|_| CompressError::DecompressFailed)
            }
        }
    }

    /// Get current statistics.
    pub fn stats(&self) -> &CompressStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = CompressStats::default();
    }

    /// Get the current configuration.
    pub fn config(&self) -> &CompressConfig {
        &self.config
    }
}

/// Decompressor for incoming data.
#[derive(Debug)]
pub struct Decompressor {
    algo: CompressionAlgo,
    /// Statistics.
    pub stats: CompressStats,
}

impl Decompressor {
    /// Create a new decompressor for the given algorithm.
    pub fn new(algo: CompressionAlgo) -> Self {
        Self {
            algo,
            stats: CompressStats::default(),
        }
    }

    /// Decompress a compressed payload.
    ///
    /// The payload must include the orig_len prefix (as produced by Compressor).
    pub fn decompress(&mut self, compressed: &[u8]) -> Result<Vec<u8>, CompressError> {
        if compressed.is_empty() {
            return Err(CompressError::InvalidData);
        }

        // Decode orig_len prefix
        let (orig_len, prefix_size) =
            decode_varint(compressed).map_err(|_| CompressError::InvalidData)?;
        let orig_len = orig_len as usize;

        if prefix_size >= compressed.len() {
            return Err(CompressError::InvalidData);
        }

        let compressed_data = &compressed[prefix_size..];

        // Decompress
        let decompressed = self.decompress_raw(compressed_data, orig_len)?;

        // Verify length
        if decompressed.len() != orig_len {
            return Err(CompressError::LengthMismatch {
                expected: orig_len,
                actual: decompressed.len(),
            });
        }

        self.stats.decompressed_count += 1;
        self.stats.bytes_in += compressed.len() as u64;
        self.stats.bytes_out += decompressed.len() as u64;

        Ok(decompressed)
    }

    fn decompress_raw(
        &self,
        compressed: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, CompressError> {
        match self.algo {
            CompressionAlgo::None => Ok(compressed.to_vec()),

            #[cfg(feature = "lowbw-lz4")]
            CompressionAlgo::Lz4 => {
                // lz4_flex::compress_prepend_size adds its own length prefix
                // We need to use decompress_size_prepended
                lz4_flex::decompress_size_prepended(compressed)
                    .map_err(|_| CompressError::DecompressFailed)
            }

            CompressionAlgo::Deflate => {
                use flate2::read::DeflateDecoder;
                use std::io::Read;

                let mut decoder = DeflateDecoder::new(compressed);
                let mut output = Vec::with_capacity(expected_len);
                decoder
                    .read_to_end(&mut output)
                    .map_err(|_| CompressError::DecompressFailed)?;
                Ok(output)
            }
        }
    }

    /// Get current statistics.
    pub fn stats(&self) -> &CompressStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = CompressStats::default();
    }
}

/// Check if a compression algorithm is available.
pub fn is_algo_available(algo: CompressionAlgo) -> bool {
    match algo {
        CompressionAlgo::None => true,
        #[cfg(feature = "lowbw-lz4")]
        CompressionAlgo::Lz4 => true,
        #[cfg(not(feature = "lowbw-lz4"))]
        CompressionAlgo::Deflate => true,
        #[cfg(feature = "lowbw-lz4")]
        CompressionAlgo::Deflate => true,
    }
}

/// Get the best available compression algorithm.
pub fn best_available_algo() -> CompressionAlgo {
    #[cfg(feature = "lowbw-lz4")]
    {
        CompressionAlgo::Lz4
    }
    #[cfg(not(feature = "lowbw-lz4"))]
    {
        CompressionAlgo::Deflate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_config_default() {
        let config = CompressConfig::default();
        assert_eq!(config.threshold, 64);
        assert!((config.ratio_gate - 0.9).abs() < 0.01);
        assert_eq!(config.deflate_level, 6);
    }

    #[test]
    fn test_compressor_skip_small_payload() {
        let mut compressor = Compressor::new(CompressConfig {
            algo: CompressionAlgo::Deflate,
            threshold: 64,
            ..Default::default()
        });

        // Small payload should be skipped
        let small = b"hello";
        let result = compressor.compress(small).unwrap();
        assert!(matches!(result, CompressResult::Skipped));
        assert_eq!(compressor.stats.skipped_threshold, 1);
    }

    #[test]
    fn test_compressor_deflate_roundtrip() {
        let config = CompressConfig {
            algo: CompressionAlgo::Deflate,
            threshold: 16,
            ratio_gate: 1.5, // Allow some expansion for testing
            ..Default::default()
        };

        let mut compressor = Compressor::new(config);
        let mut decompressor = Decompressor::new(CompressionAlgo::Deflate);

        // Compressible data (repeated pattern)
        let data: Vec<u8> = (0..256).map(|i| (i % 16) as u8).collect();

        let result = compressor.compress(&data).unwrap();

        if let CompressResult::Compressed(compressed) = result {
            let decompressed = decompressor.decompress(&compressed).unwrap();
            assert_eq!(decompressed, data);
            assert_eq!(compressor.stats.compressed_count, 1);
            assert_eq!(decompressor.stats.decompressed_count, 1);
        } else {
            // Compression skipped due to ratio - still valid
            assert!(compressor.stats.skipped_ratio > 0 || compressor.stats.skipped_threshold > 0);
        }
    }

    #[test]
    fn test_compressor_ratio_gate() {
        let config = CompressConfig {
            algo: CompressionAlgo::Deflate,
            threshold: 8,
            ratio_gate: 0.5, // Require 50% compression
            ..Default::default()
        };

        let mut compressor = Compressor::new(config);

        // Random data is hard to compress
        let random_data: Vec<u8> = (0..100).map(|i| ((i * 17 + 31) % 256) as u8).collect();

        let result = compressor.compress(&random_data).unwrap();

        // Random data likely won't achieve 50% compression
        // Either compressed or skipped due to ratio
        match result {
            CompressResult::Compressed(_) => {
                // If it did compress, check the ratio was good
                assert!(compressor.stats.ratio() <= 0.5);
            }
            CompressResult::Skipped => {
                assert!(compressor.stats.skipped_ratio > 0);
            }
        }
    }

    #[test]
    fn test_compressor_highly_compressible() {
        let config = CompressConfig {
            algo: CompressionAlgo::Deflate,
            threshold: 16,
            ratio_gate: 0.9,
            ..Default::default()
        };

        let mut compressor = Compressor::new(config);
        let mut decompressor = Decompressor::new(CompressionAlgo::Deflate);

        // Highly compressible: all zeros
        let data = vec![0u8; 256];

        let result = compressor.compress(&data).unwrap();

        match result {
            CompressResult::Compressed(compressed) => {
                // Should be much smaller
                assert!(compressed.len() < data.len());

                let decompressed = decompressor.decompress(&compressed).unwrap();
                assert_eq!(decompressed, data);
            }
            CompressResult::Skipped => {
                unreachable!("Highly compressible data should not be skipped");
            }
        }
    }

    #[test]
    fn test_decompressor_invalid_data() {
        let mut decompressor = Decompressor::new(CompressionAlgo::Deflate);

        // Empty
        assert!(decompressor.decompress(&[]).is_err());

        // Just a varint, no data
        assert!(decompressor.decompress(&[0x10]).is_err());

        // Invalid compressed data
        assert!(decompressor.decompress(&[0x10, 0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_compress_stats() {
        let config = CompressConfig {
            algo: CompressionAlgo::Deflate,
            threshold: 8,
            ratio_gate: 1.5,
            ..Default::default()
        };

        let mut compressor = Compressor::new(config);

        // Compress some data
        let data = vec![0u8; 100];
        let _ = compressor.compress(&data);

        // Check stats
        assert!(compressor.stats.bytes_in > 0 || compressor.stats.skipped_threshold > 0);
    }

    #[test]
    fn test_stats_ratio() {
        let mut stats = CompressStats::default();

        // No data yet
        assert!((stats.ratio() - 1.0).abs() < 0.01);

        // Add some compression stats
        stats.bytes_in = 1000;
        stats.bytes_out = 500;
        assert!((stats.ratio() - 0.5).abs() < 0.01);
        assert_eq!(stats.bytes_saved(), 500);
    }

    #[test]
    fn test_is_algo_available() {
        assert!(is_algo_available(CompressionAlgo::None));
        assert!(is_algo_available(CompressionAlgo::Deflate));

        #[cfg(feature = "lowbw-lz4")]
        assert!(is_algo_available(CompressionAlgo::Lz4));
    }

    #[test]
    fn test_best_available_algo() {
        let algo = best_available_algo();

        #[cfg(feature = "lowbw-lz4")]
        assert_eq!(algo, CompressionAlgo::Lz4);

        #[cfg(not(feature = "lowbw-lz4"))]
        assert_eq!(algo, CompressionAlgo::Deflate);
    }

    #[test]
    fn test_compressor_no_compression() {
        let config = CompressConfig {
            algo: CompressionAlgo::None,
            threshold: 8,
            ..Default::default()
        };

        let mut compressor = Compressor::new(config);

        let data = vec![0u8; 100];
        let result = compressor.compress(&data).unwrap();

        assert!(matches!(result, CompressResult::Skipped));
    }

    #[test]
    fn test_deflate_various_sizes() {
        let config = CompressConfig {
            algo: CompressionAlgo::Deflate,
            threshold: 8,
            ratio_gate: 1.5,
            ..Default::default()
        };

        for size in [16, 64, 256, 1024] {
            let mut compressor = Compressor::new(config.clone());
            let mut decompressor = Decompressor::new(CompressionAlgo::Deflate);

            let data: Vec<u8> = (0..size).map(|i| (i % 64) as u8).collect();

            if let CompressResult::Compressed(compressed) = compressor.compress(&data).unwrap() {
                let decompressed = decompressor.decompress(&compressed).unwrap();
                assert_eq!(decompressed, data, "Roundtrip failed for size {}", size);
            }
        }
    }

    #[test]
    fn test_compress_repeated_pattern() {
        let config = CompressConfig {
            algo: CompressionAlgo::Deflate,
            threshold: 8,
            ratio_gate: 0.95,
            ..Default::default()
        };

        let mut compressor = Compressor::new(config);
        let mut decompressor = Decompressor::new(CompressionAlgo::Deflate);

        // Repeated pattern should compress well
        let pattern = b"ABCDEFGH";
        let data: Vec<u8> = pattern.iter().cycle().take(256).copied().collect();

        let result = compressor.compress(&data).unwrap();

        if let CompressResult::Compressed(compressed) = result {
            assert!(
                compressed.len() < data.len(),
                "Repeated pattern should compress"
            );
            let decompressed = decompressor.decompress(&compressed).unwrap();
            assert_eq!(decompressed, data);
        }
    }

    #[cfg(feature = "lowbw-lz4")]
    mod lz4_tests {
        use super::*;

        #[test]
        fn test_lz4_roundtrip() {
            let config = CompressConfig {
                algo: CompressionAlgo::Lz4,
                threshold: 16,
                ratio_gate: 1.5,
                ..Default::default()
            };

            let mut compressor = Compressor::new(config);
            let mut decompressor = Decompressor::new(CompressionAlgo::Lz4);

            let data: Vec<u8> = (0..256).map(|i| (i % 16) as u8).collect();

            if let CompressResult::Compressed(compressed) = compressor.compress(&data).unwrap() {
                let decompressed = decompressor.decompress(&compressed).unwrap();
                assert_eq!(decompressed, data);
            }
        }

        #[test]
        fn test_lz4_highly_compressible() {
            let config = CompressConfig {
                algo: CompressionAlgo::Lz4,
                threshold: 16,
                ratio_gate: 0.9,
                ..Default::default()
            };

            let mut compressor = Compressor::new(config);
            let mut decompressor = Decompressor::new(CompressionAlgo::Lz4);

            let data = vec![0u8; 256];

            if let CompressResult::Compressed(compressed) = compressor.compress(&data).unwrap() {
                assert!(compressed.len() < data.len());
                let decompressed = decompressor.decompress(&compressed).unwrap();
                assert_eq!(decompressed, data);
            }
        }

        #[test]
        fn test_lz4_various_sizes() {
            let config = CompressConfig {
                algo: CompressionAlgo::Lz4,
                threshold: 8,
                ratio_gate: 1.5,
                ..Default::default()
            };

            for size in [16, 64, 256, 1024, 4096] {
                let mut compressor = Compressor::new(config.clone());
                let mut decompressor = Decompressor::new(CompressionAlgo::Lz4);

                let data: Vec<u8> = (0..size).map(|i| (i % 64) as u8).collect();

                if let CompressResult::Compressed(compressed) = compressor.compress(&data).unwrap()
                {
                    let decompressed = decompressor.decompress(&compressed).unwrap();
                    assert_eq!(decompressed, data, "LZ4 roundtrip failed for size {}", size);
                }
            }
        }
    }
}
