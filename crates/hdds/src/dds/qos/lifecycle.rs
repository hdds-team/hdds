// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Data lifecycle policies for readers and writers.
//!
//! Controls automatic disposal of instances and sample cleanup behavior.

/// Writer data lifecycle policy controlling automatic disposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterDataLifecycle {
    /// Whether to automatically dispose unregistered instances.
    pub autodispose_unregistered_instances: bool,
}

impl WriterDataLifecycle {
    /// Create WRITER_DATA_LIFECYCLE with auto-dispose (default).
    pub fn auto_dispose() -> Self {
        Self {
            autodispose_unregistered_instances: true,
        }
    }

    /// Create WRITER_DATA_LIFECYCLE with manual dispose.
    pub fn manual_dispose() -> Self {
        Self {
            autodispose_unregistered_instances: false,
        }
    }

    /// Check if auto-dispose is enabled.
    pub fn is_auto_dispose(&self) -> bool {
        self.autodispose_unregistered_instances
    }

    /// Check if manual dispose is required.
    pub fn is_manual_dispose(&self) -> bool {
        !self.autodispose_unregistered_instances
    }
}

impl Default for WriterDataLifecycle {
    fn default() -> Self {
        Self::auto_dispose()
    }
}

/// Reader data lifecycle policy controlling automatic purging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReaderDataLifecycle {
    /// Delay before purging NOT_ALIVE_NO_WRITERS instances (microseconds).
    ///
    /// `i64::MAX` = INFINITE (never purge).
    pub autopurge_nowriter_samples_delay_us: i64,
    /// Delay before purging NOT_ALIVE_DISPOSED instances (microseconds).
    ///
    /// `i64::MAX` = INFINITE (never purge).
    pub autopurge_disposed_samples_delay_us: i64,
}

impl ReaderDataLifecycle {
    /// Create READER_DATA_LIFECYCLE with INFINITE delays (never purge).
    pub fn keep_all() -> Self {
        Self {
            autopurge_nowriter_samples_delay_us: i64::MAX,
            autopurge_disposed_samples_delay_us: i64::MAX,
        }
    }

    /// Create READER_DATA_LIFECYCLE with immediate cleanup.
    pub fn immediate_cleanup() -> Self {
        Self {
            autopurge_nowriter_samples_delay_us: 0,
            autopurge_disposed_samples_delay_us: 0,
        }
    }

    /// Create READER_DATA_LIFECYCLE with delays in seconds.
    pub fn from_secs(nowriter_delay_secs: u32, disposed_delay_secs: u32) -> Self {
        Self {
            autopurge_nowriter_samples_delay_us: (nowriter_delay_secs as i64) * 1_000_000,
            autopurge_disposed_samples_delay_us: (disposed_delay_secs as i64) * 1_000_000,
        }
    }

    /// Check if autopurge is disabled (INFINITE delays).
    pub fn is_keep_all(&self) -> bool {
        self.autopurge_nowriter_samples_delay_us == i64::MAX
            && self.autopurge_disposed_samples_delay_us == i64::MAX
    }

    /// Check if immediate cleanup is enabled (both delays = 0).
    pub fn is_immediate_cleanup(&self) -> bool {
        self.autopurge_nowriter_samples_delay_us == 0
            && self.autopurge_disposed_samples_delay_us == 0
    }
}

impl Default for ReaderDataLifecycle {
    fn default() -> Self {
        Self::keep_all()
    }
}
