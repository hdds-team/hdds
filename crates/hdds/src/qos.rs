// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// QoS (Quality of Service) policies for DataWriter and DataReader
///
/// Implements minimal viable policies for Phase 7a (BestEffort only).
/// Reliable QoS and advanced policies deferred to Phase T2.
/// Deadline QoS policy - expected data update period.
pub mod deadline;
/// Destination order QoS policy - reception vs source timestamp ordering.
pub mod destination_order;
/// Durability service QoS policy - history depth for late joiners.
pub mod durability_service;
/// Entity factory QoS policy - autoenable behavior.
pub mod entity_factory;
/// Latency budget QoS policy - transport latency hint.
pub mod latency_budget;
/// Lifespan QoS policy - data expiration time.
pub mod lifespan;
/// Liveliness QoS policy - writer aliveness assertions.
pub mod liveliness;
/// Metadata QoS policy - user/topic data.
pub mod metadata;
/// Ownership QoS policy - exclusive vs shared writers.
pub mod ownership;
/// Partition QoS policy - logical data separation.
pub mod partition;
/// Presentation QoS policy - access scope and coherency.
pub mod presentation;
/// Reader data lifecycle QoS policy - instance disposal.
pub mod reader_data_lifecycle;
/// Time-based filter QoS policy - minimum sample separation.
pub mod time_based_filter;
/// Transport priority QoS policy - network QoS hint.
pub mod transport_priority;
/// Writer data lifecycle QoS policy - autodispose instances.
pub mod writer_data_lifecycle;
///
/// # Supported Policies
///
/// - **Reliability**: BestEffort (fire-and-forget)
/// - **History**: KeepLast(n) bounded queue, KeepAll within ResourceLimits
/// - **Durability**: Volatile, TransientLocal, Persistent
/// - **ResourceLimits**: max_samples, max_instances, max_samples_per_instance
///
/// # Examples
///
/// ```no_run
/// use hdds::qos::{QosProfile, History, ResourceLimits};
///
/// // Default QoS (BestEffort, KeepLast(10))
/// let qos_default = QosProfile::default();
///
/// // Custom QoS
/// let qos_custom = QosProfile {
///     history: History::KeepLast(100),
///     resource_limits: ResourceLimits {
///         max_samples: 500,
///         ..Default::default()
///     },
///     ..Default::default()
/// };
/// ```
/// QoS Profile - Collection of policies for Writer/Reader
///
/// Validated at Writer/Reader creation (fail-fast on invalid config).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QosProfile {
    /// Reliability policy
    pub reliability: Reliability,
    /// History policy (KeepLast or KeepAll)
    pub history: History,
    /// Durability policy
    pub durability: Durability,
    /// Resource limits (queue sizes, instances)
    pub resource_limits: ResourceLimits,
}

impl Default for QosProfile {
    fn default() -> Self {
        Self {
            reliability: Reliability::BestEffort,
            history: History::KeepLast(10),
            durability: Durability::Volatile,
            resource_limits: ResourceLimits::default(),
        }
    }
}

impl QosProfile {
    /// Validate QoS configuration
    ///
    /// Checks for invalid combinations and resource limits.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if valid
    /// - `Err(String)` with validation error message
    ///
    /// # Validation Rules
    ///
    /// - History::KeepLast(n) where n > 0
    /// - History::KeepAll requires ResourceLimits.max_samples > 0
    /// - max_samples >= max_samples_per_instance * max_instances
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::{QosProfile, History};
    ///
    /// let mut qos = QosProfile::default();
    /// assert!(qos.validate().is_ok());
    ///
    /// qos.history = History::KeepLast(0); // Invalid
    /// assert!(qos.validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), String> {
        // Validate History
        match self.history {
            History::KeepLast(0) => {
                return Err("History::KeepLast(n) requires n > 0".to_string());
            }
            History::KeepAll => {
                if self.resource_limits.max_samples == 0 {
                    return Err(
                        "History::KeepAll requires ResourceLimits.max_samples > 0".to_string()
                    );
                }
            }
            History::KeepLast(_) => {}
        }

        // Validate ResourceLimits
        let rl = &self.resource_limits;
        if rl.max_samples < rl.max_samples_per_instance * rl.max_instances {
            return Err(format!(
                "max_samples ({}) must be >= max_samples_per_instance ({}) * max_instances ({})",
                rl.max_samples, rl.max_samples_per_instance, rl.max_instances
            ));
        }

        // Phase 7: Reject unsupported policies
        // (Reliability::Reliable deferred to Phase T2)

        Ok(())
    }

    /// Create QoS profile for low-latency scenarios
    ///
    /// - BestEffort reliability (no retransmissions)
    /// - KeepLast(1) history (drop old samples)
    /// - Minimal resource limits
    #[must_use]
    pub fn low_latency() -> Self {
        Self {
            reliability: Reliability::BestEffort,
            history: History::KeepLast(1),
            durability: Durability::Volatile,
            resource_limits: ResourceLimits {
                max_samples: 10,
                max_instances: 1,
                max_samples_per_instance: 10,
                max_quota_bytes: 100_000, // 100 KB for low-latency
            },
        }
    }

    /// Create QoS profile for high-throughput scenarios
    ///
    /// - BestEffort reliability
    /// - KeepLast(1000) history (large queue)
    /// - High resource limits
    #[must_use]
    pub fn high_throughput() -> Self {
        Self {
            reliability: Reliability::BestEffort,
            history: History::KeepLast(1000),
            durability: Durability::Volatile,
            resource_limits: ResourceLimits {
                max_samples: 5000,
                max_instances: 1,
                max_samples_per_instance: 5000,
                max_quota_bytes: 50_000_000, // 50 MB for high-throughput
            },
        }
    }
}

/// Reliability policy
///
/// Determines delivery guarantees for samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Reliability {
    /// Fire-and-forget (no ACKs, no retransmission)
    ///
    /// Phase 7a supported. Low latency, may drop packets under congestion.
    #[default]
    BestEffort,
    /// Reliable delivery with NACK-driven retransmission
    ///
    /// Phase T2 (v0.4.0+). Guarantees delivery via ACK/NACK protocol.
    /// Writer caches messages in HistoryCache for retransmission.
    /// Reader tracks gaps and sends NACK for missing sequences.
    Reliable,
}

/// History policy
///
/// Determines how many samples to keep in queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum History {
    /// Keep last N samples (bounded queue, drops oldest)
    ///
    /// Phase 7a supported. Queue size = N.
    /// Uses u32 for network serialization compatibility.
    KeepLast(u32),
    /// Keep all samples within resource limits.
    ///
    /// Queue size is bounded by `ResourceLimits` (max_samples, max_quota_bytes).
    /// Inserts fail once the limits are reached.
    KeepAll,
}

impl Default for History {
    fn default() -> Self {
        Self::KeepLast(10)
    }
}

/// Durability policy
///
/// Determines sample persistence behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Durability {
    /// No persistence (samples lost on writer crash)
    ///
    /// Phase 7a supported. Writer does not cache sent samples.
    #[default]
    Volatile,
    /// Writer caches samples for late-joiners (v0.5.0+)
    ///
    /// Late-joining readers receive historical samples (up to History depth).
    /// Cache persists only during writer's lifetime (not durable to disk).
    /// Works with both BestEffort and Reliable QoS.
    TransientLocal,
    /// Writer persists samples to disk for late-joiners (v0.9.0+)
    ///
    /// Late-joining readers receive historical samples (up to History depth),
    /// even across writer restarts. Disk I/O applies to the write path.
    Persistent,
}

/// Resource limits for Writer/Reader
///
/// Controls queue sizes, instance limits, and memory quotas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum total samples across all instances
    pub max_samples: usize,
    /// Maximum instances (unkeyed topics = 1 in Phase 7)
    pub max_instances: usize,
    /// Maximum samples per instance
    pub max_samples_per_instance: usize,
    /// Maximum total payload bytes (Reliable QoS history cache quota)
    ///
    /// Used by HistoryCache to limit memory consumption. With KEEP_LAST,
    /// oldest entries are evicted (FIFO). With KEEP_ALL, inserts fail once
    /// the quota is reached. Only relevant for Reliable QoS.
    pub max_quota_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            // v208: Increased from 1000 to 100K to support RELIABLE retransmission
            // for burst workloads. With 1000, samples evicted before NACK arrives.
            max_samples: 100_000,
            max_instances: 1, // Phase 7: unkeyed topics only
            max_samples_per_instance: 100_000,
            max_quota_bytes: 100_000_000, // 100 MB for 100K samples @ 1KB each
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_default() {
        let qos = QosProfile::default();

        assert_eq!(qos.reliability, Reliability::BestEffort);
        assert_eq!(qos.history, History::KeepLast(10));
        assert_eq!(qos.durability, Durability::Volatile);
        assert_eq!(qos.resource_limits.max_samples, 100_000);
    }

    #[test]
    fn test_qos_validate_valid() {
        let qos = QosProfile::default();
        assert!(qos.validate().is_ok());
    }

    #[test]
    fn test_qos_validate_invalid_history_zero() {
        let qos = QosProfile {
            history: History::KeepLast(0),
            ..Default::default()
        };

        let result = qos.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("History::KeepLast(n) requires n > 0"));
    }

    #[test]
    fn test_qos_validate_keep_all_requires_limits() {
        let qos = QosProfile {
            history: History::KeepAll,
            resource_limits: ResourceLimits {
                max_samples: 0,
                max_instances: 1,
                max_samples_per_instance: 1,
                max_quota_bytes: 1000,
            },
            ..Default::default()
        };

        let result = qos.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("History::KeepAll requires ResourceLimits.max_samples > 0"));
    }

    #[test]
    fn test_qos_validate_keep_all_ok() {
        let qos = QosProfile {
            history: History::KeepAll,
            ..Default::default()
        };

        assert!(qos.validate().is_ok());
    }

    #[test]
    fn test_qos_validate_resource_limits() {
        let qos = QosProfile {
            resource_limits: ResourceLimits {
                max_samples: 10,
                max_instances: 5,
                max_samples_per_instance: 10,
                max_quota_bytes: 10_000_000,
            },
            ..Default::default()
        };

        // max_samples (10) < max_instances (5) * max_samples_per_instance (10) = 50
        let result = qos.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_samples"));
    }

    #[test]
    fn test_qos_low_latency() {
        let qos = QosProfile::low_latency();

        assert_eq!(qos.history, History::KeepLast(1));
        assert_eq!(qos.resource_limits.max_samples, 10);
        assert!(qos.validate().is_ok());
    }

    #[test]
    fn test_qos_high_throughput() {
        let qos = QosProfile::high_throughput();

        assert_eq!(qos.history, History::KeepLast(1000));
        assert_eq!(qos.resource_limits.max_samples, 5000);
        assert!(qos.validate().is_ok());
    }

    #[test]
    fn test_reliability_default() {
        assert_eq!(Reliability::default(), Reliability::BestEffort);
    }

    #[test]
    fn test_history_default() {
        assert_eq!(History::default(), History::KeepLast(10));
    }

    #[test]
    fn test_durability_default() {
        assert_eq!(Durability::default(), Durability::Volatile);
    }

    #[test]
    fn test_durability_transient_local() {
        let qos = QosProfile {
            durability: Durability::TransientLocal,
            ..Default::default()
        };

        assert_eq!(qos.durability, Durability::TransientLocal);
        assert!(qos.validate().is_ok());
    }

    #[test]
    fn test_durability_transient_local_with_reliable() {
        let qos = QosProfile {
            reliability: Reliability::Reliable,
            durability: Durability::TransientLocal,
            history: History::KeepLast(100),
            ..Default::default()
        };

        assert_eq!(qos.durability, Durability::TransientLocal);
        assert_eq!(qos.reliability, Reliability::Reliable);
        assert!(qos.validate().is_ok());
    }

    #[test]
    fn test_resource_limits_default() {
        let rl = ResourceLimits::default();

        assert_eq!(rl.max_samples, 100_000);
        assert_eq!(rl.max_instances, 1);
        assert_eq!(rl.max_samples_per_instance, 100_000);
        assert_eq!(rl.max_quota_bytes, 100_000_000);
    }

    #[test]
    fn test_resource_limits_custom() {
        let rl = ResourceLimits {
            max_samples: 500,
            max_instances: 1,
            max_samples_per_instance: 500,
            max_quota_bytes: 5_000_000,
        };

        assert_eq!(rl.max_samples, 500);
        assert_eq!(rl.max_quota_bytes, 5_000_000);
    }

    #[test]
    fn test_qos_clone() {
        let qos1 = QosProfile::default();
        let qos2 = qos1.clone();

        assert_eq!(qos1, qos2);
    }

    #[test]
    fn test_qos_debug() {
        let qos = QosProfile::default();
        let debug_str = format!("{:?}", qos);

        assert!(debug_str.contains("QosProfile"));
        assert!(debug_str.contains("BestEffort"));
    }
}
