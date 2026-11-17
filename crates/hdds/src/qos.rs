// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// DataTagQosPolicy - the data tags of an endpoint (DDS-Security v1.1).
pub mod data_tags;
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
    /// # Validation Rules (DDS v1.4 Sec.2.2.3.18, Sec.2.2.3.19)
    ///
    /// - History::KeepLast(n) where n > 0
    /// - History::KeepAll requires ResourceLimits.max_samples > 0
    /// - max_samples >= max_samples_per_instance (no rule on max_instances)
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
    ///
    /// Delegates to `crate::dds::qos::check_history_and_limits`, the one
    /// function the DataWriter and DataReader builders also call, so this
    /// profile is never checked against a rule set of its own.
    pub fn validate(&self) -> Result<(), String> {
        crate::dds::qos::check_history_and_limits("QosProfile", self.history, &self.resource_limits)
            .map_err(|e| e.to_string())
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
                max_instances: crate::reliability::LENGTH_UNLIMITED,
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
                max_instances: crate::reliability::LENGTH_UNLIMITED,
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
    /// Data outlives the writer but not the service (DDS spec rank 2)
    ///
    /// Requires a durability service to manage data independently of writers.
    /// HDDS does not implement a full durability service; this variant exists
    /// for correct QoS compatibility checking with other DDS implementations.
    /// Behavior is identical to TransientLocal when used locally.
    Transient,
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
    /// Maximum total samples across all instances (LENGTH_UNLIMITED =
    /// `usize::MAX`, the default)
    pub max_samples: usize,
    /// Maximum instances (LENGTH_UNLIMITED by default)
    pub max_instances: usize,
    /// Maximum samples per instance (LENGTH_UNLIMITED by default)
    pub max_samples_per_instance: usize,
    /// Maximum total payload bytes (Reliable QoS history cache quota)
    ///
    /// Used by HistoryCache to limit memory consumption. With KEEP_LAST,
    /// oldest entries are evicted (FIFO). With KEEP_ALL, inserts fail once
    /// the quota is reached. Only relevant for Reliable QoS.
    pub max_quota_bytes: usize,
}

impl Default for ResourceLimits {
    /// DDS v1.4 Sec.2.2.3.19: `max_samples`, `max_instances` and
    /// `max_samples_per_instance` all default to LENGTH_UNLIMITED.
    ///
    /// A `max_instances` default of 1 (or a finite `max_samples`) is wrong:
    /// the writer cache accounts a change against its real instance, so a
    /// KEEP_ALL writer would refuse its second instance. `max_quota_bytes` is an HDDS bound with
    /// no DDS counterpart and keeps its value.
    fn default() -> Self {
        Self {
            max_samples: crate::reliability::LENGTH_UNLIMITED,
            max_instances: crate::reliability::LENGTH_UNLIMITED,
            max_samples_per_instance: crate::reliability::LENGTH_UNLIMITED,
            max_quota_bytes: 100_000_000,
        }
    }
}

/// Secondary slab pool size classes for payloads that exceed the
/// primary 14-class pool.
///
/// Empty `classes` disables the secondary pool entirely; allocations that
/// outgrow the primary pool then fall through to the heap tier of the
/// allocator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LargePoolConfig {
    /// `(slot_size, slot_count)` pairs preallocated at participant start.
    pub classes: Vec<(usize, usize)>,
}

impl LargePoolConfig {
    /// Preset sized for typical large-data workloads (video frames,
    /// telemetry snapshots, small file transfers). Total prealloc 12 MB:
    /// 512 KB * 8 = 4 MB, 2 MB * 4 = 8 MB.
    pub fn typical_large_data() -> Self {
        Self {
            classes: vec![(524_288, 8), (2_097_152, 4)],
        }
    }
}

/// Allocation strategy for participant memory.
///
/// `ResourceLimits` answers "how much" (cache-wide bounds);
/// `MemoryPolicy` answers "how" (which tiers exist and how much heap
/// budget the fallback tier may consume).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryPolicy {
    /// Secondary pool for allocations larger than the primary classes.
    /// Empty = disabled, heap fallback only.
    pub large_pool: LargePoolConfig,
    /// Maximum bytes the heap fallback tier is allowed to hold at any time.
    pub max_heap_bytes: usize,
    /// Share, in percent, of every size class of the pool (rounded up to a
    /// whole slot) and of `max_heap_bytes` that writers never take: it is
    /// kept for the samples readers receive from the network, which are
    /// stored before they are acknowledged.
    ///
    /// The pool is process-wide: a writer's unacknowledged history and the
    /// samples a co-located reader receives share it. Without this share, a
    /// RELIABLE KEEP_ALL writer whose history filled the pool left its own
    /// reader no storage for the repair that would acknowledge it, and both
    /// waited for good. With it, a writer finds the pool full once only the
    /// readers' share is left, and waits up to `max_blocking_time` for its
    /// readers to acknowledge (DDS v1.4 Sec.2.2.3.18).
    ///
    /// Samples a reliable reader acknowledges before the application can
    /// take them because they are held above a gap may hold at most the
    /// readers' share of the heap tier, leaving room for the sample that
    /// would release them. The members of a coherent set a reader stages
    /// take none of the pool's tiers: each coherent reader stages in a
    /// budget of its own, derived from its RESOURCE_LIMITS, outside
    /// `max_heap_bytes` (gauge: `SlabPoolMetrics::staged_heap_bytes`), all
    /// of them within `max_staging_bytes`. Normally a set larger than its
    /// staging allowance is rejected whole (SAMPLE_REJECTED). A RELIABLE
    /// ordered GROUP network reader instead retains accepted members and
    /// refuses further members without receipt credit for repair.
    ///
    /// A process with writers only gets 100 less this share of every tier:
    /// 75 % of the pool at the default 25.
    ///
    /// Default 25. Accepted range
    /// [`READER_RESERVE_PERCENT_MIN`](Self::READER_RESERVE_PERCENT_MIN)..=
    /// [`READER_RESERVE_PERCENT_MAX`](Self::READER_RESERVE_PERCENT_MAX)
    /// (1..=93); `ParticipantBuilder::build` refuses any other value with
    /// `Error::Config`. 0 brings back the stall the share exists to
    /// prevent; above 93, writers no longer get a single slot of the
    /// primary size class with the fewest slots (16), and at 100 every
    /// write fails. A secondary (`large_pool`) class with few slots may
    /// keep none for writers well below 93: writers then use the heap tier.
    pub reader_reserve_percent: u8,
    /// Most bytes the coherent readers of the process may stage together:
    /// the members of the coherent sets they have acknowledged and not yet
    /// committed, each reader within a budget of its own besides (see
    /// `max_heap_bytes`). Staged storage is outside every tier's ceiling,
    /// so this is what bounds it process-wide.
    ///
    /// A member that would take the process past it reclaims eligible sets
    /// fairly: each reader that stages is entitled to an even share, and a
    /// set is rejected whole (acknowledged, reported SAMPLE_REJECTED) only
    /// in a reader above its share, the youngest not in order there first
    /// (the member's own set if it is that one); with nothing to reject,
    /// the member's set is normally rejected. A reader within its share is
    /// not selected as another reader's reclamation victim.
    ///
    /// RELIABLE ordered GROUP network readers retain acknowledged members
    /// while waiting for presentation. Their refused members remain missing
    /// from receipt credit. Reclamation also preserves charged loss markers;
    /// pressure can therefore refuse admission instead of reclaiming a set.
    /// An intrinsically oversized ordered GROUP unit can remain blocked
    /// under fixed limits; capacity is not an unavailable-data proof.
    /// What the process charges never passes this ceiling (each member's
    /// storage and entry).
    ///
    /// Default 64 MiB: four times the default heap tier, and above what the
    /// seeded realistic models stage at their peak (8 MiB, four writers of
    /// up to 64 KiB samples into one reader). Accepted range
    /// [`MAX_STAGING_BYTES_MIN`](Self::MAX_STAGING_BYTES_MIN) (1 MiB) and
    /// up; `ParticipantBuilder::build` refuses any other value with
    /// `Error::Config`.
    pub max_staging_bytes: usize,
}

impl MemoryPolicy {
    /// The lowest `reader_reserve_percent` accepted: 0 keeps nothing for
    /// readers.
    pub const READER_RESERVE_PERCENT_MIN: u8 = 1;
    /// The highest `reader_reserve_percent` accepted: the highest that
    /// leaves writers at least one slot of every primary size class
    /// (16 slots - ceil(16 * 93 / 100) = 1).
    pub const READER_RESERVE_PERCENT_MAX: u8 = 93;
    /// The default `max_staging_bytes`, 64 MiB.
    pub const MAX_STAGING_BYTES_DEFAULT: usize = 64 * 1024 * 1024;
    /// The lowest `max_staging_bytes` accepted, 1 MiB: eight samples of the
    /// primary pool's largest class (128 KiB). Below it, even a set of a few
    /// such samples could exhaust the ceiling.
    pub const MAX_STAGING_BYTES_MIN: usize = 1024 * 1024;

    /// Whether `max_staging_bytes` is within its accepted range; the reason
    /// when it is not.
    pub(crate) fn check_max_staging_bytes(&self) -> Result<(), String> {
        if self.max_staging_bytes >= Self::MAX_STAGING_BYTES_MIN {
            return Ok(());
        }
        Err(format!(
            "MemoryPolicy.max_staging_bytes = {} is below {}: coherent sets of a few large \
             samples would be rejected by the process staging ceiling alone",
            self.max_staging_bytes,
            Self::MAX_STAGING_BYTES_MIN
        ))
    }

    /// Whether `reader_reserve_percent` is within its accepted range; the
    /// reason when it is not.
    pub(crate) fn check_reader_reserve_percent(&self) -> Result<(), String> {
        let percent = self.reader_reserve_percent;
        if (Self::READER_RESERVE_PERCENT_MIN..=Self::READER_RESERVE_PERCENT_MAX).contains(&percent)
        {
            return Ok(());
        }
        Err(format!(
            "MemoryPolicy.reader_reserve_percent = {percent} is outside {}..={}: {}",
            Self::READER_RESERVE_PERCENT_MIN,
            Self::READER_RESERVE_PERCENT_MAX,
            if percent < Self::READER_RESERVE_PERCENT_MIN {
                "with no share kept for readers, a reliable writer's history can take the \
                 storage its co-located reader needs to acknowledge it, and both stall"
            } else {
                "writers would be left no slot of some primary size class (none at all at 100)"
            }
        ))
    }
}

impl Default for MemoryPolicy {
    fn default() -> Self {
        Self {
            large_pool: LargePoolConfig::default(),
            max_heap_bytes: 16 * 1024 * 1024,
            reader_reserve_percent: 25,
            max_staging_bytes: Self::MAX_STAGING_BYTES_DEFAULT,
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
        assert_eq!(
            qos.resource_limits.max_samples,
            crate::reliability::LENGTH_UNLIMITED
        );
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
            .contains("History::KeepLast requires depth > 0"));
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
            .contains("RESOURCE_LIMITS.max_samples must be > 0 or LENGTH_UNLIMITED"));
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
        // DDS v1.4 Sec.2.2.3.19: max_samples >= max_samples_per_instance.
        let qos = QosProfile {
            resource_limits: ResourceLimits {
                max_samples: 5,
                max_instances: 5,
                max_samples_per_instance: 10,
                max_quota_bytes: 10_000_000,
            },
            ..Default::default()
        };
        let result = qos.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_samples"));

        // DDS v1.4 Sec.2.2.3.18: depth <= max_samples_per_instance.
        let qos = QosProfile {
            history: History::KeepLast(20),
            resource_limits: ResourceLimits {
                max_samples: 100,
                max_instances: 5,
                max_samples_per_instance: 10,
                max_quota_bytes: 10_000_000,
            },
            ..Default::default()
        };
        assert!(qos.validate().unwrap_err().contains("HISTORY depth (20)"));

        // No rule on max_instances * max_samples_per_instance in the spec:
        // 10 < 5 * 10 is legal.
        let qos = QosProfile {
            resource_limits: ResourceLimits {
                max_samples: 10,
                max_instances: 5,
                max_samples_per_instance: 10,
                max_quota_bytes: 10_000_000,
            },
            ..Default::default()
        };
        assert!(qos.validate().is_ok());
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

        // DDS v1.4 Sec.2.2.3.19 defaults.
        let unlimited = crate::reliability::LENGTH_UNLIMITED;
        assert_eq!(rl.max_samples, unlimited);
        assert_eq!(rl.max_instances, unlimited);
        assert_eq!(rl.max_samples_per_instance, unlimited);
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
