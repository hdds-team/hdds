// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS builder methods for behavior policies (liveliness, ownership, partition).

use super::super::{
    GroupData, Liveliness, Ownership, OwnershipStrength, Partition, TopicData, UserData,
};
use super::structs::QoS;

impl QoS {
    /// Set liveliness policy (v0.5.0+).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, Liveliness};
    ///
    /// // Automatic liveliness with 5s lease
    /// let qos = QoS::best_effort().liveliness(Liveliness::automatic_secs(5));
    /// ```
    pub fn liveliness(mut self, liveliness: Liveliness) -> Self {
        self.liveliness = liveliness;
        self
    }

    /// Set automatic liveliness from milliseconds.
    pub fn liveliness_automatic_millis(mut self, ms: u64) -> Self {
        self.liveliness = Liveliness::automatic_millis(ms);
        self
    }

    /// Set automatic liveliness from seconds.
    pub fn liveliness_automatic_secs(mut self, secs: u64) -> Self {
        self.liveliness = Liveliness::automatic_secs(secs);
        self
    }

    /// Set manual-by-participant liveliness from milliseconds.
    pub fn liveliness_manual_participant_millis(mut self, ms: u64) -> Self {
        self.liveliness = Liveliness::manual_participant_millis(ms);
        self
    }

    /// Set manual-by-participant liveliness from seconds.
    pub fn liveliness_manual_participant_secs(mut self, secs: u64) -> Self {
        self.liveliness = Liveliness::manual_participant_secs(secs);
        self
    }

    /// Set ownership policy (v0.6.0+).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, Ownership};
    ///
    /// // Shared ownership (multiple writers)
    /// let qos = QoS::best_effort().ownership(Ownership::shared());
    ///
    /// // Exclusive ownership (highest-strength wins)
    /// let qos_exclusive = QoS::best_effort().ownership(Ownership::exclusive());
    /// ```
    pub fn ownership(mut self, ownership: Ownership) -> Self {
        self.ownership = ownership;
        self
    }

    /// Set shared ownership (multiple writers allowed).
    pub fn ownership_shared(mut self) -> Self {
        self.ownership = Ownership::shared();
        self
    }

    /// Set exclusive ownership (highest-strength writer wins).
    pub fn ownership_exclusive(mut self) -> Self {
        self.ownership = Ownership::exclusive();
        self
    }

    /// Set OWNERSHIP_STRENGTH with custom value.
    ///
    /// Only matters when OWNERSHIP is EXCLUSIVE. Higher values win.
    pub fn ownership_strength(mut self, value: i32) -> Self {
        self.ownership_strength = OwnershipStrength { value };
        self
    }

    /// Set OWNERSHIP_STRENGTH to high priority.
    ///
    /// Convenience method for high-priority writers (value: 100).
    pub fn ownership_strength_high(mut self) -> Self {
        self.ownership_strength = OwnershipStrength::high();
        self
    }

    /// Set OWNERSHIP_STRENGTH to low priority.
    ///
    /// Convenience method for backup/fallback writers (value: -100).
    pub fn ownership_strength_low(mut self) -> Self {
        self.ownership_strength = OwnershipStrength::low();
        self
    }

    /// Set partition policy (v0.6.0+).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, Partition};
    ///
    /// // Single partition
    /// let qos = QoS::best_effort().partition(Partition::single("sensor"));
    ///
    /// // Multiple partitions
    /// let qos_multi = QoS::best_effort().partition(
    ///     Partition::new(vec!["sensor".to_string(), "actuator".to_string()])
    /// );
    /// ```
    pub fn partition(mut self, partition: Partition) -> Self {
        self.partition = partition;
        self
    }

    /// Set single partition.
    pub fn partition_single(mut self, name: &str) -> Self {
        self.partition = Partition::single(name);
        self
    }

    /// Add a partition name to the partition list.
    pub fn add_partition(mut self, name: &str) -> Self {
        self.partition.add(name);
        self
    }

    /// Set USER_DATA policy (v0.7.0+).
    ///
    /// Opaque data attached to DomainParticipant or Entity.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, UserData};
    ///
    /// // Attach version info
    /// let qos = QoS::best_effort().user_data(UserData::new(b"version=1.0.0".to_vec()));
    /// ```
    pub fn user_data(mut self, user_data: UserData) -> Self {
        self.user_data = user_data;
        self
    }

    /// Set USER_DATA from byte slice.
    pub fn user_data_bytes(mut self, value: &[u8]) -> Self {
        self.user_data = UserData::new(value.to_vec());
        self
    }

    /// Set GROUP_DATA policy (v0.7.0+).
    ///
    /// Opaque data attached to Publisher or Subscriber.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, GroupData};
    ///
    /// // Attach deployment info
    /// let qos = QoS::best_effort().group_data(GroupData::new(b"deployment=production".to_vec()));
    /// ```
    pub fn group_data(mut self, group_data: GroupData) -> Self {
        self.group_data = group_data;
        self
    }

    /// Set GROUP_DATA from byte slice.
    pub fn group_data_bytes(mut self, value: &[u8]) -> Self {
        self.group_data = GroupData::new(value.to_vec());
        self
    }

    /// Set TOPIC_DATA policy (v0.7.0+).
    ///
    /// Opaque data attached to Topic.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::api::{QoS, TopicData};
    ///
    /// // Attach schema info
    /// let qos = QoS::best_effort().topic_data(TopicData::new(b"schema=v2".to_vec()));
    /// ```
    pub fn topic_data(mut self, topic_data: TopicData) -> Self {
        self.topic_data = topic_data;
        self
    }

    /// Set TOPIC_DATA from byte slice.
    pub fn topic_data_bytes(mut self, value: &[u8]) -> Self {
        self.topic_data = TopicData::new(value.to_vec());
        self
    }
}
