// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Metadata QoS policies (DDS v1.4 Sec.2.2.3.17, Sec.2.2.3.18, Sec.2.2.3.19)
//!
//! Provides opaque user metadata for DDS entities. These are hint policies
//! that do not affect QoS compatibility matching.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** Metadata policies are hints (no RxO check required)
//!
//! These policies do not affect compatibility between readers and writers.
//! They provide application-specific metadata for debugging, monitoring,
//! and custom annotations.
//!
//! # Policies
//!
//! - **USER_DATA** (Sec.2.2.3.17): Opaque data attached to DomainParticipant or Entity
//! - **GROUP_DATA** (Sec.2.2.3.18): Opaque data attached to Publisher/Subscriber
//! - **TOPIC_DATA** (Sec.2.2.3.19): Opaque data attached to Topic
//!
//! # Use Cases
//!
//! - **Debugging**: Attach version info, build IDs, or debug flags
//! - **Monitoring**: Store application name, instance ID, or deployment info
//! - **Custom annotations**: Arbitrary key-value metadata
//! - **Discovery filtering**: Application-level filtering based on metadata
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::metadata::{UserData, GroupData, TopicData};
//!
//! // USER_DATA: Attach version info to a participant
//! let user_data = UserData::new(b"version=1.0.0".to_vec());
//! assert_eq!(user_data.value, b"version=1.0.0");
//!
//! // GROUP_DATA: Attach deployment info to a publisher
//! let group_data = GroupData::new(b"deployment=production".to_vec());
//!
//! // TOPIC_DATA: Attach schema info to a topic
//! let topic_data = TopicData::new(b"schema=v2".to_vec());
//! ```

/// USER_DATA QoS policy (DDS v1.4 Sec.2.2.3.17)
///
/// Opaque data attached to DomainParticipant or Entity.
/// Applications can use this to store custom metadata.
///
/// Default: Empty (no metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserData {
    /// Opaque byte sequence (application-defined)
    pub value: Vec<u8>,
}

impl Default for UserData {
    /// Default: Empty metadata
    fn default() -> Self {
        Self::empty()
    }
}

impl UserData {
    /// Create new USER_DATA policy with specified value
    ///
    /// # Arguments
    ///
    /// * `value` - Opaque byte sequence
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::metadata::UserData;
    ///
    /// let user_data = UserData::new(b"version=1.0.0".to_vec());
    /// assert_eq!(user_data.value, b"version=1.0.0");
    /// ```
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    /// Create empty USER_DATA (no metadata)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::metadata::UserData;
    ///
    /// let user_data = UserData::empty();
    /// assert!(user_data.is_empty());
    /// ```
    pub fn empty() -> Self {
        Self { value: Vec::new() }
    }

    /// Check if metadata is empty
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Get metadata length in bytes
    pub fn len(&self) -> usize {
        self.value.len()
    }
}

/// GROUP_DATA QoS policy (DDS v1.4 Sec.2.2.3.18)
///
/// Opaque data attached to Publisher or Subscriber.
/// Applications can use this to store group-level metadata.
///
/// Default: Empty (no metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupData {
    /// Opaque byte sequence (application-defined)
    pub value: Vec<u8>,
}

impl Default for GroupData {
    /// Default: Empty metadata
    fn default() -> Self {
        Self::empty()
    }
}

impl GroupData {
    /// Create new GROUP_DATA policy with specified value
    ///
    /// # Arguments
    ///
    /// * `value` - Opaque byte sequence
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::metadata::GroupData;
    ///
    /// let group_data = GroupData::new(b"deployment=production".to_vec());
    /// assert_eq!(group_data.value, b"deployment=production");
    /// ```
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    /// Create empty GROUP_DATA (no metadata)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::metadata::GroupData;
    ///
    /// let group_data = GroupData::empty();
    /// assert!(group_data.is_empty());
    /// ```
    pub fn empty() -> Self {
        Self { value: Vec::new() }
    }

    /// Check if metadata is empty
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Get metadata length in bytes
    pub fn len(&self) -> usize {
        self.value.len()
    }
}

/// TOPIC_DATA QoS policy (DDS v1.4 Sec.2.2.3.19)
///
/// Opaque data attached to Topic.
/// Applications can use this to store topic-level metadata.
///
/// Default: Empty (no metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicData {
    /// Opaque byte sequence (application-defined)
    pub value: Vec<u8>,
}

impl Default for TopicData {
    /// Default: Empty metadata
    fn default() -> Self {
        Self::empty()
    }
}

impl TopicData {
    /// Create new TOPIC_DATA policy with specified value
    ///
    /// # Arguments
    ///
    /// * `value` - Opaque byte sequence
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::metadata::TopicData;
    ///
    /// let topic_data = TopicData::new(b"schema=v2".to_vec());
    /// assert_eq!(topic_data.value, b"schema=v2");
    /// ```
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    /// Create empty TOPIC_DATA (no metadata)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::metadata::TopicData;
    ///
    /// let topic_data = TopicData::empty();
    /// assert!(topic_data.is_empty());
    /// ```
    pub fn empty() -> Self {
        Self { value: Vec::new() }
    }

    /// Check if metadata is empty
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Get metadata length in bytes
    pub fn len(&self) -> usize {
        self.value.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // USER_DATA tests
    // ========================================================================

    #[test]
    fn test_user_data_default() {
        let user_data = UserData::default();
        assert!(user_data.is_empty());
        assert_eq!(user_data.len(), 0);
    }

    #[test]
    fn test_user_data_empty() {
        let user_data = UserData::empty();
        assert!(user_data.is_empty());
        assert_eq!(user_data.value, Vec::<u8>::new());
    }

    #[test]
    fn test_user_data_new() {
        let data = b"version=1.0.0".to_vec();
        let user_data = UserData::new(data.clone());
        assert_eq!(user_data.value, data);
        assert!(!user_data.is_empty());
        assert_eq!(user_data.len(), 13);
    }

    #[test]
    fn test_user_data_clone() {
        let user_data1 = UserData::new(b"test".to_vec());
        let user_data2 = user_data1.clone();
        assert_eq!(user_data1, user_data2);
    }

    #[test]
    fn test_user_data_equality() {
        let user_data1 = UserData::new(b"test".to_vec());
        let user_data2 = UserData::new(b"test".to_vec());
        let user_data3 = UserData::new(b"other".to_vec());

        assert_eq!(user_data1, user_data2);
        assert_ne!(user_data1, user_data3);
    }

    #[test]
    fn test_user_data_debug() {
        let user_data = UserData::new(b"test".to_vec());
        let debug_str = format!("{:?}", user_data);
        assert!(debug_str.contains("UserData"));
    }

    // ========================================================================
    // GROUP_DATA tests
    // ========================================================================

    #[test]
    fn test_group_data_default() {
        let group_data = GroupData::default();
        assert!(group_data.is_empty());
        assert_eq!(group_data.len(), 0);
    }

    #[test]
    fn test_group_data_empty() {
        let group_data = GroupData::empty();
        assert!(group_data.is_empty());
        assert_eq!(group_data.value, Vec::<u8>::new());
    }

    #[test]
    fn test_group_data_new() {
        let data = b"deployment=production".to_vec();
        let group_data = GroupData::new(data.clone());
        assert_eq!(group_data.value, data);
        assert!(!group_data.is_empty());
        assert_eq!(group_data.len(), 21);
    }

    #[test]
    fn test_group_data_clone() {
        let group_data1 = GroupData::new(b"test".to_vec());
        let group_data2 = group_data1.clone();
        assert_eq!(group_data1, group_data2);
    }

    #[test]
    fn test_group_data_equality() {
        let group_data1 = GroupData::new(b"test".to_vec());
        let group_data2 = GroupData::new(b"test".to_vec());
        let group_data3 = GroupData::new(b"other".to_vec());

        assert_eq!(group_data1, group_data2);
        assert_ne!(group_data1, group_data3);
    }

    #[test]
    fn test_group_data_debug() {
        let group_data = GroupData::new(b"test".to_vec());
        let debug_str = format!("{:?}", group_data);
        assert!(debug_str.contains("GroupData"));
    }

    // ========================================================================
    // TOPIC_DATA tests
    // ========================================================================

    #[test]
    fn test_topic_data_default() {
        let topic_data = TopicData::default();
        assert!(topic_data.is_empty());
        assert_eq!(topic_data.len(), 0);
    }

    #[test]
    fn test_topic_data_empty() {
        let topic_data = TopicData::empty();
        assert!(topic_data.is_empty());
        assert_eq!(topic_data.value, Vec::<u8>::new());
    }

    #[test]
    fn test_topic_data_new() {
        let data = b"schema=v2".to_vec();
        let topic_data = TopicData::new(data.clone());
        assert_eq!(topic_data.value, data);
        assert!(!topic_data.is_empty());
        assert_eq!(topic_data.len(), 9);
    }

    #[test]
    fn test_topic_data_clone() {
        let topic_data1 = TopicData::new(b"test".to_vec());
        let topic_data2 = topic_data1.clone();
        assert_eq!(topic_data1, topic_data2);
    }

    #[test]
    fn test_topic_data_equality() {
        let topic_data1 = TopicData::new(b"test".to_vec());
        let topic_data2 = TopicData::new(b"test".to_vec());
        let topic_data3 = TopicData::new(b"other".to_vec());

        assert_eq!(topic_data1, topic_data2);
        assert_ne!(topic_data1, topic_data3);
    }

    #[test]
    fn test_topic_data_debug() {
        let topic_data = TopicData::new(b"test".to_vec());
        let debug_str = format!("{:?}", topic_data);
        assert!(debug_str.contains("TopicData"));
    }

    // ========================================================================
    // Use case tests
    // ========================================================================

    #[test]
    fn test_user_data_version_info() {
        // Store version information in USER_DATA
        let user_data = UserData::new(b"app_version=1.2.3".to_vec());
        assert_eq!(user_data.value, b"app_version=1.2.3");
    }

    #[test]
    fn test_user_data_build_id() {
        // Store build ID in USER_DATA
        let user_data = UserData::new(b"build_id=abc123".to_vec());
        assert!(!user_data.is_empty());
        assert_eq!(user_data.len(), 15);
    }

    #[test]
    fn test_group_data_deployment_env() {
        // Store deployment environment in GROUP_DATA
        let group_data = GroupData::new(b"env=production".to_vec());
        assert_eq!(group_data.value, b"env=production");
    }

    #[test]
    fn test_group_data_organization() {
        // Store organization info in GROUP_DATA
        let group_data = GroupData::new(b"org=robotics_team".to_vec());
        assert!(!group_data.is_empty());
    }

    #[test]
    fn test_topic_data_schema_version() {
        // Store schema version in TOPIC_DATA
        let topic_data = TopicData::new(b"schema_version=2.0".to_vec());
        assert_eq!(topic_data.value, b"schema_version=2.0");
    }

    #[test]
    fn test_topic_data_units() {
        // Store units metadata in TOPIC_DATA
        let topic_data = TopicData::new(b"units=meters/second".to_vec());
        assert!(!topic_data.is_empty());
        assert_eq!(topic_data.len(), 19);
    }

    #[test]
    fn test_metadata_binary_data() {
        // Test with arbitrary binary data
        let binary_data = vec![0x01, 0x02, 0x03, 0xFF, 0xFE];
        let user_data = UserData::new(binary_data.clone());
        assert_eq!(user_data.value, binary_data);
    }

    #[test]
    fn test_metadata_large_payload() {
        // Test with larger metadata payload (1KB)
        let large_data = vec![0x42; 1024];
        let topic_data = TopicData::new(large_data.clone());
        assert_eq!(topic_data.len(), 1024);
        assert_eq!(topic_data.value, large_data);
    }

    #[test]
    fn test_metadata_json_serialized() {
        // Example: JSON-serialized metadata
        let json = b"{\"version\":\"1.0\",\"debug\":true}".to_vec();
        let user_data = UserData::new(json.clone());
        assert_eq!(user_data.value, json);
    }
}
