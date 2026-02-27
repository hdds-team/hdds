// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PARTITION QoS policy (DDS v1.4 Sec.2.2.3.13)
//!
//! Provides logical isolation of topics via partition names.
//! Writers and readers communicate only if their partitions intersect.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** Partitions must have at least one common element (RxO semantics)
//!
//! Example:
//! - Writer `["sensor"]`, Reader `["sensor"]` -> Compatible \[OK\]
//! - Writer `["sensor"]`, Reader `["actuator"]` -> Incompatible \[X\]
//! - Writer `[]`, Reader `[]` -> Compatible \[OK\] (both use default partition)
//! - Writer `["sensor", "actuator"]`, Reader `["actuator"]` -> Compatible \[OK\]
//!
//! # Use Cases
//!
//! - Multi-robot systems (partition by robot ID)
//! - Network segmentation (partition by security domain)
//! - Geographic isolation (partition by region)
//! - Logical grouping (partition by subsystem)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::partition::Partition;
//!
//! // Default partition (empty)
//! let default_partition = Partition::default();
//!
//! // Single partition
//! let sensor_partition = Partition::new(vec!["sensor".to_string()]);
//!
//! // Multiple partitions
//! let multi = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
//!
//! // Check compatibility
//! let writer = Partition::new(vec!["sensor".to_string()]);
//! let reader = Partition::new(vec!["sensor".to_string()]);
//! assert!(writer.is_compatible_with(&reader)); // Same partition \[OK\]
//! ```

/// PARTITION QoS policy
///
/// Specifies a list of partition names for logical topic isolation.
/// Empty list means default partition (matches other empty partitions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// List of partition names
    ///
    /// Empty list = default partition
    /// Partitions are case-sensitive strings
    pub names: Vec<String>,
}

impl Default for Partition {
    /// Default: Empty partition list (default partition)
    fn default() -> Self {
        Self { names: Vec::new() }
    }
}

impl Partition {
    /// Create new partition policy
    ///
    /// # Arguments
    ///
    /// * `names` - List of partition names (empty = default partition)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::partition::Partition;
    ///
    /// // Default partition
    /// let default = Partition::new(vec![]);
    ///
    /// // Named partition
    /// let sensor = Partition::new(vec!["sensor".to_string()]);
    ///
    /// // Multiple partitions
    /// let multi = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
    /// ```
    pub fn new(names: Vec<String>) -> Self {
        Self { names }
    }

    /// Create default partition (empty list)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::partition::Partition;
    ///
    /// let partition = Partition::default_partition();
    /// assert!(partition.is_default());
    /// ```
    pub fn default_partition() -> Self {
        Self::default()
    }

    /// Create partition with a single name
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::partition::Partition;
    ///
    /// let partition = Partition::single("sensor");
    /// assert_eq!(partition.names.len(), 1);
    /// assert_eq!(partition.names[0], "sensor");
    /// ```
    pub fn single(name: &str) -> Self {
        Self {
            names: vec![name.to_string()],
        }
    }

    /// Check if this is the default partition (empty list)
    pub fn is_default(&self) -> bool {
        self.names.is_empty()
    }

    /// Check QoS compatibility between offered (writer) and requested (reader)
    ///
    /// **Rule:** Partitions must have at least one common element
    ///
    /// Special case: If both are default (empty), they are compatible
    ///
    /// # Arguments
    ///
    /// * `requested` - Reader's requested partition
    ///
    /// # Returns
    ///
    /// `true` if partitions intersect or both are default
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::partition::Partition;
    ///
    /// // Same partition
    /// let writer = Partition::single("sensor");
    /// let reader = Partition::single("sensor");
    /// assert!(writer.is_compatible_with(&reader)); // \[OK\]
    ///
    /// // Different partitions
    /// let writer = Partition::single("sensor");
    /// let reader = Partition::single("actuator");
    /// assert!(!writer.is_compatible_with(&reader)); // \[X\]
    ///
    /// // Intersection
    /// let writer = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
    /// let reader = Partition::single("actuator");
    /// assert!(writer.is_compatible_with(&reader)); // \[OK\]
    ///
    /// // Both default
    /// let writer = Partition::default();
    /// let reader = Partition::default();
    /// assert!(writer.is_compatible_with(&reader)); // \[OK\]
    /// ```
    pub fn is_compatible_with(&self, requested: &Partition) -> bool {
        // Both default partitions -> compatible
        if self.is_default() && requested.is_default() {
            return true;
        }

        // If either is default but not both -> incompatible
        if self.is_default() || requested.is_default() {
            return false;
        }

        // Check intersection (at least one common partition)
        self.names
            .iter()
            .any(|writer_partition| requested.names.contains(writer_partition))
    }

    /// Add a partition name to the list
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::partition::Partition;
    ///
    /// let mut partition = Partition::default();
    /// partition.add("sensor");
    /// partition.add("actuator");
    /// assert_eq!(partition.names.len(), 2);
    /// ```
    pub fn add(&mut self, name: &str) {
        self.names.push(name.to_string());
    }

    /// Remove a partition name from the list
    ///
    /// Returns true if the name was found and removed
    pub fn remove(&mut self, name: &str) -> bool {
        if let Some(pos) = self.names.iter().position(|n| n == name) {
            self.names.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if a partition name exists in the list
    pub fn contains(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }

    /// Get the number of partitions
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Check if partition list is empty (default partition)
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_default() {
        let partition = Partition::default();
        assert!(partition.is_default());
        assert!(partition.is_empty());
        assert_eq!(partition.len(), 0);
    }

    #[test]
    fn test_partition_default_partition() {
        let partition = Partition::default_partition();
        assert!(partition.is_default());
    }

    #[test]
    fn test_partition_new_empty() {
        let partition = Partition::new(vec![]);
        assert!(partition.is_default());
    }

    #[test]
    fn test_partition_new_single() {
        let partition = Partition::new(vec!["sensor".to_string()]);
        assert!(!partition.is_default());
        assert_eq!(partition.len(), 1);
        assert_eq!(partition.names[0], "sensor");
    }

    #[test]
    fn test_partition_new_multiple() {
        let partition = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
        assert_eq!(partition.len(), 2);
        assert_eq!(partition.names[0], "sensor");
        assert_eq!(partition.names[1], "actuator");
    }

    #[test]
    fn test_partition_single() {
        let partition = Partition::single("sensor");
        assert_eq!(partition.len(), 1);
        assert_eq!(partition.names[0], "sensor");
    }

    #[test]
    fn test_compatibility_both_default() {
        let writer = Partition::default();
        let reader = Partition::default();
        assert!(writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_compatibility_same_single() {
        let writer = Partition::single("sensor");
        let reader = Partition::single("sensor");
        assert!(writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_incompatibility_different_single() {
        let writer = Partition::single("sensor");
        let reader = Partition::single("actuator");
        assert!(!writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_incompatibility_writer_default_reader_named() {
        let writer = Partition::default();
        let reader = Partition::single("sensor");
        assert!(!writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_incompatibility_writer_named_reader_default() {
        let writer = Partition::single("sensor");
        let reader = Partition::default();
        assert!(!writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_compatibility_intersection() {
        let writer = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
        let reader = Partition::single("actuator");
        assert!(writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_compatibility_multiple_intersection() {
        let writer = Partition::new(vec![
            "sensor".to_string(),
            "actuator".to_string(),
            "camera".to_string(),
        ]);
        let reader = Partition::new(vec!["camera".to_string(), "lidar".to_string()]);
        assert!(writer.is_compatible_with(&reader)); // "camera" is common
    }

    #[test]
    fn test_incompatibility_no_intersection() {
        let writer = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
        let reader = Partition::new(vec!["camera".to_string(), "lidar".to_string()]);
        assert!(!writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_add_partition() {
        let mut partition = Partition::default();
        assert!(partition.is_default());

        partition.add("sensor");
        assert!(!partition.is_default());
        assert_eq!(partition.len(), 1);
        assert!(partition.contains("sensor"));

        partition.add("actuator");
        assert_eq!(partition.len(), 2);
        assert!(partition.contains("actuator"));
    }

    #[test]
    fn test_remove_partition_existing() {
        let mut partition = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);

        assert!(partition.remove("sensor"));
        assert_eq!(partition.len(), 1);
        assert!(!partition.contains("sensor"));
        assert!(partition.contains("actuator"));
    }

    #[test]
    fn test_remove_partition_nonexistent() {
        let mut partition = Partition::single("sensor");

        assert!(!partition.remove("actuator"));
        assert_eq!(partition.len(), 1);
    }

    #[test]
    fn test_contains() {
        let partition = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);

        assert!(partition.contains("sensor"));
        assert!(partition.contains("actuator"));
        assert!(!partition.contains("camera"));
    }

    #[test]
    fn test_partition_clone() {
        let partition1 = Partition::single("sensor");
        let partition2 = partition1.clone();
        assert_eq!(partition1, partition2);
    }

    #[test]
    fn test_partition_case_sensitive() {
        let writer = Partition::single("Sensor");
        let reader = Partition::single("sensor");
        assert!(!writer.is_compatible_with(&reader)); // Case-sensitive
    }

    #[test]
    fn test_partition_eq() {
        let p1 = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
        let p2 = Partition::new(vec!["sensor".to_string(), "actuator".to_string()]);
        let p3 = Partition::new(vec!["actuator".to_string(), "sensor".to_string()]);

        assert_eq!(p1, p2);
        assert_ne!(p1, p3); // Order matters for equality
    }

    #[test]
    fn test_partition_len_empty() {
        let partition = Partition::default();
        assert_eq!(partition.len(), 0);
        assert!(partition.is_empty());
    }
}
