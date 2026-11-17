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
//! - Writer `[]`, Reader `["*"]` -> Compatible \[OK\] (`[]` is equivalent to `[""]`)
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
/// Per DDS v1.4 Sec.2.2.3.13, an empty list is equivalent to a list
/// containing one empty string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// List of partition names
    ///
    /// Empty list = default partition, equivalent to `[""]`
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
    /// **Rule:** Partitions must contain at least one pair of matching names.
    /// Empty lists are treated as `[""]`; a wildcard may occur on either side,
    /// but two names that both contain wildcards never match.
    ///
    /// # Arguments
    ///
    /// * `requested` - Reader's requested partition
    ///
    /// # Returns
    ///
    /// `true` if the effective partition name sets intersect
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
        self.effective_names().any(|offered| {
            requested
                .effective_names()
                .any(|wanted| partition_names_match(offered, wanted))
        })
    }

    fn effective_names(&self) -> impl Iterator<Item = &str> {
        self.names
            .iter()
            .map(String::as_str)
            .chain(self.names.is_empty().then_some(""))
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

fn partition_names_match(a: &str, b: &str) -> bool {
    let a_has_wildcard = has_wildcard(a);
    let b_has_wildcard = has_wildcard(b);

    if a_has_wildcard && b_has_wildcard {
        return false;
    }
    if a == b {
        return true;
    }
    if a_has_wildcard {
        return fnmatch_simple(a, b);
    }
    if b_has_wildcard {
        return fnmatch_simple(b, a);
    }
    false
}

fn has_wildcard(name: &str) -> bool {
    name.bytes().any(|byte| matches!(byte, b'*' | b'?'))
}

/// Simple fnmatch-style glob matching for partition names.
/// `*` matches any sequence of characters, `?` matches exactly one character.
fn fnmatch_simple(pattern: &str, text: &str) -> bool {
    let pat = pattern.as_bytes();
    let text_bytes = text.as_bytes();
    let mut px = 0usize;
    let mut tx = 0usize;
    let mut star_px: Option<usize> = None;
    let mut star_ti: usize = 0;

    while tx < text_bytes.len() {
        if px < pat.len() && (pat[px] == b'?' || pat[px] == text_bytes[tx]) {
            px += 1;
            tx += 1;
        } else if px < pat.len() && pat[px] == b'*' {
            star_px = Some(px);
            star_ti = tx;
            px += 1;
        } else if let Some(spx) = star_px {
            px = spx + 1;
            star_ti += 1;
            tx = star_ti;
        } else {
            return false;
        }
    }

    while px < pat.len() && pat[px] == b'*' {
        px += 1;
    }

    px == pat.len()
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
    fn test_default_is_equivalent_to_explicit_empty_name() {
        let default = Partition::default();
        let explicit_empty = Partition::single("");
        let empty_and_named = Partition::new(vec!["".to_string(), "sensor".to_string()]);

        assert!(default.is_compatible_with(&explicit_empty));
        assert!(explicit_empty.is_compatible_with(&default));
        assert!(default.is_compatible_with(&empty_and_named));
        assert!(empty_and_named.is_compatible_with(&default));
    }

    #[test]
    fn test_default_matches_single_wildcard() {
        let default = Partition::default();
        let wildcard = Partition::single("*");

        assert!(default.is_compatible_with(&wildcard));
        assert!(wildcard.is_compatible_with(&default));
    }

    #[test]
    fn test_two_wildcard_names_never_match() {
        assert!(!Partition::single("*").is_compatible_with(&Partition::single("*")));
        assert!(!Partition::single("sensor*").is_compatible_with(&Partition::single("sensor?")));
    }

    #[test]
    fn test_one_wildcard_name_matches_literal_in_either_direction() {
        let wildcard = Partition::single("sensor*");
        let literal = Partition::single("sensor-west");

        assert!(wildcard.is_compatible_with(&literal));
        assert!(literal.is_compatible_with(&wildcard));
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
