// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Lazy-binding matcher utilities orchestrating QoS, topic, and type compatibility checks.
//!

use crate::dds::qos::QoS;
use crate::xtypes::CompleteTypeObject;

mod qos;
mod topic;
mod types;

#[cfg(test)]
mod tests;

/// Lazy-binding matcher: topic/type/QoS compatibility.
///
/// Phase 4 (T0) delivers basic QoS compatibility. Phase 9 adds XTypes structural equivalence,
/// and Phase 11 introduces type assignability rules.
pub struct Matcher;

impl Matcher {
    /// Create a new matcher instance.
    pub fn new() -> Self {
        crate::trace_fn!("Matcher::new");
        Self
    }

    /// Check if reader and writer QoS are compatible.
    ///
    /// # Compatibility Rules (T0)
    ///
    /// 1. **History**: Reader <= Writer
    ///    - If reader wants KeepLast(N) and writer offers KeepLast(M), then N <= M must hold
    ///    - Rationale: Reader requests history depth, writer must provide at least that much
    ///
    /// 2. **Reliability**: Any (T0 all BestEffort)
    /// 3. **Durability**: Any (T0 all Volatile)
    ///
    /// # Returns
    /// - `true`: QoS compatible, binding allowed
    /// - `false`: QoS incompatible, binding rejected
    ///
    /// # Performance
    /// Target: < 100 ns (simple integer comparison)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::core::discovery::Matcher;
    /// use hdds::api::qos::QoS;
    ///
    /// let reader_qos = QoS::best_effort().keep_last(50);
    /// let writer_qos = QoS::best_effort().keep_last(100);
    ///
    /// assert!(Matcher::is_compatible(&reader_qos, &writer_qos)); // 50 <= 100 -> OK
    /// ```
    pub fn is_compatible(reader_qos: &QoS, writer_qos: &QoS) -> bool {
        crate::trace_fn!("Matcher::is_compatible");
        qos::is_compatible(reader_qos, writer_qos)
    }

    /// Check topic name compatibility (exact string match)
    ///
    /// # Returns
    /// - `true`: Topic names match exactly
    /// - `false`: Topic names differ
    pub fn is_topic_match(reader_topic: &str, writer_topic: &str) -> bool {
        crate::trace_fn!("Matcher::is_topic_match");
        topic::is_topic_match(reader_topic, writer_topic)
    }

    /// Check type ID compatibility (FNV-1a hash equality).
    ///
    /// # Returns
    /// - `true`: Type IDs match
    /// - `false`: Type IDs differ (incompatible types)
    pub fn is_type_match(reader_type_id: u32, writer_type_id: u32) -> bool {
        crate::trace_fn!("Matcher::is_type_match");
        topic::is_type_match(reader_type_id, writer_type_id)
    }

    /// Check type compatibility using XTypes v1.3 TypeObject (Phase 9).
    ///
    /// Implements structural type equivalence checking via EquivalenceHash. Falls back to
    /// type_name matching for legacy interoperability when TypeObjects are unavailable.
    ///
    /// # XTypes v1.3 Mode (both TypeObjects present)
    ///
    /// Compares EquivalenceHash (MD5-based 14-byte hash) of TypeObjects:
    /// - Same hash -> structurally equivalent types -> **compatible**
    /// - Different hash -> incompatible structure -> **incompatible**
    ///
    /// Benefits:
    /// - **Multi-vendor interop**: Works with FastDDS, RTI, etc.
    /// - **Type evolution**: Compatible changes allowed (e.g., add optional fields)
    /// - **Structural equivalence**: Match by structure, not name
    ///
    /// # Legacy Mode (at least one TypeObject missing)
    ///
    /// Falls back to simple type_name string comparison:
    /// - Same name -> **compatible**
    /// - Different name -> **incompatible**
    ///
    /// Used when:
    /// - Remote endpoint doesn't announce TypeObject (old HDDS version)
    /// - Local type doesn't provide TypeObject (manual DDS impl without proc-macro)
    ///
    /// # Arguments
    ///
    /// - `local_type_object`: Local endpoint TypeObject (from T::get_type_object())
    /// - `remote_type_object`: Remote endpoint TypeObject (from SEDP announcement)
    /// - `local_type_name`: Local type name (from TypeDescriptor)
    /// - `remote_type_name`: Remote type name (from SEDP)
    ///
    /// # Returns
    ///
    /// - `true`: Types are compatible (same EquivalenceHash or same name)
    /// - `false`: Types are incompatible
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::core::discovery::Matcher;
    /// use hdds::xtypes::{CompleteTypeObject, CompleteStructType, StructTypeFlag};
    /// use hdds::xtypes::{CompleteStructHeader, CompleteTypeDetail};
    ///
    /// // XTypes mode: Both have TypeObject
    /// let local_obj = CompleteTypeObject::Struct(CompleteStructType {
    ///     struct_flags: StructTypeFlag::IS_FINAL,
    ///     header: CompleteStructHeader {
    ///         base_type: None,
    ///         detail: CompleteTypeDetail::new("Point"),
    ///     },
    ///     member_seq: vec![],
    /// });
    /// let remote_obj = local_obj.clone();
    ///
    /// assert!(Matcher::is_type_compatible(
    ///     Some(&local_obj),
    ///     Some(&remote_obj),
    ///     "Point",
    ///     "Point"
    /// ));
    ///
    /// // Legacy mode: No TypeObject (fallback to name)
    /// assert!(Matcher::is_type_compatible(
    ///     None,
    ///     None,
    ///     "Temperature",
    ///     "Temperature"
    /// ));
    /// ```
    ///
    /// # Performance
    ///
    /// - XTypes mode: ~100-200 ns (MD5 hash computation + comparison)
    /// - Legacy mode: < 10 ns (string comparison)
    ///
    /// # Future Enhancements
    ///
    /// - Phase 11: Type assignability checking (implemented below)
    pub fn is_type_compatible(
        local_type_object: Option<&CompleteTypeObject>,
        remote_type_object: Option<&CompleteTypeObject>,
        local_type_name: &str,
        remote_type_name: &str,
    ) -> bool {
        types::is_type_compatible(
            local_type_object,
            remote_type_object,
            local_type_name,
            remote_type_name,
        )
    }

    /// Check if writer type is assignable to reader type (Phase 11).
    ///
    /// Implements XTypes v1.3 Type Assignability rules with extensibility support. Determines if
    /// a DataWriter of type `W` can communicate with a DataReader of type `R`.
    pub fn is_assignable_to(
        writer_type: &CompleteTypeObject,
        reader_type: &CompleteTypeObject,
    ) -> bool {
        types::is_assignable_to(writer_type, reader_type)
    }
}

impl Default for Matcher {
    fn default() -> Self {
        Self::new()
    }
}
