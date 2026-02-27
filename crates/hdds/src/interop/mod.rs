// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// hdds/crates/hdds/src/interop/mod.rs
// Interop module - Wire profiles and matching rules

pub mod matching;

use matching::{MatchingRules, MismatchReport};

/// Wire profile identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum WireProfileId {
    /// Legacy CDR1 for SENSOR/STATE/EVENT (Temperature)
    LegacyCdr1,
    /// PL_CDR2 for XCDR2 (Poly3D)
    PlCdr2,
    /// Future: RTI profiles
    RtiCdr1,
    RtiCdr2,
}

impl WireProfileId {
    /// Get matching rules for this profile
    pub fn matching_rules(&self) -> MatchingRules {
        match self {
            Self::LegacyCdr1 => MatchingRules::legacy_cdr1(),
            Self::PlCdr2 => MatchingRules::xcdr2_strict(),
            // RTI profiles will get dedicated presets when Interop v2
            // integration lands; for now we reuse the legacy rules.
            Self::RtiCdr1 => MatchingRules::legacy_cdr1(),
            Self::RtiCdr2 => MatchingRules::legacy_cdr1(),
        }
    }

    /// Determine profile from topic and peer info.
    ///
    /// This is a temporary heuristic; a dedicated ProfileNegotiator
    /// will replace it when the full Interop v2 stack is wired.
    pub fn from_context(topic: &str, has_type_object: bool) -> Self {
        // Temporary heuristic, will be replaced by negotiator
        if topic.contains("Poly3D") || topic.contains("Xcdr2") {
            Self::PlCdr2
        } else if !has_type_object {
            Self::LegacyCdr1
        } else {
            // Default to XCDR2 for new topics with TypeObject
            Self::PlCdr2
        }
    }
}

/// Future: Full wire profile trait
/// For now, just a placeholder to show the direction
#[allow(dead_code)]
pub trait WireProfile: Send + Sync {
    fn id(&self) -> WireProfileId;
    fn matching_rules(&self) -> MatchingRules;
}

/// Diagnostic collector (singleton for now)
/// Will become part of InteropRegistry
pub struct DiagnosticCollector {
    reports: parking_lot::RwLock<Vec<MismatchReport>>,
}

impl DiagnosticCollector {
    pub fn new() -> Self {
        Self {
            reports: parking_lot::RwLock::new(Vec::new()),
        }
    }

    pub fn add_report(&self, report: MismatchReport) {
        let mut reports = self.reports.write();
        // Keep a copy in the collector while using the original for logging.
        reports.push(report.clone());

        // Log immediately for debugging
        match report.severity {
            matching::MismatchSeverity::Fatal => {
                log::error!(
                    "[INTEROP] FATAL mismatch on {}: {}",
                    report.local_topic,
                    report.details
                );
            }
            matching::MismatchSeverity::Negotiable => {
                log::warn!(
                    "[INTEROP] Negotiable mismatch on {}: {}",
                    report.local_topic,
                    report.details
                );
            }
            matching::MismatchSeverity::Ignorable => {
                log::debug!(
                    "[INTEROP] Ignorable mismatch on {}: {}",
                    report.local_topic,
                    report.details
                );
            }
        }

        if let Some(suggestion) = &report.suggestion {
            log::info!("[INTEROP] Suggestion: {}", suggestion);
        }
    }

    #[allow(dead_code)] // Part of DiagnosticCollector API for future use
    pub fn drain_reports(&self) -> Vec<MismatchReport> {
        let mut reports = self.reports.write();
        std::mem::take(&mut *reports)
    }
}

// Global collector for now, will move to InteropRegistry
use std::sync::OnceLock;

pub(crate) static DIAGNOSTICS: OnceLock<DiagnosticCollector> = OnceLock::new();

pub(crate) fn get_diagnostics() -> &'static DiagnosticCollector {
    DIAGNOSTICS.get_or_init(DiagnosticCollector::new)
}

/// Return true if interop diagnostics are enabled.
///
/// Controlled via `HDDS_INTEROP_DIAGNOSTICS=1`. When disabled, SEDP/EDP
/// hot paths remain unchanged and no diagnostic work is performed.
#[inline]
pub fn diagnostics_enabled() -> bool {
    std::env::var("HDDS_INTEROP_DIAGNOSTICS").is_ok()
}
