// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Conversion Engine (MVP)
//!
//! MCQ -> MCQ conversion with validation, normalization, and fidelity scoring.

use crate::mcq::{Mcq, ValidationError};
use serde::{Deserialize, Serialize};

/// Conversion mode
#[derive(Debug, Clone, Copy)]
pub enum ConversionMode {
    /// Strict mode: reject on CRITICAL errors
    Strict,
    /// Compat mode: allow MAJOR/MINOR warnings
    Compat,
}

/// Fidelity report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FidelityReport {
    pub conversion_id: String,
    pub timestamp: String,
    pub from_vendor: String,
    pub to_vendor: String,
    pub mode: String,
    pub fidelity_score: i32,
    pub tags: Vec<String>,
    pub changes: Vec<Change>,
    pub validation_errors: Vec<ValidationSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub field: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationSummary {
    pub severity: String,
    pub field: String,
    pub message: String,
}

pub struct ConversionEngine;

impl ConversionEngine {
    /// Convert MCQ with validation and scoring
    pub fn convert(
        mut mcq_in: Mcq,
        mode: ConversionMode,
    ) -> Result<(Mcq, FidelityReport), Vec<ValidationError>> {
        // Collect validation errors
        let errors = mcq_in.collect_validation_errors();

        // Check for CRITICAL errors in strict mode
        if matches!(mode, ConversionMode::Strict) {
            let critical_errors: Vec<_> = errors
                .iter()
                .filter(|e| matches!(e, ValidationError::Critical { .. }))
                .cloned()
                .collect();

            if !critical_errors.is_empty() {
                return Err(critical_errors);
            }
        }

        // Normalize MCQ (sort, fill derived fields)
        mcq_in.normalize();

        // Calculate fidelity score
        let (score, tags) = Self::calculate_fidelity_score(&errors);

        // Generate report
        let report = FidelityReport {
            conversion_id: format!("conv-{}", chrono::Utc::now().timestamp()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            from_vendor: mcq_in.metadata.source.clone(),
            to_vendor: mcq_in.metadata.source.clone(), // Same vendor for now
            mode: format!("{mode:?}").to_lowercase(),
            fidelity_score: score,
            tags,
            changes: vec![], // No changes tracked in MVP
            validation_errors: errors
                .iter()
                .map(|e| match e {
                    ValidationError::Critical { field, message } => ValidationSummary {
                        severity: "CRITICAL".to_string(),
                        field: field.clone(),
                        message: message.clone(),
                    },
                    ValidationError::Major { field, message } => ValidationSummary {
                        severity: "MAJOR".to_string(),
                        field: field.clone(),
                        message: message.clone(),
                    },
                    ValidationError::Minor { field, message } => ValidationSummary {
                        severity: "MINOR".to_string(),
                        field: field.clone(),
                        message: message.clone(),
                    },
                })
                .collect(),
        };

        Ok((mcq_in, report))
    }

    /// Calculate fidelity score based on validation errors
    /// Base score: 100
    /// - CRITICAL: -15 points each
    /// - MAJOR: -10 points each
    /// - MINOR: -1 point each
    fn calculate_fidelity_score(errors: &[ValidationError]) -> (i32, Vec<String>) {
        let mut score: i32 = 100;
        let mut tags = Vec::new();

        let critical_count = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::Critical { .. }))
            .count();
        let major_count = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::Major { .. }))
            .count();
        let minor_count = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::Minor { .. }))
            .count();

        // Apply penalties (safe cast with saturation)
        let critical_penalty = i32::try_from(critical_count).unwrap_or(i32::MAX / 15) * 15;
        let major_penalty = i32::try_from(major_count).unwrap_or(i32::MAX / 10) * 10;
        let minor_penalty = i32::try_from(minor_count).unwrap_or(i32::MAX);

        score = score.saturating_sub(critical_penalty);
        score = score.saturating_sub(major_penalty);
        score = score.saturating_sub(minor_penalty);

        // Clamp to [0, 100]
        score = score.clamp(0, 100);

        // Assign tags based on score and error severity
        if critical_count > 0 {
            tags.push("critical-loss".to_string());
        }
        if score == 100 && errors.is_empty() {
            tags.push("lossless".to_string());
        } else if score >= 95 {
            tags.push("high-fidelity".to_string());
        } else if score >= 80 {
            tags.push("acceptable".to_string());
        } else if score >= 60 {
            tags.push("degraded".to_string());
        } else {
            tags.push("lossy".to_string());
        }

        (score, tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fidelity_score_perfect() {
        let errors = vec![];
        let (score, tags) = ConversionEngine::calculate_fidelity_score(&errors);

        assert_eq!(score, 100);
        assert!(tags.contains(&"lossless".to_string()));
    }

    #[test]
    fn test_fidelity_score_with_minor() {
        let errors = vec![ValidationError::Minor {
            field: "test".to_string(),
            message: "test".to_string(),
        }];
        let (score, tags) = ConversionEngine::calculate_fidelity_score(&errors);

        assert_eq!(score, 99);
        assert!(tags.contains(&"high-fidelity".to_string()));
    }

    #[test]
    fn test_fidelity_score_with_critical() {
        let errors = vec![ValidationError::Critical {
            field: "test".to_string(),
            message: "test".to_string(),
        }];
        let (score, tags) = ConversionEngine::calculate_fidelity_score(&errors);

        assert_eq!(score, 85);
        assert!(tags.contains(&"critical-loss".to_string()));
        assert!(tags.contains(&"acceptable".to_string()));
    }
}
