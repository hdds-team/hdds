// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::model::{
    DataReaderQos, DataWriterQos, HistoryKind, LivelinessKind, Mcq, ParticipantQos, ReliabilityKind,
};
use std::fmt;

/// Validation errors collected during MCQ validation.
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// CRITICAL invariant violation - strict mode must reject.
    Critical { field: String, message: String },
    /// MAJOR violation - should warn but may proceed in compat mode.
    Major { field: String, message: String },
    /// MINOR violation - informational only.
    Minor { field: String, message: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Critical { field, message } => {
                write!(f, "CRITICAL [{field}]: {message}")
            }
            ValidationError::Major { field, message } => {
                write!(f, "MAJOR [{field}]: {message}")
            }
            ValidationError::Minor { field, message } => {
                write!(f, "MINOR [{field}]: {message}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

impl Mcq {
    /// Parse MCQ from YAML text, rejecting on critical violations.
    pub fn from_yaml(yaml: &str) -> Result<Self, Vec<ValidationError>> {
        let mcq: Mcq = serde_yaml::from_str(yaml).map_err(|e| {
            vec![ValidationError::Critical {
                field: "parse".to_string(),
                message: format!("YAML parse error: {e}"),
            }]
        })?;

        let errors = mcq.collect_validation_errors();
        let critical: Vec<_> = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::Critical { .. }))
            .cloned()
            .collect();

        if critical.is_empty() {
            Ok(mcq)
        } else {
            Err(critical)
        }
    }

    /// Collect all validation errors (critical + warnings).
    #[must_use]
    pub fn collect_validation_errors(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        self.validate_participant(&mut errors);

        for (idx, dw) in self.datawriter_qos.iter().enumerate() {
            Self::validate_datawriter(dw, idx, &mut errors);
        }
        for (idx, dr) in self.datareader_qos.iter().enumerate() {
            Self::validate_datareader(dr, idx, &mut errors);
        }

        errors
    }

    /// Validate and return `Ok` only if no critical violations remain.
    #[allow(dead_code)]
    pub fn validate_all(&self) -> Result<(), Vec<ValidationError>> {
        let errors = self.collect_validation_errors();
        let critical: Vec<_> = errors
            .iter()
            .filter(|e| matches!(e, ValidationError::Critical { .. }))
            .cloned()
            .collect();

        if critical.is_empty() {
            Ok(())
        } else {
            Err(critical)
        }
    }

    fn validate_participant(&self, errors: &mut Vec<ValidationError>) {
        const MIN_LEASE_NS: u64 = 1_000_000; // 1 ms

        let ParticipantQos { discovery, .. } = &self.participant_qos;

        if discovery.initial_peers.is_empty() {
            errors.push(ValidationError::Minor {
                field: "discovery.initial_peers".to_string(),
                message: "Empty initial_peers (acceptable but unusual)".to_string(),
            });
        }
        if discovery.initial_peers.len() > 256 {
            errors.push(ValidationError::Critical {
                field: "discovery.initial_peers".to_string(),
                message: format!("Too many peers: {} > 256", discovery.initial_peers.len()),
            });
        }
        if discovery.participant_liveliness_lease_duration_ns < MIN_LEASE_NS {
            errors.push(ValidationError::Major {
                field: "discovery.participant_liveliness_lease_duration_ns".to_string(),
                message: format!(
                    "Lease duration {} ns < 1 ms (unstable)",
                    discovery.participant_liveliness_lease_duration_ns
                ),
            });
        }
    }

    fn validate_datawriter(dw: &DataWriterQos, idx: usize, errors: &mut Vec<ValidationError>) {
        let prefix = format!("datawriter_qos[{idx}]");

        if dw.reliability.kind == ReliabilityKind::Reliable
            && dw.reliability.max_blocking_time_ns.is_none()
        {
            errors.push(ValidationError::Critical {
                field: format!("{prefix}.reliability.max_blocking_time_ns"),
                message: "Reliable reliability requires max_blocking_time_ns".to_string(),
            });
        }

        if dw.history.kind == HistoryKind::KeepLast {
            match dw.history.depth {
                None => errors.push(ValidationError::Critical {
                    field: format!("{prefix}.history.depth"),
                    message: "KEEP_LAST requires depth >= 1".to_string(),
                }),
                Some(0) => errors.push(ValidationError::Critical {
                    field: format!("{prefix}.history.depth"),
                    message: "KEEP_LAST depth must be >= 1".to_string(),
                }),
                Some(depth) =>
                {
                    #[allow(clippy::cast_possible_wrap)]
                    if depth as i32 > dw.resource_limits.max_samples {
                        errors.push(ValidationError::Critical {
                            field: format!("{prefix}.history.depth"),
                            message: format!(
                                "depth {} > max_samples {}",
                                depth, dw.resource_limits.max_samples
                            ),
                        });
                    }
                }
            }
        }

        if dw.resource_limits.max_samples_per_instance > dw.resource_limits.max_samples {
            errors.push(ValidationError::Critical {
                field: format!("{prefix}.resource_limits"),
                message: format!(
                    "max_samples_per_instance {} > max_samples {}",
                    dw.resource_limits.max_samples_per_instance, dw.resource_limits.max_samples
                ),
            });
        }

        if dw.resource_limits.max_samples < 1 {
            errors.push(ValidationError::Critical {
                field: format!("{prefix}.resource_limits.max_samples"),
                message: "max_samples must be >= 1".to_string(),
            });
        }
        if dw.resource_limits.max_instances < 1 {
            errors.push(ValidationError::Critical {
                field: format!("{prefix}.resource_limits.max_instances"),
                message: "max_instances must be >= 1".to_string(),
            });
        }
        if dw.resource_limits.max_samples_per_instance < 1 {
            errors.push(ValidationError::Critical {
                field: format!("{prefix}.resource_limits.max_samples_per_instance"),
                message: "max_samples_per_instance must be >= 1".to_string(),
            });
        }

        if dw.liveliness.kind != LivelinessKind::Automatic
            && dw.liveliness.lease_duration_ns.is_none()
        {
            errors.push(ValidationError::Major {
                field: format!("{prefix}.liveliness.lease_duration_ns"),
                message: format!(
                    "{:?} liveliness requires lease_duration_ns",
                    dw.liveliness.kind
                ),
            });
        }
    }

    fn validate_datareader(dr: &DataReaderQos, idx: usize, errors: &mut Vec<ValidationError>) {
        let prefix = format!("datareader_qos[{idx}]");

        if dr.reliability.kind == ReliabilityKind::Reliable
            && dr.reliability.max_blocking_time_ns.is_none()
        {
            errors.push(ValidationError::Minor {
                field: format!("{prefix}.reliability.max_blocking_time_ns"),
                message: "Reliable reader should specify max_blocking_time_ns for consistency"
                    .to_string(),
            });
        }

        if dr.history.kind == HistoryKind::KeepLast {
            match dr.history.depth {
                None => errors.push(ValidationError::Critical {
                    field: format!("{prefix}.history.depth"),
                    message: "KEEP_LAST requires depth >= 1".to_string(),
                }),
                Some(0) => errors.push(ValidationError::Critical {
                    field: format!("{prefix}.history.depth"),
                    message: "KEEP_LAST depth must be >= 1".to_string(),
                }),
                Some(_) => {}
            }
        }

        if dr.reader_resource_limits.max_samples < 1 {
            errors.push(ValidationError::Critical {
                field: format!("{prefix}.reader_resource_limits.max_samples"),
                message: "max_samples must be >= 1".to_string(),
            });
        }
    }

    /// Normalize MCQ (sort, fill derived fields). Idempotent.
    pub fn normalize(&mut self) {
        self.datawriter_qos
            .sort_by(|a, b| a.topic_filter.cmp(&b.topic_filter));
        self.datareader_qos
            .sort_by(|a, b| a.topic_filter.cmp(&b.topic_filter));
    }
}
