// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Telemetry push loop for Participant.
//!
//! Background thread that periodically exports telemetry metrics
//! to the configured exporter endpoint.

use crate::telemetry;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub(super) fn telemetry_push_loop(
    metrics: Arc<telemetry::MetricsCollector>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let frame = metrics.snapshot();

        if let Some(exporter) = telemetry::get_exporter() {
            exporter.push(&frame);
        }

        thread::sleep(Duration::from_millis(100));
    }
}
