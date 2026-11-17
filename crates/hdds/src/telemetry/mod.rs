// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Telemetry collection, export, and live capture for HDDS monitoring.
//!
#![allow(missing_docs)]
//!
//! # Modules
//! - `metrics`: Thread-safe metrics collection with atomic counters and latency histograms
//! - `export`: Binary frame encoding/decoding (HDMX format)
//! - `capture`: Live telemetry streaming server for HDDS Viewer
//!
//! # Usage
//! ```rust,no_run
//! use hdds::telemetry::{init_metrics, init_exporter, get_metrics};
//!
//! // Initialize global metrics collector
//! let metrics = init_metrics();
//!
//! // Initialize telemetry exporter (optional)
//! let exporter = init_exporter("127.0.0.1", 4242).ok();
//!
//! // Record metrics
//! metrics.increment_sent(1);
//! let start_ns = 1_000_000u64;
//! let end_ns = 1_000_500u64;
//! metrics.add_latency_sample(start_ns, end_ns);
//!
//! // Snapshot current metrics
//! let frame = metrics.snapshot();
//! ```

/// Live telemetry streaming and capture server.
pub mod capture;
/// Binary telemetry frame encoding/decoding (HDMX format).
pub mod export;
/// Thread-safe metrics collection with atomic counters and latency histograms.
pub mod metrics;

pub use capture::{extract_metrics_from_collector, parse_frame_fields, Exporter};
pub use export::{decode_frame, encode_frame, MAGIC, VERSION};
pub use metrics::{Field, Frame, MetricsCollector};

use std::sync::{Arc, Mutex, OnceLock, Weak};

static GLOBAL_METRICS: OnceLock<Arc<MetricsCollector>> = OnceLock::new();
/// The exporter [`get_exporter`] answers with: the first one started that is
/// still alive. Held weakly: an exporter lives as long as a handle to it
/// (the caller of [`init_exporter`], or the participants that started it),
/// so its thread and port are released with the last of them.
// @audit-ok: one telemetry server per process is the design (one TCP port
// for the Viewer); weak, so it never outlives its holders.
static GLOBAL_EXPORTER: Mutex<Weak<Exporter>> = Mutex::new(Weak::new());

/// Initialize global metrics collector
pub fn init_metrics() -> Arc<MetricsCollector> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(MetricsCollector::new()))
        .clone()
}

/// Get global metrics collector (creates if not initialized)
pub fn get_metrics() -> Arc<MetricsCollector> {
    get_metrics_opt().cloned().unwrap_or_else(init_metrics)
}

/// Get global metrics collector (returns None if not initialized)
///
/// Returns a reference into the process-wide `OnceLock` so hot paths
/// avoid the per-call Arc clone + drop. Callers needing ownership can
/// `Arc::clone` the returned reference.
pub fn get_metrics_opt() -> Option<&'static Arc<MetricsCollector>> {
    #[cfg(test)]
    if let Some(metrics) = THREAD_METRICS_FOR_TEST.with(std::cell::Cell::get) {
        return Some(metrics);
    }
    GLOBAL_METRICS.get()
}

#[cfg(test)]
thread_local! {
    /// Test-only: a collector that replaces the process-wide one for
    /// [`get_metrics_opt`] on THIS thread (see [`private_metrics_for_test`]).
    static THREAD_METRICS_FOR_TEST: std::cell::Cell<Option<&'static Arc<MetricsCollector>>> =
        const { std::cell::Cell::new(None) };
}

/// Restores the calling thread's previous collector when dropped.
#[cfg(test)]
pub(crate) struct PrivateMetricsGuard {
    previous: Option<&'static Arc<MetricsCollector>>,
    /// The collector this guard made, freed after the thread's collector is
    /// restored (a field drops after the body of `Drop::drop`).
    _owned: crate::core::rt::TestOwned<Arc<MetricsCollector>>,
}

#[cfg(test)]
impl Drop for PrivateMetricsGuard {
    fn drop(&mut self) {
        THREAD_METRICS_FOR_TEST.with(|cell| cell.set(self.previous));
    }
}

/// Test-only: give the CURRENT thread a fresh collector of its own until
/// the guard is dropped, and return it.
///
/// The process-wide collector is shared by every test of the `--lib`
/// binary running at once, so a before/after delta of one of its counters
/// counts every concurrent test's events too. A test that asserts an
/// exact count reads a private collector instead; it sees exactly the
/// events raised on its own thread.
#[cfg(test)]
pub(crate) fn private_metrics_for_test() -> (&'static Arc<MetricsCollector>, PrivateMetricsGuard) {
    // The accessor hands out `&'static`; the guard owns the collector and
    // frees it once the thread's collector is restored.
    let owned = crate::core::rt::TestOwned::new(Arc::new(MetricsCollector::new()));
    let metrics: &'static Arc<MetricsCollector> = owned.get();
    let previous = THREAD_METRICS_FOR_TEST.with(|cell| cell.replace(Some(metrics)));
    (
        metrics,
        PrivateMetricsGuard {
            previous,
            _owned: owned,
        },
    )
}

/// Initialize global telemetry exporter
///
/// Starts a new server on `bind_addr:port`. It becomes the global exporter
/// ([`get_exporter`]) unless one is already alive. Dropping the returned
/// `Arc<Exporter>` stops the server only if it is the LAST holder of it
/// (ordinary reference counting): a participant that later shares the
/// same process exporter (via [`shared_exporter`]) keeps it alive past
/// this handle being dropped. To force a real stop regardless of who else
/// holds it, call [`Exporter::shutdown`] explicitly (what the C ABI's
/// `hdds_telemetry_stop_exporter` does) rather than relying on drop.
/// Calling this again afterwards starts a genuinely new, working server,
/// which also becomes the global exporter again (the old one is
/// recognised as dead via [`Exporter::is_shutdown`], not mistaken for
/// still alive).
pub fn init_exporter(bind_addr: &str, port: u16) -> std::io::Result<Arc<Exporter>> {
    let mut global = GLOBAL_EXPORTER.lock().unwrap_or_else(|e| e.into_inner());
    let exporter = start_exporter(bind_addr, port)?;
    if !matches!(global.upgrade(), Some(existing) if !existing.is_shutdown()) {
        *global = Arc::downgrade(&exporter);
    }
    Ok(exporter)
}

/// The exporter a participant streams to: the global one if alive, else a
/// new one on `bind_addr:port` (on any free port if that one is taken),
/// which becomes the global one. The participant holds it, so it lives as
/// long as some participant (or other handle) does.
///
/// A global exporter that was explicitly stopped (its port released,
/// [`Exporter::is_shutdown`] true) is treated as absent here, not handed
/// out: a participant built afterwards gets a fresh, live exporter rather
/// than a dead one that will never export anything.
pub(crate) fn shared_exporter(bind_addr: &str, port: u16) -> std::io::Result<Arc<Exporter>> {
    let mut global = GLOBAL_EXPORTER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(exporter) = global.upgrade() {
        if !exporter.is_shutdown() {
            return Ok(exporter);
        }
    }
    let exporter = start_exporter(bind_addr, port).or_else(|_| {
        log::debug!("[!] Port {port} busy (TIME_WAIT?), using random port");
        start_exporter(bind_addr, 0)
    })?;
    *global = Arc::downgrade(&exporter);
    Ok(exporter)
}

fn start_exporter(bind_addr: &str, port: u16) -> std::io::Result<Arc<Exporter>> {
    log::debug!("[hdds] telemetry::init_exporter({bind_addr}:{port}) starting");
    let exporter = Arc::new(Exporter::start(bind_addr, port)?);
    log::debug!("[hdds] telemetry::init_exporter({bind_addr}:{port}) ready");
    Ok(exporter)
}

/// Get global exporter (returns None if none is alive)
pub fn get_exporter() -> Option<Arc<Exporter>> {
    GLOBAL_EXPORTER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .upgrade()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::Ordering;

    /// `let _ = init_exporter(..)?;` (the explicit handle going out of
    /// scope at the end of a setup function) must NOT stop the server
    /// once something else -- a participant, in practice -- shares the
    /// same `Arc<Exporter>`: only the genuinely LAST holder's drop does
    /// that, ordinary `Arc` reference counting, never an unconditional
    /// forced stop. Uses a plain `Arc::clone` rather than
    /// `shared_exporter`/`GLOBAL_EXPORTER` so this test's outcome cannot
    /// depend on which exporter another test running at the same time
    /// happens to have made the process-global one.
    #[test]
    fn dropping_the_init_exporter_return_value_does_not_stop_a_shared_exporter() {
        let handle = init_exporter("127.0.0.1", 0).expect("exporter should start");
        let addr = handle.local_addr();
        let shared = Arc::clone(&handle); // what a participant would hold

        drop(handle); // the setup function's own binding goes out of scope

        assert!(
            TcpListener::bind(addr).is_err(),
            "a holder still sharing the exporter should keep its port held"
        );

        let closed_flag = shared.listener_closed_flag_for_test();
        drop(shared); // now the real last holder drops
        assert!(
            closed_flag.load(Ordering::Relaxed),
            "the exporter's last holder dropping should have closed its listening socket"
        );
    }

    /// An explicit [`Exporter::shutdown`] forces a real stop right now,
    /// even while another holder (a participant) still shares the same
    /// `Arc<Exporter>`.
    #[test]
    fn explicit_shutdown_stops_it_even_while_shared() {
        let handle = init_exporter("127.0.0.1", 0).expect("exporter should start");
        let shared = Arc::clone(&handle);

        handle.shutdown();

        assert!(
            handle.listener_closed_for_test(),
            "an explicit shutdown should close the listening socket even while shared"
        );
        // The sharer is not dropped, not panicking, just looking at a
        // now-shut-down exporter.
        assert!(shared.is_shutdown());
    }

    /// Starting the exporter again after an explicit stop opens a
    /// genuinely new, working server rather than reusing the dead one.
    #[test]
    fn start_after_an_explicit_stop_gets_a_live_server() {
        let first = init_exporter("127.0.0.1", 0).expect("exporter should start");
        first.shutdown();
        assert!(first.is_shutdown());
        assert!(
            first.listener_closed_for_test(),
            "the stopped exporter should have closed its listening socket"
        );

        let second = init_exporter("127.0.0.1", 0).expect("exporter should restart");
        assert!(
            !second.is_shutdown(),
            "the restarted exporter should be live"
        );
        let second_addr = second.local_addr();
        assert!(
            TcpListener::bind(second_addr).is_err(),
            "the restarted exporter should hold its new port"
        );

        second.shutdown();
        assert!(
            second.listener_closed_for_test(),
            "the restarted exporter should have closed its listening socket after an explicit shutdown"
        );
    }
}
