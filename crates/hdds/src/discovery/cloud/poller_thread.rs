// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Synchronous polling thread wrapper for cloud discovery.
//!
//! This module provides a sync interface to async cloud discovery backends
//! (Consul, AWS Cloud Map, Azure) by running a dedicated background thread
//! with its own tokio runtime.
//!
//! # Architecture
//!
//! ```text
//! +----------------------------------------------------------------------+
//! |                        Participant (sync)                            |
//! |                                                                      |
//! |   CloudDiscoveryPollerHandle        CloudPeerSink (installed at      |
//! |     cmd_tx  ------------------+     bootstrap: SpdpPeerSet feeder)   |
//! |     event_rx <------------+   |         ^                            |
//! |     status  <---------+   |   |         |                            |
//! +-----------------------|---|---|---------|----------------------------+
//!                         |   |   v         |
//! +-----------------------|---|-------------|----------------------------+
//! |          hdds-cloud-discovery thread (tokio current_thread)          |
//! |                       |   |             |                            |
//! |   every event ---> status, event channel (bounded copy for the       |
//! |                    public handle) AND sink.on_event()                |
//! |   every successful poll ---> sink.on_poll(full peer view)            |
//! |                                                                      |
//! |   CloudDiscovery backend: register (retried with backoff),           |
//! |   discover_participants (every poll_interval), deregister on stop;   |
//! |   each call bounded by REQUEST_TIMEOUT.                              |
//! +----------------------------------------------------------------------+
//! ```
//!
//! The sink is the authoritative consumer: it runs on the poller thread and
//! sees every event and every successful poll. The public handle receives a
//! copy of every event through a bounded channel, so a user polling
//! `cloud_discovery_handle()` can never steal an event from the SPDP feed
//! (and a user who never polls cannot grow memory without bound: the
//! overflow is counted in `CloudDiscoveryStatus::dropped_events`).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{
    AwsCloudMap, AwsCloudMapConfig, AzureDiscovery, CloudDiscovery, ConsulDiscovery, ConsulOptions,
    HeartbeatError, ParticipantInfo,
};
use crate::dds::Error;

/// Upper bound on one backend call (register, discover, deregister). A
/// black-holed endpoint must not stall the command loop for the backend
/// client's own (longer) timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on the one-shot warm-up (`CloudDiscovery::prepare`). It is
/// deliberately larger than `REQUEST_TIMEOUT`: the warm-up is a CHAIN (a
/// credential chain, then a service lookup), it runs once, and it exists
/// precisely so that every bounded call after it is a single operation.
pub const PREPARE_TIMEOUT: Duration = Duration::from_secs(15);
/// How long `stop()` waits for the thread before detaching it.
const STOP_JOIN_TIMEOUT: Duration = Duration::from_millis(500);
/// Command / timer granularity of the loop.
const TICK: Duration = Duration::from_millis(100);
/// Registration retry backoff bounds.
const REGISTER_BACKOFF_MIN: Duration = Duration::from_secs(1);
const REGISTER_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Consecutive heartbeat calls that may fail WITHOUT the registry saying
/// the record is gone before the poller registers again anyway. Three:
/// the record's TTL is three heartbeat intervals, so a refresh that has
/// missed three of them cannot have kept the record alive either.
pub const HEARTBEAT_FAILURE_THRESHOLD: u32 = 3;
/// Consecutive failed polls after which the poller reports loudly
/// (`log::error` + one `CloudEvent::Error`) instead of a warning per poll.
pub const LOUD_POLL_FAILURE_THRESHOLD: u32 = 3;
/// Capacity of the public event copy.
const EVENT_CHANNEL_CAPACITY: usize = 1024;
/// Default registry poll interval, and the heartbeat cadence that goes
/// with it (a backend derives its record's TTL from this).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

// ============================================================================
// Configuration
// ============================================================================

/// Cloud discovery provider type.
#[derive(Clone)]
pub enum CloudProvider {
    /// HashiCorp Consul
    Consul {
        /// Agent HTTP endpoint.
        addr: String,
        /// Service name, datacenter, ACL token, health policy.
        options: ConsulOptions,
    },
    /// AWS Cloud Map, from namespace, service and region alone: every
    /// other setting (credential chain, health filter, endpoints) takes
    /// its default. [`CloudProvider::AwsCloudMap`] is the form that carries
    /// a full configuration.
    Aws {
        namespace: String,
        service: String,
        region: String,
    },
    /// AWS Cloud Map with a full configuration.
    AwsCloudMap(Box<AwsCloudMapConfig>),
    /// Azure Service Discovery
    Azure { config_json: String },
}

/// `Azure { config_json }` may carry a SAS token or an account key: it is
/// never rendered, so a `{:?}` of any config that embeds the provider
/// cannot leak a credential into a log line.
impl fmt::Debug for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudProvider::Consul { addr, options } => f
                .debug_struct("Consul")
                .field("addr", addr)
                .field("options", options)
                .finish(),
            CloudProvider::Aws {
                namespace,
                service,
                region,
            } => f
                .debug_struct("Aws")
                .field("namespace", namespace)
                .field("service", service)
                .field("region", region)
                .finish(),
            CloudProvider::AwsCloudMap(config) => f
                .debug_struct("AwsCloudMap")
                // `redacted_json` is the config's identity without any
                // credential material.
                .field("config", &config.redacted_json())
                .finish(),
            CloudProvider::Azure { .. } => f
                .debug_struct("Azure")
                .field("config_json", &"<redacted>")
                .finish(),
        }
    }
}

/// How many heartbeat intervals make one lease: the heartbeat is a third
/// of the lease, so a record that misses this many refreshes has expired.
const LEASE_HEARTBEATS: u32 = 3;

/// Configuration for the cloud discovery poller.
///
/// `#[non_exhaustive]`: the field list grows with the backends (it just
/// gained `heartbeat_interval`), so it is built from `Default` and
/// updated field by field.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CloudPollerConfig {
    /// Cloud provider to use.
    pub provider: CloudProvider,
    /// Polling interval for discovery.
    pub poll_interval: Duration,
    /// Domain ID for filtering.
    pub domain_id: u32,
    /// How often the participant's own record is written again, for a
    /// registry that expires records on a lease (Azure Table Storage).
    ///
    /// `None` (the default, and what Consul uses) means "register once":
    /// the registration call is idempotent, so a refresh is the same
    /// call, and a registry that keeps a record until it is deleted needs
    /// no refresh at all.
    pub heartbeat_interval: Option<Duration>,
}

impl Default for CloudPollerConfig {
    fn default() -> Self {
        Self {
            provider: CloudProvider::Consul {
                addr: "http://localhost:8500".to_string(),
                options: ConsulOptions::default(),
            },
            poll_interval: DEFAULT_POLL_INTERVAL,
            domain_id: 0,
            heartbeat_interval: None,
        }
    }
}

/// Participant-side wiring installed by the builder (never by users).
#[derive(Debug, Clone, Default)]
pub(crate) struct CloudPollerWiring {
    /// The participant's own GUID: never reported as a peer.
    pub(crate) own_guid: Option<[u8; 16]>,
    /// The participant's own record, registered once the backend is up
    /// and retried with backoff until it succeeds; deregistered on stop.
    pub(crate) registration: Option<ParticipantInfo>,
}

// ============================================================================
// Commands (sync -> async)
// ============================================================================

/// Commands sent from sync world to async discovery thread.
#[derive(Debug)]
pub enum CloudCommand {
    /// Register this participant with the discovery service.
    Register { info: ParticipantInfo },
    /// Deregister this participant.
    Deregister { guid: [u8; 16] },
    /// Force an immediate discovery poll.
    PollNow,
    /// Shutdown the poller.
    Shutdown,
}

// ============================================================================
// Events (async -> sync)
// ============================================================================

/// Events sent from async discovery thread to sync world.
#[derive(Debug, Clone)]
pub enum CloudEvent {
    /// Poller is ready and running.
    Ready,
    /// New participant discovered.
    ParticipantDiscovered { info: ParticipantInfo },
    /// Participant is no longer available.
    ParticipantLost { guid: [u8; 16] },
    /// Registration succeeded.
    Registered { guid: [u8; 16] },
    /// Deregistration succeeded.
    Deregistered { guid: [u8; 16] },
    /// Error occurred.
    Error { message: String },
    /// Poller has stopped.
    Stopped,
}

// ============================================================================
// Status (async -> sync, always current)
// ============================================================================

/// Last known state of the poller, readable at any time from the handle
/// or from `Participant::cloud_discovery_status()`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CloudDiscoveryStatus {
    /// The poller thread is alive and its backend was constructed.
    pub running: bool,
    /// The participant's own record is currently registered.
    pub registered: bool,
    /// Registration attempts so far (successful or not).
    pub register_attempts: u32,
    /// Discovery polls that returned a result.
    pub successful_polls: u64,
    /// Discovery polls that failed since the last successful one.
    pub consecutive_poll_failures: u32,
    /// Peers (own GUID and foreign domains excluded) in the last
    /// successful poll.
    pub registry_peers: usize,
    /// Most recent error, registration or poll.
    pub last_error: Option<String>,
    /// Events the public handle's copy could not hold (nobody polled it).
    pub dropped_events: u64,
    /// Verdict of the last backend health check, or `None` while polls
    /// keep succeeding. The poller runs one when a run of polls has
    /// failed, so an operator can tell "the registry refuses us" from
    /// "the registry answers, this query finds nobody".
    pub last_health_check: Option<bool>,
}

// ============================================================================
// Sink (crate-private consumer)
// ============================================================================

/// Consumer installed at bootstrap; runs on the poller thread.
pub(crate) trait CloudPeerSink: Send + 'static {
    /// Every event, before it is copied to the public handle.
    fn on_event(&mut self, event: &CloudEvent);
    /// The full, domain-filtered, self-excluded peer view of one successful
    /// poll. Never called for a failed poll.
    fn on_poll(&mut self, peers: &[ParticipantInfo]);
}

/// The sink used by `spawn()`: events only reach the public handle.
struct NoSink;

impl CloudPeerSink for NoSink {
    // A null sink: `spawn()` routes events to the public handle instead, so
    // there is nothing to do here. Giving these a body to satisfy a grep would
    // add code that does nothing and reads as if it did.
    // @audit-ok: deliberate no-op, see above.
    fn on_event(&mut self, _event: &CloudEvent) {}
    // @audit-ok: deliberate no-op, see above.
    fn on_poll(&mut self, _peers: &[ParticipantInfo]) {}
}

// ============================================================================
// Handle (sync side)
// ============================================================================

/// Handle to interact with the cloud discovery poller from sync code.
#[derive(Clone)]
pub struct CloudDiscoveryPollerHandle {
    cmd_tx: Sender<CloudCommand>,
    event_rx: Arc<Mutex<Receiver<CloudEvent>>>,
    running: Arc<AtomicBool>,
    status: Arc<Mutex<CloudDiscoveryStatus>>,
}

impl CloudDiscoveryPollerHandle {
    /// Check if the poller is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Current poller status (a copy).
    pub fn status(&self) -> CloudDiscoveryStatus {
        self.status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Register this participant with the cloud discovery service.
    pub fn register(&self, info: ParticipantInfo) -> Result<(), String> {
        self.cmd_tx
            .send(CloudCommand::Register { info })
            .map_err(|e| format!("Failed to send register command: {}", e))
    }

    /// Deregister this participant.
    pub fn deregister(&self, guid: [u8; 16]) -> Result<(), String> {
        self.cmd_tx
            .send(CloudCommand::Deregister { guid })
            .map_err(|e| format!("Failed to send deregister command: {}", e))
    }

    /// Force an immediate discovery poll.
    pub fn poll_now(&self) -> Result<(), String> {
        self.cmd_tx
            .send(CloudCommand::PollNow)
            .map_err(|e| format!("Failed to send poll command: {}", e))
    }

    /// Poll for events (non-blocking).
    ///
    /// A poisoned event mutex is recovered, not swallowed: the same
    /// poison-tolerant policy `status()` and `SpdpPeerSet::lock` use.
    /// Returning an empty `Vec` forever after one unrelated panic would
    /// silence the public handle with no error and no status bit.
    pub fn poll(&self) -> Vec<CloudEvent> {
        let mut events = Vec::new();
        let rx = self
            .event_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            match rx.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        events
    }

    /// Wait for an event (blocking with timeout).
    ///
    /// Poison-tolerant for the same reason as [`Self::poll`].
    pub fn wait(&self, timeout: Duration) -> Option<CloudEvent> {
        let rx = self
            .event_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        rx.recv_timeout(timeout).ok()
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(CloudCommand::Shutdown);
    }
}

// ============================================================================
// Poller Thread
// ============================================================================

/// Cloud discovery poller thread.
pub struct CloudDiscoveryPoller {
    handle: CloudDiscoveryPollerHandle,
    thread_handle: Option<JoinHandle<()>>,
}

/// Static dispatch over the configured backend.
enum Backend {
    Consul(ConsulDiscovery),
    // Boxed: an `AwsCloudMap` carries a reqwest client and its whole
    // configuration, several times the size of the Consul backend.
    Aws(Box<AwsCloudMap>),
    Azure(AzureDiscovery),
}

impl CloudDiscovery for Backend {
    async fn prepare(&self) -> Result<(), Error> {
        match self {
            Backend::Consul(consul) => consul.prepare().await,
            Backend::Aws(aws) => aws.prepare().await,
            Backend::Azure(azure) => azure.prepare().await,
        }
    }

    async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
        match self {
            Backend::Consul(consul) => consul.register_participant(info).await,
            Backend::Aws(aws) => aws.register_participant(info).await,
            Backend::Azure(azure) => azure.register_participant(info).await,
        }
    }

    async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
        match self {
            Backend::Consul(consul) => consul.discover_participants().await,
            Backend::Aws(aws) => aws.discover_participants().await,
            Backend::Azure(azure) => azure.discover_participants().await,
        }
    }

    fn blocking_discovery_budget(&self) -> Option<Duration> {
        match self {
            Backend::Consul(consul) => consul.blocking_discovery_budget(),
            Backend::Aws(aws) => aws.blocking_discovery_budget(),
            Backend::Azure(azure) => azure.blocking_discovery_budget(),
        }
    }

    async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
        match self {
            Backend::Consul(consul) => consul.deregister_participant(guid).await,
            Backend::Aws(aws) => aws.deregister_participant(guid).await,
            Backend::Azure(azure) => azure.deregister_participant(guid).await,
        }
    }

    async fn health_check(&self) -> Result<bool, Error> {
        match self {
            Backend::Consul(consul) => consul.health_check().await,
            Backend::Aws(aws) => aws.health_check().await,
            Backend::Azure(azure) => azure.health_check().await,
        }
    }

    async fn heartbeat(&self, guid: [u8; 16]) -> Result<(), HeartbeatError> {
        match self {
            Backend::Consul(consul) => consul.heartbeat(guid).await,
            // Neither of these expires its record on a TTL, so both take
            // the trait's default no-op: a Cloud Map instance is owned by
            // its service, and an Azure row is refreshed by rewriting it
            // (the lease arm of the poller loop), not by a liveness call.
            // Named explicitly instead of caught by a wildcard, so a
            // future backend that DOES need a heartbeat fails to compile
            // here rather than silently reporting itself alive for ever.
            Backend::Aws(aws) => aws.heartbeat(guid).await,
            Backend::Azure(azure) => azure.heartbeat(guid).await,
        }
    }
}

/// Is a backend for this provider present in THIS build?
///
/// `build_backend` is the only place a backend is constructed. Every
/// provider in the tree has one today: Consul, AWS Cloud Map and Azure
/// Table Storage. The participant builder asks this BEFORE it lowers the
/// multicast default, so a provider without a backend fails `build()`
/// loudly instead of leaving a participant with neither a registry nor
/// multicast SPDP. The check is kept for the NEXT provider, not because
/// one currently fails it.
/// `backend_availability_matches_build_backend` pins the two together so
/// they cannot drift.
pub(crate) fn backend_is_available(provider: &CloudProvider) -> bool {
    match provider {
        CloudProvider::Consul { .. }
        | CloudProvider::Aws { .. }
        | CloudProvider::AwsCloudMap(_)
        | CloudProvider::Azure { .. } => true,
    }
}

/// Human-readable provider name for error and log lines (no config, no
/// credential: `CloudProvider`'s own `Debug` redacts the Azure config).
pub(crate) fn provider_label(provider: &CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Consul { .. } => "consul",
        CloudProvider::Aws { .. } | CloudProvider::AwsCloudMap(_) => "aws",
        CloudProvider::Azure { .. } => "azure",
    }
}

fn build_backend(config: &CloudPollerConfig) -> Result<Backend, String> {
    match &config.provider {
        CloudProvider::Consul { addr, options } => ConsulDiscovery::new(addr)
            .map(|consul| {
                Backend::Consul(
                    consul
                        .with_options(options.clone())
                        .with_domain_id(config.domain_id)
                        // The TTL of the registered health check is derived
                        // from the cadence the loop below really keeps.
                        .with_heartbeat_interval(config.poll_interval),
                )
            })
            .map_err(|e| format!("Failed to create Consul discovery: {}", e)),
        CloudProvider::Aws {
            namespace,
            service,
            region,
        } => AwsCloudMap::with_config(
            AwsCloudMapConfig::new(namespace, service, region).with_domain_id(config.domain_id),
        )
        .map(|aws| Backend::Aws(Box::new(aws)))
        .map_err(|e| format!("Failed to create AWS Cloud Map discovery: {}", e)),
        CloudProvider::AwsCloudMap(aws) => {
            let mut aws = (**aws).clone();
            // The poller's domain is authoritative: a config that carried
            // a different one would filter the peers of another domain in.
            aws.domain_id = config.domain_id;
            AwsCloudMap::with_config(aws)
                .map(|aws| Backend::Aws(Box::new(aws)))
                .map_err(|e| format!("Failed to create AWS Cloud Map discovery: {}", e))
        }
        // The SAME text the builder validated is parsed again here, on
        // the poller thread, so the participant and its poller can never
        // disagree about what was configured.
        CloudProvider::Azure { config_json } => {
            super::azure_config::AzureDiscoveryConfig::from_json(config_json)
                .and_then(AzureDiscovery::from_config)
                .map(|azure| Backend::Azure(azure.with_domain_id(config.domain_id)))
                .map_err(|e| format!("Failed to create Azure discovery: {}", e))
        }
    }
}

impl CloudDiscoveryPoller {
    /// Spawn a new cloud discovery poller thread.
    ///
    /// Events only reach the public handle; nothing registers the caller.
    /// The participant builder uses `spawn_wired` instead.
    pub fn spawn(config: CloudPollerConfig) -> Self {
        Self::spawn_wired(config, CloudPollerWiring::default(), NoSink)
    }

    /// Spawn with the participant's wiring: an event/peer sink and an
    /// optional self-registration.
    pub(crate) fn spawn_wired<S: CloudPeerSink>(
        config: CloudPollerConfig,
        wiring: CloudPollerWiring,
        sink: S,
    ) -> Self {
        let factory_config = config.clone();
        Self::spawn_with_backend(config, wiring, sink, move || build_backend(&factory_config))
    }

    /// Spawn over any backend; the factory runs on the poller thread.
    pub(crate) fn spawn_with_backend<D, F, S>(
        config: CloudPollerConfig,
        wiring: CloudPollerWiring,
        sink: S,
        make_backend: F,
    ) -> Self
    where
        D: CloudDiscovery + 'static,
        F: FnOnce() -> Result<D, String> + Send + 'static,
        S: CloudPeerSink,
    {
        let (cmd_tx, cmd_rx) = channel();
        let (event_tx, event_rx) = sync_channel(EVENT_CHANNEL_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));
        let status = Arc::new(Mutex::new(CloudDiscoveryStatus::default()));

        let thread_running = Arc::clone(&running);
        let thread_status = Arc::clone(&status);
        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let thread_handle = thread::Builder::new()
            .name("hdds-cloud-discovery".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                let emitter = Emitter {
                    event_tx,
                    sink,
                    status: thread_status,
                };
                run_thread(
                    config,
                    wiring,
                    cmd_rx,
                    emitter,
                    thread_running,
                    make_backend,
                );
            }))
            .expect("Failed to spawn cloud discovery poller thread");

        let handle = CloudDiscoveryPollerHandle {
            cmd_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            running,
            status,
        };

        Self {
            handle,
            thread_handle: Some(thread_handle),
        }
    }

    /// Get a handle to interact with the poller.
    pub fn handle(&self) -> CloudDiscoveryPollerHandle {
        self.handle.clone()
    }

    /// Stop the poller: the loop deregisters the participant if it had
    /// registered it, then exits. Waits at most `STOP_JOIN_TIMEOUT` for the
    /// thread; a thread still inside a backend call (bounded by
    /// `REQUEST_TIMEOUT`) is detached so a black-holed registry cannot hold
    /// `Participant::drop` for seconds.
    pub fn stop(&mut self) {
        self.handle.shutdown();
        let Some(handle) = self.thread_handle.take() else {
            return;
        };

        let deadline = Instant::now() + STOP_JOIN_TIMEOUT;
        while !handle.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }

        if handle.is_finished() {
            let _ = handle.join();
        } else {
            log::warn!(
                "[CLOUD-DISCOVERY] Poller thread did not stop within {:?}; detaching pending request",
                STOP_JOIN_TIMEOUT
            );
        }
    }
}

impl Drop for CloudDiscoveryPoller {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================================
// Thread body
// ============================================================================

/// Fan-out of one event: status, the crate sink, then the public copy.
struct Emitter<S: CloudPeerSink> {
    event_tx: SyncSender<CloudEvent>,
    sink: S,
    status: Arc<Mutex<CloudDiscoveryStatus>>,
}

impl<S: CloudPeerSink> Emitter<S> {
    fn emit(&mut self, event: CloudEvent) {
        self.sink.on_event(&event);
        if self.event_tx.try_send(event).is_err() {
            self.update(|status| status.dropped_events = status.dropped_events.saturating_add(1));
        }
    }

    fn error(&mut self, message: String) {
        self.update(|status| status.last_error = Some(message.clone()));
        self.emit(CloudEvent::Error { message });
    }

    fn update(&self, apply: impl FnOnce(&mut CloudDiscoveryStatus)) {
        let mut status = self
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        apply(&mut status);
    }
}

fn run_thread<D, F, S>(
    config: CloudPollerConfig,
    wiring: CloudPollerWiring,
    cmd_rx: Receiver<CloudCommand>,
    mut emitter: Emitter<S>,
    running: Arc<AtomicBool>,
    make_backend: F,
) where
    D: CloudDiscovery + 'static,
    F: FnOnce() -> Result<D, String>,
    S: CloudPeerSink,
{
    // Create a single-threaded tokio runtime for this thread
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            emitter.error(format!("Failed to create tokio runtime: {}", e));
            running.store(false, Ordering::Relaxed);
            return;
        }
    };

    let backend = match make_backend() {
        Ok(backend) => backend,
        Err(message) => {
            log::error!(
                "[CLOUD-DISCOVERY] Backend could not be constructed, poller stopping: {}",
                message
            );
            emitter.error(message);
            running.store(false, Ordering::Relaxed);
            emitter.emit(CloudEvent::Stopped);
            return;
        }
    };

    // A panic on this thread would leave `running` and `status.running` at
    // `true` for the life of the process, with no event and no error: the
    // poller dead and the status saying it is alive. Catch it, report it,
    // then stop the way a clean exit does.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(async {
            polling_loop(backend, config, wiring, cmd_rx, &mut emitter, &running).await;
        });
    }));
    if let Err(panic) = outcome {
        let detail = panic
            .downcast_ref::<&str>()
            .map(|text| (*text).to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown cause".to_string());
        let message = format!("Poller thread panicked: {}", detail);
        log::error!("[CLOUD-DISCOVERY] {}", message);
        emitter.error(message);
    }
    running.store(false, Ordering::Relaxed);
    emitter.update(|status| status.running = false);
    emitter.emit(CloudEvent::Stopped);
    log::info!("[CLOUD-DISCOVERY] Poller stopped");
}

/// A registration waiting for its next attempt.
struct PendingRegistration {
    info: ParticipantInfo,
    attempts: u32,
    next_attempt: Instant,
}

async fn bounded<T>(
    call: impl std::future::Future<Output = Result<T, Error>>,
    what: &str,
) -> Result<T, String> {
    bounded_by(REQUEST_TIMEOUT, call, what).await
}

async fn bounded_by<T>(
    budget: Duration,
    call: impl std::future::Future<Output = Result<T, Error>>,
    what: &str,
) -> Result<T, String> {
    match tokio::time::timeout(budget, call).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("{} failed: {}", what, e)),
        Err(_) => Err(format!("{} timed out after {:?}", what, budget)),
    }
}

/// The heartbeat, bounded like every other backend call but keeping the
/// failure KIND: a timeout is transient, never "the registry forgot me".
async fn bounded_heartbeat(
    call: impl std::future::Future<Output = Result<(), HeartbeatError>>,
) -> Result<(), HeartbeatError> {
    match tokio::time::timeout(REQUEST_TIMEOUT, call).await {
        Ok(result) => result,
        Err(_) => Err(HeartbeatError::Transient(Error::Config(format!(
            "Liveness heartbeat timed out after {:?}",
            REQUEST_TIMEOUT
        )))),
    }
}

fn register_backoff(attempts: u32) -> Duration {
    let factor = 1u32 << attempts.saturating_sub(1).min(5);
    (REGISTER_BACKOFF_MIN * factor).min(REGISTER_BACKOFF_MAX)
}

async fn polling_loop<D: CloudDiscovery, S: CloudPeerSink>(
    backend: D,
    config: CloudPollerConfig,
    wiring: CloudPollerWiring,
    cmd_rx: Receiver<CloudCommand>,
    emitter: &mut Emitter<S>,
    running: &AtomicBool,
) {
    emitter.update(|status| status.running = true);
    emitter.emit(CloudEvent::Ready);
    log::info!("[CLOUD-DISCOVERY] Poller ready");

    // One-shot warm-up, before the first bounded call and with its own
    // (larger) budget: see `CloudDiscovery::prepare`. A failure is
    // reported and nothing else - the registration path resolves lazily,
    // and its retry backoff is the right place for a registry that is
    // still coming up.
    if let Err(message) = bounded_by(PREPARE_TIMEOUT, backend.prepare(), "Warm-up").await {
        log::warn!("[CLOUD-DISCOVERY] {}", message);
        emitter.error(message);
    }

    let own_prefix = wiring.own_guid.map(|guid| {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&guid[..12]);
        prefix
    });
    let mut pending_registration = wiring.registration.map(|info| PendingRegistration {
        info,
        attempts: 0,
        next_attempt: Instant::now(),
    });
    let mut registered: Option<[u8; 16]> = None;
    // The record that was registered, kept so the loop can register it
    // again by itself when the registry forgets it (agent restart), and
    // so a lease-expiring registry can write it again unchanged.
    let mut registered_info: Option<ParticipantInfo> = None;
    let mut next_heartbeat = Instant::now() + config.poll_interval;
    // Lease-refresh arm: when the record was last written successfully.
    // The registry drops it one lease after that.
    let mut last_refresh = Instant::now();
    // TTL-heartbeat arm: consecutive heartbeat calls that failed WITHOUT
    // the registry saying the record is gone.
    let mut heartbeat_failures = 0u32;
    let mut known_participants: HashMap<[u8; 16], ParticipantInfo> = HashMap::new();
    // First poll immediately: a participant that just joined must not wait
    // a whole interval before it learns its peers.
    let mut next_poll = Instant::now();
    let mut consecutive_failures = 0u32;

    while running.load(Ordering::Relaxed) {
        // Drain every pending command; a Deregister queued before Shutdown
        // is honoured in the same tick.
        let mut force_poll = false;
        let mut shutdown = false;
        loop {
            match cmd_rx.try_recv() {
                Ok(CloudCommand::Register { info }) => {
                    pending_registration = Some(PendingRegistration {
                        info,
                        attempts: 0,
                        next_attempt: Instant::now(),
                    });
                }
                Ok(CloudCommand::Deregister { guid }) => {
                    pending_registration = None;
                    deregister(&backend, guid, emitter).await;
                    if registered == Some(guid) {
                        registered = None;
                        registered_info = None;
                    }
                    // Forget the record itself too, whatever the live
                    // slot held: it is what the shutdown path falls back
                    // on, and an explicit Deregister must not leave it
                    // behind to be deregistered a second time.
                    if registered_info
                        .as_ref()
                        .is_some_and(|info| info.guid == guid)
                    {
                        registered_info = None;
                    }
                }
                Ok(CloudCommand::PollNow) => force_poll = true,
                Ok(CloudCommand::Shutdown) => {
                    log::info!("[CLOUD-DISCOVERY] Shutdown requested");
                    shutdown = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    log::warn!("[CLOUD-DISCOVERY] Command channel disconnected");
                    shutdown = true;
                    break;
                }
            }
        }
        if shutdown {
            break;
        }

        // Registration, retried with backoff until it sticks.
        if let Some(pending) = pending_registration.as_mut() {
            if Instant::now() >= pending.next_attempt {
                pending.attempts = pending.attempts.saturating_add(1);
                let attempts = pending.attempts;
                emitter.update(|status| status.register_attempts = attempts);
                log::debug!(
                    "[CLOUD-DISCOVERY] Registering participant (attempt {})",
                    attempts
                );
                match bounded(backend.register_participant(&pending.info), "Registration").await {
                    Ok(()) => {
                        let guid = pending.info.guid;
                        let info = pending.info.clone();
                        registered = Some(guid);
                        registered_info = Some(info);
                        next_heartbeat = Instant::now()
                            + config.heartbeat_interval.unwrap_or(config.poll_interval);
                        last_refresh = Instant::now();
                        heartbeat_failures = 0;
                        pending_registration = None;
                        emitter.update(|status| status.registered = true);
                        emitter.emit(CloudEvent::Registered { guid });
                        log::info!("[CLOUD-DISCOVERY] Registered participant");
                    }
                    Err(message) => {
                        let delay = register_backoff(attempts);
                        pending.next_attempt = Instant::now() + delay;
                        log::warn!(
                            "[CLOUD-DISCOVERY] {} (attempt {}); retrying in {:?}",
                            message,
                            attempts,
                            delay
                        );
                        emitter.error(message);
                    }
                }
            }
        }

        // Liveness, and there are TWO mechanisms because there are two
        // kinds of registry. `config.heartbeat_interval` discriminates:
        //
        //   Some(interval)  the ROW itself expires (Azure Table Storage).
        //                   The record is written again every interval;
        //                   registration is idempotent, which is why it
        //                   IS the refresh.
        //   None            the registry offers a dedicated liveness call
        //                   (Consul's TTL check), driven once per poll
        //                   interval.
        //
        // AWS Cloud Map takes the second arm, and with it the trait's
        // default `heartbeat`: a no-op that always succeeds, which is
        // correct because a Cloud Map instance does not expire on its own.
        //
        // The arms are exclusive, and both are needed: dropping either one
        // would be a SILENT regression.
        //   * lease arm removed (Consul's loop alone) reddens
        //     `the_registration_is_refreshed_once_per_heartbeat_interval`:
        //     Azure rows stop being rewritten and would expire.
        //   * TTL arm made unreachable (Azure's loop alone) reddens
        //     `a_transient_heartbeat_failure_keeps_the_registration_and_
        //     does_not_re_register`: Consul's liveness call disappears.
        // So both directions have a guard.
        //
        // Note the coupling, because it is not obvious: both arms share
        // `next_heartbeat`. Whichever fires first pushes the deadline out,
        // so writing this as two independent `if`s instead of `if/else if`
        // changes NO behaviour. The
        // `else if` is kept because it says what is meant, not because the
        // alternative is a bug.
        if let Some(interval) = config.heartbeat_interval {
            if let Some(info) = registered_info.clone() {
                if Instant::now() >= next_heartbeat {
                    next_heartbeat = Instant::now() + interval;
                    match bounded(backend.register_participant(&info), "Lease refresh").await {
                        Ok(()) => last_refresh = Instant::now(),
                        Err(message) => {
                            log::warn!("[CLOUD-DISCOVERY] {}", message);
                            emitter.error(message);
                            // One failed refresh is only reported: the
                            // record is still there until its lease runs
                            // out. Refreshes failing for a WHOLE lease are
                            // different -- the registry has dropped the row
                            // by then, so the status must stop claiming a
                            // registration that no longer exists.
                            if Instant::now().duration_since(last_refresh)
                                >= interval * LEASE_HEARTBEATS
                            {
                                log::warn!(
                                    "[CLOUD-DISCOVERY] The record has not been refreshed for a \
                                     whole lease; it is no longer registered"
                                );
                                registered_info = None;
                                emitter.update(|status| status.registered = false);
                                // `registered` keeps the GUID so shutdown
                                // still attempts the delete; only the claim
                                // that the record is live is dropped.
                                pending_registration = Some(PendingRegistration {
                                    info,
                                    attempts: 0,
                                    next_attempt: Instant::now(),
                                });
                            }
                        }
                    }
                }
            }
        } else if let Some(guid) = registered {
            if Instant::now() >= next_heartbeat {
                next_heartbeat = Instant::now() + config.poll_interval;
                match bounded_heartbeat(backend.heartbeat(guid)).await {
                    Ok(()) => heartbeat_failures = 0,
                    Err(failure) => {
                        let gone = failure.is_record_gone();
                        let message = format!("Liveness heartbeat failed: {}", failure);
                        heartbeat_failures = heartbeat_failures.saturating_add(1);
                        if gone || heartbeat_failures >= HEARTBEAT_FAILURE_THRESHOLD {
                            // Either the registry says the record is gone,
                            // or the refresh has failed long enough that the
                            // record cannot have survived its own TTL.
                            // Register it again -- a straight retry when the
                            // record is gone, backed off when it is the call
                            // that keeps failing.
                            log::warn!("[CLOUD-DISCOVERY] {}; re-registering", message);
                            registered = None;
                            emitter.update(|status| status.registered = false);
                            if let Some(info) = registered_info.clone() {
                                let attempts = if gone { 0 } else { heartbeat_failures };
                                let delay = if gone {
                                    Duration::ZERO
                                } else {
                                    register_backoff(attempts)
                                };
                                pending_registration = Some(PendingRegistration {
                                    info,
                                    attempts,
                                    next_attempt: Instant::now() + delay,
                                });
                            }
                            heartbeat_failures = 0;
                            emitter.error(message);
                        } else {
                            // A hiccup says nothing about the record: keep
                            // the registration (and the public status flag
                            // that goes with it), report, retry next tick.
                            log::warn!("[CLOUD-DISCOVERY] {}", message);
                            emitter.update(|status| status.last_error = Some(message));
                        }
                    }
                }
            }
        }

        // Periodic discovery poll
        if force_poll || Instant::now() >= next_poll {
            // A long-polling backend does the waiting INSIDE the call
            // (`CloudDiscovery::blocking_discovery_budget`), so it needs
            // its own budget: `REQUEST_TIMEOUT` is five seconds and would
            // cut off every wait longer than that.
            let discovery_budget = backend.blocking_discovery_budget();
            // The plain interval is armed FIRST and only a successful
            // long poll shortens it below. A blocking query against a
            // registry that is refusing or unreachable comes back at
            // once, so re-issuing it immediately on failure would turn
            // one down agent into a tight retry loop at TICK rate --
            // strictly worse than the polling this replaces.
            next_poll = Instant::now() + config.poll_interval;

            match bounded_by(
                discovery_budget.unwrap_or(REQUEST_TIMEOUT),
                backend.discover_participants(),
                "Discovery poll",
            )
            .await
            {
                Ok(participants) => {
                    if discovery_budget.is_some() {
                        // The wait already happened inside the call:
                        // sleeping a whole interval on top of it would
                        // ADD latency to the mechanism meant to remove
                        // it. Next poll is due now (the loop's own TICK
                        // still separates them, which is what keeps
                        // commands and heartbeats responsive).
                        next_poll = Instant::now();
                    }
                    consecutive_failures = 0;
                    let filtered: Vec<ParticipantInfo> = participants
                        .into_iter()
                        .filter(|p| p.domain_id == config.domain_id)
                        .filter(|p| own_prefix != Some(prefix_of(&p.guid)))
                        .collect();
                    emitter.update(|status| {
                        status.successful_polls = status.successful_polls.saturating_add(1);
                        status.consecutive_poll_failures = 0;
                        status.registry_peers = filtered.len();
                        status.last_health_check = None;
                    });

                    // The sink gets the whole view (lease refresh + removals
                    // in one atomic peer-set update) before the diff events.
                    emitter.sink.on_poll(&filtered);

                    for info in &filtered {
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            known_participants.entry(info.guid)
                        {
                            entry.insert(info.clone());
                            emitter.emit(CloudEvent::ParticipantDiscovered { info: info.clone() });
                            log::debug!("[CLOUD-DISCOVERY] Discovered participant: {}", info.name);
                        }
                    }

                    let current: std::collections::HashSet<_> =
                        filtered.iter().map(|p| p.guid).collect();
                    let lost: Vec<_> = known_participants
                        .keys()
                        .filter(|g| !current.contains(*g))
                        .copied()
                        .collect();
                    for guid in lost {
                        known_participants.remove(&guid);
                        emitter.emit(CloudEvent::ParticipantLost { guid });
                        log::debug!("[CLOUD-DISCOVERY] Lost participant: {:02x?}", guid);
                    }
                }
                Err(message) => {
                    // A failed poll says nothing about who is gone: known
                    // peers and the sink's view are left as they are (their
                    // lease bounds the damage). It becomes loud once it
                    // persists.
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    emitter.update(|status| {
                        status.consecutive_poll_failures = consecutive_failures;
                        status.last_error = Some(message.clone());
                    });
                    if consecutive_failures == LOUD_POLL_FAILURE_THRESHOLD {
                        // A run of failures is where a health check earns
                        // its keep: it separates "the backend itself is
                        // unusable" (credentials, clock, endpoint) from
                        // "the backend answers and this query finds
                        // nobody". The verdict lands in the status so an
                        // operator reads it without a debug log.
                        let healthy = bounded(backend.health_check(), "Health check")
                            .await
                            .unwrap_or(false);
                        emitter.update(|status| status.last_health_check = Some(healthy));
                        log::error!(
                            "[CLOUD-DISCOVERY] {} consecutive discovery polls failed \
                             (backend health check: {}); last: {}",
                            consecutive_failures,
                            if healthy { "healthy" } else { "UNHEALTHY" },
                            message
                        );
                        emitter.emit(CloudEvent::Error {
                            message: format!(
                                "{} consecutive discovery polls failed (backend health check: \
                                 {}); last: {}",
                                consecutive_failures,
                                if healthy { "healthy" } else { "unhealthy" },
                                message
                            ),
                        });
                    } else {
                        log::warn!("[CLOUD-DISCOVERY] {}", message);
                    }
                }
            }
        }

        tokio::time::sleep(TICK).await;
    }

    // Deregister what this loop registered, even if the last heartbeat
    // cleared `registered`: a record the registry still holds and nobody
    // refreshes any more keeps every peer unicasting SPDP into a dead
    // address for the whole TTL plus Consul's deregister-after grace.
    // `registered_info` is cleared by an explicit Deregister command, so
    // this cannot deregister twice.
    if let Some(guid) = registered
        .take()
        .or_else(|| registered_info.as_ref().map(|info| info.guid))
    {
        deregister(&backend, guid, emitter).await;
    }
}

async fn deregister<D: CloudDiscovery, S: CloudPeerSink>(
    backend: &D,
    guid: [u8; 16],
    emitter: &mut Emitter<S>,
) {
    log::debug!("[CLOUD-DISCOVERY] Deregistering participant");
    // Whatever the outcome, this poller stops maintaining the record from
    // here on (it will not heartbeat it again), so the public flag must
    // not keep reporting `registered = true`. A partial failure -- the
    // Consul backend deregisters the service and then fails to delete its
    // KV mirror -- must not leave the flag true for a participant that is
    // out of the catalog.
    emitter.update(|status| status.registered = false);
    match bounded(backend.deregister_participant(guid), "Deregistration").await {
        Ok(()) => {
            emitter.emit(CloudEvent::Deregistered { guid });
            log::info!("[CLOUD-DISCOVERY] Deregistered participant");
        }
        Err(message) => {
            log::warn!("[CLOUD-DISCOVERY] {}", message);
            emitter.error(message);
        }
    }
}

fn prefix_of(guid: &[u8; 16]) -> [u8; 12] {
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&guid[..12]);
    prefix
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::cloud::Locator;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn test_config_default() {
        let config = CloudPollerConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert_eq!(config.domain_id, 0);
    }

    #[test]
    fn test_event_clone() {
        let event = CloudEvent::Ready;
        let cloned = event.clone();
        assert!(matches!(cloned, CloudEvent::Ready));
    }

    #[test]
    fn provider_debug_redacts_azure_config_json() {
        // @audit-ok: synthetic fixture, not a real credential. This test exists
        // precisely to assert that the value is redacted from Debug output.
        let secret = "sv=2024&sig=SECRET-SAS-TOKEN";
        let provider = CloudProvider::Azure {
            config_json: format!(r#"{{"account":"acct","sas":"{}"}}"#, secret),
        };
        let rendered = format!("{:?}", provider);
        assert!(!rendered.contains(secret), "leaked: {}", rendered);
        assert!(!rendered.contains("acct"), "leaked: {}", rendered);
        assert!(rendered.contains("<redacted>"));

        let config = CloudPollerConfig {
            provider,
            ..CloudPollerConfig::default()
        };
        assert!(!format!("{:?}", config).contains(secret));
    }

    #[test]
    fn register_backoff_grows_and_is_capped() {
        assert_eq!(register_backoff(1), Duration::from_secs(1));
        assert_eq!(register_backoff(2), Duration::from_secs(2));
        assert_eq!(register_backoff(3), Duration::from_secs(4));
        assert_eq!(register_backoff(6), Duration::from_secs(30));
        assert_eq!(register_backoff(60), Duration::from_secs(30));
    }

    // ------------------------------------------------------------------
    // Deterministic in-memory backend
    // ------------------------------------------------------------------

    #[derive(Clone, Default)]
    struct FakeBackend {
        peers: Arc<Mutex<Vec<ParticipantInfo>>>,
        fail_discover: Arc<AtomicBool>,
        hang_discover: Arc<AtomicBool>,
        panic_discover: Arc<AtomicBool>,
        register_failures_left: Arc<AtomicU32>,
        registered: Arc<Mutex<Vec<[u8; 16]>>>,
        deregistered: Arc<Mutex<Vec<[u8; 16]>>>,
        /// Warm-ups performed, and whether the warm-up fails.
        prepare_calls: Arc<AtomicU32>,
        fail_prepare: Arc<AtomicBool>,
        /// Value of `prepare_calls` observed by each registration: this is
        /// what pins the ORDER of the two.
        prepare_calls_at_register: Arc<Mutex<Vec<u32>>>,
        /// Health-check verdict, and how many were asked for.
        healthy: Arc<AtomicBool>,
        health_checks: Arc<AtomicU32>,
        /// Heartbeats served, successful or not.
        heartbeats: Arc<AtomicU32>,
        /// Heartbeats still to fail (`u32::MAX` = for ever).
        heartbeat_failures_left: Arc<AtomicU32>,
        /// Report those failures as "the registry lost the record".
        heartbeat_failure_is_gone: Arc<AtomicBool>,
        /// Deregistration removes the record but reports a failure (the
        /// Consul shape: the service is gone, the KV cleanup was refused).
        fail_deregister: Arc<AtomicBool>,
    }

    impl CloudDiscovery for FakeBackend {
        async fn prepare(&self) -> Result<(), Error> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_prepare.load(Ordering::SeqCst) {
                return Err(Error::Config("warm-up unreachable".into()));
            }
            Ok(())
        }

        async fn health_check(&self) -> Result<bool, Error> {
            self.health_checks.fetch_add(1, Ordering::SeqCst);
            Ok(self.healthy.load(Ordering::SeqCst))
        }

        async fn register_participant(&self, info: &ParticipantInfo) -> Result<(), Error> {
            self.prepare_calls_at_register
                .lock()
                .unwrap()
                .push(self.prepare_calls.load(Ordering::SeqCst));
            let left = self.register_failures_left.load(Ordering::SeqCst);
            if left > 0 {
                self.register_failures_left
                    .store(left - 1, Ordering::SeqCst);
                return Err(Error::Config("registry says 503".into()));
            }
            self.registered.lock().unwrap().push(info.guid);
            Ok(())
        }

        async fn discover_participants(&self) -> Result<Vec<ParticipantInfo>, Error> {
            assert!(
                !self.panic_discover.load(Ordering::SeqCst),
                "scripted backend panic"
            );
            if self.hang_discover.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if self.fail_discover.load(Ordering::SeqCst) {
                return Err(Error::Config("registry unreachable".into()));
            }
            Ok(self.peers.lock().unwrap().clone())
        }

        async fn deregister_participant(&self, guid: [u8; 16]) -> Result<(), Error> {
            self.deregistered.lock().unwrap().push(guid);
            if self.fail_deregister.load(Ordering::SeqCst) {
                return Err(Error::Config("KV cleanup failed: HTTP 403".into()));
            }
            Ok(())
        }

        async fn heartbeat(&self, _guid: [u8; 16]) -> Result<(), HeartbeatError> {
            self.heartbeats.fetch_add(1, Ordering::SeqCst);
            let left = self.heartbeat_failures_left.load(Ordering::SeqCst);
            if left == 0 {
                return Ok(());
            }
            if left != u32::MAX {
                self.heartbeat_failures_left
                    .store(left - 1, Ordering::SeqCst);
            }
            let error = Error::Config("check refresh refused".into());
            Err(if self.heartbeat_failure_is_gone.load(Ordering::SeqCst) {
                HeartbeatError::RecordGone(error)
            } else {
                HeartbeatError::Transient(error)
            })
        }
    }

    #[derive(Default)]
    struct RecordingSinkState {
        events: Vec<CloudEvent>,
        polls: Vec<Vec<[u8; 16]>>,
    }

    #[derive(Clone, Default)]
    struct RecordingSink(Arc<Mutex<RecordingSinkState>>);

    impl CloudPeerSink for RecordingSink {
        fn on_event(&mut self, event: &CloudEvent) {
            self.0.lock().unwrap().events.push(event.clone());
        }
        fn on_poll(&mut self, peers: &[ParticipantInfo]) {
            self.0
                .lock()
                .unwrap()
                .polls
                .push(peers.iter().map(|p| p.guid).collect());
        }
    }

    fn info(guid: u8, domain_id: u32) -> ParticipantInfo {
        ParticipantInfo {
            guid: [guid; 16],
            name: format!("peer-{}", guid),
            domain_id,
            locators: vec![Locator {
                kind: 1,
                port: 7410,
                address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, guid],
            }],
            metadata: HashMap::new(),
        }
    }

    fn fast_config(domain_id: u32) -> CloudPollerConfig {
        CloudPollerConfig {
            provider: CloudProvider::Consul {
                addr: "http://127.0.0.1:1".into(),
                options: ConsulOptions::default(),
            },
            poll_interval: Duration::from_millis(50),
            domain_id,
            heartbeat_interval: None,
        }
    }

    fn spawn_fake(
        backend: FakeBackend,
        wiring: CloudPollerWiring,
        sink: RecordingSink,
        domain_id: u32,
    ) -> CloudDiscoveryPoller {
        CloudDiscoveryPoller::spawn_with_backend(fast_config(domain_id), wiring, sink, move || {
            Ok(backend)
        })
    }

    fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        condition()
    }

    /// CLOUD-4: the crate sink and the public handle each see the same
    /// discovery event; neither consumer starves the other.
    #[test]
    fn sink_and_public_handle_both_see_discovered_event() {
        let backend = FakeBackend::default();
        backend.peers.lock().unwrap().push(info(7, 39));
        backend.peers.lock().unwrap().push(info(8, 40)); // foreign domain
        let sink = RecordingSink::default();
        let poller = spawn_fake(backend, CloudPollerWiring::default(), sink.clone(), 39);
        let handle = poller.handle();

        let mut handle_events = Vec::new();
        assert!(wait_until(Duration::from_secs(5), || {
            handle_events.extend(handle.poll());
            handle_events.iter().any(
                |e| matches!(e, CloudEvent::ParticipantDiscovered { info } if info.guid == [7; 16]),
            )
        }));
        assert!(
            !handle_events.iter().any(
                |e| matches!(e, CloudEvent::ParticipantDiscovered { info } if info.guid == [8; 16])
            ),
            "foreign-domain peer leaked to the handle"
        );

        let state = sink.0.lock().unwrap();
        assert!(state.events.iter().any(
            |e| matches!(e, CloudEvent::ParticipantDiscovered { info } if info.guid == [7; 16])
        ));
        assert!(state.events.iter().any(|e| matches!(e, CloudEvent::Ready)));
        assert!(state.polls.iter().any(|poll| poll == &vec![[7u8; 16]]));
        drop(state);

        let status = handle.status();
        assert!(status.running);
        assert_eq!(status.registry_peers, 1);
        assert!(status.successful_polls >= 1);
        assert_eq!(status.dropped_events, 0);
    }

    #[test]
    fn own_guid_is_never_reported_as_a_peer() {
        let backend = FakeBackend::default();
        let own = info(3, 39);
        backend.peers.lock().unwrap().push(own.clone());
        backend.peers.lock().unwrap().push(info(4, 39));
        let sink = RecordingSink::default();
        let wiring = CloudPollerWiring {
            own_guid: Some(own.guid),
            registration: None,
        };
        let poller = spawn_fake(backend, wiring, sink.clone(), 39);
        let handle = poller.handle();

        assert!(wait_until(Duration::from_secs(5), || {
            handle.status().successful_polls >= 2
        }));
        let state = sink.0.lock().unwrap();
        for poll in &state.polls {
            assert_eq!(poll, &vec![[4u8; 16]], "own guid leaked into a poll view");
        }
        assert!(!state.events.iter().any(
            |e| matches!(e, CloudEvent::ParticipantDiscovered { info } if info.guid == [3; 16])
        ));
    }

    /// The warm-up runs ONCE, before the first registration. Without that
    /// order the first bounded registration carries a whole credential
    /// chain plus a service lookup inside a budget sized for one call.
    #[test]
    fn the_backend_is_warmed_up_once_before_the_first_registration() {
        let backend = FakeBackend::default();
        let own = info(0x21, 39);
        let poller = spawn_fake(
            backend.clone(),
            CloudPollerWiring {
                own_guid: Some(own.guid),
                registration: Some(own.clone()),
            },
            RecordingSink::default(),
            39,
        );
        let handle = poller.handle();
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .successful_polls
            >= 3));

        assert_eq!(
            backend.prepare_calls.load(Ordering::SeqCst),
            1,
            "the warm-up must run exactly once, not once per poll"
        );
        let observed = backend.prepare_calls_at_register.lock().unwrap().clone();
        assert!(!observed.is_empty(), "nothing registered");
        assert!(
            observed.iter().all(|calls| *calls == 1),
            "a registration ran before the warm-up: {:?}",
            observed
        );
    }

    /// A warm-up that fails is reported and nothing more: registration
    /// still happens, resolving lazily, and its own backoff owns the
    /// retry.
    #[test]
    fn a_failed_warm_up_is_reported_but_does_not_stop_the_registration() {
        let backend = FakeBackend::default();
        backend.fail_prepare.store(true, Ordering::SeqCst);
        let own = info(0x22, 39);
        let sink = RecordingSink::default();
        let poller = spawn_fake(
            backend.clone(),
            CloudPollerWiring {
                own_guid: Some(own.guid),
                registration: Some(own.clone()),
            },
            sink.clone(),
            39,
        );
        let handle = poller.handle();
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));
        assert!(
            sink.0.lock().unwrap().events.iter().any(|event| {
                matches!(event, CloudEvent::Error { message } if message.contains("Warm-up"))
            }),
            "the warm-up failure was not reported: {:?}",
            sink.0.lock().unwrap().events
        );
        assert_eq!(backend.registered.lock().unwrap().len(), 1);
    }

    /// A run of failed polls asks the backend whether it is usable at all
    /// and records the verdict, so "the registry refuses us" is
    /// distinguishable from "this query finds nobody".
    #[test]
    fn a_run_of_failed_polls_records_the_backend_health_verdict() {
        let backend = FakeBackend::default();
        backend.fail_discover.store(true, Ordering::SeqCst);
        backend.healthy.store(false, Ordering::SeqCst);
        let poller = spawn_fake(
            backend.clone(),
            CloudPollerWiring::default(),
            RecordingSink::default(),
            39,
        );
        let handle = poller.handle();
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .last_health_check
            .is_some()));
        assert_eq!(handle.status().last_health_check, Some(false));
        assert!(backend.health_checks.load(Ordering::SeqCst) >= 1);

        // Once a poll succeeds again the stale verdict is dropped rather
        // than left to be read as current.
        backend.fail_discover.store(false, Ordering::SeqCst);
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .last_health_check
            .is_none()));
    }

    #[test]
    fn poll_failure_keeps_view_and_goes_loud_after_threshold() {
        let backend = FakeBackend::default();
        backend.peers.lock().unwrap().push(info(5, 39));
        let sink = RecordingSink::default();
        let poller = spawn_fake(
            backend.clone(),
            CloudPollerWiring::default(),
            sink.clone(),
            39,
        );
        let handle = poller.handle();

        assert!(wait_until(Duration::from_secs(5), || {
            handle.status().successful_polls >= 1
        }));
        let polls_before = sink.0.lock().unwrap().polls.len();
        backend.fail_discover.store(true, Ordering::SeqCst);

        assert!(wait_until(Duration::from_secs(5), || {
            handle.status().consecutive_poll_failures >= LOUD_POLL_FAILURE_THRESHOLD + 2
        }));
        let status = handle.status();
        assert_eq!(
            status.registry_peers, 1,
            "a failed poll must not empty the view"
        );
        assert!(status
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("registry unreachable"));

        let state = sink.0.lock().unwrap();
        // on_poll is never called for a failed poll (at most one more
        // successful poll could have slipped in before the flag flipped).
        assert!(state.polls.len() <= polls_before + 1);
        let loud: Vec<_> = state
            .events
            .iter()
            .filter(
                |e| matches!(e, CloudEvent::Error { message } if message.contains("consecutive")),
            )
            .collect();
        assert_eq!(
            loud.len(),
            1,
            "exactly one loud error at the threshold: {:?}",
            loud
        );
        assert!(!state
            .events
            .iter()
            .any(|e| matches!(e, CloudEvent::ParticipantLost { .. })));
        drop(state);

        // Recovery resets the failure counter.
        backend.fail_discover.store(false, Ordering::SeqCst);
        assert!(wait_until(Duration::from_secs(5), || {
            handle.status().consecutive_poll_failures == 0
        }));
    }

    #[test]
    fn registration_retries_with_backoff_until_success_and_stop_deregisters() {
        let backend = FakeBackend::default();
        backend.register_failures_left.store(1, Ordering::SeqCst);
        let sink = RecordingSink::default();
        let own = info(9, 39);
        let wiring = CloudPollerWiring {
            own_guid: Some(own.guid),
            registration: Some(own.clone()),
        };
        let mut poller = spawn_fake(backend.clone(), wiring, sink.clone(), 39);
        let handle = poller.handle();

        // First attempt fails, second (after the 1 s backoff) succeeds.
        assert!(wait_until(Duration::from_secs(1), || {
            handle.status().register_attempts == 1
        }));
        assert!(!handle.status().registered);
        assert!(handle.status().last_error.is_some());
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));
        assert_eq!(handle.status().register_attempts, 2);
        assert_eq!(backend.registered.lock().unwrap().as_slice(), &[own.guid]);
        assert!(sink
            .0
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, CloudEvent::Registered { guid } if *guid == own.guid)));

        let started = Instant::now();
        poller.stop();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(backend.deregistered.lock().unwrap().as_slice(), &[own.guid]);
        assert!(!handle.status().registered);
        assert!(!handle.status().running);
        assert!(sink
            .0
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, CloudEvent::Stopped)));
    }

    /// A hiccup on the refresh call (timeout, 5xx, reset) says NOTHING
    /// about the record: the poller must keep its registration instead of
    /// re-PUTting the whole service (and flapping the public status flag)
    /// once per poll interval against a briefly overloaded registry.
    #[test]
    fn a_transient_heartbeat_failure_keeps_the_registration_and_does_not_re_register() {
        let backend = FakeBackend::default();
        backend.heartbeat_failures_left.store(1, Ordering::SeqCst);
        let own = info(9, 39);
        let wiring = CloudPollerWiring {
            own_guid: Some(own.guid),
            registration: Some(own.clone()),
        };
        let mut poller = spawn_fake(backend.clone(), wiring, RecordingSink::default(), 39);
        let handle = poller.handle();

        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));
        // Let the failing refresh AND two good ones go by.
        assert!(wait_until(Duration::from_secs(5), || backend
            .heartbeats
            .load(Ordering::SeqCst)
            >= 3));

        assert!(
            handle.status().registered,
            "one refused refresh cleared the registration"
        );
        assert_eq!(
            backend.registered.lock().unwrap().len(),
            1,
            "the participant re-registered after a transient heartbeat failure"
        );
        poller.stop();
    }

    /// The registry saying the record is gone (Consul's 404 on an unknown
    /// check after an agent restart) IS the re-registration signal, and it
    /// is taken immediately -- no backoff, no threshold.
    #[test]
    fn a_heartbeat_that_says_the_record_is_gone_re_registers_at_once() {
        let backend = FakeBackend::default();
        backend
            .heartbeat_failure_is_gone
            .store(true, Ordering::SeqCst);
        backend.heartbeat_failures_left.store(1, Ordering::SeqCst);
        let own = info(9, 39);
        let wiring = CloudPollerWiring {
            own_guid: Some(own.guid),
            registration: Some(own.clone()),
        };
        let mut poller = spawn_fake(backend.clone(), wiring, RecordingSink::default(), 39);
        let handle = poller.handle();

        assert!(wait_until(Duration::from_secs(5), || backend
            .registered
            .lock()
            .unwrap()
            .len()
            == 2));
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));
        poller.stop();
    }

    /// A transient heartbeat failure must not cost the deregistration:
    /// the loop had cleared its `registered` slot, and the shutdown path
    /// then walked past a record the registry still holds -- every peer
    /// keeps unicasting SPDP into it until the TTL and the deregister
    /// grace expire.
    #[test]
    fn a_transient_heartbeat_failure_does_not_cost_the_deregistration_on_stop() {
        let backend = FakeBackend::default();
        // Fail for ever, and refuse the re-registration too, so the loop
        // is stopped exactly in the state this test needs.
        backend
            .heartbeat_failures_left
            .store(u32::MAX, Ordering::SeqCst);
        let own = info(9, 39);
        let wiring = CloudPollerWiring {
            own_guid: Some(own.guid),
            registration: Some(own.clone()),
        };
        let mut poller = spawn_fake(backend.clone(), wiring, RecordingSink::default(), 39);
        let handle = poller.handle();

        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));
        backend
            .register_failures_left
            .store(u32::MAX, Ordering::SeqCst);
        assert!(
            wait_until(Duration::from_secs(5), || !handle.status().registered),
            "a run of failed refreshes should eventually re-register"
        );

        poller.stop();
        assert_eq!(
            backend.deregistered.lock().unwrap().as_slice(),
            &[own.guid],
            "the record the poller had put in the registry was left behind"
        );
    }

    /// The Consul backend reports a failure when the service WAS
    /// deregistered and only its KV mirror could not be deleted. The
    /// public flag must not keep claiming the participant is registered:
    /// this poller stops refreshing the record either way.
    #[test]
    fn a_partly_failed_deregistration_still_clears_the_public_registered_flag() {
        let backend = FakeBackend::default();
        let own = info(9, 39);
        let wiring = CloudPollerWiring {
            own_guid: Some(own.guid),
            registration: Some(own.clone()),
        };
        let mut poller = spawn_fake(backend.clone(), wiring, RecordingSink::default(), 39);
        let handle = poller.handle();
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));

        backend.fail_deregister.store(true, Ordering::SeqCst);
        poller.stop();
        assert_eq!(backend.deregistered.lock().unwrap().as_slice(), &[own.guid]);
        assert!(
            !handle.status().registered,
            "status still claims a registration this poller no longer maintains"
        );
        assert!(handle
            .status()
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("KV cleanup failed"));
    }

    /// An explicit `deregister()` followed by `stop()` deregisters ONCE:
    /// the shutdown path falls back on the record kept for
    /// re-registration, so that record has to be forgotten here too.
    #[test]
    fn an_explicit_deregister_is_not_repeated_by_the_shutdown_path() {
        let backend = FakeBackend::default();
        let own = info(9, 39);
        let wiring = CloudPollerWiring {
            own_guid: Some(own.guid),
            registration: Some(own.clone()),
        };
        let mut poller = spawn_fake(backend.clone(), wiring, RecordingSink::default(), 39);
        let handle = poller.handle();
        assert!(wait_until(Duration::from_secs(5), || handle
            .status()
            .registered));

        handle.deregister(own.guid).expect("deregister command");
        assert!(wait_until(Duration::from_secs(5), || backend
            .deregistered
            .lock()
            .unwrap()
            .len()
            == 1));
        poller.stop();
        assert_eq!(
            backend.deregistered.lock().unwrap().as_slice(),
            &[own.guid],
            "the shutdown path deregistered an already deregistered record"
        );
    }

    #[test]
    fn stop_is_bounded_when_the_backend_hangs() {
        let backend = FakeBackend::default();
        backend.hang_discover.store(true, Ordering::SeqCst);
        let sink = RecordingSink::default();
        let mut poller = spawn_fake(backend, CloudPollerWiring::default(), sink, 39);
        let handle = poller.handle();
        assert!(wait_until(Duration::from_secs(2), || handle
            .status()
            .running));

        let started = Instant::now();
        poller.stop();
        let took = started.elapsed();
        assert!(
            took < STOP_JOIN_TIMEOUT + Duration::from_secs(1),
            "stop() blocked for {:?} on a hung backend",
            took
        );
    }

    #[test]
    fn backend_construction_failure_is_loud_and_stops() {
        let sink = RecordingSink::default();
        let poller = CloudDiscoveryPoller::spawn_with_backend(
            fast_config(0),
            CloudPollerWiring::default(),
            sink.clone(),
            || Err::<FakeBackend, _>("no credentials".to_string()),
        );
        let handle = poller.handle();
        assert!(wait_until(Duration::from_secs(2), || !handle.is_running()));
        let status = handle.status();
        assert!(!status.running);
        assert_eq!(status.last_error.as_deref(), Some("no credentials"));
        let events = sink.0.lock().unwrap();
        assert!(events
            .events
            .iter()
            .any(|e| matches!(e, CloudEvent::Error { message } if message == "no credentials")));
        assert!(events
            .events
            .iter()
            .any(|e| matches!(e, CloudEvent::Stopped)));
    }

    /// `backend_is_available` is what the participant builder trusts to
    /// decide whether it may lower the multicast default. It must agree
    /// with the only place a backend is really constructed, for every
    /// provider variant, or a future backend lands without the builder
    /// noticing.
    #[test]
    fn backend_availability_matches_build_backend() {
        let providers = [
            CloudProvider::Consul {
                addr: "http://127.0.0.1:8500".to_string(),
                options: ConsulOptions::default(),
            },
            CloudProvider::Aws {
                namespace: "ns".to_string(),
                service: "svc".to_string(),
                region: "eu-west-3".to_string(),
            },
            CloudProvider::AwsCloudMap(Box::new(AwsCloudMapConfig::new(
                "ns",
                "srv-1",
                "eu-west-3",
            ))),
            CloudProvider::Azure {
                config_json: r#"{"account":"hddsacct","auth":{"kind":"managed_identity"}}"#
                    .to_string(),
            },
        ];
        for provider in providers {
            let label = provider_label(&provider);
            let available = backend_is_available(&provider);
            let config = CloudPollerConfig {
                provider,
                ..CloudPollerConfig::default()
            };
            assert_eq!(
                available,
                build_backend(&config).is_ok(),
                "backend_is_available disagrees with build_backend for {}",
                label
            );
        }

        // Availability is about the BUILD, not about one configuration:
        // an azure config that does not validate still fails here, which
        // is why the participant builder parses the same JSON before it
        // lowers the multicast default.
        let broken = CloudPollerConfig {
            provider: CloudProvider::Azure {
                config_json: r#"{"account":"a"}"#.to_string(),
            },
            ..CloudPollerConfig::default()
        };
        assert!(build_backend(&broken).is_err());
    }

    /// A registry that expires records on a lease (Azure Table Storage)
    /// needs the participant's row written again before the lease runs
    /// out. `heartbeat_interval: None` -- what Consul uses, and what the
    /// loop did for every provider before this -- registers exactly once.
    #[test]
    fn the_registration_is_refreshed_once_per_heartbeat_interval() {
        // How many times the record was written within `window`, waiting
        // no longer than it takes to reach `wanted` (a slow box is slow,
        // not red).
        let registrations =
            |heartbeat: Option<Duration>, wanted: usize, window: Duration| -> usize {
                let backend = FakeBackend::default();
                let counter = Arc::clone(&backend.registered);
                let config = CloudPollerConfig {
                    heartbeat_interval: heartbeat,
                    ..fast_config(39)
                };
                let wiring = CloudPollerWiring {
                    own_guid: Some([1; 16]),
                    registration: Some(info(1, 39)),
                };
                let poller =
                    CloudDiscoveryPoller::spawn_with_backend(config, wiring, NoSink, move || {
                        Ok(backend)
                    });
                let count = Arc::clone(&counter);
                wait_until(window, || count.lock().unwrap().len() >= wanted);
                let count = counter.lock().unwrap().len();
                drop(poller);
                count
            };

        assert_eq!(
            registrations(None, 2, Duration::from_millis(350)),
            1,
            "without a heartbeat the record must be written exactly once"
        );
        let refreshed = registrations(Some(Duration::from_millis(100)), 3, Duration::from_secs(5));
        assert!(
            refreshed >= 3,
            "the record was refreshed {} times in three heartbeat intervals",
            refreshed
        );
    }

    /// A refresh that keeps failing for a whole lease means the row has
    /// expired: the status must stop claiming a registration the registry
    /// no longer holds, and the poller must go back to registering.
    #[test]
    fn a_registration_that_cannot_be_refreshed_stops_being_reported_as_registered() {
        let backend = FakeBackend::default();
        let failures = Arc::clone(&backend.register_failures_left);
        let config = CloudPollerConfig {
            heartbeat_interval: Some(Duration::from_millis(50)),
            ..fast_config(39)
        };
        let wiring = CloudPollerWiring {
            own_guid: Some([1; 16]),
            registration: Some(info(1, 39)),
        };
        let poller =
            CloudDiscoveryPoller::spawn_with_backend(config, wiring, NoSink, move || Ok(backend));
        let handle = poller.handle();
        assert!(
            wait_until(Duration::from_secs(5), || handle.status().registered),
            "the first registration never landed"
        );

        // Every write from here on fails: the lease runs out.
        failures.store(u32::MAX, Ordering::SeqCst);
        assert!(
            wait_until(Duration::from_secs(5), || !handle.status().registered),
            "a registration nobody could refresh is still reported: {:?}",
            handle.status()
        );
        assert!(handle.status().last_error.is_some());

        // The retry path was re-armed, so the registry gets the row back.
        failures.store(0, Ordering::SeqCst);
        assert!(
            wait_until(Duration::from_secs(10), || handle.status().registered),
            "the poller never registered again: {:?}",
            handle.status()
        );
    }

    /// A panic on the poller thread must not leave the status frozen at
    /// `running: true` forever: it is reported and the poller stops.
    #[test]
    fn a_panicking_backend_stops_the_poller_instead_of_freezing_its_status() {
        let backend = FakeBackend::default();
        let panic_now = Arc::clone(&backend.panic_discover);
        let poller = CloudDiscoveryPoller::spawn_with_backend(
            fast_config(39),
            CloudPollerWiring::default(),
            NoSink,
            move || Ok(backend),
        );
        let handle = poller.handle();
        assert!(
            wait_until(Duration::from_secs(5), || handle.status().running
                && handle.status().successful_polls >= 1),
            "the poller never started"
        );

        panic_now.store(true, Ordering::SeqCst);
        assert!(
            wait_until(Duration::from_secs(5), || !handle.status().running),
            "the poller thread died with its status still reporting running"
        );
        let status = handle.status();
        assert!(
            status
                .last_error
                .as_deref()
                .is_some_and(|message: &str| message.contains("panicked")),
            "the panic was never reported: {:?}",
            status
        );
    }

    /// The poller really runs the AWS Cloud Map backend: it registers this
    /// participant against a SigV4-verifying fake endpoint and feeds the
    /// peer it discovers there into the sink. Nothing is mocked below the
    /// HTTP layer, and the fake answers 403 to any request whose signature
    /// does not recompute.
    #[test]
    fn the_aws_provider_registers_and_polls_against_a_fake_cloud_map_endpoint() {
        use crate::discovery::cloud::AwsCredentialSource;
        use crate::test_support::fake_aws::{FakeCloudMap, FakeInstance, FAKE_SERVICE_ID};

        let fake = FakeCloudMap::start().expect("fake Cloud Map");
        let peer_guid = [
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x00, 0x00,
            0x01, 0xc1,
        ];
        fake.seed_instance(FakeInstance {
            instance_id: "hdds-peer".into(),
            service_id: FAKE_SERVICE_ID.into(),
            attributes: [
                ("GUID", "1112131415161718191a1b1c000001c1"),
                ("DOMAIN_ID", "39"),
                ("PARTICIPANT_NAME", "peer"),
                ("LOCATORS", "192.0.2.9:7410"),
            ]
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        });

        let own = info(0x77, 39);
        let sink = RecordingSink::default();
        let config = CloudPollerConfig {
            provider: CloudProvider::AwsCloudMap(Box::new(
                AwsCloudMapConfig::new("hdds-namespace", FAKE_SERVICE_ID, "eu-west-3")
                    .with_endpoint_override(fake.base_url())
                    .with_credentials(AwsCredentialSource::Container {
                        uri: fake.credentials_url(),
                        authorization: None,
                    }),
            )),
            poll_interval: Duration::from_millis(50),
            domain_id: 39,
            // AWS Cloud Map instances are owned by the service and carry no
            // lease, so this backend refreshes nothing.
            heartbeat_interval: None,
        };
        let mut poller = CloudDiscoveryPoller::spawn_wired(
            config,
            CloudPollerWiring {
                own_guid: Some(own.guid),
                registration: Some(own.clone()),
            },
            sink.clone(),
        );

        assert!(
            wait_until(Duration::from_secs(5), || {
                sink.0
                    .lock()
                    .unwrap()
                    .polls
                    .iter()
                    .any(|poll| poll.contains(&peer_guid))
            }),
            "the AWS backend never reported the seeded peer: {:?}",
            sink.0.lock().unwrap().events
        );
        assert!(
            wait_until(Duration::from_secs(5), || !fake.registered_ids().is_empty()),
            "the AWS backend never registered this participant"
        );

        poller.stop();
        assert!(
            fake.signature_failures().is_empty(),
            "the fake endpoint rejected a signature: {:?}",
            fake.signature_failures()
        );
        assert!(
            wait_until(Duration::from_secs(5), || !fake
                .deregistered_ids()
                .is_empty()),
            "stopping the poller did not deregister the participant"
        );
        // The own participant is never reported as its own peer.
        assert!(sink
            .0
            .lock()
            .unwrap()
            .polls
            .iter()
            .all(|poll| !poll.contains(&own.guid)));
    }
}
