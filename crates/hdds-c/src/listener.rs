// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Listener FFI Bindings
//!
//! C-compatible callback-based listener API for DataReader and DataWriter events.
//! These structs and functions wrap the Rust listener traits defined in
//! `hdds::dds::listener` for consumption by C, C++, and Python SDKs.
//!
//! # Usage from C
//!
//! ```c
//! void my_on_data(const uint8_t* data, size_t len, void* user_data) {
//!     // process data
//! }
//!
//! HddsReaderListener listener = {0};
//! listener.ON_DATA_AVAILABLE = my_on_data;
//! listener.USER_DATA = my_context;
//! hdds_reader_set_listener(reader, &listener);
//! ```
//!
//! The generated header names struct fields in SCREAMING_SNAKE_CASE, as for
//! every struct of `hdds.h` (cbindgen `rename_fields`): the Rust field
//! `on_data_available` is `ON_DATA_AVAILABLE` in C, `current_count` is
//! `CURRENT_COUNT`.
//!
//! # Threading and safety contract
//!
//! - **Which thread.** Callbacks run on HDDS threads:
//!   - a sample that reaches the reader over a transport (another process,
//!     or another participant of this process): the router thread (UDP),
//!     the TCP/QUIC routing thread, or the control thread when a
//!     HEARTBEAT/GAP releases samples held for ordering;
//!   - a sample written by a writer of the SAME participant (or of any
//!     participant of this process when one of the two has no transport,
//!     `TransportMode::IntraProcess`): the thread that called
//!     `hdds_writer_write`, inside that call;
//!   - matched / incompatible-QoS events: the discovery threads, after
//!     the match registry's dispatch;
//!   - `on_sample_rejected` / `on_sample_lost`: the thread that refused or
//!     lost the sample, once its delivery is over, in the order the
//!     statuses were taken. Under a burst, the thread that tells tells only
//!     its share; the rest is told, still in order, by a short-lived
//!     `hdds-notices` thread of that reader's own;
//!   - `on_sample_written`, `on_offered_deadline_missed`: the thread that
//!     called `hdds_writer_write`; `on_deadline_missed`: the thread that
//!     called a take/read on the reader.
//!
//!   Several callbacks of one listener can run at the same time on
//!   different threads: `user_data` must be safe to share between threads.
//! - **No HDDS lock across a callback**: take/read the reader it belongs
//!   to, write with a writer (the writer that delivered included), set or
//!   clear listeners (including its own), open an access bracket. A
//!   rejection or a loss the callback causes is told after it returns, in
//!   order, never nested in it. Status and data pointers are valid only
//!   for the duration of the callback.
//! - **`user_data`** is passed through untouched; HDDS never dereferences
//!   or frees it.
//! - **Removal waits.** `hdds_*_clear_listener`, `hdds_*_set_listener`
//!   (replacing a listener) and `hdds_reader_destroy` / `hdds_writer_destroy`
//!   return only once no callback of the previous listener is still running
//!   on another thread; after they return, its callbacks are not called
//!   again and its `user_data` may be freed. Called from inside one of that
//!   listener's own callbacks, they do not wait for the calling callback (it
//!   is the caller) but still wait for the others. Do not call them while
//!   holding a lock that one of the listener's callbacks takes, and do not
//!   have two listeners' callbacks remove each other from two threads (each
//!   removal would wait for the other callback).
//! - **Never destroy an entity from inside its own callback.** The HDDS code
//!   that called back keeps using the entity after the callback returns
//!   (`hdds_writer_write` after `on_sample_written`, a take after
//!   `on_deadline_missed`). `hdds_reader_destroy` / `hdds_writer_destroy`
//!   called there remove the listener but do not free the entity: it is
//!   leaked, with an error logged. Clearing the listener from inside a
//!   callback is fine.
//! - **`hdds_*_exchange_listener`** installs or removes a listener like
//!   set/clear and also returns the replaced listener's `user_data`: a
//!   binding that owns per-listener state frees exactly that state, whatever
//!   the order in which concurrent installs reached HDDS.
//! - **No unwinding across the boundary.** A Rust panic inside the bridge is
//!   caught before it reaches an HDDS thread or the C caller. A foreign
//!   exception (C++) must not propagate out of a callback: the C++ SDK
//!   catches it in its trampolines; a C callback must not `longjmp` out.
//! - A NULL callback field means "not interested": HDDS does not report
//!   that status to this listener, and for `on_sample_rejected` the status
//!   then stays readable through the reader's status condition.
//!
//! # What fires
//!
//! `on_data_available`, `on_subscription_matched`, `on_sample_rejected`,
//! `on_deadline_missed`, `on_incompatible_qos` (reader) and
//! `on_sample_written`, `on_publication_matched`,
//! `on_offered_deadline_missed`, `on_offered_incompatible_qos` (writer).
//! `on_liveliness_changed` (reader) reports LIVELINESS_CHANGED: the
//! matched writers alive and not alive. `on_liveliness_lost` (writer)
//! reports LIVELINESS_LOST: this writer (MANUAL_BY_PARTICIPANT,
//! MANUAL_BY_TOPIC only) failed to assert within its lease. The core does
//! not raise SAMPLE_LOST yet: `on_sample_lost` is accepted and never
//! called. Matched statuses
//! count every matching endpoint, including one of this participant: a
//! reader and a writer of one participant match each other as they would
//! across the network (the sample still flows and `on_data_available` fires).

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

use hdds::dds::listener::{
    DataReaderListener, DataWriterListener, LivelinessChangedStatus, LivelinessLostStatus,
    OfferedDeadlineMissedStatus, PublicationMatchedStatus, RequestedDeadlineMissedStatus,
    RequestedIncompatibleQosStatus, SampleLostStatus, SampleRejectedReason, SampleRejectedStatus,
    SubscriptionMatchedStatus,
};
use hdds::dds::{InstanceStateMask, ReadCondition, SampleStateMask, StatusMask, ViewStateMask};
use hdds::{DataReader, DataWriter};

use super::{reader_arc_from_handle, BytePayload, HddsDataReader, HddsDataWriter, HddsError};

// =============================================================================
// C-compatible status structs
// =============================================================================

/// Subscription matched status (C-compatible mirror of Rust SubscriptionMatchedStatus).
///
/// Reports the number of publications matched with this reader.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsSubscriptionMatchedStatus {
    /// Total cumulative count of matched publications.
    pub total_count: u32,
    /// Change in total_count since the last getter or listener report.
    pub total_count_change: i32,
    /// Current number of matched publications.
    pub current_count: u32,
    /// Change in current_count since the last getter or listener report.
    pub current_count_change: i32,
}

/// Publication matched status (C-compatible mirror of Rust PublicationMatchedStatus).
///
/// Reports the number of subscriptions matched with this writer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsPublicationMatchedStatus {
    /// Total cumulative count of matched subscriptions.
    pub total_count: u32,
    /// Change in total_count since the last getter or listener report.
    pub total_count_change: i32,
    /// Current number of matched subscriptions.
    pub current_count: u32,
    /// Change in current_count since the last getter or listener report.
    pub current_count_change: i32,
}

/// Liveliness changed status (C-compatible mirror of Rust LivelinessChangedStatus).
///
/// Reports changes in liveliness of matched writers.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsLivelinessChangedStatus {
    /// Number of publications currently asserting liveliness.
    pub alive_count: u32,
    /// Change in alive_count since the last getter or listener report.
    pub alive_count_change: i32,
    /// Number of publications that have lost liveliness.
    pub not_alive_count: u32,
    /// Change in not_alive_count since the last getter or listener report.
    pub not_alive_count_change: i32,
}

/// Liveliness lost status (C-compatible mirror of Rust LivelinessLostStatus).
///
/// Reports how many times a writer failed to assert its liveliness within
/// its offered lease (MANUAL_BY_PARTICIPANT, MANUAL_BY_TOPIC only).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsLivelinessLostStatus {
    /// Total cumulative count of liveliness losses.
    pub total_count: u32,
    /// Change in total_count since the last getter or listener report.
    pub total_count_change: i32,
}

/// Sample lost status (C-compatible mirror of Rust SampleLostStatus).
///
/// Reports samples lost due to gaps in sequence numbers.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsSampleLostStatus {
    /// Total cumulative count of lost samples.
    pub total_count: u32,
    /// Change in total_count since the last getter or listener report.
    pub total_count_change: i32,
}

/// Sample rejected status (C-compatible mirror of Rust SampleRejectedStatus).
///
/// Reports samples rejected due to resource limits.
/// `last_reason` values: 0=NotRejected, 1=ResourceLimit, 2=InstanceLimit,
/// 3=SamplesPerInstanceLimit.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsSampleRejectedStatus {
    /// Total cumulative count of rejected samples.
    pub total_count: u32,
    /// Change in total_count since the last getter or listener report.
    pub total_count_change: i32,
    /// Reason for rejection (0=NotRejected, 1=ResourceLimit, 2=InstanceLimit, 3=SamplesPerInstanceLimit).
    pub last_reason: u32,
}

/// Deadline missed status (C-compatible mirror of Rust RequestedDeadlineMissedStatus).
///
/// Reports missed deadlines on a reader or writer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsDeadlineMissedStatus {
    /// Total cumulative count of missed deadlines.
    pub total_count: u32,
    /// Change in total_count since the last getter or listener report.
    pub total_count_change: i32,
}

/// Incompatible QoS status (C-compatible mirror of Rust RequestedIncompatibleQosStatus).
///
/// Reports QoS incompatibility between matched endpoints.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsIncompatibleQosStatus {
    /// Total cumulative count of incompatible QoS offers.
    pub total_count: u32,
    /// Change in total_count since the last getter or listener report.
    pub total_count_change: i32,
    /// QosPolicyId_t of the last incompatible QoS policy (DDS v1.4
    /// Sec.2.3.3: DURABILITY 2, PRESENTATION 3, DEADLINE 4, LATENCY_BUDGET
    /// 5, OWNERSHIP 6, LIVELINESS 8, RELIABILITY 11, DESTINATION_ORDER 12;
    /// DDS-XTypes v1.3: DATA_REPRESENTATION 23).
    pub last_policy_id: u32,
}

// =============================================================================
// Callback type aliases (C function pointers)
// =============================================================================

/// Callback for data available events.
///
/// # Parameters
/// - `data`: Pointer to serialized sample bytes
/// - `len`: Length of the serialized data in bytes
/// - `user_data`: User-provided context pointer
pub type HddsOnDataAvailable =
    Option<unsafe extern "C" fn(data: *const u8, len: usize, user_data: *mut c_void)>;

/// `on_data_available` with the encapsulation identifier of the
/// representation the bytes are in: `CDR_LE` (0x0001) for XCDR1, `CDR2_LE`
/// (0x0007) for XCDR2, as `hdds_reader_take_ex` reports it. Installed with
/// `hdds_reader_set_listener_ex` / `hdds_reader_exchange_listener_ex`.
pub type HddsOnDataAvailableEx = Option<
    unsafe extern "C" fn(
        data: *const u8,
        len: usize,
        encapsulation_id: u16,
        user_data: *mut c_void,
    ),
>;

/// `on_data_available_notification` of a reader whose data is read by the
/// application (BY_SOURCE_TIMESTAMP, TIME_BASED_FILTER): no payload. Installed
/// with `hdds_reader_set_listener_notify`.
pub type HddsOnDataAvailableNotify = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

/// Callback for subscription matched events.
pub type HddsOnSubscriptionMatched = Option<
    unsafe extern "C" fn(status: *const HddsSubscriptionMatchedStatus, user_data: *mut c_void),
>;

/// Callback for publication matched events.
pub type HddsOnPublicationMatched = Option<
    unsafe extern "C" fn(status: *const HddsPublicationMatchedStatus, user_data: *mut c_void),
>;

/// Callback for liveliness changed events.
pub type HddsOnLivelinessChanged = Option<
    unsafe extern "C" fn(status: *const HddsLivelinessChangedStatus, user_data: *mut c_void),
>;

/// Callback for sample lost events.
pub type HddsOnSampleLost =
    Option<unsafe extern "C" fn(status: *const HddsSampleLostStatus, user_data: *mut c_void)>;

/// Callback for sample rejected events.
pub type HddsOnSampleRejected =
    Option<unsafe extern "C" fn(status: *const HddsSampleRejectedStatus, user_data: *mut c_void)>;

/// Callback for deadline missed events (reader side).
pub type HddsOnDeadlineMissed =
    Option<unsafe extern "C" fn(status: *const HddsDeadlineMissedStatus, user_data: *mut c_void)>;

/// Callback for incompatible QoS events (reader side).
pub type HddsOnIncompatibleQos =
    Option<unsafe extern "C" fn(status: *const HddsIncompatibleQosStatus, user_data: *mut c_void)>;

/// Callback for sample written events (writer confirmation).
///
/// # Parameters
/// - `data`: Pointer to serialized sample bytes
/// - `len`: Length of the serialized data in bytes
/// - `sequence_number`: Assigned RTPS sequence number
/// - `user_data`: User-provided context pointer
pub type HddsOnSampleWritten = Option<
    unsafe extern "C" fn(data: *const u8, len: usize, sequence_number: u64, user_data: *mut c_void),
>;

/// Callback for offered deadline missed events (writer side).
///
/// # Parameters
/// - `instance_handle`: Handle of the instance that missed the deadline (0 if none)
/// - `user_data`: User-provided context pointer
pub type HddsOnOfferedDeadlineMissed =
    Option<unsafe extern "C" fn(instance_handle: u64, user_data: *mut c_void)>;

/// Callback for offered incompatible QoS events (writer side).
///
/// # Parameters
/// - `policy_id`: QosPolicyId_t of the incompatible QoS policy (DDS v1.4
///   Sec.2.3.3, the values of `HddsIncompatibleQosStatus::last_policy_id`)
/// - `policy_name`: Null-terminated policy name string (e.g., "RELIABILITY")
/// - `user_data`: User-provided context pointer
pub type HddsOnOfferedIncompatibleQos = Option<
    unsafe extern "C" fn(policy_id: u32, policy_name: *const c_char, user_data: *mut c_void),
>;

/// Callback for liveliness lost events (writer side).
pub type HddsOnLivelinessLost =
    Option<unsafe extern "C" fn(status: *const HddsLivelinessLostStatus, user_data: *mut c_void)>;

// =============================================================================
// Listener structs
// =============================================================================

/// C-compatible DataReader listener.
///
/// Set callback fields to receive events. A NULL callback is not called,
/// and its status is not reported to this listener. `USER_DATA` is passed
/// through to every callback invocation, untouched.
///
/// # Example (C)
///
/// ```c
/// HddsReaderListener listener = {0};
/// listener.ON_DATA_AVAILABLE = my_data_callback;
/// listener.ON_SUBSCRIPTION_MATCHED = my_match_callback;
/// listener.USER_DATA = my_context;
/// hdds_reader_set_listener(reader, &listener);
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HddsReaderListener {
    /// Called when new data is available to read.
    pub on_data_available: HddsOnDataAvailable,
    /// Called when the reader matches/unmatches with a writer.
    pub on_subscription_matched: HddsOnSubscriptionMatched,
    /// Called when liveliness of a matched writer changes.
    pub on_liveliness_changed: HddsOnLivelinessChanged,
    /// Called when samples are lost (gap in sequence numbers).
    pub on_sample_lost: HddsOnSampleLost,
    /// Called when samples are rejected due to resource limits.
    pub on_sample_rejected: HddsOnSampleRejected,
    /// Called when the requested deadline is missed.
    pub on_deadline_missed: HddsOnDeadlineMissed,
    /// Called when QoS is incompatible with a matched writer.
    pub on_incompatible_qos: HddsOnIncompatibleQos,
    /// User-provided context pointer, passed to all callbacks.
    pub user_data: *mut c_void,
}

// Safety: the struct holds C function pointers and an opaque `user_data`
// that HDDS never dereferences; the module-level contract makes the C caller
// responsible for the callbacks and `user_data` being usable from any thread.
unsafe impl Send for HddsReaderListener {}
unsafe impl Sync for HddsReaderListener {}

/// C-compatible DataWriter listener.
///
/// Set callback fields to receive events. A NULL callback is not called,
/// and its status is not reported to this listener. `USER_DATA` is passed
/// through to every callback invocation, untouched.
///
/// # Example (C)
///
/// ```c
/// HddsWriterListener listener = {0};
/// listener.ON_PUBLICATION_MATCHED = my_match_callback;
/// listener.USER_DATA = my_context;
/// hdds_writer_set_listener(writer, &listener);
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HddsWriterListener {
    /// Called after a sample is successfully written.
    pub on_sample_written: HddsOnSampleWritten,
    /// Called when the writer matches/unmatches with a reader.
    pub on_publication_matched: HddsOnPublicationMatched,
    /// Called when an offered deadline is missed.
    pub on_offered_deadline_missed: HddsOnOfferedDeadlineMissed,
    /// Called when QoS is incompatible with a matched reader.
    pub on_offered_incompatible_qos: HddsOnOfferedIncompatibleQos,
    /// Called when liveliness is lost (MANUAL_BY_* only).
    pub on_liveliness_lost: HddsOnLivelinessLost,
    /// User-provided context pointer, passed to all callbacks.
    pub user_data: *mut c_void,
}

// Safety: see `HddsReaderListener`.
unsafe impl Send for HddsWriterListener {}
unsafe impl Sync for HddsWriterListener {}

// =============================================================================
// Callback drain: the guarantee behind "removal waits"
// =============================================================================

thread_local! {
    /// The callbacks running on this thread, innermost last, as (drain,
    /// entity handle) pairs (a callback can trigger another listener's
    /// callback: a write from inside `on_data_available` runs the
    /// intra-process callbacks of the readers it reaches, on this same
    /// thread).
    static RUNNING_HERE: RefCell<Vec<(usize, usize)>> = const { RefCell::new(Vec::new()) };
}

/// Whether a callback of the entity `handle` (any of its listeners, current
/// or already removed) is running on this thread. Destroying the entity
/// from there would free it under the HDDS code that called back, which
/// continues on it after the callback returns.
fn entity_running_here(handle: usize) -> bool {
    RUNNING_HERE.with(|r| r.borrow().iter().any(|&(_, entity)| entity == handle))
}

/// Counts the callbacks of one installed listener that are running, and
/// lets its removal wait until the ones on other threads have returned.
///
/// The enter/remove race is closed Dekker-style with sequentially
/// consistent operations: a callback increments `running` THEN reads
/// `active`; a removal clears `active` THEN reads `running`. At least one of
/// them sees the other: either the callback sees `active == false` and
/// backs out without calling, or the removal sees it running and waits.
struct CallbackDrain {
    active: AtomicBool,
    running: AtomicUsize,
    lock: Mutex<()>,
    returned: Condvar,
    /// The handle of the reader / writer the listener is installed on.
    entity: usize,
}

impl CallbackDrain {
    fn new(entity: usize) -> Self {
        Self {
            active: AtomicBool::new(true),
            running: AtomicUsize::new(0),
            lock: Mutex::new(()),
            returned: Condvar::new(),
            entity,
        }
    }

    fn key(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    /// Whether the listener is still installed (not removed).
    fn active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Run `call` unless the listener was removed. `call` reaches C code:
    /// a Rust panic around it is caught here (it cannot be allowed to
    /// unwind into the HDDS thread that dispatched, nor further).
    fn run(&self, call: impl FnOnce()) {
        self.running.fetch_add(1, Ordering::SeqCst);
        if self.active.load(Ordering::SeqCst) {
            RUNNING_HERE.with(|r| r.borrow_mut().push((self.key(), self.entity)));
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call));
            RUNNING_HERE.with(|r| {
                let mut r = r.borrow_mut();
                if let Some(at) = r.iter().rposition(|&(k, _)| k == self.key()) {
                    r.remove(at);
                }
            });
            if outcome.is_err() {
                log::error!("[hdds-c] a panic in a listener callback bridge was caught");
            }
        }
        self.running.fetch_sub(1, Ordering::SeqCst);
        if !self.active.load(Ordering::SeqCst) {
            // A removal may be waiting: wake it under the lock it checks
            // `running` with, so the wake cannot fall between its check and
            // its wait.
            let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
            self.returned.notify_all();
        }
    }

    /// Stop new callbacks and wait for the running ones, except those
    /// running on this thread (the caller is one of them, or is called by
    /// one: waiting for it would never return).
    fn deactivate_and_drain(&self) {
        self.active.store(false, Ordering::SeqCst);
        let mine =
            RUNNING_HERE.with(|r| r.borrow().iter().filter(|&&(k, _)| k == self.key()).count());
        let mut guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        while self.running.load(Ordering::SeqCst) > mine {
            guard = self.returned.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
    }
}

// =============================================================================
// Bridges: the Rust listeners that call the C callbacks
// =============================================================================

/// A C reader listener installed on one `DataReader<BytePayload>`.
struct ReaderBridge {
    callbacks: HddsReaderListener,
    /// Called instead of `callbacks.on_data_available` when set.
    on_data_available_ex: HddsOnDataAvailableEx,
    /// Called for `on_data_available_notification` when set; otherwise that
    /// notification reads the accepted samples and hands them to the payload
    /// callbacks (see `forward_accepted_samples`).
    on_data_available_notify: HddsOnDataAvailableNotify,
    /// The reader this listener is installed on, for the adapter. Weak: the
    /// handle owns the reader, and removing this listener (which every destroy
    /// path does before releasing the handle) waits for its callbacks.
    reader: Weak<DataReader<BytePayload>>,
    /// The NOT_READ ReadCondition the adapter reads with, created on first use.
    accepted_condition: Mutex<Option<Arc<ReadCondition>>>,
    /// Set while one thread holds the forwarding role (see
    /// `forward_accepted_samples`): only that thread reads and delivers.
    forwarding: AtomicBool,
    /// Set by every notification; the holder runs another pass while it is set.
    again: AtomicBool,
    /// Passes refused because the reader is a GROUP-scope Subscriber's and was
    /// not read inside its access bracket. The first one logs the warning.
    scope_refusals: AtomicUsize,
    drain: CallbackDrain,
}

/// Holder of a bridge's forwarding role: releases it when dropped.
struct ForwardingRole<'a>(&'a AtomicBool);

impl Drop for ForwardingRole<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Samples the adapter reads per call to the reader.
const ACCEPTED_BATCH: usize = 64;

/// The error `read_w_condition` returns for a reader of a GROUP-scope
/// Subscriber read outside its access bracket (`consume` in the reader
/// runtime, PRECONDITION_NOT_MET). The message prefix is the only handle on
/// it: the error enum has no variant of its own for it.
fn is_group_scope_refusal(error: &hdds::dds::Error) -> bool {
    matches!(
        error,
        hdds::dds::Error::InvalidState(message) if message.starts_with("PRECONDITION_NOT_MET")
    )
}

/// Passes of `reader`'s adapter refused for GROUP scope (test builds only).
#[cfg(test)]
pub(crate) fn group_scope_refusals(reader: *mut HddsDataReader) -> usize {
    reader_bridges()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(reader as usize))
        .map_or(0, |bridge| bridge.scope_refusals.load(Ordering::SeqCst))
}

impl ReaderBridge {
    /// The statuses this listener reports: those with a callback.
    fn mask(&self) -> StatusMask {
        let c = &self.callbacks;
        let mut mask = StatusMask::NONE;
        let mut add = |present: bool, status: StatusMask| {
            if present {
                mask = mask | status;
            }
        };
        add(
            c.on_data_available.is_some()
                || self.on_data_available_ex.is_some()
                || self.on_data_available_notify.is_some(),
            StatusMask::DATA_AVAILABLE,
        );
        add(
            c.on_subscription_matched.is_some(),
            StatusMask::SUBSCRIPTION_MATCHED,
        );
        add(
            c.on_liveliness_changed.is_some(),
            StatusMask::LIVELINESS_CHANGED,
        );
        add(c.on_sample_lost.is_some(), StatusMask::SAMPLE_LOST);
        add(c.on_sample_rejected.is_some(), StatusMask::SAMPLE_REJECTED);
        add(
            c.on_deadline_missed.is_some(),
            StatusMask::REQUESTED_DEADLINE_MISSED,
        );
        add(
            c.on_incompatible_qos.is_some(),
            StatusMask::REQUESTED_INCOMPATIBLE_QOS,
        );
        mask
    }
}

pub(crate) fn rejected_reason_code(reason: SampleRejectedReason) -> u32 {
    match reason {
        SampleRejectedReason::NotRejected => 0,
        SampleRejectedReason::ResourceLimit => 1,
        SampleRejectedReason::InstanceLimit => 2,
        SampleRejectedReason::SamplesPerInstanceLimit => 3,
    }
}

impl ReaderBridge {
    /// Hand one sample's bytes to the payload callback (`_ex` when installed).
    fn deliver_payload(&self, sample: &BytePayload) {
        if let Some(cb) = self.on_data_available_ex {
            let user_data = self.callbacks.user_data;
            let encapsulation_id = sample.encapsulation_id();
            // SAFETY: the callback and user_data come from the C caller, who
            // guarantees them valid until the listener is removed; removal
            // waits for this call (`CallbackDrain`). The data pointer is
            // valid for the duration of the call.
            self.drain.run(|| unsafe {
                cb(
                    sample.data.as_ptr(),
                    sample.data.len(),
                    encapsulation_id,
                    user_data,
                );
            });
        } else if let Some(cb) = self.callbacks.on_data_available {
            let user_data = self.callbacks.user_data;
            // SAFETY: as for the `_ex` call above.
            self.drain
                .run(|| unsafe { cb(sample.data.as_ptr(), sample.data.len(), user_data) });
        }
    }

    /// The adapter for a reader that delivers through
    /// `on_data_available_notification` (BY_SOURCE_TIMESTAMP, TIME_BASED_FILTER)
    /// to a listener with a payload callback and no notify callback.
    ///
    /// Reads the samples NOT_READ through a ReadCondition, which is
    /// non-consuming (the samples stay takeable) and marks them READ, so each
    /// accepted sample reaches the callback once. Instance-state transitions
    /// carry no payload and are skipped. Batches are read outside every reader
    /// lock; the bytes are handed to the C callback afterwards.
    ///
    /// Passes are serialized per bridge, so the callbacks see the samples in
    /// the order they were read (a BY_SOURCE_TIMESTAMP order must hold across
    /// threads). A notification sets `again` and, when another thread holds the
    /// role, returns at once: the holder runs one more pass before it lets go.
    /// The lost-wakeup window is closed by the order of the flags: a notifier
    /// that sets `again` after the holder's last check of it either sees the
    /// role free (and takes it) or sees it held, and then the holder's check
    /// after its release comes after that set. A callback that writes (re-entry
    /// on the holder's own thread) only sets `again`; the holder's loop serves
    /// it. No lock is held across a callback.
    fn forward_accepted_samples(&self) {
        self.again.store(true, Ordering::SeqCst);
        if self
            .forwarding
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        loop {
            self.again.store(false, Ordering::SeqCst);
            let finished = {
                // Gives the role back even if the pass panics (a panic in
                // the read itself; callback panics are caught by the drain),
                // so the adapter does not stop for good on this reader.
                let _role = ForwardingRole(&self.forwarding);
                self.forward_pass()
            };
            if !finished || !self.again.load(Ordering::SeqCst) {
                return;
            }
            if self
                .forwarding
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return;
            }
        }
    }

    /// One pass of `forward_accepted_samples`: read and deliver batches until
    /// one comes back short. Returns false when the pass stopped early (the
    /// reader is gone or a read failed).
    fn forward_pass(&self) -> bool {
        let Some(reader) = self.reader.upgrade() else {
            return false;
        };
        let Some(condition) = self.accepted_condition(&reader) else {
            return false;
        };
        loop {
            // A removed listener marks nothing further READ: samples read
            // now would be lost to the application without a callback.
            if !self.drain.active() {
                return false;
            }
            let batch = match reader.read_w_condition(&condition, ACCEPTED_BATCH) {
                Ok(batch) => batch,
                Err(e) if is_group_scope_refusal(&e) => {
                    self.refuse_group_scope();
                    return false;
                }
                Err(e) => {
                    log::error!("[hdds-c] reading the accepted samples of a reader failed: {e}");
                    return false;
                }
            };
            let full = batch.len() == ACCEPTED_BATCH;
            for (sample, _info) in batch {
                if let Some(sample) = sample {
                    self.deliver_payload(&sample);
                }
            }
            if !full {
                return true;
            }
        }
    }

    /// A pass refused for GROUP scope: the reader belongs to a Subscriber of
    /// GROUP presentation and is read outside its access bracket, so this
    /// listener's payload callback can never get a sample. Said once per
    /// bridge, not per notification.
    fn refuse_group_scope(&self) {
        if self.scope_refusals.fetch_add(1, Ordering::SeqCst) == 0 {
            log::warn!(
                "[hdds-c] a reader of a GROUP-presentation Subscriber delivers through \
                 on_data_available_notification (BY_SOURCE_TIMESTAMP or TIME_BASED_FILTER), and \
                 its samples can be read only inside hdds_subscriber_begin_access / \
                 hdds_subscriber_end_access (DDS v1.4 Sec.2.2.2.5.2.8): the payload callback \
                 gets nothing. Install hdds_reader_set_listener_notify and read the samples \
                 inside the brackets."
            );
        }
    }

    /// The NOT_READ ReadCondition of this reader, created on first use. Created
    /// outside the slot's lock; a concurrent creator's extra one is dropped.
    fn accepted_condition(
        &self,
        reader: &Arc<DataReader<BytePayload>>,
    ) -> Option<Arc<ReadCondition>> {
        if let Some(condition) = self
            .accepted_condition
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Some(condition);
        }
        let created = match reader.create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        ) {
            Ok(condition) => condition,
            Err(e) => {
                log::error!("[hdds-c] creating the accepted-samples condition failed: {e:?}");
                return None;
            }
        };
        let mut slot = self
            .accepted_condition
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Some(slot.get_or_insert(created).clone())
    }
}

impl DataReaderListener<BytePayload> for ReaderBridge {
    fn on_data_available(&self, sample: &BytePayload) {
        self.deliver_payload(sample);
    }

    fn on_data_available_notification(&self) {
        if let Some(cb) = self.on_data_available_notify {
            let user_data = self.callbacks.user_data;
            // SAFETY: as for `deliver_payload`: the callback comes from the C
            // caller and stays valid until the listener is removed.
            self.drain.run(|| unsafe { cb(user_data) });
        } else if self.callbacks.on_data_available.is_some() || self.on_data_available_ex.is_some()
        {
            // Under the drain as well: removal waits for the reads and the
            // callbacks they feed, and a removed listener reads nothing.
            self.drain.run(|| self.forward_accepted_samples());
        }
    }

    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        if let Some(cb) = self.callbacks.on_subscription_matched {
            let c_status = HddsSubscriptionMatchedStatus {
                total_count: status.total_count,
                total_count_change: status.total_count_change,
                current_count: status.current_count,
                current_count_change: status.current_count_change,
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `on_data_available`; the status lives on this frame.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }

    fn on_liveliness_changed(&self, status: LivelinessChangedStatus) {
        if let Some(cb) = self.callbacks.on_liveliness_changed {
            let c_status = HddsLivelinessChangedStatus {
                alive_count: status.alive_count,
                alive_count_change: status.alive_count_change,
                not_alive_count: status.not_alive_count,
                not_alive_count_change: status.not_alive_count_change,
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `on_data_available`.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }

    fn on_sample_lost(&self, status: SampleLostStatus) {
        if let Some(cb) = self.callbacks.on_sample_lost {
            let c_status = HddsSampleLostStatus {
                total_count: status.total_count,
                total_count_change: status.total_count_change,
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `on_data_available`.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }

    fn on_sample_rejected(&self, status: SampleRejectedStatus) {
        if let Some(cb) = self.callbacks.on_sample_rejected {
            let c_status = HddsSampleRejectedStatus {
                total_count: status.total_count,
                total_count_change: status.total_count_change,
                last_reason: rejected_reason_code(status.last_reason),
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `on_data_available`.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }

    fn on_requested_deadline_missed(&self, status: RequestedDeadlineMissedStatus) {
        if let Some(cb) = self.callbacks.on_deadline_missed {
            let c_status = HddsDeadlineMissedStatus {
                total_count: status.total_count,
                total_count_change: status.total_count_change,
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `on_data_available`.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }

    fn on_requested_incompatible_qos(&self, status: RequestedIncompatibleQosStatus) {
        if let Some(cb) = self.callbacks.on_incompatible_qos {
            let c_status = HddsIncompatibleQosStatus {
                total_count: status.total_count,
                total_count_change: status.total_count_change,
                last_policy_id: status.last_policy_id,
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `on_data_available`.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }
}

/// A C writer listener installed on one `DataWriter<BytePayload>`.
struct WriterBridge {
    callbacks: HddsWriterListener,
    drain: CallbackDrain,
}

impl WriterBridge {
    /// The statuses this listener reports: those with a callback.
    /// `on_sample_written` has no DDS status: the core calls it whenever a
    /// listener is installed.
    fn mask(&self) -> StatusMask {
        let c = &self.callbacks;
        let mut mask = StatusMask::NONE;
        let mut add = |present: bool, status: StatusMask| {
            if present {
                mask = mask | status;
            }
        };
        add(
            c.on_publication_matched.is_some(),
            StatusMask::PUBLICATION_MATCHED,
        );
        add(
            c.on_offered_deadline_missed.is_some(),
            StatusMask::OFFERED_DEADLINE_MISSED,
        );
        add(
            c.on_offered_incompatible_qos.is_some(),
            StatusMask::OFFERED_INCOMPATIBLE_QOS,
        );
        add(c.on_liveliness_lost.is_some(), StatusMask::LIVELINESS_LOST);
        mask
    }
}

impl DataWriterListener<BytePayload> for WriterBridge {
    fn on_sample_written(&self, sample: &BytePayload, sequence_number: u64) {
        if let Some(cb) = self.callbacks.on_sample_written {
            let user_data = self.callbacks.user_data;
            // SAFETY: see `ReaderBridge::on_data_available`.
            self.drain.run(|| unsafe {
                cb(
                    sample.data.as_ptr(),
                    sample.data.len(),
                    sequence_number,
                    user_data,
                );
            });
        }
    }

    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        if let Some(cb) = self.callbacks.on_publication_matched {
            let c_status = HddsPublicationMatchedStatus {
                total_count: status.total_count,
                total_count_change: status.total_count_change,
                current_count: status.current_count,
                current_count_change: status.current_count_change,
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `ReaderBridge::on_data_available`.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }

    fn on_offered_deadline_missed(&self, status: OfferedDeadlineMissedStatus) {
        if let Some(cb) = self.callbacks.on_offered_deadline_missed {
            // The legacy callback has a u64 parameter. Keep its stable
            // prefix projection; the Rust status retains the full handle.
            let handle = status.last_instance_handle.map_or(0, |handle| {
                let mut prefix = [0; 8];
                prefix.copy_from_slice(&handle.as_bytes()[..8]);
                u64::from_be_bytes(prefix)
            });
            let user_data = self.callbacks.user_data;
            // SAFETY: see `ReaderBridge::on_data_available`.
            self.drain.run(|| unsafe { cb(handle, user_data) });
        }
    }

    fn on_offered_incompatible_qos(&self, policy_id: u32, policy_name: &str) {
        if let Some(cb) = self.callbacks.on_offered_incompatible_qos {
            // Policy names are fixed ASCII identifiers; an interior NUL
            // cannot occur, and would yield an empty name, not a failure.
            let name = CString::new(policy_name).unwrap_or_default();
            let user_data = self.callbacks.user_data;
            // SAFETY: see `ReaderBridge::on_data_available`; `name` outlives
            // the call.
            self.drain
                .run(|| unsafe { cb(policy_id, name.as_ptr(), user_data) });
        }
    }

    fn on_liveliness_lost(&self, status: LivelinessLostStatus) {
        if let Some(cb) = self.callbacks.on_liveliness_lost {
            let c_status = HddsLivelinessLostStatus {
                total_count: status.total_count,
                total_count_change: status.total_count_change,
            };
            let user_data = self.callbacks.user_data;
            // SAFETY: see `ReaderBridge::on_data_available`.
            self.drain.run(|| unsafe { cb(&c_status, user_data) });
        }
    }
}

// =============================================================================
// Installed listeners, by handle
// =============================================================================

/// The C listener installed on each reader handle. The registry lock also
/// serializes every install/remove of one handle with its slot update, so
/// the slot and the registry always name the same bridge. A drain never
/// runs under it: a callback that installs a listener on another reader
/// must not wait behind a removal that waits for that callback.
fn reader_bridges() -> &'static Mutex<HashMap<usize, Arc<ReaderBridge>>> {
    static MAP: OnceLock<Mutex<HashMap<usize, Arc<ReaderBridge>>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// See [`reader_bridges`].
fn writer_bridges() -> &'static Mutex<HashMap<usize, Arc<WriterBridge>>> {
    static MAP: OnceLock<Mutex<HashMap<usize, Arc<WriterBridge>>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Install (`Some`) or remove (`None`) the C listener of `reader`, then wait
/// for the previous one's callbacks. Returns the previous listener's
/// `user_data`, `None` if there was none.
///
/// # Safety
/// `reader` must be a live `DataReader<BytePayload>` handle.
unsafe fn reader_replace(
    reader: *mut HddsDataReader,
    listener: Option<(
        HddsReaderListener,
        HddsOnDataAvailableEx,
        HddsOnDataAvailableNotify,
    )>,
) -> Option<*mut c_void> {
    let reader_ref = &*reader.cast::<DataReader<BytePayload>>();
    let key = reader as usize;
    let previous = {
        let mut map = reader_bridges().lock().unwrap_or_else(|e| e.into_inner());
        match listener {
            Some((callbacks, on_data_available_ex, on_data_available_notify)) => {
                let bridge = Arc::new(ReaderBridge {
                    callbacks,
                    on_data_available_ex,
                    on_data_available_notify,
                    reader: Arc::downgrade(&reader_arc_from_handle(reader)),
                    accepted_condition: Mutex::new(None),
                    forwarding: AtomicBool::new(false),
                    again: AtomicBool::new(false),
                    scope_refusals: AtomicUsize::new(0),
                    drain: CallbackDrain::new(key),
                });
                let mask = bridge.mask();
                let previous = map.insert(key, Arc::clone(&bridge));
                reader_ref.set_listener(
                    Some(bridge as Arc<dyn DataReaderListener<BytePayload>>),
                    mask,
                );
                previous
            }
            None => {
                let previous = map.remove(&key);
                if previous.is_some() {
                    reader_ref.set_listener(None, StatusMask::NONE);
                }
                previous
            }
        }
    };
    previous.map(|previous| {
        previous.drain.deactivate_and_drain();
        previous.callbacks.user_data
    })
}

/// See [`reader_replace`].
///
/// # Safety
/// `writer` must be a live `DataWriter<BytePayload>` handle.
unsafe fn writer_replace(
    writer: *mut HddsDataWriter,
    listener: Option<HddsWriterListener>,
) -> Option<*mut c_void> {
    let writer_ref = &*writer.cast::<DataWriter<BytePayload>>();
    let key = writer as usize;
    let previous = {
        let mut map = writer_bridges().lock().unwrap_or_else(|e| e.into_inner());
        match listener {
            Some(callbacks) => {
                let bridge = Arc::new(WriterBridge {
                    callbacks,
                    drain: CallbackDrain::new(key),
                });
                let mask = bridge.mask();
                let previous = map.insert(key, Arc::clone(&bridge));
                writer_ref.set_listener(
                    Some(bridge as Arc<dyn DataWriterListener<BytePayload>>),
                    mask,
                );
                previous
            }
            None => {
                let previous = map.remove(&key);
                if previous.is_some() {
                    writer_ref.set_listener(None, StatusMask::NONE);
                }
                previous
            }
        }
    };
    previous.map(|previous| {
        previous.drain.deactivate_and_drain();
        previous.callbacks.user_data
    })
}

/// What a destroy path may do with a handle once its listener is detached.
#[must_use]
pub(crate) enum Detached {
    /// Free it: no callback of it runs anywhere.
    Free,
    /// Do NOT free it: this thread is inside one of its callbacks, and the
    /// HDDS code that called back continues on the entity after the
    /// callback returns. The handle is leaked (logged); its listener is
    /// removed all the same.
    Leak,
}

/// Remove the C listener of a reader about to be destroyed, waiting for its
/// callbacks running on other threads. Every destroy path of a reader
/// handle calls this before releasing the handle, so the handle address can
/// never be found in the registry by a later reader allocated at the same
/// address.
///
/// # Safety
/// `reader` must be a live `DataReader<BytePayload>` handle.
pub(crate) unsafe fn reader_listener_detach(reader: *mut HddsDataReader) -> Detached {
    reader_replace(reader, None);
    if entity_running_here(reader as usize) {
        log::error!(
            "[hdds-c] hdds_reader_destroy called from inside one of the reader's own \
             listener callbacks: the reader is leaked, not freed (freeing it there \
             would be a use-after-free); destroy it outside its callbacks"
        );
        Detached::Leak
    } else {
        Detached::Free
    }
}

/// See [`reader_listener_detach`].
///
/// # Safety
/// `writer` must be a live `DataWriter<BytePayload>` handle.
pub(crate) unsafe fn writer_listener_detach(writer: *mut HddsDataWriter) -> Detached {
    writer_replace(writer, None);
    if entity_running_here(writer as usize) {
        log::error!(
            "[hdds-c] hdds_writer_destroy called from inside one of the writer's own \
             listener callbacks: the writer is leaked, not freed (freeing it there \
             would be a use-after-free); destroy it outside its callbacks"
        );
        Detached::Leak
    } else {
        Detached::Free
    }
}

// =============================================================================
// FFI functions
// =============================================================================

/// Install a listener on a DataReader, replacing any installed one.
///
/// The listener struct is copied; the caller may free it on return. The
/// callbacks and `user_data` must stay valid until the listener is removed
/// (`hdds_reader_clear_listener`, a later `hdds_reader_set_listener`, or
/// `hdds_reader_destroy`), each of which returns only once the previous
/// listener's callbacks running on other threads have returned. See the
/// threading contract in the module documentation (callbacks run on HDDS
/// threads, concurrently; NULL callbacks are not reported).
///
/// A BY_SOURCE_TIMESTAMP or TIME_BASED_FILTER reader delivers through
/// `on_data_available_notification`, and this listener's payload callbacks
/// then read the accepted samples themselves. A reader of a Subscriber with
/// GROUP presentation can be read only inside `hdds_subscriber_begin_access` /
/// `hdds_subscriber_end_access`: there the payload callbacks get nothing, and
/// one warning is logged for the listener. Install
/// `hdds_reader_set_listener_notify` on such a reader and read the samples
/// inside the brackets.
///
/// On such a reader the payload callbacks and the application's own reads
/// compete for the same NOT_READ samples. A sample the application reads or
/// takes before the adapter reads it is not handed to the callback. A sample
/// the adapter reads first is marked READ, so an application read that asks
/// for NOT_READ samples no longer returns it (a take still does).
///
/// # Safety
///
/// - `reader` must be a valid pointer returned from `hdds_reader_create` or similar.
/// - `listener` must be a valid pointer to a properly initialized `HddsReaderListener`.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if either pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_set_listener(
    reader: *mut HddsDataReader,
    listener: *const HddsReaderListener,
) -> HddsError {
    if reader.is_null() || listener.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let callbacks = *listener;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = reader_replace(reader, Some((callbacks, None, None)));
    })) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Remove the listener from a DataReader.
///
/// Returns once no callback of the removed listener is running on another
/// thread; no callback of it starts afterwards, so its `user_data` may be
/// freed. Called from inside one of its own callbacks, it does not wait for
/// that callback. Removing when no listener is installed is a no-op.
///
/// # Safety
///
/// - `reader` must be a valid pointer returned from `hdds_reader_create` or similar.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if the pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_clear_listener(reader: *mut HddsDataReader) -> HddsError {
    if reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = reader_replace(reader, None);
    })) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Install a listener on a DataWriter, replacing any installed one.
///
/// Same ownership and threading contract as `hdds_reader_set_listener`.
/// `on_sample_written` is called on the thread that calls
/// `hdds_writer_write`, after the sample is sent.
///
/// # Safety
///
/// - `writer` must be a valid pointer returned from `hdds_writer_create` or similar.
/// - `listener` must be a valid pointer to a properly initialized `HddsWriterListener`.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if either pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_set_listener(
    writer: *mut HddsDataWriter,
    listener: *const HddsWriterListener,
) -> HddsError {
    if writer.is_null() || listener.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let callbacks = *listener;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = writer_replace(writer, Some(callbacks));
    })) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Remove the listener from a DataWriter.
///
/// Same waiting contract as `hdds_reader_clear_listener`.
///
/// # Safety
///
/// - `writer` must be a valid pointer returned from `hdds_writer_create` or similar.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if the pointer is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_clear_listener(writer: *mut HddsDataWriter) -> HddsError {
    if writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = writer_replace(writer, None);
    })) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Install a listener on a DataReader (`listener` NULL: remove it) and
/// report the `user_data` of the listener it replaced.
///
/// Same contract as `hdds_reader_set_listener` / `hdds_reader_clear_listener`;
/// on return, the previous listener's callbacks running on other threads are
/// over. `*out_previous_user_data` (when `out_previous_user_data` is not
/// NULL) receives the replaced listener's `user_data`, or NULL when no
/// listener was installed. This is what lets a language binding free exactly
/// the state of the listener that was replaced, whatever the order in which
/// concurrent installs on one reader reached HDDS; a binding should never
/// install a NULL `user_data`, which this call cannot tell from "none".
///
/// # Safety
///
/// - `reader` must be a valid pointer returned from `hdds_reader_create` or similar.
/// - `listener` must be NULL or a valid pointer to a properly initialized
///   `HddsReaderListener`.
/// - `out_previous_user_data` must be NULL or valid for one pointer write.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if `reader` is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_exchange_listener(
    reader: *mut HddsDataReader,
    listener: *const HddsReaderListener,
    out_previous_user_data: *mut *mut c_void,
) -> HddsError {
    if reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let callbacks = if listener.is_null() {
        None
    } else {
        Some((*listener, None, None))
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader_replace(reader, callbacks)
    })) {
        Ok(previous) => {
            if !out_previous_user_data.is_null() {
                *out_previous_user_data = previous.unwrap_or(std::ptr::null_mut());
            }
            HddsError::HddsOk
        }
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// `hdds_reader_set_listener`, with `on_data_available_ex` called instead
/// of `listener->ON_DATA_AVAILABLE` when it is not NULL: it also receives
/// the encapsulation identifier of the representation the bytes are in
/// (0x0001 XCDR1, 0x0007 XCDR2; see `hdds_reader_take_ex`). A reader that
/// requests XCDR as well as XCDR2 (`hdds_qos_set_data_representation`)
/// needs it to pick the decoder.
///
/// # Safety
///
/// Same as `hdds_reader_set_listener`; `on_data_available_ex` must stay
/// valid until the listener is removed, like the other callbacks.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_set_listener_ex(
    reader: *mut HddsDataReader,
    listener: *const HddsReaderListener,
    on_data_available_ex: HddsOnDataAvailableEx,
) -> HddsError {
    if reader.is_null() || listener.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let callbacks = *listener;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = reader_replace(reader, Some((callbacks, on_data_available_ex, None)));
    })) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// `hdds_reader_set_listener`, with `on_data_available_notify` called for
/// `on_data_available_notification` of the reader (DDS data-available
/// notifications, DDS v1.4 Sec.2.2.4.3.2).
///
/// A BY_SOURCE_TIMESTAMP reader and a TIME_BASED_FILTER reader deliver only
/// that notification: the samples are accepted when the application reads
/// them, or when a held sample's window ends. With `on_data_available_notify`
/// the application reads them itself, with `hdds_reader_take` or
/// `hdds_reader_read`, from the callback, which runs outside every reader
/// lock. Without it, a listener that has `on_data_available` (or
/// `on_data_available_ex`) still receives each accepted sample: the bridge
/// reads them with a NON-CONSUMING read restricted to NOT_READ samples (the
/// DDS read semantics, not take), so each sample is handed over once and
/// stays takeable afterwards. A sample already read is not handed over again.
/// Instance-state transitions carry no payload and are not handed over.
///
/// The data-available status is reported to this listener when either
/// callback is set. When `on_data_available_notify` is set, the payload
/// callbacks are not called on such a reader. On a reader of a GROUP-presentation
/// Subscriber the samples are read inside `hdds_subscriber_begin_access` /
/// `hdds_subscriber_end_access`, which is where this callback is to read them.
///
/// # Safety
///
/// Same as `hdds_reader_set_listener`; `on_data_available_notify` must stay
/// valid until the listener is removed, like the other callbacks.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_set_listener_notify(
    reader: *mut HddsDataReader,
    listener: *const HddsReaderListener,
    on_data_available_notify: HddsOnDataAvailableNotify,
) -> HddsError {
    if reader.is_null() || listener.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let callbacks = *listener;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = reader_replace(reader, Some((callbacks, None, on_data_available_notify)));
    })) {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// `hdds_reader_exchange_listener` with the `on_data_available_ex` of
/// `hdds_reader_set_listener_ex` (ignored when `listener` is NULL, which
/// removes the listener).
///
/// # Safety
///
/// Same as `hdds_reader_exchange_listener`; `on_data_available_ex` must
/// stay valid until the listener is removed.
#[no_mangle]
pub unsafe extern "C" fn hdds_reader_exchange_listener_ex(
    reader: *mut HddsDataReader,
    listener: *const HddsReaderListener,
    on_data_available_ex: HddsOnDataAvailableEx,
    out_previous_user_data: *mut *mut c_void,
) -> HddsError {
    if reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let callbacks = if listener.is_null() {
        None
    } else {
        Some((*listener, on_data_available_ex, None))
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader_replace(reader, callbacks)
    })) {
        Ok(previous) => {
            if !out_previous_user_data.is_null() {
                *out_previous_user_data = previous.unwrap_or(std::ptr::null_mut());
            }
            HddsError::HddsOk
        }
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Writer counterpart of `hdds_reader_exchange_listener`.
///
/// # Safety
///
/// - `writer` must be a valid pointer returned from `hdds_writer_create` or similar.
/// - `listener` must be NULL or a valid pointer to a properly initialized
///   `HddsWriterListener`.
/// - `out_previous_user_data` must be NULL or valid for one pointer write.
///
/// # Returns
///
/// `HddsOk` on success, `HddsInvalidArgument` if `writer` is null.
#[no_mangle]
pub unsafe extern "C" fn hdds_writer_exchange_listener(
    writer: *mut HddsDataWriter,
    listener: *const HddsWriterListener,
    out_previous_user_data: *mut *mut c_void,
) -> HddsError {
    if writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let callbacks = if listener.is_null() {
        None
    } else {
        Some(*listener)
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        writer_replace(writer, callbacks)
    })) {
        Ok(previous) => {
            if !out_previous_user_data.is_null() {
                *out_previous_user_data = previous.unwrap_or(std::ptr::null_mut());
            }
            HddsError::HddsOk
        }
        Err(_) => HddsError::HddsOperationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    #[test]
    fn a_drain_waits_for_a_callback_running_on_another_thread() {
        let drain = Arc::new(CallbackDrain::new(0));
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker = {
            let (drain, entered, release, finished) = (
                Arc::clone(&drain),
                Arc::clone(&entered),
                Arc::clone(&release),
                Arc::clone(&finished),
            );
            std::thread::spawn(move || {
                drain.run(|| {
                    entered.store(true, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                    finished.store(true, Ordering::SeqCst);
                });
            })
        };
        while !entered.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        release.store(true, Ordering::SeqCst);
        drain.deactivate_and_drain();
        assert!(
            finished.load(Ordering::SeqCst),
            "the drain returned while a callback was still running"
        );
        worker.join().unwrap();
        // No callback starts after the drain.
        let ran = AtomicU32::new(0);
        drain.run(|| {
            ran.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_drain_from_inside_its_own_callback_does_not_wait_for_itself() {
        let drain = CallbackDrain::new(0);
        let ran = AtomicU32::new(0);
        drain.run(|| {
            drain.deactivate_and_drain();
            ran.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_panic_inside_a_callback_does_not_escape_the_bridge() {
        let drain = CallbackDrain::new(0);
        drain.run(|| panic!("listener bridge panic (expected by this test)"));
        // Still usable, and drainable (the running count went back down).
        drain.deactivate_and_drain();
    }
}
