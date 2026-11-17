// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ReadCondition and QueryCondition (DDS v1.4 Sec.2.2.2.5.8 and 2.2.2.5.9).
//!
//! A ReadCondition belongs to one DataReader and is created through
//! `DataReader::create_readcondition` (Sec.2.2.2.5.3.5); a QueryCondition
//! through `DataReader::create_querycondition` (Sec.2.2.2.5.3.6). Its
//! trigger is "the reader holds at least one sample whose sample, view and
//! instance states are in the condition's masks, and, for a
//! QueryCondition, whose data satisfies the query" (Sec.2.2.4.5). The
//! reader evaluates that on demand: `get_trigger_value` asks the reader
//! to move whatever its rings hold into its cache and scans it, so the
//! value returned is exact at the moment of the call and never a guess
//! made at arrival time. A WaitSet blocked on the condition is woken on
//! every DATA_AVAILABLE raise of the reader (an arrival hook on the
//! reader's StatusCondition) and re-evaluates before returning, so it
//! returns to the application only when a matching sample is present.
//!
//! The evaluation is an access to the reader's rings; the reader
//! serializes it with every other consumer of them, the condition
//! accessors and the ordinary `take`/`read` path alike, so several
//! WaitSets on different threads may hold conditions of one reader
//! while another thread drains it.

use super::condition::{ArrivalHook, Condition};
use super::filter::{ContentFilter, FilterError, FilterEvaluator};
use crate::core::rt::waitset::WaitsetSignal;
use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Sample state mask for ReadCondition
///
/// Per DDS v1.4 spec section 2.2.2.5.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleStateMask(u32);

impl SampleStateMask {
    /// Sample has been read
    pub const READ: SampleStateMask = SampleStateMask(1 << 0);

    /// Sample has not been read
    pub const NOT_READ: SampleStateMask = SampleStateMask(1 << 1);

    /// Any sample state
    pub const ANY: SampleStateMask = SampleStateMask(Self::READ.0 | Self::NOT_READ.0);

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        SampleStateMask(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if contains state
    pub const fn contains(&self, other: SampleStateMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for SampleStateMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        SampleStateMask(self.0 | rhs.0)
    }
}

/// View state mask for ReadCondition
///
/// Per DDS v1.4 spec section 2.2.2.5.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewStateMask(u32);

impl ViewStateMask {
    /// Instance is new (first sample)
    pub const NEW: ViewStateMask = ViewStateMask(1 << 0);

    /// Instance is not new (subsequent samples)
    pub const NOT_NEW: ViewStateMask = ViewStateMask(1 << 1);

    /// Any view state
    pub const ANY: ViewStateMask = ViewStateMask(Self::NEW.0 | Self::NOT_NEW.0);

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        ViewStateMask(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if contains state
    pub const fn contains(&self, other: ViewStateMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for ViewStateMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        ViewStateMask(self.0 | rhs.0)
    }
}

/// Instance state mask for ReadCondition
///
/// Per DDS v1.4 spec section 2.2.2.5.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceStateMask(u32);

impl InstanceStateMask {
    /// Instance is alive (writer exists)
    pub const ALIVE: InstanceStateMask = InstanceStateMask(1 << 0);

    /// Instance writer has disposed
    pub const NOT_ALIVE_DISPOSED: InstanceStateMask = InstanceStateMask(1 << 1);

    /// Instance writer has lost liveliness
    pub const NOT_ALIVE_NO_WRITERS: InstanceStateMask = InstanceStateMask(1 << 2);

    /// Any instance state
    pub const ANY: InstanceStateMask = InstanceStateMask(
        Self::ALIVE.0 | Self::NOT_ALIVE_DISPOSED.0 | Self::NOT_ALIVE_NO_WRITERS.0,
    );

    /// Create from raw bits
    pub const fn from_bits(bits: u32) -> Self {
        InstanceStateMask(bits)
    }

    /// Get raw bits
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if contains state
    pub const fn contains(&self, other: InstanceStateMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for InstanceStateMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        InstanceStateMask(self.0 | rhs.0)
    }
}

/// The reader side of a ReadCondition: what `get_trigger_value` calls
/// into. Implemented per reader type in `reader::conditions`, held
/// type-erased here so the condition itself is not generic.
pub(crate) trait ConditionBackend: Send + Sync {
    /// Evaluate the trigger against the reader's current samples.
    fn trigger(&self, condition: &ReadCondition) -> bool;

    /// Address of the owning reader, so `take_w_condition` can refuse a
    /// condition attached to another reader (Sec.2.2.2.5.3.11:
    /// PRECONDITION_NOT_MET).
    fn reader_addr(&self) -> usize;

    /// Sever the link to the reader (`delete_readcondition`, and the
    /// condition's drop): the reader forgets the arrival hook registered
    /// under `condition_id`.
    fn detach(&self, condition_id: u64);

    /// Downcast support: the reader recovers its typed backend.
    fn as_any(&self) -> &dyn Any;
}

/// ReadCondition - condition based on DataReader sample states
///
/// Per DDS v1.4 spec section 2.2.2.5.8, and 2.2.4.5 for the trigger:
/// "the trigger_value of the ReadCondition is tied to the presence of at
/// least a sample managed by the Service with SampleState, ViewState, and
/// InstanceState matching those of the ReadCondition."
///
/// Created with `DataReader::create_readcondition`; a condition built
/// with [`ReadCondition::new`] is bound to no reader and never triggers.
pub struct ReadCondition {
    /// Unique identifier
    id: u64,

    /// Sample state mask
    sample_state_mask: SampleStateMask,

    /// View state mask
    view_state_mask: ViewStateMask,

    /// Instance state mask
    instance_state_mask: InstanceStateMask,

    /// The query of a QueryCondition (Sec.2.2.2.5.9); `None` for a plain
    /// ReadCondition. The evaluator shares the filter's parameters, so
    /// `set_query_parameters` is seen by the next evaluation.
    query: Option<(ContentFilter, FilterEvaluator)>,

    /// The reader-side evaluation; `None` for a detached condition.
    backend: Option<Box<dyn ConditionBackend>>,

    /// False once `delete_readcondition` ran: the condition no longer
    /// belongs to its reader and its trigger is false for good.
    attached: AtomicBool,

    /// Waitset hooks to notify on data arrival
    waitset_signals: Mutex<Vec<ReadConditionHook>>,

    /// `waitset_signals.len()`, so an arrival on a condition nobody waits
    /// on costs one load. SeqCst on the paths that can raise or attach,
    /// for the store-buffering pair documented on
    /// `StatusCondition::waitset_hook_count`.
    waitset_hook_count: AtomicUsize,
}

impl ReadCondition {
    /// Create a ReadCondition bound to no DataReader.
    ///
    /// Such a condition carries its masks but has no samples to look at:
    /// its trigger is always false and `take_w_condition` refuses it
    /// (Sec.2.2.2.5.3.11, PRECONDITION_NOT_MET). Use
    /// `DataReader::create_readcondition` for a working condition.
    #[deprecated(
        since = "1.5.0",
        note = "a ReadCondition belongs to a DataReader; use DataReader::create_readcondition"
    )]
    pub fn new(
        sample_state_mask: SampleStateMask,
        view_state_mask: ViewStateMask,
        instance_state_mask: InstanceStateMask,
    ) -> Self {
        Self::with_backend(
            sample_state_mask,
            view_state_mask,
            instance_state_mask,
            None,
            None,
        )
    }

    /// Full constructor used by the reader (`reader::conditions`).
    pub(crate) fn with_backend(
        sample_state_mask: SampleStateMask,
        view_state_mask: ViewStateMask,
        instance_state_mask: InstanceStateMask,
        query: Option<ContentFilter>,
        backend: Option<Box<dyn ConditionBackend>>,
    ) -> Self {
        use std::sync::atomic::AtomicU64;
        static NEXT_ID: AtomicU64 = AtomicU64::new(2_000_000);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        let query = query.map(|filter| {
            let evaluator = filter.evaluator();
            (filter, evaluator)
        });
        let attached = backend.is_some();

        Self {
            id,
            sample_state_mask,
            view_state_mask,
            instance_state_mask,
            query,
            backend,
            attached: AtomicBool::new(attached),
            waitset_signals: Mutex::new(Vec::new()),
            waitset_hook_count: AtomicUsize::new(0),
        }
    }

    /// Get the sample state mask
    pub fn get_sample_state_mask(&self) -> SampleStateMask {
        self.sample_state_mask
    }

    /// Get the view state mask
    pub fn get_view_state_mask(&self) -> ViewStateMask {
        self.view_state_mask
    }

    /// Get the instance state mask
    pub fn get_instance_state_mask(&self) -> InstanceStateMask {
        self.instance_state_mask
    }

    /// Whether this condition still belongs to its DataReader: created by
    /// the reader and not yet deleted with `delete_readcondition`.
    pub fn is_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire) && self.backend.is_some()
    }

    /// The query evaluator of a QueryCondition, `None` for a plain
    /// ReadCondition.
    pub(crate) fn query_evaluator(&self) -> Option<&FilterEvaluator> {
        self.query.as_ref().map(|(_, evaluator)| evaluator)
    }

    /// The typed backend, for the reader's `take_w_condition`.
    pub(crate) fn backend(&self) -> Option<&dyn ConditionBackend> {
        self.backend.as_deref()
    }

    /// Detach this condition from its DataReader: the effect of
    /// `DataReader::delete_readcondition` (Sec.2.2.2.5.3.7) for a caller
    /// that no longer holds the reader, such as a binding deleting a
    /// handle. The condition stops being evaluated and stops waking its
    /// WaitSets; its trigger is false from now on, even while a WaitSet
    /// still references it. Idempotent.
    pub fn detach(&self) {
        self.mark_detached();
    }

    /// `delete_readcondition` (Sec.2.2.2.5.3.7): the condition stops
    /// belonging to its reader. Idempotent.
    pub(crate) fn mark_detached(&self) {
        self.attached.store(false, Ordering::Release);
        if let Some(backend) = &self.backend {
            backend.detach(self.id);
        }
    }

    /// Signal the attached WaitSets. Collect first, signal after the guard
    /// is gone: `signal()` is trait code reached through a public trait, so
    /// a hook that called back into this condition would deadlock on this
    /// non-reentrant mutex, and the in-house implementation writes to an
    /// eventfd, which is a syscall nobody should hold a lock across.
    fn notify_waitsets(&self) {
        if self.waitset_hook_count.load(Ordering::SeqCst) == 0 {
            return;
        }

        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] ReadCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        let mut live = Vec::with_capacity(hooks.len());
        hooks.retain(|hook| match hook.signal.upgrade() {
            Some(signal) => {
                live.push(signal);
                true
            }
            None => false,
        });
        self.waitset_hook_count.store(hooks.len(), Ordering::SeqCst);
        drop(hooks);

        for signal in live {
            signal.signal();
        }
    }
}

impl Drop for ReadCondition {
    /// The reader holds only a weak reference to its conditions, so a
    /// dropped condition would be pruned lazily; detaching here takes the
    /// hook out at once and keeps the producer's fast path at one load.
    fn drop(&mut self) {
        self.mark_detached();
    }
}

impl ArrivalHook for ReadCondition {
    /// The reader made data available: wake the attached WaitSets, which
    /// re-evaluate this condition through `get_trigger_value` before
    /// returning it. No evaluation here: this runs on the producer's
    /// thread, and the evaluation is a consumer-side access to the reader.
    fn on_data_arrival(&self) {
        self.notify_waitsets();
    }
}

struct ReadConditionHook {
    id: u64,
    signal: Weak<dyn WaitsetSignal>,
}

impl Condition for ReadCondition {
    /// Exact at the time of the call (Sec.2.2.4.5): asks the reader to
    /// pump its rings and scan its samples. False for a detached
    /// condition or once the reader is gone.
    fn get_trigger_value(&self) -> bool {
        if !self.attached.load(Ordering::Acquire) {
            return false;
        }
        match &self.backend {
            Some(backend) => backend.trigger(self),
            None => false,
        }
    }

    fn condition_id(&self) -> u64 {
        self.id
    }

    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] ReadCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        hooks.retain(|hook| hook.signal.upgrade().is_some());
        hooks.push(ReadConditionHook {
            id: signal.id(),
            signal: Arc::downgrade(&signal),
        });
        // The store half of the pair against a producer's raise
        // (`StatusCondition::signal_data_available` reads the arrival
        // hook count after its raise; the evaluation below reads the
        // wake words SeqCst before it reads the rings).
        self.waitset_hook_count.store(hooks.len(), Ordering::SeqCst);
        // Same rule as notify_waitsets: never call into the signal with the
        // hook list locked.
        drop(hooks);

        if self.get_trigger_value() {
            signal.signal();
        }
    }

    fn remove_waitset_signal(&self, signal_id: u64) {
        if let Ok(mut hooks) = self.waitset_signals.lock() {
            hooks.retain(|hook| hook.id != signal_id);
            self.waitset_hook_count
                .store(hooks.len(), Ordering::Release);
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// QueryCondition - ReadCondition with SQL-like query expression
///
/// Per DDS v1.4 spec section 2.2.2.5.9: "QueryCondition objects are
/// specialized ReadCondition objects that allow the application to also
/// specify a filter on the locally available data." The expression is the
/// subset of the DDS SQL grammar the `filter` module parses (its module
/// documentation is the reference); `%n` parameters are substituted from
/// the parameter list and can be changed with `set_query_parameters`.
///
/// Derefs to its [`ReadCondition`], so every reader operation taking a
/// `&ReadCondition` accepts a `&QueryCondition`.
pub struct QueryCondition {
    /// Base ReadCondition, carrying the query
    base: ReadCondition,
}

impl QueryCondition {
    /// Create a QueryCondition bound to no DataReader (see
    /// [`ReadCondition::new`]); use `DataReader::create_querycondition`.
    ///
    /// Returns `None` when the expression does not parse or the
    /// parameters do not fit it.
    #[deprecated(
        since = "1.5.0",
        note = "a QueryCondition belongs to a DataReader; use DataReader::create_querycondition"
    )]
    pub fn new(
        sample_state_mask: SampleStateMask,
        view_state_mask: ViewStateMask,
        instance_state_mask: InstanceStateMask,
        query_expression: String,
        query_parameters: Vec<String>,
    ) -> Option<Self> {
        let filter = ContentFilter::with_parameters(&query_expression, query_parameters).ok()?;
        Some(Self::with_backend(
            sample_state_mask,
            view_state_mask,
            instance_state_mask,
            filter,
            None,
        ))
    }

    /// Full constructor used by the reader (`reader::conditions`).
    pub(crate) fn with_backend(
        sample_state_mask: SampleStateMask,
        view_state_mask: ViewStateMask,
        instance_state_mask: InstanceStateMask,
        filter: ContentFilter,
        backend: Option<Box<dyn ConditionBackend>>,
    ) -> Self {
        Self {
            base: ReadCondition::with_backend(
                sample_state_mask,
                view_state_mask,
                instance_state_mask,
                Some(filter),
                backend,
            ),
        }
    }

    fn filter(&self) -> &ContentFilter {
        // A QueryCondition is only ever built with a query.
        match &self.base.query {
            Some((filter, _)) => filter,
            None => unreachable!("QueryCondition built without a query"),
        }
    }

    /// Get the query expression (Sec.2.2.2.5.9.1)
    pub fn get_query_expression(&self) -> &str {
        self.filter().expression()
    }

    /// Get the query parameters (Sec.2.2.2.5.9.2): those of the last
    /// successful `set_query_parameters`, else the creation ones.
    pub fn get_query_parameters(&self) -> Vec<String> {
        self.filter().parameters()
    }

    /// Set new query parameters (Sec.2.2.2.5.9.3). A parameter list that
    /// does not fit the expression is rejected and the previous parameters
    /// stay in force.
    ///
    /// New parameters can turn a sample the reader already holds into a
    /// match, which changes the trigger (Sec.2.2.4.5) without any arrival,
    /// so the attached WaitSets are signalled here exactly as an arrival
    /// signals them; they re-evaluate before returning. The signal runs
    /// after `try_set_parameters` has released the parameter lock.
    pub fn try_set_query_parameters(&self, parameters: Vec<String>) -> Result<(), FilterError> {
        self.filter().try_set_parameters(parameters)?;
        self.base.on_data_arrival();
        Ok(())
    }

    /// [`try_set_query_parameters`](Self::try_set_query_parameters) that
    /// logs a rejected list instead of returning it.
    pub fn set_query_parameters(&self, parameters: Vec<String>) {
        if let Err(error) = self.try_set_query_parameters(parameters) {
            log::warn!("QueryCondition parameter update rejected: {error}");
        }
    }
}

impl std::ops::Deref for QueryCondition {
    type Target = ReadCondition;

    fn deref(&self) -> &ReadCondition {
        &self.base
    }
}

impl ArrivalHook for QueryCondition {
    fn on_data_arrival(&self) {
        self.base.on_data_arrival();
    }
}

impl Condition for QueryCondition {
    fn get_trigger_value(&self) -> bool {
        self.base.get_trigger_value()
    }

    fn condition_id(&self) -> u64 {
        self.base.condition_id()
    }

    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
        self.base.add_waitset_signal(signal);
    }

    fn remove_waitset_signal(&self, signal_id: u64) {
        self.base.remove_waitset_signal(signal_id);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests;
