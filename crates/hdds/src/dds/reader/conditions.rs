// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ReadCondition / QueryCondition support on the DataReader (DDS v1.4
//! Sec.2.2.2.5.3.5 to 2.2.2.5.3.7, 2.2.2.5.3.10, 2.2.2.5.3.11, 2.2.4.5).
//!
//! # What a condition looks at
//!
//! The Service manages two kinds of samples for a reader: the data
//! samples in its cache, each reporting the CURRENT state of its instance
//! (Sec.2.2.2.5.1.3: ALIVE, or NOT_ALIVE_* once a transition for the
//! instance was received and no later sample revived it), and the
//! instance-state transitions (dispose, unregister) in its dispose queue,
//! each carrying the NOT_ALIVE state it announces and no data. A
//! ReadCondition matches a data sample when the sample's READ/NOT_READ
//! state, its instance's view state and its instance's state are in the
//! three masks, and a transition when its own READ/NOT_READ state (a read
//! variant marks it READ in place), the instance's view state and the
//! announced state are. A QueryCondition additionally needs the sample's data to
//! satisfy the query, so it never matches a transition, which has none.
//!
//! # When it is evaluated
//!
//! On demand, by the reader, from `Condition::get_trigger_value`: the
//! rings are pumped into the cache (without touching DATA_AVAILABLE,
//! which only read and take reset, Sec.2.2.4.2.2) and the cache and the
//! dispose queue are scanned. A WaitSet is woken on every DATA_AVAILABLE
//! raise of the reader and re-evaluates before returning, so it returns
//! the condition only when a match is present at that moment; after a
//! take that removed the last match the next evaluation is false, which
//! is the recomputation Sec.2.2.4.5 describes ("a single take operation
//! can potentially change the trigger_value of several ReadCondition").
//!
//! The pump is a consumer-side access to the reader's rings, which are
//! single-consumer. Every condition accessor (trigger evaluation,
//! `take_w_condition`, `read_w_condition`) runs under the reader's
//! consumer gate, and so does every ring pop of the ordinary accessors
//! (`take`, `read`, ...), so any number of WaitSets and threads may
//! evaluate and take through conditions of one reader while another
//! thread drains it with `take()` (Sec.2.2.4.5 contemplates several
//! WaitSets on one reader; one thread waiting while another takes is
//! the common pattern).

use super::cache::{never, CachedSample, SampleState, ViewState};
use super::runtime::DataReader;
use super::subscriber::DisposeEvent;
use crate::dds::filter::{ContentFilter, FieldValue, FilterEvaluator};
use crate::dds::read_condition::{ConditionBackend, ReadCondition};
use crate::dds::{
    Condition, Error, InstanceHandle, InstanceState, InstanceStateMask, QueryCondition, Result,
    SampleInfo, SampleStateMask, ViewStateMask, DDS,
};
use std::any::Any;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Weak};

/// What a sized condition take or read hands back: the samples it took or
/// read, or the refusal of the first sample it would have taken or read (see
/// `take_w_condition_if` and `read_w_condition_if`).
pub type SizedSamples<T, E> = std::result::Result<Vec<(Option<T>, SampleInfo)>, E>;

/// Turns a sample into the field map a query or a content filter is
/// evaluated against, or `None` when the sample has no field map at all
/// (a raw payload its type descriptor cannot decode).
///
/// `None` is a verdict, not an empty map: a content filter REJECTS the
/// sample and a query never matches it, whatever the expression says
/// (`1 = 1` admits every well-formed sample and no malformed one).
/// `DataReader::create_querycondition` uses `DDS::get_fields`; a binding
/// whose sample type is an opaque byte payload supplies its own (the C
/// binding decodes the bytes with a dynamic type descriptor). Runs under
/// the reader's cache lock: it must not call back into the reader.
pub type FieldExtractor<T> = Arc<dyn Fn(&T) -> Option<HashMap<String, FieldValue>> + Send + Sync>;

/// The reader half of a condition: a weak link back to the reader, and
/// the field extractor for a query.
pub(crate) struct ReaderBackend<T: DDS> {
    reader: Weak<DataReader<T>>,
    extractor: FieldExtractor<T>,
}

impl<T: DDS> ConditionBackend for ReaderBackend<T> {
    fn trigger(&self, condition: &ReadCondition) -> bool {
        match self.reader.upgrade() {
            Some(reader) => reader.condition_trigger(condition, &self.extractor),
            None => false,
        }
    }

    fn reader_addr(&self) -> usize {
        self.reader.as_ptr() as usize
    }

    fn detach(&self, condition_id: u64) {
        if let Some(reader) = self.reader.upgrade() {
            reader
                .get_status_condition()
                .remove_arrival_hook(condition_id);
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn sample_state_bit(state: SampleState) -> SampleStateMask {
    match state {
        SampleState::Read => SampleStateMask::READ,
        SampleState::NotRead => SampleStateMask::NOT_READ,
    }
}

fn view_state_bit(state: ViewState) -> ViewStateMask {
    match state {
        ViewState::New => ViewStateMask::NEW,
        ViewState::NotNew => ViewStateMask::NOT_NEW,
    }
}

fn instance_state_bit(state: InstanceState) -> InstanceStateMask {
    match state {
        InstanceState::Alive => InstanceStateMask::ALIVE,
        InstanceState::NotAliveDisposed => InstanceStateMask::NOT_ALIVE_DISPOSED,
        InstanceState::NotAliveNoWriters => InstanceStateMask::NOT_ALIVE_NO_WRITERS,
    }
}

/// Whether `condition` can match a NOT_ALIVE transition at all: a plain
/// ReadCondition whose instance mask admits a NOT_ALIVE state.
fn admits_transitions(condition: &ReadCondition) -> bool {
    condition.query_evaluator().is_none()
        && (condition
            .get_instance_state_mask()
            .contains(InstanceStateMask::NOT_ALIVE_DISPOSED)
            || condition
                .get_instance_state_mask()
                .contains(InstanceStateMask::NOT_ALIVE_NO_WRITERS))
}

impl<T: DDS> DataReader<T> {
    /// Create a ReadCondition attached to this reader (DDS v1.4
    /// Sec.2.2.2.5.3.5). The condition belongs to the reader: its trigger
    /// is evaluated against this reader's samples (Sec.2.2.4.5) and it is
    /// what `take_w_condition` / `read_w_condition` accept.
    ///
    /// Takes `&Arc<Self>` because the condition keeps a weak link to the
    /// reader and evaluates through it; once the reader is dropped the
    /// trigger is false for good.
    pub fn create_readcondition(
        self: &Arc<Self>,
        sample_states: SampleStateMask,
        view_states: ViewStateMask,
        instance_states: InstanceStateMask,
    ) -> Result<Arc<ReadCondition>> {
        let backend = self.backend(Arc::new(|sample: &T| Some(T::get_fields(sample))));
        let condition = Arc::new(ReadCondition::with_backend(
            sample_states,
            view_states,
            instance_states,
            None,
            Some(Box::new(backend)),
        ));
        let id = condition.condition_id();
        self.register_condition(&condition, id);
        Ok(condition)
    }

    /// Create a QueryCondition attached to this reader (DDS v1.4
    /// Sec.2.2.2.5.3.6). `query_expression` uses the SQL subset of the
    /// `filter` module (its module documentation is the grammar reference)
    /// with `%n` parameters taken from `query_parameters`; the data is
    /// exposed to the query through `DDS::get_fields`, so a type whose
    /// `get_fields` is empty never matches.
    ///
    /// Fails with [`Error::Config`] when the expression does not parse or
    /// the parameters do not fit it (Sec.2.2.2.5.3.6: "In case of failure,
    /// the operation will return a nil value").
    pub fn create_querycondition(
        self: &Arc<Self>,
        sample_states: SampleStateMask,
        view_states: ViewStateMask,
        instance_states: InstanceStateMask,
        query_expression: &str,
        query_parameters: Vec<String>,
    ) -> Result<Arc<QueryCondition>> {
        self.create_querycondition_with_fields(
            sample_states,
            view_states,
            instance_states,
            query_expression,
            query_parameters,
            Arc::new(|sample: &T| Some(T::get_fields(sample))),
        )
    }

    /// [`create_querycondition`](Self::create_querycondition) with an
    /// explicit field extractor in place of `DDS::get_fields`, for sample
    /// types that carry their schema out of band (the C binding's raw
    /// payload decoded through a dynamic type descriptor).
    pub fn create_querycondition_with_fields(
        self: &Arc<Self>,
        sample_states: SampleStateMask,
        view_states: ViewStateMask,
        instance_states: InstanceStateMask,
        query_expression: &str,
        query_parameters: Vec<String>,
        extractor: FieldExtractor<T>,
    ) -> Result<Arc<QueryCondition>> {
        let filter = ContentFilter::with_parameters(query_expression, query_parameters)
            .map_err(|error| Error::Config(format!("invalid query condition: {error}")))?;
        let backend = self.backend(extractor);
        let condition = Arc::new(QueryCondition::with_backend(
            sample_states,
            view_states,
            instance_states,
            filter,
            Some(Box::new(backend)),
        ));
        let id = condition.condition_id();
        self.register_condition(&condition, id);
        Ok(condition)
    }

    /// Delete a ReadCondition or QueryCondition attached to this reader
    /// (DDS v1.4 Sec.2.2.2.5.3.7): it stops being evaluated and stops
    /// waking its WaitSets; its trigger is false from now on. Returns
    /// [`Error::InvalidState`] (PRECONDITION_NOT_MET) when the condition
    /// is not attached to this reader.
    pub fn delete_readcondition(&self, condition: &ReadCondition) -> Result<()> {
        self.own_backend(condition)?;
        condition.mark_detached();
        Ok(())
    }

    /// Take the samples matching `condition` (DDS v1.4 Sec.2.2.2.5.3.11,
    /// "the same semantics as the take operation"): at most `max_samples`
    /// of them leave the reader. Data samples come as `(Some(data), info)`,
    /// the instance-state transitions the condition admits as
    /// `(None, info)` with `info.valid_data == false`, exactly like
    /// [`take_with_info`](Self::take_with_info), and in the same order:
    /// a transition and the data of its writer in the writer's sequence
    /// order, a transition facing another writer's data first. For a
    /// QueryCondition only samples whose data satisfies the query are
    /// taken. An empty result is the NO_DATA case.
    ///
    /// The view state is one snapshot per instance across the returned
    /// collection (Sec.2.2.2.5.1.8): the instances are recorded as
    /// accessed once the collection is complete.
    ///
    /// The condition must be attached to this reader, else
    /// [`Error::InvalidState`] (PRECONDITION_NOT_MET). A `&QueryCondition`
    /// is accepted through its `Deref`.
    pub fn take_w_condition(
        &self,
        condition: &ReadCondition,
        max_samples: usize,
    ) -> Result<Vec<(Option<T>, SampleInfo)>> {
        let unconditional = |_: &T| Ok::<(), Infallible>(());
        Ok(never(self.take_w_condition_if(
            condition,
            max_samples,
            unconditional,
        )?))
    }

    /// [`take_w_condition`](Self::take_w_condition), unless `fits` refuses
    /// the data of a sample it would take. Samples are taken in order, up to
    /// `max_samples`, and the first refusal stops the take there; the refused
    /// sample is not removed. A refusal before anything was taken is
    /// `Ok(Err(refusal))`. After samples were taken they are returned as a
    /// PREFIX (`Ok(Ok(prefix))`) and the refusal is NOT reported: the next call
    /// starts at the refused sample. A caller that cannot tell a prefix from
    /// the end of the data must use `max_samples == 1`, which is what the C
    /// ABI does. A later take returns the head of the reader, normally the
    /// refused sample (other takers and KEEP_LAST eviction can change that).
    ///
    /// Doc-hidden: the C ABI's sized condition take is its caller.
    #[doc(hidden)]
    pub fn take_w_condition_if<E>(
        &self,
        condition: &ReadCondition,
        max_samples: usize,
        fits: impl Fn(&T) -> std::result::Result<(), E>,
    ) -> Result<SizedSamples<T, E>> {
        let backend = self.own_backend(condition)?;
        self.check_requested_deadline();
        // Declared before `_gate`, so it drops after: a notice the pump
        // raises while the gate is held (a mid-merge SAMPLE_LOST, for
        // one) is held for this thread and told only once `_gate` has
        // released the consumer gate, never while this call could still
        // deadlock a listener that re-enters it (`notices::Delivering`).
        let _delivering = super::notices::Delivering::enter();
        // One ring consumer at a time, across the condition accessors of
        // this reader (several WaitSets, Sec.2.2.4.5) and its ordinary
        // accessors on other threads; see `consumer_gate`.
        let _gate = self.consume()?;
        self.pump_pending_gated()?;
        if self.qos().presentation.ordered_access {
            self.ordered_reconcile();
        }

        let query = condition.query_evaluator();
        let extractor = &backend.extractor;
        let cache = self.cache();
        let queue = self.dispose_events();
        let carries_transitions = admits_transitions(condition);
        let by_source = cache.instances().by_source_timestamp();
        let mut matches = |sample: &CachedSample<T>, view: ViewState, state: InstanceState| {
            Self::cached_matches(condition, query, extractor, sample, view, state)
                && (!self.qos().presentation.ordered_access || self.ordered_allows(sample))
        };
        let mut transition_matches = |event: &DisposeEvent| {
            Self::transition_matches(condition, cache, event)
                && self.ordered_transition_allows(event)
        };

        let mut out: Vec<(Option<T>, SampleInfo)> = Vec::new();
        let mut accessed: Vec<InstanceHandle> = Vec::new();
        let mut refusal = None;
        while out.len() < max_samples {
            if carries_transitions && !queue.is_empty() {
                let pending = cache.pending_matching_origins_from(0, &mut matches);
                let by_source = if by_source {
                    cache.pending_source_order_from(0, &mut matches)
                } else {
                    Vec::new()
                };
                if let Some(event) = queue.pop_first_matching_if_before(
                    &pending,
                    &by_source,
                    &mut transition_matches,
                ) {
                    let handle = InstanceHandle::new(event.key_hash);
                    let info = Self::transition_info(&event, cache.view_state_of(handle));
                    accessed.push(handle);
                    out.push((None, info));
                    continue;
                }
            }
            match cache.take_first_matching_if(&mut matches, &fits) {
                Ok(Some(sample)) => {
                    if self.qos().presentation.ordered_access {
                        self.ordered_accessed(&sample);
                    }
                    accessed.push(sample.instance_handle);
                    let (data, info) = sample.into_data_and_info();
                    out.push((Some(data), info));
                }
                Ok(None) => break,
                Err(error) => {
                    // Stop here and fall through to the common tail; the
                    // refusal is reported below only when nothing was taken.
                    refusal = Some(error);
                    break;
                }
            }
        }
        self.stamp_collection_ranks(&mut out);
        for handle in accessed {
            cache.note_viewed(handle);
        }

        // A take variant: reset DATA_AVAILABLE once the reader is observed
        // idle (Sec.2.2.4.2.2), with the same re-check the other takes use.
        // Transitions this condition cannot carry are announced, as
        // `take()` does, so they do not keep a StatusCondition raised.
        if self.rings_idle() && cache.is_empty() {
            self.clear_data_available_after_take(!carries_transitions);
        }
        match refusal {
            Some(refused) if out.is_empty() => Ok(Err(refused)),
            _ => Ok(Ok(out)),
        }
    }

    /// Exact trigger evaluation (Sec.2.2.4.5), from `get_trigger_value`.
    ///
    /// The wake words are read SeqCst first: that load is the read half of
    /// the store-buffering pair against a producer's raise (the producer
    /// stores its word, then reads the hook counts; a WaitSet attaching
    /// stores its hook count, then lands here), and when it observes a
    /// raise it synchronizes-with the producer's push, so the pump below
    /// sees the pushed entry. A zero means no producer has stored since
    /// the last clear, and the rings were observed empty by that clear;
    /// the cache is scanned regardless, since a read leaves samples in it
    /// with the words settled.
    pub(super) fn condition_trigger(
        &self,
        condition: &ReadCondition,
        extractor: &FieldExtractor<T>,
    ) -> bool {
        // See `take_w_condition`'s `_delivering`: declared before `_gate`,
        // so a notice the pump raises while the gate is held is told only
        // after it releases.
        let _delivering = super::notices::Delivering::enter();
        let _gate = self.gate();
        if self.get_status_condition().wake_words().any_raised() {
            if let Err(error) = self.pump_pending_gated() {
                log::debug!(
                    "[reader] condition evaluation: pump failed on topic='{}': {error:?}",
                    self.topic_name()
                );
            }
        }
        if self.qos().presentation.ordered_access {
            self.ordered_reconcile();
        }

        let query = condition.query_evaluator();
        if self.cache().any_matching(|sample, view, state| {
            Self::cached_matches(condition, query, extractor, sample, view, state)
                && (!self.qos().presentation.ordered_access || self.ordered_allows(sample))
        }) {
            return true;
        }

        if !admits_transitions(condition) {
            return false;
        }
        let cache = self.cache();
        self.dispose_events().any_matching(|event| {
            Self::transition_matches(condition, cache, event)
                && self.ordered_transition_allows(event)
        })
    }

    fn cached_matches(
        condition: &ReadCondition,
        query: Option<&FilterEvaluator>,
        extractor: &FieldExtractor<T>,
        sample: &CachedSample<T>,
        view: ViewState,
        state: InstanceState,
    ) -> bool {
        if !condition
            .get_sample_state_mask()
            .contains(sample_state_bit(sample.sample_state()))
            || !condition
                .get_view_state_mask()
                .contains(view_state_bit(view))
            || !condition
                .get_instance_state_mask()
                .contains(instance_state_bit(state))
        {
            return false;
        }
        let Some(evaluator) = query else {
            return true;
        };
        // No field map (the payload does not decode): no query matches it.
        let Some(fields) = extractor(&sample.data) else {
            return false;
        };
        match evaluator.matches(&fields) {
            Ok(matched) => matched,
            Err(error) => {
                // An unknown field or a type mismatch is a query that
                // this sample cannot satisfy, not a fault of the reader.
                log::trace!("[reader] query condition evaluation error: {error}");
                false
            }
        }
    }

    fn transition_matches(
        condition: &ReadCondition,
        cache: &super::cache::SampleCache<T>,
        event: &DisposeEvent,
    ) -> bool {
        let handle = InstanceHandle::new(event.key_hash);
        let state = Self::transition_instance_state(event.kind);
        let sample_state = if event.read {
            SampleState::Read
        } else {
            SampleState::NotRead
        };
        condition
            .get_sample_state_mask()
            .contains(sample_state_bit(sample_state))
            && condition
                .get_view_state_mask()
                .contains(view_state_bit(cache.view_state_of(handle)))
            && condition
                .get_instance_state_mask()
                .contains(instance_state_bit(state))
    }

    fn backend(self: &Arc<Self>, extractor: FieldExtractor<T>) -> ReaderBackend<T> {
        ReaderBackend {
            reader: Arc::downgrade(self),
            extractor,
        }
    }

    /// Hand the condition its arrival hook on this reader's
    /// StatusCondition, so every DATA_AVAILABLE raise wakes its WaitSets.
    fn register_condition<C>(&self, condition: &Arc<C>, id: u64)
    where
        C: crate::dds::condition::ArrivalHook + 'static,
    {
        let weak: Weak<C> = Arc::downgrade(condition);
        let hook: Weak<dyn crate::dds::condition::ArrivalHook> = weak;
        self.get_status_condition().add_arrival_hook(id, hook);
    }

    /// The typed backend of a condition that belongs to THIS reader;
    /// [`Error::InvalidState`] otherwise (PRECONDITION_NOT_MET,
    /// Sec.2.2.2.5.3.10/11 and 2.2.2.5.3.7).
    fn own_backend<'a>(&self, condition: &'a ReadCondition) -> Result<&'a ReaderBackend<T>> {
        if !condition.is_attached() {
            return Err(Error::InvalidState(
                "ReadCondition is not attached to a DataReader".to_string(),
            ));
        }
        let backend = condition.backend().ok_or_else(|| {
            Error::InvalidState("ReadCondition is not attached to a DataReader".to_string())
        })?;
        if backend.reader_addr() != self as *const Self as usize {
            return Err(Error::InvalidState(
                "ReadCondition belongs to another DataReader".to_string(),
            ));
        }
        backend
            .as_any()
            .downcast_ref::<ReaderBackend<T>>()
            .ok_or_else(|| {
                Error::InvalidState(
                    "ReadCondition belongs to a DataReader of another type".to_string(),
                )
            })
    }
}

impl<T: DDS + Clone> DataReader<T> {
    /// Read the samples matching `condition` without removing them (DDS
    /// v1.4 Sec.2.2.2.5.3.10, "the same semantics as the read operation"):
    /// at most `max_samples` samples, each marked READ afterwards (the
    /// returned `info.sample_state` is the state before this call). The
    /// same samples, in the same order and with the same view-state
    /// snapshot as [`take_w_condition`](Self::take_w_condition): data
    /// samples as `(Some(data), info)` and the instance-state transitions
    /// the condition admits as `(None, info)` with `info.valid_data ==
    /// false`, all left in the reader. An empty result is the NO_DATA case.
    ///
    /// Same attachment precondition as `take_w_condition`.
    pub fn read_w_condition(
        &self,
        condition: &ReadCondition,
        max_samples: usize,
    ) -> Result<Vec<(Option<T>, SampleInfo)>> {
        let unconditional = |_: &T| Ok::<(), Infallible>(());
        Ok(never(self.read_w_condition_if(
            condition,
            max_samples,
            unconditional,
        )?))
    }

    /// [`read_w_condition`](Self::read_w_condition), unless `fits` refuses
    /// the data of a sample it would read. Reads walk in order, and the first
    /// refusal stops the walk at that sample: it is not copied and not marked
    /// READ, so it is the first sample the next read sees. A refusal before
    /// anything was read is `Ok(Err(refusal))`; after samples were read they
    /// are returned and the refusal is left for the next call.
    ///
    /// Doc-hidden: the C ABI's sized condition read is its caller.
    #[doc(hidden)]
    pub fn read_w_condition_if<E>(
        &self,
        condition: &ReadCondition,
        max_samples: usize,
        fits: impl Fn(&T) -> std::result::Result<(), E>,
    ) -> Result<SizedSamples<T, E>> {
        let backend = self.own_backend(condition)?;
        self.check_requested_deadline();
        // See `take_w_condition`'s `_delivering`.
        let _delivering = super::notices::Delivering::enter();
        let _gate = self.consume()?;
        self.pump_pending_gated()?;
        if self.qos().presentation.ordered_access {
            self.ordered_reconcile();
        }

        let query = condition.query_evaluator();
        let extractor = &backend.extractor;
        let cache = self.cache();
        let queue = self.dispose_events();
        let carries_transitions = admits_transitions(condition);
        let by_source = cache.instances().by_source_timestamp();
        let mut matches = |sample: &CachedSample<T>, view: ViewState, state: InstanceState| {
            Self::cached_matches(condition, query, extractor, sample, view, state)
                && (!self.qos().presentation.ordered_access || self.ordered_allows(sample))
        };
        let mut transition_matches = |event: &DisposeEvent| {
            Self::transition_matches(condition, cache, event)
                && self.ordered_transition_allows(event)
        };

        let mut out: Vec<(Option<T>, SampleInfo)> = Vec::new();
        let mut accessed: Vec<InstanceHandle> = Vec::new();
        let mut refusal = None;
        // Read walks forward through both stores: what it already
        // returned is READ, and a NOT_READ predicate must not see it
        // again, an ANY one must not return it twice.
        let mut data_from = 0;
        let mut event_from = 0;
        while out.len() < max_samples {
            if carries_transitions && !queue.is_empty() {
                let pending = cache.pending_matching_origins_from(data_from, &mut matches);
                // Only what this read has not walked past yet.
                let by_source = if by_source {
                    cache.pending_source_order_from(data_from, &mut matches)
                } else {
                    Vec::new()
                };
                if let Some((next, event)) = queue.read_first_matching_from_if_before(
                    event_from,
                    &pending,
                    &by_source,
                    &mut transition_matches,
                ) {
                    event_from = next;
                    let handle = InstanceHandle::new(event.key_hash);
                    let info = Self::transition_info(&event, cache.view_state_of(handle));
                    accessed.push(handle);
                    out.push((None, info));
                    continue;
                }
            }
            match cache.read_first_matching_from_if(data_from, &mut matches, &fits) {
                Ok(Some((next, sample))) => {
                    data_from = next;
                    if self.qos().presentation.ordered_access {
                        self.ordered_accessed(&sample);
                    }
                    accessed.push(sample.instance_handle);
                    let (data, info) = sample.into_data_and_info();
                    out.push((Some(data), info));
                }
                Ok(None) => break,
                Err(error) => {
                    // Stop here and fall through to the common tail; the
                    // refusal is reported below only when nothing was taken.
                    refusal = Some(error);
                    break;
                }
            }
        }
        self.stamp_collection_ranks(&mut out);
        for handle in accessed {
            cache.note_viewed(handle);
        }
        match refusal {
            Some(refused) if out.is_empty() => Ok(Err(refused)),
            _ => Ok(Ok(out)),
        }
    }
}
