// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Conditions - event notification predicates for WaitSets
//!
//! Per DDS v1.4 specification, Conditions are predicates that can be attached
//! to WaitSets to enable event-driven blocking wait patterns.
//!

use crate::core::rt::waitset::WaitsetSignal;
use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Condition trait - base interface for all DDS conditions
///
/// A Condition is a boolean-valued predicate that can be evaluated.
/// Conditions are attached to WaitSets to enable blocking waits.
pub trait Condition: Send + Sync {
    /// Get the current trigger value of this condition
    ///
    /// Returns `true` if the condition is satisfied, `false` otherwise.
    fn get_trigger_value(&self) -> bool;

    /// Get a unique identifier for this condition (for comparison)
    fn condition_id(&self) -> u64;

    /// Register a waitset signal so this condition can wake blocked waiters.
    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>);

    /// Remove a previously registered waitset signal.
    fn remove_waitset_signal(&self, signal_id: u64);

    /// Downcast support for dynamic condition handling.
    fn as_any(&self) -> &dyn Any;
}

/// Status mask bits for StatusCondition
///
/// Per DDS v1.4 spec section 2.2.4.1 - Communication Status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusMask(u32);

impl StatusMask {
    /// No status enabled
    pub const NONE: StatusMask = StatusMask(0);

    /// All statuses enabled
    pub const ALL: StatusMask = StatusMask(0xFFFF_FFFF);

    /// Data available to read (DataReader)
    pub const DATA_AVAILABLE: StatusMask = StatusMask(1 << 0);

    /// Sample lost (DataReader)
    pub const SAMPLE_LOST: StatusMask = StatusMask(1 << 1);

    /// Sample rejected (DataReader)
    pub const SAMPLE_REJECTED: StatusMask = StatusMask(1 << 2);

    /// Liveliness changed (DataReader)
    pub const LIVELINESS_CHANGED: StatusMask = StatusMask(1 << 3);

    /// Requested deadline missed (DataReader)
    pub const REQUESTED_DEADLINE_MISSED: StatusMask = StatusMask(1 << 4);

    /// Requested incompatible QoS (DataReader)
    pub const REQUESTED_INCOMPATIBLE_QOS: StatusMask = StatusMask(1 << 5);

    /// Subscription matched (DataReader)
    pub const SUBSCRIPTION_MATCHED: StatusMask = StatusMask(1 << 6);

    /// Liveliness lost (DataWriter)
    pub const LIVELINESS_LOST: StatusMask = StatusMask(1 << 7);

    /// Offered deadline missed (DataWriter)
    pub const OFFERED_DEADLINE_MISSED: StatusMask = StatusMask(1 << 8);

    /// Offered incompatible QoS (DataWriter)
    pub const OFFERED_INCOMPATIBLE_QOS: StatusMask = StatusMask(1 << 9);

    /// Publication matched (DataWriter)
    pub const PUBLICATION_MATCHED: StatusMask = StatusMask(1 << 10);

    /// Inconsistent topic: a remote endpoint on the same topic announced
    /// an incompatible type (DDS v1.4 Sec.2.2.4.1). Reported to a reader's
    /// or a writer's listener (`on_inconsistent_topic`); no StatusCondition
    /// raises it.
    pub const INCONSISTENT_TOPIC: StatusMask = StatusMask(1 << 11);

    /// Create a new StatusMask from raw bits
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        StatusMask(bits)
    }

    /// Get the raw bits value
    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if this mask contains the given status
    #[must_use]
    pub const fn contains(&self, other: StatusMask) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two masks with bitwise OR
    #[must_use]
    pub const fn or(self, other: StatusMask) -> Self {
        StatusMask(self.0 | other.0)
    }

    /// Intersect two masks with bitwise AND
    #[must_use]
    pub const fn and(self, other: StatusMask) -> Self {
        StatusMask(self.0 & other.0)
    }
}

impl std::ops::BitOr for StatusMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.or(rhs)
    }
}

impl std::ops::BitAnd for StatusMask {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        self.and(rhs)
    }
}

/// Number of DATA_AVAILABLE wake words a [`StatusCondition`] carries.
///
/// The entity that owns the condition assigns them, one per producer
/// that can make data available (for a reader: `WakeWord` in the
/// reader runtime). Fixed so that the words share one cache line and a
/// producer holds an index, never a reference into a growable table.
pub(crate) const WAKE_WORDS: usize = 4;

/// Wake word bit: the word's producer stored after pushing.
pub(crate) const WAKE_RAISED: u32 = 1;

/// Wake word bit: the owning entity put the trigger back after its own
/// clear found the producer's work still pending.
pub(crate) const WAKE_RERAISED: u32 = 2;

/// Per-producer DATA_AVAILABLE wake words.
///
/// Several producers make data available on one reader (each bound
/// writer's merger fan-out, the network RX path, the dispose path) and
/// the reader clears the status after observing every source empty.
/// That clear is a check-then-act: a push landing between the
/// observation and the clear must not be left without a trigger, so the
/// reader re-checks its sources after clearing, and the re-check has to
/// be GUARANTEED to see such a push. That is a happens-before
/// requirement from the producer's push to the reader's re-check.
///
/// With one status word shared by every producer, each producer's raise
/// would have to be a read-modify-write: a release sequence continues
/// through RMWs only, so a plain store by one producer would end the
/// sequence headed by another's and the reader's clearing swap could
/// synchronize-with the last producer alone. That lock-prefixed
/// instruction would sit on the writer's post-commit notify and cost the
/// intra-process round trip a measured 4 ns. Here every producer owns
/// one word, and the argument is per word:
///
/// - Producer `i` is the only writer of [`WAKE_RAISED`] on word `i`
///   (its writes are ordered among themselves by the same contract
///   that makes it the single producer of its source). Its sequence is
///   push into source `i`, then [`raise`](Self::raise), a plain
///   `store(RAISED, Release)`, then the WaitSet signal.
/// - The reader's [`clear`](Self::clear) is `prev = swap(0, AcqRel)`.
///   When `prev` carries RAISED, the value the swap read is either
///   producer `i`'s latest store or a [`re_raise`](Self::re_raise) by
///   the reader, an RMW that continues the release sequence headed by
///   that latest store (the only writes that can sit between them are
///   RMWs: the reader's swaps and re-raises; a zero written by a plain
///   store, the dispose queue's drain, clears RAISED, so any RMW that
///   still carries the bit read a producer store issued after it).
///   Either way the swap synchronizes-with producer `i`'s latest store,
///   which is sequenced after its push, so the push happens-before the
///   re-check and the re-check's loads of source `i` return the pushed
///   state or a later one (coherence). Every earlier push by producer
///   `i` is sequenced before that store on the producer's side and is
///   visible the same way.
/// - When `prev` is zero, producer `i` has not stored since the
///   previous clear. A store that lands later in the modification
///   order overwrites the zero, the word ends non-zero, and the next
///   trigger read observes it. Nothing to re-raise.
/// - The re-raise is `fetch_or(RERAISED, AcqRel)`: an RMW, so it
///   continues rather than ends the release sequence of the producer
///   store before it (a later swap that reads the re-raised value still
///   synchronizes-with that store), and a distinct bit, so the next
///   clear can tell the producer's raise from the reader's own.
///
/// A word whose raises can come from several threads (the reader's
/// extra binding rings, one per writer merger; its network ring, pushed
/// from the router thread and, behind a coherent barrier, from the
/// application thread) is raised with [`raise_shared`](Self::raise_shared),
/// a `fetch_or(RAISED, Release)`: with every write to that word an RMW,
/// the release sequence headed by any producer's raise runs to the end
/// of the modification order and the clearing swap synchronizes-with
/// all of them. That is the single-word argument, confined to the words
/// whose raises are not ordered among themselves.
///
/// The release sequence above is what makes a CLEARED word safe. It is
/// not what makes an ATTACHING waiter safe, and that is a separate
/// requirement on the same word. A raise is followed by a read of
/// `waitset_hook_count` (through `signal_data_available`), and an
/// attaching thread stores that count and then reads the word: exactly
/// the store-buffering pair documented on
/// [`StatusCondition::waitset_hook_count`]. Release/Acquire leaves both
/// halves of the wake word outside the total order the SeqCst accesses
/// share, so both loads may return the value that preceded the other
/// thread's store, neither side signals, and the waiter sleeps to its
/// timeout with data available. The accesses that RAISE the word
/// ([`raise`](Self::raise), [`raise_shared`](Self::raise_shared),
/// [`re_raise`](Self::re_raise)) and the trigger read
/// ([`any_raised`](Self::any_raised)) are therefore `SeqCst`.
///
/// The accesses that LOWER the word ([`clear`](Self::clear),
/// [`settle`](Self::settle)) deliberately stay where they are: missing a
/// lowered trigger wakes a waiter that re-evaluates and sleeps again,
/// which is a spurious wake-up and allowed. Only losing a RAISE loses a
/// wake-up. This is the same rule
/// [`StatusCondition::clear_active_status`] follows, and it keeps the
/// total order off the `take()` path.
///
/// Costs, single-producer topology: producer = one SeqCst store (a
/// locked `xchg` on x86, where a Release store is a plain `mov`); reader
/// trigger read = one SeqCst load per word, first raised word wins, and
/// free on x86 where a SeqCst load is a plain `mov`; reader clear = one
/// Relaxed load per word plus one swap per raised word.
pub(crate) struct WakeWords {
    words: [AtomicU32; WAKE_WORDS],
}

impl WakeWords {
    fn new() -> Self {
        Self {
            words: std::array::from_fn(|_| AtomicU32::new(0)),
        }
    }

    /// Producer side of a single-producer word: publish the push that
    /// preceded this call. A store rather than a read-modify-write; see
    /// the type docs for why one producer per word makes that enough for
    /// the release sequence.
    ///
    /// `SeqCst`, not `Release`: this raise is the store half of the
    /// store-buffering pair against an attaching WaitSet (type docs, and
    /// [`StatusCondition::waitset_hook_count`] for the full argument).
    /// A SeqCst store is still a release store, so the release-sequence
    /// argument above is unaffected.
    #[inline]
    pub(crate) fn raise(&self, word: usize) {
        self.words[word].store(WAKE_RAISED, Ordering::SeqCst);
    }

    /// Producer side of a word shared by several producers: an RMW so
    /// that every raise joins one release sequence (type docs).
    /// `SeqCst` for the same store-buffering reason as
    /// [`raise`](Self::raise); free on x86, where the `lock or` this
    /// compiles to is already a full barrier.
    #[inline]
    pub(crate) fn raise_shared(&self, word: usize) {
        self.words[word].fetch_or(WAKE_RAISED, Ordering::SeqCst);
    }

    /// Trigger read: true when any word is non-zero, RAISED or RERAISED.
    /// At least Acquire, so that a consumer acting on `true` (a take
    /// that follows a wait) is ordered after the producer's push,
    /// independently of the source's own synchronization.
    ///
    /// `SeqCst` rather than Acquire: this is the load half of the
    /// store-buffering pair an attaching thread runs into, and an
    /// Acquire load is not in the total order the SeqCst accesses share.
    /// It sits on the wait path, not on take(), and on x86 a SeqCst load
    /// is the same plain `mov` as an Acquire load.
    #[inline]
    pub(crate) fn any_raised(&self) -> bool {
        self.words
            .iter()
            .any(|word| word.load(Ordering::SeqCst) != 0)
    }

    /// Owning entity's clear of one word after it observed the word's
    /// source empty; returns the previous value. RAISED in the result
    /// means the producer stored before this clear and its push is now
    /// visible to the caller (type docs); RERAISED alone means the last
    /// write was the entity's own re-raise.
    ///
    /// An already-zero word is left alone after a Relaxed load: a polling
    /// reader clears on every empty take, and an unconditional RMW would
    /// dirty the producer's line for no state change. Skipping is safe
    /// because a zero is either the initial value or written after a
    /// clear (this entity's swap, or the dispose drain): a producer
    /// store the Relaxed load did not see is later in the modification
    /// order than that zero, leaves the word non-zero, and the next
    /// trigger read observes it; a store before that zero was returned
    /// by the swap that wrote it and re-checked then.
    #[inline]
    pub(crate) fn clear(&self, word: usize) -> u32 {
        let word = &self.words[word];
        if word.load(Ordering::Relaxed) == 0 {
            return 0;
        }
        word.swap(0, Ordering::AcqRel)
    }

    /// Owning entity's re-raise after a clear found the word's source
    /// still pending: put the trigger back with an RMW that continues
    /// the producer's release sequence (type docs). `SeqCst` because it
    /// RAISES the trigger and is followed by a re-signal, so it is the
    /// store half of the same store-buffering pair as
    /// [`raise`](Self::raise); free on x86, where the `lock or` it
    /// compiles to is already a full barrier.
    #[inline]
    pub(crate) fn re_raise(&self, word: usize) {
        self.words[word].fetch_or(WAKE_RERAISED, Ordering::SeqCst);
    }

    /// Drop a word to zero from inside the critical section that
    /// consumed its source (the dispose queue's drain). A plain store:
    /// a producer store after it in the modification order overwrites
    /// it, one before it belongs to work the critical section took.
    #[inline]
    pub(crate) fn settle(&self, word: usize) {
        self.words[word].store(0, Ordering::Relaxed);
    }

    /// Current value of one word. The deposit side of the reader's idle
    /// re-check reads the ring words with it (`DataReader::cover_deposit`
    /// states why coherence alone carries that read); tests and
    /// diagnostics read any word.
    #[inline]
    pub(crate) fn load(&self, word: usize) -> u32 {
        self.words[word].load(Ordering::Acquire)
    }
}

/// StatusCondition - condition based on Entity communication status
///
/// Per DDS v1.4 spec section 2.2.4.1.4:
/// "A StatusCondition object is associated with each Entity. The trigger_value
/// is determined by the communication statuses of that Entity."
///
/// DATA_AVAILABLE is derived: it is active while any of the entity's
/// [`WakeWords`] is non-zero, and the entity's producers raise those
/// words instead of the mask. The other statuses live in the mask.
pub struct StatusCondition {
    /// Unique identifier for this condition
    id: u64,

    /// Enabled status mask - which statuses to monitor
    enabled_statuses: AtomicU32,

    /// Active statuses other than DATA_AVAILABLE (set by the entity
    /// when a status changes).
    active_statuses: AtomicU32,

    /// DATA_AVAILABLE, one word per producer (see [`WakeWords`]).
    wake_words: WakeWords,

    /// Waitset hooks to notify when trigger value changes
    waitset_signals: Mutex<Vec<WaitsetHook>>,

    /// Number of registered waitset hooks (fast-path skip in notify_waitsets)
    ///
    /// This counter and the status words form a store-buffering pair, so every
    /// access that can RAISE the trigger is SeqCst and not Acquire/Release.
    ///
    /// The attaching thread stores the count and then reads the trigger; the
    /// triggering thread stores the status and then reads the count. Under
    /// Acquire/Release nothing forbids BOTH loads from returning the value
    /// that preceded the other thread's store: the notifier reads count == 0
    /// and takes the fast path out, the attacher reads a trigger that is not
    /// raised yet and does not signal, and the waiter sleeps to its timeout
    /// with the condition true. Nobody is at fault and nobody signals.
    ///
    /// SeqCst puts the four accesses in one total order, in which whichever
    /// store comes second is seen by the other thread's load, so at least one
    /// of the two paths always signals. A fence on one side only would not do
    /// it; this shape needs both sides ordered.
    waitset_hook_count: AtomicUsize,

    /// The owning reader's ReadConditions (DDS v1.4 Sec.2.2.2.5.8), told on
    /// EVERY DATA_AVAILABLE raise, whatever `enabled_statuses` says: a
    /// ReadCondition's trigger is tied to the samples the reader holds
    /// (Sec.2.2.4.5), not to the DATA_AVAILABLE status, so disabling that
    /// status on this condition must not silence them. Each hook only
    /// signals the WaitSets attached to its condition; the trigger itself
    /// is evaluated by the reader when the WaitSet asks.
    arrival_hooks: Mutex<Vec<ArrivalHookEntry>>,

    /// `arrival_hooks.len()`, so the producer's post-commit path pays one
    /// load on a reader without conditions. Same store-buffering shape as
    /// `waitset_hook_count`, and the same SeqCst rule: the registering
    /// side stores the count and then reads the wake words, the producer
    /// stores its word and then reads this count.
    arrival_hook_count: AtomicUsize,

    /// Test-only: runs once, inside the next `add_arrival_hook`, while the
    /// registered hooks are being pruned under `arrival_hooks`, so a test
    /// can release a condition's last external reference at that exact
    /// point from another thread.
    #[cfg(test)]
    arrival_prune_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// A consumer that wants to know when the owning entity made data
/// available (a ReadCondition attached to the entity's reader).
pub(crate) trait ArrivalHook: Send + Sync {
    /// Called on the producer's thread right after a DATA_AVAILABLE raise,
    /// with no lock of the condition held. Must not block.
    fn on_data_arrival(&self);
}

struct ArrivalHookEntry {
    id: u64,
    hook: Weak<dyn ArrivalHook>,
}

impl StatusCondition {
    /// Create a new StatusCondition
    ///
    /// By default, no statuses are enabled (must call `set_enabled_statuses`)
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            id,
            enabled_statuses: AtomicU32::new(StatusMask::NONE.bits()),
            active_statuses: AtomicU32::new(StatusMask::NONE.bits()),
            wake_words: WakeWords::new(),
            waitset_signals: Mutex::new(Vec::new()),
            waitset_hook_count: AtomicUsize::new(0),
            arrival_hooks: Mutex::new(Vec::new()),
            arrival_hook_count: AtomicUsize::new(0),
            #[cfg(test)]
            arrival_prune_hook: Mutex::new(None),
        }
    }

    /// Install the one-shot seam run by `add_arrival_hook` during its
    /// prune (see the field docs).
    #[cfg(test)]
    pub(crate) fn set_arrival_prune_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        if let Ok(mut slot) = self.arrival_prune_hook.lock() {
            *slot = Some(hook);
        }
    }

    #[cfg(test)]
    fn run_arrival_prune_hook(&self) {
        let hook = self
            .arrival_prune_hook
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Register `hook` under `id` (the condition id of a ReadCondition)
    /// to be told of every DATA_AVAILABLE raise. Dead hooks are pruned on
    /// the way. The count is published SeqCst: it is the store half of
    /// the store-buffering pair against a producer's raise.
    ///
    /// The prune asks each `Weak` for its strong count and never upgrades
    /// it: an upgrade is a temporary owner, and if the application drops
    /// its own last reference on another thread in that window, the
    /// temporary becomes the last one and the condition's drop runs on
    /// THIS thread, under `arrival_hooks`; that drop detaches from the
    /// reader through `remove_arrival_hook`, which takes `arrival_hooks`
    /// again. A hook whose count reads zero here is dead for good (a
    /// `Weak` cannot be upgraded back), and one that dies right after the
    /// read is pruned on the next pass.
    pub(crate) fn add_arrival_hook(&self, id: u64, hook: Weak<dyn ArrivalHook>) {
        let mut hooks = self
            .arrival_hooks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hooks.retain(|entry| {
            let live = entry.hook.strong_count() > 0;
            #[cfg(test)]
            self.run_arrival_prune_hook();
            entry.id != id && live
        });
        hooks.push(ArrivalHookEntry { id, hook });
        self.arrival_hook_count.store(hooks.len(), Ordering::SeqCst);
    }

    /// Remove the hook registered under `id`, if any.
    pub(crate) fn remove_arrival_hook(&self, id: u64) {
        let mut hooks = self
            .arrival_hooks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        hooks.retain(|entry| entry.id != id);
        self.arrival_hook_count.store(hooks.len(), Ordering::SeqCst);
    }

    /// Tell every live arrival hook. Collect under the lock, call after
    /// it: `on_data_arrival` reaches WaitSet signal hooks, which are
    /// trait code behind a public trait and must never run under a lock
    /// of this condition (the rule `notify_waitsets` follows).
    fn notify_arrival_hooks(&self) {
        let live: Vec<Arc<dyn ArrivalHook>> = {
            let mut hooks = self
                .arrival_hooks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut live = Vec::with_capacity(hooks.len());
            hooks.retain(|entry| match entry.hook.upgrade() {
                Some(hook) => {
                    live.push(hook);
                    true
                }
                None => false,
            });
            self.arrival_hook_count.store(hooks.len(), Ordering::SeqCst);
            live
        };
        for hook in live {
            hook.on_data_arrival();
        }
    }

    /// Set which statuses this condition should monitor
    ///
    /// # Example
    ///
    /// ```ignore
    /// let condition = StatusCondition::new();
    /// condition.set_enabled_statuses(
    ///     StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED
    /// );
    /// ```
    pub fn set_enabled_statuses(&self, mask: StatusMask) {
        self.enabled_statuses.store(mask.bits(), Ordering::SeqCst);

        if self.get_trigger_value() {
            self.notify_waitsets();
        }
    }

    /// Get the currently enabled statuses
    pub fn get_enabled_statuses(&self) -> StatusMask {
        StatusMask::from_bits(self.enabled_statuses.load(Ordering::SeqCst))
    }

    /// Raise active statuses in the mask: OR `mask` into the active set
    /// and signal the attached WaitSets when an enabled status is among
    /// them.
    ///
    /// For the statuses that live in the mask. The entity's producers
    /// raise DATA_AVAILABLE through their [`WakeWords`] instead
    /// ([`raise_data_available`](Self::raise_data_available)); a
    /// DATA_AVAILABLE bit passed here still triggers, which is what a
    /// test that drives a condition without a producer relies on, and
    /// the reader's idle clear
    /// ([`clear_active_status`](Self::clear_active_status) on
    /// DATA_AVAILABLE) drops it with the words.
    ///
    /// OR rather than overwrite: a raise never removes a status raised
    /// in between. `Release` so that state written before the raise is
    /// visible to a waiter that observes the bit.
    ///
    /// The production producer, the reader's admission path raising
    /// SAMPLE_REJECTED on a resource-limit drop
    /// (`ReaderSubscriber::report_sample_rejected`), uses the two halves
    /// separately ([`raise_active_statuses`](Self::raise_active_statuses)
    /// under its state lock, then
    /// [`notify_waitsets_for`](Self::notify_waitsets_for) after it) so no
    /// signal hook runs under that lock; only the status's own consumers
    /// (its listener call, its getter) lower the bit again (DDS v1.4
    /// Sec.2.2.4.2.1). LIVELINESS_CHANGED is raised the same way by the
    /// reader's liveliness (`dds::liveliness`). The other mask statuses
    /// (deadline, matching, ...) are still reported through listeners and
    /// status getters only and never raised on the condition. This one-call
    /// form is what the condition and WaitSet tests drive a fixture with.
    #[cfg(test)]
    pub(crate) fn set_active_statuses(&self, mask: StatusMask) {
        self.raise_active_statuses(mask);
        self.notify_waitsets_for(mask);
    }

    /// OR `mask` into the active set without notifying the attached
    /// WaitSets (the raise half of the test-only one-call
    /// `set_active_statuses`). For a producer that raises under its own
    /// state lock (the reader's rejection state: the bit and the status it
    /// reports move together) and must not run the WaitSet signal hooks
    /// there: `WaitsetSignal` is a public trait, and a hook may call back
    /// into that producer's getter, which takes the same lock. Pair with
    /// [`notify_waitsets_for`](Self::notify_waitsets_for) once the lock is
    /// released.
    ///
    /// `fetch_or` rather than a store: a raise never removes a status
    /// raised in between. `SeqCst` because this access RAISES the trigger
    /// and so is one half of the store-buffering pair documented on
    /// `waitset_hook_count`.
    pub(crate) fn raise_active_statuses(&self, mask: StatusMask) {
        self.active_statuses.fetch_or(mask.bits(), Ordering::SeqCst);
    }

    /// The notification half: signal the attached WaitSets when an
    /// enabled status is in `mask`. The enabled set is read AFTER the
    /// caller's raise, which makes this the store-then-load side of the
    /// pair with [`set_enabled_statuses`](Self::set_enabled_statuses)
    /// (store the enabled set, then load the trigger): with both sides
    /// `SeqCst`, one of the two always observes the other's store, so
    /// enabling a status concurrently with its raise cannot lose the
    /// wake-up. (Loading the enabled set before the raise would leave that
    /// window open.)
    pub(crate) fn notify_waitsets_for(&self, mask: StatusMask) {
        if self.get_enabled_statuses().and(mask).bits() != 0 {
            self.notify_waitsets();
        }
    }

    /// Get the currently active statuses: the mask, plus DATA_AVAILABLE
    /// while any wake word is raised.
    pub fn get_active_statuses(&self) -> StatusMask {
        // `SeqCst`: this load is the trigger half of the store-buffering pair
        // documented on `waitset_hook_count`.
        let mask = StatusMask::from_bits(self.active_statuses.load(Ordering::SeqCst));
        if self.wake_words.any_raised() {
            mask.or(StatusMask::DATA_AVAILABLE)
        } else {
            mask
        }
    }

    /// Clear every status in the mask, returning the mask that was
    /// active. The wake words are not touched. Test-only: no production
    /// consumer may clear a status it did not deliver (DDS v1.4
    /// Sec.2.2.4.2.1 resets a plain communication status on ITS listener
    /// call or ITS getter, and Sec.2.2.4.2.2 lets read/take reset
    /// DATA_AVAILABLE only), so production code goes through
    /// [`clear_active_status`](Self::clear_active_status) with the one
    /// status it consumed. Kept for the condition tests that reset a
    /// fixture between steps.
    ///
    /// Same ordering rule as `clear_active_status`: it only LOWERS the
    /// trigger.
    #[cfg(test)]
    pub(crate) fn clear_active_statuses(&self) -> StatusMask {
        if self.active_statuses.load(Ordering::Relaxed) == 0 {
            return StatusMask::NONE;
        }
        StatusMask::from_bits(self.active_statuses.swap(0, Ordering::AcqRel))
    }

    /// Clear exactly the bits in `mask`, leaving every other active status
    /// untouched: the consumer of one status (the reader's idle clear for
    /// DATA_AVAILABLE, DDS v1.4 Sec.2.2.4.2.2; a listener call or a getter
    /// for a plain communication status such as SAMPLE_REJECTED,
    /// Sec.2.2.4.2.1) lowers that status and no other, so a status nobody
    /// consumed yet stays raised for its WaitSet.
    ///
    /// An already-clear bit is left alone after a Relaxed load: the
    /// reader's idle clear runs on every empty take, where the mask is
    /// zero unless a rejection is pending, so the common case is one load
    /// and no RMW. This sits on the take() path, which is measured.
    ///
    /// Deliberately NOT SeqCst, unlike every raise on this word: this only
    /// ever LOWERS the trigger, so `AcqRel` is enough -- a reader that
    /// misses this clear wakes up, re-evaluates the condition and goes
    /// back to sleep, which is a spurious wake-up and is allowed. Missing
    /// a store that RAISES the trigger is the one that loses a wake-up,
    /// so only those pay for the total order.
    pub(crate) fn clear_active_status(&self, mask: StatusMask) {
        if self.active_statuses.load(Ordering::Relaxed) & mask.bits() == 0 {
            return;
        }
        self.active_statuses
            .fetch_and(!mask.bits(), Ordering::AcqRel);
    }

    /// The entity's DATA_AVAILABLE wake words, for the entity's clear.
    #[inline]
    pub(crate) fn wake_words(&self) -> &WakeWords {
        &self.wake_words
    }

    /// Producer side of DATA_AVAILABLE on a single-producer word: raise
    /// `word` with a plain Release store, then signal the attached
    /// WaitSets when DATA_AVAILABLE is enabled. The caller has pushed to
    /// its source already; see [`WakeWords`] for the ordering argument.
    ///
    /// `Release`, not `AcqRel`: the producer publishes its push (the
    /// Release half is what the reader's Acquire pairs with) and reads
    /// nothing after this call that another thread's write to the word
    /// would have to order, so an Acquire half would add a barrier to
    /// the writer's post-commit path for an edge nobody consumes.
    #[inline]
    pub(crate) fn raise_data_available(&self, word: usize) {
        self.wake_words.raise(word);
        self.signal_data_available();
    }

    /// [`raise_data_available`](Self::raise_data_available) for a word
    /// several producers share: the raise is a read-modify-write so
    /// that every producer's raise joins one release sequence.
    #[inline]
    pub(crate) fn raise_data_available_shared(&self, word: usize) {
        self.wake_words.raise_shared(word);
        self.signal_data_available();
    }

    /// Re-raise DATA_AVAILABLE on `word` after the entity's own clear
    /// of that word found its source still pending, and signal the
    /// attached WaitSets again.
    ///
    /// The second signal is on purpose. The producer's raise that the
    /// clear just swapped away had already signalled the driver, but a
    /// waiter on another thread can consume that bit and read the
    /// cleared trigger in the window between the clear and this
    /// re-raise, after which it sleeps until the next raise. A
    /// single-threaded wait/take loop does not need the second signal
    /// (`WaitSet::wait` re-reads the trigger before blocking) and barely
    /// pays for it: the driver skips the eventfd write while its bit is
    /// still pending.
    #[inline]
    pub(crate) fn re_raise_data_available(&self, word: usize) {
        self.wake_words.re_raise(word);
        self.signal_data_available();
    }

    /// Signal the attached WaitSets for a DATA_AVAILABLE raise made
    /// directly on the wake words (a producer that had to store its word
    /// inside a critical section and signals after leaving it).
    ///
    /// The reader's ReadConditions are told afterwards, independently of
    /// the enabled statuses (see `arrival_hooks`). Their count is read
    /// SeqCst AFTER the caller's raise of its wake word, which makes this
    /// the store-then-load side of the pair against a condition being
    /// registered (store the count, then read the words): one of the two
    /// always observes the other's store, so a raise concurrent with a
    /// registration is either signalled here or seen by the registering
    /// side's own evaluation.
    #[inline]
    pub(crate) fn signal_data_available(&self) {
        if self
            .get_enabled_statuses()
            .contains(StatusMask::DATA_AVAILABLE)
        {
            self.notify_waitsets();
        }
        if self.arrival_hook_count.load(Ordering::SeqCst) != 0 {
            self.notify_arrival_hooks();
        }
    }
}

impl Condition for StatusCondition {
    fn get_trigger_value(&self) -> bool {
        let enabled = self.get_enabled_statuses();
        // `SeqCst`, not `Acquire`: this is the read half of the
        // store-buffering pair documented on `waitset_hook_count`. An
        // attaching thread stores the hook count and then lands here; an
        // `Acquire` load is not in the total order the SeqCst accesses share,
        // so it may still return the value that preceded a concurrent raise
        // while the raiser's own load returns the count that preceded the
        // attach. Neither side signals and the waiter sleeps to its timeout
        // with the condition true. This sits on the wait path, not on take().
        let active = StatusMask::from_bits(self.active_statuses.load(Ordering::SeqCst));

        // Trigger is true if any enabled status is active: the mask
        // first, then DATA_AVAILABLE derived from the wake words.
        enabled.and(active).bits() != 0
            || (enabled.contains(StatusMask::DATA_AVAILABLE) && self.wake_words.any_raised())
    }

    fn condition_id(&self) -> u64 {
        self.id
    }

    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] StatusCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        hooks.retain(|hook| hook.signal.upgrade().is_some());
        log::debug!(
            "[STATUS-CONDITION] attach signal id={} cond_id={}",
            signal.id(),
            self.id
        );
        hooks.push(WaitsetHook {
            id: signal.id(),
            signal: Arc::downgrade(&signal),
        });
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

impl Default for StatusCondition {
    fn default() -> Self {
        Self::new()
    }
}

struct WaitsetHook {
    id: u64,
    signal: Weak<dyn WaitsetSignal>,
}

impl StatusCondition {
    fn notify_waitsets(&self) {
        if self.waitset_hook_count.load(Ordering::SeqCst) == 0 {
            return;
        }

        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] StatusCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        // Collect first, signal after the guard is gone. `signal()` is trait
        // code reached through a public trait, so a hook that called back
        // into this condition would deadlock on this non-reentrant mutex,
        // and the in-house implementation writes to an eventfd, which is a
        // syscall nobody should hold a hot-path lock across.
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

/// GuardCondition - manually-triggered condition
///
/// Per DDS v1.4 spec section 2.2.4.1.5:
/// "A GuardCondition is a Condition whose trigger_value is under the control
/// of the application."
pub struct GuardCondition {
    /// Unique identifier for this condition
    id: u64,

    /// Trigger value (controlled by application)
    trigger_value: AtomicBool,

    /// Waitset hooks to notify when trigger value flips true
    waitset_signals: Mutex<Vec<WaitsetHook>>,

    /// Number of registered waitset hooks (fast-path skip in notify_waitsets)
    waitset_hook_count: AtomicUsize,
}

impl GuardCondition {
    /// Create a new GuardCondition with trigger_value = false
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(1_000_000);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            id,
            trigger_value: AtomicBool::new(false),
            waitset_signals: Mutex::new(Vec::new()),
            waitset_hook_count: AtomicUsize::new(0),
        }
    }

    /// Set the trigger value
    ///
    /// When set to `true`, any WaitSet waiting on this condition will wake up.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let guard = GuardCondition::new();
    /// guard.set_trigger_value(true);  // Wake up WaitSet
    /// ```
    pub fn set_trigger_value(&self, value: bool) {
        self.trigger_value.store(value, Ordering::SeqCst);
        if value {
            self.notify_waitsets();
        }
    }

    fn notify_waitsets(&self) {
        if self.waitset_hook_count.load(Ordering::SeqCst) == 0 {
            return;
        }

        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] GuardCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        // Collect first, signal after the guard is gone. `signal()` is trait
        // code reached through a public trait, so a hook that called back
        // into this condition would deadlock on this non-reentrant mutex,
        // and the in-house implementation writes to an eventfd, which is a
        // syscall nobody should hold a hot-path lock across.
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

impl Condition for GuardCondition {
    fn get_trigger_value(&self) -> bool {
        self.trigger_value.load(Ordering::SeqCst)
    }

    fn condition_id(&self) -> u64 {
        self.id
    }

    fn add_waitset_signal(&self, signal: Arc<dyn WaitsetSignal>) {
        let mut hooks = match self.waitset_signals.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::debug!("[condition] GuardCondition waitset_signals poisoned, recovering");
                poisoned.into_inner()
            }
        };

        hooks.retain(|hook| hook.signal.upgrade().is_some());
        hooks.push(WaitsetHook {
            id: signal.id(),
            signal: Arc::downgrade(&signal),
        });
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

impl Default for GuardCondition {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for entities that have a StatusCondition (DataReader, DataWriter).
///
/// This trait enables the convenience method `WaitSet::attach(&entity)`.
///
/// # Example
/// ```ignore
/// let reader = participant.create_reader::<MyType>("topic", QoS::default())?;
/// let waitset = WaitSet::new();
/// waitset.attach(&reader)?;  // Convenience - calls get_status_condition() internally
/// ```
pub trait HasStatusCondition {
    /// Get the StatusCondition associated with this entity.
    fn get_status_condition(&self) -> Arc<StatusCondition>;
}

#[cfg(test)]
mod tests;
