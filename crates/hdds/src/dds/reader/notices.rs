// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Application code is never called under a delivery lock.
//!
//! A reader's samples are pushed into its ring under locks of the reader
//! (a writer's delivery lock, the commit lock, the presentation barrier's
//! `publishing`). Its listener must not be called right after each push,
//! under those locks: a DATA_AVAILABLE listener that opens an access
//! bracket (DDS v1.4 Sec.2.2.2.5, pattern 1) would wait on `publishing` under
//! a writer's delivery lock, while the Subscriber's publishing thread holds
//! `publishing` and waits on that delivery lock.
//!
//! A thread that delivers marks it (`Delivering`); what it must tell the
//! application meanwhile (`notify`) is held, and told when the outermost
//! delivery of the thread ends, every lock it took released. Outside a
//! delivery, it is told at once.

//! What the application is told in a given order (`Ordered`) is queued
//! where that order is decided (under a status lock, inside a match
//! entry's dispatch) and told by one thread at a time, oldest first, a
//! bounded share of it on the thread that queued it: the rest goes to a
//! thread of that queue's own (`hand_off`), so a writer or receive thread
//! is never held telling for others without bound, and one entity's slow
//! listener never holds another entity's.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// One application call (a listener's), told once.
pub(crate) type Notice = Box<dyn FnOnce() + Send>;

std::thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    // @audit-ok: thread-local, never shared: each thread holds its own notices.
    static HELD: RefCell<Vec<Notice>> = const { RefCell::new(Vec::new()) };
    // @audit-ok: thread-local, never shared: the ordered domain this thread
    // queues into (`Scope`).
    static DOMAIN: RefCell<Option<Arc<Ordered>>> = const { RefCell::new(None) };
}

/// This thread delivers until the value is dropped. Take it before the
/// first lock of the delivery, so that it is dropped after the last.
pub(crate) struct Delivering(());

impl Delivering {
    pub(crate) fn enter() -> Self {
        // A thread whose locals are being destroyed delivers with none
        // (`notify` then tells at once).
        let _ = DEPTH.try_with(|d| d.set(d.get().saturating_add(1)));
        Self(())
    }
}

impl Drop for Delivering {
    #[inline(always)]
    fn drop(&mut self) {
        let depth = DEPTH
            .try_with(|d| {
                let depth = d.get().saturating_sub(1);
                d.set(depth);
                depth
            })
            .unwrap_or(0);
        // Told even while the delivery unwinds from a panic of its own:
        // left waiting, they were told at the thread's next delivery, maybe
        // never (an application thread), and a notice told at once meanwhile
        // overtook them. Each is told inside `catch_unwind` (`tell_held`): a
        // listener that panics is caught, never a panic during a panic.
        if depth == 0 {
            tell_held();
        }
    }
}

/// Tell the application `notice` (a listener call): into the ordered
/// domain this thread queues into (`Scope`), else, while this thread
/// delivers, once its outermost delivery ends, else at once.
pub(crate) fn notify(notice: impl FnOnce() + Send + 'static) {
    let mut notice: Option<Notice> = Some(Box::new(notice));
    let mut in_scope = false;
    let _ = DOMAIN.try_with(|domain| {
        if let Some(domain) = domain.borrow().as_ref() {
            in_scope = true;
            if let Some(call) = notice.take() {
                // Over the bound, this thread tells its own, once the scope
                // ends (`Scope::drop`), out of the domain's order.
                notice = domain.push(call).err();
            }
        }
    });
    let Some(notice) = notice else { return };
    hold_or_tell(notice, in_scope);
}

/// [`notify`], for a notice already boxed: a plain `fn`, for a caller that
/// keeps a function pointer (`DeliveryObserver::deferring`).
pub(crate) fn notify_boxed(notice: Notice) {
    notify(notice);
}

/// Hold `notice` for the end of this thread's delivery or scope (`hold`),
/// or tell it at once.
fn hold_or_tell(notice: Notice, hold: bool) {
    if !hold && DEPTH.try_with(Cell::get).unwrap_or(0) == 0 {
        tell(notice);
        return;
    }
    let mut notice = Some(notice);
    let _ = HELD.try_with(|held| {
        if let Some(n) = notice.take() {
            held.borrow_mut().push(n);
        }
    });
    if let Some(notice) = notice {
        tell(notice);
    }
}

/// Tell one notice, its panic caught and logged, as the router does.
fn tell(notice: Notice) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(notice)).is_err() {
        log::error!("[READER-SUB] an application listener panicked; caught");
    }
}

/// Tell what is held, in order, those it tells holding more included. A
/// listener that panics does not keep the others untold. The list keeps
/// its allocation for the next delivery.
fn tell_held() {
    let mut batch: Vec<Notice> = Vec::new();
    loop {
        let more = HELD
            .try_with(|held| {
                let mut held = held.borrow_mut();
                if held.is_empty() {
                    if batch.capacity() > held.capacity() {
                        std::mem::swap(&mut *held, &mut batch);
                    }
                    return false;
                }
                std::mem::swap(&mut *held, &mut batch);
                true
            })
            .unwrap_or(false);
        if !more {
            return;
        }
        for notice in batch.drain(..) {
            tell(notice);
        }
    }
}

/// While the value lives, this thread's notices go to `domain`, in order
/// with those other threads queue there; when it is dropped, the domain is
/// told (at once, or with this thread's other held notices).
pub(crate) struct Scope {
    domain: Arc<Ordered>,
    previous: Option<Arc<Ordered>>,
}

impl Scope {
    pub(crate) fn enter(domain: &Arc<Ordered>) -> Self {
        let previous = DOMAIN
            .try_with(|d| d.borrow_mut().replace(Arc::clone(domain)))
            .unwrap_or(None);
        Self {
            domain: Arc::clone(domain),
            previous,
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let outer = previous.is_some();
        let _ = DOMAIN.try_with(|d| *d.borrow_mut() = previous);
        let domain = Arc::clone(&self.domain);
        // Never into an enclosing domain: closed, it would drop this one's
        // tell, and this entity lives. Held with this thread's own while
        // it delivers or an outer scope lasts, told at once otherwise.
        hold_or_tell(Box::new(move || domain.tell()), outer);
        if !outer && DEPTH.try_with(Cell::get).unwrap_or(0) == 0 {
            // What a full domain gave back while the scope lasted.
            tell_held();
        }
    }
}

/// The most notices an `Ordered` queues: a producer that finds it full
/// tells its own instead, out of the queue's order (an overload).
const ORDERED_BOUND: usize = 4096;

/// Notices told in the order they were queued (`push`, where that order is
/// decided), by one thread at a time (`tell`).
pub(crate) struct Ordered {
    state: Mutex<OrderedState>,
}

#[derive(Default)]
struct OrderedState {
    queue: VecDeque<Notice>,
    telling: bool,
    /// The thread telling, while one does on its own budget (`tell`).
    teller: Option<std::thread::ThreadId>,
    /// Notices the teller queued itself while it told (a listener that
    /// causes another status): within its budget, they are its own.
    teller_own: usize,
    closed: bool,
}

impl Default for Ordered {
    fn default() -> Self {
        Self {
            state: Mutex::new(OrderedState::default()),
        }
    }
}

impl Ordered {
    fn state(&self) -> std::sync::MutexGuard<'_, OrderedState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue `notice`. Full, it is given back: the caller tells it itself,
    /// with no lock held. Closed, it is dropped.
    pub(crate) fn push(&self, notice: Notice) -> Result<(), Notice> {
        let mut state = self.state();
        if state.closed {
            return Ok(());
        }
        if state.queue.len() >= ORDERED_BOUND {
            return Err(notice);
        }
        if state.teller.is_some() && state.teller == Some(std::thread::current().id()) {
            state.teller_own += 1;
        }
        state.queue.push_back(notice);
        Ok(())
    }

    /// Nothing more is told (its entity is gone): what is queued is
    /// dropped, and what is queued later.
    pub(crate) fn close(&self) {
        let dropped = {
            let mut state = self.state();
            state.closed = true;
            std::mem::take(&mut state.queue)
        };
        drop(dropped);
    }

    /// Tell the queued notices, oldest first, unless another thread tells
    /// already (it tells these too). This thread tells at most as many as
    /// were queued when it began, its own among them, and those it queues
    /// itself meanwhile; what other threads queue meanwhile goes to the
    /// hand-off thread, which tells it in order.
    pub(crate) fn tell(self: &Arc<Self>) {
        let mut budget = {
            let mut state = self.state();
            if state.telling || state.queue.is_empty() {
                return;
            }
            state.telling = true;
            state.teller = Some(std::thread::current().id());
            state.teller_own = 0;
            state.queue.len()
        };
        loop {
            let next = {
                let mut state = self.state();
                budget += std::mem::take(&mut state.teller_own);
                if budget == 0 && !state.queue.is_empty() {
                    state.teller = None;
                    drop(state);
                    hand_off(Arc::clone(self));
                    return;
                }
                let next = state.queue.pop_front();
                if next.is_none() {
                    state.telling = false;
                    state.teller = None;
                }
                next
            };
            let Some(notice) = next else { return };
            tell(notice);
            budget = budget.saturating_sub(1);
        }
    }

    /// `tell` with no budget: the hand-off thread's.
    fn tell_all(&self) {
        loop {
            let next = {
                let mut state = self.state();
                let next = state.queue.pop_front();
                if next.is_none() {
                    state.telling = false;
                }
                next
            };
            let Some(notice) = next else { return };
            tell(notice);
        }
    }
}

/// Give `ordered`, still marked telling, to a thread of its own, which
/// tells what it holds and leaves: a queue whose listener is slow, or
/// blocks, holds no other queue's (one hand-off at a time per queue, rare:
/// only a teller over its budget hands off).
fn hand_off(ordered: Arc<Ordered>) {
    let handed = Arc::clone(&ordered);
    let spawned = std::thread::Builder::new()
        .name("hdds-notices".to_string())
        .spawn(move || handed.tell_all());
    if spawned.is_err() {
        // No thread: this one tells the rest.
        ordered.tell_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// Held while the thread delivers, told in order when the outermost
    /// delivery ends; told at once outside one.
    #[test]
    fn a_notice_waits_for_the_outermost_delivery() {
        let told = Arc::new(Mutex::new(Vec::new()));
        let note = |n: u32| {
            let told = Arc::clone(&told);
            move || told.lock().unwrap().push(n)
        };
        notify(note(0));
        {
            let _outer = Delivering::enter();
            notify(note(1));
            {
                let _inner = Delivering::enter();
                notify(note(2));
            }
            assert_eq!(*told.lock().unwrap(), vec![0], "held while delivering");
        }
        assert_eq!(*told.lock().unwrap(), vec![0, 1, 2]);
    }

    /// A delivery that panics tells what it held as it unwinds, a held
    /// listener that panics too included: caught, not a panic during a
    /// panic (which aborts the process).
    #[test]
    fn a_delivery_that_panics_tells_what_it_held() {
        let told = Arc::new(AtomicBool::new(false));
        let t = Arc::clone(&told);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _d = Delivering::enter();
            notify(|| panic!("a listener panics as well"));
            notify(move || t.store(true, Ordering::SeqCst));
            panic!("a delivery panics");
        }));
        assert!(unwound.is_err());
        assert!(told.load(Ordering::SeqCst), "told as the delivery unwound");
    }

    /// A notice that panics does not keep the next from being told.
    #[test]
    fn a_panicking_notice_does_not_hold_the_others() {
        let told = Arc::new(AtomicBool::new(false));
        {
            let _d = Delivering::enter();
            notify(|| panic!("a listener panics"));
            let told = Arc::clone(&told);
            notify(move || told.store(true, Ordering::SeqCst));
        }
        assert!(told.load(Ordering::SeqCst));
    }

    /// One thread tells another's notices only within its budget (those
    /// queued when it began): a slow listener and a fast producer leave the
    /// rest to the hand-off thread, and every notice is told, in order.
    #[test]
    fn a_teller_is_not_held_by_another_thread_s_notices() {
        let q = Arc::new(Ordered::default());
        let told = Arc::new(Mutex::new(Vec::new()));
        let started = Arc::new(AtomicBool::new(false));
        let note = |n: u32| -> Notice {
            let told = Arc::clone(&told);
            let started = Arc::clone(&started);
            Box::new(move || {
                started.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_micros(200));
                told.lock().unwrap().push(n);
            })
        };
        assert!(q.push(note(0)).is_ok());
        let teller = {
            let q = Arc::clone(&q);
            std::thread::spawn(move || {
                let t0 = Instant::now();
                q.tell();
                t0.elapsed()
            })
        };
        while !started.load(Ordering::SeqCst) {
            std::thread::yield_now();
        }
        for n in 1..=2000u32 {
            assert!(q.push(note(n)).is_ok());
            q.tell();
        }
        let teller_time = teller.join().unwrap();
        assert!(
            teller_time < Duration::from_millis(50),
            "the teller was held {teller_time:?} by another thread's notices"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while told.lock().unwrap().len() < 2001 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let told = told.lock().unwrap().clone();
        assert_eq!(
            told,
            (0..=2000).collect::<Vec<u32>>(),
            "every one, in order"
        );
    }

    /// A delivery from a thread-local destructor, run after this module's
    /// thread locals are gone: told at once, never a panic on the
    /// destroyed locals.
    #[test]
    fn a_delivery_from_a_thread_local_destructor_tells_at_once() {
        struct OnExit(Option<Arc<AtomicBool>>);
        impl Drop for OnExit {
            fn drop(&mut self) {
                if let Some(told) = self.0.take() {
                    let _d = Delivering::enter();
                    notify(move || told.store(true, Ordering::SeqCst));
                }
            }
        }
        std::thread_local! {
            static SLOT: RefCell<Option<OnExit>> = const { RefCell::new(None) };
        }
        let told = Arc::new(AtomicBool::new(false));
        let t = Arc::clone(&told);
        let joined = std::thread::spawn(move || {
            // Registered before this module's locals: destroyed after them.
            SLOT.with(|s| *s.borrow_mut() = Some(OnExit(None)));
            {
                let _d = Delivering::enter();
                notify(|| {});
            }
            SLOT.with(|s| *s.borrow_mut() = Some(OnExit(Some(t))));
        })
        .join();
        assert!(joined.is_ok(), "no panic on destroyed thread locals");
        assert!(told.load(Ordering::SeqCst), "told at once");
    }

    /// A notice a full domain gives back is told once its scope ends, not
    /// inside it (a match entry's dispatch gate).
    #[test]
    fn a_notice_a_full_domain_gives_back_waits_for_the_scope_end() {
        let domain = Arc::new(Ordered::default());
        for _ in 0..ORDERED_BOUND {
            assert!(domain.push(Box::new(|| {})).is_ok());
        }
        let told = Arc::new(AtomicBool::new(false));
        {
            let _scope = Scope::enter(&domain);
            let t = Arc::clone(&told);
            notify(move || t.store(true, Ordering::SeqCst));
            assert!(!told.load(Ordering::SeqCst), "not told inside the scope");
        }
        assert!(told.load(Ordering::SeqCst), "told at the scope's end");
    }

    /// A closed queue tells nothing: what is queued is dropped, and what
    /// is pushed after.
    #[test]
    fn a_closed_queue_tells_nothing() {
        let q = Arc::new(Ordered::default());
        let told = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&told);
        assert!(q
            .push(Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
            }))
            .is_ok());
        q.close();
        let c = Arc::clone(&told);
        assert!(q
            .push(Box::new(move || {
                c.fetch_add(1, Ordering::SeqCst);
            }))
            .is_ok());
        q.tell();
        assert_eq!(told.load(Ordering::SeqCst), 0);
    }

    /// A full queue gives the notice back to its producer.
    #[test]
    fn a_full_queue_gives_the_notice_back() {
        let q = Ordered::default();
        let count = Arc::new(AtomicUsize::new(0));
        for _ in 0..ORDERED_BOUND {
            assert!(q.push(Box::new(|| {})).is_ok());
        }
        let c = Arc::clone(&count);
        let back = q.push(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        let Err(back) = back else {
            panic!("given back")
        };
        back();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// Notices queued into a domain from two threads are told in the order
    /// queued, whichever thread tells.
    #[test]
    fn a_domain_keeps_the_order_across_threads() {
        let domain = Arc::new(Ordered::default());
        let told = Arc::new(Mutex::new(Vec::new()));
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let other = {
            let domain = Arc::clone(&domain);
            let told = Arc::clone(&told);
            std::thread::spawn(move || {
                go_rx.recv().unwrap();
                let _scope = Scope::enter(&domain);
                notify(move || told.lock().unwrap().push(2));
                drop(_scope);
                done_tx.send(()).unwrap();
            })
        };
        {
            let _scope = Scope::enter(&domain);
            notify(move || {
                go_tx.send(()).unwrap();
                let _ = done_rx.recv_timeout(Duration::from_secs(2));
            });
            let t = Arc::clone(&told);
            notify(move || t.lock().unwrap().push(1));
        }
        other.join().unwrap();
        // 2, another thread's, is told by the hand-off thread.
        let deadline = Instant::now() + Duration::from_secs(5);
        while told.lock().unwrap().len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(*told.lock().unwrap(), vec![1, 2]);
    }
}
