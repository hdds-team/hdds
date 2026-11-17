// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Publisher order shared by all local readers of an ordered Subscriber.

use crate::core::rt::SlabHandle;
use crate::dds::StatusCondition;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, Weak};

/// Local coordinator identities and RTPS Publisher GUIDs occupy separate spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum PublisherIdentity {
    Local(u64),
    Wire([u8; 16]),
}

impl From<u64> for PublisherIdentity {
    fn from(identity: u64) -> Self {
        Self::Local(identity)
    }
}

pub(super) type CacheKey = (Option<[u8; 16]>, u64);

struct Member {
    reader: usize,
    publisher: PublisherIdentity,
    gsn: u64,
    cached: Option<CacheKey>,
}

#[derive(Default)]
struct State {
    next: u64,
    members: HashMap<u64, Member>,
    slabs: HashMap<(usize, SlabHandle), u64>,
    publishers: HashMap<PublisherIdentity, BTreeMap<u64, Vec<u64>>>,
    pending: HashMap<(usize, PublisherIdentity, u64), u64>,
    pending_owners: HashMap<u64, usize>,
    readers: HashMap<usize, ReaderWake>,
}

struct ReaderWake {
    status: Weak<StatusCondition>,
    room: Weak<super::admission::RoomWait>,
}

enum OrderWake {
    Status(Weak<StatusCondition>),
    Room(Weak<super::admission::RoomWait>),
}

#[cfg(any(test, feature = "test-support"))]
struct RegistrationHook {
    reader: usize,
    call: Box<dyn FnOnce() + Send>,
}

#[derive(Default)]
pub(super) struct LocalReadOrder(
    Mutex<State>,
    #[cfg(any(test, feature = "test-support"))] Mutex<Option<RegistrationHook>>,
);

impl State {
    fn forget(&mut self, token: u64) -> Vec<OrderWake> {
        let Some(member) = self.members.remove(&token) else {
            return Vec::new();
        };
        let mut wakes = Vec::new();
        if self.pending.values().any(|&pending| pending == token) {
            if let Some(reader) = self.readers.get(&member.reader) {
                wakes.push(OrderWake::Room(reader.room.clone()));
            }
        }
        let before = self
            .publishers
            .get(&member.publisher)
            .and_then(|queue| queue.first_key_value().map(|(&gsn, _)| gsn));
        self.slabs.retain(|_, t| *t != token);
        self.pending.retain(|_, t| *t != token);
        self.pending_owners.remove(&token);
        if let Some(queue) = self.publishers.get_mut(&member.publisher) {
            if let Some(members) = queue.get_mut(&member.gsn) {
                members.retain(|t| *t != token);
                if members.is_empty() {
                    queue.remove(&member.gsn);
                }
            }
            if queue.is_empty() {
                self.publishers.remove(&member.publisher);
            }
        }
        let next = self
            .publishers
            .get(&member.publisher)
            .and_then(|queue| queue.first_key_value());
        if before == next.map(|(&gsn, _)| gsn) {
            return wakes;
        }
        let Some((_, tokens)) = next else {
            return wakes;
        };
        let mut notified = std::collections::HashSet::new();
        wakes.extend(
            tokens
                .iter()
                .filter(|token| !self.pending.values().any(|pending| pending == *token))
                .filter_map(|token| self.members.get(token))
                .filter(|member| notified.insert(member.reader))
                .filter_map(|member| self.readers.get(&member.reader))
                .map(|reader| OrderWake::Status(reader.status.clone())),
        );
        wakes
    }
}

impl LocalReadOrder {
    pub(super) fn register_reader(
        &self,
        reader: usize,
        status: Weak<StatusCondition>,
        room: Weak<super::admission::RoomWait>,
    ) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .readers
            .insert(reader, ReaderWake { status, room });
    }

    pub(super) fn pending_before(&self, reader: usize, publisher: u64, gsn: u64) -> usize {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state
            .pending
            .keys()
            .filter(|&&(id, identity, prior)| {
                id == reader && identity == PublisherIdentity::Local(publisher) && prior < gsn
            })
            .count()
    }

    fn advanced(readers: Vec<OrderWake>) {
        for reader in readers {
            match reader {
                OrderWake::Room(room) => {
                    if let Some(room) = room.upgrade() {
                        room.freed_slot();
                    }
                }
                OrderWake::Status(status) => {
                    if let Some(status) = status.upgrade() {
                        // Public WaitSet hooks wait for enclosing consumer/producer guards.
                        super::notices::notify(move || {
                            status.raise_data_available_shared(
                                super::runtime::WakeWord::Extra.index(),
                            )
                        });
                    }
                }
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn before_next_registration(&self, reader: usize, call: Box<dyn FnOnce() + Send>) {
        *self.1.lock().unwrap_or_else(|e| e.into_inner()) = Some(RegistrationHook { reader, call });
    }

    pub(super) fn arrival(
        &self,
        reader: usize,
        slab: SlabHandle,
        publisher: impl Into<PublisherIdentity>,
        gsn: u64,
    ) -> u64 {
        let publisher = publisher.into();
        #[cfg(any(test, feature = "test-support"))]
        {
            let hook = {
                let mut pending = self.1.lock().unwrap_or_else(|e| e.into_inner());
                if pending.as_ref().is_some_and(|hook| hook.reader == reader) {
                    pending.take()
                } else {
                    None
                }
            };
            if let Some(hook) = hook {
                (hook.call)();
            }
        }
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let pending = state.pending.remove(&(reader, publisher, gsn));
        if let Some(token) = pending {
            state.pending_owners.remove(&token);
        }
        let room =
            pending.and_then(|_| state.readers.get(&reader).map(|reader| reader.room.clone()));
        let token = pending.unwrap_or_else(|| Self::insert(&mut state, reader, publisher, gsn));
        state.slabs.insert((reader, slab), token);
        drop(state);
        if let Some(room) = room.and_then(|room| room.upgrade()) {
            room.freed_slot();
        }
        token
    }

    fn insert(state: &mut State, reader: usize, publisher: PublisherIdentity, gsn: u64) -> u64 {
        state.next += 1;
        let token = state.next;
        state.members.insert(
            token,
            Member {
                reader,
                publisher,
                gsn,
                cached: None,
            },
        );
        state
            .publishers
            .entry(publisher)
            .or_default()
            .entry(gsn)
            .or_default()
            .push(token);
        token
    }

    /// Reserve an ordinary change's place while its encoding/admission is pending.
    pub(super) fn reserve(
        &self,
        reader: usize,
        publisher: impl Into<PublisherIdentity>,
        gsn: u64,
    ) -> u64 {
        let publisher = publisher.into();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(token) = state.pending.get(&(reader, publisher, gsn)).copied() {
            *state.pending_owners.entry(token).or_default() += 1;
            return token;
        }
        let token = Self::insert(&mut state, reader, publisher, gsn);
        state.pending.insert((reader, publisher, gsn), token);
        state.pending_owners.insert(token, 1);
        token
    }

    /// A published entry now owns its token. Only an unused reservation rolls back.
    pub(super) fn cancel_pending(&self, token: u64) {
        let readers = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.pending.values().any(|&pending| pending == token) {
                match state.pending_owners.get_mut(&token) {
                    Some(owners) if *owners > 1 => {
                        *owners -= 1;
                        Vec::new()
                    }
                    _ => state.forget(token),
                }
            } else {
                Vec::new()
            }
        };
        Self::advanced(readers);
    }

    pub(super) fn cancel(&self, token: u64) {
        let readers = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .forget(token);
        Self::advanced(readers);
    }

    pub(super) fn claim(&self, reader: usize, slab: SlabHandle) -> Option<u64> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .slabs
            .remove(&(reader, slab))
    }

    pub(super) fn decoded_token(&self, token: u64, key: Option<CacheKey>) {
        let readers = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(key) = key {
                if let Some(member) = state.members.get_mut(&token) {
                    member.cached = Some(key);
                }
                Vec::new()
            } else {
                state.forget(token)
            }
        };
        Self::advanced(readers);
    }

    pub(super) fn decoded(&self, reader: usize, slab: SlabHandle, key: Option<CacheKey>) {
        if let Some(token) = self.claim(reader, slab) {
            self.decoded_token(token, key);
        }
    }

    pub(super) fn reconcile(&self, reader: usize, keys: &[CacheKey]) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let discarded: Vec<_> = state
            .members
            .iter()
            .filter_map(|(&token, member)| {
                (member.reader == reader && member.cached.is_some_and(|key| !keys.contains(&key)))
                    .then_some(token)
            })
            .collect();
        let readers = discarded
            .into_iter()
            .flat_map(|token| state.forget(token))
            .collect();
        drop(state);
        Self::advanced(readers);
    }

    pub(super) fn allows(&self, reader: usize, key: CacheKey) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // Legacy tokenless entries still follow earlier changes of their
        // own writer. Anonymous local bindings use the upper SN tag as their
        // identity; its numeric value never orders different writers.
        let tracked = state
            .members
            .values()
            .any(|member| member.reader == reader && member.cached == Some(key));
        if !tracked
            && state.members.values().any(|member| {
                member.reader == reader
                    && member.cached.is_some_and(|prior| {
                        prior.0 == key.0
                            && (key.0.is_some() || prior.1 >> 32 == key.1 >> 32)
                            && prior.1 < key.1
                    })
            })
        {
            return false;
        }
        state
            .members
            .values()
            .filter(|m| m.reader == reader && m.cached == Some(key))
            .all(|member| {
                state
                    .publishers
                    .get(&member.publisher)
                    .and_then(|queue| queue.first_key_value())
                    .is_none_or(|(&first, _)| member.gsn == first)
            })
    }

    pub(super) fn accessed(&self, reader: usize, key: CacheKey) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let accessed: Vec<_> = state
            .members
            .iter()
            .filter_map(|(&token, member)| {
                (member.reader == reader && member.cached == Some(key)).then_some(token)
            })
            .collect();
        let readers = accessed
            .into_iter()
            .flat_map(|token| state.forget(token))
            .collect();
        drop(state);
        Self::advanced(readers);
    }

    pub(super) fn forget_reader(&self, reader: usize) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.readers.remove(&reader);
        let tokens: Vec<_> = state
            .members
            .iter()
            .filter_map(|(&token, member)| (member.reader == reader).then_some(token))
            .collect();
        let readers = tokens
            .into_iter()
            .flat_map(|token| state.forget(token))
            .collect();
        drop(state);
        Self::advanced(readers);
    }
}

#[cfg(test)]
mod shared_pending_tests {
    use super::*;

    #[test]
    fn replay_and_live_owners_share_one_pending_position() {
        let order = LocalReadOrder::default();
        let first = order.reserve(1, 7u64, 1);
        assert_eq!(order.reserve(1, 7u64, 1), first);
        let later = order.arrival(2, SlabHandle::EMPTY, 7u64, 2);
        let key = (Some([2; 16]), 1);
        order.decoded_token(later, Some(key));
        order.cancel_pending(first);
        assert!(
            !order.allows(2, key),
            "one owner withdrew another owner's position"
        );
        order.cancel_pending(first);
        assert!(order.allows(2, key));
    }

    #[test]
    fn a_visible_entry_takes_over_all_pending_owners() {
        let order = LocalReadOrder::default();
        let first = order.reserve(1, 7u64, 1);
        assert_eq!(order.reserve(1, 7u64, 1), first);
        assert_eq!(order.arrival(1, SlabHandle::EMPTY, 7u64, 1), first);
        let key = (Some([1; 16]), 1);
        order.decoded_token(first, Some(key));
        order.cancel_pending(first);
        order.cancel_pending(first);
        assert!(order.allows(1, key));
        assert!(order.0.lock().unwrap().members.contains_key(&first));
        order.accessed(1, key);
        let state = order.0.lock().unwrap();
        assert!(state.members.is_empty());
        assert!(state.pending_owners.is_empty());
    }
}
