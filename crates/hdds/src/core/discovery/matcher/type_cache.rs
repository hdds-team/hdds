// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! A bounded, content-addressed store of peers' TypeObjects.
//!
//! Each entry is keyed by the EquivalenceHash it was verified against and
//! tagged with the participants that served it. Full, the least recently
//! inserted or touched entry gives way; a participant that leaves takes the
//! entries only it served with it. Never full in the sense of refusing: a
//! store that stops accepting at its bound starves every type learned after
//! it, for the life of the participant.

use crate::xtypes::{CompleteTypeObject, EquivalenceHash};
use std::collections::HashMap;

/// Entries a store keeps.
pub(crate) const TYPE_CACHE_CAPACITY: usize = 1024;

/// See the module documentation.
pub(crate) struct TypeCache {
    objects: HashMap<EquivalenceHash, CompleteTypeObject>,
    meta: HashMap<EquivalenceHash, (u64, Vec<[u8; 12]>)>,
    clock: u64,
    capacity: usize,
}

impl Default for TypeCache {
    fn default() -> Self {
        Self::with_capacity(TYPE_CACHE_CAPACITY)
    }
}

impl TypeCache {
    /// An empty store keeping at most `capacity` entries.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            objects: HashMap::new(),
            meta: HashMap::new(),
            clock: 0,
            capacity: capacity.max(1),
        }
    }

    /// Store `object` under `hash`, served by `peer`; evicts the least
    /// recently used entry when full.
    pub(crate) fn insert(
        &mut self,
        hash: EquivalenceHash,
        object: CompleteTypeObject,
        peer: [u8; 12],
    ) {
        self.clock += 1;
        if !self.objects.contains_key(&hash) && self.objects.len() >= self.capacity {
            let oldest = self
                .meta
                .iter()
                .min_by_key(|(_, (tick, _))| *tick)
                .map(|(h, _)| *h);
            if let Some(oldest) = oldest {
                self.objects.remove(&oldest);
                self.meta.remove(&oldest);
            }
        }
        self.objects.insert(hash, object);
        let entry = self.meta.entry(hash).or_insert((0, Vec::new()));
        entry.0 = self.clock;
        if !entry.1.contains(&peer) {
            entry.1.push(peer);
        }
    }

    /// Mark `hash` as just used.
    pub(crate) fn touch(&mut self, hash: &EquivalenceHash) {
        self.clock += 1;
        if let Some(entry) = self.meta.get_mut(hash) {
            entry.0 = self.clock;
        }
    }

    /// The object stored under `hash`.
    pub(crate) fn get(&self, hash: &EquivalenceHash) -> Option<&CompleteTypeObject> {
        self.objects.get(hash)
    }

    /// Whether `hash` is stored.
    #[cfg(test)]
    pub(crate) fn contains_key(&self, hash: &EquivalenceHash) -> bool {
        self.objects.contains_key(hash)
    }

    /// Entries stored.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.objects.len()
    }

    /// The stored objects, by hash.
    pub(crate) fn objects(&self) -> &HashMap<EquivalenceHash, CompleteTypeObject> {
        &self.objects
    }

    /// The participants entries were learned from.
    pub(crate) fn peers(&self) -> Vec<[u8; 12]> {
        let mut out: Vec<[u8; 12]> = Vec::new();
        for (_, peers) in self.meta.values() {
            for p in peers {
                if !out.contains(p) {
                    out.push(*p);
                }
            }
        }
        out
    }

    /// `peer` left: drop it from every entry, and the entries only it served.
    pub(crate) fn forget_peer(&mut self, peer: &[u8; 12]) {
        let objects = &mut self.objects;
        self.meta.retain(|hash, (_, peers)| {
            peers.retain(|p| p != peer);
            if peers.is_empty() {
                objects.remove(hash);
                false
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        CompleteStructHeader, CompleteStructType, CompleteTypeDetail, StructTypeFlag,
    };

    fn obj(name: &str) -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: Vec::new(),
        })
    }

    fn h(i: u8) -> EquivalenceHash {
        EquivalenceHash::from_bytes([i; 14])
    }

    #[test]
    fn a_full_cache_evicts_the_least_recently_used_and_keeps_accepting() {
        let mut c = TypeCache::with_capacity(3);
        c.insert(h(1), obj("a"), [1; 12]);
        c.insert(h(2), obj("b"), [1; 12]);
        c.insert(h(3), obj("c"), [1; 12]);
        c.touch(&h(1));
        c.insert(h(4), obj("d"), [1; 12]);
        assert_eq!(c.len(), 3, "bounded");
        assert!(!c.contains_key(&h(2)), "2, least recently used, evicted");
        assert!(c.contains_key(&h(1)) && c.contains_key(&h(3)));
        assert!(c.contains_key(&h(4)), "a full cache still accepts");
    }

    #[test]
    fn a_departed_peer_takes_only_what_it_alone_served() {
        let mut c = TypeCache::with_capacity(8);
        c.insert(h(1), obj("a"), [1; 12]);
        c.insert(h(2), obj("b"), [1; 12]);
        c.insert(h(2), obj("b"), [2; 12]);
        c.forget_peer(&[1; 12]);
        assert!(!c.contains_key(&h(1)));
        assert!(c.contains_key(&h(2)), "still served by peer 2");
        assert_eq!(c.peers(), vec![[2; 12]]);
    }
}
