// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Concurrent LRU cache for DDS/ROS2 type metadata.
//!
//! The TypeCache ensures that expensive ROS2 type introspection happens only
//! once per `(distro, fully-qualified-name, hash)` combination. Subsequent
//! lookups are served via lock-free reads that hit an in-memory LRU cache.
//! A secondary dashmap keeps track of "pinned" entries that must never be
//! evicted (ROS2 core types, common messages, etc.).

use crate::xtypes::{
    BuilderError, MessageDescriptor, RosMessageMetadata, RosidlError, TypeObjectBuilder,
};
use dashmap::DashSet;
use lru::LruCache;
use parking_lot::RwLock;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use super::distro::Distro;
use super::handle::{TypeObjectHandle, ROS_HASH_SIZE};

/// Identifies a TypeObject uniquely across distributions.
#[derive(Clone, Debug, Eq)]
pub struct TypeKey {
    distro: Distro,
    fqn: Arc<str>,
    rihs: Arc<[u8; ROS_HASH_SIZE]>,
}

impl PartialEq for TypeKey {
    fn eq(&self, other: &Self) -> bool {
        self.distro == other.distro && self.fqn == other.fqn && self.rihs == other.rihs
    }
}

impl Hash for TypeKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.distro.hash(state);
        self.fqn.hash(state);
        self.rihs.hash(state);
    }
}

/// Cache hit/miss statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct LookupStats {
    pub hits: u64,
    pub misses: u64,
    pub last_hit_ns: u64,
    pub last_miss_ns: u64,
}

/// LRU-based concurrent cache for TypeObject handles.
pub struct TypeCache {
    inner: RwLock<LruCache<TypeKey, Arc<TypeObjectHandle>>>,
    pinned: DashSet<TypeKey>,
    stats: RwLock<LookupStats>,
}

impl TypeCache {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            #[allow(clippy::expect_used)] // caller must pass capacity > 0; API contract
            inner: RwLock::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("capacity > 0"),
            )),
            pinned: DashSet::new(),
            stats: RwLock::new(LookupStats::default()),
        }
    }

    #[must_use]
    fn make_key(distro: Distro, fqn: &str, rihs: &[u8]) -> TypeKey {
        assert_eq!(
            rihs.len(),
            ROS_HASH_SIZE,
            "TypeCache keys require a {}-byte RIHS hash",
            ROS_HASH_SIZE
        );

        #[allow(clippy::expect_used)] // length validated by assert_eq above
        let hash_slice: &[u8; ROS_HASH_SIZE] = rihs
            .try_into()
            .expect("validated length to match ROS hash size");
        let hash: Arc<[u8; ROS_HASH_SIZE]> = Arc::new(*hash_slice);

        TypeKey {
            distro,
            fqn: fqn.into(),
            rihs: hash,
        }
    }

    #[must_use]
    pub fn get_or_build<F>(
        &self,
        distro: Distro,
        fqn: &str,
        rihs: &[u8],
        build: F,
    ) -> Arc<TypeObjectHandle>
    where
        F: FnOnce() -> TypeObjectHandle,
    {
        #[allow(clippy::expect_used)] // Ok::<_, ()> closure is infallible by construction
        self.get_or_try_build(distro, fqn, rihs, || Ok::<TypeObjectHandle, ()>(build()))
            .expect("builder closure is infallible")
    }

    pub fn get_or_try_build<F, E>(
        &self,
        distro: Distro,
        fqn: &str,
        rihs: &[u8],
        build: F,
    ) -> Result<Arc<TypeObjectHandle>, E>
    where
        F: FnOnce() -> Result<TypeObjectHandle, E>,
    {
        let key = Self::make_key(distro, fqn, rihs);

        if let Some(hit) = self.try_peek(&key) {
            self.record_hit();
            return Ok(hit);
        }

        let mut cache = self.inner.write();
        if let Some(hit) = cache.get(&key) {
            self.record_hit();
            return Ok(Arc::clone(hit));
        }

        let start = Instant::now();
        let built = Arc::new(build()?);
        debug_assert_eq!(
            built.ros_hash.as_ref(),
            key.rihs.as_ref(),
            "TypeObjectHandle hash must match lookup key"
        );

        if cache.len() >= cache.cap().into() && !self.free_slot(&mut cache) {
            self.record_miss(start);
            return Ok(built);
        }

        cache.put(key.clone(), Arc::clone(&built));
        self.record_miss(start);
        Ok(built)
    }

    pub fn pin(&self, distro: Distro, fqn: &str, rihs: &[u8]) {
        let key = Self::make_key(distro, fqn, rihs);
        self.pinned.insert(key);
    }

    /// Convenience helper that builds a [`TypeObjectHandle`] from a safe message descriptor.
    pub fn get_or_build_from_descriptor(
        &self,
        distro: Distro,
        descriptor: &MessageDescriptor<'_>,
    ) -> Result<Arc<TypeObjectHandle>, BuilderError> {
        let fqn = descriptor.fqn();
        self.get_or_try_build(distro, &fqn, descriptor.ros_hash, || {
            TypeObjectBuilder::from_descriptor(distro, descriptor)
        })
    }

    /// Convenience helper that builds a [`TypeObjectHandle`] from a ROS 2 type support handle.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer remains valid for the duration of the call and points to
    /// a `rosidl_message_type_support_t` originating from `rosidl_typesupport_introspection_c`.
    pub unsafe fn get_or_build_from_type_support(
        &self,
        distro: Distro,
        type_support: *const crate::xtypes::rosidl_message_type_support_t,
    ) -> Result<Arc<TypeObjectHandle>, RosidlError> {
        let metadata = RosMessageMetadata::from_type_support(type_support)?;
        let hash = metadata.hash_value;
        let fqn = metadata.fqn.clone();
        let build_metadata = metadata.clone();

        self.get_or_try_build(distro, &fqn, &hash, move || {
            TypeObjectBuilder::from_ros_metadata(distro, build_metadata.clone())
        })
    }

    #[must_use]
    pub fn stats(&self) -> LookupStats {
        *self.stats.read()
    }

    fn try_peek(&self, key: &TypeKey) -> Option<Arc<TypeObjectHandle>> {
        let cache = self.inner.read();
        cache.peek(key).map(Arc::clone)
    }
    fn free_slot(&self, cache: &mut LruCache<TypeKey, Arc<TypeObjectHandle>>) -> bool {
        if cache.len() < cache.cap().into() {
            return true;
        }

        let attempts = cache.len();
        for _ in 0..attempts {
            if let Some((old_key, old_value)) = cache.pop_lru() {
                if self.pinned.contains(&old_key) {
                    cache.put(old_key, old_value);
                } else {
                    return true;
                }
            } else {
                break;
            }
        }

        false
    }

    fn record_hit(&self) {
        let mut stats = self.stats.write();
        stats.hits = stats.hits.saturating_add(1);
        stats.last_hit_ns = 0;
    }

    fn record_miss(&self, start: Instant) {
        let mut stats = self.stats.write();
        stats.misses = stats.misses.saturating_add(1);
        stats.last_miss_ns = start.elapsed().as_nanos() as u64;
    }
}

#[cfg(test)]
mod tests;
