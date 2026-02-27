// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Replay registry for transient-local durability.
//!
//! Allows local writers to register a callback that replays historical samples
//! when a late-joining reader is discovered.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};

type ReplayCallback = Arc<dyn Fn(SocketAddr) + Send + Sync>;

#[derive(Clone)]
struct ReplayHook {
    id: u64,
    type_name: Arc<str>,
    callback: ReplayCallback,
}

struct ReplayRegistryInner {
    hooks: RwLock<HashMap<String, Vec<ReplayHook>>>,
    next_id: AtomicU64,
}

/// Registration token that removes a replay hook on drop.
#[derive(Debug)]
pub struct ReplayToken {
    id: u64,
    topic: String,
    inner: Weak<ReplayRegistryInner>,
}

impl Drop for ReplayToken {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };

        let mut hooks = match inner.hooks.write() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(list) = hooks.get_mut(&self.topic) {
            list.retain(|hook| hook.id != self.id);
            if list.is_empty() {
                hooks.remove(&self.topic);
            }
        }
    }
}

/// Registry of local writer replay callbacks keyed by topic.
#[derive(Clone)]
pub struct ReplayRegistry {
    inner: Arc<ReplayRegistryInner>,
}

impl ReplayRegistry {
    /// Create a new empty replay registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ReplayRegistryInner {
                hooks: RwLock::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// Register a replay callback for a topic + type.
    ///
    /// Returns a token that unregisters the callback on drop.
    pub fn register(
        &self,
        topic: impl Into<String>,
        type_name: impl AsRef<str>,
        callback: ReplayCallback,
    ) -> ReplayToken {
        let topic = topic.into();
        let type_name: Arc<str> = Arc::from(type_name.as_ref());
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);

        let hook = ReplayHook {
            id,
            type_name,
            callback,
        };

        let mut hooks = match self.inner.hooks.write() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
        hooks.entry(topic.clone()).or_default().push(hook);

        ReplayToken {
            id,
            topic,
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Replay to all registered callbacks for the topic + type.
    pub fn replay_for(&self, topic: &str, type_name: &str, target: SocketAddr) {
        let callbacks: Vec<ReplayCallback> = {
            let hooks = match self.inner.hooks.read() {
                Ok(lock) => lock,
                Err(poisoned) => poisoned.into_inner(),
            };

            hooks
                .get(topic)
                .map(|list| {
                    list.iter()
                        .filter(|hook| hook.type_name.as_ref() == type_name)
                        .map(|hook| Arc::clone(&hook.callback))
                        .collect()
                })
                .unwrap_or_default()
        };

        for callback in callbacks {
            callback(target);
        }
    }
}

impl Default for ReplayRegistry {
    fn default() -> Self {
        Self::new()
    }
}
