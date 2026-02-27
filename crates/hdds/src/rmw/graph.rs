// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::core::types::{TypeObjectHandle, ROS_HASH_SIZE};
use parking_lot::RwLock;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;

pub const RMW_GID_STORAGE_SIZE: usize = 24;

/// Aggregate information for a single topic within the local ROS graph.
#[derive(Clone, Debug)]
pub struct TopicSummary {
    pub name: String,
    pub type_name: String,
    pub type_hash: [u8; ROS_HASH_SIZE],
    pub writer_count: u32,
    pub reader_count: u32,
}

/// QoS settings captured for a graph endpoint.
#[derive(Clone, Debug, Default)]
pub struct EndpointQos {
    pub history: u8,
    pub depth: u32,
    pub reliability: u8,
    pub durability: u8,
    pub deadline_ns: u64,
    pub lifespan_ns: u64,
    pub liveliness: u8,
    pub liveliness_lease_ns: u64,
    pub avoid_ros_namespace_conventions: bool,
}

/// Summary of a single endpoint exposed by a node.
#[derive(Clone, Debug)]
pub struct NodeEndpointSummary {
    pub topic: String,
    pub type_name: String,
    pub type_hash: [u8; ROS_HASH_SIZE],
    pub gid: [u8; RMW_GID_STORAGE_SIZE],
    pub qos: EndpointQos,
}

/// Snapshot of a single node (name/namespace + its publishers/subscribers).
#[derive(Clone, Debug)]
pub struct NodeSummary {
    pub name: String,
    pub namespace: String,
    pub enclave: String,
    pub publishers: Vec<NodeEndpointSummary>,
    pub subscriptions: Vec<NodeEndpointSummary>,
}

/// Immutable snapshot of the graph cache (topics + nodes).
#[derive(Clone, Debug)]
pub struct GraphSnapshot {
    pub version: u64,
    pub topics: Vec<TopicSummary>,
    pub nodes: Vec<NodeSummary>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct NodeKey {
    name: String,
    namespace: String,
}

impl NodeKey {
    fn new(name: &str, namespace: &str) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
        }
    }
}

struct NodeState {
    publishers: Vec<NodeEndpointSummary>,
    subscriptions: Vec<NodeEndpointSummary>,
    enclave: String,
    explicit: bool,
}

impl NodeState {
    fn new(enclave: &str, explicit: bool) -> Self {
        Self {
            publishers: Vec::new(),
            subscriptions: Vec::new(),
            enclave: enclave.to_string(),
            explicit,
        }
    }

    fn summary(key: &NodeKey, state: &NodeState) -> NodeSummary {
        let mut publishers = state.publishers.clone();
        publishers.sort_by(|a, b| a.topic.cmp(&b.topic));

        let mut subscriptions = state.subscriptions.clone();
        subscriptions.sort_by(|a, b| a.topic.cmp(&b.topic));

        NodeSummary {
            name: key.name.clone(),
            namespace: key.namespace.clone(),
            enclave: state.enclave.clone(),
            publishers,
            subscriptions,
        }
    }
}

struct TopicState {
    handle: Arc<TypeObjectHandle>,
    writers: u32,
    readers: u32,
}

impl TopicState {
    fn new(handle: Arc<TypeObjectHandle>) -> Self {
        Self {
            handle,
            writers: 0,
            readers: 0,
        }
    }

    fn summary(name: &str, state: &TopicState) -> TopicSummary {
        let type_name = state
            .handle
            .type_name()
            .unwrap_or(state.handle.fqn.as_ref())
            .to_string();

        TopicSummary {
            name: name.to_string(),
            type_name,
            type_hash: *state.handle.ros_hash,
            writer_count: state.writers,
            reader_count: state.readers,
        }
    }
}

#[derive(Default)]
struct GraphState {
    version: u64,
    topics: HashMap<String, TopicState>,
    nodes: HashMap<NodeKey, NodeState>,
}

/// Tracks graph changes to power rmw graph queries (nodes/topics/types).
pub struct GraphCache {
    state: RwLock<GraphState>,
}

impl GraphCache {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(GraphState::default()),
        }
    }

    pub fn register_topic_type(&self, topic: &str, handle: Arc<TypeObjectHandle>) -> bool {
        let mut guard = self.state.write();
        match guard.topics.entry(topic.to_string()) {
            Entry::Occupied(mut entry) => {
                if Arc::ptr_eq(&entry.get().handle, &handle) {
                    false
                } else {
                    entry.get_mut().handle = handle;
                    guard.version += 1;
                    true
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(TopicState::new(handle));
                guard.version += 1;
                true
            }
        }
    }

    pub fn register_writer(&self, topic: &str) -> bool {
        let mut guard = self.state.write();
        if let Some(state) = guard.topics.get_mut(topic) {
            state.writers = state.writers.saturating_add(1);
            guard.version += 1;
            true
        } else {
            false
        }
    }

    pub fn unregister_writer(&self, topic: &str) -> bool {
        let mut guard = self.state.write();
        if let Some(state) = guard.topics.get_mut(topic) {
            if state.writers > 0 {
                state.writers -= 1;
                guard.version += 1;
                return true;
            }
        }
        false
    }

    pub fn register_reader(&self, topic: &str) -> bool {
        let mut guard = self.state.write();
        if let Some(state) = guard.topics.get_mut(topic) {
            state.readers = state.readers.saturating_add(1);
            guard.version += 1;
            true
        } else {
            false
        }
    }

    pub fn unregister_reader(&self, topic: &str) -> bool {
        let mut guard = self.state.write();
        if let Some(state) = guard.topics.get_mut(topic) {
            if state.readers > 0 {
                state.readers -= 1;
                guard.version += 1;
                return true;
            }
        }
        false
    }

    pub fn register_node(&self, name: &str, namespace: &str) -> bool {
        let mut guard = self.state.write();
        let key = NodeKey::new(name, namespace);
        match guard.nodes.entry(key) {
            Entry::Occupied(mut entry) => {
                let node = entry.get_mut();
                if node.explicit {
                    false
                } else {
                    node.explicit = true;
                    guard.version += 1;
                    true
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(NodeState::new("", true));
                guard.version += 1;
                true
            }
        }
    }

    pub fn register_node_with_enclave(&self, name: &str, namespace: &str, enclave: &str) -> bool {
        let mut guard = self.state.write();
        let key = NodeKey::new(name, namespace);
        match guard.nodes.entry(key) {
            Entry::Occupied(mut entry) => {
                let node = entry.get_mut();
                let mut changed = false;
                if node.enclave != enclave {
                    node.enclave = enclave.to_string();
                    changed = true;
                }
                if !node.explicit {
                    node.explicit = true;
                    changed = true;
                }
                if changed {
                    guard.version += 1;
                }
                changed
            }
            Entry::Vacant(slot) => {
                slot.insert(NodeState::new(enclave, true));
                guard.version += 1;
                true
            }
        }
    }

    pub fn unregister_node(&self, name: &str, namespace: &str) -> bool {
        let mut guard = self.state.write();
        let key = NodeKey::new(name, namespace);
        if guard.nodes.remove(&key).is_some() {
            guard.version += 1;
            true
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)] // ROS2 rmw API requirements
    pub fn register_publisher_endpoint(
        &self,
        name: &str,
        namespace: &str,
        topic: &str,
        type_name: &str,
        type_hash: &[u8; ROS_HASH_SIZE],
        gid: &[u8; RMW_GID_STORAGE_SIZE],
        qos: EndpointQos,
    ) -> bool {
        self.insert_endpoint(name, namespace, topic, type_name, type_hash, gid, qos, true)
    }

    pub fn unregister_publisher_endpoint(
        &self,
        name: &str,
        namespace: &str,
        topic: &str,
        gid: &[u8; RMW_GID_STORAGE_SIZE],
    ) -> bool {
        self.remove_endpoint(name, namespace, topic, gid, true)
    }

    #[allow(clippy::too_many_arguments)] // ROS2 rmw API requirements
    pub fn register_subscription_endpoint(
        &self,
        name: &str,
        namespace: &str,
        topic: &str,
        type_name: &str,
        type_hash: &[u8; ROS_HASH_SIZE],
        gid: &[u8; RMW_GID_STORAGE_SIZE],
        qos: EndpointQos,
    ) -> bool {
        self.insert_endpoint(
            name, namespace, topic, type_name, type_hash, gid, qos, false,
        )
    }

    pub fn unregister_subscription_endpoint(
        &self,
        name: &str,
        namespace: &str,
        topic: &str,
        gid: &[u8; RMW_GID_STORAGE_SIZE],
    ) -> bool {
        self.remove_endpoint(name, namespace, topic, gid, false)
    }

    pub fn snapshot(&self) -> GraphSnapshot {
        let guard = self.state.read();

        let mut topics: Vec<_> = guard
            .topics
            .iter()
            .map(|(name, state)| TopicState::summary(name, state))
            .collect();
        topics.sort_by(|a, b| a.name.cmp(&b.name));

        let mut nodes: Vec<_> = guard
            .nodes
            .iter()
            .map(|(key, state)| NodeState::summary(key, state))
            .collect();
        nodes.sort_by(|a, b| match a.name.cmp(&b.name) {
            std::cmp::Ordering::Equal => a.namespace.cmp(&b.namespace),
            other => other,
        });

        GraphSnapshot {
            version: guard.version,
            topics,
            nodes,
        }
    }

    #[allow(clippy::too_many_arguments)] // ROS2 rmw internal - all fields needed
    fn insert_endpoint(
        &self,
        name: &str,
        namespace: &str,
        topic: &str,
        type_name: &str,
        type_hash: &[u8; ROS_HASH_SIZE],
        gid: &[u8; RMW_GID_STORAGE_SIZE],
        qos: EndpointQos,
        is_publisher: bool,
    ) -> bool {
        let mut guard = self.state.write();
        let key = NodeKey::new(name, namespace);
        let node = guard
            .nodes
            .entry(key)
            .or_insert_with(|| NodeState::new("", false));

        let entries = if is_publisher {
            &mut node.publishers
        } else {
            &mut node.subscriptions
        };

        if let Some(entry) = entries.iter_mut().find(|entry| entry.gid == *gid) {
            entry.topic = topic.to_string();
            entry.type_name = type_name.to_string();
            entry.type_hash = *type_hash;
            entry.qos = qos;
            guard.version += 1;
            return true;
        }

        entries.push(NodeEndpointSummary {
            topic: topic.to_string(),
            type_name: type_name.to_string(),
            type_hash: *type_hash,
            gid: *gid,
            qos,
        });

        guard.version += 1;
        true
    }

    fn remove_endpoint(
        &self,
        name: &str,
        namespace: &str,
        topic: &str,
        gid: &[u8; RMW_GID_STORAGE_SIZE],
        is_publisher: bool,
    ) -> bool {
        let mut guard = self.state.write();
        let key = NodeKey::new(name, namespace);
        let mut removed = false;

        if let Entry::Occupied(mut node_entry) = guard.nodes.entry(key) {
            let node = node_entry.get_mut();
            let entries = if is_publisher {
                &mut node.publishers
            } else {
                &mut node.subscriptions
            };

            if let Some(index) = entries
                .iter()
                .position(|entry| entry.topic == topic && entry.gid == *gid)
            {
                entries.swap_remove(index);
                removed = true;
            }

            if !node.explicit && node.publishers.is_empty() && node.subscriptions.is_empty() {
                node_entry.remove();
            }
        }

        if removed {
            guard.version += 1;
        }

        removed
    }
}

impl Default for GraphCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::Distro;
    use crate::xtypes::{
        CompleteStructHeader, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
        MinimalStructHeader, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
        StructTypeFlag, TypeIdentifier, TypeKind,
    };
    use std::sync::Arc;

    fn sample_hash(seed: u8) -> [u8; ROS_HASH_SIZE] {
        let mut bytes = [0u8; ROS_HASH_SIZE];
        for (idx, byte) in bytes.iter_mut().enumerate() {
            let idx_u8 = u8::try_from(idx).expect("hash index fits in u8");
            *byte = seed.wrapping_add(idx_u8);
        }
        bytes
    }

    fn dummy_handle(distro: Distro, fqn: &str, hash: [u8; ROS_HASH_SIZE]) -> TypeObjectHandle {
        let complete = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(fqn),
            },
            member_seq: Vec::new(),
        });

        let minimal = MinimalTypeObject::Struct(MinimalStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: MinimalStructHeader {
                base_type: None,
                detail: MinimalTypeDetail::new(),
            },
            member_seq: Vec::new(),
        });

        TypeObjectHandle::new(
            distro,
            Arc::<str>::from(fqn),
            1,
            Arc::new(hash),
            complete,
            minimal,
            TypeIdentifier::primitive(TypeKind::TK_INT32),
            TypeIdentifier::primitive(TypeKind::TK_INT32),
        )
    }

    #[test]
    fn graph_cache_tracks_nodes_topics_endpoints() {
        let cache = GraphCache::new();
        let hash = sample_hash(1);
        let handle = Arc::new(dummy_handle(Distro::Humble, "pkg/Type", hash));

        assert!(cache.register_topic_type("chatter", Arc::clone(&handle)));
        assert!(cache.register_writer("chatter"));
        assert!(cache.register_reader("chatter"));

        let qos = EndpointQos {
            depth: 10,
            reliability: 1,
            ..Default::default()
        };

        let gid_pub = [1u8; RMW_GID_STORAGE_SIZE];
        let gid_sub = [2u8; RMW_GID_STORAGE_SIZE];

        assert!(cache.register_node_with_enclave("node", "/ns", "enclave"));
        assert!(cache.register_publisher_endpoint(
            "node",
            "/ns",
            "chatter",
            "pkg/Type",
            &hash,
            &gid_pub,
            qos.clone(),
        ));
        assert!(cache.register_subscription_endpoint(
            "node",
            "/ns",
            "chatter",
            "pkg/Type",
            &hash,
            &gid_sub,
            qos.clone(),
        ));

        let snapshot = cache.snapshot();
        assert_eq!(snapshot.topics.len(), 1);
        assert_eq!(snapshot.topics[0].name, "chatter");
        assert_eq!(snapshot.topics[0].writer_count, 1);
        assert_eq!(snapshot.topics[0].reader_count, 1);

        assert_eq!(snapshot.nodes.len(), 1);
        let node = &snapshot.nodes[0];
        assert_eq!(node.name, "node");
        assert_eq!(node.namespace, "/ns");
        assert_eq!(node.enclave, "enclave");
        assert_eq!(node.publishers.len(), 1);
        assert_eq!(node.subscriptions.len(), 1);
        assert_eq!(node.publishers[0].gid, gid_pub);
        assert_eq!(node.subscriptions[0].gid, gid_sub);
    }
}
