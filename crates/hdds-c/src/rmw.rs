// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::{BytePayload, HddsError, HddsRmwQosProfile};
use hdds::api::{DataReader, DataWriter, Error as ApiError, GuardCondition, QoS, StatusCondition};
use hdds::core::rt::TopicMerger;
#[cfg(feature = "xtypes")]
use hdds::core::types::TypeObjectHandle;
use hdds::core::types::ROS_HASH_SIZE;
use hdds::qos::Reliability;
use hdds::rmw::context::RmwContext;
use hdds::rmw::graph::{EndpointQos, NodeEndpointSummary, RMW_GID_STORAGE_SIZE};
use hdds::rmw::waitset::{ConditionHandle, ConditionKey};
use hdds::transport::shm::{self as shm, ShmRingReader, ShmRingWriter, DEFAULT_RING_CAPACITY};
use hdds::xtypes::builder::{
    rosidl_message_type_support_t, rosidl_typesupport_introspection_c__MessageMember,
    RosMessageMetadata, RosidlError,
};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::fmt;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

mod codec;
mod dynamic_to_ros;
mod ros2_types;

pub use codec::Ros2CodecKind;
pub use dynamic_to_ros::deserialize_dynamic_to_ros;
pub use ros2_types::ros2_type_to_descriptor;

impl From<HddsRmwQosProfile> for EndpointQos {
    fn from(profile: HddsRmwQosProfile) -> Self {
        EndpointQos {
            history: profile.history,
            depth: profile.depth,
            reliability: profile.reliability,
            durability: profile.durability,
            deadline_ns: profile.deadline_ns,
            lifespan_ns: profile.lifespan_ns,
            liveliness: profile.liveliness,
            liveliness_lease_ns: profile.liveliness_lease_ns,
            avoid_ros_namespace_conventions: profile.avoid_ros_namespace_conventions,
        }
    }
}

impl From<&EndpointQos> for HddsRmwQosProfile {
    fn from(qos: &EndpointQos) -> Self {
        HddsRmwQosProfile {
            history: qos.history,
            depth: qos.depth,
            reliability: qos.reliability,
            durability: qos.durability,
            deadline_ns: qos.deadline_ns,
            lifespan_ns: qos.lifespan_ns,
            liveliness: qos.liveliness,
            liveliness_lease_ns: qos.liveliness_lease_ns,
            avoid_ros_namespace_conventions: qos.avoid_ros_namespace_conventions,
        }
    }
}

pub unsafe fn encode_special(
    codec: Ros2CodecKind,
    ros_message: *const c_void,
) -> Result<Option<BytePayload>, ApiError> {
    codec::encode(codec, ros_message)
}

pub unsafe fn decode_special(
    codec: Ros2CodecKind,
    data: &[u8],
    ros_message: *mut c_void,
) -> Result<bool, ApiError> {
    codec::decode(codec, data, ros_message)
}

const ROS_TYPE_FLOAT: u8 = 1;
const ROS_TYPE_DOUBLE: u8 = 2;
const ROS_TYPE_LONG_DOUBLE: u8 = 3;
const ROS_TYPE_CHAR: u8 = 4;
const ROS_TYPE_WCHAR: u8 = 5;
const ROS_TYPE_BOOLEAN: u8 = 6;
const ROS_TYPE_OCTET: u8 = 7;
const ROS_TYPE_UINT8: u8 = 8;
const ROS_TYPE_INT8: u8 = 9;
const ROS_TYPE_UINT16: u8 = 10;
const ROS_TYPE_INT16: u8 = 11;
const ROS_TYPE_UINT32: u8 = 12;
const ROS_TYPE_INT32: u8 = 13;
const ROS_TYPE_UINT64: u8 = 14;
const ROS_TYPE_INT64: u8 = 15;
const ROS_TYPE_STRING: u8 = 16;
const ROS_TYPE_WSTRING: u8 = 17;
const ROS_TYPE_MESSAGE: u8 = 18;

#[cfg(target_os = "windows")]
const LONG_DOUBLE_SIZE: usize = 8;
#[cfg(not(target_os = "windows"))]
const LONG_DOUBLE_SIZE: usize = 16;

#[cfg(target_os = "windows")]
const LONG_DOUBLE_ALIGN: usize = 8;
#[cfg(not(target_os = "windows"))]
const LONG_DOUBLE_ALIGN: usize = 16;

/// Internal wrapper used by the C bindings to manage an `RmwContext`.
///
/// # Lock ordering rules
///
/// When acquiring multiple locks, always respect this hierarchy (acquire
/// higher-numbered locks AFTER lower-numbered ones):
///
///   1. `registry`
///   2. `reader_map`              (registry must be held or released first)
///   3. `graph_guard_ptr`         (only acquired inside `wait()` while registry held)
///   4. `writer_mergers`          (never held simultaneously with reader_ptrs_by_topic)
///   5. `reader_ptrs_by_topic`    (never held simultaneously with writer_mergers)
///   6. `reader_status`           (independent, never overlaps with 1-5)
///   7. `shm_writers`             (independent)
///   8. `shm_readers_by_topic`    (independent)
///
/// For `ForeignRmwWaitSet`: `reader_keys` must NEVER be held when calling
/// context methods that acquire `registry` or `reader_map`.
pub struct ForeignRmwContext {
    ctx: RmwContext,
    registry: Mutex<HashMap<ConditionKey, ConditionRecord>>,
    reader_map: Mutex<HashMap<*const c_void, ConditionKey>>,
    reader_status: Mutex<HashMap<*const c_void, Arc<StatusCondition>>>,
    graph_guard_ptr: Mutex<Option<*const GuardCondition>>,
    #[cfg(feature = "xtypes")]
    type_handles: Mutex<HashMap<*const rosidl_message_type_support_t, Arc<TypeObjectHandle>>>,
    #[cfg(feature = "xtypes")]
    topic_types: Mutex<HashMap<String, Arc<TypeObjectHandle>>>,
    metadata_cache: Mutex<HashMap<*const rosidl_message_type_support_t, Arc<RosMessageMetadata>>>,
    /// Writer mergers keyed by topic for intra-process binding
    writer_mergers: Mutex<HashMap<String, Vec<Arc<TopicMerger>>>>,
    /// Reader pointers keyed by topic for late writer binding
    reader_ptrs_by_topic: Mutex<HashMap<String, Vec<*const c_void>>>,
    /// SHM ring writers keyed by topic (for inter-process same-machine delivery).
    /// RwLock<HashMap> + per-topic Mutex avoids serializing different topics on publish.
    shm_writers: RwLock<HashMap<String, Mutex<ShmRingWriter>>>,
    /// SHM ring readers keyed by topic (for inter-process same-machine receive).
    shm_readers_by_topic: RwLock<HashMap<String, Mutex<Vec<ShmRingReader>>>>,
}

struct ConditionRecord {
    raw_ptr: *const c_void,
    handle: ConditionHandle,
    reader_ptr: Option<*const c_void>,
}

pub(crate) struct WaitHit {
    pub(crate) key: ConditionKey,
    pub(crate) condition_ptr: *const c_void,
    pub(crate) reader_ptr: Option<*const c_void>,
}

pub struct ForeignRmwWaitSet {
    ctx: Arc<ForeignRmwContext>,
    reader_keys: Mutex<HashMap<*const c_void, ConditionKey>>,
}

#[cfg(feature = "xtypes")]
fn map_rosidl_error(err: RosidlError) -> ApiError {
    match err {
        RosidlError::NullTypeSupport | RosidlError::NullMembers | RosidlError::MissingHash => {
            ApiError::Config
        }
        RosidlError::UnsupportedType(_) => ApiError::Unsupported,
        RosidlError::InvalidUtf8(_)
        | RosidlError::BoundOverflow { .. }
        | RosidlError::Builder(_) => ApiError::SerializationError,
    }
}

#[cfg(not(feature = "xtypes"))]
fn map_rosidl_error(_err: RosidlError) -> ApiError {
    ApiError::Unsupported
}

/// Generate a deterministic 16-byte pseudo-GUID from a topic name.
/// Used for SHM segment naming when writer GUID is not accessible.
fn topic_to_shm_guid(topic: &str) -> [u8; 16] {
    let mut guid = [0u8; 16];
    let mut h: u32 = 2_166_136_261;
    for byte in topic.bytes() {
        h ^= u32::from(byte);
        h = h.wrapping_mul(16_777_619);
    }
    // Spread hash across 16 bytes with different seeds
    guid[0..4].copy_from_slice(&h.to_le_bytes());
    let h2 = h.wrapping_mul(2_654_435_761);
    guid[4..8].copy_from_slice(&h2.to_le_bytes());
    let h3 = h2.wrapping_mul(2_654_435_761);
    guid[8..12].copy_from_slice(&h3.to_le_bytes());
    let h4 = h3.wrapping_mul(2_654_435_761);
    guid[12..16].copy_from_slice(&h4.to_le_bytes());
    guid
}

impl ForeignRmwContext {
    pub fn create(name: &str) -> Result<Self, ApiError> {
        let ctx = match RmwContext::create(name) {
            Ok(value) => value,
            Err(err) => {
                return Err(err);
            }
        };
        Ok(Self {
            ctx,
            registry: Mutex::new(HashMap::new()),
            reader_map: Mutex::new(HashMap::new()),
            reader_status: Mutex::new(HashMap::new()),
            graph_guard_ptr: Mutex::new(None),
            #[cfg(feature = "xtypes")]
            type_handles: Mutex::new(HashMap::new()),
            #[cfg(feature = "xtypes")]
            topic_types: Mutex::new(HashMap::new()),
            metadata_cache: Mutex::new(HashMap::new()),
            writer_mergers: Mutex::new(HashMap::new()),
            reader_ptrs_by_topic: Mutex::new(HashMap::new()),
            shm_writers: RwLock::new(HashMap::new()),
            shm_readers_by_topic: RwLock::new(HashMap::new()),
        })
    }

    pub fn graph_guard_key(&self) -> ConditionKey {
        self.ctx.graph_guard_key()
    }

    pub fn graph_guard_condition(&self) -> Arc<GuardCondition> {
        self.ctx.graph_guard_condition()
    }

    /// Returns the 12-byte GUID prefix of the underlying participant.
    pub fn guid_prefix(&self) -> [u8; 12] {
        self.ctx.participant().guid().prefix
    }

    pub fn user_unicast_locators(&self) -> Vec<SocketAddr> {
        self.ctx.user_unicast_locators()
    }

    fn metadata_for(
        &self,
        type_support: *const rosidl_message_type_support_t,
    ) -> Result<Arc<RosMessageMetadata>, ApiError> {
        if type_support.is_null() {
            return Err(ApiError::Config);
        }

        let mut cache = self
            .metadata_cache
            .lock()
            .map_err(|_| ApiError::WouldBlock)?;

        if let Some(entry) = cache.get(&type_support) {
            return Ok(Arc::clone(entry));
        }

        unsafe {
            let id_ptr = (*type_support).typesupport_identifier;
            if id_ptr.is_null() {
                return Err(ApiError::Config);
            }
            let id = CStr::from_ptr(id_ptr)
                .to_str()
                .map_err(|_| ApiError::Config)?;
            if id != "rosidl_typesupport_introspection_c" {
                return Err(ApiError::Config);
            }
        }

        let metadata = unsafe { RosMessageMetadata::from_type_support(type_support) }
            .map_err(map_rosidl_error)?;
        // RosMessageMetadata contains raw FFI pointers (not Send/Sync) but Arc is used
        // only for ref-counting within the single-threaded FFI context, not cross-thread sharing.
        #[allow(clippy::arc_with_non_send_sync)]
        let arc = Arc::new(metadata);
        cache.insert(type_support, Arc::clone(&arc));
        Ok(arc)
    }

    fn fallback_metadata(
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
    ) -> RosMessageMetadata {
        let normalized = topic.trim_start_matches('/');
        let base = if normalized.is_empty() {
            "unresolved"
        } else {
            normalized
        };

        let topic_token = base.replace('/', "_");
        let type_hint = unsafe {
            if type_support.is_null() {
                "unknown"
            } else {
                let identifier_ptr = (*type_support).typesupport_identifier;
                if identifier_ptr.is_null() {
                    "unknown"
                } else {
                    CStr::from_ptr(identifier_ptr).to_str().unwrap_or("invalid")
                }
            }
        };

        let namespace = "__rmw_hdds".to_string();
        let name = format!("{topic_token}__{type_hint}");
        let fqn = format!("{namespace}::{name}");

        RosMessageMetadata {
            type_support,
            members: ptr::null(),
            namespace,
            name,
            fqn,
            hash_version: 0,
            hash_value: [0u8; ROS_HASH_SIZE],
        }
    }

    pub fn register_node_info(&self, name: &str, namespace_: &str, enclave: &str) {
        self.ctx
            .register_node_with_enclave(name, namespace_, enclave);
    }

    pub fn unregister_node_info(&self, name: &str, namespace_: &str) {
        self.ctx.unregister_node(name, namespace_);
    }

    pub fn register_publisher_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
        gid: [u8; RMW_GID_STORAGE_SIZE],
        qos: EndpointQos,
    ) -> Result<(), ApiError> {
        let metadata = match self.metadata_for(type_support) {
            Ok(meta) => meta,
            Err(ApiError::Config) => {
                if type_support.is_null() {
                    return Err(ApiError::Config);
                }

                #[allow(clippy::arc_with_non_send_sync)]
                let fallback = Arc::new(Self::fallback_metadata(topic, type_support));
                if let Ok(mut cache) = self.metadata_cache.lock() {
                    cache.insert(type_support, Arc::clone(&fallback));
                }
                fallback
            }
            Err(err) => {
                return Err(err);
            }
        };
        self.ctx.register_publisher_endpoint(
            name,
            namespace_,
            topic,
            metadata.fqn.as_str(),
            &metadata.hash_value,
            &gid,
            qos,
        );
        Ok(())
    }

    pub fn unregister_publisher_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        gid: &[u8; RMW_GID_STORAGE_SIZE],
    ) {
        self.ctx
            .unregister_publisher_endpoint(name, namespace_, topic, gid);
    }

    pub fn register_subscription_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
        gid: [u8; RMW_GID_STORAGE_SIZE],
        qos: EndpointQos,
    ) -> Result<(), ApiError> {
        let metadata = match self.metadata_for(type_support) {
            Ok(meta) => meta,
            Err(ApiError::Config) => {
                if type_support.is_null() {
                    return Err(ApiError::Config);
                }

                #[allow(clippy::arc_with_non_send_sync)]
                let fallback = Arc::new(Self::fallback_metadata(topic, type_support));
                if let Ok(mut cache) = self.metadata_cache.lock() {
                    cache.insert(type_support, Arc::clone(&fallback));
                }
                fallback
            }
            Err(err) => {
                return Err(err);
            }
        };
        self.ctx.register_subscription_endpoint(
            name,
            namespace_,
            topic,
            metadata.fqn.as_str(),
            &metadata.hash_value,
            &gid,
            qos,
        );
        Ok(())
    }

    pub fn unregister_subscription_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        gid: &[u8; RMW_GID_STORAGE_SIZE],
    ) {
        self.ctx
            .unregister_subscription_endpoint(name, namespace_, topic, gid);
    }

    pub fn list_nodes_with<F>(&self, mut visitor: F) -> (u64, usize)
    where
        F: FnMut(&str, &str),
    {
        let snapshot = self.ctx.graph_cache().snapshot();
        for node in &snapshot.nodes {
            visitor(&node.name, &node.namespace);
        }
        (snapshot.version, snapshot.nodes.len())
    }

    pub fn list_nodes_with_enclave<F>(&self, mut visitor: F) -> (u64, usize)
    where
        F: FnMut(&str, &str, &str),
    {
        let snapshot = self.ctx.graph_cache().snapshot();
        for node in &snapshot.nodes {
            visitor(&node.name, &node.namespace, &node.enclave);
        }
        (snapshot.version, snapshot.nodes.len())
    }

    pub fn visit_publishers_with<F>(
        &self,
        name: &str,
        namespace_: &str,
        mut visitor: F,
    ) -> Result<(u64, usize), ApiError>
    where
        F: FnMut(&NodeEndpointSummary),
    {
        let snapshot = self.ctx.graph_cache().snapshot();
        let mut count = 0usize;

        for node in &snapshot.nodes {
            if node.name == name && node.namespace == namespace_ {
                for endpoint in &node.publishers {
                    visitor(endpoint);
                }
                count = node.publishers.len();
                break;
            }
        }

        Ok((snapshot.version, count))
    }

    pub fn visit_subscriptions_with<F>(
        &self,
        name: &str,
        namespace_: &str,
        mut visitor: F,
    ) -> Result<(u64, usize), ApiError>
    where
        F: FnMut(&NodeEndpointSummary),
    {
        let snapshot = self.ctx.graph_cache().snapshot();
        let mut count = 0usize;

        for node in &snapshot.nodes {
            if node.name == name && node.namespace == namespace_ {
                for endpoint in &node.subscriptions {
                    visitor(endpoint);
                }
                count = node.subscriptions.len();
                break;
            }
        }

        Ok((snapshot.version, count))
    }

    pub fn create_reader_raw(&self, topic: &str) -> Result<*mut c_void, ApiError> {
        let participant = self.ctx.participant();
        let qos = QoS::default();
        let reader = {
            #[cfg(feature = "xtypes")]
            if let Some(handle) = self.topic_type_handle(topic) {
                participant.create_reader_with_type::<BytePayload>(
                    topic,
                    qos.clone(),
                    handle.fqn.as_ref(),
                    Some(handle.complete.clone()),
                )?
            } else {
                participant.create_reader::<BytePayload>(topic, qos.clone())?
            }

            #[cfg(not(feature = "xtypes"))]
            {
                participant.create_reader::<BytePayload>(topic, qos.clone())?
            }
        };
        self.ctx.register_reader(topic);
        // Bind to any existing writers on the same topic (intra-process delivery)
        if let Ok(mergers) = self.writer_mergers.lock() {
            if let Some(topic_mergers) = mergers.get(topic) {
                for merger in topic_mergers {
                    reader.bind_to_writer(Arc::clone(merger));
                }
            }
        }
        let status = reader.get_status_condition();
        let raw = Box::into_raw(Box::new(reader)).cast::<c_void>();
        // Track reader for late writer binding
        if let Ok(mut readers) = self.reader_ptrs_by_topic.lock() {
            readers.entry(topic.to_string()).or_default().push(raw);
        }
        self.register_reader_status(raw, status);
        Ok(raw)
    }

    pub fn create_reader_raw_with_qos(
        &self,
        topic: &str,
        qos: &QoS,
    ) -> Result<*mut c_void, ApiError> {
        let participant = self.ctx.participant();
        let reader = {
            #[cfg(feature = "xtypes")]
            if let Some(handle) = self.topic_type_handle(topic) {
                participant.create_reader_with_type::<BytePayload>(
                    topic,
                    qos.clone(),
                    handle.fqn.as_ref(),
                    Some(handle.complete.clone()),
                )?
            } else {
                participant.create_reader::<BytePayload>(topic, qos.clone())?
            }

            #[cfg(not(feature = "xtypes"))]
            {
                participant.create_reader::<BytePayload>(topic, qos.clone())?
            }
        };
        self.ctx.register_reader(topic);
        // Bind to any existing writers on the same topic (intra-process delivery)
        if let Ok(mergers) = self.writer_mergers.lock() {
            if let Some(topic_mergers) = mergers.get(topic) {
                for merger in topic_mergers {
                    reader.bind_to_writer(Arc::clone(merger));
                }
            }
        }
        let status = reader.get_status_condition();
        let raw = Box::into_raw(Box::new(reader)).cast::<c_void>();
        if let Ok(mut readers) = self.reader_ptrs_by_topic.lock() {
            readers.entry(topic.to_string()).or_default().push(raw);
        }
        self.register_reader_status(raw, status);

        // Attach SHM reader if a writer segment exists for this topic
        if qos.reliability == Reliability::BestEffort {
            let domain_id = participant.domain_id();
            let guid = topic_to_shm_guid(topic);
            let seg_name = shm::segment_name(domain_id, &guid);
            let bucket = shm::TopicNotify::bucket_for_guid(&guid);
            match ShmRingReader::attach(&seg_name, DEFAULT_RING_CAPACITY, bucket) {
                Ok(shm_reader) => {
                    log::info!(
                        "[SHM] Attached reader to segment '{}' for topic '{}'",
                        seg_name,
                        topic
                    );
                    if let Ok(mut shm_map) = self.shm_readers_by_topic.write() {
                        shm_map
                            .entry(topic.to_string())
                            .or_insert_with(|| Mutex::new(Vec::new()))
                            .get_mut()
                            .map(|v| v.push(shm_reader))
                            .ok();
                    }
                }
                Err(e) => {
                    log::debug!("[SHM] No segment for '{}' (will use RTPS): {}", topic, e);
                }
            }
        }

        Ok(raw)
    }

    pub fn create_writer_raw(&self, topic: &str) -> Result<*mut c_void, ApiError> {
        let participant = self.ctx.participant();
        let qos = QoS::default();
        let writer = {
            #[cfg(feature = "xtypes")]
            if let Some(handle) = self.topic_type_handle(topic) {
                participant.create_writer_with_type::<BytePayload>(
                    topic,
                    qos.clone(),
                    handle.fqn.as_ref(),
                    Some(handle.complete.clone()),
                )?
            } else {
                participant.create_writer::<BytePayload>(topic, qos.clone())?
            }

            #[cfg(not(feature = "xtypes"))]
            {
                participant.create_writer::<BytePayload>(topic, qos.clone())?
            }
        };
        self.ctx.register_writer(topic);
        let merger = writer.merger();
        // Bind existing readers on the same topic
        if let Ok(readers) = self.reader_ptrs_by_topic.lock() {
            if let Some(reader_list) = readers.get(topic) {
                for &reader_ptr in reader_list {
                    let reader_ref = unsafe { &*reader_ptr.cast::<DataReader<BytePayload>>() };
                    reader_ref.bind_to_writer(Arc::clone(&merger));
                }
            }
        }
        // Store merger for future readers
        if let Ok(mut mergers) = self.writer_mergers.lock() {
            mergers.entry(topic.to_string()).or_default().push(merger);
        }
        Ok(Box::into_raw(Box::new(writer)).cast::<c_void>())
    }

    pub fn create_writer_raw_with_qos(
        &self,
        topic: &str,
        qos: &QoS,
    ) -> Result<*mut c_void, ApiError> {
        let participant = self.ctx.participant();
        let writer = {
            #[cfg(feature = "xtypes")]
            if let Some(handle) = self.topic_type_handle(topic) {
                participant.create_writer_with_type::<BytePayload>(
                    topic,
                    qos.clone(),
                    handle.fqn.as_ref(),
                    Some(handle.complete.clone()),
                )?
            } else {
                participant.create_writer::<BytePayload>(topic, qos.clone())?
            }

            #[cfg(not(feature = "xtypes"))]
            {
                participant.create_writer::<BytePayload>(topic, qos.clone())?
            }
        };
        self.ctx.register_writer(topic);
        let merger = writer.merger();
        if let Ok(readers) = self.reader_ptrs_by_topic.lock() {
            if let Some(reader_list) = readers.get(topic) {
                for &reader_ptr in reader_list {
                    let reader_ref = unsafe { &*reader_ptr.cast::<DataReader<BytePayload>>() };
                    reader_ref.bind_to_writer(Arc::clone(&merger));
                }
            }
        }
        if let Ok(mut mergers) = self.writer_mergers.lock() {
            mergers
                .entry(topic.to_string())
                .or_default()
                .push(Arc::clone(&merger));
        }

        // Create SHM ring buffer for inter-process delivery (BestEffort only)
        if qos.reliability == Reliability::BestEffort {
            let domain_id = participant.domain_id();
            let guid = topic_to_shm_guid(topic);
            let seg_name = shm::segment_name(domain_id, &guid);
            // Clean up any stale segment from a previous run
            let _ = shm::ShmSegment::unlink(&seg_name);
            match ShmRingWriter::create(&seg_name, DEFAULT_RING_CAPACITY, &guid) {
                Ok(shm_writer) => {
                    log::info!("[SHM] Created segment '{}' for topic '{}'", seg_name, topic);
                    if let Ok(mut shm_map) = self.shm_writers.write() {
                        shm_map.insert(topic.to_string(), Mutex::new(shm_writer));
                    }
                    // Pre-populate reader map for late reader attachment
                    if let Ok(mut readers) = self.shm_readers_by_topic.write() {
                        readers
                            .entry(topic.to_string())
                            .or_insert_with(|| Mutex::new(Vec::new()));
                    }
                }
                Err(e) => {
                    log::warn!("[SHM] Failed to create segment for '{}': {}", topic, e);
                }
            }
        }

        Ok(Box::into_raw(Box::new(writer)).cast::<c_void>())
    }

    #[cfg(feature = "xtypes")]
    pub fn bind_topic_type(
        &self,
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
    ) -> Result<(), ApiError> {
        if type_support.is_null() {
            return Err(ApiError::Config);
        }

        let handle = {
            let mut registry = self.type_handles.lock().map_err(|_| ApiError::WouldBlock)?;

            if let Some(handle) = registry.get(&type_support) {
                Arc::clone(handle)
            } else {
                let participant = self.ctx.participant();
                let handle = unsafe {
                    participant
                        .register_type_from_type_support_default(type_support)
                        .map_err(map_rosidl_error)?
                };
                registry.insert(type_support, Arc::clone(&handle));
                handle
            }
        };

        if let Err(_err) = unsafe { ros2_types::register_type_descriptor(type_support) } {
            log::debug!("register_type_descriptor({topic}) failed: {_err:?}");
        }
        self.ctx.register_topic_type(topic, Arc::clone(&handle));
        if let Ok(mut map) = self.topic_types.lock() {
            map.insert(topic.to_string(), Arc::clone(&handle));
        }
        Ok(())
    }

    #[cfg(not(feature = "xtypes"))]
    #[allow(unused_variables)]
    pub fn bind_topic_type(
        &self,
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
    ) -> Result<(), ApiError> {
        Err(ApiError::Unsupported)
    }

    pub fn destroy_writer_raw(&self, writer_ptr: *const c_void) -> Result<(), ApiError> {
        if writer_ptr.is_null() {
            return Ok(());
        }

        unsafe {
            let writer_mut =
                writer_ptr.cast::<DataWriter<BytePayload>>() as *mut DataWriter<BytePayload>;
            let topic = (*writer_mut).topic_name().to_string();
            let _ = Box::from_raw(writer_mut);
            self.ctx.unregister_writer(&topic);

            // Cleanup SHM segment for this topic
            if let Ok(mut shm_map) = self.shm_writers.write() {
                if let Some(writer_mutex) = shm_map.remove(&topic) {
                    let shm_writer = writer_mutex.into_inner().unwrap_or_else(|e| e.into_inner());
                    if let Err(e) = shm_writer.unlink() {
                        log::debug!("[SHM] unlink failed for '{}': {}", topic, e);
                    } else {
                        log::info!("[SHM] Cleaned up segment for topic '{}'", topic);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn publish_writer(
        &self,
        writer_ptr: *const c_void,
        payload: &BytePayload,
    ) -> Result<(), ApiError> {
        if writer_ptr.is_null() {
            return Err(ApiError::Config);
        }

        let writer_ref = unsafe { &*writer_ptr.cast::<DataWriter<BytePayload>>() };

        // Dual-write: RTPS (for network + discovery) + SHM (for inter-process same machine)
        // RwLock::read() only contends with writer creation/removal, not other publishes.
        let topic = writer_ref.topic_name();
        if let Ok(shm_map) = self.shm_writers.read() {
            if let Some(shm_mutex) = shm_map.get(topic) {
                if let Ok(mut shm_writer) = shm_mutex.lock() {
                    if let Err(e) = shm_writer.push(&payload.data) {
                        log::debug!("[SHM] push failed for '{}': {}", topic, e);
                    }
                }
            }
        }

        writer_ref.write(payload)
    }

    /// Try to read from SHM ring for a topic. Returns Some(data) if available.
    pub fn try_shm_take(&self, topic: &str, buf: &mut [u8]) -> Option<usize> {
        if let Ok(shm_map) = self.shm_readers_by_topic.read() {
            if let Some(readers_mutex) = shm_map.get(topic) {
                if let Ok(mut readers) = readers_mutex.try_lock() {
                    for reader in readers.iter_mut() {
                        if let Some(len) = reader.try_pop(buf) {
                            return Some(len);
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if any SHM data is available for a topic (non-blocking poll).
    pub fn shm_has_data(&self, topic: &str) -> bool {
        if let Ok(shm_map) = self.shm_readers_by_topic.read() {
            if let Some(readers_mutex) = shm_map.get(topic) {
                if let Ok(readers) = readers_mutex.try_lock() {
                    return readers.iter().any(|r| r.has_data());
                }
            }
        }
        false
    }

    pub fn register_graph_guard_ptr(&self, raw_ptr: *const GuardCondition) {
        if let Ok(mut slot) = self.graph_guard_ptr.lock() {
            *slot = Some(raw_ptr);
        }
    }

    #[cfg(feature = "xtypes")]
    fn topic_type_handle(&self, topic: &str) -> Option<Arc<TypeObjectHandle>> {
        let map = self.topic_types.lock().ok()?;
        map.get(topic).cloned()
    }

    pub fn attach_guard(
        &self,
        guard: Arc<GuardCondition>,
        raw_ptr: *const GuardCondition,
    ) -> Result<ConditionKey, ApiError> {
        let handle = self.ctx.attach_guard(&guard)?;
        let key = handle.key();
        let mut registry = self.registry.lock().map_err(|_| ApiError::WouldBlock)?;
        registry.insert(
            key,
            ConditionRecord {
                raw_ptr: raw_ptr.cast::<c_void>(),
                handle,
                reader_ptr: None,
            },
        );
        Ok(key)
    }

    pub fn attach_status(
        &self,
        status: Arc<StatusCondition>,
        raw_ptr: *const StatusCondition,
    ) -> Result<ConditionKey, ApiError> {
        self.attach_status_internal(status, raw_ptr, None)
    }

    pub fn attach_reader(
        &self,
        reader_ptr: *const c_void,
        status: Arc<StatusCondition>,
        raw_ptr: *const StatusCondition,
    ) -> Result<ConditionKey, ApiError> {
        let key = self.attach_status_internal(status, raw_ptr, Some(reader_ptr))?;

        let mut map = self.reader_map.lock().map_err(|_| ApiError::WouldBlock)?;
        if map.insert(reader_ptr, key).is_some() {
            let _ = self.detach_condition(key);
            return Err(ApiError::Config);
        }

        Ok(key)
    }

    pub fn detach_condition(&self, key: ConditionKey) -> Result<(), ApiError> {
        let mut registry = self.registry.lock().map_err(|_| ApiError::WouldBlock)?;

        if let Some(record) = registry.remove(&key) {
            if let Some(reader_ptr) = record.reader_ptr {
                if let Ok(mut map) = self.reader_map.lock() {
                    let _ = map.remove(&reader_ptr);
                }
            }
            record.handle.detach()?;
            Ok(())
        } else if key == self.ctx.graph_guard_key() {
            // Graph guard is owned by the context; detaching is not allowed.
            Err(ApiError::Config)
        } else {
            Err(ApiError::Config)
        }
    }

    pub fn detach_reader(&self, reader_ptr: *const c_void) -> Result<(), ApiError> {
        let key = {
            let mut map = self.reader_map.lock().map_err(|_| ApiError::WouldBlock)?;
            match map.remove(&reader_ptr) {
                Some(key) => key,
                None => return Err(ApiError::Config),
            }
        };

        self.detach_condition(key)
    }

    pub fn register_reader_status(&self, reader_ptr: *const c_void, status: Arc<StatusCondition>) {
        if reader_ptr.is_null() {
            return;
        }
        if let Ok(mut map) = self.reader_status.lock() {
            map.insert(reader_ptr, status);
        }
    }

    pub fn unregister_reader_status(&self, reader_ptr: *const c_void) {
        if reader_ptr.is_null() {
            return;
        }
        if let Ok(mut map) = self.reader_status.lock() {
            map.remove(&reader_ptr);
        }
    }

    pub fn status_for_reader(
        &self,
        reader_ptr: *const c_void,
    ) -> Result<Arc<StatusCondition>, ApiError> {
        if reader_ptr.is_null() {
            return Err(ApiError::Config);
        }
        let map = self
            .reader_status
            .lock()
            .map_err(|_| ApiError::WouldBlock)?;
        map.get(&reader_ptr).cloned().ok_or(ApiError::Config)
    }

    pub fn wait(&self, timeout: Option<Duration>) -> Result<Vec<WaitHit>, ApiError> {
        let keys = self.ctx.wait(timeout)?;

        let registry = self.registry.lock().map_err(|_| ApiError::WouldBlock)?;
        let guard_ptr = {
            let guard_lock = self
                .graph_guard_ptr
                .lock()
                .map_err(|_| ApiError::WouldBlock)?;
            guard_lock.as_ref().map_or(std::ptr::null(), |ptr| *ptr)
        };

        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            if key == self.ctx.graph_guard_key() {
                result.push(WaitHit {
                    key,
                    condition_ptr: guard_ptr.cast::<c_void>(),
                    reader_ptr: None,
                });
            } else if let Some(record) = registry.get(&key) {
                result.push(WaitHit {
                    key,
                    condition_ptr: record.raw_ptr,
                    reader_ptr: record.reader_ptr,
                });
            } else {
                // Don't abort on unknown keys - skip them instead
                continue;
            }
        }

        Ok(result)
    }

    pub fn destroy_reader_raw(&self, reader_ptr: *const c_void) -> Result<(), ApiError> {
        if reader_ptr.is_null() {
            return Ok(());
        }

        if let Err(err) = self.detach_reader(reader_ptr) {
            if !matches!(err, ApiError::Config) {
                return Err(err);
            }
        }

        self.unregister_reader_status(reader_ptr);
        unsafe {
            let reader_mut =
                reader_ptr.cast::<DataReader<BytePayload>>() as *mut DataReader<BytePayload>;
            let topic = (*reader_mut).topic_name().to_string();
            // Unregister from topic registry FIRST to stop intra-process delivery,
            // then remove from tracking, then drop the reader.
            self.ctx.unregister_reader(&topic);
            if let Ok(mut readers) = self.reader_ptrs_by_topic.lock() {
                if let Some(list) = readers.get_mut(&topic) {
                    list.retain(|&p| p != reader_ptr);
                }
            }
            // Clean up SHM readers for this topic to prevent stale accumulation.
            if let Ok(mut shm_map) = self.shm_readers_by_topic.write() {
                shm_map.remove(&topic);
            }
            let _ = Box::from_raw(reader_mut);
        }

        Ok(())
    }

    pub fn for_each_topic<F>(&self, mut visitor: F) -> u64
    where
        F: FnMut(&str, &str, u32, u32),
    {
        let snapshot = self.ctx.graph_cache().snapshot();
        let mut merged: HashMap<String, (String, u32, u32)> = HashMap::new();

        for entry in &snapshot.topics {
            merged.insert(
                entry.name.clone(),
                (
                    normalize_ros_type_name(&entry.type_name),
                    entry.writer_count,
                    entry.reader_count,
                ),
            );
        }

        if let Ok(discovered) = self.ctx.participant().discover_topics() {
            for topic in discovered {
                let name = topic.name;
                let type_name = normalize_ros_type_name(&topic.type_name);
                let writer_count = u32::try_from(topic.publisher_count).unwrap_or(u32::MAX);
                let reader_count = u32::try_from(topic.subscriber_count).unwrap_or(u32::MAX);

                merged
                    .entry(name)
                    .and_modify(|entry| {
                        if entry.0.is_empty() {
                            entry.0 = type_name.clone();
                        }
                        entry.1 = entry.1.max(writer_count);
                        entry.2 = entry.2.max(reader_count);
                    })
                    .or_insert((type_name, writer_count, reader_count));
            }
        }

        for (name, (type_name, writer_count, reader_count)) in merged {
            visitor(&name, &type_name, writer_count, reader_count);
        }
        snapshot.version
    }

    fn attach_status_internal(
        &self,
        status: Arc<StatusCondition>,
        raw_ptr: *const StatusCondition,
        reader_ptr: Option<*const c_void>,
    ) -> Result<ConditionKey, ApiError> {
        let handle = self.ctx.attach_status_condition(status)?;
        let key = handle.key();
        let mut registry = self.registry.lock().map_err(|_| ApiError::WouldBlock)?;
        registry.insert(
            key,
            ConditionRecord {
                raw_ptr: raw_ptr.cast::<c_void>(),
                handle,
                reader_ptr,
            },
        );
        Ok(key)
    }
}

fn normalize_ros_type_name(type_name: &str) -> String {
    if type_name.contains("::") {
        type_name.replace("::", "/")
    } else {
        type_name.to_string()
    }
}

impl ForeignRmwWaitSet {
    pub fn new(ctx: Arc<ForeignRmwContext>) -> Self {
        Self {
            ctx,
            reader_keys: Mutex::new(HashMap::new()),
        }
    }

    fn ctx(&self) -> &ForeignRmwContext {
        &self.ctx
    }

    /// Register a reader in this waitset's filter map so `wait()` will report it.
    /// If the reader was already attached to the context (via `rmw_create_subscription`),
    /// we reuse its existing ConditionKey.  Otherwise we auto-attach via the
    /// reader's status condition stored during `create_reader_raw`.
    pub fn attach_reader(&self, reader_ptr: *const c_void) -> Result<(), ApiError> {
        let key = {
            let ctx_map = self
                .ctx()
                .reader_map
                .lock()
                .map_err(|_| ApiError::WouldBlock)?;
            ctx_map.get(&reader_ptr).copied()
        };

        let key = match key {
            Some(k) => k,
            None => {
                // Auto-attach: look up the status condition and register with the context
                let status = self.ctx().status_for_reader(reader_ptr)?;
                let raw_ptr = Arc::as_ptr(&status);
                self.ctx().attach_reader(reader_ptr, status, raw_ptr)?
            }
        };

        let mut map = self.reader_keys.lock().map_err(|_| ApiError::WouldBlock)?;
        map.insert(reader_ptr, key);
        Ok(())
    }

    /// Unregister a reader from this waitset's filter map.
    /// Does NOT detach from the context -- the context owns the attachment lifetime.
    pub fn detach_reader(&self, reader_ptr: *const c_void) -> Result<(), ApiError> {
        let mut map = self.reader_keys.lock().map_err(|_| ApiError::WouldBlock)?;
        map.remove(&reader_ptr);
        Ok(())
    }

    pub fn wait(&self, timeout: Option<Duration>) -> Result<(Vec<*const c_void>, bool), ApiError> {
        let hits = self.ctx().wait(timeout)?;

        let map = self.reader_keys.lock().map_err(|_| ApiError::WouldBlock)?;
        let mut readers = Vec::new();
        let mut guard_hit = false;

        for hit in hits {
            if hit.key == self.ctx().graph_guard_key() {
                guard_hit = true;
                continue;
            }

            if let Some(reader_ptr) = hit.reader_ptr {
                if map.contains_key(&reader_ptr) {
                    readers.push(reader_ptr);
                    continue;
                }
            }

            if let Some((&ptr, _)) = map.iter().find(|(_, key)| **key == hit.key) {
                readers.push(ptr);
            }
        }

        Ok((readers, guard_hit))
    }

    pub fn detach_all(&self) {
        // Collect and clear under the lock, then release it BEFORE calling
        // context methods that acquire ctx.registry / ctx.reader_map.
        // This avoids an AB/BA deadlock with attach_reader() which acquires
        // ctx.reader_map then self.reader_keys.
        let snapshot: Vec<(*const c_void, ConditionKey)> = {
            let mut keys = match self.reader_keys.lock() {
                Ok(lock) => lock,
                Err(poisoned) => poisoned.into_inner(),
            };
            let snap: Vec<_> = keys.iter().map(|(&r, &k)| (r, k)).collect();
            keys.clear();
            snap
        };

        for (reader_ptr, key) in snapshot {
            let _ = self.ctx().detach_condition(key);
            let _ = self.ctx().detach_reader(reader_ptr);
        }
    }
}

pub fn map_api_error(err: ApiError) -> HddsError {
    match err {
        ApiError::Config | ApiError::TypeMismatch | ApiError::QosIncompatible => {
            HddsError::HddsInvalidArgument
        }
        ApiError::WouldBlock => HddsError::HddsOperationFailed,
        ApiError::Io | ApiError::IoError(_) | ApiError::SerializationError => {
            HddsError::HddsOperationFailed
        }
        ApiError::BufferTooSmall => HddsError::HddsInvalidArgument,
        _ => HddsError::HddsOperationFailed,
    }
}

#[repr(C)]
pub struct rosidl_runtime_c__String {
    pub data: *mut c_char,
    pub size: usize,
    pub capacity: usize,
}

#[repr(C)]
pub struct rosidl_runtime_c__U16String {
    pub data: *mut u16,
    pub size: usize,
    pub capacity: usize,
}

#[cfg(not(test))]
extern "C" {
    fn rosidl_runtime_c__String__init(str_: *mut rosidl_runtime_c__String) -> bool;
    fn rosidl_runtime_c__String__fini(str_: *mut rosidl_runtime_c__String);
    fn rosidl_runtime_c__String__assign(
        str_: *mut rosidl_runtime_c__String,
        value: *const c_char,
    ) -> bool;
    fn rosidl_runtime_c__U16String__init(str_: *mut rosidl_runtime_c__U16String) -> bool;
    fn rosidl_runtime_c__U16String__fini(str_: *mut rosidl_runtime_c__U16String);
    fn rosidl_runtime_c__U16String__assignn(
        str_: *mut rosidl_runtime_c__U16String,
        value: *const u16,
        len: usize,
    ) -> bool;
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn rosidl_runtime_c__String__init(
    str_: *mut rosidl_runtime_c__String,
) -> bool {
    if str_.is_null() {
        return false;
    }

    let bytes = 1usize;
    let ptr = libc::malloc(bytes);
    if ptr.is_null() {
        return false;
    }

    *(ptr as *mut u8) = 0;
    (*str_).data = ptr.cast::<c_char>();
    (*str_).size = 0;
    (*str_).capacity = 1;
    true
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn rosidl_runtime_c__String__fini(str_: *mut rosidl_runtime_c__String) {
    if str_.is_null() {
        return;
    }

    if !(*str_).data.is_null() {
        libc::free((*str_).data.cast());
        (*str_).data = ptr::null_mut();
    }
    (*str_).size = 0;
    (*str_).capacity = 0;
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn rosidl_runtime_c__String__assign(
    str_: *mut rosidl_runtime_c__String,
    value: *const c_char,
) -> bool {
    if str_.is_null() || value.is_null() {
        return false;
    }

    let bytes = std::ffi::CStr::from_ptr(value).to_bytes();
    let required = match bytes.len().checked_add(1) {
        Some(len) => len,
        None => return false,
    };

    let new_ptr = libc::realloc((*str_).data.cast::<libc::c_void>(), required);
    if new_ptr.is_null() {
        return false;
    }

    ptr::copy_nonoverlapping(bytes.as_ptr(), new_ptr as *mut u8, bytes.len());
    *(new_ptr as *mut u8).add(bytes.len()) = 0;
    (*str_).data = new_ptr.cast::<c_char>();
    (*str_).size = bytes.len();
    (*str_).capacity = required;
    true
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn rosidl_runtime_c__U16String__init(
    str_: *mut rosidl_runtime_c__U16String,
) -> bool {
    if str_.is_null() {
        return false;
    }

    let bytes = std::mem::size_of::<u16>();
    let ptr = libc::malloc(bytes);
    if ptr.is_null() {
        return false;
    }

    *(ptr as *mut u16) = 0;
    (*str_).data = ptr.cast::<u16>();
    (*str_).size = 0;
    (*str_).capacity = 1;
    true
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn rosidl_runtime_c__U16String__fini(str_: *mut rosidl_runtime_c__U16String) {
    if str_.is_null() {
        return;
    }

    if !(*str_).data.is_null() {
        libc::free((*str_).data.cast::<libc::c_void>());
        (*str_).data = ptr::null_mut();
    }
    (*str_).size = 0;
    (*str_).capacity = 0;
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[cfg(test)]
#[no_mangle]
pub unsafe extern "C" fn rosidl_runtime_c__U16String__assignn(
    str_: *mut rosidl_runtime_c__U16String,
    value: *const u16,
    len: usize,
) -> bool {
    if str_.is_null() || value.is_null() {
        return false;
    }

    let capacity = match len.checked_add(1) {
        Some(cap) => cap,
        None => return false,
    };
    let bytes = match capacity.checked_mul(std::mem::size_of::<u16>()) {
        Some(total) => total,
        None => return false,
    };

    let new_ptr = libc::realloc((*str_).data.cast::<libc::c_void>(), bytes);
    if new_ptr.is_null() {
        return false;
    }

    ptr::copy_nonoverlapping(value, new_ptr as *mut u16, len);
    *(new_ptr as *mut u16).add(len) = 0;
    (*str_).data = new_ptr.cast::<u16>();
    (*str_).size = len;
    (*str_).capacity = capacity;
    true
}

struct CdrCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CdrCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn align(&mut self, alignment: usize) -> Result<(), DeserializeError> {
        if alignment <= 1 {
            return Ok(());
        }
        let mask = alignment - 1;
        let aligned = (self.offset + mask) & !mask;
        if aligned > self.data.len() {
            return Err(DeserializeError::BufferUnderflow);
        }
        self.offset = aligned;
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, DeserializeError> {
        if self.offset >= self.data.len() {
            return Err(DeserializeError::BufferUnderflow);
        }
        let value = self.data[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, DeserializeError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, DeserializeError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, DeserializeError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_i16(&mut self) -> Result<i16, DeserializeError> {
        Ok(self.read_u16()? as i16)
    }

    fn read_i32(&mut self) -> Result<i32, DeserializeError> {
        Ok(self.read_u32()? as i32)
    }

    fn read_i64(&mut self) -> Result<i64, DeserializeError> {
        Ok(self.read_u64()? as i64)
    }

    fn read_f32(&mut self) -> Result<f32, DeserializeError> {
        Ok(f32::from_bits(self.read_u32()?))
    }

    fn read_f64(&mut self) -> Result<f64, DeserializeError> {
        Ok(f64::from_bits(self.read_u64()?))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DeserializeError> {
        if self.offset + len > self.data.len() {
            return Err(DeserializeError::BufferUnderflow);
        }
        let slice = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }
}

#[derive(Debug)]
enum DeserializeError {
    BufferUnderflow,
    UnsupportedType(&'static str),
    LengthExceeded(&'static str),
    ResizeFailed,
    MissingIntrospection,
    MissingGetFunction,
    StringAssignFailed,
    Rosidl(RosidlError),
}

impl From<RosidlError> for DeserializeError {
    fn from(err: RosidlError) -> Self {
        DeserializeError::Rosidl(err)
    }
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeserializeError::BufferUnderflow => write!(f, "buffer underflow"),
            DeserializeError::UnsupportedType(reason) => {
                write!(f, "unsupported type: {reason}")
            }
            DeserializeError::LengthExceeded(reason) => write!(f, "{reason}"),
            DeserializeError::ResizeFailed => write!(f, "resize callback failed"),
            DeserializeError::MissingIntrospection => {
                write!(f, "missing introspection metadata")
            }
            DeserializeError::MissingGetFunction => {
                write!(f, "missing get_function for sequence element")
            }
            DeserializeError::StringAssignFailed => {
                write!(f, "failed to assign string buffer")
            }
            DeserializeError::Rosidl(err) => write!(f, "rosidl error: {:?}", err),
        }
    }
}

fn map_deserialize_error(err: DeserializeError) -> ApiError {
    match err {
        DeserializeError::UnsupportedType(_) | DeserializeError::LengthExceeded(_) => {
            ApiError::Unsupported
        }
        _ => ApiError::SerializationError,
    }
}

#[derive(Debug)]
enum SerializeError {
    BufferOverflow,
    UnsupportedType(&'static str),
    LengthExceeded(&'static str),
    MissingIntrospection,
    MissingSizeFunction,
    MissingGetFunction,
    Rosidl(RosidlError),
}

impl From<RosidlError> for SerializeError {
    fn from(err: RosidlError) -> Self {
        SerializeError::Rosidl(err)
    }
}

impl From<DeserializeError> for SerializeError {
    fn from(err: DeserializeError) -> Self {
        match err {
            DeserializeError::BufferUnderflow => SerializeError::BufferOverflow,
            DeserializeError::UnsupportedType(reason) => SerializeError::UnsupportedType(reason),
            DeserializeError::LengthExceeded(reason) => SerializeError::LengthExceeded(reason),
            DeserializeError::ResizeFailed => SerializeError::MissingSizeFunction,
            DeserializeError::MissingIntrospection => SerializeError::MissingIntrospection,
            DeserializeError::MissingGetFunction => SerializeError::MissingGetFunction,
            DeserializeError::StringAssignFailed => {
                SerializeError::UnsupportedType("string assignment failed")
            }
            DeserializeError::Rosidl(err) => SerializeError::Rosidl(err),
        }
    }
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializeError::BufferOverflow => write!(f, "buffer overflow"),
            SerializeError::UnsupportedType(reason) => write!(f, "unsupported type: {reason}"),
            SerializeError::LengthExceeded(reason) => write!(f, "{reason}"),
            SerializeError::MissingIntrospection => write!(f, "missing introspection metadata"),
            SerializeError::MissingSizeFunction => {
                write!(f, "missing size_function for sequence")
            }
            SerializeError::MissingGetFunction => {
                write!(f, "missing accessor for sequence element")
            }
            SerializeError::Rosidl(err) => write!(f, "rosidl error: {:?}", err),
        }
    }
}

fn map_serialize_error(err: SerializeError) -> ApiError {
    match err {
        SerializeError::UnsupportedType(_) | SerializeError::LengthExceeded(_) => {
            ApiError::Unsupported
        }
        SerializeError::MissingIntrospection
        | SerializeError::MissingSizeFunction
        | SerializeError::MissingGetFunction => ApiError::Config,
        SerializeError::Rosidl(err) => map_deserialize_error(DeserializeError::from(err)),
        SerializeError::BufferOverflow => ApiError::SerializationError,
    }
}

struct CdrWriter {
    buffer: Vec<u8>,
}

impl CdrWriter {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn align(&mut self, alignment: usize) {
        if alignment <= 1 {
            return;
        }
        let mask = alignment - 1;
        let padding = (alignment - (self.buffer.len() & mask)) & mask;
        if padding != 0 {
            self.buffer.extend(std::iter::repeat_n(0, padding));
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    fn write_u16(&mut self, value: u16) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn write_i16(&mut self, value: i16) {
        self.write_u16(value as u16);
    }

    fn write_i32(&mut self, value: i32) {
        self.write_u32(value as u32);
    }

    fn write_i64(&mut self, value: i64) {
        self.write_u64(value as u64);
    }

    fn write_f32(&mut self, value: f32) {
        self.write_u32(value.to_bits());
    }

    fn write_f64(&mut self, value: f64) {
        self.write_u64(value.to_bits());
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    fn into_payload(self) -> BytePayload {
        BytePayload { data: self.buffer }
    }
}

struct MetadataCache {
    entries: HashMap<*const rosidl_message_type_support_t, Arc<RosMessageMetadata>>,
}

impl MetadataCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    unsafe fn get(
        &mut self,
        ts: *const rosidl_message_type_support_t,
    ) -> Result<Arc<RosMessageMetadata>, DeserializeError> {
        if ts.is_null() {
            return Err(DeserializeError::MissingIntrospection);
        }

        if let Some(entry) = self.entries.get(&ts) {
            return Ok(Arc::clone(entry));
        }

        let metadata = RosMessageMetadata::from_type_support(ts).map_err(DeserializeError::from)?;
        #[allow(clippy::arc_with_non_send_sync)]
        let arc = Arc::new(metadata);
        self.entries.insert(ts, Arc::clone(&arc));
        Ok(arc)
    }
}

pub fn deserialize_into_ros(
    type_support: *const rosidl_message_type_support_t,
    data: &[u8],
    ros_message: *mut c_void,
) -> Result<(), ApiError> {
    if ros_message.is_null() {
        return Err(ApiError::Config);
    }

    if data.is_empty() {
        // Nothing to deserialize
        return Ok(());
    }

    unsafe {
        let mut cache = MetadataCache::new();
        let metadata = cache.get(type_support).map_err(map_deserialize_error)?;
        let mut cursor = CdrCursor::new(data);
        deserialize_message(&mut cursor, metadata.as_ref(), ros_message, &mut cache)
            .map_err(map_deserialize_error)
    }
}

pub fn serialize_from_ros(
    type_support: *const rosidl_message_type_support_t,
    ros_message: *const c_void,
) -> Result<BytePayload, ApiError> {
    if ros_message.is_null() {
        return Err(ApiError::Config);
    }

    unsafe {
        let mut cache = MetadataCache::new();
        let metadata = cache
            .get(type_support)
            .map_err(SerializeError::from)
            .map_err(map_serialize_error)?;
        let mut writer = CdrWriter::new();
        serialize_message(&mut writer, metadata.as_ref(), ros_message, &mut cache)
            .map_err(map_serialize_error)?;
        Ok(writer.into_payload())
    }
}

unsafe fn serialize_message(
    writer: &mut CdrWriter,
    metadata: &RosMessageMetadata,
    ros_message: *const c_void,
    cache: &mut MetadataCache,
) -> Result<(), SerializeError> {
    writer.align(4);

    let members = &*metadata.members;
    let fields = slice::from_raw_parts(members.members_, members.member_count_ as usize);

    for member in fields {
        let field_ptr = (ros_message as *const u8).add(member.offset_ as usize) as *const c_void;
        if member.is_array_ {
            if member.array_size_ > 0 && !member.is_upper_bound_ {
                serialize_fixed_array(writer, member, field_ptr, cache)?;
            } else {
                serialize_sequence(writer, member, field_ptr, cache)?;
            }
        } else {
            serialize_value(writer, member, field_ptr, cache)?;
        }
    }

    Ok(())
}

unsafe fn serialize_fixed_array(
    writer: &mut CdrWriter,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    field_ptr: *const c_void,
    cache: &mut MetadataCache,
) -> Result<(), SerializeError> {
    let size = member.array_size_;
    if let Some(get_const_fn) = member.get_const_function {
        for index in 0..size {
            let element = get_const_fn(field_ptr, index);
            serialize_value(writer, member, element, cache)?;
        }
        Ok(())
    } else {
        let element_size = element_size(member, cache)?;
        for index in 0..size {
            let element = (field_ptr as *const u8).add(element_size * index) as *const c_void;
            serialize_value(writer, member, element, cache)?;
        }
        Ok(())
    }
}

unsafe fn serialize_sequence(
    writer: &mut CdrWriter,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    field_ptr: *const c_void,
    cache: &mut MetadataCache,
) -> Result<(), SerializeError> {
    writer.align(4);

    let len = if let Some(size_fn) = member.size_function {
        size_fn(field_ptr)
    } else if member.array_size_ > 0 && !member.is_upper_bound_ {
        member.array_size_
    } else {
        return Err(SerializeError::MissingSizeFunction);
    };

    let len_u32 = u32::try_from(len).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);

    for index in 0..len {
        let element_ptr = if let Some(get_const_fn) = member.get_const_function {
            get_const_fn(field_ptr, index)
        } else if let Some(get_fn) = member.get_function {
            get_fn(field_ptr as *mut c_void, index).cast()
        } else {
            return Err(SerializeError::MissingGetFunction);
        };

        serialize_value(writer, member, element_ptr, cache)?;
    }

    Ok(())
}

unsafe fn serialize_value(
    writer: &mut CdrWriter,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    element_ptr: *const c_void,
    cache: &mut MetadataCache,
) -> Result<(), SerializeError> {
    match member.type_id_ {
        ROS_TYPE_FLOAT => {
            writer.align(4);
            writer.write_f32(*(element_ptr as *const f32));
        }
        ROS_TYPE_DOUBLE => {
            writer.align(8);
            writer.write_f64(*(element_ptr as *const f64));
        }
        ROS_TYPE_LONG_DOUBLE => {
            writer.align(LONG_DOUBLE_ALIGN);
            let bytes = std::slice::from_raw_parts(element_ptr as *const u8, LONG_DOUBLE_SIZE);
            writer.write_bytes(bytes);
        }
        ROS_TYPE_CHAR | ROS_TYPE_OCTET | ROS_TYPE_UINT8 => {
            writer.write_u8(*(element_ptr as *const u8));
        }
        ROS_TYPE_INT8 => {
            writer.write_u8(*(element_ptr as *const i8) as u8);
        }
        ROS_TYPE_BOOLEAN => {
            writer.write_u8(u8::from(*(element_ptr as *const bool)));
        }
        ROS_TYPE_UINT16 => {
            writer.align(2);
            writer.write_u16(*(element_ptr as *const u16));
        }
        ROS_TYPE_INT16 => {
            writer.align(2);
            writer.write_i16(*(element_ptr as *const i16));
        }
        ROS_TYPE_UINT32 => {
            writer.align(4);
            writer.write_u32(*(element_ptr as *const u32));
        }
        ROS_TYPE_INT32 => {
            writer.align(4);
            writer.write_i32(*(element_ptr as *const i32));
        }
        ROS_TYPE_UINT64 => {
            writer.align(8);
            writer.write_u64(*(element_ptr as *const u64));
        }
        ROS_TYPE_INT64 => {
            writer.align(8);
            writer.write_i64(*(element_ptr as *const i64));
        }
        ROS_TYPE_WCHAR => {
            writer.align(2);
            writer.write_u16(*(element_ptr as *const u16));
        }
        ROS_TYPE_STRING => {
            let string = element_ptr as *const rosidl_runtime_c__String;
            writer.align(4);
            serialize_string(writer, member, &*string)?;
        }
        ROS_TYPE_WSTRING => {
            let wstring = element_ptr as *const rosidl_runtime_c__U16String;
            writer.align(4);
            serialize_wstring(writer, member, &*wstring)?;
        }
        ROS_TYPE_MESSAGE => {
            let nested_ts = member.members_;
            let metadata = cache.get(nested_ts)?;
            serialize_message(writer, metadata.as_ref(), element_ptr, cache)?;
        }
        _ => return Err(SerializeError::UnsupportedType("unsupported type id")),
    }

    Ok(())
}

unsafe fn serialize_string(
    writer: &mut CdrWriter,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    string: &rosidl_runtime_c__String,
) -> Result<(), SerializeError> {
    let len = string.size;
    if member.string_upper_bound_ > 0 && len > member.string_upper_bound_ {
        return Err(SerializeError::LengthExceeded("string exceeds bound"));
    }

    let data = if string.data.is_null() {
        &[]
    } else {
        slice::from_raw_parts(string.data as *const u8, len)
    };

    let total = len.checked_add(1).ok_or(SerializeError::BufferOverflow)?;
    let len_u32 = u32::try_from(total).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);

    writer.write_bytes(data);
    writer.write_u8(0);

    Ok(())
}

unsafe fn serialize_wstring(
    writer: &mut CdrWriter,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    string: &rosidl_runtime_c__U16String,
) -> Result<(), SerializeError> {
    let len = string.size;
    if member.string_upper_bound_ > 0 && len > member.string_upper_bound_ {
        return Err(SerializeError::LengthExceeded("wstring exceeds bound"));
    }

    let data = if string.data.is_null() {
        &[]
    } else {
        slice::from_raw_parts(string.data, len)
    };

    let total = len.checked_add(1).ok_or(SerializeError::BufferOverflow)?;
    let len_u32 = u32::try_from(total).map_err(|_| SerializeError::BufferOverflow)?;
    writer.write_u32(len_u32);
    writer.align(2);
    for value in data {
        writer.write_u16(*value);
    }
    writer.write_u16(0);
    Ok(())
}

unsafe fn deserialize_message(
    cursor: &mut CdrCursor<'_>,
    metadata: &RosMessageMetadata,
    ros_message: *mut c_void,
    cache: &mut MetadataCache,
) -> Result<(), DeserializeError> {
    cursor.align(4)?;

    let members = &*metadata.members;
    let fields = slice::from_raw_parts(members.members_, members.member_count_ as usize);

    for member in fields {
        let field_ptr = (ros_message as *mut u8).add(member.offset_ as usize) as *mut c_void;
        if member.is_array_ {
            if member.array_size_ > 0 && !member.is_upper_bound_ {
                deserialize_fixed_array(cursor, member, field_ptr, cache)?;
            } else {
                deserialize_sequence(cursor, member, field_ptr, cache)?;
            }
        } else {
            deserialize_value(cursor, member, field_ptr, cache)?;
        }
    }

    Ok(())
}

unsafe fn deserialize_fixed_array(
    cursor: &mut CdrCursor<'_>,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    field_ptr: *mut c_void,
    cache: &mut MetadataCache,
) -> Result<(), DeserializeError> {
    let size = member.array_size_;
    if let Some(get_fn) = member.get_function {
        for index in 0..size {
            let element = get_fn(field_ptr, index);
            deserialize_value(cursor, member, element, cache)?;
        }
        Ok(())
    } else {
        let element_size = element_size(member, cache)?;
        for index in 0..size {
            let element = (field_ptr as *mut u8).add(element_size * index) as *mut c_void;
            deserialize_value(cursor, member, element, cache)?;
        }
        Ok(())
    }
}

unsafe fn deserialize_sequence(
    cursor: &mut CdrCursor<'_>,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    field_ptr: *mut c_void,
    cache: &mut MetadataCache,
) -> Result<(), DeserializeError> {
    cursor.align(4)?;
    let len = cursor.read_u32()? as usize;

    if member.is_upper_bound_ && len > member.array_size_ {
        return Err(DeserializeError::LengthExceeded("sequence exceeds bound"));
    }

    if let Some(resize_fn) = member.resize_function {
        if !resize_fn(field_ptr, len) {
            return Err(DeserializeError::ResizeFailed);
        }
    } else if member.assign_function.is_some() {
        resize_sequence_with_assign(member, field_ptr, len, cache)?;
    } else {
        return Err(DeserializeError::UnsupportedType("sequence without resize"));
    }

    if let Some(get_fn) = member.get_function {
        for index in 0..len {
            let element = get_fn(field_ptr, index);
            deserialize_value(cursor, member, element, cache)?;
        }
        Ok(())
    } else if let Some(assign_fn) = member.assign_function {
        for index in 0..len {
            decode_sequence_element_with_assign(
                cursor, member, field_ptr, index, assign_fn, cache,
            )?;
        }
        Ok(())
    } else {
        Err(DeserializeError::MissingGetFunction)
    }
}

#[repr(C)]
struct GenericSequence {
    data: *mut c_void,
    size: usize,
    capacity: usize,
}

unsafe fn resize_sequence_with_assign(
    member: &rosidl_typesupport_introspection_c__MessageMember,
    field_ptr: *mut c_void,
    len: usize,
    cache: &mut MetadataCache,
) -> Result<(), DeserializeError> {
    let seq = &mut *(field_ptr as *mut GenericSequence);

    if !seq.data.is_null() {
        let elem_size = element_size(member, cache)?;
        for idx in 0..seq.size {
            let elem_ptr = (seq.data as *mut u8).add(idx * elem_size) as *mut c_void;
            fini_sequence_element(member, elem_ptr, cache);
        }
        libc::free(seq.data);
        seq.data = ptr::null_mut();
        seq.size = 0;
        seq.capacity = 0;
    }

    if len == 0 {
        return Ok(());
    }

    let elem_size = element_size(member, cache)?;
    let total = len
        .checked_mul(elem_size)
        .ok_or(DeserializeError::ResizeFailed)?;
    let data = libc::malloc(total);
    if data.is_null() {
        return Err(DeserializeError::ResizeFailed);
    }
    ptr::write_bytes(data, 0, total);

    if let Err(err) = init_sequence_elements(member, data, len, cache) {
        libc::free(data);
        return Err(err);
    }

    seq.data = data;
    seq.size = len;
    seq.capacity = len;
    Ok(())
}

unsafe fn init_sequence_elements(
    member: &rosidl_typesupport_introspection_c__MessageMember,
    data: *mut c_void,
    len: usize,
    cache: &mut MetadataCache,
) -> Result<(), DeserializeError> {
    match member.type_id_ {
        ROS_TYPE_STRING => {
            for idx in 0..len {
                let elem_ptr = (data as *mut u8)
                    .add(idx * std::mem::size_of::<rosidl_runtime_c__String>())
                    as *mut rosidl_runtime_c__String;
                if !rosidl_runtime_c__String__init(elem_ptr) {
                    for back in 0..idx {
                        let back_ptr = (data as *mut u8)
                            .add(back * std::mem::size_of::<rosidl_runtime_c__String>())
                            as *mut rosidl_runtime_c__String;
                        rosidl_runtime_c__String__fini(back_ptr);
                    }
                    return Err(DeserializeError::ResizeFailed);
                }
            }
        }
        ROS_TYPE_WSTRING => {
            for idx in 0..len {
                let elem_ptr = (data as *mut u8)
                    .add(idx * std::mem::size_of::<rosidl_runtime_c__U16String>())
                    as *mut rosidl_runtime_c__U16String;
                if !rosidl_runtime_c__U16String__init(elem_ptr) {
                    for back in 0..idx {
                        let back_ptr = (data as *mut u8)
                            .add(back * std::mem::size_of::<rosidl_runtime_c__U16String>())
                            as *mut rosidl_runtime_c__U16String;
                        rosidl_runtime_c__U16String__fini(back_ptr);
                    }
                    return Err(DeserializeError::ResizeFailed);
                }
            }
        }
        ROS_TYPE_MESSAGE => {
            let metadata = cache.get(member.members_)?;
            let members = unsafe { &*metadata.members };
            if let Some(init_fn) = members.init_function {
                for idx in 0..len {
                    let elem_ptr = (data as *mut u8)
                        .add(idx * members.size_of_)
                        .cast::<c_void>();
                    init_fn(elem_ptr, 0);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

unsafe fn fini_sequence_element(
    member: &rosidl_typesupport_introspection_c__MessageMember,
    elem_ptr: *mut c_void,
    cache: &mut MetadataCache,
) {
    match member.type_id_ {
        ROS_TYPE_STRING => {
            rosidl_runtime_c__String__fini(elem_ptr as *mut rosidl_runtime_c__String);
        }
        ROS_TYPE_WSTRING => {
            rosidl_runtime_c__U16String__fini(elem_ptr as *mut rosidl_runtime_c__U16String);
        }
        ROS_TYPE_MESSAGE => {
            if let Ok(metadata) = cache.get(member.members_) {
                let members = unsafe { &*metadata.members };
                if let Some(fini_fn) = members.fini_function {
                    fini_fn(elem_ptr);
                }
            }
        }
        _ => {}
    }
}

unsafe fn deserialize_value(
    cursor: &mut CdrCursor<'_>,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    element_ptr: *mut c_void,
    cache: &mut MetadataCache,
) -> Result<(), DeserializeError> {
    match member.type_id_ {
        ROS_TYPE_FLOAT => {
            cursor.align(4)?;
            *(element_ptr as *mut f32) = cursor.read_f32()?;
        }
        ROS_TYPE_DOUBLE => {
            cursor.align(8)?;
            *(element_ptr as *mut f64) = cursor.read_f64()?;
        }
        ROS_TYPE_LONG_DOUBLE => {
            cursor.align(LONG_DOUBLE_ALIGN)?;
            let bytes = cursor.read_bytes(LONG_DOUBLE_SIZE)?;
            ptr::copy_nonoverlapping(bytes.as_ptr(), element_ptr.cast::<u8>(), LONG_DOUBLE_SIZE);
        }
        ROS_TYPE_CHAR => {
            *(element_ptr as *mut u8) = cursor.read_u8()?;
        }
        ROS_TYPE_INT8 => {
            *(element_ptr as *mut i8) = cursor.read_u8()? as i8;
        }
        ROS_TYPE_BOOLEAN => {
            *(element_ptr as *mut bool) = cursor.read_u8()? != 0;
        }
        ROS_TYPE_OCTET => {
            *(element_ptr as *mut u8) = cursor.read_u8()?;
        }
        ROS_TYPE_UINT8 => {
            *(element_ptr as *mut u8) = cursor.read_u8()?;
        }
        ROS_TYPE_UINT16 => {
            cursor.align(2)?;
            *(element_ptr as *mut u16) = cursor.read_u16()?;
        }
        ROS_TYPE_INT16 => {
            cursor.align(2)?;
            *(element_ptr as *mut i16) = cursor.read_i16()?;
        }
        ROS_TYPE_UINT32 => {
            cursor.align(4)?;
            *(element_ptr as *mut u32) = cursor.read_u32()?;
        }
        ROS_TYPE_INT32 => {
            cursor.align(4)?;
            *(element_ptr as *mut i32) = cursor.read_i32()?;
        }
        ROS_TYPE_UINT64 => {
            cursor.align(8)?;
            *(element_ptr as *mut u64) = cursor.read_u64()?;
        }
        ROS_TYPE_INT64 => {
            cursor.align(8)?;
            *(element_ptr as *mut i64) = cursor.read_i64()?;
        }
        ROS_TYPE_WCHAR => {
            cursor.align(2)?;
            *(element_ptr as *mut u16) = cursor.read_u16()?;
        }
        ROS_TYPE_STRING => {
            cursor.align(4)?;
            deserialize_string(cursor, member, element_ptr as *mut rosidl_runtime_c__String)?;
        }
        ROS_TYPE_WSTRING => {
            cursor.align(4)?;
            deserialize_wstring(
                cursor,
                member,
                element_ptr as *mut rosidl_runtime_c__U16String,
            )?;
        }
        ROS_TYPE_MESSAGE => {
            cursor.align(4)?;
            let nested_ts = member.members_;
            let metadata = cache.get(nested_ts)?;
            deserialize_message(cursor, metadata.as_ref(), element_ptr, cache)?;
        }
        _ => {
            return Err(DeserializeError::UnsupportedType("unsupported type id"));
        }
    }

    Ok(())
}

unsafe fn decode_sequence_element_with_assign(
    cursor: &mut CdrCursor<'_>,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    field_ptr: *mut c_void,
    index: usize,
    assign_fn: unsafe extern "C" fn(*mut c_void, usize, *const c_void),
    cache: &mut MetadataCache,
) -> Result<(), DeserializeError> {
    macro_rules! decode_scalar {
        ($ty:ty) => {{
            let mut value = MaybeUninit::<$ty>::uninit();
            deserialize_value(cursor, member, value.as_mut_ptr().cast(), cache)?;
            assign_fn(field_ptr, index, value.as_ptr().cast());
            Ok(())
        }};
    }

    match member.type_id_ {
        ROS_TYPE_BOOLEAN => decode_scalar!(bool),
        ROS_TYPE_CHAR | ROS_TYPE_OCTET | ROS_TYPE_UINT8 => decode_scalar!(u8),
        ROS_TYPE_INT8 => decode_scalar!(i8),
        ROS_TYPE_UINT16 | ROS_TYPE_WCHAR => decode_scalar!(u16),
        ROS_TYPE_INT16 => decode_scalar!(i16),
        ROS_TYPE_UINT32 => decode_scalar!(u32),
        ROS_TYPE_INT32 => decode_scalar!(i32),
        ROS_TYPE_UINT64 => decode_scalar!(u64),
        ROS_TYPE_INT64 => decode_scalar!(i64),
        ROS_TYPE_FLOAT => decode_scalar!(f32),
        ROS_TYPE_DOUBLE => decode_scalar!(f64),
        ROS_TYPE_LONG_DOUBLE => {
            let mut storage = [0u8; 16];
            deserialize_value(cursor, member, storage.as_mut_ptr().cast(), cache)?;
            assign_fn(field_ptr, index, storage.as_ptr().cast());
            Ok(())
        }
        ROS_TYPE_STRING => {
            let mut string = rosidl_runtime_c__String {
                data: ptr::null_mut(),
                size: 0,
                capacity: 0,
            };
            if !rosidl_runtime_c__String__init(&mut string) {
                return Err(DeserializeError::StringAssignFailed);
            }
            struct RosStringGuard(*mut rosidl_runtime_c__String);
            impl Drop for RosStringGuard {
                fn drop(&mut self) {
                    unsafe { rosidl_runtime_c__String__fini(self.0) };
                }
            }
            let guard = RosStringGuard(&mut string);
            deserialize_string(cursor, member, &mut string)?;
            assign_fn(field_ptr, index, &string as *const _ as *const c_void);
            drop(guard);
            Ok(())
        }
        ROS_TYPE_WSTRING => {
            let mut wstring = rosidl_runtime_c__U16String {
                data: ptr::null_mut(),
                size: 0,
                capacity: 0,
            };
            if !rosidl_runtime_c__U16String__init(&mut wstring) {
                return Err(DeserializeError::StringAssignFailed);
            }
            struct RosWStringGuard(*mut rosidl_runtime_c__U16String);
            impl Drop for RosWStringGuard {
                fn drop(&mut self) {
                    unsafe { rosidl_runtime_c__U16String__fini(self.0) };
                }
            }
            let guard = RosWStringGuard(&mut wstring);
            deserialize_wstring(cursor, member, &mut wstring)?;
            assign_fn(field_ptr, index, &wstring as *const _ as *const c_void);
            drop(guard);
            Ok(())
        }
        ROS_TYPE_MESSAGE => {
            let metadata = cache.get(member.members_)?;
            let members = unsafe { &*metadata.members };
            let mut buffer = vec![0u8; members.size_of_];
            let element_ptr = buffer.as_mut_ptr() as *mut c_void;

            struct MessageGuard {
                ptr: *mut c_void,
                fini: Option<unsafe extern "C" fn(*mut c_void)>,
            }

            impl Drop for MessageGuard {
                fn drop(&mut self) {
                    if let Some(fini_fn) = self.fini {
                        unsafe { fini_fn(self.ptr) };
                    }
                }
            }

            if let Some(init_fn) = members.init_function {
                unsafe { init_fn(element_ptr, 0) };
            } else {
                unsafe {
                    ptr::write_bytes(element_ptr.cast::<u8>(), 0, members.size_of_);
                }
            }

            let guard = MessageGuard {
                ptr: element_ptr,
                fini: members.fini_function,
            };

            deserialize_message(cursor, metadata.as_ref(), element_ptr, cache)?;
            assign_fn(field_ptr, index, element_ptr);
            drop(guard);
            Ok(())
        }
        _ => Err(DeserializeError::UnsupportedType(
            "assign-only sequence type unsupported",
        )),
    }
}

unsafe fn deserialize_string(
    cursor: &mut CdrCursor<'_>,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    string_field: *mut rosidl_runtime_c__String,
) -> Result<(), DeserializeError> {
    let len = cursor.read_u32()? as usize;
    let raw = cursor.read_bytes(len)?;
    let content = if len > 0 && raw[len - 1] == 0 {
        &raw[..len - 1]
    } else {
        raw
    };

    if member.string_upper_bound_ > 0 && content.len() > member.string_upper_bound_ {
        return Err(DeserializeError::LengthExceeded("string exceeds bound"));
    }

    if (*string_field).data.is_null() && !rosidl_runtime_c__String__init(string_field) {
        return Err(DeserializeError::StringAssignFailed);
    }

    let mut tmp = Vec::with_capacity(content.len() + 1);
    tmp.extend_from_slice(content);
    tmp.push(0);

    if !rosidl_runtime_c__String__assign(string_field, tmp.as_ptr() as *const c_char) {
        return Err(DeserializeError::StringAssignFailed);
    }

    Ok(())
}

unsafe fn deserialize_wstring(
    cursor: &mut CdrCursor<'_>,
    member: &rosidl_typesupport_introspection_c__MessageMember,
    string_field: *mut rosidl_runtime_c__U16String,
) -> Result<(), DeserializeError> {
    let char_count = cursor.read_u32()? as usize;
    cursor.align(2)?;
    let width = std::mem::size_of::<u16>();
    let total_bytes = char_count
        .checked_mul(width)
        .ok_or(DeserializeError::UnsupportedType("wstring length overflow"))?;
    let raw = cursor.read_bytes(total_bytes)?;

    let mut values = Vec::with_capacity(char_count);
    for chunk in raw.chunks_exact(width) {
        values.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    if let Some(&0) = values.last() {
        values.pop();
    }

    if member.string_upper_bound_ > 0 && values.len() > member.string_upper_bound_ {
        return Err(DeserializeError::LengthExceeded("wstring exceeds bound"));
    }

    if (*string_field).data.is_null() && !rosidl_runtime_c__U16String__init(string_field) {
        return Err(DeserializeError::StringAssignFailed);
    }

    static EMPTY_U16: [u16; 1] = [0];
    let (ptr, len) = if values.is_empty() {
        (EMPTY_U16.as_ptr(), 0)
    } else {
        (values.as_ptr(), values.len())
    };

    if !rosidl_runtime_c__U16String__assignn(string_field, ptr, len) {
        return Err(DeserializeError::StringAssignFailed);
    }

    Ok(())
}

fn primitive_size(type_id: u8) -> Option<usize> {
    match type_id {
        ROS_TYPE_BOOLEAN => Some(1),
        ROS_TYPE_CHAR => Some(1),
        ROS_TYPE_OCTET => Some(1),
        ROS_TYPE_UINT8 => Some(1),
        ROS_TYPE_INT8 => Some(1),
        ROS_TYPE_UINT16 => Some(2),
        ROS_TYPE_INT16 => Some(2),
        ROS_TYPE_WCHAR => Some(std::mem::size_of::<u16>()),
        ROS_TYPE_FLOAT => Some(4),
        ROS_TYPE_UINT32 => Some(4),
        ROS_TYPE_INT32 => Some(4),
        ROS_TYPE_DOUBLE => Some(8),
        ROS_TYPE_UINT64 => Some(8),
        ROS_TYPE_INT64 => Some(8),
        ROS_TYPE_LONG_DOUBLE => Some(LONG_DOUBLE_SIZE),
        _ => None,
    }
}

unsafe fn element_size(
    member: &rosidl_typesupport_introspection_c__MessageMember,
    cache: &mut MetadataCache,
) -> Result<usize, DeserializeError> {
    if let Some(size) = primitive_size(member.type_id_) {
        return Ok(size);
    }

    match member.type_id_ {
        ROS_TYPE_STRING => Ok(std::mem::size_of::<rosidl_runtime_c__String>()),
        ROS_TYPE_WSTRING => Ok(std::mem::size_of::<rosidl_runtime_c__U16String>()),
        ROS_TYPE_MESSAGE => {
            let metadata = cache.get(member.members_)?;
            Ok((*metadata.members).size_of_)
        }
        _ => Err(DeserializeError::UnsupportedType(
            "unable to determine element size",
        )),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_deserialize_ros_message(
    type_support: *const rosidl_message_type_support_t,
    data: *const u8,
    len: usize,
    ros_message: *mut c_void,
) -> HddsError {
    if type_support.is_null() || ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let slice = if len == 0 || data.is_null() {
        &[]
    } else {
        slice::from_raw_parts(data, len)
    };

    match deserialize_into_ros(type_support, slice, ros_message) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => map_api_error(err),
    }
}
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rmw_serialize_ros_message(
    type_support: *const rosidl_message_type_support_t,
    ros_message: *const c_void,
    buffer: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> HddsError {
    if type_support.is_null() || ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let payload = match serialize_from_ros(type_support, ros_message) {
        Ok(payload) => payload,
        Err(err) => return map_api_error(err),
    };

    let len = payload.data.len();
    if !out_len.is_null() {
        out_len.write(len);
    }

    if len == 0 {
        return HddsError::HddsOk;
    }

    if buffer.is_null() || capacity < len {
        return HddsError::HddsOutOfMemory;
    }

    ptr::copy_nonoverlapping(payload.data.as_ptr(), buffer, len);
    HddsError::HddsOk
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdds::core::types::ROS_HASH_SIZE;
    use hdds::xtypes::builder::{
        rosidl_runtime_c__message_initialization, rosidl_type_hash_t,
        rosidl_typesupport_introspection_c__MessageMembers,
    };
    use libc::{free, malloc, realloc};
    use std::ptr;

    #[repr(C)]
    struct U32Sequence {
        data: *mut u32,
        size: usize,
        capacity: usize,
    }

    impl U32Sequence {
        fn new() -> Self {
            Self {
                data: ptr::null_mut(),
                size: 0,
                capacity: 0,
            }
        }

        unsafe fn free(&mut self) {
            if !self.data.is_null() {
                free(self.data.cast());
                self.data = ptr::null_mut();
            }
            self.size = 0;
            self.capacity = 0;
        }
    }

    unsafe extern "C" fn resize_u32_sequence(untyped_member: *mut c_void, size: usize) -> bool {
        let seq = &mut *(untyped_member as *mut U32Sequence);
        if size == 0 {
            seq.free();
            return true;
        }

        let bytes = match size.checked_mul(std::mem::size_of::<u32>()) {
            Some(total) => total,
            None => return false,
        };

        let ptr = if seq.data.is_null() {
            malloc(bytes)
        } else {
            realloc(seq.data.cast(), bytes)
        };

        if ptr.is_null() {
            return false;
        }

        seq.data = ptr.cast::<u32>();
        seq.size = size;
        seq.capacity = size;
        ptr::write_bytes(seq.data, 0, size);
        true
    }

    unsafe extern "C" fn get_u32_sequence(
        untyped_member: *mut c_void,
        index: usize,
    ) -> *mut c_void {
        let seq = &mut *(untyped_member as *mut U32Sequence);
        debug_assert!(index < seq.size);
        seq.data.add(index).cast()
    }

    unsafe extern "C" fn assign_u32_sequence(
        untyped_member: *mut c_void,
        index: usize,
        value: *const c_void,
    ) {
        let seq = &mut *(untyped_member as *mut U32Sequence);
        debug_assert!(index < seq.size);
        *seq.data.add(index) = *(value as *const u32);
    }

    fn make_member(type_id: u8) -> rosidl_typesupport_introspection_c__MessageMember {
        rosidl_typesupport_introspection_c__MessageMember {
            name_: ptr::null(),
            type_id_: type_id,
            string_upper_bound_: 0,
            members_: ptr::null(),
            is_array_: false,
            array_size_: 0,
            is_upper_bound_: false,
            offset_: 0,
            default_value_: ptr::null(),
            size_function: None,
            get_const_function: None,
            get_function: None,
            fetch_function: None,
            assign_function: None,
            resize_function: None,
        }
    }

    #[test]
    fn deserialize_string_assigns_utf8_payload() {
        let data = [3, 0, 0, 0, b'a', b'b', 0];
        let mut cursor = CdrCursor::new(&data);
        let mut member = make_member(ROS_TYPE_STRING);
        member.string_upper_bound_ = 8;
        let mut ros_string = rosidl_runtime_c__String {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };

        unsafe {
            deserialize_string(&mut cursor, &member, &mut ros_string).unwrap();
            let slice = std::slice::from_raw_parts(ros_string.data as *const u8, ros_string.size);
            assert_eq!(slice, b"ab");
            rosidl_runtime_c__String__fini(&mut ros_string);
        }
    }

    #[test]
    fn deserialize_string_respects_upper_bound() {
        let data = [3, 0, 0, 0, b'a', b'b', 0];
        let mut cursor = CdrCursor::new(&data);
        let mut member = make_member(ROS_TYPE_STRING);
        member.string_upper_bound_ = 1;
        let mut ros_string = rosidl_runtime_c__String {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };

        unsafe {
            let result = deserialize_string(&mut cursor, &member, &mut ros_string);
            assert!(matches!(
                result,
                Err(DeserializeError::LengthExceeded("string exceeds bound"))
            ));
        }
    }

    #[test]
    fn deserialize_wstring_decodes_utf16_payload() {
        let data = [
            3, 0, 0, 0, // length
            0x48, 0x00, // 'H'
            0x69, 0x00, // 'i'
            0x00, 0x00, // null terminator
        ];
        let mut cursor = CdrCursor::new(&data);
        let mut member = make_member(ROS_TYPE_WSTRING);
        member.string_upper_bound_ = 8;
        let mut ros_wstring = rosidl_runtime_c__U16String {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };

        unsafe {
            deserialize_wstring(&mut cursor, &member, &mut ros_wstring).unwrap();
            let slice = std::slice::from_raw_parts(ros_wstring.data, ros_wstring.size);
            assert_eq!(slice, &[0x0048, 0x0069]);
            rosidl_runtime_c__U16String__fini(&mut ros_wstring);
        }
    }

    #[test]
    fn deserialize_wstring_respects_upper_bound() {
        let data = [
            3, 0, 0, 0, // length
            0x48, 0x00, // 'H'
            0x69, 0x00, // 'i'
            0x00, 0x00, // null terminator
        ];
        let mut cursor = CdrCursor::new(&data);
        let mut member = make_member(ROS_TYPE_WSTRING);
        member.string_upper_bound_ = 1;
        let mut ros_wstring = rosidl_runtime_c__U16String {
            data: ptr::null_mut(),
            size: 0,
            capacity: 0,
        };

        unsafe {
            let result = deserialize_wstring(&mut cursor, &member, &mut ros_wstring);
            assert!(matches!(
                result,
                Err(DeserializeError::LengthExceeded("wstring exceeds bound"))
            ));
        }
    }

    #[test]
    fn deserialize_u32_sequence_populates_elements() {
        #[repr(C)]
        struct Message {
            seq: U32Sequence,
        }

        let mut message = Message {
            seq: U32Sequence::new(),
        };

        let mut member = make_member(ROS_TYPE_UINT32);
        member.is_array_ = true;
        member.array_size_ = 0;
        member.is_upper_bound_ = false;
        member.resize_function = Some(resize_u32_sequence);
        member.get_function = Some(get_u32_sequence);
        member.offset_ = 0;

        // CDR2 layout: length (u32 LE) followed by elements (u32 LE each).
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&42u32.to_le_bytes());

        let mut cursor = CdrCursor::new(&data);
        let mut cache = MetadataCache::new();

        unsafe {
            deserialize_sequence(
                &mut cursor,
                &member,
                &mut message.seq as *mut _ as *mut c_void,
                &mut cache,
            )
            .unwrap();

            let slice = std::slice::from_raw_parts(message.seq.data, message.seq.size);
            assert_eq!(slice, &[1, 2, 42]);
            message.seq.free();
        }
    }

    #[test]
    fn deserialize_u32_sequence_respects_upper_bound() {
        #[repr(C)]
        struct Message {
            seq: U32Sequence,
        }

        let mut message = Message {
            seq: U32Sequence::new(),
        };

        let mut member = make_member(ROS_TYPE_UINT32);
        member.is_array_ = true;
        member.array_size_ = 2;
        member.is_upper_bound_ = true;
        member.resize_function = Some(resize_u32_sequence);
        member.get_function = Some(get_u32_sequence);
        member.offset_ = 0;

        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());

        let mut cursor = CdrCursor::new(&data);
        let mut cache = MetadataCache::new();

        unsafe {
            let result = deserialize_sequence(
                &mut cursor,
                &member,
                &mut message.seq as *mut _ as *mut c_void,
                &mut cache,
            );
            assert!(matches!(
                result,
                Err(DeserializeError::LengthExceeded("sequence exceeds bound"))
            ));
            message.seq.free();
        }
    }

    #[test]
    fn deserialize_u32_sequence_with_assign_only() {
        #[repr(C)]
        struct Message {
            seq: U32Sequence,
        }

        let mut message = Message {
            seq: U32Sequence::new(),
        };

        let mut member = make_member(ROS_TYPE_UINT32);
        member.is_array_ = true;
        member.array_size_ = 0;
        member.is_upper_bound_ = false;
        member.assign_function = Some(assign_u32_sequence);
        member.offset_ = 0;

        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&7u32.to_le_bytes());

        let mut cursor = CdrCursor::new(&data);
        let mut cache = MetadataCache::new();

        unsafe {
            deserialize_sequence(
                &mut cursor,
                &member,
                &mut message.seq as *mut _ as *mut c_void,
                &mut cache,
            )
            .unwrap();

            let slice = std::slice::from_raw_parts(message.seq.data, message.seq.size);
            assert_eq!(slice, &[5, 7]);
            message.seq.free();
        }
    }

    #[repr(C)]
    struct NestedMsg {
        value: u32,
    }

    #[repr(C)]
    struct NestedSequence {
        data: *mut NestedMsg,
        size: usize,
        capacity: usize,
    }

    impl NestedSequence {
        const fn new() -> Self {
            Self {
                data: ptr::null_mut(),
                size: 0,
                capacity: 0,
            }
        }
    }

    static HASH_ZERO: rosidl_type_hash_t = rosidl_type_hash_t {
        version: 1,
        value: [0; ROS_HASH_SIZE],
    };

    unsafe extern "C" fn get_type_hash(
        _ts: *const rosidl_message_type_support_t,
    ) -> *const rosidl_type_hash_t {
        &HASH_ZERO
    }

    unsafe extern "C" fn nested_init(
        msg: *mut c_void,
        _init: rosidl_runtime_c__message_initialization,
    ) {
        if msg.is_null() {
            return;
        }
        let nested = &mut *(msg as *mut NestedMsg);
        nested.value = 0;
    }

    unsafe extern "C" fn nested_fini(_msg: *mut c_void) {}

    unsafe extern "C" fn resize_nested_sequence(untyped_member: *mut c_void, size: usize) -> bool {
        let seq = &mut *(untyped_member as *mut NestedSequence);

        if !seq.data.is_null() {
            for idx in 0..seq.size {
                nested_fini(seq.data.add(idx) as *mut c_void);
            }
            free(seq.data.cast());
            seq.data = ptr::null_mut();
            seq.size = 0;
            seq.capacity = 0;
        }

        if size == 0 {
            return true;
        }

        let bytes = match size.checked_mul(std::mem::size_of::<NestedMsg>()) {
            Some(total) => total,
            None => return false,
        };

        let ptr = malloc(bytes);
        if ptr.is_null() {
            return false;
        }

        for idx in 0..size {
            nested_init((ptr as *mut NestedMsg).add(idx) as *mut c_void, 0);
        }

        seq.data = ptr.cast::<NestedMsg>();
        seq.size = size;
        seq.capacity = size;
        true
    }

    unsafe extern "C" fn assign_nested_sequence(
        untyped_member: *mut c_void,
        index: usize,
        value: *const c_void,
    ) {
        let seq = &mut *(untyped_member as *mut NestedSequence);
        let dest = seq.data.add(index);
        ptr::copy_nonoverlapping(value as *const NestedMsg, dest, 1);
    }

    unsafe extern "C" fn container_init(
        msg: *mut c_void,
        _init: rosidl_runtime_c__message_initialization,
    ) {
        if msg.is_null() {
            return;
        }
        let container = &mut *(msg as *mut ContainerMsg);
        container.nested = NestedSequence::new();
    }

    unsafe extern "C" fn container_fini(msg: *mut c_void) {
        if msg.is_null() {
            return;
        }
        let container = &mut *(msg as *mut ContainerMsg);
        resize_nested_sequence(&mut container.nested as *mut _ as *mut c_void, 0);
    }

    #[repr(C)]
    struct ContainerMsg {
        nested: NestedSequence,
    }

    #[test]
    fn deserialize_sequence_of_messages_with_assign() {
        let mut container = ContainerMsg {
            nested: NestedSequence::new(),
        };

        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&10u32.to_le_bytes());
        data.extend_from_slice(&20u32.to_le_bytes());

        let nested_members_array = Box::leak(Box::new([
            rosidl_typesupport_introspection_c__MessageMember {
                name_: c"value".as_ptr(),
                type_id_: ROS_TYPE_UINT32,
                string_upper_bound_: 0,
                members_: ptr::null(),
                is_array_: false,
                array_size_: 0,
                is_upper_bound_: false,
                offset_: 0,
                default_value_: ptr::null(),
                size_function: None,
                get_const_function: None,
                get_function: None,
                fetch_function: None,
                assign_function: None,
                resize_function: None,
            },
        ]));

        let nested_members = Box::leak(Box::new(
            rosidl_typesupport_introspection_c__MessageMembers {
                message_namespace_: c"test".as_ptr(),
                message_name_: c"Nested".as_ptr(),
                member_count_: 1,
                size_of_: std::mem::size_of::<NestedMsg>(),
                members_: nested_members_array.as_ptr(),
                init_function: Some(nested_init),
                fini_function: Some(nested_fini),
            },
        ));

        let nested_type_support = Box::leak(Box::new(rosidl_message_type_support_t {
            typesupport_identifier: c"introspection_test".as_ptr(),
            data: nested_members as *const _ as *const c_void,
            func: None,
            get_type_hash_func: Some(get_type_hash),
            get_type_description_func: None,
            get_type_description_sources_func: None,
        }));

        let container_members_array = Box::leak(Box::new([
            rosidl_typesupport_introspection_c__MessageMember {
                name_: c"nested".as_ptr(),
                type_id_: ROS_TYPE_MESSAGE,
                string_upper_bound_: 0,
                members_: nested_type_support as *const _,
                is_array_: true,
                array_size_: 0,
                is_upper_bound_: false,
                offset_: 0,
                default_value_: ptr::null(),
                size_function: None,
                get_const_function: None,
                get_function: None,
                fetch_function: None,
                assign_function: Some(assign_nested_sequence),
                resize_function: Some(resize_nested_sequence),
            },
        ]));

        let container_members = Box::leak(Box::new(
            rosidl_typesupport_introspection_c__MessageMembers {
                message_namespace_: c"test".as_ptr(),
                message_name_: c"Container".as_ptr(),
                member_count_: 1,
                size_of_: std::mem::size_of::<ContainerMsg>(),
                members_: container_members_array.as_ptr(),
                init_function: Some(container_init),
                fini_function: Some(container_fini),
            },
        ));

        let container_type_support = Box::leak(Box::new(rosidl_message_type_support_t {
            typesupport_identifier: c"introspection_test".as_ptr(),
            data: container_members as *const _ as *const c_void,
            func: None,
            get_type_hash_func: Some(get_type_hash),
            get_type_description_func: None,
            get_type_description_sources_func: None,
        }));

        let mut cache = MetadataCache::new();
        let metadata = unsafe {
            cache
                .get(container_type_support as *const _)
                .expect("metadata")
        };

        let mut cursor = CdrCursor::new(&data);

        unsafe {
            container_init(&mut container as *mut _ as *mut c_void, 0);
            deserialize_message(
                &mut cursor,
                metadata.as_ref(),
                &mut container as *mut _ as *mut c_void,
                &mut cache,
            )
            .unwrap();

            assert_eq!(container.nested.size, 2);
            let slice = std::slice::from_raw_parts(container.nested.data, container.nested.size);
            assert_eq!(slice[0].value, 10);
            assert_eq!(slice[1].value, 20);

            container_fini(&mut container as *mut _ as *mut c_void);
        }
    }

    #[test]
    fn test_shm_writer_reader_roundtrip() {
        // Test that ForeignRmwContext creates SHM segments and can roundtrip data
        let ctx = ForeignRmwContext::create("test_shm_rt").unwrap();

        // Create writer with BestEffort QoS (triggers SHM segment creation)
        let qos = QoS::default(); // BestEffort by default
        let writer_ptr = ctx
            .create_writer_raw_with_qos("shm_test_topic", &qos)
            .unwrap();
        assert!(!writer_ptr.is_null());

        // Verify SHM writer was created
        {
            let shm_map = ctx.shm_writers.read().unwrap();
            assert!(
                shm_map.contains_key("shm_test_topic"),
                "SHM writer should be created for BestEffort topic"
            );
        }

        // Create reader with BestEffort QoS (should attach to SHM segment)
        let reader_ptr = ctx
            .create_reader_raw_with_qos("shm_test_topic", &qos)
            .unwrap();
        assert!(!reader_ptr.is_null());

        // Verify SHM reader was attached
        {
            let shm_map = ctx.shm_readers_by_topic.read().unwrap();
            let readers = shm_map["shm_test_topic"].lock().unwrap();
            assert!(!readers.is_empty(), "SHM reader list should not be empty");
        }

        // Publish data through the writer (dual-write: RTPS + SHM)
        let test_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let payload = BytePayload {
            data: test_data.clone(),
        };
        ctx.publish_writer(writer_ptr, &payload).unwrap();

        // Verify SHM has data
        assert!(
            ctx.shm_has_data("shm_test_topic"),
            "SHM should have data after publish"
        );

        // Read from SHM
        let mut buf = [0u8; 4096];
        let len = ctx
            .try_shm_take("shm_test_topic", &mut buf)
            .expect("SHM take should return data");
        assert_eq!(len, test_data.len());
        assert_eq!(&buf[..len], &test_data[..]);

        // After take, SHM should be empty
        assert!(
            !ctx.shm_has_data("shm_test_topic"),
            "SHM should be empty after take"
        );

        // Cleanup
        ctx.destroy_writer_raw(writer_ptr).unwrap();
        ctx.destroy_reader_raw(reader_ptr).unwrap();

        // Verify SHM writer was cleaned up
        {
            let shm_map = ctx.shm_writers.read().unwrap();
            assert!(
                !shm_map.contains_key("shm_test_topic"),
                "SHM writer should be removed after destroy"
            );
        }
    }

    #[test]
    fn test_shm_latency_through_rmw() {
        use std::time::Instant;

        let ctx = ForeignRmwContext::create("test_shm_lat").unwrap();
        let qos = QoS::default();

        let writer_ptr = ctx.create_writer_raw_with_qos("lat_topic", &qos).unwrap();
        let _reader_ptr = ctx.create_reader_raw_with_qos("lat_topic", &qos).unwrap();

        let test_data = vec![0u8; 64];
        let payload = BytePayload {
            data: test_data.clone(),
        };
        let mut buf = [0u8; 4096];
        let iterations = 10_000;

        // Warmup
        for _ in 0..1000 {
            let _ = ctx.publish_writer(writer_ptr, &payload);
            let _ = ctx.try_shm_take("lat_topic", &mut buf);
        }

        // Measure SHM roundtrip through rmw context
        // Note: publish_writer may return WouldBlock if no RTPS subscribers,
        // but SHM push still succeeds (it happens before RTPS write).
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = ctx.publish_writer(writer_ptr, &payload);
            ctx.try_shm_take("lat_topic", &mut buf)
                .expect("SHM take should succeed");
        }
        let elapsed = start.elapsed();

        let avg_ns = elapsed.as_nanos() as f64 / iterations as f64;
        eprintln!(
            "RMW SHM roundtrip latency: {:.1} ns ({} iterations)",
            avg_ns, iterations
        );

        // Should be reasonable (includes RTPS write + SHM write + SHM read + mutex locks)
        // Release: < 5us typically.  Debug + Docker can be 100us+.
        assert!(
            avg_ns < 500_000.0,
            "RMW SHM roundtrip too slow: {avg_ns} ns"
        );
    }
}
