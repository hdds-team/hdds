// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Safe Rust wrappers around the HDDS rmw context/ waitset FFI.

pub mod env_config;
pub mod ffi;
mod util;

pub use env_config::EnvConfig;

use std::ffi::CString;
use std::os::raw::c_void;
use std::ptr::NonNull;
use std::time::Duration;

use crate::util::map_ready_indices;
use hdds::rmw::waitset::ConditionKey;
use hdds::xtypes::builder::rosidl_message_type_support_t;
use hdds_c::{
    hdds_guard_condition_release, hdds_guard_condition_set_trigger, hdds_rmw_context_attach_reader,
    hdds_rmw_context_bind_topic_type, hdds_rmw_context_create, hdds_rmw_context_create_reader,
    hdds_rmw_context_create_reader_with_qos, hdds_rmw_context_create_writer,
    hdds_rmw_context_create_writer_with_qos, hdds_rmw_context_destroy,
    hdds_rmw_context_destroy_reader, hdds_rmw_context_destroy_writer,
    hdds_rmw_context_detach_reader, hdds_rmw_context_graph_guard_condition,
    hdds_rmw_context_graph_guard_key, hdds_rmw_context_publish, hdds_rmw_context_register_node,
    hdds_rmw_context_register_publisher_endpoint, hdds_rmw_context_register_subscription_endpoint,
    hdds_rmw_context_unregister_node, hdds_rmw_context_unregister_publisher_endpoint,
    hdds_rmw_context_unregister_subscription_endpoint, hdds_rmw_context_wait_readers,
    hdds_rmw_waitset_attach_reader, hdds_rmw_waitset_create, hdds_rmw_waitset_destroy,
    hdds_rmw_waitset_detach_reader, hdds_rmw_waitset_wait, HddsDataReader, HddsDataWriter,
    HddsError, HddsGuardCondition, HddsQoS, HddsRmwContext, HddsRmwQosProfile, HddsRmwWaitSet,
};
use thiserror::Error;

/// Maximum number of readers captured on a single wait call.
/// 256 covers large ROS 2 nodes (ros2_control ~150 subs, nav2 ~100).
const DEFAULT_MAX_READERS: usize = 256;

/// Errors emitted by the safe rmw wrappers.
#[derive(Debug, Error)]
pub enum Error {
    #[error("null pointer returned by FFI call")]
    NullPointer,
    #[error("invalid argument")]
    InvalidArgument,
    #[error("not found")]
    NotFound,
    #[error("operation failed")]
    OperationFailed,
    #[error("out of memory")]
    OutOfMemory,
    #[error(transparent)]
    FfiString(#[from] std::ffi::NulError),
}

impl Error {
    fn from_hdds(err: HddsError) -> Self {
        match err {
            HddsError::HddsOk => Self::OperationFailed, // Should not map OK directly
            HddsError::HddsInvalidArgument => Self::InvalidArgument,
            HddsError::HddsNotFound => Self::NotFound,
            HddsError::HddsOperationFailed => Self::OperationFailed,
            HddsError::HddsOutOfMemory => Self::OutOfMemory,
            // Configuration errors (10-19) -> InvalidArgument
            HddsError::HddsConfigError
            | HddsError::HddsInvalidDomainId
            | HddsError::HddsInvalidParticipantId
            | HddsError::HddsNoAvailableParticipantId
            | HddsError::HddsInvalidState => Self::InvalidArgument,
            // I/O and transport errors (20-29) -> OperationFailed
            HddsError::HddsIoError
            | HddsError::HddsTransportError
            | HddsError::HddsRegistrationFailed
            | HddsError::HddsWouldBlock => Self::OperationFailed,
            // Type and serialization errors (30-39) -> InvalidArgument
            HddsError::HddsTypeMismatch
            | HddsError::HddsSerializationError
            | HddsError::HddsBufferTooSmall
            | HddsError::HddsEndianMismatch => Self::InvalidArgument,
            // QoS and resource errors (40-49) -> InvalidArgument
            HddsError::HddsQosIncompatible | HddsError::HddsUnsupported => Self::InvalidArgument,
            // Security errors (50-59) -> OperationFailed
            HddsError::HddsPermissionDenied | HddsError::HddsAuthenticationFailed => {
                Self::OperationFailed
            }
        }
    }
}

fn map_error(err: HddsError) -> Result<(), Error> {
    match err {
        HddsError::HddsOk => Ok(()),
        other => Err(Error::from_hdds(other)),
    }
}

pub(crate) fn duration_to_ns(timeout: Option<Duration>) -> i64 {
    match timeout {
        None => -1,
        Some(d) => i64::try_from(d.as_nanos()).unwrap_or(-1),
    }
}

/// Arguments supplied to an rmw-style wait call.
pub struct WaitArgs<'a> {
    /// Subscriptions (DataReaders) to monitor for readiness.
    pub subscriptions: &'a [*mut HddsDataReader],
}

impl<'a> WaitArgs<'a> {
    /// Convenience constructor.
    #[must_use]
    pub fn new(subscriptions: &'a [*mut HddsDataReader]) -> Self {
        Self { subscriptions }
    }
}

/// Result returned by [`Context::wait_for`] / [`WaitSet::wait_for`].
#[derive(Debug, Default)]
pub struct WaitResult {
    /// Indexes into the subscription slice that became ready.
    pub ready_subscriptions: Vec<usize>,
    /// Whether the graph guard condition triggered.
    pub guard_triggered: bool,
}

/// RAII wrapper around `HddsRmwContext`.
pub struct Context {
    ptr: NonNull<HddsRmwContext>,
}

impl Context {
    /// Create a new context.
    pub fn new(name: &str) -> Result<Self, Error> {
        let cname = CString::new(name)?;
        let ptr = unsafe { hdds_rmw_context_create(cname.as_ptr()) };
        let ptr = NonNull::new(ptr).ok_or(Error::NullPointer)?;
        Ok(Self { ptr })
    }

    /// Return the raw pointer (for FFI interop).
    pub fn as_ptr(&self) -> *mut HddsRmwContext {
        self.ptr.as_ptr()
    }

    /// Obtain a handle to the graph guard condition.
    pub fn graph_guard(&self) -> Result<GraphGuard, Error> {
        let raw = unsafe { hdds_rmw_context_graph_guard_condition(self.ptr.as_ptr()) };
        if raw.is_null() {
            return Err(Error::NullPointer);
        }
        Ok(GraphGuard { ptr: raw })
    }

    /// Graph guard key exposed by the context.
    pub fn graph_guard_key(&self) -> ConditionKey {
        unsafe { hdds_rmw_context_graph_guard_key(self.ptr.as_ptr()) }
    }

    /// Attach a reader to the context (status condition registration).
    ///
    /// # Safety
    ///
    /// `reader` must be a valid, non-null pointer to a live DataReader.
    pub unsafe fn attach_reader(&self, reader: *mut HddsDataReader) -> Result<u64, Error> {
        let mut key = 0u64;
        let err = unsafe { hdds_rmw_context_attach_reader(self.ptr.as_ptr(), reader, &mut key) };
        map_error(err).map(|_| key)
    }

    /// Detach a reader previously attached to the context.
    ///
    /// # Safety
    ///
    /// `reader` must be a valid, non-null pointer to a live DataReader.
    pub unsafe fn detach_reader(&self, reader: *mut HddsDataReader) -> Result<(), Error> {
        let err = unsafe { hdds_rmw_context_detach_reader(self.ptr.as_ptr(), reader) };
        map_error(err)
    }

    /// Create a waitset bound to this context.
    pub fn create_waitset(&self) -> Result<WaitSet, Error> {
        let ptr = unsafe { hdds_rmw_waitset_create(self.ptr.as_ptr()) };
        let ptr = NonNull::new(ptr).ok_or(Error::NullPointer)?;
        Ok(WaitSet { ptr })
    }

    /// Create an HDDS DataReader bound to this context.
    pub fn create_reader(&self, topic: &str) -> Result<*mut HddsDataReader, Error> {
        let ctopic = CString::new(topic)?;
        let mut reader = std::ptr::null_mut();
        let err = unsafe {
            hdds_rmw_context_create_reader(self.ptr.as_ptr(), ctopic.as_ptr(), &mut reader)
        };
        map_error(err)?;
        NonNull::new(reader)
            .map(|nn| nn.as_ptr())
            .ok_or(Error::NullPointer)
    }

    /// Create an HDDS DataReader bound to this context with the supplied QoS.
    ///
    /// # Safety
    ///
    /// `qos` must be a valid, non-null pointer to a live QoS structure.
    pub unsafe fn create_reader_with_qos(
        &self,
        topic: &str,
        qos: *const HddsQoS,
    ) -> Result<*mut HddsDataReader, Error> {
        if qos.is_null() {
            return Err(Error::InvalidArgument);
        }
        let ctopic = CString::new(topic)?;
        let mut reader = std::ptr::null_mut();
        let err = unsafe {
            hdds_rmw_context_create_reader_with_qos(
                self.ptr.as_ptr(),
                ctopic.as_ptr(),
                qos,
                &mut reader,
            )
        };
        map_error(err)?;
        NonNull::new(reader)
            .map(|nn| nn.as_ptr())
            .ok_or(Error::NullPointer)
    }

    /// Destroy a DataReader previously created via [`Context::create_reader`].
    ///
    /// # Safety
    ///
    /// `reader` must be a valid, non-null pointer to a live DataReader.
    pub unsafe fn destroy_reader(&self, reader: *mut HddsDataReader) -> Result<(), Error> {
        map_error(unsafe { hdds_rmw_context_destroy_reader(self.ptr.as_ptr(), reader) })
    }

    /// Register the ROS 2 type associated with a topic for discovery announcements.
    ///
    /// # Safety
    ///
    /// `type_support` must be a valid, non-null pointer to a live type support structure.
    pub unsafe fn bind_topic_type(
        &self,
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
    ) -> Result<(), Error> {
        if type_support.is_null() {
            return Err(Error::InvalidArgument);
        }

        let ctopic = CString::new(topic)?;
        let err = unsafe {
            hdds_rmw_context_bind_topic_type(self.ptr.as_ptr(), ctopic.as_ptr(), type_support)
        };
        map_error(err)
    }

    /// Create an HDDS DataWriter bound to this context.
    pub fn create_writer(&self, topic: &str) -> Result<*mut HddsDataWriter, Error> {
        let ctopic = CString::new(topic)?;
        let mut writer = std::ptr::null_mut();
        let err = unsafe {
            hdds_rmw_context_create_writer(self.ptr.as_ptr(), ctopic.as_ptr(), &mut writer)
        };
        map_error(err)?;
        NonNull::new(writer)
            .map(|nn| nn.as_ptr())
            .ok_or(Error::NullPointer)
    }

    /// Create an HDDS DataWriter bound to this context with the supplied QoS.
    ///
    /// # Safety
    ///
    /// `qos` must be a valid, non-null pointer to a live QoS structure.
    pub unsafe fn create_writer_with_qos(
        &self,
        topic: &str,
        qos: *const HddsQoS,
    ) -> Result<*mut HddsDataWriter, Error> {
        if qos.is_null() {
            return Err(Error::InvalidArgument);
        }
        let ctopic = CString::new(topic)?;
        let mut writer = std::ptr::null_mut();
        let err = unsafe {
            hdds_rmw_context_create_writer_with_qos(
                self.ptr.as_ptr(),
                ctopic.as_ptr(),
                qos,
                &mut writer,
            )
        };
        map_error(err)?;
        NonNull::new(writer)
            .map(|nn| nn.as_ptr())
            .ok_or(Error::NullPointer)
    }

    /// Destroy a DataWriter previously created via [`Context::create_writer`].
    ///
    /// # Safety
    ///
    /// `writer` must be a valid, non-null pointer to a live DataWriter.
    pub unsafe fn destroy_writer(&self, writer: *mut HddsDataWriter) -> Result<(), Error> {
        map_error(unsafe { hdds_rmw_context_destroy_writer(self.ptr.as_ptr(), writer) })
    }

    /// Publish a ROS message through the given writer.
    ///
    /// # Safety
    ///
    /// - `writer` must be a valid, non-null pointer to a live DataWriter
    /// - `type_support` must be a valid, non-null pointer to a live type support structure
    /// - `ros_message` must be a valid, non-null pointer to a live ROS message
    pub unsafe fn publish(
        &self,
        writer: *mut HddsDataWriter,
        type_support: *const rosidl_message_type_support_t,
        ros_message: *const c_void,
    ) -> Result<(), Error> {
        if writer.is_null() || type_support.is_null() || ros_message.is_null() {
            return Err(Error::InvalidArgument);
        }

        let err = unsafe {
            hdds_rmw_context_publish(self.ptr.as_ptr(), writer, type_support, ros_message)
        };
        map_error(err)
    }

    /// Register a ROS 2 node in the local graph cache.
    pub fn register_node(&self, name: &str, namespace_: &str, enclave: &str) -> Result<(), Error> {
        let cname = CString::new(name)?;
        let cnamespace = CString::new(namespace_)?;
        let cenclave = CString::new(enclave)?;
        map_error(unsafe {
            hdds_rmw_context_register_node(
                self.ptr.as_ptr(),
                cname.as_ptr(),
                cnamespace.as_ptr(),
                cenclave.as_ptr(),
            )
        })
    }

    /// Remove a ROS 2 node from the local graph cache.
    pub fn unregister_node(&self, name: &str, namespace_: &str) -> Result<(), Error> {
        let cname = CString::new(name)?;
        let cnamespace = CString::new(namespace_)?;
        map_error(unsafe {
            hdds_rmw_context_unregister_node(self.ptr.as_ptr(), cname.as_ptr(), cnamespace.as_ptr())
        })
    }

    /// Register a publisher endpoint in the graph cache.
    ///
    /// # Safety
    ///
    /// `type_support` must be a valid, non-null pointer to a live type support structure.
    pub unsafe fn register_publisher_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
        gid: &[u8],
        qos_profile: &HddsRmwQosProfile,
    ) -> Result<(), Error> {
        if type_support.is_null() {
            return Err(Error::InvalidArgument);
        }
        if gid.len() != hdds_c::HDDS_RMW_GID_SIZE {
            return Err(Error::InvalidArgument);
        }

        let cname = CString::new(name)?;
        let cnamespace = CString::new(namespace_)?;
        let ctopic = CString::new(topic)?;
        map_error(unsafe {
            hdds_rmw_context_register_publisher_endpoint(
                self.ptr.as_ptr(),
                cname.as_ptr(),
                cnamespace.as_ptr(),
                ctopic.as_ptr(),
                type_support,
                gid.as_ptr(),
                qos_profile as *const HddsRmwQosProfile,
            )
        })
    }

    /// Remove a publisher endpoint from the graph cache.
    pub fn unregister_publisher_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        gid: &[u8],
    ) -> Result<(), Error> {
        if gid.len() != hdds_c::HDDS_RMW_GID_SIZE {
            return Err(Error::InvalidArgument);
        }
        let cname = CString::new(name)?;
        let cnamespace = CString::new(namespace_)?;
        let ctopic = CString::new(topic)?;
        map_error(unsafe {
            hdds_rmw_context_unregister_publisher_endpoint(
                self.ptr.as_ptr(),
                cname.as_ptr(),
                cnamespace.as_ptr(),
                ctopic.as_ptr(),
                gid.as_ptr(),
            )
        })
    }

    /// Register a subscription endpoint in the graph cache.
    ///
    /// # Safety
    ///
    /// `type_support` must be a valid, non-null pointer to a live type support structure.
    pub unsafe fn register_subscription_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        type_support: *const rosidl_message_type_support_t,
        gid: &[u8],
        qos_profile: &HddsRmwQosProfile,
    ) -> Result<(), Error> {
        if type_support.is_null() {
            return Err(Error::InvalidArgument);
        }
        if gid.len() != hdds_c::HDDS_RMW_GID_SIZE {
            return Err(Error::InvalidArgument);
        }

        let cname = CString::new(name)?;
        let cnamespace = CString::new(namespace_)?;
        let ctopic = CString::new(topic)?;
        map_error(unsafe {
            hdds_rmw_context_register_subscription_endpoint(
                self.ptr.as_ptr(),
                cname.as_ptr(),
                cnamespace.as_ptr(),
                ctopic.as_ptr(),
                type_support,
                gid.as_ptr(),
                qos_profile as *const HddsRmwQosProfile,
            )
        })
    }

    /// Remove a subscription endpoint from the graph cache.
    pub fn unregister_subscription_endpoint(
        &self,
        name: &str,
        namespace_: &str,
        topic: &str,
        gid: &[u8],
    ) -> Result<(), Error> {
        if gid.len() != hdds_c::HDDS_RMW_GID_SIZE {
            return Err(Error::InvalidArgument);
        }
        let cname = CString::new(name)?;
        let cnamespace = CString::new(namespace_)?;
        let ctopic = CString::new(topic)?;
        map_error(unsafe {
            hdds_rmw_context_unregister_subscription_endpoint(
                self.ptr.as_ptr(),
                cname.as_ptr(),
                cnamespace.as_ptr(),
                ctopic.as_ptr(),
                gid.as_ptr(),
            )
        })
    }

    /// Wait using the context-level helper (returns guard + raw reader pointers).
    pub fn wait_readers(&self, timeout: Option<Duration>) -> Result<WaitOutcome, Error> {
        let mut readers: [*mut HddsDataReader; DEFAULT_MAX_READERS] =
            [std::ptr::null_mut(); DEFAULT_MAX_READERS];
        let mut len = 0usize;
        let mut guard_hit = false;
        let err = unsafe {
            hdds_rmw_context_wait_readers(
                self.ptr.as_ptr(),
                duration_to_ns(timeout),
                readers.as_mut_ptr(),
                readers.len(),
                &mut len,
                &mut guard_hit,
            )
        };
        map_error(err)?;
        let mut result = Vec::with_capacity(len);
        result.extend_from_slice(&readers[..len]);
        Ok(WaitOutcome {
            readers: result,
            guard_triggered: guard_hit,
        })
    }

    /// Wait for activity and map triggered readers to their subscription indexes.
    pub fn wait_indices(
        &self,
        subscriptions: &[*mut HddsDataReader],
        timeout: Option<Duration>,
    ) -> Result<(Vec<usize>, bool), Error> {
        let outcome = self.wait_readers(timeout)?;
        let indices =
            map_ready_indices(subscriptions, &outcome.readers).map_err(Error::from_hdds)?;
        Ok((indices, outcome.guard_triggered))
    }

    /// High-level helper mirroring the semantics of `rmw_wait`.
    pub fn wait_for(
        &self,
        args: WaitArgs<'_>,
        timeout: Option<Duration>,
    ) -> Result<WaitResult, Error> {
        let (indexes, guard) = self.wait_indices(args.subscriptions, timeout)?;
        Ok(WaitResult {
            ready_subscriptions: indexes,
            guard_triggered: guard,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { hdds_rmw_context_destroy(self.ptr.as_ptr()) };
    }
}

/// Borrowed handle to the graph guard condition.
pub struct GraphGuard {
    ptr: *const HddsGuardCondition,
}

impl GraphGuard {
    /// Set the guard trigger value.
    pub fn set_trigger(&self, active: bool) {
        unsafe { hdds_guard_condition_set_trigger(self.ptr, active) };
    }

    /// Access the raw pointer.
    pub fn as_ptr(&self) -> *const HddsGuardCondition {
        self.ptr
    }

    /// Construct a guard from a raw pointer (takes ownership).
    ///
    /// # Safety
    /// Caller must guarantee the pointer was obtained from `graph_guard()` and
    /// has not already been released.
    pub(crate) unsafe fn from_raw(ptr: *const HddsGuardCondition) -> Self {
        Self { ptr }
    }
}

impl Drop for GraphGuard {
    fn drop(&mut self) {
        unsafe { hdds_guard_condition_release(self.ptr) };
    }
}

/// Safe wrapper around the rmw waitset FFI.
pub struct WaitSet {
    ptr: NonNull<HddsRmwWaitSet>,
}

impl WaitSet {
    /// Attach a reader to the waitset.
    ///
    /// # Safety
    ///
    /// `reader` must be a valid, non-null pointer to a live DataReader.
    pub unsafe fn attach_reader(&self, reader: *mut HddsDataReader) -> Result<(), Error> {
        let err = unsafe { hdds_rmw_waitset_attach_reader(self.ptr.as_ptr(), reader) };
        map_error(err)
    }

    /// Detach a reader from the waitset.
    ///
    /// # Safety
    ///
    /// `reader` must be a valid, non-null pointer to a live DataReader.
    pub unsafe fn detach_reader(&self, reader: *mut HddsDataReader) -> Result<(), Error> {
        let err = unsafe { hdds_rmw_waitset_detach_reader(self.ptr.as_ptr(), reader) };
        map_error(err)
    }

    /// Wait for readers/guard activity.
    pub fn wait(&self, timeout: Option<Duration>) -> Result<WaitOutcome, Error> {
        let mut readers: [*mut HddsDataReader; DEFAULT_MAX_READERS] =
            [std::ptr::null_mut(); DEFAULT_MAX_READERS];
        let mut len = 0usize;
        let mut guard_hit = false;
        let err = unsafe {
            hdds_rmw_waitset_wait(
                self.ptr.as_ptr(),
                duration_to_ns(timeout),
                readers.as_mut_ptr(),
                readers.len(),
                &mut len,
                &mut guard_hit,
            )
        };
        map_error(err)?;
        let mut result = Vec::with_capacity(len);
        result.extend_from_slice(&readers[..len]);
        Ok(WaitOutcome {
            readers: result,
            guard_triggered: guard_hit,
        })
    }

    /// Wait for activity and return the subscription indexes that triggered.
    pub fn wait_indices(
        &self,
        subscriptions: &[*mut HddsDataReader],
        timeout: Option<Duration>,
    ) -> Result<(Vec<usize>, bool), Error> {
        let outcome = self.wait(timeout)?;
        let indices =
            map_ready_indices(subscriptions, &outcome.readers).map_err(Error::from_hdds)?;
        Ok((indices, outcome.guard_triggered))
    }

    /// High-level helper mirroring the semantics of `rmw_wait`.
    pub fn wait_for(
        &self,
        args: WaitArgs<'_>,
        timeout: Option<Duration>,
    ) -> Result<WaitResult, Error> {
        let (indexes, guard) = self.wait_indices(args.subscriptions, timeout)?;
        Ok(WaitResult {
            ready_subscriptions: indexes,
            guard_triggered: guard,
        })
    }
}

impl Drop for WaitSet {
    fn drop(&mut self) {
        unsafe { hdds_rmw_waitset_destroy(self.ptr.as_ptr()) };
    }
}

/// High level helper mirroring ROS 2 `rmw_wait` semantics.
pub fn rmw_wait(
    waitset: &WaitSet,
    args: WaitArgs<'_>,
    timeout: Option<Duration>,
) -> Result<WaitResult, Error> {
    waitset.wait_for(args, timeout)
}

/// Result returned by [`WaitSet::wait`].
#[derive(Debug)]
pub struct WaitOutcome {
    /// Reader pointers that triggered.
    pub readers: Vec<*mut HddsDataReader>,
    /// Whether the participant graph guard triggered.
    pub guard_triggered: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_wait_for_reports_guard() {
        unsafe {
            let ctx = Context::new("rmw_wait_indices_ctx").expect("context");
            let reader = ctx.create_reader("rmw_wait_indices_topic").expect("reader");
            ctx.attach_reader(reader).expect("attach reader");

            let guard = ctx.graph_guard().expect("guard");
            guard.set_trigger(true);
            drop(guard);

            let result = ctx
                .wait_for(WaitArgs::new(&[reader]), Some(Duration::from_millis(1)))
                .expect("wait");

            assert!(result.ready_subscriptions.is_empty());
            assert!(result.guard_triggered);

            ctx.detach_reader(reader).expect("detach reader");
            ctx.destroy_reader(reader).expect("destroy reader");
        }
    }

    #[test]
    fn graph_guard_wait_reports_trigger() {
        let ctx = Context::new("rmw_wait_guard").expect("context");
        let guard = ctx.graph_guard().expect("guard");
        guard.set_trigger(true);

        let outcome = ctx
            .wait_readers(Some(Duration::from_millis(1)))
            .expect("wait");
        assert!(outcome.guard_triggered, "graph guard should have triggered");
        assert!(outcome.readers.is_empty());
        // guard released on drop
    }

    #[test]
    fn waitset_attach_and_wait() {
        unsafe {
            let ctx = Context::new("rmw_waitset_ctx").expect("context");
            let reader = ctx.create_reader("waitset_topic").expect("reader");
            let waitset = ctx.create_waitset().expect("waitset");

            waitset.attach_reader(reader).expect("attach");

            // Guard wakeup should propagate through waitset wait as guard triggered flag
            let guard_handle = ctx.graph_guard().expect("guard");
            guard_handle.set_trigger(true);

            let outcome = waitset.wait(Some(Duration::from_millis(1))).expect("wait");
            assert!(outcome.guard_triggered);

            let wait_result = waitset
                .wait_for(WaitArgs::new(&[reader]), Some(Duration::from_millis(1)))
                .expect("wait_for");
            assert!(wait_result.ready_subscriptions.is_empty());
            assert!(wait_result.guard_triggered);

            waitset.detach_reader(reader).expect("detach");
            drop(waitset);
            drop(guard_handle);

            ctx.destroy_reader(reader).expect("destroy reader");
        }
    }

    #[test]
    fn register_and_unregister_node_via_context() {
        let ctx = Context::new("rmw_register_node_ctx").expect("context");
        ctx.register_node("demo_node", "/demo_ns", "")
            .expect("register node");
        ctx.unregister_node("demo_node", "/demo_ns")
            .expect("unregister node");
    }

    #[test]
    fn create_context_logs_error() {
        std::env::set_var("HDDS_EXPORTER_DISABLE", "1");
        std::env::set_var("RCUTILS_LOGGING_USE_STDOUT", "1");
        std::env::set_var("ROS_LOG_DIR", "/tmp");

        match Context::new("test_ctx_for_unit") {
            Ok(_) => println!("context created OK"),
            Err(err) => println!("context create failed: {:?}", err),
        }
    }

    #[test]
    fn create_context_without_exporter_disable() {
        std::env::remove_var("HDDS_EXPORTER_DISABLE");
        std::env::set_var("RCUTILS_LOGGING_USE_STDOUT", "1");
        std::env::set_var("ROS_LOG_DIR", "/tmp");

        match Context::new("test_ctx_for_unit_no_disable") {
            Ok(_) => println!("context created OK"),
            Err(err) => println!("context create failed: {:?}", err),
        }
    }
}
