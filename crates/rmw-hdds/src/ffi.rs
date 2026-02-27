// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::env_config::EnvConfig;
use crate::util::map_ready_indices;
use crate::GraphGuard;
use crate::{Context, Error, WaitArgs, WaitSet};
use hdds::xtypes::builder::rosidl_message_type_support_t;
use hdds_c::{
    hdds_rmw_context_for_each_user_locator, hdds_rmw_context_guid_prefix, HddsDataReader,
    HddsDataWriter, HddsError, HddsGuardCondition, HddsQoS, HddsRmwQosProfile,
};
use libc::c_char;
use std::ffi::CStr;
use std::mem::ManuallyDrop;
use std::os::raw::c_void;
use std::sync::Once;
use std::time::Duration;

/// One-time initialization of environment configuration
static ENV_CONFIG_INIT: Once = Once::new();

/// Initialize environment configuration (called once per process)
fn init_env_config() {
    ENV_CONFIG_INIT.call_once(|| {
        let config = EnvConfig::from_env();

        // Apply log level if not already set
        config.apply_log_level();

        // Log configuration if custom
        if config.is_custom() {
            eprintln!(
                "[rmw_hdds] Environment config: domain_id={}, interface={:?}, log_level={}",
                config.domain_id, config.interface, config.log_level
            );
            if let Some(ref path) = config.qos_profile_path {
                eprintln!("[rmw_hdds] QoS profile path: {}", path);
            }
        }
    });
}

#[repr(C)]
pub struct rmw_hdds_context_t {
    ctx: Context,
}

#[repr(C)]
pub struct rmw_hdds_waitset_t {
    waitset: WaitSet,
}

#[allow(non_camel_case_types)]
pub type rmw_hdds_topic_visitor_t =
    unsafe extern "C" fn(*const c_char, *const c_char, u32, u32, *mut c_void);
#[allow(non_camel_case_types)]
pub type rmw_hdds_node_visitor_t = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void);
#[allow(non_camel_case_types)]
pub type rmw_hdds_node_enclave_visitor_t =
    unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void);
#[allow(non_camel_case_types)]
pub type rmw_hdds_endpoint_visitor_t = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const u8,
    *const HddsRmwQosProfile,
    *mut c_void,
);
#[allow(non_camel_case_types)]
pub type rmw_hdds_locator_visitor_t = unsafe extern "C" fn(*const c_char, u16, *mut c_void);

fn timeout_from_ns(timeout_ns: i64) -> Option<Duration> {
    if timeout_ns < 0 {
        None
    } else {
        u64::try_from(timeout_ns).ok().map(Duration::from_nanos)
    }
}

fn err_from(error: Error) -> HddsError {
    match error {
        Error::NullPointer => HddsError::HddsOperationFailed,
        Error::InvalidArgument | Error::FfiString(_) => HddsError::HddsInvalidArgument,
        Error::NotFound => HddsError::HddsNotFound,
        Error::OperationFailed => HddsError::HddsOperationFailed,
        Error::OutOfMemory => HddsError::HddsOutOfMemory,
    }
}

/// Creates a new RMW HDDS context.
///
/// Reads configuration from environment variables on first call:
/// - `HDDS_DOMAIN_ID`: DDS domain ID (default: 0, or ROS_DOMAIN_ID if set)
/// - `HDDS_INTERFACE`: Network interface for multicast
/// - `HDDS_LOG_LEVEL`: Logging level (default: "info")
/// - `HDDS_QOS_PROFILE_PATH`: Path to QoS profile file
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `name` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `out_context` is a valid, non-null pointer for writing the resulting context pointer
/// - No data races occur on the memory pointed to by `out_context`
/// - The returned context must be destroyed with `rmw_hdds_context_destroy`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_create(
    name: *const c_char,
    out_context: *mut *mut rmw_hdds_context_t,
) -> HddsError {
    // Initialize environment configuration once per process
    init_env_config();

    if name.is_null() || out_context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    match Context::new(name_str) {
        Ok(ctx) => {
            let boxed = Box::new(rmw_hdds_context_t { ctx });
            out_context.write(Box::into_raw(boxed));
            HddsError::HddsOk
        }
        Err(err) => {
            eprintln!("[rmw_hdds] Context::new({}) failed: {}", name_str, err);
            err_from(err)
        }
    }
}

/// Destroys an RMW HDDS context and releases all associated resources.
///
/// # Safety
///
/// This function is unsafe because it dereferences and frees a raw pointer. Callers must ensure:
/// - `context` was previously created by `rmw_hdds_context_create`
/// - `context` is not used after this call (no use-after-free)
/// - `context` is not destroyed multiple times (no double-free)
/// - No other threads are accessing the context concurrently
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_destroy(context: *mut rmw_hdds_context_t) {
    if !context.is_null() {
        let _ = Box::from_raw(context);
    }
}

/// Copy the participant GUID prefix (12 bytes) into `out_prefix`.
///
/// This provides a stable, cross-process identifier for the participant.
/// Combined with an entity-specific suffix, it forms a proper DDS GUID
/// suitable for use in `rmw_gid_t`.
///
/// # Safety
///
/// - `context` must be a valid, non-null pointer to a live context
/// - `out_prefix` must point to a buffer of at least 12 bytes
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_guid_prefix(
    context: *mut rmw_hdds_context_t,
    out_prefix: *mut u8,
) -> HddsError {
    if context.is_null() || out_prefix.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let ctx = &(*context).ctx;
    hdds_rmw_context_guid_prefix(ctx.as_ptr(), out_prefix)
}

/// Retrieves the graph guard condition key for a context.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `out_key` is a valid, non-null pointer for writing the key value
/// - No data races occur on the memory pointed to by `out_key`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_graph_guard_key(
    context: *mut rmw_hdds_context_t,
    out_key: *mut u64,
) -> HddsError {
    if context.is_null() || out_key.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    out_key.write((*context).ctx.graph_guard_key());
    HddsError::HddsOk
}

/// Sets the graph guard condition active state for a context.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - No other threads are modifying the context graph guard concurrently
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_set_guard(
    context: *mut rmw_hdds_context_t,
    active: bool,
) -> HddsError {
    if context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.graph_guard() {
        Ok(guard) => {
            guard.set_trigger(active);
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Retrieves the graph guard condition handle for a context.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `out_guard` is a valid, non-null pointer for writing the guard pointer
/// - The returned guard pointer must be released with `rmw_hdds_guard_condition_release`
/// - No data races occur on the memory pointed to by `out_guard`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_graph_guard_condition(
    context: *mut rmw_hdds_context_t,
    out_guard: *mut *const HddsGuardCondition,
) -> HddsError {
    if context.is_null() || out_guard.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.graph_guard() {
        Ok(guard) => {
            let guard = ManuallyDrop::new(guard);
            out_guard.write(guard.as_ptr());
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Waits for data to be available on attached readers or for the graph guard to trigger.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `out_readers` is a valid pointer to an array of at least `max_readers` elements
/// - `out_len` is a valid, non-null pointer for writing the result count
/// - `out_guard_triggered` (if not null) is a valid pointer for writing the guard state
/// - No data races occur on the output memory regions
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_wait_readers(
    context: *mut rmw_hdds_context_t,
    timeout_ns: i64,
    out_readers: *mut *mut HddsDataReader,
    max_readers: usize,
    out_len: *mut usize,
    out_guard_triggered: *mut bool,
) -> HddsError {
    if context.is_null() || out_readers.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(false);
    }

    out_len.write(0);

    let timeout = timeout_from_ns(timeout_ns);

    let outcome = match (*context).ctx.wait_readers(timeout) {
        Ok(o) => o,
        Err(err) => return err_from(err),
    };

    if outcome.readers.len() > max_readers {
        return HddsError::HddsOperationFailed;
    }

    for (idx, reader) in outcome.readers.iter().enumerate() {
        out_readers.add(idx).write(*reader);
    }

    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(outcome.guard_triggered);
    }

    out_len.write(outcome.readers.len());
    HddsError::HddsOk
}

/// Creates a new data reader for a topic.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `topic` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `out_reader` is a valid, non-null pointer for writing the resulting reader pointer
/// - No data races occur on the memory pointed to by `out_reader`
/// - The returned reader must be destroyed with `rmw_hdds_context_destroy_reader`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_create_reader(
    context: *mut rmw_hdds_context_t,
    topic: *const c_char,
    out_reader: *mut *mut HddsDataReader,
) -> HddsError {
    if context.is_null() || topic.is_null() || out_reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    match (*context).ctx.create_reader(topic_str) {
        Ok(ptr) => {
            out_reader.write(ptr);
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Creates a new data reader with an explicit QoS.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `topic` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `qos` is a valid, non-null pointer to a live QoS object
/// - `out_reader` is a valid, non-null pointer for writing the resulting reader pointer
/// - No data races occur on the memory pointed to by `out_reader`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_create_reader_with_qos(
    context: *mut rmw_hdds_context_t,
    topic: *const c_char,
    qos: *const HddsQoS,
    out_reader: *mut *mut HddsDataReader,
) -> HddsError {
    if context.is_null() || topic.is_null() || qos.is_null() || out_reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    match (*context).ctx.create_reader_with_qos(topic_str, qos) {
        Ok(ptr) => {
            out_reader.write(ptr);
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Destroys a data reader and releases associated resources.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `reader` was previously created by `rmw_hdds_context_create_reader`
/// - `reader` is not used after this call (no use-after-free)
/// - `reader` is not destroyed multiple times (no double-free)
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_destroy_reader(
    context: *mut rmw_hdds_context_t,
    reader: *mut HddsDataReader,
) -> HddsError {
    if context.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.destroy_reader(reader) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Attaches a reader to the context waitset and returns its key.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `reader` is a valid, non-null pointer to a live reader
/// - `out_key` is a valid, non-null pointer for writing the key value
/// - No data races occur on the memory pointed to by `out_key`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_attach_reader(
    context: *mut rmw_hdds_context_t,
    reader: *mut HddsDataReader,
    out_key: *mut u64,
) -> HddsError {
    if context.is_null() || reader.is_null() || out_key.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.attach_reader(reader) {
        Ok(key) => {
            out_key.write(key);
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Detaches a reader from the context waitset.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `reader` is a valid, non-null pointer to a live reader previously attached
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_detach_reader(
    context: *mut rmw_hdds_context_t,
    reader: *mut HddsDataReader,
) -> HddsError {
    if context.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.detach_reader(reader) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Creates a new data writer for a topic.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `topic` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `out_writer` is a valid, non-null pointer for writing the resulting writer pointer
/// - No data races occur on the memory pointed to by `out_writer`
/// - The returned writer must be destroyed with `rmw_hdds_context_destroy_writer`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_create_writer(
    context: *mut rmw_hdds_context_t,
    topic: *const c_char,
    out_writer: *mut *mut HddsDataWriter,
) -> HddsError {
    if context.is_null() || topic.is_null() || out_writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    match (*context).ctx.create_writer(topic_str) {
        Ok(ptr) => {
            out_writer.write(ptr);
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Creates a new data writer with an explicit QoS.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `topic` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `qos` is a valid, non-null pointer to a live QoS object
/// - `out_writer` is a valid, non-null pointer for writing the resulting writer pointer
/// - No data races occur on the memory pointed to by `out_writer`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_create_writer_with_qos(
    context: *mut rmw_hdds_context_t,
    topic: *const c_char,
    qos: *const HddsQoS,
    out_writer: *mut *mut HddsDataWriter,
) -> HddsError {
    if context.is_null() || topic.is_null() || qos.is_null() || out_writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    match (*context).ctx.create_writer_with_qos(topic_str, qos) {
        Ok(ptr) => {
            out_writer.write(ptr);
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Destroys a data writer and releases associated resources.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `writer` was previously created by `rmw_hdds_context_create_writer`
/// - `writer` is not used after this call (no use-after-free)
/// - `writer` is not destroyed multiple times (no double-free)
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_destroy_writer(
    context: *mut rmw_hdds_context_t,
    writer: *mut HddsDataWriter,
) -> HddsError {
    if context.is_null() || writer.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.destroy_writer(writer) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Binds type support information to a topic.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `topic` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `type_support` is a valid, non-null pointer to type support data
/// - The lifetime of `type_support` extends for the duration of the context
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_bind_topic_type(
    context: *mut rmw_hdds_context_t,
    topic: *const c_char,
    type_support: *const rosidl_message_type_support_t,
) -> HddsError {
    if context.is_null() || topic.is_null() || type_support.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let topic_str = match CStr::from_ptr(topic).to_str() {
        Ok(s) => s,
        Err(_) => return HddsError::HddsInvalidArgument,
    };

    match (*context).ctx.bind_topic_type(topic_str, type_support) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => {
            eprintln!(
                "[rmw_hdds] bind_topic_type failed for topic {topic_str}: {:?}",
                err
            );
            err_from(err)
        }
    }
}

/// Registers a node with the context graph.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `node_namespace` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_register_node(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
    node_enclave: *const c_char,
) -> HddsError {
    if context.is_null() || node_name.is_null() || node_namespace.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let enclave = if node_enclave.is_null() {
        ""
    } else {
        match CStr::from_ptr(node_enclave).to_str() {
            Ok(value) => value,
            Err(_) => return HddsError::HddsInvalidArgument,
        }
    };

    match (*context).ctx.register_node(name, namespace_, enclave) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Unregisters a node from the context graph.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - `node_namespace` is a valid, non-null pointer to a null-terminated C string with valid UTF-8
/// - The node was previously registered with `rmw_hdds_context_register_node`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_unregister_node(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
) -> HddsError {
    if context.is_null() || node_name.is_null() || node_namespace.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    match (*context).ctx.unregister_node(name, namespace_) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Registers a publisher endpoint in the context graph.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name`, `node_namespace`, `topic_name` are valid, non-null pointers to null-terminated C strings with valid UTF-8
/// - `type_support` is a valid, non-null pointer to type support data
/// - The lifetime of `type_support` extends for the duration of the endpoint registration
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_register_publisher_endpoint(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    type_support: *const rosidl_message_type_support_t,
    endpoint_gid: *const u8,
    qos_profile: *const HddsRmwQosProfile,
) -> HddsError {
    if context.is_null()
        || node_name.is_null()
        || node_namespace.is_null()
        || topic_name.is_null()
        || type_support.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(topic) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let default_gid = [0u8; hdds_c::HDDS_RMW_GID_SIZE];
    let gid = if endpoint_gid.is_null() {
        &default_gid
    } else {
        std::slice::from_raw_parts(endpoint_gid, hdds_c::HDDS_RMW_GID_SIZE)
    };

    let default_qos = HddsRmwQosProfile::default();
    let qos = if qos_profile.is_null() {
        &default_qos
    } else {
        &*qos_profile
    };

    match (*context).ctx.register_publisher_endpoint(
        name,
        namespace_,
        topic,
        type_support,
        gid,
        qos,
    ) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Unregisters a publisher endpoint from the context graph.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name`, `node_namespace`, `topic_name` are valid, non-null pointers to null-terminated C strings with valid UTF-8
/// - The endpoint was previously registered with `rmw_hdds_context_register_publisher_endpoint`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_unregister_publisher_endpoint(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    endpoint_gid: *const u8,
) -> HddsError {
    if context.is_null() || node_name.is_null() || node_namespace.is_null() || topic_name.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(topic) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let default_gid = [0u8; hdds_c::HDDS_RMW_GID_SIZE];
    let gid = if endpoint_gid.is_null() {
        &default_gid
    } else {
        std::slice::from_raw_parts(endpoint_gid, hdds_c::HDDS_RMW_GID_SIZE)
    };

    match (*context)
        .ctx
        .unregister_publisher_endpoint(name, namespace_, topic, gid)
    {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Registers a subscription endpoint in the context graph.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name`, `node_namespace`, `topic_name` are valid, non-null pointers to null-terminated C strings with valid UTF-8
/// - `type_support` is a valid, non-null pointer to type support data
/// - The lifetime of `type_support` extends for the duration of the endpoint registration
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_register_subscription_endpoint(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    type_support: *const rosidl_message_type_support_t,
    endpoint_gid: *const u8,
    qos_profile: *const HddsRmwQosProfile,
) -> HddsError {
    if context.is_null()
        || node_name.is_null()
        || node_namespace.is_null()
        || topic_name.is_null()
        || type_support.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(topic) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let default_gid = [0u8; hdds_c::HDDS_RMW_GID_SIZE];
    let gid = if endpoint_gid.is_null() {
        &default_gid
    } else {
        std::slice::from_raw_parts(endpoint_gid, hdds_c::HDDS_RMW_GID_SIZE)
    };

    let default_qos = HddsRmwQosProfile::default();
    let qos = if qos_profile.is_null() {
        &default_qos
    } else {
        &*qos_profile
    };

    match (*context).ctx.register_subscription_endpoint(
        name,
        namespace_,
        topic,
        type_support,
        gid,
        qos,
    ) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Unregisters a subscription endpoint from the context graph.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name`, `node_namespace`, `topic_name` are valid, non-null pointers to null-terminated C strings with valid UTF-8
/// - The endpoint was previously registered with `rmw_hdds_context_register_subscription_endpoint`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_unregister_subscription_endpoint(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
    topic_name: *const c_char,
    endpoint_gid: *const u8,
) -> HddsError {
    if context.is_null() || node_name.is_null() || node_namespace.is_null() || topic_name.is_null()
    {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(name) = CStr::from_ptr(node_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(namespace_) = CStr::from_ptr(node_namespace).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(topic) = CStr::from_ptr(topic_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    let default_gid = [0u8; hdds_c::HDDS_RMW_GID_SIZE];
    let gid = if endpoint_gid.is_null() {
        &default_gid
    } else {
        std::slice::from_raw_parts(endpoint_gid, hdds_c::HDDS_RMW_GID_SIZE)
    };

    match (*context)
        .ctx
        .unregister_subscription_endpoint(name, namespace_, topic, gid)
    {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Iterates over all topics in the context graph using a visitor callback.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `visitor` (if not None) is a valid function pointer that remains valid for the call duration
/// - `user_data` (if not null) is a valid pointer passed to the visitor
/// - `out_version` (if not null) is a valid pointer for writing the graph version
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_for_each_topic(
    context: *mut rmw_hdds_context_t,
    visitor: Option<rmw_hdds_topic_visitor_t>,
    user_data: *mut c_void,
    out_version: *mut u64,
) -> HddsError {
    if context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    hdds_c::hdds_rmw_context_for_each_topic(
        (*context).ctx.as_ptr(),
        visitor.map(|cb| cb as hdds_c::HddsTopicVisitor),
        user_data,
        out_version,
    )
}

/// Iterates over user unicast locators via a visitor callback.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `visitor` (if not None) is a valid function pointer that remains valid for the call duration
/// - `user_data` (if not null) is a valid pointer passed to the visitor
/// - `out_count` (if not null) is a valid pointer for writing the locator count
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_for_each_user_locator(
    context: *mut rmw_hdds_context_t,
    visitor: Option<rmw_hdds_locator_visitor_t>,
    user_data: *mut c_void,
    out_count: *mut usize,
) -> HddsError {
    if context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    hdds_rmw_context_for_each_user_locator(
        (*context).ctx.as_ptr(),
        visitor.map(|cb| cb as hdds_c::HddsLocatorVisitor),
        user_data,
        out_count,
    )
}

/// Iterates over all nodes in the context graph using a visitor callback.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `visitor` (if not None) is a valid function pointer that remains valid for the call duration
/// - `user_data` (if not null) is a valid pointer passed to the visitor
/// - `out_version` (if not null) is a valid pointer for writing the graph version
/// - `out_count` (if not null) is a valid pointer for writing the node count
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_for_each_node(
    context: *mut rmw_hdds_context_t,
    visitor: Option<rmw_hdds_node_visitor_t>,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    hdds_c::hdds_rmw_context_for_each_node(
        (*context).ctx.as_ptr(),
        visitor,
        user_data,
        out_version,
        out_count,
    )
}

/// Iterates over nodes (name/namespace/enclave) using a visitor callback.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `visitor` (if not None) is a valid function pointer that remains valid for the call duration
/// - `user_data` (if not null) is a valid pointer passed to the visitor
/// - `out_version` (if not null) is a valid pointer for writing the graph version
/// - `out_count` (if not null) is a valid pointer for writing the node count
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_for_each_node_with_enclave(
    context: *mut rmw_hdds_context_t,
    visitor: Option<rmw_hdds_node_enclave_visitor_t>,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    hdds_c::hdds_rmw_context_for_each_node_with_enclave(
        (*context).ctx.as_ptr(),
        visitor,
        user_data,
        out_version,
        out_count,
    )
}

/// Iterates over publisher endpoints for a node using a visitor callback.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name`, `node_namespace` are valid, non-null pointers to null-terminated C strings
/// - `visitor` (if not None) is a valid function pointer that remains valid for the call duration
/// - `user_data` (if not null) is a valid pointer passed to the visitor
/// - `out_version` (if not null) is a valid pointer for writing the graph version
/// - `out_count` (if not null) is a valid pointer for writing the endpoint count
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_for_each_publisher_endpoint(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
    visitor: Option<rmw_hdds_endpoint_visitor_t>,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    hdds_c::hdds_rmw_context_for_each_publisher_endpoint(
        (*context).ctx.as_ptr(),
        node_name,
        node_namespace,
        visitor,
        user_data,
        out_version,
        out_count,
    )
}

/// Iterates over subscription endpoints for a node using a visitor callback.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `node_name`, `node_namespace` are valid, non-null pointers to null-terminated C strings
/// - `visitor` (if not None) is a valid function pointer that remains valid for the call duration
/// - `user_data` (if not null) is a valid pointer passed to the visitor
/// - `out_version` (if not null) is a valid pointer for writing the graph version
/// - `out_count` (if not null) is a valid pointer for writing the endpoint count
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_for_each_subscription_endpoint(
    context: *mut rmw_hdds_context_t,
    node_name: *const c_char,
    node_namespace: *const c_char,
    visitor: Option<rmw_hdds_endpoint_visitor_t>,
    user_data: *mut c_void,
    out_version: *mut u64,
    out_count: *mut usize,
) -> HddsError {
    if context.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    hdds_c::hdds_rmw_context_for_each_subscription_endpoint(
        (*context).ctx.as_ptr(),
        node_name,
        node_namespace,
        visitor,
        user_data,
        out_version,
        out_count,
    )
}

/// Publishes a message using the specified writer.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `writer` is a valid, non-null pointer to a live writer
/// - `type_support` is a valid, non-null pointer to type support matching the message type
/// - `ros_message` is a valid, non-null pointer to a properly initialized ROS message
/// - No data races occur on the message data during serialization
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_publish(
    context: *mut rmw_hdds_context_t,
    writer: *mut HddsDataWriter,
    type_support: *const rosidl_message_type_support_t,
    ros_message: *const c_void,
) -> HddsError {
    if context.is_null() || writer.is_null() || type_support.is_null() || ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.publish(writer, type_support, ros_message) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Publishes a message using the specified writer and codec.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `writer` is a valid, non-null pointer to a live writer
/// - `ros_message` is a valid, non-null pointer to a properly initialized ROS message
/// - `codec_kind` specifies a valid codec supported by the writer
/// - No data races occur on the message data during serialization
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_publish_with_codec(
    context: *mut rmw_hdds_context_t,
    writer: *mut HddsDataWriter,
    codec_kind: u8,
    ros_message: *const c_void,
) -> HddsError {
    if context.is_null() || writer.is_null() || ros_message.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    hdds_c::hdds_rmw_context_publish_with_codec(
        (*context).ctx.as_ptr(),
        writer,
        codec_kind,
        ros_message,
    )
}

/// Waits for data on specified subscriptions or for the graph guard to trigger.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `subscriptions` (if subscriptions_len > 0) is a valid pointer to an array of `subscriptions_len` reader pointers
/// - `out_indexes` is a valid pointer to an array of at least `max_indexes` elements
/// - `out_len` is a valid, non-null pointer for writing the result count
/// - `out_guard_triggered` (if not null) is a valid pointer for writing the guard state
/// - All pointers in the subscriptions array point to live readers
/// - No data races occur on the output memory regions
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_context_wait_subscriptions(
    context: *mut rmw_hdds_context_t,
    timeout_ns: i64,
    subscriptions: *const *mut HddsDataReader,
    subscriptions_len: usize,
    out_indexes: *mut usize,
    max_indexes: usize,
    out_len: *mut usize,
    out_guard_triggered: *mut bool,
) -> HddsError {
    if context.is_null() || out_indexes.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    if subscriptions_len > 0 && subscriptions.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(false);
    }

    out_len.write(0);

    let subs_slice = if subscriptions_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(subscriptions, subscriptions_len)
    };

    let timeout = timeout_from_ns(timeout_ns);
    let result = match (*context).ctx.wait_for(WaitArgs::new(subs_slice), timeout) {
        Ok(res) => res,
        Err(err) => return err_from(err),
    };

    if result.ready_subscriptions.len() > max_indexes {
        return HddsError::HddsOperationFailed;
    }

    for (idx, value) in result.ready_subscriptions.iter().enumerate() {
        out_indexes.add(idx).write(*value);
    }

    out_len.write(result.ready_subscriptions.len());
    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(result.guard_triggered);
    }

    HddsError::HddsOk
}

/// Creates a new waitset associated with a context.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `context` is a valid, non-null pointer to a live context
/// - `out_waitset` is a valid, non-null pointer for writing the resulting waitset pointer
/// - No data races occur on the memory pointed to by `out_waitset`
/// - The returned waitset must be destroyed with `rmw_hdds_waitset_destroy`
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_waitset_create(
    context: *mut rmw_hdds_context_t,
    out_waitset: *mut *mut rmw_hdds_waitset_t,
) -> HddsError {
    if context.is_null() || out_waitset.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*context).ctx.create_waitset() {
        Ok(waitset) => {
            let boxed = Box::new(rmw_hdds_waitset_t { waitset });
            out_waitset.write(Box::into_raw(boxed));
            HddsError::HddsOk
        }
        Err(err) => err_from(err),
    }
}

/// Destroys a waitset and releases associated resources.
///
/// # Safety
///
/// This function is unsafe because it dereferences and frees a raw pointer. Callers must ensure:
/// - `waitset` was previously created by `rmw_hdds_waitset_create`
/// - `waitset` is not used after this call (no use-after-free)
/// - `waitset` is not destroyed multiple times (no double-free)
/// - No other threads are accessing the waitset concurrently
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_waitset_destroy(waitset: *mut rmw_hdds_waitset_t) {
    if !waitset.is_null() {
        let _ = Box::from_raw(waitset);
    }
}

/// Attaches a reader to a waitset.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `waitset` is a valid, non-null pointer to a live waitset
/// - `reader` is a valid, non-null pointer to a live reader
/// - The reader remains valid while attached to the waitset
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_waitset_attach_reader(
    waitset: *mut rmw_hdds_waitset_t,
    reader: *mut HddsDataReader,
) -> HddsError {
    if waitset.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*waitset).waitset.attach_reader(reader) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Detaches a reader from a waitset.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `waitset` is a valid, non-null pointer to a live waitset
/// - `reader` is a valid, non-null pointer to a live reader previously attached
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_waitset_detach_reader(
    waitset: *mut rmw_hdds_waitset_t,
    reader: *mut HddsDataReader,
) -> HddsError {
    if waitset.is_null() || reader.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    match (*waitset).waitset.detach_reader(reader) {
        Ok(()) => HddsError::HddsOk,
        Err(err) => err_from(err),
    }
}

/// Waits for data on attached readers or for the graph guard to trigger.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `waitset` is a valid, non-null pointer to a live waitset
/// - `out_readers` is a valid pointer to an array of at least `max_readers` elements
/// - `out_len` is a valid, non-null pointer for writing the result count
/// - `out_guard_triggered` (if not null) is a valid pointer for writing the guard state
/// - No data races occur on the output memory regions
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_waitset_wait(
    waitset: *mut rmw_hdds_waitset_t,
    timeout_ns: i64,
    out_readers: *mut *mut HddsDataReader,
    max_readers: usize,
    out_len: *mut usize,
    out_guard_triggered: *mut bool,
) -> HddsError {
    // Allow out_readers to be NULL when max_readers is 0 (no subscriptions case)
    if waitset.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    if out_readers.is_null() && max_readers > 0 {
        return HddsError::HddsInvalidArgument;
    }

    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(false);
    }

    out_len.write(0);

    let timeout = timeout_from_ns(timeout_ns);

    let outcome = match (*waitset).waitset.wait(timeout) {
        Ok(o) => o,
        Err(err) => return err_from(err),
    };

    if outcome.readers.len() > max_readers {
        return HddsError::HddsOperationFailed;
    }

    for (idx, reader) in outcome.readers.iter().enumerate() {
        out_readers.add(idx).write(*reader);
    }

    out_len.write(outcome.readers.len());

    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(outcome.guard_triggered);
    }

    HddsError::HddsOk
}

/// Wait on an rmw waitset and populate the ready subscription indexes.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `waitset` is a valid, non-null pointer to a live waitset
/// - `subscriptions` (if `subscriptions_len > 0`) is a valid pointer to an array of at least `subscriptions_len` reader pointers
/// - `out_indices` is a valid pointer to an array of at least `max_indices` elements
/// - `out_len` is a valid, non-null pointer for writing the result count
/// - `out_guard_triggered` (if not null) is a valid pointer for writing the guard state
/// - No data races occur on the output memory regions
/// - The waitset and reader pointers remain valid for the duration of the call
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_waitset_wait_indices(
    waitset: *mut rmw_hdds_waitset_t,
    subscriptions: *const *mut HddsDataReader,
    subscriptions_len: usize,
    out_indices: *mut usize,
    max_indices: usize,
    out_len: *mut usize,
    timeout_ns: i64,
    out_guard_triggered: *mut bool,
) -> HddsError {
    if waitset.is_null() || out_indices.is_null() || out_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    if subscriptions_len > 0 && subscriptions.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(false);
    }

    out_len.write(0);

    let timeout = timeout_from_ns(timeout_ns);
    let outcome = match (*waitset).waitset.wait(timeout) {
        Ok(o) => o,
        Err(err) => return err_from(err),
    };

    if !out_guard_triggered.is_null() {
        out_guard_triggered.write(outcome.guard_triggered);
    }

    let subscriptions = if subscriptions_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(subscriptions, subscriptions_len)
    };

    let ready = match map_ready_indices(subscriptions, &outcome.readers) {
        Ok(indices) => indices,
        Err(err) => return err,
    };

    if ready.len() > max_indices {
        return HddsError::HddsOperationFailed;
    }

    for (idx, value) in ready.iter().copied().enumerate() {
        out_indices.add(idx).write(value);
    }

    out_len.write(ready.len());
    HddsError::HddsOk
}

/// Releases a guard condition handle obtained from `rmw_hdds_context_graph_guard_condition`.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `guard` was obtained from `rmw_hdds_context_graph_guard_condition`
/// - `guard` is not used after this call (no use-after-free)
/// - `guard` is not released multiple times (no double-free)
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_guard_condition_release(guard: *const HddsGuardCondition) {
    if guard.is_null() {
        return;
    }
    let guard = GraphGuard::from_raw(guard);
    drop(guard);
}

/// Alias that mirrors the ROS 2 `rmw_wait` signature.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers. Callers must ensure:
/// - `waitset` is a valid, non-null pointer to a live waitset
/// - `subscriptions` (if `subscriptions_len > 0`) is a valid pointer to an array of at least `subscriptions_len` reader pointers
/// - `out_indices` is a valid pointer to an array of at least `max_indices` elements
/// - `out_len` is a valid, non-null pointer for writing the result count
/// - `out_guard_triggered` (if not null) is a valid pointer for writing the guard state
/// - No data races occur on the output memory regions
/// - The waitset and reader pointers remain valid for the duration of the call
#[no_mangle]
pub unsafe extern "C" fn rmw_hdds_wait(
    waitset: *mut rmw_hdds_waitset_t,
    timeout_ns: i64,
    subscriptions: *const *mut HddsDataReader,
    subscriptions_len: usize,
    out_indices: *mut usize,
    max_indices: usize,
    out_len: *mut usize,
    out_guard_triggered: *mut bool,
) -> HddsError {
    rmw_hdds_waitset_wait_indices(
        waitset,
        subscriptions,
        subscriptions_len,
        out_indices,
        max_indices,
        out_len,
        timeout_ns,
        out_guard_triggered,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;
    use std::time::Duration;

    unsafe fn create_rmw_reader(
        ctx_ptr: *mut rmw_hdds_context_t,
        topic: &str,
    ) -> *mut HddsDataReader {
        let ctopic = CString::new(topic).unwrap();
        let mut reader = ptr::null_mut();
        assert_eq!(
            rmw_hdds_context_create_reader(ctx_ptr, ctopic.as_ptr(), &mut reader),
            HddsError::HddsOk
        );
        assert!(!reader.is_null());
        reader
    }

    #[test]
    fn context_lifecycle_via_ffi() {
        unsafe {
            let name = CString::new("ffi_context_lifecycle").unwrap();
            let mut ctx_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_context_create(name.as_ptr(), &mut ctx_ptr),
                HddsError::HddsOk
            );
            assert!(!ctx_ptr.is_null());

            let mut key = 0u64;
            assert_eq!(
                rmw_hdds_context_graph_guard_key(ctx_ptr, &mut key),
                HddsError::HddsOk
            );
            assert_ne!(key, 0);

            rmw_hdds_context_destroy(ctx_ptr);
        }
    }

    #[test]
    fn waitset_wait_reports_guard() {
        unsafe {
            let ctx_name = CString::new("ffi_waitset_ctx").unwrap();
            let mut ctx_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_context_create(ctx_name.as_ptr(), &mut ctx_ptr),
                HddsError::HddsOk
            );

            let reader = create_rmw_reader(ctx_ptr, "ffi_waitset_topic");

            let mut waitset_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_waitset_create(ctx_ptr, &mut waitset_ptr),
                HddsError::HddsOk
            );

            assert_eq!(
                rmw_hdds_waitset_attach_reader(waitset_ptr, reader),
                HddsError::HddsOk
            );

            assert_eq!(rmw_hdds_context_set_guard(ctx_ptr, true), HddsError::HddsOk);

            let mut readers = [ptr::null_mut(); 4];
            let mut len = 0usize;
            let mut guard_hit = false;
            let status = rmw_hdds_waitset_wait(
                waitset_ptr,
                crate::duration_to_ns(Some(Duration::from_millis(1))),
                readers.as_mut_ptr(),
                readers.len(),
                &mut len,
                &mut guard_hit,
            );
            assert_eq!(status, HddsError::HddsOk);
            assert_eq!(len, 0);
            assert!(guard_hit);

            assert_eq!(
                rmw_hdds_waitset_detach_reader(waitset_ptr, reader),
                HddsError::HddsOk
            );

            rmw_hdds_waitset_destroy(waitset_ptr);
            rmw_hdds_context_destroy_reader(ctx_ptr, reader);
            rmw_hdds_context_destroy(ctx_ptr);
        }
    }

    #[test]
    fn waitset_wait_indices_empty_result() {
        unsafe {
            let ctx_name = CString::new("ffi_waitset_indices_ctx").unwrap();
            let mut ctx_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_context_create(ctx_name.as_ptr(), &mut ctx_ptr),
                HddsError::HddsOk
            );

            let reader = create_rmw_reader(ctx_ptr, "ffi_waitset_indices_topic");

            let mut waitset_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_waitset_create(ctx_ptr, &mut waitset_ptr),
                HddsError::HddsOk
            );

            assert_eq!(
                rmw_hdds_waitset_attach_reader(waitset_ptr, reader),
                HddsError::HddsOk
            );

            let subscriptions = [reader];
            let mut indices = [usize::MAX; 4];
            let mut ready_len = 0usize;
            let mut guard_hit = false;

            assert_eq!(rmw_hdds_context_set_guard(ctx_ptr, true), HddsError::HddsOk);

            let status = rmw_hdds_waitset_wait_indices(
                waitset_ptr,
                subscriptions.as_ptr(),
                subscriptions.len(),
                indices.as_mut_ptr(),
                indices.len(),
                &mut ready_len,
                crate::duration_to_ns(Some(Duration::from_millis(1))),
                &mut guard_hit,
            );

            assert_eq!(status, HddsError::HddsOk);
            assert_eq!(ready_len, 0);
            assert!(guard_hit);

            assert_eq!(
                rmw_hdds_waitset_detach_reader(waitset_ptr, reader),
                HddsError::HddsOk
            );

            rmw_hdds_waitset_destroy(waitset_ptr);
            rmw_hdds_context_destroy_reader(ctx_ptr, reader);
            rmw_hdds_context_destroy(ctx_ptr);
        }
    }

    #[test]
    fn context_wait_subscriptions_reports_guard() {
        unsafe {
            let ctx_name = CString::new("ffi_ctx_wait_subscriptions_ctx").unwrap();
            let mut ctx_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_context_create(ctx_name.as_ptr(), &mut ctx_ptr),
                HddsError::HddsOk
            );

            let reader = create_rmw_reader(ctx_ptr, "ffi_ctx_wait_subscriptions_topic");

            let mut reader_key = 0u64;
            assert_eq!(
                rmw_hdds_context_attach_reader(ctx_ptr, reader, &mut reader_key),
                HddsError::HddsOk
            );

            assert_eq!(rmw_hdds_context_set_guard(ctx_ptr, true), HddsError::HddsOk);

            let subscriptions = [reader];
            let mut indexes = [usize::MAX; 4];
            let mut len = 0usize;
            let mut guard = false;

            let status = rmw_hdds_context_wait_subscriptions(
                ctx_ptr,
                crate::duration_to_ns(Some(Duration::from_millis(1))),
                subscriptions.as_ptr(),
                subscriptions.len(),
                indexes.as_mut_ptr(),
                indexes.len(),
                &mut len,
                &mut guard,
            );

            assert_eq!(status, HddsError::HddsOk);
            assert_eq!(len, 0);
            assert!(guard);

            assert_eq!(
                rmw_hdds_context_detach_reader(ctx_ptr, reader),
                HddsError::HddsOk
            );

            rmw_hdds_context_destroy_reader(ctx_ptr, reader);
            rmw_hdds_context_destroy(ctx_ptr);
        }
    }

    #[test]
    fn rmw_wait_reports_guard_flag() {
        unsafe {
            let ctx_name = CString::new("ffi_rmw_wait_guard_ctx").unwrap();
            let mut ctx_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_context_create(ctx_name.as_ptr(), &mut ctx_ptr),
                HddsError::HddsOk
            );

            let reader = create_rmw_reader(ctx_ptr, "ffi_rmw_wait_guard_topic");

            let mut waitset_ptr = ptr::null_mut();
            assert_eq!(
                rmw_hdds_waitset_create(ctx_ptr, &mut waitset_ptr),
                HddsError::HddsOk
            );
            assert_eq!(
                rmw_hdds_waitset_attach_reader(waitset_ptr, reader),
                HddsError::HddsOk
            );
            assert_eq!(rmw_hdds_context_set_guard(ctx_ptr, true), HddsError::HddsOk);

            let mut indexes = [usize::MAX; 4];
            let mut len = 0usize;
            let mut guard = false;
            let status = rmw_hdds_wait(
                waitset_ptr,
                crate::duration_to_ns(Some(Duration::from_millis(1))),
                std::ptr::null(),
                0,
                indexes.as_mut_ptr(),
                indexes.len(),
                &mut len,
                &mut guard,
            );

            assert_eq!(status, HddsError::HddsOk);
            assert_eq!(len, 0);
            assert!(guard);

            assert_eq!(
                rmw_hdds_waitset_detach_reader(waitset_ptr, reader),
                HddsError::HddsOk
            );

            rmw_hdds_waitset_destroy(waitset_ptr);
            rmw_hdds_context_destroy_reader(ctx_ptr, reader);
            rmw_hdds_context_destroy(ctx_ptr);
        }
    }
}
