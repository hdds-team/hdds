// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS-RPC C FFI bindings.
//!
//! Request/reply communication over DDS topics.
//!
//! # Usage from C
//!
//! ```c
//! // --- Client side ---
//! HddsRpcClient* client = hdds_rpc_client_create(participant, "echo", 5000);
//!
//! uint8_t* reply = NULL;
//! size_t reply_len = 0;
//! HddsError err = hdds_rpc_client_call(client,
//!     (const uint8_t*)"hello", 5,
//!     5000, &reply, &reply_len);
//!
//! if (err == HDDS_OK) {
//!     // use reply[0..reply_len]
//!     hdds_rpc_reply_free(reply, reply_len);
//! }
//! hdds_rpc_client_destroy(client);
//!
//! // --- Server side ---
//! int32_t my_handler(const uint8_t* req, size_t req_len,
//!                    uint8_t** out_reply, size_t* out_reply_len,
//!                    void* user_data) {
//!     *out_reply = malloc(req_len);
//!     memcpy(*out_reply, req, req_len); // echo
//!     *out_reply_len = req_len;
//!     return 0; // success
//! }
//!
//! HddsRpcServer* server = hdds_rpc_server_create(participant, "echo",
//!                                                 my_handler, NULL);
//! hdds_rpc_server_spin(server); // blocks until shutdown
//! hdds_rpc_server_destroy(server);
//! ```

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hdds::dds::Participant;
use hdds::rpc::{
    list_services, RemoteExceptionCode, RequestHandler, ServiceClient, ServiceServer,
    SampleIdentity,
};

use crate::{HddsError, HddsParticipant};

// =============================================================================
// Opaque handles
// =============================================================================

/// Opaque handle to an RPC client.
#[repr(C)]
pub struct HddsRpcClient {
    _private: [u8; 0],
}

/// Opaque handle to an RPC server.
#[repr(C)]
pub struct HddsRpcServer {
    _private: [u8; 0],
}

// =============================================================================
// C callback type
// =============================================================================

/// C callback for handling RPC requests.
///
/// The handler receives a request payload and must produce a reply payload.
///
/// # Parameters
/// - `request`: Pointer to request payload bytes (read-only).
/// - `request_len`: Length of request payload.
/// - `out_reply`: On success, handler must set this to a `malloc()`-allocated reply buffer.
/// - `out_reply_len`: On success, handler must set this to the reply length.
/// - `user_data`: User-provided context pointer.
///
/// # Returns
/// 0 on success. On error, return a `RemoteExceptionCode` value (1-6).
/// When returning non-zero, `out_reply` and `out_reply_len` are ignored.
///
/// # Memory
/// The reply buffer `*out_reply` must be allocated with `malloc()`.
/// HDDS will `free()` it after sending the reply.
pub type HddsRpcHandlerFn = unsafe extern "C" fn(
    request: *const u8,
    request_len: usize,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
    user_data: *mut c_void,
) -> i32;

// =============================================================================
// Exception codes
// =============================================================================

/// RPC exception codes (mirrors DDS-RPC spec).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsRpcExceptionCode {
    /// No error
    HddsRpcOk = 0,
    /// Service not found
    HddsRpcUnsupportedService = 1,
    /// Method not found
    HddsRpcUnsupportedMethod = 2,
    /// Invalid arguments
    HddsRpcInvalidArgument = 3,
    /// Service unavailable
    HddsRpcServiceUnavailable = 4,
    /// Request timed out
    HddsRpcTimeout = 5,
    /// Internal error
    HddsRpcInternalError = 6,
    /// Unknown error
    HddsRpcUnknown = -1,
}

// =============================================================================
// Internal wrapper types
// =============================================================================

/// Wrapper for RPC client, holds the tokio runtime needed for async calls.
struct RpcClientWrapper {
    client: ServiceClient,
    runtime: tokio::runtime::Runtime,
}

/// Wrapper for RPC server, manages lifecycle and shutdown.
struct RpcServerWrapper {
    server: Option<ServiceServer>,
    shutdown: Arc<AtomicBool>,
    background_thread: Option<std::thread::JoinHandle<()>>,
    service_name: String,
    request_timeout: Option<Duration>,
}

/// Bridge from C function pointer to Rust RequestHandler trait.
struct CHandlerBridge {
    callback: HddsRpcHandlerFn,
    user_data: *mut c_void,
}

// SAFETY: CHandlerBridge is sent across threads (for server spin).
// The C callback and user_data must be thread-safe (documented in C API).
unsafe impl Send for CHandlerBridge {}
unsafe impl Sync for CHandlerBridge {}

impl RequestHandler for CHandlerBridge {
    fn handle(
        &self,
        _request_id: SampleIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, (RemoteExceptionCode, String)> {
        let mut reply_ptr: *mut u8 = ptr::null_mut();
        let mut reply_len: usize = 0;

        let rc = unsafe {
            (self.callback)(
                payload.as_ptr(),
                payload.len(),
                &mut reply_ptr,
                &mut reply_len,
                self.user_data,
            )
        };

        if rc == 0 {
            if reply_ptr.is_null() || reply_len == 0 {
                Ok(Vec::new())
            } else {
                // Copy the data, then free the C-allocated buffer
                let reply = unsafe { std::slice::from_raw_parts(reply_ptr, reply_len).to_vec() };
                unsafe {
                    libc::free(reply_ptr as *mut c_void);
                }
                Ok(reply)
            }
        } else {
            Err((RemoteExceptionCode::from_i32(rc), String::new()))
        }
    }
}

// =============================================================================
// Client lifecycle
// =============================================================================

/// Create an RPC client for a service.
///
/// # Arguments
/// - `participant`: Valid participant handle.
/// - `service_name`: Null-terminated service name.
/// - `default_timeout_ms`: Default timeout in milliseconds for calls.
///
/// Returns NULL on failure.
///
/// # Safety
/// - `participant` must be a valid handle from `hdds_participant_create` or `hdds_config_build`.
/// - `service_name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_create(
    participant: *mut HddsParticipant,
    service_name: *const c_char,
    default_timeout_ms: u64,
) -> *mut HddsRpcClient {
    if participant.is_null() || service_name.is_null() {
        return ptr::null_mut();
    }
    let Ok(name) = CStr::from_ptr(service_name).to_str() else {
        return ptr::null_mut();
    };
    let participant_arc = &*participant.cast::<Arc<Participant>>();
    let timeout = Duration::from_millis(default_timeout_ms);

    // Create a current-thread tokio runtime for async operations
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        log::error!("hdds_rpc_client_create: failed to create tokio runtime");
        return ptr::null_mut();
    };

    // Enter the runtime context so tokio::spawn() works inside ServiceClient::new()
    let _guard = runtime.enter();

    match ServiceClient::with_timeout(participant_arc, name, timeout) {
        Ok(client) => {
            let wrapper = RpcClientWrapper { client, runtime };
            Box::into_raw(Box::new(wrapper)).cast::<HddsRpcClient>()
        }
        Err(e) => {
            log::error!("hdds_rpc_client_create: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Send a request and wait (blocking) for the reply.
///
/// On success, `*out_reply` points to a reply buffer of `*out_reply_len` bytes.
/// The caller MUST free this buffer with `hdds_rpc_reply_free()`.
///
/// # Safety
/// - `client` must be valid.
/// - `request` must point to `request_len` bytes (or be NULL if `request_len` is 0).
/// - `out_reply` and `out_reply_len` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_call(
    client: *mut HddsRpcClient,
    request: *const u8,
    request_len: usize,
    timeout_ms: u64,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
) -> HddsError {
    if client.is_null() || out_reply.is_null() || out_reply_len.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let wrapper = &*client.cast::<RpcClientWrapper>();
    let payload = if request.is_null() || request_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(request, request_len)
    };
    let timeout = Duration::from_millis(timeout_ms);

    match wrapper.runtime.block_on(wrapper.client.call_raw(payload, timeout)) {
        Ok(reply_vec) => {
            let reply_boxed = reply_vec.into_boxed_slice();
            let len = reply_boxed.len();
            if len == 0 {
                *out_reply = ptr::null_mut();
                *out_reply_len = 0;
            } else {
                let ptr = Box::into_raw(reply_boxed) as *mut u8;
                *out_reply = ptr;
                *out_reply_len = len;
            }
            HddsError::HddsOk
        }
        Err(e) => {
            log::error!("hdds_rpc_client_call: {:?}", e);
            *out_reply = ptr::null_mut();
            *out_reply_len = 0;
            HddsError::HddsOperationFailed
        }
    }
}

/// Free a reply buffer returned by `hdds_rpc_client_call`.
///
/// # Safety
/// - `reply` must be a pointer previously returned in `out_reply` by `hdds_rpc_client_call`,
///   or NULL.
/// - `len` must match the `out_reply_len` value from that same call.
/// - Must only be called once per reply.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_reply_free(reply: *mut u8, len: usize) {
    if !reply.is_null() && len > 0 {
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(reply, len));
    }
}

/// Get the client's service name. Returns bytes needed (excluding null).
///
/// # Safety
/// - `client` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_service_name(
    client: *const HddsRpcClient,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if client.is_null() {
        return 0;
    }
    let wrapper = &*client.cast::<RpcClientWrapper>();
    let name = wrapper.client.service_name();
    copy_str_to_buf(name, out_buf, capacity)
}

/// Shutdown the RPC client. Cancels any pending requests.
///
/// # Safety
/// - `client` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_shutdown(client: *mut HddsRpcClient) {
    if !client.is_null() {
        let wrapper = &*client.cast::<RpcClientWrapper>();
        wrapper.client.shutdown();
    }
}

/// Destroy an RPC client.
///
/// # Safety
/// - `client` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_destroy(client: *mut HddsRpcClient) {
    if !client.is_null() {
        let _ = Box::from_raw(client.cast::<RpcClientWrapper>());
    }
}

// =============================================================================
// Server lifecycle
// =============================================================================

/// Create an RPC server for a service.
///
/// The `handler` callback is invoked for each incoming request. It must:
/// 1. Allocate a reply buffer with `malloc()`.
/// 2. Set `*out_reply` and `*out_reply_len`.
/// 3. Return 0 on success, or a `RemoteExceptionCode` (1-6) on error.
///
/// HDDS will `free()` the reply buffer after sending.
///
/// Returns NULL on failure.
///
/// # Safety
/// - `participant` must be a valid handle.
/// - `service_name` must be null-terminated.
/// - `handler` must be a valid function pointer. It must be thread-safe.
/// - `user_data` is passed through to the handler (may be NULL).
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_create(
    participant: *mut HddsParticipant,
    service_name: *const c_char,
    handler: HddsRpcHandlerFn,
    user_data: *mut c_void,
) -> *mut HddsRpcServer {
    if participant.is_null() || service_name.is_null() {
        return ptr::null_mut();
    }
    let Ok(name) = CStr::from_ptr(service_name).to_str() else {
        return ptr::null_mut();
    };
    let participant_arc = &*participant.cast::<Arc<Participant>>();

    let bridge = CHandlerBridge {
        callback: handler,
        user_data,
    };

    match ServiceServer::new(participant_arc, name, bridge) {
        Ok(server) => {
            let wrapper = RpcServerWrapper {
                server: Some(server),
                shutdown: Arc::new(AtomicBool::new(false)),
                background_thread: None,
                service_name: name.to_string(),
                request_timeout: None,
            };
            Box::into_raw(Box::new(wrapper)).cast::<HddsRpcServer>()
        }
        Err(e) => {
            log::error!("hdds_rpc_server_create: {:?}", e);
            ptr::null_mut()
        }
    }
}

/// Set the request timeout for the server.
///
/// Requests older than this timeout are skipped with a Timeout reply.
/// Must be called before `hdds_rpc_server_spin` / `hdds_rpc_server_spin_background`.
///
/// # Safety
/// - `server` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_set_request_timeout(
    server: *mut HddsRpcServer,
    timeout_ms: u64,
) -> HddsError {
    if server.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let wrapper = &mut *server.cast::<RpcServerWrapper>();
    wrapper.request_timeout = Some(Duration::from_millis(timeout_ms));
    HddsError::HddsOk
}

/// Run the server event loop (blocking).
///
/// Processes requests until `hdds_rpc_server_shutdown()` is called from another thread.
/// Returns `HddsOk` when the server shuts down cleanly.
///
/// # Safety
/// - `server` must be valid.
/// - Must not be called more than once on the same server.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_spin(server: *mut HddsRpcServer) -> HddsError {
    if server.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let wrapper = &mut *server.cast::<RpcServerWrapper>();

    let mut srv = match wrapper.server.take() {
        Some(s) => s,
        None => {
            log::error!("hdds_rpc_server_spin: server already consumed (spin called twice?)");
            return HddsError::HddsInvalidArgument;
        }
    };

    if let Some(timeout) = wrapper.request_timeout {
        srv = srv.with_request_timeout(timeout);
    }

    let shutdown = wrapper.shutdown.clone();

    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        log::error!("hdds_rpc_server_spin: failed to create tokio runtime");
        return HddsError::HddsOperationFailed;
    };

    rt.block_on(async move {
        tokio::select! {
            _ = srv.spin() => {},
            _ = poll_shutdown(&shutdown) => {},
        }
    });

    HddsError::HddsOk
}

/// Run the server event loop in a background thread (non-blocking).
///
/// The server processes requests until `hdds_rpc_server_shutdown()` is called.
///
/// # Safety
/// - `server` must be valid.
/// - Must not be called more than once on the same server.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_spin_background(
    server: *mut HddsRpcServer,
) -> HddsError {
    if server.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let wrapper = &mut *server.cast::<RpcServerWrapper>();

    let mut srv = match wrapper.server.take() {
        Some(s) => s,
        None => {
            log::error!(
                "hdds_rpc_server_spin_background: server already consumed (spin called twice?)"
            );
            return HddsError::HddsInvalidArgument;
        }
    };

    if let Some(timeout) = wrapper.request_timeout {
        srv = srv.with_request_timeout(timeout);
    }

    let shutdown = wrapper.shutdown.clone();
    let svc_name = wrapper.service_name.clone();

    match std::thread::Builder::new()
        .name(format!("hdds-rpc-{}", svc_name))
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                log::error!("hdds_rpc_server background thread: failed to create tokio runtime");
                return;
            };
            rt.block_on(async move {
                tokio::select! {
                    _ = srv.spin() => {},
                    _ = poll_shutdown(&shutdown) => {},
                }
            });
        })
    {
        Ok(handle) => {
            wrapper.background_thread = Some(handle);
            HddsError::HddsOk
        }
        Err(e) => {
            log::error!("hdds_rpc_server_spin_background: thread spawn failed: {}", e);
            HddsError::HddsOperationFailed
        }
    }
}

/// Signal the server to stop processing requests.
///
/// If the server was started with `hdds_rpc_server_spin`, it will return.
/// If started with `hdds_rpc_server_spin_background`, the background thread will exit.
///
/// # Safety
/// - `server` must be valid or NULL. Thread-safe.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_shutdown(server: *mut HddsRpcServer) {
    if server.is_null() {
        return;
    }
    let wrapper = &*server.cast::<RpcServerWrapper>();
    wrapper.shutdown.store(true, Ordering::Relaxed);
    // If server hasn't been spun yet, call its internal shutdown too
    if let Some(ref srv) = wrapper.server {
        srv.shutdown();
    }
}

/// Check if the server is running.
///
/// # Safety
/// - `server` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_is_running(server: *const HddsRpcServer) -> bool {
    if server.is_null() {
        return false;
    }
    let wrapper = &*server.cast::<RpcServerWrapper>();
    // Running = server was consumed by spin AND shutdown not signalled
    wrapper.server.is_none() && !wrapper.shutdown.load(Ordering::Relaxed)
}

/// Get the server's service name. Returns bytes needed (excluding null).
///
/// # Safety
/// - `server` must be valid.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_service_name(
    server: *const HddsRpcServer,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if server.is_null() {
        return 0;
    }
    let wrapper = &*server.cast::<RpcServerWrapper>();
    copy_str_to_buf(&wrapper.service_name, out_buf, capacity)
}

/// Destroy an RPC server.
///
/// If the server is running in the background, this signals shutdown and
/// waits for the background thread to finish.
///
/// # Safety
/// - `server` must be valid or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_destroy(server: *mut HddsRpcServer) {
    if server.is_null() {
        return;
    }
    let mut wrapper = *Box::from_raw(server.cast::<RpcServerWrapper>());
    // Signal shutdown
    wrapper.shutdown.store(true, Ordering::Relaxed);
    // Wait for background thread if running
    if let Some(thread) = wrapper.background_thread.take() {
        let _ = thread.join();
    }
    // Drop remaining fields (server, runtime)
}

// =============================================================================
// Service registry
// =============================================================================

/// Get the number of currently registered RPC services.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_service_count() -> usize {
    list_services().len()
}

/// Get the name of a registered RPC service by index.
///
/// Returns bytes needed (excluding null), or 0 if index is out of range.
///
/// # Safety
/// - `out_buf` must point to `capacity` bytes, or be NULL (to query length only).
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_service_name(
    index: usize,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    let services = list_services();
    match services.get(index) {
        Some(info) => copy_str_to_buf(&info.name, out_buf, capacity),
        None => 0,
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Poll an AtomicBool until it becomes true.
async fn poll_shutdown(flag: &AtomicBool) {
    loop {
        if flag.load(Ordering::Relaxed) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Copy a Rust str into a C buffer. Returns bytes needed (excluding null).
fn copy_str_to_buf(s: &str, out_buf: *mut c_char, capacity: usize) -> usize {
    let needed = s.as_bytes().len();
    if !out_buf.is_null() && capacity > 0 {
        let copy_len = needed.min(capacity - 1);
        unsafe {
            ptr::copy_nonoverlapping(s.as_bytes().as_ptr(), out_buf.cast::<u8>(), copy_len);
            *out_buf.add(copy_len) = 0;
        }
    }
    needed
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_null_safety() {
        unsafe {
            // Client null checks
            assert!(hdds_rpc_client_create(ptr::null_mut(), ptr::null(), 5000).is_null());
            hdds_rpc_client_shutdown(ptr::null_mut());
            hdds_rpc_client_destroy(ptr::null_mut());
            assert_eq!(
                hdds_rpc_client_call(
                    ptr::null_mut(),
                    ptr::null(),
                    0,
                    1000,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(hdds_rpc_client_service_name(ptr::null(), ptr::null_mut(), 0), 0);

            // Server null checks
            assert!(hdds_rpc_server_create(
                ptr::null_mut(),
                ptr::null(),
                null_handler,
                ptr::null_mut(),
            )
            .is_null());
            hdds_rpc_server_shutdown(ptr::null_mut());
            hdds_rpc_server_destroy(ptr::null_mut());
            assert_eq!(
                hdds_rpc_server_spin(ptr::null_mut()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_rpc_server_spin_background(ptr::null_mut()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_rpc_server_set_request_timeout(ptr::null_mut(), 1000),
                HddsError::HddsInvalidArgument,
            );
            assert!(!hdds_rpc_server_is_running(ptr::null()));
            assert_eq!(hdds_rpc_server_service_name(ptr::null(), ptr::null_mut(), 0), 0);

            // Reply free with null
            hdds_rpc_reply_free(ptr::null_mut(), 0);
        }
    }

    unsafe extern "C" fn null_handler(
        _request: *const u8,
        _request_len: usize,
        _out_reply: *mut *mut u8,
        _out_reply_len: *mut usize,
        _user_data: *mut c_void,
    ) -> i32 {
        0
    }

    #[test]
    fn test_reply_free_roundtrip() {
        unsafe {
            // Simulate what hdds_rpc_client_call does with the reply
            let data = vec![1u8, 2, 3, 4, 5];
            let boxed = data.into_boxed_slice();
            let len = boxed.len();
            let ptr = Box::into_raw(boxed) as *mut u8;

            // Verify data is accessible
            let slice = std::slice::from_raw_parts(ptr, len);
            assert_eq!(slice, &[1, 2, 3, 4, 5]);

            // Free it
            hdds_rpc_reply_free(ptr, len);
        }
    }

    #[test]
    fn test_copy_str_to_buf() {
        let mut buf = [0u8; 32];
        let needed = copy_str_to_buf("hello", buf.as_mut_ptr().cast(), 32);
        assert_eq!(needed, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(buf[5], 0); // null terminator

        // Buffer too small
        let mut small = [0u8; 4];
        let needed = copy_str_to_buf("hello", small.as_mut_ptr().cast(), 4);
        assert_eq!(needed, 5); // still reports needed length
        assert_eq!(&small[..3], b"hel");
        assert_eq!(small[3], 0); // null terminator at capacity-1
    }

    #[test]
    fn test_exception_code_enum() {
        assert_eq!(HddsRpcExceptionCode::HddsRpcOk as i32, 0);
        assert_eq!(HddsRpcExceptionCode::HddsRpcTimeout as i32, 5);
        assert_eq!(HddsRpcExceptionCode::HddsRpcUnknown as i32, -1);
    }

    #[test]
    fn test_service_registry_ffi() {
        unsafe {
            // Service count should be >= 0 (may have services from other tests)
            let count = hdds_rpc_service_count();
            // Out-of-range index returns 0
            assert_eq!(hdds_rpc_service_name(999, ptr::null_mut(), 0), 0);
            let _ = count; // suppress unused warning
        }
    }

    #[test]
    fn test_c_handler_bridge() {
        // Test that the CHandlerBridge correctly bridges C callbacks
        unsafe extern "C" fn echo_handler(
            request: *const u8,
            request_len: usize,
            out_reply: *mut *mut u8,
            out_reply_len: *mut usize,
            _user_data: *mut c_void,
        ) -> i32 {
            if request.is_null() || request_len == 0 {
                return 3; // InvalidArgument
            }
            let reply = libc::malloc(request_len) as *mut u8;
            if reply.is_null() {
                return 6; // InternalError
            }
            ptr::copy_nonoverlapping(request, reply, request_len);
            *out_reply = reply;
            *out_reply_len = request_len;
            0
        }

        let bridge = CHandlerBridge {
            callback: echo_handler,
            user_data: ptr::null_mut(),
        };

        let result = bridge.handle(SampleIdentity::zero(), b"test_data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test_data");
    }

    #[test]
    fn test_c_handler_bridge_error() {
        unsafe extern "C" fn error_handler(
            _request: *const u8,
            _request_len: usize,
            _out_reply: *mut *mut u8,
            _out_reply_len: *mut usize,
            _user_data: *mut c_void,
        ) -> i32 {
            3 // InvalidArgument
        }

        let bridge = CHandlerBridge {
            callback: error_handler,
            user_data: ptr::null_mut(),
        };

        let result = bridge.handle(SampleIdentity::zero(), b"test");
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, RemoteExceptionCode::InvalidArgument);
    }

    #[test]
    fn test_c_handler_bridge_empty_reply() {
        unsafe extern "C" fn empty_handler(
            _request: *const u8,
            _request_len: usize,
            _out_reply: *mut *mut u8,
            _out_reply_len: *mut usize,
            _user_data: *mut c_void,
        ) -> i32 {
            // Success with no reply data
            0
        }

        let bridge = CHandlerBridge {
            callback: empty_handler,
            user_data: ptr::null_mut(),
        };

        let result = bridge.handle(SampleIdentity::zero(), b"test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
