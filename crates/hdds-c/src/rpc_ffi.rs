// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Synchronous C RPC API, available with the Cargo `rpc` feature.
//!
//! Client calls and shutdown may run concurrently on a live handle. Destroy
//! requires exclusive ownership: join all external calls, including blocking
//! server spin, first. Callbacks run sequentially on a worker thread and may
//! call another service. Callback thread identity is not stable across calls. A callback must not destroy its own server or form a
//! synchronous call cycle back to that server. See sdk/c/RPC.md for contracts.

use crate::rpc_runtime::{CallFailure, ClientWorker};
use crate::{HddsError, HddsParticipant};
use hdds::rpc::{
    list_services, RemoteExceptionCode, RequestHandler, RpcError, SampleIdentity, ServiceServer,
};
use hdds::Participant;
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Opaque RPC client handle.
pub struct HddsRpcClient {
    _private: [u8; 0],
}
/// Opaque RPC server handle.
pub struct HddsRpcServer {
    _private: [u8; 0],
}

/// Callback invoked sequentially on blocking workers, with borrowed request bytes.
/// The executing thread is not guaranteed to stay the same across calls.
///
/// Return 0 for success, or an HDDS_RPC_* exception code on error; any other
/// non-zero value reaches the client as HDDS_RPC_UNKNOWN_EXCEPTION. On success,
/// transfer a malloc-allocated buffer (compatible with HDDS's C runtime free)
/// through out_reply/out_reply_len. NULL/0 is a valid empty reply. HDDS copies
/// and frees every non-NULL success buffer, including a zero-length allocation.
/// On error, outputs are ignored and the callback owns any allocations it made.
/// user_data and the callback must remain valid until server_destroy returns.
/// Do not unwind, destroy this server, or wait for this server from its callback.
pub type HddsRpcHandlerFn = Option<
    unsafe extern "C" fn(
        request: *const u8,
        request_len: usize,
        out_reply: *mut *mut u8,
        out_reply_len: *mut usize,
        user_data: *mut c_void,
    ) -> i32,
>;

/// RPC remote exception codes: the six `RemoteExceptionCode_t` values of OMG
/// DDS-RPC 1.0 (clause 7.5.2) with their wire values. The specification has no
/// timeout code, so a server-side handler timeout is reported as
/// HDDS_RPC_UNKNOWN_EXCEPTION.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsRpcExceptionCode {
    HddsRpcOk = 0,
    HddsRpcUnsupported = 1,
    HddsRpcInvalidArgument = 2,
    HddsRpcOutOfResources = 3,
    HddsRpcUnknownOperation = 4,
    HddsRpcUnknownException = 5,
}

struct RpcClientWrapper {
    worker: ClientWorker,
    service_name: String,
    default_timeout: Duration,
}

struct ServerControl {
    shutdown: watch::Sender<bool>,
    running: AtomicBool,
}
struct ServerState {
    server: Option<ServiceServer>,
    thread: Option<std::thread::JoinHandle<()>>,
}
struct RpcServerWrapper {
    state: Mutex<ServerState>,
    control: Arc<ServerControl>,
    service_name: String,
}

struct CHandlerBridge {
    callback: HddsRpcHandlerFn,
    user_data: *mut c_void,
}
// SAFETY: the C contract requires callback/user_data to be valid on the worker
// until destruction joins it. No concurrent callback is started by this server.
unsafe impl Send for CHandlerBridge {}
unsafe impl Sync for CHandlerBridge {}

struct CallbackReply(*mut u8);
impl Drop for CallbackReply {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.0.cast());
        }
    }
}
impl RequestHandler for CHandlerBridge {
    fn handle(
        &self,
        _id: SampleIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, (RemoteExceptionCode, String)> {
        let mut buffer = ptr::null_mut();
        let mut len = 0;
        let Some(callback) = self.callback else {
            return Err((
                RemoteExceptionCode::UnknownException,
                "missing callback".into(),
            ));
        };
        let result = unsafe {
            callback(
                if payload.is_empty() {
                    ptr::null()
                } else {
                    payload.as_ptr()
                },
                payload.len(),
                &mut buffer,
                &mut len,
                self.user_data,
            )
        };
        if result != 0 {
            // Error outputs were never transferred to HDDS. A value outside
            // the spec enum cannot go on the wire; it becomes the generic code.
            let code = RemoteExceptionCode::from_wire(result)
                .unwrap_or(RemoteExceptionCode::UnknownException);
            return Err((code, String::new()));
        }
        let _owned = CallbackReply(buffer);
        if (buffer.is_null() && len != 0) || len > isize::MAX as usize {
            return Err((
                RemoteExceptionCode::UnknownException,
                "invalid callback reply".into(),
            ));
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        Ok(unsafe { std::slice::from_raw_parts(buffer, len).to_vec() })
    }
}

/// Create a client. Returns NULL on invalid input or initialization failure.
/// default_timeout_ms is used by hdds_rpc_client_call_default.
///
/// # Safety
/// participant must be live; service_name must be a readable NUL-terminated string.
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
    if name.is_empty() {
        return ptr::null_mut();
    }
    let timeout = Duration::from_millis(default_timeout_ms);
    if Instant::now().checked_add(timeout).is_none() {
        return ptr::null_mut();
    }
    let participant = (&*participant.cast::<Arc<Participant>>()).clone();
    match ClientWorker::start(participant, name.to_owned(), timeout) {
        Ok(worker) => Box::into_raw(Box::new(RpcClientWrapper {
            worker,
            service_name: name.to_owned(),
            default_timeout: timeout,
        }))
        .cast(),
        Err(error) => {
            log::error!("RPC client creation failed: {error}");
            ptr::null_mut()
        }
    }
}

/// Send a request, blocking until reply, shutdown or timeout (including queue time).
/// Zero timeout expires immediately. On success, free the reply exclusively with
/// hdds_rpc_reply_free and its exact length. Valid outputs are reset on failure.
///
/// # Safety
/// client must be live. request must contain request_len readable bytes, or NULL/0.
/// Output pointers must be writable and not alias the request or each other.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_call(
    client: *mut HddsRpcClient,
    request: *const u8,
    request_len: usize,
    timeout_ms: u64,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
) -> HddsError {
    call_with_timeout(
        client,
        request,
        request_len,
        Duration::from_millis(timeout_ms),
        out_reply,
        out_reply_len,
    )
}

/// Send using the timeout configured at client creation.
///
/// # Safety
/// The handle, request and output requirements are the same as hdds_rpc_client_call.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_call_default(
    client: *mut HddsRpcClient,
    request: *const u8,
    request_len: usize,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
) -> HddsError {
    let timeout = if client.is_null() {
        Duration::ZERO
    } else {
        (&*client.cast::<RpcClientWrapper>()).default_timeout
    };
    call_with_timeout(
        client,
        request,
        request_len,
        timeout,
        out_reply,
        out_reply_len,
    )
}

unsafe fn call_with_timeout(
    client: *mut HddsRpcClient,
    request: *const u8,
    request_len: usize,
    timeout: Duration,
    out_reply: *mut *mut u8,
    out_reply_len: *mut usize,
) -> HddsError {
    if !out_reply.is_null() {
        *out_reply = ptr::null_mut();
    }
    if !out_reply_len.is_null() {
        *out_reply_len = 0;
    }
    if client.is_null()
        || out_reply.is_null()
        || out_reply_len.is_null()
        || (request.is_null() && request_len != 0)
        || request_len > isize::MAX as usize
    {
        return HddsError::HddsInvalidArgument;
    }
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return HddsError::HddsInvalidArgument;
    };
    let payload = if request_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(request, request_len).to_vec()
    };
    let wrapper = &*client.cast::<RpcClientWrapper>();
    match wrapper.worker.call(payload, deadline) {
        Ok(reply) => {
            if !reply.is_empty() {
                *out_reply_len = reply.len();
                *out_reply = Box::into_raw(reply.into_boxed_slice()).cast::<u8>();
            }
            HddsError::HddsOk
        }
        Err(CallFailure::Rpc(RpcError::Timeout)) => HddsError::HddsTimeout,
        Err(CallFailure::Rpc(RpcError::Shutdown)) => HddsError::HddsInvalidState,
        Err(CallFailure::Busy) => HddsError::HddsWouldBlock,
        Err(CallFailure::Rpc(error)) => {
            log::error!("RPC call failed: {error}");
            HddsError::HddsOperationFailed
        }
    }
}

/// Free a successful client reply. NULL is accepted.
///
/// # Safety
/// reply and len must be the exact pair from one successful call, freed only once.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_reply_free(reply: *mut u8, len: usize) {
    if !reply.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            reply, len,
        )));
    }
}

/// Get the service name length, excluding NUL; copy a terminated prefix if supplied.
///
/// # Safety
/// client must be live. out_buf must be writable for capacity bytes, or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_service_name(
    client: *const HddsRpcClient,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if client.is_null() {
        return 0;
    }
    copy_str_to_buf(
        &(&*client.cast::<RpcClientWrapper>()).service_name,
        out_buf,
        capacity,
    )
}

/// Cancel pending calls and refuse new calls. Thread-safe on a live handle.
///
/// # Safety
/// client must be live or NULL; destruction must not run concurrently.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_shutdown(client: *mut HddsRpcClient) {
    if !client.is_null() {
        (&*client.cast::<RpcClientWrapper>()).worker.shutdown();
    }
}

/// Stop and join the client's worker, then free its handle.
///
/// # Safety
/// client must be live or NULL. Join all external calls before destruction.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_client_destroy(client: *mut HddsRpcClient) {
    if !client.is_null() {
        drop(Box::from_raw(client.cast::<RpcClientWrapper>()));
    }
}

/// Create a server handle. The callback starts only after spin. NULL on failure.
///
/// # Safety
/// participant must be live, service_name NUL-terminated, and handler/user_data
/// must satisfy HddsRpcHandlerFn's lifetime, allocation and threading contract.
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
    let (Ok(name), Some(callback)) = (CStr::from_ptr(service_name).to_str(), handler) else {
        return ptr::null_mut();
    };
    if name.is_empty() {
        return ptr::null_mut();
    }
    let participant = &*participant.cast::<Arc<Participant>>();
    match ServiceServer::new(
        participant,
        name,
        CHandlerBridge {
            callback: Some(callback),
            user_data,
        },
    ) {
        Ok(server) => {
            let (shutdown, _) = watch::channel(false);
            Box::into_raw(Box::new(RpcServerWrapper {
                state: Mutex::new(ServerState {
                    server: Some(server),
                    thread: None,
                }),
                control: Arc::new(ServerControl {
                    shutdown,
                    running: AtomicBool::new(false),
                }),
                service_name: name.to_owned(),
            }))
            .cast()
        }
        Err(error) => {
            log::error!("RPC server creation failed: {error}");
            ptr::null_mut()
        }
    }
}

/// Set the handler execution deadline before spin. Does not measure request age
/// in DDS. A timeout sends a reply, then drains the callback before serving the
/// next request. No timeout can forcibly terminate a C callback.
///
/// # Safety
/// server must be live.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_set_request_timeout(
    server: *mut HddsRpcServer,
    timeout_ms: u64,
) -> HddsError {
    if server.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let timeout = Duration::from_millis(timeout_ms);
    if Instant::now().checked_add(timeout).is_none() {
        return HddsError::HddsInvalidArgument;
    }
    let wrapper = &*server.cast::<RpcServerWrapper>();
    let mut state = wrapper.state.lock().unwrap_or_else(|e| e.into_inner());
    if *wrapper.control.shutdown.borrow() {
        return HddsError::HddsInvalidState;
    }
    let Some(service) = state.server.take() else {
        return HddsError::HddsInvalidState;
    };
    state.server = Some(service.with_request_timeout(timeout));
    HddsError::HddsOk
}

fn start_server(wrapper: &RpcServerWrapper) -> HddsError {
    let mut state = wrapper.state.lock().unwrap_or_else(|e| e.into_inner());
    if *wrapper.control.shutdown.borrow() {
        return HddsError::HddsInvalidState;
    }
    let Some(server) = state.server.take() else {
        return HddsError::HddsInvalidState;
    };
    let control = wrapper.control.clone();
    let mut shutdown = control.shutdown.subscribe();
    let (ready, initialized) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(format!("hdds-rpc-server-{}", wrapper.service_name))
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => {
                    let _ = ready.send(HddsError::HddsOperationFailed);
                    return;
                }
            };
            runtime.block_on(async move {
                if *shutdown.borrow() {
                    let _ = ready.send(HddsError::HddsInvalidState);
                    return;
                }
                control.running.store(true, Ordering::Release);
                let _ = ready.send(HddsError::HddsOk);
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => {},
                    _ = server.spin() => {},
                }
                control.running.store(false, Ordering::Release);
            });
            // Runtime drop joins every started blocking callback before thread exit.
        });
    match thread {
        Ok(thread) => state.thread = Some(thread),
        Err(_) => return HddsError::HddsOperationFailed,
    }
    drop(state);
    initialized.recv().unwrap_or(HddsError::HddsOperationFailed)
}

/// Start once and block until shutdown, including completion of an active callback.
///
/// # Safety
/// server must be live. Another thread may request shutdown. Join this call before
/// destroying the handle; never call spin from this server's callback.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_spin(server: *mut HddsRpcServer) -> HddsError {
    if server.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let wrapper = &*server.cast::<RpcServerWrapper>();
    let result = start_server(wrapper);
    if result != HddsError::HddsOk {
        return result;
    }
    let thread = wrapper
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .thread
        .take();
    match thread.map(|thread| thread.join()) {
        Some(Ok(())) => HddsError::HddsOk,
        _ => HddsError::HddsOperationFailed,
    }
}

/// Start once on a background thread; success acknowledges runtime initialization.
///
/// # Safety
/// server must be live; destruction must not run concurrently.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_spin_background(server: *mut HddsRpcServer) -> HddsError {
    if server.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    start_server(&*server.cast::<RpcServerWrapper>())
}

/// Signal shutdown. An active callback may finish; destroy joins it. Thread-safe.
///
/// # Safety
/// server must be live or NULL; destruction must not run concurrently.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_shutdown(server: *mut HddsRpcServer) {
    if !server.is_null() {
        (&*server.cast::<RpcServerWrapper>())
            .control
            .shutdown
            .send_replace(true);
    }
}

/// True after successful spin initialization and before shutdown/stopping.
///
/// # Safety
/// server must be live or NULL; destruction must not run concurrently.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_is_running(server: *const HddsRpcServer) -> bool {
    if server.is_null() {
        return false;
    }
    let control = &(&*server.cast::<RpcServerWrapper>()).control;
    control.running.load(Ordering::Acquire) && !*control.shutdown.borrow()
}

/// Get the service name length, excluding NUL; copy a terminated prefix if supplied.
///
/// # Safety
/// server must be live. out_buf must be writable for capacity bytes, or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_service_name(
    server: *const HddsRpcServer,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    if server.is_null() {
        return 0;
    }
    copy_str_to_buf(
        &(&*server.cast::<RpcServerWrapper>()).service_name,
        out_buf,
        capacity,
    )
}

/// Stop, join workers and active callbacks, then free the server handle.
///
/// # Safety
/// server must be live or NULL. All external calls, including blocking spin,
/// must have returned. Never call from this server's callback. user_data may
/// be freed after this returns; a non-returning callback prevents destruction.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_server_destroy(server: *mut HddsRpcServer) {
    if server.is_null() {
        return;
    }
    let wrapper = Box::from_raw(server.cast::<RpcServerWrapper>());
    wrapper.control.shutdown.send_replace(true);
    let thread = wrapper
        .state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .thread
        .take();
    if let Some(thread) = thread {
        let _ = thread.join();
    }
}

/// Count process-local server registrations, grouped by name across DDS domains.
/// Presence does not imply spinning or remote reachability. Each call is a snapshot.
#[no_mangle]
pub extern "C" fn hdds_rpc_service_count() -> usize {
    list_services().len()
}

/// Get a local registration name. Index may change between calls if servers change.
/// Returns the length excluding NUL, or zero for an out-of-range index.
///
/// # Safety
/// out_buf must be writable for capacity bytes, or NULL to query length only.
#[no_mangle]
pub unsafe extern "C" fn hdds_rpc_service_name(
    index: usize,
    out_buf: *mut c_char,
    capacity: usize,
) -> usize {
    list_services()
        .get(index)
        .map_or(0, |info| copy_str_to_buf(&info.name, out_buf, capacity))
}

unsafe fn copy_str_to_buf(s: &str, out_buf: *mut c_char, capacity: usize) -> usize {
    if !out_buf.is_null() && capacity > 0 {
        let count = s.len().min(capacity - 1);
        ptr::copy_nonoverlapping(s.as_ptr(), out_buf.cast(), count);
        *out_buf.add(count) = 0;
    }
    s.len()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!(
                hdds_rpc_client_service_name(ptr::null(), ptr::null_mut(), 0),
                0
            );

            // Server null checks
            assert!(hdds_rpc_server_create(
                ptr::null_mut(),
                ptr::null(),
                Some(null_handler),
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
            assert_eq!(
                hdds_rpc_server_service_name(ptr::null(), ptr::null_mut(), 0),
                0
            );

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
        let needed = unsafe { copy_str_to_buf("hello", buf.as_mut_ptr().cast(), 32) };
        assert_eq!(needed, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(buf[5], 0); // null terminator

        // Buffer too small
        let mut small = [0u8; 4];
        let needed = unsafe { copy_str_to_buf("hello", small.as_mut_ptr().cast(), 4) };
        assert_eq!(needed, 5); // still reports needed length
        assert_eq!(&small[..3], b"hel");
        assert_eq!(small[3], 0); // null terminator at capacity-1
    }

    #[test]
    fn test_exception_code_enum_matches_the_spec_and_the_core() {
        let pairs = [
            (HddsRpcExceptionCode::HddsRpcOk, RemoteExceptionCode::Ok),
            (
                HddsRpcExceptionCode::HddsRpcUnsupported,
                RemoteExceptionCode::Unsupported,
            ),
            (
                HddsRpcExceptionCode::HddsRpcInvalidArgument,
                RemoteExceptionCode::InvalidArgument,
            ),
            (
                HddsRpcExceptionCode::HddsRpcOutOfResources,
                RemoteExceptionCode::OutOfResources,
            ),
            (
                HddsRpcExceptionCode::HddsRpcUnknownOperation,
                RemoteExceptionCode::UnknownOperation,
            ),
            (
                HddsRpcExceptionCode::HddsRpcUnknownException,
                RemoteExceptionCode::UnknownException,
            ),
        ];
        for (expected, (c_code, core_code)) in (0i32..).zip(pairs) {
            assert_eq!(c_code as i32, expected);
            assert_eq!(core_code.as_i32(), expected);
        }
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
                return HddsRpcExceptionCode::HddsRpcInvalidArgument as i32;
            }
            let reply = libc::malloc(request_len) as *mut u8;
            if reply.is_null() {
                return HddsRpcExceptionCode::HddsRpcOutOfResources as i32;
            }
            ptr::copy_nonoverlapping(request, reply, request_len);
            *out_reply = reply;
            *out_reply_len = request_len;
            0
        }

        let bridge = CHandlerBridge {
            callback: Some(echo_handler),
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
            HddsRpcExceptionCode::HddsRpcInvalidArgument as i32
        }

        let bridge = CHandlerBridge {
            callback: Some(error_handler),
            user_data: ptr::null_mut(),
        };

        let result = bridge.handle(SampleIdentity::zero(), b"test");
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, RemoteExceptionCode::InvalidArgument);
    }

    #[test]
    fn test_c_handler_bridge_maps_codes_outside_the_spec_to_unknown_exception() {
        unsafe extern "C" fn stray_code_handler(
            _request: *const u8,
            _request_len: usize,
            _out_reply: *mut *mut u8,
            _out_reply_len: *mut usize,
            _user_data: *mut c_void,
        ) -> i32 {
            99
        }

        let bridge = CHandlerBridge {
            callback: Some(stray_code_handler),
            user_data: ptr::null_mut(),
        };

        let (code, _) = bridge.handle(SampleIdentity::zero(), b"test").unwrap_err();
        assert_eq!(code, RemoteExceptionCode::UnknownException);
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
            callback: Some(empty_handler),
            user_data: ptr::null_mut(),
        };

        let result = bridge.handle(SampleIdentity::zero(), b"test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
