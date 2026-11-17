// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! C ABI over the browser-side SDK, for the hand-written JavaScript glue.
//!
//! No `wasm-bindgen`: the module exports plain `extern "C"` functions and its
//! linear memory, and `js/hdds-wasm.js` drives them. That keeps the
//! dependency list empty and the artefact readable by any WebAssembly host
//! (the gate uses node, a browser needs nothing else).
//!
//! Calling convention:
//! - buffers are (pointer, length) pairs into the module's own memory,
//!   allocated by [`hdds_wasm_alloc`] and released by [`hdds_wasm_free`];
//! - builders return the number of bytes written into the output buffer, or a
//!   negative [`error code`](ERR_NULL_ARG) on failure. They never panic and
//!   never write past `out_cap`.

use core::slice;

use crate::cdr::{CdrDecoder, CdrEncoder};
use crate::participant::WasmParticipant;
use crate::protocol::RelayMessage;

// Error codes returned in place of a length.
/// A required pointer argument was null.
pub const ERR_NULL_ARG: i32 = -1;
/// The output buffer is too small for the message.
pub const ERR_BUFFER_TOO_SMALL: i32 = -2;
/// The protocol operation failed (unknown topic, not connected, bad bytes).
pub const ERR_PROTOCOL: i32 = -3;
/// The bytes are not valid UTF-8 where a string was required.
pub const ERR_UTF8: i32 = -4;

// Event codes returned by `hdds_wasm_process`.
/// The relay acknowledged the connection.
pub const EVENT_CONNECT_ACK: i32 = 1;
/// The relay acknowledged a topic; the topic id is in the out buffer.
pub const EVENT_TOPIC_ACK: i32 = 2;
/// A sample arrived; the out buffer holds topic id then payload.
pub const EVENT_DATA: i32 = 3;
/// Keepalive answer.
pub const EVENT_PONG: i32 = 4;
/// The relay reported an error; the out buffer holds the reason text.
pub const EVENT_ERROR: i32 = 5;
/// The relay closed the session.
pub const EVENT_DISCONNECTED: i32 = 6;
/// A message this side does not act on.
pub const EVENT_OTHER: i32 = 7;

/// The layout every [`hdds_wasm_alloc`] block is allocated and freed with.
///
/// Byte-aligned and exactly `len` long, so allocation and deallocation name
/// the SAME layout. Going through `Vec` instead would only guarantee a
/// capacity of at least `len`, and freeing with a layout the allocator did
/// not hand out is undefined behaviour even when it happens to work.
fn block_layout(len: usize) -> Option<core::alloc::Layout> {
    core::alloc::Layout::from_size_align(len, 1).ok()
}

/// Allocate `len` bytes inside the module's linear memory.
///
/// Returns null for a zero length. The caller owns the block until it hands
/// it back to [`hdds_wasm_free`] with the same length.
#[no_mangle]
pub extern "C" fn hdds_wasm_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return core::ptr::null_mut();
    }
    let Some(layout) = block_layout(len) else {
        return core::ptr::null_mut();
    };
    // SAFETY: layout has a non-zero size (len != 0 above).
    unsafe { std::alloc::alloc(layout) }
}

/// Release a block obtained from [`hdds_wasm_alloc`].
///
/// # Safety
/// `ptr` must come from [`hdds_wasm_alloc`] with exactly this `len`, and must
/// not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let Some(layout) = block_layout(len) else {
        return;
    };
    // SAFETY: the contract above says ptr came from hdds_wasm_alloc with this
    // len, so it was allocated with exactly this layout.
    unsafe { std::alloc::dealloc(ptr, layout) };
}

/// Create a participant for `domain_id`. Free it with
/// [`hdds_wasm_participant_free`].
#[no_mangle]
pub extern "C" fn hdds_wasm_participant_new(domain_id: u16) -> *mut WasmParticipant {
    Box::into_raw(Box::new(WasmParticipant::new(domain_id)))
}

/// Destroy a participant.
///
/// # Safety
/// `p` must come from [`hdds_wasm_participant_new`] and must not be used again.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_participant_free(p: *mut WasmParticipant) {
    if p.is_null() {
        return;
    }
    // SAFETY: the contract above says p came from Box::into_raw.
    drop(unsafe { Box::from_raw(p) });
}

/// True once the relay has answered CONNECT.
///
/// # Safety
/// `p` must be a live participant pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_is_connected(p: *const WasmParticipant) -> i32 {
    if p.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees p is live.
    i32::from(unsafe { &*p }.connected)
}

/// Relay-assigned id of a topic previously acknowledged, or -1.
///
/// # Safety
/// `p` must be live and `name` must point at `name_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_topic_id(
    p: *const WasmParticipant,
    name: *const u8,
    name_len: usize,
) -> i32 {
    if p.is_null() || name.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees the pointer/length pair is readable.
    let bytes = unsafe { slice::from_raw_parts(name, name_len) };
    let Ok(topic) = core::str::from_utf8(bytes) else {
        return ERR_UTF8;
    };
    // SAFETY: caller guarantees p is live.
    match unsafe { &*p }.topics.get(topic) {
        Some(&id) => i32::from(id),
        None => ERR_PROTOCOL,
    }
}

/// Copy `bytes` into the output buffer, or report why it did not fit.
///
/// # Safety
/// `out` must point at `out_cap` writable bytes.
unsafe fn write_out(bytes: &[u8], out: *mut u8, out_cap: usize) -> i32 {
    if out.is_null() {
        return ERR_NULL_ARG;
    }
    if bytes.len() > out_cap {
        return ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: length checked against out_cap just above; the source is a live
    // slice and the regions do not overlap (out comes from hdds_wasm_alloc).
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len() as i32
}

/// Build a CONNECT message into `out`.
///
/// # Safety
/// `p` must be live, `out` must point at `out_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_build_connect(
    p: *mut WasmParticipant,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if p.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees p is live and exclusively borrowed here.
    let msg = unsafe { &mut *p }.build_connect();
    // SAFETY: caller guarantees out/out_cap.
    unsafe { write_out(&msg, out, out_cap) }
}

/// Build a CREATE_TOPIC message into `out`.
///
/// # Safety
/// All pointer/length pairs must be valid for their stated length.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_build_create_topic(
    p: *mut WasmParticipant,
    name: *const u8,
    name_len: usize,
    type_name: *const u8,
    type_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if p.is_null() || name.is_null() || type_name.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees both pointer/length pairs are readable.
    let (name_bytes, type_bytes) = unsafe {
        (
            slice::from_raw_parts(name, name_len),
            slice::from_raw_parts(type_name, type_len),
        )
    };
    let (Ok(name), Ok(type_name)) = (
        core::str::from_utf8(name_bytes),
        core::str::from_utf8(type_bytes),
    ) else {
        return ERR_UTF8;
    };
    // SAFETY: caller guarantees p is live.
    let msg = unsafe { &mut *p }.build_create_topic(name, type_name);
    // SAFETY: caller guarantees out/out_cap.
    unsafe { write_out(&msg, out, out_cap) }
}

/// Register a reader and build a SUBSCRIBE message into `out`.
///
/// # Safety
/// `p` must be live, `out` must point at `out_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_build_subscribe(
    p: *mut WasmParticipant,
    topic_id: u16,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if p.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees p is live.
    let participant = unsafe { &mut *p };
    let _ = participant.create_reader(topic_id);
    let msg = participant.build_subscribe(topic_id);
    // SAFETY: caller guarantees out/out_cap.
    unsafe { write_out(&msg, out, out_cap) }
}

/// Register a writer and build a PUBLISH message carrying `data`.
///
/// # Safety
/// All pointer/length pairs must be valid for their stated length.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_build_publish(
    p: *mut WasmParticipant,
    topic_id: u16,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if p.is_null() || data.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees the payload pointer/length pair is readable.
    let payload = unsafe { slice::from_raw_parts(data, data_len) };
    // SAFETY: caller guarantees p is live.
    let participant = unsafe { &mut *p };
    let _ = participant.create_writer(topic_id);
    let Ok(msg) = participant.build_publish(topic_id, payload) else {
        return ERR_PROTOCOL;
    };
    // SAFETY: caller guarantees out/out_cap.
    unsafe { write_out(&msg, out, out_cap) }
}

/// Feed one relay message to the participant.
///
/// Returns an `EVENT_*` code. The out buffer receives, depending on the
/// event: nothing (CONNECT_ACK, PONG, DISCONNECTED, OTHER), the topic id as
/// two little-endian bytes (TOPIC_ACK), the topic id followed by the CDR
/// payload (DATA), or the reason text (ERROR). `out_len` receives how many
/// bytes were written.
///
/// # Safety
/// All pointer/length pairs must be valid for their stated length.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_process(
    p: *mut WasmParticipant,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    if p.is_null() || msg.is_null() || out_len.is_null() || out.is_null() {
        return ERR_NULL_ARG;
    }
    // process_message MUTATES the participant (connection state, topic ids,
    // reader counters), so the output buffer is checked BEFORE it runs.
    // Otherwise the glue's documented "retry with a bigger buffer" would push
    // the same relay frame through the state machine a second time.
    //
    // Every event writes at most two bytes of topic id plus a slice of the
    // frame itself, so a buffer that can hold the frame plus two bytes can
    // hold any outcome.
    if out_cap < msg_len.saturating_add(2) {
        return ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: caller guarantees the message pointer/length pair is readable.
    let bytes = unsafe { slice::from_raw_parts(msg, msg_len) };
    // SAFETY: caller guarantees p is live.
    let participant = unsafe { &mut *p };
    let Ok(parsed) = participant.process_message(bytes) else {
        return ERR_PROTOCOL;
    };

    let (code, payload): (i32, Vec<u8>) = match parsed {
        RelayMessage::ConnectAck { .. } => (EVENT_CONNECT_ACK, Vec::new()),
        RelayMessage::TopicAck { topic_id, .. } => {
            (EVENT_TOPIC_ACK, topic_id.to_le_bytes().to_vec())
        }
        RelayMessage::Data {
            topic_id, payload, ..
        } => {
            let mut buf = topic_id.to_le_bytes().to_vec();
            buf.extend_from_slice(&payload);
            (EVENT_DATA, buf)
        }
        RelayMessage::Pong { .. } => (EVENT_PONG, Vec::new()),
        RelayMessage::Error { reason } => (EVENT_ERROR, reason.into_bytes()),
        RelayMessage::Disconnected => (EVENT_DISCONNECTED, Vec::new()),
        _ => (EVENT_OTHER, Vec::new()),
    };

    // SAFETY: caller guarantees out/out_cap.
    let written = unsafe { write_out(&payload, out, out_cap) };
    if written < 0 {
        return written;
    }
    // SAFETY: caller guarantees out_len points at a writable usize.
    unsafe { *out_len = written as usize };
    code
}

// ---------------------------------------------------------------------------
// CDR helpers
// ---------------------------------------------------------------------------

/// Create a CDR encoder. Free it with [`hdds_wasm_cdr_encoder_free`].
#[no_mangle]
pub extern "C" fn hdds_wasm_cdr_encoder_new() -> *mut CdrEncoder {
    Box::into_raw(Box::new(CdrEncoder::new()))
}

/// Destroy a CDR encoder without reading its bytes.
///
/// # Safety
/// `e` must come from [`hdds_wasm_cdr_encoder_new`] and not be used again.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_cdr_encoder_free(e: *mut CdrEncoder) {
    if e.is_null() {
        return;
    }
    // SAFETY: the contract above says e came from Box::into_raw.
    drop(unsafe { Box::from_raw(e) });
}

macro_rules! cdr_push {
    ($name:ident, $method:ident, $ty:ty) => {
        /// Append one value to the encoder.
        ///
        /// # Safety
        /// `e` must be a live encoder pointer.
        #[no_mangle]
        pub unsafe extern "C" fn $name(e: *mut CdrEncoder, v: $ty) -> i32 {
            if e.is_null() {
                return ERR_NULL_ARG;
            }
            // SAFETY: caller guarantees e is live and exclusively borrowed.
            unsafe { &mut *e }.$method(v);
            0
        }
    };
}

cdr_push!(hdds_wasm_cdr_encode_u32, encode_u32, u32);
cdr_push!(hdds_wasm_cdr_encode_i32, encode_i32, i32);
cdr_push!(hdds_wasm_cdr_encode_u64, encode_u64, u64);
cdr_push!(hdds_wasm_cdr_encode_f32, encode_f32, f32);
cdr_push!(hdds_wasm_cdr_encode_f64, encode_f64, f64);

/// Append a UTF-8 string to the encoder.
///
/// # Safety
/// `e` must be live and `s` must point at `s_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_cdr_encode_string(
    e: *mut CdrEncoder,
    s: *const u8,
    s_len: usize,
) -> i32 {
    if e.is_null() || s.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees the pointer/length pair is readable.
    let bytes = unsafe { slice::from_raw_parts(s, s_len) };
    let Ok(text) = core::str::from_utf8(bytes) else {
        return ERR_UTF8;
    };
    // SAFETY: caller guarantees e is live.
    unsafe { &mut *e }.encode_string(text);
    0
}

/// Bytes the encoder currently holds, so a caller can size its buffer before
/// calling [`hdds_wasm_cdr_encoder_finish`].
///
/// # Safety
/// `e` must be a live encoder pointer.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_cdr_encoder_len(e: *const CdrEncoder) -> i32 {
    if e.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees e is live.
    unsafe { &*e }.len() as i32
}

/// Consume the encoder and copy its bytes into `out`.
///
/// The encoder is freed ONLY when the bytes were delivered. On
/// [`ERR_BUFFER_TOO_SMALL`] it is still alive and the handle is still valid,
/// so the caller can grow its buffer (or ask
/// [`hdds_wasm_cdr_encoder_len`] first) and call again. Freeing on that path
/// would hand the caller a dangling handle for the retry the calling
/// convention documents.
///
/// # Safety
/// `e` must be live, `out` must point at `out_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_cdr_encoder_finish(
    e: *mut CdrEncoder,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if e.is_null() {
        return ERR_NULL_ARG;
    }
    if out.is_null() {
        return ERR_NULL_ARG;
    }
    // Peek without taking ownership: the encoder must survive a refusal.
    // SAFETY: caller guarantees e is live.
    if unsafe { &*e }.len() > out_cap {
        return ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: the contract above says e came from Box::into_raw.
    let encoder = unsafe { Box::from_raw(e) };
    let bytes = encoder.finish();
    // SAFETY: caller guarantees out/out_cap, and the length was checked.
    unsafe { write_out(&bytes, out, out_cap) }
}

/// Decode a `(u32, f64, string)` tuple, the shape the browser example uses,
/// writing `u32` then `f64` then the UTF-8 string into `out`.
///
/// This exists so the node gate can prove a real CDR round trip through the
/// glue without a code generator; typed decoding in the browser is done by
/// the application on top of the primitive decoders.
///
/// # Safety
/// All pointer/length pairs must be valid for their stated length.
#[no_mangle]
pub unsafe extern "C" fn hdds_wasm_cdr_decode_u32_f64_string(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if data.is_null() {
        return ERR_NULL_ARG;
    }
    // SAFETY: caller guarantees the pointer/length pair is readable.
    let bytes = unsafe { slice::from_raw_parts(data, data_len) };
    let mut decoder = CdrDecoder::new(bytes);
    let (Ok(a), Ok(b), Ok(c)) = (
        decoder.decode_u32(),
        decoder.decode_f64(),
        decoder.decode_string(),
    ) else {
        return ERR_PROTOCOL;
    };
    let mut buf = Vec::with_capacity(12 + c.len());
    buf.extend_from_slice(&a.to_le_bytes());
    buf.extend_from_slice(&b.to_le_bytes());
    buf.extend_from_slice(c.as_bytes());
    // SAFETY: caller guarantees out/out_cap.
    unsafe { write_out(&buf, out, out_cap) }
}
