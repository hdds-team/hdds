// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Micro C FFI Bindings
//!
//! C-compatible FFI bindings for HDDS Micro embedded DDS.
//! Designed for ESP32, RP2040, STM32, Arduino, and other microcontrollers.
//!
//! # Usage
//!
//! ```c
//! #include "hdds_micro.h"
//!
//! // Create transport (platform-specific UART)
//! HddsMicroTransport* transport = hdds_micro_transport_create_serial(
//!     uart_write_fn, uart_read_fn, user_data
//! );
//!
//! // Create participant
//! HddsMicroParticipant* participant = hdds_micro_participant_create(0, transport);
//!
//! // Create writer
//! HddsMicroWriter* writer = hdds_micro_writer_create(
//!     participant, "sensor/temperature", NULL
//! );
//!
//! // Write data
//! uint8_t buffer[64];
//! size_t len = hdds_micro_encode_f32(buffer, sizeof(buffer), 23.5f);
//! hdds_micro_write(writer, buffer, len);
//!
//! // Cleanup
//! hdds_micro_writer_destroy(writer);
//! hdds_micro_participant_destroy(participant);
//! hdds_micro_transport_destroy(transport);
//! ```

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_void, CStr};
use std::ptr;
use std::slice;

use hdds_micro::cdr::{CdrDecoder, CdrEncoder};
use hdds_micro::rtps::Locator;
use hdds_micro::transport::{NullTransport, Transport};
use hdds_micro::{Error, MicroParticipant, MicroReader, MicroWriter};

// =============================================================================
// ERROR CODES
// =============================================================================

/// Error codes returned by HDDS Micro functions
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsMicroError {
    /// Success (no error)
    Ok = 0,
    /// Invalid parameter
    InvalidParameter = 1,
    /// Buffer too small
    BufferTooSmall = 2,
    /// Transport error
    TransportError = 3,
    /// Timeout
    Timeout = 4,
    /// Resource exhausted
    ResourceExhausted = 5,
    /// Encoding error
    EncodingError = 6,
    /// Decoding error
    DecodingError = 7,
    /// Not initialized
    NotInitialized = 8,
    /// Null pointer
    NullPointer = 9,
    /// Unknown error
    Unknown = 255,
}

impl From<Error> for HddsMicroError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidParameter => HddsMicroError::InvalidParameter,
            Error::BufferTooSmall => HddsMicroError::BufferTooSmall,
            Error::TransportError => HddsMicroError::TransportError,
            Error::Timeout => HddsMicroError::Timeout,
            Error::ResourceExhausted => HddsMicroError::ResourceExhausted,
            Error::EncodingError => HddsMicroError::EncodingError,
            Error::DecodingError => HddsMicroError::DecodingError,
            _ => HddsMicroError::Unknown,
        }
    }
}

// =============================================================================
// OPAQUE HANDLES
// =============================================================================

/// Opaque handle to a Participant
#[repr(C)]
pub struct HddsMicroParticipant {
    _private: [u8; 0],
}

/// Opaque handle to a Writer
#[repr(C)]
pub struct HddsMicroWriter {
    _private: [u8; 0],
}

/// Opaque handle to a Reader
#[repr(C)]
pub struct HddsMicroReader {
    _private: [u8; 0],
}

/// Opaque handle to a Transport
#[repr(C)]
pub struct HddsMicroTransport {
    _private: [u8; 0],
}

// =============================================================================
// QOS CONFIGURATION
// =============================================================================

/// QoS profile for writers/readers
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HddsMicroQos {
    /// Reliability: 0 = BEST_EFFORT, 1 = RELIABLE
    pub reliability: u8,
    /// History depth (number of samples to keep)
    pub history_depth: u8,
}

impl Default for HddsMicroQos {
    fn default() -> Self {
        Self {
            reliability: 0, // BEST_EFFORT
            history_depth: 1,
        }
    }
}

// =============================================================================
// LOCATOR
// =============================================================================

/// Network locator (address + port)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HddsMicroLocator {
    /// Address (IPv4: last 4 bytes, IPv6: all 16 bytes)
    pub address: [u8; 16],
    /// Port number
    pub port: u32,
}

impl From<Locator> for HddsMicroLocator {
    fn from(loc: Locator) -> Self {
        Self {
            address: loc.address,
            port: loc.port,
        }
    }
}

impl From<HddsMicroLocator> for Locator {
    fn from(loc: HddsMicroLocator) -> Self {
        Locator {
            kind: 1, // UDPv4
            port: loc.port,
            address: loc.address,
        }
    }
}

// =============================================================================
// CALLBACK TRANSPORT
// =============================================================================

/// UART write callback: write(data, len, user_data) -> bytes_written
pub type UartWriteFn = unsafe extern "C" fn(*const u8, usize, *mut c_void) -> i32;

/// UART read callback: read(buf, max_len, timeout_ms, user_data) -> bytes_read
pub type UartReadFn = unsafe extern "C" fn(*mut u8, usize, u32, *mut c_void) -> i32;

/// Callback-based transport (wraps platform UART)
struct CallbackTransport {
    write_fn: UartWriteFn,
    read_fn: UartReadFn,
    user_data: *mut c_void,
    node_id: u8,
}

unsafe impl Send for CallbackTransport {}
unsafe impl Sync for CallbackTransport {}

impl Transport for CallbackTransport {
    fn init(&mut self) -> hdds_micro::Result<()> {
        Ok(())
    }

    fn send(&mut self, data: &[u8], _dest: &Locator) -> hdds_micro::Result<usize> {
        let written = unsafe { (self.write_fn)(data.as_ptr(), data.len(), self.user_data) };
        if written < 0 {
            return Err(Error::TransportError);
        }
        Ok(written as usize)
    }

    fn recv(&mut self, buf: &mut [u8]) -> hdds_micro::Result<(usize, Locator)> {
        let read = unsafe { (self.read_fn)(buf.as_mut_ptr(), buf.len(), 1000, self.user_data) };
        if read < 0 {
            return Err(Error::TransportError);
        }
        if read == 0 {
            return Err(Error::Timeout);
        }
        Ok((read as usize, Locator::udpv4([0, 0, 0, 0], 0)))
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> hdds_micro::Result<(usize, Locator)> {
        let read = unsafe { (self.read_fn)(buf.as_mut_ptr(), buf.len(), 0, self.user_data) };
        if read <= 0 {
            return Err(Error::ResourceExhausted);
        }
        Ok((read as usize, Locator::udpv4([0, 0, 0, 0], 0)))
    }

    fn local_locator(&self) -> Locator {
        Locator::udpv4([0, 0, 0, self.node_id], 0)
    }

    fn mtu(&self) -> usize {
        256
    }

    fn shutdown(&mut self) -> hdds_micro::Result<()> {
        Ok(())
    }
}

// =============================================================================
// BOXED TRANSPORT WRAPPER
// =============================================================================

/// Type-erased transport wrapper
struct BoxedTransport {
    inner: Box<dyn Transport + Send>,
}

impl Transport for BoxedTransport {
    fn init(&mut self) -> hdds_micro::Result<()> {
        self.inner.init()
    }

    fn send(&mut self, data: &[u8], dest: &Locator) -> hdds_micro::Result<usize> {
        self.inner.send(data, dest)
    }

    fn recv(&mut self, buf: &mut [u8]) -> hdds_micro::Result<(usize, Locator)> {
        self.inner.recv(buf)
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> hdds_micro::Result<(usize, Locator)> {
        self.inner.try_recv(buf)
    }

    fn local_locator(&self) -> Locator {
        self.inner.local_locator()
    }

    fn mtu(&self) -> usize {
        self.inner.mtu()
    }

    fn shutdown(&mut self) -> hdds_micro::Result<()> {
        self.inner.shutdown()
    }
}

// =============================================================================
// VERSION INFO
// =============================================================================

/// Get HDDS Micro version string
#[no_mangle]
pub extern "C" fn hdds_micro_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

// =============================================================================
// TRANSPORT API
// =============================================================================

/// Create a serial transport using callbacks
///
/// # Safety
///
/// - `write_fn` and `read_fn` must be valid function pointers
/// - `user_data` will be passed to callbacks, can be NULL
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_transport_create_serial(
    write_fn: UartWriteFn,
    read_fn: UartReadFn,
    node_id: u8,
    user_data: *mut c_void,
) -> *mut HddsMicroTransport {
    let transport = CallbackTransport {
        write_fn,
        read_fn,
        user_data,
        node_id,
    };

    let boxed = BoxedTransport {
        inner: Box::new(transport),
    };

    Box::into_raw(Box::new(boxed)) as *mut HddsMicroTransport
}

/// Create a null transport (for testing)
#[no_mangle]
pub extern "C" fn hdds_micro_transport_create_null() -> *mut HddsMicroTransport {
    let transport = BoxedTransport {
        inner: Box::new(NullTransport::default()),
    };
    Box::into_raw(Box::new(transport)) as *mut HddsMicroTransport
}

/// Destroy a transport
///
/// # Safety
///
/// - `transport` must be a valid pointer created by `hdds_micro_transport_create_*`
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_transport_destroy(transport: *mut HddsMicroTransport) {
    if !transport.is_null() {
        drop(Box::from_raw(transport as *mut BoxedTransport));
    }
}

// =============================================================================
// PARTICIPANT API
// =============================================================================

/// Create a new participant
///
/// # Safety
///
/// - `transport` must be a valid pointer created by `hdds_micro_transport_create_*`
/// - Takes ownership of transport (do not destroy transport separately)
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_participant_create(
    domain_id: u32,
    transport: *mut HddsMicroTransport,
) -> *mut HddsMicroParticipant {
    if transport.is_null() {
        return ptr::null_mut();
    }

    // Take ownership of transport
    let transport = Box::from_raw(transport as *mut BoxedTransport);

    match MicroParticipant::new(domain_id, *transport) {
        Ok(participant) => Box::into_raw(Box::new(participant)) as *mut HddsMicroParticipant,
        Err(_) => ptr::null_mut(),
    }
}

/// Get participant's domain ID
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_participant_domain_id(
    participant: *const HddsMicroParticipant,
) -> u32 {
    if participant.is_null() {
        return 0;
    }
    let p = &*(participant as *const MicroParticipant<BoxedTransport>);
    p.domain_id()
}

/// Destroy a participant
///
/// # Safety
///
/// - `participant` must be a valid pointer created by `hdds_micro_participant_create`
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_participant_destroy(participant: *mut HddsMicroParticipant) {
    if !participant.is_null() {
        let p = Box::from_raw(participant as *mut MicroParticipant<BoxedTransport>);
        let _ = p.shutdown();
    }
}

// =============================================================================
// WRITER API
// =============================================================================

/// Internal writer with reference to participant's transport
struct WriterHandle {
    writer: MicroWriter,
    participant: *mut MicroParticipant<BoxedTransport>,
}

/// Create a new writer
///
/// # Safety
///
/// - `participant` must be a valid pointer
/// - `topic_name` must be a valid null-terminated string
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_writer_create(
    participant: *mut HddsMicroParticipant,
    topic_name: *const c_char,
    _qos: *const HddsMicroQos,
) -> *mut HddsMicroWriter {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let topic = match CStr::from_ptr(topic_name).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let p = &mut *(participant as *mut MicroParticipant<BoxedTransport>);

    // Allocate entity ID
    let entity_id = p.allocate_entity_id(true);

    // Default destination (multicast)
    let dest = Locator::udpv4([239, 255, 0, 1], 7400);

    match MicroWriter::new(p.guid_prefix(), entity_id, topic, dest) {
        Ok(writer) => {
            let handle = WriterHandle {
                writer,
                participant: participant as *mut MicroParticipant<BoxedTransport>,
            };
            Box::into_raw(Box::new(handle)) as *mut HddsMicroWriter
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Write data
///
/// # Safety
///
/// - `writer` must be a valid pointer
/// - `data` must point to `len` bytes of valid data
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_write(
    writer: *mut HddsMicroWriter,
    data: *const u8,
    len: usize,
) -> HddsMicroError {
    if writer.is_null() || data.is_null() {
        return HddsMicroError::NullPointer;
    }

    let handle = &mut *(writer as *mut WriterHandle);
    let payload = slice::from_raw_parts(data, len);

    let participant = &mut *handle.participant;

    match handle.writer.write(payload, participant.transport_mut()) {
        Ok(_) => HddsMicroError::Ok,
        Err(e) => e.into(),
    }
}

/// Destroy a writer
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_writer_destroy(writer: *mut HddsMicroWriter) {
    if !writer.is_null() {
        drop(Box::from_raw(writer as *mut WriterHandle));
    }
}

// =============================================================================
// READER API
// =============================================================================

/// Internal reader with reference to participant's transport
struct ReaderHandle {
    reader: MicroReader,
    participant: *mut MicroParticipant<BoxedTransport>,
}

/// Sample info returned when reading data
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HddsMicroSampleInfo {
    /// Writer GUID prefix (12 bytes)
    pub writer_guid_prefix: [u8; 12],
    /// Writer entity ID (4 bytes)
    pub writer_entity_id: [u8; 4],
    /// Sequence number (i64)
    pub sequence_number: i64,
    /// Valid data flag (1 if payload contains data)
    pub valid_data: u8,
}

/// Create a new reader
///
/// # Safety
///
/// - `participant` must be a valid pointer
/// - `topic_name` must be a valid null-terminated string
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_reader_create(
    participant: *mut HddsMicroParticipant,
    topic_name: *const c_char,
    _qos: *const HddsMicroQos,
) -> *mut HddsMicroReader {
    if participant.is_null() || topic_name.is_null() {
        return ptr::null_mut();
    }

    let topic = match CStr::from_ptr(topic_name).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let p = &mut *(participant as *mut MicroParticipant<BoxedTransport>);

    // Allocate entity ID for reader (is_writer = false)
    let entity_id = p.allocate_entity_id(false);

    match MicroReader::new(p.guid_prefix(), entity_id, topic) {
        Ok(reader) => {
            let handle = ReaderHandle {
                reader,
                participant: participant as *mut MicroParticipant<BoxedTransport>,
            };
            Box::into_raw(Box::new(handle)) as *mut HddsMicroReader
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Read data (non-blocking)
///
/// Returns HDDS_MICRO_ERROR_OK if data was read, HDDS_MICRO_ERROR_TIMEOUT if no data available.
/// On success, `out_data` contains the payload and `out_len` contains the length.
/// `out_info` is filled with sample metadata if not NULL.
///
/// # Safety
///
/// - `reader` must be a valid pointer
/// - `out_data` must point to a buffer of at least `max_len` bytes
/// - `out_len` must be a valid pointer
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_read(
    reader: *mut HddsMicroReader,
    out_data: *mut u8,
    max_len: usize,
    out_len: *mut usize,
    out_info: *mut HddsMicroSampleInfo,
) -> HddsMicroError {
    if reader.is_null() || out_data.is_null() || out_len.is_null() {
        return HddsMicroError::NullPointer;
    }

    let handle = &mut *(reader as *mut ReaderHandle);
    let participant = &mut *handle.participant;

    match handle.reader.read(participant.transport_mut()) {
        Ok(Some(sample)) => {
            // Check buffer size
            if sample.payload.len() > max_len {
                return HddsMicroError::BufferTooSmall;
            }

            // Copy payload
            let out_buf = slice::from_raw_parts_mut(out_data, max_len);
            out_buf[..sample.payload.len()].copy_from_slice(sample.payload);
            *out_len = sample.payload.len();

            // Fill sample info if provided
            if !out_info.is_null() {
                let info = &mut *out_info;
                info.writer_guid_prefix = sample.writer_guid.prefix.0;
                info.writer_entity_id = sample.writer_guid.entity_id.0;
                info.sequence_number = sample.sequence_number.0;
                info.valid_data = 1;
            }

            HddsMicroError::Ok
        }
        Ok(None) => {
            // No data available
            *out_len = 0;
            HddsMicroError::Timeout
        }
        Err(e) => e.into(),
    }
}

/// Take data (non-blocking, same as read for BEST_EFFORT)
///
/// Alias for hdds_micro_read - in embedded BEST_EFFORT mode there's no difference.
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_take(
    reader: *mut HddsMicroReader,
    out_data: *mut u8,
    max_len: usize,
    out_len: *mut usize,
    out_info: *mut HddsMicroSampleInfo,
) -> HddsMicroError {
    hdds_micro_read(reader, out_data, max_len, out_len, out_info)
}

/// Get reader's topic name
///
/// # Safety
///
/// - `reader` must be a valid pointer
/// - `out_name` must point to a buffer of at least `max_len` bytes
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_reader_topic_name(
    reader: *const HddsMicroReader,
    out_name: *mut c_char,
    max_len: usize,
) -> i32 {
    if reader.is_null() || out_name.is_null() || max_len == 0 {
        return -1;
    }

    let handle = &*(reader as *const ReaderHandle);
    let topic = handle.reader.topic_name();

    if topic.len() >= max_len {
        return -1;
    }

    let out_buf = slice::from_raw_parts_mut(out_name as *mut u8, max_len);
    out_buf[..topic.len()].copy_from_slice(topic.as_bytes());
    out_buf[topic.len()] = 0; // Null terminator

    topic.len() as i32
}

/// Destroy a reader
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_reader_destroy(reader: *mut HddsMicroReader) {
    if !reader.is_null() {
        drop(Box::from_raw(reader as *mut ReaderHandle));
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Get error code description
///
/// Returns a static string describing the error code.
#[no_mangle]
pub extern "C" fn hdds_micro_error_str(error: HddsMicroError) -> *const c_char {
    let msg = match error {
        HddsMicroError::Ok => "Success\0",
        HddsMicroError::InvalidParameter => "Invalid parameter\0",
        HddsMicroError::BufferTooSmall => "Buffer too small\0",
        HddsMicroError::TransportError => "Transport error\0",
        HddsMicroError::Timeout => "Timeout (no data available)\0",
        HddsMicroError::ResourceExhausted => "Resource exhausted\0",
        HddsMicroError::EncodingError => "Encoding error\0",
        HddsMicroError::DecodingError => "Decoding error\0",
        HddsMicroError::NotInitialized => "Not initialized\0",
        HddsMicroError::NullPointer => "Null pointer\0",
        HddsMicroError::Unknown => "Unknown error\0",
    };
    msg.as_ptr() as *const c_char
}

// =============================================================================
// CDR ENCODING HELPERS
// =============================================================================

/// Encode a u8 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_u8(buf: *mut u8, buf_len: usize, value: u8) -> i32 {
    if buf.is_null() || buf_len == 0 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_u8(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode a u16 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_u16(buf: *mut u8, buf_len: usize, value: u16) -> i32 {
    if buf.is_null() || buf_len < 2 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_u16(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode a u32 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_u32(buf: *mut u8, buf_len: usize, value: u32) -> i32 {
    if buf.is_null() || buf_len < 4 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_u32(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode a u64 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_u64(buf: *mut u8, buf_len: usize, value: u64) -> i32 {
    if buf.is_null() || buf_len < 8 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_u64(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode a f32 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_f32(buf: *mut u8, buf_len: usize, value: f32) -> i32 {
    if buf.is_null() || buf_len < 4 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_f32(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode a f64 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_f64(buf: *mut u8, buf_len: usize, value: f64) -> i32 {
    if buf.is_null() || buf_len < 8 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_f64(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode bytes (raw data)
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_bytes(
    buf: *mut u8,
    buf_len: usize,
    data: *const u8,
    data_len: usize,
) -> i32 {
    if buf.is_null() || data.is_null() || buf_len < data_len {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let src = slice::from_raw_parts(data, data_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_bytes(src) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode an i8 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_i8(buf: *mut u8, buf_len: usize, value: i8) -> i32 {
    if buf.is_null() || buf_len == 0 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_i8(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode an i16 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_i16(buf: *mut u8, buf_len: usize, value: i16) -> i32 {
    if buf.is_null() || buf_len < 2 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_i16(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode an i32 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_i32(buf: *mut u8, buf_len: usize, value: i32) -> i32 {
    if buf.is_null() || buf_len < 4 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_i32(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode an i64 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_i64(buf: *mut u8, buf_len: usize, value: i64) -> i32 {
    if buf.is_null() || buf_len < 8 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_i64(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode a bool value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_bool(buf: *mut u8, buf_len: usize, value: bool) -> i32 {
    if buf.is_null() || buf_len == 0 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_bool(value) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

/// Encode a string (length-prefixed with null terminator)
///
/// # Safety
///
/// - `str_ptr` must be a valid null-terminated string
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_encode_string(
    buf: *mut u8,
    buf_len: usize,
    str_ptr: *const c_char,
) -> i32 {
    if buf.is_null() || str_ptr.is_null() {
        return -1;
    }
    let s = match CStr::from_ptr(str_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // Need 4 bytes for length + string bytes + 1 null terminator
    if buf_len < 4 + s.len() + 1 {
        return -1;
    }
    let buffer = slice::from_raw_parts_mut(buf, buf_len);
    let mut encoder = CdrEncoder::new(buffer);
    match encoder.encode_string(s) {
        Ok(_) => encoder.position() as i32,
        Err(_) => -1,
    }
}

// =============================================================================
// CDR DECODING HELPERS
// =============================================================================

/// Decode a u8 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_u8(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut u8,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len == 0 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_u8() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode a u16 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_u16(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut u16,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 2 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_u16() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode a u32 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_u32(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut u32,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 4 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_u32() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode a f32 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_f32(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut f32,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 4 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_f32() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode a u64 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_u64(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut u64,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 8 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_u64() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode an i8 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_i8(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut i8,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len == 0 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_i8() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode an i16 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_i16(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut i16,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 2 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_i16() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode an i32 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_i32(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut i32,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 4 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_i32() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode an i64 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_i64(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut i64,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 8 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_i64() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode an f64 value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_f64(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut f64,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len < 8 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_f64() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode a bool value
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_bool(
    buf: *const u8,
    buf_len: usize,
    out_value: *mut bool,
) -> i32 {
    if buf.is_null() || out_value.is_null() || buf_len == 0 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_bool() {
        Ok(v) => {
            *out_value = v;
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode a string (length-prefixed with null terminator)
///
/// Copies the decoded string into `out_str` buffer and null-terminates it.
/// Returns the number of bytes consumed from `buf`, or -1 on error.
///
/// # Safety
///
/// - `out_str` must point to a buffer of at least `max_len` bytes
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_string(
    buf: *const u8,
    buf_len: usize,
    out_str: *mut c_char,
    max_len: usize,
) -> i32 {
    if buf.is_null() || out_str.is_null() || buf_len < 4 || max_len == 0 {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_string_borrowed() {
        Ok(s) => {
            if s.len() >= max_len {
                return -1; // Buffer too small
            }
            let out_buf = slice::from_raw_parts_mut(out_str as *mut u8, max_len);
            out_buf[..s.len()].copy_from_slice(s.as_bytes());
            out_buf[s.len()] = 0; // Null terminator
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

/// Decode raw bytes
///
/// Copies `count` bytes from `buf` into `out_data`.
/// Returns the number of bytes consumed, or -1 on error.
///
/// # Safety
///
/// - `out_data` must point to a buffer of at least `count` bytes
#[no_mangle]
pub unsafe extern "C" fn hdds_micro_decode_bytes(
    buf: *const u8,
    buf_len: usize,
    out_data: *mut u8,
    count: usize,
) -> i32 {
    if buf.is_null() || out_data.is_null() || buf_len < count {
        return -1;
    }
    let buffer = slice::from_raw_parts(buf, buf_len);
    let mut decoder = CdrDecoder::new(buffer);
    match decoder.decode_bytes(count) {
        Ok(bytes) => {
            let out_buf = slice::from_raw_parts_mut(out_data, count);
            out_buf.copy_from_slice(bytes);
            decoder.position() as i32
        }
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let v = hdds_micro_version();
        assert!(!v.is_null());
    }

    #[test]
    fn test_null_transport() {
        let transport = hdds_micro_transport_create_null();
        assert!(!transport.is_null());

        unsafe {
            let participant = hdds_micro_participant_create(0, transport);
            assert!(!participant.is_null());

            let domain = hdds_micro_participant_domain_id(participant);
            assert_eq!(domain, 0);

            hdds_micro_participant_destroy(participant);
        }
    }

    #[test]
    fn test_encode_decode() {
        let mut buf = [0u8; 64];

        unsafe {
            // Encode
            let len = hdds_micro_encode_f32(buf.as_mut_ptr(), buf.len(), 23.5);
            assert!(len > 0);

            // Decode
            let mut value: f32 = 0.0;
            let read = hdds_micro_decode_f32(buf.as_ptr(), len as usize, &mut value);
            assert!(read > 0);
            assert!((value - 23.5).abs() < 0.01);
        }
    }
}
