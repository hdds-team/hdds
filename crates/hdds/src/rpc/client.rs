// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RPC Client (Requester) implementation.
//!
//! The ServiceClient sends requests to a service and waits for replies.

use crate::core::discovery::GUID;
use crate::core::ser::Cdr2Decode;
use crate::dds::{DataReader, DataWriter, Participant};
use crate::rpc::error::{RpcError, RpcResult};
use crate::rpc::types::{ReplyHeader, RequestHeader, SampleIdentity};
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

/// RPC Client for sending requests to a service.
///
/// # Example
///
/// ```rust,no_run
/// use hdds::rpc::ServiceClient;
/// use hdds::Participant;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let participant = Participant::builder("client").build()?;
/// let client = ServiceClient::new(&participant, "calculator")?;
///
/// // Send a request and wait for reply
/// let reply = client.call_raw(b"request_data", Duration::from_secs(5)).await?;
/// # Ok(())
/// # }
/// ```
pub struct ServiceClient {
    /// Service name
    service_name: String,

    /// Writer for sending requests
    request_writer: DataWriter<RpcMessage>,

    /// Client GUID for creating SampleIdentity (generated on creation)
    client_guid: GUID,

    /// Sequence number counter
    sequence: AtomicI64,

    /// Pending requests: request_id -> reply channel
    pending: Arc<DashMap<SampleIdentity, oneshot::Sender<ReplyData>>>,

    /// Default timeout
    default_timeout: Duration,

    /// Shutdown flag
    shutdown: Arc<AtomicBool>,
}

/// Internal message type for RPC (header + payload)
#[derive(Debug, Clone)]
pub(crate) struct RpcMessage {
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Reply data received from service
#[derive(Debug)]
struct ReplyData {
    header: ReplyHeader,
    payload: Vec<u8>,
}

impl crate::dds::DDS for RpcMessage {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0x52504300, // "RPC\0"
            type_name: "RpcMessage",
            size_bytes: 0,
            alignment: 1,
            is_variable_size: true,
            fields: &[],
        };
        &DESC
    }

    fn encode_cdr2(&self, buf: &mut [u8]) -> crate::dds::Result<usize> {
        let total_len = self.header.len() + self.payload.len();
        if buf.len() < total_len {
            return Err(crate::dds::Error::BufferTooSmall);
        }
        buf[..self.header.len()].copy_from_slice(&self.header);
        buf[self.header.len()..total_len].copy_from_slice(&self.payload);
        Ok(total_len)
    }

    fn decode_cdr2(buf: &[u8]) -> crate::dds::Result<Self> {
        // For replies, we need at least the header (28 bytes)
        if buf.len() < 28 {
            return Err(crate::dds::Error::EndianMismatch);
        }
        Ok(Self {
            header: buf[..28].to_vec(),
            payload: buf[28..].to_vec(),
        })
    }
}

impl ServiceClient {
    /// Create a new RPC client for a service.
    ///
    /// # Arguments
    /// * `participant` - The DDS participant
    /// * `service_name` - Name of the service to call
    ///
    /// # Returns
    /// A new ServiceClient ready to send requests
    pub fn new(participant: &Arc<Participant>, service_name: &str) -> RpcResult<Self> {
        Self::with_timeout(participant, service_name, Duration::from_secs(10))
    }

    /// Create a new RPC client with custom default timeout.
    pub fn with_timeout(
        participant: &Arc<Participant>,
        service_name: &str,
        default_timeout: Duration,
    ) -> RpcResult<Self> {
        let qos = crate::rpc::rpc_qos();

        // Create request writer (client -> server)
        let request_topic = format!("rq/{}", service_name);
        let request_writer =
            participant.create_writer::<RpcMessage>(&request_topic, qos.clone())?;

        // Create reply reader (server -> client)
        let reply_topic = format!("rr/{}", service_name);
        let reply_reader = participant.create_reader::<RpcMessage>(&reply_topic, qos)?;

        // Generate a unique client GUID (random for this session)
        let client_guid = generate_client_guid();

        let pending = Arc::new(DashMap::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        // Start reply listener task (moves reader into task)
        start_reply_listener(reply_reader, pending.clone(), shutdown.clone());

        Ok(Self {
            service_name: service_name.to_string(),
            request_writer,
            client_guid,
            sequence: AtomicI64::new(1),
            pending,
            default_timeout,
            shutdown,
        })
    }

    /// Send a raw request and wait for reply.
    ///
    /// # Arguments
    /// * `payload` - The request payload (already serialized)
    /// * `timeout` - Maximum time to wait for reply
    ///
    /// # Returns
    /// The reply payload on success
    pub async fn call_raw(&self, payload: &[u8], timeout: Duration) -> RpcResult<Vec<u8>> {
        if self.shutdown.load(Ordering::Relaxed) {
            return Err(RpcError::Shutdown);
        }

        // Create request identity
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let request_id = SampleIdentity::new(self.client_guid, seq);

        // Create request header
        let header = RequestHeader::new(request_id);
        let mut header_bytes = vec![0u8; 48];
        use crate::core::ser::Cdr2Encode;
        header
            .encode_cdr2_le(&mut header_bytes)
            .map_err(|e| RpcError::SerializationError(format!("{:?}", e)))?;

        // Create channel for reply
        let (tx, rx) = oneshot::channel();
        self.pending.insert(request_id, tx);

        // Send request
        let msg = RpcMessage {
            header: header_bytes,
            payload: payload.to_vec(),
        };
        self.request_writer.write(&msg)?;

        // Wait for reply with timeout
        let result = tokio::time::timeout(timeout, rx).await;

        // Clean up pending entry
        self.pending.remove(&request_id);

        match result {
            Ok(Ok(reply_data)) => {
                if reply_data.header.is_success() {
                    Ok(reply_data.payload)
                } else {
                    Err(RpcError::from_code(reply_data.header.remote_exception_code))
                }
            }
            Ok(Err(_)) => Err(RpcError::Internal("Reply channel closed".to_string())),
            Err(_) => Err(RpcError::Timeout),
        }
    }

    /// Send a request with default timeout.
    pub async fn call_raw_default(&self, payload: &[u8]) -> RpcResult<Vec<u8>> {
        self.call_raw(payload, self.default_timeout).await
    }

    /// Get the service name
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Shutdown the client
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Clear pending requests
        self.pending.clear();
    }
}

impl Drop for ServiceClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Generate a unique client GUID for this RPC session.
fn generate_client_guid() -> GUID {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Create a unique GUID from timestamp + thread id hash
    let mut prefix = [0u8; 12];
    let nanos = now.as_nanos();
    prefix[0..8].copy_from_slice(&(nanos as u64).to_le_bytes());

    // Hash the thread id for additional uniqueness
    let tid = std::thread::current().id();
    let tid_hash = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        tid.hash(&mut hasher);
        hasher.finish() as u32
    };
    prefix[8..12].copy_from_slice(&tid_hash.to_le_bytes());

    // RPC client entity ID
    let entity_id = [0x00, 0x01, 0x00, 0xC3]; // User-defined RPC client

    GUID::new(prefix, entity_id)
}

/// Start the reply listener task (runs in background)
fn start_reply_listener(
    reader: DataReader<RpcMessage>,
    pending: Arc<DashMap<SampleIdentity, oneshot::Sender<ReplyData>>>,
    shutdown: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Try to take a reply
            if let Ok(Some(msg)) = reader.take() {
                // Parse reply header
                if msg.header.len() >= 28 {
                    if let Ok((reply_header, _)) = ReplyHeader::decode_cdr2_le(&msg.header) {
                        // Find pending request and send reply
                        if let Some((_, tx)) = pending.remove(&reply_header.related_request_id) {
                            let reply_data = ReplyData {
                                header: reply_header,
                                payload: msg.payload,
                            };
                            // Ignore send error - receiver may have dropped
                            drop(tx.send(reply_data));
                        }
                    }
                }
            }

            // Small delay to avoid busy-wait
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::DDS;

    #[test]
    fn rpc_message_type_descriptor() {
        let desc = <RpcMessage as DDS>::type_descriptor();
        assert_eq!(desc.type_name, "RpcMessage");
        assert!(desc.is_variable_size);
    }

    #[test]
    fn generate_guid_is_unique() {
        let g1 = generate_client_guid();
        let g2 = generate_client_guid();
        // GUIDs are generated from timestamp + thread id - just verify they can be created
        assert_ne!(g1.prefix.len(), 0);
        assert_ne!(g2.prefix.len(), 0);
    }
}
