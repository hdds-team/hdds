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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// RPC type identifier: ASCII "RPC\0" as u32
const RPC_TYPE_ID: u32 = 0x5250_4300;

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

    /// Serialize request admission with shutdown.
    admission: Mutex<()>,

    /// Default timeout
    default_timeout: Duration,

    /// Shutdown flag
    shutdown: Arc<AtomicBool>,
}

/// Opaque RPC wire body. The receiving endpoint knows the header type.
#[derive(Debug, Clone)]
pub(crate) struct RpcMessage {
    pub bytes: Vec<u8>,
}

/// Reply data received from service
#[derive(Debug)]
struct ReplyData {
    header: ReplyHeader,
    payload: Vec<u8>,
}

/// Remove the sender even when the caller drops the request future.
struct PendingRequest<'a> {
    requests: &'a DashMap<SampleIdentity, oneshot::Sender<ReplyData>>,
    id: SampleIdentity,
}

impl Drop for PendingRequest<'_> {
    fn drop(&mut self) {
        self.requests.remove(&self.id);
    }
}

impl crate::dds::DDS for RpcMessage {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: RPC_TYPE_ID,
            type_name: "RpcMessage",
            size_bytes: 0,
            alignment: 1,
            is_variable_size: true,
            fields: &[],
        };
        &DESC
    }

    fn encode(
        &self,
        buf: &mut [u8],
        _version: crate::dds::CdrVersion,
    ) -> crate::dds::Result<usize> {
        if buf.len() < self.bytes.len() {
            return Err(crate::dds::Error::BufferTooSmall);
        }
        buf[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }

    fn decode(buf: &[u8], _version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        // Request and reply headers have different sizes. Validate and split
        // them in the respective endpoint, without changing the wire format.
        Ok(Self {
            bytes: buf.to_vec(),
        })
    }

    /// Opaque bytes the RPC layer encodes in classic CDR: the RPC topics are
    /// pinned to XCDR1 (`rpc_qos`, DDS-RPC 1.0 Basic mapping), which must not
    /// be refused for the type.
    fn encodes_xcdr1_natively() -> bool {
        true
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
    ///
    /// Uses the HDDS default topic names; see [`Self::with_topic_names`]
    /// to point at a peer using a different convention (module's Topic
    /// Naming section).
    pub fn with_timeout(
        participant: &Arc<Participant>,
        service_name: &str,
        default_timeout: Duration,
    ) -> RpcResult<Self> {
        Self::with_topic_names(
            participant,
            service_name,
            &format!("rq/{}", service_name),
            &format!("rr/{}", service_name),
            default_timeout,
        )
    }

    /// Create a new RPC client using explicit request/reply topic names,
    /// instead of the HDDS `rq/{service_name}` / `rr/{service_name}`
    /// default. Both ends of an RPC exchange must agree on the topic names
    /// regardless of how each picked them (DDS-RPC 1.0 clause 7.4.2).
    ///
    /// # Arguments
    /// * `participant` - The DDS participant
    /// * `service_name` - Name of the service (used only for
    ///   diagnostics; the topics are named explicitly)
    /// * `request_topic` - Topic carrying client -> server requests
    /// * `reply_topic` - Topic carrying server -> client replies
    /// * `default_timeout` - Default per-call timeout
    pub fn with_topic_names(
        participant: &Arc<Participant>,
        service_name: &str,
        request_topic: &str,
        reply_topic: &str,
        default_timeout: Duration,
    ) -> RpcResult<Self> {
        tokio::runtime::Handle::try_current()
            .map_err(|_| RpcError::Internal("RPC client requires a Tokio runtime".into()))?;
        let qos = crate::rpc::rpc_qos();

        // Create request writer (client -> server)
        let request_writer = participant
            .topic::<RpcMessage>(request_topic)?
            .writer()
            .qos(qos.clone())
            .build()?;

        // Create reply reader (server -> client)
        let reply_reader = participant
            .topic::<RpcMessage>(reply_topic)?
            .reader()
            .qos(qos)
            .build()?;

        let client_guid = request_writer.rpc_endpoint_guid().ok_or_else(|| {
            RpcError::Internal("RPC request writer has no endpoint identity".into())
        })?;

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
            admission: Mutex::new(()),
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
        if self.shutdown.load(Ordering::Acquire) {
            return Err(RpcError::Shutdown);
        }

        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| RpcError::Internal("RPC timeout exceeds clock range".into()))?;

        // Create request identity
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let request_id = SampleIdentity::new(self.client_guid, seq);

        // Create request header
        use crate::core::ser::Cdr2Encode;
        let header = RequestHeader::new(request_id);
        let mut header_bytes = vec![0u8; header.max_cdr2_size()];
        let written = header
            .encode_cdr2_le(&mut header_bytes)
            .map_err(|e| RpcError::SerializationError(format!("{:?}", e)))?;
        header_bytes.truncate(written);

        // Create channel for reply
        let (tx, rx) = oneshot::channel();
        {
            let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
            if self.shutdown.load(Ordering::Acquire) {
                return Err(RpcError::Shutdown);
            }
            self.pending.insert(request_id, tx);
        }
        let _pending = PendingRequest {
            requests: &self.pending,
            id: request_id,
        };

        // Send request
        header_bytes.extend_from_slice(payload);
        let msg = RpcMessage {
            bytes: header_bytes,
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(RpcError::Timeout);
        }
        if let Err(e) = self.request_writer.write(&msg) {
            return Err(e.into());
        }

        // Wait for reply with timeout
        let result = tokio::time::timeout_at(deadline, rx).await;

        match result {
            Ok(Ok(reply_data)) => {
                if reply_data.header.is_success() {
                    Ok(reply_data.payload)
                } else {
                    Err(RpcError::from_code(reply_data.header.remote_exception_code))
                }
            }
            Ok(Err(_)) if self.shutdown.load(Ordering::Acquire) => Err(RpcError::Shutdown),
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
        let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.shutdown.store(true, Ordering::Release);
        // Clear pending requests
        self.pending.clear();
    }
}

impl Drop for ServiceClient {
    fn drop(&mut self) {
        self.shutdown();
    }
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
                match ReplyHeader::decode_cdr2_le(&msg.bytes) {
                    Ok((reply_header, consumed)) => {
                        if let Some((_, tx)) = pending.remove(&reply_header.related_request_id) {
                            let reply_data = ReplyData {
                                header: reply_header,
                                payload: msg.bytes[consumed..].to_vec(),
                            };
                            // The caller may have cancelled the request.
                            drop(tx.send(reply_data));
                        }
                    }
                    // Truncated, or a remoteEx outside the spec enum: the
                    // reply is dropped and the request runs into its timeout.
                    Err(e) => log::warn!("Dropping reply with a malformed header: {e:?}"),
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

    #[tokio::test]
    async fn cancelled_future_releases_pending_request_and_shutdown_wakes_call() {
        let participant = Participant::builder("rpc_cancel")
            .domain_id(0)
            .with_transport(crate::TransportMode::IntraProcess)
            .build()
            .unwrap();
        let client = ServiceClient::new(&participant, "rpc_cancel").unwrap();
        {
            let call = client.call_raw(b"cancel", Duration::from_secs(30));
            tokio::pin!(call);
            tokio::select! {
                _ = &mut call => panic!("call completed without a server"),
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
            assert_eq!(client.pending.len(), 1);
        }
        assert!(client.pending.is_empty());

        let (result, ()) = tokio::join!(
            client.call_raw(b"shutdown", Duration::from_secs(30)),
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                client.shutdown();
            }
        );
        assert!(matches!(result, Err(RpcError::Shutdown)));
        assert!(client.pending.is_empty());
        assert!(matches!(
            client.call_raw(b"late", Duration::from_secs(30)).await,
            Err(RpcError::Shutdown)
        ));
    }

    #[test]
    fn rpc_message_type_descriptor() {
        let desc = <RpcMessage as DDS>::type_descriptor();
        assert_eq!(desc.type_name, "RpcMessage");
        assert!(desc.is_variable_size);
    }
}
