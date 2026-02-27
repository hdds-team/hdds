// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RPC Server (Replier) implementation.
//!
//! The ServiceServer receives requests, dispatches them to a handler,
//! and sends replies back to clients.

use crate::core::ser::{Cdr2Decode, Cdr2Encode};
use crate::dds::{DataReader, DataWriter, Participant};
use crate::rpc::client::RpcMessage;
use crate::rpc::error::RpcResult;
use crate::rpc::types::{RemoteExceptionCode, ReplyHeader, RequestHeader, SampleIdentity};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Handler trait for processing RPC requests.
///
/// Implement this trait to define your service logic.
pub trait RequestHandler: Send + Sync + 'static {
    /// Handle a request and return the reply payload.
    ///
    /// # Arguments
    /// * `request_id` - Identity of the request (for logging/tracing)
    /// * `payload` - The request payload (raw bytes)
    ///
    /// # Returns
    /// Ok(payload) on success, or an error with exception code
    fn handle(
        &self,
        request_id: SampleIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, (RemoteExceptionCode, String)>;
}

/// A function-based request handler.
impl<F> RequestHandler for F
where
    F: Fn(SampleIdentity, &[u8]) -> Result<Vec<u8>, (RemoteExceptionCode, String)>
        + Send
        + Sync
        + 'static,
{
    fn handle(
        &self,
        request_id: SampleIdentity,
        payload: &[u8],
    ) -> Result<Vec<u8>, (RemoteExceptionCode, String)> {
        self(request_id, payload)
    }
}

/// RPC Server for handling service requests.
///
/// # Example
///
/// ```rust,no_run
/// use hdds::rpc::{ServiceServer, RequestHandler, RemoteExceptionCode, SampleIdentity};
/// use hdds::Participant;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let participant = Participant::builder("server").build()?;
///
/// let handler = |_id: SampleIdentity, payload: &[u8]| {
///     // Process request and return reply
///     Ok(payload.to_vec()) // Echo for demo
/// };
///
/// let server = ServiceServer::new(&participant, "echo", handler)?;
/// server.spin().await;
/// # Ok(())
/// # }
/// ```
pub struct ServiceServer {
    /// Service name
    service_name: String,

    /// Reader for receiving requests (moved to spin task)
    request_reader: Option<DataReader<RpcMessage>>,

    /// Writer for sending replies
    reply_writer: DataWriter<RpcMessage>,

    /// Request handler
    handler: Arc<dyn RequestHandler>,

    /// Shutdown flag
    shutdown: Arc<AtomicBool>,

    /// Statistics
    requests_processed: AtomicU64,
}

impl ServiceServer {
    /// Create a new RPC server for a service.
    ///
    /// # Arguments
    /// * `participant` - The DDS participant
    /// * `service_name` - Name of the service
    /// * `handler` - Handler for processing requests
    pub fn new<H: RequestHandler>(
        participant: &Arc<Participant>,
        service_name: &str,
        handler: H,
    ) -> RpcResult<Self> {
        let qos = crate::rpc::rpc_qos();

        // Create request reader (client -> server)
        let request_topic = format!("rq/{}", service_name);
        let request_reader =
            participant.create_reader::<RpcMessage>(&request_topic, qos.clone())?;

        // Create reply writer (server -> client)
        let reply_topic = format!("rr/{}", service_name);
        let reply_writer = participant.create_writer::<RpcMessage>(&reply_topic, qos)?;

        log::info!("ServiceServer '{}' started", service_name);
        log::info!("  Request topic: {}", request_topic);
        log::info!("  Reply topic: {}", reply_topic);

        Ok(Self {
            service_name: service_name.to_string(),
            request_reader: Some(request_reader),
            reply_writer,
            handler: Arc::new(handler),
            shutdown: Arc::new(AtomicBool::new(false)),
            requests_processed: AtomicU64::new(0),
        })
    }

    /// Run the server, processing requests until shutdown.
    ///
    /// This is an async blocking call that will process requests continuously.
    /// Note: This method takes ownership of the reader.
    pub async fn spin(mut self) {
        log::info!("ServiceServer '{}' spinning...", self.service_name);

        // Take the reader (moves ownership into this method)
        let reader = match self.request_reader.take() {
            Some(r) => r,
            None => {
                log::error!("ServiceServer::spin called but reader already consumed");
                return;
            }
        };

        while !self.shutdown.load(Ordering::Relaxed) {
            // Try to take a request
            if let Ok(Some(msg)) = reader.take() {
                self.process_request(msg).await;
            }

            tokio::time::sleep(Duration::from_micros(100)).await;
        }

        log::info!("ServiceServer '{}' stopped", self.service_name);
    }

    /// Process a single request message
    async fn process_request(&self, msg: RpcMessage) {
        // Parse request header
        let request_header = match RequestHeader::decode_cdr2_le(&msg.header) {
            Ok((header, _)) => header,
            Err(e) => {
                log::warn!("Failed to parse request header: {:?}", e);
                return;
            }
        };

        let request_id = request_header.request_id;
        log::debug!("Processing request: seq={}", request_id.sequence_number);

        // Invoke handler
        let result = self.handler.handle(request_id, &msg.payload);

        // Build reply
        let (reply_header, reply_payload) = match result {
            Ok(payload) => (ReplyHeader::success(request_id), payload),
            Err((code, message)) => {
                log::warn!("Handler error: {:?} - {}", code, message);
                (ReplyHeader::error(request_id, code), Vec::new())
            }
        };

        // Encode reply header
        let mut header_bytes = vec![0u8; 28];
        if let Err(e) = reply_header.encode_cdr2_le(&mut header_bytes) {
            log::error!("Failed to encode reply header: {:?}", e);
            return;
        }

        // Send reply
        let reply_msg = RpcMessage {
            header: header_bytes,
            payload: reply_payload,
        };

        if let Err(e) = self.reply_writer.write(&reply_msg) {
            log::error!("Failed to send reply: {}", e);
            return;
        }

        self.requests_processed.fetch_add(1, Ordering::Relaxed);
        log::debug!("Reply sent for request seq={}", request_id.sequence_number);
    }

    /// Shutdown the server
    pub fn shutdown(&self) {
        log::info!("ServiceServer '{}' shutting down...", self.service_name);
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::Relaxed)
    }

    /// Get the service name
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// Get the number of requests processed
    pub fn requests_processed(&self) -> u64 {
        self.requests_processed.load(Ordering::Relaxed)
    }
}

impl Drop for ServiceServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_trait_with_closure() {
        // Test that closures can be used as handlers
        let handler =
            |_id: SampleIdentity,
             payload: &[u8]|
             -> Result<Vec<u8>, (RemoteExceptionCode, String)> { Ok(payload.to_vec()) };

        let result = handler.handle(SampleIdentity::zero(), b"test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"test");
    }

    #[test]
    fn handler_trait_with_error() {
        let handler = |_id: SampleIdentity,
                       _payload: &[u8]|
         -> Result<Vec<u8>, (RemoteExceptionCode, String)> {
            Err((
                RemoteExceptionCode::InvalidArgument,
                "bad input".to_string(),
            ))
        };

        let result = handler.handle(SampleIdentity::zero(), b"test");
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, RemoteExceptionCode::InvalidArgument);
        assert_eq!(msg, "bad input");
    }
}
