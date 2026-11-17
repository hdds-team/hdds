// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Client connection handling for discovery server.

use super::protocol::{DiscoveryMessage, ProtocolError};
use super::registry::GuidPrefix;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long a single outbound message may take to reach the socket.
///
/// A discovery message is a few hundred bytes; taking seconds to hand it to
/// the kernel means the peer has stopped reading, not that the link is slow.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A connected client.
pub struct ClientConnection {
    stream: TcpStream,
    peer_addr: SocketAddr,
    max_message_size: usize,
    guid_prefix: Option<GuidPrefix>,
    read_buffer: Vec<u8>,
    /// Frames dropped because their type is not implemented by this build.
    unknown_messages: u64,
}

impl ClientConnection {
    /// Create a new client connection.
    pub fn new(stream: TcpStream, peer_addr: SocketAddr, max_message_size: usize) -> Self {
        Self {
            stream,
            peer_addr,
            max_message_size,
            guid_prefix: None,
            read_buffer: Vec::with_capacity(4096),
            unknown_messages: 0,
        }
    }

    /// Get the peer address.
    #[allow(dead_code)]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get the registered GUID prefix (if any).
    pub fn guid_prefix(&self) -> Option<&GuidPrefix> {
        self.guid_prefix.as_ref()
    }

    /// Set the GUID prefix after participant registration.
    pub fn set_guid_prefix(&mut self, guid_prefix: GuidPrefix) {
        self.guid_prefix = Some(guid_prefix);
    }

    /// Read a message from the client.
    ///
    /// Returns `Ok(None)` if the connection is closed gracefully.
    ///
    /// # Cancel safety
    ///
    /// This is safe to use as a branch of `tokio::select!`. Bytes already
    /// pulled off the socket live in `self.read_buffer`, which survives the
    /// future being dropped, and the only await point is `read`, which tokio
    /// guarantees consumes nothing when cancelled.
    ///
    /// The previous implementation used `read_exact` for the 4-byte length
    /// prefix and again for the body. Losing that race - the server's own
    /// `select!` has an outbound branch that can fire between the two - threw
    /// away a prefix that had already left the socket, and every later frame
    /// was then decoded at the wrong offset. A desynchronised stream does not
    /// announce itself: it surfaces later as "Invalid JSON" or a nonsense
    /// length, far from the cause.
    pub async fn read_message(&mut self) -> Result<Option<DiscoveryMessage>, ConnectionError> {
        loop {
            if let Some(msg) = self.decode_buffered()? {
                return Ok(Some(msg));
            }

            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| ConnectionError::Io(e.to_string()))?;

            if read == 0 {
                // Peer closed. Anything left in the buffer is a truncated
                // frame, which is a protocol error rather than a clean close.
                if self.read_buffer.is_empty() {
                    return Ok(None);
                }
                return Err(ConnectionError::Protocol(format!(
                    "connection closed mid-frame with {} buffered bytes",
                    self.read_buffer.len()
                )));
            }

            self.read_buffer.extend_from_slice(&chunk[..read]);
        }
    }

    /// Decode buffered frames until one of them is a message we implement.
    ///
    /// The loop exists for unimplemented types: they are consumed and
    /// skipped, so the next buffered frame must be tried right away.
    /// Returning `Ok(None)` there would send `read_message` back to the
    /// socket and leave a complete, decodable frame sitting in the buffer
    /// until unrelated bytes happened to arrive.
    fn decode_buffered(&mut self) -> Result<Option<DiscoveryMessage>, ConnectionError> {
        const LENGTH_PREFIX: usize = 4;

        loop {
            if self.read_buffer.len() < LENGTH_PREFIX {
                return Ok(None);
            }

            // Indexed rather than a fallible conversion: the guard above
            // already proved there are four bytes.
            let len = u32::from_be_bytes([
                self.read_buffer[0],
                self.read_buffer[1],
                self.read_buffer[2],
                self.read_buffer[3],
            ]) as usize;

            if len == 0 {
                return Err(ConnectionError::Protocol("Empty message".into()));
            }
            if len > self.max_message_size {
                return Err(ConnectionError::Protocol(format!(
                    "Message too large: {} > {}",
                    len, self.max_message_size
                )));
            }

            let frame_len = LENGTH_PREFIX + len;
            if self.read_buffer.len() < frame_len {
                return Ok(None);
            }

            let frame: Vec<u8> = self.read_buffer[LENGTH_PREFIX..frame_len].to_vec();
            self.read_buffer.drain(..frame_len);

            let msg: DiscoveryMessage = serde_json::from_slice(&frame)
                .map_err(|e| ConnectionError::Protocol(format!("Invalid JSON: {}", e)))?;

            if matches!(msg, DiscoveryMessage::Unknown) {
                self.note_unknown_message(&frame);
                continue;
            }

            return Ok(Some(msg));
        }
    }

    /// Count and report a frame whose type this build does not implement.
    ///
    /// Ignoring it is deliberate: closing the connection would make a client
    /// one version ahead of its server unusable. It is not a silent swallow
    /// either - the first one warns, and every later one keeps the running
    /// total visible.
    fn note_unknown_message(&mut self, frame: &[u8]) {
        self.unknown_messages = self.unknown_messages.saturating_add(1);
        let wire_type = wire_type_name(frame);
        if self.unknown_messages == 1 {
            tracing::warn!(
                "[connection] ignoring a frame of type '{}' from {}: this build does not implement it",
                wire_type,
                self.peer_addr
            );
        } else {
            tracing::debug!(
                "[connection] ignored {} frames this build does not implement from {} (last: '{}')",
                self.unknown_messages,
                self.peer_addr,
                wire_type
            );
        }
    }

    /// Number of frames ignored because their type is not implemented here.
    pub fn unknown_messages(&self) -> u64 {
        self.unknown_messages
    }

    /// Send a message to the client.
    pub async fn send_message(&mut self, msg: DiscoveryMessage) -> Result<(), ConnectionError> {
        let json = serde_json::to_vec(&msg)
            .map_err(|e| ConnectionError::Protocol(format!("Serialize error: {}", e)))?;

        // Check size
        if json.len() > self.max_message_size {
            return Err(ConnectionError::Protocol(format!(
                "Response too large: {} > {}",
                json.len(),
                self.max_message_size
            )));
        }

        // Write length prefix, body and flush under ONE deadline.
        //
        // Without it, a client that stops reading leaves this task parked in
        // `write_all` until the kernel gives up on the TCP connection, which
        // takes minutes. During that time the participant still holds a
        // registry entry and a connection slot while being, in practice, gone.
        let len = json.len() as u32;
        let write = async {
            self.stream.write_all(&len.to_be_bytes()).await?;
            self.stream.write_all(&json).await?;
            self.stream.flush().await
        };

        match tokio::time::timeout(WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(ConnectionError::Io(e.to_string())),
            Err(_elapsed) => Err(ConnectionError::Io(format!(
                "write timed out after {:?}: the peer is not reading",
                WRITE_TIMEOUT
            ))),
        }
    }

    /// Shutdown the connection.
    #[allow(dead_code)]
    pub async fn shutdown(&mut self) -> Result<(), ConnectionError> {
        self.stream
            .shutdown()
            .await
            .map_err(|e| ConnectionError::Io(e.to_string()))
    }
}

/// Name the wire type of a frame that matched no implemented variant.
///
/// `DiscoveryMessage::Unknown` has to be a unit variant - `#[serde(other)]`
/// requires one - so serde cannot carry the tag into it, and a log that
/// cannot name what it dropped is a poor record. This second parse only runs
/// on a frame already known to be unimplemented, so it is a cold path.
fn wire_type_name(frame: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct TypeTag {
        #[serde(rename = "type")]
        value: String,
    }

    serde_json::from_slice::<TypeTag>(frame)
        .map(|tag| tag.value)
        .unwrap_or_else(|_| "<unnamed>".to_string())
}

/// Connection error types.
#[derive(Debug)]
pub enum ConnectionError {
    Io(String),
    Protocol(String),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O error: {}", s),
            Self::Protocol(s) => write!(f, "Protocol error: {}", s),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<ProtocolError> for ConnectionError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e.to_string())
    }
}

impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_error_display() {
        let err = ConnectionError::Io("test".into());
        assert!(err.to_string().contains("I/O"));

        let err = ConnectionError::Protocol("invalid".into());
        assert!(err.to_string().contains("Protocol"));
    }

    /// DS-3 regression: a read cancelled mid-frame must not lose the bytes it
    /// already pulled off the socket.
    ///
    /// The server reads in a `tokio::select!` whose other branch sends queued
    /// outbound messages. When that branch fires, the read future is dropped.
    /// With `read_exact` the 4-byte prefix was already consumed and gone, so
    /// the next read decoded the body as a length: the stream desynchronised
    /// permanently, and surfaced much later as "Invalid JSON".
    #[tokio::test]
    async fn read_message_survives_being_cancelled_mid_frame() {
        use super::super::protocol::GuidPrefixWire;
        use std::time::Duration;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let dialer = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
        let (server_side, peer) = listener.accept().await.expect("accept");
        let mut writer = dialer.await.expect("dialer");

        let mut conn = ClientConnection::new(server_side, peer, 1024 * 1024);

        let msg = DiscoveryMessage::Heartbeat {
            guid_prefix: GuidPrefixWire("aa".repeat(12)),
        };
        let body = serde_json::to_vec(&msg).expect("serialize");

        // The length prefix and a single body byte: a deliberately torn frame.
        writer
            .write_all(
                &u32::try_from(body.len())
                    .expect("length fits")
                    .to_be_bytes(),
            )
            .await
            .expect("write prefix");
        writer
            .write_all(&body[..1])
            .await
            .expect("write first byte");
        writer.flush().await.expect("flush");

        // Cancelled here, exactly as the server's select! cancels it.
        let cancelled = tokio::time::timeout(Duration::from_millis(100), conn.read_message()).await;
        assert!(
            cancelled.is_err(),
            "the frame is incomplete, so the read must still have been pending"
        );

        // The rest of the frame arrives afterwards.
        writer.write_all(&body[1..]).await.expect("write rest");
        writer.flush().await.expect("flush rest");

        let decoded = tokio::time::timeout(Duration::from_secs(2), conn.read_message())
            .await
            .expect("a cancelled read must not lose the bytes it already pulled")
            .expect("read")
            .expect("a complete frame");

        assert!(
            matches!(decoded, DiscoveryMessage::Heartbeat { .. }),
            "the frame must decode intact after the cancellation"
        );
    }

    /// Frame a JSON body the way the protocol does: 4-byte BE length, body.
    fn framed(json: &str) -> Vec<u8> {
        let mut out = u32::try_from(json.len())
            .expect("test frame fits a u32 length")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(json.as_bytes());
        out
    }

    /// Open a connected `ClientConnection` and the socket that feeds it.
    async fn connected_pair() -> (ClientConnection, tokio::net::TcpStream) {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let dialer = tokio::spawn(async move { TcpStream::connect(addr).await.expect("connect") });
        let (server_side, peer) = listener.accept().await.expect("accept");
        let writer = dialer.await.expect("dialer");

        (
            ClientConnection::new(server_side, peer, 1024 * 1024),
            writer,
        )
    }

    /// RELAY-0: a frame of a type this build does not implement must be
    /// skipped and counted, never turned into an error that ends the session.
    ///
    /// `serde` reports an unrecognised tag as a deserialisation failure.
    /// `read_message` turned that into a protocol error and the server's
    /// connection loop turned THAT into a `break`, so a client one version
    /// ahead of its server could not talk to it at all.
    #[tokio::test]
    async fn an_unimplemented_frame_type_is_skipped_and_counted() {
        use super::super::protocol::GuidPrefixWire;
        use std::time::Duration;

        let (mut conn, mut writer) = connected_pair().await;

        // A type from a future protocol revision, then one we implement.
        // The second frame is what proves the stream stayed synchronised
        // rather than merely that the first one did not crash.
        writer
            .write_all(&framed(
                r#"{"type":"something_newer","destination":"ff","payload":[1]}"#,
            ))
            .await
            .expect("write unknown frame");
        let known = serde_json::to_string(&DiscoveryMessage::Heartbeat {
            guid_prefix: GuidPrefixWire("aa".repeat(12)),
        })
        .expect("serialize");
        writer
            .write_all(&framed(&known))
            .await
            .expect("write known frame");
        writer.flush().await.expect("flush");

        let decoded = tokio::time::timeout(Duration::from_secs(2), conn.read_message())
            .await
            .expect("an unimplemented frame type must not block the reader")
            .expect("an unimplemented frame type must not be an error")
            .expect("the frame after it is complete and must be delivered");

        assert!(
            matches!(decoded, DiscoveryMessage::Heartbeat { .. }),
            "the frame following the skipped one must still decode, got {:?}",
            decoded
        );
        assert_eq!(
            conn.unknown_messages(),
            1,
            "the skipped frame must be counted, not silently swallowed"
        );
    }

    /// The counterpart: tolerating an unknown TYPE must not make the decoder
    /// tolerant of a corrupt frame. A type we do implement, with a body that
    /// does not satisfy it, is a real protocol error and still ends the
    /// session.
    #[tokio::test]
    async fn a_known_type_with_a_malformed_body_is_still_an_error() {
        use std::time::Duration;

        let (mut conn, mut writer) = connected_pair().await;

        // `heartbeat` requires `guid_prefix`.
        writer
            .write_all(&framed(r#"{"type":"heartbeat"}"#))
            .await
            .expect("write malformed frame");
        writer.flush().await.expect("flush");

        let outcome = tokio::time::timeout(Duration::from_secs(2), conn.read_message())
            .await
            .expect("the decoder must not block on a malformed frame");

        assert!(
            matches!(outcome, Err(ConnectionError::Protocol(_))),
            "a malformed body of a known type must stay a protocol error, got {:?}",
            outcome
        );
        assert_eq!(
            conn.unknown_messages(),
            0,
            "a malformed frame is not an unimplemented type"
        );
    }
}
