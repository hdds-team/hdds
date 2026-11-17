// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The native relay (feature `relay`).
//!
//! A WebSocket server that turns browser clients into real DDS endpoints: one
//! [`Participant`], one raw writer and one raw reader per topic a client
//! creates, and the browser's binary relay protocol on the socket.
//!
//! ONE data path. [`RelayHandler::route_publication`] can fan a publication
//! out to other clients in relay memory; this server does not use it. Every
//! sample goes out on DDS and comes back through the topic's reader, so a
//! browser subscriber and a native subscriber see the same bytes with the
//! same QoS semantics, and there is no second delivery path to keep in sync.
//! A client that publishes and subscribes to one topic therefore receives its
//! own sample, exactly as a native DDS participant would.
//!
//! Where this sits next to `tools/hdds-ws`: hdds-ws speaks JSON over
//! WebSocket for dashboards and needs a TypeObject to project samples;
//! this relay carries raw CDR both ways for applications that own their
//! codec (the WASM SDK). Neither replaces the other.
//!
//! Security: like every bridge in this repository, the relay writes into the
//! domain with its own participant identity and does not authenticate WebSocket
//! clients. It binds loopback unless told otherwise. Because nobody is
//! authenticated, the number of DDS endpoint pairs a client can make the relay
//! create is capped ([`RelayServer::with_max_topics`]), and a topic's
//! endpoints and its polling task are dropped once no client is left using
//! it - otherwise a peer that can reach the socket grows both without bound.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use hdds::dds::{Participant, RawDataReader, RawDataWriter, TransportMode};
use hdds::CdrVersion;
use hdds::QoS;
use tokio::sync::{broadcast, Mutex};

use crate::protocol::{self, RelayMessage};
use crate::qos::{WasmDurability, WasmQos, WasmReliability};
use crate::relay::RelayHandler;

/// How often a topic's reader is polled for new samples.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Broadcast buffer per relay (samples, not bytes).
const BROADCAST_CAPACITY: usize = 1024;

/// Default ceiling on live DDS endpoint pairs. The relay authenticates
/// nobody, so this is a bound, not a tuning knob.
const DEFAULT_MAX_TOPICS: usize = 64;

/// Consecutive read failures a topic's polling task tolerates before it gives
/// the topic up. A transient error must not retire the DDS -> browser
/// direction for the life of the process.
const MAX_CONSECUTIVE_READ_ERRORS: u32 = 20;

/// Errors from the relay server.
#[derive(Debug)]
pub enum RelayServerError {
    Dds(String),
    Io(std::io::Error),
}

impl std::fmt::Display for RelayServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dds(m) => write!(f, "DDS error: {}", m),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for RelayServerError {}

impl From<std::io::Error> for RelayServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// A DDS sample on its way to the browsers.
#[derive(Clone, Debug)]
struct DdsSample {
    topic_id: u16,
    payload: Vec<u8>,
}

struct TopicEndpoints {
    writer: RawDataWriter,
    /// Kept alive for the polling task; dropping it unregisters the reader.
    _reader: Arc<RawDataReader>,
    /// The polling task, aborted when the topic goes away.
    poll: tokio::task::JoinHandle<()>,
    /// Clients currently holding this topic. The endpoints are dropped when
    /// it reaches zero.
    users: usize,
}

/// The relay's shared state.
pub struct RelayServer {
    participant: Arc<Participant>,
    handler: Mutex<RelayHandler>,
    topics: Mutex<HashMap<u16, TopicEndpoints>>,
    samples: broadcast::Sender<DdsSample>,
    max_topics: AtomicUsize,
}

/// The browser SDK encodes and decodes XCDR2 (`cdr` module), and the relay
/// passes the bytes through untouched. Both endpoints therefore declare
/// DATA_REPRESENTATION XCDR2 only (DDS-XTypes 1.3 7.6.3.1): the writer's
/// samples go out under the XCDR2 identifier whatever the reader, and the
/// reader is matched only with writers that send XCDR2. A peer that speaks
/// XCDR1 only is refused at matching (INCOMPATIBLE_QOS, policy 23) instead
/// of exchanging bytes the other side decodes with the wrong alignment.
fn xcdr2_only(qos: QoS) -> QoS {
    qos.data_representation_xcdr2()
}

fn to_hdds_qos(qos: &WasmQos) -> QoS {
    let base = match qos.reliability {
        WasmReliability::Reliable => QoS::reliable(),
        WasmReliability::BestEffort => QoS::best_effort(),
    };
    let base = match qos.durability {
        WasmDurability::TransientLocal => base.transient_local(),
        WasmDurability::Volatile => base,
    };
    base.keep_last(qos.history_depth.max(1))
}

impl RelayServer {
    /// Create the relay's participant on `domain_id`.
    pub fn new(domain_id: u32, participant_name: &str) -> Result<Arc<Self>, RelayServerError> {
        let participant = Participant::builder(participant_name)
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .map_err(|e| RelayServerError::Dds(e.to_string()))?;
        let (samples, _) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(Arc::new(Self {
            participant,
            handler: Mutex::new(RelayHandler::new()),
            topics: Mutex::new(HashMap::new()),
            samples,
            max_topics: AtomicUsize::new(DEFAULT_MAX_TOPICS),
        }))
    }

    /// Change the ceiling on live DDS endpoint pairs.
    ///
    /// Takes effect for the next topic a client asks for; topics already
    /// held are kept. Callable on a shared relay: other references to the
    /// `Arc` may exist.
    pub fn with_max_topics(self: Arc<Self>, max_topics: usize) -> Arc<Self> {
        self.max_topics.store(max_topics, Ordering::Relaxed);
        self
    }

    /// Number of live DDS endpoint pairs.
    pub async fn topic_count(&self) -> usize {
        self.topics.lock().await.len()
    }

    /// The axum router serving the relay at `/ws`.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/ws", get(ws_handler))
            .route("/health", get(|| async { "ok" }))
            .with_state(Arc::clone(self))
    }

    /// Serve until the process ends.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr) -> Result<(), RelayServerError> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let router = self.router();
        axum::serve(listener, router).await?;
        Ok(())
    }

    /// Create (or reuse) the DDS endpoints for a topic and return its id.
    async fn ensure_topic(
        self: &Arc<Self>,
        client_id: u32,
        topic_name: &str,
        type_name: &str,
        qos: Option<WasmQos>,
    ) -> Result<u16, RelayServerError> {
        let topic_id = {
            let mut handler = self.handler.lock().await;
            let request =
                protocol::build_create_topic_with_qos(topic_name, type_name, qos.as_ref(), 0);
            handler
                .process_client_message(client_id, &request)
                .map_err(|e| RelayServerError::Dds(e.to_string()))?;
            handler
                .get_topic_id(topic_name)
                .ok_or_else(|| RelayServerError::Dds("topic id not allocated".to_string()))?
        };

        let mut topics = self.topics.lock().await;
        if let Some(endpoints) = topics.get_mut(&topic_id) {
            endpoints.users += 1;
            return Ok(topic_id);
        }
        let max_topics = self.max_topics.load(Ordering::Relaxed);
        if topics.len() >= max_topics {
            return Err(RelayServerError::Dds(format!(
                "the relay already holds its maximum of {} topics",
                max_topics
            )));
        }

        let dds_qos = Some(xcdr2_only(
            qos.as_ref().map(to_hdds_qos).unwrap_or_default(),
        ));
        let writer = self
            .participant
            .create_raw_writer_with_type(topic_name, type_name, dds_qos.clone(), None, None)
            .map_err(|e| RelayServerError::Dds(e.to_string()))?;
        let reader = Arc::new(
            self.participant
                .create_raw_reader_with_type(topic_name, type_name, dds_qos, None, None)
                .map_err(|e| RelayServerError::Dds(e.to_string()))?,
        );
        // One polling task per topic, feeding the single data path. A read
        // error is retried: retiring the task on the first one would kill the
        // DDS -> browser direction for this topic for the life of the
        // process, while ensure_topic kept answering that the topic exists.
        let samples = self.samples.clone();
        let poll_reader = Arc::clone(&reader);
        let poll = tokio::spawn(async move {
            let mut consecutive_errors = 0u32;
            loop {
                match poll_reader.try_take_raw_with_encoding() {
                    Ok(batch) => {
                        consecutive_errors = 0;
                        for (sample, version) in batch {
                            // The reader accepts XCDR2 only, so a writer
                            // that negotiated with it sends XCDR2, and an
                            // HDDS reader does not deliver an XCDR1 sample
                            // to it. This is the backstop for a peer that
                            // labels a sample against the negotiation: the
                            // browser would decode it with the wrong
                            // alignment, so it is refused.
                            if version != CdrVersion::Xcdr2 {
                                log::warn!(
                                    "relay reader for topic {} refused a {:?} sample; \
                                     browsers decode XCDR2",
                                    topic_id,
                                    version
                                );
                                continue;
                            }
                            let _ = samples.send(DdsSample {
                                topic_id,
                                payload: sample.payload,
                            });
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        log::warn!(
                            "relay reader for topic {} failed ({} in a row): {}",
                            topic_id,
                            consecutive_errors,
                            e
                        );
                        if consecutive_errors >= MAX_CONSECUTIVE_READ_ERRORS {
                            log::error!(
                                "relay reader for topic {} gave up after {} consecutive failures",
                                topic_id,
                                consecutive_errors
                            );
                            return;
                        }
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });

        topics.insert(
            topic_id,
            TopicEndpoints {
                writer,
                _reader: reader,
                poll,
                users: 1,
            },
        );

        Ok(topic_id)
    }

    /// Give one client's hold on a topic back. The DDS endpoints and the
    /// polling task go away with the last user.
    async fn release_topic(self: &Arc<Self>, topic_id: u16) {
        let mut topics = self.topics.lock().await;
        let Some(endpoints) = topics.get_mut(&topic_id) else {
            return;
        };
        endpoints.users = endpoints.users.saturating_sub(1);
        if endpoints.users == 0 {
            if let Some(endpoints) = topics.remove(&topic_id) {
                endpoints.poll.abort();
            }
        }
    }

    /// Publish a browser sample onto DDS.
    async fn publish(
        self: &Arc<Self>,
        topic_id: u16,
        payload: &[u8],
    ) -> Result<(), RelayServerError> {
        let topics = self.topics.lock().await;
        match topics.get(&topic_id) {
            Some(endpoints) => endpoints
                .writer
                .write_raw(payload)
                .map_err(|e| RelayServerError::Dds(e.to_string())),
            None => Err(RelayServerError::Dds(format!(
                "publish on unknown topic id {}",
                topic_id
            ))),
        }
    }
}

async fn ws_handler(
    State(state): State<Arc<RelayServer>>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| serve_client(state, socket))
}

/// One browser connection.
async fn serve_client(state: Arc<RelayServer>, mut socket: WebSocket) {
    let client_id = {
        let mut handler = state.handler.lock().await;
        let (id, _ack) = handler.accept_client();
        id
    };
    let mut subscriptions: HashSet<u16> = HashSet::new();
    // Every ensure_topic that succeeded for THIS client, so the holds are
    // given back one for one when the socket goes away.
    let mut held_topics: Vec<u16> = Vec::new();
    let mut samples = state.samples.subscribe();

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let Some(Ok(message)) = incoming else { break };
                let frame = match message {
                    Message::Binary(bytes) => bytes,
                    Message::Close(_) => break,
                    // The relay protocol is binary. A text frame is a client
                    // bug, not something to guess at.
                    Message::Text(_) => {
                        let _ = socket
                            .send(Message::Binary(protocol::build_error(
                                "relay protocol frames are binary",
                                0,
                            )))
                            .await;
                        continue;
                    }
                    _ => continue,
                };

                let parsed = match protocol::parse_message(&frame) {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = socket
                            .send(Message::Binary(protocol::build_error(&e.to_string(), 0)))
                            .await;
                        continue;
                    }
                };

                match parsed {
                    RelayMessage::Connect { .. } => {
                        let responses = {
                            let mut handler = state.handler.lock().await;
                            handler
                                .process_client_message(client_id, &frame)
                                .unwrap_or_default()
                        };
                        let mut closed = false;
                        for response in responses {
                            if socket.send(Message::Binary(response)).await.is_err() {
                                closed = true;
                                break;
                            }
                        }
                        if closed {
                            break;
                        }
                    }
                    RelayMessage::CreateTopic { topic_name, type_name, qos } => {
                        match state.ensure_topic(client_id, &topic_name, &type_name, qos).await {
                            Ok(topic_id) => {
                                held_topics.push(topic_id);
                                let ack = protocol::build_topic_ack(topic_id, &topic_name, 0);
                                if socket.send(Message::Binary(ack)).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = socket
                                    .send(Message::Binary(protocol::build_error(&e.to_string(), 0)))
                                    .await;
                            }
                        }
                    }
                    RelayMessage::Subscribe { topic_id } => {
                        subscriptions.insert(topic_id);
                    }
                    RelayMessage::Unsubscribe { topic_id } => {
                        subscriptions.remove(&topic_id);
                    }
                    RelayMessage::Publish { topic_id, payload, .. } => {
                        if let Err(e) = state.publish(topic_id, &payload).await {
                            let _ = socket
                                .send(Message::Binary(protocol::build_error(&e.to_string(), 0)))
                                .await;
                        }
                    }
                    RelayMessage::Ping { sequence_nr } => {
                        if socket
                            .send(Message::Binary(protocol::build_pong(sequence_nr)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    RelayMessage::Disconnected => break,
                    _ => {
                        let _ = socket
                            .send(Message::Binary(protocol::build_error(
                                "unexpected message type",
                                0,
                            )))
                            .await;
                    }
                }
            }
            sample = samples.recv() => {
                match sample {
                    Ok(sample) => {
                        if subscriptions.contains(&sample.topic_id) {
                            let data = protocol::build_data(sample.topic_id, 0, &sample.payload);
                            if socket.send(Message::Binary(data)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("relay client {} lagged {} samples", client_id, n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    for topic_id in held_topics {
        state.release_topic(topic_id).await;
    }
    let mut handler = state.handler.lock().await;
    handler.remove_client(client_id);
}
