# HDDS Sequence Diagrams

> Version 1.0.5 | Last updated: 2026-02-13

Detailed Mermaid sequence diagrams for the core HDDS protocols.

---

## 1. Participant Discovery (SPDP)

The Simple Participant Discovery Protocol is the first phase of RTPS discovery.
All participants periodically multicast SPDP announcements to find each other.

Implementation: `crates/hdds/src/protocol/discovery/spdp/`

```mermaid
sequenceDiagram
    participant A as Participant A<br/>(GUID: 0xAA...)
    participant MC as Multicast Group<br/>239.255.0.1:7400
    participant B as Participant B<br/>(GUID: 0xBB...)

    Note over A: Participant::builder("A")<br/>.domain_id(0)<br/>.with_transport(UdpMulticast)<br/>.build()

    Note over B: Participant::builder("B")<br/>.domain_id(0)<br/>.with_transport(UdpMulticast)<br/>.build()

    Note over A,B: Phase 1: Join multicast group

    A->>MC: Join 239.255.0.1:7400
    B->>MC: Join 239.255.0.1:7400

    Note over A,B: Phase 2: Initial SPDP announcements

    A->>MC: SPDP DATA (PID_PARTICIPANT_GUID=0xAA,<br/>PID_BUILTIN_ENDPOINT_SET,<br/>PID_METATRAFFIC_UNICAST_LOCATOR,<br/>PID_DEFAULT_UNICAST_LOCATOR,<br/>PID_PARTICIPANT_LEASE_DURATION=30s,<br/>PID_VENDORID=HDDS,<br/>PID_PARTICIPANT_NAME="A")
    MC-->>B: SPDP received
    B->>B: DiscoveryFsm.on_spdp(A)<br/>Parse SPDP payload via spdp::parse<br/>Extract locators, lease, name
    B->>B: Add Participant A to peer table<br/>Start lease timer (30s)
    B->>B: DialectDetector.observe(A)<br/>Detect vendor from VENDORID PID

    B->>MC: SPDP DATA (PID_PARTICIPANT_GUID=0xBB,<br/>PID_BUILTIN_ENDPOINT_SET,<br/>PID_METATRAFFIC_UNICAST_LOCATOR,<br/>PID_DEFAULT_UNICAST_LOCATOR,<br/>PID_PARTICIPANT_LEASE_DURATION=30s,<br/>PID_VENDORID=HDDS,<br/>PID_PARTICIPANT_NAME="B")
    MC-->>A: SPDP received
    A->>A: DiscoveryFsm.on_spdp(B)<br/>Add Participant B to peer table

    Note over A,B: Phase 3: Periodic re-announcements

    loop Every lease_duration / 3 (~10s)
        A->>MC: SPDP re-announce
        B->>MC: SPDP re-announce
    end

    Note over A,B: Phase 4: Lease expiration handling

    Note over B: If A stops announcing...
    B->>B: LeaseTracker: A lease expired (30s)<br/>Remove A from peer table<br/>Trigger SEDP unmatch for all endpoints
    B->>B: Hub.publish(Event::OnUnmatch)

    Note over A,B: Phase 5: Unicast replay for late discovery
    Note over A: A creates new writer after B is known
    A->>B: SPDP unicast replay to B's metatraffic locator<br/>(ensures B receives A's updated endpoint set)
```

---

## 2. Endpoint Discovery (SEDP)

The Simple Endpoint Discovery Protocol follows SPDP. It announces DataWriter
and DataReader endpoints to enable topic matching.

Implementation: `crates/hdds/src/protocol/discovery/sedp/`

```mermaid
sequenceDiagram
    participant A as Participant A
    participant AW as DataWriter<Temp><br/>topic="sensors/temp"
    participant BUS as Engine Hub
    participant B as Participant B
    participant BR as DataReader<Temp><br/>topic="sensors/temp"

    Note over A,B: SPDP complete -- participants know each other

    Note over A: A creates a writer
    A->>AW: create_writer::<Temperature>("sensors/temp", QoS::reliable())
    A->>A: Assign entity ID (next_entity_key)<br/>Build writer GUID: [guid_prefix | entity_id]

    Note over A: A announces the writer via SEDP
    A->>B: SEDP Publication (unicast to B's metatraffic locator)<br/>- writer_guid: 0xAA..02<br/>- topic_name: "sensors/temp"<br/>- type_name: "Temperature"<br/>- type_object: CompleteTypeObject::Struct(...)<br/>- qos: {reliability=RELIABLE, history=KEEP_LAST(10)}<br/>- locators: [unicast_addr, multicast_addr]
    B->>B: sedp::parse::parse_sedp_publication()<br/>Extract topic, type, QoS, GUID

    Note over B: B checks for matching reader
    B->>B: TopicRegistry.register_writer_guid(0xAA..02, "sensors/temp")
    B->>B: Check local readers for topic "sensors/temp"
    B->>BR: Found match: DataReader<Temperature>
    B->>B: Verify QoS compatibility<br/>(writer=RELIABLE, reader=RELIABLE -> OK)
    B->>B: Verify type compatibility via XTypes<br/>(TypeIdentifier matching)

    Note over B: B announces its reader via SEDP
    B->>A: SEDP Subscription (unicast to A's metatraffic locator)<br/>- reader_guid: 0xBB..04<br/>- topic_name: "sensors/temp"<br/>- type_name: "Temperature"<br/>- qos: {reliability=RELIABLE, history=KEEP_LAST(10)}
    A->>A: sedp::parse -- extract reader info
    A->>A: TopicRegistry.register_writer_guid(0xBB..04, "sensors/temp")

    Note over A,B: MATCHED -- Data can flow

    A->>BUS: Hub.publish(Event::OnMatch{writer_id, reader_id})
    B->>BUS: Hub.publish(Event::OnMatch{writer_id, reader_id})

    AW->>BR: DATA packets can now be delivered<br/>via multicast or unicast

    Note over A,B: Cached for replay
    A->>A: sedp_announcements.push(Publication)
    B->>B: sedp_announcements.push(Subscription)
    Note over A,B: When a new participant C joins,<br/>A and B replay cached SEDP to C
```

---

## 3. Reliable Data Exchange

The RTPS reliability protocol ensures all samples are delivered even with packet loss.

Implementation: `crates/hdds/src/reliability/`

```mermaid
sequenceDiagram
    participant W as DataWriter<T><br/>(HeartbeatTx + HistoryCache)
    participant NET as Network (UDP)
    participant R as DataReader<T><br/>(HeartbeatRx + GapTracker + NackScheduler)

    Note over W: writer.write(&sample_1)
    W->>W: SeqNumGenerator: seq=1
    W->>W: HistoryCache.insert(seq=1, data)
    W->>NET: DATA (writerSN=1, payload)
    NET->>R: DATA received
    R->>R: GapTracker.record(seq=1)<br/>expected_next=2

    Note over W: writer.write(&sample_2)
    W->>W: seq=2, HistoryCache.insert(seq=2)
    W->>NET: DATA (writerSN=2, payload)
    Note over NET: LOST -- packet dropped

    Note over W: writer.write(&sample_3)
    W->>W: seq=3, HistoryCache.insert(seq=3)
    W->>NET: DATA (writerSN=3, payload)
    NET->>R: DATA received
    R->>R: GapTracker.record(seq=3)<br/>Gap detected: seq=2 missing<br/>expected_next was 2, got 3

    Note over W,R: Periodic heartbeat (HeartbeatScheduler)

    W->>NET: HEARTBEAT (firstSN=1, lastSN=3, count=1)
    NET->>R: HEARTBEAT received
    R->>R: HeartbeatRx.process(first=1, last=3)<br/>GapTracker confirms seq=2 missing
    R->>R: NackScheduler.schedule_nack(missing=[2])

    Note over R: NackScheduler fires (jittered delay)
    R->>NET: ACKNACK (readerSN_state: base=2,<br/>bitmap=[1], count=1)<br/>Meaning: "I am missing seq=2"
    NET->>W: ACKNACK received
    W->>W: WriterRetransmitHandler.on_nack([2])
    W->>W: HistoryCache.get(seq=2)

    Note over W: Retransmit missing sample
    W->>NET: DATA (writerSN=2, payload) [retransmit]
    NET->>R: DATA received
    R->>R: GapTracker.record(seq=2)<br/>Gap filled. expected_next=4

    Note over W: Next heartbeat
    W->>NET: HEARTBEAT (firstSN=1, lastSN=3, count=2)
    NET->>R: HEARTBEAT received
    R->>R: No gaps detected
    R->>NET: ACKNACK (readerSN_state: base=4,<br/>bitmap=[], count=2)<br/>Meaning: "I have everything up to seq=3"

    Note over W: HistoryCache cleanup
    W->>W: All readers acknowledged up to seq=3<br/>HistoryCache.evict(seq <= 3)
```

---

## 4. QUIC Handshake + Data

HDDS supports QUIC transport for NAT traversal and connection migration.
Feature-gated behind the `quic` feature flag.

Implementation: `crates/hdds/src/transport/quic/`

```mermaid
sequenceDiagram
    participant A as Participant A<br/>(QUIC Client)
    participant QA as QuicIoThread A<br/>(mini tokio runtime)
    participant NET as Network
    participant QB as QuicIoThread B<br/>(mini tokio runtime)
    participant B as Participant B<br/>(QUIC Server)

    Note over A: ParticipantBuilder<br/>.with_quic(QuicConfig::builder()<br/>  .bind_addr("0.0.0.0:0")<br/>  .build())<br/>.build()

    Note over A,B: Phase 1: QUIC connection establishment

    A->>QA: QuicTransport::connect(B_addr)
    QA->>NET: QUIC Initial (ClientHello + CRYPTO)
    NET->>QB: QUIC Initial received
    QB->>NET: QUIC Handshake (ServerHello + CRYPTO + CERT)
    NET->>QA: QUIC Handshake received
    QA->>QA: Verify server certificate (TLS 1.3)
    QA->>NET: QUIC Handshake Complete (Finished)
    NET->>QB: Connection established
    QB->>B: QuicConnectionState::Connected

    QA->>A: QuicConnectionState::Connected<br/>QuicTransportHandle available<br/>via participant.quic_handle()

    Note over A,B: Phase 2: RTPS over QUIC stream

    A->>QA: quic_handle().send_rtps(rtps_packet)
    QA->>QA: Open bidirectional QUIC stream
    QA->>NET: QUIC STREAM frame<br/>[RTPS header | DATA submessage]
    NET->>QB: QUIC STREAM received
    QB->>QB: Decode RTPS from stream
    QB->>B: route_raw_rtps_message()<br/>via UnicastRouter

    B->>QB: Response (ACKNACK via QUIC)
    QB->>NET: QUIC STREAM frame<br/>[RTPS header | ACKNACK submessage]
    NET->>QA: ACKNACK received
    QA->>A: Process ACKNACK

    Note over A,B: Phase 3: Connection migration (optional)

    Note over A: Network interface changes<br/>(WiFi -> Cellular)
    QA->>NET: QUIC PATH_CHALLENGE (new address)
    NET->>QB: PATH_CHALLENGE received
    QB->>NET: QUIC PATH_RESPONSE
    NET->>QA: PATH_RESPONSE received
    QA->>QA: Migration complete<br/>RTPS traffic continues on new path
```

---

## 5. Security Handshake

DDS Security v1.1 authentication exchange between two participants.
Feature-gated behind the `security` feature flag.

Implementation: `crates/hdds/src/security/auth/handshake.rs`

```mermaid
sequenceDiagram
    participant A as Participant A<br/>(SecurityPluginSuite)
    participant AA as AuthenticationPlugin A<br/>(X.509 + ECDH)
    participant MC as Network
    participant AB as AuthenticationPlugin B<br/>(X.509 + ECDH)
    participant B as Participant B<br/>(SecurityPluginSuite)

    Note over A,B: Phase 0: SPDP with identity_token

    A->>MC: SPDP DATA + identity_token<br/>(X.509 certificate PEM,<br/> class_id="DDS:Auth:PKI-DH:1.0")
    MC->>B: SPDP received with identity_token
    B->>AB: validate_identity(A_cert_pem)
    AB->>AB: Parse X.509 certificate<br/>Verify CA chain (ca_certificates)<br/>Check expiration<br/>Check CRL/OCSP (if configured)
    AB->>B: IdentityHandle(A) -- valid

    Note over A,B: Phase 1: Handshake Request

    B->>AB: begin_handshake(A_identity)
    AB->>AB: Generate ECDH keypair (B_dh_pub)
    AB->>AB: Generate challenge nonce (B_challenge)
    B->>MC: HandshakeRequestToken<br/>(class_id="DDS:Auth:PKI-DH:1.0",<br/> B_dh_pub, B_challenge, B_cert)
    MC->>A: HandshakeRequest received
    A->>AA: process_handshake(B_request)
    AA->>AA: Validate B certificate chain<br/>Verify B challenge signature
    AA->>AA: Generate ECDH keypair (A_dh_pub)<br/>Generate challenge nonce (A_challenge)

    Note over A,B: Phase 2: Handshake Reply

    A->>MC: HandshakeReplyToken<br/>(A_dh_pub, A_challenge, A_cert,<br/> B_challenge_response)
    MC->>B: HandshakeReply received
    B->>AB: process_handshake(A_reply)
    AB->>AB: Validate A certificate<br/>Verify challenge response<br/>Compute shared_secret = ECDH(B_dh_priv, A_dh_pub)

    Note over A,B: Phase 3: Handshake Final

    B->>MC: HandshakeFinalToken<br/>(A_challenge_response, hash)
    MC->>A: HandshakeFinal received
    A->>AA: process_handshake(B_final)
    AA->>AA: Verify B's challenge response<br/>Compute shared_secret = ECDH(A_dh_priv, B_dh_pub)

    Note over A,B: Both sides now have the same shared_secret

    Note over A,B: Phase 4: Session key derivation

    A->>AA: Derive session keys<br/>HKDF(shared_secret, A_challenge + B_challenge)<br/>-> session_key_enc (AES-256-GCM)<br/>-> session_key_mac (HMAC-SHA256)

    B->>AB: Derive session keys<br/>HKDF(shared_secret, A_challenge + B_challenge)<br/>-> session_key_enc (AES-256-GCM)<br/>-> session_key_mac (HMAC-SHA256)

    Note over A,B: Phase 5: Secure data exchange

    A->>A: CryptoPlugin.encode(data, session_key_enc)<br/>AES-256-GCM encrypt + tag
    A->>MC: Encrypted DATA submessage<br/>(SecureBodySubmessage)
    MC->>B: Encrypted DATA received
    B->>B: CryptoPlugin.decode(ciphertext, session_key_enc)<br/>AES-256-GCM decrypt + verify tag
    B->>B: Route decrypted data to reader

    Note over A,B: Audit logging (if enabled)
    A->>A: LoggingPlugin.log_event(<br/>SecurityEvent::AuthSuccess(B_guid))
    B->>B: LoggingPlugin.log_event(<br/>SecurityEvent::AuthSuccess(A_guid))
```

---

## 6. Fragmentation (DATA_FRAG)

Large messages that exceed the MTU are fragmented into multiple DATA_FRAG
submessages and reassembled on the reader side. HEARTBEAT_FRAG and NACK_FRAG
provide reliable fragment delivery.

Implementation:
- Sender: `crates/hdds/src/protocol/rtps/data.rs` (`encode_data_frag`)
- Receiver: `crates/hdds/src/engine/router.rs` (`route_data_frag_packet`)
- Fragment buffer: `crates/hdds/src/core/discovery/` (`FragmentBuffer`)
- NACK_FRAG: `crates/hdds/src/protocol/builder/nack_frag.rs`

```mermaid
sequenceDiagram
    participant W as DataWriter<T><br/>(writer GUID: 0xAA..02)
    participant BLD as protocol::builder
    participant NET as Network
    participant RTR as Router Thread
    participant FB as FragmentBuffer<br/>(max_pending=256, timeout=1000ms)
    participant R as DataReader<T>

    Note over W: writer.write(&large_sample)<br/>Serialized size: 192KB<br/>Fragment size: 64KB<br/>Total fragments: 3

    W->>BLD: encode_data_frag(guid, seq=5,<br/>frag_num=1, total_frags=3, frag_data)
    W->>NET: DATA_FRAG (seq=5, frag=1/3, 64KB)
    W->>NET: DATA_FRAG (seq=5, frag=2/3, 64KB)
    W->>NET: DATA_FRAG (seq=5, frag=3/3, 64KB)

    Note over NET: Fragment 2 is lost!

    NET->>RTR: DATA_FRAG (seq=5, frag=1/3)
    RTR->>RTR: route_data_frag_packet_with_addr()
    RTR->>FB: insert_fragment_with_addr(<br/>guid=0xAA..02, seq=5,<br/>frag=1, total=3, data, src_addr)
    FB->>FB: Create FragmentSequence(seq=5)<br/>Received: {1}, Missing: {2, 3}
    RTR->>RTR: RouteStatus::Delivered (buffered)

    NET->>RTR: DATA_FRAG (seq=5, frag=3/3)
    RTR->>FB: insert_fragment(frag=3)
    FB->>FB: Received: {1, 3}, Missing: {2}
    RTR->>RTR: RouteStatus::Delivered (buffered)

    Note over W,R: Writer sends HEARTBEAT_FRAG

    W->>NET: HEARTBEAT_FRAG (seq=5, last_frag=3)
    NET->>RTR: HEARTBEAT_FRAG received
    RTR->>RTR: handle_heartbeat_frag()
    RTR->>FB: get_missing_fragments(guid, seq=5)
    FB-->>RTR: missing=[2], total=3

    Note over RTR: Router builds and sends NACK_FRAG

    RTR->>RTR: derive_reader_entity_id(0x02 -> 0x04)
    RTR->>BLD: build_nack_frag_packet(<br/>our_guid_prefix,<br/>peer_guid_prefix,<br/>reader_entity_id=0x..04,<br/>writer_entity_id=0x..02,<br/>seq=5, missing=[2], count=1)
    RTR->>NET: NACK_FRAG (seq=5, missing_frags=[2])
    NET->>W: NACK_FRAG received

    Note over W: Writer retransmits missing fragment

    W->>W: Look up fragment 2 from send buffer
    W->>NET: DATA_FRAG (seq=5, frag=2/3, 64KB) [retransmit]
    NET->>RTR: DATA_FRAG (seq=5, frag=2/3)
    RTR->>FB: insert_fragment(frag=2)
    FB->>FB: Received: {1, 2, 3} -- COMPLETE!
    FB-->>RTR: Some(reassembled_payload) (192KB)

    Note over RTR: Route complete reassembled sample

    RTR->>RTR: route_reassembled_data(<br/>guid=0xAA..02, seq=5,<br/>reassembled_payload)
    RTR->>RTR: Strip CDR encapsulation header
    RTR->>RTR: TopicRegistry.get_topic_by_guid(0xAA..02)
    RTR->>R: Topic.deliver(seq=5, payload)
    R->>R: DDS::decode_cdr2() -- deserialize<br/>Push to reader cache

    Note over RTR: Metrics updated
    RTR->>RTR: RouterMetrics.packets_routed += 1<br/>RouterMetrics.bytes_delivered += 192KB
```

### Timeout-Based NACK_FRAG (Backup Path)

If HEARTBEAT_FRAG is not received, the router's periodic stale-fragment check
provides a backup path for requesting retransmission.

```mermaid
sequenceDiagram
    participant RTR as Router Thread
    participant FB as FragmentBuffer
    participant NET as Network
    participant W as DataWriter

    Note over RTR: Every 50ms: check_stale_fragments_with_transport()

    RTR->>FB: get_stale_sequences(threshold=100ms)
    FB-->>RTR: [(guid, seq=5, missing=1, total=3, age=120ms, src_addr)]

    RTR->>FB: get_missing_fragments(guid, seq=5)
    FB-->>RTR: missing=[2], total=3

    RTR->>RTR: RouterMetrics.nack_frag_requests += 1
    RTR->>NET: NACK_FRAG (seq=5, missing=[2])
    NET->>W: Retransmit fragment 2

    Note over RTR: If sequence exceeds timeout (1000ms)
    RTR->>FB: evict_expired()
    FB->>FB: Remove stale sequence (seq=5)
    RTR->>RTR: RouterMetrics.fragment_timeouts += 1
```

---

## 7. Intra-Process Auto-Binding

When both writer and reader are in the same process, HDDS uses the
`DomainRegistry` to bypass network transport entirely.

Implementation: `crates/hdds/src/dds/domain_registry.rs`

```mermaid
sequenceDiagram
    participant App as Application
    participant PA as Participant A<br/>(IntraProcess)
    participant REG as DomainRegistry<br/>(DomainState)
    participant DW as DataWriter<T>
    participant DR as DataReader<T>
    participant PB as Participant B<br/>(IntraProcess, same domain)

    App->>PA: Participant::builder("A").build()
    PA->>REG: Register participant A in domain 0

    App->>PB: Participant::builder("B").domain_id(0).build()
    PB->>REG: Register participant B in domain 0

    App->>PA: create_writer::<Temp>("sensors", QoS)
    PA->>DW: Create DataWriter
    DW->>REG: Register endpoint<br/>(topic="sensors", kind=Writer, type_id)
    REG->>REG: Check for matching readers
    REG-->>DW: No matches yet -> BindToken

    App->>PB: create_reader::<Temp>("sensors", QoS)
    PB->>DR: Create DataReader
    DR->>REG: Register endpoint<br/>(topic="sensors", kind=Reader, type_id)
    REG->>REG: Check for matching writers
    REG->>REG: Found: DW on topic="sensors"<br/>MatchKey(Writer, Reader) -> AUTO-BIND

    Note over DW,DR: Auto-bound via DomainRegistry<br/>No network, no serialization overhead

    App->>DW: write(&Temperature{value: 23.5})
    DW->>DW: encode_cdr2()
    DW->>REG: Deliver to matched readers
    REG->>DR: Direct CDR2 delivery
    DR->>DR: decode_cdr2()
    Note over DR: StatusCondition triggered<br/>WaitSet unblocks
```

---

## 8. TCP Connection Lifecycle

TCP transport for WAN environments where UDP multicast is blocked.

Implementation: `crates/hdds/src/transport/tcp/`

```mermaid
sequenceDiagram
    participant A as Participant A<br/>(TCP Client)
    participant IO as TcpIoThread<br/>(mio event loop)
    participant CM as ConnectionManager
    participant NET as Network (TCP)
    participant B as Participant B<br/>(TCP Server)

    Note over A: ParticipantBuilder<br/>.with_tcp(TcpConfig{<br/>  role: Client,<br/>  connect_addr: "B:7420"<br/>})

    A->>IO: Spawn TCP I/O thread
    IO->>IO: Create mio::Poll, register listener

    Note over A,B: Phase 1: TCP connection

    IO->>NET: TCP SYN
    NET->>B: TCP SYN received
    B->>NET: TCP SYN-ACK
    NET->>IO: TCP SYN-ACK
    IO->>NET: TCP ACK
    IO->>CM: pending_outbound.insert(B_addr)

    Note over A,B: Phase 2: RTPS over TCP (framed)

    A->>IO: Send RTPS packet
    IO->>IO: FrameCodec.encode([len: u32 | RTPS bytes])
    IO->>NET: TCP frame: [4-byte length | RTPS message]
    NET->>B: TCP frame received
    B->>B: FrameCodec.decode()<br/>Extract RTPS message

    Note over B: First RTPS message from A
    B->>B: extract_guid_prefix_from_rtps()<br/>Extract A's GUID prefix from RTPS header
    B->>CM: Promote pending_inbound -> active<br/>ConnectionManager.connections[A_guid] = stream
    B->>B: Emit Connected event<br/>Route RTPS via UnicastRouter

    Note over A,B: Phase 3: TLS upgrade (if tcp-tls feature)

    Note over IO: If TcpConfig.tls_config is set
    IO->>IO: TlsConnectionState::new(rustls config)
    IO->>NET: TLS ClientHello
    NET->>B: TLS ServerHello + Certificate
    IO->>IO: rustls verify certificate chain
    IO->>NET: TLS Finished
    Note over IO,B: All subsequent TCP frames are encrypted
    IO->>IO: FrameCodec.feed(tls_plaintext)<br/>decode_buffered() for RTPS extraction
```
