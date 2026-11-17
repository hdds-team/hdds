# Changelog

All notable changes to HDDS are documented here, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) shape, and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## How versions work here

The published line is the crate on crates.io: **1.0.8 (2026-02-27) through 1.1.2 (2026-04-17)**.
Those seven releases are the only versions anyone outside the project has been able to install,
and the sections at the end of this file describe them. Every date given for them is the
crates.io publication date, so each one can be checked there.

Two other families of numbers exist and are deliberately not releases:

- Work after 1.1.2 carried higher workspace versions (1.1.3 to 1.4.x) on internal branches, some of
  them also as git tags, while the source was held back. None of those numbers was ever published on crates.io,
  so nobody outside the project could install them. They are listed under "Version numbers that
  were never published" below. 1.5.0 is the release that publishes that work.
- The interoperability binary submitted to the OMG `dds-rtps` test suite is named after the build
  that produced it (`hdds-1.4.6`, `hdds-1.4.7`, `hdds-1.4.8`). It is a single test executable, not
  the library, and its number counts submissions rather than releases, which is why those numbers
  do not line up with the ones below.

Entries list what changed for someone using HDDS. Where the record does not say precisely which
release carried a change, the entry says so rather than guessing.

## [1.5.0]

### Why there was no public release since 1.1.x

The work between 1.1.x and 1.5.0 (including the 1.4.0 entries below, never published)
stayed offline while hdds took part in the OMG DDS interoperability tests. This was an
explicit choice: the code under test was not changed in public while the tests ran.
We are sorry for the long silence it meant for everyone following the project; 1.5.0
publishes all of that work at once.

### Highlights

- **Upgrade notes first.** Read "Upgrading" below before moving from 1.1.x (the last published crates are 1.1.2). In particular:
  - regenerate Rust code produced by hddsgen 1.x with hddsgen 2.0 (XCDR1 capability, and APPENDABLE as the default extensibility of an unannotated type, per DDS-XTypes 1.3 7.3.1.2.1.8);
  - a FINAL type (the hddsgen 1.x default) no longer matches the APPENDABLE type Connext 6 declares for the same unannotated IDL, because 1.5.0 now reads the legacy TypeObject that Connext and CoreDX announce;
  - `HDDS_SOURCE_ALLOW` / `HDDS_SOURCE_DENY` are now refused at participant creation: they were parsed but never applied;
  - protected payloads use the DDS-Security 1.1 CryptoHeader/Content/Footer; upgrade secure peers together.
- **Reliable data loss fixed.** A reliable reader could permanently lose samples in four join situations, now owed and delivered:
  - DATA dropped before its writer was discovered;
  - coherent sets and partitions;
  - GROUP-ordered access;
  - multicast DATA dropped by the router before the writer was bound to its topic.
  The remaining drop-versus-binding race is documented as a known limitation.
- **Security.**
  - The secure reader decides payload protection once, at the router; the first sample could previously be decoded with its CDR header across the SEDP race.
  - The per-writer state kept for unauthenticated DATA is bounded (memory DoS).
  - A governance requesting metadata or RTPS protection that this release does not implement is refused, proven by tests.
  - Known limitations are documented.
- **Interoperability.**
  - 1.5.0 reads the legacy TypeObject v1 (Connext PID 0x8021, CoreDX PID 0x0072) and judges types with it.
- **hdds-micro on seL4.** hdds-micro, the embedded subset of HDDS, runs inside seL4
  Microkit protection domains: on a Raspberry Pi 4 it exchanged RTPS samples with a
  Linux hdds-micro peer over the LAN in both directions (static unicast, no discovery
  yet). Details and evidence in crates/hdds-micro-sel4/README.md.

### Upgrading

- Setting `HDDS_SOURCE_ALLOW` or `HDDS_SOURCE_DENY` now makes participant
  creation fail with a configuration error. These variables were parsed but
  never applied: a participant that seemed to filter sources accepted every
  peer. Unset them; source filtering is planned for a later release.
- `SampleInfo` gains four public fields: `disposed_generation_count`,
  `sample_rank`, `generation_rank` and `absolute_generation_rank`; add them to
  explicit struct literals. The ranks are computed at access against the
  returned collection, the absolute one against the newest sample received,
  and the generation distance combines the disposed and no-writers counts
  (DDS v1.4 Sec.2.2.2.5.1.5-6).

- `IndexEntry.flags` is now `u16` (was `u8`); a struct literal or a stored
  copy of that public field needs the wider type.
- Protected user payloads now use DDS-Security 1.1 CryptoHeader, CryptoContent
  and CryptoFooter in place of the complete SerializedPayload. Upgrade secure
  peers together; the private payload envelope and its `SecuredPayload` Rust
  API are removed, with no compatibility decoder. The user-data codec now
  exposes `encode_serialized_payload` and `decode_serialized_payload`, using
  the complete writer key material. Secure 1.4.x peers remain
  refused during authentication. Encrypted keyed types must implement
  `DDS::write_key_holder` to compute the protected MD5 KeyHash. A keyed type
  must also read its own key-only payload back (`DDS::key_hash_of_key_payload`,
  advertised together with `DDS::encode_key` by `DDS::keys_round_trip`):
  without it, every dispose and unregister of a key-protected topic would be
  dropped by the reader. Generated types provide the whole set; a
  hand-written type that does not is refused at endpoint creation, writer and
  reader alike, on a topic under key protection (`data_protection_kind`
  ENCRYPT). Opaque keyed writers without key serialization are refused when
  key protection is enabled.

- `hdds_persistence::dds_interface::DurabilityKind` now includes `Transient`.
  Add that arm to exhaustive matches; the durability ordering is Volatile,
  TransientLocal, Transient, Persistent (`rank()` values 0 through 3).

- `RawDataReader::try_take_raw_with_info_and_encoding()` returns each payload
  with its `SampleInfo` (including the instance handle) and CDR version.
  `RawSample` retains its previous fields for struct literals and exhaustive
  destructuring; consumers needing instance metadata should use the new method.

- `hdds_persistence::store::RetentionPolicy` gains `max_instances` (0 means
  unlimited). Add the field to existing struct literals. External backends
  must override `save_with_instance_limit` for atomic finite-limit admission;
  its default implementation returns an error for a finite limit. Service
  subscribers count rejected samples in `samples_rejected`.
  Add that field to explicit `SubscriberStats` struct literals.

- Persistence `Sample` and `ReceivedSample` gain `source_timestamp_ns` and
  `destination_order_by_source`; add them to struct literals. Older serialized
  records and databases default to unknown source time and reception order.
  External DDS backends supporting source order must implement
  `create_writer_with_destination_order`.

- External persistence backends must implement `save_with_policy` for atomic
  total-capacity admission; its default refuses finite total limits. Service
  subscribers call this method with their full policy. The old instance-only
  method remains available.

- **Upgrade readers before writers.** A DataWriter that sets no
  DATA_REPRESENTATION now offers and encodes XCDR1 by default (see the
  entry below); a reader still running the 1.4.x line, or any C/C++/Python/
  TypeScript SDK or `libhdds_c` build from before this release, announces
  `DATA_REPRESENTATION = [XCDR1]` too (DDS-XTypes 1.3 7.6.3.1.1's "empty
  list" default was already XCDR1 for a reader on both lineages) but its
  decoder was generated to read XCDR2 bytes only, because every 1.4.x
  default WRITER encoded XCDR2 at run time -- the pairing worked by two
  defaults happening to agree on content, not because the reader
  requested or decoded XCDR1 natively. Once a 1.5.0 default writer is in
  the mix, that 1.4.x reader matches it (both announce XCDR1) and is
  handed genuinely XCDR1-encoded bytes its decoder cannot read: a
  REQUESTED_INCOMPATIBLE_QOS never fires (the QoS announcement matched),
  and the failure surfaces as a decode error or a wrong value instead.
  Upgrade every reader -- the C ABI (`libhdds_c`) and every SDK built on
  top of it (C, C++, Python, TypeScript) -- to 1.5.0 before any writer in
  the same deployment moves to a 1.5.0 default. A writer that explicitly
  sets `data_representation_xcdr2()` (Rust) / the equivalent QoS call in
  any SDK is unaffected either way: its offer does not change across this
  release
- **Regenerate Rust code produced by `hddsgen` 1.2.x or earlier with
  `hddsgen` 1.3.** Such code does not implement
  `DDS::encodes_xcdr1_natively`, which now defaults to `false` (see the
  entry on the default writer representation), so under 1.5.0 its default
  writer offers and encodes XCDR2 instead of XCDR1. A peer whose reader
  requests XCDR1 alone (a default Fast DDS reader, for example) refuses
  the pair with an incompatible DATA_REPRESENTATION and receives nothing.
  Code from `hddsgen` 1.3 declares the capability. `hddsgen` 1.3 also makes
  a type with no extensibility annotation APPENDABLE; pass
  `--default-extensibility final` to keep the 1.2.x layout. The
  extensibility now decides matching with peers that announce a legacy
  TypeObject (Connext 6, CoreDX), which 1.5.0 reads: Connext 6 declares an
  unannotated IDL type APPENDABLE, so a FINAL type (the 1.2.x default) no
  longer matches it, as XTypes requires. Regenerate with 1.3 or annotate
  both sides alike
- **A typed reader's raw `take()` can return bytes with no representation
  id to check against.** In every SDK, `take_with_encapsulation()` /
  `takeWithEncapsulation()` (and the C ABI's `hdds_reader_take_ex`) pair
  the bytes with the encapsulation id that names their CDR version; the
  plain `take()` on a TYPED reader does not, because it decodes through
  the generated type's own decoder, which already knows its version. The
  C++ SDK's typed `DataReader<T>::take()` is the one exception worth
  calling out explicitly: when `T::deserialize` has no
  `decode_by_encapsulation` overload (a type generated before `hddsgen`
  1.3), `take()` silently assumes XCDR2 and decodes whatever bytes it is
  handed with no check at all -- see `docs/api/cpp.md` for the warning on
  that fallback and how to tell whether a given `T` has it
- **A keyed type generated by `hdds_gen` does not agree with its 1.4.x
  build on instances: upgrade every writer and reader of such a topic
  together.** 1.4.x generated an FNV-1a `compute_key`, 1.5.0 (with `hddsgen`
  1.3 and later) the KeyHash of DDSI-RTPS 2.5 9.6.4.8 / DDS-XTypes 1.3 7.6.8
  (see "The instance KeyHash is the one RTPS 2.5 9.6.4.8 specifies" under
  Fixed). Nothing on the wire says which one a peer computes, so no
  translation is possible. What happens across the boundary:
  - **Samples are not affected**: a reader names a sample's instance by
    computing it from the sample, both ways
  - **1.4.x writer to 1.5.0 reader**: a `dispose`, `unregister_instance` or
    unregister-and-dispose (also the unregisters a writer sends when it is
    deleted) carries the FNV hash as PID_KEY_HASH and no key (the 1.4.x
    generated `encode_key` was empty). The 1.5.0 reader names a change by
    its serialized key when there is one; failing that, by the real
    instance that SAME writer's own FNV hash already named on one of its
    ordinary ALIVE samples, if this reader decoded one (every 1.4.x sample
    carries the hash, not only a lifecycle one) -- and only then by the
    raw PID_KEY_HASH, which, with nothing yet decoded to resolve it
    against, names an instance the reader never wrote. In that residual
    case the application takes a NOT_ALIVE_DISPOSED or
    NOT_ALIVE_NO_WRITERS for the phantom handle, the real instance stays
    ALIVE, and under EXCLUSIVE ownership the owner's unregister does not
    release it: a weaker writer stays hidden until the owner leaves. The
    writer's departure (its SEDP dispose, its participant leaving or its
    lease expiring) still releases what it wrote, since the reader tracks a
    writer's instances by its own KeyHash
  - **1.5.0 writer to 1.4.x reader**: the same, reversed. The 1.5.0 writer
    sends the specification's KeyHash and its serialized key; the 1.4.x
    reader names the change by PID_KEY_HASH alone, which is not its FNV
    value
  - **A key `hdds_gen` does not cover** (a map, `fixed`, `long double`,
    `@optional`, a collection of non-primitive elements) gets no KeyHolder:
    every sample of the type is one instance in 1.5.0 (the all-zero
    KeyHash, a warning logged once), where the 1.4.x FNV digest told them
    apart
  - **Not affected**: types whose 1.4.x `compute_key` already was the KeyHash
    (the shapes demo's ShapeType, hand-written ones), `#[derive(DDS)]`
    types (1.4.x had no `#[key]`, so they were unkeyed), the C, C++, Python
    and TypeScript SDKs (they write through the C API as keyless payloads
    and have no dispose or unregister call, in both releases), and
    `hdds-micro` (no inline QoS, no lifecycle change)
- **A reader that requests DESTINATION_ORDER BY_SOURCE_TIMESTAMP no longer
  has its listener's `on_data_available` called with each sample.** 1.4.x
  ignored the policy and delivered in reception order, payload callbacks
  included. 1.5.0 implements it (see "DESTINATION_ORDER BY_SOURCE_TIMESTAMP"
  under Fixed): the application reads samples selected by the reader's
  source-ordered history, whose retained contents can change before access.
  The DATA_AVAILABLE status and any WaitSet on it are still
  raised; an application that consumed callback payloads on such a reader
  must implement the new payload-less
  `DataReaderListener::on_data_available_notification` callback and reads
  with `take`/`read` there instead (DDS v1.4 Sec.2.2.4.3.2). Notifications
  run outside reader locks on network, coherent and intra-process delivery;
  the DATA_AVAILABLE listener mask controls them. Readers with the default
  policy are unaffected.

### Breaking changes

- **The DDS-Security handshake is signed as the specification defines it,
  and an HDDS 1.4.x secure peer can no longer authenticate with 1.5.0.**
  The AuthReply signature of every earlier release covered
  `c.id || challenge1 || dh1 || challenge2`: the responder's DH public key
  (`dh2`) was unsigned, so an attacker on the path could replace it in a
  genuine reply with a key of its own, and the initiator then completed
  the handshake on a secret the attacker knew. The AuthFinal signature
  covered no hash, so neither side's key vouched for its `c.` properties (a
  permissions document replaced on the way was taken as the peer's).
  1.5.0 follows DDS Security v1.1 Sec.9.3.2.5 throughout, and accepts
  nothing else (accepting the old signature would keep the hole open)
  - The reply signs the CDR Big Endian BinaryPropertySeq `hash_c2,
    challenge2, dh2, challenge1, dh1, hash_c1` (Table 50), the final
    `hash_c1, challenge1, dh1, challenge2, dh2, hash_c2` (Table 51);
    `hash_c1`/`hash_c2` are the SHA-256 of the request's and the reply's
    `c.` properties (Tables 49 and 50)
  - The request and the reply carry `c.id`, `c.perm`, `c.pdata`,
    `c.dsign_algo` and `c.kagree_algo` as binary properties, and send
    `hash_c1`/`hash_c2`, checked when a peer sends them
  - `c.perm` is sent always, empty without access control (Cyclone DDS
    refuses a handshake message without it). An absent, empty or lone-NUL
    `c.perm` from a peer is no permissions document, judged by our
    governance alone; the NUL Cyclone DDS appends to its document is no
    part of it
  - The reply's `dh1` and the final's `dh1` and `dh2` are optional
    (Tables 50 and 51): accepted absent, and refused when present and not
    the session's
  - `c.pdata` is the sender's ParticipantBuiltinTopicData, a big-endian
    parameter list carrying its participant GUID (earlier releases sent it
    empty). A peer's `c.pdata` must name the participant the handshake is
    with, under a prefix bound to its certificate: bit 0 set and bits 1 to
    47 those of the SHA-256 of its SubjectName (Sec.9.3.3, Table 52,
    `begin_handshake_reply`), checked on the request and on the reply as
    Cyclone DDS and Fast DDS do. The unbound prefix of HDDS before 1.5
    (vendor id first) is refused like any other.
    `HandshakeMachine::start` no longer takes a `local_pdata` argument: the
    machine serializes the participant data itself
  - Rust API: the public token structs re-exported by
    `hdds::security::handshake` change shape, so code that builds or
    destructures them must follow. `AuthReplyToken.dh1`,
    `AuthFinalToken.dh1` and `AuthFinalToken.dh2` are `Option<Vec<u8>>`
    (were `Vec<u8>`); `AuthReplyToken` gains `pdata`, `dsign_algo`,
    `kagree_algo` and `hash_c1: Option<[u8; 32]>`; `AuthFinalToken` gains
    `hash_c1` and `hash_c2` (`Option<[u8; 32]>`); `AuthRequestToken` and
    `AuthReplyToken` gain `permissions_doc: Option<Vec<u8>>`.
    `HandshakeMachine::start` takes `(local_guid, remote_guid,
    local_cert_der, local_key_pem)`, without the former `local_pdata`
  - A handshake token travels in its ParticipantStatelessMessage
    (Sec.7.4.3.3: message identity, destination participant, class id
    `dds.sec.auth` or `dds.sec.auth_request`, the token in message_data)
    behind a CDR encapsulation header; earlier releases put the bare token
    in the DATA, which no other implementation reads, and read nothing
    else
  - A handshake message that arrives as DATA_FRAG (an AuthReply of
    Cyclone DDS is five fragments) reaches the handshake once reassembled;
    it was dropped
  - An IdentityToken's properties are optional (Table 45; Cyclone DDS
    sends none) and its class id is compared by plugin name and major
    version (Table 52); a participant whose token carried no
    `dds.cert.sn` was refused
  - The three messages carry the class ids of Tables 49 to 51
    (`DDS:Auth:PKI-DH:1.0+Req`, `+Reply`, `+Final`, where earlier releases
    sent `+AuthRequest`, `+AuthReply`, `+AuthFinal`)
  - An ECDSA signature is the DER-encoded value of ANSI X9.62 (earlier
    releases sent the fixed-width `r || s`, which Cyclone DDS and Fast DDS
    refuse)
  - An RSA identity signs RSASSA-PSS with SHA-256 and MGF1-SHA-256
    (Sec.9.3.2.5.2; earlier releases signed PKCS#1 v1.5, and could not
    verify an RSA peer at all), and `c.dsign_algo` names the algorithm of
    the identity's key (`RSASSA-PSS-SHA256` or `ECDSA-SHA256`) instead of
    always `ECDSA-SHA256`. A peer's signatures are verified by the
    algorithm it announces, which must be its key's; any other is refused
  - A peer's RSASSA-PSS signature is verified whatever its salt length,
    read from the signature (the specification fixes none). OpenSSL before
    3.1 signs with the maximum salt by default, and Cyclone DDS sets no salt
    length, so a Cyclone DDS built on OpenSSL 1.1.1 or 3.0 sends the
    maximum, which HDDS refused; Fast DDS signs with the digest length.
    PKCS#1 v1.5 and MGF1-SHA1 stay refused. HDDS signs with a salt of the
    digest length (32 octets)
  - What a mixed deployment sees: a 1.4.x peer's handshake message is
    refused with "peer uses the pre-1.5 handshake signature", logged at
    warning level, and an HDDS participant announcing no
    `CAP_ONE_FUTURE_CHALLENGE` (every 1.4.x release) is logged and recorded
    in the audit chain as unable to authenticate, once, when discovery
    first sees it. Upgrade every secure participant to 1.5.0 together;
    participants without security are unaffected
- **A remote participant that presents no permissions document gets no
  access to an access-controlled topic.** With `enable_join_access_control`
  FALSE, a peer whose handshake carried no `c.perm` (or an empty one) was
  admitted on every topic, including those whose governance rule sets
  `enable_read_access_control` or `enable_write_access_control`: a peer
  whose valid document denies a topic could simply stop sending it. Join
  access control decides whether the participant gets in; each endpoint is
  then `check_remote_datawriter` / `check_remote_datareader` (DDS-Security
  v1.1 Table 63), which succeeds without a grant only on a topic whose rule
  leaves that access control off. Such a peer is now refused on a topic
  whose rule enables it, and on a topic no rule matches (9.4.1.2.7). The
  short governance form (no `<topic_access_rules>`) controls every topic.
  A peer without a document still authenticates, and still matches on the
  topics the governance leaves open
- **`MemoryPolicy` has a new public field, `reader_reserve_percent`.** A
  `MemoryPolicy { large_pool, max_heap_bytes }` literal no longer compiles:
  add `..MemoryPolicy::default()`. `ParticipantBuilder::build` refuses a
  value outside `MemoryPolicy::READER_RESERVE_PERCENT_MIN..=
  READER_RESERVE_PERCENT_MAX` (1..=93) with `Error::Config` naming the
  field. A process that only writes now gets 75 % of each tier of the slab
  pool at the default 25 (see "Changed")
- **`MemoryPolicy` has a new public field, `max_staging_bytes`**: the most
  bytes the coherent readers of the process stage together (default
  `MemoryPolicy::MAX_STAGING_BYTES_DEFAULT`, 64 MiB). A literal without
  `..MemoryPolicy::default()` no longer compiles. `ParticipantBuilder::build`
  refuses a value below `MemoryPolicy::MAX_STAGING_BYTES_MIN` (1 MiB) with
  `Error::Config` naming the field (see "Changed")
- **A DDS-Security governance document that does not say what it protects is
  now refused at load.** The previous parser recognised four element names and
  dropped everything else with no diagnostic, and three of those four appear in
  no DDS-Security document. A governance file written to the specification
  parsed into a rule with every protection OFF, silently. A file written to the
  short names this project's own security guide documented parsed correctly.
  Both now go through the same strict reader
  - Inside `<domain_rule>`, these are REQUIRED and have no default:
    `<domains>`, `<allow_unauthenticated_participants>`,
    `<enable_join_access_control>`, a discovery protection element and a data
    protection element. A rule missing one is refused, naming it. An absent
    element used to read as "off" - the one reading an operator never intends
  - The short names (`<allow_unauthenticated>`, `<encrypt_discovery>`,
    `<encrypt_topics>`) still parse, because documents written against our own
    guide exist and breaking them would punish people for following our
    documentation. New documents should use the specification's names
  - Booleans are read as the specification writes them (`TRUE`, `FALSE`,
    case-insensitive, `1`, `0`); `yes` and an empty element are refused
    rather than read as `false`. An element given twice in one rule is
    refused
  - Per-topic rules are read (DDS-Security v1.1 9.4.1.2.6): a
    `<topic_access_rules>` block of `<topic_rule>` elements, every element
    required, the first rule whose `fnmatch` expression matches a topic
    applied to it, and a topic no rule matches refused. A domain-level
    `<data_protection_kind>` with no topic rules is the shorthand for one `*`
    rule; the two together are refused
  - The rules produce the specification's security attributes: each endpoint
    is announced on the secure discovery topics when its topic rule says
    `<enable_discovery_protection>TRUE`, protected by
    `<discovery_protection_kind>` (`NONE`, `SIGN` = AES-GMAC, `ENCRYPT` =
    AES-GCM, or either with origin authentication), and only to
    participants that have authenticated; otherwise on the regular ones, in
    clear. `PID_PARTICIPANT_SECURITY_INFO` and `PID_ENDPOINT_SECURITY_INFO`
    carry the attribute bits. `<enable_read_access_control>` /
    `<enable_write_access_control>` `FALSE` let readers / writers of a topic
    through without the permissions document. A topic whose
    `<data_protection_kind>` is `ENCRYPT` refuses its writers and readers on a
    participant built without `enable_encryption(true)`, where its samples
    used to cross in clear. A reader of such a topic refuses a sample whose
    payload is not sealed (counted, logged once per reader): the DATA
    around a payload is not authenticated, so a cleartext one is a forgery
    anybody can send under the writer's GUID
  - `<allow_unauthenticated_participants>` is applied; it used to be parsed,
    announced and read by nothing. `FALSE` rejects at discovery a
    participant that presents no identity token, whatever
    `require_authentication` says (DDS-Security v1.1 8.8.2.2). `TRUE` admits
    it, and on a topic with read or write access control it is refused like
    any endpoint the security plugins refuse (below). On a topic with
    neither, it is matched like any participant
  - What the match refuses, the data plane refuses: one admission verdict
    per remote participant, topic and endpoint kind, reached when discovery
    pairs them and cached until the participant leaves, its authentication
    state changes or an endpoint is announced (a cache lookup per packet
    and endpoint after that; skipped when security is not configured). It refuses an
    unauthenticated participant where the governance does (above), a
    participant whose handshake is in progress or failed, and an
    authenticated one whose permissions do not grant the topic in the
    endpoint's partitions (8.8.7.1, 9.3.4, 9.4.3), and an endpoint whose
    participant's credentials went between its admission and its
    per-endpoint judgement (fail closed). Our writers send a
    refused reader nothing: not data, heartbeats or repairs, not the
    late-joiner history replay of a TRANSIENT_LOCAL writer (which used to
    hand a refused reader the writer's whole history; a reader refused while
    its participant's handshake is in progress gets it when the handshake
    completes, at most 256 such replays and 64 KiB of names kept per
    participant and 4096 and 1 MiB overall, a participant past its bound
    losing only its own oldest), not the
    participant fallback taken before any reader is known (which used to
    send every sample to every participant's default locator, the refused
    ones included), and its ACKNACK is not answered (it used to be served
    as "a GUID discovery never announced", durability history included).
    Our readers refuse a refused writer's samples, dispose and unregister,
    its HEARTBEATs and GAPs (no ACKNACK, no change to what the reader
    acknowledges, asks again or counts as lost), and a sample or lifecycle
    change that names no writer; our writers
    leave unanswered a NACK that names no reader, whose repair went to the
    multicast group. Before this, a
    match refused for an authenticated peer's permissions or an incomplete
    handshake left the data flowing both ways. Not reached: data a writer
    sends to a multicast group, or puts in its shared-memory ring, reaches
    whoever listens on the group or opens the ring on the host. A protected
    topic's writer no longer falls back to multicast towards an audience it
    does not know, nor sends large samples on the multicast route: not its
    samples, HEARTBEATs, HEARTBEAT_FRAGs or ends of coherent sets, and not
    its repairs (a DATA_FRAG repair on the large-payload route, or a repair
    for a requester whose locator is unknown, used to reach the group); only
    `<data_protection_kind>ENCRYPT` keeps captured traffic unreadable
  - The TypeLookup service (DDS-XTypes getTypes and HDDS's own) no longer
    describes a type to a participant that has not authenticated with us
    when our endpoints announce that type on discovery-protected topics
    only: their announcement, type information included, goes on the secure
    SEDP topics to authenticated participants (DDS-Security v1.1 7.4.1.7,
    7.4.1.8, 9.4.1.2.6.2; the specification says nothing of TypeLookup
    itself). A type one of our endpoints announces on the regular topics is
    served to anyone, as before
  - The writer-less ingest path refuses a cleartext payload on a topic whose
    payload the governance protects, as the per-writer path already did
  - What this release does not apply is refused at load, by name:
    `<rtps_protection_kind>` and `<liveliness_protection_kind>` other than
    `NONE`, `<enable_liveliness_protection>TRUE`, `<metadata_protection_kind>`
    other than `NONE`, and `<data_protection_kind>SIGN`
  - Any other element inside `<domain_rule>` or `<topic_rule>` is an error
    naming the element
  - A value must be one run of character data. A comment, processing
    instruction or element inside it (`Open<!-- x -->Secret`) is refused,
    naming the element: the parser kept only the text before it, so
    `*<!-- -->Secret` read as `*`. The same holds in the permissions
    document, where an `<allow_rule>` or `<deny_rule>` that does not read is
    now an error instead of a rule silently left out
  - Both documents are refused before parsing when their elements nest
    more than 64 levels deep (the schemas nest seven) or when they carry a
    DTD. Ten thousand nested elements overflowed the parser's stack and
    aborted the process, a peer's permissions document in the handshake
    included
  - A `<topic_expression>` ending in an unpaired backslash matches no topic,
    as glibc's `fnmatch` decides; it used to match a name ending in a
    backslash
  - `<id_range>` is stored as bounds and never expanded. The previous parser
    expanded it into a list clamped at 255, which silently discarded every
    legitimate domain id above 255; removing the clamp without changing the
    representation would have let a signed document carrying
    `<max>4294967295</max>` allocate roughly 17 GB before any rule was
    evaluated. `<max>` may now be omitted, meaning "from `<min>` upwards"
  - **If your governance document loads today and fails after upgrading, the
    error names the element.** `docs/security-guide.md` carries a complete
    accepted example, and every example in the guides and the SDK samples is
    now parsed verbatim by a test
- **Certificate revocation is checked, and `check_certificate_revocation`
  without a CRL no longer builds.** The flag shipped with no way to supply a
  list: its only effect was to make identity validation refuse
  unconditionally, so `secure_builder()` could not authenticate at all
  - Name a CRL with `certificate_revocation_list(path)`, PEM or DER. It is
    REQUIRED whenever the flag is on, and `SecurityConfig::build()` now refuses
    the pair by name rather than starting and checking nothing
  - Both the local identity and every remote peer certificate are checked, on
    both authentication paths (the PKI-DH handshake machine and the X.509
    plugin's `process_handshake`). The remote half is new in the sense that it
    never existed: the handshake's certificate trust check had no revocation
    logic of any kind, so a revoked peer authenticated
  - **A CRL is believed only if it comes from the certificate's issuer and its
    signature verifies against that CA's key.** A list from another CA says
    nothing about this certificate and is not "not applicable", it is a
    refusal: with the flag on, every certificate's issuing CA must have a
    current CRL in the list. A list that names the right issuer and fails to
    verify is forged or corrupt and is refused by name
  - The list may be a PEM bundle of several CRLs (one per issuing CA), or a
    single DER CRL. Every block is parsed; a corrupt one fails the check
    rather than being skipped
  - **A CRL past its `nextUpdate`, or carrying none, is REFUSED.** Stale
    revocation data cannot prove a certificate has not been revoked since the
    list was issued. If your CRL expires, participants stop admitting peers -
    that is the intended behaviour, and it means a CRL refresh is now an
    operational duty
  - A revoked LOCAL identity fails at participant BUILD, before a socket is
    bound or anything is announced, not at the first handshake
  - `certificate_revocation_list` with `check_certificate_revocation` OFF is
    refused too: the flag is the single switch, and a list nobody consults is
    a configuration that looks like revocation checking and is not
  - A system clock before the Unix epoch is an error on every certificate
    validity check; it used to read as `now = 0`
- **A remote peer is now checked against its own permissions, and a grant
  reaches only the domains it names.** Two changes that bite together
  - Each participant presents its signed permissions document in the handshake
    as the DDS-Security `c.perm` property, and a discovered remote endpoint is
    refused if that document does not grant the topic. A peer presenting NO
    document is judged by your governance: refused when
    `<enable_join_access_control>` is `true`, admitted when `false`. **No HDDS
    release before 1.5.0 sends `c.perm`**, so a secured deployment that mixes
    1.5.0 with an earlier version must upgrade together, or set
    `<enable_join_access_control>false</enable_join_access_control>` for that
    domain
  - `Rule::domains` in a permissions grant was parsed and read by nothing: an
    `<allow_rule>` written for domain 229 applied on every domain the
    participant joined. It is now enforced. A grant that names the wrong
    domain, or names none, stops granting - check your `<allow_rule>` and
    `<deny_rule>` domains before upgrading
  - `<id_range>` in a permissions grant is stored as bounds rather than
    expanded, so ids above 255 are no longer silently dropped. This was fixed
    in the governance parser and missed here; both now share one reader
- **`QoS` gains `data_tags`, the DataTagQosPolicy of DDS-Security v1.1
  7.2.5.** A struct literal of `QoS` without `..QoS::default()` must name it.
  A remote endpoint's tags are read from `PID_DATA_TAGS` (0x1003) in its
  SEDP announcement (XCDR1 and XCDR2 layouts, at most 256 tags); an
  announcement whose tags do not read whole is refused. HDDS does not
  announce data tags of its own endpoints: creating a writer or reader whose
  QoS carries tags fails with `InvalidQos`
- **A permissions grant is read as the specification writes it, never
  wider.** Each of these can refuse what 1.4.x allowed
  - Topic expressions are POSIX `fnmatch()` patterns (DDS-Security v1.1
    9.4.1.3.2.3.1.3), matched by the governance's matcher. The previous one
    knew `*`, `prefix/*`, `*/suffix` and `*middle*` only: a deny rule on
    `Secret*` denied nothing, so `allow *` granted `SecretPlans`. `?` and
    `[...]` now work, POSIX bracket classes (`[[:upper:]]`), equivalence
    classes and collating symbols included, matched as glibc's
    `fnmatch(p, s, 0)` matches them in the "C" locale, byte by byte (one
    matcher for the governance and the permissions): outside ASCII a
    character is its UTF-8 bytes, so `?` matches one byte of it, a bracket
    element is one byte, ranges compare bytes and no class holds a byte
    above 0x7F. glibc in a UTF-8 locale matches by character instead; the
    two agree on ASCII. A bracket glibc gives up on (an unknown class name
    such as `[[:uper:]]`, a multi-character collating symbol, a multi-byte
    character in one) is refused at load, and so is an expression longer
    than 4096 bytes (governance and permissions alike)
  - The rules of a grant apply in document order, allow and deny alike,
    the first that matches deciding (9.4.1.3.2.3: "The rules are applied in
    the same order that appear in the document"); the previous engine
    consulted every deny rule first. A rule matches when one of its
    `<publish>` (writers) or `<subscribe>` (readers) criteria matches the
    topic AND the endpoint's partitions AND its data tags, each criterion
    on its own (9.4.1.3.2.3.1.2). `Grant` holds `rules` in document order,
    each a `Rule` of `kind` allow or deny with its `publish` and `subscribe`
    `Criterion`s; `allow_rules`, `deny_rules`, `publish_topics`,
    `subscribe_topics` and `partitions` are gone
  - `<partitions>` and `<data_tags>` are evaluated, locally at creation (on
    every partition the endpoint names, where the builders passed one) and
    remotely at matching and on the data plane (on what the remote
    endpoint announced; a re-announcement that changes them is judged
    again). The previous parser dropped them, so an allow rule limited to
    partition A granted every partition
    - an allow rule's `<partitions>` is met when every partition of the
      endpoint matches one of its expressions (fnmatch), without
      `<partitions>` only the default partition (9.4.1.3.2.3.1.4). The
      "legacy matching" the same section asks implementations to offer (met
      when ONE partition of the endpoint matches, an allow rule for {A, B}
      then covering {A, B, C}) is selected by
      `SecurityConfig::builder().legacy_partition_matching(true)`, for this
      participant's document and its peers' alike; off by default
    - a deny rule's `<partitions>` is met when one partition matches,
      without `<partitions>` always (9.4.1.3.2.3.2.4)
    - an allow rule's `<data_tags>` is met when the endpoint's tags are a
      subset of its own, without `<data_tags>` only by an endpoint without
      tags (9.4.1.3.2.3.1.5); a deny rule's when the endpoint has one of its
      tags, without `<data_tags>` always (9.4.1.3.2.3.2.5)
    - a criterion without `<topics>`, an empty `<partitions>` or
      `<data_tags>`, a `<tag>` without one `<name>` and one `<value>`, or a
      condition given twice is refused at load; `<relay>` criteria are read
      and not applied (no relay-only matching)
  - An access-control audit record names the partitions the endpoint names,
    `topic (partitions [...])`, where it read `topic (partition "X" not
    evaluated)`
  - `<default>` is read (`ALLOW` or `DENY`, absent = `DENY`) and decides
    what no rule matches; it used to be ignored, as `DENY`. `Grant` gains
    the public field `default_allow`
- **A participant is refused on a domain its governance does not cover.**
  `check_create_participant` existed and had no caller anywhere in production:
  the governance was parsed, its domain rules were stored, and only a unit test
  read them. A deployment could name domain 5 in its governance, join domain
  400, and every layer above reported a secured participant. `Participant::
  build` now asks before anything binds a socket, and a domain no rule covers
  fails with `PermissionDenied`
  - Add the domain to a `<domain_rule>`, as a single `<id>` or inside an
    `<id_range>`
- **Audit records name only what the decision was made on.** An access-control
  record read `resource: "topic:partition"`, formatted as though both had been
  matched; the partition was never read by any check. A record now carries the
  topic, and says `topic (partition "X" not evaluated)` when a partition was
  requested. Anything parsing those records for the old `topic:partition` shape
  must be updated
- **HDDS now sends the registered DDS Foundation vendorId `{0x01, 0x1A}`.**
  Both the core and `hdds-micro` previously sent placeholders: the core sent
  `{0x01, 0xAA}` ("experimental, not assigned in OMG registry"), and
  `hdds-micro` sent `{0x01, 0x14}`, which is the identity actually registered
  to Dust DDS. Every RTPS message header, `PID_VENDOR_ID` in SPDP and SEDP,
  the GUID-prefix generator and the vendor classifier now carry `0x011A`
  - Any peer, capture filter, dissector rule or test fixture that keys on
    `0x01AA` or `0x0114` to recognise HDDS must be updated
- **`DataWriter<T>` is `Send` but no longer `Sync`.** `write()` produces into
  single-producer reader rings, so two threads calling `write()` on one shared
  writer violated that contract and compiled silently. The constraint is now in
  the type system, so sharing `&DataWriter<T>` across threads is a compile
  error
  - Move the writer into the thread that uses it, or place it behind your own
    mutex. `Arc<DataWriter<T>>` shared between threads no longer compiles
- **DDS-RPC changed on the wire and in the API, and is not compatible with a
  1.4 HDDS RPC peer.** The Basic-mapping headers are now byte-exact to
  `formal/17-04-01` section 7.5.1.1.1
  - `SampleIdentity.sequence_number` serializes as RTPS `SequenceNumber_t`
    (`high: i32` then `low: u32`), not as a single little-endian `i64`
  - `RequestHeader` carries `request_id: SampleIdentity` followed by
    `instance_name: String` (bounded to 255), replacing a second
    `SampleIdentity`. `RequestHeader::with_instance()` becomes
    `with_instance_name()` and the field `instance_id` becomes `instance_name`
  - `RemoteExceptionCode` now holds exactly the six values the spec defines
    (`Ok = 0`, `Unsupported = 1`, `InvalidArgument = 2`, `OutOfResources = 3`,
    `UnknownOperation = 4`, `UnknownException = 5`). The previous set
    (`UnsupportedService`, `UnsupportedMethod`, `ServiceUnavailable`,
    `Timeout`, `InternalError`, `Unknown`) is gone, and only the value `0`
    meant the same thing in both. `from_i32(i32) -> Self` is replaced by
    `from_wire(i32) -> Option<Self>`, which reports an unknown code instead of
    silently folding it into a catch-all
  - RPC traffic is pinned to `PLAIN_CDR_LE` encapsulation (`0x0001`) instead of
    following the representation a default writer chose at run time
- **`hdds::dds::Error::Config` is now `Error::Config(String)`.** The variant
  used to carry nothing, so a configuration failure reached the caller with no
  indication of what was wrong
  - `match` arms and `if let` patterns on `Error::Config` need a binding
- **`ShmPolicy::default()` is `Disable` instead of `Prefer` -- but read the
  next sentence before acting on it.** The enum's `Default` impl changed;
  **`ParticipantBuilder` does not use it.** The builder sets
  `shm_policy: ShmPolicy::Prefer` at `dds/participant/builder.rs:225`, as it
  has since the first public release and still does. So for every participant
  built through the normal API, **shared memory is offered by default, on both
  lineages, and this release does not change that.** The `Default` impl is
  reachable only by constructing a `ShmPolicy` on its own.

  What DID change is what that default now does. Before 1.5.0 the selection
  verdict had no consumer outside its own module, so `Prefer` resolved to UDP
  in practice. 1.5.0 wires the shared-memory data path for real, so a
  same-host, `BestEffort`, co-located pairing that used to take UDP now takes
  shared memory, silently, with no code change on your side. **That is the
  behaviour change to plan for**, and it is the opposite of what the first
  line alone suggests. Turn it off with `.shm_policy(ShmPolicy::Disable)`.

  One consequence worth stating because it is visible from outside the host:
  a participant offering shared memory announces a capability hint in an
  HDDS vendor-reserved discovery parameter, for every `BestEffort` endpoint.
  Peers of other vendors ignore it, as the parameter range requires, but it
  is on the wire by default
  - `ShmPolicy::Require` is now refused by `ParticipantBuilder::build()`
    outright. Fragmented samples are never carried over shared memory and
    whether a participant will ever write one is not knowable at build time,
    so `Require` could not be honoured honestly
- **`QoS` gained a public field, `type_consistency:
  Option<TypeConsistencyEnforcement>`.** `QoS` is not `#[non_exhaustive]`, so
  an exhaustive struct literal that does not end in `..Default::default()`
  stops compiling. The `QoS::default()`, `best_effort()` and `reliable()`
  constructors are unaffected
- **Public enums that gained variants.** None of these carry
  `#[non_exhaustive]`, so an exhaustive `match` on any of them stops
  compiling
  - `dds::Error` gained `EncryptionUnavailable(String)` (feature `security`),
    raised when a writer cannot encrypt and refuses the write rather than
    emitting cleartext
  - `transport::shm::TransportSelectionError` gained `ColocationNotProvable`,
    `LocalNonceUntrustworthy` and `RemoteNoNonce`
- **`discovery::cloud::CloudPollerConfig` is now `#[non_exhaustive]`**
  (feature `cloud-discovery`), so it can no longer be built with struct
  literal syntax from outside the crate
- **TypeLookup RTPS entity-id constants renamed.** The two old names were
  backwards relative to the bytes they held. `RTPS_ENTITYID_TYPELOOKUP_READER`
  becomes `RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER` and
  `RTPS_ENTITYID_TYPELOOKUP_WRITER` becomes
  `RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER`, both keeping their byte values,
  and `_REPLY_WRITER` / `_REPLY_READER` are added
- **DDS-Security plugin accessors changed** (feature `security`):
  - `SecurityPluginSuite::logging()` returns `Option<&AuditChain>` instead of
    `Option<&std::sync::Mutex<LoggingPlugin>>`, so the fail-closed degradation
    gate cannot be bypassed by taking the raw mutex
  - `SecurityPluginSuite::cryptographic_mut()` is removed
  - `SessionKeyManager` is now a fieldless namespace of derivation functions.
    Its `new()` and `Default` impl are gone
- **C ABI: opaque handles are plain incomplete types.** `HddsParticipant` and
  its siblings were declared as `typedef struct HddsX { uint8_t PRIVATE[0]; }
  HddsX;`, which relies on a GNU zero-length-array extension. They are now
  `typedef struct HddsX HddsX;`
  - Exported symbols are unchanged. This only affects code that took
    `sizeof()` of a handle or embedded one by value, neither of which a
    conforming consumer can do with an opaque type
- **The default Cargo feature set gained `xtypes-structural-assignability`.**
  It was `["xtypes", "qos-loaders"]` and is now
  `["xtypes", "qos-loaders", "xtypes-structural-assignability"]`. Opt out with
  `default-features = false`

- **Shared memory exists on Linux only, and the `TransportSelectionError`
  variants do not exist anywhere else.** `transport::shm` is gated on
  `target_os = "linux"`; on every other target the stub keeps
  `TransportSelectionError` as a plain `pub struct
  TransportSelectionError(pub String)` with no variants at all. A `match`
  written against `ColocationNotProvable`, `LocalNonceUntrustworthy` or
  `RemoteNoNonce` compiles on Linux and fails to compile on macOS and Windows.
  The Linux-only split is not new; the variants are
- **`ConsulOptions::with_health_check(port)` is removed.** Configure health
  checking with `with_health(ConsulHealthPolicy)`, which defaults to a
  self-reported TTL check instead of an HTTP port your process had to serve.
  There is no same-named drop-in
- **Public enums and structs without `#[non_exhaustive]` gained variants
  and fields.** An exhaustive `match` or a struct literal that names every
  field stops compiling; `..Default::default()` and a wildcard arm keep
  working
  - `hdds::core::discovery::multicast::PacketKind` gains `ParticipantMessage`
    (a peer's plaintext liveliness writer) and `UnknownBuiltin` (a builtin
    writer id no handler claims)
  - `TransportOptions` and `ResolvedTransportOptions` gain
    `external_locators`; `DiscoveryMetrics` gains `unclaimed_builtin_data`
  - Discovery Server client: `DiscoveryServerConfig` gains `relay`,
    `ClientError` gains `Backpressure`, `ClientMessage` and `ServerMessage`
    gain `Data`, `ClientEvent` gains `RelayDataReceived`
- **Fragment metadata describes a geometry, not a count.**
  `FragmentMetadata.total_frags` (a `u16` field) is replaced by a `geometry:
  FragmentGeometry` field (`fragment_size`, `sample_size`) and a
  `total_frags()` method, and `FragmentBuffer::insert_fragment` /
  `insert_fragment_with_addr` take a `FragmentGeometry` instead of a fragment
  count. A sample now completes only when its declared sizes are satisfied
  (see Fixed)
- **`DataWriter::write` on a RELIABLE writer whose history is full now waits
  up to 100 ms for acknowledgements, then returns `Error::WriteTimeout`.** It
  used to return `Ok` after sending a sample it could not store, so the sample
  could be neither repaired nor replayed. A sample larger than the history's
  quota returns `Error::ResourceLimitExceeded` at once, and any other refusal
  of the history is returned instead of `Ok`. `WriteTimeout` existed in 1.4.x
  but nothing produced it
- **QoS validation refuses a KEEP_LAST depth greater than
  `max_samples_per_instance`** (and the same for the durability service's
  `history_depth`), and drops the rule `max_samples >= max_samples_per_instance
  * max_instances`. A new instance past `max_instances` is now refused at
  write. See Changed for the new defaults, which make both limits unlimited
  unless you set them
- **Creating a DataReader with an inconsistent HISTORY / RESOURCE_LIMITS
  pair now fails, as creating a DataWriter already did.** DDS 1.4 2.2.3.18
  and 2.2.3.19 state the rules for every entity: KEEP_LAST `depth <=
  max_samples_per_instance`, `max_samples >= max_samples_per_instance`, every
  limit > 0 or LENGTH_UNLIMITED, and "an attempt to set this policy to
  inconsistent values when an entity is created [...] will cause the
  operation to fail". Only DataWriter creation checked them; a reader was
  created and enforced something else. Writer and reader now call the same
  check, and the error names the entity and the broken rule. In the C ABI the
  reader constructor returns NULL and logs the reason; the Python SDK raises
  `RuntimeError` naming the rule (it already did for writers), and the
  TypeScript SDK's `HddsError` now names it too, through a new
  `QoS.consistencyProblems()` that mirrors Python's `consistency_problems()`.
  The `resource_limits` sample (Rust, Python, C, C++) built exactly such a
  reader (default depth 100, `max_samples_per_instance` 5) and now sets the
  depth to 5; the QoS guide's example did the same and is fixed
- **The Discovery Server relay frame carries its payload as a base64
  string**, no longer a JSON array of numbers. Only the `data` frame of a
  server started with `--relay` is concerned; a 1.4.x client never sent one
- **A `#[derive(DDS)]` type is `@appendable`, and its XCDR2 layout is the
  specification's: both change its bytes from 1.4.x.** DDS-XTypes 1.3
  7.3.1.2.1.8: "In the event that the representation of a given type does not
  indicate the type's extensibility kind, the type shall be considered
  appendable". The derive has no way to indicate one, so a derived type is now
  `@appendable`; 1.4.x made it `@final`. Under XCDR2 its body is
  DELIMITED_CDR, a DHEADER (the byte count of the members) followed by the
  members laid out as PLAIN_CDR2 (7.4.3.1, Table 35), and its DATA carries
  D_CDR2_LE (0x0009). Inside, an 8-byte member (`i64`, `u64`, `f64`) is
  aligned at 4: 7.4.3.2.2, `MAXALIGN(VERSION2) = 4`, `ALIGN(N)` aligns to
  `MIN(N, MAXALIGN)`. The derive aligned it at 8 whatever the negotiated
  version, which is the XCDR1 rule, so a `{ a: u8, b: i64 }` carried 7 padding
  bytes where the specification puts 3. Its TypeObject announces
  `IS_APPENDABLE`, and the key-only payload of a dispose or unregister
  carries the same DHEADER under XCDR2. A reader skips what a newer writer
  appended after the members it knows, inside the DHEADER. The new layout,
  sample and key-only payload, is checked byte for byte against Eclipse
  Cyclone DDS 0.11 for the same types declared `@appendable`
  - **Which representation**: XCDR2, when the writer offers it
    (`data_representation_xcdr2()`). A writer that sets no
    DataRepresentation QoS offers XCDR1 (see the entry on the default writer
    representation). An appendable type is PLAIN_CDR under XCDR1 (Table 35),
    so XCDR1 bytes do not change; nor does the KeyHash
  - **A 1.4.x and a 1.5.0 endpoint of the same derived type do not match**
    when both announce their TypeObject, which a derived type does: one says
    `IS_FINAL`, the other `IS_APPENDABLE`, and two structures are assignable
    only if they "have the same extensibility kind" (7.2.4.4, Table 19), so
    the type check refuses the pair, under XCDR1 as well. Should samples
    cross anyway (a peer that matches by name), a 1.5.0 reader takes the
    first word of a 1.4.x XCDR2 sample for a DHEADER and refuses the sample
    when that runs past its end; a 1.4.x reader takes the DHEADER of a 1.5.0
    sample for its first members and delivers wrong values: the `{ a: 0x11,
    b: 0x0102030405060708 }` of a 1.5.0 writer reads as `a = 0x0c`
  - **Upgrade both sides together.** A derived type that must keep the 1.4.x
    layout says so with `#[dds(final)]` on the struct (new): PLAIN_CDR2,
    `IS_FINAL`, and the XCDR2 layout of this entry, which aligns 8-byte
    members at 4 where 1.4.x aligned them at 8. `#[dds(appendable)]` states
    the default; `#[dds(mutable)]` and any other `#[dds(...)]`, on the struct
    or on a field, are compile errors (1.4.x accepted and ignored them)
  - `DDS::encodes_xcdr1_natively()` is new; the derive answers `true`, so a
    derived type with a `String` or `Vec<u8>` member and an 8-byte member is
    no longer refused when XCDR1 is negotiated. A hand-written `DDS` impl keeps
    that refusal unless it overrides the method
  - **The TypeObject of a derived type changes, and with it both its
    EquivalenceHashes** (PID_TYPE_INFORMATION, TypeLookup). Every member
    carries TRY_CONSTRUCT1, the DISCARD try-construct behavior that is the
    default when none is declared (DDS-XTypes 1.3 7.2.2.7); 1.4.x wrote no
    try-construct bits, which Annex B `bitmask MemberFlag` defines as
    INVALID. A key member carries IS_KEY, IS_MUST_UNDERSTAND and
    TRY_CONSTRUCT1. A `String` member is a TI_STRING8_SMALL TypeIdentifier
    (bound 0, unbounded) and a `Vec<u8>` member a plain sequence of uint8
    (7.3.4.4); 1.4.x wrote the bare TypeKinds 0x20 and 0x60, which no decoder
    accepts, HDDS's own included, so a derived type carrying either was
    announced with no TypeObject and no TypeInformation at all. It now is.
    Checked byte for byte against the TypeObject Eclipse Cyclone DDS 0.11
    `idlc` emits for the same IDL, which differs only by leaving
    IS_MUST_UNDERSTAND off key members
- **A dynamic type that names no extensibility is appendable.**
  `TypeDescriptor::new`, `TypeDescriptor::struct_type`, the
  `TypeDescriptorBuilder` and `Extensibility::default()` gave `Final`; they
  give `Appendable`, the specification's default (DDS-XTypes 1.3
  7.3.1.2.1.8). Such a structure or union is encoded under XCDR2 behind a
  DHEADER, and its TypeObject announces `IS_APPENDABLE`; XCDR1 bytes do not
  change. `.with_extensibility(Extensibility::Final)` gives the 1.4.x layout
  - A union read from a TypeObject keeps the extensibility the object
    declares; 1.4.x read every such union as `Final`. A structure or union
    object that carries no extensibility flag at all (malformed: DDS-XTypes
    1.3 Annex B requires exactly one) is still read as `Final`, deliberately,
    for compatibility
  - Not concerned: the shapes demo's `ShapeType`, which says `@appendable`
    itself; ROS 2 message types built from their type support, which stay
    `IS_FINAL`; and a hand-written `DDS` impl, whose encoder decides its bytes.
    Code generated by `hdds_gen` follows the same default from the matching
    `hdds_gen` on (`--default-extensibility final` keeps the old one)
- **TypeObject model: seven public `hdds::xtypes` structs changed to follow
  DDS-XTypes 1.3 Annex B.** The serializer now writes every field the
  specification serializes, which the model had to be able to hold
  - `CompleteEnumeratedType`, `MinimalEnumeratedType`, `CompleteBitmaskType`
    and `MinimalBitmaskType` gain `enum_flags` / `bitmask_flags`
    (`EnumTypeFlag` / `BitmaskTypeFlag`, both `TypeFlag` as the IDL typedefs
    them): the declared extensibility, serialized and so part of both
    EquivalenceHashes. 1.4.x wrote a constant there (`IS_APPENDABLE`, 0x0002,
    for every enum, 0x0000 for every bitmask)
  - `CompleteAliasBody` loses `detail` (a whole `CompleteTypeDetail`) and
    gains `ann_builtin` / `ann_custom`, the two optional annotation fields
    the specification declares
  - `AppliedBuiltinMemberAnnotations::min` / `max` are
    `Option<AnnotationParameterValue>` (were `Option<f64>`, never written)
  - `AppliedBuiltinTypeAnnotations::verbatim` is
    `Option<AppliedVerbatimAnnotation>` (placement, language, text; was a
    single `String`)
  - **Rust generated by `hdds_gen` must come from the matching `hdds_gen`:**
    code generated by an earlier one builds the enum and bitmask literals
    without the new fields and does not compile
  - **A TypeObject hand-built and encoded by 1.4.8 or earlier that uses a
    base type, builtin member annotations (`@hashid`, `@unit`, `@min`,
    `@max`, `@range`), custom annotations or `@verbatim` is not decodable by
    1.5.0**: 1.4.x wrote those parts in a layout no other vendor uses. An
    endpoint whose TypeObject does not decode is matched by name, unless the
    reader forces type validation (`force_type_validation`)

- **A participant's unicast ports are now its own: a second participant on
  them is refused instead of silently sharing them.** DDSI-RTPS 2.5 9.6.1.1
  derives the metatraffic and user-data unicast ports from the participant id
  so that they are unique on the host. Both sockets were bound with
  `SO_REUSEADDR` (and `SO_REUSEPORT` under `HDDS_REUSEPORT=1`), so two
  participants given the same explicit id (`.participant_id(Some(n))`,
  `HDDS_PARTICIPANT_ID`) or the same custom ports (`with_discovery_ports`), in
  one process or in two, both bound them without error. The kernel then
  hands each unicast datagram to ONE of the two sockets: one participant
  received no unicast discovery and no unicast user data, and nothing said so
  - Those unicast sockets now set no reuse option, plus `SO_EXCLUSIVEADDRUSE`
    on Windows, where a later `SO_REUSEADDR` binder could otherwise take the
    port over
  - The second participant's `build()` fails with `Error::IoError`
    (`AddrInUse`), naming the port and the participant id. Leave the id unset
    to get a free one
  - Auto-assignment (no id given) keeps the two sockets its probe bound and
    hands them to the participant, on every platform; it used to close them
    and bind again, which left a window to another process outside Linux.
    When every participant id of the domain is in use it now fails with
    `AddrInUse` instead of building on the last id's ports under id 0
  - `HDDS_REUSEPORT=1` now applies to the two shared multicast sockets only
  - UDP has no TIME_WAIT: the ports are free again as soon as the participant
    (or its process) is gone
- **Access brackets follow the Subscriber's PRESENTATION access scope**
  (DDS v1.4 Sec.2.2.2.5.2.8)
  - When a Subscriber's access scope is GROUP, every reader built with
    `ReaderBuilder::subscriber()` is read only inside
    `begin_access()`/`end_access()`. Outside a bracket, read, take and their
    `_w_condition` forms return `Error::InvalidState` (PRECONDITION_NOT_MET);
    in C, `HDDS_INVALID_STATE`. This holds whatever the reader's own
    coherent or ordered access, and it is new for an ordered-only or plain
    reader of a GROUP Subscriber. A GROUP coherent reader of a Subscriber of
    another scope no longer needs a bracket
  - For any other access scope a bracket has no effect: it no longer holds
    back the publication of coherent sets
  - `begin_access()` nests; each is closed by its own `end_access()`.
    `end_access()` with none open is PRECONDITION_NOT_MET. A nested
    `begin_access()` used to fail
  - Readers created from a Subscriber by the deprecated
    `Subscriber::create_reader()` and by the C API's
    `hdds_subscriber_create_reader(_with_qos)` (C++ and Python SDKs
    included) are now readers of that Subscriber: held to its brackets
    and, coherent, members of its presentation barrier. They used to be
    neither
- **A dynamic type's `@hashid` member takes its hashed member id under the
  default `@autoid(SEQUENTIAL)` too** (DDS-XTypes 1.3 Sec.7.3.1.2.1.1:
  `@hashid`, like `@id`, assigns the id explicitly). A member built with
  `FieldDescriptor::with_hashid_name` in a struct without `with_autoid_hash()`
  used to get its sequential id; it now gets the hash of the `@hashid` value,
  and the next sequential member that id plus one. An empty value
  (`@hashid` without a parameter) hashes the member's own name, under either
  `@autoid`; it used to hash the empty string under `@autoid(HASH)`. The
  member ids are now Cyclone DDS 0.11 idlc's for the same IDL
  - **Wire change, for such types only:** the member ids move in the
    TypeObject (so its EquivalenceHash and PID_TYPE_INFORMATION), in the
    XCDR2 EMHEADERs and XCDR1 parameter ids of a mutable sample, and in the
    KeyHash, whose key members are taken in member id order. Against HDDS
    1.4.x for such a type: a different TypeIdentifier, and mutable samples
    whose member ids disagree
  - No other type changes: a struct with no `@hashid` member, an
    `@autoid(HASH)` struct whose `@hashid` values are not empty, a type
    read from a received TypeObject (its announced ids are kept), the
    `shape_main` ShapeType and every generated type keep their ids and
    hashes
- **A union case's Minimal name hash is the hash of its name, whatever its
  `@hashid`** (DDS-XTypes 1.3 Sec.7.3.4.6, as for a struct member). Deriving
  the Minimal object of a union whose Complete cases carry a `hash_id`
  annotation (hdds_gen writes one for a `@hashid` case) used the `@hashid`
  value instead, and the empty string for `@hashid` without a parameter
  - **Wire change, for such unions only:** their Minimal TypeObject, its
    hash, and so PID_TYPE_INFORMATION's minimal identifier. No other type
    changes; ShapeType is a struct and carries no `@hashid`
  - `CompleteMemberDetail::hash_name` returns the member's name for an
    empty `hash_id`
- **A DataWriter that sets no DATA_REPRESENTATION now offers and encodes
  XCDR1** (DDS-XTypes 1.3 7.6.3.1.1: "An empty list of preferences shall be
  taken to be equivalent to a list containing the single element XCDR";
  "Writers offer a single representation"). It announced XCDR1 first but
  chose at every write among the readers it knew, XCDR2 as soon as one
  accepted it and with no reader at all, so a peer reading the announced offer
  could receive XCDR2, and a TRANSIENT_LOCAL history kept XCDR2 for a late
  XCDR1 reader
  - The representation is resolved once, when the writer is created, and
    `DataWriter::qos()` shows it (`[XCDR1]`). A writer announces that one
    representation, the first element of its list, and encodes every sample,
    repair and history replay in it. The write path no longer looks up the
    readers discovery knows
  - **Default HDDS<->HDDS traffic is XCDR1 again.** For XCDR2, set it on the
    writer: `QoS::data_representation_xcdr2()`, or a list whose first element
    is XCDR2 (`0x0002`)
  - A type that does not encode XCDR1 natively (`DDS::encodes_xcdr1_natively`
    false) offers XCDR2 when it sets none; logged once at info
  - **`DDS::encodes_xcdr1_natively` now defaults to `false`**: a type is
    taken to encode XCDR1 only when it says so. The default guessed from the
    descriptor (only a variable-size type with an 8-byte alignment refused)
    and missed a hand-written type that relies on the `Cdr2Encode` default
    `encode_xcdr1_le`, which delegates to the XCDR2 path (the pattern
    docs/api/rust.md recommended): a fixed-size `{ u32, f64 }` went out
    labelled XCDR1 with the `f64` at offset 4. Such a type now offers XCDR2
    when it sets no list, and an XCDR1 pair for it is refused
    (INCOMPATIBLE_QOS, policy 23), as a writer and as a reader.
    `#[derive(DDS)]` and the Rust code `hdds_gen` emits answer `true`, as do
    the opaque payload types (`RawBytes` of the raw readers and writers, the
    RPC message, the C ABI payload) and the bundled examples whose XCDR1
    bytes are XCDR1 (`shape_main`'s `ShapeType`, the Temperature examples,
    the embedded samples). **A hand-written type whose XCDR1 encoding is
    real must now say so** (`fn encodes_xcdr1_natively() -> bool { true }`),
    or its default writer moves to XCDR2 and an XCDR1-only peer is refused
  - A reader that sets no DATA_REPRESENTATION, of a type that does not
    decode XCDR1 natively, requests `[XCDR2]` alone and announces it
    (DDS-XTypes 1.3 7.6.3.1.1: a reader requests XCDR only when it can
    deserialize it); `DataReader::qos()` shows it. It refused an XCDR1
    writer on its side while announcing `[XCDR1, XCDR2]`, so that writer
    counted the pair matched; now both ends report the incompatibility. A
    reader of a type that does decode XCDR1 still requests `[XCDR1, XCDR2]`
  - A reader that explicitly sets `DATA_REPRESENTATION = [XCDR1]`, of a type
    that does not decode XCDR1 natively, is now refused at creation
    (`Error::InvalidQos`), the same as a writer whose first element names a
    representation it cannot encode (below). DDS-XTypes 1.3 7.6.3.1.1 makes
    requesting XCDR1 conditional on the capability ("Optionally may
    generate or include run-time code that can deserialize version 1
    encodings. In this case they shall also request XCDR encoding"). It
    used to keep the list: a remote writer, which reads only the announced
    `[XCDR1]`, counted the pair matched while this reader's own
    `on_requested_incompatible_qos` fired for the same wire form -- the two
    ends disagreed, and in the window before that notification this reader
    could receive a sample its type reads as the wrong layout
  - A writer whose first element is neither XCDR1 nor XCDR2 (XML, an unknown
    identifier) is refused at creation (`Error::InvalidQos`). So is a writer
    that explicitly sets `[XCDR1]` while its type does not encode it
    natively, for the same asymmetric-match reason as the reader rule above:
    it used to keep the list and encode the XCDR2 layout under an XCDR1
    header
  - Independent of matching: a reader whose type cannot decode XCDR1 now
    drops any XCDR1-encoded sample at the data plane by its own real decode
    capability, not only by its announced `DATA_REPRESENTATION` list. This
    closes a corrupt-delivery window the two refusal rules above leave
    possible in principle, should a reader of that shape ever exist by some
    other construction path than `ReaderBuilder::build`: the SEDP
    writer-block gate judges a remote writer against ALL local readers on a
    topic at once, so a writer compatible with some OTHER local reader is
    not blocked, and reaches every reader on the topic regardless of its
    own per-pair match verdict
  - A default writer and a reader that requests XCDR2 alone are now
    incompatible, at both ends (OFFERED/REQUESTED_INCOMPATIBLE_QOS, policy
    23), and nothing is delivered, whether the reader is in another
    participant, the same one or the same process. They were matched with
    XCDR2 within one participant, and disagreed across two
  - A reader that sets none still requests `[XCDR1, XCDR2]` when its type
    decodes XCDR1 natively; otherwise `[XCDR2]` (above), and a C ABI reader
    `[XCDR2]` (below)
  - Writers created through the C ABI with no DATA_REPRESENTATION offer
    XCDR2: the C, C++, Python and TypeScript codecs `hdds_gen` emits serialize
    XCDR2 only, and the bytes travel unchanged
  - Readers created through the C ABI with no DATA_REPRESENTATION request
    XCDR2 only (every path: `hdds_reader_create*`,
    `hdds_subscriber_create_reader*`, `hdds_create_reader_filtered*`): the
    codecs of `hdds_gen` 1.x and earlier read XCDR2 only, and the ABI cannot
    tell which codec decodes (DDS-XTypes 1.3 7.6.3.1.1, a reader requests
    XCDR only when it can deserialize it; one whose decoders read XCDR1
    asks for it, below). They requested `[XCDR1, XCDR2]`
    and were matched with any default writer, HDDS or foreign, whose XCDR1
    bytes the caller then decoded as XCDR2 without an error. Such a pair is
    now a REQUESTED_INCOMPATIBLE_QOS (policy 23) at the C reader and an
    OFFERED_INCOMPATIBLE_QOS at the writer, and delivers nothing: set XCDR2
    on the writer. rmw endpoints keep `[XCDR1]`
  - **A C ABI reader can request XCDR1 as well, and learn the representation
    of each sample** (DDS-XTypes 1.3 7.6.3.1.1: a reader that deserializes
    version 1 requests XCDR in addition to XCDR2):
    `hdds_qos_set_data_representation(qos, ids, count)` sets the list
    (`HDDS_XCDR_DATA_REPRESENTATION`, `HDDS_XCDR2_DATA_REPRESENTATION`; any
    other identifier is refused) and `hdds_qos_get_data_representation`
    reads it back. `hdds_reader_take_ex`, `hdds_reader_take_w_condition_ex`,
    `hdds_reader_take_w_query_condition_ex`, `hdds_reader_read_w_condition_ex`,
    `hdds_reader_read_w_query_condition_ex` and the listener's
    `on_data_available_ex` (`hdds_reader_set_listener_ex`,
    `hdds_reader_exchange_listener_ex`) also report the encapsulation
    identifier of the sample's representation: `CDR_LE` (0x0001) for XCDR1,
    `CDR2_LE` (0x0007) for XCDR2, what the `_decode_by_encapsulation`
    decoders of `hdds_gen` 2.0 take. The reader keeps the encoding version,
    not the extensibility framing: a `PL_CDR_LE` sample reports 0x0001, a
    `D_CDR2_LE` or `PL_CDR2_LE` one 0x0007. The existing functions and
    structs are unchanged; a reader that sets no list still requests XCDR2
    alone
  - A C content filter or query condition reads a sample's fields in the
    representation the sample is in: an XCDR1 sample at a reader that
    requests XCDR is decoded as XCDR1 (it was decoded as XCDR2, every member
    after the first misread). `hdds_dynamic_data_decode_ex(desc, buf, len,
    encapsulation_id)` decodes a body by the identifier the `_ex` takes
    report (0x0001 and 0x0003 as XCDR1, 0x0007, 0x0009 and 0x000b as XCDR2,
    anything else refused); `hdds_dynamic_data_decode` still reads XCDR2
  - **A C ABI writer can label its samples with their type's extensibility**
    (DDS-XTypes 1.3 7.6.3.1.2, Table 60):
    `hdds_writer_create_with_extensibility(participant, topic, type_name,
    qos, extensibility)` with `HDDS_EXTENSIBILITY_FINAL`, `_APPENDABLE` or
    `_MUTABLE` sends `CDR2_LE`, `D_CDR2_LE` or `PL_CDR2_LE` under XCDR2
    (`CDR_LE`, `CDR_LE` or `PL_CDR_LE` under XCDR1). A C ABI writer has no
    TypeObject to read it from, and the other constructors label every body
    `CDR2_LE`, which is wrong for the APPENDABLE and MUTABLE bodies the
    `hdds_gen` encoders produce (an IDL type without an annotation is
    APPENDABLE): a peer that frames by identifier refuses or misreads them.
    Rust: `Participant::create_writer_with_type_and_extensibility`
  - **C++ SDK: a typed reader requests what its type decodes**
    (DDS-XTypes 1.3 7.6.3.1.1): `create_reader<T>()` (Participant and
    Subscriber) of a type with `decode_by_encapsulation` (`hddsgen` 1.3,
    detected at compile time) requests `[XCDR, XCDR2]`, so a default writer,
    which offers XCDR, reaches it, and `take()` decodes each sample by its
    encapsulation identifier. A type with `decode_cdr2_le` only keeps the
    reader at XCDR2 (such a writer is a visible REQUESTED_INCOMPATIBLE_QOS),
    and refuses an XCDR1 sample with `hdds::Error` instead of misreading it
    when the QoS asked for XCDR by hand. New: `QoS::data_representation()` /
    `get_data_representation()`, `DataReader::take_raw_sample()` (bytes and
    identifier), `create_reader_raw_decoding_xcdr1()`, and
    `create_writer_raw(topic, qos, Extensibility)` to label samples with the
    type's extensibility
  - **Python SDK: a reader told its message class requests what the class
    decodes**: `create_reader(topic, qos, type_name, msg_type=Cls)`
    (Participant and Subscriber) requests `[XCDR, XCDR2]` when `Cls` has
    `decode_by_encapsulation` (`hdds_gen` 2.0) and the QoS sets no list, and
    `take_typed(Cls)` decodes each sample by its encapsulation identifier;
    a class with `decode_cdr2_le` only keeps the reader at XCDR2 and refuses
    an XCDR1 sample with `ValueError`. New: `QoS.data_representation(*ids)`
    / `get_data_representation()`, `DataReader.take_with_encapsulation()`,
    `create_writer(..., extensibility="appendable")`. An older libhdds_c
    (predating `hdds_qos_set_data_representation`/`hdds_reader_take_ex`,
    added together) still loads and still creates a reader of a class with
    `decode_cdr2_le` only; `create_reader(..., msg_type=Cls)` for a class
    with `decode_by_encapsulation` REFUSES instead on such a library
    (`RuntimeError`), rather than request XCDR2 only silently and have
    `take_with_encapsulation` mislabel an XCDR1 sample `CDR2_LE`
  - **TypeScript SDK: a reader told its generated module requests what it
    decodes**: `createReader(topic, qos, typeName, codec)` with `codec` the
    generated module (`import * as types`) requests `[XCDR, XCDR2]` when
    `types.HDDS_DECODES_XCDR1` (`hdds_gen` 2.0) and the QoS sets no list;
    `takeTyped(decode<Name>ByEncapsulation)` decodes by the sample's
    identifier, and a one-parameter XCDR2 decoder is never handed an XCDR1
    sample (HddsError). New: `QoS.dataRepresentation(...ids)` /
    `getDataRepresentation()`, `DataReader.takeWithEncapsulation()`,
    `createWriter(topic, qos, typeName, "appendable")`, the `ReaderCodec`
    type. An older native library (predating
    `hdds_qos_set_data_representation`/`hdds_reader_take_ex`, added
    together) still loads and still creates a reader whose `codec` has no
    `HDDS_DECODES_XCDR1`; `createReader(..., codec)` for one that does
    REFUSES instead on such a library (`HddsError`), rather than request
    XCDR2 only silently and have `takeWithEncapsulation` mislabel an
    XCDR1 sample `CDR2_LE`
  - `hdds_dynamic_data_encode` / `hdds_dynamic_data_decode` (C ABI) write and
    read an XCDR2 body: the representation C writers label their samples with
    and C readers request by default (a C content filter or query condition
    decodes each sample in its own representation, above). They wrote XCDR1 (an 8-byte member aligned at 8,
    no DHEADER) that a C writer sent labelled XCDR2. An APPENDABLE struct
    built with `hdds_type_builder_*` now starts with its DHEADER, so an empty
    one encodes to four bytes, and bytes stored from the old encoder do not
    decode with the new one
- **A raw relay now carries every DATA_REPRESENTATION it sees, truthfully,
  instead of labelling everything with the one a plain raw writer happened to
  resolve at creation.** A `RawDataWriter` created with no `DATA_REPRESENTATION`
  resolves XCDR1 once, at creation (`RawBytes::encodes_xcdr1_natively()` is
  `true`), and stamps every sample it is given with that one representation
  forever; `try_take_raw` also discarded the per-sample version before a relay
  ever saw it. A relay forwarding an XCDR2 sample through such a writer sent it
  on the wire labelled XCDR1.
  - **New: `RawDataWriter::write_raw_with_encoding(payload, version)`**
    writes only when `version` is this writer's resolved offer, refusing
    otherwise, instead of sending a payload whose label does not match its
    bytes
  - **New: `RawRelayWriter`** (`hdds::RawRelayWriter`) is one real raw writer
    per representation a relay has carried, each created to offer exactly
    that representation; `relay_write(payload, version)` picks or lazily
    creates the writer that actually offers `version`. An `eager_hint` lets a
    caller that already knows a representation in advance (a discovered
    source writer's resolved offer, a recording's stored version) create that
    one writer immediately, keeping prior discovery timing for the
    overwhelmingly common single-representation case; any other
    representation is created on its first sample, trading a one-time
    first-sample latency for never mislabelling it
  - **New: `CdrVersion::representation_code` / `::from_representation_code`**,
    a public round-trip to the DATA_REPRESENTATION wire code (DDS-XTypes 1.3
    7.6.2.1.2: `0x0000` XCDR1, `0x0002` XCDR2), for a caller outside the
    engine that needs to read or seed one from a discovered QoS
  - `hdds-router`: a relay's raw reader no longer inherits the first
    discovered writer's resolved `data_representation` (that field is
    directional - a writer announces one offer, a reader its whole
    acceptance list), and its writer is a `RawRelayWriter`: two source
    writers on one topic, one XCDR1 and one XCDR2, both now relay correctly
    where before only the first-discovered representation ever matched
  - `hdds-recording`: the `.hdds` format gains a per-message
    `representation` field (format version 1 -> 2; a version-1 file still
    opens, defaulting every message to XCDR1, the DDS-XTypes default for an
    unstated representation). `bin/record.rs` records the real per-sample
    version (and no longer restricts its own reader's representation);
    `bin/replay.rs` replays through a `RawRelayWriter` keyed off it
  - `hdds-persistence`: `store::Sample` and `dds_interface::ReceivedSample`
    gain `representation` (sqlite schema migrates in place, defaulting
    existing rows to XCDR1; `#[serde(default)]` for any JSON record).
    `HddsDataWriter` relays through a `RawRelayWriter`; a durability replay
    carries the representation a sample was actually recorded with
  - `hdds-xrce`: DDS-XRCE v1.0 7.7.1 requires every payload a client writes
    or an agent forwards to a client to be XCDR version 2, unconditionally.
    The bridge's writer and reader now build their QoS with
    `data_representation_xcdr2()` explicitly instead of an unset default (XCDR1
    for the writer); a DDS writer on the domain that offers XCDR1 simply does
    not match the bridge's reader anymore, rather than have its bytes
    forwarded to a client mislabelled XCDR2
  - `hdds-ws`: `publish()`'s writer now offers XCDR1 explicitly, matching
    what its own `json_to_raw_cdr` encoder implements, instead of an
    unstated default that happened to agree by coincidence
  - `hdds-influx-sink`: the dynamic-decode path now reads each sample's real
    DATA_REPRESENTATION (`try_take_raw_with_encoding` +
    `cdr_to_json_dynamic_with_version`) instead of hardcoding XCDR1
    (`cdr_to_json_dynamic`'s documented default), which silently misdecoded
    an XCDR2 sample through a resolved TypeObject
  - `hdds-logger`: the collector's raw reader no longer inherits the first
    discovered log writer's resolved representation, the same directional
    QoS mistake as `hdds-router`

### Added

- A governance topic rule that enables read or write access control with
  discovery, metadata and data protection all off is named in a warning when
  the participant is built: access control then judges an endpoint announced
  in the clear under an authenticated participant's prefix by that
  participant's permissions, and nothing authenticates the endpoint
  (DDS Security v1.1 Sec.9.4.1.2.6).
- C, C++ and Python SDKs expose value-returning reader/writer status getters.
  Reading a status preserves cumulative totals and consumes change counters
  (DDS 1.4 Sec.2.2.4.2.1), sharing consumption with listener callbacks.
- C, C++ and Python SDKs expose timestamped write, dispose and unregister,
  plus instance registration with or without a timestamp. Explicit timestamps
  use nanoseconds since the Unix epoch. Raw-byte topics remain keyless;
  registration returns the nil handle and emits no sample. The C++ writer
  also exposes `wait_for_acknowledgments`.
- **`Publisher::wait_for_acknowledgments`** (DDS v1.4 Sec.2.2.2.4.1.12):
  blocks until the data of every DataWriter of the Publisher has been
  acknowledged by every matched RELIABLE reader, or `max_wait` elapses
  (`Error::AcknowledgmentTimeout`). The writers share one deadline: the call
  lasts at most `max_wait`, not `max_wait` per writer. Each writer is waited
  for as `DataWriter::wait_for_acknowledgments` does, so a BEST_EFFORT writer
  owes nothing and a dropped writer is no longer the Publisher's.
  Default-provided trait method, non-breaking:
  `CoherentWriter::wait_for_acknowledgments_until()`.
- C, C++ and Python SDKs expose `Publisher` `wait_for_acknowledgments`
  (`hdds_publisher_wait_for_acknowledgments`, `hdds::Publisher`,
  `hdds.Publisher`): `HDDS_TIMEOUT`, `false` and `False` when the wait ran out.
  The timeout bounds the whole Publisher.
- **`DataWriter::wait_for_acknowledgments`** (DDS v1.4 Sec.2.2.2.4.2.15):
  blocks until every sample written has been acknowledged by every matched
  RELIABLE reader, or `max_wait` elapses. Returns at once on a BEST_EFFORT
  writer, per the same spec section; a BEST_EFFORT reader is never counted
  (it never gains an entry in the writer's ACKNACK watermark map), and a
  cross-participant RELIABLE reader in this same process is counted
  exactly like a remote one, through the same map, whatever transport it
  rides (RTPS, same host). A reader of the SAME participant is counted
  too: a local RELIABLE binding feeds the same map when the merger admits
  a sample into the reader's history, so the call waits for it. Built on `fully_acked` (DataWriter
  had carried it with no production caller) and woken by the history
  cache's own condition variable -- the one an ACKNACK already signals --
  so there is
  no polling thread. `DataWriter::write_w_timestamp`,
  `dispose_w_timestamp` and `unregister_instance_w_timestamp` (Sec.
  2.2.2.4.2.12/2.2.2.4.2.13/2.2.2.4.2.8) let the application supply the
  `source_timestamp` DESTINATION_ORDER and `SampleInfo` read, instead of
  the one read from the clock; the override governs exactly the one
  change it emits and is cleared on every exit, including an error
  returned before that change was ever built, so it can never reach a
  later plain `write()`/`dispose()`/`unregister_instance()`.
  All three now honor it on a transport-less (`IntraProcess`) writer
  exactly as on one with a transport. `write_w_timestamp` did not,
  for a writer with no remote peer: its intra-process fast path stamped
  every local ring entry from the real write-time clock, never from the
  staged override, so a purely local reader's
  `SampleInfo::source_timestamp_ns` for a DATA sample was always the
  clock reading, whatever the application asked for -- found and fixed
  while implementing DESTINATION_ORDER BY_SOURCE_TIMESTAMP below, which
  depends on it (the override is now taken once, before any leg of
  `write()`, and reused by the wire, journal, and both intra-process
  paths instead of each reading the clock or re-taking the override on
  its own).
  `DataWriter::register_instance` / `register_instance_w_timestamp`
  (Sec.2.2.2.4.2.5/6) return the instance's KeyHash as an
  `InstanceHandle` -- purely local bookkeeping, since this API never
  requires one (every method also takes `&T` directly, the spec's
  `HANDLE_NIL` path). C ABI gains `hdds_writer_wait_for_acknowledgments`;
  the Python SDK gains `DataWriter.wait_for_acknowledgments()`. Not yet:
  a Publisher-level `wait_for_acknowledgments` (Sec.2.2.2.4.1.12) -- a
  `Publisher` keeps no type-erased registry of its writers' acknowledgment
  state, only of their coherent-set role, so this is not the "if cheap"
  addition the rest of this item is.
- **DataReader/DataWriter status getters and DataWriter StatusCondition**
  (DDS v1.4 Sec.2.2.4, read-and-reset per Sec.2.2.4.2.1). New reader getters:
  `get_requested_deadline_missed_status` (Sec.2.2.2.5.3.22),
  `get_requested_incompatible_qos_status` (Sec.2.2.2.5.3.23),
  `get_subscription_matched_status` (Sec.2.2.2.5.3.26),
  `get_matched_publications` (Sec.2.2.2.5.3.34). New writer getters:
  `get_offered_deadline_missed_status` (Sec.2.2.2.4.2.17),
  `get_offered_incompatible_qos_status` (Sec.2.2.2.4.2.18),
  `get_publication_matched_status` (Sec.2.2.2.4.2.19),
  `get_matched_subscriptions` (Sec.2.2.2.4.2.24), and `get_status_condition`
  itself (Sec.2.2.2.1.1.5) -- a `DataWriter` had no StatusCondition at all
  before this. PUBLICATION_MATCHED, SUBSCRIPTION_MATCHED and the two
  `*_INCOMPATIBLE_QOS` statuses now also raise/clear their bit on the
  StatusCondition and wake an attached WaitSet when no listener is
  installed; they were listener-only before. Fed by either source that can
  report a match (the SEDP registry or `domain_registry::LocalMatchStatus`,
  for a peer with no wire path at all), same as the existing match-count
  APIs. `get_matched_publications` / `get_matched_subscriptions` read the
  live matched-GUID sets those sources already keep. C ABI gains
  `hdds_writer_get_status_condition`; the C++ and Python SDKs gain
  `DataWriter::get_status_condition()` / `DataWriter.get_status_condition()`
  and (Python) `WaitSet.attach_writer` / `detach_writer`. Not yet: a
  value-returning status getter in any of the three bindings, for any
  status (not even the ones that already existed in Rust core) -- only
  StatusCondition handles and listener callbacks are bound there;
  `Topic::get_inconsistent_topic_status` (DDS v1.4 Sec.2.2.2.3.2.1) is not
  provided yet -- `Topic` has no entity state of its own to report it from,
  and the spec puts this operation on Topic only (DataReader/DataWriter do
  not have it).
- **LIVELINESS, AUTOMATIC kind, detected on the wire, and a lease that ends
  now moves the instance and EXCLUSIVE ownership accordingly** (DDS v1.4
  Sec.2.2.3.11, Sec.2.2.3.23.1.2, Sec.2.2.3.23.2, Sec.2.2.2.5.1.4, Sec.2.2.4.1;
  RTPS v2.5 Sec.8.4.13). Each participant runs one `hdds-liveliness` thread
  over a heap of lease deadlines, stopped and joined with the participant. A
  writer with a finite AUTOMATIC lease is asserted by its participant: a
  ParticipantMessageData of kind AUTOMATIC every third of the shortest such
  lease, to each discovered participant that announces the
  BuiltinParticipantMessage reader, the first at once; `write()` is
  unchanged. A reader keeps one lease per matched remote writer: any RTPS
  message of the writer's participant renews an AUTOMATIC one, as Cyclone
  DDS and Fast DDS do; a received ParticipantMessage of kind MANUAL, or the
  writer's data, renews a MANUAL_BY_PARTICIPANT one; its own data renews a
  MANUAL_BY_TOPIC one. `DataReader::get_liveliness_changed_status()` reports
  the matched writers alive and not alive, `on_liveliness_changed` is called
  on each change, and `StatusMask::LIVELINESS_CHANGED` is raised on the
  reader's StatusCondition when no listener takes it. A writer whose lease
  ended and that was renewed again before the thread ran is still reported
  not alive, then alive. A writer's own lease ending - not only its
  departure or an explicit unregister - now moves every instance it alone
  held to NOT_ALIVE_NO_WRITERS, visible through `read()`/`take()` and the
  instance-state mask; writing again revives it with
  `SampleInfo::no_writers_generation_count` incremented. Under EXCLUSIVE
  ownership it also releases ownership at once, no DEADLINE wait, to the
  next alive writer by OWNERSHIP_STRENGTH; the former owner regains it by
  the normal strength rule once it resumes and writes again.
- **LIVELINESS, MANUAL_BY_PARTICIPANT and MANUAL_BY_TOPIC kinds, plus
  `assert_liveliness()` and LIVELINESS_LOST on the writer** (DDS v1.4
  Sec.2.2.3.11, Sec.2.2.2.2.4.19, Sec.2.2.2.4.2.22, Sec.2.2.4.1; RTPS v2.5
  Sec.8.4.13.5, Sec.8.3.7.5). `DataWriter::assert_liveliness()` and the new
  `DomainParticipant::assert_liveliness()` manually renew a MANUAL writer's
  lease with nothing to write; `write()`, `dispose()` and
  `unregister_instance()` already did (unchanged for AUTOMATIC, which the
  participant keeps alive on its own). MANUAL_BY_PARTICIPANT shares one
  lease, and one wire assertion, across every writer of that kind on a
  participant: a ParticipantMessageData of kind MANUAL, the same
  BuiltinParticipantMessageWriter and sequence-number space as the
  AUTOMATIC kind's, sent only when one of them actually asserted since the
  last check (RTPS v2.5 Sec.8.4.13.5 R9 -- unlike AUTOMATIC's unconditional
  period). MANUAL_BY_TOPIC is per writer: ordinary traffic already asserted
  it; `assert_liveliness()` with nothing new to write now sends a HEARTBEAT
  with the Final and Liveliness flags set, BEST_EFFORT writers included,
  and a reader renews that writer's lease from either the flag or its data,
  never from a HEARTBEAT received for a different writer. New
  `LivelinessLostStatus { total_count, total_count_change }` (Sec.2.2.4.1)
  and `DataWriter::get_liveliness_lost_status()` (read-and-reset): raised
  once per writer per lapse, for MANUAL_BY_PARTICIPANT and MANUAL_BY_TOPIC
  only -- AUTOMATIC's liveliness is the participant's to keep, never the
  application's to miss. See Changed for the listener signature this
  status required.
  - `assert_liveliness()` is in the C, C++ and Python SDKs too:
    `hdds_writer_assert_liveliness` / `hdds_participant_assert_liveliness`
    (C ABI, both returning `HddsError`); C++ `DataWriter::assert_liveliness()`
    / `TypedDataWriter<T>::assert_liveliness()` / `Participant::assert_liveliness()`;
    Python `DataWriter.assert_liveliness()` / `Participant.assert_liveliness()`
    (`NotImplementedError` against a `libhdds_c` older than 1.5.0, same as
    `matched_reader_count()`)
- **Access brackets for C, C++ and Python**: `hdds_subscriber_begin_access`
  and `hdds_subscriber_end_access`; C++ `Subscriber::begin_access()`,
  `end_access()` and the RAII `Subscriber::access()` guard; Python
  `Subscriber.begin_access()`, `end_access()` and `with
  subscriber.access():`
- **A mixed `hddsgen`/`hdds` version mismatch now fails with one named
  error instead of thousands of cryptic ones.** Generated code calling into
  `hdds` internals (`DDS::nested_type_objects`, `write_key_holder`,
  `encodes_xcdr1_natively`, `core::key_hash`, `xtypes` `TypeObject` shapes)
  against a runtime that predates those internals used to produce ~6700
  unrelated-looking compiler errors. `hdds::codegen::CODEGEN_ABI` (checked by
  a `const` assert `hddsgen` emits once per generated file) turns that into a
  single error naming the required `hdds` version; see `hdds::codegen` docs.

- **`QoS::reliability_max_blocking_time` and `QoS::max_blocking_time(d)`**
  (DDS v1.4 Sec.2.2.3.14 RELIABILITY `max_blocking_time`, default 100 ms):
  how long a RELIABLE writer's `write()` may block for room, in its own
  history or in a reliable reader's of the same process, before it returns
  `WriteTimeout`. It was a fixed 100 ms. One `write()` blocks at most this
  long in total, and SEDP PID_RELIABILITY announces it. The FastDDS XML
  loader reads `<reliability><max_blocking_time>`, the YAML loader
  `max_blocking_time_ms`. `QoS` is a struct with public fields: a struct
  literal that names every field without `..QoS::default()` must add this one
- **RELIABILITY `max_blocking_time` is exposed in the C, C++ and Python
  SDKs.** C: `hdds_qos_set_max_blocking_time_ns(qos, duration_ns)` /
  `hdds_qos_get_max_blocking_time_ns(qos)`, the same nanosecond-duration
  style as `hdds_qos_set_deadline_ns`/`hdds_qos_set_lifespan_ns`. C++:
  `QoS::max_blocking_time(d)` (any `std::chrono::duration`). Python:
  `QoS.max_blocking_time_ms(ms)` / `QoS.max_blocking_time_secs(s)` and
  `QoS.get_max_blocking_time_ns()`
- **Listeners work from C, C++ and Python.** `hdds_reader_set_listener`,
  `hdds_writer_set_listener` and their `clear` counterparts returned
  `HDDS_UNSUPPORTED`; they now install the callbacks. Struct layouts and
  function names are unchanged (the header's examples spelled the fields in
  lower case; the generated header spells them `ON_DATA_AVAILABLE`,
  `USER_DATA`, as every struct of `hdds.h`). Fire: data available,
  subscription / publication matched, liveliness changed, sample rejected,
  requested / offered deadline missed, requested / offered incompatible
  QoS, sample written, liveliness lost. Sample lost alone is accepted and
  never called: the core does not raise SAMPLE_LOST yet. The contract,
  documented in `docs/api/c.md#listeners`:
  - callbacks run on HDDS threads, and on the thread calling
    `hdds_writer_write` (inside it) for a reader of the same participant;
    several can run at once
  - no HDDS lock is held across a callback: it may take from its reader,
    write, and set or clear listeners, its own included
  - clear, replace and destroy return only once no callback of the previous
    listener runs on another thread, so its `user_data` may be freed on
    return; from inside one of its own callbacks they do not wait for it
  - a NULL callback is not reported, and a NULL `on_sample_rejected` leaves
    SAMPLE_REJECTED on the status condition; no panic or exception crosses
    the boundary
  - destroying a reader or writer from inside one of its own callbacks
    removes the listener but leaks the entity (logged) instead of freeing
    it under the HDDS code that called back
  - new, ABI-additive: `hdds_reader_exchange_listener` /
    `hdds_writer_exchange_listener` install or remove like set/clear and
    return the replaced listener's `user_data`, so a binding frees exactly
    the state of the listener that was drained, whatever order concurrent
    installs reached HDDS in
  - C++ (`hdds_listener.hpp`): `ReaderCallbacks` / `WriterCallbacks`
    (`std::function`) and `shared_ptr` listeners owned by the entity, an
    exception escaping a callback caught and reported
    (`set_listener_exception_handler`); Python: `set_listener` with the GIL
    taken by the callback thread, exceptions logged on `hdds.listener`, only
    overridden methods installed, listeners removed at exit
  - tests: `sdk/c/tests/test_listener.c` (also clean under
    AddressSanitizer), `sdk/cxx/tests/test_listener.cpp`,
    `sdk/python/tests/test_listener.py`
- **`DataReader::set_listener` / `DataWriter::set_listener`** install,
  replace or remove a listener on a live entity, with a `StatusMask` (DDS
  v1.4 Sec.2.2.2.1.1). A status outside the mask is not reported;
  SAMPLE_REJECTED outside it is not consumed by the listener. It reaches
  every callback site, the match notifications registered at build time
  included. It does not wait for a callback already running (that callback
  holds its own `Arc`). `StatusMask::INCONSISTENT_TOPIC` is new
- **A participant that discovers nobody says where to look, once.** About
  two SPDP announcement periods after start (6 s by default), a participant
  that knows no remote participant and has nothing but multicast to discover
  one with (no static peer, `HDDS_SPDP_UNICAST_PEERS`, Discovery Server or
  cloud discovery) logs one line naming what to check: `HDDS_INTERFACE`,
  unicast peers, a Discovery Server, and the page
  https://docs.hdds.io/getting-started/network-prerequisites. It is INFO,
  since a participant alone on its network is legitimate, and WARN when the
  transport's multicast send probe on the primary interface was refused at
  start-up (the existing "blocked (VPN/tunnel policy?)" detection), since a
  measured local cause then explains the silence. Evaluated once, by the SPDP
  announcer thread; nothing on the data path, and never repeated
- **Local restriction overlay for DDS-Security access control.** A plain,
  unsigned file, re-read when it changes, that can only take an action away
  from what the signed `permissions.xml` already granted. Configured with
  `SecurityConfig::builder().permissions_overlay(path)` and
  `.permissions_overlay_poll(interval)`, or from C with
  `hdds_security_config_set_permissions_overlay()` and
  `hdds_security_config_set_permissions_overlay_poll_ms()`
  - The point is the day you have to close a topic on a running fleet.
    Granting still means reissuing a document signed by the Permissions CA;
    DDS Security v1.1 9.4.1.3 makes that CA the root of what a participant may
    do, and an unsigned file that could widen a grant would be a way around
    the chain of trust. Narrowing breaks no guarantee, so it needs no
    signature
  - Subjects are matched as RFC 4514 distinguished names through the same
    reader the signed document uses, so attribute order, spacing and alias
    spellings do not matter. A subject the file does not name is not
    restricted at all
  - Unlike the signed document's rules, deny lines win over allow lines
    whatever their order (the overlay's own format); `partitions=` is
    evaluated on every partition the endpoint names, a refusal in one
    refusing the endpoint (during this release cycle it read the first
    named partition only)
  - A missing overlay file fails the participant build by name; a malformed
    edit while running keeps the previous document and records a `FileError`.
    Both failure modes are the same choice: a restriction that quietly does
    not apply is worse than one that is loudly absent
  - Format, behaviour table and rationale: `docs/security-guide.md`, "Local
    Restriction Overlay"

- **Participant-level transport options**, grouped into one `TransportOptions`
  struct passed to `ParticipantBuilder::with_transport_options()`, for
  constrained and non-multicast networks
  - IP TTL, DSCP marking, and an interface allowlist, each of which still
    falls back to its environment variable (`HDDS_TTL`, `HDDS_DSCP`,
    `HDDS_INTERFACE_ALLOW`) when left unset
  - `MulticastMode` with three states: `Enabled` (the default, unchanged
    behaviour), `ReceiveOnly` (listen but never emit multicast, for asymmetric
    links) and `Disabled` (no group join at all, for containers, WAN segments
    and Discovery Server deployments). In the two non-default modes SPDP goes
    unicast to static peers, `HDDS_SPDP_UNICAST_PEERS`, Discovery Server
    locators and every participant already known
  - `require_multicast_join`: by default a participant that cannot join its
    multicast group now degrades to unicast-only discovery with a warning and
    a queryable `UdpTransport::multicast_join_error()`, instead of failing;
    set it to `true` for fail-fast
  - Shorthands `TransportOptions::unicast_only()` and
    `TransportOptions::receive_only()` for `MulticastMode::Disabled` and
    `MulticastMode::ReceiveOnly`. They are on the options struct, not on
    `ParticipantBuilder`, so they compose with the other setters above and
    reach the participant through `with_transport_options()`
- **UDP socket buffer sizing** through `ParticipantBuilder`, the
  `HDDS_RCVBUF_BYTES` / `HDDS_SNDBUF_BYTES` environment variables and the C
  API, with the kernel-clamped effective value read back and logged
- **Shared-memory transport for co-located BEST_EFFORT endpoints.** The data
  path is wired end to end. It is on by default for a participant built
  through `ParticipantBuilder`, which sets `ShmPolicy::Prefer` (see the
  `ShmPolicy` entry under Breaking changes), and off with
  `ShmPolicy::Disable`. A pairing only
  gets a shared-memory leg when both endpoints are BEST_EFFORT, the peer
  advertises the capability, and co-location is provable; every other pairing
  stays on UDP, decided once at SEDP match time
  - The segment is authenticated: its control block carries the owner's GUID
    and a per-participant nonce announced over discovery, and a reader refuses
    a segment that does not match. Size and slot geometry are validated before
    mapping
  - A peer that selected shared memory but has not claimed a presence entry
    keeps its UDP leg, so a wrong co-location verdict degrades to "stays on
    UDP" rather than to data loss
  - Per-endpoint override via `WriterBuilder::shm_policy()` /
    `ReaderBuilder::shm_policy()`
- **The full DDS 1.4 Annex B query and filter grammar** for
  ContentFilteredTopic and QueryCondition expressions
  - `AND`, `OR`, `NOT`, parentheses, the three comparison forms,
    `BETWEEN` / `NOT BETWEEN`, the operators `=`, `>`, `>=`, `<`, `<=`, `<>`
    and `LIKE`, and `%0` to `%99` parameters
  - Field names with unlimited dotted depth, signed and hexadecimal integers,
    floats with exponents, character, string and enumerated literals
  - `QueryExpression` accepts an optional condition plus an `ORDER BY` field
    list, returned in `QueryExpression::order_by`. The list is parsed and
    reported; no read path orders samples by it yet
  - `!=` and `==` are accepted as local aliases of `<>` and `=`, and `TRUE` /
    `FALSE` are accepted against a boolean field. Both are extensions beyond
    Annex B and are documented as such
  - Anything outside the grammar is a `FilterError::ParseError` naming the
    rule or token that was violated
- **Working `ReadCondition` and `QueryCondition`.** They are fed from the
  DataReader's own cache and dispose-event queue and evaluate on every trigger
  check. Before 1.5.0 `get_trigger_value()` read a manually set flag and
  `QueryCondition` stored the expression string without ever evaluating it
  - New `DataReader::read_w_condition()` and `take_w_condition()`, which return
    matching data and the instance-state transitions the condition's masks
    select
- **`DataReader::take_with_info()` and a real `SampleInfo`**, carrying
  `source_timestamp_ns`, `reception_timestamp_ns`, `writer_guid`,
  `sequence_number`, `instance_handle`, `instance_state`, `valid_data`,
  `sample_state` and `view_state`
- **`SAMPLE_REJECTED` is a real DDS status**, raised on actual resource-limit
  drops (slab-pool exhaustion, per-reader ring full), reset before the
  callback runs, and notifying attached WaitSets
- **`on_inconsistent_topic()` on `DataReaderListener` and
  `DataWriterListener`**, backed by an `InconsistentTopicStatus`. It has a
  default no-op body, so existing implementors are unaffected
- **DDS-XTypes TypeLookup `getTypes`**, implemented on both sides: HDDS serves
  incoming requests and issues its own, resolving remote TypeInformation
  hashes to local TypeObjects at SEDP ingress with a name-based second
  recourse
  - `PID_TYPE_INFORMATION` (0x0075) is announced for struct, enum and union
    endpoints, and the dependency list follows plain collection element and
    key identifiers
  - Union TypeObject support: minimal hash, XCDR2 `DHEADER` / `EMHEADER`
    framing and XCDR1 `PL_CDR1` framing, 1-based branch member ids
  - CDR2 encode and decode for `AppliedAnnotation`
  - Structural type assignability for nested complex references is on by
    default (see Breaking changes for the feature-set note)
- **`#[derive(DDS)]` generates `get_fields()`**, so a derived type can be used
  with a content filter without a hand-written extractor. Primitive and
  `String` members are exposed; `Vec<u8>` is not
- **Cloud and DNS discovery backends** (feature `cloud-discovery`, off by
  default), replacing what the README listed as stubs
  - AWS Cloud Map over SigV4-signed HTTPS, with the full credential chain
  - Azure Table Storage with Managed Identity and AKS Workload Identity
  - Consul with a TTL health check, ACL token, a single KV mirror key,
    explicit deregistration and rollback when a registration is refused
  - DNS-SD over SRV and A/AAAA records with an in-tree RFC 1035 codec and no
    external dependency (feature `dns-sd`)
  - Builder entry points `with_consul_options()`, `with_aws_cloud_map_config()`,
    `with_azure_discovery_config()` and `with_dns_sd()`, and a
    `CloudDiscoveryStatus` that distinguishes a registry refusing the poll from
    a registry that simply knows nobody
- **Automatic Discovery Server rendezvous.** A client runtime owned by the
  participant connects, announces itself, streams peer events and feeds them
  into the SPDP peer set, so server-learned peers receive unicast SPDP like
  any other
- **DDS-Security data plane and document verification** (feature `security`,
  off by default)
  - User-data payloads and dispose/unregister lifecycle DATA are encrypted
    with AES-256-GCM under per-writer keys
  - Governance and permissions documents are PKCS#7 / S-MIME signature
    verified against the configured Permissions CA before a participant
    starts, and only the grants issued to this identity are applied. A signed
    document with no configured CA, or an unsigned document, is refused unless
    the operator explicitly opts out
  - Per-writer data keys are distributed to authenticated peers over a
    volatile secure channel, wrapped with a per-peer key derived from the
    PKI-DH shared secret
  - Key agreement negotiates between ECDH P-256 and P-384 from the
    `kagree_algo` configuration string and refuses an unknown suite rather
    than falling back
  - SEDP announcements are encrypted once a peer has completed the PKI-DH
    handshake: the CDR payload is wrapped under the metatraffic key derived
    from the shared secret, and the writer entity id moves into the secure
    `0xff` namespace. A peer that has not authenticated still receives
    plaintext, and a wrap that fails while we hold the peer's key logs an
    error rather than downgrading silently
  - Participant-message traffic is NOT encrypted, because HDDS sends none.
    The secure ParticipantMessage endpoints (`0xff0200c2` / `0xff0200c7`) are
    enumerated, advertised in `PID_BUILTIN_ENDPOINT_SET` and recognised by
    the packet classifier on receive, but no send path in the crate ever
    builds one. HDDS writes no `ParticipantMessage` sample at all: the only
    traffic it emits on the plain P2P endpoints is an empty HEARTBEAT
    (`firstSN` 1, `lastSN` 0, meaning "this writer exists, no data yet") and
    a preemptive ACKNACK, both interoperability gestures toward peers that
    wait for them.
    LIVELINESS is a local monitor riding the SPDP lease renewal and has no
    wire protocol of its own, so there is nothing for a secure tunnel to
    carry
  - A hash-chained audit log, one file per participant, mode 0600 on Unix,
    with a `verify_chain` check. A failed write marks the chain degraded and
    every later security decision then refuses to proceed. Off unless
    `SecurityConfig::audit_log_path` is set
  - `hdds_security_config_set_permissions_ca()` in the C API
  - Note that this crypto framing is HDDS to HDDS. It is not the spec's
    `SEC_PREFIX` / `SEC_BODY` / `SEC_POSTFIX` submessage form and does not
    interoperate with another vendor's secure builtins
- **A much larger C API.** All additions; no exported symbol was removed
  - Transport tuning: DSCP, socket send and receive buffer sizes, SPDP
    announcement period, participant lease duration, unicast and multicast
    TTL, an allowed-interface list and the three-state multicast mode
  - Discovery: `hdds_writer_matched_reader_count()` and
    `hdds_writer_wait_for_matched_readers()`, with a new `HDDS_TIMEOUT` error
    code
  - TLS material setters (feature `tcp-tls`), which fail closed:
    `hdds_config_build` returns NULL if material was set without
    `hdds_config_enable_tls`, or if the library was built without the feature
  - ReadCondition, QueryCondition, ContentFilteredTopic and dynamic-data
    accessors. These source files existed before 1.5.0 but were never declared
    as modules, so they were compiled out of every shipped library
  - An optional synchronous DDS-RPC client and server (feature `rpc`)
  - `hdds_build_git_sha()`, matching the new `hdds::BUILD_GIT_SHA` constant
- **TLS configuration hardening** (feature `tcp-tls`)
  - `TlsConfigBuilder::try_build()` returns a typed `TlsBuildError` instead of
    a vague I/O error, and refuses two build ambiguities outright: requiring a
    client certificate with no client CA, and configuring a CRL on a server
    that does not require client certificates
  - CRL-based client certificate revocation via `with_crl_pem()`
  - Protocol version bounds (`min_protocol_version` / `max_protocol_version`,
    default TLS 1.2 through 1.3) and a `disable_session_resumption()` switch
- **Python SDK packaging.** A real `pyproject.toml` building a pure-Python
  wheel over a `ctypes` binding, with a fail-closed tiered library search that
  raises an `ImportError` naming every path it tried, and both licence texts
  bundled in the wheel
- **TypeScript SDK.** The native binding now loads (it raised a `TypeError` on
  the first call before 1.5.0 because of an unrecognised koffi type name), the
  package entry points match what `tsc` actually emits, and the five samples
  the README advertised exist and are exercised, including a WebSocket bridge
  sample that talks to the `hdds-ws` tool
- **A real WebAssembly artefact.** A hand-written C ABI plus ES-module JS glue
  over linear memory, and a native relay (feature `relay`) that bridges
  browser WebSocket clients onto a real DDS domain, carrying a QoS block that
  reaches the participant
- **ROS 2 support for Iron and Jazzy** alongside Humble in `rmw_hdds`, with a
  per-distro symbol list and a hermetic per-distro build gate
- **DDS-XRCE.** The agent bridges XRCE clients onto a real DDS domain instead
  of the previous null bridge that dropped every sample, and a new
  `hdds-xrce-client` crate provides a `#![no_std]`, `#![deny(unsafe_code)]`,
  zero-allocation client
- **Schema registry and InfluxDB sink became real services.** The registry is
  an HTTP server with versioning, compatibility checking, file persistence and
  DDS distribution; the sink now actually performs the HTTP writes its own
  documentation previously said it did not
- **`hdds-gen` answers `--version`, `-V` and `version`**

- **`ReaderBuilder::with_field_extractor()` and `with_type_name()`**: supply
  manual field access so content filtering works on a type whose schema is not
  derived, and announce a discovery type name different from the Rust type's own
- **`ParticipantBuilder::with_participant_lease_duration()` and
  `with_spdp_announcement_period()`**, so Rust callers can tune the discovery
  cadence that until now only the C API exposed
- **`Participant::discover_endpoints()`**, with `DiscoveredEndpointKind` and
  `DiscoveredEndpointInfo`: a per-endpoint snapshot of what discovery has seen,
  for building tooling and viewers
- **`WriterBuilder::publisher()`**, the write-side twin of the already
  documented `ReaderBuilder::subscriber()`, and what a writer needs in order to
  join a GROUP-scope coherent set
- **Two default-provided methods on the `DDS` trait**, `nested_type_objects()`
  and `encode_key()`. Non-breaking, since both have defaults, but new surface
  if you implement `DDS` by hand rather than deriving it
- **An externally mapped address can be announced**:
  `TransportOptions::with_external_locator()` /
  `with_external_locators()`, or `HDDS_EXTERNAL_LOCATOR`, for a participant
  behind a NAT with a fixed public IPv4 address and ports. It is announced
  after the local locators, never in their place, so peers on the LAN keep
  using the local address. Values no peer can reach (0/8, loopback, multicast,
  broadcast, 169.254/16, 240/4, port 0) are refused; a malformed environment
  value announces nothing external and logs an error
- **A WAN relay through the Discovery Server**, opt-in with
  `DiscoveryServerConfig::with_relay()` (off by default). A peer whose
  announced addresses are all unreachable is given a synthetic address in
  240.0.0.0/8; datagrams to it travel inside the Discovery Server session, and
  datagrams relayed to this participant enter the same receive path as UDP
  traffic, with their own counters. The client session is event-driven: heavy
  traffic in both directions no longer makes it block against itself, and a
  session whose writes stall for a heartbeat interval (500 ms minimum) ends
  - New on `DiscoveryServerClient`: `send_relay_data()`,
    `misrouted_relay_frames()`, `unknown_messages()`, `wait_for_io()`,
    `waker()`, `rearm()`, `outbox_room()`, `flush()`, `flush_blocking()`, and
    `SessionWaker`. The client socket is non-blocking: `read_message()`
    drains until the socket is empty and `Ok(None)` means nothing is left
- `hdds::reliability::ENTITYID_UNKNOWN` (RTPS 2.5 9.3.1.2, all zero), which
  replaces the two side-named constants (see Deprecated)
- `HeartbeatMsg::decode_all_from_packet()` and
  `control_parser::parse_all_acknack_submessages()`: every HEARTBEAT and every
  ACKNACK of a datagram, in wire order
- `DiscoveryFsm::remove_remote_endpoint()`, `FragmentGeometry`,
  `Scheduler::max_record_size()` and `SchedulerStats::records_too_large` (low
  bandwidth transport), `ChangeMetadata::status_info`,
  `build_dispose_packet_with_context_ts()`, and the plaintext
  `RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER` / `_READER`
  constants in `core::rtps_constants`
- Default-provided trait methods, non-breaking: `engine::Subscriber::
  reader_entity_id()` (default `None`, meaning "receives everything"), and
  `engine::NackHandler::on_acknack()`. New `TopicRegistry::deliver_acknack()`
  and `HistoryCache` methods `set_release_policy()`, `set_acked_floor()`,
  `acked_floor()` and `insert_with_metadata_until()`
- hdds-micro: `SubmessageHeader::framing()` reads a submessage header in the
  endianness it declares
- Default-provided hooks, non-breaking: `DiscoveryListener::
  on_participant_departed()` (a remote participant left, by any removal)
  and `on_participant_forgotten()` (its per-peer records must go), and
  `engine::Subscriber::on_dispose_from_writer()` (a dispose or unregister
  with the DataWriter that sent it; defaults to `on_dispose`). New
  `TopicRegistry::register_writer_lifespan_of()` and
  `deliver_dispose_from_writer()`
- Default-provided trait method, non-breaking:
  `protocol::dialect::DialectEncoder::build_spdp_in_domain()`, which writes
  the participant's domain into every domain-id parameter the encoder
  writes (`build_spdp()` carries no domain id)

- seL4 / Microkit transport for the embedded subset, `hdds-micro` on a
  Microkit protection domain: the standalone crate `hdds-micro-sel4`
  (`crates/hdds-micro-sel4/`, outside the workspace) provides a packet ring over the sDDF
  network queues, a UDP `Transport` on top of it, and publisher and subscriber
  protection-domain modes. What is verified, and what is not, is listed in
  `crates/hdds-micro-sel4/README.md`.

### Changed

- **One domain rule in every binding: a domain set in code wins, else
  `HDDS_DOMAIN_ID` if valid, else 0.** Before, the core ignored the variable,
  the C API read it with a silent fallback to 0, and the C++, Python and
  TypeScript constructors passed an explicit 0. A malformed or out-of-range
  `HDDS_DOMAIN_ID` now fails the participant build (Rust `Error::Config`, C
  NULL) and the ROS 2 init, instead of landing on domain 0. Breaking for C++:
  the `domain_id` argument is `std::optional<uint32_t>`, so C++ callers need a
  rebuild.
- **Breaking: `DataWriterListener::on_liveliness_lost` takes a
  `LivelinessLostStatus` (DDS v1.4 Sec.2.2.4.1).** It took no argument
  before, which could not carry `total_count`/`total_count_change`; every
  Rust implementor must add the parameter. Mirrored into the C ABI
  (`HddsOnLivelinessLost` now takes a `const HddsLivelinessLostStatus*`),
  the C++ SDK (`WriterListener::on_liveliness_lost(const
  LivelinessLostStatus&)`, `WriterCallbacks::on_liveliness_lost` likewise)
  and the Python SDK (`WriterListener.on_liveliness_lost(self, status)`) --
  the same breaking change in all four.
- **`hdds-shm-viewer` recognises version-2 notify segments.** It previously
  listed only the legacy `/hdds_notify_d<domain>_<topic>` name; v1 segments
  are now labelled legacy and the current `/hdds_notify_v2_d<domain>_<topic>`
  segments are listed with their header's magic/version, open/closed state,
  and a best-effort live-user-row count read without taking the header's
  mutex. An `.owner` sidecar file is no longer listed as a segment of its
  own: its pid is attached to the ring segment it belongs to. The tool also
  dropped its 13 unsafe `shm_open`/`mmap`/atomic-pointer blocks and its one
  unchecked cast in favour of plain `std::fs::File` reads of the first bytes
  of each segment (`/dev/shm` already is the file backing a POSIX shared
  memory object), clearing the audit debt that had been blocking edits to
  this file
- **The slab pool keeps a share of every tier for the samples readers
  receive: `MemoryPolicy::reader_reserve_percent`, default 25.** The pool is
  process-wide: a RELIABLE KEEP_ALL writer's unacknowledged history and the
  samples a co-located reader receives share it. A writer whose history
  filled it left its own reader no storage for the repair that would
  acknowledge that history, and both waited for good (seen end to end: 4000
  samples of 6 kB in one process over UDP, write 2935 timed out after 30 s,
  one sample delivered). Writers now never take the share: of every size
  class (rounded up to a whole slot) and of `max_heap_bytes`
  - **Effect on a process that only writes**: it gets 100 less the share of
    each tier, 75 % at the default (measured with the default policy: 2205
    writes of 6 kB where the whole pool took 2940, 12 of 1 MB where it took
    16). A reliable write that finds the pool full waits up to
    `max_blocking_time` for its readers to acknowledge (DDS 1.4
    2.2.3.18), then fails with `WriteTimeout`
  - Accepted range 1..=93, refused otherwise at build: 0 keeps nothing for
    readers and brings the stall back (verified: same burst, write 2935 of
    4000 timed out); above 93 writers lose the last slot of the 16-slot
    primary class, and at 100 every write fails. A `large_pool` class with
    few slots may keep none for writers below 93: they use the heap tier
  - **A reliable reader stores a sample before it acknowledges it, also
    when it cannot be taken yet**: one its reorder gate holds above a gap,
    one of a coherent set still staged. Such samples used to be kept in
    their received form and stored only at their release, past the pool's
    ceiling (up to several times `max_heap_bytes`), or lost once
    acknowledged. Now one with no storage is refused unacknowledged and its
    writer sends it again. A sample held above a gap stays within the
    readers' share of the heap tier, and keeps room for the sample that
    would release it (an estimate that follows the sizes the reader stores)
  - The next sample of a writer, in order, at a reliable reader, may take
    the heap tier past `max_heap_bytes` by itself alone when every tier is
    full, and only while the tier is not past it already: the heap tier's
    gauge exceeds `max_heap_bytes` by at most one sample at any time.
    Refused, it waited for storage held for the samples it releases, or for
    a co-located writer's history that only its acknowledgement frees
  - **A coherent reader stages its sets in a budget of its own, outside
    the pool's tiers.** A staged sample is stored in the heap tier but
    outside `max_heap_bytes` and `heap_bytes_used`, on a gauge of its own
    (`SlabPoolMetrics::staged_heap_bytes`), and charged to its reader only:
    no other reader and no writer takes from that budget, nor it from
    theirs. Every staged change is charged: its storage and its entry (256
    bytes), a dispose or unregister of the set, or a sample that does not
    decode, its entry alone (uncharged, such changes piled up without bound
    below a change staged high, 2997 for 3000 sent). A set may take `N`
    changes and `L = N x S` bytes, `N` being RESOURCE_LIMITS `max_samples`,
    else `max_instances` x `max_samples_per_instance`, else 4096, and never
    more than 4096, and `S` the largest charge of the sets the reader
    stages now (storage as stored: re-encoded, after its writer's GUID;
    the arriving one included; never more than 16 MiB, the largest sample
    a reader re-encodes), not the largest it ever staged. A set in order
    (nothing of its writer awaited below its first sample) is never
    refused; the sets staged above a gap share one `L`, and a change past
    it is refused unacknowledged and resent. A staged change is charged
    until it leaves the reorder gate for the application
  - **The coherent readers of a process stage at most
    `MemoryPolicy::max_staging_bytes` together** (64 MiB by default),
    staged storage being outside every tier's ceiling: eight remote
    writers' sets, never closed, could stage 100 MB in one reader of a
    process whose heap tier held 1 MiB. What the process charges never
    passes it: a change is charged only if the process stays within it,
    atomically. A change that would take the process past it never waits
    for room: the ceiling is split evenly among the readers that stage,
    and a set is rejected whole only in a reader above its share, the
    youngest not in order there first, then the youngest in order, the
    change's own set if it is that one (a set with nothing staged yet is
    the youngest); with nothing left to reject, the change's own set is
    rejected, and so is a set that alone would pass the ceiling. A reader
    within its share loses no set to another reader: a reader flooded by
    a hostile peer used to make a well-behaved one lose its sets. A set
    rejected after it committed, held by its writer's gate above a gap,
    gives its storage back there too (its changes deliver nothing):
    kept, a set in order was staged past the ceiling (3.7 MB under 2 MiB)
  - A coherent set is rejected whole, and only then, when it alone would
    take more than `L` or `N` changes, or when the process ceiling makes
    room as above. Its staged samples give their storage back at once;
    every sample of it, staged before or arriving since, is acknowledged,
    delivered never, and reported as SAMPLE_REJECTED
    (REJECTED_BY_SAMPLES_LIMIT) once, as it is rejected or arrives, no
    longer once the set is closed. What is left of the set is a record of
    constant size: a sample of it arriving later takes no storage, no
    staging entry and is not decoded (refused unacknowledged only when its
    writer's reorder gate holds no more above a gap). A set rejected and
    never closed used to keep one staging entry per sample for good, each
    sample walking them all (20000 samples, 20000 entries)
  - A writer's staging bound (4096 staged changes) no longer refuses its
    set in order (nothing of the writer awaited below it, once its gate
    has a baseline: at most `N` changes more), nor the change that rejects
    its set (a set at `N` changes): each was refused for good, and the
    writer's stream stalled. A change merely below one staged is no
    exception any more. Nothing of a rejected set is staged any more: no
    change of one passes the bound, nor the GROUP set bound (8192). A
    writer has at most 256 GROUP sets open: a change opening one more is
    refused unacknowledged, but its set in order's (a peer opened one per
    change, a fresh GSN each, never closed)
  - A set rejected while its commit waited for places in the history is no
    longer put back staged: its charge kept, it was delivered after it
    was reported rejected
  - A coherent sample that arrives after a reliable reader's reorder gate
    passed its sequence number (its writer gave it up, a HEARTBEAT's
    firstSN past it, and the reader reported it lost) is dropped, as a
    duplicate is: staged, its set was delivered behind later samples, out
    of order
- **The serialized payload of a sample ends on a 4-octet boundary, and its
  encapsulation options say how many padding octets that took.** DDS-XTypes
  1.3 7.6.3.1.2: the two low bits of the second options byte count the
  padding after the serialized data, and the receiver reads them to find
  where the data ends. HDDS sent options `0x0000` on everything: a DATA or
  DATA_FRAG whose body was not a multiple of 4 octets ended unpadded, and the
  key-only DATA of a dispose or unregister was padded while its options said
  it was not. Every user DATA, DATA_FRAG and key-only DATA now pads its
  payload with zeros to a multiple of 4 and counts them, as Cyclone DDS 0.11
  does (`0007 0003` in front of a 13-octet body)
  - On receipt the counted padding is cut before the sample reaches the
    reader, at both doors a sample takes (a DATA, a reassembled DATA_FRAG). A
    typed decoder stops at its last member and never saw the difference; an
    opaque payload (`BytePayload` of the C API and `rmw_hdds`, `RawBytes` of
    live capture, the XRCE bridge) from a padding writer is now delivered at
    its exact length instead of with up to three extra zero octets
  - **1.4.x compatibility**: a 1.4.x reader does not read the count, so a
    1.5.0 sample whose body is not a multiple of 4 reaches it with up to three
    zero octets more. A typed reader decodes it as before; an opaque reader
    sees the extra octets. A 1.4.x writer's options are zero, so a 1.5.0
    reader cuts nothing from its samples
  - **Protected payloads carry their own representation.** The protected
    SerializedPayload includes its CDR encapsulation and declared padding.
    Packet builders copy CryptoHeader, CryptoContent and CryptoFooter
    byte-for-byte and add no outer encapsulation. The reader cuts the
    original CDR padding only after authentication; see Upgrading for the
    secure-wire transition
  - SPDP and SEDP keep options zero, as DDSI-RTPS 2.5 10.3 requires of the
    built-in endpoints. The TypeLookup service, which frames its own
    requests and replies, is not changed by this entry
- **Configuring a cloud registry, DNS-SD or a Discovery Server now turns
  multicast SPDP off by default**, since the registry replaces it. This only
  applies while the transport is still at its own default; an explicit
  `with_transport_options()` is respected, and
  `cloud_discovery_disable_multicast(false)` /
  `dns_sd_disable_multicast(false)` restore multicast alongside the registry
- **PARTITION QoS matching follows DDS 1.4 section 2.2.3.13.** The rule had
  been written out separately in several places, three of them wrong
  - An empty partition list is now treated as `[""]`, so a writer in the
    default partition matches a reader requesting `"*"`. It previously did not
  - Two names that both contain wildcards no longer match each other
- **Content filter accessors return the expression you supplied.**
  `ContentFilteredTopic::filter_expression()`, `ContentFilter::expression()`
  and `hdds_filter_get_expression()` return the source text verbatim, per DDS
  1.4 section 2.2.2.3.3.2. The Annex B normalised form is available separately
  through `canonical_expression()` and `hdds_filter_get_canonical_expression()`.
  This release does NOT announce `ContentFilterProperty` over SEDP - there is
  no encoder or decoder for RTPS parameter id `0x0035` anywhere in the crate -
  so content filtering is applied reader-side only and neither form of the
  expression currently reaches the wire
- **A late-joining reader receives historical samples in writer-sequence
  order.** For every DURABILITY kind other than `VOLATILE`, a per-writer
  reorder buffer now holds out-of-order samples and releases them only once a
  contiguous run is available, seeded from the writer's first HEARTBEAT. On
  the wire a late joiner sees the current change interleaved with unicast
  retransmits of the backlog; `read()` and `take()` no longer expose that
  order. The buffer is capped per writer
- **`unregister_instance()` honours `WRITER_DATA_LIFECYCLE`.** It previously
  sent an unregister on the wire regardless of
  `autodispose_unregistered_instances`; it now sends a disposed-unregistered
  change when the policy asks for one
- **Dropping a `DataWriter` honours `WRITER_DATA_LIFECYCLE` too.** Deleting a
  DataWriter unregisters its instances, and the same flag decides whether
  that disposes them (DDS 1.4 2.2.2.4.1.6, 2.2.3.21). The drop used to send a
  plain unregister whatever the policy, so readers, remote and in the same
  participant alike, saw NOT_ALIVE_NO_WRITERS where the default asks for
  NOT_ALIVE_DISPOSED. It now applies the rule `unregister_instance()` applies
  - **With the default policy (TRUE), dropping a writer now leaves its
    instances NOT_ALIVE_DISPOSED.** An application that wants them to read as
    NOT_ALIVE_NO_WRITERS after the writer goes away sets
    `writer_data_lifecycle_manual_dispose()` on the writer
  - An instance the application already disposed is still left alone by the
    drop, whatever the policy: nothing more is sent for it
  - `examples/shape_main.rs` turns the policy off for its plain-exit run,
    whose expected outcome is NOT_ALIVE_NO_WRITERS, as it already did for the
    explicit-unregister run; what it puts on the wire is unchanged
- **Certificate revocation checking defaults differ by builder.**
  `SecurityConfig::builder()` leaves `check_certificate_revocation` at `false`;
  `SecurityConfig::secure_builder()` sets it to `true`
  - A configuration from `secure_builder()` therefore needs a CRL: with the
    flag on and no `certificate_revocation_list()`, `SecurityConfig::build()`
    refuses it by name (see Breaking changes). Name a list, or call
    `.check_certificate_revocation(false)` to state that revocation is out
    of scope for your deployment
  - OCSP is not supported and is documented as out of scope: it needs an
    outbound HTTP connection that air-gapped deployments do not have
- **The published intra-process latency figure was mislabelled and has been
  corrected.** The 257 ns result is a write-path measurement (POD encode plus
  publish) from a v0.8.0-era benchmark, not an end-to-end intra-process
  latency, and the documentation now says so wherever it appears. The ROS 2
  latency table also named the wrong reference machine
- **`hdds-c`'s `security` Cargo feature now forwards to the core.** It was
  declared as an empty feature list, so enabling it did nothing

- **The ROS 2 environment variables now do what they say, which can change a
  working deployment.** At 1.4.x `rmw-hdds` parsed `HDDS_MULTICAST_DISABLE`
  into a field no caller ever read, so setting it changed nothing. It now maps
  to `MulticastMode::Disabled`, and `HDDS_DISCOVERY_PEERS` /
  `HDDS_INITIAL_PEERS` likewise now seed static peers. **An operator who set
  `HDDS_MULTICAST_DISABLE` defensively, and harmlessly, loses multicast
  discovery for real on upgrade.** Unset it, or keep it deliberately
- **Discovering a peer with vendor id `0x0101` now emits up to 12 extra
  empty ACKNACKs** at that peer's SEDP publications writer, 150 ms apart, to
  solicit an earlier flush of its endpoint announcements. Gated strictly on
  vendor id `0x0101`, so no other peer sees it. It is listed because it is
  new outbound traffic that a packet capture will show
- **`md-5` is now an unconditional dependency of the `hdds` crate.** It was
  optional behind the `xtypes` feature; the domain registry and the DNS-SD
  runtime now use it outside any feature gate, so a `--no-default-features`
  build can no longer drop it
- **RESOURCE_LIMITS and DURABILITY_SERVICE default to unlimited**, as DDS
  1.4 2.2.3.19 specifies: `ResourceLimits::default()` goes from 100 000 / 1 /
  100 000 (max_samples / max_instances / max_samples_per_instance) to
  `LENGTH_UNLIMITED`, and `DurabilityService::default()` from 1000 / 1 / 1000.
  `QosProfile::low_latency()` and `high_throughput()` no longer cap instances
  at 1. On the wire, `PID_RESOURCE_LIMITS` is a signed long with -1 for
  unlimited. A writer's history is now kept per instance (see Fixed), and a
  TRANSIENT_LOCAL writer uses its own HISTORY and RESOURCE_LIMITS rather than
  DURABILITY_SERVICE for what it keeps
- **An `engine::Subscriber` that names no reader receives only what is
  addressed to every reader.** A DATA, HEARTBEAT or GAP whose readerId names a
  specific reader goes to the subscriber reporting that id through
  `reader_entity_id()`; one reporting `None` receives ENTITYID_UNKNOWN traffic
  only
- **`Router::start_with_notifier()` and `start_with_transport()` request no
  fragments.** A NACK_FRAG is sent in the name of a local reader matched with
  the writer, and these constructors know no reader; they used to send it
  under an identifier derived from the writer's, which could be the real id
  of an unrelated reader. A participant's own router is unaffected
- **`MulticastListener::spawn*()` and `engine::route_raw_rtps_message()` know
  no participant**, so they apply every submessage of a datagram, including
  one an INFO_DST destines to another participant. A participant's own
  receive paths filter those first (see Fixed); a caller that receives for a
  participant must do the same
- The public parsers in `core::discovery::multicast::control_parser` return
  at most 64 HEARTBEATs, GAPs, ACKNACKs or NACK_FRAG samples per datagram, and
  skip a submessage whose declared length cannot hold its fields instead of
  reading the next one's bytes. `HeartbeatMsg::decode_from_packet()` reads the
  endianness each submessage declares, treats a length of 0 as "to the end of
  the message" and aligns every submessage on four octets
- The Discovery Server client skips a frame of a type it does not implement
  (counted by `unknown_messages()`) instead of returning a protocol error; an
  unknown type is reported as `io::ErrorKind::Unsupported`
- `LowBwTransport::send()` returns `TransportError::Fragment(
  FragError::PayloadTooLarge)` for a message no frame can carry, and
  `Scheduler::enqueue()` is `#[must_use]`
- **An inconsistent HISTORY / RESOURCE_LIMITS or DURABILITY_SERVICE QoS now
  returns `Error::InvalidQos`, not `Error::InvalidState`.** DDS 1.4 2.2.1.1
  and the create_datawriter / create_datareader text define this as
  INCONSISTENT_POLICY, a distinct return code from PRECONDITION_NOT_MET; the
  previous `InvalidState` was never the spec's name for it and the dedicated
  `InvalidQos` variant existed but was never constructed. Callers matching on
  `Error::InvalidState` for a bad QoS (HISTORY depth over
  `max_samples_per_instance`, a zero RESOURCE_LIMITS field, `max_samples` under
  `max_samples_per_instance`, or an invalid DURABILITY_SERVICE) must match
  `Error::InvalidQos` instead; the message text is unchanged in spirit. The C
  ABI and `rmw_hdds` already map `InvalidQos` to `HddsInvalidArgument`,
  consistently with `Config`
- `QosProfile::validate()` now calls the same HISTORY / RESOURCE_LIMITS
  consistency rule the DataWriter and DataReader builders use
  (`check_history_and_limits`) instead of carrying its own copy; a couple of
  its error messages changed wording to match (still `Result<(), String>`,
  still describing the same two DDS 1.4 rules)
- A reader with a time-based filter reports a sample's arrival to its listener through
  `on_data_available_notification`, not through `on_data_available(&sample)`, the way a reader that
  orders by source timestamp already does: which sample the application sees is decided when it enters
  the reader's history, so the arrival's value may not be the one shown. Take or read to obtain it.
- **The C ABI payload callbacks are called again on a BY_SOURCE_TIMESTAMP or TIME_BASED_FILTER reader.**
  A C, C++ or Python listener with `on_data_available` (or `on_data_available_ex`) received nothing on
  such a reader, since the bridge did not override the notification. The bridge now reads the accepted
  samples itself with a NOT_READ read that does not consume them (DDS read, not take), so each sample
  reaches the callback once and stays takeable. New `hdds_reader_set_listener_notify(reader, &listener,
  on_data_available_notify)` hands the payload-less `on_data_available_notification` to C instead; with
  it the payload callbacks are not called on such a reader, and the application reads the samples
  itself. Rust listeners that do not implement `on_data_available_notification` on such a reader log one
  warning per listener type. On a reader of a GROUP-presentation Subscriber the samples can be read only
  inside `hdds_subscriber_begin_access` / `hdds_subscriber_end_access`: the bridge cannot read them
  there, so its payload callbacks get nothing, and one warning is logged per listener. Use
  `hdds_reader_set_listener_notify` and read the samples inside the brackets. The payload callback and
  an application read or take of the same NOT_READ samples compete: a sample the application reads or
  takes first is not handed to the callback.

### Removed

- **`crates/hdds/src/security/auth/` is gone.** Four files, 1170 lines - an
  X.509 validator, a challenge-response handshake and an identity-token codec -
  present since the first public release and declared by no `mod` statement in
  any commit since. The compiler never built them, their tests never ran, and
  the live authentication and handshake live in `security/authentication/` and
  `security/handshake/`. Nothing that runs is affected: default build, full
  test suite and workspace check are identical before and after. It is removed
  because it misled: two separate analyses read it as "revocation implemented
  but not wired", and the configuration docs pointed operators at a type in it
  as the way to supply a CRL

### Deprecated

Each of these still works and still compiles, with a `#[deprecated(since =
"1.5.0")]` note pointing at the replacement.

- `QoS::rti_defaults()` -- use `QoS::reliable().keep_last(10)`, the same
  profile. The values are an HDDS preset, not documented as any vendor's
  defaults. The C ABI symbol `hdds_qos_rti_defaults` and the SDK wrappers
  keep their name
- `ReadCondition::new()` and `QueryCondition::new()` -- use
  `DataReader::create_readcondition()` and `create_querycondition()`, which
  attach the condition to the reader it belongs to
- `DataReader::get_dispose_events()` -- use `take_with_info()` and read
  `instance_state`
- `AzureDiscoveryConfig::with_service_bus()` -- no replacement. It was never
  wired to anything; Table Storage is the registry
- `reliability::ENTITYID_UNKNOWN_READER` and `ENTITYID_UNKNOWN_WRITER` --
  use `ENTITYID_UNKNOWN`. RTPS 2.5 9.3.1.2 defines a single ENTITYID_UNKNOWN,
  all zero. **Their values change too**: they were `00 00 00 C7` and
  `00 00 00 C2`, which Table 9.1 reads as a built-in reader and writer with
  key 0 that no participant has, and they are now all zero, so a caller that
  keeps using them puts the specification's value on the wire.
  `GapTx::new()` starts from ENTITYID_UNKNOWN on both sides for the same
  reason
- `TopicRegistry::enable_exclusive_ownership()` and `check_ownership()` --
  no replacement. EXCLUSIVE ownership is arbitrated by each DataReader; the
  first does nothing and the second answers `true`
- `TopicRegistry::register_writer_lifespan(topic, ns)` -- use
  `register_writer_lifespan_of(topic, writer, ns)`. A sample expires by the
  lifespan of its own writer; the 1.4 form knows no writer and still records
  only the topic's smallest, which applies to samples whose writer the
  reader does not know

### Fixed

Wire-format and interoperability defects. Where a defect was found by the OMG
conformance matrix, the measurement was made on the 1.4.x ship lineage
(`hdds-1.4.6`, `1.4.7`, `1.4.8`), which is what the matrix consumes: it runs a
published release asset, never repository source. **A matrix result for this
release is a separate measurement and is not claimed here.**

Three hundred and twenty-two entries follow, counting each top-level item of this
section once (its sub-items, and the three group labels below, are not
counted). One hundred and twelve are marked *[no 1.4.x exposure]*: each describes a defect
born and fixed inside this unreleased cycle, in code that did not exist, or
was a stub with no reachable path, at the 1.4.x baseline (`8701c0b6`, or the
1.4.8 source itself for the entries checked last, or the in-cycle commit
that introduced the defect). They are listed because the work was done and
the code changed, not because you were ever affected. **An unmarked entry is
not a claim that the defect is in 1.4.x**: not every unmarked entry has been
checked against the 1.4.x source, so if you run 1.4.6, 1.4.7 or 1.4.8, read
an unmarked entry as possibly applying to you, not as certainly applying.

- **Telemetry counters were dead, double-counted or raised on one path only.** `messages_received` was raised only by the deprecated `try_take`, so it stayed at 0 for `take`, `read`, `take_batch` and every other accessor; it now counts each sample deposited in a reader's history, from any transport (intra-process, shared memory, UDP), and `try_take` no longer adds its own. `bytes_sent` had no increment site at all; it now counts the serialized payload bytes of every successful write, beside `messages_sent`. `cache_insert_errors` is raised at the writer history's own insert (a coherent-set close that swallowed its error left no trace before), a lifecycle change (dispose, unregister) whose send fails now counts a `transport_errors`, a write refused with `WouldBlock` by the writer history counts a `would_block`, a sample pushed unread out of a KEEP_LAST history is a `messages_dropped` wherever it is replaced, and every `ResourceLimit` SAMPLE_REJECTED report (coherent-set rejections and co-located readers included) now increments exactly one of `samples_rejected_ring_full` / `samples_rejected_slab_exhausted`. `messages_received` sits on its own cache line so reader threads do not bounce the line writer threads increment.
- **A pairing with no TypeObject on one side was matched whatever the two type names were.** XTypes 1.3 Sec.7.6.3.4.2 Step 2 requires the names to be equal, compared as announced, and refuses the pairing under force_type_validation. The check is now evaluated under `HDDS_TYPE_NAME_MATCH`: `warn` (the default) still matches as before but logs and counts each name pair it would refuse, `enforce` refuses the pair and reports an inconsistent topic, and `off` is the old behaviour. A side whose TypeObject a TypeLookup reply has not yet delivered keeps the old verdict, so a pairing does not flap when the reply lands.
- **A remote writer or reader announced during startup could be held back forever.** The match registry was installed after the discovery threads had started, so an announcement handled in that window was judged by no one. A writer's samples then waited for a QoS verdict that never came, and its reliable stream stalled: a peer does not repeat an announcement it saw accepted. The registry is now installed before any discovery thread starts. The QoS verdicts of the remote writers and readers already known are recorded at installation, which also delivers the samples those writers had deferred. A writer whose verdict stays missing past the discovery lease is logged once as an error, rather than stalling silently.
- **A VOLATILE reader could receive history written before its match.** A reliable writer answered the first ACKNACK of a reader whose discovery had not reached it yet, and repaired every sample it still held. A VOLATILE reader is owed none of them (DDS 1.4 2.2.3.4), so when its endpoint announcement lagged its first HEARTBEAT, which happens under load, it received samples written before the match. Such an ACKNACK is now left unanswered until the reader is paired; the reader asks again at the next HEARTBEAT.
- **A certificate that is not a CA could vouch for others.** The chain check
  took any trust-store entry whose name matched the issuer and whose signature
  verified, without asking whether that entry was a CA: a leaf certificate in
  the CA bundle could sign an identity that was then accepted. The issuer must
  now assert cA TRUE, and keyCertSign when a KeyUsage extension is present
  (RFC 5280 4.2.1.9, 4.2.1.3). An identity whose KeyUsage lacks
  digitalSignature is refused. The handshake and the X.509 plugin share one
  validator, so the rule is the same on both paths.
- **The identity private key was printed by `Debug` and never wiped.** The X.509
  authentication plugin derived `Debug` over its PEM private key, so a `{:?}` on
  the plugin wrote the key into whatever log or panic message carried it. The
  plugin now prints a placeholder. The key read from disk, and the DER copy
  made to sign, are wiped when they drop.
- **An authenticated session outlived the expiry of its peer's certificate.**
  The certificate was checked once, at the handshake, so a participant whose
  certificate had run out kept its session until restart. The handshake
  machine's periodic pass now ends a session once the peer certificate's
  notAfter has passed (RFC 5280 4.1.2.5: inclusive), reports it as a failure,
  and discovery releases that peer's keys. A re-authentication with the expired
  certificate is refused by the same check as before.

- **Every handshake leaked the peer's certificate.** Reading a certificate's
  subject name or expiry copied its DER into a buffer that was never freed,
  under a comment saying certificates were parsed once at startup. The remote
  certificate of every handshake request is read that way, so a peer that
  kept starting handshakes grew the process without bound (a few KiB each).
  The certificate is now parsed in a scope that frees the buffer.
- **An identity certificate issued through an intermediate CA was refused.**
  The path check took the issuer of a certificate from the trust store alone,
  so an identity whose path to the Identity CA goes through a subordinate CA
  could not authenticate. The path is now built from the certificate the peer
  presents and the trust store, and every link is checked: its signature, the
  validity of each certificate on the path, that each issuer is a CA, and each
  pathLenConstraint (RFC 5280 4.2.1.9, 6.1.4(l)). Revocation is checked on every
  link. DDS Security v1.1 Sec.9.3.1.3 requires an identity certificate "that
  chains up to the Identity CA".
- **An expired local identity kept its authenticated sessions and kept
  handshaking.** The identity certificate was checked when the participant
  started and never again. Once its notAfter has passed, the handshake machine
  refuses to begin or advance a handshake, ends every authenticated session, and
  records one revocation of the local identity in the audit log (DDS Security
  v1.1 Sec.8.3.2.12.2: the middleware "shall terminate any communications" with
  the participant whose identity is revoked).
- **The revocation list was read once at start-up and never again.** A
  certificate revoked after the participant started kept its session for ever.
  The list file is now re-read when its modification time changes. A list that
  lists an authenticated peer's certificate ends that session. A stale list
  replaces the one in force and refuses new handshakes, as before, but ends no
  standing session. The check of the participant's own identity follows the
  same list. A file that cannot be read, parsed or verified keeps the last good
  list, and is logged and audited once.
- **The TCP TLS private key was held in an ordinary buffer.** The builder kept
  the PEM key in a `Vec` that was not wiped when the configuration was dropped.
  It is now held in a buffer that is wiped on drop.

- **A forged AuthRequest no longer makes a participant spend a signature
  and keep a session for ever.** An AuthRequest is signed by nobody, and a
  certificate is public: replayed under prefixes whose free bits vary, each
  one cost a chain verification, a key pair and a signature, and left a
  session that, once failed, nothing removed. A request is now answered only
  for a participant discovery has seen, within a budget of 64 responder
  sessions per second over all peers (a request refused is retransmitted by
  its initiator), and a participant holds at most 4096 sessions; the failed
  session of a participant discovery no longer knows is freed, with every
  entry it held. A participant that really restarted still authenticates
  (DDS Security v1.1 Sec.9.3.2.4). *[no 1.4.x exposure]*
- **A forged authentication request no longer locks a peer out.** A
  responder kept one AuthRequestMessageToken per peer, the last received: a
  forged one under the peer's prefix replaced the peer's own, and the
  peer's Request, whose challenge1 is that announcement's future_challenge,
  was refused at every retransmission. The last four announcements of each
  peer are now kept and a Request may answer any one of them; an initiator
  likewise accepts a Reply answering the announcement its session was begun
  on or one the peer made since, so a forged announcement under a completed
  peer's prefix no longer spends its re-authentication (DDS Security v1.1
  Sec.9.3.3, Table 52). *[no 1.4.x exposure]*
- **A volatile-channel submessage sent back to its sender is dropped.** Both
  ends of a pair seal the ParticipantVolatileMessageSecure endpoints with the
  same KxKeys (DDS Security v1.1 Sec.9.5.2.1.2, Table 67), so a participant's
  own DATA, HEARTBEAT, GAP or ACKNACK, sent back to it under the peer's
  prefix, opened as the peer's: a reflected DATA marked the peer's change at
  that sequence number received, and the peer's real key tokens there were
  discarded as duplicates; a reflected ACKNACK acknowledged our own writer.
  Each participant now seals its volatile channel under SessionIds of its
  own, and a submessage under one of them is dropped and counted.
  *[no 1.4.x exposure]*
- **A comma in a certificate's common name no longer selects another
  subject's grants.** The subject of an identity certificate was printed
  without escaping and parsed again, so a common name `bob, O=Admin` read as
  the two attributes of `CN=bob,O=Admin`. The subject is now read from the
  certificate's DER RDN sequence, attribute type and value, and compared
  with the grant's `subject_name` (DDS Security v1.1 Sec.9.4.1.3), for remote
  peers, for the local identity and for the local permissions overlay alike.
  *[no 1.4.x exposure]*
- **`insecure_allow_unsigned_documents` covers this participant's own
  documents only.** A peer's unsigned permissions document was accepted
  under it, so any participant could grant itself anything by sending plain
  XML; a peer's document must now always verify against the Permissions CA
  (DDS Security v1.1 Sec.9.4.1.3). *[no 1.4.x exposure]*
- **Key installations no longer set the audit file's pace.** Every key that
  changed was one audit record and one fsync, so an authenticated peer
  announcing new keys in a loop drove the disk. At most 64 key-change
  records are now written per second; past that they are counted, and the
  count is written as one record ahead of the next one, or when the chain
  closes. *[no 1.4.x exposure]*
- **Secure discovery datagrams held for a handshake in progress are bounded
  overall.** The SEDP datagrams a participant sends while its keys change
  here are held until its handshake completes, at most 16 per participant;
  nothing bounded the number of participants, and a session that failed
  kept holding them. Both queues of held datagrams are now bounded to 256
  participants and 4 MiB each; nothing is held for a participant whose
  session failed, and what was held for one is handed back when the room is
  needed. A datagram refused at a bound is left unacknowledged, for its
  writer to send again (DDS-Security v1.1 Sec.8.8.2.2; DDSI-RTPS v2.5
  Sec.8.4.12.2) *[no 1.4.x exposure]*
- **A sample naming an unknown key moves no VOLATILE reader's join point.**
  A protected sample whose key has not arrived is dropped unacknowledged, and
  a VOLATILE reliable reader took its sequence number as where it joins the
  writer. Anyone can send such a sample under the writer's GUID: one far
  ahead of the writer made the reader drop every real sample as history from
  before its join. The reader now joins there only when the writer's first
  authenticated sample arrives at or above it, so samples that came before
  their key are still repaired and delivered (DDS-Security v1.1
  Sec.8.5.1.9.6) *[no 1.4.x exposure]*
- **A remote endpoint that announces its deletion takes its key material
  with it.** The CryptoTokens it sent stayed installed for as long as its
  participant lived, and its data still opened. They are now removed with
  the endpoint (DDS-Security v1.1 Sec.8.5.1.7) *[no 1.4.x exposure]*
- **A plain participant announcement moves no locator while its handshake
  is in progress.** The record of an authenticated participant is frozen at
  the completion of its handshake (DDS-Security v1.1 Sec.7.4.1.6), and any
  announcement under its prefix received just before could set its
  locators, leaving the participant unreachable. The locators now stay
  those of the announcement that began the handshake; after a failed
  session the next announcement is taken whole *[no 1.4.x exposure]*
- **A coherent reader created after its peers presented a GROUP set
  receives its part of it.** The readers of a Subscriber present a remote
  Publisher's coherent sets together, one generation at a time. A
  TRANSIENT_LOCAL reader the application creates after another reader of
  the same Subscriber has already presented a set receives its own part of
  that set from the writer's retained history, and no release could pair
  that part with the one already presented. 1.4.x discarded the part after
  a fixed number of release attempts. Without that bound, removed earlier in
  this cycle because a retry count proves nothing, the part held every later
  set of the Publisher behind it and the readers received nothing more. It
  is now presented whole on its own, the later sets aligned after it (DDS
  v1.4 Sec.2.2.3.4, Sec.2.2.3.6).
- **A reader matched just after a coherent set closed still receives the
  set.** A writer's end-of-set marker is a change of its history like any
  other: a reliable VOLATILE reader matched after the marker was written is
  now owed it, so the marker and the set it closes stay in the history until
  that reader acknowledges them, a NACK for it resends the marker, and the
  HEARTBEAT never advertises a first sequence number past it. Before, the
  new reader's acknowledgement floor started at the writer's last sequence
  number, the marker was discarded and the reader never delivered the set.
  While discovery knows no reader of the topic yet, the marker also takes
  the participant route the data takes, toward HDDS peers and peers that
  speak the specification's group form (RTPS 2.5 Sec.8.7.6,
  Sec.8.4.2.2.3).
- **A reliable reader acknowledges what it received before the match.** A
  remote writer's samples can reach a reader before the reader is matched
  with it, for instance when the writer's SEDP arrives before its
  participant's SPDP; the reader delivers them. Its WriterProxy, created at
  the match, did not know them, so its first ACKNACK requested again every
  change it already held. A writer that repairs a fragmented change with its
  first fragments only then left each one incomplete, and a reliable
  large-data stream stalled behind them. The proxy now starts with the
  changes the reader received from that writer (RTPS v2.5 Sec.8.4.10.4,
  Sec.8.4.12.2); what it received is dropped if the pair unmatches first.
  *[no 1.4.x exposure]*
- **A NACK_FRAG goes to the writer, not to its participant's default
  locator.** A reliable reader asks for the fragments it is missing of a
  sample at the unicast locator the writer announced in SEDP, as it already
  did for its ACKNACKs; the participant's SPDP default unicast locator is
  used only for a writer that announced none (RTPS v2.5 Sec.8.4.10.4,
  Sec.8.5.3.1). A peer that announces a default locator nobody reads and
  carries its user traffic on the endpoint's own locator never received the
  request, and a sample whose repair it answers with the first fragments only
  could never be completed: a reliable large-data stream from such a writer
  stalled behind that sample.
- **A discovery ACKNACK asks for every announcement it is missing.** When a
  remote SEDP writer's HEARTBEAT announced several publications or
  subscriptions we had not received, our ACKNACK requested only the first
  of them; each further one waited for another HEARTBEAT of that writer,
  which some implementations send every few seconds, so a remote endpoint
  could stay undiscovered for that long after its participant was known.
  The ACKNACK now lists every change still missing up to the HEARTBEAT's
  lastSN in one SequenceNumberSet (RTPS v2.5 Sec.8.4.12.2).
- **A DATA with neither payload nor key is a change, and ends the coherent
  set before it.** A writer may end its open coherent set with a DATA
  submessage that carries no serialized payload, no key and no inline QoS
  (`D=0 K=0`): a change without PID_COHERENT_SET is no member of the set
  (RTPS v2.5 Sec.8.7.6). The router dropped it as a DATA missing its
  payload: never acknowledged, so a reliable writer repaired it for as long
  as it kept it, and the set it ended stayed open until the writer's next
  set began. It is now received as a change without a sample: acknowledged,
  passed by the reader's order, never a sample, and it ends the set staged
  before it, also when it overtakes the set's first member or arrives while
  that member is still reassembled from DATA_FRAG. A repair of a member
  received already closes nothing. It is ignored when the DATA is invalid
  (an inline QoS with no PID_SENTINEL, Sec.8.3.4.1), when its writer is not
  one of the reader's or the security plugins do not admit it, and when the
  writer's payload is protected, where it carries nothing to authenticate
  (RTPS 2.5 Sec.8.7.6; DDS-Security 1.1 Sec.8.5.1.9.4). GROUP ordered
  readers capture the same arrival frame as for other DATA, and a sample-less
  repair of a provisionally retained member cannot credit or end its set
  while its ordered wait is legitimate. An admitted control accounts for its
  GSN, leaving the next writer's DATA reachable (DDS v1.4 Sec.2.2.3.6).
- **Ordered GROUP copy retirement does not recursively lock departure proofs.**
  A queued writer reannouncement cannot deadlock the reader between participant
  and writer proof checks. Each provider domain is read once, in a stable order,
  and remains guarded through retirement of the owed copies
  (DDS v1.4 Sec.2.2.3.6 and Sec.2.2.3.14). *[no 1.4.x exposure]*

- **Irregular GROUP GAP proof overflow remains repairable.**
  The bounded cache retains the lowest proofs. A RELIABLE reader does not
  credit a native GAP until its own ordered cursor has consumed that GAP's
  GSN interval, so an omitted higher proof is requested again by ACKNACK.
  HEARTBEATs retain the repair range without erasing this proof debt. This
  also works when TRANSIENT_LOCAL history keeps an older sample and its
  advertised first sequence number cannot advance
  (DDS v1.4 Sec.2.2.3.6 and Sec.2.2.3.14). *[no 1.4.x exposure]*

- **KEEP_LAST replacement releases local presentation order.**
  Evicted unread entries no longer leave order tokens blocking their surviving
  values or another DataReader of the same Subscriber (DDS v1.4 Sec.2.2.3.6).

- **Writer history departure closes future coherent replay admission.**
  Removing one writer's retained history makes future local and wire snapshots
  of the whole set ineligible. A complete snapshot already captured for one
  Subscriber remains valid; partial snapshots from different Subscribers cannot
  be combined (DDS v1.4 Sec.2.2.2.4.1.10; RTPS v2.5 Sec.8.7.5-6).

- **Ordered network waits end only on unavailable-data proof.**
  RELIABLE repair and GROUP Publisher order remain active while a writer still
  retains the missing data. Neither elapsed waiting time nor a retry count
  abandons it. A GAP, a HEARTBEAT passing the owed sequence number, writer or
  participant departure, or the waiting sample's source-time LIFESPAN expiry
  can resolve the wait. Departure proof also works without a validated roster;
  an individual writer's departure never proves an unknown Publisher roster
  gone (DDS v1.4 Sec.2.2.3.6, Sec.2.2.3.14 and Sec.2.2.3.16).

- **Durable readers do not classify their first live traffic as replay.**
  The historical obligation is frozen from announcements available when the
  reader joins. Later live observations cannot create a pre-join prefix
  (DDS v1.4 Sec.2.2.3.4 and Sec.2.2.3.6).

- **RELIABLE ordered GROUP network admission retains previously accepted data.**
  Memory pressure refuses new bytes without receipt credit, including
  concurrent duplicates of a still-provisional admission. Ordered GROUP
  suffixes remain repairable until the predecessor can be staged, so they
  cannot consume its capacity. Configured resource and staging limits still
  apply to the head unit. A complete unit already acknowledged in staging
  remains owned if its history cannot hold it whole; a resource bound is not
  absence proof. TOPIC, INSTANCE and unordered GROUP keep their existing
  whole-set resource rejection policy (DDS v1.4 Sec.2.2.3.14 and Sec.2.2.3.19).

- **Proven abandonment reports actual received or owed samples.**
  Ordered GROUP wire SAMPLE_LOST counts identified samples once, including
  RELIABLE samples, without counting controls or inventing losses from unknown
  GSN positions.
  Source-time LIFESPAN expiration retires a coherent unit whole while leaving
  actual network receipt credit independent of presentation
  (DDS v1.4 Sec.2.2.2.5.1.3, Sec.2.2.3.6 and Sec.2.2.3.16).

- **Network GAP order proofs have bounded storage without stranding sparse traces.**
  Duplicate, overlapping and adjacent intervals merge; exact arithmetic runs
  also retain alternating writer positions. Consumed proofs retire. Each
  writer/reader pair keeps at most 512 descriptors. Irregular overflow retains
  the lowest gating proofs and waits conservatively for a real HEARTBEAT or
  departure proof at uncovered positions (RTPS v2.5 Sec.8.3.7.4).

- **Ordinary topics skip GROUP receive bookkeeping.**
  Topics without GROUP ordered readers use a cached interest flag before
  parsing ordering parameters or changing route-order TLS. TOPIC and INSTANCE
  coherent writer commits skip the GROUP pending-order registry. Ordinary
  HEARTBEATs also use the cached interest flag before GROUP arrival capture,
  classification lookup and TLS. All hooks of a GROUP HEARTBEAT use one
  recipient snapshot, including when a callback registers another reader.

- **Reader teardown cannot panic coherent admission.**
  A reader closed after capacity planning releases its reservations and leaves
  surviving readers able to receive their complete projection of the coherent
  set (DDS v1.4 Sec.2.2.2.4.1.10).

- **GROUP ordered access includes ordinary changes across writers.**
  DataReaders of one Subscriber now read ordinary changes from a Publisher's
  DataWriters in Publisher GSN order inside access brackets, over both local
  and RTPS delivery (DDS v1.4 Sec.2.2.3.6). Pending local writes retain their
  position before publication; network changes retain GROUP_INFO order through
  reordering and wait for predecessor data or protocol absence proofs.
  Advancing the order also wakes a waiting condition on another reader.
  Durable network readers retain their own historical prefix when joining
  an existing Subscriber, so newer visible changes wait for owed replay.
  Writer-deletion proofs are revoked by accepted discovery and remain tied
  to the announcement captured before a queued deletion.
  A later incomplete set cannot strand an older complete set after explicit
  writer deletion, including when the later set's closing marker was lost.
  Control-only prefixes reclaim bounded order metadata using current roster
  and protocol absence proofs, without requiring a later queued DATA sample.

- **Durable replay never presents a truncated coherent set.**
  When KEEP_LAST or another history removal discards a coherent member, late
  joiners skip the entire damaged set, including other writers' surviving
  parts of a GROUP set (DDS v1.4 Sec.2.2.2.4.1.10; RTPS v2.5 Sec.8.7.5-6).
  Live staged delivery and retained bytes used for RTPS repair are preserved;
  intact older and newer sets remain eligible for replay.

- **Prepared DATA cannot enter a replacement writer's sequence state.**
  A direct DATA could be decoding when its writer was deleted and
  re-announced under the same GUID. Once the new writer's first sample
  cleared the departure, the old DATA could enter the new duplicate window
  and discard its next samples. Direct DATA now retains the writer's
  incarnation through preparation and checks it before admission, as
  discovery-held DATA already does. Removing a different writer does not
  reject the sample (RTPS 2.5 Sec.8.4.10.3, 8.4.12.1; DDS 1.4 Sec.2.2.3.14).
- **A dynamic type's `@hashid` member carries its annotation in the
  Complete TypeObject** (DDS-XTypes 1.3 Annex B,
  `AppliedBuiltinMemberAnnotations { ... @optional string hash_id; }`). The
  dynamic type bridge wrote the hashed member id but left
  `ann_builtin.hash_id` out of the member's `CompleteMemberDetail`, where
  Cyclone DDS idlc (0.11.0 and 11.0.1), OpenDDS 3.34 `opendds_idl` and
  `hdds_gen` all write the value the IDL gave: empty for a bare `@hashid`,
  `"x1"` for `@hashid("x1")`. A struct built with
  `FieldDescriptor::with_hashid_name` now builds Cyclone's Complete object
  byte for byte. A struct read from a received TypeObject also keeps its
  `@autoid(HASH)` flag (`IS_AUTOID_HASH`), so it lowers back to the object
  that was received
  - **Wire change, for dynamic types with a `@hashid` member only:** their
    Complete TypeObject and Complete EquivalenceHash, so the complete
    identifier of PID_TYPE_INFORMATION. The Minimal object, the member ids
    and every generated type are unchanged
- **ROS 2 serialized messages carry their CDR encapsulation header.**
  `rmw_take_serialized_message`, `rmw_publish_serialized_message`,
  `rmw_serialize`, `rmw_deserialize` and `rmw_get_serialized_message_size`
  treated an `rmw_serialized_message_t` as the bare CDR body. The rmw contract
  that rosbag2 and rclcpp's generic publisher and subscription rely on starts
  it with the 4-byte header `00 01 00 00` (CDR_LE, DDS-XTypes v1.3
  Sec.7.6.3.1.2), as rmw_cyclonedds and rmw_fastrtps write it. A bag recorded
  through `rmw_hdds` had no header, and a message serialized by another rmw
  was published with its header as part of the sample. The rmw layer now puts
  the header in front of a taken sample and removes it before a serialized
  publish; the sample on the wire is unchanged. A serialized message that is
  not CDR_LE (big endian, CDR2) or is shorter than the header is refused with
  `RMW_RET_INVALID_ARGUMENT`. A message with no content is the header and one
  zero byte, as rmw_cyclonedds and rmw_fastrtps write it: `rmw_serialize` and
  a take of an empty sample produce it, and a publish or a deserialize accepts
  it as well as the header alone. Four C ABI helpers carry the rule (`hdds_rmw_encapsulate_cdr`,
  `hdds_rmw_decapsulate_cdr`, `hdds_rmw_serialize_ros_message_encapsulated`,
  `hdds_rmw_deserialize_ros_message_encapsulated`).
- **`rmw_publisher_wait_for_all_acked` waits.** It returned `RMW_RET_OK` at
  once whatever was unacknowledged, so no caller above the rmw layer ever
  waited. It now waits on the publisher's
  writer (DDS v1.4 Sec.2.2.2.4.2.15) for at most `wait_timeout` and returns
  `RMW_RET_TIMEOUT` when a matched RELIABLE reader has not acknowledged in
  time, as rmw_cyclonedds does; `RMW_DURATION_INFINITE` waits without bound
  and a wait that is not a whole number of milliseconds is rounded up.
- **The rmw fast codecs no longer print to stderr.** Encoding a `std_msgs`
  string, an `rcl_interfaces` log message or a parameter event wrote a debug
  line with raw pointers to the process's stderr on every publish through
  those codecs. The codecs now publish silently.
- **Deleting a RELIABLE DataWriter waits for its last lifecycle change to be
  acknowledged.** The delete auto-unregisters the instances the writer still
  holds (DDS 1.4 Sec.2.2.2.4.1.6) and then retires the writer from SEDP.
  Nothing repaired that change afterwards: its NACK handlers and its
  HEARTBEATs go away with the writer. User data and discovery travel on
  different ports, so a reader could process the SEDP dispose first and then
  refuse the unregister of a writer it no longer knew, leaving the instances
  NOT_ALIVE_NO_WRITERS instead of NOT_ALIVE_DISPOSED, with no event and no
  retry. The delete now waits, bounded by three default heartbeat periods,
  for every matched RELIABLE reader to acknowledge the change before the
  departure is announced (RTPS 2.5 Sec.8.4.2.2.3); the acknowledgement, or the
  reader's own departure, ends the wait. The wait is owed for every lifecycle
  change the writer emitted, not only the ones the delete emits itself: an
  application's `dispose` or `unregister_instance` just before the delete is
  as unrecoverable once the writer is gone, and the auto-unregister loop
  skips an instance the application already disposed. A BEST_EFFORT writer,
  and the delete of a writer that emitted no lifecycle change at all, do not
  wait.
- **Per-sample keyed adapters preserve their protected instance identity
  through dispose, unregister and writer deletion.** The normal typed
  constructor now uses the sample's key presence when selecting a lifecycle
  KeyHash, including codecs whose static `has_key()` is false. With payload
  ENCRYPT and metadata NONE, lifecycle DATA uses the same protected digest
  as write DATA and does not expose short clear key fields. The current
  policy still decides whether a cached protected digest is used
  (DDS-Security 1.1 Sec.7.3.4; RTPS 2.5 Sec.9.6.4.8).
  *[no 1.4.x exposure]*
- **Durable GROUP replay preserves writer order across coherent sets and
  ordinary changes.** Batches keep distinct set and change identities while
  their first member's GSN determines replay order, so a later set cannot
  advance delivery past an intervening retained sample (DDS 1.4
  Sec.2.2.3.6, Sec.2.2.3.14). *[no 1.4.x exposure]*
- **Non-coherent intra-process writes use the ordinary admission path
  without carrying coherent control guards.** Writer mode is selected once;
  ordinary tickets retain their original layout and compile out grouped
  notification dispatch and optional coherent write-guard teardown. Shared
  coherent reader tracking replaces the identity slot, preserving the
  ordinary registration size. Idle clearing checks one immutable
  replay-eligibility flag before entering
  GROUP bookkeeping. *[no 1.4.x exposure]*
- **Deleting an ordered GROUP reader cannot strand surviving readers
  behind its late order registration.** A publisher racing reader teardown
  checks closure both before and after registering its member and cancels
  the exact token if teardown has already forgotten that reader. Members
  of the same coherent set remain accessible to its surviving readers
  (DDS 1.4 Sec.2.2.3.6). *[no 1.4.x exposure]*
- **Accepted local RELIABLE changes wait for reader capacity behind their
  coherent prefix.** An ordinary sample or unregister queued behind an
  earlier retained set keeps its entry until the reader makes room. Closing
  an access bracket does not discard the accepted tail after a delivery
  timeout. Retrying occurs off the reader's consumer thread, after all
  tentative reservations have been returned (DDS 1.4 Sec.2.2.3.14,
  Sec.2.2.3.18-19). *[no 1.4.x exposure]*
- **A BEST_EFFORT reader keeps the tail of a received burst when discovery
  releases it concurrently with live DATA.** A DATA arriving while another
  thread admits samples held for the writer's SEDP now joins that writer's
  active flush. It cannot advance the sequence watermark ahead of the
  received prefix and cause its remaining samples to be discarded as old.
  Live DATA starting the drain does not evict the retained prefix from
  the bounded discovery queue. A panic in application decoding or field
  extraction is propagated after the remaining received samples, including
  DATA that joined the drain, have been processed. Delivery remains ordered,
  without waiting for missing network samples
  (DDS 1.4 Sec.2.2.3.14; RTPS 2.5 Sec.8.4.12.1 T2). Deferred samples and
  their drain carry a per-writer incarnation token, invalidated on departure
  and checked at admission. Re-announcing the same GUID cannot admit an old
  extracted batch or attach the new writer's DATA to its drain
  (RTPS 2.5 Sec.8.4.10.3, 8.4.12.1 T1/T3).
- **A protected lifecycle change is not acknowledged when its payload cannot
  authenticate.** A key-only dispose or unregister whose instance cannot be
  resolved now passes the protected-payload check before its sequence can be
  credited. A missing data key or failed authentication leaves the change
  repairable, without moving instance state, on ordinary and coherent readers.
  Inline lifecycle DATA and reassembled DATA_FRAG keep the same authentication
  requirement and ordered admission (DDS-Security 1.1 Sec.8.5.1.9.4, 9.5.3.3).
  *[no 1.4.x exposure]*

- *[no 1.4.x exposure]* SDK writers retain their creation mode when dispatching typed operations:
  old constructors and older generated codecs continue using the legacy C
  ABI. Typed keyed writers accept pre-encoded bytes by recovering key metadata
  with the supplied codec before publishing (RTPS 2.5 9.6.4.8).

- All C Publisher writer constructors preserve their Publisher association,
  inherited PARTITION and group EntityId (DDS 1.4 2.2.2.4.1, RTPS 2.5 8.7.5).

- Lifecycle changes choose the KeyHash using the current endpoint security
  policy after a reload, so a cached protected digest cannot identify a plain
  instance. A newly protected key without a cached digest fails closed
  (DDS-Security 1.1 7.3.4).

- Keyed samples published through the C ABI and generated C, C++, Python and
  TypeScript codecs retain their instance identity. Additive keyed writer
  constructors announce WITH_KEY; keyed writes carry the RTPS KeyHash, and
  dispose/unregister carry the serialized KeyHolder with the writer's encoding.
  Under payload ENCRYPT, the inline KeyHash is the required MD5 of CDR
  big-endian key fields, while lifecycle key payloads are encrypted too
  (RTPS 2.5 9.4.5.3, 9.6.4.8; DDS-Security 1.1 7.3.4).
  Internal history and instance handles keep the normal KeyHash. Regenerate
  types with the current `hddsgen` and use the typed SDK operations or the
  additive keyed C ABI; existing raw-byte functions keep their previous
  behavior.
- **Local coherent delivery permits callbacks to re-enter DDS.** A listener
  released by `end_access` can read another reader or open another access
  bracket. Data listeners, observers and public WaitSet hooks run after the
  retry, producer and publication guards are released, including ordinary
  writes through a coherent Publisher (DDS 1.4 Sec.2.2.2.5.2.8).
  *[no 1.4.x exposure]*

- **Local coherent admission reserves a whole set before publishing it.**
  A capacity wait returns every reservation first, allowing two Publishers
  sharing a KEEP_ALL reader to make progress. BEST_EFFORT capacity skips
  refuse the entire Subscriber set, KEEP_LAST plans room for all incoming
  ring positions, and TOPIC/INSTANCE timeouts cannot publish a prefix.
  An unavailable Subscriber does not discard another Subscriber's complete
  set (DDS 1.4 Sec.2.2.3.6, Sec.2.2.3.14, Sec.2.2.3.18, Sec.2.2.3.19;
  RTPS 2.5 Sec.8.7.6). *[no 1.4.x exposure]*

- **GROUP durable replay keeps local sets whole at matching boundaries.**
  Replay uses the same set admission as live delivery and waits outside an
  open access bracket. Readers joining an open Publisher set receive its
  earlier members when it completes. A snapshot cannot expose a set with
  outstanding stamped writes, and a closed set at the replay/live boundary
  cannot reserve its reader room twice. A reader matched between replay
  collection and live delivery receives its older history before that live
  set, without losing it behind a newer delivery cursor
  (DDS 1.4 Sec.2.2.2.4.1.10/11,
  Sec.2.2.2.5.2.8, Sec.2.2.3.4; RTPS 2.5 Sec.8.7.6).
  *[no 1.4.x exposure]*

- **GROUP ordered access follows Publisher order across local readers.**
  Each coherent member retains its Publisher group sequence number, live
  and in durable replay. A later member on one reader waits until the
  earlier member on another reader has been read or taken; taking an
  already-read sample remains possible, and instance lifecycle information
  remains accessible through `take_with_info` (DDS 1.4 Sec.2.2.3.6,
  Sec.2.2.2.5.2.8; RTPS 2.5 Sec.8.7.5). *[no 1.4.x exposure]*

- **A writer's later local changes cannot overtake its retained coherent
  set.** Ordinary writes and unregisters, including writer deletion, keep
  their sequence position until earlier coherent publication or rejection
  finishes. Durable replay preserves that same order across coherent and
  ordinary history, and new live changes wait for older replay. Deferred
  ordinary deliveries keep their original local destinations (DDS 1.4
  Sec.2.2.3.6, Sec.2.2.3.17). *[no 1.4.x exposure]*

- **Coherent writers without local readers keep the remote-only resource
  and sequence-number behavior.** Their pending local copy owns encoded
  bytes and a 64-bit sequence, without reserving local transport slabs.
  Local entries are materialized only for the readers present at the
  publication cut, so local pool pressure and the ring's 32-bit sequence
  ceiling cannot refuse a remote-only write (RTPS 2.5 Sec.8.2.3).
  *[no 1.4.x exposure]*

- **A reader joining an open local set receives its earlier lifecycle
  changes too.** Dispose and unregister remain members when no reader
  existed at the time of the change, including VOLATILE writers with no
  history cache (DDS 1.4 Sec.2.2.3.6). *[no 1.4.x exposure]*

- **TOPIC and INSTANCE coherent Publishers do not arm a GROUP producer
  mutex for a single writer.** A logical local stream lease serializes
  ordinary delivery against a concurrent coherent close and defers
  callbacks until that lease and the write's guards are released (DDS 1.4
  Sec.2.2.3.6). *[no 1.4.x exposure]*

- **Ordinary local backpressure does not allocate a blocked-reader box.**
  Waiting for a RELIABLE reader keeps only its ring, door and activity
  state by value, without cloning coherent replay cursors or allocating
  on each failed admission attempt (DDS 1.4 Sec.2.2.3.14).
  *[no 1.4.x exposure]*

- **Durable GROUP replay raises DATA_AVAILABLE before the first access
  bracket.** Late readers with a retained coherent set wake their WaitSets
  without waiting for new traffic or calling `begin_access` first. An idle
  status clear also preserves pending replay as available work (DDS 1.4
  Sec.2.2.2.5.2.8, Sec.2.2.4.2.2). *[no 1.4.x exposure]*

- **A ReadCondition cannot leave an ordered local member untracked.**
  Its Publisher order token is registered before the ring entry is visible,
  including when a condition pumps before the publication notifications.
  A refused delivery cancels that exact token instead of leaving later
  members blocked behind it (DDS 1.4 Sec.2.2.3.6, Sec.2.2.4.5).
  *[no 1.4.x exposure]*

- **A GROUP Publisher's coherent set now reaches its local readers whole.**
  Every change of every DataWriter of one Publisher between
  `begin_coherent_changes` and `end_coherent_changes` is one set. A
  co-located reader used to be handed writer A's part the moment that writer
  closed its own part, so a reader of one topic saw its share while the
  reader of another topic still had nothing: a torn GROUP presentation. The
  Publisher now collects one part per writer of the set, a writer with no
  change of its own included, and delivers the whole set at once; nothing of
  it reaches a reader while a Subscriber access bracket is open, the
  outermost `end_access` delivers it, and a listener is told only once every
  reader's part is in place (DDS v1.4 Sec.2.2.2.4.1.10, Sec.2.2.2.5.2.8,
  Sec.2.2.3.6; RTPS v2.5 Sec.8.7.5, Sec.8.7.6). *[no 1.4.x exposure]*

- **A local coherent set too large for a reader's RESOURCE_LIMITS is
  delivered to no reader of the Subscriber.** Admission of every member of
  every part is decided before any of them is pushed, so a reader without
  room for one member receives none of the set instead of a partial group.
  Each member it will not get is reported to it as SAMPLE_REJECTED with
  RESOURCE_LIMITS, after its writer's `reliability_max_blocking_time` when
  that writer is RELIABLE -- the local counterpart of the wire leg declaring
  an incomplete set lost and adding nothing (RTPS v2.5 Sec.8.7.6
  "Incomplete coherent sets shall not be added"; DDS v1.4 Sec.2.2.3.19).
  *[no 1.4.x exposure]*

- Reliable writers now count reliable readers in the same participant in
  `wait_for_acknowledgments`. Local delivery acknowledges admission into the
  reader's history, including its delivery ring, and waits or times out while
  coherent delivery is deferred (DDS 1.4 2.2.2.4.2.15).

- `wait_for_acknowledgments` no longer loses a completion notification that
  arrives between checking acknowledgments and waiting, including when durable
  history retains the acknowledged samples. Reader arrivals and departures
  are also covered when they restore an earlier acknowledgment floor
  (DDS 1.4 2.2.2.4.2.15).

- Local publication and subscription match statuses serialize membership,
  counters and callback publication. A concurrent reader or writer departure
  can no longer be overwritten by a delayed match snapshot (DDS 1.4 2.2.4.1).
- **Secure participant departures use the standard DCPSParticipantsSecure status change.**
  Leaving participants now send DATA with PID_STATUS_INFO disposed/unregistered
  and their participant key on the secure participant writer, replacing the
  private departure payload. Discovery governance selects NONE, SIGN or
  ENCRYPT; the receiver checks the required protection and accepts either an
  inline key hash or a serialized participant key. Departures can be sent to
  every authenticated peer, independently of its vendor (DDS Security 1.1
  Sec.7.4.1.6; DDSI-RTPS 2.5 Sec.8.5.3, Sec.9.6.4.8, Sec.9.6.4.9).
- **Secure SEDP endpoint tracking is bounded per participant and retires endpoint memberships.**
  Dispose/unregister removes an endpoint's secure-topic membership immediately.
  Live memberships and sequence-order records are each capped at 1024
  identities per participant prefix, so one peer's endpoint count can never
  refuse another peer's announcements; existing entries keep progressing at
  capacity. The identities of retired endpoints are reclaimed before a new
  identity is refused, and a participant that leaves takes its records with
  it. Bounded sequence tombstones remain until participant retirement or
  reauthentication, so a stale protected announcement cannot bring a disposed
  endpoint back, and a plain announcement about one is ignored while its
  tombstone stands. Refused announcements are neither registered nor
  acknowledged as received; each refusal is counted in
  `DiscoveryMetrics::snapshot` and logged, rate limited (DDSI-RTPS 2.5
  Sec.8.4.12).
- **XTypes dependency identities now follow the containing representation.**
  Safe descriptor TypeObjects use Complete references in Complete objects and
  Minimal references in Minimal objects, retaining the reachable objects for
  TypeLookup and SEDP dependency announcements. Manually implemented DDS
  types reuse previously registered dependencies, and shared Minimal
  identities retain distinct Complete descriptions. Native generated graphs are
  converted transitively to Minimal,
  including struct bases, union discriminators and branches, aliases, and
  nested plain collections. Unresolved Complete dependencies now prevent
  conversion rather than producing a hybrid Minimal object. Collection
  headers inherit their dependencies'
  equivalence kind; only fully descriptive collections use EK_BOTH. Dynamic
  bitmask members and collection elements retain their named type identity;
  their unsigned-holder and equal-bound assignability remains available
  through dependency resolution (Sec.7.2.4.4.4 and Sec.7.2.4.4.7).
  These DDS-XTypes 1.3 Sec.7.3.4 and Annex B conformance fixes deliberately
  change affected Complete and Minimal equivalence hashes. Rebuild and restart
  communicating applications together when they rely on the old identities;
  ROS RIHS01 metadata remains unchanged.
- **GROUP coherent sets have bounded control-only state.**
  End markers and writer-set announcements use the same per-writer staging
  limit as DATA, with one extra in-order head to make progress. Refused
  RELIABLE changes stay unacknowledged and can be repaired; late or retired
  parts cannot reopen finalized sets or commit only part of a group
  (DDS 1.4 Sec.2.2.3.6; RTPS 2.5 Sec.8.7.6/9.6.4.5).

- **Retained legacy key aliases preserve ordered NO_WRITERS transitions.**
  Learning a key hash from DATA waiting on a reliable sequence gap no longer
  preregisters its instance. An earlier unregister takes effect before that
  DATA revives it, including its no-writers generation count. Sequence-aware
  alias retirement still permits newer retained DATA to identify its key
  (DDS 1.4 Sec.2.2.2.4.2.7/2.2.2.5.1.5).

- **BEST_EFFORT readers report sequence gaps as SAMPLE_LOST.**
  A newer DATA now counts the unreceived samples it permanently skips,
  including gaps observed while coherent samples are staged. The first
  sample establishes each writer's baseline; received control markers,
  filtered changes, duplicates, rejected samples, and previously reported
  losses are excluded. The shared reporter updates the status, notifies
  listeners, and wakes WaitSets (DDS 1.4 Sec.2.2.4.1; RTPS 2.5 Sec.8.4.12.1).

- **Coherent controls respect reader PARTITION compatibility.**
  Undiscovered writers cannot change a default-partition reader's GROUP
  state. Durable SEDP partition metadata still admits compatible final sets
  after discovery purges, and repeated announcements refresh cached partition
  decisions when PARTITION changes (DDS 1.4 Sec.2.2.3.13/2.2.3.6).

- **Reader generation counters and ranks include disposed instances.**
  `SampleInfo.disposed_generation_count` records each DISPOSED-to-ALIVE
  transition, stamped at receipt on data and lifecycle notifications.
  Generation ranks combine disposed and no-writers counters, and conditional
  read/take sample ranks describe the actual returned collection
  (DDS 1.4 Sec.2.2.2.5.1.5-6).
- **Generated keyed types read their own key payload back, and a keyed type
  that cannot is refused under key protection.** Every backend emitted
  `encode_key` without `key_hash_of_key_payload`, so a reader had no way to
  name the instance an encrypted dispose or unregister concerned and dropped
  every one of them in silence. Generated types now emit the inverse of
  `encode_key` (the reader framing of XTypes 1.3 7.4.3.5.3, hashed member by
  member as `compute_key` does), and endpoint creation refuses a keyed type
  that declares `keys_round_trip` false on a topic whose
  `data_protection_kind` is ENCRYPT, writer and reader alike, instead of
  accepting a topic that can never be disposed. *[no 1.4.x exposure]*

- **A secure reader delivers a plain writer's samples where the governance
  protects nothing.** A reader whose participant ran a security suite
  conflated a writer discovery had resolved without
  PID_ENDPOINT_SECURITY_INFO with a writer discovery did not hold yet: it
  answered "key unknown" to every sample, so on a topic whose
  `data_protection_kind` protects no payload, a reliable writer's repair
  looped for ever and the reader delivered nothing. The two answers are now
  kept apart: an unresolved writer still withholds the sample, a resolved
  writer that announced no payload protection is read in the clear, and it
  is dropped where the governance marks the topic payload-protected
  (DDS-Security 1.1 Sec.9.4.1.2.7, Sec.9.5.3.3). *[no 1.4.x exposure]*

- Protected user samples now follow DDS-Security 1.1 8.5.1.9.1 and
  9.5.3.3.3-4: encrypt the complete SerializedPayload with the session key
  derived from the writer's announced master key and salt, and select
  decoding from endpoint attributes. Fragmentation, reliable repair, durable
  replay and coherent staging preserve the protected representation.
  Encrypted instance keys use the mandatory MD5 KeyHash (7.3.4), and lifecycle
  payloads are authenticated before acting on an instance.

- Governance `data_protection_kind` ENCRYPT now refuses writes on
  paths without a cipher even when `enable_encryption` is false. Disabling
  the optional crypto plugin cannot override the announced payload policy
  or make ordinary and lifecycle DATA fall back to cleartext.

- **Persistence service keeps unlimited sample capacity when merging writer hints.**
  An unlimited DURABILITY_SERVICE.max_samples offer now dominates finite
  offers in either discovery order. A finite writer's retained instance
  no longer prevents another writer with an unlimited offer from storing
  a new instance (DDS 1.4 Sec.2.2.3.5/2.2.3.19).

- **Fragmented keyed samples with long topic names fit the UDP payload limit.**
  The writer reserves the first fragment's exact inline-QoS size before
  selecting one fragmentSize for the whole sample, covering both GROUP
  forms and all configured fragment sizes. Repairs reuse that recorded
  size, so large OpenDDS-dialect fragments remain deliverable
  (RTPS 2.5 Sec.8.3.8.3/9.4.5.5). *[no 1.4.x exposure]*

- **Keyed fragmented samples retain their instance identity.**
  The first DATA_FRAG now carries PID_KEY_HASH for ordinary keyed writes
  and opaque replays, including outside coherent sets. Raw KEEP_LAST readers
  retain each instance independently (RTPS 2.5 Sec.9.4.5.4/9.6.4.8).

- **Persistence replay preserves the original source timestamp and destination order.**
  Capture stores SampleInfo source time separately from reception time and
  retains the original writer's DESTINATION_ORDER offer. Local historical
  delivery keeps that same source time. Replay restores the source time and
  uses separate writers for each recorded destination-order offer, so
  BY_SOURCE_TIMESTAMP late readers match and observe the original timestamp
  (DDS 1.4 Sec.2.2.2.5.5/2.2.3.17). Legacy rows retain an unknown source time
  and reception-order offer.

- **Persistence service sample capacity refuses growth without evicting retained data.**
  DURABILITY_SERVICE.max_samples is now an atomic admission limit. A full
  topic rejects new samples and counts refusals while allowing KEEP_LAST
  replacement within an existing instance. Lowering the limit does not
  destroy retained history (DDS 1.4 Sec.2.2.3.5/2.2.3.19).

- **Local persistence capture preserves the original writer GUID.**
  The service recognizes samples already covered by a live local writer and
  replays only departed writers' data, avoiding duplicate or stale replay
  (DDS 1.4 Sec.2.2.3.4). *[no 1.4.x exposure]*
- *[no 1.4.x exposure]* **A colliding legacy FNV KeyHash no longer selects the last observed
  real instance.** Two distinct admitted instances for the same writer and
  hash make that hint permanently ambiguous until writer departure. Empty-key
  dispose and unregister messages then retain the previous raw-hash fallback,
  protecting both real instances from an arbitrary state or ownership change
  (RTPS 2.5 8.7.10, DDS 1.4 2.2.3.23.3)

- *[no 1.4.x exposure]* **Legacy KeyHash compatibility state is learned only from admitted samples
  and bounded to 4096 hashes per participant across all writers.** Reader
  history, instance, duplicate and matching refusals no longer teach the
  table. Admitted samples held above a reorder gap already teach their hash,
  so an unregister overtaking delivery still names the correct instance;
  an older unregister cannot retire a newer admitted sample's mapping.
  Excess hashes retain the previous raw-hash fallback and increment
  `TopicRegistry::legacy_key_hash_refused`. A writer's unregister retires its
  instance mapping only for a writer flagged as legacy; conformant writers
  never lock or scan the compatibility table during unregister. Writer and
  participant departures clear their mappings
  behind the DATA delivery fence. A dispose retains registration and its
  mapping (DDS 1.4 2.2.2.4.2.7, 2.2.3.19, 2.2.3.23.3)
- **Obsolete CryptoTokens cannot pin the volatile secure channel.** A source
  endpoint's SEDP dispose/unregister consumes its held tokens with a counted
  refusal. Expiry also consumes deferred DATA, including resource refusals
  with no held copy, so the reader window and writer history can advance.
  Each new endpoint match event sends fresh tokens even for unchanged keys
  and GUIDs. USER pairs also receive fresh messages after the installation
  lifetime, so discovery that catches up only at the receiver recovers;
  builtin keys retain their single announcement. Builtin keys and new USER
  announcements precede renewals, and older renewals precede newer ones,
  so repeated expiry cannot starve later keys (DDS-Security v1.1 7.4.4.2, 8.5.1.8.3; DDSI-RTPS v2.5 8.4.12.2)
  *[no 1.4.x exposure]*
- **Deferred CryptoTokens remain repairable when their hold queue is full.**
  Until their installation deadline, the volatile secure reader keeps these
  DATA changes missing in ACKNACKs so the retained history can repair them.
  Each peer can occupy at most 64 of the 256 deferred-token slots (DDS-Security v1.1 7.4.4.2,
  DDSI-RTPS v2.5 8.4.12.2) *[no 1.4.x exposure]*
- **Deferred CryptoTokens cannot outlive their authentication generation or
  replace newer installed material.** Retry validates the Kx fingerprint
  under the authentication lease, and each endpoint rejects material older
  than its latest installed message identity. Byte-identical repairs retain
  their authorization while later messages are processed; a session
  transition clears deferred copies before new tokens are consumed
  (DDS-Security v1.1 7.4.4.3, 7.4.4.6.2-3) *[no 1.4.x exposure]*
- **Deferred CryptoTokens obey their capacity and lifetime during retry.**
  Entries remain counted while their endpoint matches are checked, and an
  expired entry is discarded before testing its match. Concurrent admission
  cannot exceed either the shared or per-peer limit (DDS v1.4 2.2.3.19)
  *[no 1.4.x exposure]*
- **Directed samples survive asymmetric endpoint discovery.** A DATA naming
  a local reader can reach that reader's bounded discovery holding area even
  before the writer's SEDP publication arrives. Samples remain unacknowledged
  until admitted after the type and QoS verdict; evicted reliable samples
  remain requested and their repairs precede later retained samples. This
  prevents losing the beginning of a publish-after-match burst, including
  with RELIABLE and VOLATILE QoS. Deferred samples retain their own source
  timestamps for lifespan and SampleInfo. Publishing the writer's topic and
  OWNERSHIP metadata does not release them before discovery records the
  pair's type and QoS verdict.

- **GROUP presentation keeps native readers flowing independently of classic peers.**
  Coherent and ordered GROUP writers now allocate every change;
  an unmatched sibling writer or an unconfirmed classic participant no longer
  suppresses native readers. Classic peers use a per-reader wire sequence
  window for data, fragments and reliability controls, including inverse
  acknowledgement mapping. Native packets at shared locators carry INFO_DST,
  so their original sequence numbers cannot enter a classic reader's window.
  A late VOLATILE classic reader starts with the
  next complete writer part; existing readers retain their sequence spaces.
  Successful local-only writes advance the match watermark too, including
  VOLATILE RELIABLE and BEST_EFFORT writers. A vendor resolved after pairing
  initializes existing matches at the next complete volatile part, without
  emitting a second publication-match notification. Unknown vendors receive
  native sequence numbers and normal reliability; late classification keeps
  that origin and resumes durable replay, including for BEST_EFFORT readers.
  Rematching the same reader GUID preserves its wire origin until a
  two-minute control quiet period expires. Later packet reinjection requires
  a fresh GUID because UDP controls carry no pairing epoch. Fragment controls
  for other writers neither renew that quiet period nor count as refusals.
  ACKNACK and NACK_FRAG validate committed bounds before dispatch, and
  acknowledgment updates reject replaced pairing generations. Refused
  controls are counted in reliability telemetry. Native unicast packets gain
  INFO_DST only while a classic reader of that writer shares their locator;
  already addressed fragment heartbeats retain their original bytes.

- **C writer timestamp and instance operations contain Rust panics.** Payload
  construction and writer calls now return `HddsOperationFailed` on an
  unwinding panic instead of aborting the process at the C ABI boundary.
  Instance-registration output handles are written only on success
  *[no 1.4.x exposure]*
- **Recover secure discovery when the pre-token queue overflows.**
  The bounded queue retains a repair obligation instead of acknowledging dropped
  ciphertext. Once tokens arrive, the reader NACKs both secure SEDP writers;
  requests retry until the reader synchronizes. The control path serves secure
  builtin writer ids from retained discovery history (DDS-Security v1.1
  7.4.1.7-8; DDSI-RTPS v2.5 8.4.2.2-3) *[no 1.4.x exposure]*
- **Unknown secure discovery key ids cannot block valid traffic.**
  Known-key secure SEDP is decoded independently of the pre-token queue.
  Unknown ids wait only while an authenticated peer still owes builtin writer
  tokens; after token installation they are dropped with a diagnostic counter.
  The queue remains bounded per peer, and authenticated sequence checks prevent
  a delayed announcement from undoing a newer dispose (DDS-Security v1.1
  8.5.1.9.6, 8.8.9.2) *[no 1.4.x exposure]*
- **Remove the unreachable HDDS 1.4.x secure discovery format.**
  The current PKI-DH handshake refuses pre-1.5 class ids before authentication
  (DDS-Security v1.1 9.3.2.5.1-3, Tables 49-51), so a 1.4.x secure peer never
  reaches SEDP. The legacy shared-secret key derivation, payload-only codec and
  capability-based selection are removed. Every authenticated peer uses secure
  builtin writer key material and the discovery protection kind
  (8.8.8.3, 8.8.9.2, 9.4.1.2.5.4). Clearing a capability in SPDP or signed
  c.pdata cannot select weaker protection. This adds no interoperability break:
  1.4.x secure peers already require an upgrade for the handshake. The public
  legacy SEDP codec helpers and metatraffic-key accessors are removed
  *[no 1.4.x exposure]*
- **The handshake initiator announces its own AuthRequestMessageToken.**
  When no remote AuthRequestMessageToken has been received for the attempt,
  starting a handshake sends the local token (class id
  `DDS:Auth:PKI-DH:1.0+AuthReq`) and uses its future_challenge as challenge1.
  The announcement comes from the committed Request even at cache capacity.
  A received remote token instead suppresses the local announcement and binds
  the Reply's challenge2, including when it arrives before SPDP. Retries keep
  the same Request; a restarted attempt uses a fresh challenge. Received
  announcements and their waiting state share one deadline, including when
  SPDP arrives later. Expiring an older exchange preserves a newer pending
  announcement. Rejected Requests do not reserve their nonces in the replay
  window.
  Before completing authentication, a responder refuses a Request whose
  challenge1 differs from its pending announcement (DDS-Security v1.1
  9.3.2.5.1, 9.3.3 Table 52,
  `validate_remote_identity`, `begin_handshake_request`, `begin_handshake_reply`,
  `process_handshake`) *[no 1.4.x exposure]*
- **Clear secure discovery DATA keeps its inline QoS outside the payload.**
  With discovery protection NONE, the classifier and decoder now agree on the
  serialized payload after the inline-QoS sentinel, for HDDS as for every vendor.
  A secure dispose or unregister is no longer read at the start of its QoS list
  (DDSI-RTPS v2.5 9.4.5.3; DDS-Security v1.1 9.4.1.2.5.4)
  *[no 1.4.x exposure]*
- **Retire secure writer keys at replacement, reauthentication and departure.**
  Installing new DatawriterCryptoTokens removes the writer's previous key ids
  without a grace interval. A completed replacement handshake clears remote
  writer material and pending ciphertext before endpoint sequence state resets.
  Secure builtin writers mint a fresh local generation, and a token sweep cannot
  reinstall the generation retired by authentication. Discovery departure
  releases the participant's remote writer material
  (DDS-Security v1.1 8.8.9.2, 8.5.1.7.7-8). Captured old secure DATA cannot
  recreate an endpoint after fresh tokens arrive *[no 1.4.x exposure]*
- **Secure discovery uses the sending builtin writer's exchanged key material.**
  Each secure publications, subscriptions and participant writer mints its own
  key and salt and announces them as DatawriterCryptoTokens over the volatile
  channel (DDS-Security v1.1 8.8.8.3, 8.8.9.2, Tables 70-71). Outgoing SEDP
  and the HDDS sealed participant departure use that writer's material;
  incoming submessages use the sender's writer GUID and the CryptoHeader key
  id. A secure announcement received before its writer's tokens is held and
  replayed in order when they arrive. ParticipantCryptoTokens protect whole
  RTPS messages (8.8.9.1), not secure SEDP. No shared-secret SEDP derivation
  or pre-1.5 secure wire format remains
- **Writer and participant CryptoTokens preserve the sender's random salt.**
  New key material includes an independent random master_salt, carried in the
  token and used with master_sender_key to derive session keys (DDS-Security
  v1.1 9.5.2.1.1, 9.5.3.3.3). Substituting a locally chosen salt prevented
  decoding material announced by a peer that supplied a different one
- **Discovery origin authentication is refused at governance load.**
  SIGN_WITH_ORIGIN_AUTHENTICATION and ENCRYPT_WITH_ORIGIN_AUTHENTICATION
  require a receiver-specific key for each matched reader (DDS-Security v1.1
  Table 70). Secure discovery currently distributes one common material per
  writer; accepting either setting claimed a protection it did not apply.
  The load error identifies the unsupported setting and recommends SIGN or
  ENCRYPT

- **An ACKNACK whose writerId is ENTITYID_UNKNOWN is now refused instead of
  claimed by every writer of the participant.** RTPS v2.5 8.3.8.1 gives
  writerId no ENTITYID_UNKNOWN broadcast form (unlike readerId on a
  HEARTBEAT or GAP, 8.3.7.5 / 8.3.8.4): Table 8.40 lists no such case, and a
  sweep of 1,387,238 real ACKNACKs captured across every vendor in the OMG interoperability test suite
  found none carrying it. Every writer of the participant repairing on an
  unnamed ACKNACK multiplied spurious repair rounds *[no 1.4.x exposure]*
- **The DurabilityService cleanup timer now applies all three of DDS 1.4
  2.2.3.5's own conditions, and never to TRANSIENT_LOCAL.**
  `service_cleanup_delay` scopes to the TRANSIENT/PERSISTENT persistence
  service alone; TRANSIENT_LOCAL's history serves late joiners directly
  from the writer, bounded by HISTORY/RESOURCE_LIMITS alone (2.2.3.4).
  Setting the delay on a TRANSIENT_LOCAL writer spawned the cleanup timer
  anyway, and for every durability kind the timer removed every
  acknowledged change on a plain delay with none of the spec's three
  conditions (explicitly disposed, no live writer still claiming it, the
  delay elapsed since both) checked: a late joiner matching after every
  current reader had acknowledged everything got an empty history
  instead of its KEEP_LAST depth, for ANY durable writer with the delay
  set, not only TRANSIENT_LOCAL. TRANSIENT_LOCAL is now exempt outright;
  TRANSIENT and PERSISTENT now check all three conditions per instance,
  tracked incrementally as its changes are written rather than read
  off its single latest one -- `dispose()` then a LATER, separate
  `unregister_instance()` (the `manual_dispose` policy, which keeps the
  DDS default's two bits from landing in one wire change) is seen the
  same as the one combined change the default autodispose lifecycle
  sends, and a write after either revives the instance, resetting the
  rule -- before removing anything of it
  *[no 1.4.x exposure]*

- **The vendor-specific 0x80 submessage that follows a SEDP HEARTBEAT goes
  to vendor 0x0101 peers only.** HDDS appended it, under its own vendor id,
  to the HEARTBEAT answering every peer's SEDP ACKNACK; its only recorded
  need is interop with that vendor. Every other peer now receives INFO_DST +
  HEARTBEAT, which a conforming receiver was already reducing it to (RTPS
  2.5 Sec.8.3.4.1)
- **A vendor 0x0101 SEDP that carries no QoS PID gets the DDS 1.4 defaults**,
  as every other vendor's does, instead of RELIABLE/KEEP_LAST(10)
- **The dialect SPDP builders announce the real domain.** The RTI dialect
  wrote 0 into PID_DOMAIN_ID and its vendor-range domain parameter whatever
  the domain, and announced PID_PROTOCOL_VERSION 2.6 while every HDDS
  header says 2.4. Neither builder is on the live discovery path, which
  already announced the real domain and 2.4
- **An SDK writer of a generated type labels its samples with the type's
  extensibility, without being told.** A C++, Python or TypeScript writer,
  or a C writer created the usual way, labelled every sample `CDR2_LE`
  (0x0007), whatever its type: the body of an APPENDABLE type (the
  `hdds_gen` default since 1.3, or `@appendable`) starts with a DHEADER and
  must be `D_CDR2_LE` (0x0009), that of a MUTABLE type `PL_CDR2_LE` (0x000b)
  (DDS-XTypes 1.3 7.6.3.1.2, Table 60). HDDS readers decode by type and did
  not notice; a foreign reader that frames by identifier refuses or
  misreads such a sample. The types `hdds_gen` 2.0 generates now say their
  extensibility, and the SDK writers read it: C++ `create_writer<T>()`
  (Participant and Publisher) from `T::hdds_extensibility`, detected at
  compile time; Python `create_writer(..., msg_type=Cls)` (Participant and
  Publisher) from `Cls.HDDS_EXTENSIBILITY`; TypeScript
  `createWriter(topic, qos, typeName, extensibility<Name>)` with the
  constant the generated module exports (an unknown string is now refused
  with `HddsError` instead of reaching the C ABI as `undefined`); C
  `hdds_writer_create_with_extensibility(participant, topic, NULL, qos,
  <name>_extensibility())`. New: `hdds_publisher_create_writer_with_extensibility`,
  C++ `Publisher::create_writer_raw(topic, [qos,] Extensibility)` and
  `Participant::create_writer_raw(topic, Extensibility)`. A type generated
  by an older `hdds_gen` says nothing and keeps the earlier writer (every
  sample `CDR2_LE`); an explicit `extensibility` (Python, TypeScript) still
  wins
- **The default path of three SDK writers still labelled FINAL.** The entry
  above fixed the explicit path; a writer created the plain way kept
  mislabelling every sample of an APPENDABLE or MUTABLE type `CDR2_LE`
  regardless. Now automatic: Python `create_writer(topic, Cls)` reads
  `Cls.HDDS_EXTENSIBILITY` with `Cls` positional (the natural call, not
  `msg_type=Cls`); a writer created without it, then handed a non-FINAL
  typed instance in `write_typed()`, warns once instead of staying silent.
  TypeScript `createWriter(topic, qos, typeName, Module)` reads
  `Module[\`extensibility${typeName}\`]` from the generated module itself
  the same way `createReader`'s `codec` argument is read (a bare
  `extensibility<Name>` string still wins, as before). C: `hdds_gen` now
  also emits `<name>_create_writer(participant, topic_name, qos)` and
  `<name>_create_writer_from_publisher(publisher, topic_name, qos)`, each
  calling `hdds_writer_create_with_extensibility` /
  `hdds_publisher_create_writer_with_extensibility` with
  `<name>_extensibility()` so the natural call needs no extensibility
  argument at all; the old `hdds_writer_create*` functions are unchanged
  (still FINAL by default, as documented) *[no 1.4.x exposure]*
- **An HDDS 1.4.x reader is no longer sent PID_TYPE_OBJECT.** A 1.4.x reader
  compares a TypeObject whose string member is the TI_STRING8_SMALL that
  DDS-XTypes 1.3 7.3.4.4 requires with the bare TK_STRING8 (0x20) of its
  own type as two incompatible TypeIdentifiers: it pairs with the writer,
  reports nothing and drops every sample. Whether an SEDP announcement
  carries PID_TYPE_OBJECT is now decided per peer from what its SPDP
  announced: only to HDDS announcing the new `CAP_TYPE_OBJECT_SPEC_STRINGS`
  bit (bit 1) of PID_HDDS_CAPABILITIES, which this release sets and 1.4.x,
  announcing no capabilities, does not. A 1.4.x peer still receives
  PID_TYPE_INFORMATION, and matches. Foreign vendors are withheld
  PID_TYPE_OBJECT as before. An SEDP ACKNACK from a participant discovery
  does not know is no longer answered (RTPS v2.5 Sec.8.4.7, Sec.8.5.3): its
  SPDP sends it the announcements
- **The shapes demo announces its ShapeType's TypeObject.** `color` was
  announced as the bare TypeKind TK_STRING8 (0x20), which HDDS's own decoder
  refuses, so no ShapeType announcement carried PID_TYPE_OBJECT or
  PID_TYPE_INFORMATION and every run logged `TypeObject decode failed`. It
  is now the specification's TypeObject for the OMG IDL (`@key string<128>
  color`, TRY_CONSTRUCT1 on every member, IS_MUST_UNDERSTAND on the key)

- **A RELIABLE reader no longer acknowledges a sample it could not keep.**
  The reader stored a sample for the application after it had credited it
  to its writer proxy, so a sample refused at that point was acknowledged
  and never sent again: lost for good, although DDS 1.4 2.2.3.19 (footnote
  28) has a reliable service discard a sample at the reader only "so that
  the sample can be re-sent at a later time". A sample the reorder gate
  passes straight on now takes the storage it needs before its
  acknowledgement, at the one admission step that already took a KEEP_ALL
  reader's history place, and a sample that finds none is refused
  unacknowledged and reported as SAMPLE_REJECTED (REJECTED_BY_SAMPLES_LIMIT);
  the writer repairs it once there is room. A BEST_EFFORT reader drops it and
  reports it, as before. A panic while preparing a sample (decoder, field
  extractor) no longer escapes before its acknowledgement: the sample is
  received and delivers nothing, so its resends cannot stop the writer's
  stream at that sequence
  - Process-wide slab pool exhausted (the pool is shared by every reader of
    the process, so a busy neighbour could cause it): with the old order
    put back, a reliable reader that received 20 samples while the pool was
    full took none of them, ever, once it had room again; it now takes all
    20, once each, in order. Counted as `samples_rejected_slab_exhausted`
  - Network ring of a KEEP_LAST reader full (1023 samples not yet taken): the
    newest samples were acknowledged and dropped. With the old unbounded ring
    put back, a KEEP_LAST(1) reader that fell behind a writer of 1500 samples
    kept value 1023 for good. Its network ring is now bounded by a room like
    a KEEP_ALL reader's, whose places it gives back as samples leave the ring
    (its cache keeps the newest per instance rather than refuse them); it now
    ends on value 1500. While its application does not take, such a
    reader now holds a RELIABLE writer back (the writer repairs what it
    refused) where it used to drop the newest samples after acknowledging
    them
  - A VOLATILE reader joins its writer at the first sample it receives,
    refused or not. It joined at the first sample it stored, so when room
    came back in the middle of a repair (samples 1 to 4 refused, 5 stored)
    it delivered 5 and up ahead of 1 to 4, then took their resends for
    history from before its join and dropped them, acknowledged: lost for
    good. Seen in the end-to-end test above in 6 runs of 25 before this fix,
    none of 30 after it; the samples above a refused one now wait for it.
    The same for every other sample dropped unacknowledged for its writer to
    send again: one whose DDS-Security data key had not arrived yet, one
    evicted while its writer's OWNERSHIP was still unknown, and a coherent
    set member refused at staging (whose repaired set was discarded whole)
  - Not covered, each still a loss reported as SAMPLE_REJECTED: a sample the
    reorder gate held (out of order, or before the writer's first HEARTBEAT
    on a durable reader), which is acknowledged on arrival and takes its
    storage, and a KEEP_LAST reader's ring place, only when released, so
    that what the gate holds never takes the room the awaited sample needs;
    and a sample of a coherent set that a coherent-access reader staged,
    acknowledged when staged and stored when the set is committed
- **`HDDS_INTERFACE` now also confines the user-data multicast join.** The
  SPDP/SEDP sockets joined their groups on the forced interface only, but the
  user-data multicast socket joined on every interface auto-detection found,
  so a participant told to use one interface still listened for multicast
  user data on all the others
- **Interface auto-detection no longer ignores every address in
  172.16.0.0/12.** A "Docker bridge" rule skipped that whole range, which is
  also an RFC 1918 range real LANs use (172.20.x.x is common in corporate
  networks) and the range Docker gives the `eth0` inside a container: such a
  host joined multicast nowhere it could be reached and, unless the routing
  probe happened to pick its address, announced no usable one. The rule is now
  by device name: `docker0`, `br-<12 hex digits>` (Docker user-defined
  networks), `veth*`, `podman<N>`, `cni-podman<N>`, and on Windows the WSL /
  Hyper-V NAT switches (`vEthernet (WSL...)`, `(Default Switch)`, `(nat)`,
  `(DockerNAT)`). A Linux bridge is not skipped for being a bridge: a
  hypervisor's LAN address commonly lives on one. An allowlist
  (`HDDS_INTERFACE_ALLOW`) that names a container bridge now gets it, where
  the old rule ran before the allowlist and overrode it; `HDDS_INTERFACE`
  still overrides everything. The address range that used to catch Cloudflare
  WARP (`172.16.0.2/32`) is no longer needed for the primary-address choice
  on Linux and macOS, which reject it as a point-to-point interface; like
  other point-to-point tunnels it is now in the multicast join list, as
  WireGuard and OpenVPN interfaces already were. On Windows the interface
  list carries no point-to-point flag, so a VPN that is the default route can
  now be picked as the primary address: set `HDDS_INTERFACE` there
- **A sample whose encode fails no longer leaves a hole in the writer's
  sequence numbers.** `DataWriter::write` takes the sample's sequence number
  before it encodes it, and an encode failure (or, on the intra-process path,
  a full slab pool) returned the error without giving the number back. The
  next sample then skipped a number nothing would ever send, and a RELIABLE
  reader waits on such a hole. The number is now given back on those paths,
  as it already was when DDS-Security refused the sample
- **Dropping a participant while it answered an SPDP announcement could
  hang both for good** *[no 1.4.x exposure]*. An SPDP handler holds the
  read side of the participant's "departed" lock while it may answer, and
  `depart` (run by the drop) takes the write side to wait for those
  handlers. The handler then asked "have we departed?" through a second
  read of the same lock, which queues behind the waiting writer: handler
  and drop waited on each other. Seen as a hang of
  `tests/rtps_port_mapping.rs` (five participant-lifecycle tests past 60 s,
  stack taken). The question is now answered by a flag set inside
  `depart`'s write section, read without the lock; the handlers still hold
  the read side, so `depart` still waits for them
- **The four TypeLookup endpoints are reliable, and a TypeLookup reader is
  never left waiting on a number it will not get.** The request writer
  (0x000300C3) and the reply writer (0x000301C3) drew from one counter, so
  once this participant sent getTypes requests of its own, its first reply
  carried sequence number 2 with nothing announcing 1, and a RELIABLE reply
  reader (DDS-XTypes 1.3 7.6.3.3.3: RELIABLE, KEEP_ALL) waited for 1 for good.
  RTPS 2.5 8.3.5.4 ("Sequence numbers begin at 1") and 8.3.8.2 writerSN
  ("Each RTPS Writer maintains is own sequence number"). Neither writer sent a
  HEARTBEAT, and neither reader answered one. Now:
  - one sequence-number space per writer, a number taken only when the
    datagram exists (a de-duplicated, unaddressable or unbuildable request or
    reply takes none)
  - every sample goes to one participant, so the numbers a writer used for
    other participants are irrelevant to this one: each DATA is preceded by
    a GAP (RTPS 2.5 8.3.8.4) for the numbers since the last one this
    participant was sent. A number sent with no destination (HTLK) is never
    GAPped
  - each writer keeps the samples a participant has not acknowledged (up to
    16 per participant, for up to 256 participants) and HEARTBEATs them every
    second (8.4.2.2.3); an ACKNACK is answered with a repair of every held
    sample it names, a GAP for every number never sent to that participant,
    and a HEARTBEAT whose firstSN says what is no longer held. Only a
    participant discovery knows is answered, at the locator it announced,
    once per ACKNACK count, at most once per 5 ms
  - our request and reply readers answer a peer TypeLookup writer's
    HEARTBEAT with an ACKNACK naming what they miss, honour its GAPs, and do
    not process a sample twice
- **A peer's type learned by getTypes is judged only once the types it
  references are known, and a COMPLETE reference and a MINIMAL reference to
  the same type are assignable.** A peer's COMPLETE TypeObject names its
  member types by COMPLETE hash (DDS-XTypes 1.3 7.3.4.5); a local TypeObject
  names them by MINIMAL hash. The type verdict compared the two identifiers
  as values, found them of different kinds and refused, and it judged the
  pairing as soon as the root type arrived, before any member type it
  references was known. The refusal was final, and whether data flowed first
  depended on timing. Now:
  - a getTypes reply for an endpoint's type is held until every type it
    references is known, and each missing COMPLETE reference is requested
    from the peer that served the root; the endpoint's type stays unknown
    meanwhile, so the verdict is pending (7.6.3.4.2 Step 2). A periodic tick
    bounds the wait at 15 s (then the type is judged on what is known),
    retries an endpoint's unanswered request up to 5 times, and forgets the
    participants discovery no longer knows
  - an EK_COMPLETE identifier and an EK_MINIMAL identifier are resolved each
    by its own kind and the types compared (7.6.3.4.2 Step 1 compares
    types), under the same nested FINAL-struct rule as two identifiers of
    one kind, and only under ALLOW_TYPE_COERCION
  - peers' types learned by getTypes resolve hash references at match time
    (a local type wins under a shared hash) and never stand in for a local
    type by name. Both stores of them are bounded at 1024 by
    least-recently-used eviction and cleaned of what a departed participant
    alone served: a full store never refuses a type, and never loses a type
    an endpoint waits for
- **The TypeObject serializer is exact against DDS-XTypes 1.3 Annex B.**
  Measured against a foreign oracle, Cyclone DDS 0.11 idlc: every one of the
  130 Complete and Minimal TypeObjects it emits for a 65-type corpus now
  decodes and re-encodes byte for byte with the same EquivalenceHash (104 of
  130 did); annotation records are checked against Fast DDS 3.4's own
  serializer. Six layouts were wrong: a struct's `base_type` was written as an
  @optional (a presence octet in front of the identifier); builtin member
  annotations had no DHEADER and dropped `min` / `max`; `CompleteAliasBody`
  carried a type detail instead of two annotation fields; enum and bitmask
  flags were constants; applied annotations and their sequences had no
  DHEADER; `@verbatim` was one string instead of three
  - **No TypeObject, hash or PID that HDDS announces changes.** Nothing HDDS
    builds uses the six layouts; measured byte-identical before and after for
    `shape_main` and sixteen dynamic types, across every PID and getTypes
    reply. The `shape_main` ShapeType kept its 1.4.x form there: the
    specification's form (built field by field from Annex B in the tests) was
    in the code behind `SHAPE_TYPE_OBJECT_SPEC_EXACT`, off, pending
    validation. The release announces that form (see above), and the 1.4.x
    form, whose `@key color` carried the inert bare `TK_STRING8`, is removed
    from the tree rather than left behind the switch
  - **TypeLookup replies from other vendors for `@final` enums, bitmasks,
    derived structs and annotated members are now accepted.** A reply is
    re-hashed on receipt and dropped when its object does not hash to the
    requested identifier; HDDS re-encoded those objects differently, so all
    26 such Cyclone objects of the corpus were silently refused
- **Every annotation parameter value of DDS-XTypes 1.3 Annex B is decoded.**
  `AnnotationParameterValue` modelled 4 of its cases (boolean, int32,
  string8, enum); a TypeObject carrying any other was refused whole. Cyclone
  DDS 0.11 idlc writes `@max(4000000000) unsigned long` as a uint32 and any
  floating point `@min` / `@max` / `@range` as a float64, so such a type
  could not be resolved by TypeLookup. The enum now has a variant per case
  (byte, int8, uint8, int16, uint16, uint32, int64, uint64, float32, float64
  and float128 as bit patterns, char8, char16, string16) and `Extended` for
  the `default` case; checked against Fast DDS 3.4's serializer case by case
  and Cyclone's object byte for byte. Two places where Fast DDS departs from
  the specification follow the specification: a string16 length counts
  octets (7.4.1.1.2), and a float128 is IEEE 754 binary128
  - API: `AnnotationParameterValue` gained variants; an exhaustive `match`
    on it needs the new arms
  - No TypeObject HDDS announces changes: the four existing cases encode as
    before
- **Bitset TypeObjects follow DDS-XTypes 1.3 Annex B.** The bitset headers
  carried a `base_type` 1.3 does not declare (an extra octet), and the
  bitfield sequences, of `@appendable` elements, had no DHEADER. A Fast DDS
  3.4 bitset object now decodes and re-encodes byte for byte; before, it did
  not decode
  - API: `CompleteBitsetHeader` and `MinimalBitsetHeader` lose `base_type`
  - No TypeObject HDDS announces changes: HDDS builds no bitset object
- **Annotation TypeObjects follow DDS-XTypes 1.3 Annex B.** Six layout
  departures: no `annotation_flag`; the Complete header was a type detail
  where Annex B has the annotation's name alone; the parameter sequence, of
  `@appendable` elements, had no DHEADER; `default_value` was written as an
  @optional where it is mandatory; the Minimal `name_hash` (four octets) was
  aligned like an integer; and the Complete parameters were ordered by name
  hash where Annex B orders them by name (the Minimal ones are ordered by
  their name hash octets). Fast DDS 3.4's annotation objects now decode and
  re-encode byte for byte; before, they did not decode
  - API: `CompleteAnnotationType` and `MinimalAnnotationType` gain
    `annotation_flag` (new `AnnotationTypeFlag`); `CompleteAnnotationHeader`
    holds `annotation_name` instead of `detail`; the parameters'
    `default_value` is no longer an `Option`
  - No TypeObject HDDS announces changes: HDDS builds no annotation object
- **Sequence, map and Complete array TypeObjects follow DDS-XTypes 1.3
  Annex B.** The objects had no `collection_flag`; a Complete collection
  header wrote its type detail as mandatory where it is @optional; a
  Complete collection element had no element detail (its annotations); and
  a Complete array carried a collection header with a bound plus a trailing
  bound sequence where Annex B has an array header holding the dimensions.
  Fast DDS 3.4's Complete sequence, map and array objects now decode and
  re-encode byte for byte; before, they did not decode
  - The Minimal array object keeps its previous layout, which is not Annex
    B's: the ROS 2 type builder hashes it into the identifiers it announces
    for any message with a fixed-size array, so it moves with that builder's
    own fix (plain collection identifiers). A test pins those identifiers
  - API: the sequence, map and Complete array types gain `collection_flag`
    (new `CollectionTypeFlag`); `CompleteArrayType` holds a
    `CompleteArrayHeader { bound_seq, detail }`; `CompleteCollectionHeader`
    has `detail: Option<CompleteTypeDetail>`; `CompleteCollectionElement`
    has `detail: CompleteElementDetail`
  - No TypeObject HDDS announces changes: the Minimal sequence and map
    encode as before (a zero flag falls where alignment padding was), and
    HDDS builds no Complete collection object
- **A build without the `security` feature reported success for security
  operations it could not perform.** `pub mod security;` is unconditional
  while the feature is not, so a default `cargo build` compiled fail-OPEN
  bodies: `validate_certificate_chain` returned `Ok(())` for any bytes,
  `verify_signature` returned `Ok(true)` for any non-empty buffer, `sign_data`
  returned the input concatenated with the private key, `get_expiration_time`
  reported the year 2100, and `derive_guid_from_certificate` returned a ZERO
  GUID - which is also a correctness defect, since every participant on such
  a build then derives the same GUID. Observed, not inferred: a separate
  program using only the published API printed
  `GUID(00.00.00.00.00.00.00.00.00.00.00.00.00.00.00.00)`; the same program
  now fails with an error naming the feature
  - Ten such bodies now return `Err` naming the missing feature, in
    `authentication/x509/{crypto,cert}.rs` and `handshake/machine.rs`.
    `generate_challenge` already did, which is what kept the private key out
    of `begin_handshake`
  - Building a participant was never affected: the security suite is
    constructed under `#[cfg(feature = "security")]`. What was affected is any
    caller of the public `X509AuthenticationPlugin`
  - Gating the module itself (`#[cfg(feature = "security")] pub mod security;`)
    is the state with nothing to get wrong, and it removes public items: that
    is a 2.0 change, recorded as such
- **`hdds_security_config_check_revocation(cfg, true)` was unsatisfiable from
  C.** The Rust builder now refuses the flag without a list, and the C API had
  no way to supply one. `hdds_security_config_set_crl(cfg, path)` is added -
  a PEM bundle of CRLs or a single DER CRL, mirroring the Rust
  `certificate_revocation_list`
- **DDS-Security tokens were unreadable by any conformant peer, and the
  PermissionsToken PID was wrong.** Two wire defects in the same codec, both
  present since `4b6cf73e` (2026-05-28), both invisible to HDDS<->HDDS
  because both sides were wrong the same way:
  - The `DataHolder` codec wrote a 4-byte CDR boolean after every property
    and expected one back. DDS Security v1.1 Section 7.2.1.1 and Section 7.2.2.1 declare
    `propagate` non-serialized and Section 7.4.1.4 says the serialization shall omit
    it: it is a local instruction about whether to SEND a property, not a
    field. Four extra octets per property put every IdentityToken,
    PermissionsToken, PKI-DH handshake token and volatile key holder out of
    reach of conformant implementations, in both directions. The flag now
    does what it means - a property with `propagate = false` is omitted - and
    the golden vector is locked against bytes produced by **Fast-CDR 2.2.5**,
    a foreign toolchain, instead of by our own encoder
  - `PID_PERMISSIONS_TOKEN` was `0x1007`; DDS Security v1.1 Table 10 assigns
    `0x1002` (`tshark -G values` agrees). `0x1007` carries neither the vendor
    bit nor the incompatible bit, so a conformant peer dropped HDDS's
    PermissionsToken in silence while its own landed in our wildcard arm
  - **Breaking on the secure path:** a 1.5.0 participant with
    `--features security` does not exchange tokens with a 1.4.x one. The
    secure path is HDDS<->HDDS by design, so this is a same-version
    requirement, not a cross-vendor regression - and it is what makes
    cross-vendor secure discovery possible for the first time
- **A `DataHolder` length word could slice backwards on a 32-bit build.**
  `offset + len` was unchecked on both readers with both terms wire-supplied;
  a 0xFFFFFFFF length wrapped the bound test and panicked the SPDP receive
  thread. Checked now. Latent: every gated target is 64-bit
- **The `binary_properties` count cap had no test**, on either side of its
  boundary. `Vec::with_capacity` of `u32::MAX` 56-byte tuples is a 223 GiB
  request - below `isize::MAX`, so a real allocation that aborts on a 16-64
  GiB host and merely succeeds lazily on a 314 GiB one, which is a green test
  on the dev box and a dead process in the field. Both caps are now pinned at
  64, 65 and `u32::MAX`
- **A reload of the local permissions overlay that revoked a topic did not
  reach an already-admitted remote endpoint, and a partition-scoped overlay
  rule was never applied to a remote endpoint at all.** `check_create_datawriter`
  / `check_create_datareader` were re-checked against the new content, but a
  writer already matched kept sending data, HEARTBEATs and repairs to a
  revoked reader, and a reader kept accepting a revoked writer's data
  (DDS-Security 1.1 Sec.8.4.2.9: `check_remote_datawriter` /
  `check_remote_datareader` must reflect the CURRENT permissions). Separately,
  the overlay was probed against the default partition only, so a rule like
  "deny publish on topic X in partition Classified" never refused a remote
  reader that actually announced partition `Classified`. The overlay's
  reload now moves the same generation counter the signed-document admission
  gate already used to invalidate its cache, and a rule scoped to a
  partition defers the verdict to the endpoint's own announced partitions
  (re-judged on a later SEDP update too) instead of the default one alone --
  still O(1) per packet, keyed per endpoint and epoch
- **A permissions document's `<relay>` action was parsed and validated, then
  silently discarded: never enforced, but also never applied to a grant it
  shared a document with.** Per DDS-Security 1.1 Sec.8.4.2.9.11, relay is an
  OUTPUT of check_remote_datareader alone (`allow_relay_only`), not a
  load-time validity gate; check_remote_datawriter (Sec.8.4.2.9.10) has no
  relay concept at all. It is now kept in the model: a relay grant still
  never grants publish or subscribe by itself, and has an effect on the
  subscribe side only -- a remote reader whose only matching permission for
  a topic is relay is refused rather than admitted with full access, HDDS
  having no routing-service role and minting no `relay_only` cryptographic
  material (Sec.9.5.3.3.4) -- while on the publish side a relay criterion is
  ignored outright, exactly as if it were absent
- **Whether an incoming payload was ciphertext was decided by sniffing its
  first four bytes for the `SECB` magic, not by the endpoint's resolved
  security attributes.** On a topic governance explicitly resolves as
  unprotected, a plain payload whose serialized bytes happened to start with
  those four bytes was still handed to a key lookup that could never succeed
  (or, with no security suite configured at all, dropped outright) -- real
  application data lost to a coincidence of its first four bytes. The
  decision now uses the writer's announced `is_payload_protected` attribute;
  no payload prefix selects decryption
- **The SEND side had the same `SECB`-sniffing defect the entry above fixes
  on receive: a payload's own first four bytes, not the writer's actual
  protection state, decided whether its wire encapsulation carried the
  DDS-XTypes 1.3 7.6.3.1.2 padding count.** An ordinary cleartext payload
  (an opaque/raw type, the C ABI's `BytePayload`) that happened to start
  with the magic had its padding silently dropped and its options left at
  zero, corrupting its wire length for a reader that honours the count. The
  writer's own record of whether it actually sealed this sample
  (`DataWriter::seal_payload_for_wire`'s return, carried into the cached
  `ChangeMetadata::key_epoch` for a repair or replay to read back) now
  decides, never the bytes
- **The access-control topic/partition matcher (`fnmatch`) bounded the
  pattern's length but not the matched name's.** The matcher's own worst
  case is a product of the two, and the name is whatever a remote peer
  announced over SEDP, never bounded by a document load: a peer announcing
  an unbounded topic or partition name made every governance and permissions
  match against it as expensive as that worst case allows. A name past 4096
  bytes now never matches, at `fnmatch` itself -- the one function every
  topic and partition match in access control goes through
- **An unknown `HDDS_TRANSPORT` value took UDP silently.** The ROS 2 adapter
  recognised `intra` and `udp`; every other value, including the
  `intra_process` spelling the ROS 2 guide itself used, fell into the default
  arm and opened UDP sockets without a word, so a test that believed itself
  hermetic was on the network. Both documented spellings are accepted now,
  and any other value is refused at startup by name. `tcp`, `quic` and
  `low_bandwidth`, which the C++ pages told readers to put in this variable,
  are refused with the reason: the variable is read only by the ROS 2 adapter,
  and those transports are not selectable through it in this version (TCP and
  QUIC are wired for receive only; the low-bandwidth link has no production
  constructor). The C++ pages now say so instead of promising it
- **Two SEDP HEARTBEATs could carry the same `Count_t`.** Three sites read the
  shared SEDP heartbeat counter directly, two taking the post-increment value
  and one the pre-increment value, so a re-announcement HEARTBEAT could repeat
  the count of the one before it. DDSI-RTPS v2.5 Sec.8.3.7.5 has a reader
  ignore a HEARTBEAT whose count does not exceed the last seen from that
  writer, so that HEARTBEAT was discarded and the peer never re-NACKed. One
  accessor now hands out strictly increasing counts to all three sites
- **ACKNACK and NACK_FRAG bitmap bounds were computed with unchecked
  arithmetic** (`max_seq - seq_base`, `frag_base + num_bits`), so a maximum
  below the base or a fragment base near the top of the u32 range could
  underflow or wrap the bound, and a wrapped bound admits every number. The
  offset is now computed with a checked subtraction and the bound is tested
  on the offset. Latent: no known peer produced those inputs
- **A DATA_FRAG that did not fit `octetsToNextHeader` went out as an RTPS
  header plus INFO_TS with no submessage behind it**, inside a full-looking
  packet list, so the writer reported success while the reader never
  reassembled. A fragment that cannot be framed now empties the whole list,
  which the writer already treats as "build failed", and says why. The same
  rule now holds for every packet builder in `protocol::builder`: a
  submessage that cannot be encoded yields an EMPTY packet, never a bare
  header *[no 1.4.x exposure]*
- **A getTypes request or reply of exactly 65536 body octets was refused.**
  The `octetsToNextHeader` rule refuses a body that does not fit the u16,
  which is right for a submessage that may be followed by another one, but
  the TypeLookup DATA is the LAST submessage of its message, and for that case
  DDSI-RTPS v2.5 Sec.8.3.3.2.3 defines the sentinel 0, "extends to the end of
  the message", which HDDS already honours on receive. The rule and its one
  exception now live in one place (`protocol::rtps`), the dialect layer
  delegates to it, and the TypeLookup builders use the last-submessage form
  *[no 1.4.x exposure]*
- **A secure SEDP announcement that could not be encrypted left a permanent
  hole in the peer's reliable SEDP channel.** The fail-closed drop (an
  endpoint we cannot protect is not announced in the clear) was right, but the
  sequence number had already been allotted and the writer's high water
  raised, so our HEARTBEATs advertised a sequence the peer would never
  receive; a reliable in-order reader then withheld every later SEDP sample
  too, and the peer stopped discovering anything from us. The refusal is
  deterministic (the encrypted body no longer fits `octetsToNextHeader`), so
  it recurred on every retry. The refused sequence is now retired with a
  single-SN GAP on the peer's metatraffic locators, and the refusals are
  counted (`secure_sedp::wrap_refusals`) so a loop of them is visible
  *[no 1.4.x exposure]*
- **The `ParticipantVolatileMessageSecure` channel protected its
  key-distribution envelopes with an ad hoc HKDF key and framing, not the
  key material and codec DDS Security v1.1 specifies for this one channel.**
  Sec.9.5.2.1.2 (Table 67, cookies Table 68) derives this channel's KxKeys
  from the authentication `SharedSecret` and both handshake challenges by an
  HMAC-SHA256 recipe, independently and identically on both sides -- no
  CryptoToken exchange needed, unlike every other secure endpoint. The
  envelope is now a real protected submessage (SEC_PREFIX/SEC_BODY/
  SEC_POSTFIX, `secure_submessage::encode_datawriter_submessage`, the same
  codec secure SEDP already uses) keyed by that derivation, replacing the
  bespoke AES-GCM blob keyed from an HDDS-internal HKDF salt. Left
  unmarked, per this section's own calibration: no git tag identifies what
  shipped as hdds-1.4.6, 1.4.7 or 1.4.8 (the matrix runs a published
  release asset, never repository source), so whether the ad hoc scheme
  this replaces (introduced 2026-08-15) was packaged into one of them
  could not be established here
- **A refused dispose or unregister burnt a sequence number.** The writer
  took the next sequence before building the packet, so a build that was
  refused left a hole the peer would NACK. The sequence is now taken only
  once the packet exists *[no 1.4.x exposure]*
- **The live `PID_TOPIC_NAME` encoder checked the UNALIGNED length** against
  the u16 `parameterLength` while writing the aligned one, so a topic name of
  65533 to 65535 bytes wrapped the field. The aligned length is what is
  checked now; the other copy of the encoder already did this
  *[no 1.4.x exposure]*
- **Fragment reassembly trusted the announced fragment count.** A DATA_FRAG
  claiming 2^32 fragments made the reassembly buffer allocate for all of
  them (a remote allocation of gigabytes from one datagram), and a later
  fragment announcing a SMALLER total than the first shrank the expected
  count, so a truncated sample was delivered to the application as complete.
  The count is bounded at admission (`MAX_FRAGMENTS_PER_SAMPLE`) and the first
  announced total wins; a fragment that disagrees is refused
  *[no 1.4.x exposure]*

- **No TypeLookup message was ever recognised on the previous lineage.** The
  packet classifier matched an incoming DATA against
  `RTPS_ENTITYID_TYPELOOKUP_WRITER`, whose value was `0x000300C4`. Per
  DDS-XTypes v1.3 Sec.7.6.3.1 and the RTPS entityKind encoding, `0xC4` is a
  BUILTIN READER kind: the TypeLookup request writer is `0x000300C3` and the
  reply writer is `0x000301C3`. So the comparison was against an entity id that
  no writer ever carries, and every TypeLookup DATA -- from any vendor, and from
  HDDS itself -- fell through to the user-data branch instead. The two constants
  held each other's bytes, which is why the names read plausibly while the wire
  behaviour did not.

  The classifier now matches the request writer OR the reply writer, and all
  four entity ids exist with the values the specification gives them. This is
  what makes the `getTypes` support listed under Added reachable at all: the
  service could not have worked while its packets were classified as user data.


- **`hdds-micro` encoded RTPS `SequenceNumber_t` as a single little-endian
  `i64`** in HEARTBEAT and ACKNACK, instead of the split `high: i32` plus
  `low: u32` layout required by DDS-RTPS v2.5 section 9.3.2.5. A standard peer
  decoded sequence number 1 as 2^32, so every `hdds-micro` HEARTBEAT and
  ACKNACK toward a mainstream vendor was unintelligible. It never showed up in
  self-tests because both sides were wrong in the same way. DATA submessages
  were already correct
- *[no 1.4.x exposure]* **A peer that announces a newly registered vendorId was not recognised.**
  The dialect for one peer was keyed on a single placeholder id, so when that
  vendor moved to its registered id the dialect stopped applying and its
  acknowledgements went to a port it discards. The dialect is now keyed on the
  whole set of ids a vendor may present
- **Compound RTPS message parsing.** A `GAP` submessage preceding `DATA` was
  not skipped when locating the payload, an embedded `HEARTBEAT` in a
  GAP-first compound message was not extracted, embedded `GAP` and `NACK_FRAG`
  submessages were not forwarded, and ACKNACK routing and GAP semantics have
  been hardened
- **`GAP` sequence-number words and SPDP lease-duration fractions were encoded
  incorrectly**, and GAP could name sequence numbers that had not been written
- **IPv6 locators.** SPDP misread a UDPv6 `Locator_t` as garbage IPv4 because
  the kind field was ignored, and IPv6 SEDP locators were not preserved.
  Locator encoding is now centralised
- **`DATA_FRAG`.** `octetsToInlineQos` is set to 28 per RTPS v2.5 section
  9.4.5.3.4, the E flag is respected when computing `octets_to_next` while
  extracting the writer GUID and inline QoS, the Q flag is honoured for the
  payload offset, the fragmented flag is consistent across every leg, and
  repair and replay legs reuse the journaled fragment size
- **A DATA submessage with no inline QoS (Q=0) was mishandled**, and
  `PID_STATUS_INFO` is now written as an octet array per RTPS v2.5 Sec.9.6.4.9
- **`PID_DEFAULT_MULTICAST_LOCATOR` had stopped being announced in SPDP**
- **Durable and reliable delivery**: retransmits for a NACK or NACK_FRAG go
  unicast to the requesting reader instead of multicast, ACKNACKs addressed to
  another writer are ignored, a durable writer announces an empty-history
  HEARTBEAT when it matches, KEEP_ALL durable history is no longer clamped,
  aggregate NACK_FRAG rate is capped so a lossy link cannot trigger a repair
  storm, and the writer-side fragment-recovery control plane was repaired
- *[no 1.4.x exposure]* **Coherent sets across vendors.** Standalone end-of-coherent-set markers from
  another vendor are routed into the flush, classic-model sets commit per
  set sequence number, group sets are keyed on a private vendor PID so a peer
  does not arm its own group barrier, and a coherent barrier at a cross-vendor
  discovery seam is bounded instead of waiting forever
- **A reliable reader could drop the already-staged early samples of a
  coherent set, reading valid data as stale.** A coherent set's END marker
  can arrive after the writer's own next HEARTBEAT has advanced `firstSN`
  past the set's first sequence numbers -- the writer purging what every
  acknowledging reader no longer needs, including samples a reader is
  holding back pending the set's close -- and the reorder gate took that
  HEARTBEAT to mean the reader had lost those samples rather than that the
  writer no longer holds them (RTPS v2.5 Sec.8.4.12 says the latter). A
  sample the gate already admitted once, and is holding staged, is never
  stale. The TOPIC path (which bypasses the reorder gate) already delivered
  correctly; the GROUP and HDDS coherent-set flush now release a staged
  sample the gate already passed as it is, instead of re-testing it against
  `firstSN`
  - A reader keeps a per-writer join floor so a staged repair of an older
    set, or a backlog replayed after a later set already arrived, cannot
    deliver history from before the reader joined. The floor applies only to
    a gate seeded by its own first DATA (VOLATILE, BEST_EFFORT): a gate
    seeded by a HEARTBEAT or a GAP owes the reader the writer's whole
    retained history and takes no floor, which matters for TRANSIENT_LOCAL --
    without this exemption, a set staged before the writer's first HEARTBEAT
    reached the reader lost its own first samples. The floor sits at the
    start of the first coherent set the reader observes (`PID_COHERENT_SET`,
    RTPS v2.5 Sec.8.7.5), not at the first staged sample it happens to see,
    so a first set that arrives slightly out of order is not cut; it is
    checked before anything else, so it also keeps out an older set that
    closes before any gate has been seeded at all
  - A VOLATILE reliable reader whose first change from a writer is a member
    of a coherent set now joins the writer at that set's start, as it does
    at a first plain DATA. Its gate was left unseeded while the set waited
    (for its end, a repair, or room in the history), and the writer's next
    plain DATA seeded it above the set: that DATA reached the application
    first and the set after it, or, when a member was still missing, never
    (measured: `[15, 11, 12, 13, 14, 16]`, and `[15, 16]` with the set lost).
    Delivery now follows the writer's order (DDS v1.4 Sec.2.2.3.6, 2.2.3.14);
    a HEARTBEAT still seeds no VOLATILE gate, and members the writer purged
    before the reader received them are crossed as before
  - A BEST_EFFORT gate's own freshness rule (RTPS v2.5 Sec.8.4.12.1, T2) is
    applied only when a sample arrives, never again at release: a staged
    sample is credited as received the moment it is staged, and a later DATA
    of the same writer accepted meanwhile can no longer make an entire
    already-admitted staged set look stale and drop it
  - An HDDS writer's sample delivered straight through to a GROUP-scope
    reader because it carries no group set is no longer mistaken for a
    staged sample, so a BEST_EFFORT gate no longer refuses it as old after
    the fact; and a `PID_COHERENT_SET` start of 0 is ignored rather than read
    as a real join floor, since RTPS sequence numbers start at 1 (Sec.8.3.5.4)
- **SEDP.** The endpoint group identity is advertised correctly, the reader's
  real `TIME_BASED_FILTER` minimum separation is advertised instead of a
  placeholder, sequence numbers are positionally stable so a duplicate number
  cannot produce a dead topic, an absent remote `TypeConsistencyEnforcement`
  is read as the spec defaults, `INCONSISTENT_TOPIC` is deterministic
  regardless of arrival order, and OpenDDS 3.35+ spec-fraction `Duration_t`
  values are accepted for `PID_LIFESPAN`
- **SEDP announced DEADLINE, LIFESPAN and LIVELINESS as explicit non-default
  values even when both endpoints held the default policy.** PID_DEADLINE and
  PID_LIFESPAN were written as INFINITE ({0x7FFFFFFF, 0xFFFFFFFF}, RTPS v2.5
  Sec.9.3.2) whenever at their default, and PID_LIVELINESS always as
  AUTOMATIC with an infinite lease regardless of the endpoint's own policy,
  instead of omitting the parameter the way most implementations do and RTPS
  v2.5 Sec.9.6.2.2.1 lets a receiver assume. A receiver that does not
  recognise the explicit INFINITE value reads it as a finite period and
  refuses the pairing on DEADLINE and LIVELINESS incompatibility -- against
  a pairing that should have matched outright. The three policies are now announced
  only off their default, and LIVELINESS carries the endpoint's actual kind
  (AUTOMATIC, MANUAL_BY_PARTICIPANT or MANUAL_BY_TOPIC) and lease: the wire
  value was wrong for any endpoint with a non-default LIVELINESS policy, not
  only for the all-default case that triggered the refusal
- **A recycled participant id inherited a dead peer's SEDP state**, so it was
  treated as already announced. Any process that destroys and recreates
  participants could silently lose discovery
- **A participant now leaves by disposing and unregistering its own
  DCPSParticipant built-in-topic instance, sent once, rather than announcing
  a lease of 0 twice.** A departing HDDS participant previously sent a full
  SPDP announcement with a lease of 0 and no default locators from both the
  announcer's own shutdown and the Drop that follows it, which is not how
  RTPS says a participant leaves: it reads as a change to the participant's
  immutable bootstrap configuration, which the interoperability tests against
  RTI Connext 7.x (public OMG interoperability executable) flagged at every
  HDDS shutdown; an HDDS receiver ran the same
  announcement through full SPDP handling -- dialect detection, an immediate
  reply, SEDP re-announcements, a retry thread -- toward a participant that
  was leaving. A departure is now the dispose and unregister of the
  participant's DCPSParticipant instance (the dispose/unregister message of
  RTPS v2.5 Sec.8.7.4): a DATA of
  the SPDP writer with no payload, inline QoS PID_STATUS_INFO set to
  DISPOSED and UNREGISTERED (Sec.9.6.4.9) and PID_KEY_HASH carrying the
  participant GUID (Sec.9.6.4.8), sent once, after the announcer thread has stopped, multicast
  where allowed and to every unicast SPDP destination, and never run through
  announcement handling on receipt: the departing participant is retired
  from discovery and from the unicast SPDP destination list, and nothing
  else applies
  - The key-only departure form (a DATA carrying the serialized key) is also
    read
  - A departure naming a participant other than the one that sent it is
    refused
  - A departed peer's per-peer discovery records are forgotten, not merely
    marked retired
  - A key-only dispose is read against its own DATA: the serialized key
    stops at its submessage (it ran to the end of the datagram), and the
    StatusInfo and key-hash checks read that DATA's inline QoS (they read the
    first DATA of the datagram). For a well-formed key the bound changes no
    result; what it refuses is a key its own submessage cuts short, which
    was completed from the octets that followed it
  - With DDS Security, a departure received on the plain DCPSParticipants
    topic from a participant that has completed authentication is ignored,
    in every form, the lease-0 announcement included (DDS Security v1.1
    Sec.7.4.1.6): anyone could send one under that participant's prefix.
    The deletion is to be sent on DCPSParticipantsSecure instead, and an
    HDDS participant now sends its own there, sealed, to each authenticated
    HDDS peer as it is deleted: a DATA of the secure participant writer
    (0xff0101c2) whose payload, its GUID, is sealed under the metatraffic
    key of that pair, applied only when it opens under the key of the
    participant it names. The sealing is HDDS's own (no SecureSubmessage),
    so it goes to HDDS peers only, and the rest of DCPSParticipantsSecure is
    not served. A participant of another vendor, and an HDDS participant
    that crashes, leave when their lease expires: with an infinite lease,
    never, as without security
  - A participant that has sent its departure answers no SPDP announcement
    received after it; an answer brought it back at the receiver for a lease
  - An announcement with a lease of 0 is still read as a departure, for any
    HDDS peer that still sends the old form
  - **Compatibility:** an HDDS 1.4.x participant does not read the new
    departure message and keeps a departed 1.5.0 participant until its lease
    expires, rather than dropping it at once the way it would for a 1.4.x
    peer's departure; a 1.5.0 participant still reads the old lease-0
    farewell from a 1.4.x peer
- **With DDS Security, discovery took plain announcements from an
  authenticated participant as changes, kept its handshake session for
  ever, and lost the endpoints it announced during the handshake.** DDS
  Security v1.1 Sec.7.4.1.6: after authentication, changes to a
  participant's ParticipantBuiltinTopicData received on the plain
  DCPSParticipants topic are ignored, and may be used only to maintain its
  liveliness. Anyone can send on the plain topics under any prefix
  - A plain announcement of an authenticated participant now refreshes its
    liveliness and nothing else. Its lease, metatraffic locators, the
    unicast locator its handshake, keys and user data are sent to, and its
    vendor id stay as they were when it authenticated, and no handshake
    packet, immediate SPDP reply or SEDP re-announcement goes to the
    addresses such a datagram carries. Before, any datagram under its
    prefix could redirect that traffic (the lease and locator rewrite came
    in this cycle; the vendor id one is 1.4.x's)
  - While a participant's handshake is pending (a session with it exists
    and has not completed), each plain announcement it is admitted with is
    held to a lease of at most the RTPS default, 100 s, and the lease it
    declared is kept aside: an infinite one, forged before anything vouched
    for it, would never let the participant leave, its plain departures
    being ignored once it authenticates. When the handshake completes it
    gets back the shortest lease declared in those announcements: none of
    them is authenticated, so a forger can make the lease shorter, never
    longer. (The lease of the last one used to be restored, so an infinite
    lease announced under its prefix during the handshake outlived it.) An
    announcement admitted before any session exists is not among them and
    is not bounded; if none arrived while the session was pending, the
    participant keeps the lease it was admitted with
  - A plain announcement or dispose of an endpoint an authenticated
    participant already announced is ignored, whole: before, it could move
    the endpoint to another locator, change its topic or type, block a
    writer at the router with another ownership, set the lifespan the
    samples of its topic expired by, or unmatch it. A change is taken from
    the secure SEDP topics (Sec.7.4.1.7, 7.4.1.8), and HDDS now sends its
    own changes to authenticated peers there: an endpoint created after
    discovery, the dispose of a deleted one, a repair. A new endpoint
    announced on the plain topic is still taken. A secure SEDP datagram
    from a participant whose handshake is still completing here is held
    until it completes, rather than dropped
  - A participant the security policy refuses (an identity the validator
    rejects, or none where authentication is required) is no longer made an
    SPDP destination nor sent the discovery handshake and our SEDP: the SPDP
    handlers did not read the discovery verdict at all
  - A participant removed from discovery (its departure, its lease expiry, a
    probation or zombie purge) takes its handshake session with it, and the
    record that we answered it and re-announced our endpoints to it goes
    too (not for a 1.4.x peer's lease-0 farewell, which is still answered).
    One that comes back under the same prefix after that is authenticated
    again
  - A participant re-created under the same prefix within its lease (the
    HDDS norm for a participant re-created in the same process) is
    authenticated again too. Discovery cannot tell it from the one before
    it - its farewell on the plain topic is ignored, its announcements only
    keep the old one alive - so it asks: a responder holding no session
    sends an authentication request (DDS Security v1.1 Sec.7.4.3.6.2, the
    AuthRequestMessageToken of Sec.9.3.2.4) and the initiator begins a new
    handshake next to its completed one, which the new one replaces once it
    verifies; our endpoints are then announced to it again, sealed, and the
    endpoints it announced before are forgotten, so what it announces now is
    taken fresh. Before, where we initiated, it waited for ever and nothing
    we sent it could be read. One such re-authentication per peer per 30 s,
    and none while one is in flight: a forger gains at most a re-keying the
    real peer has to sign, and a participant that really restarted may wait
    30 s plus an SPDP period for it
  - Every completed handshake, the first or a re-authentication, is
    answered with our endpoints, sealed: the restarted side announced them
    in the clear before it authenticated, which the other side ignores for
    endpoints it already knew
  - A re-authentication abandoned after we answered the peer's request, or
    asked the peer to begin, is asked for again until a session completes:
    the peer may have completed it alone, and the two sides then held
    different keys for good. A duplicate AuthReply of a completed session is
    answered again only when it echoes that session's own request; any other
    reply, of an abandoned session or forged, completes nothing
  - Secure SEDP that does not open under the key held while a
    re-authentication is in flight is held until the keys settle, rather
    than dropped: it was sealed under the new key, one message before we
    hold it. What the peer sends behind something held is held behind it,
    and applied in the order received
  - The participant with the lower GUID initiates the handshake (DDS
    Security v1.1 Sec.9.3.4). HDDS elected the higher one, the opposite of
    every conforming implementation; between two HDDS participants of this
    release only which side begins changes
  - A handshake message verified while its session was dropped or replaced
    installs nothing, and an AuthRequest - signed by nobody - no longer
    replaces a session, completed or in progress: a new session runs next
    to it and replaces it only when its AuthFinal, signed by the peer,
    verifies, and for a completed session only under the certificate it
    completed with
  - The endpoints a participant announced while its handshake was in
    progress are offered again when the handshake completes. They were
    refused then and never offered again, so a secure participant that
    joined after the other's first 250 ms was not matched
  - A secure participant's builtin endpoint set names the secure endpoints
    it serves and no other: the stateless and volatile channels and the
    secure SEDP endpoints. It used to name DCPSParticipantsSecure,
    BuiltinParticipantMessageSecure and bits 28-29 (DCPSTopic in RTPS v2.5),
    none of them served, and to leave out the volatile key channel, which
    is served
  - **Compatibility:** an HDDS 1.4.x participant and a 1.5.0 one do not
    authenticate each other: 1.4.x serializes the handshake tokens'
    `propagate` flag, which this release no longer reads, and elects the
    other initiator. The handshake and
    the authentication request are HDDS's own stateless framing, not the
    ParticipantGenericMessage of the specification: secure discovery is
    HDDS to HDDS
  - Not done: HDDS does not serve DCPSParticipantsSecure beyond its own
    sealed departure, so an authenticated participant's locators are not
    followed; HDDS does not send an authentication request as the
    initiator, nor take a challenge from one (Table 52, a responder checks
    it only when it received one); the governance's discovery protection
    does not refuse a NEW endpoint announced on the plain topic; a
    participant's GUID prefix is not yet bound to its certificate (the
    47-bit subject-name check of Sec.9.3.3)
- **A sample expired by the shortest lifespan of its topic.** LIFESPAN is a
  DataWriter QoS (DDS v1.4 Sec.2.2.3.16), but a remote writer's lifespan
  was kept per topic, as the smallest announced, and applied to the
  samples of every writer of the topic: one writer announcing a short
  lifespan expired the others' samples. A sample whose writer is known
  now expires by that writer's lifespan; one whose writer is not known
  (the intra-process leg) still by the smallest of the matched writers.
  A reader's own lifespan is kept apart from its writers', whichever is
  created first, and a writer's lifespan record goes when the writer does
  - `TopicRegistry::register_writer_lifespan(topic, ns)` keeps its
    signature, deprecated: it records the topic-wide value, as before.
    `register_writer_lifespan_of(topic, writer, ns)` records one writer's
    lifespan as well
- **A deleted DataWriter or DataReader stayed matched at every remote peer
  for as long as its participant lived.** The history of the SEDP
  publications (subscriptions) writer holds one data-object per DataWriter
  (DataReader) of the participant, deleted each time that endpoint is
  deleted (RTPS v2.5 Sec.8.5.4.4, Tables 8.82 and 8.83). HDDS only ever
  inserted: nothing was sent when an endpoint went away, and the deleted
  endpoint was announced alive again to every late joiner by the discovery
  replay, by retransmission and by the OpenDDS reader re-announcement. Between
  two HDDS participants, a remote writer kept the dead reader in its
  acknowledgement table, so a KEEP_ALL writer could block on it
  - Deleting an endpoint now sends the dispose of its SEDP instance to the
    peers already known, followed by a HEARTBEAT: a DATA with inline
    PID_KEY_HASH (Sec.9.6.4.8) and PID_STATUS_INFO set to DISPOSED and
    UNREGISTERED (Sec.9.6.4.9), carrying the key-only payload
    (PID_ENDPOINT_GUID). Its announcement is never sent again: replay and
    retransmission send a GAP in its place, then the dispose
  - A DataWriter sends that dispose after the unregisters of the instances
    it wrote (DDS v1.4 Sec.2.2.2.4.1.6), so a reader does not hear them from
    a writer it already forgot. A participant that is being deleted sends
    no endpoint dispose: its own departure retires every endpoint at once
  - Sequence numbers stay unique per SEDP writer. The OpenDDS reader
    re-announcement took its number from a process-wide counter while the
    announcements took theirs from the history, so a reader created after a
    re-announcement, or a dispose, could go out under the number the
    re-announcement had used, which a receiver drops as a duplicate. The
    re-announcement is now a change of the history like any other
  - The HEARTBEAT of an SEDP writer starts at its first change still
    available, so a late joiner does not ask for an announcement the writer
    has retired
  - A GAP from a remote SEDP writer is now credited to the SEDP reader,
    including the numbers its bitmap names (RTPS v2.5 Sec.8.3.8.4): a number
    the writer retired was otherwise asked for again as long as it lived
  - **Compatibility:** an HDDS 1.4.x participant sends no dispose when it
    deletes an endpoint, so a 1.5.0 participant keeps a deleted 1.4.x
    endpoint matched for the life of that participant, as a 1.4.x one does.
    A deleted 1.4.x reader stays matched at a 1.5.0 reliable writer and
    never acknowledges again: a KEEP_ALL writer keeps every sample for it,
    so its history grows without bound or, bounded by resource limits,
    blocks the writer
- **A remote writer's departure moved its instances to the wrong state at a
  reader.** The departure of one DataWriter moved to NOT_ALIVE_NO_WRITERS an
  instance another DataWriter still writes, one that wrote it and has not
  unregistered it since (DDS v1.4 Sec.2.2.2.4.2.7: NOT_ALIVE_NO_WRITERS only
  "if no other DataWriter entities are writing the instance"; a dispose does
  not unregister, Sec.2.2.3.23.3), and moved an instance already
  NOT_ALIVE_DISPOSED to NOT_ALIVE_NO_WRITERS; it now stays NOT_ALIVE_DISPOSED
  (Sec.2.2.3.22: the last sample is NOT_ALIVE_NO_WRITERS or
  NOT_ALIVE_DISPOSED depending on whether the last writer disposed the
  instance)
  - An unregister from one of several DataWriters writing an instance moved
    it to NOT_ALIVE_NO_WRITERS, and the next sample of another of them then
    reported it as a NEW instance. The instance now stays ALIVE, its view
    state unchanged, until the last of its writers unregisters it or leaves.
    A remote dispose or unregister now reaches the reader with the
    DataWriter that sent it. A DataWriter of the reader's own process
    counts among an instance's writers too, for a SHARED and an EXCLUSIVE
    reader alike (see the local-writer items of the EXCLUSIVE ownership
    entry below)
  - The departure of a whole participant, by its own dispose, by lease
    expiry or by a purge of the startup probation, never moved its writers'
    instances to NOT_ALIVE_NO_WRITERS; it now does, as the dispose of each
    of its writers would. A probation purge counts: a reader takes its
    WriterProxy at discovery, so a participant purged for its silence may
    have delivered samples, and for a writer that delivered nothing the
    departure changes no instance
  - An SEDP endpoint dispose is applied only when it comes from the
    participant that owns the endpoint
- **EXCLUSIVE ownership never changed hands once the strongest writer had
  an instance.** The participant's router arbitrated ownership in a map that
  nothing cleared: not the owner's unregister ("it will relinquish ownership
  of the instance", DDS v1.4 Sec.2.2.3.23.3), not its deletion, not its
  participant's departure or lease expiry, not a change of its strength, so a
  weaker writer stayed hidden after the owner was gone. The router's samples
  of the weaker writer never reached the reader either, so the owner's
  unregister moved the instance to NOT_ALIVE_NO_WRITERS while that writer
  was still writing it; a dispose from a writer that did not own the
  instance was applied (Sec.2.2.2.5.1.3: only the owner's); equal strengths
  went to whichever writer arrived first, not to one every reader picks
  (Sec.2.2.3.9.2); and the instance was named by a hash of the payload's
  leading bytes, which for a type whose first member is not a string key
  covered non-key fields too, so every sample was its own instance and
  nothing was filtered at all
  - Each EXCLUSIVE DataReader now arbitrates (Sec.2.2.3.10: "The arbitration
    is performed by the DataReader") on the instance key it computes from
    the decoded sample (`T::compute_key`), and a key-only dispose or
    unregister is matched on the PID_KEY_HASH it carries. The two agree for
    HDDS writers; see the known limitation below. The strongest writer
    owns an instance, ties going to the lower GUID; the owner's unregister,
    dispose-and-unregister, deletion or departure releases it, and the next
    writer to modify the instance takes it. A contender is weighed at its
    current strength against the owner's, and, when the reader requested a
    finite DEADLINE, against an owner that let the period pass without
    modifying the instance (Sec.2.2.3.9.2 (d)). Only the owner's dispose
    moves the instance to NOT_ALIVE_DISPOSED, and the weaker writer stays
    hidden after it (Sec.2.2.3.23.3). A dispose is a modification: a
    stronger writer that only disposes takes the instance, and a writer
    that disposes an instance holds it registered (Sec.2.2.2.4.2.7: to
    "modify (write or dispose)" an instance a writer registers it), under
    SHARED ownership too
  - A remote writer that announced PID_OWNERSHIP_STRENGTH without
    PID_OWNERSHIP was read as EXCLUSIVE but its strength was recorded only
    when the parsed kind was EXCLUSIVE, which it never is without the PID,
    so it was arbitrated at strength 0. The strength is now recorded from
    every announcement (0 when absent, so a re-announcement without it does
    not leave a stale value), before the kind, the kind is inferred by one
    rule wherever a remote endpoint's kind is read, and a deleted writer's
    strength leaves with its SEDP dispose
  - A foreign writer sends the RTPS KeyHash (DDSI-RTPS v2.5 Sec.9.6.4.8),
    while the reader names an instance by `T::compute_key`. When the two
    differ, a foreign owner's key-only unregister does not release the
    instance (a weaker writer stays hidden), and a foreign non-owner's
    dispose is applied to an instance the application never saw. Since the
    KeyHash entry below, `compute_key` is that KeyHash for every
    `hdds_gen`-generated Rust type, every `#[derive(DDS)]` type with
    `#[key]` and the shapes demo's ShapeType; and a dispose or unregister
    that serializes its key is named by the key, whatever its PID_KEY_HASH
    (see "A received dispose or unregister is named by its serialized key")
  - An EXCLUSIVE reader whose local writer was deleted without its
    unregisters reaching it (a slab or journal failure in its `Drop`)
    released the writer's instances silently; it now announces those left
    without writers NOT_ALIVE_NO_WRITERS, as for a remote writer's
    departure. It notices a deletion on the next sample or lifecycle change
    with one atomic load per admission, instead of looking at every local
    writer each time
  - A SHARED reader did not count a DataWriter of its own process among an
    instance's writers: a remote writer's unregister or departure moved the
    instance to NOT_ALIVE_NO_WRITERS while the local writer still wrote it,
    and so did one of two local writers unregistering. The reader now asks
    its local writers, through the instances each one holds, before it
    declares an instance without writers; this happens on the lifecycle and
    departure paths only, so the intra-process data path is unchanged
  - A writer's dispose or unregister was placed against the sample at the
    front of the reader's cache only, so with another writer's sample in
    front it was returned before the writer's own earlier sample. It now
    waits while any sample of its writer at or before it is still queued
  - The router no longer filters ownership: a SHARED reader of a topic that
    also has an EXCLUSIVE reader in the same participant was filtered with
    it. A writer's liveliness is only lost here with its participant (an
    SPDP dispose, a lease expiry or a probation purge); a MANUAL_BY_TOPIC
    liveliness lapse is not detected by a reader
  - A DataWriter in the reader's own process was not arbitrated at all: its
    samples and its disposes reached an EXCLUSIVE reader through the
    intra-process ring with no writer identity, so a local writer of
    strength 0 overrode a remote owner of strength 100. Each writer's merger
    now carries the writer's GUID and strength, and an EXCLUSIVE reader's
    binding arbitrates every local sample and lifecycle change on the
    writer's thread, before the ring push, in the same table as its network
    path, on the key hash the writer computed for the write (a history
    replay to a late-joining reader carries none: the gate derives it from
    the sample). A writer of no participant takes a GUID prefix drawn at
    random once per process, the same for every such writer of the process,
    and its own entity id (a counter, with the user-writer kind); it is not
    the all-zero GUIDPREFIX_UNKNOWN, which a peer may carry and which won
    every strength tie against a remote writer, ties going to the lower
    GUID. A deleted local writer releases what it owned. A SHARED reader's
    local path is unchanged. Cost, measured with the intra-process latency
    example (write to take, 16-octet keyless sample, one pinned core,
    interleaved runs) on a development host (88 cores, `schedutil`
    governor, load between 1.3 and 4.8 over the two series below), not on
    the certified bench host, so read the differences, not the values:
    SHARED p50 median 240 ns before this work and 236.5 ns after it (40 runs
    each); the same pair made EXCLUSIVE, 364 ns p50 median against 234 ns
    for SHARED in the same rounds (25 runs), the price of an arbitration
    that did not run before
- **A FastDDS vendor-flagged XCDR1 payload was mislabelled as XCDR2**
- **`PID_TYPE_INFORMATION` zero-dependency wire format**, enum and struct
  TypeObject encoding, declaration-order struct members, `@key` members
  treated as implicitly must-understand, and `@autoid(HASH)` / `@hashid`
  member ids

  **Known open defect, stated here rather than left to be discovered.**
  `CompleteStructHeader` / `MinimalStructHeader.base_type` is still encoded
  through an XCDR2 optional-field wrapper instead of the plain
  `TypeIdentifier` that Annex B requires, so **a struct that INHERITS from
  another still produces a wrong Minimal and Complete hash** against a strict
  vendor. Types without inheritance are unaffected. The fix exists on a branch
  that is not part of this release
- **One type verdict decides a pairing, whichever of the two endpoints and
  the TypeLookup reply arrives first.** Four places decided whether a remote
  writer's type is assignable to a local reader's (DDS-XTypes v1.3
  Sec.7.6.3.4.2), each its own way, and the TypeObject a TypeLookup reply
  filled in for an endpoint announced by TypeInformation alone was judged
  by none of them. With a writer of another vendor, a run failed when the
  getTypes reply landed before the local reader registered: the writer was
  judged incompatible and its samples gated off, then reported matched, and
  every sample was dropped; when the reply landed after the reader, a writer
  of a genuinely incompatible type was matched and delivered. One verdict
  is now asked everywhere (both types known: structural assignability;
  either unknown: refused only under `force_type_validation`), on the type
  discovery knows now, and each of the three events that can change it
  judges it again: a remote endpoint discovered, a local endpoint
  registered, a remote type learned
  - The data-plane type gate is per (writer, reader) pair, not per writer: a
    writer one local reader refused was gated off for every reader of the
    participant, so another reader reported it matched and received nothing
  - A getTypes reply resolves exactly the endpoints whose TypeInformation
    announced its hash (Sec.7.3.4.8), not every endpoint of the type name:
    with two peers publishing different types under one name, the first
    reply typed both. A reply no longer gives a peer's type to a local
    endpoint of the same name
  - A type found in the TypeLookup cache is applied after the endpoint is
    registered; it used to resolve nothing, and the endpoint stayed untyped
  - Under `force_type_validation`, a writer refused while its type was
    unknown is matched once the type is learned compatible; a match applied
    on a verdict taken just before the type was learned is undone if the
    learned type refuses it
  - A re-announcement of a writer by the same TypeInformation keeps the
    TypeObject already learned for that hash; it erased it, and a reader
    forcing type validation that had matched the writer gated it off,
    reported matched and delivering nothing
  - An endpoint whose type a TypeLookup reply resolved is no longer
    reported to discovery listeners a second time
  - The matcher reads the inert `TK_STRING8` / `TK_STRING16` identifiers as
    the unbounded strings they denote (any narrow string is assignable from
    any narrow string, Sec.7.2.4.4.5 Table 16), and compares bounds across
    small and large string identifiers when bounds are enforced. A string,
    sequence or map key member follows `ignore_string_bounds` /
    `ignore_sequence_bounds` like any other member (Sec.7.6.3.4.1 makes no
    exception for keys): under the default (TRUE) a writer's `string<20>` key
    is assignable to a reader's `string<10>` key, nested structure keys
    included; with the flag FALSE the key bound of Sec.7.2.4.4.8 Table 19
    (m1.type.length >= m2.type.length) refuses it. The inert string
    identifiers compare as unbounded strings
  - An enumerated key member is held to Table 19's literal rule, which no
    flag relaxes: every literal of the writer's key enumeration must appear
    in the reader's. A reader whose key enumeration lacks a writer literal
    is refused; it was matched whenever the TypeLookup resolver could read
    both enumerations, since the literal intersection rule for plain
    enumerated members was the only one applied
  - The dynamic CDR decoder never trims nor defaults a key: a key member, or
    anything inside one, longer than the reader's bound refuses the sample
    whatever `@try_construct` it declares, and so does a union discriminator
    that is the key and carries a literal the reader's enumeration lacks.
    Trimming would have turned the key into another instance's (the
    "without aliasing or loss of information" Note of Table 19). A member
    whose type is a typedef, an enumeration or another named type declared
    apart now applies the member's own `@try_construct`; it applied
    USE_DEFAULT whatever the member declared, so an over-long string behind a
    typedef was read as empty instead of refusing the sample
  - The shapes demo's ShapeType TypeObject declared `additional_payload_size`
    a bare `uint8` while the demo writes a `sequence<uint8>`, so the
    ShapeType of other vendors was refused against it once TypeLookup
    resolved it; it is now the sequence, its collection header says EK_BOTH
    (Sec.7.3.4.4), and the tests judge the TypeObject the demo announces.
    The TypeInformation hashes and `PID_TYPE_OBJECT` bytes of the demo's
    ShapeType change. Its TypeObject still does not decode for a strict
    reader (the inert `color` member)

- **OpenDDS peers now receive the TypeInformation of the endpoint's actual
  type.** The OpenDDS dialect announced a fixed `PID_TYPE_INFORMATION` to any
  endpoint whose type was named `Temperature` or
  `TemperatureModule::Temperature`: the minimal identifier of an
  `@appendable @nested { float value; unsigned long timestamp; }` struct,
  which none of HDDS's own Temperature types is, and a `TK_NONE` complete
  identifier, which DDS-XTypes 1.3 Sec.7.6.3.2.1 does not allow. Every other
  endpoint announced none. The dialect now announces, for every endpoint
  with a TypeObject, the TypeInformation the generic SEDP path announces
  (minimal and complete identifiers of the endpoint's own type, dependencies
  included when resolved), written by the same code; an endpoint without a
  TypeObject announces none. OpenDDS peers see new TypeInformation bytes for
  every endpoint that has a TypeObject. A TypeInformation that fails to
  encode is left out and the endpoint is still announced

Delivery, conditions and lifecycle:

- **`WaitSet::notify()` did not wake a blocked `wait()`**, which is the one
  thing it is documented to do, and two WaitSets attached to the same
  condition disarmed each other. Changing a QueryCondition's parameters now
  re-signals attached WaitSets even with no new data. Several lost-wakeup and
  lock-ordering races on the `DATA_AVAILABLE` path are closed
- **A reader lost samples when two writers used the same sequence number.**
  Its sample cache took a sample whose sequence number it already held for
  a duplicate, without looking at the writer, and every remote writer of a
  reader shares one ring, so a second writer's change 1 was dropped as the
  first writer's. Under RELIABLE the loss was permanent, the change having
  been credited for acknowledgement already: KEEP_ALL delivered half of what
  it received, and KEEP_LAST(1) on an instance written by two writers kept
  the older value. A sample is now a duplicate only when its writer and its
  sequence number both match (RTPS v2.5 Sec.8.3.8.2: the writerSN
  identifies a change among the changes of its writer)
- **A key-only dispose or unregister now keeps its own sequence number.** The
  walk that delivers key-only DATA (K flag, RTPS 2.5 9.4.5.3) handed every
  one to the reader as sequence number 0, so it
  sat before every sample of its writer, and a reliable repair of a sample
  sent BEFORE the dispose brought the disposed instance back to ALIVE. Each
  is now delivered under its own DATA's writerSN (RTPS v2.5 Sec.8.3.8.2,
  Sec.8.7.4), and its inline QoS and serialized key are read inside its own
  submessage, so a HEARTBEAT or PAD behind it can neither complete a key nor
  end its parameter list
- *[no 1.4.x exposure]* **`instance_state` was hardcoded to `Alive`.** It is now computed from
  tracked dispose and unregister transitions, and a sample reports the current
  instance state. A writer and a reader in the same process produce them
  too: see "Disposes and unregisters are changes of the writer's history"
  below
- **A TRANSIENT_LOCAL writer with one live in-process reader kept an empty
  history**, so a later local joiner received nothing: the intra-process fast
  path never journaled. Replay also rebuilt entries with the default CDR
  version instead of the version each sample was encoded with, misreading
  retained XCDR1 samples
- **A content filter was not applied to intra-process delivery.** The merger
  fanned every sample into a ContentFilteredTopic reader's ring; filtering now
  runs before the ring push, so a filtered-out sample raises no
  `DATA_AVAILABLE` and is not replayed to a late joiner
- **OWNERSHIP KIND compatibility had no data-plane gate.** Per-instance
  strength arbitration already ran on the wire path (what it got wrong is the
  EXCLUSIVE ownership entry above); what nothing checked was
  whether the writer's OWNERSHIP kind was compatible with the reader's in the
  first place. TYPE, PARTITION and DATA_REPRESENTATION each had a per-sample
  delivery gate and OWNERSHIP had none, so an incompatible pairing delivered
  its samples to the application while the separate
  `on_requested_incompatible_qos` notification raced the registration order.
  There is now a per-sample kind gate on the network receive path, a writer
  not yet resolved through SEDP is held back rather than delivered, and the
  registration-time scan applies the same check its live-SEDP sibling already
  did. The intra-process path does not flow through this gate
- **The deprecated `try_take()` sent a forged ACKNACK**, built on a hardcoded
  GUID prefix and SEDP entity ids that belonged to no real pairing. It is
  gone, and the reader no longer drives `NackScheduler` at all. A DataReader's
  repair path is the per-writer `ReaderProxyRegistry`, credited on every
  admitted sample, and the control-plane ACKNACK built from it.
  `NackScheduler` and `GapTracker` remain public as standalone bookkeeping
  utilities and their documentation now says so instead of presenting them as
  the reader's repair path
- *[no 1.4.x exposure]* **Per-writer and per-reader `shm_policy()` was a public setter that did
  nothing.** The shared-memory leg always used the participant's policy, so
  disabling shared memory on one endpoint had no effect
- **A shared-memory writer that died mid-write wedged its reader forever.**
  Overrun recovery now keeps what is still in the ring and reports how many
  samples were lost, a presence claim is perishable and read as a snapshot,
  and a peer publishes its start cursor so a handover cannot lose a sample
- *[no 1.4.x exposure]* **A multicast send refused by the multicast policy reported success.** It
  now returns an `Unsupported` error and is counted
- **A reader's `on_data_available` was never called for a sample written in
  the same process.** A writer delivers to a reader of its own participant
  (or to any reader of the process when one side has no transport) through
  its merger, which never passed through the reader's network subscriber,
  the only place the listener was called. The sample reached the ring and
  woke WaitSets; the listener heard nothing, even one given to the builder.
  The merger now calls the reader's listener after the push, on the
  writer's thread, while a listener covers DATA_AVAILABLE; otherwise the
  push pays one relaxed load per bound reader. History replayed to a
  TRANSIENT_LOCAL late joiner from a local writer at bind time is still not
  announced (it runs under the reader's binding lock)
- **The requested and offered deadline-missed listeners ran under the
  deadline tracker's lock**, so a callback that read or wrote with the same
  entity deadlocked. They now run after it is released

- **The shared-memory notify segment of every topic was left in `/dev/shm`
  forever**, one per topic ever used on the host, and a second writer on a
  topic replaced it (its creation unlinked the existing one), so processes
  attached before and after stopped waking each other. The segment
  (`/hdds_notify_v2_d<domain>_<topic>`, layout version 2, mode 0600) now
  carries a table of the processes using it, under a robust process-shared
  lock, and the last live user unlinks it; a user that crashed is reclaimed
  by the next one to attach or leave, or by the next participant start on
  the domain. Only processes that write to the topic over shared memory, or
  block on `take_blocking`, take a row; up to 1024 per topic per host, and
  one more is refused (its writer falls back to UDP, logged once). An object
  under the name that belongs to another user or is not mode 0600 is
  refused and left alone. A process of an earlier release on the same host keeps using the
  version-1 name: the two never touch each other's segment, and they no
  longer share wake-ups for `take_blocking` (the participant's own receive
  path does not wait on them). Version-1 segments already in `/dev/shm` are not removed,
  since nothing can tell whether an older process still uses one
- **A remote writer that stopped without a word stayed alive forever.**
  LIVELINESS was matched (RxO) and announced (SEDP `PID_LIVELINESS`), but no
  lease was ever judged: `on_liveliness_changed` had no caller, a reader's
  StatusCondition never raised LIVELINESS_CHANGED, and the
  ParticipantMessage assertions HDDS asks every peer for (its SPDP announces
  the BuiltinParticipantMessage reader) were classified and dropped at the
  listener. A crashed AUTOMATIC writer is now reported not alive within
  about one lease (DDS v1.4 Sec.2.2.3.11; see Added)

Platform and portability:

- **DSCP and TTL used hardcoded Linux socket-option values** for `IP_TOS`,
  `IP_TTL` and `IP_MULTICAST_TTL`, which differ on macOS and BSD and failed
  there with `ENOPROTOOPT`. They now come from `libc` per-platform constants
- **Interface enumeration no longer shells out to the `ip` binary** and parses
  its text output; it reads the kernel interface table through `getifaddrs` on
  Unix and a native crate on Windows. A trimmed BSD netmask sockaddr is
  zero-extended instead of refused
- **Windows: the user-data send socket now binds the unspecified address**, so
  a participant can reach a loopback peer under Windows' strong host model,
  plus two other portability defects found by the first native Windows run
- **A domain and a participant id can each be legal while their sum is not.**
  At domain 232 the user-unicast base already sits at 65411, so participant id
  63 runs past `u16::MAX`. This is reachable in ordinary use, not only from a
  hand-written constant, because `auto_assign` walks ids 0 to 119 on any
  domain. Measured: id 62 lands exactly on 65535, and id 63 panicked in a debug
  build and would have wrapped in release. `calculate()` now computes the
  highest of the four ports in `u32` and returns `Error::InvalidParticipantId`,
  so `auto_assign` stops at the last usable id instead of dying
  - The same pass hardened three `pub const fn` port helpers that cast the
    domain to `u16` before multiplying, so they wrapped rather than failing:
    domain 244 gives `7400 + 250 * 244 = 68400`, which lands on 2864. They now
    compute in `u32` and assert. **This one is hardening, not a fix, and the
    distinction is worth stating because an earlier draft of this entry got it
    wrong.** No participant could reach the wrap. Their only production caller
    is `DialectDetector::with_domain(self.domain_id)`, which receives the LOCAL
    domain, and `build()` calls `PortMapping::calculate(self.domain_id, ..)?`
    four times before constructing the detector, each returning
    `InvalidDomainId` above 232
- **`ParticipantBuilder::with_seed_peers()` did nothing.** The list was stored
  and never read. It now registers each entry as a static peer
- **Two same-process participants on custom ports without an explicit
  participant id could share a GUID prefix** and drop each other's SPDP as
  self-loopback
- **A fixed-port bind failure now names the socket and the port**, and a
  domain and participant id that cannot produce a port say so

Bindings and tools:

- **`ROS_DOMAIN_ID` reached rcl but never reached the participant**, which is
  worse than a plain hardcode. `rmw_init` did read the variable, did validate
  it, and did report it back as the context's `actual_domain_id`, so ROS
  introspection answered with the domain you had asked for. It then created
  the participant through `rmw_hdds_context_create()`, which takes no domain
  argument and built on domain 0. Every node sat on domain 0's discovery ports
  while every tool agreed it was somewhere else. The resolved id now goes to a
  domain-taking constructor; `HDDS_DOMAIN_ID` is honoured ahead of
  `ROS_DOMAIN_ID`, as the adapter's own documentation had always claimed and
  as its parsed-then-dropped config never did; and a domain above 232 that
  rcl passed in explicitly is refused with `RMW_RET_INVALID_ARGUMENT` instead
  of being bound. The same fix closes an out-of-bounds read where the FFI
  copied 24 bytes of GID into a 16-byte buffer on Iron and Jazzy
  - **Known limitation, stated here rather than left to be discovered.** On
    the environment path only, a value that is malformed or above 232 still
    falls back to domain 0 silently, with no log and no error:
    `ROS_DOMAIN_ID=500` and `ROS_DOMAIN_ID=abc` both start a node on domain 0
    rather than refusing. The range refusal above applies only to a domain
    rcl supplied explicitly
- **A ROS 2 wait set asked about the whole context instead of its own
  readers**, and the ROS introspection layout is now read from the object
  rather than guessed, which was segfaulting on Jazzy
- **The C++ SDK zeroed the liveliness lease.** `QoS::c_handle()`
  unconditionally called the liveliness setter, overwriting the C library's
  default even when the caller never touched liveliness
- *[no 1.4.x exposure]* **A WebAssembly use-after-free**: the CDR encoder was freed even on a
  buffer-too-small result, so the documented retry used a dangling handle
- *[no 1.4.x exposure]* **The InfluxDB sink's `tls` feature was dead code**, unreachable behind an
  unconditional refusal, and a 5xx response was supposed to keep the batch but
  dropped it
- *[no 1.4.x exposure]* **The schema registry answered 500 after a persistence failure while still
  serving the schema**, so a retry got a spurious 409. Registration and
  persistence are now one step under one lock, rolled back on failure
- *[no 1.4.x exposure]* **An access-control refusal taken by
  `create_writer_with_type` / `create_reader_with_type` left no trace in the
  audit chain.** Both `xtypes` entry points evaluated the signed document
  inline and then handed the QoS to the builder, which evaluates it again -
  so an allowed endpoint was decided twice and recorded once, and a REFUSED
  one was rejected before reaching the builder and therefore recorded not at
  all. The audit chain is the artefact whose whole job is to be evidence of
  what was decided, and the decisions missing from it were exactly the
  refusals. The inline copies are gone; every endpoint creation now goes
  through one door, which takes both verdicts (signed document, then local
  overlay) before writing exactly one record. At the 1.4.x baseline these two
  paths did log their own event, so the gap was opened inside this cycle
- **Every submessage of a datagram is read, and read inside its own
  bounds.** RTPS lets a peer batch submessages freely (RTPS 2.5 8.3.3), and
  several readers of the receive path stopped at the first one of a kind or
  measured a body against the whole datagram
  - Every DATA reaches discovery, each with its own INFO_TS and INFO_DST
    context: a datagram carrying one SPDP and two SEDP announcements had
    only the SPDP processed
  - Every GAP and every ACKNACK reaches reliability, and a writer services
    every ACKNACK addressed to it, not the first of the datagram: a writer
    whose request rode second never repaired (measured: zero repair packets)
  - Every embedded NACK_FRAG reaches its writer, whatever the datagram is
    classified as; one behind a HEARTBEAT or a GAP was dropped
  - Every HEARTBEAT of a datagram is answered, one malformed HEARTBEAT no
    longer hides the valid one behind it, and a big-endian HEARTBEAT is
    decoded in its own endianness (on the TCP/QUIC path, and on UDP without
    the control channel)
  - Every sample of a batch keeps its own source timestamp; samples 2..N took
    the first one's, which LIFESPAN then used
  - Each SEDP announcement and each SEDP dispose of a datagram is read from
    its own DATA, so each is acknowledged under its own writer and sequence
    number and none is missed
  - A DATA_FRAG's fragments, a DATA's inline QoS and its writer id are read
    from the octets the submessage owns; a submessage that under-declared its
    length took them from the next one, which reassembly then delivered as
    sample data
  - A fragment payload on the TCP/QUIC path stops where its submessage does;
    `[INFO_TS, DATA_FRAG, HEARTBEAT]` delivered the HEARTBEAT's octets as the
    end of the sample
  - The receive walks realign every submessage on four octets (RTPS 2.5
    9.4.1); two of them lost their place after a body whose length is not
    a multiple of four, so a batch of disposes in one datagram left
    instances ALIVE
  - The recovery after a length that runs past the datagram can stop on a
    DATA_FRAG, the case it exists for; a fragmented SPDP behind such a length
    was lost
- **An empty PAD or INFO_TS is not the last submessage.** RTPS 2.5 9.4.5.1.3:
  a length of 0 marks the last submessage EXCEPT for PAD and INFO_TS, where
  the next header follows at once. Everything after an INFO_TS that only
  invalidates the timestamp, or an empty PAD, was ignored. The INFO_TS
  InvalidateFlag now clears the timestamp (8.3.8.11), where the eight octets
  behind the header were read as a Time_t, and an INFO_TS or INFO_DST too
  short for its contents invalidates the rest of the message (8.3.4.1)
- **A DATA's inline QoS ends inside its own submessage, or there is none.**
  The inline-QoS reader walked the ParameterList to the end of the
  datagram and, finding no PID_SENTINEL, returned everything up to there:
  a DATA with an unterminated list followed by a PAD or a HEARTBEAT whose
  octets read as StatusInfo and KeyHash delivered a dispose built from the
  PAD's bytes. Every reader of that function took the foreign parameters:
  key-only detection, the router's topic lookup and dispose fallback, the
  coherent-set marker recognisers, the serialized-key reader and the SPDP
  and SEDP departure detectors. The walk now stops at the DATA's own end
  (`octetsToNextHeader`, 0 meaning "to the end of the message", RTPS 2.5
  9.4.5.1.3), and a list without a sentinel inside it is no inline QoS at
  all (9.4.2.11; an invalid inlineQos makes the DATA invalid, 8.3.8.2).
  Well-formed lists read exactly as before
- **A datagram that opens with a PAD is no longer lost.** The classifier
  named such a datagram `Pad`, and an ACKNACK behind it, or, from an HDDS
  peer or a peer with vendor id `0x0101`, a DATA of 100 octets or less, was
  never delivered
- **A submessage an INFO_DST destines to another participant is no longer
  applied here** (RTPS 2.5 8.3.8.8): it names none of our endpoints, whatever
  its entityId says, and entityIds are shared across participants as a matter
  of course. Applied on the UDP, Discovery Server relay, TCP/QUIC and shared
  memory receive paths
- **A fragmented announcement is reassembled before it is read.** A
  fragmented SPDP was parsed from its first fragment, registering the peer
  with a fixed lease, domain 0, no locators and no identity token; its
  payload offset also landed 12 octets early. A fragmented TypeLookup request
  or reply now reaches the TypeLookup service (it was never answered), and a
  builtin fragment is classified by its writer exactly like a whole DATA
- **A sample is complete when its declared sizes are satisfied**, not when a
  count of fragments arrived: 28 octets had been delivered as a complete
  64-octet sample. Short fragments are refused and long ones clipped. A peer
  that packs several fragments in one DATA_FRAG is split correctly on the
  unicast path, where its sample never completed
- **A participant first learned without an address takes one from its next
  announcement**; it stayed unreachable for good
- **A peer's routable address is preferred over a private one it does not
  share with us.** The receiver always sent to the private address of a peer
  announcing both, which across a WAN Discovery Server reached whatever
  machine held that address on the sender's own LAN. The order is now: an
  address in one of our own subnets, then a globally routable one, then the
  former choice
- **A DDS reliable reader** now
  - acknowledges under its own name, one ACKNACK per reader: a participant
    answered once for all its readers, often under an id no reader had
    announced, and a writer freeing history on acknowledgement stalled
    (measured: 4 of 40 writes, now 40 of 40)
  - applies a HEARTBEAT or GAP addressed to another reader of the same writer
    to that reader only (RTPS 2.5 8.3.8.4, 8.3.8.6)
  - records every sequence number a GAP's bitmap lists, so it stops
    requesting them, on the UDP and TCP/QUIC paths
  - delivers samples it already holds when a HEARTBEAT moves the writer's
    first sequence past a hole (RTPS 2.5 8.4.10.4); they were deleted
  - on the TCP/QUIC path, is seeded and released by HEARTBEAT and GAP like on
    UDP; a TRANSIENT_LOCAL reader fed that way delivered nothing
- **A reliable reader's WriterProxy was created only once the DDS match
  notification surfaced, not when discovery paired the endpoints**. When a
  remote participant's startup SPDP burst ended inside this participant's
  probation window (a peer may send a short burst at startup and then
  announce every 30 s, as seen in the OMG interoperability tests), the match
  stayed deferred until its next announcement (the
  probation entry below says what changed there); its writer got no proxy
  meanwhile: no ACKNACK went out under the reader's id, and the reorder
  gate waited on samples only a NACK would have fetched.
  `matched_writer_add` is a discovery event (RTPS v2.5 Sec.8.4.12): a
  reliable reader now takes its WriterProxy for a compatible writer as soon
  as discovery pairs them, ahead of the confirmation and probation gates
  that still hold back the DDS match notification itself
  - A reliable writer now does the same for a reader (`matched_reader_add`,
    RTPS v2.5 Sec.8.4.9.2, transition T1): it takes its ReaderProxy when
    discovery pairs them, with the acknowledgement watermark at the last
    change written then. Before, while a reader's match was deferred, the
    writer ignored that reader's ACKNACKs and, tracking no reliable reader,
    counted its whole history as acknowledged by all, so a VOLATILE
    KEEP_ALL writer freed what it owed a reader that had not asked yet. The
    proxy goes with the reader whether or not its match ever surfaced
  - The VOLATILE HEARTBEAT floor (the `firstSN` that hides from a late
    reader what was written before it subscribed) is taken with the first
    reliable reader's watermark at that same discovery pairing, not at the
    surfaced match: a sample written in between was owed to the reader yet
    below the advertised `firstSN`, and never repaired once lost
  - The discovery-time proxy was itself created ahead of the DDS Security
    access-control gate (DDS Security v1.1 Sec.9.3.4): a reader could answer
    HEARTBEATs and solicit history from a writer whose participant had not
    authenticated, or that access control refuses on its topic, before the
    surfaced match ever applied that same refusal. One predicate now gates
    the surfaced match, the discovery-time proxy and the reader-registration
    catch-up alike, which also closes an older hole where a reader
    registered after an unauthenticated peer's writer was matched to it once
    that participant later confirmed
  - A pairing `ShmPolicy::Require` refuses never matches, and no longer gets
    a discovery-time proxy either
- **The startup probation no longer holds back a participant whose own
  traffic proves it alive, and lets go sooner of one that does not.** The
  probation (the first 250 ms of a participant's discovery) is an HDDS
  heuristic, not an RTPS rule (RTPS v2.5 Sec.8.5.3.2 keeps a participant
  alive for its leaseDuration after each announcement): it keeps the
  buffered packets of a process that died before we started from reaching
  the application. It also withheld live peers. A peer that announced
  five times at startup and then only sent SEDP and HEARTBEATs, its next
  SPDP 30 s later (as seen in the OMG interoperability tests), had its match
  surfaced 30 s late or never
  - The probation boundary fires on our own clock, from the control
    thread's periodic wake, as well as on an SPDP or SEDP; it used to fire
    only on an SPDP or SEDP arriving after 250 ms, so with a quiet peer it
    did not fire at all
  - A participant is confirmed by its own traffic: an SPDP, a remote SEDP
    or any control message (ACKNACK, HEARTBEAT, GAP, NACK_FRAG) under its
    prefix is a liveness mark when it lands at least 100 ms after the
    participant was first heard and 100 ms after its previous mark, so a
    burst drained from a socket buffer counts once at most. Two marks, or
    two counted SPDPs, confirm it; the probation keeps a participant with
    one mark
  - A participant first heard during our probation is judged when it is
    itself 250 ms old, not at our boundary: one first heard shortly before
    the boundary could not have earned a mark yet and was purged, coming
    back only with its next SPDP
  - One that is kept on a single mark and then falls silent (no SPDP, SEDP
    or control message) for one second is purged, instead of living to its
    lease: discovery gives its readers a ReaderProxy in every local
    reliable writer, so meanwhile a KEEP_ALL writer timed out on every write
    past its depth. A participant whose matches may surface lives by its
    lease, however quiet. A purged participant that was alive after all is
    rebuilt by its next SPDP
  - One rule decides when a participant's matches surface, on every path
    (the live SEDP, the boundary's drain, the SPDP replay, the replay a late
    mark triggers, the registration catch-up): a participant first heard
    after our boundary from its first announcement; one first heard during
    the probation once it is match eligible (two marks or three counted
    SPDPs), or from the first mark it earns after the boundary. The paths
    asked different questions, so the same peer's matches surfaced on one
    path and not another
  - A local endpoint registered after the boundary is matched once its
    peer's matches may surface. The catch-up skipped a peer that could not
    surface yet and nothing queued the pairing, and the peer does not send
    its SEDP again, so the two were never matched. A match the boundary's
    drain put back is no longer left waiting for the next SPDP when an SPDP
    racing the drain brings the mark that makes its participant eligible
  - Matches released by control traffic, and the probation ticks, run on a
    discovery worker thread, not on the control thread, and the match
    registry calls listeners on a snapshot taken outside its lock: a slow
    listener stalled every HEARTBEAT and ACKNACK behind it, and a listener
    that created an endpoint from inside a match callback deadlocked. A
    listener that panics no longer ends the worker, and a callback that
    re-enters its own entry, or deletes its own endpoint, no longer
    deadlocks on the entry's dispatch gate; no callback of an entry starts
    once its unregister has returned
  - A pairing or a match dispatched for an endpoint removed meanwhile (its
    dispose or a purge landing between the deferred list and the dispatch)
    is undone; it used to stay matched, and a writer's ReaderProxy for the
    gone reader held a KEEP_ALL RELIABLE writer's history back for good. A
    participant that has sent its departure surfaces no late match
  - This participant's own endpoints surface at once, inside the probation
    too: one created in the first 250 ms was dropped by the drain as a
    zombie, since our own prefix is never among the remote participants
- *[no 1.4.x exposure]* **A participant first heard during the startup
  probation that sent two announcements and left was never matched.** The
  single surfacing rule above first required such a participant to be
  match eligible on every path, the SPDP replay included, where it used to
  replay on any SPDP after the boundary; a peer whose second SPDP landed
  after the boundary and that left before a third never had its match
  surfaced. The Discovery Server integration test caught it, though the
  Discovery Server path was not the cause. Such a participant is now also
  trusted from the first liveness mark it earns after the boundary, which
  also exempts it from the silence purge
- **A best-effort reader accepts changes the way RTPS 2.5 8.4.12.1 says**:
  only a sequence number above the highest received from that writer. A
  BEST_EFFORT + TRANSIENT_LOCAL reader received nothing from a best-effort
  writer; a BEST_EFFORT + VOLATILE one passed duplicates and reordered changes
- **A DATA reaches the reader its readerId names** (RTPS 2.5 8.3.8.2). A
  TRANSIENT_LOCAL writer's replay to a late durable reader also reached a
  VOLATILE reader of the same participant (measured: five samples), and a
  late VOLATILE reliable reader could receive the whole history through NACK
  repair; the writer now answers a request below a reader's starting point
  with a GAP, sent to that reader alone, and ignores requests from a reader
  it has not paired yet. A NACK_FRAG is sent once per missing sample, under
  the id of a local reader matched with the writer
- **A writer's history is kept per instance**, as DDS 1.4 2.2.3.18 defines
  it: a TRANSIENT_LOCAL KEEP_LAST(1) writer of three instances replayed one
  sample to a late joiner instead of three, and KEEP_LAST(2) over two
  instances lost the first entirely
- **A change is stored in the writer's history before it is sent**, and a
  VOLATILE writer frees what every matched reliable reader acknowledged; a
  KEEP_ALL writer that had filled once could never repair again, and on UDP
  pure acknowledgements never reached the writer
- **Disposes and unregisters are changes of the writer's history**: they are
  replayed to late joiners (a disposed instance arrived ALIVE), repaired on
  NACK (a GAP answered the request), replace the sample under KEEP_LAST(1),
  and reach readers in the writer's own process, which never saw them
- **A remote DataReader or DataWriter that announces its deletion leaves the
  match**; `publication_matched` / `subscription_matched` counts only went
  down when the whole participant left
- **hdds-micro reads a submessage header in the endianness it declares**:
  the gateway misread big-endian peers and forwarded them past its topic
  filter, read a length of 0 as an empty body, and encoded headers flagged
  big-endian as little-endian
- **A decrypted secure SEDP packet states its true DATA length** and keeps the
  submessages that followed it; it declared the AEAD overhead as payload and
  dropped the HEARTBEAT behind it. No loss measured, as downstream readers
  are lenient
- **The low-bandwidth transport refuses a record no frame can carry**: a
  record wider than a frame, a token bucket too small for one frame, or an
  MTU above the frame size stalled that priority queue for good with no drop
  counted. The shipped profiles are not affected
- **The low-bandwidth scheduler credits the configured rate whatever the poll
  cadence.** Refilling credited whole bytes and then moved its reference time
  to now, discarding the sub-byte part of every credit: an event loop polling
  at a cadence that does not divide a byte earned less than `rate_bps`, up to
  one byte per credit - 2 ms of link time at the LoRa profile. The remainder
  now carries until it adds up to a whole byte
- **The Discovery Server client survives a frame type it does not
  implement** (the server did too): one such frame ended the session, and on
  the relay path any client chose the frames another received
- **`reliability::ENTITYID_UNKNOWN_READER` / `_WRITER` had non-specification
  values** (see Deprecated). A GAP built by `GapTx` before its ids were set
  named a reader no participant has. Production DataWriters set the ids, so
  only direct users of `GapTx` and of the constants were affected. A 1.1.x
  writer still sends such GAPs, and a 1.5.0 reader, which honours the GAP
  readerId, applies them to no reader
- **A change the writer wrote and no longer holds is answered with a GAP
  even when the whole history is gone.** The writer told "gone" from "not
  written yet" by the newest entry of its history, so once every entry had
  left it (LIFESPAN expiry; in 1.5.0 also acknowledged changes freed by a
  VOLATILE writer), a request for one of them got neither the data nor a
  GAP, and the reader asked forever
- **The router reassembled our own fragments** when multicast brought them
  back: the self-loopback rule it applies to DATA looked for a DATA in a
  datagram of fragments and never applied. It now takes the sender from the
  RTPS header. No duplicate delivery was observed
- **`ReliableMetrics::retransmit_sent()` counts fragment repairs.** The
  NACK_FRAG repair path called the getter where an increment was meant, so
  a repair by fragments never showed. The read-only getters are
  `#[must_use]`
- **A received dispose or unregister is named by its serialized key.** A
  key-only DATA (K=1) carries "the value of the key that identifies the
  registered instance" (DDSI-RTPS v2.5 8.3.7.2), and maybe a PID_KEY_HASH,
  "a hint for the key"; "when the key hash is not received by a DataReader,
  it should be computed from the data itself" (8.7.10). The router named the
  change by PID_KEY_HASH alone and, without one, by a type-blind reading of
  the payload that knows only a leading short string and gives its
  zero-padded form. A reader now names it by the key whenever its type can
  read it, and by PID_KEY_HASH otherwise. With neither, the change names no
  instance for that reader: it is dropped, counted in the new
  `RouterMetrics::lifecycle_unnamed`, and logged once per process. The
  type-blind reading is gone: it named the zero-padded form, which is the
  instance only of a type keyed by one string of at most 11 characters,
  and on a payload the type refused it could name, and under EXCLUSIVE
  ownership release, another instance. The vendor case it was added for
  (the FinalInstanceState disposes of CoreDX, Cyclone and OpenDDS, which
  send ShapeType's key without PID_KEY_HASH) goes through ShapeType's own
  reading of its key
  - Fixed by it: a writer that sends no PID_KEY_HASH (Eclipse Cyclone DDS,
    whose `Internal/GenerateKeyhash` defaults to false) disposed nothing of a type keyed otherwise than by
    a leading short string, and disposed the zero-padded form of ShapeType's
    color where ShapeType's KeyHash is the MD5 one; a writer whose
    PID_KEY_HASH is not the reader's KeyHash disposed an instance nobody
    wrote even when it serialized the key
  - A type reads its key through the new `DDS::key_hash_of_key_payload`
    hook (default `None`, which keeps PID_KEY_HASH), built on
    `hdds::core::key_hash::KeyPayloadReader`: `#[derive(DDS)]` implements it
    for a `#[key]` type, `hdds_gen` (Rust backend) for a keyed struct whose
    KeyHolder holds no union, and the shapes demo for ShapeType. It reads
    CDR in both byte orders (XCDR1 and XCDR2, every extensibility), and a
    payload that is not CDR, truncated, over-long, out of bound or sealed is
    no key, nor is a MUTABLE member that does not fill what its length code
    says or an enumerator no literal has: the change keeps its PID_KEY_HASH
  - Still named by PID_KEY_HASH alone, and by nothing without one: a
    dispose with no serialized key (an HDDS 1.4.x writer of a generated type
    sends none), one of a type whose KeyHolder holds a union or that does
    not implement the hook, and a live sample (D=1) that carries a
    StatusInfo
- **The instance KeyHash is the one RTPS 2.5 9.6.4.8 specifies, computed by
  the library.** The `DDS` trait documented `compute_key` as an FNV-1a hash
  and returned zeros by default, so a keyed type either hand-wrote the
  specification's algorithm (only the shapes demo did) or put a value in
  `PID_KEY_HASH` that no other implementation computes for the same key. The
  default `compute_key` now serializes the KeyHolder (the key members, or all
  members of a nested type that has none, in member-id order, PLAIN_CDR2 big
  endian with alignment capped at 4) and keeps it padded to 16 bytes when the
  KeyHolder's maximum size is at most 16, its MD5 otherwise
  - A keyed type implements one new hook, `write_key_holder`, which writes
    the KeyHolder through `hdds::core::key_hash::KeyHolderWriter` and returns
    its maximum size as `Option<KeyMaxSize>`, so the size cannot be
    forgotten. A type that overrides `compute_key` is unchanged, a type with
    no key keeps the all-zero value, and so does a type that declares a key
    and implements neither (with a warning logged once)
  - `DynamicData::compute_key_hash()` computes it from the type descriptor
    through the same writer, ordering key members by the member id the
    TypeObject announces. It returns `None` for a type without key, and an
    error for a key it does not cover (a collection of non-primitive
    elements, `long double`) or a value beyond its bound
  - `#[derive(DDS)]` accepts `#[key]` on a field: the type then reports
    `has_key()`, flags the member `IS_KEY` in its TypeObject, and implements
    the hook, members in declaration order. A `String` or `Vec<u8>` key
    is unbounded, so its KeyHash is the MD5. It also emits `encode_key`, so
    a dispose or unregister of a derived keyed type carries its key (the
    key members little endian at the writer's version, behind a DHEADER
    under XCDR2 for an `@appendable` type, the derive's default) instead of
    an empty payload
  - A write computes the KeyHash once (it computed it two or three times),
    serializes the key-only payload only for an instance the writer has
    not written yet, keeps a KeyHolder of up to 32 bytes on the stack, and
    remembers per thread the MD5 of the last eight short KeyHolders, since
    a writer repeats its instances
  - The three examples of the specification, the KeyHash of the shapes
    demo's "BLUE" (which an independent transcription of the algorithm
    reproduces), and boundary vectors (a maximum of 16
    bytes padded, 17 hashed; 8-byte members aligned at 4) are golden tests
  - Generated code: `hdds_gen` emits `write_key_holder` and `encode_key`
    in its Rust backend, and the KeyHash itself in its micro, C, c-micro,
    C++, Python and TypeScript backends, since `hddsgen` 1.3 (it emitted an
    FNV-1a `compute_key` in every backend before). A key the generator does
    not cover (a map, `fixed`, `long double`, `@optional`, a collection of
    non-primitive elements) gets no KeyHolder and a comment saying why. What
    reaches the wire:
    - A Rust type generated by `hdds_gen` and written through the `hdds`
      crate puts the KeyHash in `PID_KEY_HASH` of every DATA, dispose and
      unregister, and its key in the payload of a dispose and unregister
    - The C, C++, Python and TypeScript SDKs write through the C API as an
      opaque, keyless payload: the core sends no `PID_KEY_HASH` for them
      and their generated `compute_key` does not reach the wire. Every
      sample of such a writer is one instance to the core
    - `hdds-micro` sends no inline QoS at all, so no `PID_KEY_HASH`; the
      KeyHash generated for its types stays local
    - Against 1.4.x, whose generated types computed the FNV-1a value, a
      keyed generated type does not agree on instances: see the upgrade
      notes
- **A 1.4.x writer's dispose or unregister, which carries its FNV-1a
  `PID_KEY_HASH` and no serialized key (its generated `encode_key` was
  empty), now resolves to the real instance when this reader has already
  decoded one of that writer's ordinary samples.** Every sample a 1.4.x
  writer sends -- not only a lifecycle one -- carries the same FNV hash in
  `PID_KEY_HASH`, so a reader that has seen one already knows the real
  instance it names. A participant of vendor HDDS that does not announce
  the new `CAP_CONFORMANT_KEY_HASH` capability (a 1.4.x peer, or an
  unreleased pre-bit 1.5.0 snapshot) is flagged once at its writer's SEDP
  discovery; an ordinary ALIVE sample from a flagged writer teaches the
  reader its (hash, real instance) pair, and a later dispose or unregister
  with nothing but that hash looks it up before trusting the raw bytes.
  Bookkeeping stays off the hot path for every other writer (any foreign
  vendor, any conforming HDDS peer): one relaxed flag check per packet
  while none is flagged. With no prior sample to resolve against (the
  writer's very first change for an instance is itself the unregister) the
  hash still names an instance nobody wrote, unchanged from before -- no
  reader can resolve a hash it has nothing to compare it to
- **A dynamic-type enum or bitmask is serialized in the holder its
  `@bit_bound` gives** (DDS-XTypes 1.3 7.4.3.5.3 rules 5 and 6, Table 40):
  Int8, Int16 or Int32 for an enum, UInt8 to UInt64 for a bitmask. The
  dynamic CDR codec wrote and read every enum as a 32-bit word, and the
  TypeObject bridge dropped the `bit_bound` of a received enumerated or
  bitmask type, and did not mark a received bitmask as one
  - On the wire this changes the DATA of dynamic types that hold an enum
    with `@bit_bound` up to 16, or a bitmask whose bound is not 32: those
    values now take 1, 2 or 8 bytes, as the type's TypeObject declares and
    as a generated reader of the same type expects. A 32-bit enum is
    unchanged. A received bitmask converted to a descriptor and announced
    again carries a bitmask identity instead of an enumerated one
  - The KeyHash of such a key, through `DynamicData::compute_key_hash`,
    follows the same width
  - A received `@bit_bound` outside its range (DDS-XTypes 1.3 7.2.2.4.1:
    1 to 32 for an enum, 1 to 64 for a bitmask) is read as the default, 32,
    and logged; a bitmask's 0 used to be read as a 64-bit holder
- **A member without `@id` that follows one with `@id` takes the previous
  member's id plus one** (DDS-XTypes 1.3 7.3.1.2.1.1), not its declaration
  index: `struct { long a; @id(10) long b; long c; }` is 0, 10, 11, where
  HDDS gave 0, 10, 2. Union cases follow the same rule after the
  discriminator (member 0)
  - On the wire this changes, for a dynamic type built with explicit ids
    (`FieldDescriptor::with_id`, `TypeDescriptorBuilder::field_with_id`,
    `UnionCase::with_member_id`) whose later members carry none: its
    TypeObject, so its TypeIdentifier hashes and the TypeInformation of its
    endpoints; the EMHEADER and PL_CDR parameter ids of its mutable samples;
    and, keyed, the order of its KeyHolder
  - Unchanged: a type with no explicit id or with every id explicit (every
    type received as a TypeObject is the latter), the TypeObject of
    `@autoid(HASH)` types, `#[derive(DDS)]` types, the XTypes and ROS2
    builders, and the shapes demo's ShapeType, whose TypeObject is written
    by hand
  - A mutable `@autoid(HASH)` dynamic struct announced name-hash member
    ids in its TypeObject but headed its samples' members with sequential
    ones, so no reader working from the TypeObject found them; its EMHEADER
    and PL_CDR parameter ids are now the announced hashes
- **A dispose or unregister carries the encapsulation of the writer's
  DATA.** The key-only DATA (RTPS 2.5 9.4.5.3, K=1: "the serialized Key",
  the KeyHolder of DDS-XTypes 1.3 7.2.2.4.7, which keeps the type's
  extensibility) was stamped D_CDR2_LE for every writer, and its key was
  encoded at XCDR2 whatever the writer had negotiated. A `@final` type's
  DATA is PLAIN_CDR2_LE (CDR_LE under XCDR1), so its lifecycle samples
  contradicted its data: a peer may drop such a sample, and one that reads
  a `@final` key as delimited takes its first word for a DHEADER. The K
  payload now takes the identifier a DATA of the same writer carries at
  the same version, its key is encoded at that version, and both are kept
  with the change, so a repair, a late joiner's replay and the drop-time
  unregister frame it the same way
  - Unchanged on the wire: an `@appendable` type under XCDR2, such as the
    shapes demo's ShapeType (D_CDR2_LE with a DHEADER, as before)
  - `build_dispose_packet_with_context_ts` takes the key's `CdrVersion`;
    `build_dispose_packet_with_context` keeps its signature and frames XCDR2
- *[no 1.4.x exposure]* **A NACK_FRAG asking for no fragment ended the
  dispatch of its datagram**, dropping the fragment requests and HEARTBEAT
  behind it
- *[no 1.4.x exposure]* **A dispose racing with the close of a coherent set on
  another thread could share its sequence number**
- *[no 1.4.x exposure]* **A repaired or replayed dispose now keeps its
  original source timestamp**
- *[no 1.4.x exposure]* **A Discovery Server client evicted by the server
  stayed connected, registered and deaf**, and one whose frame was only
  partly written left the stream mid-frame; it now closes and reconnects
- **One telemetry exporter per process, and an explicit stop now actually
  stops it.** Every participant build used to start its own exporter (a
  TCP listener on port 4242, else a random port on conflict) and drop its
  handle at once: only the first became the live, usable one, and every
  later participant leaked a thread and a listening socket on a random
  port that no client ever connects to, forever. A participant now shares
  the live exporter of the process, or starts it, and holds it; the last
  of its holders to drop stops the accept thread (joined) and closes the
  port. `hdds_telemetry_stop_exporter` used to only drop ONE reference to
  the shared exporter, so a user's explicit stop did nothing while a
  participant still held its own reference. It now calls
  `Exporter::shutdown()` explicitly, which shuts the exporter down right
  there, whatever else still holds it: its accept thread is joined and
  its port released before the call returns. `init_exporter`'s return
  type (`Arc<Exporter>`) and drop semantics are unchanged -- dropping it
  stops the server only when it is the last holder, same as any other
  `Arc<T>`; a caller that wants the same forced stop as the C ABI calls
  `Exporter::shutdown()` itself rather than relying on drop. A participant
  that was sharing the exporter when it is force-stopped is not affected
  beyond losing its export -- it keeps running, and its telemetry pushes
  become no-ops rather than a panic or a stuck call. Starting the
  exporter again afterwards (`hdds_telemetry_start_exporter` /
  `init_exporter`) opens a genuinely working server, which also becomes
  the one later participants share, rather than reusing the stopped one
- **A participant's drop is synchronous: by the time it returns, every
  thread it started has ended, its unicast ports can be bound again, and
  nothing holds its transport.** Its threads (multicast listeners, the
  control handler and discovery worker, the router, the SHM receiver, the
  SPDP announcer, unicast routing, QUIC I/O, the lease tracker, the K8s
  discovery poll, the TypeLookup tick, the security stateless writer, and
  the telemetry push and exporter accept threads) are each joined bounded:
  a warning past 2 s, given up past 10 s with an error log, and never the
  calling thread (which cannot join itself). A thread past its give-up is
  left to end on its own; what it holds is released only when it does.
  Dropped from inside one of its own listener callbacks -- which runs on a
  discovery thread already holding a lock the teardown would otherwise
  wait on -- the drop hands its teardown to a thread of its own instead of
  deadlocking, and returns at once; its resources release once that
  callback returns. Everywhere else the teardown runs inline, the same
  way as before. Building the same participant id again right after a
  drop no longer races its own leftover threads or sockets for the port
- *[no 1.4.x exposure]* **A GROUP coherent set's own end-of-set marker was
  counted as a lost sample.** The marker (RTPS v2.5 Sec.8.7.5) reserves a
  writer sequence number of its own but carries no application sample, and
  was never admitted into the reader's duplicate record (`on_ecs`): once a
  HEARTBEAT purged a GROUP set that could never complete, SAMPLE_LOST (DDS
  v1.4 Sec.2.2.4.1, "a sample has been lost") re-read the marker's own
  sequence number as a DATA sample never received and counted it alongside
  the set's genuinely lost DATA samples. The marker is now admitted like any
  other change the writer sent, so SAMPLE_LOST counts only DATA samples
- *[no 1.4.x exposure]* **A GROUP-scope reader's per-writer GSN record
  (`writer_gsns`, the spec-dialect GROUP checks of RTPS v2.5 Sec.8.7.5) was
  never forgotten.** A writer that left, or whose participant was lost,
  left its entry behind forever. It now goes when the writer says it left
  (its SEDP dispose, its participant's farewell), so a writer re-created
  under the same GUID is checked for "strictly monotonically increasing"
  GSNs from its own start; and, for a writer that only fell silent (lease
  expiry), when its departure is itself forgotten without it coming back.
  Until then the record is kept, so the same writer returning with a GSN
  gone backward still breaks its set.
- **The local permission file watcher could apply a torn write, could
  silently stop reporting an unreadable file, and a manual reload could
  make it log a spurious second change.** `watcher_poll_cycle` reloaded
  whenever the file's mtime changed and trusted whatever `read_to_string`
  returned on the first try; a writer that rewrites the file
  non-atomically (truncate then write, as most editors and `echo >` do)
  can be read mid-write, and the torn result can still be a syntactically
  valid document -- an empty file parses as zero grants, a file cut after
  some lines as a valid subset. Since this file exists only to TAKE
  PERMISSIONS AWAY, applying either one is not harmless, and if the final
  write happened to land on the same mtime tick as the torn read, the
  complete content was never reloaded again. The watcher now decides a
  reload on CONTENT, not mtime: a read whose own `(len, mtime)` changed
  while it was being read is discarded outright, and a new content is
  applied only once it has been read identically on two consecutive polls
  (compared directly, not through a hash -- the file is small enough that
  a hash only bought a collision question this did not need). Separately,
  a read error (permission revoked, the file deleted and never replaced)
  used to return silently with no audit trail, so a file that stayed
  unreadable gave no operator signal ever again; it now logs a `FileError`
  once on the readable-to-unreadable transition, stays quiet on repeated
  polls of the same outage, and logs again once a read has succeeded in
  between and a later one fails anew, while the document already in force
  is left untouched throughout. And the manual `reload()` API used to
  update only its own `last_mtime`, leaving the watcher's debounce still
  believing the content from before that reload was the one settled; the
  watcher would then read the just-applied content as if unseen and, once
  it read it twice in a row, re-apply it and log a spurious second
  `FileReloaded` for a change already in force -- `reload()` now settles
  the watcher's state too, through the same single recorder the watcher
  itself uses. Operators should still prefer an atomic replace (write a
  temp file, then `rename` it over the target) over relying on the
  debounce, and must not regenerate the file continuously: content that
  never reads identically on two consecutive polls is, by the same
  mechanism, never applied either
- **A remote participant of vendor RTI Connext negotiating XCDR1 for a type
  that contains `wchar`/`wstring` is now refused at matching, both
  directions, instead of exchanging wrong values silently.** RTI documents
  Connext's XCDR1 `wchar` encoding as 4 bytes (`Char32`); DDS-XTypes v1.3's
  conformant width, which HDDS encodes and decodes, is 2 bytes. Measured: a
  Connext writer's XCDR1 `wchar`/`wstring` samples arrived at an HDDS reader
  with wrong values, silently (the 2-byte decode of 4-byte data happens to
  parse); an HDDS writer's XCDR1 `wchar`/`wstring` was refused outright by
  Connext. Neither side can tell the width from the wire bytes alone, and no
  XTypes bit announces it, so the pair is now refused at the one QoS verdict
  (`match_notification::rxo_verdict`) rather than matched: a remote of vendor
  RTI (Connext DDS 0x0101 or Connext Micro 0x010A; resolved once at
  pairing from SPDP, the vendor zone,
  `DiscoveryFsm::vendor_id_for_participant`), negotiating XCDR1
  (`cdr_negotiation::pair_effective_cdr_version`), whose local type contains
  `wchar`/`wstring` anywhere in its structure -- struct and union members,
  aliases, sequence/array/map elements and keys, followed transitively
  through a locally-registered nested type
  (`cdr_negotiation::type_contains_wchar`) -- is reported
  OFFERED/REQUESTED_INCOMPATIBLE_QOS on the DATA_REPRESENTATION policy,
  counted (`cdr_negotiation::rti_xcdr1_wchar_refusals`), and logged. An RTI
  peer that negotiates XCDR2 instead (XCDR2 `wchar` is 2 bytes, conformant
  per the same RTI documentation) is unaffected -- the existing negotiation
  already prefers XCDR2 over refusing when both sides offer it. HDDS<->HDDS
  and every other vendor are unaffected. Perimeter: the check reads the
  LOCAL type's TypeObject (every `hdds_gen` type has one); a hand-written
  type without one, or a build without the `xtypes` feature, cannot be
  checked and is matched as before, with a debug log line saying so
- **`core::ser::pl_cdr2::decode_pl_cdr2_struct`, a public PL_CDR2
  mutable-struct decoder, accepted only length code 4 (NEXTINT) and silently
  read the REST OF THE STRUCT PAYLOAD as a member's length for every other
  length code (0-3, 5-7), and its own doc wrongly called length code 5
  DHEADER-based and 6/7 reserved.** DDS-XTypes v1.3 7.4.3.4.2 defines all
  eight: 0-3 an implicit 1/2/4/8-byte member (no NEXTINT); 4 an explicit
  NEXTINT byte count (not itself part of the member); 5/6/7 a NEXTINT reused
  as the member's own leading word, length `4 + NEXTINT * 1/4/8`. A struct
  with an earlier member at any length code but 4, or any member at 5/6/7,
  had that member's bytes misread as reaching the struct's end, silently
  absorbing every member after it. The function has no production caller in
  this crate (only `tests/pl_cdr2_poly3d.rs` and the decode fuzz target, both
  exercising only this crate's own encoder, which always chooses length code
  4), so no shipped wire behavior changes; it was a public API that lied
  about the spec and a third, divergent copy of the length-code rule in the
  crate. Fixed by extracting the rule once
  (`core::ser::pl_cdr2::emheader_member_extent`), shared with
  `dynamic::cdr_dynamic::CdrDecoder::read_emheader_member` (the struct/union
  XCDR2 mutable-member walker), which already implemented the rule correctly
  and now calls the same function instead of carrying its own copy.
  `core::key_hash::payload::KeyPayloadReader::read_emheader` (the key-hash
  reader, also already correct) keeps its own, genuinely independent copy --
  a new test cross-checks the two against identical spec-built bytes for
  every length code. Separately investigated: whether `hdds_gen`'s five
  generated-code backends (Rust, C, C++, Python, TypeScript) accept length
  codes 5-7 on decode -- they do, each with its own correct implementation of
  the same `4 + NEXTINT * 1/4/8` rule, matching the two production readers in
  this crate. A measured Connext `sequence<enum>` mutable member using
  length code 6 is not explained by a length-code bug anywhere in this tree;
  it is the documented consequence of RTI's XTypes compliance mask treating
  an enum as a collection primitive by default (no inner DHEADER needed,
  length code 6 is self-describing), where HDDS's own encoder, following the
  spec's default (an enum is not a collection primitive), chooses length
  code 5 with a DHEADER for the same member -- a layout difference tracked
  separately (decision 2026-10-23), not a conformance
  defect in any decoder
- **A `TransportMode::IntraProcess` participant never raised
  PUBLICATION_MATCHED/SUBSCRIPTION_MATCHED or OFFERED/
  REQUESTED_INCOMPATIBLE_QOS, same participant or across two.**
  IntraProcess builds no `discovery_fsm`, so `Participant::match_registry`
  is always `None` and the SEDP-fed `MatchNotificationRegistry` that
  reports those statuses for every other transport mode never even runs:
  `matched_reader_count()` stayed 0, no listener fired, and no counter
  moved, however many compatible local writers and readers were created,
  in one participant or in two of the same process. The data path was
  unaffected (domain_registry.rs's own auto-bind already delivered these
  pairs); only the application-visible status was silent. Fixed in
  domain_registry.rs with a second, narrower status path
  (`LocalMatchStatus`), driven by the exact same QoS verdict the
  data-path bind already reads (`qos_verdict`/`scope_allows`, what
  `pair_delivers` composes them into) rather than a second copy of the
  rxo rules, so a pair is never matched on one path and refused, or
  reported, on another; `DataWriter::matched_reader_count()` now falls
  back to it when there is no `MatchNotificationRegistry` token to read
  instead. current_count also drops when a matched IntraProcess peer is
  deleted. (The UDP transport's own gap in this area -- a writer and a
  reader of the SAME participant not matching each other at all -- was
  already fixed separately; see "A writer and a reader of the SAME
  participant match each other" above.) Two gaps in this first cut are
  fixed separately below: `LocalMatchStatus` was wired up ONLY for a
  participant with no `match_registry` at all, and its callbacks could
  run while `domain_registry.rs`'s own registry lock was still held.
- **A late IntraProcess reader catching up to an existing TRANSIENT_LOCAL
  writer could be handed its replayed history before being told the
  writer matched.** Once the entry above gave IntraProcess pairs a
  SUBSCRIPTION_MATCHED/PUBLICATION_MATCHED path at all, the order it and
  the history replay (`TopicMerger::add_reader`, already correct) fire in
  needed checking: domain_registry.rs now reports the match to both ends
  BEFORE calling the data-path bind that replays the writer's history into
  the late reader's ring, matching the DDS v1.4 Sec.2.2.4.1 order a remote
  pairing over UDP already kept.
- *[no 1.4.x exposure]* **A listener reached from inside domain_registry.rs's own registration
  or unregistration could deadlock the thread against itself.**
  `DomainState::register_writer_with_match`/`register_reader_with_match`
  (registering an endpoint) and `unregister` (an endpoint's drop) all
  decide PUBLICATION_MATCHED/SUBSCRIPTION_MATCHED/OFFERED-or-
  REQUESTED_INCOMPATIBLE_QOS while holding `endpoints`, a plain,
  non-reentrant `RwLock`, and reach the application's listener through
  `notices::notify`. Unlike the SEDP path (`MatchNotificationRegistry`),
  which always opens a `notices::Scope` before dispatching, nothing made
  that call deferred here: `register_reader_with_match`'s caller in
  reader/builder.rs happened to wrap it in its own `Delivering::enter()`
  (for an unrelated reason -- ordering a TRANSIENT_LOCAL replay after the
  match), but `register_writer_with_match` had no such wrap at all, and
  neither did `unregister`, reached from any `DataReader`/`DataWriter`
  drop. A listener that creates or deletes an endpoint on the same domain
  from inside such a callback -- for example a reader's
  on_subscription_matched building a replacement writer when its matched
  writer is dropped -- re-took the same lock on the same thread and hung
  forever. Fixed by moving the deferral into domain_registry.rs itself,
  at the one place that takes the lock: each of the three functions now
  opens its own `Delivering::enter()` before acquiring `endpoints`, so
  any listener a registration or unregistration reaches is told only
  after that function has released the lock, whichever of the three
  functions is reached and whether or not its caller already wraps it.
- *[no 1.4.x exposure]* **Counted did not always equal delivered for a mixed-transport pair.**
  domain_registry.rs's data-path bind (`scope_allows`) correctly covers
  any pair where at least one endpoint has no wire path at all (an
  IntraProcess endpoint is never announced over SEDP, so this registry is
  the only route for it), but the match-status fix above only gave
  `LocalMatchStatus` to a participant with no `match_registry` at all: an
  IntraProcess writer paired, through this registry, with a
  UdpMulticast-transport reader of a DIFFERENT co-located participant
  delivered the sample (the data path has always followed `scope_allows`
  correctly) while that reader's PUBLICATION_MATCHED-side counterpart
  (SUBSCRIPTION_MATCHED) stayed at `current_count` 0 forever: its
  participant's `MatchNotificationRegistry` was waiting for an SEDP
  announcement the IntraProcess writer can never send. Fixed by building
  `LocalMatchStatus` for EVERY endpoint with a participant, not only one
  with no `match_registry`, and firing it (new predicate
  `local_status_applies`, narrower than `scope_allows`) only for a pair
  where the peer has no wire path either: a same-participant pair where
  BOTH sides are wire-capable is still SEDP's loopback to report alone,
  never double-counted by this always-built fallback.
  `DataWriter::matched_reader_count()` now sums its
  `MatchNotificationRegistry` token's count with `LocalMatchStatus`'s
  (disjoint peer sets by construction, so the sum is never a
  double-count).
- *[no 1.4.x exposure]* **The BuiltinParticipantMessageWriter/Reader pair
  was not actually RELIABLE.** RTPS v2.5 Sec.8.4.13.3 fixes this pair's
  QoS: durability TRANSIENT_LOCAL, history KEEP_LAST depth 1, the writer
  RELIABLE. An ACKNACK naming our writer fell through to the generic
  topic-registry branch, which answers by looking up a DDS topic writer
  by GUID (this builtin endpoint keeps no history there), so it was never
  answered: no retransmit, no GAP. A remote participant's writer HEARTBEAT
  matched no route either (its entity kind is neither a user writer's nor
  SEDP's or TypeLookup's), so it was logged and dropped as an unhandled
  builtin endpoint: we never ACKNACKed it, so a peer's reliable writer
  never learned we held its assertion and never repaired one we lost.
  Both sides now answer as the reliable KEEP_LAST(1) pair the spec
  requires: an ACKNACK gets the current sample while the peer still lacks
  it, or a GAP for whatever it superseded; a HEARTBEAT gets a positive ack
  of what is held, or a request for the newest sequence number alone,
  since an older assertion has no value under KEEP_LAST(1)
- **A writer with no transport (`TransportMode::IntraProcess`, or any
  writer not yet matched with a remote peer) recorded its coherent sets
  with no set membership at all**, in both directions. Live: the writer's
  intra-process fast path never computed `PID_COHERENT_SET` /
  `PID_GROUP_COHERENT_SET` for a non-GROUP writer, and the general
  write() path only computed them inside its UDP-send branches (dead for
  a writer with no transport at all), so a co-located coherent-access
  `DataReader` saw every member of an open set the instant `write()`
  returned instead of atomically with the rest of its set (DDS v1.4
  Sec.2.2.3.6). History: `HistoryCache::snapshot_for_local_replay` kept
  no `ChangeKind` and applied no per-writer closed/open boundary, so a
  late-joining local reader replayed every retained sample as
  independent, including a set the writer never closed (RTPS v2.5
  Sec.8.7.6: an unfinished coherent set must not be delivered). Fixed:
  the coherent markers are computed wherever a sample is journaled,
  whatever the transport; `snapshot_for_local_replay` withholds any
  member whose set has no closing (`EcsClose`) marker in the retained
  history (a close always takes a fresh SN strictly after every member it
  closes, so the highest retained close SN is a sufficient per-writer
  boundary); and a member's local delivery is held back per writer until
  its set is both closed and complete, then delivered whole, in order.
  The close never waits for a member still on its way, and a write that
  fails is left out of its set (the application got the error, as a GAP
  leaves a change out on the wire); see the in-cycle entry below for how
  the set completes. `WriterCoherentBridge::emit_ecs_data` also returned
  before journaling anything for a writer with no RTPS endpoint context
  at all (built without a participant -- unreachable through the public
  `topic.writer()` API, but exercised by this crate's own low-level
  coherent wire tests): it now journals the close regardless.
- *[no 1.4.x exposure]* **`HistoryCache::snapshot_for_local_replay` carried
  no `ChangeKind`, so the intra-process replay of ANY durable coherent
  writer's history (whatever its transport) included its `EcsClose`
  entries undistinguished from an ordinary user change** -- an
  empty-payload slot that exists only to carry the set's close (RTPS v2.5
  Sec.8.7.6), fed to a late joiner's decoder exactly like a real sample.
  Fixed by the same change as the entry above, which excludes every
  `EcsClose` entry from a local replay outright.
- *[no 1.4.x exposure]* **The first intra-process staging of coherent sets
  in this cycle (`1ae3bde6`) lost or misattributed a member racing the
  set's close, and its correction (`94fa8cee`) could freeze the whole
  Publisher.** A coherent write marks its change a member of the open set
  under the Publisher's lock, then serializes, journals and stages it
  with no lock held. The close drained the writer's staging queue at
  once: a write preempted between the two steps landed in a queue already
  drained for its own set, lost if the writer never closed a set again,
  delivered with a later set it was never a member of if it did. The
  correction made the close wait, still holding the Publisher's lock, for
  every marked write to stage; a marked write that failed before staging
  (its journal timing out on a full RESOURCE_LIMITS history after
  `max_blocking_time`, slab exhaustion, an encode error) needs that same
  lock to give its sequence number back, so the two waited for each other
  forever, and every later write or set of the Publisher with them. The
  same flush, run under the lock, also deadlocked a co-located reader's
  listener that began or ended a set on the same Publisher. Now: marking
  a change registers an outstanding member of its set; the write later
  stages its sample, or, failing, withdraws it. The close only marks the
  set closed under the lock, never waiting, and delivers with the lock
  released. A set is delivered by whichever of its close, its last stage
  or its last withdrawal comes last, sets of one writer strictly in
  order, one delivering thread at a time; the readers' listeners that
  delivery runs may write, or begin and end a set, on the same Publisher.
- *[no 1.4.x exposure]* **A VOLATILE coherent writer with no confirmed
  remote reader never delivered its sets to co-located readers, in this
  cycle (`1ae3bde6`).** Its sets are kept off the wire (no end of set is
  sent before a remote reader is confirmed), and the flush of its staged
  local deliveries sat after that early return in
  `WriterCoherentBridge::emit_ecs_data`: each set was held back and never
  released. Local delivery no longer goes through the wire close at all
  (see the entry above): a VOLATILE writer's co-located readers get each
  set whole at its close.
- *[no 1.4.x exposure]* **A writer matched with BOTH a co-located reader
  and a remote peer delivered its co-located reader's share of an open
  coherent set at once, through the merger, instead of holding it back
  for the close (DDS v1.4 Sec.2.2.3.6).** `write()`'s mixed branch (local
  AND remote readers; the intra-process-only fast path above is a
  separate branch and was not affected) took a `CoherentStamp` for the
  change's wire tags, like every coherent write, but never staged it: the
  merger push ran at once and the unused stamp silently withdrew on drop,
  so a co-located coherent-access reader of such a writer saw every
  member of a set the instant `write()` returned, while the same writer's
  remote (wire) readers correctly waited for the set's end. Fixed: the
  mixed branch now stages through the same `CoherentStamp` the
  intra-process-only fast path uses, withholding the co-located delivery
  until the set is closed and complete.
- *[no 1.4.x exposure]* **A dispose or unregister issued inside an open
  coherent set reached a co-located reader at once, never held back with
  the rest of the set.** `emit_lifecycle_change` took a `CoherentStamp`
  for the change's wire tags, like a sample, but dropped it on the spot
  and delivered to co-located readers unconditionally
  (`push_lifecycle_to_local_readers`): a dispose or unregister is a
  member of its set like any other change (DDS v1.4 Sec.2.2.3.6), and a
  coherent-access reader could observe it ahead of the set's close. Hit
  both a lone intra-process writer (no transport) and any writer with a
  transport (UDP, matched or not yet with a remote peer). Fixed: the
  stamp is now carried to the local delivery, staged with the set when
  there is a co-located target, withdrawn otherwise.
- **A manual `DynamicPermissionManager::reload()` could silently skip a real
  permission-file rewrite.** It decided whether to reload by comparing the
  file's mtime alone; a non-atomic rewrite (truncate then write, as most
  editors and `echo >` do) that lands within the same filesystem timestamp
  tick reads as "unchanged" and the new, more restrictive rules are never
  applied -- for a file whose only job is to take permissions away, a
  silently un-applied restriction is a security defect, not a no-op. The
  background watcher thread already decided this on file CONTENT, through a
  debounce that rejects a torn read; `reload()` now shares that exact same
  state instead of keeping its own mtime-only copy, so the two can never
  disagree about what is currently applied, and a manual reload applies any
  real content change on its first call, mtime included or not.
- **A GROUP coherent set of the 1.4.x wire was delivered in part, and its
  last part never, when one writer still owed a change before its part.**
  A set spanning two writers was flushed once both had ended it, even while
  the gate of one of them was still waiting for an earlier change of that
  writer (a repair in flight, or the GAP for a change not sent to this
  reader). That writer's part was held in its gate and the other part went
  to the application; the held part was released later on its own, outside
  its set, and across a Subscriber's readers the other reader's part waited
  for a generation that never came, for good: the last set of a burst of
  `{1,2} {3} {4,5}` over two topics arrived as `{4}`. DDS v1.4 Sec.2.2.3.6
  wants the set whole. The rule that already held a set of the spec
  dialect until every writer's gate reached its part now holds a set of
  any dialect, but a vendor 0x0101 writer replaying without end markers,
  whose hole below the part the flush steps over itself.
- *[no 1.4.x exposure]* **A reader of the 1.4.x GROUP wire counted a sample
  lost for every set a writer wrote nothing in.** Such a writer still ends
  the set; a reader that does not speak the spec GROUP dialect is not sent
  that end, and is told by a GAP that its sequence number is not for it.
  The GAP was a plain one, which a receiver must read as changes that left
  the writer, and HDDS counted one SAMPLE_LOST each time (DDS v1.4
  Sec.2.2.4.1 counts samples never received; this number carried none).
  The GAP now has its FilteredCountFlag set and a filteredCount of 1 (RTPS
  v2.5 Sec.8.3.8.4, Sec.9.4.5.6; Sec.8.4.9.2: filtered changes are not
  samples lost), both when the end is sent and when it is repaired. The
  parsers of HDDS 1.4.8, Cyclone DDS, Fast DDS, OpenDDS 3.34 and dust_dds
  read no flag of a GAP but E and skip what follows the gapList, so the
  extra element changes nothing for them.
- **A TOPIC or INSTANCE coherent set committed behind an earlier change
  of its writer still owed went to the application outside its set and
  outside its Subscriber's barrier.** The set was committed once its own
  changes were all received, even while its writer's gate still waited
  for an earlier change of that writer (a repair in flight, a GAP still
  to come). Its samples were held in the gate and released later as plain
  changes: never deposited in the Subscriber's presentation barrier, where
  the sets of the Subscriber's other readers waited for them. A set now
  waits until its writer's gate can pass it, the rule a GROUP set's part
  already follows (`ReorderGate::would_hold`), and is decided again when
  the gate moves (a GAP, a HEARTBEAT, the owed change delivered, an
  earlier set decided). DDS v1.4 Sec.2.2.3.6.
- **DEADLINE (DDS v1.4 Sec.2.2.3.7) was evaluated only when the application
  called `take()`/`read()`/`write()`: an application blocked on a WaitSet,
  or relying only on a listener, was never told a REQUESTED_DEADLINE_MISSED
  or OFFERED_DEADLINE_MISSED (Sec.2.2.4.1) had happened, for as long as it
  made no further call.** The per-reader/per-writer tracker also missed one
  period's worth of silence per call, not per elapsed period (Sec.2.2.4.1:
  "each deadline period the total_count will be incremented by one"), and
  tracked one timestamp for the whole entity rather than one per instance.
  DEADLINE is now evaluated per instance on the same scheduler thread
  LIVELINESS already runs on each participant (one timer per instance,
  re-armed every elapsed period while the instance stays silent); the
  take()/read()/write() check still runs, sharing the exact same
  evaluation and lock, so the two never disagree about what was already
  reported. A disposed instance stops being watched; a reader retains
  its watch in NOT_ALIVE_NO_WRITERS so DEADLINE can report lost periodic
  connectivity (Sec.2.2.3.23.2). A writer stops watching on unregistration.
  Explicit writer registration starts monitoring before the first write;
  repeating registration preserves an active period and keeps a disposed
  instance untimed (Sec.2.2.2.4.2.5, Sec.2.2.3.21).
  An infinite deadline (the default) creates no timer or timestamp store.
  Finite updates use an instance lookup and a publication lock around the
  clock capture and relaxed timestamp store, nothing added to a cached
  sample. With a participant scheduler, the lazy write check evaluates
  only the written instance in O(1); the scheduler handles other instances.
  A standalone writer has no scheduler and checks all active instances on
  each write, so a silent instance is still reported while others update.
  Cancellation and rearming compact stale heap entries to bound storage by live watches plus fixed
  slack.
  **Rust API change:**
  `RequestedDeadlineMissedStatus`/`OfferedDeadlineMissedStatus::last_instance_handle`,
  declared since 1.4.x but never populated, now has type
  `Option<InstanceHandle>` and reports the full 16-byte instance handle.
  The previous `Option<u64>` could not distinguish keys sharing their first
  eight bytes. The legacy C offered-deadline callback retains its existing
  `uint64_t` parameter and receives the leading eight bytes, big-endian.
  Reader timers start when samples are delivered, including local delivery,
  rather than when the application consumes them. Timely updates made
  before the scheduler runs cannot create a false miss: evaluation and
  timestamp publication share per-instance arbitration, including arrivals
  paused after clock capture. A late resumption preserves every period
  preceding its arrival, without counting periods after that arrival.
  Disposal, or writer unregistration, records periods already elapsed
  before stopping future ones. A committed write updates its deadline state
  before writer or local reader callbacks can dispose or unregister that
  instance, so returning from the write cannot restart a retired timer.
  Zero-period deadlines are explicitly
  rejected at endpoint creation because periodic scheduling cannot realize
  an unbounded update rate.
- **A coherent-access, default-partition reader could revive a NOT_ALIVE
  instance, or receive data at all, from a remote writer this participant
  never discovered via SEDP.** *[no 1.4.x exposure]* The plain DATA path is
  protected by the OWNERSHIP data-plane gate's resolve-or-defer (an
  undiscovered writer's sample is held, never delivered), and a
  non-default-partition reader's PARTITION gate already drops an
  undiscovered writer outright; coherent staging committed straight to the
  cache with neither protection, and a default-partition reader bypasses
  the PARTITION gate entirely. A writer this participant has never
  discovered via SEDP (RTPS v2.5 Sec.8.4.15's matched-writer-proxy
  requirement) now has no standing to stage a coherent sample, resolved
  through the engine's durable GUID->topic record rather than the live
  discovery FSM so a departing writer's own last, already-queued change
  is never mistaken for one that was never discovered at all.
- **A decode failure mid-merge on a reader fed by two or more writers (the
  K>1 ring-merge path) discarded every OTHER writer's already-admitted,
  already-acknowledged sample instead of keeping it.**
  *[no 1.4.x exposure]* DDS v1.4 Sec.2.2.3.19 footnote 28 / RTPS v2.5 Sec.8.4.12.2.8:
  a change already added to reader history is kept, or its writer is
  allowed to retransmit it; an ACK does not license discarding it. Each
  such sibling is now delivered through the ordinary path instead of
  discarded; only one that ALSO, independently, fails to decode there
  truly cannot be kept, and is the only thing SAMPLE_LOST now counts for
  this path -- reported through the one existing door
  (`ReaderSubscriber::report_sample_lost`, which notifies an installed
  listener and the WaitSet) rather than a second, listener-less counter.
- **An unknown remote writer's DISPOSE/UNREGISTER (D=1/Q=1 DATA with
  inline KeyHash and a disposed StatusInfo) could still move a reader's
  instance state.** *[no 1.4.x exposure]* `writer_refused` answers false
  for a writer this reader has never judged at all, the same gap already
  closed on the coherent staging door; the lifecycle path reaches the
  reader independently of the deferred OWNERSHIP verdict on the sample
  value, so it needed the same `writer_undiscovered` gate (RTPS v2.5
  Sec.8.4.15: no matched writer proxy, no standing to move instance
  state).
- **A remote writer's OWNERSHIP strength, OWNERSHIP kind, and GROUP
  dialect record were not retired when its participant announced its own
  departure, only when the writer itself was explicitly disposed; the
  topic's minimum finite Lifespan was never recomputed when the writer
  holding it departed, by either path.** The OWNERSHIP-kind and GROUP
  dialect parts have no 1.4.x exposure (neither record existed there);
  the strength leak on an announced participant departure, and the stale
  topic-minimum lifespan, predate this cycle. All three durable per-writer
  records are now retired together, in the one place both removal paths
  reach, and still preserved (by design) across an unannounced departure
  (a lease expiry or a probation purge), since such a writer may return
  under the same GUID with no new SEDP at all. The topic's minimum
  Lifespan is recomputed from the writers still recorded whenever the
  departing writer (Deleted or Unheard) had a finite one of its own (DDS
  v1.4 Sec.2.2.3.16: a sample expires by ITS OWN writer's lifespan, never
  a departed one's). The writer's GUID->topic routing entry is
  deliberately NOT retired here: a participant-level departure finds its
  writers by filtering that same map, so retiring an individual writer's
  entry on its own dispose would make it invisible to a later departure
  of its whole participant.
- **`dispose_w_timestamp` / `unregister_instance_w_timestamp`'s
  application-supplied source timestamp never reached the reader: the
  resulting NOT_ALIVE `SampleInfo::source_timestamp_ns` was always
  absent, and the local writer-side path stamped the current clock
  instead of the supplied timestamp.** *[no 1.4.x exposure]* The
  timestamp of the datagram (or, for a local writer, the change's own
  source timestamp rather than `current_time_ns()`) now carries through
  to the transition's `SampleInfo` (DDS v1.4 Sec.2.2.2.5.5), and
  survives two transitions of the same instance coalescing into one
  queued notification. At the time this was written, DESTINATION_ORDER
  BY_SOURCE_TIMESTAMP did not yet read it for cross-writer ordering;
  that separate, larger change is implemented below.
- **A TOPIC/INSTANCE-scope coherent set whose every member was rejected for
  storage could consume a generation of its own in the cross-reader
  presentation barrier.** *[no 1.4.x exposure]* Such a set's payload list is
  non-empty by length alone (every entry a placeholder carrying no sample),
  so neither the barrier's own empty-set guard nor the TOPIC-scope deposit
  path caught it; deposited anyway, with a second reader on the same
  Publisher it could pair with that reader's real generation and strand a
  later real generation of its own behind a round the barrier believed
  already delivered. GROUP scope already filtered this; the TOPIC-scope
  door now does too.
- **A SAMPLE_LOST listener that called `take()` of its own deadlocked on
  the reader's own consumer gate.** *[no 1.4.x exposure]* The mid-merge
  SAMPLE_LOST report ran the listener inline while `take()`'s consumer
  gate -- and, for the K>1 merge path, the bindings mutex and the network
  consumer guard -- were still held; a reentrant `take()` call then spun
  on that same, non-reentrant gate forever. `take()`, `read()`, and the
  three condition-evaluation accessors now enter the reader's existing
  deferred-notification scope before taking the gate, the same discipline
  every other delivery path in this reader already follows, so a held
  notice is told only once every lock the call took has released.
- **A reader whose cached Lifespan had already gone finite from one
  writer's short announcement never looked at the registry again for the
  rest of its life, even after that writer departed and the registry's
  minimum for the topic changed or disappeared entirely.** The epoch
  check `probe_writer_lifespan` uses to skip its own expensive lookup was
  gated on the cached value still being "no limit"; once a writer's
  finite Lifespan set it, the gate never reopened. The cheap half of the
  probe (one atomic epoch load) now always runs; the expensive half (the
  registry lookup) stays gated on the epoch having actually moved, so a
  later increase, decrease, or removal of the topic's minimum (DDS v1.4
  Sec.2.2.3.16: a sample expires by ITS OWN writer's lifespan, never a
  departed one's) still reaches a reader that had already settled on a
  finite value.
- **A reader's strong hold on its own subscriber, kept alive past the
  point where giving a history room's places back could schedule a
  coherent set's weak-reference retry of room it was still waiting for,
  let that retry's `Weak` upgrade still succeed after `Drop::drop` had
  already drained this reader's own ring.** *[no 1.4.x exposure]* A
  successful, late upgrade could commit the waiting set into an
  already-drained ring with no remaining consumer -- a leaked slab
  handle, and a DATA_AVAILABLE raised after teardown. `Drop::drop` now
  releases this hold explicitly, alongside the token that stops the
  reader's own network fanout, before any of the cache or ring teardown
  that follows: the retry's upgrade then finds it already dead, as it
  would have before this hold existed.
- **A decode failure mid-merge (the K>1 ring-merge path) flushed every
  other already-parked sibling out of its own ring's timestamp order,
  ahead of that same ring's own still-unpopped next entry.** Two writers
  queued, say, [a poisoned change, then a good one] and [one good change
  sent after both of the first writer's]: the poisoned change's failure
  deposited the second writer's change at once, and the first writer's
  own good change only landed on a later pump, behind it -- under
  KEEP_LAST(1) this could keep the older of the two good changes instead
  of the newer one. The merge now keeps draining, in the same timestamp
  order a fully successful pass would use, after a decode failure: a ring
  whose head just failed is refilled from its own next entry like any
  other, and every entry, parked or freshly popped, competes purely by
  timestamp. The first decode failure in a drain is still that call's own
  `Err`; a later one in the same drain counts toward SAMPLE_LOST, as
  before.
- **Coalescing two writers' dispose/unregister transitions into one
  queued notification could keep the OLDER transition's source timestamp
  and writer, because the comparison that decided which one to keep
  compared the two writers' own sequence numbers directly -- numbers from
  two independent streams that DDS promises no order between at all (DDS
  v1.4 Sec.2.2.3.19).** *[no 1.4.x exposure]* A writer whose own sequence
  happened to run higher than a chronologically later transition from a
  different writer kept its own, earlier timestamp reported to the
  application. The comparison is now trusted only when both transitions
  name the same known writer GUID (a `None`, every local writer's
  lifecycle entry, proves nothing about identity either); otherwise the
  transition just queued is received strictly after whatever is already
  there, and arrival order decides.
- **A writer's departure could recompute a topic's minimum finite
  Lifespan from a snapshot already stale by the time it was published,
  overwriting a different writer's finite Lifespan a concurrent SEDP
  registration had just published for the same topic.**
  *[no 1.4.x exposure]* The snapshot of the topic's remaining writers and the
  publish of the recomputed minimum are two different locks, taken one
  after the other, with no lock shared with a concurrent registration on
  an entirely separate path; a departure computing "no limit" from its
  snapshot, raced by a new writer's registration publishing a finite
  minimum in between, published its own stale "no limit" over it. The
  epoch already bumped under the published map's own write lock by every
  writer of it is now re-checked after taking that same lock, against
  the value read before the snapshot; a mismatch retakes the snapshot
  fresh rather than publishing it stale.
- **A DataReader's own ACKNACK and NACK_FRAG went out, and were accepted,
  in clear on a topic whose DDS-Security governance requires submessage
  protection.** *[no 1.4.x exposure]* `is_submessage_protected` was
  advertised for readers, but only `encode_datawriter_submessage` /
  `decode_datawriter_submessage` (DDS-Security 1.1 Sec.9.5.3.3.1, Table 72)
  existed, so a reader's own control traffic -- the opposite direction from
  the DATA/HEARTBEAT/GAP a writer protects -- was never wrapped, and a
  secure builtin SEDP writer accepted a clear ACKNACK from an authenticated
  peer as readily as a protected one. `encode_datareader_submessage` /
  `decode_datareader_submessage` now protect a reader's ACKNACK/NACK_FRAG
  with a key the reader mints and announces over the same
  `ParticipantVolatileMessageSecure` channel as a writer's key
  (`DatareaderCryptoTokens`, Sec.7.4.4.6.3, Sec.8.8.9.3, mirroring the
  existing `DatawriterCryptoTokens` path, Sec.7.4.4.6.2); the two secure
  SEDP readers and the ParticipantMessageSecure reader mint and
  distribute this key at bootstrap -- a USER reader's own ACKNACK/
  NACK_FRAG is unaffected either way, since it mints no key of its own
  (below). A secure SEDP writer now refuses a clear ACKNACK from an
  authenticated peer when the topic's discovery protection requires it
  (NACK_FRAG has no symmetric gate: a SEDP builtin writer never answers a
  NACK_FRAG at all today -- the topic registry it is dispatched through
  holds handlers for USER writers only, so a SEDP-targeted NACK_FRAG,
  clear or protected, matches none and is silently inert; the decode and
  protection below still apply to it when it rides the secure reader-
  control channel, ready for the day a SEDP fragment repair path exists
  to gate), and decodes a protected one before answering it: bound to
  the specific reader whose announced key opened it (the decoded
  readerId/writerId must name that reader and its matching builtin
  writer, mirroring the writer-side DATA check already in place),
  checked against the governance's required protection strength (the
  same `protection_satisfies` rule the writer-side DATA path already
  applies). *[second round, 2026-10-26]* A datagram carrying more than
  one independently-protected control submessage used to lose every
  envelope after the first in two concrete shapes an independent review
  reproduced: a zero-length INFO_TS or PAD between two protected ACKNACKs
  (the compound scanner treated ANY zero-length submessage as running to
  the datagram's end; RTPS v2.5 Sec.9.4.5.1.3 reserves that reading for
  every OTHER kind -- INFO_TS and PAD specifically mean a genuinely empty
  body, with the message continuing behind them), and a protected SEDP
  DATA followed by a
  protected ACKNACK (the DATA arm stopped the scan unconditionally,
  assuming it had always consumed the rest of the datagram). Both are
  fixed, by delegating the compound scanner to the same validated
  submessage walker the rest of the crate uses rather than reimplementing
  its rules, and by having the SEDP-DATA arm check for a further envelope
  via the same scanner the reader-control arm already used; a production-
  dispatch regression test (not a unit test that opens both envelopes
  itself) feeds a real two-envelope datagram through the listener's own
  entry point and requires both to reach the control channel. A separate
  defect found by the same review -- the compound scanner followed a
  SEC_PREFIX's declared length past where the ordinary submessage walk
  had already stopped on an invalid RTPS context (an undersized INFO_DST,
  say), delivering a control submessage RTPS v2.5 Sec.8.3.4.1 rule 6 says
  the remainder of that message must not reach -- is fixed by making the
  secure-prefix scanner reuse the walker's own boundary instead of
  re-deriving it. Only the bytes actually recovered from a given envelope
  are ever marked protected; a clear submessage riding ahead of a valid encrypted
  one in the same datagram no longer inherits that status. The repair
  path that recovers a secure SEDP reader after a queue overflow protects
  its own recovery ACKNACK the same way, rather than sending it in clear
  to a peer that would now refuse it. *[second round, 2026-10-26]* The
  positive proof of this used to stop short of the claim it made: it
  built a synthetic `AckNackInfo` directly and flagged it `.protected()`
  by hand, which proves the metric's own counting logic but never that a
  genuinely protected ACKNACK decodes at all -- "hand-built bytes" was an
  overstatement with no bytes in it. It now builds a real ACKNACK packet,
  protects it with the exact function a peer's reader would call, decodes
  it back with the exact function production dispatch calls on receipt
  (the AEAD verify runs for real), and only then hands the result to the
  control handler; the repair response is itself decoded and checked for
  an actual DATA submessage, not merely "something arrived on the wire".
  The counter this proves (`protected_sedp_retransmissions`) turned out to
  move on a GAP-only answer too (a purged or not-for-this-participant
  number the writer answers without ever sending DATA) -- correct by its
  own definition ("a repair response, driven by this ACKNACK, of any
  shape"), but not what "drives an actual retransmission" implies. A
  second, narrower counter (`protected_sedp_data_retransmissions`) now
  exists for "and real DATA crossed the wire", with its own positive and
  GAP-only regression tests. A submessage-protected ACKNACK naming real
  missing sequence numbers drives an actual DATA retransmission, counted
  by both, and never confused with the unrelated case of a repair
  happening but the ACKNACK that asked for it arriving in clear. A live
  two-participant check confirms, separately,
  that a reader joining the domain AFTER several endpoints already exist
  on a governed secure SEDP topic is still caught up correctly end to
  end (the protected topic is never read on the plain SEDP topic, so a
  broken wiring would leave such a reader stuck forever) -- that specific
  catch-up is served by the proactive SEDP reannounce on handshake
  completion, not by an ACKNACK round trip, so it is evidence for the
  protect/decode/dispatch wiring in general, not for the ACKNACK-driven
  retransmission claim specifically.
  ParticipantMessageSecure's own ACKNACK wire path is not yet wired
  (its reader key is minted and distributed, under its own LIVELINESS
  protection kind, Sec.9.4.1.2.5.5, not discovery's); neither is a
  payload-protected USER topic's reader-side submessage protection --
  such a reader mints no key and sends its ACKNACK/NACK_FRAG in clear,
  which is consistent with its OWN `is_submessage_protected` being false
  (payload protection and submessage protection are separate governance
  attributes), not a gap in what this entry claims. The
  `ParticipantVolatileMessageSecure` channel this reader-token
  announcement travels over now has the specification's own wire shape
  and reliability (the two entries on that channel at the end of this
  section).
- **A builtin secure writer's `DatawriterCryptoTokens` always announced
  `destination_endpoint_guid = GUID_UNKNOWN`, and nothing checked the
  field on receipt.** *[no 1.4.x exposure]* DDS-Security 1.1 Sec.7.4.4.6.2
  wants the matched reader named; for the six builtin secure tunnels the
  writer and its peer's mirrored reader pair 1:1 by construction, so the
  destination is always nameable (a plain USER writer's tokens are
  addressed per matched reader since; see the entry on USER endpoint
  addressing at the end of this section). A received
  announcement naming one of this participant's own endpoints now has to
  name the RIGHT one -- the tunnel's matching reader -- or it is refused
  rather than installed; `GUID_UNKNOWN` is refused here too for these six
  builtin tunnels (a sender that skips naming the peer it always knows),
  narrowed further in the second round (2026-10-26): it is STILL ACCEPTED
  for a USER writer's or reader's own announcement -- the conformance gap
  just described, unchanged here -- but a NAMED USER destination must now
  be this participant's own prefix and the opposite endpoint direction
  from the one announced -- a participant entity id or any other
  non-endpoint kind used to pass as "not a reader" without being "a
  writer" either, and no longer does. The new `DatareaderCryptoTokens` of
  the entry above carries and checks the same field, addressed to the
  matched writer, and shares the same USER-endpoint conformance gap.
- **QoS guide no longer says `autodispose_unregistered_instances` is
  ignored.** It said the flag was "accepted but not yet consulted at
  runtime"; `unregister_instance()` has read it all along, through
  `StatusInfoKind::for_unregister` (`dds/writer/runtime.rs`), to choose
  between a disposed-and-unregistered and a plain unregister.
- **Eclipse Cyclone DDS vendorId corrected in rustdoc.** The supported-
  dialect table in `protocol/dialect/mod.rs` listed Cyclone DDS as
  `0x0112`; the `VendorId` enum and the wire encoder have used `0x0110`
  for Cyclone all along (`0x0112` is RustDDS/Atostek's assignment, also
  listed in that same table).
- **`rti_defaults()` docs no longer call the preset "RTI Connext
  compatible".** It sets Reliable, Volatile, KeepLast(10), not a vendor's
  defaults (the constructor itself was deprecated in 1.5.0 for the same
  reason). Corrected the wording in the SDK READMEs and the getting-
  started, QoS and API docs that still called it an RTI compatibility
  preset.
- **One writer's periodic HEARTBEAT could stall every other writer's,
  because the single `hdds-hb-sender` thread the participant liveliness
  scheduler introduced earlier in this cycle processes jobs strictly one
  at a time, and the plain blocking `UdpSocket` it sends through can, by
  POSIX semantics, block that thread for as long as its kernel send
  buffer stays full.** *[no 1.4.x exposure]* (the 1.4.x line gave each
  reliable writer its own dedicated send thread, so one writer's blocked
  send never touched another's; the shared worker this defect lives in
  was born in this same unreleased cycle). The periodic HEARTBEAT path's
  unicast and multicast-fallback sends now use a best-effort,
  non-blocking transmit (`MSG_DONTWAIT`, which this crate's pinned
  `libc` provides for Linux, Android, macOS/iOS, and the whole BSD
  family -- FreeBSD, DragonFly, NetBSD, OpenBSD; an earlier draft of
  this entry claimed the BSD family lacked it and kept the ordinary
  blocking send there too -- that was simply wrong, caught by an
  independent review reading the exact `libc` source files, and is
  corrected here. Windows remains the one real, left-open gap: Winsock
  has no per-call non-blocking flag, so that target still uses the
  ordinary blocking send on this path): a destination that would
  otherwise make the send wait now drops that one tick instead, legal
  for a periodic, idempotent message where stalling the worker is not.
  DATA, the on-write ("piggyback") HEARTBEAT, ACKNACK and coherent
  control keep the exact blocking send they always had -- the socket's
  own blocking mode is never touched, only this one call's flags are
  (an intermediate draft of this fix routed piggyback and the
  MANUAL_BY_TOPIC assert-liveliness HEARTBEAT through the non-blocking
  send too, since they share the same `send_heartbeat_to_readers`
  helper the periodic origin uses; a review caught that scope
  regression before it shipped, and an explicit `best_effort` parameter
  -- `true` only from the periodic origin -- now keeps the two apart).
- **The send-gate check that is supposed to guarantee "no periodic
  HEARTBEAT reaches the wire after a writer's drop returns" only
  checked a flag immediately before each transmit, then released the
  lock before window translation, relay lookup and the transmit
  itself -- a send already past that check could still be mid-transmit
  when `drop`'s own bounded (2 s) wait gave up and returned, and reach
  the wire afterward.** *[no 1.4.x exposure]* (the gate is new-in-cycle,
  introduced by an earlier review pass in this same cycle; 1.4.x's
  dedicated per-writer thread closed this a different way, by joining
  the thread). A first fix held the gate across the periodic origin's
  ENTIRE fanout instead -- every discovery/registry lookup and
  window-table translation too, not just the transmits -- which a
  further review found reintroduced the exact same class of problem
  one level up: `drop`'s `revoke_sends()` could now wait, unbounded, on
  whatever unrelated thread happened to be holding one of THOSE locks.
  The periodic origin now resolves everything it needs (discovery
  snapshot, registry lookups, window-table translation, AND the relay
  peer lookup a destination in a Discovery Server relay range needs)
  FIRST, with no gate held at all, and takes the gate only around: the
  one revoke check, a window-pairing revalidation, and the already-
  resolved transmits themselves. A fourth review found two of those
  THREE still able to wait while holding the gate: the window-pairing
  check used a blocking `peers.lock()` -- and production code holds
  that SAME mutex across a callback (a classic ACKNACK's acknowledgment
  accounting, into the history ring, with its own poison-recovery
  logging on that path) that is not bounded either -- and the relay
  sink's own offer could still log synchronously on its first oversized
  datagram or failed wake. Both are now non-blocking under the gate:
  the pairing check is a `try_lock` that drops this one reader's packet
  for this tick on contention (legal, the periodic origin retries every
  period), and the relay sink only collects what it could not log,
  returned and logged after the gate releases, the same as the
  multicast-fallback error already was. On Windows, where that transmit
  is still the ordinary blocking kernel send (no per-call non-blocking
  flag in Winsock), this gate is not taken at all: that platform's only
  guarantee remains the older, bounded `wait_idle`, with an explicit
  per-transmit revocation check kept in its loop even without the gate
  -- rechecked a second time immediately before each submission, not
  just once per entry at the top of the loop, so revocation landing
  while that same pairing check was itself contending `peers` cannot
  let a stale send through (an earlier Windows branch dropped the
  per-call check entirely along with the gate, letting a tick resumed
  after `drop` revoked sends still transmit; this round's review found
  the recheck alone still left that one-entry gap). Piggyback and
  MANUAL_BY_TOPIC assert-liveliness keep the cheaper per-call check,
  unchanged -- they never shared this specific race, since they run on
  the writer's own thread, not the worker drop can race against from
  another thread. A dedicated test drives a real matched CLASSIC-dialect
  reader through this path and holds the window table's mutex from
  another thread while a periodic tick is due, confirmed (a one-shot
  signal fired the instant the tick's own resolve call reaches that
  contested lock, with RAII release on every exit path including a
  failed assertion) to have actually reached it before `drop` is
  measured against it -- an earlier version of this test held the mutex
  with no matched reader at all, so the tick never touched it and the
  test proved nothing about where the gate was placed. Left open, named
  rather than hidden: the ACKNACK-side hold of `peers` across its own
  callback, and `MatchNotificationRegistry`'s unbounded wait for an
  in-flight discovery dispatch pass, are both pre-existing, unrelated
  mechanisms this change does not touch -- the gate itself no longer
  waits on either, which is the guarantee this entry makes.
- **The periodic HEARTBEAT path's non-blocking multicast fallback
  bypassed `MulticastMode` entirely**, calling the bare syscall with no
  `multicast_send_refused` check at all, while every ordinary multicast
  send still enforced it -- `ReceiveOnly`/`Disabled` was silently
  ignored for this one path, and its refusal never counted in
  `suppressed_multicast_sends`. *[no 1.4.x exposure]* (a regression
  from this cycle's own resolve/transmit split above, which the 1.4.x
  dedicated-thread design never had). A first fix called
  `multicast_send_refused` -- which counts and logs -- during prepare
  to decide the permission, which a further review found counted a
  refusal on EVERY tick `MulticastMode` disables multicast for, even
  one whose unicast delivery succeeded and never needed the fallback
  at all. The permission is now read with no side effect during
  prepare (`multicast_send_allowed`); the count and log happen after
  the gate releases, and only when this tick's unicast genuinely did
  not deliver and the route was otherwise open -- the same moment an
  ordinary multicast send would make that call. Tested with both
  `ReceiveOnly` and `Disabled`, including a unicast-success case that
  must count zero refusals.
- **The durable-writer first-match announcement's retry used a
  blocking, ungated, non-relayed `transport.send()` to the metatraffic
  multicast address, on the SHARED worker** -- no per-reader locators,
  no relay routing (unreachable to a relay-only peer), no send-gate
  revocation, and a real block if that socket's kernel buffer were ever
  full, stalling every OTHER writer's tick queued behind it: the exact
  class of defect this change exists to close, reintroduced for this
  one origin. *[no 1.4.x exposure]* (the retry mechanism itself is new
  in this cycle; see the count-serialization entry above). It now goes
  through the same prepare + gated non-blocking transmit path as an
  ordinary periodic tick. A first fix still read success from that
  path's historical "unicast delivered" return alone, which a further
  review found left a successful MULTICAST delivery looking identical
  to total failure: the retry re-armed itself forever, resending the
  empty announcement every period, even after it had already,
  genuinely, reached the wire. The retry now checks delivery by either
  route; re-armed on an actual send failure by both too, not only on
  `send_serial` contention -- a transient failure must not silently
  drop the announcement any more than contention does.
- **A caught panic while allocating/transmitting a periodic HEARTBEAT
  (the worker's own `catch_unwind` around the whole tick keeps the
  WORKER thread alive, but does nothing about a lock that tick was
  holding) poisoned the per-writer `send_serial` lock forever: the
  periodic origin's `try_lock` treated `Poisoned` exactly like
  `WouldBlock`, so every LATER tick for that one writer silently
  skipped -- an idle reliable writer would stop announcing
  unacknowledged data, permanently, with nothing in the logs to say
  why.** *[no 1.4.x exposure]* (`send_serial` is new-in-cycle; see the
  count-ordering entry below). `Poisoned` is now recovered
  (`into_inner`, the same recovery every other lock in this crate
  already uses) and only a genuine `WouldBlock` skips the tick.
- **The periodic and the on-write ("piggyback") HEARTBEAT origins
  shared one atomic HEARTBEAT count, but allocating it and sending it
  were two separate steps with nothing to keep them atomic ACROSS
  origins: periodic could allocate N, pause for any reason, piggyback
  allocate and send N+1 on the writer's own thread, and periodic's N
  reach the wire only afterward -- a reader seeing N+1 first discards
  the late N as stale (RTPS v2.5 Sec.8.3.8.6 requires one monotonic
  count per writer ON THE WIRE, not only in allocation order).**
  *[no 1.4.x exposure]* (both origins already existed before this
  cycle, but shared the exact same counter only once the periodic
  scheduler did too; see the entries above). A per-writer lock
  (`HeartbeatSchedulerState::send_serial`) now holds allocate-then-send
  as one critical section for every origin: piggyback and
  MANUAL_BY_TOPIC assert-liveliness block on it briefly (their own
  thread, their own writer's lock, never another writer's); the
  periodic origin `try_lock`s it instead and skips the tick entirely on
  contention, so the shared worker never waits ON THIS LOCK for a
  different thread to release it -- legal to skip, since a HEARTBEAT
  for that writer is then either about to reach the wire or just did.
  (This is specific to `send_serial`: the same worker CAN still wait,
  bounded only by what holds it, on the window table's mutex while
  resolving a classic-dialect destination -- see the send-gate entry
  above for why that wait is never behind the send gate itself.) A
  durable writer's first-match announce HEARTBEAT (fired from the
  discovery thread that found the match, never the worker) used to
  allocate its count and send directly, bypassing this same lock
  entirely -- a second announce racing the periodic origin's own tick
  could land out of order on the wire. It now goes through the same
  try-lock-and-retry discipline: a contended try is **not lost**, it
  marks itself pending and this writer's own next periodic tick (which
  already holds the retry machinery for the panic-recovery case above)
  retries it, so the discovery thread itself never blocks on this lock
  either.
- **`EndpointRegistry` treated a poisoned lock as "no route" on a read
  and silently skipped the write on a write** (a panic anywhere while
  one of its maps was held -- unrelated to this change -- would have
  left every later DATA/HEARTBEAT destination lookup for that map
  failing forever, with the failure looking like a routing gap, not a
  poisoned lock). The registry predates this cycle with the same
  behavior (`8701c0b6`'s own `if let Ok(mut map) = ...write()`/
  `.read().ok()?`), so a 1.4.x operator is exposed too, same as this
  entry; every other lock in this crate already recovers a poisoned
  guard the same way, this one did not. Recovered (`into_inner`) on
  every read and write, consistent with the rest of the crate.
- **DESTINATION_ORDER BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17) was
  accepted as a QoS setting and matched on, selectable since the 1.4.x
  baseline, but never read by the reader: it kept reception order
  regardless.** A reader with this policy now keeps, per instance, a
  persistent acceptance watermark beside the instance's ALIVE/NOT_ALIVE
  state: the key of the last change it accepted, `(source timestamp,
  writer GUID, writer sequence number)`, the sequence number the
  writer's full 64-bit one. A change whose key is not greater is refused
  and changes nothing of the instance but writer presence (below), so
  every reader of the same writers settles on the same final value
  whatever order the changes arrived in, a tie on timestamp going to the
  greater writer GUID on every reader, and one writer's two changes at
  one timestamp (a write and a dispose at the same `_w_timestamp`) both
  accepted in the order it sent them. The watermark survives every
  sample leaving the cache, so a late, older sample never becomes the
  instance's value again after the newer one was taken or read. One
  acceptance point per change: network DATA and lifecycle changes enter
  history in writer order, and coherent changes at atomic set commit;
  intra-process ring DATA is admitted when application access
  decodes it. A sample with no source timestamp of its own (a datagram
  without INFO_TS) is not ordered. Under this policy:
  - **The listener's `on_data_available` is not called with a sample**
    (network path, intra-process path, coherent sets alike): a sample is
    selected from the source-ordered history at application access, and
    newer changes can replace its retained contents before then. The
    DATA_AVAILABLE status
    and every WaitSet on it are still raised, and the payload-less
    `on_data_available_notification` callback is delivered outside reader
    locks (Sec.2.2.4.3.2); read the accepted samples with `take`/`read`
    there. Local durable replay sends one notification after its batch,
    once binding locks are released; deadline watches still observe each
    replayed sample. The default reader's payload listener is unchanged.
  - A network sample already older than the watermark when it arrives is
    acknowledged and not stored: it takes no place in the history, so a
    bounded RELIABLE KEEP_ALL history it would have filled keeps room for
    the next valid sample.
  - `take`, `take_w_condition` and `read_w_condition` present an
    instance's changes in source order whatever their writers: a dispose
    waits behind an older sample of its instance still buffered and
    matched by the access (Sec.2.2.2.5.3.8). What was already taken, read
    past or not matched holds nothing back.
  - Writer presence (NOT_ALIVE_NO_WRITERS, Sec.2.2.2.5.1.3) is not
    ordered: the last writer's unregister applies even when its own
    timestamp loses, and a writer that holds a writerless instance revives
    it even when its sample's value is refused; neither moves the
    watermark, a writer never revives NOT_ALIVE_DISPOSED, and both re-check
    the registration under the instance lock.
  - TIME_BASED_FILTER is consumed only by an admitted sample, and a local
    writer's dispose ends the instance's DEADLINE watch only once the
    reader admits it.
  - A full KEEP_LAST ring (network, and intra-process) keeps the samples
    with the greatest keys of each instance, not the latest arrivals.
  - A local writer's samples and dispose/unregister carry its real
    identity for the tie-break (captured when the reader binds it, so it
    survives the writer's deletion), on every intra-process delivery path.
  The default reader (BY_RECEPTION_TIMESTAMP) keeps its behaviour: the
  policy is resolved once at reader creation into a flag, and an
  intra-process write with an application-supplied source timestamp
  carries the moment it was written ahead of its payload, by which the
  default reader keeps merging its local writers. No performance figure of
  this entry has been measured. Two defects independent of the policy
  were fixed on the way: a coherently-staged sample's
  `SampleInfo::source_timestamp_ns` was always absent, and a DATA_FRAG
  sample's was its reception time, or the INFO_TS of an unrelated
  datagram; each fragment now takes the INFO_TS in force where it sits in
  its datagram (RTPS v2.5 Sec.8.3.7.9). Not covered: (1) the network
  ring's compaction decodes every retained entry on each pass under this
  policy, where the default reader reuses cached keys; (2) a sample with
  no source timestamp is admitted unordered but sorts as the oldest of its
  instance in compaction, two conventions for one case;
  (3) two PARTITION gaps found while confirming the `writer_shut_out` fix
  below, see that entry.
- **A reader could present DATA ahead of its writer's earlier dispose once
  the writer's sequence number exceeded 32 bits.** Presentation now compares
  the full writer sequence numbers for DATA and lifecycle changes under both
  destination-order policies (DDS v1.4 Sec.2.2.2.5.3.8). The cache reuses its
  existing sequence field; ordinary BY_RECEPTION network entries retain their
  layout, adding the full-SN prefix only beyond 32 bits. Anonymous local
  samples retain their ring tags for deduplication.
- **Default reception-order merging copied a parked heap-tier payload on
  every comparison when a local writer supplied a source timestamp.**
  *[no 1.4.x exposure]* The merge now reads only the fixed-size reception
  prefix in place, including under the heap store lock, without a
  payload-sized allocation or copy (DDS v1.4 Sec.2.2.3.17). Ordinary
  unprefixed entries still use their entry timestamp directly.
- **A local TRANSIENT_LOCAL late joiner lost the retained changes' source
  timestamps.** Replay now carries the journaled timestamp and its validity
  for DATA and lifecycle changes. BY_SOURCE_TIMESTAMP KEEP_LAST keeps the
  newest source value even if an older-timestamped value was written later
  (DDS v1.4 Sec.2.2.3.4, Sec.2.2.3.17); a genuine epoch timestamp remains
  distinct from an unknown one. Replay keeps its previous zero reception
  merge key separate from source time, so application timestamps do not
  reorder a default reader's writers. DATA replay shares the retained payload
  slab with every late reader, so preserving source time adds no slab
  allocation or new pool-exhaustion loss condition.
- **`ReaderSubscriber::writer_shut_out`'s own doc comment claimed
  PARTITION incompatibility was covered through `writer_refused`, but a
  writer never discovered via SEDP at all slipped through both:
  `writer_refused` answers false for a writer it never judged, and
  `writer_partition_incompatible` -- the gate DDS v1.4 Sec.2.2.3.13 gives
  a partitioned reader against exactly this case -- was never
  consulted.** *[no 1.4.x exposure]* `on_group_change`,
  `on_writer_group_heartbeat`, `on_ecs`, `on_coherent_end` and
  `on_coherent_end_marker` all gate solely on `writer_shut_out`, so an
  undiscovered writer could move a non-default-partition reader's GROUP
  state (confirmed before the fix: its GroupInfo was recorded in
  `writer_gsns` exactly like a real, matched writer's). A DISCOVERED
  writer with a genuinely incompatible PARTITION was already refused
  (PARTITION is one of the policies the QoS verdict judges, and any
  failure of it is recorded as a QoS refusal, not only a named-policy
  one), so the comment's claim held for that case; `writer_shut_out` now
  also consults `writer_partition_incompatible` directly, closing the
  undiscovered-writer case too for a reader with a NON-default
  PARTITION. Not covered, narrower than an earlier version of this
  entry claimed: a DEFAULT-partition reader's UNDISCOVERED writer on
  the GROUP-control paths `writer_shut_out` gates (`on_group_change`,
  `on_writer_group_heartbeat`, `on_ecs`, `on_coherent_end`,
  `on_coherent_end_marker`). A DISCOVERED writer with a genuinely
  incompatible PARTITION talking to a default reader is NOT exposed by
  this: PARTITION failure is recorded as a QoS refusal at match time,
  and `writer_refused` -- `writer_shut_out`'s OTHER check, which runs
  regardless of the reader's own PARTITION -- already catches it there,
  on the ordinary DATA path too. The default-partition bypass inside
  `writer_partition_incompatible` only matters for a writer this
  participant has not discovered via SEDP at all, which `writer_refused`
  cannot judge (it "answers false for a writer it never judged", not
  refused) -- closing that specific case would need the same care
  already taken to keep `writer_shut_out` off live FSM presence for a
  writer's own departing final marker, not a small addition to this fix.
  Also pre-existing and unchanged by this one: `writer_partition_incompatible`
  always resolves a writer's PARTITION through the live discovery FSM
  (`resolve_writer_partition`), never through the durable `TopicRegistry`
  `writer_undiscovered` prefers for exactly this reason -- so a writer
  whose FSM record has already disappeared (a departure racing its own
  final control marker, the same race `writer_undiscovered`'s own doc
  documents) is judged exactly like one never discovered at all. Whether
  that cold-cache case can lose a populated last set in practice was not
  established either way.
- **A ROS 2 Complete TypeObject referenced a nested message by its Minimal
  identifier, and shared one `TypeIdentifier` between the Complete and
  Minimal representations.** The ROS 2 introspection TypeObject builder
  (`xtypes/builder/ros.rs`, the path a ROS 2 node registers its type over
  through `rmw_hdds`) built both representations from one
  `CommonStructMember`, so a struct member naming a nested ROS message
  carried the SAME `TypeIdentifier` -- the nested type's Minimal one --
  whether it sat inside the outer Complete TypeObject or the outer Minimal
  one. Per DDS-XTypes v1.3 Sec.7.3.4 a Complete TypeObject must reference a
  nested type by its EK_COMPLETE identifier and a Minimal one by its
  EK_MINIMAL identifier; nothing rewrites a ROS type's `complete` field into
  a separate spec-correct wire form the way the native HDDS-generated-type
  registration path does, so this was the identifier an OMG TypeLookup
  request actually received for such a type. Each representation now
  carries its own identifier for a nested member, matching that nested
  type's own Complete or Minimal `TypeIdentifier`. The builder also never
  read a member's `@key` annotation (the one member property ROS 2's
  `rosidl_typesupport_introspection_c` can express, Jazzy and later): a
  `MessageMember.is_key_` now sets `MemberFlag::IS_KEY` on both
  representations. This moves the EquivalenceHash, hence the TypeIdentifier,
  of every ROS 2 message type with a nested message field or a `@key`
  member on the `rmw_hdds` path; it does not touch ROS 2's own RIHS01 type
  hash (`rosidl_type_hash_t`), a different hash computed by `rosidl` itself
  and carried through unchanged.
- **ROS 2 and descriptor-built members now encode default DISCARD, and
  keys are also must-understand.** DDS-XTypes 1.3 Sec.7.2.2.7 and
  Sec.7.2.2.4.4.4.8 require flags `0x0001` on an ordinary member and
  `0x0031` on a key. The introspection and safe descriptor builders emitted
  zero or KEY alone, changing both TypeObject hashes relative to conformant
  peers. This corrects their Complete and Minimal member flags; ROS RIHS01
  hashes remain the values supplied by rosidl.
- **Anonymous ROS 2 and descriptor-built arrays and sequences now carry
  plain TypeIdentifiers.** Per DDS-XTypes 1.3 Sec.7.3.4.1 and Sec.7.3.4.6,
  these collections have no separate TypeObject: their identifiers carry
  bounds, dimensions, default element DISCARD and the element identifier.
  The builders used a hash of a temporary Minimal collection object that
  was then discarded. Complete ROS objects now reference Complete elements
  through these collections, Minimal objects reference Minimal elements,
  and fully descriptive collections use EK_BOTH, including nested plain
  collections. This changes the enclosing XTypes hashes without changing
  ROS RIHS01 hashes.
- **Registering a ROS 2 type now publishes its reachable dependency
  objects to TypeLookup and the structural matcher.** DDS-XTypes 1.3
  Sec.7.3.4 and Sec.7.6.3 require the hash references in a TypeObject to
  resolve to their objects. The introspection builder retained only nested
  identifiers, so registering the root left those references unresolved.
  Its cache handle now retains both representations of every reachable
  message, including through anonymous arrays and sequences. Registration
  serves each dependency by its exact Complete and Minimal identifiers and
  populates the matcher under both hashes. Distinct Complete names sharing
  a Minimal representation retain separate Complete objects, so structurally
  compatible parents can match under ALLOW_TYPE_COERCION.

- **Deep inline collection identifiers no longer prevent TypeObject hashing.**
  *[no 1.4.x exposure]* The ROS 2 and descriptor builders' plain collection
  identifiers recursively include element identifiers and array dimensions
  (DDS-XTypes 1.3 Sec.7.3.4.6 and Annex B). The hash serializer still allocated
  from fixed size estimates, so a member containing 16 nested unbounded
  sequences of int32 failed with `BufferTooSmall`. Hashing now grows the
  buffer and restarts serialization until the entire outer XCDR2 TypeObject
  fits, preserving alignment, DHEADER lengths and the canonical Complete
  and Minimal hashes without a fixed collection size cap.
  narrowed further in the second round (2026-10-26): a NAMED USER
  destination must be this participant's own prefix and the opposite
  endpoint direction from the one announced -- a participant entity id or
  any other non-endpoint kind used to pass as "not a reader" without being
  "a writer" either, and no longer does (USER endpoints are now held to
  more than that, by the addressing entry at the end of this section). The
  new `DatareaderCryptoTokens` of the entry above carries and checks the
  same field, addressed to the matched writer.
- **The `ParticipantVolatileMessageSecure` DATA travelled in clear, around a
  private envelope.** *[no 1.4.x exposure]* DDS-Security 1.1 Sec.7.4.4.1
  (Table 17) makes this topic submessage-protected, and Sec.8.5.1.9.2 gives
  its writer the pair's Table 67 KxKeys as the receiving key material: the
  DATA submessage that carries the CDR `ParticipantGenericMessage` is
  itself replaced by SEC_PREFIX/SEC_BODY/SEC_POSTFIX (Sec.9.5.3.3.4.5).
  HDDS wrapped the message in a private PAD-framed blob protected under the
  KxKeys and sent that blob as the payload of an ordinary clear DATA, which
  a conforming peer does not read, while a conforming peer's protected DATA
  was tried against secure SEDP key material only and never opened. The
  protected DATA now sits in the RTPS message itself, after INFO_DST and
  INFO_TS. On receipt a SEC_PREFIX is tried under the sender's KxKeys
  first, before secure SEDP holds anything back: the keys a held secure
  SEDP datagram waits for are what this channel carries. A clear DATA of
  the volatile endpoints, anything else that opens under the KxKeys, and a
  submessage naming the KxKeys' key id that does not authenticate under
  them are refused and counted, and the `destination_participant_guid`
  content filter of Sec.7.4.4.4 is applied (a message naming another
  participant is refused and counted)
- **The `ParticipantVolatileMessageSecure` channel was best effort and
  re-announced every key every two seconds.** *[no 1.4.x exposure]*
  Sec.7.4.4.2 (Tables 18 and 19) makes its writer a reliable StatefulWriter
  and its reader a reliable StatefulReader (RTPS v2.5 Sec.8.4.9.2,
  Sec.8.4.12.2), RELIABLE, KEEP_ALL, VOLATILE. The writer now keeps one
  history and one sequence-number space, and per authenticated peer a
  reader proxy holding that peer's unacknowledged changes. A message is
  addressed to one participant (Sec.7.4.4.4), so every other change of the
  history is irrelevant to a reader and is announced to it with a GAP; a
  reader proxy with unacknowledged changes gets a HEARTBEAT every second;
  an ACKNACK purges what it acknowledges and is answered with the changes
  it asks for (or a GAP for one that is not that reader's, never another
  peer's message); a NACK_FRAG is answered with the whole change, the
  channel never fragmenting. A proxy holding 256 unacknowledged changes
  refuses a new one, which is offered again later, rather than dropping
  any. The reader delivers each change once and in order and answers a
  HEARTBEAT with an ACKNACK. Every one of these submessages is protected
  under the pair's KxKeys. Both proxies are bound to the KxKeys they were
  built under: a peer that authenticates again starts both over, what it
  must hold is written again, and the replay guard forgets the old
  session. Each message is now written once; nothing is re-announced on a
  timer
- **A USER endpoint's CryptoTokens went to the whole peer as `GUID_UNKNOWN`,
  and were accepted that way.** *[no 1.4.x exposure]* Sec.7.4.4.6.2 and
  Sec.7.4.4.6.3 address a DataWriter's tokens to "the DataReader that
  should receive" them, and a DataReader's to the matched DataWriter, one
  message per matched endpoint (Sec.8.5.1.8.3, Sec.8.5.1.8.5); the key
  material may be shared, the addressing may not. A writer's tokens now go
  to each matched reader of the peer, each naming it. On receipt the
  destination must be an endpoint of this participant, of the kind the
  source addresses, matched with the source: `GUID_UNKNOWN`, another
  participant's endpoint, an endpoint of the wrong kind or of no existence
  here is refused and counted. Tokens naming a real local endpoint not
  matched with their source yet are held, up to 256 globally and 64 per peer
  for 30 s, without acknowledging their DATA, and
  installed when the match comes, since the sender writes them once it has
  matched and this participant matches the sender's endpoint on its own
  discovery. The match registry now answers for a local endpoint by its
  GUID, which is what both ends read

- **Remote endpoint and participant security masks are compared at admission.**
  `PID_ENDPOINT_SECURITY_INFO` (DDS-Security v1.1 Sec.7.2.8, 7.4.1.5) is
  parsed from SEDP in either parameter-list byte order and compared against
  the local topic's governance attributes. Each standard and plugin mask is
  compared independently: if either side's validity bit is clear, that mask
  is ignored; otherwise its complete value must agree. This includes read,
  write, discovery and liveliness protection, and compares plugin masks as
  opaque values. An absent PID defaults to two zero masks and skips both
  comparisons, preserving compatibility with older peers. A mismatch refuses
  the pair with a visible reason and uses the existing admission cache.
  `PID_PARTICIPANT_SECURITY_INFO` (Sec.7.2.7, 7.4.1.4, 9.4.2.4) follows the
  same matching rule at SPDP admission for peers presenting an identity
  token. SPDP parsing normalizes both u32 masks from the parameter list's
  byte order, so big-endian peers receive the same admission decision.
  *[no 1.4.x exposure]*
- **The persistence service retains keyed histories per instance using its
  own DURABILITY_SERVICE policy.** DDS v1.4 Sec.2.2.3.5 configures the
  service's history and resource limits independently of the source writer's
  HISTORY and RESOURCE_LIMITS. `history_depth` and `max_samples_per_instance`
  bound each instance, while `max_samples` bounds the topic. The default
  service policy still means KEEP_LAST(1), and a writer with KEEP_LAST(1)
  no longer truncates a service configured for KEEP_LAST(10).
  Existing SQLite records migrate in place with a nil instance handle;
  their original keys cannot be recovered from the old schema.
- **The persistence service enforces DURABILITY_SERVICE.max_instances.**
  SQLite atomically refuses samples of new instances at capacity while
  accepting updates of retained instances. The subscriber counts refusals.
  Retention sweeps preserve
  existing instances, including databases already over the configured limit
  (DDS v1.4 Sec.2.2.3.5/2.2.3.19).
- **Equal timestamps no longer keep an older persistent value.** Both
  per-instance and topic-wide sample count trims break timestamp ties by
  descending insertion id, retaining the newest received value for
  KEEP_LAST (DDS v1.4 Sec.2.2.3.18).
- **A live writer no longer suppresses service replay for departed writers.**
  TRANSIENT and PERSISTENT replay skips only samples whose original writer
  is still compatible and present, preserving other writers' retained data
  without duplicating the live writer's own replay (DDS v1.4 Sec.2.2.3.4).
- **Retiring a persistence replay writer does not dispose durable instances.**
  Replay writers unregister without disposal when replaced or when the
  service stops, preserving the original application's instance lifecycle
  (DDS v1.4 Sec.2.2.3.4/2.2.3.21). *[no 1.4.x exposure]*
- **Persistence replay preserves the stored instance KeyHash.** Opaque
  replay writers emit PID_KEY_HASH and retain it in their history, so raw
  and typed late readers keep distinct instances at KEEP_LAST(1)
  (RTPS v2.5 Sec.9.6.4.8, DDS v1.4 Sec.2.2.3.18).
- **Raw capture retains the real instance identity for persistence.** Wire
  PID_KEY_HASH reaches raw `SampleInfo` through admission and retained sample
  storage, and local capture retains the writer's key on live delivery and
  history replay, including local samples carrying a separate reception-time
  prefix for an explicit source timestamp. The persistence reader keeps that
  identity together with the payload's actual CDR version, so two keys at depth one retain two
  samples (RTPS v2.5 Sec.9.6.4.8, DDS v1.4 Sec.2.2.3.5).
- **RawSample retains source compatibility for existing Rust callers.**
  The unreleased instance-handle field is removed so previous struct
  literals and exhaustive destructuring compile again. Instance identity
  is available through `RawDataReader::try_take_raw_with_info_and_encoding()`
  together with the payload and CDR version. The listener adapter preserves
  both reception-order payload callbacks and BY_SOURCE_TIMESTAMP notifications
  without a payload (DDS v1.4 Sec.2.2.4.3.2). *[no 1.4.x exposure]*
- **TRANSIENT history is replayed after the original writer leaves.** The
  persistence service preserves all four DURABILITY kinds, stores TRANSIENT
  and PERSISTENT data, and offers the requested durability on its replay
  writer. TRANSIENT_LOCAL storage and replay remain the source writer's
  responsibility (DDS v1.4 Sec.2.2.3.4).
- **A handshake message being verified no longer hides its session.** While
  an AuthReply or an AuthFinal is verified, its session is out of the session
  table, and the table read as if the peer had no session at all: the secure
  SEDP the peer sent in that window was dropped as coming from a participant
  that has not authenticated, and what was already held for it was handed
  back into the same refusal. Reliable secure SEDP does not recover what its
  reader dropped after the writer sent it, so on a loaded host two
  participants could authenticate and never match their endpoints. A session
  (and a re-authentication) being verified is now a session in progress
  (DDS Security v1.1 Sec.8.8.2.1, Sec.9.3.4): the peer's SEDP is held until
  it completes and handed back in order.
- **An InterCOM DDS reader sees the dispose of a writer deleted right
  after it.** A writer deleted after `dispose` waits for its readers to
  acknowledge the change, then announces its departure over SEDP. InterCOM
  DDS 4.3.1 acknowledges a dispose on receipt but hands it to its
  application only at the next read, and discards it when the writer's
  departure arrives first: the application never saw NOT_ALIVE_DISPOSED
  (its own writer loses the dispose against its own reader the same way).
  A conformant reader keeps the untaken dispose (DDS v1.4 Sec.2.2.3.22), so
  every other reader still costs the deletion no wait; with an InterCOM
  reader matched, the writer now stays announced 300 ms after the
  acknowledgement before its SEDP dispose. *[no 1.4.x exposure]*

- **Building the `hdds` crate no longer prints cargo warnings.** The build script
  reported each generated file (`Generated src/generated/temperature.rs` and
  `mod.rs`) as a `cargo:warning`, which showed up in every user build with paths
  that do not exist in the user's tree. The generation is silent now.
- **The `01_basics` hello-world samples use `HDDS_DOMAIN_ID` and wait for their
  peer.** Rust, C, C++ and Python read the domain from `HDDS_DOMAIN_ID` (default
  0) and print it. The publisher waits for a matched subscriber before its first
  write, so the first samples are no longer lost to discovery, and exits non-zero
  with a message after 30 s without one. The subscriber exits after 30 s without
  a message and reports how many it received, instead of waiting forever for a
  lost sample. The C sample also used type and function names that the current
  `hddsgen` output does not define, so it did not compile; it now does.
- **A time-based filter could skip a whole period against a publisher that sends one sample per
- **A C take that was too small for its sample consumed it.** `hdds_reader_take`, `hdds_reader_take_ex`, `hdds_reader_take_w_condition[_ex]` and the `_w_query_condition` forms returned `HDDS_OUT_OF_MEMORY` with the sample already gone, so the retry with a bigger buffer got `HDDS_NOT_FOUND`. The size check now runs inside the take, under the reader's consumer gate: a refused take removes nothing, and a later take returns the head of the reader (normally that sample).
- **A C read with a too-small buffer marked its sample READ, so a NOT_READ read skipped it.** `hdds_reader_read_w_condition[_ex]` and `hdds_reader_read_w_query_condition[_ex]` returned `HDDS_OUT_OF_MEMORY` after marking the sample READ, and the retry with a bigger buffer under a NOT_READ mask got the next sample instead. The size check now runs before the mark: a refused sample stays unread.
- **A too-small SHM take stalled the rmw reader on its message.** `hdds_rmw_context_shm_try_take` reported a message longer than the buffer as NOT_FOUND, counted it as corrupt, and left it at the head of the ring, so every later take stalled on it. It now returns `HDDS_OUT_OF_MEMORY` with the message length, validated against the slot payload first, and consumes nothing. `rmw_hdds` takes its messages at `raw_message_size` only: a longer one is skipped without a copy (`hdds_rmw_context_shm_skip_oversize`), a shorter one is consumed, and both are counted (`shm_size_mismatches`) and delivered from RTPS. The ring reader gains a sized pop (`ShmRingReader::try_pop_sized`) and `discard_if_longer`.
- **The C++ and Python readers threw on a sample longer than their buffer.** `take_raw`, `take_raw_sample`, and the Python reader's take paths now take such a sample again at the length the reader reported (bounded to a few attempts), since the sample stays in the reader.
  period.** The filter measured the separation between two arrivals and dropped a sample that came a
  fraction of a millisecond before one separation had elapsed since the last accepted one; the next one
  then came a full period later, so a reader with `minimum_separation` of one second against a writer
  that sends once a second lost a window whenever network jitter made one arrive early. The policy says
  the application must not *see* more than one sample of an instance per separation, and that HISTORY
  and RELIABILITY apply after the filter, so the separation is now measured between the instants two
  samples become visible to the application, at its first access: a sample that arrives while the
  previous one's window is open waits and is shown at the first access at or after the window's end
  (never before), a newer sample of the same window replaces it, and a participant's WaitSet or listener
  is woken at that instant. Against a writer faster than the separation, a sample the writer produced
  less than a separation (less a 5 percent jitter allowance) after the one shown, by the writer's own
  timestamps, waits for a newer one and is shown anyway a full separation after the window ended
  (counted from the window, so a stream that keeps arriving does not restart that wait), so the last
  sample of a stream is not lost; a sample that carries only its reception time is not judged by a
  writer's clock. A sample the reader admitted is never refused for the depth of its receive queue,
  and a waiting application is woken again whenever a newer sample moves the instant the parked one
  is due. A value that waits is dropped, not shown late, when its instance went through a transition
  of its own writer in the meantime or when its lifespan ran out; neither closes the window of the
  sample that follows. A separation too long to be added to a clock reading
  (`time_based_filter_secs(u64::MAX)`) shows the first sample and holds the rest instead of
  panicking the reading thread. A reader that orders by source timestamp, one with ordered access
  and one with coherent access still drop a sample that arrives with the window closed, as before:
  letting it wait would show it out of its order or apart from its coherent set. They show every
  sample that finds the window open, whatever its source timestamp, so they never show fewer
  samples than one per separation.

### Performance

- **A writer's per-write statistics are plain counters again, not atomics.**
  The send and sample counters added during this cycle were atomic
  read-modify-writes on every write; a `DataWriter` is not `Sync`, so they
  are now `Cell`s. One-thread write->take of a 16-byte POD
  (benchmark host, i9-9900KF, governor performance, thin LTO, cgu=1, core 3,
  `HDDS_INTERFACE=lo`, `latency_benchmark_prof`, interleaved rounds,
  2026-11-10): p50 186 -> 176 ns in that series. Measured again on the release
  binary, the default build gives p50 180 ns, p99 190 ns and 5.05 M delivered
  msg/s, and the 176 ns of the earlier series was not reproduced on the same
  host; a build of an earlier revision measured the same as the release
  binary, so the difference is not a change in the code. For the regime and
  the spread, see the benchmarks page. An earlier revision carried a 114 ns
  certificate; the process-global metrics counters account for about 6 ns of
  what remains and are not changed in this release.

- **An idle participant no longer runs the shared-memory receive thread, and its multicast listeners sleep until a datagram or their shutdown wake arrives.** The shared-memory poller (`hdds-shm-rx`) is started by the first attach from a co-located peer, so it does not exist with SHM disabled or without a peer. Each multicast listener (`hdds-mcast-rx`) blocks on its socket with no timeout instead of waking every 1 ms; shutdown wakes it at once. Measured on a Raspberry Pi Zero 2 W (Cortex-A53, governor ondemand, 60 s windows, 5 rounds, four bare and idle-endpoint configurations with SHM on and off): the total thread load went from 16.6-16.9% of one core (about 10,150 wake-ups/s) to 1.9-2.0% (about 440-500 wake-ups/s). Each multicast listener used 1.5% of a core at 937 wake-ups/s before.
- **The shared-memory poller can back off its idle sleep, opt-in through `HDDS_SHM_IDLE_CAP_US`.** By default an attached poller sweeps its rings every 100 us even while they are quiet, so the first sample after an idle stretch is popped at once; nothing changes for that default. Setting the variable to a cap in microseconds (clamped to 100 to 10000, read once when the poller starts; text that is not a whole number falls back to the default with a warning) lets the poller back off: after a packet it sweeps every 100 us for 10 ms, then doubles its sleep up to the cap, and the next packet restarts the 100 us cadence. A request and its reply, a round trip apart, keep the shared-memory latency; a sample that arrives on a quiet ring waits up to the cap. Measured on the benchmark host (one-way, first sample after 5 s idle, median): 0.14 ms at the 100 us default, 0.36 ms at a 500 us cap and 1.2 ms at a 2 ms cap. Idle CPU of `hdds-shm-rx` with an attached, silent SHM peer on a Raspberry Pi Zero 2 W (governor ondemand, 60 s windows, 5 rounds): 8.83% of one core at 100 us, 3.51% at 500 us and 1.05% at 2 ms. See `docs/reference/environment-vars.md`.

- **Four per-sample costs removed from the write and acknowledgement paths, behaviour unchanged.**
  A writer now sends each packet from a borrowed view of its matched readers (two GUIDs and the
  PARTITION verdict) instead of cloning every reader's whole discovery record, QoS and TypeObject
  included, per packet; a peer's vendor id is found by its participant key before any scan; a
  write reads the clock once for its source timestamp; and an acknowledgement on a reliable local
  pairing wakes the history's waiters only when one is waiting, instead of a futex system call per
  sample. Measured on the benchmark host (i9-9900KF, governor performance, thin LTO, cgu=1, interleaved runs,
  medians): one-thread write->take of a 16-byte POD, KeepLast(1), 10 x 10M samples, core 3:
  BEST_EFFORT p50 180.5 -> 168 ns, RELIABLE p50 365 -> 260 ns; RELIABLE KeepLast(1) keyed
  back-to-back writes to a reader in another process over UDP loopback, 8 x 15 x 20000: 3632 ->
  3084 ns per write, and 4589 -> 3746 ns with TOPIC coherent sets of 10.
- **A reliable writer's periodic HEARTBEAT (RTPS v2.5 Sec.8.4.7.2) is now an entry on its
  participant's liveliness scheduler instead of a dedicated per-writer thread.** One participant
  with 50 reliable writers ran 50 `hdds-heartbeat` threads before this change; it runs 0 after, the
  single `hdds-liveliness` thread already carrying LIVELINESS and DEADLINE now also carrying every
  one of those 50 periodic HEARTBEATs (measured via `/proc/self/task` thread-name counts,
  benchmark host, 2026-10-25; a writer built with no participant still gets its own dedicated thread, unchanged --
  it was already the only writer shape that mechanism ever ran for, since a writer gets no RTPS
  endpoint, and so no periodic HEARTBEAT origin of either kind, without a participant). The actual
  wire sends go out on one further long-lived `hdds-hb-sender` thread per participant (never the
  scheduler thread, never the thread application callbacks use), fed by a bounded queue with a
  per-writer admission gate: at most one send in flight or queued per writer at a time, a tick that
  comes due while one is still outstanding is coalesced rather than piling up, and a writer's drop
  waits, bounded, for its own in-flight send before returning, same intent as the dedicated
  thread's old join -- the sub-points below cover where that bound holds unconditionally
  (non-Windows) and where it is still the older, best-effort `wait_idle` fallback (Windows, and
  anything else listed there a send can still block on). Measured (strace, `clone`/`clone3`, 50 writers
  idle for 1.28 s at their ~100 ms period, 2026-10-25): every thread this setup ever creates is
  created during the initial 17 ms of participant/writer construction (18 total); zero new threads
  during the steady-state window itself. The one-thread write-then-take hot path this does not
  touch either way (BEST_EFFORT, as `latency_benchmark` always is): benchmark host, `cargo build --release`
  (default profile), taskset -c 4, governor performance restored after, 3 runs, p50 152-154 ns /
  p99 166-167 ns / 5.77-5.82 M msg/s, matching the existing 2026-10-23 baseline (p50 152-153 ns /
  p99 167-169 ns / 5.76-5.81 M msg/s) within run-to-run noise -- a RELIABLE writer's on-write path
  still pays the same single `Option` check it always did, now behind an enum match instead of a
  direct field.
  - Five review passes tightened the deletion barrier further. "No HEARTBEAT SUBMITTED after
    drop returns" is now the guarantee on every platform where the periodic transmit is
    non-blocking (every supported Unix target; Windows is the standing exception noted above,
    still only the older `wait_idle` bound): the periodic origin holds its send gate for its
    ENTIRE submission (every per-reader send and the multicast fallback, one critical section,
    every check inside it a `try_lock` that drops a packet on contention rather than waiting),
    and a writer's drop takes that exact same lock to revoke send permission -- it cannot return
    while that submission is still running, closing a gap the first two passes' "check the flag
    right before each transmit, then release" discipline still left open (a send already past
    its own check could out-wait the OLD bounded 2 s fallback below and reach the wire
    afterward). Submission, deliberately, not delivery: a destination in a Discovery Server
    relay range is hand off to the relay's own queue (`RelaySink::offer`, returning once the
    datagram is accepted, same as a socket's own `send_to`), and a datagram already accepted
    there before drop revoked sends can still be drained and put on the wire by the relay
    session's own thread afterward -- the gate bounds when this writer stops HANDING OFF
    packets, not when every packet already handed off finishes its own trip. A panicking sink
    (a bug in a dialect/codec path, say) no longer takes the single sender thread -- and every
    other writer's periodic HEARTBEAT with it -- down permanently (`catch_unwind` around each
    `fire()`, with an RAII-cleared admission slot so a panic can never leave a writer stuck
    coalescing forever). A writer destroyed by code running ON the scheduler or sender thread
    itself (a sink callback owning the last reference to it) skips the separate, still-bounded
    `wait_idle` fallback instead of stalling every other timer on that thread for up to 2
    seconds -- the gate-holding revoke already gives the real guarantee with nothing further to
    wait for.
  - Trade-off, documented rather than hidden: the single sender thread still processes jobs
    strictly one at a time, so one writer's blocked send would still delay every other writer's
    periodic HEARTBEAT queued behind it, where the one-thread-per-writer design before this
    change gave each independent progress. The kernel socket send specifically is closed on
    most platforms (see the Fixed entries above: non-blocking transmit, Windows the one
    remaining gap) and the two inherited ordering defects those entries also close. That is a
    narrower claim than "nothing can block this worker": `HistoryCache::oldest_seq` (lifespan
    pruning plus a ring-mutex read), the classic-dialect window table's own mutex, `EndpointRegistry`
    's blocking `RwLock` reads, and the ordinary synchronous logger's global lock are all still
    blocking, ordinary acquisitions on this path, same as before this change and shared with
    write()/dispose()/ACKNACK far beyond this one call site -- converting them to a
    try-and-defer-the-tick discipline is a larger, separate piece of work, listed rather than done
    here (see `dds::liveliness::scheduler`'s module doc for the precise list).
- **The one-thread write-then-take latency is back from 148 ns to 132 ns
  (p50) in the default build, 128 ns with the new `fast-consumer-gate`
  feature; the 2026-08-30 certificate was 114 ns.** Regime: benchmark host
  (i9-9900KF), `latency_benchmark` example (`write` of a 16-byte POD then
  `take`, one thread pinned to core 3, BEST_EFFORT KEEP_LAST 1, 10 000
  messages), governor performance, stock idle policy, release + thin LTO +
  one codegen unit + empty RUSTFLAGS + `--locked`, rustc 1.92.0,
  `HDDS_INTERFACE=lo`, 8 rounds interleaved with the 1.5.0 candidate before
  the change and with the certificate binary; each figure is the median of
  the per-round p50 (2026-10-11).
  - A KEEP_ALL reader's history place is a one-byte flag on the cached
    sample instead of a field with a destructor, and the sample cache gives
    places back at each site a sample leaves it. The destructor had made
    every cached sample of every reader carry drop glue, and the take path
    moves samples through stack temporaries: blocked store-forwards went
    from 12 to 3.5 per message. 147.5 ns -> 131 ns (2026-10-10, same
    regime without `HDDS_INTERFACE`). Two compile-time assertions now
    refuse drop glue on `CachedSample` and any growth past 72 bytes
  - New Cargo feature `fast-consumer-gate`, off by default. With it, the
    reader's consumer gate costs a reader drained by a single thread no
    locked instruction: that thread enters with plain stores and loads, and
    the first other consumer (a WaitSet thread, a second take thread)
    engages the compare-and-swap for good through a `membarrier(2)`
    handshake. Its correctness rests on the Linux kernel's membarrier
    contract and on a compiler fence acting as a compiler barrier, outside
    the Rust abstract memory model, which is why the default build keeps
    the compare-and-swap gate. Linux only; elsewhere, under Miri, or where
    `membarrier` is refused, the feature falls back to the compare-and-swap.
    One-time cost: the process's first DataReader registers `membarrier`,
    an RCU grace period (40 ms measured on the benchmark host). 132 ns -> 128 ns
  - 10 000 000-message variant of the same loop, 5 interleaved rounds:
    p50 130 ns default, 127 ns with the feature (certificate binary 113 ns);
    p99 143 / 141 ns (125); 6.61 / 6.74 M msg/s (7.59). The 1.5.0 candidate
    before the change measured p50 147 ns, p99 161 ns, 5.90 M msg/s
    (2026-10-10)
  - Unchanged, measured against the same candidate on 2026-10-10 with both
    changes: the cross-thread polling and WaitSet arms of
    `latency_benchmark_xthread` (cores 2 and 3, idle states past C1
    disabled, 10 rounds: p50 329 -> 318.5 ns and 2598.5 -> 2604.5 ns), and
    the 64-byte UDP loopback round trip (8 rounds: 22.25 -> 21.98 us)
  - Not recovered: about 5 ns came with the view state stamped on every
    take (DDS v1.4 Sec.2.2.2.5.1.8), about 2.5 ns with the commits that
    followed it in September, and about 3.5 ns are not attributed: the
    candidate with the place fix (131 ns) stays above the parent of the
    KEEP_ALL change (127.5 ns), and no bisect has yet separated this fix
    from the commits made since
  - Measuring this example on a host that sees other DDS participants on
    its domain is not the regime above: any discovered remote participant
    sends every write down the wire path (`has_remote_peers`), and the
    figure becomes a different one (533 ns for the feature build, whose
    40 ms registration lets discovery land before the loop starts)

UDP round-trip figures below come from a two-process ping/pong (keyed 12-byte
header + baggage, RELIABLE / KEEP_LAST 1 / VOLATILE, listener-driven like
Cyclone DDS `ddsperf`), benchmark host (i9-9900KF, governor performance), both
processes on loopback, pong pinned to CPUs 4-5 and ping to CPUs 2-3, 100 000
round trips per round after 1000 warm-up, rounds interleaved with the
previous commit's binary. Each figure is the median over the rounds, with the
[min..max] across rounds; CPU is ping + pong process time per 100 000 round
trips.

- **`DataWriter::write` no longer allocates and zeroes 64 KiB per sample on
  the wire path.** The sample is encoded into a scratch buffer kept by the
  writer and kept all zero at rest: the bytes an encode touched are zeroed
  again afterwards, so an encoder that skips padding still emits zeros and
  never a byte of an earlier sample. 6 rounds per cell:

  | payload | p50 before | p50 after | p99 before | p99 after | CPU before | CPU after |
  |---|---|---|---|---|---|---|
  | 64 B | 27.52 us [26.94..27.89] | 25.43 us [24.98..25.89] | 45.60 us | 41.93 us | 4.92 s | 4.62 s |
  | 1024 B | 28.78 us [28.20..28.96] | 26.23 us [25.91..26.93] | 47.02 us | 43.41 us | 5.05 s | 4.83 s |
  | 8192 B | 36.40 us [35.80..36.83] | 34.16 us [33.65..34.27] | 60.71 us | 56.53 us | 5.96 s | 5.70 s |

- **A network reader no longer allocates and zeroes 64 KiB per received
  sample.** Each sample a reader admits off the wire is re-encoded before it
  enters the reader's ring, and that re-encode also went into a fresh
  `vec![0u8; 65_536]`. It now uses the same all-zero-at-rest scratch as the
  writer, kept by the reader. 6 rounds per cell, against the previous
  commit:

  | payload | p50 before | p50 after | p99 before | p99 after | CPU before | CPU after |
  |---|---|---|---|---|---|---|
  | 64 B | 25.06 us [24.92..25.39] | 22.37 us [22.09..22.91] | 41.93 us | 37.24 us | 4.62 s | 4.34 s |
  | 1024 B | 26.12 us [25.88..27.22] | 23.86 us [23.36..24.85] | 43.75 us | 40.29 us | 4.82 s | 4.51 s |
  | 8192 B | 33.78 us [33.62..35.01] | 31.59 us [31.28..31.84] | 56.08 us | 53.05 us | 5.67 s | 5.45 s |

- **The router thread is woken by a park/unpark instead of a mutex and a
  condvar.** When a receive thread hands a datagram to an idle router,
  `WakeNotifier::notify` used to take a mutex to learn whether the router
  slept, then signal a condvar whose waiter re-took the mutex before it
  could run. It is now one futex wake on the router's own thread parker,
  with no shared lock on either side; a sequentially consistent flag pair
  keeps any wakeup from being lost (pinned by a 2000-round park/unpark
  test). Public API unchanged. 6 rounds per cell, against the previous
  commit:

  | payload | p50 before | p50 after | p99 before | p99 after | CPU before | CPU after |
  |---|---|---|---|---|---|---|
  | 64 B | 22.57 us [22.16..22.95] | 22.05 us [21.98..22.39] | 37.40 us | 36.60 us | 4.36 s | 4.31 s |
  | 1024 B | 23.86 us [23.52..24.62] | 23.31 us [22.78..24.20] | 39.39 us | 37.76 us | 4.53 s | 4.45 s |
  | 8192 B | 31.69 us [31.22..32.30] | 30.81 us [30.64..31.27] | 53.26 us | 53.05 us | 5.45 s | 5.37 s |

- **The router's spin before it sleeps can be set in wall time:
  `HDDS_ROUTER_SPIN_US`.** Unset, nothing changes (200 `PAUSE`, about 7 us
  of CPU per wake on the machine below, judging by the CPU it costs). The
  spin pays only when the next datagram arrives inside it. The default one
  did not move the p50 in any of the three regimes measured, but it is
  not inert: in a later same-run back-to-back comparison against `0` (64 B,
  5 rounds each) it had the same p50 (21.91 against 22.16 us), a better
  p99 (32.24 against 36.63 us) and a lower minimum (14.08 against
  20.76 us, close to a 30 us spin's 14.04 us), at 4.29 against 2.77 s of
  CPU. So it catches a reply now and then, at a CPU price; superseded
  below, where it is measured against adaptive and removed. Same harness; "fixed rate" sends one ping per period
  from the application thread instead of chaining pings; CPU is ping +
  pong process time for the whole run:

  | regime | setting | p50 | p90 | p99 | CPU |
  |---|---|---|---|---|---|
  | back-to-back, 64 B | unset | 22.50 us [22.24..23.39] | 24.87 us | 38.10 us | 4.35 s |
  | back-to-back, 64 B | `20` | 14.93 us [14.85..15.05] | 15.61 us | 20.76 us | 3.83 s |
  | back-to-back, 1024 B | unset | 23.62 us [23.26..23.68] | 25.91 us | 35.54 us | 4.47 s |
  | back-to-back, 1024 B | `20` | 16.11 us [15.86..16.19] | 17.14 us | 23.03 us | 4.17 s |
  | back-to-back, 8192 B | unset | 31.45 us [31.23..32.12] | 33.81 us | 51.62 us | 5.41 s |
  | back-to-back, 8192 B | `20` | 23.42 us [23.33..23.65] | 24.66 us | 39.40 us | 5.86 s |
  | fixed 1 kHz, 64 B | unset | 81.73 us [81.22..82.42] | 113.74 us | 141.08 us | 1.69 s |
  | fixed 1 kHz, 64 B | `0` | 82.50 us [81.68..85.53] | 116.15 us | 138.20 us | 1.45 s |
  | fixed 1 kHz, 64 B | `20` | 84.02 us [82.79..86.07] | 111.30 us | 139.39 us | 1.91 s |
  | fixed 10 kHz, 64 B | unset | 24.82 us [24.70..24.91] | 51.14 us | 78.26 us | 2.85 s |
  | fixed 10 kHz, 64 B | `0` | 24.93 us [24.69..25.10] | 56.13 us | 79.25 us | 2.11 s |
  | fixed 10 kHz, 64 B | `20` | 24.83 us [24.48..25.73] | 45.34 us | 73.77 us | 4.08 s |

  Back-to-back: 5 rounds of 100 000, this commit's binary. Fixed rate: 3
  rounds of 10 000 (1 kHz) and 50 000 (10 kHz), "unset" being the previous
  commit and `0`/`20` the experimental build this knob came from (the same
  spin loop, reading the variable inline). A loopback request/reply peer turns around
  in about 10 to 12 us here, and every budget from 15 us to 50 us gave
  the same back-to-back p50; 10 us caught only part of the replies. Over a
  real network the turnaround includes the wire, and a budget shorter
  than it buys nothing.

- **`HDDS_ROUTER_SPIN_US=adaptive`, and counters that say what a spin
  buys.** Opt-in; unset and numeric values keep their meaning. Each router
  thread learns its budget in the manner of KVM halt-polling: the time
  from finding its ring empty to the next datagram doubles the budget
  (from 2 us, up to 50 us) when a bigger spin would have caught it and
  halves it (to 0 below 2 us) when even 50 us would not; missed spins are
  capped at 5% of a core per 100 ms. Not measured yet, so not a default.
  `RouterMetrics` (reached through `Participant::router()`) gains
  `spin_hits`, `spin_misses`, `spin_ns_wasted`, `parks` and
  `spin_budget_ns`, updated for every setting, the default included; a
  pop that succeeds at once reads no clock and updates no counter. The
  200-`PAUSE` spin now reads the clock twice per park to time its misses.
  `config::env_flags::router_spin_budget()` (new in this cycle) became
  `router_spin()`, returning a `RouterSpin`.

- **The router spin's default is now `adaptive`, and the historical
  200-`PAUSE` spin is removed.** `HDDS_ROUTER_SPIN_US` unset, empty, or
  unparseable now reads as adaptive, same as `adaptive` itself; `0`
  restores the old park-immediately behaviour (no spin at all); a whole
  number of microseconds is still a fixed wall-time budget. The
  200-`PAUSE` spin is gone (its duration depends on the CPU
  microarchitecture, and it is dominated by adaptive on p50 and by `0`
  on CPU in every regime below), so `RouterSpin::Legacy` no longer
  exists. Measured on the benchmark host (i9-9900KF, governor performance, loopback,
  ping pinned to CPUs 2-3, pong to 4-5, 5 rounds per row interleaved with
  rotating order, one binary at `9b666504` with the variable set per
  run, 2026-10-12; CPU is the ping+pong process time per 100 000 round
  trips; values are median [min..max] across rounds; evidence kept by
  the maintainers):

  | regime | setting | p50 | p90 | p99 | CPU |
  |---|---|---|---|---|---|
  | back-to-back, 64 B | previous default (200 PAUSE) | 23.74 us [23.47..23.81] | 25.70 us | 37.91 us | 4.60 s |
  | back-to-back, 64 B | `0` | 23.82 us [23.63..23.93] | 25.48 us | 38.35 us | 2.99 s |
  | back-to-back, 64 B | `20` | 16.48 us [16.29..16.68] | 17.32 us | 23.22 us | 4.24 s |
  | back-to-back, 64 B | adaptive | 16.52 us [16.26..16.70] | 17.28 us | 22.76 us | 4.24 s |
  | back-to-back, 8192 B | previous default | 32.14 us [31.96..32.61] | 34.30 us | 47.26 us | 5.61 s |
  | back-to-back, 8192 B | `0` | 32.24 us [32.08..32.38] | 34.35 us | 50.08 us | 4.01 s |
  | back-to-back, 8192 B | `20` | 24.56 us [24.48..24.65] | 25.68 us | 38.78 us | 6.09 s |
  | back-to-back, 8192 B | adaptive | 24.46 us [24.34..24.76] | 25.64 us | 37.77 us | 6.07 s |
  | fixed 1 kHz, 64 B | previous default | 85.38 us [84.27..88.47] | 113.86 us | 141.98 us | 1.74 s |
  | fixed 1 kHz, 64 B | `0` | 85.18 us [82.84..86.28] | 119.89 us | 141.60 us | 1.49 s |
  | fixed 1 kHz, 64 B | `20` | 88.71 us [86.98..92.52] | 121.55 us | 146.29 us | 1.98 s |
  | fixed 1 kHz, 64 B | adaptive | 86.04 us [85.62..91.03] | 120.90 us | 148.22 us | 1.52 s |
  | fixed 5 kHz, 64 B | previous default | 58.69 us [58.22..58.88] | 92.64 us | 116.86 us | 2.10 s |
  | fixed 5 kHz, 64 B | `0` | 59.96 us [58.83..65.17] | 95.50 us | 124.82 us | 1.60 s |
  | fixed 5 kHz, 64 B | `20` | 57.57 us [54.09..57.92] | 90.55 us | 114.41 us | 2.62 s |
  | fixed 5 kHz, 64 B | adaptive | 59.68 us [58.44..60.13] | 94.39 us | 127.01 us | 1.59 s |
  | fixed 10 kHz, 64 B | previous default | 25.63 us [25.33..25.88] | 51.60 us | 78.47 us | 2.94 s |
  | fixed 10 kHz, 64 B | `0` | 25.73 us [25.65..25.91] | 57.17 us | 80.84 us | 2.11 s |
  | fixed 10 kHz, 64 B | `20` | 25.60 us [25.21..25.71] | 45.19 us | 73.59 us | 4.16 s |
  | fixed 10 kHz, 64 B | adaptive | 25.85 us [25.70..25.90] | 57.26 us | 80.25 us | 2.12 s |

  Back-to-back, adaptive caught about 99.7% of its wakes in a spin (e.g.
  100871 hits against 311 misses at 64 B), with a learned budget of
  25-50 us; at 1, 5 and 10 kHz the learned budget stayed at 0. The
  honest trade-off: at a fixed rate, the previous default had a better
  p90 than adaptive (113.86 against 120.90 us at 1 kHz, 51.60 against
  57.26 us at 10 kHz) for 14-39% more CPU; adaptive gives that up for the
  lower CPU. So the earlier framing of this knob as "not a default" no
  longer holds: adaptive measured equal to or better than the previous
  default everywhere, and is now it.

### Security

By Keep-a-Changelog convention a `Security` heading reads as "vulnerabilities
that existed in the last published release". **Thirteen of the fifteen entries
below are exactly that.** The two marked *[no 1.4.x exposure]* are not: they harden
subsystems introduced during this cycle, and no published release ever shipped
the code they concern. A 1.4.x operator has no DNS-SD module at all, and an
Azure backend that makes no network call, so neither can reach them. Saying so
is the point -- a reader who cannot tell the two apart has to assume the worst
about a release that does not deserve it.

- **ROS 2 `ROS_SECURITY_STRATEGY=Enforce` was fail-open.** A node started
  unsecured when security could not be established. `rmw_init` now returns an
  error and refuses to start; `Permissive` is still allowed and logs loudly
- **A DDS-Security configuration with only half of a governance or permissions
  document pair was treated as permissive** rather than as the configuration
  error it is
- **Cloud registry endpoints must be HTTPS.** Plaintext `http://` is accepted
  only for a literal loopback host, with no flag or environment escape hatch,
  and instance-metadata endpoints are restricted to link-local or loopback.
  All three cloud HTTP clients are built with proxying disabled, so
  `HTTP_PROXY` or `ALL_PROXY` cannot route a registry call through an
  unintended host
- *[no 1.4.x exposure]* **A DNS-SD answer is now matched against the question that was asked.** The
  echoed-question check was skipped when `QDCOUNT` was zero and answer records
  were validated by type only, so a responder that echoed the message id could
  return an address record for any name it chose. A partial lookup failure also
  no longer retires peers it never mentioned
- **A `participant_announce` with a missing or malformed domain id defaulted
  to domain 0**, which is a real domain and not a sentinel, silently breaking
  domain isolation. It is now rejected
- **A primitive sequence count is checked against the remaining wire bytes
  before allocating**, so a hostile or corrupt dynamic sample cannot drive a
  large allocation
- **`LIKE` matching is iterative and polynomial**, and filter expressions are
  bounded in nesting depth and node count, which also closes a stack overflow
  on deeply nested expressions
- *[no 1.4.x exposure]* **Azure request URLs are no longer echoed into error messages**, a registry
  row is no longer trusted blindly, a hostile token lifetime is clamped, and
  the AWS credential chain can no longer panic or misencode
- **One datagram could flood the reliability control channel.** A single
  unauthenticated 65 535-octet datagram of HEARTBEATs that each declared a
  one-octet body became 13 097 HEARTBEATs, read against the datagram rather
  than their submessage, 12.8 times the channel's 1024 slots, flushing every
  other peer's HEARTBEATs and ACKNACKs. Bodies are now read inside their own
  submessage, and each datagram contributes at most 64 HEARTBEATs, GAPs,
  ACKNACKs and NACK_FRAG samples
- **One HEARTBEAT could make a reader allocate hundreds of megabytes.** A
  big-endian HEARTBEAT decoded little-endian produced a bogus range, and the
  missing-sequence list grew one entry per number (671 MB for one datagram).
  The list is capped at the ACKNACK bitmap width
- **One malformed GAP blinded a reader for good.** A GAP with a zero or
  negative gapStart, or an invalid gapList, moved the reader's delivery base
  near 2^63, and every later DATA from that writer was dropped silently. Such
  GAPs are refused at decode (RTPS 2.5 8.3.8.4)
- **A DATA from a writer that is not a discovery writer could register a
  participant.** Four crafted octets sufficed: a DATA declaring an 8-octet body
  took its writer id from the next submessage. Any DATA from a writer no
  builtin handler claims, including an application topic or a peer's
  liveliness writer, went through the SPDP parser and registered a
  participant if its payload carried a participant GUID. Discovery now trusts
  only the builtin writers, and a writer id is read inside its own DATA
- **A Discovery Server started with `--relay` could be stalled by one client
  that stopped reading, and deadlocked for good by two**, and on every path a
  write to a stuck client had no deadline. A stalled client is now evicted
  and replayed in full when it reconnects, writes give up after 10 s, a
  cancelled read no longer desynchronises the stream, and relayed data no
  longer crosses domains
- **A flood of spoofed DATA_FRAGs could evict a genuine peer's reassembly,
  and the reassembly buffer had no memory bound.** Any source, before
  authentication, could fill the discovery buffer's 256 sequences from as
  many forged GUID prefixes and push out the sequence a genuine peer was
  reassembling (a fragmented handshake message, an SPDP or SEDP
  announcement): 1.4.0 evicted the oldest sequence of any writer. Each
  sequence could also hold up to its declared `sampleSize`, one allocation
  per fragment, at any fragmentSize down to 1 octet. Now a sequence holds
  its sample in one buffer with a bitmap of the fragments received, and is
  charged that buffer, the bitmap and its bookkeeping from its first
  fragment against an octet budget (16 MiB for discovery, 256 MiB by
  default); one that would cost more is refused at its first fragment.
  The prefixes discovery does not know share a quarter of each bound, and
  one sample of theirs may cost at most that pool's octets over its
  sequences (64 KiB for discovery, 1 MiB for user data); among them the
  sequence idle longest goes. They never evict a known participant's
  sequence, so a flood from forged prefixes competes with itself; a
  participant not known yet still completes a fragmented SPDP unless the
  flood opens 64 sequences between two of its fragments. Among known
  participants the sequence furthest from completion goes, and a
  participant's first sequence is never its own victim. Known means an
  SPDP with a usable locator was received for it, which no authentication
  backs, so a source that also forges SPDP announcements competes with
  genuine peers, under three limits: a sequence past half its sample's
  octets and over 16 KiB received is never evicted by one of its rank,
  within its participant's share of the sequence bound; a participant's
  most advanced sequence goes only for one further along, so two samples
  that cannot be held together complete one after the other; and both
  last the buffer's timeout from the first fragment. Every buffer drops
  its expired sequences before making room, not only the one a timer
  sweeps. Our own prefix ranks as a source not known (our own fragments
  never reach a buffer), and a participant authenticated by DDS Security
  ranks above the merely known only when the governance protects whole
  RTPS messages, since nothing else authenticates the prefix a DATA_FRAG
  claims
- Two flagged dependency advisories resolved

---

The interoperability builds published during this cycle as `hdds-1.4.6`,
`hdds-1.4.7` and `hdds-1.4.8` were conformance-matrix assets rather than
crate releases. Everything they carried is folded into 1.5.0.

---

### Known issues

- On Windows, shutting down or dropping an `AdminApi` server (the admin TCP
  server the debugger examples start) can wait until a client connects,
  because its accept thread blocks; participants and their data path are not
  affected.
- On Windows, when a DNS server answers a DNS-SD query with a datagram larger
  than the advertised UDP size, the resolver reports a generic I/O error and
  tries the next nameserver or attempt instead of reporting a truncated
  answer; no partial peer list is ever used.

### Contributors

Thanks to the people who sent changes for this release:

- Kristaps Skujiņš: use the libc constants for `IP_TTL` / `IP_MULTICAST_TTL` and `IP_TOS` in the UDP transport (#16)
- Carlo Corradini: fix the WaitSet wait in the Rust hello-world documentation (#14)

## [1.4.0] - not published

This number was a workspace version, never published on crates.io and never cut as a release.
Its content is described here as it was recorded and is part of the work 1.5.0 publishes.

### Added
- **Cross-reader coherent presentation** under the PRESENTATION QoS with
  `coherent_access` enabled: coherent changes (RTPS 2.5 coherent sets) are
  now aligned across all DataReaders attached to the same Subscriber, so a
  coherent update spanning multiple topics becomes visible as one consistent
  generation instead of per-reader slices
  - New `ReaderBuilder::subscriber()` API to attach a DataReader to a
    Subscriber for cross-reader alignment
- Listener API for callback-based data notifications
  - `DataReaderListener` trait with `on_data_available()`, `on_subscription_matched()`, etc.
  - `DataWriterListener` trait with `on_sample_written()`, `on_publication_matched()`, etc.
  - `ClosureListener<T, F>` for simple closure-based callbacks
  - Builder pattern: `.with_listener(Arc::new(MyListener))`
- **QUIC Transport** for modern connectivity (feature `quic`)
  - NAT traversal and firewall-friendly (UDP-based)
  - 0-RTT connection establishment for known peers
  - Connection migration (IP change without disconnect)
  - Built-in TLS 1.3 encryption
  - Self-signed certificates for HDDS-to-HDDS
- Content-filtered topics
- Shared memory transport (experimental)

### Changed
- Workspace version bumped to 1.4.0
- License metadata aligned across the workspace: every crate now resolves
  to `Apache-2.0 OR MIT`

### Fixed
- **DATA_FRAG payload extraction** for large messages: the fragment
  metadata that DATA_FRAG carries beyond a plain DATA submessage is now
  accounted for when locating the serialized payload, and the CDR
  encapsulation header is stripped during reassembly

## Version numbers that were never published

The numbers 1.1.3, 1.1.4 and 1.1.5 exist only as git tags. They were never published on
crates.io, there is no crate, no release and no installable artifact under any of them, and the
1.1.x line published on crates.io ends at 1.1.2. They are not releases. No entry is kept for 1.1.4.

What the repository records for the other two is kept here for completeness. It is unpublished
like the numbers themselves:

### 1.1.5 (git tag only, not published)

- CoreDX DDS Q-flag interoperability fix.

### 1.1.3 (git tag only, not published)

- Publisher group sequence number (GSN) runtime and coherent-set end markers per RTPS 8.7.5.
- Audit findings across the workspace.

## [1.1.2] - 2026-04-17

### Fixed

- Interoperability corrections raised by RTI on the OMG continuous-integration runs.
- The C++ binding routes raw readers and writers through an explicit type-name entry point.
- Cross-language tests detect the network interface instead of requiring `HDDS_INTERFACE` to be
  set by hand.

### Added

- `TimeBasedFilter` and `Lifespan` are honoured, and a writer unregisters its instances
  automatically.

### Security

- Patched the advisories RUSTSEC-2026-0098 and RUSTSEC-2026-0099 in `rustls-webpki`.

## [1.1.1] - 2026-03-26

### Added

- `on_publication_matched` and `on_subscription_matched` are reported by the middleware, per
  DDS 1.4 clause 2.2.2.4.
- `HDDS_INTERFACE` forces the network interface used for discovery and data.
- `HDDS_INTEROP_DIAGNOSTICS` enumerates received submessages, for diagnosing a foreign peer.

### Fixed

- Bidirectional interoperability with RTI Connext 7.3.0: a deadlock, a wrong entity kind, and a
  race in endpoint discovery.
- Heartbeats embedded in a compound RTPS message were ignored; they are now extracted.
- Acknowledgements are sent to the peer's metatraffic port rather than to the source port of the
  data, and carry the Final flag.
- QoS matching is applied to endpoint discovery, so incompatible endpoints no longer match.

### Security

- Patched the published advisories in `lz4_flex` and `rustls-webpki`.

## [1.1.0] - 2026-03-16

### Added

- QoS is enforced in the library rather than by the sample applications, which is what took the
  OMG interoperability suite to 48 of 48 at the time.
- The instance lifecycle is implemented: dispose, unregister, and a native deadline.

### Fixed

- The ROS 2 middleware layer enables data-available notifications when a reader is attached to a
  wait set.

## [1.0.11] - 2026-03-13

### Added

- A typed Python API with listener methods, and Rust SDK documentation.
- A Java sample built on the Panama foreign-function interface.
- Per-domain discovery-server support in the router.

### Changed

- Generated type code is no longer stored in the repository; a script regenerates it.

### Fixed

- A domain identifier of 0 was treated as unset.
- A failed write left a pending entry behind in the remote-procedure-call client.
- End-of-file was reported as an endianness mismatch.

## [1.0.10] - 2026-03-09

### Added

- macOS support.
- A builder API for participants, writers and readers, replacing the older constructors.

### Fixed

- Multicast failed to bind on Windows with error 10049.
- Corrections across the Python, C++ and TypeScript bindings.

## [1.0.9] - 2026-03-07

### Added

- A configuration builder and domain-identifier support across every language binding, with typed
  cross-language tests.
- The intra-process fast path.

### Fixed

- Factual errors in the README.

## [1.0.8] - 2026-02-27

First public release.

## Migration notes

### Constructors to builders (1.0.10)

The direct constructors were replaced by builders. Both forms exist in 1.0.10 and later; the
builder is the supported one.

```rust
// before
let writer = participant.create_writer::<Shape>(&topic)?;

// after
let writer = topic.writer().build()?;
```

### Generated code (1.0.11)

Generated type code was removed from the repository. Run the generator (`generate.sh` in the sample
directories) as part of your build rather than relying on committed output.
