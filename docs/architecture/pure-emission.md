# Pure Emission: Journal Fidelity Design (DRAFT for review)

Status: Phase-0 landed; Phase-1 schema in design review. No production emission
path is rerouted yet -- the migration below (section 4) is in progress at Phase 1.
Executable problem statement: `crates/hdds/src/dds/writer/emission_parity_tests.rs`
(5 red tests, run with `cargo test -p hdds --lib emission_parity_tests -- --ignored`).
Phase-0 proof (read-only, zero behaviour change): a pure Canonical oracle
reproduces the live self bytes for all four emission forms (plain/coherent DATA,
ECS close, dispose/unregister, DATA_FRAG), gated by `*_golden_still_matches_live`
+ `*_oracle_reproduces_*_byte_for_byte` tests in
`crates/hdds/src/dds/writer/emit_canonical.rs`.

## 1. Problem

The writer's `HistoryCache` stores approximately `(seq, payload)`. Everything else the
live path puts on the wire -- source timestamp, coherent-set tags, key hash, status info,
the CDR version the body was encoded with, the coherent close marker's wire form -- is
computed on the fly at live-send time and is not recorded. Repair (`nack.rs`) and
transient-local replay (`runtime.rs::replay_to`) therefore rebuild cached samples from
payload alone and physically cannot reproduce the bytes the live path emitted.

Measured consequences on the current tree (each is one red test):

1. Repair strips `PID_COHERENT_SET` / `PID_GROUP_COHERENT_SET` / `PID_GROUP_ENTITY_ID` /
   `PID_KEY_HASH` that live emitted.
2. Repair's encapsulation header is derived from the writer's stable default CDR version,
   not the version the cached body was actually encoded with: the header can lie about
   the body.
3. A NACK for a coherent close marker's SN is answered with a generic empty DATA
   (flags 0x07), not the close wire form (flags 0x03 + `PID_COHERENT_SET`): the cache
   holds an empty stub for that SN.
4. `dispose()` / `unregister_instance()` consume a writer SN that never enters the
   cache at all: instance lifecycle is unreplayable for late joiners.
5. Emission is not deterministic: `INFO_TS` is re-stamped on every build, so the same
   change emitted twice never produces the same bytes.

## 2. Invariants (the journal constitution)

- J1  -- everything that consumes a writer SN lives in the journal, with its form
  (`kind`). This includes the coherent close and dispose/unregister.
- J1' -- journal CONTENT never depends on the audience. Whether a close exists is
  decided by QoS/API, never by discovery state. Only the FORM is per-peer.
- J2  -- dialect(unresolved peer) = NATIVE, never foreign. Tombstone test: bytes
  emitted to a never-resolved peer equal the self-dialect bytes.
- J3  -- reader side: a close re-received for an already-committed set is a no-op.
  On the TOPIC/INSTANCE path this is proven and locked by
  `close_redelivery_is_noop_on_committed_set` (mutation-tested teeth). On the
  GROUP path it holds OBSERVABLY today but by accident of buffer emptiness, not
  by an explicit monotone guard (a replayed close does a transient
  create-then-remove of a phantom empty set; see the reader-side tracker in
  section 5). The refactor MUST make J3 structural on the GROUP path too, so the
  invariant is enforced by a monotone tracker rather than by a side effect.
- J4  -- cryptography is an `address()` step, never an `emit_canonical()` step.
  `emit_canonical` output is plaintext by contract, which makes an
  encrypted-live/plaintext-repair divergence impossible by construction. Crypto
  and fragmentation both live in `address()` and their ORDER is pinned: the
  serialized payload is encrypted first, then the (ciphertext) result is what
  fragmentation splits -- so a fragment boundary never falls inside a plaintext
  region and reassembly on the peer decrypts the recombined payload. Because
  `emit_canonical` is plaintext, the journal stores plaintext (a security build
  today re-emits plaintext on repair -- the inventory's third bombshell); routing
  repair through `address()` closes that hole by construction rather than by a
  patch. Wire-verified only when a security pair exists in the rig (deferred).

## 3. Target architecture

The concrete type is `CacheEntry` in `crates/hdds/src/reliability/history_cache.rs`
(the writer history-cache ring element), `#[repr(C)]`, `Copy`, guarded by a
compile-time `size_of` / `align_of` assert so any layout drift fails the build:

```
CacheEntry {
    seq: u64,             // writer SN + ring scan key; MUST stay at offset 0
    ts_ns: u64,           // insert wall clock; drives LIFESPAN (unchanged)
    instance_key: u64,    // 64-bit bookkeeping hash for per-instance limits
    coherent_sn: u64,     // set-first SN, self-carried per member; 0 = not in a set
    group_sn: u64,        // publisher GSN under GROUP scope; 0 = not GROUP scope
    source_ts_sec: u32,   // RTPS Time_t; dormant until Phase 2 (stored, not emitted)
    source_ts_frac: u32,
    slab: SlabHandle,     // body-only payload (no encap header), plaintext (J4)
    len: u32,             // payload length (u32 so the size is 32-bit-target stable)
    key_hash: Option<[u8; 16]>,  // wire PID_KEY_HASH; None for unkeyed / CoherentClose
    kind: EntryKind,      // Data | Dispose | Unregister | DisposeUnregister | CoherentClose
    cdr_version: CdrVersion,     // version the body was encoded with (encap bridge)
}
```

`coherent_sn` / `group_sn` use a `0` sentinel (RTPS SNs are `>= 1`) rather than
`Option<u64>` to save 16 bytes per entry; call sites stay `Option`-typed via a
`CacheEntryMeta` insert descriptor and `CacheEntry::coherent_sn()/group_sn()`
accessors. The closure travels INSIDE the entry (no side table -- constraint C1).
Storing the payload BODY-ONLY plus `cdr_version` is a deliberate bridge: it lets a
later phase re-derive the encapsulation header deterministically (or migrate to a
verbatim encap+body blob) WITHOUT coupling a repair-routing change into the schema
phase. `key_hash` is the 16-byte wire identity; the pre-existing `instance_key` u64
stays for fast per-instance bookkeeping (two masters, two fields).

Derivable (never stored, recomputed deterministically): status-info bits (from `kind`),
submessage flags (from `kind` + dialect), `PID_GROUP_ENTITY_ID` presence (from
`group_sn`), inline-QoS ordering and padding, encapsulation header (from `cdr_version`
+ dialect), fragmentation split (from payload length + fragment size).

Two pure stages, one implementation, called by live, replay and repair alike:

```
emit_canonical(change: &CacheEntry, ctx: &WriterCtx) -> Canonical<'a>
    // Stage 1: audience-BLIND. Produces the NATIVE (self) bytes ALWAYS, as a
    // zero-copy borrowing descriptor over the cached payload + writer context.
    // Dialect is deliberately NOT a parameter here: keeping it out makes J1'
    // (journal content is audience-independent) structural, enforced by the type.
    // Deterministic for a fixed change -- this is the differential-test surface.

address(canonicals: &[Canonical], dest: &Dest, dialect: Dialect) -> Wire
    // Stage 2: the ONLY layer that knows the destination dialect. Consumes a
    // SEQUENCE (deterministic fold => batching / fragmentation), does the readerId
    // patch, INFO_TS / INFO_DST assembly, locators, uni/multicast, header-extension
    // prepend, encapsulation downgrade, and crypto (J4). Foreign dialects are data
    // here, never separate code paths.
```

`Dialect` is resolved once at pairing time and stored per-peer (cold path). The
resolution key is `(vendor_id, product_version)`, NOT vendor alone: wire behaviour
can differ across a vendor's own releases, so the profile table is
two-dimensional. Product version
is read from SPDP participant properties at discovery. Unresolved peers get
`Dialect::Native` (J2). The dialect is a projection input at emission time, never part
of the journal (J1') -- this is what makes durable late-joiner replay work: changes
written before a peer existed still project correctly toward it.

The two-dimensional key is a COLD-path richness only: it makes discovery-time
resolution finer, and MUST NOT leak any per-message lookup onto the hot path
(constraint C1). More granularity is allowed as long as every bit of it is resolved
once, at pairing, into a per-peer O(1) read. Note (security, unresolved): both
`vendor_id` and `product_version` are unauthenticated in standard RTPS discovery -- a
spoofed value forces a dialect selection; the mitigation posture is shared with the
SPDP-vendor-spoofing finding and is deferred to the dialect/security design.

GROUP model: one close per writer referencing the publisher GSN. N writers in a set
produce N journaled closes; the reader barrier commits at N.

## 4. Migration plan (strangler, each phase gated)

Gates for every phase: the red differential tests it claims to fix turn green; the
green tests stay green; the full unit suite passes; the docker self pair
(CoherentSets 19/21 among others) stays PASS. The self wire path must remain
byte-identical or provably equivalent at every step.

- Phase 1 -- journal SCHEMA (J1), schema only. `CacheEntry` grows `kind`,
  `coherent_sn`, `group_sn`, `key_hash`, `cdr_version`, and a dormant `source_ts`.
  The DATA write path records its full closure; the coherent ECS close is journaled
  WITH its `CoherentClose` kind (it already occupied a ring slot today, so eviction
  stays byte-for-byte unchanged). No emission change, and the repair classifier
  (`on_nack`) is left UNTOUCHED: everything journaled in this phase (`Data`,
  `CoherentClose`) is legacy-retransmittable, so repair reproduces exactly today's
  bytes. Deliberately DEFERRED out of Phase 1: (a) dispose/unregister journaling ->
  Phase 3, because a new dispose ring occupant could FIFO-evict a live DATA under
  KEEP_LAST and flip a DATA retransmit into a GAP (a self wire change); the dispose
  entry and its KEY repair form, with non-displacing eviction accounting, land
  together in Phase 3. (b) `source_ts` CAPTURE -> Phase 2, when INFO_TS is actually
  emitted from it (Phase 1 stores `(0,0)`, avoiding a hot-path clock read for a value
  nothing yet consumes). Red #4 (dispose unreplayable) therefore stays RED through
  Phase 1 by design. A repair budget (bound retransmits per HEARTBEAT interval, a
  promoted cert item) is a PRE-EXISTING `on_nack` hardening gap, tracked separately
  so a mis-sized default cannot throttle legitimate deep-history replay on the self
  path.
- Phase 2 -- `emit_canonical` extracted from the existing live builders and proven:
  live output routed through it is byte-identical (golden vectors + differential
  tests). `source_ts` capture lands here (from the same wall clock the live INFO_TS
  uses), so INFO_TS becomes deterministic. Reds #1/#2/#5 green for self.
- Phase 3 -- replay and NACK repair routed through the same `emit_canonical`.
  Red #3 green. This is the step the two dead fix generations attempted without
  phases 1-2. A partial-revert arbitration on the second dead branch showed its
  self-regression was NOT wire content (bytes were proven identical) but the
  routing infrastructure added to hot paths: per-emission map/lock lookups in
  `write()` / `replay_to()` / `on_nack()` plus per-burst reader resolution.
  Hence a hard constraint for this design:

  C1 -- `emit_canonical` and the dialect lookup add ZERO locking and ZERO map
  lookups to the emission hot paths. The dialect is resolved once at pairing
  time and stored as a per-peer O(1) read; the closure travels INSIDE the
  CacheEntry (no side-table). Any phase that adds a lock acquisition to
  write/replay/repair fails its gate by definition, regardless of test results.
- Phase 4 -- `address()` extracted (readerId, header-extension, downgrade, crypto
  hook). Foreign dialects become data (`Dialect` variants), not code paths.

## 5. Open questions (named dragons, not solved here)

- Eviction: lifetime(close) = lifetime(set). Trivial under KEEP_ALL (the cert path);
  KEEP_LAST can evict members of a still-referenced set -- partially-repairable sets
  are an open, logged question.
- Singleton closes: whether per-write closes are needed for some foreign collators is
  unproven (no packet capture yet). J1' forbids making close creation
  discovery-dependent; if ever needed it is a QoS/policy decision, on for all peers.
- Reader-side GROUP tracker accepts a replayed close by accident of buffer emptiness
  rather than by an explicit monotone guard (phantom create-and-remove per replayed
  close). The refactor should make J3 structural on the GROUP path too.

## 6. Non-goals

- No cross-vendor scoring fixes before the refactor lands (hand-sewn pre-refactor
  patches on the repair path are a proven dead end -- two generations died there).
- No change to the reader delivery semantics beyond J3.
- No wire-format changes on the self path, ever: self is the reference.
