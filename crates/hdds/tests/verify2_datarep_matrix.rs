// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DATA_REPRESENTATION pairing matrix, HDDS<->HDDS, Rust endpoints, three
//! placements. Kept as the
//! regression proof for DDS-XTypes v1.3 Sec.7.6.3.1.1 end to end (both the
//! builder-time refusal rule and the data-plane backstop), since it is the
//! only test that drives every (writer type+QoS, reader type+QoS) cell over
//! real Participants and checks what was actually DELIVERED, not only what
//! the QoS objects say.
//!
//! Two Rust types share one type name `{ u32 tag; f64 value }`:
//! * `Native` encodes and decodes by version (f64 at 8 under XCDR1, at 4
//!   under XCDR2) and declares `encodes_xcdr1_natively() == true`.
//! * `Plain` always writes and reads the XCDR2 layout and declares nothing
//!   (`encodes_xcdr1_natively()` stays at the trait default, `false`): it
//!   cannot actually produce or read the XCDR1 layout.
//!
//! An endpoint that explicitly sets `DATA_REPRESENTATION = [XCDR1]` (`Q::X1`
//! below) is claiming it can speak XCDR1. DDS-XTypes v1.3 Sec.7.6.3.1.1
//! makes that claim conditional on the capability: a writer "Optionally may
//! generate or include run-time code that can serialize using version 1
//! encodings. In this case, they shall offer the means to configure at
//! run-time the encoding version used"; a reader "Optionally may generate
//! or include run-time code that can deserialize version 1 encodings. In
//! this case they shall also request XCDR encoding in addition to XCDR2
//! encoding." A `Plain` endpoint built with `Q::X1` is claiming a
//! capability it does not have, so `ReaderBuilder::build` /
//! `WriterBuilder::build` REFUSE it (`InvalidQos`), at creation: this makes
//! both ends of an explicit-XCDR1 pair agree trivially (neither exists
//! unless its type can actually speak it), rather than letting a remote
//! peer -- which sees only the announced list, never the Rust type behind
//! it -- match a pair this reader's own `on_requested_incompatible_qos`
//! disagrees with. See `cdr_negotiation::resolve_writer_data_representation`
//! / `resolve_reader_data_representation`.
//!
//! For every (writer type+QoS, reader type+QoS, placement) `run` builds
//! both ends (recording whether each build was refused, and whether that
//! matched the prediction), and when both built, writes one sample and
//! checks: what each end announces (two participants only), match and
//! incompatible counts at both ends, what the reader took (value correct?
//! label). Assertions at the end, so the whole matrix prints.

use hdds::api::DDS;
use hdds::core::types::TypeDescriptor;
use hdds::dds::{DataReaderListener, DataWriterListener, PublicationMatchedStatus};
use hdds::dds::{RequestedIncompatibleQosStatus, SubscriptionMatchedStatus};
use hdds::test_support::domains::unique_domain;
use hdds::{CdrVersion, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static LABELS: Mutex<Vec<(u32, CdrVersion)>> = Mutex::new(Vec::new());

static DESC: TypeDescriptor = TypeDescriptor {
    type_id: 0x7E21_0001,
    type_name: "Verify2DatarepProbe",
    size_bytes: 16,
    alignment: 8,
    is_variable_size: false,
    fields: &[],
};

fn put(buf: &mut [u8], tag: u32, value: f64, f_at: usize) -> hdds::api::Result<usize> {
    if buf.len() < f_at + 8 {
        return Err(hdds::api::Error::BufferTooSmall);
    }
    buf[..4].copy_from_slice(&tag.to_le_bytes());
    for b in &mut buf[4..f_at] {
        *b = 0;
    }
    buf[f_at..f_at + 8].copy_from_slice(&value.to_le_bytes());
    Ok(f_at + 8)
}

fn get(buf: &[u8], f_at: usize) -> hdds::api::Result<(u32, f64)> {
    if buf.len() < f_at + 8 {
        return Err(hdds::api::Error::SerializationError);
    }
    let tag = u32::from_le_bytes(buf[..4].try_into().unwrap());
    let value = f64::from_le_bytes(buf[f_at..f_at + 8].try_into().unwrap());
    Ok((tag, value))
}

fn f_at(version: CdrVersion) -> usize {
    match version {
        CdrVersion::Xcdr1 => 8,
        CdrVersion::Xcdr2 => 4,
    }
}

#[derive(Debug, Clone)]
struct Native {
    tag: u32,
    value: f64,
}

impl DDS for Native {
    fn type_descriptor() -> &'static TypeDescriptor {
        &DESC
    }
    fn encode(&self, buf: &mut [u8], version: CdrVersion) -> hdds::api::Result<usize> {
        put(buf, self.tag, self.value, f_at(version))
    }
    fn decode(buf: &[u8], version: CdrVersion) -> hdds::api::Result<Self> {
        let (tag, value) = get(buf, f_at(version))?;
        LABELS.lock().unwrap().push((tag, version));
        Ok(Self { tag, value })
    }
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct Plain {
    tag: u32,
    value: f64,
}

impl DDS for Plain {
    fn type_descriptor() -> &'static TypeDescriptor {
        &DESC
    }
    fn encode(&self, buf: &mut [u8], _version: CdrVersion) -> hdds::api::Result<usize> {
        put(buf, self.tag, self.value, 4)
    }
    fn decode(buf: &[u8], version: CdrVersion) -> hdds::api::Result<Self> {
        let (tag, value) = get(buf, 4)?;
        LABELS.lock().unwrap().push((tag, version));
        Ok(Self { tag, value })
    }
}

trait Probe: DDS + Clone {
    fn make(tag: u32, value: f64) -> Self;
    fn parts(&self) -> (u32, f64);
}
impl Probe for Native {
    fn make(tag: u32, value: f64) -> Self {
        Self { tag, value }
    }
    fn parts(&self) -> (u32, f64) {
        (self.tag, self.value)
    }
}
impl Probe for Plain {
    fn make(tag: u32, value: f64) -> Self {
        Self { tag, value }
    }
    fn parts(&self) -> (u32, f64) {
        (self.tag, self.value)
    }
}

#[derive(Default)]
struct Seen {
    current: AtomicI32,
    incompat: AtomicU32,
}
impl<T: DDS> DataWriterListener<T> for Seen {
    fn on_publication_matched(&self, s: PublicationMatchedStatus) {
        self.current.store(s.current_count as i32, Ordering::SeqCst);
    }
    fn on_offered_incompatible_qos(&self, _p: u32, _n: &str) {
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}
impl<T: DDS> DataReaderListener<T> for Seen {
    fn on_subscription_matched(&self, s: SubscriptionMatchedStatus) {
        self.current.store(s.current_count as i32, Ordering::SeqCst);
    }
    fn on_requested_incompatible_qos(&self, _s: RequestedIncompatibleQosStatus) {
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Placement {
    Two,
    One,
    InProc,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Q {
    Default,
    X1,
    X2,
}
fn qos(q: Q) -> QoS {
    let base = QoS::reliable();
    match q {
        Q::Default => base,
        Q::X1 => base.data_representation_xcdr1(),
        Q::X2 => base.data_representation_xcdr2(),
    }
}

/// Representation a Rust endpoint ends up with, per the claimed end state.
fn w_offer(native: bool, q: Q) -> u16 {
    match q {
        Q::Default => {
            if native {
                0
            } else {
                2
            }
        }
        Q::X1 => 0,
        Q::X2 => 2,
    }
}
fn r_list(native: bool, q: Q) -> Vec<u16> {
    match q {
        Q::Default => {
            if native {
                vec![0, 2]
            } else {
                vec![2]
            }
        }
        Q::X1 => vec![0],
        Q::X2 => vec![2],
    }
}

fn wait_for(t: Duration, mut f: impl FnMut() -> bool) -> bool {
    let d = Instant::now() + t;
    while Instant::now() < d {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    f()
}

struct Outcome {
    line: String,
    problems: Vec<String>,
}

static TAG: AtomicU32 = AtomicU32::new(1000);

fn run<W: Probe, R: Probe>(placement: Placement, wn: bool, wq: Q, rn: bool, rq: Q) -> Outcome {
    let domain = unique_domain();
    let mode = if placement == Placement::InProc {
        TransportMode::IntraProcess
    } else {
        TransportMode::UdpMulticast
    };
    let tag = TAG.fetch_add(1, Ordering::SeqCst);
    let topic = format!("v2dr_{tag}");
    let p = Participant::builder(&format!("{topic}_p"))
        .domain_id(domain.id())
        .with_transport(mode)
        .build()
        .unwrap();
    let s = if placement == Placement::Two {
        Participant::builder(&format!("{topic}_s"))
            .domain_id(domain.id())
            .with_transport(mode)
            .build()
            .unwrap()
    } else {
        Arc::clone(&p)
    };
    let ws = Arc::new(Seen::default());
    let rs = Arc::new(Seen::default());

    // DDS-XTypes v1.3 Sec.7.6.3.1.1: an endpoint that explicitly requests
    // XCDR1 (`Q::X1`) while its type cannot actually encode/decode it is
    // refused at creation (`InvalidQos`), not matched then dropped. `Q::
    // Default` never triggers this: a refusing type with no explicit list
    // is resolved to XCDR2 instead (`resolve_writer_data_representation` /
    // `resolve_reader_data_representation`), which is always buildable.
    let writer_should_refuse = wq == Q::X1 && !wn;
    let reader_should_refuse = rq == Q::X1 && !rn;

    let writer_result = p
        .topic::<W>(&topic)
        .unwrap()
        .writer()
        .qos(qos(wq))
        .with_listener(Arc::clone(&ws) as Arc<dyn DataWriterListener<W>>)
        .build();
    let reader_result = s
        .topic::<R>(&topic)
        .unwrap()
        .reader()
        .qos(qos(rq))
        .with_listener(Arc::clone(&rs) as Arc<dyn DataReaderListener<R>>)
        .build();

    let mut problems = Vec::new();
    if writer_result.is_err() != writer_should_refuse {
        problems.push(format!(
            "writer build: expected refused={writer_should_refuse} got {:?}",
            writer_result.as_ref().err()
        ));
    }
    if reader_result.is_err() != reader_should_refuse {
        problems.push(format!(
            "reader build: expected refused={reader_should_refuse} got {:?}",
            reader_result.as_ref().err()
        ));
    }

    let side = |n: bool| if n { "N" } else { "P" };
    let refusal_line = format!(
        "W[{} {:?}] -> R[{} {:?}]: writer_refused={} reader_refused={}",
        side(wn),
        wq,
        side(rn),
        rq,
        writer_result.is_err(),
        reader_result.is_err(),
    );
    let (writer, reader) = match (writer_result, reader_result) {
        (Ok(w), Ok(r)) => (w, r),
        _ => {
            return Outcome {
                line: refusal_line,
                problems,
            }
        }
    };
    let w_qos = writer.qos().data_representation.clone();
    let r_qos = reader.qos().data_representation.clone();

    let offer = w_offer(wn, wq);
    let list = r_list(rn, rq);
    // Both ends built: by construction, neither claims an XCDR1 capability
    // its type lacks, so the spec-level list intersection IS the whole
    // compatibility verdict -- no separate "local refusal" term.
    let expect_compat = list.contains(&offer);

    let _ = wait_for(Duration::from_millis(2500), || {
        (ws.current.load(Ordering::SeqCst) == 1 && rs.current.load(Ordering::SeqCst) == 1)
            || (ws.incompat.load(Ordering::SeqCst) > 0 && rs.incompat.load(Ordering::SeqCst) > 0)
    });
    if !expect_compat {
        std::thread::sleep(Duration::from_millis(400));
    }
    // announcements, from the other participant
    let mut announced = String::new();
    if placement == Placement::Two {
        let ann_w = s
            .discover_endpoints()
            .unwrap_or_default()
            .into_iter()
            .find(|e| e.topic_name == topic && e.kind == hdds::DiscoveredEndpointKind::Writer)
            .map(|e| e.qos.data_representation);
        let ann_r = p
            .discover_endpoints()
            .unwrap_or_default()
            .into_iter()
            .find(|e| e.topic_name == topic && e.kind == hdds::DiscoveredEndpointKind::Reader)
            .map(|e| e.qos.data_representation);
        announced = format!(" annW={ann_w:?} annR={ann_r:?}");
    }
    let value = 1.25 + f64::from(tag);
    let _ = writer.write(&W::make(tag, value));
    let mut taken: Vec<(u32, f64)> = Vec::new();
    let _ = wait_for(
        Duration::from_millis(if expect_compat { 3000 } else { 800 }),
        || {
            while let Ok(Some(x)) = reader.take() {
                taken.push(x.parts());
            }
            !taken.is_empty()
        },
    );
    let labels: Vec<CdrVersion> = LABELS
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _)| *t == tag)
        .map(|(_, v)| *v)
        .collect();
    let wc = ws.current.load(Ordering::SeqCst);
    let wi = ws.incompat.load(Ordering::SeqCst);
    let rc = rs.current.load(Ordering::SeqCst);
    let ri = rs.incompat.load(Ordering::SeqCst);
    let correct = taken.iter().all(|(t, v)| *t == tag && *v == value);
    if !taken.is_empty() && !correct {
        problems.push(format!("CORRUPT delivery {taken:?} expected {value}"));
    }
    if expect_compat && taken.is_empty() {
        problems.push("expected delivery, nothing taken".into());
    }
    if !expect_compat && !taken.is_empty() {
        problems.push("delivered on an incompatible pair".into());
    }
    if placement != Placement::InProc {
        if (wc == 1) != (rc == 1) {
            problems.push(format!("ends disagree on match: w={wc} r={rc}"));
        }
        if (wi > 0) != (ri > 0) {
            problems.push(format!("ends disagree on incompat: w={wi} r={ri}"));
        }
        if expect_compat && (wc != 1 || rc != 1) {
            problems.push("expected matched".into());
        }
        if !expect_compat && (wc == 1 || rc == 1) {
            problems.push("matched on an incompatible pair".into());
        }
    }
    let line = format!(
        "W[{} {:?}] qos={:?} -> R[{} {:?}] qos={:?}: expect={} | w cur={} inc={} | r cur={} inc={} | taken={} correct={} labels={:?}{}",
        if wn { "N" } else { "P" },
        wq,
        w_qos,
        if rn { "N" } else { "P" },
        rq,
        r_qos,
        expect_compat,
        wc,
        wi,
        rc,
        ri,
        taken.len(),
        correct,
        labels,
        announced
    );
    Outcome { line, problems }
}

fn matrix(placement: Placement) {
    let qs = [Q::Default, Q::X1, Q::X2];
    let mut fails = Vec::new();
    let mut out = String::new();
    for wn in [true, false] {
        for &wq in &qs {
            for rn in [true, false] {
                for &rq in &qs {
                    let o = match (wn, rn) {
                        (true, true) => run::<Native, Native>(placement, wn, wq, rn, rq),
                        (true, false) => run::<Native, Plain>(placement, wn, wq, rn, rq),
                        (false, true) => run::<Plain, Native>(placement, wn, wq, rn, rq),
                        (false, false) => run::<Plain, Plain>(placement, wn, wq, rn, rq),
                    };
                    let mark = if o.problems.is_empty() {
                        "ok  "
                    } else {
                        "FAIL"
                    };
                    out.push_str(&format!(
                        "{placement:?} {mark} {} {:?}\n",
                        o.line, o.problems
                    ));
                    if !o.problems.is_empty() {
                        fails.push(format!("{placement:?} {} {:?}", o.line, o.problems));
                    }
                }
            }
        }
    }
    eprintln!("{out}");
    assert!(
        fails.is_empty(),
        "{} failing pairings:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn matrix_two_participants() {
    matrix(Placement::Two);
}
#[test]
fn matrix_one_participant() {
    matrix(Placement::One);
}
#[test]
fn matrix_in_process() {
    matrix(Placement::InProc);
}

/// One remote default writer (Native, offers XCDR1) and, in the other
/// participant, four readers attempted on the topic: Native default
/// ([XCDR1, XCDR2], compatible), Native [XCDR2] (incompatible by list),
/// Plain default ([XCDR2], incompatible by list), Plain [XCDR1] -- list-
/// compatible with the writer's offer, but the type refuses XCDR1, so this
/// one is refused AT CREATION (`InvalidQos`, DDS-XTypes v1.3
/// Sec.7.6.3.1.1): it never exists to receive anything. Only the first
/// reader may receive anything.
#[test]
fn mixed_local_readers_behind_one_remote_writer() {
    let domain = unique_domain();
    let tag = TAG.fetch_add(1, Ordering::SeqCst);
    let topic = format!("v2dr_mixed_{tag}");
    let p = Participant::builder("v2mix_p")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let s = Participant::builder("v2mix_s")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let ra = s
        .topic::<Native>(&topic)
        .unwrap()
        .reader()
        .qos(qos(Q::Default))
        .build()
        .unwrap();
    let rb = s
        .topic::<Native>(&topic)
        .unwrap()
        .reader()
        .qos(qos(Q::X2))
        .build()
        .unwrap();
    let rc = s
        .topic::<Plain>(&topic)
        .unwrap()
        .reader()
        .qos(qos(Q::Default))
        .build()
        .unwrap();
    let rd_result = s
        .topic::<Plain>(&topic)
        .unwrap()
        .reader()
        .qos(qos(Q::X1))
        .build();
    assert!(
        matches!(rd_result, Err(hdds::Error::InvalidQos(_))),
        "D plain [XCDR1] (type refuses XCDR1) must be refused at creation, got {:?}",
        rd_result.map(|_| ()).err()
    );
    let ws = Arc::new(Seen::default());
    let w = p
        .topic::<Native>(&topic)
        .unwrap()
        .writer()
        .qos(qos(Q::Default))
        .with_listener(Arc::clone(&ws) as Arc<dyn DataWriterListener<Native>>)
        .build()
        .unwrap();
    let _ = wait_for(Duration::from_secs(3), || {
        ws.current.load(Ordering::SeqCst) >= 1
    });
    std::thread::sleep(Duration::from_millis(500));
    let value = 2.5 + f64::from(tag);
    for _ in 0..3 {
        w.write(&Native { tag, value }).unwrap();
    }
    std::thread::sleep(Duration::from_millis(1500));
    let mut a = Vec::new();
    while let Ok(Some(x)) = ra.take() {
        a.push(x.parts());
    }
    let mut b = Vec::new();
    while let Ok(Some(x)) = rb.take() {
        b.push(x.parts());
    }
    let mut c = Vec::new();
    while let Ok(Some(x)) = rc.take() {
        c.push(x.parts());
    }
    eprintln!(
        "writer matched={} | A native default: {a:?} | B native X2: {b:?} | C plain default: {c:?}",
        ws.current.load(Ordering::SeqCst)
    );
    assert!(
        !a.is_empty() && a.iter().all(|(t, v)| *t == tag && *v == value),
        "A"
    );
    assert!(b.is_empty(), "B [XCDR2] received XCDR1 samples: {b:?}");
    assert!(
        c.is_empty(),
        "C plain [XCDR2] received XCDR1 samples: {c:?}"
    );
}

#[derive(hdds::DDS, Debug, Clone)]
struct DeriveMix {
    a: u8,
    b: i64,
    s: String,
}

#[derive(hdds::DDS, Debug, Clone)]
#[dds(final)]
struct DeriveFinal {
    a: u8,
    b: i64,
}

/// The bytes a default writer of a derive type sends, as a raw reader in
/// another participant takes them, with the version the identifier named.
#[test]
fn derive_default_writer_body_is_xcdr1() {
    let domain = unique_domain();
    let tag = TAG.fetch_add(1, Ordering::SeqCst);
    let mk = |n: &str| {
        Participant::builder(n)
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .unwrap()
    };
    let p = mk("v2body_p");
    let s = mk("v2body_s");
    let t1 = format!("v2body_mix_{tag}");
    let t2 = format!("v2body_fin_{tag}");
    let w1 = p
        .topic::<DeriveMix>(&t1)
        .unwrap()
        .writer()
        .qos(QoS::reliable())
        .build()
        .unwrap();
    let w2 = p
        .topic::<DeriveFinal>(&t2)
        .unwrap()
        .writer()
        .qos(QoS::reliable())
        .build()
        .unwrap();
    let n1 = <DeriveMix as DDS>::type_descriptor().type_name;
    let n2 = <DeriveFinal as DDS>::type_descriptor().type_name;
    let r1 = s
        .create_raw_reader_with_type(&t1, n1, Some(QoS::reliable()), None, None)
        .unwrap();
    let r2 = s
        .create_raw_reader_with_type(&t2, n2, Some(QoS::reliable()), None, None)
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    w1.write(&DeriveMix {
        a: 0x11,
        b: 0x0102030405060708,
        s: "hi".into(),
    })
    .unwrap();
    w2.write(&DeriveFinal {
        a: 0x11,
        b: 0x0102030405060708,
    })
    .unwrap();
    let mut g1 = Vec::new();
    let mut g2 = Vec::new();
    let _ = wait_for(Duration::from_secs(4), || {
        g1.extend(r1.try_take_raw_with_encoding().unwrap());
        g2.extend(r2.try_take_raw_with_encoding().unwrap());
        !g1.is_empty() && !g2.is_empty()
    });
    let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    for (n, g) in [("mix(appendable)", &g1), ("final", &g2)] {
        for (sample, v) in g.iter() {
            eprintln!("{n}: version={v:?} body={}", h(&sample.payload));
        }
    }
    // XCDR1 PLAIN_CDR: u8, pad to 8, i64, u32 len 3, "hi\0"
    let x1_mix = "1100000000000000080706050403020103000000686900";
    let x1_fin = "11000000000000000807060504030201";
    assert_eq!(g1.len(), 1);
    assert_eq!(g1[0].1, CdrVersion::Xcdr1);
    assert!(h(&g1[0].0.payload).starts_with(x1_mix), "mix body");
    assert_eq!(g2[0].1, CdrVersion::Xcdr1);
    assert!(h(&g2[0].0.payload).starts_with(x1_fin), "final body");
}
