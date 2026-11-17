// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Model-based schedules of a reliable TRANSIENT_LOCAL reader's admission
//! path, the one the network delivers through (`ReaderSubscriber` with its
//! history room, reorder gate, coherent staging and acknowledgement state).
//!
//! Each seed draws, deterministically (xorshift64*), a reader and up to
//! three writers, then a schedule: every change each writer sends, dropped,
//! duplicated or delayed at random and interleaved across writers, with
//! HEARTBEATs (and the repairs the reader asks for) and application takes
//! at random times. A drain follows, as a network would end: each writer
//! sends a HEARTBEAT, repairs what the reader asks for, and the application
//! takes, until the reader asks for nothing more and nothing more comes.
//!
//! What it draws:
//! - writers: plain DATA only; classic coherent sets (PID_COHERENT_SET on
//!   each sample) closed by the next set or a plain DATA; classic sets
//!   closed by a standalone end marker, with or without a sample count
//!   (vendor 0x0101); HDDS sets closed by an end-of-set DATA, under TOPIC or
//!   GROUP scope (one publisher per writer).
//! - reader: coherent access off, TOPIC or GROUP; KEEP_ALL or KEEP_LAST
//!   (1..=3); small max_samples, max_samples_per_instance, max_instances.
//!
//! What it checks once drained:
//! 1. liveness: every writer fully acknowledged, every sample delivered
//!    (KEEP_LAST: the newest of each instance), unless refused for good by
//!    `max_instances` (an instance its writer still holds), or lost;
//! 2. a sample acknowledged and not delivered is a loss, and losses are
//!    never more than the SAMPLE_REJECTED reports;
//! 3. no sample delivered twice;
//! 4. a coherent set delivered whole or not at all (KEEP_ALL);
//! 5. each writer's samples delivered in its order;
//! 6. KEEP_LAST delivers the newest of each instance (with 1);
//! 7. the history room's places and instance counts are all back once
//!    everything is taken.
//!
//! A reported loss (2, with reports) is not a violation, but it is counted:
//! a seed that loses an acknowledged sample, even reported, is listed.

use super::tests_history_limits::{encoded, Keyed, NetworkReader};
use crate::core::reader::HeartbeatSeen;
use crate::dds::QoS;
use crate::engine::Subscriber as _;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const UNLIMITED: usize = crate::reliability::LENGTH_UNLIMITED;

fn trace() -> bool {
    std::env::var_os("HDDS_MODEL_TRACE").is_some()
}

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn range(&mut self, low: u64, high: u64) -> u64 {
        low + self.below(high - low + 1)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Model {
    Plain,
    /// Sets closed by the next set's first sample or by a plain DATA.
    ClassicImplicit,
    /// Sets closed by a standalone end marker (vendor 0x0101).
    ClassicExplicit,
    /// Sets closed by an HDDS end-of-set DATA.
    Ecs,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scope {
    Off,
    Topic,
    Group,
}

#[derive(Clone, Debug)]
enum Msg {
    Data {
        instance: i32,
        set_start: Option<u64>,
        group: Option<u64>,
    },
    Marker {
        end_sn: u64,
        count: Option<u32>,
    },
    Ecs {
        last: u64,
        group: Option<u64>,
    },
    /// A dispose written inside a coherent set: a key-only DATA tagged as a
    /// member of the set (RTPS v2.5 Sec.8.7.6: every change of the set).
    Lifecycle {
        instance: i32,
        set_start: Option<u64>,
        group: Option<u64>,
    },
    /// A change of a set the reader is not to receive: filtered for it, or
    /// a write abandoned inside the set (D16). The writer sends a GAP that
    /// says so, never the change.
    Filtered {
        set_start: Option<u64>,
        group: Option<u64>,
    },
}

struct Writer {
    guid: [u8; 16],
    index: i32,
    model: Model,
    /// `msgs[sn - 1]`.
    msgs: Vec<Msg>,
    publisher: [u8; 4],
    hb_count: u32,
    /// `gsns[sn - 1]`: the GSN of each change, for the writers of a shared
    /// Publisher (`Run::assign_gsns`).
    gsns: Vec<Option<u64>>,
}

struct Plan {
    scope: Scope,
    keep_last: Option<u32>,
    max_samples: usize,
    max_instances: usize,
    max_per_instance: usize,
    writers: Vec<Writer>,
    /// Each coherent set the reader must deliver atomically: writer, SNs.
    sets: Vec<(usize, Vec<u64>)>,
}

impl Plan {
    fn draw(rng: &mut Rng) -> Self {
        let scope = match rng.below(10) {
            0..=2 => Scope::Off,
            3..=7 => Scope::Topic,
            _ => Scope::Group,
        };
        let keep_last = rng
            .chance(30)
            .then(|| u32::try_from(rng.range(1, 3)).expect("small"));
        let (mut max_samples, mut max_per_instance, mut max_instances) =
            (UNLIMITED, UNLIMITED, UNLIMITED);
        if keep_last.is_none() {
            if rng.chance(70) {
                max_samples = usize::try_from(rng.range(3, 10)).expect("small");
            }
            if rng.chance(30) {
                max_per_instance = usize::try_from(rng.range(2, 4)).expect("small");
                max_per_instance = max_per_instance.min(max_samples);
            }
        }
        if scope == Scope::Off && rng.chance(30) {
            max_instances = usize::try_from(rng.range(1, 4)).expect("small");
        }
        let n_writers = rng.range(1, 3);
        let mut sets = Vec::new();
        let mut writers = Vec::new();
        for w in 0..n_writers {
            let index = i32::try_from(w).expect("small");
            let model = match scope {
                Scope::Group => {
                    if rng.chance(25) {
                        Model::Plain
                    } else {
                        Model::Ecs
                    }
                }
                _ => match rng.below(4) {
                    0 => Model::Plain,
                    1 => Model::ClassicImplicit,
                    2 => Model::ClassicExplicit,
                    _ => Model::Ecs,
                },
            };
            let n_instances = rng.range(1, 3);
            let w_index = usize::try_from(w).expect("small");
            let msgs = Self::draw_writer(rng, model, scope, n_instances, index, &mut sets, w_index);
            let byte = 0x70 + u8::try_from(w).expect("small");
            writers.push(Writer {
                guid: [byte; 16],
                index,
                model,
                msgs,
                publisher: [0, 0, byte, 0xC8],
                hb_count: 0,
                gsns: Vec::new(),
            });
        }
        if scope == Scope::Off {
            sets.clear();
        }
        Self {
            scope,
            keep_last,
            max_samples,
            max_instances,
            max_per_instance,
            writers,
            sets,
        }
    }

    fn draw_writer(
        rng: &mut Rng,
        model: Model,
        scope: Scope,
        n_instances: u64,
        index: i32,
        sets: &mut Vec<(usize, Vec<u64>)>,
        w: usize,
    ) -> Vec<Msg> {
        let target = rng.range(3, 12);
        let mut msgs: Vec<Msg> = Vec::new();
        let mut gsn = 0u64;
        let instance = |rng: &mut Rng| {
            (index + 1) * 1000 + i32::try_from(rng.below(n_instances)).expect("small")
        };
        let plain = |rng: &mut Rng| Msg::Data {
            instance: instance(rng),
            set_start: None,
            group: None,
        };
        let mut open_set = false;
        while u64::try_from(msgs.len()).expect("small") < target {
            if model == Model::Plain || rng.chance(30) {
                msgs.push(plain(rng));
                open_set = false;
                continue;
            }
            let size = rng.range(1, 3);
            let first = u64::try_from(msgs.len()).expect("small") + 1;
            gsn += 1;
            let group = (scope == Scope::Group && model == Model::Ecs).then_some(gsn);
            let mut members = Vec::new();
            for k in 0..size {
                members.push(first + k);
                msgs.push(Msg::Data {
                    instance: instance(rng),
                    set_start: Some(first),
                    group,
                });
            }
            sets.push((w, members));
            match model {
                Model::ClassicExplicit => {
                    let count = rng.chance(50).then(|| u32::try_from(size).expect("small"));
                    msgs.push(Msg::Marker {
                        end_sn: first,
                        count,
                    });
                    open_set = false;
                }
                Model::Ecs => {
                    msgs.push(Msg::Ecs {
                        last: first + size - 1,
                        group,
                    });
                    open_set = false;
                }
                _ => open_set = true,
            }
        }
        if open_set {
            // A classic implicit set is closed by what follows it.
            msgs.push(plain(rng));
        }
        msgs
    }

    fn qos(&self) -> QoS {
        let mut qos = match self.keep_last {
            Some(depth) => QoS::reliable().keep_last(depth),
            None => QoS::reliable().keep_all(),
        };
        qos.resource_limits.max_samples = self.max_samples;
        qos.resource_limits.max_instances = self.max_instances;
        qos.resource_limits.max_samples_per_instance = self.max_per_instance;
        qos
    }
}

fn value_of(index: i32, sn: u64) -> i32 {
    index * 100_000 + i32::try_from(sn).expect("small")
}

fn origin(sample: &Keyed) -> (i32, u64) {
    (
        sample.value / 100_000,
        u64::try_from(sample.value % 100_000).expect("positive"),
    )
}

/// What the extended model draws besides the plan (`run_seed_ext`).
#[derive(Clone, Copy, Default)]
struct Ext {
    /// Percent of DATA changes (never a writer's last) the writer GAPs.
    gap_pct: u64,
    /// Percent chance that one writer departs mid-schedule.
    depart_pct: u64,
    /// In-flight changes of a departed writer still land.
    late: bool,
    /// Percent chance a departed writer was alive all along (a lease expiry
    /// over an outage) and comes back: matched again, announced again, it
    /// goes on writing and repairing.
    return_pct: u64,
    /// A GAP may reach the reader before the writer's first HEARTBEAT.
    early_gap: bool,
    /// Percent chance the reader is BEST_EFFORT (no repair, no HEARTBEAT).
    best_effort_pct: u64,
    /// Percent chance the application takes (and reads) from inside its
    /// on_data_available listener.
    listener_pct: u64,
    /// Percent of coherent set members that are a dispose of their
    /// instance rather than a sample.
    dispose_pct: u64,
    /// Percent of DATA changes (never a writer's last) the writer GAPs after
    /// it sent them (replaced in a KEEP_LAST history): the GAP lands after
    /// the DATA, received already.
    regap_pct: u64,
    /// Percent chance the GROUP writers belong to one Publisher (one GUID
    /// prefix, one publisher entity id): a group set spans their parts.
    shared_publisher_pct: u64,
}

impl Ext {
    /// Every dimension on: what `model_ext` runs.
    fn all() -> Self {
        Self {
            gap_pct: 8,
            depart_pct: 25,
            late: true,
            return_pct: 50,
            early_gap: true,
            best_effort_pct: 15,
            listener_pct: 25,
            dispose_pct: 15,
            regap_pct: 6,
            shared_publisher_pct: 60,
        }
    }
}

/// An on_data_available listener that reads, then takes everything, from
/// inside the delivery: what an application commonly does.
struct TakingListener {
    reader: std::sync::Weak<super::DataReader<Keyed>>,
    delivered: Arc<std::sync::Mutex<Vec<Keyed>>>,
}

impl crate::dds::listener::DataReaderListener<Keyed> for TakingListener {
    fn on_data_available(&self, _sample: &Keyed) {
        let Some(reader) = self.reader.upgrade() else {
            return;
        };
        let _ = reader.read();
        let mut got = Vec::new();
        while let Ok(Some(sample)) = reader.take() {
            got.push(sample);
        }
        if trace() && !got.is_empty() {
            let shown: Vec<(i32, u64)> = got.iter().map(origin).collect();
            eprintln!("listener take {shown:?}");
        }
        self.delivered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(got);
    }
}

/// A writer discovery knows: its Publisher, its EntityId, whether it
/// writes the reader's topic.
type KnownWriter = ([u8; 4], [u8; 4], bool);

/// What discovery knows of the shared Publishers' writers, for the reader.
struct ModelRoster {
    prefix: [u8; 12],
    writers: std::sync::Mutex<Vec<KnownWriter>>,
}

impl super::subscriber::GroupRoster for ModelRoster {
    fn writers_of(
        &self,
        prefix: &[u8; 12],
        publisher: [u8; 4],
        _topic: &str,
    ) -> Vec<([u8; 4], bool)> {
        if *prefix != self.prefix {
            return Vec::new();
        }
        self.writers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(p, _, _)| *p == publisher)
            .map(|(_, id, on_topic)| (*id, *on_topic))
            .collect()
    }
}

/// The writers of the shared Publishers (`Run::share_publisher`).
struct Shared {
    /// Each shared writer: its plan index, Publisher and EntityId.
    writers: Vec<(usize, [u8; 4], [u8; 4])>,
    /// The writer set each Publisher's changes announce.
    writer_sets: BTreeMap<[u8; 4], [u8; 4]>,
    roster: Arc<ModelRoster>,
}

impl Shared {
    fn of(&self, w: usize) -> Option<([u8; 4], [u8; 4])> {
        self.writers
            .iter()
            .find(|(sw, _, _)| *sw == w)
            .map(|(_, publisher, id)| (*publisher, *id))
    }
}

struct Run {
    plan: Plan,
    net: NetworkReader<Keyed>,
    /// What the application took, in order: by the harness and, when on,
    /// by the listener from inside a delivery.
    delivered: Arc<std::sync::Mutex<Vec<Keyed>>>,
    /// A BEST_EFFORT reader: no HEARTBEAT, no repair.
    best_effort: bool,
    ext: Ext,
    gapped: Vec<BTreeSet<u64>>,
    /// DATA the writer GAPs after it sent them (`Ext::regap_pct`).
    regapped: Vec<BTreeSet<u64>>,
    /// The regapped DATA sent once already: what is sent of them since is
    /// their GAP.
    regap_sent: std::cell::RefCell<Vec<BTreeSet<u64>>>,
    /// GAPs to send, after (countdown, writer, sn).
    gap_later: std::cell::RefCell<Vec<(u64, usize, u64)>>,
    /// The regapped DATA whose first GAP reached the reader, and of those
    /// the ones it had acknowledged by then: owed to the application.
    regap_gapped: std::cell::RefCell<Vec<BTreeSet<u64>>>,
    regap_owed: std::cell::RefCell<Vec<BTreeSet<u64>>>,
    /// Each writer's acknowledgement base, from its last HEARTBEAT answer.
    ack_base: Vec<u64>,
    /// The group sets of writers sharing a Publisher: each the (writer, SN)
    /// of every sample of every writer's part.
    group_sets: Vec<Vec<(usize, u64)>>,
    /// The writers sharing a Publisher, in the spec GROUP dialect: theirs,
    /// what discovery knows of them, and the writer set they announce.
    shared: Option<Shared>,
    departed: Vec<bool>,
    /// (step, writer) at which a writer departs.
    depart_at: Option<(u64, usize)>,
    /// Steps after its departure at which the departed writer comes back.
    return_after: Option<u64>,
}

impl Run {
    fn new(seed: u64, plan: Plan, best_effort: bool) -> Self {
        let coherent = super::subscriber::CoherentConfig {
            coherent_access: plan.scope != Scope::Off,
            is_group_scope: plan.scope == Scope::Group,
        };
        let mut qos = plan.qos();
        let gate = if best_effort {
            qos.reliability = crate::dds::qos::Reliability::BestEffort;
            super::reorder::ReorderGate::new_best_effort()
        } else {
            super::reorder::ReorderGate::new(true, false)
        };
        let net = NetworkReader::<Keyed>::with_parts(
            &format!("model-{seed}"),
            qos,
            gate,
            crate::qos::ownership::OwnershipKind::default(),
            coherent,
        );
        for writer in &plan.writers {
            net.credit.match_writer(writer.guid);
        }
        let n = plan.writers.len();
        Self {
            plan,
            net,
            delivered: Arc::new(std::sync::Mutex::new(Vec::new())),
            best_effort,
            ext: Ext::default(),
            gapped: vec![BTreeSet::new(); n],
            regapped: vec![BTreeSet::new(); n],
            regap_sent: std::cell::RefCell::new(vec![BTreeSet::new(); n]),
            gap_later: std::cell::RefCell::new(Vec::new()),
            regap_gapped: std::cell::RefCell::new(vec![BTreeSet::new(); n]),
            regap_owed: std::cell::RefCell::new(vec![BTreeSet::new(); n]),
            ack_base: vec![1; n],
            group_sets: Vec::new(),
            shared: None,
            departed: vec![false; n],
            depart_at: None,
            return_after: None,
        }
    }

    fn with_ext(mut self, seed: u64, ext: Ext, listener: bool) -> Self {
        self.ext = ext;
        if listener {
            let taking = Arc::new(TakingListener {
                reader: Arc::downgrade(&self.net.reader),
                delivered: Arc::clone(&self.delivered),
            });
            self.net.subscriber.listener.set(
                Some(taking as Arc<dyn crate::dds::listener::DataReaderListener<Keyed>>),
                crate::dds::StatusMask::DATA_AVAILABLE,
            );
        }
        // GROUP writers of one Publisher, drawn apart so the other
        // dimensions keep their draws.
        let mut shared_rng = Rng::new(seed ^ 0x5EA7_ED00_0B11);
        if shared_rng.chance(ext.shared_publisher_pct) {
            self.share_publisher(&mut shared_rng);
        }
        let mut x = Rng::new(seed ^ 0x0005_EED0_F6A9);
        for (w, writer) in self.plan.writers.iter().enumerate() {
            let len = writer.msgs.len();
            for (i, m) in writer.msgs.iter().enumerate() {
                if i + 1 == len {
                    continue;
                }
                if matches!(m, Msg::Data { .. }) && x.chance(ext.gap_pct) {
                    self.gapped[w].insert(u64::try_from(i + 1).expect("small"));
                }
            }
        }
        if x.chance(ext.depart_pct) {
            let w = usize::try_from(x.below(u64::try_from(self.plan.writers.len()).expect("s")))
                .expect("s");
            self.depart_at = Some((x.range(1, 30), w));
            if x.chance(ext.return_pct) {
                self.return_after = Some(x.range(1, 10));
            }
        }
        // Coherent set members written as disposes of their instance.
        let mut lifecycle: Vec<(usize, u64)> = Vec::new();
        for (w, writer) in self.plan.writers.iter_mut().enumerate() {
            for (i, m) in writer.msgs.iter_mut().enumerate() {
                if let Msg::Data {
                    instance,
                    set_start: Some(start),
                    group,
                } = *m
                {
                    if x.chance(ext.dispose_pct) {
                        *m = Msg::Lifecycle {
                            instance,
                            set_start: Some(start),
                            group,
                        };
                        lifecycle.push((w, u64::try_from(i + 1).expect("small")));
                    }
                }
            }
        }
        for (w, members) in &mut self.plan.sets {
            members.retain(|sn| !lifecycle.contains(&(*w, *sn)));
        }
        for members in &mut self.group_sets {
            members.retain(|member| !lifecycle.contains(member));
        }
        // DATA GAPped after they were sent.
        for (w, writer) in self.plan.writers.iter().enumerate() {
            let len = writer.msgs.len();
            for (i, m) in writer.msgs.iter().enumerate() {
                let sn = u64::try_from(i + 1).expect("small");
                if i + 1 != len
                    && matches!(m, Msg::Data { .. })
                    && !self.gapped[w].contains(&sn)
                    && x.chance(ext.regap_pct)
                {
                    self.regapped[w].insert(sn);
                }
            }
        }
        self
    }

    /// Make the plan's GROUP writers, when there are two or more, the
    /// writers of Publishers of one participant speaking the spec GROUP
    /// dialect (RTPS v2.5 Sec.8.7.6): one Publisher, or two (same GUID
    /// prefix, the sets of each numbered from 1); each change of a set
    /// naming its Publisher's writer set; every writer ending every set of
    /// its Publisher, with an end of its own SN for a set it wrote nothing
    /// in (D6). Drawn on top: sets no writer writes in (empty), changes of
    /// a set filtered or abandoned (D16), every change of a set filtered,
    /// a writer of the Publisher not matched with the reader (another
    /// topic), and writers the reader joins late (their first changes
    /// GAPped). The reader learns the writers from a discovery that loses a
    /// departed writer.
    fn share_publisher(&mut self, rng: &mut Rng) {
        let ecs_writers: Vec<usize> = (0..self.plan.writers.len())
            .filter(|&w| self.plan.writers[w].model == Model::Ecs)
            .collect();
        if self.plan.scope != Scope::Group || ecs_writers.len() < 2 {
            return;
        }
        let groups: Vec<Vec<usize>> = if rng.chance(25) {
            vec![ecs_writers[..1].to_vec(), ecs_writers[1..].to_vec()]
        } else {
            vec![ecs_writers.clone()]
        };
        let prefix = [0x7A; 12];
        let mut roster: Vec<KnownWriter> = Vec::new();
        let mut shared = Vec::new();
        let mut writer_sets = BTreeMap::new();
        let mut group_sets = Vec::new();
        for (g, group) in groups.iter().enumerate() {
            let publisher = [0, 0, 0x7A + u8::try_from(g).expect("s"), 0xC8];
            let mut ids = Vec::new();
            for &w in group {
                ids.push(self.share_writer(w, prefix, publisher));
            }
            group_sets.extend(self.renumber_sets(group, rng));
            for (&w, id) in group.iter().zip(&ids) {
                roster.push((publisher, *id, true));
                shared.push((w, publisher, *id));
            }
            let mut members = ids.clone();
            if rng.chance(30) {
                // A writer of the Publisher on another topic.
                let other = [0, 0, 0x30 + u8::try_from(g).expect("s"), 0x02];
                roster.push((publisher, other, false));
                members.push(other);
            }
            writer_sets.insert(publisher, crate::protocol::group::group_digest(members));
        }
        // Late joining: a writer's first changes GAPped (not its last).
        for &w in &ecs_writers {
            let len = u64::try_from(self.plan.writers[w].msgs.len()).expect("small");
            if len > 2 && rng.chance(15) {
                let before = rng.range(2, len.min(5));
                for sn in 1..before {
                    let idx = usize::try_from(sn - 1).expect("small");
                    if matches!(self.plan.writers[w].msgs[idx], Msg::Data { .. }) {
                        self.gapped[w].insert(sn);
                    }
                }
            }
        }
        self.group_sets = group_sets;
        let roster = Arc::new(ModelRoster {
            prefix,
            writers: std::sync::Mutex::new(roster),
        });
        let _ = self
            .net
            .subscriber
            .group_roster
            .set(Arc::clone(&roster) as Arc<dyn super::subscriber::GroupRoster>);
        // Discovery here never lags: a writer set it does not know is one
        // of a departed writer, decided at once.
        self.net
            .subscriber
            .group_roster_wait_ms
            .store(0, std::sync::atomic::Ordering::Relaxed);
        self.shared = Some(Shared {
            writers: shared,
            writer_sets,
            roster,
        });
    }

    /// Writer `w` of Publisher `publisher` of participant `prefix`: its
    /// GUID and Publisher. Returns its EntityId.
    fn share_writer(&mut self, w: usize, prefix: [u8; 12], publisher: [u8; 4]) -> [u8; 4] {
        let writer = &mut self.plan.writers[w];
        self.net.credit.unmatch_writer(&writer.guid);
        let id = [0, 0, 0x10 + u8::try_from(w).expect("s"), 0x02];
        let mut guid = [0u8; 16];
        guid[..12].copy_from_slice(&prefix);
        guid[12..].copy_from_slice(&id);
        writer.guid = guid;
        writer.publisher = publisher;
        self.net.credit.match_writer(guid);
        id
    }

    /// The sets of the writers `group` of one Publisher, in the spec
    /// dialect: numbered for the Publisher (a writer's set `s` becomes the
    /// Publisher's set `2s`, and an empty set `2s - 1` may come before
    /// it), every writer ending every set, some changes filtered. Returns
    /// the Publisher's sets, each the (writer, SN) of its samples.
    fn renumber_sets(&mut self, group: &[usize], rng: &mut Rng) -> Vec<Vec<(usize, u64)>> {
        let set_of = |m: &Msg| match m {
            Msg::Data { group, .. }
            | Msg::Lifecycle { group, .. }
            | Msg::Ecs { group, .. }
            | Msg::Filtered { group, .. } => *group,
            Msg::Marker { .. } => None,
        };
        let mut all_sets: BTreeSet<u64> = group
            .iter()
            .flat_map(|&w| self.plan.writers[w].msgs.iter().filter_map(set_of))
            .map(|s| 2 * s)
            .collect();
        let empty: Vec<u64> = all_sets
            .iter()
            .filter(|_| rng.chance(10))
            .map(|s| s - 1)
            .collect();
        all_sets.extend(empty);
        let filtered_sets: BTreeSet<u64> =
            all_sets.iter().copied().filter(|_| rng.chance(5)).collect();
        for &w in group {
            let writer = &mut self.plan.writers[w];
            let own: BTreeSet<u64> = writer
                .msgs
                .iter()
                .filter_map(set_of)
                .map(|s| 2 * s)
                .collect();
            let mut idle: std::collections::VecDeque<u64> =
                all_sets.difference(&own).copied().collect();
            let old = std::mem::take(&mut writer.msgs);
            // Old SN -> new SN.
            let mut renumber: Vec<u64> = vec![0; old.len() + 1];
            let mut msgs: Vec<Msg> = Vec::new();
            let idle_end = |msgs: &mut Vec<Msg>, set: u64| {
                let sn = u64::try_from(msgs.len()).expect("small") + 1;
                msgs.push(Msg::Ecs {
                    last: sn - 1,
                    group: Some(set),
                });
            };
            for (i, m) in old.iter().enumerate() {
                let sn = u64::try_from(i + 1).expect("small");
                if let Msg::Data {
                    set_start: Some(start),
                    group: Some(set),
                    ..
                } = m
                {
                    if *start == sn {
                        while idle.front().is_some_and(|before| *before < 2 * set) {
                            let before = idle.pop_front().expect("front");
                            idle_end(&mut msgs, before);
                        }
                    }
                }
                renumber[i + 1] = u64::try_from(msgs.len()).expect("small") + 1;
                let mut m = m.clone();
                match &mut m {
                    Msg::Data {
                        set_start, group, ..
                    }
                    | Msg::Lifecycle {
                        set_start, group, ..
                    }
                    | Msg::Filtered { set_start, group } => {
                        if let Some(start) = set_start {
                            *start = renumber[usize::try_from(*start).expect("small")];
                        }
                        if let Some(set) = group {
                            *set *= 2;
                        }
                    }
                    Msg::Ecs { last, group } => {
                        *last = renumber[usize::try_from(*last).expect("small")];
                        if let Some(set) = group {
                            *set *= 2;
                        }
                    }
                    Msg::Marker { .. } => {}
                }
                // A change of the set filtered for the reader, or a write
                // abandoned inside it (D16).
                if let Msg::Data {
                    set_start,
                    group: Some(set),
                    ..
                } = m
                {
                    if filtered_sets.contains(&set) || rng.chance(8) {
                        m = Msg::Filtered {
                            set_start,
                            group: Some(set),
                        };
                    }
                }
                msgs.push(m);
            }
            while let Some(set) = idle.pop_front() {
                idle_end(&mut msgs, set);
            }
            writer.msgs = msgs;
            for (set_writer, members) in &mut self.plan.sets {
                if *set_writer == w {
                    for member in members.iter_mut() {
                        *member = renumber[usize::try_from(*member).expect("small")];
                    }
                    let msgs = &self.plan.writers[w].msgs;
                    members.retain(|member| {
                        !matches!(
                            msgs[usize::try_from(*member - 1).expect("small")],
                            Msg::Filtered { .. }
                        )
                    });
                }
            }
        }
        self.assign_gsns(group);
        let mut by_set: BTreeMap<u64, Vec<(usize, u64)>> = BTreeMap::new();
        for &w in group {
            for (i, m) in self.plan.writers[w].msgs.iter().enumerate() {
                if let Msg::Data {
                    group: Some(set), ..
                } = m
                {
                    by_set
                        .entry(*set)
                        .or_default()
                        .push((w, u64::try_from(i + 1).expect("small")));
                }
            }
        }
        by_set.into_values().collect()
    }

    /// The GSNs of the changes of the writers `group` of one Publisher, as
    /// its writer takes them (RTPS v2.5 Sec.8.7.5, Sec.8.7.6): set by set,
    /// the changes of no set before it, then its members (from the set's
    /// first GSN), then one GSN for every writer's end of it (the last
    /// plus one, D2; an empty set's first GSN is its end's). Each set's id
    /// becomes its first GSN (PID_GROUP_COHERENT_SET).
    fn assign_gsns(&mut self, group: &[usize]) {
        let set_of = |m: &Msg| match m {
            Msg::Data { group, .. }
            | Msg::Lifecycle { group, .. }
            | Msg::Ecs { group, .. }
            | Msg::Filtered { group, .. } => *group,
            Msg::Marker { .. } => None,
        };
        let sets: BTreeSet<u64> = group
            .iter()
            .flat_map(|&w| self.plan.writers[w].msgs.iter().filter_map(set_of))
            .collect();
        let mut out: Vec<Vec<Option<u64>>> = group
            .iter()
            .map(|&w| vec![None; self.plan.writers[w].msgs.len()])
            .collect();
        // Each writer's next message not given a GSN yet.
        let mut next: Vec<usize> = vec![0; group.len()];
        let mut g = 1u64;
        let mut first_of: BTreeMap<u64, u64> = BTreeMap::new();
        for &set in &sets {
            // The changes of no set before this set's members or end.
            for (k, &w) in group.iter().enumerate() {
                let msgs = &self.plan.writers[w].msgs;
                while next[k] < msgs.len() && set_of(&msgs[next[k]]).is_none() {
                    out[k][next[k]] = Some(g);
                    g += 1;
                    next[k] += 1;
                }
            }
            first_of.insert(set, g);
            // Its members.
            for (k, &w) in group.iter().enumerate() {
                let msgs = &self.plan.writers[w].msgs;
                while next[k] < msgs.len()
                    && set_of(&msgs[next[k]]) == Some(set)
                    && !matches!(msgs[next[k]], Msg::Ecs { .. })
                {
                    out[k][next[k]] = Some(g);
                    g += 1;
                    next[k] += 1;
                }
            }
            // Every writer's end of it.
            for (k, &w) in group.iter().enumerate() {
                let msgs = &self.plan.writers[w].msgs;
                assert!(
                    matches!(msgs.get(next[k]), Some(Msg::Ecs { group: Some(s), .. }) if *s == set),
                    "model: writer {w}'s end of set {set} follows its part"
                );
                out[k][next[k]] = Some(g);
                next[k] += 1;
            }
            g += 1;
        }
        for (k, &w) in group.iter().enumerate() {
            let n = self.plan.writers[w].msgs.len();
            while next[k] < n {
                out[k][next[k]] = Some(g);
                g += 1;
                next[k] += 1;
            }
        }
        for (k, &w) in group.iter().enumerate() {
            self.plan.writers[w].gsns = std::mem::take(&mut out[k]);
        }
        // A set's id on the wire is its first GSN.
        for &w in group {
            for m in &mut self.plan.writers[w].msgs {
                match m {
                    Msg::Data { group, .. }
                    | Msg::Lifecycle { group, .. }
                    | Msg::Ecs { group, .. }
                    | Msg::Filtered { group, .. } => {
                        if let Some(set) = group {
                            *set = first_of[set];
                        }
                    }
                    Msg::Marker { .. } => {}
                }
            }
        }
    }

    /// The GroupInfo of `w`'s HEARTBEAT announcing 1..=`last`, as its
    /// writer computes it (`group_heartbeat_info`): currentGSN the
    /// Publisher's last GSN, stopped at the first GSN of `w` not announced;
    /// firstGSN and lastGSN those of its first and last change announced.
    fn group_heartbeat(&self, w: usize, last: u64) -> Option<[u64; 3]> {
        let shared = self.shared.as_ref()?;
        shared.of(w)?;
        let gsns = &self.plan.writers[w].gsns;
        let publisher = self.plan.writers[w].publisher;
        let mut current = shared
            .writers
            .iter()
            .filter(|(_, p, _)| *p == publisher)
            .flat_map(|(sw, _, _)| self.plan.writers[*sw].gsns.iter().flatten())
            .copied()
            .max()?;
        let last = usize::try_from(last).expect("small").min(gsns.len());
        if let Some(Some(unannounced)) = gsns.get(last) {
            current = current.min(*unannounced);
        }
        let announced: Vec<u64> = gsns[..last].iter().flatten().copied().collect();
        match (announced.first(), announced.last()) {
            (Some(&first), Some(&last_gsn)) => Some([current.max(last_gsn), first, last_gsn]),
            _ => (current > 0).then(|| [current, current, current - 1]),
        }
    }

    fn depart(&mut self, w: usize) {
        if trace() {
            eprintln!("depart w{w}");
        }
        if let Some(shared) = &self.shared {
            if let Some((publisher, id)) = shared.of(w) {
                shared
                    .roster
                    .writers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|known| *known != (publisher, id, true));
            }
        }
        let guid = self.plan.writers[w].guid;
        self.net.subscriber.on_writer_dispose(
            &self.net.topic,
            guid,
            crate::engine::subscriber::DisposeKind::Unregistered,
        );
        self.net.credit.unmatch_writer(&guid);
        self.departed[w] = true;
    }

    /// `w`, taken for departed, comes back: discovered again, matched
    /// again (a reliable reader's proxy), announced again.
    fn come_back(&mut self, w: usize) {
        if trace() {
            eprintln!("back w{w}");
        }
        if let Some(shared) = &self.shared {
            if let Some((publisher, id)) = shared.of(w) {
                let mut known = shared
                    .roster
                    .writers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                known.push((publisher, id, true));
                known.sort_unstable();
                known.dedup();
            }
        }
        let guid = self.plan.writers[w].guid;
        if !self.best_effort {
            self.net.credit.match_writer(guid);
        }
        self.net.subscriber.on_writer_qos_resolved(guid);
        self.departed[w] = false;
    }

    /// A regapped DATA the reader lost to its GAP: one it did not hold when
    /// the GAP came (refused, or not received), so the GAP declared it
    /// irrelevant. One it had acknowledged is owed; one it held is kept.
    fn regap_lost(&self, w: usize, sn: u64, seen: &BTreeSet<(i32, u64)>) -> bool {
        self.regapped[w].contains(&sn)
            && !self.regap_owed.borrow()[w].contains(&sn)
            && !seen.contains(&(self.plan.writers[w].index, sn))
    }

    /// The sets with a GAPped member: never deliverable whole.
    fn broken_sets(&self, seen: &BTreeSet<(i32, u64)>) -> Vec<usize> {
        self.plan
            .sets
            .iter()
            .enumerate()
            .filter(|(_, (w, members))| {
                members
                    .iter()
                    .any(|sn| self.gapped[*w].contains(sn) || self.regap_lost(*w, *sn, seen))
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// The GAPs of DATA the writers replaced after sending them, those due
    /// (all of them with `all`).
    fn send_gaps_due(&self, all: bool) {
        let due: Vec<(usize, u64)> = {
            let mut later = self.gap_later.borrow_mut();
            let mut due = Vec::new();
            later.retain_mut(|(countdown, w, sn)| {
                *countdown = countdown.saturating_sub(1);
                if *countdown == 0 || all {
                    due.push((*w, *sn));
                    false
                } else {
                    true
                }
            });
            due
        };
        for (w, sn) in due {
            if self.departed[w] && self.return_after.is_none() {
                continue;
            }
            if trace() {
                eprintln!("regap w{w} sn{sn}");
            }
            self.note_regap(w, sn);
            let guid = self.plan.writers[w].guid;
            self.net
                .subscriber
                .on_writer_gap(guid, sn, sn + 1, Vec::new());
        }
    }

    /// A regapped DATA's GAP reaches the reader: owed if acknowledged.
    fn note_regap(&self, w: usize, sn: u64) {
        if self.regap_gapped.borrow_mut()[w].insert(sn) && self.ack_base[w] > sn {
            self.regap_owed.borrow_mut()[w].insert(sn);
        }
    }

    fn send(&self, w: usize, sn: u64) {
        // A writer that comes back was alive all along: what it sends lands.
        if self.departed[w] && !self.ext.late && self.return_after.is_none() {
            return;
        }
        let writer = &self.plan.writers[w];
        let regap = self.regapped[w].contains(&sn) && {
            let mut sent = self.regap_sent.borrow_mut();
            if sent[w].insert(sn) {
                // Sent once, as DATA; its GAP follows.
                self.gap_later.borrow_mut().push((2, w, sn));
                false
            } else {
                true
            }
        };
        if self.gapped[w].contains(&sn) || regap {
            // A GAP before the writer's first HEARTBEAT, only if asked.
            if writer.hb_count == 0 && !self.ext.early_gap {
                return;
            }
            if trace() {
                eprintln!("gap w{w} sn{sn}");
            }
            if regap {
                self.note_regap(w, sn);
            }
            self.net
                .subscriber
                .on_writer_gap(writer.guid, sn, sn + 1, Vec::new());
            return;
        }
        if let Msg::Filtered { .. } = writer.msgs[usize::try_from(sn - 1).expect("small")] {
            // Its GAP, filtered: the change is in no set for this reader.
            if writer.hb_count == 0 && !self.ext.early_gap {
                return;
            }
            if trace() {
                eprintln!("filtered w{w} sn{sn}");
            }
            self.net
                .subscriber
                .on_writer_gap_filtered(writer.guid, sn, sn + 1, Vec::new(), 1);
            return;
        }
        if trace() {
            eprintln!(
                "send w{w} sn{sn} {:?}",
                writer.msgs[usize::try_from(sn - 1).expect("small")]
            );
        }
        crate::engine::router::set_route_writer_is_hdds_for_test(writer.model == Model::Ecs);
        let sub = &self.net.subscriber;
        let topic = &self.net.topic;
        let idx = usize::try_from(sn - 1).expect("small");
        // A writer of the spec GROUP dialect names the writer set on every
        // change of a set (D5), as the router hands it over.
        if let Some(shared) = self.shared.as_ref().filter(|sh| sh.of(w).is_some()) {
            let set = match &writer.msgs[idx] {
                Msg::Data { group, .. } | Msg::Lifecycle { group, .. } | Msg::Ecs { group, .. } => {
                    *group
                }
                Msg::Marker { .. } | Msg::Filtered { .. } => None,
            };
            if let Some(set) = set {
                // On its end of the set, the first SN of its part: its own
                // SN when it wrote nothing in the set (D6).
                let part_first = matches!(writer.msgs[idx], Msg::Ecs { .. }).then(|| {
                    writer
                        .msgs
                        .iter()
                        .find_map(|m| match m {
                            Msg::Data {
                                set_start: Some(start),
                                group: Some(g),
                                ..
                            }
                            | Msg::Lifecycle {
                                set_start: Some(start),
                                group: Some(g),
                                ..
                            }
                            | Msg::Filtered {
                                set_start: Some(start),
                                group: Some(g),
                            } if *g == set => Some(*start),
                            _ => None,
                        })
                        .unwrap_or(sn)
                });
                crate::engine::Subscriber::on_group_change(
                    sub.as_ref(),
                    writer.guid,
                    crate::engine::GroupChange {
                        seq: sn,
                        group_sn: set,
                        publisher_entity_id: writer.publisher,
                        writer_set: shared.writer_sets[&writer.publisher],
                        gsn: writer.gsns.get(idx).copied().flatten(),
                        part_first_sn: part_first,
                    },
                );
            }
        }
        match writer.msgs[idx] {
            Msg::Data {
                instance,
                set_start: None,
                group: None,
            } => sub.on_data_with_writer(
                topic,
                writer.guid,
                sn,
                &encoded(&Keyed {
                    id: instance,
                    value: value_of(writer.index, sn),
                }),
                crate::dds::CdrVersion::Xcdr2,
            ),
            Msg::Data {
                instance,
                set_start,
                group,
            } => sub.on_data_coherent(
                topic,
                writer.guid,
                sn,
                &encoded(&Keyed {
                    id: instance,
                    value: value_of(writer.index, sn),
                }),
                crate::dds::CdrVersion::Xcdr2,
                set_start,
                group,
                group.map(|_| writer.publisher),
            ),
            Msg::Marker { end_sn, count } => {
                sub.on_coherent_end_marker(topic, writer.guid, None, None, end_sn, count, sn);
            }
            Msg::Lifecycle {
                instance,
                set_start,
                group,
            } => {
                let key = crate::dds::DDS::compute_key(&Keyed {
                    id: instance,
                    value: 0,
                });
                sub.on_lifecycle_coherent(
                    topic,
                    writer.guid,
                    sn,
                    key,
                    crate::engine::subscriber::DisposeKind::Disposed,
                    set_start,
                    group,
                    group.map(|_| writer.publisher),
                );
            }
            Msg::Ecs { last, group } => sub.on_ecs(
                topic,
                writer.guid,
                sn,
                last,
                group,
                group.map(|_| writer.publisher),
            ),
            Msg::Filtered { .. } => {}
        }
        crate::engine::router::set_route_writer_is_hdds_for_test(false);
    }

    /// `w`'s HEARTBEAT announcing 1..=`last`; the SNs the reader asks for,
    /// and whether it acknowledges everything.
    fn heartbeat(&mut self, w: usize, last: u64) -> (Vec<u64>, bool) {
        let writer = &mut self.plan.writers[w];
        writer.hb_count += 1;
        let guid = writer.guid;
        let count = writer.hb_count;
        // A writer of the spec GROUP dialect's GroupInfo, before the
        // HEARTBEAT itself (as `seed_reorder_gate` hands them over).
        if let Some([current, first, last_gsn]) = self.group_heartbeat(w, last) {
            crate::engine::Subscriber::on_writer_group_heartbeat(
                self.net.subscriber.as_ref(),
                guid,
                current,
                first,
                last_gsn,
            );
        }
        self.net.subscriber.on_writer_heartbeat_range(guid, 1, last);
        if trace() {
            eprintln!("heartbeat w{w} 1..={last}");
        }
        let answer = self
            .net
            .credit
            .answer_heartbeat(
                &guid,
                &HeartbeatSeen {
                    first_seq: 1,
                    last_seq: i64::try_from(last).expect("small"),
                    count,
                    final_flag: false,
                },
            )
            .expect("matched");
        let done = answer.bitmap_base > last && answer.missing.is_empty();
        self.ack_base[w] = self.ack_base[w].max(answer.bitmap_base);
        if trace() {
            eprintln!(
                "  ack base {} missing {:?}",
                answer.bitmap_base, answer.missing
            );
        }
        let mut asked = answer.missing.clone();
        asked.retain(|&sn| sn >= 1 && sn <= last);
        (asked, done)
    }

    /// The retries room given back scheduled, as the retry thread would run
    /// them between two events.
    fn step_retries(&self) {
        if super::admission::retries::run_queued() && trace() {
            eprintln!("retries ran");
        }
    }

    fn take(&mut self) -> bool {
        self.step_retries();
        let delivered_arc = Arc::clone(&self.delivered);
        let mut delivered = delivered_arc.lock().unwrap_or_else(|e| e.into_inner());
        let before = delivered.len();
        let taken = self.net.take_all();
        if trace() && !taken.is_empty() {
            let got: Vec<(i32, u64)> = taken.iter().map(origin).collect();
            eprintln!("take {got:?}");
        }
        delivered.extend(taken);
        let any = delivered.len() > before;
        drop(delivered);
        self.step_retries();
        any
    }

    fn schedule(&mut self, rng: &mut Rng) {
        let n = self.plan.writers.len();
        let mut next: Vec<u64> = vec![1; n];
        let mut sent_max: Vec<u64> = vec![0; n];
        // (countdown, writer, sn)
        let mut delayed: Vec<(u64, usize, u64)> = Vec::new();
        let mut step = 0u64;
        loop {
            step += 1;
            self.step_retries();
            if let Some((at, w)) = self.depart_at {
                if at == step && !self.departed[w] {
                    self.depart(w);
                    if self.return_after.is_none() {
                        next[w] = u64::try_from(self.plan.writers[w].msgs.len()).expect("s") + 1;
                    }
                }
                if let Some(after) = self.return_after {
                    if at + after == step && self.departed[w] {
                        self.come_back(w);
                        // A best-effort reader cannot tell a copy the
                        // writer sent before its departure from a change
                        // of a writer re-created under its GUID (no
                        // HEARTBEAT tells it where the writer is): it
                        // delivers what lands once the writer is
                        // announced again. In a network such a copy does
                        // not outlive the writer's rediscovery (seconds,
                        // an SPDP period at least): the schedule, whose
                        // steps are not seconds, drops it here.
                        if self.best_effort {
                            delayed.retain(|&(_, dw, _)| dw != w);
                        }
                    }
                }
            }
            let pending: Vec<usize> = (0..n)
                .filter(|&w| {
                    usize::try_from(next[w]).expect("small") <= self.plan.writers[w].msgs.len()
                })
                .collect();
            if pending.is_empty() && delayed.is_empty() {
                break;
            }
            if !pending.is_empty() {
                let w = pending[usize::try_from(
                    rng.below(u64::try_from(pending.len()).expect("small")),
                )
                .expect("small")];
                let sn = next[w];
                next[w] += 1;
                sent_max[w] = sent_max[w].max(sn);
                if rng.chance(15) {
                    // Lost on the way.
                } else if rng.chance(15) {
                    delayed.push((rng.range(1, 4), w, sn));
                } else {
                    self.send(w, sn);
                    if rng.chance(10) {
                        delayed.push((rng.range(1, 6), w, sn));
                    }
                }
            }
            let mut due = Vec::new();
            delayed.retain_mut(|(countdown, w, sn)| {
                *countdown = countdown.saturating_sub(1);
                if *countdown == 0 || pending.is_empty() {
                    due.push((*w, *sn));
                    false
                } else {
                    true
                }
            });
            for (w, sn) in due {
                self.send(w, sn);
            }
            self.send_gaps_due(false);
            if rng.chance(12) {
                let w =
                    usize::try_from(rng.below(u64::try_from(n).expect("small"))).expect("small");
                if sent_max[w] > 0 && !self.departed[w] && !self.best_effort {
                    let (asked, _) = self.heartbeat(w, sent_max[w]);
                    if rng.chance(60) {
                        for sn in asked {
                            if !rng.chance(20) {
                                self.send(w, sn);
                            }
                        }
                    }
                }
            }
            if rng.chance(12) {
                self.take();
            }
        }
    }

    /// The network ends: repairs until the reader asks for nothing.
    /// Returns which writers are fully acknowledged.
    fn drain(&mut self) -> Vec<bool> {
        let n = self.plan.writers.len();
        if trace() {
            eprintln!("drain");
        }
        self.send_gaps_due(true);
        // With max_instances, each writer lets its instances go once it has
        // sent everything (out of band: an unregister is no change the
        // reader's acknowledgement counts here), so that the instances the
        // others need are reclaimed as the application takes.
        if self.plan.max_instances != UNLIMITED {
            for writer in &self.plan.writers {
                let last = u64::try_from(writer.msgs.len()).expect("small");
                let instances: BTreeSet<i32> = writer
                    .msgs
                    .iter()
                    .filter_map(|m| match m {
                        Msg::Data { instance, .. } => Some(*instance),
                        _ => None,
                    })
                    .collect();
                for instance in instances {
                    self.net.subscriber.on_dispose_from_writer(
                        &self.net.topic,
                        writer.guid,
                        last + 1,
                        crate::dds::DDS::compute_key(&Keyed {
                            id: instance,
                            value: 0,
                        }),
                        crate::engine::subscriber::DisposeKind::Unregistered,
                    );
                }
            }
        }
        let mut done = vec![false; n];
        let mut quiet = 0;
        for _round in 0..80 {
            for (w, flag) in done.iter_mut().enumerate() {
                // A BEST_EFFORT writer repairs nothing.
                if self.departed[w] || self.best_effort {
                    *flag = true;
                    continue;
                }
                let last = u64::try_from(self.plan.writers[w].msgs.len()).expect("small");
                let (asked, all) = self.heartbeat(w, last);
                *flag = all;
                for sn in asked {
                    self.send(w, sn);
                }
            }
            let progress = self.take();
            if done.iter().all(|d| *d) && !progress {
                quiet += 1;
                if quiet >= 2 {
                    break;
                }
            } else {
                quiet = 0;
            }
        }
        self.take();
        done
    }

    /// The violations, by invariant, and whether an acknowledged sample was
    /// lost with a report.
    fn check(&self, acked: &[bool]) -> (Vec<String>, bool) {
        let mut bad = Vec::new();
        let plan = &self.plan;
        let reports = usize::try_from(self.net.rejected().total_count)
            .unwrap_or(usize::MAX)
            .saturating_add(usize::try_from(self.net.lost()).unwrap_or(usize::MAX));
        // 3. duplicates, 5. order.
        let mut seen = BTreeSet::new();
        let mut last_of: BTreeMap<i32, u64> = BTreeMap::new();
        let delivered = self
            .delivered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for sample in &delivered {
            let (w, sn) = origin(sample);
            if !seen.insert((w, sn)) {
                bad.push(format!("3-duplicate w{w} sn{sn}"));
            }
            if let Some(&prev) = last_of.get(&w) {
                if sn <= prev {
                    bad.push(format!("5-order w{w} sn{sn} after sn{prev}"));
                }
            }
            last_of.insert(w, sn);
        }
        // Instances delivered, for the max_instances allowance.
        let delivered_instances: BTreeSet<i32> = delivered.iter().map(|s| s.id).collect();
        // Instances beyond max_instances while their writers held the others:
        // refused, and taken once the others are let go and taken.
        let instance_bound_full = false;
        let _ = &delivered_instances;
        let mut losses = 0usize;
        let broken: BTreeSet<(usize, u64)> = self
            .broken_sets(&seen)
            .into_iter()
            .flat_map(|i| {
                let (w, members) = &plan.sets[i];
                members.iter().map(move |sn| (*w, *sn))
            })
            .collect();
        for (w, writer) in plan.writers.iter().enumerate() {
            // A departed writer, or a BEST_EFFORT one, owes no sample: only
            // what is delivered is checked.
            if self.departed[w] || self.best_effort {
                continue;
            }
            let data: Vec<(u64, i32)> = writer
                .msgs
                .iter()
                .enumerate()
                .filter_map(|(i, m)| match m {
                    Msg::Data { instance, .. } => {
                        Some((u64::try_from(i + 1).expect("small"), *instance))
                    }
                    _ => None,
                })
                .filter(|(sn, _)| !self.gapped[w].contains(sn) && !self.regap_lost(w, *sn, &seen))
                .collect();
            let expected: Vec<(u64, i32)> = match plan.keep_last {
                None => data
                    .iter()
                    .copied()
                    .filter(|(sn, _)| !broken.contains(&(w, *sn)))
                    .collect(),
                Some(_) => {
                    // The newest of each instance, owed unless its set is
                    // broken: a broken set's member still replaces the
                    // older samples of its instance.
                    let mut newest: BTreeMap<i32, u64> = BTreeMap::new();
                    for &(sn, inst) in &data {
                        newest.insert(inst, sn);
                    }
                    newest
                        .into_iter()
                        .map(|(inst, sn)| (sn, inst))
                        .filter(|(sn, _)| !broken.contains(&(w, *sn)))
                        .collect()
                }
            };
            for (sn, inst) in expected {
                if seen.contains(&(writer.index, sn)) {
                    continue;
                }
                let refused_for_good = instance_bound_full && !delivered_instances.contains(&inst);
                if refused_for_good {
                    continue;
                }
                if acked[w] {
                    losses += 1;
                } else {
                    bad.push(format!("1-stuck w{w} sn{sn} (unacknowledged, undelivered)"));
                }
            }
            if !acked[w] && !instance_bound_full {
                bad.push(format!("1-stuck w{w} never fully acknowledged"));
            }
        }
        if losses > reports {
            bad.push(format!("2-silent-loss {losses} lost, {reports} reported"));
        }
        // 4. atomicity.
        if plan.keep_last.is_none() {
            for (w, members) in &plan.sets {
                let index = plan.writers[*w].index;
                let got = members
                    .iter()
                    .filter(|sn| seen.contains(&(index, **sn)))
                    .count();
                if got != 0 && got != members.len() {
                    bad.push(format!(
                        "4-partial-set w{w} {got}/{} {members:?}",
                        members.len()
                    ));
                }
            }
        }
        // 4. GROUP atomicity across the writers of one Publisher.
        if plan.keep_last.is_none() {
            for members in &self.group_sets {
                let got = members
                    .iter()
                    .filter(|(w, sn)| seen.contains(&(plan.writers[*w].index, *sn)))
                    .count();
                if got != 0 && got != members.len() {
                    bad.push(format!(
                        "4-partial-group-set {got}/{} {members:?}",
                        members.len()
                    ));
                }
            }
        }
        // 7. counters.
        if let Some(room) = self.net.reader.network_room_for_test() {
            if room.taken() != 0 {
                bad.push(format!("7-places {} still taken", room.taken()));
            }
            if room.instance_samples() != 0 {
                bad.push(format!(
                    "7-instances {} still counted",
                    room.instance_samples()
                ));
            }
        }
        bad.sort();
        bad.dedup();
        (bad, losses > 0)
    }
}

/// Run `seed`: the violations, and whether it lost an acknowledged sample
/// (reported).
fn run_seed(seed: u64) -> (Vec<String>, bool) {
    run_seed_ext(seed, Ext::default())
}

fn run_seed_ext(seed: u64, ext: Ext) -> (Vec<String>, bool) {
    let mut rng = Rng::new(seed);
    let plan = Plan::draw(&mut rng);
    // Drawn apart from the plan and the schedule, so that the plain model's
    // seeds keep their schedules.
    let mut reader_rng = Rng::new(seed ^ 0xBE5_7EFF);
    let best_effort = reader_rng.chance(ext.best_effort_pct);
    let listener = reader_rng.chance(ext.listener_pct);
    // Retries of the coherent sets waiting for room run when the schedule
    // says so (`Run::step_retries`), not on the process's retry thread:
    // the schedule stays deterministic.
    super::admission::retries::queue_on_this_thread();
    let mut run = Run::new(seed, plan, best_effort).with_ext(seed, ext, listener);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.schedule(&mut rng);
        let acked = run.drain();
        run.check(&acked)
    }));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    outcome.unwrap_or_else(|_| (vec!["0-panic".to_string()], false))
}

/// `run_seed_ext` on its own thread: a seed that does not finish within ten
/// seconds is a deadlock (its thread is left behind).
fn run_seed_bounded(seed: u64, ext: Ext) -> (Vec<String>, bool) {
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name(format!("model-{seed}"))
        .spawn(move || {
            let _ = tx.send(run_seed_ext(seed, ext));
        });
    if spawned.is_err() {
        return (vec!["0-spawn".to_string()], false);
    }
    let secs = std::env::var("HDDS_X_TIMEOUT_S")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    rx.recv_timeout(std::time::Duration::from_secs(secs))
        .unwrap_or_else(|_| (vec!["0-deadlock".to_string()], false))
}

/// A short description of `seed`'s plan, for a failure report.
fn describe(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    let plan = Plan::draw(&mut rng);
    let models: Vec<String> = plan
        .writers
        .iter()
        .map(|w| format!("{:?}x{}", w.model, w.msgs.len()))
        .collect();
    format!(
        "seed {seed}: {:?} keep_last={:?} max_samples={} max_instances={} max_per_instance={} writers={models:?}",
        plan.scope,
        plan.keep_last,
        if plan.max_samples == UNLIMITED { 0 } else { plan.max_samples },
        if plan.max_instances == UNLIMITED { 0 } else { plan.max_instances },
        if plan.max_per_instance == UNLIMITED { 0 } else { plan.max_per_instance },
    )
}

fn run_seeds(seeds: std::ops::Range<u64>) {
    run_seeds_ext(seeds, Ext::default());
}

/// `Ext::all`, each dimension overridable from the environment
/// (HDDS_X_GAP, HDDS_X_DEPART, HDDS_X_LATE, HDDS_X_EARLY_GAP, HDDS_X_BE,
/// HDDS_X_LISTENER, HDDS_X_RETURN, HDDS_X_DISPOSE, HDDS_X_REGAP,
/// HDDS_X_SHARED).
fn ext_from_env() -> Ext {
    let all = Ext::all();
    let num = |k: &str, default: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    Ext {
        gap_pct: num("HDDS_X_GAP", all.gap_pct),
        depart_pct: num("HDDS_X_DEPART", all.depart_pct),
        late: num("HDDS_X_LATE", u64::from(all.late)) != 0,
        return_pct: num("HDDS_X_RETURN", all.return_pct),
        early_gap: num("HDDS_X_EARLY_GAP", u64::from(all.early_gap)) != 0,
        best_effort_pct: num("HDDS_X_BE", all.best_effort_pct),
        listener_pct: num("HDDS_X_LISTENER", all.listener_pct),
        dispose_pct: num("HDDS_X_DISPOSE", all.dispose_pct),
        regap_pct: num("HDDS_X_REGAP", all.regap_pct),
        shared_publisher_pct: num("HDDS_X_SHARED", all.shared_publisher_pct),
    }
}

/// Every dimension the plain model leaves out: GAPs (before the first
/// HEARTBEAT too), a writer leaving mid-schedule with its in-flight changes
/// landing after, BEST_EFFORT readers, and an application that takes from
/// inside its listener. Fast enough for every lib run.
#[test]
fn model_ext() {
    let n = std::env::var("HDDS_X_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    run_seeds_ext(0..n, ext_from_env());
}

/// `model_ext` with GROUP writers sharing a Publisher (HDDS_X_SHARED
/// overrides the 60 percent).
#[test]
fn model_ext_shared_publishers() {
    let n = std::env::var("HDDS_X_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    let shared = std::env::var("HDDS_X_SHARED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    run_seeds_ext(
        0..n,
        Ext {
            shared_publisher_pct: shared,
            ..ext_from_env()
        },
    );
}

/// The long run of `model_ext`.
#[test]
#[ignore = "long: many more seeds"]
fn model_ext_long() {
    run_seeds_ext(0..20_000, ext_from_env());
}

#[test]
#[ignore = "debugging aid"]
fn model_ext_one() {
    let seed = std::env::var("HDDS_MODEL_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // RUST_LOG=hdds::dds::reader=debug shows the reader's side.
    let _ = env_logger::builder().is_test(true).try_init();
    eprintln!("{}", describe(seed));
    let (bad, lost) = run_seed_ext(seed, ext_from_env());
    eprintln!("violations {bad:?} reported loss {lost}");
    assert!(bad.is_empty());
}

fn run_seeds_ext(seeds: std::ops::Range<u64>, ext: Ext) {
    let total = seeds.end - seeds.start;
    let mut by_invariant: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut failing = Vec::new();
    let mut reported_losses = Vec::new();
    // Debugging aid: only the seeds whose plan has this scope.
    let only = std::env::var("HDDS_MODEL_SCOPE").ok();
    let mut total = total;
    for seed in seeds {
        if let Some(only) = &only {
            let mut rng = Rng::new(seed);
            if format!("{:?}", Plan::draw(&mut rng).scope) != *only {
                total -= 1;
                continue;
            }
        }
        let (bad, lost) = run_seed_bounded(seed, ext);
        if lost {
            reported_losses.push(seed);
        }
        if bad.is_empty() {
            continue;
        }
        failing.push((seed, bad.clone()));
        let kinds: BTreeSet<String> = bad
            .iter()
            .map(|b| b.split(' ').next().unwrap_or("").to_string())
            .collect();
        for kind in kinds {
            by_invariant.entry(kind).or_default().push(seed);
        }
    }
    // Debugging aid: every failing seed and its invariants, one per line.
    if let Some(path) = std::env::var_os("HDDS_MODEL_DUMP") {
        let lines: Vec<String> = failing
            .iter()
            .map(|(seed, bad)| {
                let kinds: BTreeSet<&str> = bad
                    .iter()
                    .map(|b| b.split(' ').next().unwrap_or(""))
                    .collect();
                format!("{seed} {}", kinds.into_iter().collect::<Vec<_>>().join(","))
            })
            .collect();
        let _ = std::fs::write(path, lines.join("\n"));
    }
    if let Some(path) = std::env::var_os("HDDS_MODEL_DUMP_LOSSES") {
        let lines: Vec<String> = reported_losses.iter().map(u64::to_string).collect();
        let _ = std::fs::write(path, lines.join("\n"));
    }
    eprintln!(
        "model: {total} seeds, {} failing, {} with a reported loss",
        failing.len(),
        reported_losses.len()
    );
    for (kind, seeds) in &by_invariant {
        eprintln!(
            "  {kind}: {} seeds, first {:?}",
            seeds.len(),
            &seeds[..seeds.len().min(8)]
        );
    }
    for (seed, bad) in failing.iter().take(6) {
        eprintln!("  {}\n    {bad:?}", describe(*seed));
    }
    if !reported_losses.is_empty() {
        eprintln!(
            "  reported losses: first {:?}",
            &reported_losses[..reported_losses.len().min(8)]
        );
    }
    assert!(
        failing.is_empty(),
        "{} of {total} seeds fail",
        failing.len()
    );
}

/// Fast enough for every lib run.
#[test]
fn model_schedules() {
    run_seeds(0..400);
}

/// The long run: `cargo test -p hdds --lib model_schedules_long -- --ignored`.
#[test]
#[ignore = "long: many more seeds"]
fn model_schedules_long() {
    run_seeds(0..20_000);
}

/// One seed, for a failure to reproduce: `HDDS_MODEL_SEED=n`.
#[test]
#[ignore = "debugging aid"]
fn model_one_seed() {
    let seed = std::env::var("HDDS_MODEL_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // RUST_LOG=hdds::dds::reader=debug shows the reader's side.
    let _ = env_logger::builder().is_test(true).try_init();
    eprintln!("{}", describe(seed));
    let (bad, lost) = run_seed(seed);
    eprintln!("violations {bad:?} reported loss {lost}");
    assert!(bad.is_empty());
}

/// Debugging aid: the plan of every seed of the long run, one per line, to
/// `HDDS_MODEL_DUMP`.
#[test]
#[ignore = "debugging aid"]
fn model_plans() {
    let lines: Vec<String> = (0..20_000).map(describe).collect();
    if let Some(path) = std::env::var_os("HDDS_MODEL_DUMP") {
        let _ = std::fs::write(path, lines.join("\n"));
    }
}

/// `run_seed_ext` with the reader's retry thread (no `queue_on_this_thread`)
/// and `HDDS_MT_TAKERS` application threads (2 by default) taking
/// concurrently with the receive thread: commits, retries and HEARTBEATs
/// race the takes, as in production. Takes are serialized against each
/// other through the `delivered` lock, so the order check stays meaningful.
/// No listener (its pushes would race the order check). Nondeterministic:
/// a seed is a schedule, not an interleaving.
fn run_seed_mt(seed: u64, ext: Ext) -> (Vec<String>, bool) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut rng = Rng::new(seed);
    let plan = Plan::draw(&mut rng);
    let mut reader_rng = Rng::new(seed ^ 0xBE5_7EFF);
    let best_effort = reader_rng.chance(ext.best_effort_pct);
    let _listener = reader_rng.chance(ext.listener_pct);
    let env = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    if env("HDDS_MT_WORKER", 1) == 0 {
        super::admission::retries::queue_on_this_thread();
    }
    let n_takers = env("HDDS_MT_TAKERS", 2);
    let mut run = Run::new(seed, plan, best_effort).with_ext(seed, ext, false);
    let stop = Arc::new(AtomicBool::new(false));
    let mut takers = Vec::new();
    for _ in 0..n_takers {
        let reader = Arc::clone(&run.net.reader);
        let delivered = Arc::clone(&run.delivered);
        let stop = Arc::clone(&stop);
        takers.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                {
                    let mut d = delivered.lock().unwrap_or_else(|e| e.into_inner());
                    while let Ok(Some(s)) = reader.take() {
                        if trace() {
                            eprintln!("taker got {:?}", origin(&s));
                        }
                        d.push(s);
                    }
                }
                std::thread::yield_now();
            }
        }));
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run.schedule(&mut rng);
        let mut result = (vec![], false);
        for _ in 0..40 {
            let acked = run.drain();
            std::thread::sleep(std::time::Duration::from_millis(5));
            let _ = run.take();
            result = run.check(&acked);
            if result.0.is_empty() {
                break;
            }
        }
        result
    }));
    stop.store(true, Ordering::Relaxed);
    for t in takers {
        let _ = t.join();
    }
    outcome.unwrap_or_else(|_| (vec!["0-panic".to_string()], false))
}

/// `run_seed_mt` over `seeds`, each on its own thread with a timeout;
/// panics with the failing seeds by invariant.
fn run_seeds_mt(seeds: std::ops::Range<u64>, ext: Ext) {
    let total = seeds.end - seeds.start;
    let mut by: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for seed in seeds {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(run_seed_mt(seed, ext));
        });
        let (bad, _) = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .unwrap_or_else(|_| (vec!["0-deadlock".to_string()], false));
        for b in bad {
            let key: String = b.split_whitespace().next().unwrap_or("").to_string();
            let seeds = by.entry(key).or_default();
            if seeds.last() != Some(&seed) {
                seeds.push(seed);
            }
        }
    }
    let summary: Vec<String> = by
        .iter()
        .map(|(k, v)| format!("{k}: {} seeds, first {:?}", v.len(), &v[..v.len().min(10)]))
        .collect();
    eprintln!("MT model: {total} seeds, {summary:#?}");
    assert!(by.is_empty(), "{summary:#?}");
}

/// The extended model with application threads taking concurrently.
#[test]
fn model_mt() {
    let n = std::env::var("HDDS_X_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    run_seeds_mt(0..n, ext_from_env());
}

/// A GROUP flush delivers the writer's changes in its order while the
/// receive thread releases more of them: seed 3302 (GROUP, two ECS
/// writers) failed about one run in two when the flush took what the gate
/// had released for the writer in one gate lock and fed the set's samples
/// in others, a change released in between was delivered after the set's
/// later samples. Thirty runs of the seed.
#[test]
fn a_group_flush_keeps_the_writers_order_under_concurrent_takes() {
    for run in 0..30 {
        let (bad, _) = run_seed_mt(3302, Ext::all());
        assert!(bad.is_empty(), "run {run}: {bad:?}");
    }
}

/// The long run of `model_mt`.
#[test]
#[ignore = "long: many more seeds"]
fn model_mt_long() {
    run_seeds_mt(0..10_000, ext_from_env());
}

/// One `model_mt` seed, `HDDS_REPS` times (50 by default).
#[test]
#[ignore = "debugging aid"]
fn model_mt_one() {
    let seed: u64 = std::env::var("HDDS_MODEL_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let reps: u64 = std::env::var("HDDS_REPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    // RUST_LOG=hdds::dds::reader=debug shows the reader's side.
    let _ = env_logger::builder().is_test(true).try_init();
    eprintln!("{}", describe(seed));
    let mut fails = 0;
    for _ in 0..reps {
        let (bad, _) = run_seed_mt(seed, ext_from_env());
        if !bad.is_empty() {
            fails += 1;
            eprintln!("violations {bad:?}");
        }
    }
    eprintln!("seed {seed}: {fails}/{reps} failing");
    assert_eq!(fails, 0);
}
