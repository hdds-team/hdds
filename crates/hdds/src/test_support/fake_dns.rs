// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Minimal in-process DNS server (UDP, RFC 1035) for hermetic DNS-SD tests.
//!
//! Answers `A` and `SRV` questions from a table the test fills in, on a
//! `127.0.0.1:0` socket, so a resolver can be exercised without touching
//! `/etc/resolv.conf` or the network. Negative modes cover what a resolver
//! must survive: `NXDOMAIN`, a truncated (`TC`) answer, and a server that
//! never answers (timeout / retry paths).
//!
//! The wire codec ([`encode_query`], [`decode_message`]) is deliberately
//! self-contained and tiny: it is the test oracle for whatever resolver the
//! DNS-SD backend ships, and must not share code with it.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// `QTYPE` / `TYPE` for an IPv4 address record.
pub const QTYPE_A: u16 = 1;
/// `QTYPE` / `TYPE` for a service locator record (RFC 2782).
pub const QTYPE_SRV: u16 = 33;
/// `QCLASS` / `CLASS` IN.
pub const QCLASS_IN: u16 = 1;

const RCODE_NXDOMAIN: u16 = 3;
const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const TTL: u32 = 60;
const MAX_DATAGRAM: usize = 4096;

/// How the fake answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeDnsMode {
    /// Answer from the record table; an unknown name gets `NOERROR` with
    /// zero answers (the "exists but no such type" shape).
    Answer,
    /// Every question is answered `NXDOMAIN`.
    NxDomain,
    /// Every question is answered with the `TC` bit set and no records
    /// (the "retry over TCP" signal a UDP-only resolver must reject).
    Truncated,
    /// Questions are recorded but never answered.
    Silent,
}

/// Record data the fake can serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeRData {
    /// IPv4 address.
    A(Ipv4Addr),
    /// Service locator: priority, weight, port, target name.
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Anything else, as raw RDATA (for negative tests).
    Raw(Vec<u8>),
}

/// One question as the fake received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeDnsQuery {
    /// Message ID.
    pub id: u16,
    /// Question name, normalised (lower-case, no trailing dot).
    pub name: String,
    /// Question type.
    pub qtype: u16,
    /// Question class.
    pub qclass: u16,
}

/// A decoded resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Owner name, normalised (lower-case, no trailing dot).
    pub name: String,
    /// Record type.
    pub rtype: u16,
    /// Record class.
    pub rclass: u16,
    /// Time to live.
    pub ttl: u32,
    /// Decoded data (`Raw` for types this codec does not know).
    pub data: FakeRData,
}

/// A decoded DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    /// Message ID.
    pub id: u16,
    /// Header flags word.
    pub flags: u16,
    /// Questions: (name, qtype, qclass).
    pub questions: Vec<(String, u16, u16)>,
    /// Answer section.
    pub answers: Vec<DnsRecord>,
    /// Authority section.
    pub authorities: Vec<DnsRecord>,
    /// Additional section.
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    /// `QR` bit: this is a response.
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    /// `TC` bit: the answer was truncated.
    pub fn is_truncated(&self) -> bool {
        self.flags & FLAG_TC != 0
    }

    /// `RCODE` (low four bits of the flags).
    pub fn rcode(&self) -> u16 {
        self.flags & 0x000F
    }
}

/// Records keyed by (normalised name, type).
type RecordTable = HashMap<(String, u16), Vec<FakeRData>>;

/// A DNS server bound to `127.0.0.1:0`, answering on a background thread
/// until dropped.
pub struct FakeDnsServer {
    addr: SocketAddr,
    records: Arc<Mutex<RecordTable>>,
    mode: Arc<Mutex<FakeDnsMode>>,
    queries: Arc<Mutex<Vec<FakeDnsQuery>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeDnsServer {
    /// Bind a loopback UDP port and start answering in `Answer` mode.
    pub fn start() -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let addr = socket.local_addr()?;
        let records: Arc<Mutex<RecordTable>> = Arc::new(Mutex::new(HashMap::new()));
        let mode = Arc::new(Mutex::new(FakeDnsMode::Answer));
        let queries = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread_records = Arc::clone(&records);
        let thread_mode = Arc::clone(&mode);
        let thread_queries = Arc::clone(&queries);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("hdds-fake-dns".to_string())
            .spawn(move || {
                serve(
                    &socket,
                    &thread_records,
                    &thread_mode,
                    &thread_queries,
                    &thread_stop,
                );
            })?;

        Ok(Self {
            addr,
            records,
            mode,
            queries,
            stop,
            thread: Some(thread),
        })
    }

    /// The bound address (hand it to the resolver as its nameserver).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serve an `A` record.
    pub fn add_a(&self, name: &str, address: Ipv4Addr) {
        self.add_record(name, QTYPE_A, FakeRData::A(address));
    }

    /// Serve an `SRV` record. If `target` also has `A` records in the
    /// table they are returned in the additional section, as a real
    /// server would.
    pub fn add_srv(&self, name: &str, priority: u16, weight: u16, port: u16, target: &str) {
        self.add_record(
            name,
            QTYPE_SRV,
            FakeRData::Srv {
                priority,
                weight,
                port,
                target: normalise(target),
            },
        );
    }

    /// Serve an arbitrary record.
    pub fn add_record(&self, name: &str, rtype: u16, data: FakeRData) {
        lock(&self.records)
            .entry((normalise(name), rtype))
            .or_default()
            .push(data);
    }

    /// Forget every record.
    pub fn clear_records(&self) {
        lock(&self.records).clear();
    }

    /// Switch the answering mode; takes effect for the next question.
    pub fn set_mode(&self, mode: FakeDnsMode) {
        *lock(&self.mode) = mode;
    }

    /// Every question received so far, in order (answered or not).
    pub fn queries(&self) -> Vec<FakeDnsQuery> {
        lock(&self.queries).clone()
    }
}

impl Drop for FakeDnsServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Lower-case, no trailing dot: the comparison form for names.
pub fn normalise(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn serve(
    socket: &UdpSocket,
    records: &Mutex<RecordTable>,
    mode: &Mutex<FakeDnsMode>,
    queries: &Mutex<Vec<FakeDnsQuery>>,
    stop: &AtomicBool,
) {
    let mut buffer = [0u8; MAX_DATAGRAM];
    while !stop.load(Ordering::SeqCst) {
        let (len, from) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        let Ok(message) = decode_message(&buffer[..len]) else {
            continue;
        };
        let Some((name, qtype, qclass)) = message.questions.first().cloned() else {
            continue;
        };
        lock(queries).push(FakeDnsQuery {
            id: message.id,
            name: name.clone(),
            qtype,
            qclass,
        });

        let current_mode = *lock(mode);
        let rd = message.flags & FLAG_RD;
        let response = match current_mode {
            FakeDnsMode::Silent => continue,
            FakeDnsMode::NxDomain => encode_response(
                message.id,
                FLAG_QR | rd | FLAG_RA | RCODE_NXDOMAIN,
                &(name, qtype, qclass),
                &[],
                &[],
            ),
            FakeDnsMode::Truncated => encode_response(
                message.id,
                FLAG_QR | rd | FLAG_RA | FLAG_TC,
                &(name, qtype, qclass),
                &[],
                &[],
            ),
            FakeDnsMode::Answer => {
                let table = lock(records);
                let answers: Vec<DnsRecord> = table
                    .get(&(name.clone(), qtype))
                    .map(|entries| {
                        entries
                            .iter()
                            .map(|data| DnsRecord {
                                name: name.clone(),
                                rtype: qtype,
                                rclass: QCLASS_IN,
                                ttl: TTL,
                                data: data.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut additionals = Vec::new();
                for answer in &answers {
                    if let FakeRData::Srv { target, .. } = &answer.data {
                        if let Some(addresses) = table.get(&(target.clone(), QTYPE_A)) {
                            for data in addresses {
                                additionals.push(DnsRecord {
                                    name: target.clone(),
                                    rtype: QTYPE_A,
                                    rclass: QCLASS_IN,
                                    ttl: TTL,
                                    data: data.clone(),
                                });
                            }
                        }
                    }
                }
                encode_response(
                    message.id,
                    FLAG_QR | rd | FLAG_RA,
                    &(name, qtype, qclass),
                    &answers,
                    &additionals,
                )
            }
        };
        let _ = socket.send_to(&response, from);
    }
}

// ----------------------------------------------------------------------------
// Wire codec
// ----------------------------------------------------------------------------

/// Encode a standard recursive query for one question.
pub fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    write_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&QCLASS_IN.to_be_bytes());
    out
}

fn encode_response(
    id: u16,
    flags: u16,
    question: &(String, u16, u16),
    answers: &[DnsRecord],
    additionals: &[DnsRecord],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&section_count(answers.len(), "ANCOUNT").to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&section_count(additionals.len(), "ARCOUNT").to_be_bytes());
    write_name(&mut out, &question.0);
    out.extend_from_slice(&question.1.to_be_bytes());
    out.extend_from_slice(&question.2.to_be_bytes());
    for record in answers.iter().chain(additionals) {
        write_record(&mut out, record);
    }
    out
}

/// A section count, as RFC 1035 section 4.1.1 writes it: a `u16`.
///
/// Refuses what it cannot describe instead of wrapping it. The previous
/// `answers.len() as u16` announced 65536 answers as zero, and 65537 as
/// one: a reader then stops after the header, or after the first record,
/// and everything behind it is parsed as the next section. The test that
/// asked the fixture for those records would have asserted, quietly, on a
/// packet no decoder can reassemble - which is the opposite of a fixture's
/// job.
///
/// Failing loudly is what this module is for; `lib.rs` scopes the
/// `clippy::panic` allow to `test_support` for exactly this reason, and
/// nothing here is compiled into a shipped library.
fn section_count(records: usize, field: &str) -> u16 {
    match u16::try_from(records) {
        Ok(count) => count,
        Err(_) => panic!(
            "fake DNS: the fixture holds {} records, more than the u16 {} field \
             of RFC 1035 section 4.1.1 can count",
            records, field
        ),
    }
}

/// Write a name as uncompressed labels.
///
/// A label is at most 63 octets (RFC 1035 section 2.3.4). Clipping a longer
/// label to 63 bytes would encode a name the fixture was never asked for;
/// like `section_count`, this panics with the offending label instead.
fn write_name(out: &mut Vec<u8>, name: &str) {
    for label in normalise(name).split('.').filter(|label| !label.is_empty()) {
        let bytes = label.as_bytes();
        let len = match u8::try_from(bytes.len()) {
            Ok(len) if len <= 63 => len,
            _ => panic!(
                "fake DNS: label {:?} is {} octets, more than the 63 of RFC 1035 section 2.3.4",
                label,
                bytes.len()
            ),
        };
        out.push(len);
        out.extend_from_slice(bytes);
    }
    out.push(0);
}

fn write_record(out: &mut Vec<u8>, record: &DnsRecord) {
    write_name(out, &record.name);
    out.extend_from_slice(&record.rtype.to_be_bytes());
    out.extend_from_slice(&record.rclass.to_be_bytes());
    out.extend_from_slice(&record.ttl.to_be_bytes());
    let mut rdata = Vec::new();
    match &record.data {
        FakeRData::A(address) => rdata.extend_from_slice(&address.octets()),
        FakeRData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            rdata.extend_from_slice(&priority.to_be_bytes());
            rdata.extend_from_slice(&weight.to_be_bytes());
            rdata.extend_from_slice(&port.to_be_bytes());
            write_name(&mut rdata, target);
        }
        FakeRData::Raw(bytes) => rdata.extend_from_slice(bytes),
    }
    // RDLENGTH is a u16 (RFC 1035 section 4.1.3), so RDATA over 65535 bytes
    // is not expressible in DNS at all - `FakeRData::Raw` is the only way to
    // hand this fixture that much. A wrapping cast would announce 0 bytes
    // while carrying 65536, and a reader would parse the payload as the
    // next record's owner name. Refuse it where the test can see which
    // record did it.
    let rdlength = match u16::try_from(rdata.len()) {
        Ok(length) => length,
        Err(_) => panic!(
            "fake DNS: RDATA for {} is {} bytes, more than the u16 RDLENGTH \
             of RFC 1035 section 4.1.3 can describe",
            record.name,
            rdata.len()
        ),
    };
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(&rdata);
}

/// Decode a message (query or response). Names may use compression
/// pointers; loops and out-of-range pointers are rejected.
pub fn decode_message(bytes: &[u8]) -> Result<DnsMessage, String> {
    if bytes.len() < 12 {
        return Err(format!("message too short: {} bytes", bytes.len()));
    }
    let id = read_u16(bytes, 0)?;
    let flags = read_u16(bytes, 2)?;
    let qdcount = read_u16(bytes, 4)?;
    let ancount = read_u16(bytes, 6)?;
    let nscount = read_u16(bytes, 8)?;
    let arcount = read_u16(bytes, 10)?;

    let mut offset = 12;
    let mut questions = Vec::with_capacity(usize::from(qdcount));
    for _ in 0..qdcount {
        let (name, next) = read_name(bytes, offset)?;
        let qtype = read_u16(bytes, next)?;
        let qclass = read_u16(bytes, next + 2)?;
        questions.push((name, qtype, qclass));
        offset = next + 4;
    }

    let mut read_section = |count: u16| -> Result<Vec<DnsRecord>, String> {
        let mut records = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (name, next) = read_name(bytes, offset)?;
            let rtype = read_u16(bytes, next)?;
            let rclass = read_u16(bytes, next + 2)?;
            let ttl =
                u32::from(read_u16(bytes, next + 4)?) << 16 | u32::from(read_u16(bytes, next + 6)?);
            let rdlength = usize::from(read_u16(bytes, next + 8)?);
            let rdata_start = next + 10;
            let rdata_end = rdata_start + rdlength;
            if rdata_end > bytes.len() {
                return Err("RDATA runs past the end of the message".to_string());
            }
            let rdata = &bytes[rdata_start..rdata_end];
            let data = match rtype {
                QTYPE_A if rdlength == 4 => {
                    FakeRData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
                }
                QTYPE_SRV if rdlength >= 7 => {
                    let (target, _) = read_name(bytes, rdata_start + 6)?;
                    FakeRData::Srv {
                        priority: read_u16(bytes, rdata_start)?,
                        weight: read_u16(bytes, rdata_start + 2)?,
                        port: read_u16(bytes, rdata_start + 4)?,
                        target,
                    }
                }
                _ => FakeRData::Raw(rdata.to_vec()),
            };
            records.push(DnsRecord {
                name,
                rtype,
                rclass,
                ttl,
                data,
            });
            offset = rdata_end;
        }
        Ok(records)
    };

    let answers = read_section(ancount)?;
    let authorities = read_section(nscount)?;
    let additionals = read_section(arcount)?;

    Ok(DnsMessage {
        id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    match bytes.get(offset..offset + 2) {
        Some(&[high, low]) => Ok(u16::from_be_bytes([high, low])),
        _ => Err(format!("truncated at offset {}", offset)),
    }
}

/// Read a (possibly compressed) name starting at `offset`. Returns the
/// normalised name and the offset just past the name in the ORIGINAL
/// stream (a pointer ends the name there, whatever it points to).
fn read_name(bytes: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut end_after: Option<usize> = None;
    let mut hops = 0;
    loop {
        let length = *bytes
            .get(offset)
            .ok_or_else(|| format!("name runs past the end at offset {}", offset))?;
        match length {
            0 => {
                offset += 1;
                break;
            }
            l if l & 0xC0 == 0xC0 => {
                let pointer = usize::from(read_u16(bytes, offset)? & 0x3FFF);
                if end_after.is_none() {
                    end_after = Some(offset + 2);
                }
                hops += 1;
                if hops > 16 || pointer >= offset {
                    return Err("compression pointer loop".to_string());
                }
                offset = pointer;
            }
            l if l & 0xC0 != 0 => {
                return Err(format!("unsupported label type 0x{:02x}", l));
            }
            l => {
                let start = offset + 1;
                let stop = start + usize::from(l);
                let label = bytes
                    .get(start..stop)
                    .ok_or_else(|| "label runs past the end".to_string())?;
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                offset = stop;
            }
        }
    }
    Ok((labels.join("."), end_after.unwrap_or(offset)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(server: &FakeDnsServer, id: u16, name: &str, qtype: u16) -> Option<DnsMessage> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("read timeout");
        socket
            .send_to(&encode_query(id, name, qtype), server.addr())
            .expect("send query");
        let mut buffer = [0u8; MAX_DATAGRAM];
        let (len, _) = socket.recv_from(&mut buffer).ok()?;
        Some(decode_message(&buffer[..len]).expect("decodable response"))
    }

    #[test]
    fn fake_dns_answers_srv_with_additional_a() {
        let server = FakeDnsServer::start().expect("start fake dns");
        server.add_srv(
            "_hdds._udp.Example.test.",
            10,
            5,
            7410,
            "node-a.example.test",
        );
        server.add_srv(
            "_hdds._udp.example.test",
            20,
            1,
            7412,
            "node-b.example.test.",
        );
        server.add_a("node-a.example.test", Ipv4Addr::new(192, 0, 2, 1));
        server.add_a("node-b.example.test", Ipv4Addr::new(192, 0, 2, 2));

        let response =
            ask(&server, 0x1234, "_hdds._udp.example.test", QTYPE_SRV).expect("an answer");
        assert_eq!(response.id, 0x1234);
        assert!(response.is_response());
        assert!(!response.is_truncated());
        assert_eq!(response.rcode(), 0);
        assert_eq!(
            response.questions,
            vec![("_hdds._udp.example.test".to_string(), QTYPE_SRV, QCLASS_IN)]
        );
        assert_eq!(response.answers.len(), 2);
        assert_eq!(
            response.answers[0].data,
            FakeRData::Srv {
                priority: 10,
                weight: 5,
                port: 7410,
                target: "node-a.example.test".to_string()
            }
        );
        assert_eq!(response.answers[0].name, "_hdds._udp.example.test");
        assert_eq!(response.answers[0].ttl, TTL);
        let additional_addresses: Vec<_> = response
            .additionals
            .iter()
            .map(|record| (record.name.as_str(), record.data.clone()))
            .collect();
        assert_eq!(
            additional_addresses,
            vec![
                (
                    "node-a.example.test",
                    FakeRData::A(Ipv4Addr::new(192, 0, 2, 1))
                ),
                (
                    "node-b.example.test",
                    FakeRData::A(Ipv4Addr::new(192, 0, 2, 2))
                ),
            ]
        );

        // A plain A question is answered without additionals.
        let response = ask(&server, 7, "NODE-A.example.test", QTYPE_A).expect("an answer");
        assert_eq!(response.answers.len(), 1);
        assert!(response.additionals.is_empty());

        let queries = server.queries();
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].qtype, QTYPE_SRV);
        assert_eq!(queries[1].name, "node-a.example.test");
    }

    #[test]
    fn fake_dns_negative_modes_nxdomain_truncated_and_silent() {
        let server = FakeDnsServer::start().expect("start fake dns");
        server.add_a("node.example.test", Ipv4Addr::new(192, 0, 2, 9));

        // Unknown name in Answer mode: NOERROR, no records.
        let response = ask(&server, 1, "missing.example.test", QTYPE_A).expect("an answer");
        assert_eq!(response.rcode(), 0);
        assert!(response.answers.is_empty());

        server.set_mode(FakeDnsMode::NxDomain);
        let response = ask(&server, 2, "node.example.test", QTYPE_A).expect("an answer");
        assert_eq!(response.rcode(), RCODE_NXDOMAIN);
        assert!(response.answers.is_empty());

        server.set_mode(FakeDnsMode::Truncated);
        let response = ask(&server, 3, "node.example.test", QTYPE_A).expect("an answer");
        assert!(response.is_truncated());
        assert!(response.answers.is_empty());

        server.set_mode(FakeDnsMode::Silent);
        assert!(ask(&server, 4, "node.example.test", QTYPE_A).is_none());
        assert_eq!(
            server.queries().len(),
            4,
            "silent questions are still recorded"
        );

        server.set_mode(FakeDnsMode::Answer);
        let response = ask(&server, 5, "node.example.test", QTYPE_A).expect("an answer");
        assert_eq!(
            response.answers[0].data,
            FakeRData::A(Ipv4Addr::new(192, 0, 2, 9))
        );
    }

    #[test]
    fn codec_follows_compression_pointers_and_rejects_loops() {
        // Hand-built response: question "a.test" then an answer whose owner
        // name is a pointer back to offset 12 (the question name).
        let mut wire = Vec::new();
        wire.extend_from_slice(&0x0102u16.to_be_bytes());
        wire.extend_from_slice(&(FLAG_QR | FLAG_RD | FLAG_RA).to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        wire.extend_from_slice(&0u16.to_be_bytes());
        write_name(&mut wire, "a.test");
        wire.extend_from_slice(&QTYPE_A.to_be_bytes());
        wire.extend_from_slice(&QCLASS_IN.to_be_bytes());
        wire.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer -> offset 12
        wire.extend_from_slice(&QTYPE_A.to_be_bytes());
        wire.extend_from_slice(&QCLASS_IN.to_be_bytes());
        wire.extend_from_slice(&300u32.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&[10, 0, 0, 1]);

        let message = decode_message(&wire).expect("decodes");
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].name, "a.test");
        assert_eq!(message.answers[0].ttl, 300);
        assert_eq!(
            message.answers[0].data,
            FakeRData::A(Ipv4Addr::new(10, 0, 0, 1))
        );

        // A pointer to itself must not spin.
        let mut looping = wire[..12].to_vec();
        looping.extend_from_slice(&0xC00Cu16.to_be_bytes());
        looping.extend_from_slice(&QTYPE_A.to_be_bytes());
        looping.extend_from_slice(&QCLASS_IN.to_be_bytes());
        assert!(decode_message(&looping).is_err());
        assert!(decode_message(&wire[..5]).is_err());
    }
    /// Every length field the fixture writes describes the bytes it
    /// actually wrote.
    ///
    /// Checked on the emitted bytes, not inferred: a wrapped RDLENGTH is
    /// a silent failure. A record carrying 65536 bytes of RDATA while
    /// announcing 0 makes a reader treat the payload as the next record's
    /// owner name, and the test built on that fixture asserts on garbage.
    #[test]
    fn the_length_fields_describe_what_was_written() {
        let mut name_only = Vec::new();
        write_name(&mut name_only, "big.example.test");
        // Where RDLENGTH sits in a record: name, TYPE, CLASS, TTL.
        let rdlength_at = name_only.len() + 2 + 2 + 4;

        for size in [0usize, 1, 255, 256, 65_535] {
            let record = DnsRecord {
                name: "big.example.test".to_string(),
                rtype: 99,
                rclass: QCLASS_IN,
                ttl: TTL,
                data: FakeRData::Raw(vec![0xAB; size]),
            };
            let mut wire = Vec::new();
            write_record(&mut wire, &record);
            let declared = u16::from_be_bytes([wire[rdlength_at], wire[rdlength_at + 1]]);
            assert_eq!(
                usize::from(declared),
                size,
                "RDLENGTH announced for {} bytes of RDATA",
                size
            );
            assert_eq!(
                wire.len(),
                rdlength_at + 2 + size,
                "bytes actually written for {} bytes of RDATA",
                size
            );
        }

        // The section counts, against a response the fixture's own decoder
        // reads back.
        let record = DnsRecord {
            name: "node-a.example.test".to_string(),
            rtype: QTYPE_A,
            rclass: QCLASS_IN,
            ttl: TTL,
            data: FakeRData::A(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let response = encode_response(
            0x4242,
            FLAG_QR,
            &("_hdds._udp.example.test".to_string(), QTYPE_SRV, QCLASS_IN),
            &[record.clone(), record.clone()],
            std::slice::from_ref(&record),
        );
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 2, "ANCOUNT");
        assert_eq!(
            u16::from_be_bytes([response[10], response[11]]),
            1,
            "ARCOUNT"
        );
        let decoded = decode_message(&response).expect("the fixture's own response decodes");
        assert_eq!(decoded.answers.len(), 2);
        assert_eq!(decoded.additionals.len(), 1);
    }

    /// One byte past what RDLENGTH can describe: refused, naming the
    /// record, instead of wrapped into a well-formed lie.
    #[test]
    #[should_panic(expected = "RDLENGTH")]
    fn rdata_too_long_for_rdlength_is_refused_not_wrapped() {
        let record = DnsRecord {
            name: "big.example.test".to_string(),
            rtype: 99,
            rclass: QCLASS_IN,
            ttl: TTL,
            data: FakeRData::Raw(vec![0u8; usize::from(u16::MAX) + 1]),
        };
        write_record(&mut Vec::new(), &record);
    }

    /// One record past what ANCOUNT can count: refused, not wrapped to 0.
    #[test]
    #[should_panic(expected = "ANCOUNT")]
    fn more_answers_than_ancount_can_count_is_refused_not_wrapped() {
        let record = DnsRecord {
            name: "node-a.example.test".to_string(),
            rtype: QTYPE_A,
            rclass: QCLASS_IN,
            ttl: TTL,
            data: FakeRData::A(Ipv4Addr::new(192, 0, 2, 1)),
        };
        let answers = vec![record; usize::from(u16::MAX) + 1];
        encode_response(
            1,
            FLAG_QR,
            &("_hdds._udp.example.test".to_string(), QTYPE_SRV, QCLASS_IN),
            &answers,
            &[],
        );
    }
}
