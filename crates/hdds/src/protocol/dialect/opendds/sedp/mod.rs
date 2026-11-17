// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS SEDP Builder
//!
//! Builds SEDP endpoint announcements for OpenDDS interoperability.
//!
//!
//! # XTypes parameters
//!
//! Announcements for vendor 0x0103 peers carry the XTypes discovery
//! parameters (DDS-XTypes 1.3 7.6.3.2):
//! - PID_DATA_REPRESENTATION (0x0073), listing XCDR2;
//! - PID_TYPE_INFORMATION (0x0075), derived from the endpoint's own
//!   TypeObject, absent when the endpoint has none.
//!
//! # PID Order
//!
//! The PID order follows standard RTPS conventions:
//! 1. CDR encapsulation header (PL_CDR_LE)
//! 2. Locators (PID_UNICAST_LOCATOR)
//! 3. Identity (PID_PARTICIPANT_GUID, PID_ENDPOINT_GUID)
//! 4. Strings (PID_TOPIC_NAME, PID_TYPE_NAME)
//! 5. Version (PID_PROTOCOL_VERSION, PID_VENDOR_ID)
//! 6. XTypes (PID_DATA_REPRESENTATION, PID_TYPE_INFORMATION)
//! 7. QoS (RELIABILITY, DURABILITY, HISTORY, etc.)
//! 8. PID_SENTINEL

mod locators;
mod metadata;
mod qos;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::SedpEndpointData;

/// PID constants
mod pids {
    pub const PID_SENTINEL: u16 = 0x0001;
}

/// Build SEDP discovery announcement for OpenDDS.
///
/// Includes PID_TYPE_INFORMATION (0x0075) for XTypes compatibility.
// @audit-ok: Sequential builder (cyclo 19, cogni 2) - linear write_xxx calls without complex branching
pub fn build_sedp(data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
    // Pre-allocate buffer (2KB - typical SEDP with TypeInfo)
    let mut buf = vec![0u8; 2048];
    let mut offset = 0;

    // CDR encapsulation header (PL_CDR_LE = 0x0003)
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset += 4;

    // ===== LOCATORS SECTION =====
    for locator in data.unicast_locators {
        locators::write_unicast_locator(locator, &mut buf, &mut offset)?;
    }

    // ===== IDENTITY SECTION =====
    metadata::write_participant_guid(&data.participant_guid, &mut buf, &mut offset)?;
    metadata::write_endpoint_guid(&data.endpoint_guid, &mut buf, &mut offset)?;

    // ===== STRING SECTION =====
    metadata::write_topic_name(data.topic_name, &mut buf, &mut offset)?;
    metadata::write_type_name(data.type_name, &mut buf, &mut offset)?;

    // ===== VERSION SECTION =====
    metadata::write_protocol_version(&mut buf, &mut offset)?;
    metadata::write_vendor_id(&mut buf, &mut offset)?;

    // ===== XTYPES SECTION =====
    // PID_DATA_REPRESENTATION (0x0073).
    // Emit the endpoint's ACTUAL DataRepresentationQosPolicy so the OpenDDS
    // peer can run its own RxO check (DDS-XTypes v1.3 sec. 7.6.3.1.2). When the
    // local QoS left the list empty ("no restriction"), fall back to the
    // always-both advertisement [XCDR1, XCDR2] so default-profile
    // endpoints match OpenDDS. An explicit `-x 1` / `-x 2`
    // endpoint advertises exactly that representation, letting OpenDDS
    // report on_offered_incompatible_qos against a mismatched representation
    // instead of falsely matching on the hardcoded XCDR1 entry.
    let explicit_dr: &[u16] = data
        .qos
        .map(|q| q.data_representation.as_slice())
        .unwrap_or(&[]);
    if explicit_dr.is_empty() {
        metadata::write_data_representation_xcdr2(&mut buf, &mut offset)?;
    } else {
        metadata::write_data_representation_list(&mut buf, &mut offset, explicit_dr)?;
    }

    // PID_TYPE_CONSISTENCY (0x0074) is not emitted by this dialect; type
    // matching relies on PID_TYPE_INFORMATION (or the type name).
    // metadata::write_type_consistency(&mut buf, &mut offset)?;

    // PID_TYPE_INFORMATION (0x0075), DDS-XTypes 1.3 7.6.3.2.1. A receiver
    // that matches endpoints on their TypeIdentifiers leaves an endpoint
    // announced without this parameter unmatched (PID_TYPE_CONSISTENCY, not
    // emitted here, carries no identifier), so this dialect carries it, in
    // the XTypes group, right after PID_DATA_REPRESENTATION. The
    // value is the one the generic SEDP path announces for the same
    // endpoint, written by the same writer: the minimal and complete
    // identifiers of the endpoint's own type. An endpoint without a
    // TypeObject announces none: any value would describe some other type.
    if let Some(param) = type_information_parameter(data) {
        // Grow the buffer by the parameter's size so the headroom left for
        // the QoS section is unchanged.
        buf.resize(buf.len() + param.len(), 0);
        buf[offset..offset + param.len()].copy_from_slice(&param);
        offset += param.len();
    }

    // ===== QOS SECTION =====
    qos::write_durability(data.qos, &mut buf, &mut offset)?;
    qos::write_reliability(data.qos, &mut buf, &mut offset)?;
    qos::write_history(data.qos, &mut buf, &mut offset)?;
    qos::write_deadline(data.qos, &mut buf, &mut offset)?;
    crate::protocol::dialect::write_liveliness_pid(data.qos, &mut buf, &mut offset)?;
    crate::protocol::dialect::write_latency_budget_pid(data.qos, &mut buf, &mut offset, true)?;
    crate::protocol::dialect::write_destination_order_pid(data.qos, &mut buf, &mut offset, true)?;
    qos::write_ownership(data.qos, &mut buf, &mut offset)?;
    qos::write_ownership_strength(data.qos, &mut buf, &mut offset)?;
    crate::protocol::dialect::write_presentation_pid(data.qos, &mut buf, &mut offset, true)?;
    // PID_PARTITION (0x0029) -- emitted only when non-default. The first SEDP
    // sample HDDS sends for an endpoint must carry its partition: a later
    // copy with the same sequence number is a duplicate for the peer's
    // reliable reader and is discarded, so the peer would keep matching
    // against the default (empty) partition.
    qos::write_partition(data.qos, &mut buf, &mut offset)?;

    // ===== SENTINEL =====
    write_sentinel(&mut buf, &mut offset)?;

    // Truncate to actual size
    buf.truncate(offset);
    Ok(buf)
}

/// The `PID_TYPE_INFORMATION` parameter for the endpoint's own type, or
/// `None` when the endpoint has no TypeObject (or one that cannot produce a
/// minimal TypeObject). Same value as the generic SEDP path:
/// `announced_type_information` picks the announce-time value with resolved
/// dependencies when there is one, else derives it from the TypeObject.
///
/// A TypeInformation that fails to encode is left out, and the endpoint is
/// still announced: a peer then matches on the type name (DDS-XTypes 1.3
/// 7.6.3.4.2 Step 2) instead of never hearing of the endpoint at all.
#[cfg(feature = "xtypes")]
fn type_information_parameter(data: &SedpEndpointData) -> Option<Vec<u8>> {
    use crate::protocol::discovery::sedp::build::{
        announced_type_information, encode_type_information_parameter,
    };
    let type_obj = data.decoded_type_object("opendds")?;
    #[cfg(feature = "xtypes-structural-assignability")]
    let precomputed = data.type_information.as_ref();
    #[cfg(not(feature = "xtypes-structural-assignability"))]
    let precomputed = None;
    let info = announced_type_information(&type_obj, precomputed)?;
    match encode_type_information_parameter(&info) {
        Ok(param) => param,
        Err(e) => {
            log::warn!(
                "[opendds] TypeInformation of '{}' not encodable ({:?}): announced without it",
                data.type_name,
                e
            );
            None
        }
    }
}

/// Without the `xtypes` feature no TypeObject reaches the encoder, so no
/// TypeInformation is announced.
#[cfg(not(feature = "xtypes"))]
fn type_information_parameter(_data: &SedpEndpointData) -> Option<Vec<u8>> {
    None
}

/// Write PID_SENTINEL (0x0001)
fn write_sentinel(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 4 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_SENTINEL.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&0u16.to_le_bytes());
    *offset += 4;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dialect::Guid;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    const PID_DATA_REPRESENTATION: u16 = 0x0073;
    const PID_TYPE_INFORMATION: u16 = 0x0075;

    fn test_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x03, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0x04],
        }
    }

    fn test_participant_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x03, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0xC1],
        }
    }

    /// An endpoint announcement of `type_name` whose TypeObject travels as
    /// `type_object` (HDDS' own CDR2 encoding, as `build_sedp_rtps_packet`
    /// hands it to the dialect encoders).
    fn endpoint<'a>(
        type_name: &'a str,
        locators: &'a [SocketAddr],
        type_object: Option<&'a [u8]>,
    ) -> SedpEndpointData<'a> {
        SedpEndpointData {
            endpoint_guid: test_guid(),
            participant_guid: test_participant_guid(),
            topic_name: "TemperatureTopic",
            type_name,
            unicast_locators: locators,
            multicast_locators: &[],
            qos: None,
            type_object,
            user_data: None,
            hdds_shm_capability: None,
            hdds_peer_destination: false,
            group_entity_id: None,
            type_consistency: None,
            #[cfg(feature = "xtypes-structural-assignability")]
            type_information: None,
            emit_type_object_pid: true,
        }
    }

    /// The parameters of a PL_CDR_LE parameter list, in wire order, up to
    /// PID_SENTINEL: `(pid, value)`.
    fn parameters(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00], "PL_CDR_LE header");
        let mut out = Vec::new();
        let mut at = 4;
        loop {
            let pid = u16::from_le_bytes([buf[at], buf[at + 1]]);
            let len = usize::from(u16::from_le_bytes([buf[at + 2], buf[at + 3]]));
            at += 4;
            if pid == pids::PID_SENTINEL {
                assert_eq!(at, buf.len(), "nothing after PID_SENTINEL");
                return out;
            }
            out.push((pid, buf[at..at + len].to_vec()));
            at += len;
        }
    }

    fn type_information_of(buf: &[u8]) -> Option<Vec<u8>> {
        let mut found = parameters(buf)
            .into_iter()
            .filter(|(pid, _)| *pid == PID_TYPE_INFORMATION);
        let first = found.next().map(|(_, v)| v);
        assert!(found.next().is_none(), "at most one PID_TYPE_INFORMATION");
        first
    }

    #[test]
    fn an_endpoint_without_a_type_object_announces_no_type_information() {
        let locators = [SocketAddr::from(SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 22),
            7411,
        ))];
        // Neither the short nor the qualified name of a type earns a
        // TypeInformation: only a TypeObject does.
        for name in [
            "Temperature",
            "TemperatureModule::Temperature",
            "SensorReading",
        ] {
            let buf = build_sedp(&endpoint(name, &locators, None)).expect("build_sedp");
            let params = parameters(&buf);
            assert!(
                params
                    .iter()
                    .any(|(pid, _)| *pid == PID_DATA_REPRESENTATION),
                "PID_DATA_REPRESENTATION is announced for {name}"
            );
            assert_eq!(
                type_information_of(&buf),
                None,
                "no TypeObject, no TypeInformation, for {name}"
            );
        }
    }

    /// TypeInformation tests: the identifiers announced are those of the
    /// endpoint's own type, computed here independently of HDDS' TypeObject
    /// encoder, from the DDS-XTypes 1.3 Annex B IDL and the XCDR2 rules
    /// (7.4.3).
    #[cfg(feature = "xtypes")]
    mod type_information {
        use super::*;
        use crate::core::ser::traits::Cdr2Encode;
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
            TypeIdentifier,
        };

        const EK_MINIMAL: u8 = 0xF1;
        const EK_COMPLETE: u8 = 0xF2;
        const TK_INT32: u8 = 0x04;
        const TK_UINT32: u8 = 0x07;
        const TK_FLOAT32: u8 = 0x09;
        const IS_FINAL: u16 = 0x0001;
        const IS_APPENDABLE: u16 = 0x0002;

        /// A struct type: name, struct flags, members (name, member flags,
        /// primitive TypeKind) in member-id order.
        struct Shape {
            name: &'static str,
            struct_flags: u16,
            members: &'static [(&'static str, u16, u8)],
        }

        /// `struct Temperature { float value; long timestamp; }`, @final,
        /// the type `build.rs` generates.
        const BUILD_RS: Shape = Shape {
            name: "Temperature",
            struct_flags: IS_FINAL,
            members: &[("value", 0, TK_FLOAT32), ("timestamp", 0, TK_INT32)],
        };

        /// The same members, qualified name: the type of the
        /// `temperature_generated` and `temperature_rti` examples.
        const EXAMPLES: Shape = Shape {
            name: "TemperatureData::Temperature",
            struct_flags: IS_FINAL,
            members: &[("value", 0, TK_FLOAT32), ("timestamp", 0, TK_INT32)],
        };

        /// What `#[derive(DDS)]` gives
        /// `struct Temperature { sensor_id: u32, celsius: f32 }`: @appendable,
        /// no member flags.
        const DERIVED: Shape = Shape {
            name: "Temperature",
            struct_flags: IS_APPENDABLE,
            members: &[("sensor_id", 0, TK_UINT32), ("celsius", 0, TK_FLOAT32)],
        };

        /// The same members as the derived type under a name no dialect
        /// knows anything about.
        const OTHER_NAME: Shape = Shape {
            name: "SensorReading",
            struct_flags: IS_APPENDABLE,
            members: &[("sensor_id", 0, TK_UINT32), ("celsius", 0, TK_FLOAT32)],
        };

        fn type_identifier(kind: u8) -> TypeIdentifier {
            match kind {
                TK_INT32 => TypeIdentifier::TK_INT32,
                TK_UINT32 => TypeIdentifier::TK_UINT32,
                TK_FLOAT32 => TypeIdentifier::TK_FLOAT32,
                _ => unreachable!("not used by these shapes"),
            }
        }

        /// The HDDS model of `shape`, as a type's `get_type_object` returns it.
        fn complete_type_object(shape: &Shape) -> CompleteTypeObject {
            CompleteTypeObject::Struct(CompleteStructType {
                struct_flags: StructTypeFlag(shape.struct_flags),
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new(shape.name),
                },
                member_seq: shape
                    .members
                    .iter()
                    .enumerate()
                    .map(|(id, (name, flags, kind))| CompleteStructMember {
                        common: CommonStructMember {
                            member_id: u32::try_from(id).expect("small"),
                            member_flags: MemberFlag(*flags),
                            member_type_id: type_identifier(*kind),
                        },
                        detail: CompleteMemberDetail::new(*name),
                    })
                    .collect(),
            })
        }

        /// HDDS' CDR2 encoding of the TypeObject, the bytes the dialect
        /// encoders receive in `SedpEndpointData::type_object`.
        fn hdds_encoding(obj: &CompleteTypeObject) -> Vec<u8> {
            let mut buf = vec![0u8; obj.max_cdr2_size()];
            let len = obj.encode_cdr2_le(&mut buf).expect("encode");
            buf.truncate(len);
            buf
        }

        /// Little-endian XCDR2 stream (DDS-XTypes 1.3 7.4.3), alignment
        /// relative to its start.
        #[derive(Default)]
        struct Xcdr2Le(Vec<u8>);

        impl Xcdr2Le {
            fn align(&mut self, n: usize) {
                while !self.0.len().is_multiple_of(n) {
                    self.0.push(0);
                }
            }
            fn u8(&mut self, v: u8) {
                self.0.push(v);
            }
            fn u16(&mut self, v: u16) {
                self.align(2);
                self.0.extend_from_slice(&v.to_le_bytes());
            }
            fn u32(&mut self, v: u32) {
                self.align(4);
                self.0.extend_from_slice(&v.to_le_bytes());
            }
            /// u32 length counting the NUL, the octets, the NUL.
            fn string(&mut self, s: &str) {
                self.u32(u32::try_from(s.len() + 1).expect("short"));
                self.0.extend_from_slice(s.as_bytes());
                self.u8(0);
            }
            /// A DHEADER (7.4.3.5.2) then the body it counts.
            fn delimited(&mut self, body: impl FnOnce(&mut Self)) {
                self.align(4);
                let at = self.0.len();
                self.u32(0);
                body(self);
                let len = u32::try_from(self.0.len() - at - 4).expect("short");
                self.0[at..at + 4].copy_from_slice(&len.to_le_bytes());
            }
        }

        fn md5(bytes: &[u8]) -> [u8; 16] {
            use md5::{Digest, Md5};
            Md5::digest(bytes).into()
        }

        /// The serialized minimal TypeObject of `shape` (Annex B): the
        /// @appendable `TypeObject` union, EK_MINIMAL, then the
        /// `MinimalStructType`.
        fn minimal_bytes(shape: &Shape) -> Vec<u8> {
            let mut w = Xcdr2Le::default();
            w.delimited(|w| {
                w.u8(EK_MINIMAL);
                w.u8(0x51); // TK_STRUCTURE
                w.u16(shape.struct_flags);
                // MinimalStructHeader (@appendable): base_type TK_NONE,
                // empty MinimalTypeDetail.
                w.delimited(|w| w.u8(0x00));
                w.delimited(|w| {
                    w.u32(u32::try_from(shape.members.len()).expect("small"));
                    for (id, (name, flags, kind)) in shape.members.iter().enumerate() {
                        // MinimalStructMember (@appendable): CommonStructMember,
                        // then NameHash = MD5(name)[0..4].
                        w.delimited(|w| {
                            w.u32(u32::try_from(id).expect("small"));
                            w.u16(*flags);
                            w.u8(*kind);
                            w.0.extend_from_slice(&md5(name.as_bytes())[..4]);
                        });
                    }
                });
            });
            w.0
        }

        /// The serialized complete TypeObject of `shape` (Annex B).
        fn complete_bytes(shape: &Shape) -> Vec<u8> {
            let mut w = Xcdr2Le::default();
            w.delimited(|w| {
                w.u8(EK_COMPLETE);
                w.u8(0x51); // TK_STRUCTURE
                w.u16(shape.struct_flags);
                // CompleteStructHeader (@appendable): base_type TK_NONE, then
                // CompleteTypeDetail (@final): ann_builtin and ann_custom
                // absent (presence flags), type_name.
                w.delimited(|w| {
                    w.u8(0x00);
                    w.u8(0);
                    w.u8(0);
                    w.string(shape.name);
                });
                w.delimited(|w| {
                    w.u32(u32::try_from(shape.members.len()).expect("small"));
                    for (id, (name, flags, kind)) in shape.members.iter().enumerate() {
                        // CompleteStructMember (@appendable): CommonStructMember,
                        // then CompleteMemberDetail { name, two absent optionals }.
                        w.delimited(|w| {
                            w.u32(u32::try_from(id).expect("small"));
                            w.u16(*flags);
                            w.u8(*kind);
                            w.string(name);
                            w.u8(0);
                            w.u8(0);
                        });
                    }
                });
            });
            w.0
        }

        /// One `TypeIdentifierWithDependencies` of a TypeInformation value.
        #[derive(Debug, PartialEq)]
        struct Identifier {
            member_id: u32,
            kind: u8,
            hash: [u8; 14],
            typeobject_serialized_size: u32,
            dependent_typeid_count: i32,
            dependent_typeids: u32,
        }

        fn rd_u32(b: &[u8], at: &mut usize) -> u32 {
            let v = u32::from_le_bytes([b[*at], b[*at + 1], b[*at + 2], b[*at + 3]]);
            *at += 4;
            v
        }

        /// Decode a `TypeInformation` value (DDS-XTypes 1.3 7.6.3.2.1, @mutable,
        /// XCDR2): every DHEADER and NEXTINT is checked against the bytes it
        /// delimits.
        fn decode(v: &[u8]) -> Vec<Identifier> {
            let mut at = 0;
            let total = rd_u32(v, &mut at) as usize;
            assert_eq!(total + 4, v.len(), "TypeInformation DHEADER");
            let mut out = Vec::new();
            while at < v.len() {
                let emheader = rd_u32(v, &mut at);
                assert_eq!(emheader >> 28, 4, "EMHEADER1 LC=4, M=0");
                let nextint = rd_u32(v, &mut at) as usize;
                let end = at + nextint;
                let tiwd = rd_u32(v, &mut at) as usize;
                assert_eq!(at + tiwd, end, "TypeIdentifierWithDependencies DHEADER");
                let tiws = rd_u32(v, &mut at) as usize;
                let tiws_end = at + tiws;
                let kind = v[at];
                let mut hash = [0u8; 14];
                hash.copy_from_slice(&v[at + 1..at + 15]);
                at += 16;
                let typeobject_serialized_size = rd_u32(v, &mut at);
                assert_eq!(at, tiws_end, "TypeIdentifierWithSize DHEADER");
                let dependent_typeid_count = i32::from_le_bytes(rd_u32(v, &mut at).to_le_bytes());
                let seq = rd_u32(v, &mut at) as usize;
                let seq_start = at;
                let dependent_typeids = rd_u32(v, &mut at);
                at = seq_start + seq;
                assert_eq!(at, end, "member NEXTINT");
                out.push(Identifier {
                    member_id: emheader & 0x0FFF_FFFF,
                    kind,
                    hash,
                    typeobject_serialized_size,
                    dependent_typeid_count,
                    dependent_typeids,
                });
            }
            out
        }

        fn announced(shape: &Shape, type_name: &str) -> Vec<Identifier> {
            let encoded = hdds_encoding(&complete_type_object(shape));
            let locators = [SocketAddr::from(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 1, 22),
                7411,
            ))];
            let buf =
                build_sedp(&endpoint(type_name, &locators, Some(&encoded))).expect("build_sedp");
            // XTypes group order: PID_DATA_REPRESENTATION, then
            // PID_TYPE_INFORMATION.
            let pids: Vec<u16> = parameters(&buf).iter().map(|(pid, _)| *pid).collect();
            let dr = pids
                .iter()
                .position(|p| *p == PID_DATA_REPRESENTATION)
                .expect("PID_DATA_REPRESENTATION");
            assert_eq!(pids.get(dr + 1), Some(&PID_TYPE_INFORMATION));
            decode(&type_information_of(&buf).expect("PID_TYPE_INFORMATION"))
        }

        /// What the endpoint must announce for `shape`, from the hand-built
        /// Annex B objects: the EquivalenceHash is the first 14 bytes of the
        /// MD5 of the serialized TypeObject (7.3.4.8), the size is that
        /// serialization's length, and no dependency (primitive members).
        fn expected(shape: &Shape) -> Vec<Identifier> {
            let id = |member_id, kind, bytes: Vec<u8>| {
                let mut hash = [0u8; 14];
                hash.copy_from_slice(&md5(&bytes)[..14]);
                Identifier {
                    member_id,
                    kind,
                    hash,
                    typeobject_serialized_size: u32::try_from(bytes.len()).expect("small"),
                    dependent_typeid_count: 0,
                    dependent_typeids: 0,
                }
            };
            vec![
                id(0x1001, EK_MINIMAL, minimal_bytes(shape)),
                id(0x1002, EK_COMPLETE, complete_bytes(shape)),
            ]
        }

        #[test]
        fn each_temperature_shape_announces_its_own_type() {
            for (shape, name) in [
                (&BUILD_RS, "Temperature"),
                (&EXAMPLES, "TemperatureData::Temperature"),
                (&DERIVED, "Temperature"),
                // A qualified name gated nothing either: same object, same
                // identifiers, whatever the announced type name.
                (&BUILD_RS, "TemperatureModule::Temperature"),
            ] {
                assert_eq!(announced(shape, name), expected(shape), "{name}");
            }
            // Three types. A minimal object carries no type name, so the two
            // @final { float; long } shapes share their minimal identifier
            // and differ by their complete one; the derived type shares
            // neither.
            let [b, e, d] = [&BUILD_RS, &EXAMPLES, &DERIVED].map(expected);
            assert_eq!(b[0].hash, e[0].hash);
            assert_ne!(b[1].hash, e[1].hash);
            for other in [&b, &e] {
                assert_ne!(d[0].hash, other[0].hash);
                assert_ne!(d[1].hash, other[1].hash);
            }
            // The build.rs type's minimal identifier, as the generic SEDP
            // path announces it.
            assert_eq!(hex(&b[0].hash), "e482712dbbaee044664e091fed0d");
        }

        /// The fixed type that must NOT be announced for every endpoint named
        /// Temperature, whatever its TypeObject:
        /// `@appendable @nested struct { float value; unsigned long timestamp; }`,
        /// members TRY_CONSTRUCT1 (DISCARD). None of HDDS' Temperature
        /// types is that type.
        const FORMERLY_ANNOUNCED: Shape = Shape {
            name: "TemperatureModule::Temperature",
            struct_flags: 0x000A, // IS_APPENDABLE | IS_NESTED
            members: &[
                ("value", 0x0001, TK_FLOAT32),
                ("timestamp", 0x0001, TK_UINT32),
            ],
        };

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        #[test]
        fn no_hdds_temperature_announces_the_formerly_fixed_identifier() {
            let former = expected(&FORMERLY_ANNOUNCED)[0].hash;
            assert_eq!(hex(&former), "62e837c4ddfe55e73a7bba1d6267");
            for (shape, name) in [
                (&BUILD_RS, "Temperature"),
                (&EXAMPLES, "TemperatureData::Temperature"),
                (&DERIVED, "Temperature"),
                (&BUILD_RS, "TemperatureModule::Temperature"),
            ] {
                assert_ne!(announced(shape, name)[0].hash, former, "{name}");
            }
        }

        #[test]
        fn a_type_with_any_other_name_announces_its_own_type() {
            assert_eq!(
                announced(&OTHER_NAME, "SensorReading"),
                expected(&OTHER_NAME)
            );
        }

        /// The OpenDDS dialect announces, byte for byte, the
        /// PID_TYPE_INFORMATION the generic SEDP path (the HDDS dialect)
        /// announces for the same endpoint.
        #[test]
        fn the_parameter_is_the_generic_paths_parameter() {
            let encoded = hdds_encoding(&complete_type_object(&DERIVED));
            let locators: [SocketAddr; 0] = [];
            let data = endpoint("Temperature", &locators, Some(&encoded));
            let ours = build_sedp(&data).expect("opendds");
            let generic = crate::protocol::dialect::build_sedp_for_dialect(
                crate::protocol::dialect::Dialect::Hdds,
                &data,
            )
            .expect("hdds");
            let generic_ti = type_information_of(&generic).expect("generic announces it");
            assert_eq!(type_information_of(&ours), Some(generic_ti));
        }

        /// With the announce-time TypeInformation (dependencies resolved
        /// from the type store), the dialect announces that value, as the
        /// generic path does.
        #[cfg(feature = "xtypes-structural-assignability")]
        #[test]
        fn the_announce_time_value_is_announced_when_present() {
            use crate::protocol::discovery::types::{
                TypeIdentifierWithDependencies, TypeIdentifierWithSize, TypeInformation,
            };
            use crate::xtypes::EquivalenceHash;
            let dep = |kind, byte| TypeIdentifierWithSize {
                kind,
                hash: EquivalenceHash::from_bytes([byte; 14]),
                typeobject_serialized_size: 40,
            };
            let info = TypeInformation {
                minimal: Some(TypeIdentifierWithDependencies {
                    hash: EquivalenceHash::from_bytes([0x11; 14]),
                    typeobject_serialized_size: 60,
                    dependent_typeids: vec![dep(EK_MINIMAL, 0x33)],
                }),
                complete: Some(TypeIdentifierWithDependencies {
                    hash: EquivalenceHash::from_bytes([0x22; 14]),
                    typeobject_serialized_size: 90,
                    dependent_typeids: vec![dep(EK_COMPLETE, 0x44)],
                }),
            };
            let encoded = hdds_encoding(&complete_type_object(&DERIVED));
            let locators: [SocketAddr; 0] = [];
            let mut data = endpoint("Temperature", &locators, Some(&encoded));
            data.type_information = Some(info);
            let ours = build_sedp(&data).expect("opendds");
            let got = decode(&type_information_of(&ours).expect("announced"));
            assert_eq!(got.len(), 2);
            assert_eq!((got[0].kind, got[0].hash), (EK_MINIMAL, [0x11; 14]));
            assert_eq!((got[1].kind, got[1].hash), (EK_COMPLETE, [0x22; 14]));
            assert_eq!(got[0].dependent_typeid_count, 1);
            assert_eq!(got[1].dependent_typeids, 1);
            let generic = crate::protocol::dialect::build_sedp_for_dialect(
                crate::protocol::dialect::Dialect::Hdds,
                &data,
            )
            .expect("hdds");
            assert_eq!(
                type_information_of(&ours),
                type_information_of(&generic),
                "same value as the generic path"
            );
        }
    }
}
