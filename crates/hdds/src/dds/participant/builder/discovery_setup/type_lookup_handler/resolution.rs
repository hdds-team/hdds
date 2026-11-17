// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Poll-driven dynamic decoding with bounded, content-addressed dependencies.

use super::*;
use crate::core::discovery::GUID;
use crate::dds::{Error, Result};
use crate::dynamic::{type_descriptor_from_xtypes_with_registry, TypeDescriptor, TypeRegistry};
#[cfg(test)]
use crate::xtypes::StructTypeFlag;
use crate::xtypes::{MemberFlag, TypeIdentifier};
use std::collections::HashSet;

struct RegistryView<'a>(&'a HashMap<EquivalenceHash, CompleteTypeObject>);
impl TypeRegistry for RegistryView<'_> {
    fn lookup(&self, hash: &EquivalenceHash) -> Option<&CompleteTypeObject> {
        self.0.get(hash)
    }
}

impl TypeLookupService {
    pub(in crate::dds::participant) fn resolve_type_descriptor(
        &self,
        endpoint_guid: &GUID,
    ) -> Result<Option<Arc<TypeDescriptor>>> {
        let endpoint = self
            .fsm
            .get_all_topics()
            .into_values()
            .flat_map(|(writers, readers)| writers.into_iter().chain(readers))
            .find(|e| e.endpoint_guid == *endpoint_guid);
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };
        // `GUID` stores the prefix as its own field, so there is nothing to
        // reslice and nothing that can fail. The previous form went through
        // `as_bytes()[..12].try_into().expect(..)`, which reconstructed a
        // 16-byte array for every database entry it compared against.
        let peer = endpoint.participant_guid.prefix;
        let address = self.fsm.db().read().ok().and_then(|db| {
            db.iter()
                .find(|(guid, _)| guid.prefix == peer)
                .and_then(|(_, info)| info.endpoints.first().copied())
        });
        let cache = self.resolved_types.read().objects().clone();
        let announced_hash = endpoint
            .type_information
            .as_ref()
            .and_then(|info| info.complete.as_ref())
            .map(|id| id.hash);
        // Prefer the advertised COMPLETE identity over an older inline hybrid
        // whose member references may still use minimal hashes.
        let root = if let Some(hash) = announced_hash {
            cache.get(&hash).cloned().or_else(|| {
                endpoint
                    .type_object
                    .filter(|obj| obj.compute_equivalence_hash().ok() == Some(hash))
            })
        } else {
            endpoint.type_object
        };
        let Some(root) = root else {
            if let (Some(hash), Some(address)) = (announced_hash, address) {
                self.request_complete_type(None, hash, Origin::direct(address), peer);
            }
            return Ok(None);
        };
        let missing = missing_dependencies(&root, &cache)?;
        if !missing.is_empty() {
            if let Some(address) = address {
                for hash in missing {
                    self.request_complete_type(None, hash, Origin::direct(address), peer);
                }
            }
            return Ok(None);
        }
        Ok(Some(type_descriptor_from_xtypes_with_registry(
            &root,
            Some(&RegistryView(&cache)),
        )))
    }
}

/// Check the entire supported layout before the permissive converter sees it.
/// Repeated branches count toward the budget because conversion expands them.
fn missing_dependencies(
    root: &CompleteTypeObject,
    cache: &HashMap<EquivalenceHash, CompleteTypeObject>,
) -> Result<HashSet<EquivalenceHash>> {
    let mut walk = LayoutWalk {
        cache,
        missing: HashSet::new(),
        path: HashSet::new(),
        budget: 4096,
    };
    walk.object(root, 0)?;
    Ok(walk.missing)
}

struct LayoutWalk<'a> {
    cache: &'a HashMap<EquivalenceHash, CompleteTypeObject>,
    missing: HashSet<EquivalenceHash>,
    path: HashSet<EquivalenceHash>,
    budget: usize,
}

fn unsupported(reason: &str) -> Error {
    Error::InvalidState(format!("Dynamic type resolution: {reason}"))
}

impl LayoutWalk<'_> {
    fn object(&mut self, obj: &CompleteTypeObject, depth: usize) -> Result<()> {
        if depth >= 32 || self.budget == 0 {
            return Err(unsupported("layout exceeds the depth or expansion limit"));
        }
        self.budget -= 1;
        match obj {
            CompleteTypeObject::Struct(s) => {
                if s.header.base_type.is_some() {
                    return Err(unsupported("inherited structs are not supported"));
                }
                for member in &s.member_seq {
                    if member.common.member_flags.contains(MemberFlag::IS_OPTIONAL) {
                        return Err(unsupported(
                            "optional members have no exact dynamic decoder",
                        ));
                    }
                    self.identifier(&member.common.member_type_id, depth + 1)?;
                }
            }
            CompleteTypeObject::Alias(a) => {
                self.identifier(&a.body.common.related_type, depth + 1)?
            }
            CompleteTypeObject::Enumerated(e) => {
                if e.header.bit_bound != 32
                    || e.literal_seq.iter().any(|literal| literal.common.value < 0)
                {
                    return Err(unsupported(
                        "only nonnegative 32-bit enums have an exact decoder",
                    ));
                }
            }
            _ => return Err(unsupported("layout has no complete dynamic decoder")),
        }
        Ok(())
    }

    fn identifier(&mut self, id: &TypeIdentifier, depth: usize) -> Result<()> {
        if self.budget == 0 {
            return Err(unsupported("layout exceeds the expansion limit"));
        }
        self.budget -= 1;
        match id {
            TypeIdentifier::Complete(hash) => {
                if !self.path.insert(*hash) {
                    return Err(unsupported("cyclic type dependency"));
                }
                if let Some(obj) = self.cache.get(hash) {
                    self.object(obj, depth)?;
                } else {
                    self.missing.insert(*hash);
                    if self.missing.len() > 128 {
                        return Err(unsupported("too many missing dependencies"));
                    }
                }
                self.path.remove(hash);
            }
            TypeIdentifier::Primitive(kind) => {
                use crate::xtypes::TypeKind as K;
                if !matches!(
                    kind,
                    K::TK_BOOLEAN
                        | K::TK_BYTE
                        | K::TK_INT8
                        | K::TK_UINT8
                        | K::TK_INT16
                        | K::TK_UINT16
                        | K::TK_INT32
                        | K::TK_UINT32
                        | K::TK_INT64
                        | K::TK_UINT64
                        | K::TK_FLOAT32
                        | K::TK_FLOAT64
                        | K::TK_CHAR8
                ) {
                    return Err(unsupported("primitive has no exact dynamic decoder"));
                }
            }
            TypeIdentifier::StringSmall { .. }
            | TypeIdentifier::StringLarge { .. }
            | TypeIdentifier::WStringSmall { .. }
            | TypeIdentifier::WStringLarge { .. } => {}
            _ => {
                return Err(unsupported(
                    "requires COMPLETE references and supported collection layouts",
                ))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, MemberFlag,
    };

    fn structure(name: &str, fields: Vec<(&str, TypeIdentifier)>) -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: fields
                .into_iter()
                .enumerate()
                .map(|(i, (name, id))| CompleteStructMember {
                    common: CommonStructMember {
                        member_id: i as u32,
                        member_flags: MemberFlag::empty(),
                        member_type_id: id,
                    },
                    detail: CompleteMemberDetail::new(name),
                })
                .collect(),
        })
    }

    #[test]
    fn transitive_dependencies_are_required_before_decoding() {
        let inner = structure(
            "Vector3",
            vec![
                ("x", TypeIdentifier::TK_FLOAT32),
                ("y", TypeIdentifier::TK_FLOAT32),
                ("z", TypeIdentifier::TK_FLOAT32),
            ],
        );
        let inner_hash = inner.compute_equivalence_hash().unwrap();
        let pose = structure(
            "Pose",
            vec![("position", TypeIdentifier::Complete(inner_hash))],
        );
        let pose_hash = pose.compute_equivalence_hash().unwrap();
        let root = structure(
            "State",
            vec![
                ("pose", TypeIdentifier::Complete(pose_hash)),
                ("tail", TypeIdentifier::TK_UINT32),
            ],
        );
        let mut cache = HashMap::new();
        assert_eq!(
            missing_dependencies(&root, &cache).unwrap(),
            HashSet::from([pose_hash])
        );
        cache.insert(pose_hash, pose);
        assert_eq!(
            missing_dependencies(&root, &cache).unwrap(),
            HashSet::from([inner_hash])
        );
        cache.insert(inner_hash, inner);
        assert!(missing_dependencies(&root, &cache).unwrap().is_empty());
        #[cfg(feature = "json")]
        {
            let desc =
                type_descriptor_from_xtypes_with_registry(&root, Some(&RegistryView(&cache)));
            let mut bytes = Vec::new(); // RawDataReader supplies the CDR body without encapsulation.
            for value in [1.25f32, -2.5, 3.75] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&123456u32.to_le_bytes());
            let value = crate::dynamic::json::cdr_to_json_dynamic(&bytes, &desc);
            assert_eq!(value["pose"]["position"]["x"], 1.25);
            assert_eq!(value["pose"]["position"]["y"], -2.5);
            assert_eq!(value["pose"]["position"]["z"], 3.75);
            assert_eq!(value["tail"], 123456);
        }
    }

    #[test]
    fn incomplete_and_unsupported_layouts_never_become_ready() {
        let hash = EquivalenceHash::from_bytes([9; 14]);
        let root = structure("Cycle", vec![("child", TypeIdentifier::Complete(hash))]);
        let cache = HashMap::from([(hash, root.clone())]);
        assert!(missing_dependencies(&root, &cache).is_err());
        let minimal = structure("Minimal", vec![("child", TypeIdentifier::Minimal(hash))]);
        assert!(missing_dependencies(&minimal, &HashMap::new()).is_err());
        let mut inherited = structure("Inherited", vec![]);
        if let CompleteTypeObject::Struct(s) = &mut inherited {
            s.header.base_type = Some(TypeIdentifier::Complete(hash));
        }
        assert!(missing_dependencies(&inherited, &HashMap::new()).is_err());
        let mut optional = structure("Optional", vec![("x", TypeIdentifier::TK_FLOAT32)]);
        if let CompleteTypeObject::Struct(s) = &mut optional {
            s.member_seq[0].common.member_flags = MemberFlag::IS_OPTIONAL;
        }
        assert!(missing_dependencies(&optional, &HashMap::new()).is_err());
        let negative = crate::dynamic::TypeDescriptor::new(
            "Negative",
            crate::dynamic::TypeKind::Enum(crate::dynamic::EnumDescriptor::new(vec![
                crate::dynamic::EnumVariant::new("negative", -1),
            ])),
        );
        let negative = crate::dynamic::type_descriptor_to_xtypes(&negative).unwrap();
        assert!(missing_dependencies(&negative, &HashMap::new()).is_err());
        let mut appendable = structure("Appendable", vec![]);
        if let CompleteTypeObject::Struct(s) = &mut appendable {
            s.struct_flags = StructTypeFlag::IS_APPENDABLE;
        }
        assert!(missing_dependencies(&appendable, &HashMap::new())
            .unwrap()
            .is_empty());
        let desc = type_descriptor_from_xtypes_with_registry(
            &appendable,
            Some(&RegistryView(&HashMap::new())),
        );
        assert_eq!(
            desc.extensibility,
            crate::dynamic::Extensibility::Appendable
        );
    }

    fn reply(
        service: &TypeLookupService,
        obj: CompleteTypeObject,
        claimed_hash: EquivalenceHash,
        seq: u64,
    ) -> Vec<u8> {
        use crate::core::types::{Distro, ROS_HASH_SIZE};
        let minimal = crate::dynamic::complete_to_minimal_type_object(&obj).unwrap();
        let min_hash = minimal.compute_equivalence_hash().unwrap();
        let handle = Arc::new(TypeObjectHandle::new(
            Distro::Humble,
            Arc::from("Fixture"),
            0,
            Arc::new([0; ROS_HASH_SIZE]),
            obj,
            minimal,
            TypeIdentifier::Complete(claimed_hash),
            TypeIdentifier::Minimal(min_hash),
        ));
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&service.our_guid_prefix);
        writer[12..].copy_from_slice(&RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER);
        encode_omg_get_types_reply(
            &writer,
            (seq >> 32) as i32,
            seq as u32,
            &[(EK_COMPLETE, *claimed_hash.as_bytes(), handle)],
        )
        .unwrap()
    }

    #[test]
    fn replies_require_peer_sequence_hash_and_live_request() {
        let domain = crate::test_support::domains::unique_domain();
        let participant = crate::Participant::builder("lookup-correlation-test")
            .domain_id(domain.id())
            .with_transport(crate::TransportMode::UdpMulticast)
            .build()
            .unwrap();
        let service = participant.type_lookup.as_ref().unwrap();
        let peer = [6u8; 12];
        let address = Origin::direct("127.0.0.1:9".parse().unwrap());
        let obj = structure("Fixture", vec![("value", TypeIdentifier::TK_FLOAT32)]);
        let hash = obj.compute_equivalence_hash().unwrap();
        let key = (peer, *hash.as_bytes());
        service.request_complete_type(None, hash, address, peer);
        let first_seq = service.pending_requests.lock()[&key].sequence;
        service.request_complete_type(Some("Fixture"), hash, address, peer);
        assert_eq!(service.pending_requests.lock()[&key].sequence, first_seq);
        assert_eq!(
            service.pending_requests.lock()[&key].type_name.as_deref(),
            Some("Fixture")
        );
        let valid_reply = reply(service, obj.clone(), hash, first_seq);
        service.handle_omg_get_types_reply(&valid_reply, Some([7; 12]));
        service.handle_omg_get_types_reply(
            &reply(service, obj.clone(), hash, first_seq + 100),
            Some(peer),
        );
        service.handle_omg_get_types_reply(
            &reply(service, structure("Different", vec![]), hash, first_seq),
            Some(peer),
        );
        assert!(!service.resolved_types.read().contains_key(&hash));
        assert!(service.pending_requests.lock().contains_key(&key));
        service
            .pending_requests
            .lock()
            .get_mut(&key)
            .unwrap()
            .sent_at = Instant::now() - Duration::from_secs(6);
        service.handle_omg_get_types_reply(&valid_reply, Some(peer));
        assert!(!service.resolved_types.read().contains_key(&hash));
        service.request_complete_type(None, hash, address, peer);
        let retry_seq = service.pending_requests.lock()[&key].sequence;
        assert_ne!(retry_seq, first_seq);
        service.handle_omg_get_types_reply(&valid_reply, Some(peer));
        assert_eq!(service.pending_requests.lock()[&key].sequence, retry_seq);
        service
            .handle_omg_get_types_reply(&reply(service, obj.clone(), hash, retry_seq), Some(peer));
        assert_eq!(service.resolved_types.read().get(&hash), Some(&obj));
        assert!(!service.pending_requests.lock().contains_key(&key));
        for end in 0..valid_reply.len() {
            let _ = parse_omg_get_types_reply(&valid_reply[..end]);
        }
    }

    #[test]
    fn zero_length_type_object_is_rejected_without_panicking() {
        // A single identifier followed by an empty TypeObject delimiter.
        let mut data = vec![0; 24];
        data[..4].copy_from_slice(&1u32.to_le_bytes());
        data[4] = EK_COMPLETE;
        let mut pairs = Vec::new();
        parse_type_object_pairs(&data, 0, data.len(), &mut pairs);
        assert!(pairs.is_empty());
    }
}
