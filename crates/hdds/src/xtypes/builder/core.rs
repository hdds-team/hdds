// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Core `TypeObjectBuilder` implementation using safe message descriptors.
//!

use super::errors::BuilderError;
use super::model::{FieldType, MessageDescriptor};
use crate::core::types::{Distro, TypeObjectHandle, ROS_HASH_SIZE};
use crate::xtypes::{
    CollectionElementFlag, CompleteStructHeader, CompleteStructMember, CompleteStructType,
    CompleteTypeDetail, CompleteTypeObject, EquivalenceKind, MemberFlag, MinimalStructHeader,
    MinimalStructMember, MinimalStructType, MinimalTypeDetail, MinimalTypeObject,
    PlainArrayLElemDefn, PlainArraySElemDefn, PlainCollectionHeader, PlainSequenceLElemDefn,
    PlainSequenceSElemDefn, StructTypeFlag, TypeIdentifier,
};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;

pub(super) struct StructArtifacts {
    pub(super) complete: CompleteStructType,
    pub(super) minimal: MinimalStructType,
    pub(super) type_id_complete: TypeIdentifier,
    pub(super) type_id_minimal: TypeIdentifier,
}

/// Stateful builder capable of producing `TypeObjectHandle`s from safe descriptors.
pub struct TypeObjectBuilder<'a> {
    pub(super) distro: Distro,
    pub(super) interned: HashMap<String, (TypeIdentifier, TypeIdentifier)>,
    pub(super) stack: Vec<String>,
    pub(super) ros_dependencies: Vec<Arc<TypeObjectHandle>>,
    pub(super) _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> TypeObjectBuilder<'a> {
    /// Build a [`TypeObjectHandle`] from a safe [`MessageDescriptor`].
    pub fn from_descriptor(
        distro: Distro,
        descriptor: &MessageDescriptor<'a>,
    ) -> Result<TypeObjectHandle, BuilderError> {
        let mut builder = Self::new(distro);
        let mut handle = builder.build_handle(descriptor)?;
        handle.dependencies = builder.ros_dependencies;
        Ok(handle)
    }

    // XTypes 1.3 7.2.2.7: absent @try_construct means DISCARD.
    // 7.2.2.4.4.4.8: every key member is also must-understand.
    pub(super) fn default_member_flags(is_key: bool) -> MemberFlag {
        MemberFlag(
            MemberFlag::TRY_CONSTRUCT1.0
                | if is_key {
                    MemberFlag::IS_KEY.0 | MemberFlag::IS_MUST_UNDERSTAND.0
                } else {
                    0
                },
        )
    }

    pub(super) fn new(distro: Distro) -> Self {
        Self {
            distro,
            interned: HashMap::new(),
            stack: Vec::new(),
            ros_dependencies: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub(super) fn build_handle(
        &mut self,
        descriptor: &MessageDescriptor<'a>,
    ) -> Result<TypeObjectHandle, BuilderError> {
        let artifacts = self.build_struct_artifacts(descriptor)?;
        let fqn = descriptor.fqn();
        let fqn_arc: Arc<str> = Arc::<str>::from(fqn.as_str());
        let hash_arc: Arc<[u8; ROS_HASH_SIZE]> = Arc::new(*descriptor.ros_hash);

        Ok(TypeObjectHandle::new(
            self.distro,
            fqn_arc,
            descriptor.ros_hash_version,
            hash_arc,
            CompleteTypeObject::Struct(artifacts.complete),
            MinimalTypeObject::Struct(artifacts.minimal),
            artifacts.type_id_complete,
            artifacts.type_id_minimal,
        ))
    }

    pub(super) fn build_struct_artifacts(
        &mut self,
        descriptor: &MessageDescriptor<'a>,
    ) -> Result<StructArtifacts, BuilderError> {
        let fqn = descriptor.fqn();
        if self.stack.iter().any(|entry| entry == &fqn) {
            return Err(BuilderError::RecursiveType { fqn });
        }

        if let Some(ids) = self.interned.get(&fqn) {
            let artifacts = self.rebuild_struct(descriptor, ids.clone())?;
            return Ok(artifacts);
        }

        self.stack.push(fqn.clone());

        let mut complete_members = Vec::with_capacity(descriptor.members.len());
        let mut minimal_members = Vec::with_capacity(descriptor.members.len());

        for (index, member) in descriptor.members.iter().enumerate() {
            let (complete_id, minimal_id) =
                self.build_member_type_identifiers(&member.field_type)?;

            let member_flags = Self::default_member_flags(member.is_key);

            #[allow(clippy::expect_used)] // index is a struct member count, always fits in u32
            let member_id = u32::try_from(index).expect("struct member index fits within u32");
            let common = crate::xtypes::CommonStructMember {
                member_id,
                member_flags,
                member_type_id: complete_id,
            };

            complete_members.push(CompleteStructMember {
                common: common.clone(),
                detail: crate::xtypes::CompleteMemberDetail::new(member.name),
            });
            minimal_members.push(MinimalStructMember {
                common: crate::xtypes::CommonStructMember {
                    member_type_id: minimal_id,
                    ..common
                },
                detail: crate::xtypes::MinimalMemberDetail::from_name(member.name),
            });
        }

        let complete_struct = CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(fqn.clone()),
            },
            member_seq: complete_members,
        };

        let minimal_struct = MinimalStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: MinimalStructHeader {
                base_type: None,
                detail: MinimalTypeDetail::new(),
            },
            member_seq: minimal_members,
        };

        let complete_hash =
            CompleteTypeObject::Struct(complete_struct.clone()).compute_equivalence_hash()?;
        let minimal_hash =
            MinimalTypeObject::Struct(minimal_struct.clone()).compute_equivalence_hash()?;

        let type_id_complete = TypeIdentifier::complete(complete_hash);
        let type_id_minimal = TypeIdentifier::minimal(minimal_hash);

        self.stack.pop();
        self.interned
            .insert(fqn, (type_id_complete.clone(), type_id_minimal.clone()));

        Ok(StructArtifacts {
            complete: complete_struct,
            minimal: minimal_struct,
            type_id_complete,
            type_id_minimal,
        })
    }

    pub(super) fn rebuild_struct(
        &mut self,
        descriptor: &MessageDescriptor<'a>,
        ids: (TypeIdentifier, TypeIdentifier),
    ) -> Result<StructArtifacts, BuilderError> {
        let mut complete_members = Vec::with_capacity(descriptor.members.len());
        let mut minimal_members = Vec::with_capacity(descriptor.members.len());

        for (index, member) in descriptor.members.iter().enumerate() {
            let (complete_id, minimal_id) =
                self.build_member_type_identifiers(&member.field_type)?;
            let member_flags = Self::default_member_flags(member.is_key);
            #[allow(clippy::expect_used)] // index is a struct member count, always fits in u32
            let member_id = u32::try_from(index).expect("struct member index fits within u32");
            let common = crate::xtypes::CommonStructMember {
                member_id,
                member_flags,
                member_type_id: complete_id,
            };
            complete_members.push(CompleteStructMember {
                common: common.clone(),
                detail: crate::xtypes::CompleteMemberDetail::new(member.name),
            });
            minimal_members.push(MinimalStructMember {
                common: crate::xtypes::CommonStructMember {
                    member_type_id: minimal_id,
                    ..common
                },
                detail: crate::xtypes::MinimalMemberDetail::from_name(member.name),
            });
        }

        let fqn = descriptor.fqn();

        Ok(StructArtifacts {
            complete: CompleteStructType {
                struct_flags: StructTypeFlag::IS_FINAL,
                header: CompleteStructHeader {
                    base_type: None,
                    detail: CompleteTypeDetail::new(fqn.clone()),
                },
                member_seq: complete_members,
            },
            minimal: MinimalStructType {
                struct_flags: StructTypeFlag::IS_FINAL,
                header: MinimalStructHeader {
                    base_type: None,
                    detail: MinimalTypeDetail::new(),
                },
                member_seq: minimal_members,
            },
            type_id_complete: ids.0,
            type_id_minimal: ids.1,
        })
    }

    pub(super) fn ensure_struct_ids(
        &mut self,
        descriptor: &MessageDescriptor<'a>,
    ) -> Result<(TypeIdentifier, TypeIdentifier), BuilderError> {
        let fqn = descriptor.fqn();
        if let Some(ids) = self.interned.get(&fqn) {
            return Ok(ids.clone());
        }

        let artifacts = self.build_struct_artifacts(descriptor)?;
        let ids = (
            artifacts.type_id_complete.clone(),
            artifacts.type_id_minimal.clone(),
        );
        self.ros_dependencies.push(Arc::new(TypeObjectHandle::new(
            self.distro,
            Arc::from(fqn),
            descriptor.ros_hash_version,
            Arc::new(*descriptor.ros_hash),
            CompleteTypeObject::Struct(artifacts.complete),
            MinimalTypeObject::Struct(artifacts.minimal),
            artifacts.type_id_complete,
            artifacts.type_id_minimal,
        )));
        Ok(ids)
    }

    fn build_member_type_identifiers(
        &mut self,
        field_type: &FieldType<'a>,
    ) -> Result<(TypeIdentifier, TypeIdentifier), BuilderError> {
        let id = match field_type {
            FieldType::Primitive(prim) => TypeIdentifier::primitive(prim.to_type_kind()),
            FieldType::String { bound } => TypeIdentifier::string(bound.unwrap_or(0)),
            FieldType::WString { bound } => TypeIdentifier::wstring(bound.unwrap_or(0)),
            FieldType::Nested(descriptor) => return self.ensure_struct_ids(descriptor),
            FieldType::Array {
                element,
                dimensions,
            } => {
                let (complete, minimal) = self.build_member_type_identifiers(element)?;
                return Ok((
                    Self::array_type_identifier_from_element(complete, dimensions)?,
                    Self::array_type_identifier_from_element(minimal, dimensions)?,
                ));
            }
            FieldType::Sequence { element, bound } => {
                let (complete, minimal) = self.build_member_type_identifiers(element)?;
                return Ok((
                    Self::sequence_type_identifier_from_element(complete, *bound)?,
                    Self::sequence_type_identifier_from_element(minimal, *bound)?,
                ));
            }
        };
        Ok((id.clone(), id))
    }

    pub(super) fn sequence_type_identifier_from_element(
        element_id: TypeIdentifier,
        bound: Option<u32>,
    ) -> Result<TypeIdentifier, BuilderError> {
        let header = Self::plain_collection_header(&element_id);
        let bound = bound.unwrap_or(0);
        Ok(match u8::try_from(bound) {
            Ok(bound) => TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
                header,
                bound,
                element_identifier: Box::new(element_id),
            }),
            Err(_) => TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
                header,
                bound,
                element_identifier: Box::new(element_id),
            }),
        })
    }

    // XTypes 1.3 7.3.4.6: indirect hash identifiers retain the
    // equivalence kind of their dependency, including nested collections.
    fn plain_collection_header(element: &TypeIdentifier) -> PlainCollectionHeader {
        use TypeIdentifier::*;
        let equiv_kind = match element {
            Complete(_) => EquivalenceKind::Complete,
            Minimal(_) => EquivalenceKind::Minimal,
            StronglyConnected(scc) => scc.kind,
            PlainSequenceSmall(s) => s.header.equiv_kind,
            PlainSequenceLarge(s) => s.header.equiv_kind,
            PlainArraySmall(a) => a.header.equiv_kind,
            PlainArrayLarge(a) => a.header.equiv_kind,
            PlainMapSmall(m) => m.header.equiv_kind,
            PlainMapLarge(m) => m.header.equiv_kind,
            _ => EquivalenceKind::Both,
        };
        PlainCollectionHeader {
            equiv_kind,
            element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
        }
    }

    pub(super) fn array_type_identifier_from_element(
        element_id: TypeIdentifier,
        dimensions: &[u32],
    ) -> Result<TypeIdentifier, BuilderError> {
        if dimensions.is_empty() || dimensions.contains(&0) {
            return Err(BuilderError::InvalidBound {
                context: "array dimensions",
            });
        }

        let header = Self::plain_collection_header(&element_id);
        let small_dimensions: Result<Vec<u8>, _> =
            dimensions.iter().copied().map(u8::try_from).collect();
        Ok(match small_dimensions {
            Ok(array_bound_seq) => TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
                header,
                array_bound_seq,
                element_identifier: Box::new(element_id),
            }),
            Err(_) => TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
                header,
                array_bound_seq: dimensions.to_vec(),
                element_identifier: Box::new(element_id),
            }),
        })
    }
}
