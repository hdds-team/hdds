// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Core `TypeObjectBuilder` implementation using safe message descriptors.
//!

use super::errors::BuilderError;
use super::model::{FieldType, MessageDescriptor};
use crate::core::types::{Distro, TypeObjectHandle, ROS_HASH_SIZE};
use crate::xtypes::{
    CollectionElementFlag, CompleteStructHeader, CompleteStructMember, CompleteStructType,
    CompleteTypeDetail, CompleteTypeObject, MemberFlag, MinimalArrayType, MinimalCollectionElement,
    MinimalCollectionHeader, MinimalSequenceType, MinimalStructHeader, MinimalStructMember,
    MinimalStructType, MinimalTypeDetail, MinimalTypeObject, StructTypeFlag, TypeIdentifier,
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
    pub(super) _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> TypeObjectBuilder<'a> {
    /// Build a [`TypeObjectHandle`] from a safe [`MessageDescriptor`].
    pub fn from_descriptor(
        distro: Distro,
        descriptor: &MessageDescriptor<'a>,
    ) -> Result<TypeObjectHandle, BuilderError> {
        let mut builder = Self::new(distro);
        builder.build_handle(descriptor)
    }

    pub(super) fn new(distro: Distro) -> Self {
        Self {
            distro,
            interned: HashMap::new(),
            stack: Vec::new(),
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
            let type_id = self.build_member_type_identifier(&member.field_type)?;

            let member_flags = if member.is_key {
                MemberFlag::IS_KEY
            } else {
                MemberFlag::empty()
            };

            #[allow(clippy::expect_used)] // index is a struct member count, always fits in u32
            let member_id = u32::try_from(index).expect("struct member index fits within u32");
            let common = crate::xtypes::CommonStructMember {
                member_id,
                member_flags,
                member_type_id: type_id,
            };

            complete_members.push(CompleteStructMember {
                common: common.clone(),
                detail: crate::xtypes::CompleteMemberDetail::new(member.name),
            });
            minimal_members.push(MinimalStructMember {
                common,
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
            let type_id = self.build_member_type_identifier(&member.field_type)?;
            let member_flags = if member.is_key {
                MemberFlag::IS_KEY
            } else {
                MemberFlag::empty()
            };
            #[allow(clippy::expect_used)] // index is a struct member count, always fits in u32
            let member_id = u32::try_from(index).expect("struct member index fits within u32");
            let common = crate::xtypes::CommonStructMember {
                member_id,
                member_flags,
                member_type_id: type_id,
            };
            complete_members.push(CompleteStructMember {
                common: common.clone(),
                detail: crate::xtypes::CompleteMemberDetail::new(member.name),
            });
            minimal_members.push(MinimalStructMember {
                common,
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
        Ok((artifacts.type_id_complete, artifacts.type_id_minimal))
    }

    pub(super) fn build_member_type_identifier(
        &mut self,
        field_type: &FieldType<'a>,
    ) -> Result<TypeIdentifier, BuilderError> {
        match field_type {
            FieldType::Primitive(prim) => Ok(TypeIdentifier::primitive(prim.to_type_kind())),
            FieldType::String { bound } => Ok(TypeIdentifier::string(bound.unwrap_or(0))),
            FieldType::WString { bound } => Ok(TypeIdentifier::wstring(bound.unwrap_or(0))),
            FieldType::Nested(descriptor) => {
                let (_, minimal) = self.ensure_struct_ids(descriptor)?;
                Ok(minimal)
            }
            FieldType::Array {
                element,
                dimensions,
            } => self.array_type_identifier(element, dimensions),
            FieldType::Sequence { element, bound } => {
                self.sequence_type_identifier(element, *bound)
            }
        }
    }

    fn sequence_type_identifier(
        &mut self,
        element: &FieldType<'a>,
        bound: Option<u32>,
    ) -> Result<TypeIdentifier, BuilderError> {
        let element_id = self.build_member_type_identifier(element)?;
        Self::sequence_type_identifier_from_element(element_id, bound)
    }

    fn array_type_identifier(
        &mut self,
        element: &FieldType<'a>,
        dimensions: &[u32],
    ) -> Result<TypeIdentifier, BuilderError> {
        let element_id = self.build_member_type_identifier(element)?;
        Self::array_type_identifier_from_element(element_id, dimensions)
    }

    pub(super) fn sequence_type_identifier_from_element(
        element_id: TypeIdentifier,
        bound: Option<u32>,
    ) -> Result<TypeIdentifier, BuilderError> {
        let minimal_sequence = MinimalSequenceType {
            header: MinimalCollectionHeader {
                bound: bound.unwrap_or(0),
            },
            element: MinimalCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: element_id,
            },
        };

        let minimal_hash =
            MinimalTypeObject::Sequence(minimal_sequence).compute_equivalence_hash()?;
        Ok(TypeIdentifier::minimal(minimal_hash))
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

        let minimal_array = MinimalArrayType {
            header: MinimalCollectionHeader {
                bound: dimensions[0],
            },
            element: MinimalCollectionElement {
                flags: CollectionElementFlag::empty(),
                type_id: element_id,
            },
            bound_seq: dimensions.to_vec(),
        };

        let minimal_hash = MinimalTypeObject::Array(minimal_array).compute_equivalence_hash()?;
        Ok(TypeIdentifier::minimal(minimal_hash))
    }
}
