// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// ROS2 type to HDDS Dynamic TypeDescriptor mapping for generic subscriptions.

use hdds::dynamic::{
    ArrayDescriptor, FieldDescriptor, PrimitiveKind, SequenceDescriptor, TypeDescriptor,
    TypeDescriptorBuilder, TypeKind,
};
#[cfg(feature = "xtypes")]
use hdds::xtypes::builder::{
    rosidl_message_type_support_t, rosidl_typesupport_introspection_c__MessageMember, BuilderError,
    RosMessageMetadata, RosidlError,
};
use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::{Arc, Mutex, OnceLock};

/// Get a TypeDescriptor for a ROS2 type name.
/// Returns None if the type is not in the built-in mapping.
pub fn ros2_type_to_descriptor(type_name: &str) -> Option<Arc<TypeDescriptor>> {
    // Normalize type name: "std_msgs/msg/String" -> "std_msgs/String"
    let normalized = normalize_ros2_type(type_name);
    if let Some(desc) = lookup_registry(&normalized) {
        return Some(desc);
    }

    match normalized.as_str() {
        // std_msgs primitives
        "std_msgs/String" => Some(Arc::new(std_msgs_string())),
        "std_msgs/Bool" => Some(Arc::new(std_msgs_bool())),
        "std_msgs/Int8" => Some(Arc::new(std_msgs_primitive("Int8", PrimitiveKind::I8))),
        "std_msgs/Int16" => Some(Arc::new(std_msgs_primitive("Int16", PrimitiveKind::I16))),
        "std_msgs/Int32" => Some(Arc::new(std_msgs_primitive("Int32", PrimitiveKind::I32))),
        "std_msgs/Int64" => Some(Arc::new(std_msgs_primitive("Int64", PrimitiveKind::I64))),
        "std_msgs/UInt8" => Some(Arc::new(std_msgs_primitive("UInt8", PrimitiveKind::U8))),
        "std_msgs/UInt16" => Some(Arc::new(std_msgs_primitive("UInt16", PrimitiveKind::U16))),
        "std_msgs/UInt32" => Some(Arc::new(std_msgs_primitive("UInt32", PrimitiveKind::U32))),
        "std_msgs/UInt64" => Some(Arc::new(std_msgs_primitive("UInt64", PrimitiveKind::U64))),
        "std_msgs/Float32" => Some(Arc::new(std_msgs_primitive("Float32", PrimitiveKind::F32))),
        "std_msgs/Float64" => Some(Arc::new(std_msgs_primitive("Float64", PrimitiveKind::F64))),

        // std_msgs with Header
        "std_msgs/Header" => Some(Arc::new(std_msgs_header())),

        // std_msgs arrays
        "std_msgs/Int32MultiArray" => Some(Arc::new(std_msgs_int32_multi_array())),

        // geometry_msgs
        "geometry_msgs/Point" => Some(Arc::new(geometry_msgs_point())),
        "geometry_msgs/Point32" => Some(Arc::new(geometry_msgs_point32())),
        "geometry_msgs/Vector3" => Some(Arc::new(geometry_msgs_vector3())),
        "geometry_msgs/Quaternion" => Some(Arc::new(geometry_msgs_quaternion())),
        "geometry_msgs/Pose" => Some(Arc::new(geometry_msgs_pose())),
        "geometry_msgs/Twist" => Some(Arc::new(geometry_msgs_twist())),

        _ => None,
    }
}

fn normalize_ros2_type(type_name: &str) -> String {
    // "std_msgs/msg/String" -> "std_msgs/String"
    // "geometry_msgs/msg/Point" -> "geometry_msgs/Point"
    type_name.replace("/msg/", "/")
}

static DYNAMIC_DESCRIPTOR_REGISTRY: OnceLock<Mutex<HashMap<String, Arc<TypeDescriptor>>>> =
    OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, Arc<TypeDescriptor>>> {
    DYNAMIC_DESCRIPTOR_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lookup_registry(type_name: &str) -> Option<Arc<TypeDescriptor>> {
    let guard = match registry().lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.get(type_name).cloned()
}

#[cfg(feature = "xtypes")]
pub(crate) unsafe fn register_type_descriptor(
    type_support: *const rosidl_message_type_support_t,
) -> Result<Arc<TypeDescriptor>, RosidlError> {
    let metadata = RosMessageMetadata::from_type_support(type_support)?;
    let mut guard = match registry().lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut stack = Vec::new();
    build_descriptor_from_metadata(&metadata, &mut guard, &mut stack)
}

#[cfg(feature = "xtypes")]
fn build_descriptor_from_metadata(
    metadata: &RosMessageMetadata,
    registry: &mut HashMap<String, Arc<TypeDescriptor>>,
    stack: &mut Vec<String>,
) -> Result<Arc<TypeDescriptor>, RosidlError> {
    let type_name = normalize_ros2_type(&ros2_type_name_from_metadata(metadata));
    if let Some(desc) = registry.get(&type_name) {
        return Ok(Arc::clone(desc));
    }
    if stack.iter().any(|name| name == &type_name) {
        return Err(RosidlError::Builder(BuilderError::RecursiveType {
            fqn: type_name,
        }));
    }

    stack.push(type_name.clone());
    let result = (|| {
        let members = metadata.members;
        if members.is_null() {
            return Err(RosidlError::NullMembers);
        }

        let member_ptr = unsafe { (*members).members_ };
        if member_ptr.is_null() {
            return Err(RosidlError::NullMembers);
        }

        let count = unsafe { (*members).member_count_ as usize };
        let member_slice = unsafe { std::slice::from_raw_parts(member_ptr, count) };
        let mut fields = Vec::with_capacity(member_slice.len());

        for member in member_slice {
            let field_name = field_name_from_member(member)?;
            let field_desc = build_field_descriptor(member, registry, stack)?;
            fields.push(FieldDescriptor::new(field_name, field_desc));
        }

        let descriptor = Arc::new(TypeDescriptor::struct_type(type_name.clone(), fields));
        registry.insert(type_name, Arc::clone(&descriptor));
        Ok(descriptor)
    })();
    stack.pop();
    result
}

#[cfg(feature = "xtypes")]
fn build_field_descriptor(
    member: &rosidl_typesupport_introspection_c__MessageMember,
    registry: &mut HashMap<String, Arc<TypeDescriptor>>,
    stack: &mut Vec<String>,
) -> Result<Arc<TypeDescriptor>, RosidlError> {
    let base_desc = match member.type_id_ {
        super::ROS_TYPE_FLOAT => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F32)),
        super::ROS_TYPE_DOUBLE => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F64)),
        super::ROS_TYPE_CHAR => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::Char)),
        super::ROS_TYPE_WCHAR => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U16)),
        super::ROS_TYPE_BOOLEAN => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::Bool)),
        super::ROS_TYPE_OCTET => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
        super::ROS_TYPE_UINT8 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
        super::ROS_TYPE_INT8 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I8)),
        super::ROS_TYPE_UINT16 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U16)),
        super::ROS_TYPE_INT16 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I16)),
        super::ROS_TYPE_UINT32 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
        super::ROS_TYPE_INT32 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
        super::ROS_TYPE_UINT64 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U64)),
        super::ROS_TYPE_INT64 => Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I64)),
        super::ROS_TYPE_STRING => {
            let bound = if member.string_upper_bound_ > 0 {
                Some(member.string_upper_bound_)
            } else {
                None
            };
            Arc::new(TypeDescriptor::primitive(
                "",
                PrimitiveKind::String { max_length: bound },
            ))
        }
        super::ROS_TYPE_WSTRING => {
            let bound = if member.string_upper_bound_ > 0 {
                Some(member.string_upper_bound_)
            } else {
                None
            };
            Arc::new(TypeDescriptor::primitive(
                "",
                PrimitiveKind::WString { max_length: bound },
            ))
        }
        super::ROS_TYPE_MESSAGE => {
            if member.members_.is_null() {
                return Err(RosidlError::NullMembers);
            }
            let nested_metadata =
                unsafe { RosMessageMetadata::from_type_support(member.members_) }?;
            build_descriptor_from_metadata(&nested_metadata, registry, stack)?
        }
        super::ROS_TYPE_LONG_DOUBLE => {
            Arc::new(TypeDescriptor::primitive("", PrimitiveKind::LongDouble))
        }
        _ => return Err(RosidlError::UnsupportedType(member.type_id_)),
    };

    if !member.is_array_ {
        return Ok(base_desc);
    }

    let array_size = member.array_size_;
    let descriptor = if member.is_upper_bound_ {
        if array_size == 0 {
            TypeKind::Sequence(SequenceDescriptor::unbounded(base_desc))
        } else {
            TypeKind::Sequence(SequenceDescriptor::bounded(base_desc, array_size))
        }
    } else if array_size > 0 {
        TypeKind::Array(ArrayDescriptor::new(base_desc, array_size))
    } else {
        TypeKind::Sequence(SequenceDescriptor::unbounded(base_desc))
    };

    Ok(Arc::new(TypeDescriptor::new("", descriptor)))
}

#[cfg(feature = "xtypes")]
fn field_name_from_member(
    member: &rosidl_typesupport_introspection_c__MessageMember,
) -> Result<String, RosidlError> {
    if member.name_.is_null() {
        return Err(RosidlError::NullMembers);
    }
    let name = unsafe { CStr::from_ptr(member.name_) }.to_str()?;
    Ok(name.to_string())
}

#[cfg(feature = "xtypes")]
fn ros2_type_name_from_metadata(metadata: &RosMessageMetadata) -> String {
    if metadata.namespace.is_empty() {
        return metadata.name.clone();
    }
    format!(
        "{}/{}",
        metadata.namespace.replace("::", "/"),
        metadata.name
    )
}

// ============================================
// std_msgs types
// ============================================

fn std_msgs_string() -> TypeDescriptor {
    TypeDescriptorBuilder::new("std_msgs/String")
        .string_field("data")
        .build()
}

fn std_msgs_bool() -> TypeDescriptor {
    TypeDescriptorBuilder::new("std_msgs/Bool")
        .field("data", PrimitiveKind::Bool)
        .build()
}

fn std_msgs_primitive(name: &str, kind: PrimitiveKind) -> TypeDescriptor {
    TypeDescriptorBuilder::new(format!("std_msgs/{}", name))
        .field("data", kind)
        .build()
}

fn std_msgs_header() -> TypeDescriptor {
    // Header contains:
    // - builtin_interfaces/Time stamp (sec: int32, nanosec: uint32)
    // - string frame_id
    let stamp_type = Arc::new(builtin_time());

    TypeDescriptorBuilder::new("std_msgs/Header")
        .nested_field("stamp", stamp_type)
        .string_field("frame_id")
        .build()
}

fn std_msgs_int32_multi_array() -> TypeDescriptor {
    // MultiArrayLayout layout
    // int32[] data
    let layout_type = Arc::new(multi_array_layout());

    TypeDescriptorBuilder::new("std_msgs/Int32MultiArray")
        .nested_field("layout", layout_type)
        .sequence_field("data", PrimitiveKind::I32)
        .build()
}

fn multi_array_layout() -> TypeDescriptor {
    // MultiArrayDimension[] dim
    // uint32 data_offset
    let dim_type = Arc::new(multi_array_dimension());
    let dim_seq = SequenceDescriptor::unbounded(dim_type);
    let dim_type_desc = Arc::new(TypeDescriptor::new("", TypeKind::Sequence(dim_seq)));

    TypeDescriptorBuilder::new("std_msgs/MultiArrayLayout")
        .field_with_type("dim", dim_type_desc)
        .field("data_offset", PrimitiveKind::U32)
        .build()
}

fn multi_array_dimension() -> TypeDescriptor {
    TypeDescriptorBuilder::new("std_msgs/MultiArrayDimension")
        .string_field("label")
        .field("size", PrimitiveKind::U32)
        .field("stride", PrimitiveKind::U32)
        .build()
}

// ============================================
// builtin_interfaces types
// ============================================

fn builtin_time() -> TypeDescriptor {
    TypeDescriptorBuilder::new("builtin_interfaces/Time")
        .field("sec", PrimitiveKind::I32)
        .field("nanosec", PrimitiveKind::U32)
        .build()
}

// ============================================
// geometry_msgs types
// ============================================

fn geometry_msgs_point() -> TypeDescriptor {
    TypeDescriptorBuilder::new("geometry_msgs/Point")
        .field("x", PrimitiveKind::F64)
        .field("y", PrimitiveKind::F64)
        .field("z", PrimitiveKind::F64)
        .build()
}

fn geometry_msgs_point32() -> TypeDescriptor {
    TypeDescriptorBuilder::new("geometry_msgs/Point32")
        .field("x", PrimitiveKind::F32)
        .field("y", PrimitiveKind::F32)
        .field("z", PrimitiveKind::F32)
        .build()
}

fn geometry_msgs_vector3() -> TypeDescriptor {
    TypeDescriptorBuilder::new("geometry_msgs/Vector3")
        .field("x", PrimitiveKind::F64)
        .field("y", PrimitiveKind::F64)
        .field("z", PrimitiveKind::F64)
        .build()
}

fn geometry_msgs_quaternion() -> TypeDescriptor {
    TypeDescriptorBuilder::new("geometry_msgs/Quaternion")
        .field("x", PrimitiveKind::F64)
        .field("y", PrimitiveKind::F64)
        .field("z", PrimitiveKind::F64)
        .field("w", PrimitiveKind::F64)
        .build()
}

fn geometry_msgs_pose() -> TypeDescriptor {
    let position = Arc::new(geometry_msgs_point());
    let orientation = Arc::new(geometry_msgs_quaternion());

    TypeDescriptorBuilder::new("geometry_msgs/Pose")
        .nested_field("position", position)
        .nested_field("orientation", orientation)
        .build()
}

fn geometry_msgs_twist() -> TypeDescriptor {
    let linear = Arc::new(geometry_msgs_vector3());
    let angular = Arc::new(geometry_msgs_vector3());

    TypeDescriptorBuilder::new("geometry_msgs/Twist")
        .nested_field("linear", linear)
        .nested_field("angular", angular)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hdds::dynamic::{decode_dynamic, encode_dynamic, DynamicData};

    #[test]
    fn test_std_msgs_string() {
        let desc = ros2_type_to_descriptor("std_msgs/msg/String").unwrap();
        let mut data = DynamicData::new(&desc);
        data.set("data", "Hello HDDS!").unwrap();

        let encoded = encode_dynamic(&data).expect("encode");
        let decoded = decode_dynamic(&encoded, &desc).expect("decode");

        assert_eq!(decoded.get::<String>("data").unwrap(), "Hello HDDS!");
    }

    #[test]
    fn test_std_msgs_int32() {
        let desc = ros2_type_to_descriptor("std_msgs/msg/Int32").unwrap();
        let mut data = DynamicData::new(&desc);
        data.set("data", 42i32).unwrap();

        let encoded = encode_dynamic(&data).expect("encode");
        let decoded = decode_dynamic(&encoded, &desc).expect("decode");

        assert_eq!(decoded.get::<i32>("data").unwrap(), 42);
    }

    #[test]
    fn test_geometry_msgs_point() {
        let desc = ros2_type_to_descriptor("geometry_msgs/msg/Point").unwrap();
        let mut data = DynamicData::new(&desc);
        data.set("x", 1.0f64).unwrap();
        data.set("y", 2.0f64).unwrap();
        data.set("z", 3.0f64).unwrap();

        let encoded = encode_dynamic(&data).expect("encode");
        let decoded = decode_dynamic(&encoded, &desc).expect("decode");

        assert!((decoded.get::<f64>("x").unwrap() - 1.0).abs() < 1e-10);
        assert!((decoded.get::<f64>("y").unwrap() - 2.0).abs() < 1e-10);
        assert!((decoded.get::<f64>("z").unwrap() - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_normalize_type_name() {
        assert_eq!(
            normalize_ros2_type("std_msgs/msg/String"),
            "std_msgs/String"
        );
        assert_eq!(
            normalize_ros2_type("geometry_msgs/msg/Point"),
            "geometry_msgs/Point"
        );
        assert_eq!(normalize_ros2_type("std_msgs/String"), "std_msgs/String");
    }

    #[test]
    fn test_all_test_types_exist() {
        // These are the 10 types tested by test_ros2_rmw_hdds_types.sh
        assert!(ros2_type_to_descriptor("std_msgs/msg/String").is_some());
        assert!(ros2_type_to_descriptor("std_msgs/msg/Int32").is_some());
        assert!(ros2_type_to_descriptor("std_msgs/msg/Float64").is_some());
        assert!(ros2_type_to_descriptor("std_msgs/msg/Bool").is_some());
        assert!(ros2_type_to_descriptor("geometry_msgs/msg/Point").is_some());
        assert!(ros2_type_to_descriptor("geometry_msgs/msg/Vector3").is_some());
        assert!(ros2_type_to_descriptor("geometry_msgs/msg/Twist").is_some());
        assert!(ros2_type_to_descriptor("geometry_msgs/msg/Pose").is_some());
        assert!(ros2_type_to_descriptor("std_msgs/msg/Header").is_some());
        assert!(ros2_type_to_descriptor("std_msgs/msg/Int32MultiArray").is_some());
    }
}
