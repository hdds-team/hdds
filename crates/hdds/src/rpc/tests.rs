// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Integration tests for DDS-RPC module.

use super::*;

#[test]
fn test_rpc_qos_profile() {
    let qos = rpc_qos();

    // RPC should use reliable, keep-all, volatile
    assert!(matches!(qos.reliability, crate::dds::Reliability::Reliable));
    assert!(matches!(qos.history, crate::dds::History::KeepAll));
    assert!(matches!(qos.durability, crate::dds::Durability::Volatile));
}

#[test]
fn test_sample_identity_hash() {
    use std::collections::HashSet;

    let id1 = SampleIdentity::new(crate::core::discovery::GUID::zero(), 1);
    let id2 = SampleIdentity::new(crate::core::discovery::GUID::zero(), 2);
    let id1_clone = SampleIdentity::new(crate::core::discovery::GUID::zero(), 1);

    let mut set = HashSet::new();
    set.insert(id1);
    set.insert(id2);

    assert_eq!(set.len(), 2);
    assert!(set.contains(&id1_clone));
}

#[test]
fn test_request_header_creation() {
    let id = SampleIdentity::new(crate::core::discovery::GUID::zero(), 42);
    let header = RequestHeader::new(id);

    assert_eq!(header.request_id.sequence_number, 42);
    assert_eq!(header.instance_id, SampleIdentity::zero());
}

#[test]
fn test_reply_header_success() {
    let id = SampleIdentity::new(crate::core::discovery::GUID::zero(), 42);
    let header = ReplyHeader::success(id);

    assert!(header.is_success());
    assert_eq!(header.remote_exception_code, RemoteExceptionCode::Ok);
}

#[test]
fn test_reply_header_error() {
    let id = SampleIdentity::new(crate::core::discovery::GUID::zero(), 42);
    let header = ReplyHeader::error(id, RemoteExceptionCode::Timeout);

    assert!(!header.is_success());
    assert_eq!(header.remote_exception_code, RemoteExceptionCode::Timeout);
}

#[test]
fn test_rpc_error_display() {
    let err = RpcError::Timeout;
    assert!(err.to_string().contains("timed out"));

    let err = RpcError::ServiceNotFound("calc".to_string());
    assert!(err.to_string().contains("calc"));

    let err = RpcError::remote(RemoteExceptionCode::InvalidArgument);
    assert!(err.to_string().contains("InvalidArgument"));
}

#[test]
fn test_rpc_error_from_code() {
    let err = RpcError::from_code(RemoteExceptionCode::Timeout);
    assert!(matches!(err, RpcError::Timeout));

    let err = RpcError::from_code(RemoteExceptionCode::InvalidArgument);
    assert!(matches!(
        err,
        RpcError::RemoteException {
            code: RemoteExceptionCode::InvalidArgument,
            ..
        }
    ));
}
