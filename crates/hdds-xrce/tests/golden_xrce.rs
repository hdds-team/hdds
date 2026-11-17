// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Golden vectors pinning the DDS-XRCE 1.0 framing this crate speaks.
//!
//! Scope, stated plainly: the *framing* below is the spec's. The message
//! header layout (session id, stream id, little-endian sequence number and
//! the ClientKey rule), the submessage header, the submessage ids, the
//! FRAGMENT flag and the STATUS codes are the DDS-XRCE 1.0 values,
//! cross-checked against the reference implementation
//! (eProsima Micro-XRCE-DDS-Client: `src/c/core/session/submessage_internal.h`
//! for the ids, `src/c/core/serialization/xrce_header_internal.h` plus
//! `xrce_header.c` for the ClientKey rule, and
//! `include/uxr/client/core/session/session_info.h` for the status codes).
//!
//! The submessage *payload bodies* are this crate's compact profile, not the
//! spec's `CLIENT_Representation` / `ObjectVariant` CDR structures: an
//! hdds-xrce agent talks to an hdds-xrce client, it does not yet interoperate
//! with a Micro-XRCE-DDS client. Nothing here claims otherwise.

use hdds_xrce::protocol::{
    parse_message, serialize_message, CreateClientPayload, MessageHeader, StatusCode, Submessage,
    WriteDataPayload, XrceError, XrceMessage, CLIENT_KEY_SIZE, FLAG_LAST_FRAGMENT,
    MAX_MESSAGE_HEADER_SIZE, MESSAGE_HEADER_SIZE, SESSION_ID_WITHOUT_CLIENT_KEY, SUBMSG_ACKNACK,
    SUBMSG_CREATE, SUBMSG_CREATE_CLIENT, SUBMSG_DATA, SUBMSG_DELETE, SUBMSG_FRAGMENT,
    SUBMSG_GET_INFO, SUBMSG_HEARTBEAT, SUBMSG_INFO, SUBMSG_READ_DATA, SUBMSG_RESET, SUBMSG_STATUS,
    SUBMSG_STATUS_AGENT, SUBMSG_TIMESTAMP, SUBMSG_TIMESTAMP_REPLY, SUBMSG_WRITE_DATA,
};

#[test]
fn submessage_ids_match_the_spec_table() {
    assert_eq!(SUBMSG_CREATE_CLIENT, 0);
    assert_eq!(SUBMSG_CREATE, 1);
    assert_eq!(SUBMSG_GET_INFO, 2);
    assert_eq!(SUBMSG_DELETE, 3);
    assert_eq!(SUBMSG_STATUS_AGENT, 4);
    assert_eq!(SUBMSG_STATUS, 5);
    assert_eq!(SUBMSG_INFO, 6);
    assert_eq!(SUBMSG_WRITE_DATA, 7);
    assert_eq!(SUBMSG_READ_DATA, 8);
    assert_eq!(SUBMSG_DATA, 9);
    assert_eq!(SUBMSG_ACKNACK, 10);
    assert_eq!(SUBMSG_HEARTBEAT, 11);
    assert_eq!(SUBMSG_RESET, 12);
    assert_eq!(SUBMSG_FRAGMENT, 13);
    assert_eq!(SUBMSG_TIMESTAMP, 14);
    assert_eq!(SUBMSG_TIMESTAMP_REPLY, 15);
    assert_eq!(FLAG_LAST_FRAGMENT, 0x02);
}

#[test]
fn status_codes_match_the_spec_table() {
    assert_eq!(StatusCode::Ok.as_u8(), 0x00);
    assert_eq!(StatusCode::OkMatched.as_u8(), 0x01);
    assert_eq!(StatusCode::ErrDdsError.as_u8(), 0x80);
    assert_eq!(StatusCode::ErrMismatch.as_u8(), 0x81);
    assert_eq!(StatusCode::ErrAlreadyExists.as_u8(), 0x82);
    assert_eq!(StatusCode::ErrDenied.as_u8(), 0x83);
    assert_eq!(StatusCode::ErrUnknownRef.as_u8(), 0x84);
    assert_eq!(StatusCode::ErrInvalidData.as_u8(), 0x85);
    assert_eq!(StatusCode::ErrIncompatible.as_u8(), 0x86);
    assert_eq!(StatusCode::ErrResources.as_u8(), 0x87);
    // 0x02..0x7F are not status codes.
    assert!(StatusCode::from_u8(0x02).is_err());
}

#[test]
fn header_with_and_without_client_key() {
    assert_eq!(SESSION_ID_WITHOUT_CLIENT_KEY, 0x80);
    assert_eq!(CLIENT_KEY_SIZE, 4);
    assert_eq!(MESSAGE_HEADER_SIZE, 4);
    assert_eq!(MAX_MESSAGE_HEADER_SIZE, 8);

    // session_id < 0x80: the ClientKey is part of every header.
    let keyed = MessageHeader::with_key(0x01, 0x00, 0x0201, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        keyed.to_bytes().expect("keyed header"),
        vec![0x01, 0x00, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]
    );

    // session_id >= 0x80: no ClientKey, 4 bytes.
    let plain = MessageHeader::new(0x81, 0x01, 0x0201);
    assert_eq!(
        plain.to_bytes().expect("plain header"),
        vec![0x81, 0x01, 0x01, 0x02]
    );

    // A keyed session id with no key is refused at serialization: a short
    // header on a keyed session would silently desynchronise the peer.
    assert!(matches!(
        MessageHeader::new(0x01, 0, 0).to_bytes(),
        Err(XrceError::MissingClientKey(0x01))
    ));

    // Parsing follows the same rule, including "not enough bytes for the key".
    assert!(MessageHeader::parse(&[0x01, 0x00, 0x00, 0x00]).is_err());
    assert_eq!(
        MessageHeader::parse(&[0x01, 0x00, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF]).unwrap(),
        keyed
    );
}

#[test]
fn golden_create_client_bytes() {
    let msg = XrceMessage {
        header: MessageHeader::with_key(0x00, 0x00, 0x0000, [0xDE, 0xAD, 0xBE, 0xEF]),
        submessages: vec![Submessage::CreateClient(CreateClientPayload {
            client_key: [0xDE, 0xAD, 0xBE, 0xEF],
            properties: 0x00,
        })],
    };
    let bytes = serialize_message(&msg).expect("serialize CREATE_CLIENT");
    assert_eq!(
        bytes,
        vec![
            // message header: session 0x00, stream 0x00, seq 0x0000, ClientKey
            0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
            // submessage header: id 0 (CREATE_CLIENT), flags 0, length 5
            0x00, 0x00, 0x05, 0x00, // payload: ClientKey + properties
            0xDE, 0xAD, 0xBE, 0xEF, 0x00,
        ]
    );
    assert_eq!(parse_message(&bytes).unwrap(), msg);
}

#[test]
fn golden_write_data_bytes() {
    let msg = XrceMessage {
        header: MessageHeader::new(0x80, 0x01, 0x0007),
        submessages: vec![Submessage::WriteData(WriteDataPayload {
            writer_id: 0x000A,
            data: vec![0x11, 0x22, 0x33],
        })],
    };
    let bytes = serialize_message(&msg).expect("serialize WRITE_DATA");
    assert_eq!(
        bytes,
        vec![
            // message header: session 0x80 (no ClientKey), stream 1, seq 7
            0x80, 0x01, 0x07, 0x00, // submessage header: id 7 (WRITE_DATA), flags 0, length 5
            0x07, 0x00, 0x05, 0x00, // payload: writer id + data
            0x0A, 0x00, 0x11, 0x22, 0x33,
        ]
    );
    assert_eq!(parse_message(&bytes).unwrap(), msg);
}
