// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
// PL_CDR2 struct roundtrip against a mutable struct with optional member.

use hdds::core::ser::pl_cdr2::{
    align_offset, decode_pl_cdr2_struct, encode_pl_cdr2_struct, padding_for_alignment,
    PlMemberEncoder,
};
use hdds::{Cdr2Decode, Cdr2Encode, CdrError};

const MEMBER_ID_POINTS: u32 = 0x0e81ab0a;
const MEMBER_ID_ALTITUDE: u32 = 0x0093d814;
const POINT3D_ENCODED_SIZE: usize = 24;

// EMHEADER1 format: (LengthCode::NextInt << 28) | member_id
// LengthCode::NextInt = 5, so EMHEADER = 0x50000000 | member_id
const EMHEADER_POINTS: u32 = 0x50000000 | MEMBER_ID_POINTS;
const EMHEADER_ALTITUDE: u32 = 0x50000000 | MEMBER_ID_ALTITUDE;

#[derive(Debug, Clone, PartialEq)]
struct Point3D {
    x: f64,
    y: f64,
    z: f64,
}

impl Cdr2Encode for Point3D {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset: usize = 0;

        offset = align_offset(offset, 8);
        if dst.len() < offset + 8 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 8].copy_from_slice(&self.x.to_le_bytes());
        offset += 8;

        offset = align_offset(offset, 8);
        if dst.len() < offset + 8 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 8].copy_from_slice(&self.y.to_le_bytes());
        offset += 8;

        offset = align_offset(offset, 8);
        if dst.len() < offset + 8 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 8].copy_from_slice(&self.z.to_le_bytes());
        offset += 8;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        7 + 8 + 7 + 8 + 7 + 8
    }
}

impl Cdr2Decode for Point3D {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset: usize = 0;

        offset = align_offset(offset, 8);
        if src.len() < offset + 8 {
            return Err(CdrError::UnexpectedEof);
        }
        let x = {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&src[offset..offset + 8]);
            f64::from_le_bytes(tmp)
        };
        offset += 8;

        offset = align_offset(offset, 8);
        if src.len() < offset + 8 {
            return Err(CdrError::UnexpectedEof);
        }
        let y = {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&src[offset..offset + 8]);
            f64::from_le_bytes(tmp)
        };
        offset += 8;

        offset = align_offset(offset, 8);
        if src.len() < offset + 8 {
            return Err(CdrError::UnexpectedEof);
        }
        let z = {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&src[offset..offset + 8]);
            f64::from_le_bytes(tmp)
        };
        offset += 8;

        Ok((Self { x, y, z }, offset))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Poly3D {
    points: Vec<Point3D>,
    altitude: Option<f64>,
}

impl Cdr2Encode for Poly3D {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_points = |buf: &mut [u8], abs_off: usize| -> Result<usize, CdrError> {
            let mut offset = 0;

            let pad_len = padding_for_alignment(abs_off + offset, 4);
            if buf.len() < offset + pad_len + 4 {
                return Err(CdrError::BufferTooSmall);
            }
            buf[offset..offset + pad_len].fill(0);
            offset += pad_len;

            let count = u32::try_from(self.points.len()).map_err(|_| CdrError::InvalidEncoding)?;
            buf[offset..offset + 4].copy_from_slice(&count.to_le_bytes());
            offset += 4;

            for point in &self.points {
                let pad = padding_for_alignment(abs_off + offset, 8);
                if buf.len() < offset + pad + POINT3D_ENCODED_SIZE {
                    return Err(CdrError::BufferTooSmall);
                }
                buf[offset..offset + pad].fill(0);
                offset += pad;

                let used = point.encode_cdr2_le(&mut buf[offset..])?;
                offset += used;
            }

            Ok(offset)
        };

        let mut members = Vec::with_capacity(2);
        members.push(PlMemberEncoder {
            member_id: MEMBER_ID_POINTS,
            align: 4,
            encode: &mut encode_points,
        });

        let mut enc_altitude = |buf: &mut [u8], abs_off: usize| -> Result<usize, CdrError> {
            let mut offset = 0;
            let pad_len = padding_for_alignment(abs_off + offset, 8);
            if buf.len() < offset + pad_len + 8 {
                return Err(CdrError::BufferTooSmall);
            }
            buf[offset..offset + pad_len].fill(0);
            offset += pad_len;

            let alt = self.altitude.expect("altitude should be present");
            buf[offset..offset + 8].copy_from_slice(&alt.to_le_bytes());
            offset += 8;
            Ok(offset)
        };

        if self.altitude.is_some() {
            members.push(PlMemberEncoder {
                member_id: MEMBER_ID_ALTITUDE,
                align: 8,
                encode: &mut enc_altitude,
            });
        }

        encode_pl_cdr2_struct(dst, &mut members)
    }

    fn max_cdr2_size(&self) -> usize {
        let points_stride = 7 + POINT3D_ENCODED_SIZE;
        let altitude_max = if self.altitude.is_some() {
            4 + 7 + 8
        } else {
            0
        };
        12 + points_stride * self.points.len() + altitude_max
    }
}

impl Cdr2Decode for Poly3D {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut points: Option<Vec<Point3D>> = None;
        let mut altitude: Option<f64> = None;

        // Calculate consumed bytes from DHEADER (first 4 bytes contain payload length)
        if src.len() < 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let payload_len = u32::from_le_bytes(src[..4].try_into().unwrap()) as usize;
        let consumed = 4 + payload_len;

        decode_pl_cdr2_struct(src, |member_id, src, offset, end| {
            match member_id {
                MEMBER_ID_POINTS => {
                    let pad_len = padding_for_alignment(*offset, 4);
                    if *offset + pad_len + 4 > end {
                        return Err(CdrError::UnexpectedEof);
                    }
                    *offset += pad_len;

                    let count = {
                        let mut tmp = [0u8; 4];
                        tmp.copy_from_slice(&src[*offset..*offset + 4]);
                        u32::from_le_bytes(tmp) as usize
                    };
                    *offset += 4;

                    let mut vec = Vec::with_capacity(count);
                    for _ in 0..count {
                        let pad = padding_for_alignment(*offset, 8);
                        if *offset + pad + POINT3D_ENCODED_SIZE > end {
                            return Err(CdrError::UnexpectedEof);
                        }
                        *offset += pad;

                        let (point, _used) = Point3D::decode_cdr2_le(&src[*offset..])?;
                        *offset += POINT3D_ENCODED_SIZE;
                        vec.push(point);
                    }
                    points = Some(vec);
                }
                MEMBER_ID_ALTITUDE => {
                    let pad_len = padding_for_alignment(*offset, 8);
                    if *offset + pad_len + 8 > end {
                        return Err(CdrError::UnexpectedEof);
                    }
                    *offset += pad_len;

                    let mut tmp = [0u8; 8];
                    tmp.copy_from_slice(&src[*offset..*offset + 8]);
                    altitude = Some(f64::from_le_bytes(tmp));
                    *offset += 8;
                }
                _ => return Err(CdrError::InvalidEncoding),
            }
            Ok(())
        })?;

        Ok((
            Self {
                points: points.unwrap_or_default(),
                altitude,
            },
            consumed,
        ))
    }
}

#[test]
fn pl_cdr2_roundtrip_with_altitude() {
    let poly = Poly3D {
        points: vec![
            Point3D {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            Point3D {
                x: 4.0,
                y: 5.0,
                z: 6.0,
            },
        ],
        altitude: Some(100.0),
    };

    let mut buf = [0u8; 128];
    let encoded_len = poly.encode_cdr2_le(&mut buf).expect("encode failed");

    // DHEADER payload length (should exclude the delimiter itself)
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 76);
    // EMHEADER1 for points (includes LC=NEXTINT in upper bits)
    assert_eq!(
        u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        EMHEADER_POINTS
    );
    // Sequence length = 2 (at offset 12, after EMHEADER+NEXTINT)
    assert_eq!(u32::from_le_bytes(buf[12..16].try_into().unwrap()), 2);
    // EMHEADER1 for altitude after two points (at offset 64)
    assert_eq!(
        u32::from_le_bytes(buf[64..68].try_into().unwrap()),
        EMHEADER_ALTITUDE
    );
    assert_eq!(encoded_len, 80);

    let (decoded, _) = Poly3D::decode_cdr2_le(&buf[..encoded_len]).expect("decode failed");
    assert_eq!(decoded, poly);
}

#[test]
fn pl_cdr2_roundtrip_without_altitude() {
    let poly = Poly3D {
        points: vec![Point3D {
            x: 1.0,
            y: 2.0,
            z: 3.0,
        }],
        altitude: None,
    };

    let mut buf = [0u8; 128];
    let encoded_len = poly.encode_cdr2_le(&mut buf).expect("encode failed");

    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 36);
    // EMHEADER1 for points (includes LC=NEXTINT in upper bits)
    assert_eq!(
        u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        EMHEADER_POINTS
    );
    assert_eq!(encoded_len, 40);

    let (decoded, _) = Poly3D::decode_cdr2_le(&buf[..encoded_len]).expect("decode failed");
    assert_eq!(decoded, poly);
}
