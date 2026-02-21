use std::convert::TryFrom;

use super::{HubId, HUB_ID_LEN};
use crate::ht;
use hex::encode;

#[test]
fn hub_id_parses_from_hex_string() {
    let bytes = [0xAB; HUB_ID_LEN];
    let hex = encode(bytes);
    let parsed = hex.parse::<HubId>().expect("parse hub id");
    assert_eq!(parsed.as_bytes(), &bytes);
    assert_eq!(parsed.to_string(), hex);
}

#[test]
fn hub_id_derives_from_public_key() {
    let mut public_key = [0u8; HUB_ID_LEN];
    for (index, byte) in public_key.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let hub_id = HubId::derive(public_key).expect("derive hub id");
    let expected = [
        0xea, 0x9b, 0x65, 0x36, 0x91, 0x53, 0x41, 0x54, 0x67, 0xc6, 0x68, 0x5b, 0x12, 0xa1, 0xb5,
        0x68, 0xcd, 0x74, 0x4c, 0x37, 0xb8, 0xea, 0x56, 0xa5, 0x2f, 0xaa, 0x00, 0xa9, 0x18, 0x0b,
        0x5d, 0xb9,
    ];
    assert_eq!(hub_id.as_bytes(), &expected);
}

#[test]
fn hub_id_from_slice_enforces_length() {
    let bytes = [0x11; HUB_ID_LEN];
    let id = HubId::from_slice(&bytes).expect("valid hub id");
    assert_eq!(id.as_bytes(), &bytes);

    let err = HubId::from_slice(&bytes[..HUB_ID_LEN - 1]).expect_err("length error");
    assert_eq!(err.expected(), HUB_ID_LEN);
    assert_eq!(err.actual(), HUB_ID_LEN - 1);
}

#[test]
fn hub_id_derive_enforces_public_key_length() {
    let mut public_key = vec![0xAA; HUB_ID_LEN + 1];
    let err = HubId::derive(&public_key).expect_err("length error");
    assert_eq!(err.expected(), HUB_ID_LEN);
    assert_eq!(err.actual(), HUB_ID_LEN + 1);

    public_key.pop();
    let id = HubId::derive(&public_key).expect("derive hub id");
    assert_eq!(id.as_bytes(), &ht("veen/hub-id", &public_key));
}

#[test]
fn hub_id_from_and_as_ref() {
    let bytes = [0xCC; HUB_ID_LEN];
    let id1 = HubId::from(bytes);
    let id2 = HubId::from(&bytes);
    assert_eq!(id1, id2);
    assert_eq!(id1.as_ref(), &bytes[..]);
    assert_eq!(id1.as_bytes(), &bytes);
}

#[test]
fn hub_id_try_from_slice_and_vec() {
    let bytes = [0x55; HUB_ID_LEN];
    let id = HubId::try_from(bytes.as_slice()).expect("try_from slice");
    assert_eq!(id.as_bytes(), &bytes);

    let err = HubId::try_from([0u8; 1].as_slice()).expect_err("too short");
    assert_eq!(err.expected(), HUB_ID_LEN);

    let id2 = HubId::try_from(bytes.to_vec()).expect("try_from vec");
    assert_eq!(id2, id);

    let err2 = HubId::try_from(vec![0u8; 1]).expect_err("too short");
    assert_eq!(err2.expected(), HUB_ID_LEN);
}

#[test]
fn hub_id_serde_roundtrip() {
    let id = HubId::new([0x99; HUB_ID_LEN]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&id, &mut buf).expect("serialize");
    let decoded: HubId = ciborium::de::from_reader(buf.as_slice()).expect("deserialize");
    assert_eq!(decoded, id);
}

#[test]
fn hub_id_serde_invalid_length() {
    let short: &[u8] = &[0u8; HUB_ID_LEN - 1];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&serde_bytes::Bytes::new(short), &mut buf).expect("serialize");
    let result: Result<HubId, _> = ciborium::de::from_reader(buf.as_slice());
    assert!(result.is_err(), "should reject wrong-length bytes");
}

#[test]
fn hub_id_new_and_display() {
    let bytes = [0xBB; HUB_ID_LEN];
    let id = HubId::new(bytes);
    assert_eq!(id.to_string(), hex::encode(bytes));
}
