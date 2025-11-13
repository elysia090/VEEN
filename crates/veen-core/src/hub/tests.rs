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
