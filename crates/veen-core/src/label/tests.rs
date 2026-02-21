use std::convert::TryFrom;

use ciborium::{de::from_reader, ser::into_writer};
use hex::ToHex;

use super::{Label, StreamId, LABEL_LEN, STREAM_ID_LEN};
use crate::hexutil::ParseHexError;

#[test]
fn stream_and_label_round_trip_via_strings() {
    let stream_bytes = [0x12; STREAM_ID_LEN];
    let label_bytes = [0x34; LABEL_LEN];
    let stream_hex = stream_bytes.encode_hex::<String>();
    let label_hex = label_bytes.encode_hex::<String>();

    let parsed_stream = stream_hex.parse::<StreamId>().expect("parse stream id");
    let parsed_label = label_hex.parse::<Label>().expect("parse label");

    assert_eq!(parsed_stream.as_bytes(), &stream_bytes);
    assert_eq!(parsed_stream.to_string(), stream_hex);
    assert_eq!(parsed_label.as_bytes(), &label_bytes);
    assert_eq!(parsed_label.to_string(), label_hex);
}

#[test]
fn derive_label_matches_known_vector() {
    let routing_key = b"routing-key";
    let mut stream_id_bytes = [0u8; STREAM_ID_LEN];
    for (index, byte) in stream_id_bytes.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let stream_id = StreamId::from(stream_id_bytes);
    let label = Label::derive(routing_key, stream_id, 0x0123_4567_89ab_cdef);

    let expected = [
        0x98, 0x05, 0x04, 0xe8, 0xeb, 0xa5, 0xbb, 0x36, 0xd2, 0x9b, 0xac, 0xd6, 0xef, 0xf0, 0x3e,
        0xdc, 0x8f, 0xf8, 0x62, 0xd7, 0xc8, 0xc1, 0x46, 0x56, 0xba, 0x93, 0x91, 0x79, 0x78, 0xa9,
        0x4c, 0x5f,
    ];

    assert_eq!(label.as_bytes(), &expected);
}

#[test]
fn label_and_stream_id_display_as_hex() {
    let mut stream_id_bytes = [0u8; STREAM_ID_LEN];
    stream_id_bytes[STREAM_ID_LEN - 1] = 0xff;
    let stream_id = StreamId::from(stream_id_bytes);
    let label = Label::from([0u8; LABEL_LEN]);

    assert_eq!(
        stream_id.to_string(),
        stream_id_bytes.encode_hex::<String>()
    );
    assert_eq!(label.to_string(), [0u8; LABEL_LEN].encode_hex::<String>());
}

#[test]
fn stream_id_serializes_as_cbor_bstr() {
    let stream_id = StreamId::from([0x55; STREAM_ID_LEN]);
    let mut buf = Vec::new();
    into_writer(&stream_id, &mut buf).expect("serialize stream id");
    assert_eq!(buf[0], 0x58);
    assert_eq!(buf[1], STREAM_ID_LEN as u8);
    assert_eq!(&buf[2..], stream_id.as_bytes());

    let decoded: StreamId = from_reader(buf.as_slice()).expect("deserialize stream id");
    assert_eq!(decoded, stream_id);
}

#[test]
fn label_serialization_enforces_length() {
    let label = Label::from([0xaa; LABEL_LEN]);
    let mut buf = Vec::new();
    into_writer(&label, &mut buf).expect("serialize label");
    assert_eq!(buf[0], 0x58);
    assert_eq!(buf[1], 32);
    assert_eq!(&buf[2..], label.as_bytes());

    let mut truncated = vec![0x58, 0x1f];
    truncated.extend([0u8; 31]);
    let result: Result<Label, _> = from_reader(truncated.as_slice());
    assert!(result.is_err(), "expected error for invalid label length");
}

#[test]
fn stream_id_from_slice_enforces_exact_length() {
    let bytes = [0x11; STREAM_ID_LEN];
    let id = StreamId::from_slice(&bytes).expect("valid stream id");
    assert_eq!(id.as_bytes(), &bytes);

    let err = StreamId::from_slice(&bytes[..STREAM_ID_LEN - 1]).expect_err("length error");
    assert_eq!(err.expected(), STREAM_ID_LEN);
    assert_eq!(err.actual(), STREAM_ID_LEN - 1);
}

#[test]
fn label_from_slice_enforces_exact_length() {
    let bytes = [0x22; LABEL_LEN];
    let label = Label::from_slice(&bytes).expect("valid label");
    assert_eq!(label.as_bytes(), &bytes);

    let err = Label::from_slice(&bytes[..LABEL_LEN - 2]).expect_err("length error");
    assert_eq!(err.expected(), LABEL_LEN);
    assert_eq!(err.actual(), LABEL_LEN - 2);
}

#[test]
fn stream_id_from_str_rejects_invalid_length() {
    let err = "abcd".parse::<StreamId>().expect_err("length error");
    assert!(matches!(
        err,
        ParseHexError::InvalidLength {
            expected: 64,
            actual: 4
        }
    ));
}

#[test]
fn label_from_str_rejects_invalid_character() {
    let input = format!("g{}", "0".repeat(63));
    let err = input.parse::<Label>().expect_err("invalid character");
    assert!(matches!(
        err,
        ParseHexError::InvalidCharacter {
            index: 0,
            character: 'g'
        }
    ));
}

#[test]
fn stream_id_from_str_accepts_uppercase_hex() {
    let input = "AA".repeat(STREAM_ID_LEN);
    let parsed = input.parse::<StreamId>().expect("uppercase hex stream id");
    assert_eq!(parsed.as_bytes(), &[0xaa; STREAM_ID_LEN]);
}

#[test]
fn stream_id_new_and_as_ref() {
    let bytes = [0x77; STREAM_ID_LEN];
    let id = StreamId::new(bytes);
    assert_eq!(id.as_bytes(), &bytes);
    assert_eq!(id.as_ref(), &bytes[..]);
}

#[test]
fn stream_id_from_ref_array() {
    let bytes = [0x88; STREAM_ID_LEN];
    let id = StreamId::from(&bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn stream_id_try_from_slice_and_vec() {
    let bytes = [0x99; STREAM_ID_LEN];
    let id = StreamId::try_from(bytes.as_slice()).expect("try_from slice");
    assert_eq!(id.as_bytes(), &bytes);

    let err = StreamId::try_from([0u8; 1].as_slice()).expect_err("too short");
    assert_eq!(err.expected(), STREAM_ID_LEN);

    let id2 = StreamId::try_from(bytes.to_vec()).expect("try_from vec");
    assert_eq!(id2, id);

    let err2 = StreamId::try_from(vec![0u8; 1]).expect_err("too short");
    assert_eq!(err2.expected(), STREAM_ID_LEN);
}

#[test]
fn stream_id_serde_invalid_length() {
    let short: &[u8] = &[0u8; STREAM_ID_LEN - 1];
    let mut buf = Vec::new();
    into_writer(&serde_bytes::Bytes::new(short), &mut buf).expect("serialize");
    let result: Result<StreamId, _> = from_reader(buf.as_slice());
    assert!(result.is_err(), "should reject wrong-length bytes");
}

#[test]
fn label_from_ref_array() {
    let bytes = [0xAA; LABEL_LEN];
    let label = Label::from(&bytes);
    assert_eq!(label.as_bytes(), &bytes);
}

#[test]
fn label_try_from_slice_and_vec() {
    let bytes = [0xBB; LABEL_LEN];
    let label = Label::try_from(bytes.as_slice()).expect("try_from slice");
    assert_eq!(label.as_bytes(), &bytes);

    let err = Label::try_from([0u8; 1].as_slice()).expect_err("too short");
    assert_eq!(err.expected(), LABEL_LEN);

    let label2 = Label::try_from(bytes.to_vec()).expect("try_from vec");
    assert_eq!(label2, label);

    let err2 = Label::try_from(vec![0u8; 1]).expect_err("too short");
    assert_eq!(err2.expected(), LABEL_LEN);
}

#[test]
fn label_as_ref() {
    let bytes = [0xCC; LABEL_LEN];
    let label = Label::from(bytes);
    assert_eq!(label.as_ref(), &bytes[..]);
}

#[test]
fn label_serde_roundtrip() {
    let label = Label::from([0xDD; LABEL_LEN]);
    let mut buf = Vec::new();
    into_writer(&label, &mut buf).expect("serialize");
    let decoded: Label = from_reader(buf.as_slice()).expect("deserialize");
    assert_eq!(decoded, label);
}
