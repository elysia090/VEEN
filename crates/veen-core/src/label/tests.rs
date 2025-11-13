use ciborium::{de::from_reader, ser::into_writer};
use hex::ToHex;

use super::{Label, StreamId, LABEL_LEN, STREAM_ID_LEN};

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
