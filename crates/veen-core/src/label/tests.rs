use hex::ToHex;

use super::{Label, StreamId, STREAM_ID_LEN};

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
        0x98, 0x05, 0x04, 0xe8, 0xeb, 0xa5, 0xbb, 0x36, 0xd2, 0x9b, 0xac, 0xd6, 0xef, 0xf0,
        0x3e, 0xdc, 0x8f, 0xf8, 0x62, 0xd7, 0xc8, 0xc1, 0x46, 0x56, 0xba, 0x93, 0x91, 0x79,
        0x78, 0xa9, 0x4c, 0x5f,
    ];

    assert_eq!(label.as_bytes(), &expected);
}

#[test]
fn label_and_stream_id_display_as_hex() {
    let mut stream_id_bytes = [0u8; STREAM_ID_LEN];
    stream_id_bytes[STREAM_ID_LEN - 1] = 0xff;
    let stream_id = StreamId::from(stream_id_bytes);
    let label = Label::from([0u8; 32]);

    assert_eq!(stream_id.to_string(), stream_id_bytes.encode_hex::<String>());
    assert_eq!(label.to_string(), [0u8; 32].encode_hex::<String>());
}
