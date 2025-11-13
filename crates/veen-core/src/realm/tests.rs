use crate::ht;

use super::{RealmId, REALM_ID_LEN};

#[test]
fn realm_id_from_slice_enforces_length() {
    let bytes = [0x33; REALM_ID_LEN];
    let id = RealmId::from_slice(&bytes).expect("valid realm id");
    assert_eq!(id.as_bytes(), &bytes);

    let err = RealmId::from_slice(&bytes[..REALM_ID_LEN - 1]).expect_err("length error");
    assert_eq!(err.expected(), REALM_ID_LEN);
    assert_eq!(err.actual(), REALM_ID_LEN - 1);
}

#[test]
fn admin_stream_derivations_match_spec() {
    let mut realm_bytes = [0u8; REALM_ID_LEN];
    for (index, byte) in realm_bytes.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let realm = RealmId::from(realm_bytes);

    let fed_admin = realm.stream_fed_admin();
    let revocation = realm.stream_revocation();
    let label_class = realm.stream_label_class();
    let schema_meta = realm.stream_schema_meta();

    assert_eq!(
        fed_admin.to_string(),
        "327f1f9dda60ed0d0699c2b78d7d7bf3e14f6a1403b2971aea216fc7129d52a2"
    );
    assert_eq!(
        revocation.to_string(),
        "e571cba547e810c9274cdd56361793f93d5de250f589cfc27e9b46b3f0728af8"
    );
    assert_eq!(
        label_class.to_string(),
        "cd1d8a0af4b2e11b7e6b57a694ce4a18c01fa0cef9922a17663f107b43315d0c"
    );
    assert_eq!(
        schema_meta.to_string(),
        "20e9eec16bda9716ffa61fa2b2386eaf4f0be0c54253bffcc37554494b91ba44"
    );
}

#[test]
fn realm_id_derivation_matches_spec() {
    let derived = RealmId::derive("example-app");
    let expected = RealmId::from(ht("id/realm", b"example-app"));
    assert_eq!(derived, expected);
}
