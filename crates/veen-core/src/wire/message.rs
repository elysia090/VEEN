use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::{ByteBuf, Bytes};
use thiserror::Error;

use crate::{
    label::Label,
    profile::ProfileId,
    wire::{
        cbor::{seq_next_required, seq_no_trailing},
        derivation::{hash_tagged, TAG_NONCE, TAG_SIG},
        types::{
            truncate_nonce, AuthRef, ClientId, CtHash, LeafHash, Signature64, SignatureVerifyError,
            AEAD_NONCE_LEN,
        },
        CborError,
    },
};

use super::signing::{serialize_signable, tagged_hash};

/// Wire format version for `MSG` objects.
pub const MSG_VERSION: u64 = 1;

/// VEEN MSG object as defined in section 4.1 of spec-1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msg {
    pub ver: u64,
    pub profile_id: ProfileId,
    pub label: Label,
    pub client_id: ClientId,
    pub client_seq: u64,
    pub prev_ack: u64,
    pub auth_ref: Option<AuthRef>,
    pub ct_hash: CtHash,
    pub ciphertext: Vec<u8>,
    pub sig: Signature64,
}

/// Errors produced when verifying `MSG.sig` against the embedded client_id.
#[derive(Debug, Error)]
pub enum MsgVerifyError {
    /// Failed to serialize the signable view using deterministic CBOR.
    #[error("failed to compute signing digest: {0}")]
    Signing(#[from] CborError),
    /// Signature verification failure (invalid key, encoding, or mismatch).
    #[error(transparent)]
    Signature(#[from] SignatureVerifyError),
}

#[derive(Debug)]
struct MsgSignable<'a> {
    ver: u64,
    profile_id: &'a ProfileId,
    label: &'a Label,
    client_id: &'a ClientId,
    client_seq: u64,
    prev_ack: u64,
    auth_ref: Option<&'a AuthRef>,
    ct_hash: &'a CtHash,
    ciphertext: &'a Bytes,
}

impl<'a> From<&'a Msg> for MsgSignable<'a> {
    fn from(value: &'a Msg) -> Self {
        Self {
            ver: value.ver,
            profile_id: &value.profile_id,
            label: &value.label,
            client_id: &value.client_id,
            client_seq: value.client_seq,
            prev_ack: value.prev_ack,
            auth_ref: value.auth_ref.as_ref(),
            ct_hash: &value.ct_hash,
            ciphertext: Bytes::new(&value.ciphertext),
        }
    }
}

impl Serialize for MsgSignable<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(9))?;
        seq.serialize_element(&self.ver)?;
        seq.serialize_element(&self.profile_id)?;
        seq.serialize_element(&self.label)?;
        seq.serialize_element(&self.client_id)?;
        seq.serialize_element(&self.client_seq)?;
        seq.serialize_element(&self.prev_ack)?;
        seq.serialize_element(&self.auth_ref)?;
        seq.serialize_element(&self.ct_hash)?;
        seq.serialize_element(self.ciphertext)?;
        seq.end()
    }
}

impl Serialize for Msg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(10))?;
        seq.serialize_element(&self.ver)?;
        seq.serialize_element(&self.profile_id)?;
        seq.serialize_element(&self.label)?;
        seq.serialize_element(&self.client_id)?;
        seq.serialize_element(&self.client_seq)?;
        seq.serialize_element(&self.prev_ack)?;
        seq.serialize_element(&self.auth_ref.as_ref())?;
        seq.serialize_element(&self.ct_hash)?;
        seq.serialize_element(&Bytes::new(&self.ciphertext))?;
        seq.serialize_element(&self.sig)?;
        seq.end()
    }
}

struct MsgVisitor;

impl<'de> Visitor<'de> for MsgVisitor {
    type Value = Msg;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VEEN MSG array with 10 elements")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let expecting = "VEEN MSG array with 10 elements";
        let ver = seq_next_required(&mut seq, 0, expecting)?;
        let profile_id = seq_next_required(&mut seq, 1, expecting)?;
        let label = seq_next_required(&mut seq, 2, expecting)?;
        let client_id = seq_next_required(&mut seq, 3, expecting)?;
        let client_seq = seq_next_required(&mut seq, 4, expecting)?;
        let prev_ack = seq_next_required(&mut seq, 5, expecting)?;
        let auth_ref: Option<AuthRef> = seq_next_required(&mut seq, 6, expecting)?;
        let ct_hash = seq_next_required(&mut seq, 7, expecting)?;
        let ciphertext: ByteBuf = seq_next_required(&mut seq, 8, expecting)?;
        let sig = seq_next_required(&mut seq, 9, expecting)?;
        seq_no_trailing(&mut seq, 10, expecting)?;

        Ok(Msg {
            ver,
            profile_id,
            label,
            client_id,
            client_seq,
            prev_ack,
            auth_ref,
            ct_hash,
            ciphertext: ciphertext.into_vec(),
            sig,
        })
    }
}

impl<'de> Deserialize<'de> for Msg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(MsgVisitor)
    }
}

impl Msg {
    /// Derives the AEAD nonce `Trunc_24(Ht("veen/nonce", …))` defined by the specification.
    #[must_use]
    pub fn derive_body_nonce(
        label: &Label,
        prev_ack: u64,
        client_id: &ClientId,
        client_seq: u64,
    ) -> [u8; AEAD_NONCE_LEN] {
        let mut data = [0u8; 80];
        let mut offset = 0;
        data[offset..offset + 32].copy_from_slice(label.as_ref());
        offset += 32;
        data[offset..offset + 8].copy_from_slice(&prev_ack.to_be_bytes());
        offset += 8;
        data[offset..offset + 32].copy_from_slice(client_id.as_ref());
        offset += 32;
        data[offset..offset + 8].copy_from_slice(&client_seq.to_be_bytes());

        truncate_nonce(hash_tagged(TAG_NONCE, &data))
    }

    /// Returns the AEAD nonce derived from the message fields.
    #[must_use]
    pub fn body_nonce(&self) -> [u8; AEAD_NONCE_LEN] {
        Self::derive_body_nonce(&self.label, self.prev_ack, &self.client_id, self.client_seq)
    }

    /// Returns `true` if the message declares the canonical wire version.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.ver == MSG_VERSION
    }

    /// Computes the canonical ciphertext hash from the stored ciphertext.
    #[must_use]
    pub fn computed_ct_hash(&self) -> CtHash {
        CtHash::compute(&self.ciphertext)
    }

    /// Returns `true` if `ct_hash` matches `H(ciphertext)`.
    #[must_use]
    pub fn ct_hash_matches(&self) -> bool {
        self.ct_hash == self.computed_ct_hash()
    }

    /// Computes the canonical leaf hash `Ht("veen/leaf", …)` defined by the specification.
    #[must_use]
    pub fn leaf_hash(&self) -> LeafHash {
        LeafHash::derive(
            &self.label,
            &self.profile_id,
            &self.ct_hash,
            &self.client_id,
            self.client_seq,
        )
    }

    /// Returns the message identifier, which is equal to `leaf_hash`.
    #[must_use]
    pub fn msg_id(&self) -> LeafHash {
        self.leaf_hash()
    }

    /// Serializes the message without the signature field using the canonical
    /// deterministic CBOR ordering required by spec-1.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CborError> {
        serialize_signable(&MsgSignable::from(self))
    }

    /// Computes the domain separated hash `Ht("veen/sig", …)` used for
    /// Ed25519 signatures over `MSG` objects.
    pub fn signing_tagged_hash(&self) -> Result<[u8; 32], CborError> {
        tagged_hash(TAG_SIG, &MsgSignable::from(self))
    }

    /// Verifies `MSG.sig` using the embedded `client_id` and signing digest.
    pub fn verify_signature(&self) -> Result<(), MsgVerifyError> {
        let digest = self.signing_tagged_hash()?;
        self.sig
            .verify(self.client_id.as_bytes(), digest.as_ref())
            .map_err(MsgVerifyError::from)
    }
}

#[cfg(test)]
mod tests {
    use ciborium::value::Value;
    use ed25519_dalek::{Signer, SigningKey};
    use hex::FromHex;

    use super::*;
    use crate::wire::derivation::{hash_tagged, TAG_LEAF, TAG_NONCE, TAG_SIG};

    #[test]
    fn msg_version_matches_spec() {
        let msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x11; 32]).unwrap(),
            label: Label::from_slice(&[0x22; 32]).unwrap(),
            client_id: ClientId::new([0x33; 32]),
            client_seq: 7,
            prev_ack: 4,
            auth_ref: None,
            ct_hash: CtHash::new([0x44; 32]),
            ciphertext: vec![0xAA; 16],
            sig: Signature64::new([0x55; 64]),
        };
        assert!(msg.has_valid_version());
    }

    #[test]
    fn ciphertext_hash_matches_sha256() {
        let mut msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x11; 32]).unwrap(),
            label: Label::from_slice(&[0x22; 32]).unwrap(),
            client_id: ClientId::new([0x33; 32]),
            client_seq: 1,
            prev_ack: 0,
            auth_ref: None,
            ct_hash: CtHash::new([0u8; 32]),
            ciphertext: b"ciphertext".to_vec(),
            sig: Signature64::new([0x55; 64]),
        };

        let computed = msg.computed_ct_hash();
        msg.ct_hash = computed;
        assert!(msg.ct_hash_matches());
    }

    #[test]
    fn leaf_hash_matches_manual_derivation() {
        let profile_id = ProfileId::from_slice(
            &<[u8; 32]>::from_hex(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            )
            .unwrap(),
        )
        .unwrap();
        let label = Label::from_slice(
            &<[u8; 32]>::from_hex(
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            )
            .unwrap(),
        )
        .unwrap();
        let client_id = ClientId::new(
            <[u8; 32]>::from_hex(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            )
            .unwrap(),
        );
        let ct_hash = CtHash::new(
            <[u8; 32]>::from_hex(
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
            )
            .unwrap(),
        );
        let client_seq = 42u64;

        let msg = Msg {
            ver: MSG_VERSION,
            profile_id,
            label,
            client_id,
            client_seq,
            prev_ack: 0,
            auth_ref: None,
            ct_hash,
            ciphertext: Vec::new(),
            sig: Signature64::new([0xFF; 64]),
        };

        let mut data = Vec::new();
        data.extend_from_slice(label.as_ref());
        data.extend_from_slice(profile_id.as_ref());
        data.extend_from_slice(ct_hash.as_ref());
        data.extend_from_slice(client_id.as_ref());
        data.extend_from_slice(&client_seq.to_be_bytes());
        let expected = LeafHash::new(hash_tagged(TAG_LEAF, &data));

        assert_eq!(msg.leaf_hash(), expected);
        assert_eq!(msg.msg_id(), expected);
    }

    #[test]
    fn signing_tagged_hash_matches_manual_encoding() {
        let msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x01; 32]).unwrap(),
            label: Label::from_slice(&[0x02; 32]).unwrap(),
            client_id: ClientId::new([0x03; 32]),
            client_seq: 9,
            prev_ack: 8,
            auth_ref: Some(AuthRef::from_slice(&[0x04; 32]).unwrap()),
            ct_hash: CtHash::new([0x05; 32]),
            ciphertext: vec![0xAA, 0xBB, 0xCC],
            sig: Signature64::new([0x06; 64]),
        };

        let view = MsgSignable::from(&msg);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&view, &mut buf).unwrap();
        let expected = hash_tagged(TAG_SIG, &buf);

        let computed = msg.signing_tagged_hash().unwrap();
        assert_eq!(computed.as_slice(), expected);
    }

    #[test]
    fn body_nonce_matches_spec_formula() {
        let msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x01; 32]).unwrap(),
            label: Label::from_slice(&[0x02; 32]).unwrap(),
            client_id: ClientId::new([0x03; 32]),
            client_seq: 9,
            prev_ack: 4,
            auth_ref: None,
            ct_hash: CtHash::new([0x04; 32]),
            ciphertext: vec![0xAA; 8],
            sig: Signature64::new([0x05; 64]),
        };

        let mut data = Vec::new();
        data.extend_from_slice(msg.label.as_ref());
        data.extend_from_slice(&msg.prev_ack.to_be_bytes());
        data.extend_from_slice(msg.client_id.as_ref());
        data.extend_from_slice(&msg.client_seq.to_be_bytes());
        let digest = hash_tagged(TAG_NONCE, &data);

        let mut expected = [0u8; AEAD_NONCE_LEN];
        expected.copy_from_slice(&digest[..AEAD_NONCE_LEN]);

        assert_eq!(msg.body_nonce(), expected);
        assert_eq!(
            Msg::derive_body_nonce(&msg.label, msg.prev_ack, &msg.client_id, msg.client_seq),
            expected
        );
    }

    #[test]
    fn ciphertext_serializes_as_cbor_bstr() {
        let msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x10; 32]).unwrap(),
            label: Label::from_slice(&[0x11; 32]).unwrap(),
            client_id: ClientId::new([0x12; 32]),
            client_seq: 1,
            prev_ack: 0,
            auth_ref: None,
            ct_hash: CtHash::new([0x13; 32]),
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            sig: Signature64::new([0x14; 64]),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&msg, &mut buf).unwrap();
        let value: Value = ciborium::de::from_reader(buf.as_slice()).unwrap();

        let array = match value {
            Value::Array(entries) => entries,
            _ => panic!("expected array"),
        };

        let ciphertext_value = array.get(8).expect("ciphertext entry at index 8");

        assert!(matches!(ciphertext_value, Value::Bytes(_)));
    }

    #[test]
    fn msg_serializes_as_cbor_array_with_null_auth_ref() {
        let msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x20; 32]).unwrap(),
            label: Label::from_slice(&[0x21; 32]).unwrap(),
            client_id: ClientId::new([0x22; 32]),
            client_seq: 2,
            prev_ack: 1,
            auth_ref: None,
            ct_hash: CtHash::new([0x23; 32]),
            ciphertext: vec![0xAA, 0xBB],
            sig: Signature64::new([0x24; 64]),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&msg, &mut buf).unwrap();
        let value: Value = ciborium::de::from_reader(buf.as_slice()).unwrap();

        let array = match value {
            Value::Array(entries) => entries,
            _ => panic!("expected array"),
        };

        assert_eq!(array.len(), 10);
        assert!(matches!(array.get(6), Some(Value::Null)));
    }

    #[test]
    fn verify_signature_accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let client_id = ClientId::from(*signing_key.verifying_key().as_bytes());

        let mut msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x01; 32]).unwrap(),
            label: Label::from_slice(&[0x02; 32]).unwrap(),
            client_id,
            client_seq: 5,
            prev_ack: 3,
            auth_ref: None,
            ct_hash: CtHash::new([0xAA; 32]),
            ciphertext: vec![0x10, 0x20],
            sig: Signature64::new([0u8; 64]),
        };

        let digest = msg.signing_tagged_hash().unwrap();
        let signature = signing_key.sign(digest.as_ref());
        msg.sig = Signature64::from(signature.to_bytes());

        assert!(msg.verify_signature().is_ok());
    }

    #[test]
    fn verify_signature_rejects_invalid_signature() {
        let signing_key = SigningKey::from_bytes(&[0x24; 32]);
        let client_id = ClientId::from(*signing_key.verifying_key().as_bytes());

        let mut msg = Msg {
            ver: MSG_VERSION,
            profile_id: ProfileId::from_slice(&[0x05; 32]).unwrap(),
            label: Label::from_slice(&[0x06; 32]).unwrap(),
            client_id,
            client_seq: 8,
            prev_ack: 7,
            auth_ref: None,
            ct_hash: CtHash::new([0xBB; 32]),
            ciphertext: vec![0x30, 0x40],
            sig: Signature64::new([0u8; 64]),
        };

        let digest = msg.signing_tagged_hash().unwrap();
        let signature = signing_key.sign(digest.as_ref());
        let mut bytes = signature.to_bytes();
        bytes[0] ^= 0xFF;
        msg.sig = Signature64::from(bytes);

        assert!(matches!(
            msg.verify_signature(),
            Err(MsgVerifyError::Signature(
                SignatureVerifyError::VerificationFailed(_)
            ))
        ));
    }
}
