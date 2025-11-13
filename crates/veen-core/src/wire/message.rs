use serde::{Deserialize, Serialize};

use crate::{
    label::Label,
    profile::ProfileId,
    wire::types::{AuthRef, ClientId, CtHash, LeafHash, Signature64},
};

/// Wire format version for `MSG` objects.
pub const MSG_VERSION: u64 = 1;

/// VEEN MSG object as defined in section 5 of spec-1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Msg {
    pub ver: u64,
    pub profile_id: ProfileId,
    pub label: Label,
    pub client_id: ClientId,
    pub client_seq: u64,
    pub prev_ack: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_ref: Option<AuthRef>,
    pub ct_hash: CtHash,
    pub ciphertext: Vec<u8>,
    pub sig: Signature64,
}

impl Msg {
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
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;
    use crate::hash::ht;

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
        let expected = LeafHash::new(ht("veen/leaf", &data));

        assert_eq!(msg.leaf_hash(), expected);
        assert_eq!(msg.msg_id(), expected);
    }
}
