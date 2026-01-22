use std::io::{self, Cursor};

use ed25519_dalek::Signer;
use ed25519_dalek::{Signature as DalekSignature, SigningKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    hash::{h, ht},
    label::StreamId,
    limits::MAX_CAP_CHAIN,
    wire::types::{AuthRef, ClientId, Signature64, SignatureVerifyError, HASH_LEN},
    LengthError,
};
use hex::FromHexError;

/// Current capability token version defined by the VEEN specification.
pub const CAP_TOKEN_VERSION: u64 = 1;

/// Token bucket configuration embedded inside a capability allowance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapTokenRate {
    pub per_sec: u64,
    pub burst: u64,
}

/// Capability allowance describing the streams, TTL, and optional rate limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapTokenAllow {
    pub stream_ids: Vec<StreamId>,
    pub ttl: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<CapTokenRate>,
}

/// Capability token as defined in section 11 of `doc/spec.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapToken {
    pub ver: u64,
    pub issuer_pk: ClientId,
    pub subject_pk: ClientId,
    pub allow: CapTokenAllow,
    pub sig_chain: Vec<Signature64>,
}

type CborError = ciborium::ser::Error<io::Error>;

type CborDecodeError = ciborium::de::Error<std::io::Error>;

/// Errors produced when serialising capability tokens.
#[derive(Debug, Error)]
pub enum CapTokenEncodeError {
    #[error("failed to encode capability token using deterministic CBOR: {0}")]
    Cbor(#[from] CborError),
}

/// Errors produced when decoding capability tokens from CBOR.
#[derive(Debug, Error)]
pub enum CapTokenDecodeError {
    #[error("failed to decode capability token from CBOR: {0}")]
    Cbor(#[from] CborDecodeError),
}

/// Errors produced when verifying capability token signature chains.
#[derive(Debug, Error)]
pub enum CapTokenVerifyError {
    #[error("capability token signature chain is empty")]
    EmptyChain,
    #[error("capability token signature chain exceeds limit ({len} > {max})")]
    ChainTooLong { len: usize, max: usize },
    #[error("failed to encode capability token link for verification: {0}")]
    Encoding(#[from] CapTokenEncodeError),
    #[error("capability token signature verification failed at link {index}: {source}")]
    Signature {
        index: usize,
        #[source]
        source: SignatureVerifyError,
    },
}

/// Errors produced when issuing capability tokens.
#[derive(Debug, Error)]
pub enum CapTokenIssueError {
    #[error("failed to encode capability token link for signing: {0}")]
    Encoding(#[from] CapTokenEncodeError),
}

/// Errors produced when parsing stream identifiers for capability tokens.
#[derive(Debug, Error)]
pub enum StreamIdParseError {
    #[error("invalid stream identifier hex: {0}")]
    Hex(#[from] FromHexError),
    #[error("invalid stream identifier length: {0}")]
    Length(#[from] LengthError),
}

impl CapToken {
    /// Issues a new capability token signed by the issuer for the provided subject and allowance.
    pub fn issue(
        issuer: &SigningKey,
        subject_pk: ClientId,
        allow: CapTokenAllow,
    ) -> Result<Self, CapTokenIssueError> {
        let issuer_pk = ClientId::from(issuer.verifying_key().to_bytes());
        let allow_bytes = allow_cbor(&allow)?;
        let mut token = Self {
            ver: CAP_TOKEN_VERSION,
            issuer_pk,
            subject_pk,
            allow,
            sig_chain: Vec::new(),
        };
        let digest = link_digest_from_allow_bytes(
            token.issuer_pk.as_bytes(),
            token.subject_pk.as_bytes(),
            &allow_bytes,
            &[0u8; HASH_LEN],
        );
        let signature: DalekSignature = issuer.sign(digest.as_ref());
        token
            .sig_chain
            .push(Signature64::from(signature.to_bytes()));
        Ok(token)
    }

    /// Serialises the capability token using deterministic CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CapTokenEncodeError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Computes the capability authorization reference `Ht("veen/cap", CBOR(cap_token))`.
    pub fn auth_ref(&self) -> Result<AuthRef, CapTokenEncodeError> {
        let encoded = self.to_cbor()?;
        Ok(AuthRef::from(ht("veen/cap", &encoded)))
    }

    /// Verifies the capability token signature chain using the embedded issuer key.
    pub fn verify(&self) -> Result<(), CapTokenVerifyError> {
        if self.sig_chain.is_empty() {
            return Err(CapTokenVerifyError::EmptyChain);
        }
        if self.sig_chain.len() > MAX_CAP_CHAIN {
            return Err(CapTokenVerifyError::ChainTooLong {
                len: self.sig_chain.len(),
                max: MAX_CAP_CHAIN,
            });
        }
        let allow_bytes = allow_cbor(&self.allow)?;
        let mut prev_hash = [0u8; HASH_LEN];
        for (index, signature) in self.sig_chain.iter().enumerate() {
            let digest = link_digest_from_allow_bytes(
                self.issuer_pk.as_bytes(),
                self.subject_pk.as_bytes(),
                &allow_bytes,
                &prev_hash,
            );
            if let Err(source) = signature.verify(self.issuer_pk.as_bytes(), digest.as_ref()) {
                return Err(CapTokenVerifyError::Signature { index, source });
            }
            prev_hash = h(signature.as_ref());
        }
        Ok(())
    }
}

impl CapTokenAllow {
    #[must_use]
    pub fn new(stream_ids: Vec<StreamId>, ttl: u64) -> Self {
        Self {
            stream_ids,
            ttl,
            rate: None,
        }
    }
}

impl CapTokenRate {
    #[must_use]
    pub const fn new(per_sec: u64, burst: u64) -> Self {
        Self { per_sec, burst }
    }
}

fn allow_cbor(allow: &CapTokenAllow) -> Result<Vec<u8>, CapTokenEncodeError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(allow, &mut buf)?;
    Ok(buf)
}

fn link_digest_from_allow_bytes(
    issuer_pk: &[u8; HASH_LEN],
    subject_pk: &[u8; HASH_LEN],
    allow_bytes: &[u8],
    prev_link_hash: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    let mut data = Vec::with_capacity(HASH_LEN * 2 + allow_bytes.len() + HASH_LEN);
    data.extend_from_slice(issuer_pk);
    data.extend_from_slice(subject_pk);
    data.extend_from_slice(allow_bytes);
    data.extend_from_slice(prev_link_hash);
    ht("veen/cap-link", &data)
}

/// Decodes a capability token from deterministic CBOR bytes.
pub fn from_cbor(bytes: &[u8]) -> Result<CapToken, CapTokenDecodeError> {
    let mut cursor = Cursor::new(bytes);
    Ok(ciborium::de::from_reader(&mut cursor)?)
}

/// Derives a canonical [`StreamId`] from either a hexadecimal identifier or a human-readable label.
pub fn stream_id_from_label(label: &str) -> Result<StreamId, StreamIdParseError> {
    if label.len() == 64 && label.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(label)?;
        Ok(StreamId::from_slice(&bytes)?)
    } else {
        Ok(StreamId::from(ht("cli/stream", label.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_signing_key(prefix: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = prefix.wrapping_add(index as u8);
        }
        SigningKey::from_bytes(&bytes)
    }

    fn sample_stream_id(tag: u8) -> StreamId {
        let mut bytes = [0u8; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = tag ^ (index as u8);
        }
        StreamId::from(bytes)
    }

    #[test]
    fn round_trip_cbor_and_auth_ref() {
        let issuer = sample_signing_key(0x10);
        let subject = ClientId::from([0x42u8; HASH_LEN]);
        let allow = CapTokenAllow {
            stream_ids: vec![sample_stream_id(0xA5)],
            ttl: 600,
            rate: Some(CapTokenRate::new(5, 10)),
        };

        let token = CapToken::issue(&issuer, subject, allow.clone()).expect("cap token");
        let encoded = token.to_cbor().expect("encode");
        let decoded = from_cbor(&encoded).expect("decode");

        assert_eq!(decoded.ver, CAP_TOKEN_VERSION);
        assert_eq!(decoded.allow, allow);
        assert_eq!(decoded.sig_chain.len(), 1);

        token.verify().expect("verify original");
        decoded.verify().expect("verify decoded");

        let auth_ref_original = token.auth_ref().expect("auth_ref");
        let auth_ref_decoded = decoded.auth_ref().expect("auth_ref decoded");
        assert_eq!(auth_ref_original, auth_ref_decoded);
    }

    #[test]
    fn tampered_signature_chain_rejected() {
        let issuer = sample_signing_key(0x20);
        let subject = ClientId::from([0x24u8; HASH_LEN]);
        let allow = CapTokenAllow::new(vec![sample_stream_id(0x55)], 1200);
        let mut token = CapToken::issue(&issuer, subject, allow).expect("cap token");

        token.verify().expect("verify before tamper");

        let mut sig_bytes = *token.sig_chain[0].as_bytes();
        sig_bytes[0] ^= 0xFF;
        token.sig_chain[0] = Signature64::from(sig_bytes);

        match token.verify() {
            Err(CapTokenVerifyError::Signature { index, .. }) => assert_eq!(index, 0),
            other => panic!("unexpected verification result: {other:?}"),
        }
    }

    #[test]
    fn signature_chain_length_enforced() {
        let issuer = sample_signing_key(0x30);
        let subject = ClientId::from([0x33u8; HASH_LEN]);
        let allow = CapTokenAllow::new(vec![sample_stream_id(0x77)], 3600);
        let mut token = CapToken::issue(&issuer, subject, allow).expect("cap token");

        // Extend the signature chain beyond the allowed limit by cloning the
        // valid signature.  Verification should reject the token before
        // attempting to evaluate the additional signatures.
        let signature = token.sig_chain[0];
        while token.sig_chain.len() <= MAX_CAP_CHAIN {
            token.sig_chain.push(signature);
        }

        match token.verify() {
            Err(CapTokenVerifyError::ChainTooLong { len, max }) => {
                assert_eq!(max, MAX_CAP_CHAIN);
                assert!(len > max);
            }
            other => panic!("unexpected verification result: {other:?}"),
        }
    }

    #[test]
    fn stream_id_from_label_accepts_hex_identifier() {
        let stream = sample_stream_id(0x42);
        let hex = hex::encode(stream.as_ref());
        let parsed = stream_id_from_label(&hex).expect("hex stream id");
        assert_eq!(parsed, stream);

        let upper = hex.to_uppercase();
        let parsed_upper = stream_id_from_label(&upper).expect("uppercase hex stream id");
        assert_eq!(parsed_upper, stream);
    }

    #[test]
    fn stream_id_from_label_derives_from_text_label() {
        let label = "core/main";
        let derived = stream_id_from_label(label).expect("derived stream id");
        let expected = StreamId::from(super::ht("cli/stream", label.as_bytes()));
        assert_eq!(derived, expected);
    }

    #[test]
    fn stream_id_from_label_handles_non_hex_64_char_input() {
        let mut label = hex::encode(sample_stream_id(0x99).as_ref());
        label.replace_range(10..11, "g");

        let derived = stream_id_from_label(&label).expect("derived stream id");
        let expected = StreamId::from(super::ht("cli/stream", label.as_bytes()));
        assert_eq!(derived, expected);
    }
}
