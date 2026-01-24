use std::io::{self, Cursor};

use ed25519_dalek::Signer;
use ed25519_dalek::{Signature as DalekSignature, SigningKey};
use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    hash::ht,
    label::StreamId,
    limits::MAX_CAP_CHAIN,
    wire::types::{AuthRef, ClientId, Signature64, SignatureVerifyError, HASH_LEN},
    LengthError,
};
use hex::FromHexError;

/// Current capability token version defined by the VEEN specification.
pub const CAP_TOKEN_VERSION: u64 = 1;

/// Token bucket configuration embedded inside a capability allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapTokenRate {
    pub per_sec: u64,
    pub burst: u64,
}

/// Capability allowance describing the streams, TTL, and optional rate limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapTokenAllow {
    pub stream_ids: Vec<StreamId>,
    pub ttl: u64,
    pub rate: Option<CapTokenRate>,
}

/// Capability token as defined in section 11 of `doc/spec.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    #[error("capability token stream_ids must be non-empty and sorted")]
    InvalidStreamIds,
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
    #[error("capability token stream_ids must be non-empty and sorted")]
    InvalidStreamIds,
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
        if !stream_ids_sorted(&allow.stream_ids) {
            return Err(CapTokenIssueError::InvalidStreamIds);
        }
        let issuer_pk = ClientId::from(issuer.verifying_key().to_bytes());
        let mut token = Self {
            ver: CAP_TOKEN_VERSION,
            issuer_pk,
            subject_pk,
            allow,
            sig_chain: Vec::new(),
        };
        let signable_bytes = signable_cbor(&token)?;
        let digest = link_digest_from_signable(&signable_bytes, &[0u8; 64]);
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
        if !stream_ids_sorted(&self.allow.stream_ids) {
            return Err(CapTokenVerifyError::InvalidStreamIds);
        }
        if self.sig_chain.is_empty() {
            return Err(CapTokenVerifyError::EmptyChain);
        }
        if self.sig_chain.len() > MAX_CAP_CHAIN {
            return Err(CapTokenVerifyError::ChainTooLong {
                len: self.sig_chain.len(),
                max: MAX_CAP_CHAIN,
            });
        }
        let signable_bytes = signable_cbor(self)?;
        let mut prev_sig = [0u8; 64];
        for (index, signature) in self.sig_chain.iter().enumerate() {
            let digest = link_digest_from_signable(&signable_bytes, &prev_sig);
            if let Err(source) = signature.verify(self.issuer_pk.as_bytes(), digest.as_ref()) {
                return Err(CapTokenVerifyError::Signature { index, source });
            }
            prev_sig.copy_from_slice(signature.as_ref());
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

fn signable_cbor(token: &CapToken) -> Result<Vec<u8>, CapTokenEncodeError> {
    let mut buf = Vec::new();
    let signable = CapTokenSignable {
        ver: token.ver,
        issuer_pk: &token.issuer_pk,
        subject_pk: &token.subject_pk,
        allow: &token.allow,
    };
    ciborium::ser::into_writer(&signable, &mut buf)?;
    Ok(buf)
}

fn link_digest_from_signable(signable_bytes: &[u8], prev_sig: &[u8; 64]) -> [u8; HASH_LEN] {
    let mut data = Vec::with_capacity(signable_bytes.len() + prev_sig.len());
    data.extend_from_slice(signable_bytes);
    data.extend_from_slice(prev_sig);
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

fn stream_ids_sorted(stream_ids: &[StreamId]) -> bool {
    if stream_ids.is_empty() {
        return false;
    }
    for window in stream_ids.windows(2) {
        let prev = window[0].as_ref();
        let next = window[1].as_ref();
        if prev >= next {
            return false;
        }
    }
    true
}

struct CapTokenRateVisitor;

impl<'de> Visitor<'de> for CapTokenRateVisitor {
    type Value = CapTokenRate;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("capability rate map with integer keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut per_sec: Option<u64> = None;
        let mut burst: Option<u64> = None;

        while let Some(key) = map.next_key::<u64>()? {
            match key {
                1 => {
                    if per_sec.is_some() {
                        return Err(DeError::duplicate_field("per_sec"));
                    }
                    per_sec = Some(map.next_value()?);
                }
                2 => {
                    if burst.is_some() {
                        return Err(DeError::duplicate_field("burst"));
                    }
                    burst = Some(map.next_value()?);
                }
                _ => {
                    return Err(DeError::custom(format!(
                        "unknown capability rate key: {key}"
                    )));
                }
            }
        }

        let per_sec = per_sec.ok_or_else(|| DeError::missing_field("per_sec"))?;
        let burst = burst.ok_or_else(|| DeError::missing_field("burst"))?;
        Ok(CapTokenRate { per_sec, burst })
    }
}

impl Serialize for CapTokenRate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(&1u64, &self.per_sec)?;
        map.serialize_entry(&2u64, &self.burst)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for CapTokenRate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CapTokenRateVisitor)
    }
}

struct CapTokenAllowVisitor;

impl<'de> Visitor<'de> for CapTokenAllowVisitor {
    type Value = CapTokenAllow;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("capability allow map with integer keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut stream_ids: Option<Vec<StreamId>> = None;
        let mut ttl: Option<u64> = None;
        let mut rate: Option<CapTokenRate> = None;

        while let Some(key) = map.next_key::<u64>()? {
            match key {
                1 => {
                    if stream_ids.is_some() {
                        return Err(DeError::duplicate_field("stream_ids"));
                    }
                    stream_ids = Some(map.next_value()?);
                }
                2 => {
                    if ttl.is_some() {
                        return Err(DeError::duplicate_field("ttl"));
                    }
                    ttl = Some(map.next_value()?);
                }
                3 => {
                    if rate.is_some() {
                        return Err(DeError::duplicate_field("rate"));
                    }
                    rate = Some(map.next_value()?);
                }
                _ => {
                    return Err(DeError::custom(format!(
                        "unknown capability allow key: {key}"
                    )));
                }
            }
        }

        let stream_ids = stream_ids.ok_or_else(|| DeError::missing_field("stream_ids"))?;
        let ttl = ttl.ok_or_else(|| DeError::missing_field("ttl"))?;
        if !stream_ids_sorted(&stream_ids) {
            return Err(DeError::custom(
                "capability allow stream_ids must be non-empty and sorted",
            ));
        }

        Ok(CapTokenAllow {
            stream_ids,
            ttl,
            rate,
        })
    }
}

impl Serialize for CapTokenAllow {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(if self.rate.is_some() { 3 } else { 2 }))?;
        map.serialize_entry(&1u64, &self.stream_ids)?;
        map.serialize_entry(&2u64, &self.ttl)?;
        if let Some(rate) = &self.rate {
            map.serialize_entry(&3u64, rate)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for CapTokenAllow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CapTokenAllowVisitor)
    }
}

struct CapTokenVisitor;

impl<'de> Visitor<'de> for CapTokenVisitor {
    type Value = CapToken;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("capability token map with integer keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut ver: Option<u64> = None;
        let mut issuer_pk: Option<ClientId> = None;
        let mut subject_pk: Option<ClientId> = None;
        let mut allow: Option<CapTokenAllow> = None;
        let mut sig_chain: Option<Vec<Signature64>> = None;

        while let Some(key) = map.next_key::<u64>()? {
            match key {
                1 => {
                    if ver.is_some() {
                        return Err(DeError::duplicate_field("ver"));
                    }
                    ver = Some(map.next_value()?);
                }
                2 => {
                    if issuer_pk.is_some() {
                        return Err(DeError::duplicate_field("issuer_pk"));
                    }
                    issuer_pk = Some(map.next_value()?);
                }
                3 => {
                    if subject_pk.is_some() {
                        return Err(DeError::duplicate_field("subject_pk"));
                    }
                    subject_pk = Some(map.next_value()?);
                }
                4 => {
                    if allow.is_some() {
                        return Err(DeError::duplicate_field("allow"));
                    }
                    allow = Some(map.next_value()?);
                }
                5 => {
                    if sig_chain.is_some() {
                        return Err(DeError::duplicate_field("sig_chain"));
                    }
                    sig_chain = Some(map.next_value()?);
                }
                _ => {
                    return Err(DeError::custom(format!(
                        "unknown capability token key: {key}"
                    )));
                }
            }
        }

        let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
        let issuer_pk = issuer_pk.ok_or_else(|| DeError::missing_field("issuer_pk"))?;
        let subject_pk = subject_pk.ok_or_else(|| DeError::missing_field("subject_pk"))?;
        let allow = allow.ok_or_else(|| DeError::missing_field("allow"))?;
        let sig_chain = sig_chain.ok_or_else(|| DeError::missing_field("sig_chain"))?;

        Ok(CapToken {
            ver,
            issuer_pk,
            subject_pk,
            allow,
            sig_chain,
        })
    }
}

impl Serialize for CapToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry(&1u64, &self.ver)?;
        map.serialize_entry(&2u64, &self.issuer_pk)?;
        map.serialize_entry(&3u64, &self.subject_pk)?;
        map.serialize_entry(&4u64, &self.allow)?;
        map.serialize_entry(&5u64, &self.sig_chain)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for CapToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(CapTokenVisitor)
    }
}

struct CapTokenSignable<'a> {
    ver: u64,
    issuer_pk: &'a ClientId,
    subject_pk: &'a ClientId,
    allow: &'a CapTokenAllow,
}

impl Serialize for CapTokenSignable<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&1u64, &self.ver)?;
        map.serialize_entry(&2u64, &self.issuer_pk)?;
        map.serialize_entry(&3u64, &self.subject_pk)?;
        map.serialize_entry(&4u64, &self.allow)?;
        map.end()
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
    fn issue_rejects_unsorted_stream_ids() {
        let issuer = sample_signing_key(0x40);
        let subject = ClientId::from([0x55u8; HASH_LEN]);
        let stream_a = sample_stream_id(0x11);
        let stream_b = sample_stream_id(0x22);
        let (first, second) = if stream_a.as_ref() < stream_b.as_ref() {
            (stream_b, stream_a)
        } else {
            (stream_a, stream_b)
        };
        let allow = CapTokenAllow::new(vec![first, second], 900);

        match CapToken::issue(&issuer, subject, allow) {
            Err(CapTokenIssueError::InvalidStreamIds) => {}
            other => panic!("unexpected issuance result: {other:?}"),
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
