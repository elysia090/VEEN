use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use veen_core::wire::message::MSG_VERSION;
use veen_core::{
    cap_stream_id_from_label, AuthRef, ClientId, CtHash, Label, Msg, Profile, Signature64,
    CIPHERTEXT_LEN_PREFIX, HPKE_ENC_LEN, MAX_MSG_BYTES,
};
use veen_hub::pipeline::{StreamResponse, SubmitRequest, SubmitResponse};

pub const DATA_PLANE_VERSION: u64 = 1;

pub struct SubmitRequestCbor<'a> {
    pub stream: &'a str,
    pub client_id: &'a str,
    pub msg: &'a str,
    pub attachments: Option<&'a [veen_hub::pipeline::AttachmentUpload]>,
    pub auth_ref: Option<&'a str>,
    pub idem: Option<u64>,
    pub pow_cookie: Option<&'a veen_hub::pipeline::PowCookieEnvelope>,
}

#[allow(dead_code)]
pub struct StreamRequestCbor<'a> {
    pub stream: &'a str,
    pub from: u64,
    pub to: Option<u64>,
    pub with_receipts: bool,
    pub with_mmr_proof: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ClientSecretBundle {
    #[serde(with = "serde_bytes")]
    signing_key: ByteBuf,
}

#[allow(dead_code)]
pub fn read_signing_key(client_dir: &Path) -> Result<SigningKey> {
    let path = client_dir.join("keystore.enc");
    let file = std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let bundle: ClientSecretBundle = ciborium::de::from_reader(file)
        .with_context(|| format!("decoding client keystore {}", path.display()))?;
    let signing_key_bytes: [u8; 32] = bundle
        .signing_key
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("invalid signing key length"))?;
    Ok(SigningKey::from_bytes(&signing_key_bytes))
}

pub fn encode_submit_request_cbor(request: &SubmitRequest) -> Result<Vec<u8>> {
    let payload = SubmitRequestCbor {
        stream: &request.stream,
        client_id: &request.client_id,
        msg: &request.msg,
        attachments: request.attachments.as_deref(),
        auth_ref: request.auth_ref.as_deref(),
        idem: request.idem,
        pow_cookie: request.pow_cookie.as_ref(),
    };
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded).context("encoding submit request")?;
    Ok(encoded)
}

pub fn decode_submit_response_cbor(body: &[u8]) -> Result<SubmitResponse> {
    let mut cursor = std::io::Cursor::new(body);
    ciborium::de::from_reader(&mut cursor).context("decoding submit response")
}

#[allow(dead_code)]
pub fn encode_stream_request_cbor(
    stream: &str,
    from: u64,
    to: Option<u64>,
    with_proof: bool,
) -> Result<Vec<u8>> {
    let payload = StreamRequestCbor {
        stream,
        from,
        to,
        with_receipts: with_proof,
        with_mmr_proof: with_proof,
    };
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded).context("encoding stream request")?;
    Ok(encoded)
}

#[allow(dead_code)]
pub fn decode_stream_response_cbor(body: &[u8]) -> Result<StreamResponse> {
    let mut cursor = std::io::Cursor::new(body);
    ciborium::de::from_reader(&mut cursor).context("decoding stream response")
}

pub fn encode_submit_msg(
    stream: &str,
    client_signing: &SigningKey,
    client_seq: u64,
    prev_ack: u64,
    auth_ref_hex: Option<&str>,
    payload: &[u8],
) -> Result<String> {
    let msg = build_msg(
        stream,
        client_signing,
        client_seq,
        prev_ack,
        auth_ref_hex,
        payload,
    )?;
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&msg, &mut encoded).context("encoding submit msg")?;
    Ok(BASE64_STANDARD.encode(encoded))
}

pub fn client_id_hex(client_signing: &SigningKey) -> String {
    let client_id = ClientId::from(*client_signing.verifying_key().as_bytes());
    hex::encode(client_id.as_ref())
}

fn build_msg(
    stream: &str,
    client_signing: &SigningKey,
    client_seq: u64,
    prev_ack: u64,
    auth_ref_hex: Option<&str>,
    payload: &[u8],
) -> Result<Msg> {
    let label = derive_label_for_stream(stream)?;
    let profile_id = Profile::default()
        .id()
        .context("computing profile id for msg")?;
    let client_id = ClientId::from(*client_signing.verifying_key().as_bytes());
    let auth_ref = auth_ref_hex
        .map(AuthRef::from_str)
        .transpose()
        .context("parsing auth_ref")?;
    let ciphertext = build_ciphertext_envelope(&[], payload, 256)?;
    if ciphertext.len() > MAX_MSG_BYTES {
        return Err(anyhow!(
            "ciphertext length {} exceeds limit {}",
            ciphertext.len(),
            MAX_MSG_BYTES
        ));
    }
    let ct_hash = CtHash::compute(&ciphertext);
    let mut msg = Msg {
        ver: MSG_VERSION,
        profile_id,
        label,
        client_id,
        client_seq,
        prev_ack,
        auth_ref,
        ct_hash,
        ciphertext,
        sig: Signature64::new([0u8; 64]),
    };
    let digest = msg
        .signing_tagged_hash()
        .context("computing signing digest for msg")?;
    let signature = client_signing.sign(digest.as_ref());
    msg.sig = Signature64::from(signature.to_bytes());
    Ok(msg)
}

fn derive_label_for_stream(stream: &str) -> Result<Label> {
    let stream_id = cap_stream_id_from_label(stream)
        .with_context(|| format!("deriving stream identifier for {}", stream))?;
    Ok(Label::derive([], stream_id, 0))
}

fn build_ciphertext_envelope(header: &[u8], body: &[u8], pad_block: u64) -> Result<Vec<u8>> {
    if header.len() > u32::MAX as usize || body.len() > u32::MAX as usize {
        return Err(anyhow!("ciphertext lengths overflow u32"));
    }
    let mut ciphertext =
        Vec::with_capacity(HPKE_ENC_LEN + CIPHERTEXT_LEN_PREFIX + header.len() + body.len());
    ciphertext.extend_from_slice(&[0u8; HPKE_ENC_LEN]);
    ciphertext.extend_from_slice(&(header.len() as u32).to_be_bytes());
    ciphertext.extend_from_slice(&(body.len() as u32).to_be_bytes());
    ciphertext.extend_from_slice(header);
    ciphertext.extend_from_slice(body);
    if pad_block > 0 {
        let pad_block = usize::try_from(pad_block)
            .map_err(|_| anyhow!("invalid pad_block size {pad_block}"))?;
        if pad_block == 0 {
            return Err(anyhow!("pad_block must be non-zero when enabled"));
        }
        let remainder = ciphertext.len() % pad_block;
        if remainder != 0 {
            let padding = pad_block - remainder;
            ciphertext.extend(std::iter::repeat_n(0u8, padding));
        }
    }
    Ok(ciphertext)
}

impl Serialize for SubmitRequestCbor<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry(&1u64, &DATA_PLANE_VERSION)?;
        map.serialize_entry(&2u64, &self.msg)?;
        map.serialize_entry(&3u64, &self.stream)?;
        map.serialize_entry(&4u64, &self.client_id)?;
        if let Some(attachments) = self.attachments {
            map.serialize_entry(&5u64, attachments)?;
        }
        if let Some(auth_ref) = self.auth_ref {
            map.serialize_entry(&6u64, auth_ref)?;
        }
        if let Some(idem) = self.idem {
            map.serialize_entry(&7u64, &idem)?;
        }
        if let Some(pow_cookie) = self.pow_cookie {
            map.serialize_entry(&8u64, pow_cookie)?;
        }
        map.end()
    }
}

impl Serialize for StreamRequestCbor<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry(&1u64, &DATA_PLANE_VERSION)?;
        map.serialize_entry(&2u64, &self.stream)?;
        map.serialize_entry(&3u64, &self.from)?;
        if let Some(to) = self.to {
            map.serialize_entry(&4u64, &to)?;
        }
        map.serialize_entry(&7u64, &self.with_receipts)?;
        map.serialize_entry(&8u64, &self.with_mmr_proof)?;
        map.end()
    }
}
