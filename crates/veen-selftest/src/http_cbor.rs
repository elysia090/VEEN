use std::fmt;

use anyhow::{anyhow, Context, Result};
use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

use veen_hub::pipeline::{
    AttachmentUpload, PowCookieEnvelope, StoredAttachment, StoredMessage, StreamMessageWithProof,
    StreamProof, StreamReceipt, SubmitRequest, SubmitResponse,
};

const DATA_PLANE_VERSION: u64 = 1;

pub fn encode_submit_request(request: &SubmitRequest) -> Result<Vec<u8>> {
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

pub fn decode_submit_response(bytes: &[u8]) -> Result<SubmitResponse> {
    let mut cursor = std::io::Cursor::new(bytes);
    let response: SubmitResponseCbor =
        ciborium::de::from_reader(&mut cursor).context("decoding submit response")?;
    if response.ver != DATA_PLANE_VERSION {
        return Err(anyhow!(
            "unexpected submit response version {}",
            response.ver
        ));
    }
    Ok(SubmitResponse {
        stream: response.stream,
        seq: response.seq,
        mmr_root: response.mmr_root,
        stored_attachments: response.stored_attachments,
    })
}

pub fn encode_stream_request(stream: &str, from: u64, to: Option<u64>) -> Result<Vec<u8>> {
    let payload = StreamRequestCbor {
        stream,
        from,
        to,
        with_receipts: true,
        with_mmr_proof: true,
    };
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&payload, &mut encoded).context("encoding stream request")?;
    Ok(encoded)
}

pub fn decode_stream_proofs(bytes: &[u8]) -> Result<Vec<StreamMessageWithProof>> {
    let mut cursor = std::io::Cursor::new(bytes);
    let response: StreamResponseCbor =
        ciborium::de::from_reader(&mut cursor).context("decoding stream response")?;
    if response.ver != DATA_PLANE_VERSION {
        return Err(anyhow!(
            "unexpected stream response version {}",
            response.ver
        ));
    }
    response
        .items
        .into_iter()
        .map(|item| {
            Ok(StreamMessageWithProof {
                message: item.message,
                receipt: item.receipt.ok_or_else(|| {
                    anyhow!(
                        "stream response missing receipt for seq {}",
                        item.stream_seq
                    )
                })?,
                proof: item.proof.ok_or_else(|| {
                    anyhow!("stream response missing proof for seq {}", item.stream_seq)
                })?,
            })
        })
        .collect()
}

struct SubmitRequestCbor<'a> {
    stream: &'a str,
    client_id: &'a str,
    msg: &'a str,
    attachments: Option<&'a [AttachmentUpload]>,
    auth_ref: Option<&'a str>,
    idem: Option<u64>,
    pow_cookie: Option<&'a PowCookieEnvelope>,
}

struct StreamRequestCbor<'a> {
    stream: &'a str,
    from: u64,
    to: Option<u64>,
    with_receipts: bool,
    with_mmr_proof: bool,
}

#[derive(Debug)]
struct SubmitResponseCbor {
    ver: u64,
    stream: String,
    seq: u64,
    mmr_root: String,
    stored_attachments: Vec<StoredAttachment>,
}

#[derive(Debug)]
struct StreamResponseCbor {
    ver: u64,
    stream: String,
    from_seq: u64,
    to_seq: Option<u64>,
    items: Vec<StreamItemCbor>,
}

#[derive(Debug)]
struct StreamItemCbor {
    stream_seq: u64,
    message: StoredMessage,
    receipt: Option<StreamReceipt>,
    proof: Option<StreamProof>,
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

impl<'de> Deserialize<'de> for SubmitResponseCbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SubmitResponseVisitor;

        impl<'de> Visitor<'de> for SubmitResponseVisitor {
            type Value = SubmitResponseCbor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("submit response CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut ver = None;
                let mut stream = None;
                let mut seq = None;
                let mut mmr_root = None;
                let mut stored_attachments = None;

                while let Some(key) = map.next_key::<u64>()? {
                    match key {
                        1 => {
                            if ver.is_some() {
                                return Err(DeError::duplicate_field("ver"));
                            }
                            ver = Some(map.next_value()?);
                        }
                        2 => {
                            if stream.is_some() {
                                return Err(DeError::duplicate_field("stream"));
                            }
                            stream = Some(map.next_value()?);
                        }
                        3 => {
                            if seq.is_some() {
                                return Err(DeError::duplicate_field("seq"));
                            }
                            seq = Some(map.next_value()?);
                        }
                        4 => {
                            if mmr_root.is_some() {
                                return Err(DeError::duplicate_field("mmr_root"));
                            }
                            mmr_root = Some(map.next_value()?);
                        }
                        5 => {
                            if stored_attachments.is_some() {
                                return Err(DeError::duplicate_field("stored_attachments"));
                            }
                            stored_attachments = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(DeError::custom(format!(
                                "unknown submit response key {key}"
                            )));
                        }
                    }
                }

                let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
                let stream = stream.ok_or_else(|| DeError::missing_field("stream"))?;
                let seq = seq.ok_or_else(|| DeError::missing_field("seq"))?;
                let mmr_root = mmr_root.ok_or_else(|| DeError::missing_field("mmr_root"))?;
                let stored_attachments = stored_attachments
                    .ok_or_else(|| DeError::missing_field("stored_attachments"))?;

                Ok(SubmitResponseCbor {
                    ver,
                    stream,
                    seq,
                    mmr_root,
                    stored_attachments,
                })
            }
        }

        deserializer.deserialize_map(SubmitResponseVisitor)
    }
}

impl<'de> Deserialize<'de> for StreamResponseCbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StreamResponseVisitor;

        impl<'de> Visitor<'de> for StreamResponseVisitor {
            type Value = StreamResponseCbor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("stream response CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut ver = None;
                let mut stream = None;
                let mut from_seq = None;
                let mut to_seq = None;
                let mut items = None;

                while let Some(key) = map.next_key::<u64>()? {
                    match key {
                        1 => {
                            if ver.is_some() {
                                return Err(DeError::duplicate_field("ver"));
                            }
                            ver = Some(map.next_value()?);
                        }
                        2 => {
                            if stream.is_some() {
                                return Err(DeError::duplicate_field("stream"));
                            }
                            stream = Some(map.next_value()?);
                        }
                        3 => {
                            if from_seq.is_some() {
                                return Err(DeError::duplicate_field("from_seq"));
                            }
                            from_seq = Some(map.next_value()?);
                        }
                        4 => {
                            if to_seq.is_some() {
                                return Err(DeError::duplicate_field("to_seq"));
                            }
                            to_seq = Some(map.next_value()?);
                        }
                        5 => {
                            if items.is_some() {
                                return Err(DeError::duplicate_field("items"));
                            }
                            items = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(DeError::custom(format!(
                                "unknown stream response key {key}"
                            )));
                        }
                    }
                }

                let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
                let stream = stream.ok_or_else(|| DeError::missing_field("stream"))?;
                let from_seq = from_seq.ok_or_else(|| DeError::missing_field("from_seq"))?;
                let items = items.ok_or_else(|| DeError::missing_field("items"))?;

                Ok(StreamResponseCbor {
                    ver,
                    stream,
                    from_seq,
                    to_seq,
                    items,
                })
            }
        }

        deserializer.deserialize_map(StreamResponseVisitor)
    }
}

impl<'de> Deserialize<'de> for StreamItemCbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StreamItemVisitor;

        impl<'de> Visitor<'de> for StreamItemVisitor {
            type Value = StreamItemCbor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("stream item CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut stream_seq = None;
                let mut message = None;
                let mut receipt = None;
                let mut proof = None;

                while let Some(key) = map.next_key::<u64>()? {
                    match key {
                        1 => {
                            if stream_seq.is_some() {
                                return Err(DeError::duplicate_field("stream_seq"));
                            }
                            stream_seq = Some(map.next_value()?);
                        }
                        2 => {
                            if message.is_some() {
                                return Err(DeError::duplicate_field("message"));
                            }
                            message = Some(map.next_value()?);
                        }
                        3 => {
                            if receipt.is_some() {
                                return Err(DeError::duplicate_field("receipt"));
                            }
                            receipt = Some(map.next_value()?);
                        }
                        4 => {
                            if proof.is_some() {
                                return Err(DeError::duplicate_field("proof"));
                            }
                            proof = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(DeError::custom(format!("unknown stream item key {key}")));
                        }
                    }
                }

                let stream_seq = stream_seq.ok_or_else(|| DeError::missing_field("stream_seq"))?;
                let message = message.ok_or_else(|| DeError::missing_field("message"))?;

                Ok(StreamItemCbor {
                    stream_seq,
                    message,
                    receipt,
                    proof,
                })
            }
        }

        deserializer.deserialize_map(StreamItemVisitor)
    }
}
