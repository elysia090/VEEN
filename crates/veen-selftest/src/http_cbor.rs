use anyhow::{anyhow, Context, Result};
use serde::ser::SerializeMap;
use serde::Serialize;

use veen_hub::pipeline::{
    AttachmentUpload, PowCookieEnvelope, StreamMessageWithProof, StreamResponse, SubmitRequest,
    SubmitResponse,
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
    let response: SubmitResponse =
        ciborium::de::from_reader(&mut cursor).context("decoding submit response")?;
    if response.ver != DATA_PLANE_VERSION {
        return Err(anyhow!(
            "unexpected submit response version {}",
            response.ver
        ));
    }
    Ok(response)
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
    let response: StreamResponse =
        ciborium::de::from_reader(&mut cursor).context("decoding stream response")?;
    if response.ver != DATA_PLANE_VERSION {
        return Err(anyhow!(
            "unexpected stream response version {}",
            response.ver
        ));
    }
    if response.items.is_empty() {
        return Ok(Vec::new());
    }
    let proof = response
        .mmr_proof
        .ok_or_else(|| anyhow!("stream response missing mmr proof"))?;
    response
        .items
        .into_iter()
        .map(|item| {
            Ok(StreamMessageWithProof {
                message: item.msg,
                receipt: item.receipt.ok_or_else(|| {
                    anyhow!(
                        "stream response missing receipt for seq {}",
                        item.stream_seq
                    )
                })?,
                proof: proof.clone(),
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
