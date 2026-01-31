use std::io::Cursor;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::{
    header::{CONTENT_TYPE, RETRY_AFTER},
    HeaderValue, StatusCode,
};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{body::Bytes, Json, Router};
use ciborium::ser::into_writer;
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::pipeline::{
    AnchorRequest, BridgeIngestRequest, CapabilityError, CheckpointResponse, HubPipeline,
    HubProfileDescriptor, ObservabilityReport, ProofResponse, ReceiptResponse, SubmitError,
    SubmitRequest,
};
use std::str::FromStr;
use veen_core::label::StreamId;
use veen_core::RealmId;

const DATA_PLANE_VERSION: u64 = 1;

pub struct HubServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<Result<()>>,
}

impl HubServerHandle {
    pub async fn spawn(
        listen: SocketAddr,
        pipeline: HubPipeline,
        tooling_enabled: bool,
    ) -> Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding hub listener on {listen}"))?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let core_routes = Router::new()
            .route("/v1/submit", post(handle_submit))
            .route("/v1/stream", post(handle_stream))
            .route("/v1/receipt", post(handle_receipt))
            .route("/v1/proof", post(handle_proof))
            .route("/v1/checkpoint", post(handle_checkpoint));

        let tooling_routes = Router::new()
            .route("/commit_wait", get(handle_commit_wait))
            .route("/resync", post(handle_resync))
            .route("/authorize", post(handle_authorize))
            .route("/anchor", post(handle_anchor))
            .route("/bridge", post(handle_bridge))
            .route("/healthz", get(handle_health))
            .route("/readyz", get(handle_ready))
            .route("/metrics", get(handle_metrics))
            .route("/profile", get(handle_profile))
            .route("/role", get(handle_role))
            .route("/kex_policy", get(handle_kex_policy))
            .route("/admission", get(handle_admission))
            .route("/admission_log", get(handle_admission_log))
            .route("/cap_status", post(handle_cap_status))
            .route("/pow_request", get(handle_pow_request))
            .route("/checkpoint_latest", get(handle_checkpoint_latest))
            .route("/checkpoint_range", get(handle_checkpoint_range));

        let app = if tooling_enabled {
            core_routes.nest("/tooling", tooling_routes)
        } else {
            core_routes
        }
        .with_state(pipeline);

        let server = axum::serve(listener, app.into_make_service()).with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        let join = tokio::spawn(async move {
            server
                .await
                .map_err(|err| anyhow::anyhow!("hub transport failed: {err}"))
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            join,
        })
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.join.await.context("awaiting hub transport shutdown")?
    }
}

#[derive(Debug)]
struct StreamRequest {
    ver: u64,
    stream: String,
    from: Option<u64>,
    to: Option<u64>,
    max_items: Option<u64>,
    cursor: Option<u64>,
    with_receipts: Option<bool>,
    with_mmr_proof: Option<bool>,
}

#[derive(Debug)]
struct ReceiptRequest {
    ver: u64,
    stream: String,
    seq: u64,
}

#[derive(Debug)]
struct ProofRequest {
    ver: u64,
    stream: String,
    seq: u64,
}

#[derive(Debug)]
struct CheckpointRequest {
    ver: u64,
    stream: String,
    upto_seq: u64,
}

#[derive(Debug)]
struct SubmitRequestCbor {
    ver: u64,
    msg: String,
    stream: String,
    client_id: String,
    attachments: Option<Vec<crate::pipeline::AttachmentUpload>>,
    auth_ref: Option<String>,
    idem: Option<u64>,
    pow_cookie: Option<crate::pipeline::PowCookieEnvelope>,
}

impl<'de> Deserialize<'de> for SubmitRequestCbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SubmitRequestVisitor;

        impl<'de> Visitor<'de> for SubmitRequestVisitor {
            type Value = SubmitRequestCbor;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("submit request CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut ver = None;
                let mut msg = None;
                let mut stream = None;
                let mut client_id = None;
                let mut attachments = None;
                let mut auth_ref = None;
                let mut idem = None;
                let mut pow_cookie = None;

                while let Some(key) = map.next_key::<u64>()? {
                    match key {
                        1 => {
                            if ver.is_some() {
                                return Err(DeError::duplicate_field("ver"));
                            }
                            ver = Some(map.next_value()?);
                        }
                        2 => {
                            if msg.is_some() {
                                return Err(DeError::duplicate_field("msg"));
                            }
                            msg = Some(map.next_value()?);
                        }
                        3 => {
                            if stream.is_some() {
                                return Err(DeError::duplicate_field("stream"));
                            }
                            stream = Some(map.next_value()?);
                        }
                        4 => {
                            if client_id.is_some() {
                                return Err(DeError::duplicate_field("client_id"));
                            }
                            client_id = Some(map.next_value()?);
                        }
                        5 => {
                            if attachments.is_some() {
                                return Err(DeError::duplicate_field("attachments"));
                            }
                            attachments = Some(map.next_value()?);
                        }
                        6 => {
                            if auth_ref.is_some() {
                                return Err(DeError::duplicate_field("auth_ref"));
                            }
                            auth_ref = Some(map.next_value()?);
                        }
                        7 => {
                            if idem.is_some() {
                                return Err(DeError::duplicate_field("idem"));
                            }
                            idem = Some(map.next_value()?);
                        }
                        8 => {
                            if pow_cookie.is_some() {
                                return Err(DeError::duplicate_field("pow_cookie"));
                            }
                            pow_cookie = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(DeError::custom(format!(
                                "unknown submit request key {key}"
                            )));
                        }
                    }
                }

                let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
                let msg = msg.ok_or_else(|| DeError::missing_field("msg"))?;
                let stream = stream.ok_or_else(|| DeError::missing_field("stream"))?;
                let client_id = client_id.ok_or_else(|| DeError::missing_field("client_id"))?;

                Ok(SubmitRequestCbor {
                    ver,
                    msg,
                    stream,
                    client_id,
                    attachments,
                    auth_ref,
                    idem,
                    pow_cookie,
                })
            }
        }

        deserializer.deserialize_map(SubmitRequestVisitor)
    }
}

impl<'de> Deserialize<'de> for StreamRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StreamRequestVisitor;

        impl<'de> Visitor<'de> for StreamRequestVisitor {
            type Value = StreamRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("stream request CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut ver = None;
                let mut stream = None;
                let mut from = None;
                let mut to = None;
                let mut max_items = None;
                let mut cursor = None;
                let mut with_receipts = None;
                let mut with_mmr_proof = None;

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
                            if from.is_some() {
                                return Err(DeError::duplicate_field("from"));
                            }
                            from = Some(map.next_value()?);
                        }
                        4 => {
                            if to.is_some() {
                                return Err(DeError::duplicate_field("to"));
                            }
                            to = Some(map.next_value()?);
                        }
                        5 => {
                            if max_items.is_some() {
                                return Err(DeError::duplicate_field("max_items"));
                            }
                            max_items = Some(map.next_value()?);
                        }
                        6 => {
                            if cursor.is_some() {
                                return Err(DeError::duplicate_field("cursor"));
                            }
                            cursor = Some(map.next_value()?);
                        }
                        7 => {
                            if with_receipts.is_some() {
                                return Err(DeError::duplicate_field("with_receipts"));
                            }
                            with_receipts = Some(map.next_value()?);
                        }
                        8 => {
                            if with_mmr_proof.is_some() {
                                return Err(DeError::duplicate_field("with_mmr_proof"));
                            }
                            with_mmr_proof = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(DeError::custom(format!(
                                "unknown stream request key {key}"
                            )));
                        }
                    }
                }

                let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
                let stream = stream.ok_or_else(|| DeError::missing_field("stream"))?;

                Ok(StreamRequest {
                    ver,
                    stream,
                    from,
                    to,
                    max_items,
                    cursor,
                    with_receipts,
                    with_mmr_proof,
                })
            }
        }

        deserializer.deserialize_map(StreamRequestVisitor)
    }
}

impl<'de> Deserialize<'de> for ReceiptRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ReceiptRequestVisitor;

        impl<'de> Visitor<'de> for ReceiptRequestVisitor {
            type Value = ReceiptRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("receipt request CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut ver = None;
                let mut stream = None;
                let mut seq = None;

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
                        _ => {
                            return Err(DeError::custom(format!(
                                "unknown receipt request key {key}"
                            )));
                        }
                    }
                }

                let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
                let stream = stream.ok_or_else(|| DeError::missing_field("stream"))?;
                let seq = seq.ok_or_else(|| DeError::missing_field("seq"))?;

                Ok(ReceiptRequest { ver, stream, seq })
            }
        }

        deserializer.deserialize_map(ReceiptRequestVisitor)
    }
}

impl<'de> Deserialize<'de> for ProofRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ProofRequestVisitor;

        impl<'de> Visitor<'de> for ProofRequestVisitor {
            type Value = ProofRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("proof request CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut ver = None;
                let mut stream = None;
                let mut seq = None;

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
                        _ => {
                            return Err(DeError::custom(format!(
                                "unknown proof request key {key}"
                            )));
                        }
                    }
                }

                let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
                let stream = stream.ok_or_else(|| DeError::missing_field("stream"))?;
                let seq = seq.ok_or_else(|| DeError::missing_field("seq"))?;

                Ok(ProofRequest { ver, stream, seq })
            }
        }

        deserializer.deserialize_map(ProofRequestVisitor)
    }
}

impl<'de> Deserialize<'de> for CheckpointRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CheckpointRequestVisitor;

        impl<'de> Visitor<'de> for CheckpointRequestVisitor {
            type Value = CheckpointRequest;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("checkpoint request CBOR map with integer keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut ver = None;
                let mut stream = None;
                let mut upto_seq = None;

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
                            if upto_seq.is_some() {
                                return Err(DeError::duplicate_field("upto_seq"));
                            }
                            upto_seq = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(DeError::custom(format!(
                                "unknown checkpoint request key {key}"
                            )));
                        }
                    }
                }

                let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
                let stream = stream.ok_or_else(|| DeError::missing_field("stream"))?;
                let upto_seq = upto_seq.ok_or_else(|| DeError::missing_field("upto_seq"))?;

                Ok(CheckpointRequest {
                    ver,
                    stream,
                    upto_seq,
                })
            }
        }

        deserializer.deserialize_map(CheckpointRequestVisitor)
    }
}

#[derive(Debug, Deserialize)]
struct CommitWaitQuery {
    stream: String,
    seq: u64,
}

#[derive(Debug, Deserialize)]
struct ResyncRequest {
    stream: String,
}

#[derive(Debug, Deserialize)]
struct CheckpointRangeQuery {
    from_epoch: Option<u64>,
    to_epoch: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AdmissionLogQuery {
    limit: Option<usize>,
    codes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CapStatusRequest {
    auth_ref: String,
}

#[derive(Debug, Deserialize)]
struct PowRequestQuery {
    difficulty: Option<u8>,
}

async fn handle_submit(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    let request: SubmitRequestCbor = match decode_cbor_body(&body) {
        Ok(request) => request,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid submit request body: {err}"),
            )
                .into_response();
        }
    };
    if request.ver != DATA_PLANE_VERSION {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported submit version {}", request.ver),
        )
            .into_response();
    }
    let stream_label = request.stream.clone();
    let client_id = request.client_id.clone();
    let submit_request = SubmitRequest {
        stream: request.stream,
        client_id: request.client_id,
        msg: request.msg,
        attachments: request.attachments,
        auth_ref: request.auth_ref,
        idem: request.idem,
        pow_cookie: request.pow_cookie,
    };
    match pipeline.submit(submit_request).await {
        Ok(response) => match cbor_response(&response) {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = ?err, "serialising submit response failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        },
        Err(err) => {
            if let Some(cap_err) = err.downcast_ref::<CapabilityError>() {
                tracing::warn!(error = ?cap_err, "submit failed");
                let code = cap_err.code();
                pipeline.observability().record_submit_err(code);
                if let Err(err) = pipeline
                    .record_admission_failure(
                        &stream_label,
                        &client_id,
                        cap_err.code(),
                        &cap_err.to_string(),
                    )
                    .await
                {
                    tracing::warn!(error = ?err, "recording admission failure failed");
                }
                let status = match code {
                    "E.RATE" => StatusCode::TOO_MANY_REQUESTS,
                    "E.SIZE" => StatusCode::PAYLOAD_TOO_LARGE,
                    "E.AUTH" | "E.CAP" => StatusCode::FORBIDDEN,
                    _ => StatusCode::BAD_REQUEST,
                };
                let mut response = (status, cap_err.to_string()).into_response();
                if let Some(wait) = cap_err.retry_after() {
                    if let Ok(value) = HeaderValue::from_str(&wait.to_string()) {
                        response.headers_mut().insert(RETRY_AFTER, value);
                    }
                }
                response
            } else if let Some(submit_err) = err.downcast_ref::<SubmitError>() {
                tracing::warn!(error = ?submit_err, "submit failed");
                let code = submit_err.code();
                pipeline.observability().record_submit_err(code);
                if let Err(err) = pipeline
                    .record_admission_failure(
                        &stream_label,
                        &client_id,
                        code,
                        &submit_err.to_string(),
                    )
                    .await
                {
                    tracing::warn!(error = ?err, "recording admission failure failed");
                }
                (StatusCode::CONFLICT, submit_err.to_string()).into_response()
            } else {
                tracing::warn!(error = ?err, "submit failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        }
    }
}

async fn handle_stream(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    let query: StreamRequest = match decode_cbor_body(&body) {
        Ok(request) => request,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid stream request body: {err}"),
            )
                .into_response();
        }
    };
    if query.ver != DATA_PLANE_VERSION {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported stream version {}", query.ver),
        )
            .into_response();
    }
    if query.max_items.is_some() || query.cursor.is_some() {
        tracing::debug!(
            stream = %query.stream,
            "stream pagination hints ignored"
        );
    }
    let from = query.cursor.unwrap_or(query.from.unwrap_or(0));
    let with_receipts = query.with_receipts.unwrap_or(false);
    let with_mmr_proof = query.with_mmr_proof.unwrap_or(false);
    match pipeline
        .stream(&query.stream, from, query.to, with_receipts, with_mmr_proof)
        .await
    {
        Ok(response) => match cbor_response(&response) {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = ?err, "serialising stream response failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        },
        Err(err) => {
            tracing::warn!(error = ?err, "stream request failed");
            (StatusCode::NOT_FOUND, err.to_string()).into_response()
        }
    }
}

async fn handle_receipt(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    let query: ReceiptRequest = match decode_cbor_body(&body) {
        Ok(request) => request,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid receipt request body: {err}"),
            )
                .into_response();
        }
    };
    if query.ver != DATA_PLANE_VERSION {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported receipt version {}", query.ver),
        )
            .into_response();
    }
    match pipeline.receipt(&query.stream, query.seq).await {
        Ok(receipt) => match cbor_response(&ReceiptResponse {
            ver: DATA_PLANE_VERSION,
            receipt,
            server_version: None,
        }) {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = ?err, "serialising receipt response failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        },
        Err(err) => {
            tracing::warn!(error = ?err, "receipt request failed");
            (StatusCode::NOT_FOUND, err.to_string()).into_response()
        }
    }
}

async fn handle_proof(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    let query: ProofRequest = match decode_cbor_body(&body) {
        Ok(request) => request,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid proof request body: {err}"),
            )
                .into_response();
        }
    };
    if query.ver != DATA_PLANE_VERSION {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported proof version {}", query.ver),
        )
            .into_response();
    }
    match pipeline.proof(&query.stream, query.seq).await {
        Ok(proof) => match cbor_response(&ProofResponse {
            ver: DATA_PLANE_VERSION,
            mmr_proof: proof,
            server_version: None,
        }) {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = ?err, "serialising proof response failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        },
        Err(err) => {
            tracing::warn!(error = ?err, "proof request failed");
            (StatusCode::NOT_FOUND, err.to_string()).into_response()
        }
    }
}

async fn handle_checkpoint(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    let query: CheckpointRequest = match decode_cbor_body(&body) {
        Ok(request) => request,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid checkpoint request body: {err}"),
            )
                .into_response();
        }
    };
    if query.ver != DATA_PLANE_VERSION {
        return (
            StatusCode::BAD_REQUEST,
            format!("unsupported checkpoint version {}", query.ver),
        )
            .into_response();
    }
    match pipeline.checkpoint(&query.stream, query.upto_seq).await {
        Ok(Some(checkpoint)) => match cbor_response(&CheckpointResponse {
            ver: DATA_PLANE_VERSION,
            checkpoint,
            server_version: None,
        }) {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = ?err, "serialising checkpoint response failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        },
        Ok(None) => (StatusCode::NOT_FOUND, "checkpoint not found".to_string()).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "checkpoint request failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_commit_wait(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<CommitWaitQuery>,
) -> impl IntoResponse {
    match pipeline.commit_status(&query.stream, query.seq).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "commit not available".to_string()).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "commit wait failed");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

async fn handle_resync(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<ResyncRequest>,
) -> impl IntoResponse {
    match pipeline.resync(&request.stream).await {
        Ok(state) => (StatusCode::OK, Json(state)).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "resync failed");
            (StatusCode::NOT_FOUND, err.to_string()).into_response()
        }
    }
}

async fn handle_authorize(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    match pipeline.authorize_capability(&body).await {
        Ok(response) => {
            let mut encoded = Vec::new();
            if let Err(err) = into_writer(&response, &mut encoded) {
                tracing::error!(error = ?err, "failed to encode authorize response as CBOR");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to encode authorize response",
                )
                    .into_response();
            }
            let mut resp = (StatusCode::OK, encoded).into_response();
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/cbor"));
            resp
        }
        Err(err) => {
            tracing::warn!(error = ?err, "authorize failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_kex_policy(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let descriptor = pipeline.kex_policy_descriptor().await;
    (StatusCode::OK, Json(descriptor)).into_response()
}

async fn handle_admission(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let report = pipeline.admission_report().await;
    (StatusCode::OK, Json(report)).into_response()
}

async fn handle_admission_log(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<AdmissionLogQuery>,
) -> impl IntoResponse {
    let codes = query.codes.as_ref().map(|raw| {
        raw.split(',')
            .filter_map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            })
            .collect::<Vec<_>>()
    });
    let response = pipeline.admission_log(query.limit, codes).await;
    (StatusCode::OK, Json(response)).into_response()
}

async fn handle_cap_status(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<CapStatusRequest>,
) -> impl IntoResponse {
    match pipeline.capability_status(&request.auth_ref).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "cap status failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_pow_request(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<PowRequestQuery>,
) -> impl IntoResponse {
    match pipeline.pow_challenge(query.difficulty).await {
        Ok(descriptor) => (StatusCode::OK, Json(descriptor)).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "pow request failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_anchor(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<AnchorRequest>,
) -> impl IntoResponse {
    match pipeline.anchor_checkpoint(request).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "anchor request failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_bridge(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<BridgeIngestRequest>,
) -> impl IntoResponse {
    match pipeline.bridge_ingest(request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "bridge ingest failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_health(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let ObservabilityReport {
        uptime,
        submit_ok_total,
        submit_err_total,
        last_stream_seq,
        mmr_roots,
        peaks_count,
        profile_id,
        hub_id,
        hub_public_key,
        role,
        data_dir,
    } = pipeline.metrics_snapshot().await;
    let body = serde_json::json!({
        "ok": true,
        "uptime": humantime::format_duration(uptime).to_string(),
        "submit_ok_total": submit_ok_total,
        "submit_err_total": submit_err_total,
        "last_stream_seq": last_stream_seq,
        "mmr_roots": mmr_roots,
        "peaks_count": peaks_count,
        "profile_id": profile_id,
        "hub_id": hub_id,
        "hub_public_key": hub_public_key,
        "role": role,
        "data_dir": data_dir,
    });
    (StatusCode::OK, Json(body)).into_response()
}

async fn handle_ready(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    match pipeline.readiness_report().await {
        Ok(report) => {
            let status = if report.ok {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (status, Json(report)).into_response()
        }
        Err(err) => {
            tracing::warn!(error = ?err, "readiness report failed");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

async fn handle_metrics(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let report = pipeline.metrics_snapshot().await;
    (StatusCode::OK, Json(report)).into_response()
}

async fn handle_profile(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let descriptor: HubProfileDescriptor = pipeline.profile_descriptor().await;
    (StatusCode::OK, Json(descriptor)).into_response()
}

#[derive(Debug, Deserialize)]
struct RoleQuery {
    #[serde(rename = "realm_id")]
    realm_id: Option<String>,
    #[serde(rename = "stream_id")]
    stream_id: Option<String>,
}

async fn handle_role(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<RoleQuery>,
) -> impl IntoResponse {
    let realm = match query.realm_id {
        Some(ref hex) => match RealmId::from_str(hex) {
            Ok(realm) => Some(realm),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid realm_id; expected 64 hexadecimal characters".to_string(),
                )
                    .into_response();
            }
        },
        None => None,
    };
    let stream = match query.stream_id {
        Some(ref hex) => match StreamId::from_str(hex) {
            Ok(stream) => Some(stream),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    "invalid stream_id; expected 64 hexadecimal characters".to_string(),
                )
                    .into_response();
            }
        },
        None => None,
    };

    match pipeline.role_descriptor(realm, stream).await {
        Ok(descriptor) => (StatusCode::OK, Json(descriptor)).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "role descriptor failed");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

async fn handle_checkpoint_latest(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    match pipeline.latest_checkpoint().await {
        Ok(Some(checkpoint)) => match cbor_response(&checkpoint) {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = ?err, "serialising checkpoint response failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            "no checkpoints available".to_string(),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "fetching latest checkpoint failed");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

async fn handle_checkpoint_range(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<CheckpointRangeQuery>,
) -> impl IntoResponse {
    match pipeline
        .checkpoint_range(query.from_epoch, query.to_epoch)
        .await
    {
        Ok(checkpoints) => match cbor_response(&checkpoints) {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = ?err, "serialising checkpoint range failed");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        },
        Err(err) => {
            tracing::warn!(error = ?err, "fetching checkpoint range failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

fn cbor_response<T>(value: &T) -> Result<Response>
where
    T: Serialize,
{
    let mut body = Vec::new();
    into_writer(value, &mut body).context("serialising CBOR response body")?;
    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, HeaderValue::from_static("application/cbor"))],
        body,
    )
        .into_response())
}

fn decode_cbor_body<T>(body: &[u8]) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut cursor = Cursor::new(body);
    ciborium::de::from_reader(&mut cursor).context("decoding CBOR body")
}
