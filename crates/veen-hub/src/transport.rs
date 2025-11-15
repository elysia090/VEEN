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
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use hex;

use crate::pipeline::{
    AnchorRequest, BridgeIngestRequest, CapabilityError, HubPipeline, HubProfileDescriptor,
    HubRoleDescriptor, ObservabilityReport, SubmitRequest,
};
use std::str::FromStr;
use veen_core::label::StreamId;
use veen_core::RealmId;

pub struct HubServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    join: JoinHandle<Result<()>>,
}

impl HubServerHandle {
    pub async fn spawn(listen: SocketAddr, pipeline: HubPipeline) -> Result<Self> {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding hub listener on {listen}"))?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let app = Router::new()
            .route("/submit", post(handle_submit))
            .route("/stream", get(handle_stream))
            .route("/resync", post(handle_resync))
            .route("/authorize", post(handle_authorize))
            .route("/authority", post(handle_authority))
            .route("/authority_view", get(handle_authority_view))
            .route("/label-class", post(handle_label_class))
            .route("/label_authority", get(handle_label_authority))
            .route("/schema", post(handle_schema_descriptor))
            .route("/anchor", post(handle_anchor))
            .route("/bridge", post(handle_bridge))
            .route("/revoke", post(handle_revoke))
            .route("/healthz", get(handle_health))
            .route("/readyz", get(handle_ready))
            .route("/metrics", get(handle_metrics))
            .route("/profile", get(handle_profile))
            .route("/role", get(handle_role))
            .route("/checkpoint_latest", get(handle_checkpoint_latest))
            .route("/checkpoint_range", get(handle_checkpoint_range))
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

#[derive(Debug, Deserialize)]
struct StreamQuery {
    stream: String,
    from: Option<u64>,
    #[serde(default)]
    with_proof: bool,
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
struct AuthorityViewQuery {
    realm_id: String,
    stream_id: String,
}

#[derive(Debug, Deserialize)]
struct LabelAuthorityQuery {
    label: String,
}

async fn handle_submit(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<SubmitRequest>,
) -> impl IntoResponse {
    match pipeline.submit(request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            if let Some(cap_err) = err.downcast_ref::<CapabilityError>() {
                tracing::warn!(error = ?cap_err, "submit failed");
                let code = cap_err.code();
                pipeline.observability().record_submit_err(code);
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
            } else {
                tracing::warn!(error = ?err, "submit failed");
                (StatusCode::BAD_REQUEST, err.to_string()).into_response()
            }
        }
    }
}

async fn handle_stream(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<StreamQuery>,
) -> impl IntoResponse {
    match pipeline
        .stream(&query.stream, query.from.unwrap_or(0), query.with_proof)
        .await
    {
        Ok(messages) => (StatusCode::OK, Json(messages)).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "stream request failed");
            (StatusCode::NOT_FOUND, err.to_string()).into_response()
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

async fn handle_revoke(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    match pipeline.publish_revocation(&body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "revocation publish failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_authority(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    match pipeline.publish_authority(&body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "authority publish failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_authority_view(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<AuthorityViewQuery>,
) -> impl IntoResponse {
    let realm_id = match parse_realm_id_hex(&query.realm_id) {
        Ok(value) => value,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    let stream_id = match parse_stream_id_hex(&query.stream_id) {
        Ok(value) => value,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let descriptor = pipeline
        .authority_view_descriptor(realm_id, stream_id)
        .await;
    (StatusCode::OK, Json(descriptor)).into_response()
}

async fn handle_label_class(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    match pipeline.publish_label_class(&body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "label class publish failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_label_authority(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<LabelAuthorityQuery>,
) -> impl IntoResponse {
    let stream_id = match parse_stream_id_hex(&query.label) {
        Ok(value) => value,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };

    let descriptor = pipeline.label_authority_descriptor(stream_id).await;
    (StatusCode::OK, Json(descriptor)).into_response()
}

async fn handle_schema_descriptor(
    State(pipeline): State<HubPipeline>,
    body: Bytes,
) -> impl IntoResponse {
    match pipeline.register_schema_descriptor(&body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "schema descriptor publish failed");
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
    let report = pipeline.readiness_report().await;
    let status = if report.ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(report)).into_response()
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

    let descriptor: HubRoleDescriptor = pipeline.role_descriptor(realm, stream).await;
    (StatusCode::OK, Json(descriptor)).into_response()
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

fn parse_realm_id_hex(input: &str) -> Result<RealmId, String> {
    let bytes = hex::decode(input).map_err(|err| format!("invalid realm_id: {err}"))?;
    RealmId::from_slice(&bytes).map_err(|err| format!("invalid realm_id length: {err}"))
}

fn parse_stream_id_hex(input: &str) -> Result<StreamId, String> {
    let bytes = hex::decode(input).map_err(|err| format!("invalid stream identifier: {err}"))?;
    StreamId::from_slice(&bytes).map_err(|err| format!("invalid stream identifier length: {err}"))
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
