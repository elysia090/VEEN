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

use crate::pipeline::{
    AnchorRequest, BridgeIngestRequest, CapabilityError, HubPipeline, ObservabilityReport,
    SubmitRequest,
};

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
            .route("/label-class", post(handle_label_class))
            .route("/schema", post(handle_schema_descriptor))
            .route("/anchor", post(handle_anchor))
            .route("/bridge", post(handle_bridge))
            .route("/revoke", post(handle_revoke))
            .route("/healthz", get(handle_health))
            .route("/metrics", get(handle_metrics))
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

async fn handle_submit(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<SubmitRequest>,
) -> impl IntoResponse {
    match pipeline.submit(request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            if let Some(cap_err) = err.downcast_ref::<CapabilityError>() {
                tracing::warn!(error = ?cap_err, "submit failed");
                pipeline.observability().record_submit_err(cap_err.code());
                let status = match cap_err {
                    CapabilityError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
                    _ => StatusCode::FORBIDDEN,
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
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
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

async fn handle_label_class(State(pipeline): State<HubPipeline>, body: Bytes) -> impl IntoResponse {
    match pipeline.publish_label_class(&body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "label class publish failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
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

async fn handle_metrics(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let report = pipeline.metrics_snapshot().await;
    (StatusCode::OK, Json(report)).into_response()
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
