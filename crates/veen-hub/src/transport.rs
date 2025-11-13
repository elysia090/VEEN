use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::pipeline::{
    AnchorRequest, CapabilityRequest, HubPipeline, ObservabilityReport, SubmitRequest,
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
            .route("/anchor", post(handle_anchor))
            .route("/healthz", get(handle_health))
            .route("/metrics", get(handle_metrics))
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
}

#[derive(Debug, Deserialize)]
struct ResyncRequest {
    stream: String,
}

async fn handle_submit(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<SubmitRequest>,
) -> impl IntoResponse {
    match pipeline.submit(request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::warn!(error = ?err, "submit failed");
            (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
    }
}

async fn handle_stream(
    State(pipeline): State<HubPipeline>,
    Query(query): Query<StreamQuery>,
) -> impl IntoResponse {
    match pipeline
        .stream(&query.stream, query.from.unwrap_or(0))
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

async fn handle_authorize(
    State(pipeline): State<HubPipeline>,
    Json(request): Json<CapabilityRequest>,
) -> impl IntoResponse {
    match pipeline.authorize_capability(request).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
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

async fn handle_health(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let ObservabilityReport {
        uptime,
        submit_ok_total,
        submit_err_total,
        last_stream_seq,
        mmr_roots,
    } = pipeline.metrics_snapshot().await;
    let body = serde_json::json!({
        "ok": true,
        "uptime": humantime::format_duration(uptime).to_string(),
        "submit_ok_total": submit_ok_total,
        "submit_err_total": submit_err_total,
        "last_stream_seq": last_stream_seq,
        "mmr_roots": mmr_roots,
    });
    (StatusCode::OK, Json(body)).into_response()
}

async fn handle_metrics(State(pipeline): State<HubPipeline>) -> impl IntoResponse {
    let report = pipeline.metrics_snapshot().await;
    (StatusCode::OK, Json(report)).into_response()
}
