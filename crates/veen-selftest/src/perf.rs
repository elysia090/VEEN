use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use rand::rngs::OsRng;
use reqwest::{Client, ClientBuilder};
use serde::Serialize;
use tempfile::TempDir;
use tokio::sync::{Mutex, Semaphore};

use veen_core::cap_stream_id_from_label;
use veen_core::profile::Profile;
use veen_core::wire::types::ClientId;
use veen_hub::pipeline::{HubPipeline, SubmitRequest, SubmitResponse};
use veen_hub::runtime::{
    AdmissionConfig, AnchorConfig, DedupConfig, FederationConfig, HubRole, HubRuntimeConfig,
    ObservabilityConfig,
};
use veen_hub::server::HubServerHandle;
use veen_hub::storage::HubStorage;

use crate::metrics::{HistogramSnapshot, HubMetricsSnapshot, LatencyRecorder};
use crate::{SelftestGoalReport, SelftestReporter};

const DEFAULT_REQUESTS: usize = 256;
const DEFAULT_CONCURRENCY: usize = 32;
const MAX_LATENCY_MS: u64 = 600_000;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfMode {
    InProcess,
    Http,
}

impl PerfMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PerfMode::InProcess => "in_process",
            PerfMode::Http => "http",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PerfConfig {
    pub requests: usize,
    pub concurrency: usize,
    pub mode: PerfMode,
}

impl Default for PerfConfig {
    fn default() -> Self {
        Self {
            requests: DEFAULT_REQUESTS,
            concurrency: DEFAULT_CONCURRENCY,
            mode: PerfMode::InProcess,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PerfSummary {
    pub workload: PerfConfig,
    pub metrics: HubMetricsSnapshot,
    pub throughput_rps: f64,
    pub verify_p95_ms: f64,
    pub verify_p99_ms: f64,
    pub commit_p95_ms: f64,
    pub commit_p99_ms: f64,
    pub end_to_end_p95_ms: f64,
    pub end_to_end_p99_ms: f64,
}

struct HttpContext {
    base_url: String,
    client: Client,
}

struct PerfHarness {
    mode: PerfMode,
    pipeline: HubPipeline,
    stream_label: String,
    client_id: String,
    http: Option<Arc<HttpContext>>,
    _tempdir: TempDir,
    server: Option<HubServerHandle>,
}

impl PerfHarness {
    async fn start(mode: PerfMode) -> Result<Self> {
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, pick_port()?));
        let tempdir = TempDir::new().context("creating perf workspace")?;
        let data_dir = tempdir.path().to_path_buf();
        let config = build_runtime_config(listen, data_dir.clone())?;

        let storage = HubStorage::bootstrap(&config).await?;
        let pipeline = HubPipeline::initialise(&config, &storage).await?;
        let client_id = random_client_id_hex();
        let stream_label = "perf/main".to_string();
        cap_stream_id_from_label(&stream_label).context("validating perf stream label")?;

        let (server, http) = match mode {
            PerfMode::InProcess => (None, None),
            PerfMode::Http => {
                let server = HubServerHandle::spawn(listen, pipeline.clone()).await?;
                let url = format!("http://{}:{}", listen.ip(), listen.port());
                let client = ClientBuilder::new()
                    .build()
                    .context("building HTTP client for perf harness")?;
                let http = Arc::new(HttpContext {
                    base_url: url,
                    client,
                });
                (Some(server), Some(http))
            }
        };

        Ok(Self {
            mode,
            pipeline,
            stream_label,
            client_id,
            http,
            _tempdir: tempdir,
            server,
        })
    }

    async fn shutdown(self) -> Result<()> {
        if let Some(server) = self.server {
            server.shutdown().await?;
        }
        Ok(())
    }

    async fn drive(&self, cfg: &PerfConfig) -> Result<PerfSummary> {
        let verify = Arc::new(Mutex::new(new_latency_recorder()?));
        let commit = Arc::new(Mutex::new(new_latency_recorder()?));
        let end_to_end = Arc::new(Mutex::new(new_latency_recorder()?));

        let semaphore = Arc::new(Semaphore::new(cfg.concurrency));
        let mut tasks = Vec::with_capacity(cfg.requests);
        let start = Instant::now();

        for request_idx in 0..cfg.requests {
            let permit = Arc::clone(&semaphore).acquire_owned().await?;
            let driver = PerfDriver::new(self, request_idx as u64)?;
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let mut verify_local = new_latency_recorder()?;
                let mut commit_local = new_latency_recorder()?;
                let mut end_local = new_latency_recorder()?;
                driver
                    .run_single(&mut verify_local, &mut commit_local, &mut end_local)
                    .await?;
                Ok::<_, anyhow::Error>(TaskLatencies {
                    verify: verify_local,
                    commit: commit_local,
                    end: end_local,
                })
            }));
        }

        let mut submit_ok_total = 0u64;
        let mut submit_err_total = std::collections::BTreeMap::new();
        for task in tasks {
            match task.await? {
                Ok(task_latencies) => {
                    merge_task_latencies(
                        Arc::clone(&verify),
                        Arc::clone(&commit),
                        Arc::clone(&end_to_end),
                        task_latencies,
                    )
                    .await?;
                    submit_ok_total += 1;
                }
                Err(err) => {
                    *submit_err_total.entry(err.to_string()).or_default() += 1;
                }
            }
        }

        let elapsed = start.elapsed().as_secs_f64().max(f64::EPSILON);
        let throughput_rps = submit_ok_total as f64 / elapsed;

        let verify_guard = verify.lock().await;
        let commit_guard = commit.lock().await;
        let end_guard = end_to_end.lock().await;

        let metrics = HubMetricsSnapshot {
            submit_ok_total,
            submit_err_total,
            verify_latency_ms: HistogramSnapshot::from_histogram(
                verify_guard.histogram(),
                &verify_guard.stats(),
            ),
            commit_latency_ms: HistogramSnapshot::from_histogram(
                commit_guard.histogram(),
                &commit_guard.stats(),
            ),
            end_to_end_latency_ms: HistogramSnapshot::from_histogram(
                end_guard.histogram(),
                &end_guard.stats(),
            ),
        };

        Ok(PerfSummary {
            workload: cfg.clone(),
            throughput_rps,
            verify_p95_ms: metrics.verify_latency_ms.p95.unwrap_or_default(),
            verify_p99_ms: metrics.verify_latency_ms.p99.unwrap_or_default(),
            commit_p95_ms: metrics.commit_latency_ms.p95.unwrap_or_default(),
            commit_p99_ms: metrics.commit_latency_ms.p99.unwrap_or_default(),
            end_to_end_p95_ms: metrics.end_to_end_latency_ms.p95.unwrap_or_default(),
            end_to_end_p99_ms: metrics.end_to_end_latency_ms.p99.unwrap_or_default(),
            metrics,
        })
    }
}

struct TaskLatencies {
    verify: LatencyRecorder,
    commit: LatencyRecorder,
    end: LatencyRecorder,
}

async fn merge_task_latencies(
    verify: Arc<Mutex<LatencyRecorder>>,
    commit: Arc<Mutex<LatencyRecorder>>,
    end: Arc<Mutex<LatencyRecorder>>,
    task_latencies: TaskLatencies,
) -> Result<()> {
    verify
        .lock()
        .await
        .merge_from(&task_latencies.verify)?;
    commit
        .lock()
        .await
        .merge_from(&task_latencies.commit)?;
    end.lock().await.merge_from(&task_latencies.end)?;
    Ok(())
}

fn new_latency_recorder() -> Result<LatencyRecorder> {
    LatencyRecorder::with_bounds(1, MAX_LATENCY_MS, 3)
}

fn build_runtime_config(listen: SocketAddr, data_dir: PathBuf) -> Result<HubRuntimeConfig> {
    Ok(HubRuntimeConfig {
        listen,
        data_dir,
        role: HubRole::Primary,
        profile_id: Some(Profile::default().id()?.to_string()),
        anchors: AnchorConfig::default(),
        observability: ObservabilityConfig::default(),
        dedup: DedupConfig::default(),
        admission: AdmissionConfig {
            capability_gating_enabled: false,
            ..AdmissionConfig::default()
        },
        federation: FederationConfig::default(),
        config_path: None,
    })
}

#[derive(Clone)]
struct PerfDriver {
    mode: PerfMode,
    pipeline: HubPipeline,
    stream_label: String,
    client_id: String,
    http: Option<Arc<HttpContext>>,
    payload: serde_json::Value,
    idem: u64,
}

impl PerfDriver {
    fn new(harness: &PerfHarness, idx: u64) -> Result<Self> {
        let payload = serde_json::json!({
            "kind": "perf",
            "idx": idx,
            "ts": current_millis(),
        });
        Ok(Self {
            mode: harness.mode,
            pipeline: harness.pipeline.clone(),
            stream_label: harness.stream_label.clone(),
            client_id: harness.client_id.clone(),
            http: harness.http.clone(),
            payload,
            idem: idx,
        })
    }

    async fn run_single(
        &self,
        verify_hist: &mut LatencyRecorder,
        commit_hist: &mut LatencyRecorder,
        end_hist: &mut LatencyRecorder,
    ) -> Result<()> {
        let submit_start = Instant::now();
        let response = self.submit().await?;
        let verify_done = Instant::now();
        self.await_commit(response).await?;
        let finished = Instant::now();

        let verify_ms = millis(submit_start, verify_done);
        let commit_ms = millis(verify_done, finished);
        let end_ms = millis(submit_start, finished);

        verify_hist.record_ms(verify_ms)?;
        commit_hist.record_ms(commit_ms)?;
        end_hist.record_ms(end_ms)?;

        Ok(())
    }

    async fn submit(&self) -> Result<SubmitResponse> {
        let request = SubmitRequest {
            stream: self.stream_label.clone(),
            client_id: self.client_id.clone(),
            payload: self.payload.clone(),
            attachments: None,
            auth_ref: None,
            expires_at: None,
            schema: None,
            idem: Some(self.idem),
            pow_cookie: None,
        };

        match self.mode {
            PerfMode::InProcess => self.pipeline.submit(request).await,
            PerfMode::Http => {
                let http = self
                    .http
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing HTTP context for perf run"))?;
                let url = format!("{}/submit", http.base_url);
                let response = http
                    .client
                    .post(url)
                    .json(&request)
                    .send()
                    .await
                    .context("issuing HTTP submit")?;
                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    return Err(anyhow!("HTTP submit failed: {status} {body}"));
                }
                response
                    .json::<SubmitResponse>()
                    .await
                    .context("decoding hub response")
            }
        }
    }

    async fn await_commit(&self, response: SubmitResponse) -> Result<()> {
        match self.mode {
            PerfMode::InProcess => {
                if !self
                    .pipeline
                    .commit_status(&self.stream_label, response.seq)
                    .await?
                {
                    return Err(anyhow!("commit not yet available in process"));
                }
            }
            PerfMode::Http => {
                let http = self
                    .http
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing HTTP context for perf run"))?;
                let url = format!(
                    "{}/commit_wait?stream={}&seq={}",
                    http.base_url, self.stream_label, response.seq
                );
                let response = http.client.get(url).send().await?;
                if !response.status().is_success() {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    return Err(anyhow!(
                        "failed to confirm commit over HTTP: {status} {body}"
                    ));
                }
            }
        }
        Ok(())
    }
}

pub async fn run_perf(
    config: PerfConfig,
    reporter: &mut SelftestReporter<'_>,
) -> Result<PerfSummary> {
    let harness = PerfHarness::start(config.mode).await?;
    let summary = harness.drive(&config).await?;

    let mut entry = SelftestGoalReport::new("SELFTEST.PERF");
    entry
        .environment
        .push(format!("mode={}", config.mode.as_str()));
    entry
        .environment
        .push(format!("requests={}", summary.workload.requests));
    entry
        .environment
        .push(format!("concurrency={}", summary.workload.concurrency));
    entry
        .invariants
        .push("submit round-trip latencies recorded".into());
    entry.invariants.push("commit confirmation succeeds".into());
    entry
        .evidence
        .push(format!("throughput_rps={:.2}", summary.throughput_rps));
    entry
        .evidence
        .push(format!("verify_p95_ms={:.2}", summary.verify_p95_ms));
    entry
        .evidence
        .push(format!("verify_p99_ms={:.2}", summary.verify_p99_ms));
    entry
        .evidence
        .push(format!("commit_p95_ms={:.2}", summary.commit_p95_ms));
    entry
        .evidence
        .push(format!("commit_p99_ms={:.2}", summary.commit_p99_ms));
    entry.evidence.push(format!(
        "end_to_end_p95_ms={:.2}",
        summary.end_to_end_p95_ms
    ));
    entry.evidence.push(format!(
        "end_to_end_p99_ms={:.2}",
        summary.end_to_end_p99_ms
    ));
    entry.perf = Some(summary.clone());
    reporter.record(entry);

    harness.shutdown().await?;
    Ok(summary)
}

fn millis(start: Instant, end: Instant) -> u64 {
    end.duration_since(start).as_millis() as u64
}

fn random_client_id_hex() -> String {
    let signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let verifier = signing.verifying_key();
    let id = ClientId::from(*verifier.as_bytes());
    hex::encode(id.as_ref())
}

fn current_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn pick_port() -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .context("binding probing listener")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}
