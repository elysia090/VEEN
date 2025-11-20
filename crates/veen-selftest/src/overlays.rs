use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::fs;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::info;

use veen_bridge::{run_bridge, BridgeConfig, EndpointConfig};
use veen_hub::config::{HubConfigOverrides, HubRole, HubRuntimeConfig};
use veen_hub::pipeline::{
    BridgeIngestRequest, HubStreamState, StoredMessage, StreamReceipt, SubmitRequest,
};
use veen_hub::runtime::HubRuntime;
use veen_hub::storage::HUB_KEY_FILE;

use crate::{SelftestGoalReport, SelftestReporter};

const FED_CHAT_STREAM: &str = "fed/chat";
const DEFAULT_CLIENT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const EXPORT_STREAM: &str = "export/events";
const ONLINE_AUDIT_STREAM: &str = "bridge/online/log";
const OFFLINE_AUDIT_STREAM: &str = "bridge/offline/log";

const HUB_KEY_VERSION: u8 = 1;

#[derive(Deserialize)]
struct MetricsSnapshot {
    #[serde(default)]
    mmr_roots: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct HubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

pub async fn run_overlays(subset: Option<&str>, reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let mut executed = Vec::new();
    if subset.is_none() || subset == Some("fed-auth") {
        run_fed_auth()
            .await
            .context("executing federation authority overlay self-test")?;
        executed.push("fed-auth");
        reporter.record(SelftestGoalReport {
            goal: "SELFTEST.OVERLAYS.fed-auth".into(),
            environment: vec![
                format!("subset={}", subset.unwrap_or("fed-auth")),
                format!("stream={FED_CHAT_STREAM}"),
            ],
            invariants: vec![
                "replica rejects direct submissions".into(),
                "bridge relays submissions across hubs".into(),
                "MMR roots converge after replication".into(),
            ],
            evidence: vec!["fed-auth scenario executed with bridge and hubs".into()],
            perf: None,
        });
    }

    if subset.is_none() || subset == Some("agb0") {
        run_airgap_bridge()
            .await
            .context("executing airgap bridge overlay self-test")?;
        executed.push("agb0");
        reporter.record(SelftestGoalReport {
            goal: "SELFTEST.OVERLAYS.agb0".into(),
            environment: vec![
                "subset=agb0".into(),
                format!("export={EXPORT_STREAM}"),
                format!("audit_online={ONLINE_AUDIT_STREAM}"),
                format!("audit_offline={OFFLINE_AUDIT_STREAM}"),
            ],
            invariants: vec![
                "bridged imports require ordered bundles".into(),
                "tampered bundles fail validation".into(),
                "reconciliation detects missing bundle ranges".into(),
                "audit events are emitted for online and offline actions".into(),
            ],
            evidence: vec![
                "agb0 scenario replicated bundles via file transfer and bridge ingest".into(),
            ],
            perf: None,
        });
    }

    if executed.is_empty() {
        bail!("unknown overlay subset {}", subset.unwrap_or("<none>"));
    }
    Ok(())
}

async fn run_fed_auth() -> Result<()> {
    let primary_dir = TempDir::new().context("creating primary hub directory")?;
    let replica_dir = TempDir::new().context("creating replica hub directory")?;

    let primary_addr = next_listen_addr()?;
    let replica_addr = next_listen_addr()?;

    ensure_hub_key(primary_dir.path()).await?;
    ensure_hub_key(replica_dir.path()).await?;

    let primary_config = HubRuntimeConfig::from_sources(
        primary_addr,
        primary_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            capability_gating_enabled: Some(false),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    let replica_config = HubRuntimeConfig::from_sources(
        replica_addr,
        replica_dir.path().to_path_buf(),
        None,
        HubRole::Replica,
        HubConfigOverrides {
            replica_targets: Some(vec![format!("http://{}", primary_addr)]),
            ..HubConfigOverrides::default()
        },
    )
    .await?;

    let primary_runtime = HubRuntime::start(primary_config).await?;
    let replica_runtime = HubRuntime::start(replica_config).await?;

    let primary_base = format!("http://{}", primary_runtime.listen_addr());
    let replica_base = format!("http://{}", replica_runtime.listen_addr());

    let http = Client::new();

    let bridge_shutdown = CancellationToken::new();
    let bridge_handle = spawn_bridge(&primary_base, &replica_base, bridge_shutdown.clone())?;

    // Allow bridge loop to start.
    sleep(Duration::from_millis(100)).await;

    let submit_request = SubmitRequest {
        stream: FED_CHAT_STREAM.to_string(),
        client_id: DEFAULT_CLIENT_ID.to_string(),
        payload: json!({ "message": "hello from primary" }),
        attachments: None,
        auth_ref: None,
        expires_at: None,
        schema: None,
        idem: None,
        pow_cookie: None,
    };

    http.post(format!("{primary_base}/submit"))
        .json(&submit_request)
        .send()
        .await
        .context("submitting message to primary hub")?
        .error_for_status()
        .context("primary hub rejected submit")?;

    let replica_result = http
        .post(format!("{replica_base}/submit"))
        .json(&submit_request)
        .send()
        .await
        .context("submitting message directly to replica")?;
    ensure_replica_rejects(replica_result.status())?;

    wait_for_replication(&http, &replica_base).await?;
    verify_mmr_roots(&http, &primary_base, &replica_base).await?;

    bridge_shutdown.cancel();
    match bridge_handle.await {
        Ok(result) => result?,
        Err(err) => return Err(anyhow!("bridge task terminated unexpectedly: {err}")),
    }

    primary_runtime.shutdown().await?;
    replica_runtime.shutdown().await?;

    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
struct StoredBundle {
    #[serde(flatten)]
    message: StoredMessage,
    #[serde(default)]
    receipt: Option<StreamReceipt>,
}

#[derive(Clone)]
struct ExportedBundle {
    seq: u64,
    message: StoredMessage,
    expected_mmr_root: String,
    raw: Vec<u8>,
}

async fn run_airgap_bridge() -> Result<()> {
    let online_dir = TempDir::new().context("creating online hub directory")?;
    let offline_dir = TempDir::new().context("creating offline hub directory")?;

    ensure_hub_key(online_dir.path()).await?;
    ensure_hub_key(offline_dir.path()).await?;

    let online_runtime = start_overlay_hub(online_dir.path(), HubRole::Primary)
        .await
        .with_context(|| format!("starting online hub in {}", online_dir.path().display()))?;
    let offline_runtime = start_overlay_hub(offline_dir.path(), HubRole::Replica)
        .await
        .with_context(|| format!("starting offline hub in {}", offline_dir.path().display()))?;

    let online_base = format!("http://{}", online_runtime.listen_addr());
    let offline_base = format!("http://{}", offline_runtime.listen_addr());
    let http = Client::new();

    let export_messages = vec![
        json!({ "body": "alpha" }),
        json!({ "body": "beta" }),
        json!({ "body": "gamma" }),
    ];

    for body in &export_messages {
        submit_message(&http, &online_base, EXPORT_STREAM, body).await?;
    }

    let bundles = export_bundles(online_runtime.data_dir(), EXPORT_STREAM)
        .await
        .context("exporting bundles from online hub storage for offline transfer")?;
    ensure!(
        bundles.len() >= export_messages.len(),
        "expected at least {} bundles for export stream",
        export_messages.len()
    );

    for bundle in &bundles {
        record_online_audit(&http, &online_base, bundle)
            .await
            .context("recording online audit log")?;
    }

    import_bundle(&http, &offline_base, &bundles[0])
        .await
        .context("importing first bundle into offline hub")?;
    record_offline_audit(&http, &offline_base, &bundles[0], "import", true)
        .await
        .context("recording offline audit for first bundle")?;

    let tampered = tamper_bundle(&bundles[1]);
    let tamper_error = expect_import_error(&http, &offline_base, &tampered)
        .await
        .context("ensuring tampered bundle import fails")?;
    ensure!(
        tamper_error.contains("mmr root"),
        "tampered bundle error did not mention mmr root mismatch: {tamper_error}",
    );
    record_offline_audit(
        &http,
        &offline_base,
        &bundles[1],
        &format!("tamper_error: {tamper_error}"),
        false,
    )
    .await
    .context("recording offline audit for tampered bundle")?;

    let gap_error = expect_import_error(&http, &offline_base, &bundles[2])
        .await
        .context("detecting missing bundle range during reconciliation")?;
    ensure!(
        gap_error.contains("out of order") || gap_error.contains("expected 2"),
        "gap detection did not report missing range: {gap_error}",
    );
    record_offline_audit(
        &http,
        &offline_base,
        &bundles[2],
        &format!("gap_detected: {gap_error}"),
        false,
    )
    .await
    .context("recording offline audit for missing range detection")?;

    import_bundle(&http, &offline_base, &bundles[1])
        .await
        .context("importing withheld bundle to close gap")?;
    record_offline_audit(&http, &offline_base, &bundles[1], "reconciled", true)
        .await
        .context("recording offline audit for reconciled bundle")?;

    import_bundle(&http, &offline_base, &bundles[2])
        .await
        .context("importing final bundle after reconciliation")?;
    record_offline_audit(&http, &offline_base, &bundles[2], "import", true)
        .await
        .context("recording offline audit for final bundle")?;

    let offline_state = fetch_stream_state(&http, &offline_base, EXPORT_STREAM).await?;
    ensure!(
        offline_state.messages.len() >= export_messages.len(),
        "offline hub missing imported bundles"
    );

    verify_stream_root_match(&http, &online_base, &offline_base, EXPORT_STREAM)
        .await
        .context("checking export/import stream parity")?;

    let online_audit = fetch_stream_state(&http, &online_base, ONLINE_AUDIT_STREAM).await?;
    ensure!(
        !online_audit.messages.is_empty(),
        "online audit stream is empty"
    );

    let offline_audit = fetch_stream_state(&http, &offline_base, OFFLINE_AUDIT_STREAM).await?;
    ensure!(
        offline_audit.messages.len() >= 4,
        "offline audit stream missing expected entries"
    );

    let bridge_shutdown = CancellationToken::new();
    let bridge_handle = spawn_bridge(&online_base, &offline_base, bridge_shutdown.clone())?;
    sleep(Duration::from_millis(200)).await;
    bridge_shutdown.cancel();
    match bridge_handle.await {
        Ok(result) => result?,
        Err(err) => return Err(anyhow!("bridge task terminated unexpectedly: {err}")),
    }

    online_runtime.shutdown().await?;
    offline_runtime.shutdown().await?;

    Ok(())
}

async fn ensure_hub_key(dir: &Path) -> Result<()> {
    let path = dir.join(HUB_KEY_FILE);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking hub key at {}", path.display()))?
    {
        return Ok(());
    }

    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    let material = HubKeyMaterial {
        version: HUB_KEY_VERSION,
        created_at: current_unix_timestamp(),
        public_key: ByteBuf::from(verifying.as_bytes().to_vec()),
        secret_key: ByteBuf::from(signing.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&material, &mut encoded)
        .context("serializing overlay hub key material")?;
    fs::write(&path, encoded)
        .await
        .with_context(|| format!("writing hub key material to {}", path.display()))?;
    Ok(())
}

async fn start_overlay_hub(dir: &Path, role: HubRole) -> Result<HubRuntime> {
    let listen = next_listen_addr()?;
    let mut overrides = HubConfigOverrides {
        capability_gating_enabled: Some(false),
        ..HubConfigOverrides::default()
    };
    if matches!(role, HubRole::Replica) {
        overrides.replica_targets = Some(Vec::new());
    }
    let config =
        HubRuntimeConfig::from_sources(listen, dir.to_path_buf(), None, role, overrides).await?;
    HubRuntime::start(config).await
}

async fn submit_message(
    client: &Client,
    hub_base: &str,
    stream: &str,
    body: &serde_json::Value,
) -> Result<()> {
    let request = SubmitRequest {
        stream: stream.to_string(),
        client_id: DEFAULT_CLIENT_ID.to_string(),
        payload: body.clone(),
        idem: None,
        schema: None,
        expires_at: None,
        attachments: None,
        auth_ref: None,
        pow_cookie: None,
    };

    client
        .post(format!("{hub_base}/submit"))
        .json(&request)
        .send()
        .await
        .context("submitting overlay message")?
        .error_for_status()
        .context("hub rejected overlay message")?;
    Ok(())
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_secs()
}

fn stream_storage_name(stream: &str) -> String {
    let mut safe = String::with_capacity(stream.len());
    for ch in stream.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            safe.push(ch);
        } else if ch.is_whitespace() {
            safe.push('_');
        } else {
            safe.push('-');
        }
    }
    if safe.is_empty() {
        safe.push_str("stream");
    }
    let digest = Sha256::digest(stream.as_bytes());
    let suffix = hex::encode(&digest[..8]);
    format!("{safe}-{suffix}")
}

fn message_bundle_path(data_dir: &Path, stream: &str, seq: u64) -> PathBuf {
    data_dir
        .join("state")
        .join("messages")
        .join(format!("{}-{seq:08}.json", stream_storage_name(stream)))
}

async fn export_bundles(data_dir: &Path, stream: &str) -> Result<Vec<ExportedBundle>> {
    let mut seq = 1;
    let mut bundles = Vec::new();
    loop {
        let path = message_bundle_path(data_dir, stream, seq);
        if !fs::try_exists(&path)
            .await
            .with_context(|| format!("checking bundle {}", path.display()))?
        {
            break;
        }
        let raw = fs::read(&path)
            .await
            .with_context(|| format!("reading bundle {}", path.display()))?;
        let bundle: StoredBundle = serde_json::from_slice(&raw)
            .with_context(|| format!("decoding stored bundle from {}", path.display()))?;
        let expected_mmr_root = bundle
            .receipt
            .as_ref()
            .map(|receipt| receipt.mmr_root.clone())
            .unwrap_or_default();

        bundles.push(ExportedBundle {
            seq,
            message: bundle.message,
            expected_mmr_root,
            raw,
        });
        seq += 1;
    }

    Ok(bundles)
}

fn tamper_bundle(original: &ExportedBundle) -> ExportedBundle {
    let mut tampered = original.message.clone();
    tampered.body = Some("{\"tampered\":true}".into());

    let raw = serde_json::to_vec(&StoredBundle {
        message: tampered.clone(),
        receipt: Some(StreamReceipt {
            seq: original.seq,
            leaf_hash: String::new(),
            mmr_root: original.expected_mmr_root.clone(),
            hub_ts: current_unix_timestamp(),
        }),
    })
    .unwrap_or_default();

    ExportedBundle {
        seq: original.seq,
        message: tampered,
        expected_mmr_root: original.expected_mmr_root.clone(),
        raw,
    }
}

async fn import_bundle(client: &Client, hub_base: &str, bundle: &ExportedBundle) -> Result<()> {
    let request = BridgeIngestRequest {
        message: bundle.message.clone(),
        expected_mmr_root: bundle.expected_mmr_root.clone(),
    };

    client
        .post(format!("{hub_base}/bridge"))
        .json(&request)
        .send()
        .await
        .context("issuing bridge ingest for bundle")?
        .error_for_status()
        .context("bridge ingest rejected bundle")?;
    Ok(())
}

async fn expect_import_error(
    client: &Client,
    hub_base: &str,
    bundle: &ExportedBundle,
) -> Result<String> {
    let request = BridgeIngestRequest {
        message: bundle.message.clone(),
        expected_mmr_root: bundle.expected_mmr_root.clone(),
    };

    let response = client
        .post(format!("{hub_base}/bridge"))
        .json(&request)
        .send()
        .await
        .context("sending bundle to replica")?;

    ensure!(
        !response.status().is_success(),
        "bridge ingest unexpectedly accepted invalid bundle"
    );

    Ok(response
        .text()
        .await
        .unwrap_or_else(|_| "<unable to read error body>".into()))
}

fn bundle_digest_hex(bundle: &ExportedBundle) -> String {
    let digest = Sha256::digest(&bundle.raw);
    hex::encode(digest)
}

async fn record_online_audit(
    client: &Client,
    hub_base: &str,
    bundle: &ExportedBundle,
) -> Result<()> {
    let body = json!({
        "bundle_id": bundle_digest_hex(bundle),
        "stream": bundle.message.stream,
        "seq": bundle.seq,
        "expected_mmr_root": bundle.expected_mmr_root,
    });
    submit_message(client, hub_base, ONLINE_AUDIT_STREAM, &body).await
}

async fn record_offline_audit(
    client: &Client,
    hub_base: &str,
    bundle: &ExportedBundle,
    status: &str,
    success: bool,
) -> Result<()> {
    let state = fetch_stream_state(client, hub_base, OFFLINE_AUDIT_STREAM).await?;
    let next_seq = state.messages.last().map(|m| m.seq + 1).unwrap_or(1);
    let body = json!({
        "bundle_id": bundle_digest_hex(bundle),
        "stream": bundle.message.stream,
        "seq": bundle.seq,
        "status": status,
        "success": success,
    });

    let message = StoredMessage {
        stream: OFFLINE_AUDIT_STREAM.to_string(),
        seq: next_seq,
        sent_at: current_unix_timestamp(),
        client_id: DEFAULT_CLIENT_ID.to_string(),
        schema: None,
        expires_at: None,
        parent: None,
        body: Some(body.to_string()),
        body_digest: None,
        attachments: Vec::new(),
        auth_ref: None,
        idem: None,
    };

    let request = BridgeIngestRequest {
        message,
        expected_mmr_root: String::new(),
    };

    client
        .post(format!("{hub_base}/bridge"))
        .json(&request)
        .send()
        .await
        .context("submitting offline audit event")?
        .error_for_status()
        .context("offline audit ingest failed")?;
    Ok(())
}

fn spawn_bridge(
    primary: &str,
    replica: &str,
    shutdown: CancellationToken,
) -> Result<JoinHandle<Result<()>>> {
    let config = BridgeConfig {
        primary: EndpointConfig::new(primary.parse()?, None),
        replica: EndpointConfig::new(replica.parse()?, None),
        poll_interval: Duration::from_millis(100),
        initial_streams: Vec::new(),
    };

    Ok(tokio::spawn(run_bridge(config, shutdown)))
}

async fn wait_for_replication(client: &Client, replica_base: &str) -> Result<()> {
    const MAX_ATTEMPTS: usize = 20;
    for attempt in 0..MAX_ATTEMPTS {
        let state = fetch_stream_state(client, replica_base, FED_CHAT_STREAM).await?;
        if let Some(message) = state.messages.first() {
            if message.client_id == DEFAULT_CLIENT_ID {
                info!(seq = message.seq, "replica observed bridged message");
                return Ok(());
            }
        }
        sleep(Duration::from_millis(100)).await;
        if attempt == MAX_ATTEMPTS - 1 {
            bail!("replica did not receive bridged message within timeout");
        }
    }
    Ok(())
}

async fn verify_mmr_roots(client: &Client, primary_base: &str, replica_base: &str) -> Result<()> {
    let primary_metrics = fetch_metrics(client, primary_base).await?;
    let replica_metrics = fetch_metrics(client, replica_base).await?;

    let primary_root = primary_metrics
        .mmr_roots
        .get(FED_CHAT_STREAM)
        .cloned()
        .ok_or_else(|| anyhow!("primary hub missing mmr root for {FED_CHAT_STREAM}"))?;
    let replica_root = replica_metrics
        .mmr_roots
        .get(FED_CHAT_STREAM)
        .cloned()
        .ok_or_else(|| anyhow!("replica hub missing mmr root for {FED_CHAT_STREAM}"))?;

    if primary_root != replica_root {
        bail!(
            "primary and replica mmr roots diverged: primary={} replica={}",
            primary_root,
            replica_root
        );
    }

    Ok(())
}

async fn verify_stream_root_match(
    client: &Client,
    primary_base: &str,
    replica_base: &str,
    stream: &str,
) -> Result<()> {
    let primary_metrics = fetch_metrics(client, primary_base).await?;
    let replica_metrics = fetch_metrics(client, replica_base).await?;

    let primary_root = primary_metrics
        .mmr_roots
        .get(stream)
        .cloned()
        .ok_or_else(|| anyhow!("primary hub missing mmr root for {stream}"))?;
    let replica_root = replica_metrics
        .mmr_roots
        .get(stream)
        .cloned()
        .ok_or_else(|| anyhow!("replica hub missing mmr root for {stream}"))?;

    ensure!(
        primary_root == replica_root,
        "mmr roots diverged for {stream}"
    );
    Ok(())
}

async fn fetch_stream_state(
    client: &Client,
    hub_base: &str,
    stream: &str,
) -> Result<HubStreamState> {
    let response = client
        .post(format!("{hub_base}/resync"))
        .json(&serde_json::json!({ "stream": stream }))
        .send()
        .await
        .context("requesting replica resync state")?;
    if response.status().is_success() {
        Ok(response
            .json::<HubStreamState>()
            .await
            .context("decoding replica stream state")?)
    } else if response.status().as_u16() == 404 {
        Ok(HubStreamState::default())
    } else {
        bail!("replica resync failed with status {}", response.status());
    }
}

async fn fetch_metrics(client: &Client, base: &str) -> Result<MetricsSnapshot> {
    client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .context("fetching hub metrics")?
        .error_for_status()
        .context("metrics endpoint returned error")?
        .json::<MetricsSnapshot>()
        .await
        .context("decoding metrics snapshot")
}

fn ensure_replica_rejects(status: reqwest::StatusCode) -> Result<()> {
    if status.is_success() {
        bail!("replica hub accepted write despite replica role");
    }
    Ok(())
}

fn next_listen_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}
