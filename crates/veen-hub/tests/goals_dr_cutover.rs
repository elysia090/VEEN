use std::net::{SocketAddr, TcpListener};
use std::path::Path;

use anyhow::{anyhow, ensure, Context, Result};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tempfile::TempDir;
use tokio::fs;

use veen_hub::pipeline::{
    BridgeIngestRequest, BridgeIngestResponse, StreamMessageWithProof, SubmitRequest,
};
use veen_hub::runtime::HubRuntime;
use veen_hub::runtime::{HubConfigOverrides, HubRole, HubRuntimeConfig};
mod support;
use support::{
    client_id_hex, decode_stream_response_cbor, decode_submit_response_cbor,
    encode_stream_request_cbor, encode_submit_msg, encode_submit_request_cbor,
    stream_items_to_proofs,
};

/// Scenario acceptance covering disaster recovery cutover with replicated hubs.
///
/// Expectations:
/// - Bootstrap hub A and hub B connected through a bridge for replication.
/// - Promote hub B after verifying replication from hub A.
/// - Validate matching MMR roots and transfer identifiers after cutover.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_dr_cutover() -> Result<()> {
    let primary_dir = TempDir::new().context("creating primary hub directory")?;
    let replica_dir = TempDir::new().context("creating replica hub directory")?;

    ensure_hub_key(primary_dir.path()).await?;
    ensure_hub_key(replica_dir.path()).await?;

    let primary_addr = next_listen_addr()?;
    let replica_addr = next_listen_addr()?;

    let primary_runtime = HubRuntime::start(
        HubRuntimeConfig::from_sources(
            primary_addr,
            primary_dir.path().to_path_buf(),
            None,
            HubRole::Primary,
            HubConfigOverrides {
                tooling_enabled: Some(true),
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            },
        )
        .await?,
    )
    .await?;

    let replica_runtime = HubRuntime::start(
        HubRuntimeConfig::from_sources(
            replica_addr,
            replica_dir.path().to_path_buf(),
            None,
            HubRole::Replica,
            HubConfigOverrides {
                tooling_enabled: Some(true),
                capability_gating_enabled: Some(false),
                replica_targets: Some(vec![format!("http://{}", primary_addr)]),
                ..HubConfigOverrides::default()
            },
        )
        .await?,
    )
    .await?;

    let http = Client::builder().no_proxy().build()?;
    let stream = "dr/cutover";
    let client_signing = generate_client_signing();
    let client_id = client_id_hex(&client_signing);

    let primary_base = format!("http://{}", primary_runtime.listen_addr());
    let replica_base = format!("http://{}", replica_runtime.listen_addr());

    let mut submit_roots = Vec::new();
    let mut bridged_receipts = 0usize;
    for idx in 0..3u8 {
        let body = serde_json::json!({"text": format!("primary-{idx}")});
        let msg = encode_submit_msg(
            stream,
            &client_signing,
            u64::from(idx) + 1,
            0,
            None,
            &serde_json::to_vec(&body)?,
        )?;
        let submit_request = SubmitRequest {
            stream: stream.to_string(),
            client_id: client_id.clone(),
            msg,
            attachments: None,
            auth_ref: None,
            idem: None,
            pow_cookie: None,
        };
        let submit_body = encode_submit_request_cbor(&submit_request)?;
        let response = decode_submit_response_cbor(
            &http
                .post(format!("{}/v1/submit", primary_base))
                .header("Content-Type", "application/cbor")
                .body(submit_body)
                .send()
                .await
                .context("submitting primary message")?
                .error_for_status()
                .context("primary submit returned error")?
                .bytes()
                .await
                .context("reading primary submit response")?,
        )?;
        submit_roots.push(response);
    }

    let stream_body = encode_stream_request_cbor(stream, 1, None, true)?;
    let response = decode_stream_response_cbor(
        &http
            .post(format!("{}/v1/stream", primary_base))
            .header("Content-Type", "application/cbor")
            .body(stream_body)
            .send()
            .await
            .context("fetching proven stream messages from primary")?
            .error_for_status()
            .context("primary stream endpoint returned error")?
            .bytes()
            .await
            .context("reading primary stream response")?,
    )?;
    let proven: Vec<StreamMessageWithProof> = stream_items_to_proofs(response.items)?;
    ensure!(
        proven.len() == submit_roots.len(),
        "expected proven messages to match submissions"
    );

    for message in proven {
        let ingest: BridgeIngestResponse = http
            .post(format!("{}/tooling/bridge", replica_base))
            .json(&BridgeIngestRequest {
                message: message.message.clone(),
                expected_mmr_root: message.receipt.mmr_root.clone(),
            })
            .send()
            .await
            .context("forwarding message to replica")?
            .error_for_status()
            .context("replica bridge ingestion failed")?
            .json()
            .await
            .context("decoding bridge ingest response")?;
        ensure!(
            ingest.mmr_root == message.receipt.mmr_root,
            "replica computed unexpected mmr root"
        );
        bridged_receipts += 1;
    }

    let primary_metrics: ObservabilitySnapshot = http
        .get(format!("{}/tooling/metrics", primary_base))
        .send()
        .await
        .context("fetching primary metrics")?
        .error_for_status()
        .context("primary metrics endpoint returned error")?
        .json()
        .await
        .context("decoding primary metrics")?;
    let replica_metrics: ObservabilitySnapshot = http
        .get(format!("{}/tooling/metrics", replica_base))
        .send()
        .await
        .context("fetching replica metrics")?
        .error_for_status()
        .context("replica metrics endpoint returned error")?
        .json()
        .await
        .context("decoding replica metrics")?;

    let primary_root = primary_metrics
        .mmr_roots
        .get(stream)
        .cloned()
        .ok_or_else(|| anyhow!("primary missing mmr root for {stream}"))?;
    let replica_root = replica_metrics
        .mmr_roots
        .get(stream)
        .cloned()
        .ok_or_else(|| anyhow!("replica missing mmr root for {stream}"))?;
    ensure!(
        primary_root == replica_root,
        "replica MMR root diverged before cutover"
    );

    primary_runtime.shutdown().await?;
    replica_runtime.shutdown().await?;

    let promoted_runtime = HubRuntime::start(
        HubRuntimeConfig::from_sources(
            replica_addr,
            replica_dir.path().to_path_buf(),
            None,
            HubRole::Primary,
            HubConfigOverrides {
                tooling_enabled: Some(true),
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            },
        )
        .await?,
    )
    .await?;

    let promoted_base = format!("http://{}", promoted_runtime.listen_addr());
    let promote_body = serde_json::json!({"text":"cutover"});
    let promote_msg = encode_submit_msg(
        stream,
        &client_signing,
        4,
        0,
        None,
        &serde_json::to_vec(&promote_body)?,
    )?;
    let promote_request = SubmitRequest {
        stream: stream.to_string(),
        client_id: client_id.clone(),
        msg: promote_msg,
        attachments: None,
        auth_ref: None,
        idem: None,
        pow_cookie: None,
    };
    let promote_body = encode_submit_request_cbor(&promote_request)?;
    let promote_response = decode_submit_response_cbor(
        &http
            .post(format!("{}/v1/submit", promoted_base))
            .header("Content-Type", "application/cbor")
            .body(promote_body)
            .send()
            .await
            .context("submitting message after cutover")?
            .error_for_status()
            .context("promoted hub rejected submission")?
            .bytes()
            .await
            .context("reading promoted submission response")?,
    )?;
    ensure!(
        promote_response.seq as usize == submit_roots.len() + 1,
        "promoted hub did not continue sequence"
    );

    let promoted_metrics: ObservabilitySnapshot = http
        .get(format!("{}/tooling/metrics", promoted_base))
        .send()
        .await
        .context("fetching promoted hub metrics")?
        .error_for_status()
        .context("promoted metrics endpoint returned error")?
        .json()
        .await
        .context("decoding promoted metrics")?;
    let promoted_root = promoted_metrics
        .mmr_roots
        .get(stream)
        .cloned()
        .ok_or_else(|| anyhow!("promoted hub missing mmr root"))?;
    ensure!(
        promoted_root == promote_response.mmr_root,
        "promoted hub reported inconsistent mmr root"
    );

    log_goal_dr_cutover(GoalDrCutoverSummary {
        stream: stream.to_string(),
        primary_addr,
        replica_addr,
        bridged_receipts,
        shared_mmr_root_before_cutover: primary_root.clone(),
        post_promotion_seq: promote_response.seq,
        post_promotion_root: promoted_root.clone(),
    });

    promoted_runtime.shutdown().await?;
    Ok(())
}

fn generate_client_signing() -> ed25519_dalek::SigningKey {
    use ed25519_dalek::SigningKey;
    let mut rng = OsRng;
    SigningKey::generate(&mut rng)
}

async fn ensure_hub_key(data_dir: &Path) -> Result<()> {
    let path = data_dir.join("hub_key.cbor");
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking hub key at {}", path.display()))?
    {
        return Ok(());
    }

    use ed25519_dalek::SigningKey;
    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    let material = HubKeyMaterial {
        version: HUB_KEY_VERSION,
        created_at,
        public_key: ByteBuf::from(verifying.to_bytes().to_vec()),
        secret_key: ByteBuf::from(signing.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&material, &mut encoded).context("encoding hub key material")?;
    fs::write(&path, encoded)
        .await
        .with_context(|| format!("writing hub key material to {}", path.display()))
}

fn next_listen_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding ephemeral port")?;
    let addr = listener
        .local_addr()
        .context("retrieving listener address")?;
    drop(listener);
    Ok(addr)
}

#[derive(Deserialize)]
struct ObservabilitySnapshot {
    mmr_roots: std::collections::HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct HubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

const HUB_KEY_VERSION: u8 = 1;

struct GoalDrCutoverSummary {
    stream: String,
    primary_addr: SocketAddr,
    replica_addr: SocketAddr,
    bridged_receipts: usize,
    shared_mmr_root_before_cutover: String,
    post_promotion_seq: u64,
    post_promotion_root: String,
}

fn log_goal_dr_cutover(summary: GoalDrCutoverSummary) {
    println!(
        "goal: DR.CUTOVER\n\
stream: {}\n\
primary_listen_addr: {}\n\
replica_listen_addr: {}\n\
bridged_receipts: {}\n\
shared_mmr_root_before_cutover: {}\n\
post_promotion_sequence: {}\n\
post_promotion_root: {}",
        summary.stream,
        summary.primary_addr,
        summary.replica_addr,
        summary.bridged_receipts,
        summary.shared_mmr_root_before_cutover,
        summary.post_promotion_seq,
        summary.post_promotion_root,
    );
}
