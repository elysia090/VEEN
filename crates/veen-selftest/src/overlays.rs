use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;
use tempfile::TempDir;
use tokio::fs;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::info;

use veen_bridge::{run_bridge, BridgeConfig, EndpointConfig};
use veen_hub::config::{HubConfigOverrides, HubRole, HubRuntimeConfig};
use veen_hub::pipeline::{HubStreamState, SubmitRequest};
use veen_hub::runtime::HubRuntime;
use veen_hub::storage::HUB_KEY_FILE;

use crate::{SelftestGoalReport, SelftestReporter};

const FED_CHAT_STREAM: &str = "fed/chat";
const DEFAULT_CLIENT_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
    match subset {
        None | Some("fed-auth") => run_fed_auth()
            .await
            .context("executing federation authority overlay self-test")?,
        Some(other) => bail!("unknown overlay subset {other}"),
    }
    let subset_label = subset.unwrap_or("fed-auth");
    reporter.record(SelftestGoalReport {
        goal: format!("SELFTEST.OVERLAYS.{subset_label}"),
        environment: vec![
            format!("subset={subset_label}"),
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

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_secs()
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
        let state = fetch_replica_stream(client, replica_base).await?;
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

async fn fetch_replica_stream(client: &Client, replica_base: &str) -> Result<HubStreamState> {
    let response = client
        .post(format!("{replica_base}/resync"))
        .json(&serde_json::json!({ "stream": FED_CHAT_STREAM }))
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
