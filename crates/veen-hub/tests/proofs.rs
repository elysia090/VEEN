use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ciborium::ser::into_writer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::Client;
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::fs;

use veen_hub::pipeline::{StreamMessageWithProof, SubmitRequest, SubmitResponse};
use veen_hub::runtime::HubRuntime;
use veen_hub::runtime::{HubConfigOverrides, HubRole, HubRuntimeConfig};

const HUB_KEY_VERSION: u8 = 1;

#[derive(Serialize)]
struct TestHubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_proof_reuses_stored_entries() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub directory")?;
    ensure_hub_key(hub_dir.path()).await?;

    let listen = next_listen_addr()?;
    let config = HubRuntimeConfig::from_sources(
        listen,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            capability_gating_enabled: Some(false),
            ..HubConfigOverrides::default()
        },
    )
    .await?;

    let runtime = HubRuntime::start(config.clone()).await?;
    let client = Client::builder().no_proxy().build()?;
    let base = format!("http://{}", runtime.listen_addr());
    let stream = "proofs/constant";
    let client_id = hex::encode([0x11; 32]);

    for idx in 0..5u8 {
        submit_message(&client, &base, stream, &client_id, idx).await?;
    }

    runtime.shutdown().await?;

    let bundle = message_bundle_path(hub_dir.path(), stream, 5);
    overwrite_proof_peaks(&bundle, "deadbeef").await?;

    let runtime = HubRuntime::start(config).await?;
    let proven: Vec<StreamMessageWithProof> = client
        .get(format!("{}/stream", base))
        .query(&[("stream", stream), ("from", "5"), ("with_proof", "true")])
        .send()
        .await
        .context("requesting stream proofs")?
        .error_for_status()
        .context("stream endpoint returned error")?
        .json()
        .await
        .context("decoding proven messages")?;
    assert_eq!(
        proven.len(),
        1,
        "only the latest message should be returned"
    );
    assert_eq!(proven[0].proof.peaks_after, vec!["deadbeef".to_string()]);

    runtime.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_bundles_are_migrated() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub directory")?;
    ensure_hub_key(hub_dir.path()).await?;

    let listen = next_listen_addr()?;
    let config = HubRuntimeConfig::from_sources(
        listen,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            capability_gating_enabled: Some(false),
            ..HubConfigOverrides::default()
        },
    )
    .await?;

    let runtime = HubRuntime::start(config.clone()).await?;
    let client = Client::builder().no_proxy().build()?;
    let base = format!("http://{}", runtime.listen_addr());
    let stream = "proofs/migrate";
    let client_id = hex::encode([0x33; 32]);

    submit_message(&client, &base, stream, &client_id, 0).await?;

    runtime.shutdown().await?;

    let bundle = message_bundle_path(hub_dir.path(), stream, 1);
    strip_proof_metadata(&bundle).await?;

    let runtime = HubRuntime::start(config).await?;

    let proven: Vec<StreamMessageWithProof> = client
        .get(format!("{}/stream", base))
        .query(&[("stream", stream), ("with_proof", "true")])
        .send()
        .await
        .context("requesting stream proofs")?
        .error_for_status()
        .context("stream endpoint returned error")?
        .json()
        .await
        .context("decoding proven messages")?;
    assert_eq!(proven.len(), 1, "single legacy message should remain");
    assert!(!proven[0].receipt.mmr_root.is_empty());

    let data = fs::read(&bundle)
        .await
        .with_context(|| format!("reading migrated bundle from {}", bundle.display()))?;
    let value: Value = serde_json::from_slice(&data).context("decoding migrated bundle")?;
    assert!(
        value.get("receipt").is_some(),
        "migration must restore receipt metadata"
    );
    assert!(
        value.get("proof").is_some(),
        "migration must restore proof metadata"
    );

    runtime.shutdown().await?;
    Ok(())
}

async fn submit_message(
    client: &Client,
    base: &str,
    stream: &str,
    client_id: &str,
    idx: u8,
) -> Result<SubmitResponse> {
    client
        .post(format!("{}/submit", base))
        .json(&SubmitRequest {
            stream: stream.to_string(),
            client_id: client_id.to_string(),
            payload: json!({"text": format!("msg-{idx}")}),
            attachments: None,
            auth_ref: None,
            expires_at: None,
            schema: None,
            idem: None,
            pow_cookie: None,
        })
        .send()
        .await
        .context("submitting message")?
        .error_for_status()
        .context("submit endpoint returned error")?
        .json()
        .await
        .context("decoding submit response")
}

async fn overwrite_proof_peaks(path: &Path, marker: &str) -> Result<()> {
    let data = fs::read(path)
        .await
        .with_context(|| format!("reading bundle from {}", path.display()))?;
    let mut value: Value = serde_json::from_slice(&data).context("decoding bundle json")?;
    let proof = value
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .context("bundle missing proof")?;
    proof.insert(
        "peaks_after".to_string(),
        Value::Array(vec![Value::String(marker.to_string())]),
    );
    let encoded = serde_json::to_vec(&value).context("encoding patched bundle")?;
    fs::write(path, encoded)
        .await
        .with_context(|| format!("writing patched bundle to {}", path.display()))
}

async fn strip_proof_metadata(path: &Path) -> Result<()> {
    let data = fs::read(path)
        .await
        .with_context(|| format!("reading bundle from {}", path.display()))?;
    let mut value: Value = serde_json::from_slice(&data).context("decoding bundle json")?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("receipt");
        obj.remove("proof");
    }
    let encoded = serde_json::to_vec(&value).context("encoding stripped bundle")?;
    fs::write(path, encoded)
        .await
        .with_context(|| format!("writing stripped bundle to {}", path.display()))
}

async fn ensure_hub_key(data_dir: &Path) -> Result<()> {
    let path = data_dir.join("hub_key.cbor");
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking hub key at {}", path.display()))?
    {
        return Ok(());
    }

    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    let material = TestHubKeyMaterial {
        version: HUB_KEY_VERSION,
        created_at,
        public_key: ByteBuf::from(verifying.to_bytes().to_vec()),
        secret_key: ByteBuf::from(signing.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    into_writer(&material, &mut encoded).context("encoding hub key material")?;
    fs::write(&path, encoded)
        .await
        .with_context(|| format!("writing hub key material to {}", path.display()))
}

fn next_listen_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("binding ephemeral port")?;
    let addr = listener.local_addr().context("reading listener address")?;
    drop(listener);
    Ok(addr)
}

fn message_bundle_path(base_dir: &Path, stream: &str, seq: u64) -> PathBuf {
    base_dir
        .join("state")
        .join("messages")
        .join(format!("{}-{seq:08}.json", stream_storage_name(stream)))
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
