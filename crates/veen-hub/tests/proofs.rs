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

use veen_hub::pipeline::{SubmitRequest, SubmitResponse};
use veen_hub::runtime::HubRuntime;
use veen_hub::runtime::{HubConfigOverrides, HubRole, HubRuntimeConfig};
mod support;
use support::{
    client_id_hex, decode_stream_response_cbor, decode_submit_response_cbor,
    encode_stream_request_cbor, encode_submit_msg, encode_submit_request_cbor,
};

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
            tooling_enabled: Some(true),
            capability_gating_enabled: Some(false),
            ..HubConfigOverrides::default()
        },
    )
    .await?;

    let runtime = HubRuntime::start(config.clone()).await?;
    let client = Client::builder().no_proxy().build()?;
    let base = format!("http://{}", runtime.listen_addr());
    let stream = "proofs/constant";
    let mut rng = OsRng;
    let client_signing = SigningKey::generate(&mut rng);

    for idx in 0..5u8 {
        submit_message(&client, &base, stream, &client_signing, idx).await?;
    }

    runtime.shutdown().await?;

    let bundle = message_bundle_path(hub_dir.path(), stream, 5);
    overwrite_proof_peaks(&bundle, "deadbeef").await?;

    let runtime = HubRuntime::start(config).await?;
    let stream_body = encode_stream_request_cbor(stream, 5, None, true)?;
    let response = decode_stream_response_cbor(
        &client
            .post(format!("{}/v1/stream", base))
            .header("Content-Type", "application/cbor")
            .body(stream_body)
            .send()
            .await
            .context("requesting stream proofs")?
            .error_for_status()
            .context("stream endpoint returned error")?
            .bytes()
            .await
            .context("reading stream response")?,
    )?;
    assert_eq!(
        response.items.len(),
        1,
        "only the latest message should be returned"
    );
    let proof = response
        .mmr_proof
        .ok_or_else(|| anyhow::anyhow!("stream response missing mmr proof"))?;
    let peak_hex = hex::encode(
        proof
            .peaks_after
            .first()
            .ok_or_else(|| anyhow::anyhow!("stream response missing proof peaks"))?
            .as_bytes(),
    );
    assert_eq!(peak_hex, "deadbeef".repeat(8));

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
            tooling_enabled: Some(true),
            capability_gating_enabled: Some(false),
            ..HubConfigOverrides::default()
        },
    )
    .await?;

    let runtime = HubRuntime::start(config.clone()).await?;
    let client = Client::builder().no_proxy().build()?;
    let base = format!("http://{}", runtime.listen_addr());
    let stream = "proofs/migrate";
    let mut rng = OsRng;
    let client_signing = SigningKey::generate(&mut rng);

    submit_message(&client, &base, stream, &client_signing, 0).await?;

    runtime.shutdown().await?;

    let bundle = message_bundle_path(hub_dir.path(), stream, 1);
    strip_proof_metadata(&bundle).await?;

    let runtime = HubRuntime::start(config).await?;

    let stream_body = encode_stream_request_cbor(stream, 0, None, true)?;
    let response = decode_stream_response_cbor(
        &client
            .post(format!("{}/v1/stream", base))
            .header("Content-Type", "application/cbor")
            .body(stream_body)
            .send()
            .await
            .context("requesting stream proofs")?
            .error_for_status()
            .context("stream endpoint returned error")?
            .bytes()
            .await
            .context("reading stream response")?,
    )?;
    assert_eq!(
        response.items.len(),
        1,
        "single legacy message should remain"
    );
    let receipt = response.items[0]
        .receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing receipt in stream response"))?;
    assert!(
        receipt.mmr_root.as_bytes().iter().any(|value| *value != 0),
        "receipt must carry a non-empty MMR root"
    );

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
    client_signing: &SigningKey,
    idx: u8,
) -> Result<SubmitResponse> {
    let msg = encode_submit_msg(
        stream,
        client_signing,
        u64::from(idx) + 1,
        0,
        None,
        &serde_json::to_vec(&json!({"text": format!("msg-{idx}")}))?,
    )?;
    let submit_request = SubmitRequest {
        stream: stream.to_string(),
        client_id: client_id_hex(client_signing),
        msg,
        attachments: None,
        auth_ref: None,
        idem: None,
        pow_cookie: None,
    };
    let submit_body = encode_submit_request_cbor(&submit_request)?;
    decode_submit_response_cbor(
        &client
            .post(format!("{}/v1/submit", base))
            .header("Content-Type", "application/cbor")
            .body(submit_body)
            .send()
            .await
            .context("submitting message")?
            .error_for_status()
            .context("submit endpoint returned error")?
            .bytes()
            .await
            .context("reading submit response")?,
    )
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
        Value::Array(vec![Value::String(marker.repeat(8))]),
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
