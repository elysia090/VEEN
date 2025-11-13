use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use ciborium::de::from_reader;
use reqwest::Client;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use veen_hub::config::{HubRole, HubRuntimeConfig};
use veen_hub::pipeline::{
    AnchorRequest, AttachmentUpload, CapabilityRequest, SubmitRequest, SubmitResponse,
};
use veen_hub::runtime::HubRuntime;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_core_pipeline() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub temp directory")?;
    let client_dir = hub_dir.path().join("client");

    run_cli(["keygen", "--out", client_dir.to_str().unwrap()])
        .context("generating client identity")?;

    let listen_addr = next_listen_addr()?;
    let config = HubRuntimeConfig::from_sources(
        listen_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
    )
    .await?;
    let runtime = HubRuntime::start(config).await?;

    let client_id = read_client_id(&client_dir.join("identity_card.pub"))?;

    let http = Client::new();
    let submit_endpoint = format!("http://{}/submit", runtime.listen_addr());

    let _main_response: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/main".to_string(),
            client_id: client_id.clone(),
            payload: serde_json::json!({ "text": "hello-veens" }),
            attachments: None,
            capability: None,
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting core message")?
        .error_for_status()
        .context("submit endpoint returned error")?
        .json()
        .await
        .context("parsing submit response")?;

    run_cli([
        "stream",
        "--hub",
        hub_dir.path().to_str().unwrap(),
        "--client",
        client_dir.to_str().unwrap(),
        "--stream",
        "core/main",
        "--from",
        "0",
    ])
    .context("streaming messages via CLI")?;

    // Attachments
    let attachment_path = hub_dir.path().join("attachment.bin");
    std::fs::write(&attachment_path, b"attachment-bytes")
        .context("writing attachment test file")?;
    let attachment_data = BASE64_ENGINE.encode(std::fs::read(&attachment_path)?);

    let attachment_response: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/att".to_string(),
            client_id: client_id.clone(),
            payload: serde_json::json!({ "text": "attachment" }),
            attachments: Some(vec![AttachmentUpload {
                name: Some("file.bin".into()),
                data: attachment_data,
            }]),
            capability: None,
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting attachment message")?
        .error_for_status()
        .context("attachment submit returned error")?
        .json()
        .await
        .context("parsing attachment submit response")?;

    let bundle_path = message_bundle_path(hub_dir.path(), "core/att", attachment_response.seq);
    run_cli([
        "attachment",
        "verify",
        "--msg",
        bundle_path.to_str().unwrap(),
        "--file",
        attachment_path.to_str().unwrap(),
        "--index",
        "0",
    ])
    .context("verifying attachment via CLI")?;

    // Capability issuance via CLI, authorization via HTTP.
    let admin_dir = hub_dir.path().join("admin");
    run_cli(["keygen", "--out", admin_dir.to_str().unwrap()])
        .context("generating admin identity")?;

    let cap_file = hub_dir.path().join("cap.json");
    run_cli([
        "cap",
        "issue",
        "--issuer",
        admin_dir.to_str().unwrap(),
        "--subject",
        client_dir.to_str().unwrap(),
        "--stream",
        "core/capped",
        "--ttl",
        "600",
        "--out",
        cap_file.to_str().unwrap(),
    ])
    .context("issuing capability via CLI")?;

    let cap_token: CapabilityFile = read_json(&cap_file)?;
    http.post(format!("http://{}/authorize", runtime.listen_addr()))
        .json(&CapabilityRequest {
            token_id: cap_token.token_id.clone(),
            subject: hex::encode(&cap_token.subject),
            stream: cap_token.stream.clone(),
            expires_at: cap_token.expires_at,
            max_uses: Some(2),
        })
        .send()
        .await
        .context("authorizing capability")?
        .error_for_status()
        .context("authorize endpoint returned error")?;

    let unauthorized = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: "deadbeef".into(),
            payload: serde_json::json!({"text":"denied"}),
            attachments: None,
            capability: Some(cap_token.token_id.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting unauthorized message")?;
    assert!(unauthorized.status().is_client_error());

    let _authorized: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: hex::encode(&cap_token.subject),
            payload: serde_json::json!({"text":"authorized"}),
            attachments: None,
            capability: Some(cap_token.token_id.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting authorized message")?
        .error_for_status()
        .context("authorized submit returned error")?
        .json()
        .await
        .context("parsing authorized submit response")?;

    // Anchor log via HTTP
    http.post(format!("http://{}/anchor", runtime.listen_addr()))
        .json(&AnchorRequest {
            stream: "core/main".into(),
            mmr_root: "mmr-root".into(),
            backend: Some("file".into()),
        })
        .send()
        .await
        .context("submitting anchor request")?
        .error_for_status()
        .context("anchor endpoint returned error")?;

    // Metrics & health endpoints
    http.get(format!("http://{}/metrics", runtime.listen_addr()))
        .send()
        .await
        .context("fetching metrics")?
        .error_for_status()
        .context("metrics endpoint error")?;

    http.get(format!("http://{}/healthz", runtime.listen_addr()))
        .send()
        .await
        .context("fetching healthz")?
        .error_for_status()
        .context("healthz endpoint error")?;

    run_cli(["selftest", "core"]).context("running selftest core suite")?;

    runtime.shutdown().await?;
    Ok(())
}

fn next_listen_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding ephemeral port")?;
    let port = listener
        .local_addr()
        .context("retrieving listener address")?
        .port();
    drop(listener);
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

fn run_cli<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let status = StdCommand::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("veen-cli")
        .arg("--")
        .args(args)
        .status()
        .context("executing veen-cli command")?;
    if !status.success() {
        bail!("veen-cli command failed with status {status}");
    }
    Ok(())
}

fn read_client_id(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let bundle: ClientPublicBundle = from_reader(file).context("decoding client identity card")?;
    Ok(hex::encode(bundle.client_id))
}

fn message_bundle_path(hub_dir: &Path, stream: &str, seq: u64) -> PathBuf {
    let name = stream_storage_name(stream);
    hub_dir
        .join("state")
        .join("messages")
        .join(format!("{name}-{seq:08}.json"))
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

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let value = serde_json::from_slice(&data)
        .with_context(|| format!("decoding JSON from {}", path.display()))?;
    Ok(value)
}

#[derive(Deserialize)]
struct CapabilityFile {
    token_id: String,
    #[serde(with = "serde_bytes")]
    subject: ByteBuf,
    stream: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct ClientPublicBundle {
    #[serde(with = "serde_bytes")]
    client_id: ByteBuf,
}
