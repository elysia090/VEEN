use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, ensure, Context, Result};
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::Digest;
use tempfile::TempDir;
use tokio::fs;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use veen_core::label::Label;
use veen_core::wire::checkpoint::{Checkpoint, CHECKPOINT_VERSION};
use veen_core::wire::types::{MmrRoot, Signature64};
use veen_hub::pipeline::{AnchorLog, AnchorRequest};
use veen_hub::runtime::HubRuntime;
use veen_hub::runtime::{HubConfigOverrides, HubRole, HubRuntimeConfig};
mod support;
use support::{
    client_id_hex, decode_submit_response_cbor, encode_submit_msg, encode_submit_request_cbor,
};

/// Scenario acceptance covering audit anchor workflows with checkpoint binding.
///
/// Expectations:
/// - Stand up a pseudo-anchor backend capable of accepting checkpoints.
/// - Bind submitted checkpoints to their corresponding MMR roots.
/// - Verify that anchored state can be audited against the pseudo-backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_audit_anchor() -> Result<()> {
    let pseudo_backend = PseudoAnchor::spawn().await?;
    let hub_dir = TempDir::new().context("creating hub directory for anchor scenario")?;
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
            anchor_backend: Some("pseudo-backend".into()),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    let runtime = HubRuntime::start(config).await?;

    let http = reqwest::Client::builder().no_proxy().build()?;
    let stream = "audit/tooling/anchor";
    let client_signing = generate_client_id();
    let client_id = client_id_hex(&client_signing);
    let msg = encode_submit_msg(
        stream,
        &client_signing,
        1,
        0,
        None,
        &serde_json::to_vec(&serde_json::json!({"text":"anchor"}))?,
    )?;
    let submit_request = veen_hub::pipeline::SubmitRequest {
        stream: stream.to_string(),
        client_id: client_id.clone(),
        msg,
        attachments: None,
        auth_ref: None,
        idem: None,
        pow_cookie: None,
    };
    let submit_body = encode_submit_request_cbor(&submit_request)?;
    let submit = decode_submit_response_cbor(
        &http
            .post(format!("http://{}/v1/submit", runtime.listen_addr()))
            .header("Content-Type", "application/cbor")
            .body(submit_body)
            .send()
            .await
            .context("submitting anchor-bound message")?
            .error_for_status()
            .context("submit endpoint returned error for anchor scenario")?
            .bytes()
            .await
            .context("reading anchor submit response")?,
    )?;

    let submit_mmr_root = hex::encode(submit.receipt.mmr_root.as_bytes());
    let checkpoint_bytes = create_signed_checkpoint(
        hub_dir.path(),
        stream,
        submit.receipt.stream_seq,
        &submit_mmr_root,
    )
    .await?;
    append_checkpoint(hub_dir.path(), &checkpoint_bytes).await?;

    pseudo_backend
        .submit(
            stream,
            submit.receipt.stream_seq,
            &submit_mmr_root,
            &checkpoint_bytes,
        )
        .await
        .context("submitting checkpoint to pseudo backend")?;

    http.post(format!("http://{}/tooling/anchor", runtime.listen_addr()))
        .json(&AnchorRequest {
            stream: stream.to_string(),
            mmr_root: submit_mmr_root.clone(),
            backend: Some("pseudo-backend".into()),
        })
        .send()
        .await
        .context("sending anchor request to hub")?
        .error_for_status()
        .context("hub rejected anchor request")?;

    let backend_url = format!("http://{}", pseudo_backend.listen_addr());

    runtime.shutdown().await?;
    pseudo_backend.shutdown().await?;

    let entries = pseudo_backend.records().await;
    ensure!(
        !entries.is_empty(),
        "pseudo backend did not store any checkpoints"
    );
    let stored = entries
        .into_iter()
        .find(|entry| entry.stream == stream)
        .ok_or_else(|| anyhow!("pseudo backend missing record for {stream}"))?;
    ensure!(
        stored.mmr_root == submit_mmr_root,
        "pseudo backend recorded unexpected mmr root"
    );
    ensure!(
        stored.upto_seq == submit.receipt.stream_seq,
        "pseudo backend recorded unexpected upto_seq"
    );

    let decoded: Checkpoint = from_reader(stored.checkpoint.as_slice())
        .context("decoding stored checkpoint for audit verification")?;
    ensure!(
        hex::encode(decoded.mmr_root.as_bytes()) == submit_mmr_root,
        "decoded checkpoint mmr_root does not match submission"
    );
    ensure!(
        decoded.upto_seq == submit.receipt.stream_seq,
        "decoded checkpoint upto_seq does not match submission"
    );

    let anchor_log = read_anchor_log(hub_dir.path()).await?;
    let record = anchor_log
        .entries
        .into_iter()
        .find(|record| record.stream == stream)
        .ok_or_else(|| anyhow!("anchor log missing record for {stream}"))?;
    ensure!(
        record.mmr_root == submit_mmr_root,
        "anchor log mmr root mismatch"
    );
    ensure!(
        record.backend.as_deref() == Some("pseudo-backend"),
        "anchor log did not record pseudo backend binding"
    );

    let label_hex = hex::encode(decoded.label_curr.as_bytes());
    let checkpoint_mmr_root = hex::encode(decoded.mmr_root.as_bytes());
    let report = format_goal_audit_anchor_report(
        stream,
        submit.receipt.stream_seq,
        &label_hex,
        &backend_url,
        &checkpoint_mmr_root,
        &stored.mmr_root,
        &record.mmr_root,
    );
    println!("{report}");

    Ok(())
}

struct PseudoAnchor {
    state: Arc<Mutex<Vec<PseudoAnchorRecord>>>,
    shutdown: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    join: Arc<Mutex<Option<JoinHandle<Result<()>>>>>,
    addr: SocketAddr,
}

impl PseudoAnchor {
    async fn spawn() -> Result<Self> {
        let listener =
            TcpListener::bind("127.0.0.1:0").context("binding pseudo anchor listener")?;
        let state = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let router = Router::new()
            .route("/checkpoint", post(Self::handle_checkpoint))
            .with_state(state.clone());
        listener
            .set_nonblocking(true)
            .context("setting pseudo anchor listener non-blocking")?;
        let listener =
            TokioTcpListener::from_std(listener).context("converting pseudo anchor listener")?;
        let addr = listener
            .local_addr()
            .context("querying pseudo anchor listener address")?;
        let server = axum::serve(listener, router).with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
        let join = tokio::spawn(async move {
            server
                .await
                .map_err(|err| anyhow!("pseudo anchor server error: {err}"))
        });
        Ok(Self {
            state,
            shutdown: Arc::new(Mutex::new(Some(shutdown_tx))),
            join: Arc::new(Mutex::new(Some(join))),
            addr,
        })
    }

    fn listen_addr(&self) -> SocketAddr {
        self.addr
    }

    async fn submit(
        &self,
        stream: &str,
        upto_seq: u64,
        mmr_root: &str,
        checkpoint: &[u8],
    ) -> Result<()> {
        let client = reqwest::Client::builder().no_proxy().build()?;
        client
            .post(format!("http://{}/checkpoint", self.addr))
            .json(&PseudoAnchorSubmission {
                stream: stream.to_string(),
                upto_seq,
                mmr_root: mmr_root.to_string(),
                checkpoint: hex::encode(checkpoint),
            })
            .send()
            .await
            .context("sending checkpoint to pseudo anchor")?
            .error_for_status()
            .context("pseudo anchor rejected checkpoint submission")?;
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(tx) = self.shutdown.lock().await.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join.lock().await.take() {
            handle.await.context("awaiting pseudo anchor shutdown")??;
        }
        Ok(())
    }

    async fn records(&self) -> Vec<PseudoAnchorRecord> {
        let guard = self.state.lock().await;
        guard.clone()
    }

    async fn handle_checkpoint(
        State(state): State<Arc<Mutex<Vec<PseudoAnchorRecord>>>>,
        Json(payload): Json<PseudoAnchorSubmission>,
    ) -> Result<(), (axum::http::StatusCode, String)> {
        let checkpoint = match hex::decode(&payload.checkpoint) {
            Ok(bytes) => bytes,
            Err(err) => {
                return Err((
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("invalid checkpoint encoding: {err}"),
                ))
            }
        };
        let mut guard = state.lock().await;
        guard.push(PseudoAnchorRecord {
            stream: payload.stream,
            upto_seq: payload.upto_seq,
            mmr_root: payload.mmr_root,
            checkpoint,
        });
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PseudoAnchorSubmission {
    stream: String,
    upto_seq: u64,
    mmr_root: String,
    checkpoint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PseudoAnchorRecord {
    stream: String,
    upto_seq: u64,
    mmr_root: String,
    #[serde(with = "serde_bytes")]
    checkpoint: Vec<u8>,
}

fn format_goal_audit_anchor_report(
    stream: &str,
    upto_seq: u64,
    label_hex: &str,
    backend_url: &str,
    checkpoint_mmr_root: &str,
    pseudo_backend_mmr_root: &str,
    anchor_log_mmr_root: &str,
) -> String {
    format!(
        concat!(
            "goal: AUDIT.ANCHOR",
            " stream={stream}",
            " label={label}",
            " upto_seq={upto}",
            " backend_uri={backend}",
            " mmr_root.checkpoint={checkpoint}",
            " mmr_root.backend={pseudo} (matches checkpoint)",
            " mmr_root.anchor_log={anchor} (matches checkpoint)"
        ),
        stream = stream,
        label = label_hex,
        upto = upto_seq,
        backend = backend_url,
        checkpoint = checkpoint_mmr_root,
        pseudo = pseudo_backend_mmr_root,
        anchor = anchor_log_mmr_root,
    )
}

fn generate_client_id() -> SigningKey {
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
    into_writer(&material, &mut encoded).context("encoding hub key material")?;
    fs::write(&path, encoded)
        .await
        .with_context(|| format!("writing hub key material to {}", path.display()))
}

async fn create_signed_checkpoint(
    data_dir: &Path,
    stream: &str,
    upto_seq: u64,
    mmr_root_hex: &str,
) -> Result<Vec<u8>> {
    let key_path = data_dir.join("hub_key.cbor");
    let key_bytes = fs::read(&key_path)
        .await
        .with_context(|| format!("reading hub key from {}", key_path.display()))?;
    let material: HubKeyMaterial =
        from_reader(key_bytes.as_slice()).context("decoding hub key material")?;
    if material.version != HUB_KEY_VERSION {
        bail!("unsupported hub key version {}", material.version);
    }
    if material.secret_key.len() != 32 || material.public_key.len() != 32 {
        bail!("hub key material must contain 32-byte keys");
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(material.secret_key.as_ref());
    let signing = SigningKey::from_bytes(&secret);

    let label_bytes = sha2::Sha256::digest(stream.as_bytes());
    let label = Label::from_slice(&label_bytes).context("constructing checkpoint label")?;
    let mmr_root = parse_mmr_root_hex(mmr_root_hex)?;

    let mut checkpoint = Checkpoint {
        ver: CHECKPOINT_VERSION,
        label_prev: label,
        label_curr: label,
        upto_seq,
        mmr_root,
        epoch: upto_seq,
        hub_sig: Signature64::from([0u8; 64]),
        witness_sigs: None,
    };
    let digest = checkpoint
        .signing_tagged_hash()
        .context("computing checkpoint signing digest")?;
    let signature = signing.sign(&digest);
    checkpoint.hub_sig = Signature64::from(signature.to_bytes());

    let mut encoded = Vec::new();
    into_writer(&checkpoint, &mut encoded).context("encoding checkpoint to cbor")?;
    Ok(encoded)
}

async fn append_checkpoint(data_dir: &Path, checkpoint: &[u8]) -> Result<()> {
    let path = data_dir.join("checkpoints.cborseq");
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("opening checkpoint log {}", path.display()))?;
    use tokio::io::AsyncWriteExt;
    file.write_all(checkpoint)
        .await
        .context("appending checkpoint payload")?;
    file.flush()
        .await
        .context("flushing checkpoint log to disk")
}

async fn read_anchor_log(data_dir: &Path) -> Result<AnchorLog> {
    let path = data_dir.join("anchors").join("anchor_log.json");
    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading anchor log from {}", path.display()))?;
    let log = serde_json::from_slice(&data)
        .with_context(|| format!("decoding anchor log from {}", path.display()))?;
    Ok(log)
}

fn parse_mmr_root_hex(value: &str) -> Result<MmrRoot> {
    let bytes = hex::decode(value).with_context(|| format!("decoding mmr root {value}"))?;
    MmrRoot::from_slice(&bytes).with_context(|| format!("parsing mmr root {value}"))
}

fn next_listen_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding ephemeral port")?;
    let addr = listener
        .local_addr()
        .context("retrieving listener address")?;
    drop(listener);
    Ok(addr)
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
