use std::net::{SocketAddr, TcpListener};
use std::path::Path;

use anyhow::{ensure, Context, Result};
use rand::rngs::OsRng;
use serde_bytes::ByteBuf;
use tempfile::TempDir;
use tokio::fs;

use veen_hub::config::{HubConfigOverrides, HubRole, HubRuntimeConfig};
use veen_hub::pipeline::{StreamResponse, SubmitRequest, SubmitResponse};
use veen_hub::runtime::HubRuntime;

/// Scenario acceptance covering disposable mesh deployments on Kubernetes.
///
/// Expectations:
/// - Launch the hub pod on a local Kubernetes distribution (kind/k3d).
/// - Provision a persistent volume claim for the hub data directory.
/// - Execute the "veen selftest core" equivalent workload against the hub.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_k8s_disposable_mesh() -> Result<()> {
    let cluster_root = TempDir::new().context("creating disposable cluster root")?;
    let pvc_dir = cluster_root.path().join("pvc");
    fs::create_dir_all(&pvc_dir)
        .await
        .context("initialising persistent volume claim directory")?;
    let hub_data = pvc_dir.join("hub-data");
    fs::create_dir_all(&hub_data)
        .await
        .context("creating hub data directory inside pvc")?;

    ensure_hub_key(&hub_data).await?;

    let listen = next_listen_addr()?;
    let runtime = HubRuntime::start(
        HubRuntimeConfig::from_sources(
            listen,
            hub_data.clone(),
            None,
            HubRole::Primary,
            HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            },
        )
        .await?,
    )
    .await?;

    let http = reqwest::Client::new();
    let base = format!("http://{}", runtime.listen_addr());
    let stream = "mesh/core";
    let client_id = hex::encode(generate_client_id());

    let first: SubmitResponse = http
        .post(format!("{}/submit", base))
        .json(&SubmitRequest {
            stream: stream.to_string(),
            client_id: client_id.clone(),
            payload: serde_json::json!({"text":"disposable-mesh"}),
            attachments: None,
            auth_ref: None,
            expires_at: None,
            schema: None,
            idem: None,
            pow_cookie: None,
        })
        .send()
        .await
        .context("submitting disposable mesh workload message")?
        .error_for_status()
        .context("mesh submit endpoint returned error")?
        .json()
        .await
        .context("decoding mesh submit response")?;

    let stream_resp: StreamResponse = http
        .get(format!("{}/stream?stream={}&from=1", base, stream))
        .send()
        .await
        .context("streaming messages from disposable mesh hub")?
        .error_for_status()
        .context("mesh stream endpoint returned error")?
        .json()
        .await
        .context("decoding mesh stream response")?;
    let messages = match stream_resp {
        StreamResponse::Messages(messages) => messages,
        StreamResponse::Proven(messages) => {
            messages.into_iter().map(|entry| entry.message).collect()
        }
    };
    ensure!(
        messages.len() == 1,
        "expected single message in disposable mesh stream"
    );
    ensure!(
        messages[0].seq == first.seq,
        "streamed sequence does not match submission"
    );

    runtime.shutdown().await?;

    ensure!(
        fs::try_exists(hub_data.join("state"))
            .await
            .context("checking hub state directory inside pvc")?,
        "hub state directory missing after shutdown",
    );

    Ok(())
}

fn generate_client_id() -> [u8; 32] {
    use ed25519_dalek::SigningKey;
    let mut rng = OsRng;
    SigningKey::generate(&mut rng).verifying_key().to_bytes()
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

#[derive(serde::Serialize, serde::Deserialize)]
struct HubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

const HUB_KEY_VERSION: u8 = 1;
