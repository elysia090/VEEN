use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Context, Result};
use sha2::Digest;
use tokio::fs::{self, OpenOptions};

use crate::config::HubRuntimeConfig;

pub const RECEIPTS_FILE: &str = "receipts.cborseq";
pub const PAYLOADS_FILE: &str = "payloads.cborseq";
pub const CHECKPOINTS_FILE: &str = "checkpoints.cborseq";
pub const HUB_PID_FILE: &str = "hub.pid";
pub const HUB_KEY_FILE: &str = "hub_key.cbor";
pub const STATE_DIR: &str = "state";
pub const STREAMS_DIR: &str = "streams";
pub const MESSAGES_DIR: &str = "messages";
pub const CAPABILITIES_DIR: &str = "capabilities";
pub const CRDT_DIR: &str = "crdt";
pub const ATTACHMENTS_DIR: &str = "attachments";
pub const ANCHORS_DIR: &str = "anchors";
pub const TLS_INFO_FILE: &str = "tls_info.json";
pub const REVOCATIONS_FILE: &str = "revocations.json";
pub const AUTHORITY_FILE: &str = "authority_records.json";
pub const LABEL_CLASS_FILE: &str = "label_classes.json";
pub const SCHEMA_REGISTRY_FILE: &str = "schema_descriptors.json";

#[derive(Clone)]
pub struct HubStorage {
    data_dir: PathBuf,
}

impl HubStorage {
    pub async fn bootstrap(config: &HubRuntimeConfig) -> Result<Self> {
        ensure_data_dir_layout(&config.data_dir).await?;
        write_pid_file(&config.data_dir).await?;
        ensure_tls_snapshot(&config.data_dir).await?;
        Ok(Self {
            data_dir: config.data_dir.clone(),
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn receipts_path(&self) -> PathBuf {
        self.data_dir.join(RECEIPTS_FILE)
    }

    pub fn payloads_path(&self) -> PathBuf {
        self.data_dir.join(PAYLOADS_FILE)
    }

    pub fn checkpoints_path(&self) -> PathBuf {
        self.data_dir.join(CHECKPOINTS_FILE)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.data_dir.join(STATE_DIR)
    }

    pub fn streams_dir(&self) -> PathBuf {
        self.state_dir().join(STREAMS_DIR)
    }

    pub fn messages_dir(&self) -> PathBuf {
        self.state_dir().join(MESSAGES_DIR)
    }

    pub fn capabilities_dir(&self) -> PathBuf {
        self.state_dir().join(CAPABILITIES_DIR)
    }

    pub fn attachments_dir(&self) -> PathBuf {
        self.state_dir().join(ATTACHMENTS_DIR)
    }

    pub fn anchors_dir(&self) -> PathBuf {
        self.data_dir.join(ANCHORS_DIR)
    }

    pub fn hub_key_path(&self) -> PathBuf {
        self.data_dir.join(HUB_KEY_FILE)
    }

    pub fn tls_info_path(&self) -> PathBuf {
        self.state_dir().join(TLS_INFO_FILE)
    }

    pub async fn flush(&self) -> Result<()> {
        flush_file_if_exists(&self.receipts_path()).await?;
        flush_file_if_exists(&self.payloads_path()).await?;
        flush_file_if_exists(&self.checkpoints_path()).await?;
        flush_file_if_exists(&self.tls_info_path()).await?;
        Ok(())
    }

    pub async fn teardown(&self) -> Result<()> {
        remove_pid_file(&self.data_dir).await
    }

    pub fn stream_state_path(&self, stream: &str) -> PathBuf {
        self.streams_dir()
            .join(format!("{}.json", stream_storage_name(stream)))
    }

    pub fn message_bundle_path(&self, stream: &str, seq: u64) -> PathBuf {
        self.messages_dir()
            .join(format!("{}-{seq:08}.json", stream_storage_name(stream)))
    }

    pub fn crdt_stream_dir(&self, stream: &str) -> PathBuf {
        self.state_dir()
            .join(CRDT_DIR)
            .join(stream_storage_name(stream))
    }

    pub fn capabilities_store_path(&self) -> PathBuf {
        self.capabilities_dir().join("authorized_caps.json")
    }

    pub fn anchor_log_path(&self) -> PathBuf {
        self.anchors_dir().join("anchor_log.json")
    }

    pub fn revocations_store_path(&self) -> PathBuf {
        self.state_dir().join(REVOCATIONS_FILE)
    }

    pub fn authority_store_path(&self) -> PathBuf {
        self.state_dir().join(AUTHORITY_FILE)
    }

    pub fn label_class_store_path(&self) -> PathBuf {
        self.state_dir().join(LABEL_CLASS_FILE)
    }

    pub fn schema_registry_path(&self) -> PathBuf {
        self.state_dir().join(SCHEMA_REGISTRY_FILE)
    }
}

async fn ensure_data_dir_layout(data_dir: &Path) -> Result<()> {
    fs::create_dir_all(data_dir)
        .await
        .with_context(|| format!("creating hub data directory {}", data_dir.display()))?;

    ensure_file(&data_dir.join(RECEIPTS_FILE)).await?;
    ensure_file(&data_dir.join(PAYLOADS_FILE)).await?;
    ensure_file(&data_dir.join(CHECKPOINTS_FILE)).await?;

    let state_dir = data_dir.join(STATE_DIR);
    fs::create_dir_all(&state_dir)
        .await
        .with_context(|| format!("creating hub state directory {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(STREAMS_DIR))
        .await
        .with_context(|| format!("creating streams directory under {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(MESSAGES_DIR))
        .await
        .with_context(|| format!("creating messages directory under {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(CAPABILITIES_DIR))
        .await
        .with_context(|| {
            format!(
                "creating capabilities directory under {}",
                state_dir.display()
            )
        })?;
    fs::create_dir_all(state_dir.join(CRDT_DIR))
        .await
        .with_context(|| format!("creating CRDT directory under {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(ATTACHMENTS_DIR))
        .await
        .with_context(|| {
            format!(
                "creating attachments directory under {}",
                state_dir.display()
            )
        })?;

    fs::create_dir_all(data_dir.join(ANCHORS_DIR))
        .await
        .with_context(|| format!("creating anchors directory under {}", data_dir.display()))?;

    Ok(())
}

async fn ensure_file(path: &Path) -> Result<()> {
    if fs::try_exists(path)
        .await
        .with_context(|| format!("checking {}", path.display()))?
    {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating parent directory {}", parent.display()))?;
    }

    fs::write(path, &[])
        .await
        .with_context(|| format!("initialising {}", path.display()))?;
    Ok(())
}

async fn ensure_tls_snapshot(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(STATE_DIR).join(TLS_INFO_FILE);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking TLS snapshot {}", path.display()))?
    {
        return Ok(());
    }

    const TLS_INFO_JSON: &str =
        "{\"version\":\"TLS 1.3\",\"cipher\":\"TLS_AES_256_GCM_SHA384\",\"aead\":true,\"compression\":false}";

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring TLS metadata directory {}", parent.display()))?;
    }

    fs::write(&path, TLS_INFO_JSON)
        .await
        .with_context(|| format!("writing TLS metadata to {}", path.display()))?;
    Ok(())
}

async fn write_pid_file(data_dir: &Path) -> Result<()> {
    let pid_path = data_dir.join(HUB_PID_FILE);
    if fs::try_exists(&pid_path)
        .await
        .with_context(|| format!("checking PID file {}", pid_path.display()))?
    {
        bail!(
            "hub PID file {} already exists; is another hub running?",
            pid_path.display()
        );
    }

    let pid_contents = process::id().to_string();
    fs::write(&pid_path, pid_contents)
        .await
        .with_context(|| format!("writing PID file {}", pid_path.display()))?;
    restrict_private_permissions(&pid_path).await?;
    Ok(())
}

async fn remove_pid_file(data_dir: &Path) -> Result<()> {
    let pid_path = data_dir.join(HUB_PID_FILE);
    if fs::try_exists(&pid_path)
        .await
        .with_context(|| format!("checking PID file {}", pid_path.display()))?
    {
        fs::remove_file(&pid_path)
            .await
            .with_context(|| format!("removing PID file {}", pid_path.display()))?;
    }
    Ok(())
}

async fn flush_file_if_exists(path: &Path) -> Result<()> {
    if !fs::try_exists(path)
        .await
        .with_context(|| format!("checking {} before flush", path.display()))?
    {
        return Ok(());
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .await
        .with_context(|| format!("opening {} for flush", path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("flushing {}", path.display()))?;
    Ok(())
}

async fn restrict_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .await
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }

    #[cfg(not(unix))]
    let _ = path;

    Ok(())
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
    let digest = sha2::Sha256::digest(stream.as_bytes());
    let suffix = hex::encode(&digest[..8]);
    format!("{safe}-{suffix}")
}
