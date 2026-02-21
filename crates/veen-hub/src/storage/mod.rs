use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Context, Result};
use sha2::Digest;
use tokio::fs::{self, OpenOptions};

use crate::runtime::HubRuntimeConfig;

pub mod attachments;
pub mod stream_index;

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
pub const ATTACHMENT_REFS_DIR: &str = "refs";
pub const ANCHORS_DIR: &str = "anchors";
pub const TLS_INFO_FILE: &str = "tls_info.json";
pub const REVOCATIONS_FILE: &str = "revocations.json";
pub const AUTHORITY_FILE: &str = "authority_records.json";
pub const LABEL_CLASS_FILE: &str = "label_classes.json";
pub const SCHEMA_REGISTRY_FILE: &str = "schema_descriptors.json";
pub const RECENT_LEAF_HASHES_FILE: &str = "recent_leaf_hashes.json";

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

    pub fn stream_index_path(&self, stream: &str) -> PathBuf {
        self.streams_dir()
            .join(format!("{}.index", stream_storage_name(stream)))
    }

    pub fn stream_index_head_path(&self, stream: &str) -> PathBuf {
        self.streams_dir()
            .join(format!("{}.head.json", stream_storage_name(stream)))
    }

    pub fn capabilities_dir(&self) -> PathBuf {
        self.state_dir().join(CAPABILITIES_DIR)
    }

    pub fn attachments_dir(&self) -> PathBuf {
        self.state_dir().join(ATTACHMENTS_DIR)
    }

    pub fn attachment_refs_dir(&self) -> PathBuf {
        self.attachments_dir().join(ATTACHMENT_REFS_DIR)
    }

    pub fn attachment_ref_path(&self, digest: &str) -> PathBuf {
        self.attachment_refs_dir().join(format!("{digest}.ref"))
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

    pub fn recent_leaf_hashes_path(&self) -> PathBuf {
        self.state_dir().join(RECENT_LEAF_HASHES_FILE)
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

    pub fn message_bundle_filename(&self, stream: &str, seq: u64) -> String {
        format!("{}-{seq:08}.json", stream_storage_name(stream))
    }

    pub fn message_bundle_path(&self, stream: &str, seq: u64) -> PathBuf {
        self.messages_dir()
            .join(self.message_bundle_filename(stream, seq))
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

/// Ensure the canonical hub data directory layout exists under `data_dir`.
pub async fn ensure_data_dir_layout(data_dir: &Path) -> Result<()> {
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
    fs::create_dir_all(state_dir.join(ATTACHMENTS_DIR).join(ATTACHMENT_REFS_DIR))
        .await
        .with_context(|| {
            format!(
                "creating attachment ref index directory under {}",
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

/// Create the default TLS metadata snapshot if it is missing.
pub async fn ensure_tls_snapshot(data_dir: &Path) -> Result<()> {
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

/// Flush filesystem buffers for `path` if it exists.
pub async fn flush_file_if_exists(path: &Path) -> Result<()> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── stream_storage_name ──────────────────────────────────────────

    #[test]
    fn stream_storage_name_alphanumeric() {
        let name = stream_storage_name("my-stream_1.0");
        // All characters should pass through unchanged; suffix is appended.
        assert!(name.starts_with("my-stream_1.0-"));
        // Suffix is 16 hex characters (8 bytes).
        let suffix = name.strip_prefix("my-stream_1.0-").unwrap();
        assert_eq!(suffix.len(), 16);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn stream_storage_name_whitespace_replaced_with_underscore() {
        let name = stream_storage_name("hello world");
        assert!(name.starts_with("hello_world-"));
    }

    #[test]
    fn stream_storage_name_special_chars_replaced_with_dash() {
        let name = stream_storage_name("a/b:c@d");
        assert!(name.starts_with("a-b-c-d-"));
    }

    #[test]
    fn stream_storage_name_empty_input() {
        let name = stream_storage_name("");
        assert!(name.starts_with("stream-"));
    }

    #[test]
    fn stream_storage_name_deterministic() {
        let a = stream_storage_name("test");
        let b = stream_storage_name("test");
        assert_eq!(a, b);
    }

    #[test]
    fn stream_storage_name_different_inputs_differ() {
        let a = stream_storage_name("alpha");
        let b = stream_storage_name("beta");
        assert_ne!(a, b);
    }

    // ── HubStorage path accessors ────────────────────────────────────

    fn make_storage(data_dir: &std::path::Path) -> HubStorage {
        HubStorage {
            data_dir: data_dir.to_path_buf(),
        }
    }

    #[test]
    fn data_dir_accessor() {
        let p = PathBuf::from("/tmp/hub-test");
        let s = make_storage(&p);
        assert_eq!(s.data_dir(), p.as_path());
    }

    #[test]
    fn receipts_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(s.receipts_path(), PathBuf::from("/data/receipts.cborseq"));
    }

    #[test]
    fn payloads_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(s.payloads_path(), PathBuf::from("/data/payloads.cborseq"));
    }

    #[test]
    fn checkpoints_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.checkpoints_path(),
            PathBuf::from("/data/checkpoints.cborseq")
        );
    }

    #[test]
    fn state_dir_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(s.state_dir(), PathBuf::from("/data/state"));
    }

    #[test]
    fn streams_dir_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(s.streams_dir(), PathBuf::from("/data/state/streams"));
    }

    #[test]
    fn messages_dir_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(s.messages_dir(), PathBuf::from("/data/state/messages"));
    }

    #[test]
    fn capabilities_dir_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.capabilities_dir(),
            PathBuf::from("/data/state/capabilities")
        );
    }

    #[test]
    fn attachments_dir_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.attachments_dir(),
            PathBuf::from("/data/state/attachments")
        );
    }

    #[test]
    fn attachment_refs_dir_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.attachment_refs_dir(),
            PathBuf::from("/data/state/attachments/refs")
        );
    }

    #[test]
    fn attachment_ref_path_for_digest() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.attachment_ref_path("abc123"),
            PathBuf::from("/data/state/attachments/refs/abc123.ref")
        );
    }

    #[test]
    fn anchors_dir_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(s.anchors_dir(), PathBuf::from("/data/anchors"));
    }

    #[test]
    fn hub_key_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(s.hub_key_path(), PathBuf::from("/data/hub_key.cbor"));
    }

    #[test]
    fn tls_info_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.tls_info_path(),
            PathBuf::from("/data/state/tls_info.json")
        );
    }

    #[test]
    fn recent_leaf_hashes_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.recent_leaf_hashes_path(),
            PathBuf::from("/data/state/recent_leaf_hashes.json")
        );
    }

    #[test]
    fn stream_state_path_uses_storage_name() {
        let s = make_storage(Path::new("/data"));
        let p = s.stream_state_path("my-stream");
        assert!(p.to_str().unwrap().ends_with(".json"));
        assert!(p.starts_with("/data/state/streams"));
    }

    #[test]
    fn stream_index_path_uses_storage_name() {
        let s = make_storage(Path::new("/data"));
        let p = s.stream_index_path("my-stream");
        assert!(p.to_str().unwrap().ends_with(".index"));
        assert!(p.starts_with("/data/state/streams"));
    }

    #[test]
    fn stream_index_head_path_uses_storage_name() {
        let s = make_storage(Path::new("/data"));
        let p = s.stream_index_head_path("my-stream");
        assert!(p.to_str().unwrap().ends_with(".head.json"));
        assert!(p.starts_with("/data/state/streams"));
    }

    #[test]
    fn message_bundle_filename_zero_padded() {
        let s = make_storage(Path::new("/data"));
        let f = s.message_bundle_filename("s", 42);
        // Should have 8-digit zero-padded sequence.
        assert!(f.ends_with("-00000042.json"));
    }

    #[test]
    fn message_bundle_path_in_messages_dir() {
        let s = make_storage(Path::new("/data"));
        let p = s.message_bundle_path("s", 1);
        assert!(p.starts_with("/data/state/messages"));
        assert!(p.to_str().unwrap().ends_with(".json"));
    }

    #[test]
    fn crdt_stream_dir_path() {
        let s = make_storage(Path::new("/data"));
        let p = s.crdt_stream_dir("my-crdt");
        assert!(p.starts_with("/data/state/crdt"));
    }

    #[test]
    fn capabilities_store_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.capabilities_store_path(),
            PathBuf::from("/data/state/capabilities/authorized_caps.json")
        );
    }

    #[test]
    fn anchor_log_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.anchor_log_path(),
            PathBuf::from("/data/anchors/anchor_log.json")
        );
    }

    #[test]
    fn revocations_store_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.revocations_store_path(),
            PathBuf::from("/data/state/revocations.json")
        );
    }

    #[test]
    fn authority_store_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.authority_store_path(),
            PathBuf::from("/data/state/authority_records.json")
        );
    }

    #[test]
    fn label_class_store_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.label_class_store_path(),
            PathBuf::from("/data/state/label_classes.json")
        );
    }

    #[test]
    fn schema_registry_path() {
        let s = make_storage(Path::new("/data"));
        assert_eq!(
            s.schema_registry_path(),
            PathBuf::from("/data/state/schema_descriptors.json")
        );
    }

    // ── ensure_data_dir_layout ───────────────────────────────────────

    #[tokio::test]
    async fn ensure_data_dir_layout_creates_all_dirs_and_files() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        ensure_data_dir_layout(&data).await.unwrap();

        // Top-level files.
        assert!(data.join(RECEIPTS_FILE).exists());
        assert!(data.join(PAYLOADS_FILE).exists());
        assert!(data.join(CHECKPOINTS_FILE).exists());

        // State sub-directories.
        let state = data.join(STATE_DIR);
        assert!(state.join(STREAMS_DIR).is_dir());
        assert!(state.join(MESSAGES_DIR).is_dir());
        assert!(state.join(CAPABILITIES_DIR).is_dir());
        assert!(state.join(CRDT_DIR).is_dir());
        assert!(state.join(ATTACHMENTS_DIR).is_dir());
        assert!(state
            .join(ATTACHMENTS_DIR)
            .join(ATTACHMENT_REFS_DIR)
            .is_dir());

        // Anchors at data root.
        assert!(data.join(ANCHORS_DIR).is_dir());
    }

    #[tokio::test]
    async fn ensure_data_dir_layout_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        ensure_data_dir_layout(&data).await.unwrap();
        // Running again should succeed without error.
        ensure_data_dir_layout(&data).await.unwrap();
    }

    // ── ensure_tls_snapshot ──────────────────────────────────────────

    #[tokio::test]
    async fn ensure_tls_snapshot_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        ensure_data_dir_layout(&data).await.unwrap();
        ensure_tls_snapshot(&data).await.unwrap();

        let tls_path = data.join(STATE_DIR).join(TLS_INFO_FILE);
        assert!(tls_path.exists());
        let content = tokio::fs::read_to_string(&tls_path).await.unwrap();
        assert!(content.contains("TLS 1.3"));
    }

    #[tokio::test]
    async fn ensure_tls_snapshot_does_not_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        ensure_data_dir_layout(&data).await.unwrap();

        let tls_path = data.join(STATE_DIR).join(TLS_INFO_FILE);
        tokio::fs::write(&tls_path, "custom-data").await.unwrap();

        ensure_tls_snapshot(&data).await.unwrap();
        let content = tokio::fs::read_to_string(&tls_path).await.unwrap();
        assert_eq!(content, "custom-data");
    }

    // ── flush_file_if_exists ─────────────────────────────────────────

    #[tokio::test]
    async fn flush_file_if_exists_nonexistent_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does_not_exist");
        flush_file_if_exists(&missing).await.unwrap();
    }

    #[tokio::test]
    async fn flush_file_if_exists_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("data.bin");
        tokio::fs::write(&f, b"hello").await.unwrap();
        flush_file_if_exists(&f).await.unwrap();
    }

    // ── HubStorage flush ─────────────────────────────────────────────

    #[tokio::test]
    async fn hub_storage_flush_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        ensure_data_dir_layout(&data).await.unwrap();
        ensure_tls_snapshot(&data).await.unwrap();
        let s = make_storage(&data);
        s.flush().await.unwrap();
    }

    // ── write_pid_file / remove_pid_file ─────────────────────────────

    #[tokio::test]
    async fn write_and_remove_pid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        tokio::fs::create_dir_all(&data).await.unwrap();

        write_pid_file(&data).await.unwrap();

        let pid_path = data.join(HUB_PID_FILE);
        assert!(pid_path.exists());
        let contents = tokio::fs::read_to_string(&pid_path).await.unwrap();
        let pid: u32 = contents.parse().unwrap();
        assert_eq!(pid, process::id());

        remove_pid_file(&data).await.unwrap();
        assert!(!pid_path.exists());
    }

    #[tokio::test]
    async fn write_pid_file_fails_when_already_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        tokio::fs::create_dir_all(&data).await.unwrap();

        write_pid_file(&data).await.unwrap();
        // Second call should fail.
        let result = write_pid_file(&data).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        // Cleanup.
        remove_pid_file(&data).await.unwrap();
    }

    #[tokio::test]
    async fn remove_pid_file_noop_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        remove_pid_file(tmp.path()).await.unwrap();
    }

    // ── restrict_private_permissions ─────────────────────────────────

    #[tokio::test]
    #[cfg(unix)]
    async fn restrict_private_permissions_sets_mode_600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("secret");
        tokio::fs::write(&f, b"data").await.unwrap();

        restrict_private_permissions(&f).await.unwrap();

        let meta = tokio::fs::metadata(&f).await.unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    // ── HubStorage teardown ──────────────────────────────────────────

    #[tokio::test]
    async fn teardown_removes_pid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("hub");
        tokio::fs::create_dir_all(&data).await.unwrap();
        write_pid_file(&data).await.unwrap();

        let s = make_storage(&data);
        s.teardown().await.unwrap();

        assert!(!data.join(HUB_PID_FILE).exists());
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(RECEIPTS_FILE, "receipts.cborseq");
        assert_eq!(PAYLOADS_FILE, "payloads.cborseq");
        assert_eq!(CHECKPOINTS_FILE, "checkpoints.cborseq");
        assert_eq!(HUB_PID_FILE, "hub.pid");
        assert_eq!(HUB_KEY_FILE, "hub_key.cbor");
        assert_eq!(STATE_DIR, "state");
        assert_eq!(STREAMS_DIR, "streams");
        assert_eq!(MESSAGES_DIR, "messages");
        assert_eq!(CAPABILITIES_DIR, "capabilities");
        assert_eq!(CRDT_DIR, "crdt");
        assert_eq!(ATTACHMENTS_DIR, "attachments");
        assert_eq!(ATTACHMENT_REFS_DIR, "refs");
        assert_eq!(ANCHORS_DIR, "anchors");
        assert_eq!(TLS_INFO_FILE, "tls_info.json");
        assert_eq!(REVOCATIONS_FILE, "revocations.json");
        assert_eq!(AUTHORITY_FILE, "authority_records.json");
        assert_eq!(LABEL_CLASS_FILE, "label_classes.json");
        assert_eq!(SCHEMA_REGISTRY_FILE, "schema_descriptors.json");
        assert_eq!(RECENT_LEAF_HASHES_FILE, "recent_leaf_hashes.json");
    }

    // ── attachments module ───────────────────────────────────────────

    #[tokio::test]
    async fn load_refcounts_returns_none_when_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());
        // refs dir does not exist yet
        let result = attachments::load_refcounts(&s).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn write_and_read_refcount() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        // Write a refcount.
        attachments::write_refcount(&s, "abc123", 5).await.unwrap();
        let count = attachments::read_refcount(&s, "abc123").await.unwrap();
        assert_eq!(count, Some(5));

        // Update to a new value.
        attachments::write_refcount(&s, "abc123", 10).await.unwrap();
        let count = attachments::read_refcount(&s, "abc123").await.unwrap();
        assert_eq!(count, Some(10));

        // Zero count removes the file.
        attachments::write_refcount(&s, "abc123", 0).await.unwrap();
        let count = attachments::read_refcount(&s, "abc123").await.unwrap();
        assert!(count.is_none());
    }

    #[tokio::test]
    async fn read_refcount_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());
        let count = attachments::read_refcount(&s, "nonexistent").await.unwrap();
        assert!(count.is_none());
    }

    #[tokio::test]
    async fn load_refcounts_reads_existing_refs() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        attachments::write_refcount(&s, "digest1", 3).await.unwrap();
        attachments::write_refcount(&s, "digest2", 7).await.unwrap();

        let counts = attachments::load_refcounts(&s).await.unwrap().unwrap();
        assert_eq!(counts.get("digest1"), Some(&3));
        assert_eq!(counts.get("digest2"), Some(&7));
    }

    #[tokio::test]
    async fn rewrite_all_refcounts() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        // Pre-populate with one entry.
        attachments::write_refcount(&s, "old", 1).await.unwrap();

        let mut new_counts = std::collections::HashMap::new();
        new_counts.insert("alpha".to_string(), 2u64);
        new_counts.insert("beta".to_string(), 0u64); // zero counts must be skipped
        attachments::rewrite_all_refcounts(&s, &new_counts)
            .await
            .unwrap();

        let loaded = attachments::load_refcounts(&s).await.unwrap().unwrap();
        assert_eq!(loaded.get("alpha"), Some(&2));
        assert!(
            !loaded.contains_key("beta"),
            "zero counts should not be written"
        );
        assert!(!loaded.contains_key("old"), "old entry should be removed");
    }

    // ── stream_index module ──────────────────────────────────────────

    #[tokio::test]
    async fn stream_index_reader_returns_none_for_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent.index");
        let reader = stream_index::StreamIndexReader::open(&path).await.unwrap();
        assert!(reader.is_none());
    }

    #[tokio::test]
    async fn append_and_load_stream_index() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        let entry1 = stream_index::StreamIndexEntry {
            seq: 1,
            leaf_hash: "aa".to_string(),
            bundle: "bundle1.json".to_string(),
        };
        let entry2 = stream_index::StreamIndexEntry {
            seq: 2,
            leaf_hash: "bb".to_string(),
            bundle: "bundle2.json".to_string(),
        };

        stream_index::append_stream_index(&s, "my-stream", &entry1)
            .await
            .unwrap();
        stream_index::append_stream_index(&s, "my-stream", &entry2)
            .await
            .unwrap();

        let path = s.stream_index_path("my-stream");
        let entries = stream_index::load_stream_index(&path).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], entry1);
        assert_eq!(entries[1], entry2);
    }

    #[tokio::test]
    async fn load_stream_index_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("no-stream.index");
        let entries = stream_index::load_stream_index(&path).await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn load_stream_index_range() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        for seq in 1u64..=5 {
            let entry = stream_index::StreamIndexEntry {
                seq,
                leaf_hash: format!("{:02x}", seq),
                bundle: format!("b{seq}.json"),
            };
            stream_index::append_stream_index(&s, "stream", &entry)
                .await
                .unwrap();
        }

        let path = s.stream_index_path("stream");
        let range = stream_index::load_stream_index_range(&path, 2, 4)
            .await
            .unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0].seq, 2);
        assert_eq!(range[2].seq, 4);

        // from > to returns empty
        let empty = stream_index::load_stream_index_range(&path, 5, 3)
            .await
            .unwrap();
        assert!(empty.is_empty());

        // Missing file returns empty
        let missing_path = tmp.path().join("missing.index");
        let missing = stream_index::load_stream_index_range(&missing_path, 1, 10)
            .await
            .unwrap();
        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn load_stream_index_head() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        // Missing head returns None.
        let head = stream_index::load_stream_index_head(&s, "stream")
            .await
            .unwrap();
        assert!(head.is_none());

        let entry = stream_index::StreamIndexEntry {
            seq: 7,
            leaf_hash: "deadbeef".to_string(),
            bundle: "b7.json".to_string(),
        };
        stream_index::append_stream_index(&s, "stream", &entry)
            .await
            .unwrap();

        let head = stream_index::load_stream_index_head(&s, "stream")
            .await
            .unwrap();
        let head = head.expect("head must exist after append");
        assert_eq!(head.last_seq, 7);
        assert_eq!(head.last_leaf_hash, "deadbeef");
    }

    #[tokio::test]
    async fn bundle_path_absolute_vs_relative() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        let relative_entry = stream_index::StreamIndexEntry {
            seq: 1,
            leaf_hash: "aa".to_string(),
            bundle: "relative/bundle.json".to_string(),
        };
        let abs_path = stream_index::bundle_path(&s, &relative_entry);
        assert!(abs_path.starts_with(s.messages_dir()));

        let absolute_entry = stream_index::StreamIndexEntry {
            seq: 1,
            leaf_hash: "bb".to_string(),
            bundle: "/absolute/path/bundle.json".to_string(),
        };
        let abs_abs_path = stream_index::bundle_path(&s, &absolute_entry);
        assert_eq!(abs_abs_path.to_str().unwrap(), "/absolute/path/bundle.json");
    }

    #[tokio::test]
    async fn load_refcounts_skips_non_ref_files_and_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        // Write a legitimate ref.
        attachments::write_refcount(&s, "abc", 1).await.unwrap();

        // Write a file without .ref extension – should be skipped.
        let refs_dir = s.attachment_refs_dir();
        tokio::fs::write(refs_dir.join("ignored.txt"), "2")
            .await
            .unwrap();

        // Create a subdirectory – should be skipped (is_file() returns false).
        tokio::fs::create_dir_all(refs_dir.join("subdir"))
            .await
            .unwrap();

        let counts = attachments::load_refcounts(&s).await.unwrap().unwrap();
        // Only "abc" should be present.
        assert_eq!(counts.len(), 1);
        assert_eq!(counts.get("abc"), Some(&1));
    }

    #[tokio::test]
    async fn write_refcount_zero_when_file_absent_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        // Writing zero for a non-existent file must succeed without error.
        attachments::write_refcount(&s, "ghost", 0)
            .await
            .expect("zero write for absent file must be ok");

        // Nothing should have been created.
        let count = attachments::read_refcount(&s, "ghost").await.unwrap();
        assert!(count.is_none());
    }

    #[tokio::test]
    async fn stream_index_reader_iterates_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let s = make_storage(tmp.path());

        let e1 = stream_index::StreamIndexEntry {
            seq: 10,
            leaf_hash: "aabbcc".to_string(),
            bundle: "b10.json".to_string(),
        };
        let e2 = stream_index::StreamIndexEntry {
            seq: 11,
            leaf_hash: "ddeeff".to_string(),
            bundle: "b11.json".to_string(),
        };
        stream_index::append_stream_index(&s, "iter-stream", &e1)
            .await
            .unwrap();
        stream_index::append_stream_index(&s, "iter-stream", &e2)
            .await
            .unwrap();

        let path = s.stream_index_path("iter-stream");
        let mut reader = stream_index::StreamIndexReader::open(&path)
            .await
            .unwrap()
            .expect("reader must be Some");

        let first = reader.next_entry().await.unwrap().expect("first entry");
        assert_eq!(first, e1);
        let second = reader.next_entry().await.unwrap().expect("second entry");
        assert_eq!(second, e2);
        // EOF
        let eof = reader.next_entry().await.unwrap();
        assert!(eof.is_none());
    }
}
