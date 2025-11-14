use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use hex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::fs::OpenOptions;
use tokio::sync::Mutex;

use veen_core::wire::mmr::Mmr;
use veen_core::wire::types::{LeafHash, MmrRoot};
use veen_core::{
    cap_stream_id_from_label, cap_token_from_cbor, CapTokenRate, StreamIdParseError,
    CAP_TOKEN_VERSION,
};

use thiserror::Error;

use crate::config::{AdmissionConfig, FederationConfig, HubRole, HubRuntimeConfig};
use crate::observability::HubObservability;
use crate::storage::HubStorage;

#[derive(Clone)]
pub struct HubPipeline {
    storage: HubStorage,
    observability: HubObservability,
    inner: Arc<Mutex<HubState>>,
    role: HubRole,
    profile_id: Option<String>,
    admission: AdmissionConfig,
    federation: FederationConfig,
}

struct HubState {
    streams: HashMap<String, StreamRuntime>,
    capabilities: CapabilityStore,
    anchors: AnchorLog,
}

struct StreamRuntime {
    state: HubStreamState,
    mmr: Mmr,
}

impl StreamRuntime {
    fn new(state: HubStreamState) -> Result<Self> {
        let mut mmr = Mmr::new();
        for message in &state.messages {
            let leaf = leaf_hash_for(message)?;
            mmr.append(leaf);
        }
        Ok(Self { state, mmr })
    }
}

impl HubPipeline {
    pub async fn initialise(config: &HubRuntimeConfig, storage: &HubStorage) -> Result<Self> {
        let observability = HubObservability::new();
        let streams = load_existing_streams(storage).await?;
        let capabilities = load_capabilities(storage).await?;
        let anchors = load_anchor_log(storage).await?;
        let state = HubState {
            streams,
            capabilities,
            anchors,
        };

        if config.anchors.enabled && state.anchors.entries.is_empty() {
            tracing::info!("anchoring enabled; awaiting first checkpoint emission");
        }

        Ok(Self {
            storage: storage.clone(),
            observability,
            inner: Arc::new(Mutex::new(state)),
            role: config.role,
            profile_id: config.profile_id.clone(),
            admission: config.admission.clone(),
            federation: config.federation.clone(),
        })
    }

    pub fn observability(&self) -> HubObservability {
        self.observability.clone()
    }

    #[allow(dead_code)]
    pub fn profile_id(&self) -> Option<&str> {
        self.profile_id.as_deref()
    }

    #[allow(dead_code)]
    pub fn admission_config(&self) -> &AdmissionConfig {
        &self.admission
    }

    #[allow(dead_code)]
    pub fn federation_config(&self) -> &FederationConfig {
        &self.federation
    }

    pub async fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse> {
        if matches!(self.role, HubRole::Replica) {
            bail!("replica hubs are read-only");
        }
        let SubmitRequest {
            stream,
            client_id,
            payload,
            attachments,
            auth_ref,
            expires_at,
            schema,
            idem,
        } = request;

        let attachments = attachments.unwrap_or_default();
        let submitted_at = current_unix_timestamp();
        let mut guard = self.inner.lock().await;
        if let Some(cap) = auth_ref.as_ref() {
            if let Err(err) = enforce_capability(
                &mut guard.capabilities,
                cap,
                &client_id,
                &stream,
                submitted_at,
            ) {
                update_capability_store(&self.storage, &guard.capabilities).await?;
                return Err(anyhow::Error::new(err));
            }
        }

        let stream_runtime = guard.streams.entry(stream.clone()).or_insert_with(|| {
            StreamRuntime::new(HubStreamState::default()).expect("empty stream state")
        });

        let seq = stream_runtime
            .state
            .messages
            .last()
            .map(|m| m.seq + 1)
            .unwrap_or(1);

        let stored_attachments = persist_attachments(&self.storage, &stream, &attachments).await?;

        let stored_message = StoredMessage {
            stream: stream.clone(),
            seq,
            sent_at: submitted_at,
            client_id: client_id.clone(),
            schema,
            expires_at,
            parent: None,
            body: Some(payload.to_string()),
            body_digest: None,
            attachments: stored_attachments.clone(),
            auth_ref: auth_ref.clone(),
            idem,
        };

        let leaf = leaf_hash_for(&stored_message)?;
        let (_, mmr_root) = stream_runtime.mmr.append(leaf);
        stream_runtime.state.messages.push(stored_message.clone());

        persist_stream_state(&self.storage, &stream, &stream_runtime.state).await?;
        persist_message_bundle(&self.storage, &stream, seq, &stored_message).await?;
        append_receipt(&self.storage, &stream, seq, &leaf, &mmr_root, submitted_at).await?;
        update_capability_store(&self.storage, &guard.capabilities).await?;

        self.observability.record_submit_ok();

        Ok(SubmitResponse {
            stream,
            seq,
            mmr_root: hex::encode(mmr_root.as_bytes()),
            stored_attachments,
        })
    }

    pub async fn bridge_ingest(
        &self,
        request: BridgeIngestRequest,
    ) -> Result<BridgeIngestResponse> {
        if matches!(self.role, HubRole::Primary) {
            bail!("bridge ingestion is only supported on replica hubs");
        }

        let BridgeIngestRequest {
            message,
            expected_mmr_root,
        } = request;
        let stream = message.stream.clone();

        let mut guard = self.inner.lock().await;
        let stream_runtime = guard.streams.entry(stream.clone()).or_insert_with(|| {
            StreamRuntime::new(HubStreamState::default()).expect("empty stream state")
        });

        if let Some(existing) = stream_runtime
            .state
            .messages
            .iter()
            .find(|stored| stored.seq == message.seq)
        {
            if existing != &message {
                bail!(
                    "replica already has divergent message for {}#{}",
                    stream,
                    message.seq
                );
            }
            let mmr_root = stream_runtime
                .mmr
                .root()
                .map(|root| hex::encode(root.as_bytes()))
                .unwrap_or_default();
            if !expected_mmr_root.is_empty() && expected_mmr_root != mmr_root {
                bail!("replica MMR root mismatch for {}#{}", stream, message.seq);
            }
            return Ok(BridgeIngestResponse {
                stream,
                seq: message.seq,
                mmr_root,
            });
        }

        let expected_seq = stream_runtime
            .state
            .messages
            .last()
            .map(|m| m.seq + 1)
            .unwrap_or(1);

        if message.seq != expected_seq {
            bail!(
                "bridge message out of order for {}: expected {}, got {}",
                stream,
                expected_seq,
                message.seq
            );
        }

        let leaf = leaf_hash_for(&message)?;
        let (_, mmr_root) = stream_runtime.mmr.append(leaf);
        let computed_root = hex::encode(mmr_root.as_bytes());
        if !expected_mmr_root.is_empty() && expected_mmr_root != computed_root {
            bail!(
                "bridge mmr root mismatch for {}#{}: expected {}, computed {}",
                stream,
                message.seq,
                expected_mmr_root,
                computed_root
            );
        }

        stream_runtime.state.messages.push(message.clone());

        persist_stream_state(&self.storage, &stream, &stream_runtime.state).await?;
        persist_message_bundle(&self.storage, &stream, message.seq, &message).await?;
        append_receipt(
            &self.storage,
            &stream,
            message.seq,
            &leaf,
            &mmr_root,
            message.sent_at,
        )
        .await?;

        self.observability.record_submit_ok();

        Ok(BridgeIngestResponse {
            stream,
            seq: message.seq,
            mmr_root: computed_root,
        })
    }

    pub async fn stream(&self, stream: &str, from: u64) -> Result<Vec<StoredMessage>> {
        let guard = self.inner.lock().await;
        let runtime = guard
            .streams
            .get(stream)
            .ok_or_else(|| anyhow!("stream {stream} has no stored messages"))?;
        let messages = runtime
            .state
            .messages
            .iter()
            .filter(|msg| msg.seq >= from)
            .cloned()
            .collect();
        Ok(messages)
    }

    pub async fn resync(&self, stream: &str) -> Result<HubStreamState> {
        let guard = self.inner.lock().await;
        let runtime = guard
            .streams
            .get(stream)
            .ok_or_else(|| anyhow!("stream {stream} has no stored messages"))?;
        Ok(runtime.state.clone())
    }

    pub async fn authorize_capability(&self, token_bytes: &[u8]) -> Result<AuthorizeResponse> {
        if matches!(self.role, HubRole::Replica) {
            bail!("replica hubs are read-only");
        }

        let token = cap_token_from_cbor(token_bytes).context("decoding capability token")?;
        if token.ver != CAP_TOKEN_VERSION {
            bail!("unsupported capability token version {}", token.ver);
        }
        token
            .verify()
            .map_err(|err| anyhow!("capability token verification failed: {err}"))?;
        if token.allow.ttl == 0 {
            bail!("capability ttl must be greater than zero seconds");
        }

        let now = current_unix_timestamp();
        let expires_at = now.saturating_add(token.allow.ttl);
        let auth_ref = token.auth_ref().context("computing capability auth_ref")?;
        let auth_ref_hex = hex::encode(auth_ref.as_ref());
        let subject_hex = hex::encode(token.subject_pk.as_ref());
        let stream_ids: Vec<String> = token
            .allow
            .stream_ids
            .iter()
            .map(|id| hex::encode(id.as_ref()))
            .collect();

        tracing::info!(
            auth_ref = %auth_ref_hex,
            subject = %subject_hex,
            streams = ?stream_ids,
            ttl = token.allow.ttl,
            rate = ?token.allow.rate,
            expires_at,
            "authorised capability admission"
        );

        let mut guard = self.inner.lock().await;
        let record = CapabilityRecord {
            subject: subject_hex,
            stream_ids,
            expires_at,
            ttl: token.allow.ttl,
            rate: token.allow.rate.clone(),
            bucket_state: token.allow.rate.as_ref().map(|rate| TokenBucketState {
                tokens: rate.burst,
                last_refill: now,
            }),
            uses: 0,
        };
        guard
            .capabilities
            .records
            .insert(auth_ref_hex.clone(), record);
        update_capability_store(&self.storage, &guard.capabilities).await?;

        Ok(AuthorizeResponse {
            auth_ref: auth_ref_hex,
            expires_at,
        })
    }

    pub async fn anchor_checkpoint(&self, anchor: AnchorRequest) -> Result<()> {
        let mut guard = self.inner.lock().await;
        guard.anchors.entries.push(AnchorRecord {
            stream: anchor.stream,
            mmr_root: anchor.mmr_root,
            timestamp: current_unix_timestamp(),
            backend: anchor.backend,
        });
        persist_anchor_log(&self.storage, &guard.anchors).await
    }

    pub async fn metrics_snapshot(&self) -> ObservabilityReport {
        let snapshot = self.observability.snapshot();
        let guard = self.inner.lock().await;
        let mut last_seq = HashMap::new();
        let mut peaks = HashMap::new();
        for (stream, runtime) in &guard.streams {
            let seq = runtime.mmr.seq();
            if seq > 0 {
                last_seq.insert(stream.clone(), seq);
                if let Some(root) = runtime.mmr.root() {
                    peaks.insert(stream.clone(), hex::encode(root.as_bytes()));
                }
            }
        }
        ObservabilityReport {
            uptime: snapshot.uptime,
            submit_ok_total: snapshot.submit_ok_total,
            submit_err_total: snapshot.submit_err_total,
            last_stream_seq: last_seq,
            mmr_roots: peaks,
        }
    }

    pub async fn anchor_log(&self) -> Result<AnchorLog> {
        let guard = self.inner.lock().await;
        Ok(guard.anchors.clone())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubmitRequest {
    pub stream: String,
    pub client_id: String,
    pub payload: JsonValue,
    pub attachments: Option<Vec<AttachmentUpload>>,
    pub auth_ref: Option<String>,
    pub expires_at: Option<u64>,
    pub schema: Option<String>,
    pub idem: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AttachmentUpload {
    pub name: Option<String>,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitResponse {
    pub stream: String,
    pub seq: u64,
    pub mmr_root: String,
    pub stored_attachments: Vec<StoredAttachment>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BridgeIngestRequest {
    pub message: StoredMessage,
    pub expected_mmr_root: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeIngestResponse {
    pub stream: String,
    pub seq: u64,
    pub mmr_root: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AnchorRequest {
    pub stream: String,
    pub mmr_root: String,
    pub backend: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct HubStreamState {
    pub messages: Vec<StoredMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredMessage {
    pub stream: String,
    pub seq: u64,
    pub sent_at: u64,
    pub client_id: String,
    pub schema: Option<String>,
    pub expires_at: Option<u64>,
    pub parent: Option<String>,
    pub body: Option<String>,
    pub body_digest: Option<String>,
    pub attachments: Vec<StoredAttachment>,
    pub auth_ref: Option<String>,
    pub idem: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAttachment {
    pub name: String,
    pub digest: String,
    pub size: u64,
    pub stored_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnchorLog {
    pub entries: Vec<AnchorRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRecord {
    pub stream: String,
    pub mmr_root: String,
    pub timestamp: u64,
    pub backend: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CapabilityStore {
    records: HashMap<String, CapabilityRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapabilityRecord {
    subject: String,
    stream_ids: Vec<String>,
    expires_at: u64,
    ttl: u64,
    rate: Option<CapTokenRate>,
    #[serde(default)]
    bucket_state: Option<TokenBucketState>,
    uses: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBucketState {
    tokens: u64,
    last_refill: u64,
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("E.AUTH capability {auth_ref} is not authorised")]
    Unauthorized { auth_ref: String },
    #[error("E.CAP capability {auth_ref} subject mismatch")]
    SubjectMismatch { auth_ref: String },
    #[error("E.CAP capability {auth_ref} stream derivation failed: {source}")]
    StreamMismatch {
        auth_ref: String,
        #[source]
        source: StreamIdParseError,
    },
    #[error("E.CAP capability {auth_ref} does not permit stream {stream}")]
    StreamDenied { auth_ref: String, stream: String },
    #[error("E.CAP capability {auth_ref} has expired")]
    Expired { auth_ref: String },
    #[error("E.RATE capability {auth_ref} is rate limited (retry after {retry_after}s)")]
    RateLimited { auth_ref: String, retry_after: u64 },
}

impl CapabilityError {
    pub fn retry_after(&self) -> Option<u64> {
        if let Self::RateLimited { retry_after, .. } = self {
            Some(*retry_after)
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub auth_ref: String,
    pub expires_at: u64,
}

#[derive(Debug, Serialize)]
pub struct ObservabilityReport {
    #[serde(with = "humantime_serde")]
    pub uptime: std::time::Duration,
    pub submit_ok_total: u64,
    pub submit_err_total: std::collections::BTreeMap<String, u64>,
    pub last_stream_seq: HashMap<String, u64>,
    pub mmr_roots: HashMap<String, String>,
}

async fn load_existing_streams(storage: &HubStorage) -> Result<HashMap<String, StreamRuntime>> {
    let mut map = HashMap::new();
    let mut dir = fs::read_dir(storage.streams_dir())
        .await
        .with_context(|| format!("listing streams under {}", storage.streams_dir().display()))?;
    while let Some(entry) = dir
        .next_entry()
        .await
        .context("reading stream directory entry")?
    {
        if entry
            .file_type()
            .await
            .context("checking stream entry type")?
            .is_file()
        {
            let path = entry.path();
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                let data = fs::read(&path)
                    .await
                    .with_context(|| format!("reading stream state from {}", path.display()))?;
                let state: HubStreamState = serde_json::from_slice(&data)
                    .with_context(|| format!("decoding stream state from {}", path.display()))?;
                let stream_name = state
                    .messages
                    .first()
                    .map(|msg| msg.stream.clone())
                    .unwrap_or_else(|| name.to_string());
                let runtime = StreamRuntime::new(state)?;
                map.insert(stream_name, runtime);
            }
        }
    }
    Ok(map)
}

async fn persist_stream_state(
    storage: &HubStorage,
    stream: &str,
    state: &HubStreamState,
) -> Result<()> {
    let path = storage.stream_state_path(stream);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring stream state directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(state)
        .with_context(|| format!("encoding stream state for {}", stream))?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing stream state to {}", path.display()))
}

async fn persist_message_bundle(
    storage: &HubStorage,
    stream: &str,
    seq: u64,
    message: &StoredMessage,
) -> Result<()> {
    let path = storage.message_bundle_path(stream, seq);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring message directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(message)
        .with_context(|| format!("encoding message bundle for {stream}#{seq}"))?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing message bundle to {}", path.display()))
}

async fn append_receipt(
    storage: &HubStorage,
    stream: &str,
    seq: u64,
    leaf: &LeafHash,
    mmr_root: &MmrRoot,
    submitted_at: u64,
) -> Result<()> {
    let receipt = ReceiptRecord {
        stream: stream.to_string(),
        seq,
        leaf_hash: hex::encode(leaf.as_bytes()),
        mmr_root: hex::encode(mmr_root.as_bytes()),
        hub_ts: submitted_at,
    };
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&receipt, &mut encoded).context("serialising receipt record")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(storage.receipts_path())
        .await
        .context("opening receipt sequence for append")?;
    use tokio::io::AsyncWriteExt;
    file.write_all(&encoded)
        .await
        .context("appending receipt")?;
    Ok(())
}

#[derive(Serialize)]
struct ReceiptRecord {
    stream: String,
    seq: u64,
    leaf_hash: String,
    mmr_root: String,
    hub_ts: u64,
}

async fn persist_attachments(
    storage: &HubStorage,
    stream: &str,
    attachments: &[AttachmentUpload],
) -> Result<Vec<StoredAttachment>> {
    if attachments.is_empty() {
        return Ok(Vec::new());
    }

    let mut stored = Vec::with_capacity(attachments.len());
    fs::create_dir_all(storage.attachments_dir())
        .await
        .with_context(|| {
            format!(
                "ensuring attachments directory {}",
                storage.attachments_dir().display()
            )
        })?;

    for (index, attachment) in attachments.iter().enumerate() {
        let data = BASE64_STANDARD
            .decode(&attachment.data)
            .with_context(|| format!("decoding attachment {} for stream {}", index, stream))?;
        let digest = sha2::Sha256::digest(&data);
        let digest_hex = hex::encode(digest);
        let file_name = format!("{digest_hex}.bin");
        let path = storage.attachments_dir().join(&file_name);
        fs::write(&path, &data)
            .await
            .with_context(|| format!("writing attachment to {}", path.display()))?;
        stored.push(StoredAttachment {
            name: attachment
                .name
                .clone()
                .unwrap_or_else(|| format!("attachment-{index}")),
            digest: digest_hex,
            size: data.len() as u64,
            stored_path: path.to_string_lossy().into_owned(),
        });
    }

    Ok(stored)
}

fn enforce_capability(
    store: &mut CapabilityStore,
    auth_ref: &str,
    subject: &str,
    stream: &str,
    now: u64,
) -> Result<(), CapabilityError> {
    if !store.records.contains_key(auth_ref) {
        return Err(CapabilityError::Unauthorized {
            auth_ref: auth_ref.to_string(),
        });
    }

    if let Some(expired) = store
        .records
        .get(auth_ref)
        .map(|record| record.expires_at < now)
    {
        if expired {
            store.records.remove(auth_ref);
            return Err(CapabilityError::Expired {
                auth_ref: auth_ref.to_string(),
            });
        }
    }

    let record = store
        .records
        .get_mut(auth_ref)
        .expect("capability existence checked above");

    if record.subject != subject {
        return Err(CapabilityError::SubjectMismatch {
            auth_ref: auth_ref.to_string(),
        });
    }

    if record.rate.is_some() && record.bucket_state.is_none() {
        record.bucket_state = record.rate.as_ref().map(|rate| TokenBucketState {
            tokens: rate.burst,
            last_refill: now,
        });
    }

    let stream_id =
        cap_stream_id_from_label(stream).map_err(|err| CapabilityError::StreamMismatch {
            auth_ref: auth_ref.to_string(),
            source: err,
        })?;
    let stream_hex = hex::encode(stream_id.as_ref());
    if !record
        .stream_ids
        .iter()
        .any(|allowed| allowed == &stream_hex)
    {
        return Err(CapabilityError::StreamDenied {
            auth_ref: auth_ref.to_string(),
            stream: stream.to_string(),
        });
    }

    if let (Some(rate), Some(state)) = (&record.rate, record.bucket_state.as_mut()) {
        refill_bucket(state, rate, now);
        if state.tokens == 0 {
            let retry_after = retry_after_seconds(state, now);
            return Err(CapabilityError::RateLimited {
                auth_ref: auth_ref.to_string(),
                retry_after,
            });
        }
        state.tokens = state.tokens.saturating_sub(1);
    }

    record.uses = record.uses.saturating_add(1);
    Ok(())
}

fn refill_bucket(state: &mut TokenBucketState, rate: &CapTokenRate, now: u64) {
    if now <= state.last_refill {
        return;
    }
    let elapsed = now.saturating_sub(state.last_refill);
    if elapsed == 0 {
        return;
    }
    let new_tokens = state
        .tokens
        .saturating_add(elapsed.saturating_mul(rate.per_sec));
    state.tokens = new_tokens.min(rate.burst);
    state.last_refill = now;
}

fn retry_after_seconds(state: &TokenBucketState, now: u64) -> u64 {
    if state.last_refill > now {
        return 1;
    }
    let target = state.last_refill.saturating_add(1);
    let wait = target.saturating_sub(now);
    if wait == 0 {
        1
    } else {
        wait
    }
}

async fn update_capability_store(storage: &HubStorage, store: &CapabilityStore) -> Result<()> {
    let path = storage.capabilities_store_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring capability directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(store).context("encoding capability store")?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing capability store to {}", path.display()))
}

async fn load_capabilities(storage: &HubStorage) -> Result<CapabilityStore> {
    let path = storage.capabilities_store_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking capabilities store {}", path.display()))?
    {
        return Ok(CapabilityStore::default());
    }
    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading capabilities store from {}", path.display()))?;
    let store = serde_json::from_slice(&data)
        .with_context(|| format!("parsing capability store from {}", path.display()))?;
    Ok(store)
}

async fn load_anchor_log(storage: &HubStorage) -> Result<AnchorLog> {
    let path = storage.anchor_log_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking anchor log {}", path.display()))?
    {
        return Ok(AnchorLog::default());
    }
    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading anchor log from {}", path.display()))?;
    let log = serde_json::from_slice(&data)
        .with_context(|| format!("parsing anchor log from {}", path.display()))?;
    Ok(log)
}

async fn persist_anchor_log(storage: &HubStorage, log: &AnchorLog) -> Result<()> {
    let path = storage.anchor_log_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring anchor directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(log).context("encoding anchor log")?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing anchor log to {}", path.display()))
}

fn leaf_hash_for(message: &StoredMessage) -> Result<LeafHash> {
    let encoded = serde_json::to_vec(message).context("encoding message for leaf hash")?;
    let digest = sha2::Sha256::digest(&encoded);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(LeafHash::new(bytes))
}

fn current_unix_timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH");
    now.as_secs()
}
