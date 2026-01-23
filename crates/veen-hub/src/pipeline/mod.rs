use std::cmp::Ordering;
use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::convert::TryInto;
use std::io::{Cursor, ErrorKind};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bloomfilter::Bloom;
use ciborium::de::from_reader;
use hex;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::Value as JsonValue;
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::fs::OpenOptions;
use tokio::sync::{Mutex, RwLock, RwLockWriteGuard};
use tracing::Instrument;

use veen_core::hub::HubId;
use veen_core::meta::SchemaRegistry;
use veen_core::revocation::{
    cap_token_hash, schema_revocation, RevocationKind, RevocationRecord, RevocationTarget,
    RevocationView,
};
use veen_core::wire::checkpoint::Checkpoint;
use veen_core::wire::{
    mmr::Mmr,
    proof::{Direction, MmrPathNode, MmrProof},
    types::{AuthRef, ClientId, LeafHash, MmrNode},
};
use veen_core::{
    cap_stream_id_from_label, cap_token_from_cbor, schema_fed_authority, schema_label_class,
    schema_meta_schema, AuthorityPolicy, AuthorityRecord, AuthorityView, CapTokenRate, Label,
    LabelClassRecord, LabelPolicy, PowCookie, RealmId, SchemaDescriptor, StreamId,
    StreamIdParseError, CAP_TOKEN_VERSION, MAX_ATTACHMENTS_PER_MSG, MAX_BODY_BYTES, MAX_MSG_BYTES,
};

use thiserror::Error;

use crate::runtime::{AdmissionConfig, DedupConfig, FederationConfig, HubRole, HubRuntimeConfig};
use crate::runtime::{HubObservability, ObservabilitySnapshot};
use crate::storage::{
    attachments,
    stream_index::{self, StreamIndexEntry},
    HubStorage,
};
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clone)]
pub struct HubPipeline {
    storage: HubStorage,
    observability: HubObservability,
    inner: Arc<RwLock<HubState>>,
    attachment_ref_counts: Arc<Mutex<HashMap<String, u64>>>,
    role: HubRole,
    profile_id: Option<String>,
    admission: AdmissionConfig,
    federation: FederationConfig,
    identity: HubIdentity,
    dedup: Arc<Mutex<DuplicateDetector>>,
}

struct HubState {
    streams: HashMap<String, StreamRuntime>,
    capabilities: CapabilityStore,
    anchors: AnchorLog,
    revocations: RevocationView,
    revocation_log: Vec<RevocationRecord>,
    revocation_index: HashMap<(RevocationKind, RevocationTarget), RevocationRecord>,
    revocation_order: BTreeMap<u64, Vec<usize>>,
    admission_events: VecDeque<AdmissionLogEvent>,
    authority_records: Vec<AuthorityRecord>,
    authority_view: AuthorityView,
    label_class_records: Vec<LabelClassRecord>,
    label_class_index: HashMap<Label, LabelClassRecord>,
    schema_descriptors: Vec<SchemaDescriptor>,
    schema_registry: SchemaRegistry,
}

#[derive(Clone)]
struct StreamRuntime {
    state: HubStreamState,
    proven_messages: VecDeque<StreamMessageWithProof>,
    mmr: Mmr,
    message_index: HashMap<u64, usize>,
    leaf_index: HashSet<LeafHash>,
}

impl StreamRuntime {
    fn new(state: HubStreamState, proven_messages: Vec<StreamMessageWithProof>) -> Result<Self> {
        if state.messages.len() < proven_messages.len() {
            bail!(
                "stream state and proof history length mismatch: {} vs {}",
                state.messages.len(),
                proven_messages.len()
            );
        }
        let mut mmr = Mmr::new();
        let mut message_index = HashMap::with_capacity(state.messages.len());
        let mut leaf_index = HashSet::with_capacity(state.messages.len());
        for (idx, message) in state.messages.iter().enumerate() {
            let leaf = leaf_hash_for(message)?;
            mmr.append(leaf);
            message_index.insert(message.seq, idx);
            leaf_index.insert(leaf);
        }
        let mut runtime = Self {
            state,
            proven_messages: VecDeque::from(proven_messages),
            mmr,
            message_index,
            leaf_index,
        };
        runtime.trim_proven_messages();
        Ok(runtime)
    }

    fn empty() -> Self {
        Self::new(HubStreamState::default(), Vec::new()).expect("empty stream state")
    }

    fn push_proven(&mut self, message: StreamMessageWithProof) {
        self.proven_messages.push_back(message);
        self.trim_proven_messages();
    }

    fn insert_message_with_leaf(&mut self, message: StoredMessage, leaf: LeafHash) {
        let index = self.state.messages.len();
        self.message_index.insert(message.seq, index);
        self.leaf_index.insert(leaf);
        self.state.messages.push(message);
    }

    fn message_by_seq(&self, seq: u64) -> Option<&StoredMessage> {
        self.message_index
            .get(&seq)
            .and_then(|index| self.state.messages.get(*index))
    }

    fn messages_from(&self, from: u64) -> Vec<StoredMessage> {
        let start = self.state.messages.partition_point(|msg| msg.seq < from);
        self.state.messages[start..].to_vec()
    }

    fn proven_messages_from(&self, from: u64) -> Vec<StreamMessageWithProof> {
        if self.proven_messages.is_empty() {
            return Vec::new();
        }

        let (front, back) = self.proven_messages.as_slices();
        if front.is_empty() {
            return Self::proven_slice_from(back, from).to_vec();
        }

        let front_last_seq = front
            .last()
            .expect("front slice checked for emptiness")
            .message
            .seq;
        if from <= front_last_seq {
            let front_slice = Self::proven_slice_from(front, from);
            let mut out = Vec::with_capacity(front_slice.len() + back.len());
            out.extend_from_slice(front_slice);
            out.extend_from_slice(back);
            return out;
        }

        Self::proven_slice_from(back, from).to_vec()
    }

    fn proven_slice_from(slice: &[StreamMessageWithProof], from: u64) -> &[StreamMessageWithProof] {
        let start = slice.partition_point(|entry| entry.message.seq < from);
        &slice[start..]
    }

    fn has_leaf_hash(&self, leaf_hash: &LeafHash) -> bool {
        self.leaf_index.contains(leaf_hash)
    }

    fn trim_proven_messages(&mut self) {
        while self.proven_messages.len() > PROVEN_MESSAGES_MEMORY_LIMIT {
            self.proven_messages.pop_front();
        }
    }
}

struct DuplicateDetector {
    bloom: Bloom<[u8; 32]>,
    recent: LruCache<DedupKey, ()>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct DedupKey {
    stream: String,
    leaf_hash: LeafHash,
}

impl DedupKey {
    fn new(stream: String, leaf_hash: LeafHash) -> Self {
        Self { stream, leaf_hash }
    }
}

#[derive(Deserialize, Serialize)]
struct DedupCacheEntry {
    stream: String,
    leaf_hash: String,
}

impl From<&DedupKey> for DedupCacheEntry {
    fn from(key: &DedupKey) -> Self {
        Self {
            stream: key.stream.clone(),
            leaf_hash: hex::encode(key.leaf_hash.as_bytes()),
        }
    }
}

enum DedupCheck {
    RecentDuplicate,
    BloomHit,
    New,
}

impl DuplicateDetector {
    fn new(config: &DedupConfig) -> Self {
        let bloom_capacity = config.bloom_capacity.max(1);
        let lru_capacity = NonZeroUsize::new(config.lru_capacity.max(1)).unwrap();
        Self {
            bloom: Bloom::new_for_fp_rate(bloom_capacity, config.bloom_false_positive_rate)
                .expect("valid bloom filter configuration"),
            recent: LruCache::new(lru_capacity),
        }
    }

    fn seed<I: IntoIterator<Item = DedupKey>>(&mut self, entries: I) {
        for entry in entries {
            self.insert(entry);
        }
    }

    fn insert(&mut self, key: DedupKey) {
        let key_bytes = dedup_key_bytes(&key.stream, &key.leaf_hash);
        self.bloom.set(&key_bytes);
        self.recent.put(key, ());
    }

    fn check_and_insert(&mut self, stream: &str, leaf_hash: &LeafHash) -> DedupCheck {
        let key = DedupKey::new(stream.to_string(), *leaf_hash);
        if self.recent.get(&key).is_some() {
            return DedupCheck::RecentDuplicate;
        }
        let key_bytes = dedup_key_bytes(stream, leaf_hash);
        if self.bloom.check(&key_bytes) {
            return DedupCheck::BloomHit;
        }
        self.insert(key);
        DedupCheck::New
    }

    fn confirm_duplicate(&mut self, stream: &str, leaf_hash: &LeafHash) {
        self.recent
            .put(DedupKey::new(stream.to_string(), *leaf_hash), ());
    }

    fn confirm_unique(&mut self, stream: &str, leaf_hash: &LeafHash) {
        self.insert(DedupKey::new(stream.to_string(), *leaf_hash));
    }

    fn recent_keys(&self) -> Vec<DedupKey> {
        self.recent
            .iter()
            .rev()
            .map(|(key, _)| key.clone())
            .collect()
    }
}

fn dedup_key_bytes(stream: &str, leaf_hash: &LeafHash) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(stream.as_bytes());
    hasher.update(leaf_hash.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

const MAX_ADMISSION_EVENTS: usize = 512;
const PROVEN_MESSAGES_MEMORY_LIMIT: usize = 2048;

impl HubPipeline {
    pub async fn initialise(config: &HubRuntimeConfig, storage: &HubStorage) -> Result<Self> {
        let observability = HubObservability::new();
        let streams = load_existing_streams(storage).await?;
        let attachment_ref_counts = load_attachment_ref_counts(storage, &streams).await?;
        let capabilities = load_capabilities(storage).await?;
        let anchors = load_anchor_log(storage).await?;
        let revocation_log = load_revocation_log(storage).await?;
        let mut revocations = RevocationView::new();
        revocations.extend(revocation_log.iter().cloned());
        let revocation_index = build_revocation_index(&revocation_log);
        let revocation_order = build_revocation_order(&revocation_log);
        let authority_records = load_authority_records(storage).await?;
        let mut authority_view = AuthorityView::new();
        authority_view.extend(authority_records.iter().cloned());
        let label_class_records = load_label_classes(storage).await?;
        let label_class_index = build_label_class_index(&label_class_records);
        let schema_descriptors = load_schema_descriptors(storage).await?;
        let schema_registry = build_schema_registry(&schema_descriptors);
        let identity = load_hub_identity(storage).await?;
        let mut dedup_detector = DuplicateDetector::new(&config.dedup);
        let recent_entries = match load_recent_dedup_cache(storage, &config.dedup).await? {
            Some(entries) => entries,
            None => {
                let entries = collect_recent_dedup_entries(&streams, &config.dedup)?;
                persist_recent_dedup_cache(storage, &entries).await?;
                entries
            }
        };
        dedup_detector.seed(recent_entries);
        let state = HubState {
            streams,
            capabilities,
            anchors,
            revocations,
            revocation_log,
            revocation_index,
            revocation_order,
            authority_records,
            authority_view,
            label_class_records,
            label_class_index,
            schema_descriptors,
            schema_registry,
            admission_events: VecDeque::new(),
        };

        if config.anchors.enabled && state.anchors.entries.is_empty() {
            tracing::info!("anchoring enabled; awaiting first checkpoint emission");
        }

        Ok(Self {
            storage: storage.clone(),
            observability,
            inner: Arc::new(RwLock::new(state)),
            attachment_ref_counts: Arc::new(Mutex::new(attachment_ref_counts)),
            role: config.role,
            profile_id: config.profile_id.clone(),
            admission: config.admission.clone(),
            federation: config.federation.clone(),
            identity,
            dedup: Arc::new(Mutex::new(dedup_detector)),
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
            pow_cookie,
        } = request;

        let (
            stream_id,
            payload_json,
            prepared_attachments,
            stored_attachments,
            submitted_at,
            submitted_at_ms,
            client_target,
            auth_target,
        ) = {
            let _validation_span = tracing::info_span!("hub_submit.validation_parsing").entered();

            if let Some(required) = self.admission.pow_difficulty {
                match pow_cookie {
                    Some(cookie) => {
                        if cookie.difficulty < required {
                            return Err(anyhow::Error::new(
                                CapabilityError::ProofOfWorkInsufficient {
                                    required,
                                    provided: cookie.difficulty,
                                },
                            ));
                        }
                        let decoded = cookie.into_pow_cookie();
                        if !decoded.meets_difficulty() {
                            return Err(anyhow::Error::new(CapabilityError::ProofOfWorkInvalid {
                                required,
                            }));
                        }
                    }
                    None => {
                        return Err(anyhow::Error::new(CapabilityError::ProofOfWorkRequired {
                            difficulty: required,
                        }));
                    }
                }
            }

            let stream_id = cap_stream_id_from_label(&stream).map_err(|err| {
                anyhow::Error::new(CapabilityError::StreamInvalid {
                    stream: stream.clone(),
                    source: err,
                })
            })?;

            let attachments = attachments.unwrap_or_default();
            if attachments.len() > MAX_ATTACHMENTS_PER_MSG {
                return Err(anyhow::Error::new(
                    CapabilityError::AttachmentCountExceeded {
                        count: attachments.len(),
                        limit: MAX_ATTACHMENTS_PER_MSG,
                    },
                ));
            }

            let payload_json =
                serde_json::to_string(&payload).context("serialising submit payload to JSON")?;
            if payload_json.len() > MAX_BODY_BYTES {
                return Err(anyhow::Error::new(CapabilityError::MessageBodyTooLarge {
                    body_bytes: payload_json.len(),
                    limit: MAX_BODY_BYTES,
                }));
            }
            let prepared_attachments = prepare_attachments_for_storage(
                &self.storage,
                &stream,
                &attachments,
                payload_json.len(),
            )?;
            let stored_attachments = prepared_attachments.stored;
            let prepared_attachments = prepared_attachments.prepared;
            let submitted_at = current_unix_timestamp()?;
            let submitted_at_ms = current_unix_timestamp_millis()?;
            let client_id_value = ClientId::from_str(&client_id).with_context(|| {
                format!("parsing client_id {client_id} as hex-encoded identifier")
            })?;
            let client_target = RevocationTarget::from_slice(client_id_value.as_ref())
                .context("constructing client revocation target")?;
            let auth_target = if let Some(ref auth_hex) = auth_ref {
                let parsed = AuthRef::from_str(auth_hex).with_context(|| {
                    format!("parsing auth_ref {auth_hex} as hex-encoded identifier")
                })?;
                Some(
                    RevocationTarget::from_slice(parsed.as_ref())
                        .context("constructing auth_ref revocation target")?,
                )
            } else {
                None
            };

            (
                stream_id,
                payload_json,
                prepared_attachments,
                stored_attachments,
                submitted_at,
                submitted_at_ms,
                client_target,
                auth_target,
            )
        };

        let (mut guard, mut capability_store_dirty, usage_update) = async {
            {
                let guard = self.inner.read().await;
                let authority = guard
                    .authority_view
                    .label_authority_for_stream(stream_id, submitted_at);
                if !authority.allows_hub(self.identity.hub_id) {
                    let policy_str = match authority.policy {
                        LabelPolicy::SinglePrimary => "single-primary",
                        LabelPolicy::MultiPrimary => "multi-primary",
                        LabelPolicy::Unspecified => "unspecified",
                    };

                    let detail = match authority.policy {
                        LabelPolicy::SinglePrimary => authority
                            .primary_hub
                            .map(|primary| {
                                format!("; expected primary {}", hex::encode(primary.as_ref()))
                            })
                            .unwrap_or_default(),
                        LabelPolicy::MultiPrimary => {
                            let mut allowed = Vec::new();
                            if let Some(primary) = authority.primary_hub {
                                allowed.push(hex::encode(primary.as_ref()));
                            }
                            allowed.extend(
                                authority
                                    .replica_hubs
                                    .iter()
                                    .map(|hub| hex::encode(hub.as_ref())),
                            );
                            if allowed.is_empty() {
                                String::new()
                            } else {
                                format!("; allowed hubs {}", allowed.join(","))
                            }
                        }
                        LabelPolicy::Unspecified => String::new(),
                    };

                    return Err(anyhow::Error::new(
                        CapabilityError::NotAuthorisedForStream {
                            stream: stream.clone(),
                            policy: policy_str,
                            detail,
                        },
                    ));
                }

                if matches!(authority.policy, LabelPolicy::MultiPrimary) {
                    let mut allowed = Vec::new();
                    if let Some(primary) = authority.primary_hub {
                        allowed.push(hex::encode(primary.as_ref()));
                    }
                    allowed.extend(
                        authority
                            .replica_hubs
                            .iter()
                            .map(|hub| hex::encode(hub.as_ref())),
                    );
                    tracing::debug!(
                        stream = %stream,
                        allowed_hubs = %allowed.join(","),
                        "accepting multi-primary stream"
                    );
                }

                if guard
                    .revocations
                    .is_revoked(RevocationKind::ClientId, client_target, submitted_at)
                {
                    return Err(anyhow::Error::new(CapabilityError::ClientIdRevoked {
                        client_id: client_id.clone(),
                    }));
                }

                if let (Some(auth_hex), Some(target)) = (auth_ref.as_ref(), auth_target) {
                    if guard
                        .revocations
                        .is_revoked(RevocationKind::AuthRef, target, submitted_at)
                    {
                        return Err(anyhow::Error::new(CapabilityError::AuthRefRevoked {
                            auth_ref: auth_hex.clone(),
                        }));
                    }
                }
            }

            let mut guard = self.inner.write().await;
            let mut capability_store_dirty = false;

            let token_revocation = if let Some(auth_hex) = auth_ref.as_ref() {
                if let Some(record) = guard.capabilities.records.get(auth_hex) {
                    if let Some(hash) = record.token_hash.as_ref() {
                        Some((hash.clone(), revocation_target_from_hex_str(hash)?))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(cap) = auth_ref.as_ref() {
                let capability_dirty = match enforce_capability(
                    &mut guard.capabilities,
                    cap,
                    &client_id,
                    &stream,
                    submitted_at,
                    submitted_at_ms,
                ) {
                    Ok(dirty) => dirty,
                    Err(err) => {
                        return self.capability_err(guard, err).await;
                    }
                };
                capability_store_dirty |= capability_dirty;
            } else if self.admission.capability_gating_enabled {
                return self
                    .capability_err(
                        guard,
                        CapabilityError::Unauthorized {
                            auth_ref: "missing".to_string(),
                        },
                    )
                    .await;
            }

            if let Some((token_hash, target)) = token_revocation {
                if guard
                    .revocations
                    .is_revoked(RevocationKind::CapToken, target, submitted_at)
                {
                    return self
                        .capability_err(guard, CapabilityError::CapTokenRevoked { token_hash })
                        .await;
                }
            }

            let (usage_update, usage_dirty) = match check_client_usage(
                &mut guard.capabilities,
                &self.admission,
                &client_id,
                &stream,
                submitted_at,
            ) {
                Ok(result) => result,
                Err(err) => {
                    return self.capability_err(guard, err).await;
                }
            };
            capability_store_dirty |= usage_dirty;

            Ok((guard, capability_store_dirty, usage_update))
        }
        .instrument(tracing::info_span!("hub_submit.capability_checks"))
        .await?;
        let stream_runtime = guard
            .streams
            .entry(stream.clone())
            .or_insert_with(StreamRuntime::empty);

        let seq = stream_runtime
            .state
            .messages
            .last()
            .map(|m| m.seq + 1)
            .unwrap_or(1);

        let stored_message = StoredMessage {
            stream: stream.clone(),
            seq,
            sent_at: submitted_at,
            client_id: client_id.clone(),
            schema,
            expires_at,
            parent: None,
            body: Some(payload_json),
            body_digest: None,
            attachments: stored_attachments.clone(),
            auth_ref: auth_ref.clone(),
            idem,
        };

        let (leaf, leaf_hex, confirmed_duplicate) = async {
            let leaf = leaf_hash_for(&stored_message)?;
            let leaf_hex = hex::encode(leaf.as_bytes());
            let mut confirmed_duplicate = false;
            let dedup_result = {
                let mut dedup = self.dedup.lock().await;
                dedup.check_and_insert(&stream, &leaf)
            };
            match dedup_result {
                DedupCheck::RecentDuplicate => {
                    confirmed_duplicate = true;
                }
                DedupCheck::BloomHit => {
                    confirmed_duplicate = leaf_hash_exists(stream_runtime, &leaf)?;
                    let mut dedup = self.dedup.lock().await;
                    if confirmed_duplicate {
                        dedup.confirm_duplicate(&stream, &leaf);
                    } else {
                        dedup.confirm_unique(&stream, &leaf);
                    }
                }
                DedupCheck::New => {}
            }
            Ok::<_, anyhow::Error>((leaf, leaf_hex, confirmed_duplicate))
        }
        .instrument(tracing::info_span!("hub_submit.dedup_lookup"))
        .await?;
        if confirmed_duplicate {
            tracing::warn!(
                stream = %stream,
                client_id = %client_id,
                leaf_hash = %leaf_hex,
                "dropping duplicate message by leaf hash"
            );
            drop(guard);
            self.observability.record_submit_err("E.DUP");
            self.record_admission_failure(&stream, &client_id, "E.DUP", "duplicate leaf hash")
                .await?;
            return Err(anyhow::Error::new(SubmitError::Duplicate {
                leaf_hash: leaf_hex,
            }));
        }
        let (computed_seq, mmr_root, proof) =
            tracing::info_span!("hub_submit.mmr_append").in_scope(|| {
                stream_runtime.mmr.append_with_proof(leaf)
            });
        debug_assert_eq!(computed_seq, seq, "stream mmr seq must match message seq");
        stream_runtime.insert_message_with_leaf(stored_message.clone(), leaf);
        let mmr_root_hex = hex::encode(mmr_root.as_bytes());
        let receipt = StreamReceipt {
            seq,
            leaf_hash: leaf_hex.clone(),
            mmr_root: mmr_root_hex.clone(),
            hub_ts: submitted_at,
        };
        let message_with_proof = StreamMessageWithProof {
            message: stored_message.clone(),
            receipt: receipt.clone(),
            proof: StreamProof::from(proof),
        };
        stream_runtime.push_proven(message_with_proof.clone());

        let usage_applied_dirty =
            match apply_client_usage_update(&mut guard.capabilities, usage_update) {
                Ok(dirty) => dirty,
                Err(err) => {
                    return self.capability_err(guard, err).await;
                }
            };
        capability_store_dirty |= usage_applied_dirty;

        let stream_index_entry = StreamIndexEntry {
            seq,
            leaf_hash: leaf_hex,
            bundle: self.storage.message_bundle_filename(&stream, seq),
        };
        let capability_snapshot = if capability_store_dirty {
            Some(guard.capabilities.clone())
        } else {
            None
        };
        drop(guard);

        async {
            persist_attachments(
                &self.storage,
                &prepared_attachments,
                &self.attachment_ref_counts,
            )
            .await?;
            persist_stream_state(&self.storage, &stream, &stream_index_entry).await?;
            persist_message_bundle(&self.storage, &stream, seq, &message_with_proof).await?;
            append_receipt(&self.storage, &message_with_proof).await?;

            if let Some(store) = capability_snapshot {
                update_capability_store(&self.storage, &store).await?;
            }

            if let Err(err) = self
                .persist_recent_dedup_cache()
                .await
                .context("persisting recent dedup cache")
            {
                tracing::warn!(error = ?err, "failed to persist recent dedup cache");
            }

            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::info_span!("hub_submit.persistence"))
        .await?;

        self.observability.record_submit_ok();

        Ok(SubmitResponse {
            stream,
            seq,
            mmr_root: mmr_root_hex,
            stored_attachments,
        })
    }

    pub async fn commit_status(&self, stream: &str, seq: u64) -> Result<bool> {
        let guard = self.inner.read().await;
        let Some(runtime) = guard.streams.get(stream) else {
            return Ok(false);
        };
        let last_seq = runtime
            .state
            .messages
            .last()
            .map(|message| message.seq)
            .unwrap_or_default();
        Ok(last_seq >= seq)
    }

    async fn capability_err<T>(
        &self,
        guard: RwLockWriteGuard<'_, HubState>,
        err: CapabilityError,
    ) -> Result<T> {
        let snapshot = guard.capabilities.clone();
        drop(guard);
        update_capability_store(&self.storage, &snapshot).await?;
        Err(anyhow::Error::new(err))
    }

    async fn persist_recent_dedup_cache(&self) -> Result<()> {
        let entries = {
            let dedup = self.dedup.lock().await;
            dedup.recent_keys()
        };
        persist_recent_dedup_cache(&self.storage, &entries).await
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

        let mut guard = self.inner.write().await;
        let stream_runtime = guard
            .streams
            .entry(stream.clone())
            .or_insert_with(StreamRuntime::empty);

        if let Some(existing) = stream_runtime.message_by_seq(message.seq) {
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
        let (_, mmr_root, proof) = stream_runtime.mmr.append_with_proof(leaf);
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

        stream_runtime.insert_message_with_leaf(message.clone(), leaf);
        let receipt = StreamReceipt {
            seq: message.seq,
            leaf_hash: hex::encode(leaf.as_bytes()),
            mmr_root: computed_root.clone(),
            hub_ts: message.sent_at,
        };
        let message_with_proof = StreamMessageWithProof {
            message: message.clone(),
            receipt: receipt.clone(),
            proof: StreamProof::from(proof),
        };
        stream_runtime.push_proven(message_with_proof.clone());

        persist_message_bundle(&self.storage, &stream, message.seq, &message_with_proof).await?;
        stream_index::append_stream_index(
            &self.storage,
            &stream,
            &StreamIndexEntry {
                seq: message.seq,
                leaf_hash: hex::encode(leaf.as_bytes()),
                bundle: self.storage.message_bundle_filename(&stream, message.seq),
            },
        )
        .await?;
        append_receipt(&self.storage, &message_with_proof).await?;

        self.observability.record_submit_ok();

        Ok(BridgeIngestResponse {
            stream,
            seq: message.seq,
            mmr_root: computed_root,
        })
    }

    pub async fn publish_revocation(&self, payload: &[u8]) -> Result<()> {
        if matches!(self.role, HubRole::Replica) {
            bail!("replica hubs are read-only");
        }

        let envelope: SignedEnvelope<RevocationRecord> =
            ciborium::de::from_reader(payload).context("decoding revocation envelope")?;
        if envelope.schema.as_ref() != schema_revocation().as_slice() {
            bail!("unexpected schema identifier in revocation envelope");
        }

        let record = envelope.body;
        tracing::info!(?record, "recorded revocation");

        let mut guard = self.inner.write().await;
        guard.revocations.insert(record.clone());
        update_revocation_index(&mut guard.revocation_index, &record);
        let index = guard.revocation_log.len();
        guard.revocation_log.push(record.clone());
        update_revocation_order(&mut guard.revocation_order, record.ts, index);
        persist_revocations(&self.storage, &guard.revocation_log).await
    }

    pub async fn publish_authority(&self, payload: &[u8]) -> Result<()> {
        if matches!(self.role, HubRole::Replica) {
            bail!("replica hubs are read-only");
        }

        let envelope: SignedEnvelope<AuthorityRecord> =
            ciborium::de::from_reader(payload).context("decoding authority envelope")?;
        if envelope.schema.as_ref() != schema_fed_authority().as_slice() {
            bail!("unexpected schema identifier in authority envelope");
        }

        let record = envelope.body;
        tracing::info!(?record, "recorded authority record");

        let mut guard = self.inner.write().await;
        guard.authority_records.push(record.clone());
        guard.authority_view.insert(record);
        persist_authority_records(&self.storage, &guard.authority_records).await
    }

    pub async fn publish_label_class(&self, payload: &[u8]) -> Result<()> {
        if matches!(self.role, HubRole::Replica) {
            bail!("replica hubs are read-only");
        }

        let envelope: SignedEnvelope<LabelClassRecord> =
            ciborium::de::from_reader(payload).context("decoding label class envelope")?;
        if envelope.schema.as_ref() != schema_label_class().as_slice() {
            bail!("unexpected schema identifier in label class envelope");
        }

        let record = envelope.body;
        tracing::info!(?record, "recorded label class");

        let mut guard = self.inner.write().await;
        guard.label_class_index.insert(record.label, record.clone());
        guard.label_class_records.push(record);
        persist_label_classes(&self.storage, &guard.label_class_records).await
    }

    pub async fn register_schema_descriptor(&self, payload: &[u8]) -> Result<()> {
        if matches!(self.role, HubRole::Replica) {
            bail!("replica hubs are read-only");
        }

        let envelope: SignedEnvelope<SchemaDescriptor> =
            ciborium::de::from_reader(payload).context("decoding schema descriptor envelope")?;
        if envelope.schema.as_ref() != schema_meta_schema().as_slice() {
            bail!("unexpected schema identifier in schema descriptor envelope");
        }

        let descriptor = envelope.body;
        tracing::info!(?descriptor, "registered schema descriptor");

        let mut guard = self.inner.write().await;
        guard.schema_descriptors.push(descriptor.clone());
        let seq = guard.schema_descriptors.len() as u64;
        guard.schema_registry.upsert(descriptor, seq);
        persist_schema_descriptors(&self.storage, &guard.schema_descriptors).await
    }

    pub async fn stream(
        &self,
        stream: &str,
        from: u64,
        with_proof: bool,
    ) -> Result<StreamResponse> {
        if !with_proof {
            let messages = {
                let guard = self.inner.read().await;
                let runtime = guard
                    .streams
                    .get(stream)
                    .ok_or_else(|| anyhow!("stream {stream} has no stored messages"))?;
                runtime.messages_from(from)
            };
            return Ok(StreamResponse::Messages(messages));
        }

        let (window_start, last_seq, proven_tail) = {
            let guard = self.inner.read().await;
            let runtime = guard
                .streams
                .get(stream)
                .ok_or_else(|| anyhow!("stream {stream} has no stored messages"))?;
            let window_start = runtime
                .proven_messages
                .front()
                .map(|entry| entry.message.seq);
            let last_seq = runtime.state.messages.last().map(|msg| msg.seq).unwrap_or(0);
            let proven_tail = runtime.proven_messages_from(from);
            (window_start, last_seq, proven_tail)
        };
        let mut proven = Vec::new();
        if let Some(window_start) = window_start {
            if from < window_start {
                let end = window_start.saturating_sub(1);
                if from <= end {
                    proven.extend(
                        load_proven_messages_range(&self.storage, stream, from, end).await?,
                    );
                }
            }
            proven.extend(proven_tail);
        } else if from <= last_seq {
            proven.extend(load_proven_messages_range(&self.storage, stream, from, last_seq).await?);
        }

        Ok(StreamResponse::Proven(proven))
    }

    pub async fn resync(&self, stream: &str) -> Result<HubStreamState> {
        let runtime = {
            let guard = self.inner.read().await;
            guard
                .streams
                .get(stream)
                .cloned()
                .ok_or_else(|| anyhow!("stream {stream} has no stored messages"))?
        };
        Ok(runtime.state)
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

        let now = current_unix_timestamp()?;
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
        let stream_id_set: HashSet<String> = stream_ids.iter().cloned().collect();

        tracing::info!(
            auth_ref = %auth_ref_hex,
            subject = %subject_hex,
            streams = ?stream_ids,
            ttl = token.allow.ttl,
            rate = ?token.allow.rate,
            expires_at,
            "authorised capability admission"
        );

        let mut guard = self.inner.write().await;
        let bucket_state = match token.allow.rate.as_ref() {
            Some(rate) => Some(TokenBucketState::new(
                rate.burst,
                current_unix_timestamp_millis()?,
            )),
            None => None,
        };
        let record = CapabilityRecord {
            subject: subject_hex,
            stream_ids,
            stream_id_set,
            expires_at,
            ttl: token.allow.ttl,
            rate: token.allow.rate.clone(),
            bucket_state,
            uses: 0,
            token_hash: Some(hex::encode(cap_token_hash(token_bytes))),
        };
        guard
            .capabilities
            .records
            .insert(auth_ref_hex.clone(), record);
        update_capability_store(&self.storage, &guard.capabilities).await?;

        Ok(AuthorizeResponse {
            auth_ref,
            expires_at,
        })
    }

    pub async fn anchor_checkpoint(&self, anchor: AnchorRequest) -> Result<()> {
        let mut guard = self.inner.write().await;
        guard.anchors.entries.push(AnchorRecord {
            stream: anchor.stream,
            mmr_root: anchor.mmr_root,
            timestamp: current_unix_timestamp()?,
            backend: anchor.backend,
        });
        persist_anchor_log(&self.storage, &guard.anchors).await
    }

    pub async fn metrics_snapshot(&self) -> ObservabilityReport {
        let snapshot = self.observability.snapshot();
        let guard = self.inner.read().await;
        let mut last_seq = HashMap::new();
        let mut peaks = HashMap::new();
        let mut max_seq = 0u64;
        for (stream, runtime) in &guard.streams {
            let seq = runtime.mmr.seq();
            if seq > 0 {
                last_seq.insert(stream.clone(), seq);
                if let Some(root) = runtime.mmr.root() {
                    peaks.insert(stream.clone(), hex::encode(root.as_bytes()));
                }
            }
            max_seq = max_seq.max(seq);
        }
        let ObservabilitySnapshot {
            uptime,
            submit_ok_total,
            submit_err_total,
        } = snapshot;
        ObservabilityReport {
            uptime,
            submit_ok_total,
            submit_err_total,
            last_stream_seq: last_seq,
            mmr_roots: peaks,
            peaks_count: max_seq,
            profile_id: self.profile_id.clone(),
            hub_id: Some(self.identity.hub_id_hex.clone()),
            hub_public_key: Some(self.identity.public_key_hex.clone()),
            role: match self.role {
                HubRole::Primary => "primary".to_string(),
                HubRole::Replica => "replica".to_string(),
            },
            data_dir: self.storage.data_dir().to_string_lossy().into_owned(),
        }
    }

    pub async fn readiness_report(&self) -> Result<HubReadinessReport> {
        let mut details = Vec::new();
        let data_dir = self.storage.data_dir().to_string_lossy().into_owned();
        let state_dir = self.storage.state_dir();
        let state_dir_accessible = match fs::metadata(&state_dir).await {
            Ok(_) => true,
            Err(err) => {
                details.push(format!(
                    "state directory {} not accessible: {err}",
                    state_dir.display()
                ));
                false
            }
        };

        let now = current_unix_timestamp()?;
        let mut indexes_initialised = true;
        let authority_readiness = {
            let guard = self.inner.read().await;
            for (stream, runtime) in &guard.streams {
                let mmr_seq = runtime.mmr.seq();
                let message_count = runtime.state.messages.len() as u64;
                if mmr_seq != message_count {
                    indexes_initialised = false;
                    details.push(format!(
                        "stream {stream} MMR seq {mmr_seq} diverges from stored message count {message_count}"
                    ));
                }
            }

            let mut latest_ts: Option<u64> = None;
            let mut active = 0usize;
            let mut stale = 0usize;
            for record in &guard.authority_records {
                if record.is_active_at(now) {
                    active += 1;
                } else {
                    stale += 1;
                }
                latest_ts = Some(match latest_ts {
                    Some(current) => current.max(record.ts),
                    None => record.ts,
                });
            }

            AuthorityReadiness {
                ok: active > 0 || stale == 0,
                active_records: active,
                stale_records: stale,
                latest_record_ts: latest_ts,
            }
        };

        if !authority_readiness.ok {
            details.push("no active authority records in view".to_string());
        }

        let ok = state_dir_accessible && indexes_initialised && authority_readiness.ok;

        Ok(HubReadinessReport {
            ok,
            data_dir,
            state_dir_accessible,
            indexes_initialised,
            authority_view: authority_readiness,
            details,
        })
    }

    pub async fn profile_descriptor(&self) -> HubProfileDescriptor {
        let guard = self.inner.read().await;
        let features = HubProfileFeatures {
            core: true,
            fed1: matches!(self.role, HubRole::Replica)
                || !self.federation.replica_targets.is_empty()
                || !guard.authority_records.is_empty(),
            auth1: !guard.authority_records.is_empty(),
            kex1_plus: guard
                .capabilities
                .records
                .values()
                .any(|record| record.rate.is_some())
                || self.admission.pow_difficulty.is_some(),
            sh1_plus: self.admission.capability_gating_enabled,
            lclass0: !guard.label_class_records.is_empty(),
            meta0_plus: !guard.schema_descriptors.is_empty(),
        };
        HubProfileDescriptor {
            ok: true,
            version: "veen-0.0.1+".to_string(),
            profile_id: self.profile_id.clone(),
            hub_id: self.identity.hub_id_hex.clone(),
            features,
        }
    }

    pub async fn role_descriptor(
        &self,
        realm_id: Option<RealmId>,
        stream_id: Option<StreamId>,
    ) -> Result<HubRoleDescriptor> {
        let role = match self.role {
            HubRole::Primary => {
                if self.federation.replica_targets.is_empty() {
                    "standalone"
                } else {
                    "federated-primary"
                }
            }
            HubRole::Replica => "federated-replica",
        }
        .to_string();

        if let Some(stream_id) = stream_id {
            let guard = self.inner.read().await;
            let now = current_unix_timestamp()?;
            let authority = guard
                .authority_view
                .label_authority(stream_id, realm_id, now);
            let realm_hex = authority.realm_id.map(|realm| hex::encode(realm.as_ref()));
            let stream_hex = hex::encode(stream_id.as_ref());
            let label_hex = hex::encode(Label::derive([], stream_id, 0).as_ref());
            let policy = match authority.policy {
                LabelPolicy::SinglePrimary => "single-primary",
                LabelPolicy::MultiPrimary => "multi-primary",
                LabelPolicy::Unspecified => "unspecified",
            }
            .to_string();
            let primary_hex = authority.primary_hub.map(|hub| hex::encode(hub.as_ref()));
            let local_is_primary = authority.primary_hub == Some(self.identity.hub_id);

            Ok(HubRoleDescriptor {
                ok: true,
                hub_id: self.identity.hub_id_hex.clone(),
                role,
                stream: Some(HubRoleStreamDescriptor {
                    realm_id: realm_hex,
                    stream_id: stream_hex,
                    label: label_hex,
                    policy,
                    primary_hub: primary_hex,
                    local_is_primary,
                }),
            })
        } else {
            Ok(HubRoleDescriptor {
                ok: true,
                hub_id: self.identity.hub_id_hex.clone(),
                role,
                stream: None,
            })
        }
    }

    pub async fn kex_policy_descriptor(&self) -> HubKexPolicyDescriptor {
        let guard = self.inner.read().await;
        let default_cap_ttl_sec = guard
            .capabilities
            .records
            .values()
            .next()
            .map(|record| record.ttl);
        let max_cap_ttl_sec = guard
            .capabilities
            .records
            .values()
            .map(|record| record.ttl)
            .max();

        HubKexPolicyDescriptor {
            ok: true,
            max_client_id_lifetime_sec: self.admission.max_client_id_lifetime_sec,
            max_msgs_per_client_id_per_label: self.admission.max_msgs_per_client_id_per_label,
            default_cap_ttl_sec,
            max_cap_ttl_sec,
            revocation_stream: None,
            rotation_window_sec: self.admission.max_client_id_lifetime_sec,
        }
    }

    pub async fn admission_report(&self) -> HubAdmissionReport {
        let guard = self.inner.read().await;
        let mut stages = Vec::new();
        let mut recent_err_rates = BTreeMap::new();
        recent_err_rates.insert("E.AUTH".to_string(), 0.0);
        recent_err_rates.insert("E.CAP".to_string(), 0.0);

        stages.push(HubAdmissionStage {
            name: "capability-gating".to_string(),
            enabled: self.admission.capability_gating_enabled,
            responsibilities: vec![
                "verify capability auth_ref".to_string(),
                "enforce per-stream grants".to_string(),
            ],
            queue_depth: 0,
            max_queue_depth: 0,
            recent_err_rates: recent_err_rates.clone(),
        });

        if self.admission.max_client_id_lifetime_sec.is_some()
            || self.admission.max_msgs_per_client_id_per_label.is_some()
        {
            let usage_entries = guard.capabilities.client_usage.len();
            stages.push(HubAdmissionStage {
                name: "client-usage".to_string(),
                enabled: true,
                responsibilities: vec![
                    "track client lifetime".to_string(),
                    "enforce per-label quotas".to_string(),
                ],
                queue_depth: usage_entries as u64,
                max_queue_depth: usage_entries.saturating_add(1) as u64,
                recent_err_rates: BTreeMap::new(),
            });
        }

        stages.push(HubAdmissionStage {
            name: "revocation-enforcement".to_string(),
            enabled: true,
            responsibilities: vec!["apply client/capability revocations".to_string()],
            queue_depth: guard.revocation_log.len() as u64,
            max_queue_depth: guard.revocation_log.len() as u64,
            recent_err_rates: BTreeMap::new(),
        });

        if let Some(difficulty) = self.admission.pow_difficulty {
            stages.push(HubAdmissionStage {
                name: "proof-of-work".to_string(),
                enabled: true,
                responsibilities: vec![format!("require cookie with difficulty >= {difficulty}")],
                queue_depth: 0,
                max_queue_depth: 0,
                recent_err_rates: BTreeMap::new(),
            });
        }

        HubAdmissionReport { ok: true, stages }
    }

    pub async fn admission_log(
        &self,
        limit: Option<usize>,
        codes: Option<Vec<String>>,
    ) -> HubAdmissionLogResponse {
        let guard = self.inner.read().await;
        let code_filter = codes.map(|values| {
            values
                .into_iter()
                .map(|value| value.trim().to_ascii_uppercase())
                .collect::<BTreeSet<_>>()
        });

        let mut events: Vec<AdmissionLogEvent> = guard
            .admission_events
            .iter()
            .rev()
            .filter(|event| match &code_filter {
                Some(set) => set.contains(&event.code),
                None => true,
            })
            .cloned()
            .collect();
        if let Some(limit) = limit {
            events.truncate(limit);
        }

        HubAdmissionLogResponse { ok: true, events }
    }

    pub async fn record_admission_failure(
        &self,
        label: &str,
        client_id: &str,
        code: &str,
        detail: &str,
    ) -> Result<()> {
        let mut guard = self.inner.write().await;
        if guard.admission_events.len() >= MAX_ADMISSION_EVENTS {
            guard.admission_events.pop_front();
        }
        guard.admission_events.push_back(AdmissionLogEvent {
            ts: current_unix_timestamp()?,
            code: code.trim().to_ascii_uppercase(),
            label_prefix: identifier_prefix(label),
            client_id_prefix: identifier_prefix(client_id),
            detail: detail.to_string(),
        });
        Ok(())
    }

    pub async fn capability_status(&self, auth_ref_hex: &str) -> Result<HubCapStatusResponse> {
        if auth_ref_hex.is_empty() {
            bail!("auth_ref must not be empty");
        }
        let auth_target = revocation_target_from_hex_str(auth_ref_hex)?;
        let now = current_unix_timestamp()?;
        let guard = self.inner.read().await;
        let record = guard.capabilities.records.get(auth_ref_hex);
        let mut revocation_detail: Option<(RevocationKind, RevocationRecord)> = guard
            .revocation_index
            .get(&(RevocationKind::AuthRef, auth_target))
            .cloned()
            .map(|record| (RevocationKind::AuthRef, record));

        if revocation_detail.is_none() {
            if let Some(cap_record) = record {
                if let Some(token_hash) = cap_record.token_hash.as_ref() {
                    if let Ok(target) = revocation_target_from_hex_str(token_hash) {
                        if let Some(entry) = guard
                            .revocation_index
                            .get(&(RevocationKind::CapToken, target))
                            .cloned()
                        {
                            revocation_detail = Some((RevocationKind::CapToken, entry));
                        }
                    }
                }
            }
        }

        let (revocation_kind, revocation_ts, reason) =
            if let Some((kind, entry)) = revocation_detail {
                (
                    Some(revocation_kind_label(kind).to_string()),
                    Some(entry.ts),
                    entry.reason.clone(),
                )
            } else {
                (None, None, None)
            };

        Ok(HubCapStatusResponse {
            ok: true,
            auth_ref: auth_ref_hex.to_string(),
            hub_known: record.is_some(),
            currently_valid: record.map(|rec| rec.expires_at > now).unwrap_or(false),
            revoked: revocation_kind.is_some(),
            expires_at: record.map(|rec| rec.expires_at),
            revocation_kind,
            revocation_ts,
            reason,
        })
    }

    pub async fn revocation_list(
        &self,
        kind: Option<RevocationKind>,
        since: Option<u64>,
        active_only: bool,
        limit: Option<usize>,
    ) -> Result<HubRevocationList> {
        let now = current_unix_timestamp()?;
        let guard = self.inner.read().await;
        let mut entries = Vec::new();
        let range = match since {
            Some(start) => guard.revocation_order.range(start..),
            None => guard.revocation_order.range(..),
        };
        for (_, indices) in range.rev() {
            for &index in indices {
                let record = guard
                    .revocation_log
                    .get(index)
                    .expect("revocation index entry missing");
                if let Some(expected) = kind {
                    if record.kind != expected {
                        continue;
                    }
                }
                let active_now = record.is_active_at(now);
                if active_only && !active_now {
                    continue;
                }
                entries.push(HubRevocationEntry {
                    kind: revocation_kind_label(record.kind).to_string(),
                    target: hex::encode(record.target.as_bytes()),
                    ts: record.ts,
                    ttl: record.ttl,
                    reason: record.reason.clone(),
                    active_now,
                });
                if let Some(limit) = limit {
                    if entries.len() >= limit {
                        break;
                    }
                }
            }
            if let Some(limit) = limit {
                if entries.len() >= limit {
                    break;
                }
            }
        }
        Ok(HubRevocationList {
            ok: true,
            revocations: entries,
        })
    }

    pub async fn pow_challenge(&self, requested: Option<u8>) -> Result<HubPowChallengeDescriptor> {
        let difficulty = requested.or(self.admission.pow_difficulty).unwrap_or(1);
        if difficulty == 0 {
            bail!("pow difficulty must be greater than zero");
        }
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        Ok(HubPowChallengeDescriptor {
            ok: true,
            challenge: hex::encode(challenge),
            difficulty,
        })
    }

    pub async fn authority_view_descriptor(
        &self,
        realm_id: RealmId,
        stream_id: StreamId,
    ) -> Result<HubAuthorityRecordDescriptor> {
        let now = current_unix_timestamp()?;
        let records = {
            let guard = self.inner.read().await;
            guard.authority_view.records_for(realm_id, stream_id)
        };

        let ordering = |a: &AuthorityRecord, b: &AuthorityRecord| {
            a.ts.cmp(&b.ts)
                .then_with(|| a.primary_hub.as_ref().cmp(b.primary_hub.as_ref()))
        };

        let mut selected = None;
        let mut active = None;
        for record in &records {
            if selected
                .map(|current| ordering(record, current) == Ordering::Less)
                .unwrap_or(true)
            {
                selected = Some(record);
            }
            if record.is_active_at(now)
                && active
                    .map(|current| ordering(record, current) == Ordering::Less)
                    .unwrap_or(true)
            {
                active = Some(record);
            }
        }
        let selected = active.or(selected);

        let primary_hub = selected.map(|record| hex::encode(record.primary_hub.as_ref()));
        let replica_hubs = selected
            .map(|record| {
                record
                    .replica_hubs
                    .iter()
                    .map(|hub| hex::encode(hub.as_ref()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let policy = selected
            .map(|record| match record.policy {
                AuthorityPolicy::SinglePrimary => "single-primary".to_string(),
                AuthorityPolicy::MultiPrimary => "multi-primary".to_string(),
            })
            .unwrap_or_else(|| "unspecified".to_string());
        let ts = selected.map(|record| record.ts).unwrap_or(0);
        let ttl = selected.map(|record| record.ttl).unwrap_or(0);
        let expires_at = selected.and_then(|record| record.expires_at());
        let active_now = active.is_some();

        Ok(HubAuthorityRecordDescriptor {
            ok: true,
            realm_id: hex::encode(realm_id.as_ref()),
            stream_id: hex::encode(stream_id.as_ref()),
            primary_hub,
            replica_hubs,
            policy,
            ts,
            ttl,
            expires_at,
            active_now,
        })
    }

    pub async fn label_authority_descriptor(
        &self,
        stream_id: StreamId,
    ) -> Result<HubLabelAuthorityDescriptor> {
        let now = current_unix_timestamp()?;
        let authority = {
            let guard = self.inner.read().await;
            guard
                .authority_view
                .label_authority_for_stream(stream_id, now)
        };

        let policy = match authority.policy {
            LabelPolicy::SinglePrimary => "single-primary".to_string(),
            LabelPolicy::MultiPrimary => "multi-primary".to_string(),
            LabelPolicy::Unspecified => "unspecified".to_string(),
        };

        let primary_hub = authority.primary_hub.map(|hub| hex::encode(hub.as_ref()));
        let replica_hubs = authority
            .replica_hubs
            .iter()
            .map(|hub| hex::encode(hub.as_ref()))
            .collect::<Vec<_>>();
        let realm_id = authority
            .realm_id
            .map(|realm| hex::encode(realm.as_ref()))
            .filter(|value| !value.is_empty());
        let local_is_authorized = authority.allows_hub(self.identity.hub_id);

        Ok(HubLabelAuthorityDescriptor {
            ok: true,
            label: hex::encode(stream_id.as_ref()),
            realm_id,
            stream_id: hex::encode(stream_id.as_ref()),
            policy,
            primary_hub,
            replica_hubs,
            local_hub_id: self.identity.hub_id_hex.clone(),
            local_is_authorized,
        })
    }

    pub async fn label_class_descriptor(&self, label: Label) -> HubLabelClassDescriptor {
        let record = {
            let guard = self.inner.read().await;
            guard.label_class_index.get(&label).cloned()
        };

        let class_text = record.as_ref().map(|record| record.class.clone());
        let sensitivity = record
            .as_ref()
            .and_then(|record| record.sensitivity.clone());
        let retention_hint = record.and_then(|record| record.retention_hint);
        let normalized = class_text
            .as_deref()
            .map(|value| value.to_ascii_lowercase());
        let pad_block = pad_block_for_class(normalized.as_deref());
        let retention_policy = retention_policy_for_class(normalized.as_deref());
        let rate_policy = rate_policy_for_class(normalized.as_deref());

        HubLabelClassDescriptor {
            ok: true,
            label: hex::encode(label.as_bytes()),
            class: class_text,
            sensitivity,
            retention_hint,
            pad_block_effective: pad_block,
            retention_policy: retention_policy.to_string(),
            rate_policy: rate_policy.to_string(),
        }
    }

    pub async fn label_class_list(&self, class_filter: Option<String>) -> HubLabelClassList {
        let class_filter = class_filter.as_deref();
        let entries = {
            let guard = self.inner.read().await;
            let mut entries = guard
                .label_class_records
                .iter()
                .filter(|record| {
                    if let Some(filter) = class_filter {
                        record.class.eq_ignore_ascii_case(filter)
                    } else {
                        true
                    }
                })
                .map(|record| HubLabelClassListEntry {
                    label: hex::encode(record.label.as_bytes()),
                    class: record.class.clone(),
                    sensitivity: record.sensitivity.clone(),
                    retention_hint: record.retention_hint,
                })
                .collect::<Vec<_>>();
            entries.sort_by(|a, b| a.label.cmp(&b.label));
            entries
        };

        HubLabelClassList { ok: true, entries }
    }

    pub async fn anchor_log(&self) -> Result<AnchorLog> {
        let guard = self.inner.read().await;
        Ok(guard.anchors.clone())
    }

    pub async fn latest_checkpoint(&self) -> Result<Option<Checkpoint>> {
        let mut checkpoints = read_checkpoints(&self.storage).await?;
        Ok(checkpoints.pop())
    }

    pub async fn checkpoint_range(
        &self,
        from_epoch: Option<u64>,
        to_epoch: Option<u64>,
    ) -> Result<Vec<Checkpoint>> {
        let start = from_epoch.unwrap_or(0);
        let end = to_epoch.unwrap_or(u64::MAX);
        if start > end {
            bail!(
                "invalid checkpoint epoch range: start {} is after end {}",
                start,
                end
            );
        }

        let checkpoints = read_checkpoints(&self.storage).await?;
        Ok(checkpoints
            .into_iter()
            .filter(|checkpoint| checkpoint.epoch >= start && checkpoint.epoch <= end)
            .collect())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PowCookieEnvelope {
    #[serde(with = "serde_bytes")]
    pub challenge: ByteBuf,
    pub nonce: u64,
    pub difficulty: u8,
}

impl PowCookieEnvelope {
    pub fn into_pow_cookie(self) -> PowCookie {
        PowCookie {
            challenge: self.challenge.into_vec(),
            nonce: self.nonce,
            difficulty: self.difficulty,
        }
    }

    pub fn from_cookie(cookie: &PowCookie) -> Self {
        Self {
            challenge: ByteBuf::from(cookie.challenge.clone()),
            nonce: cookie.nonce,
            difficulty: cookie.difficulty,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SubmitRequest {
    pub stream: String,
    pub client_id: String,
    pub payload: JsonValue,
    pub attachments: Option<Vec<AttachmentUpload>>,
    pub auth_ref: Option<String>,
    pub expires_at: Option<u64>,
    pub schema: Option<String>,
    pub idem: Option<u64>,
    #[serde(default)]
    pub pow_cookie: Option<PowCookieEnvelope>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Debug, Deserialize)]
struct SignedEnvelope<T> {
    #[serde(with = "serde_bytes")]
    schema: ByteBuf,
    body: T,
    #[serde(with = "serde_bytes")]
    #[allow(dead_code)]
    signature: ByteBuf,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StreamResponse {
    Messages(Vec<StoredMessage>),
    Proven(Vec<StreamMessageWithProof>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamReceipt {
    pub seq: u64,
    pub leaf_hash: String,
    pub mmr_root: String,
    pub hub_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMessageWithProof {
    pub message: StoredMessage,
    pub receipt: StreamReceipt,
    pub proof: StreamProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamProofNode {
    pub dir: Direction,
    pub sib: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamProof {
    pub ver: u64,
    pub leaf_hash: String,
    pub path: Vec<StreamProofNode>,
    pub peaks_after: Vec<String>,
}

impl From<MmrProof> for StreamProof {
    fn from(proof: MmrProof) -> Self {
        let path = proof
            .path
            .into_iter()
            .map(|node| StreamProofNode {
                dir: node.dir,
                sib: hex::encode(node.sib.as_bytes()),
            })
            .collect();
        let peaks_after = proof
            .peaks_after
            .into_iter()
            .map(|peak| hex::encode(peak.as_bytes()))
            .collect();
        Self {
            ver: proof.ver,
            leaf_hash: hex::encode(proof.leaf_hash.as_bytes()),
            path,
            peaks_after,
        }
    }
}

impl StreamProof {
    pub fn try_into_mmr(self) -> Result<MmrProof> {
        let leaf_bytes = hex::decode(&self.leaf_hash)
            .with_context(|| format!("decoding leaf hash {}", self.leaf_hash))?;
        let leaf = LeafHash::from_slice(&leaf_bytes)
            .with_context(|| format!("parsing leaf hash {}", self.leaf_hash))?;

        let path = self
            .path
            .into_iter()
            .map(|node| {
                let sib_bytes = hex::decode(&node.sib)
                    .with_context(|| format!("decoding path sibling {}", node.sib))?;
                let sib = MmrNode::from_slice(&sib_bytes)
                    .with_context(|| format!("parsing path sibling {}", node.sib))?;
                Ok(MmrPathNode { dir: node.dir, sib })
            })
            .collect::<Result<Vec<_>>>()?;

        let peaks_after = self
            .peaks_after
            .into_iter()
            .map(|peak| {
                let bytes =
                    hex::decode(&peak).with_context(|| format!("decoding peak hash {}", peak))?;
                MmrNode::from_slice(&bytes).with_context(|| format!("parsing peak hash {}", peak))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(MmrProof {
            ver: self.ver,
            leaf_hash: leaf,
            path,
            peaks_after,
        })
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessageBundle {
    #[serde(flatten)]
    message: StoredMessage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<StreamReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proof: Option<StreamProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAttachment {
    pub name: String,
    pub digest: String,
    pub size: u64,
    pub stored_path: String,
}

struct PreparedAttachment {
    digest: String,
    path: PathBuf,
    data: Vec<u8>,
}

struct PreparedAttachments {
    prepared: Vec<PreparedAttachment>,
    stored: Vec<StoredAttachment>,
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
    #[serde(default)]
    client_usage: HashMap<String, ClientAdmissionState>,
}

impl CapabilityStore {
    fn normalise_bucket_state(&mut self) {
        for record in self.records.values_mut() {
            if let Some(state) = record.bucket_state.as_mut() {
                state.normalise_units();
            }
        }
    }

    fn rebuild_stream_indexes(&mut self) {
        for record in self.records.values_mut() {
            record.rebuild_stream_index();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapabilityRecord {
    subject: String,
    stream_ids: Vec<String>,
    #[serde(skip)]
    stream_id_set: HashSet<String>,
    expires_at: u64,
    ttl: u64,
    rate: Option<CapTokenRate>,
    #[serde(default)]
    bucket_state: Option<TokenBucketState>,
    uses: u64,
    #[serde(default)]
    token_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientAdmissionState {
    first_seen: u64,
    #[serde(default)]
    per_stream_counts: HashMap<String, u64>,
}

impl ClientAdmissionState {
    fn new(first_seen: u64) -> Self {
        Self {
            first_seen,
            per_stream_counts: HashMap::new(),
        }
    }
}

struct ClientUsageUpdate {
    client_id: String,
    stream: String,
    first_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBucketState {
    tokens: u64,
    last_refill: u64,
}

impl TokenBucketState {
    fn new(burst: u64, now_ms: u64) -> Self {
        Self {
            tokens: burst,
            last_refill: now_ms,
        }
    }

    fn normalise_units(&mut self) {
        if self.last_refill < 1_000_000_000_000 {
            self.last_refill = self.last_refill.saturating_mul(1_000);
        }
    }
}

impl CapabilityRecord {
    fn rebuild_stream_index(&mut self) {
        self.stream_id_set = self.stream_ids.iter().cloned().collect();
    }

    fn allows_stream(&self, stream_hex: &str) -> bool {
        self.stream_id_set.contains(stream_hex)
    }
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
    #[error("E.AUTH invalid stream identifier {stream}: {source}")]
    StreamInvalid {
        stream: String,
        #[source]
        source: StreamIdParseError,
    },
    #[error("E.CAP capability {auth_ref} does not permit stream {stream}")]
    StreamDenied { auth_ref: String, stream: String },
    #[error("E.CAP capability {auth_ref} has expired")]
    Expired { auth_ref: String },
    #[error("E.AUTH client_id {client_id} has been revoked")]
    ClientIdRevoked { client_id: String },
    #[error("E.CAP auth_ref {auth_ref} has been revoked")]
    AuthRefRevoked { auth_ref: String },
    #[error("E.CAP capability token {token_hash} has been revoked")]
    CapTokenRevoked { token_hash: String },
    #[error("E.AUTH client_id {client_id} lifetime exceeded ({lifetime}s limit)")]
    ClientLifetimeExceeded { client_id: String, lifetime: u64 },
    #[error("E.AUTH client_id {client_id} exceeded quota for stream {stream} (limit {limit})")]
    ClientQuotaExceeded {
        client_id: String,
        stream: String,
        limit: u64,
    },
    #[error("E.AUTH client_id {client_id} message count overflow for stream {stream}")]
    ClientUsageOverflow { client_id: String, stream: String },
    #[error("E.RATE capability {auth_ref} is rate limited (retry after {retry_after}s)")]
    RateLimited { auth_ref: String, retry_after: u64 },
    #[error("E.AUTH proof-of-work cookie with difficulty >= {difficulty} required")]
    ProofOfWorkRequired { difficulty: u8 },
    #[error(
        "E.AUTH proof-of-work cookie difficulty insufficient (required {required}, provided {provided})"
    )]
    ProofOfWorkInsufficient { required: u8, provided: u8 },
    #[error("E.AUTH proof-of-work cookie failed verification (required {required})")]
    ProofOfWorkInvalid { required: u8 },
    #[error("E.AUTH hub not authorised for stream {stream} under {policy}{detail}")]
    NotAuthorisedForStream {
        stream: String,
        policy: &'static str,
        detail: String,
    },
    #[error("E.SIZE payload body size {body_bytes} bytes exceeds limit {limit} bytes")]
    MessageBodyTooLarge { body_bytes: usize, limit: usize },
    #[error("E.SIZE total message size {total_bytes} bytes exceeds limit {limit} bytes")]
    MessageTotalTooLarge { total_bytes: usize, limit: usize },
    #[error("E.SIZE attachment count {count} exceeds limit {limit}")]
    AttachmentCountExceeded { count: usize, limit: usize },
}

impl CapabilityError {
    pub fn retry_after(&self) -> Option<u64> {
        if let Self::RateLimited { retry_after, .. } = self {
            Some(*retry_after)
        } else {
            None
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::RateLimited { .. } => "E.RATE",
            Self::Unauthorized { .. }
            | Self::ClientIdRevoked { .. }
            | Self::ClientLifetimeExceeded { .. }
            | Self::ClientQuotaExceeded { .. }
            | Self::ClientUsageOverflow { .. }
            | Self::StreamInvalid { .. }
            | Self::NotAuthorisedForStream { .. } => "E.AUTH",
            Self::SubjectMismatch { .. }
            | Self::StreamMismatch { .. }
            | Self::StreamDenied { .. }
            | Self::Expired { .. }
            | Self::AuthRefRevoked { .. }
            | Self::CapTokenRevoked { .. } => "E.CAP",
            Self::ProofOfWorkRequired { .. }
            | Self::ProofOfWorkInsufficient { .. }
            | Self::ProofOfWorkInvalid { .. } => "E.AUTH",
            Self::MessageBodyTooLarge { .. }
            | Self::MessageTotalTooLarge { .. }
            | Self::AttachmentCountExceeded { .. } => "E.SIZE",
        }
    }
}

#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("E.DUP duplicate leaf hash {leaf_hash}")]
    Duplicate { leaf_hash: String },
}

impl SubmitError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Duplicate { .. } => "E.DUP",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub auth_ref: AuthRef,
    pub expires_at: u64,
}

#[derive(Debug, Serialize)]
pub struct ObservabilityReport {
    #[serde(with = "humantime_serde")]
    pub uptime: std::time::Duration,
    pub submit_ok_total: u64,
    pub submit_err_total: BTreeMap<String, u64>,
    pub last_stream_seq: HashMap<String, u64>,
    pub mmr_roots: HashMap<String, String>,
    pub peaks_count: u64,
    pub profile_id: Option<String>,
    pub hub_id: Option<String>,
    pub hub_public_key: Option<String>,
    pub role: String,
    pub data_dir: String,
}

#[derive(Debug, Serialize)]
pub struct AuthorityReadiness {
    pub ok: bool,
    pub active_records: usize,
    pub stale_records: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_record_ts: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HubReadinessReport {
    pub ok: bool,
    pub data_dir: String,
    pub state_dir_accessible: bool,
    pub indexes_initialised: bool,
    pub authority_view: AuthorityReadiness,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HubProfileDescriptor {
    pub ok: bool,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    pub hub_id: String,
    pub features: HubProfileFeatures,
}

#[derive(Debug, Serialize)]
pub struct HubProfileFeatures {
    pub core: bool,
    pub fed1: bool,
    pub auth1: bool,
    pub kex1_plus: bool,
    pub sh1_plus: bool,
    pub lclass0: bool,
    pub meta0_plus: bool,
}

#[derive(Debug, Serialize)]
pub struct HubRoleDescriptor {
    pub ok: bool,
    pub hub_id: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<HubRoleStreamDescriptor>,
}

#[derive(Debug, Serialize)]
pub struct HubRoleStreamDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    pub stream_id: String,
    pub label: String,
    pub policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_hub: Option<String>,
    pub local_is_primary: bool,
}

#[derive(Debug, Serialize)]
pub struct HubAuthorityRecordDescriptor {
    pub ok: bool,
    pub realm_id: String,
    pub stream_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_hub: Option<String>,
    pub replica_hubs: Vec<String>,
    pub policy: String,
    pub ts: u64,
    pub ttl: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub active_now: bool,
}

#[derive(Debug, Serialize)]
pub struct HubLabelClassDescriptor {
    pub ok: bool,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_hint: Option<u64>,
    pub pad_block_effective: u64,
    pub retention_policy: String,
    pub rate_policy: String,
}

#[derive(Debug, Serialize)]
pub struct HubLabelClassList {
    pub ok: bool,
    pub entries: Vec<HubLabelClassListEntry>,
}

#[derive(Debug, Serialize)]
pub struct HubLabelClassListEntry {
    pub label: String,
    pub class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_hint: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HubLabelAuthorityDescriptor {
    pub ok: bool,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<String>,
    pub stream_id: String,
    pub policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_hub: Option<String>,
    pub replica_hubs: Vec<String>,
    pub local_hub_id: String,
    pub local_is_authorized: bool,
}

#[derive(Debug, Serialize)]
pub struct HubKexPolicyDescriptor {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_id_lifetime_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_msgs_per_client_id_per_label: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_cap_ttl_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cap_ttl_sec: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation_window_sec: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct HubAdmissionReport {
    pub ok: bool,
    pub stages: Vec<HubAdmissionStage>,
}

#[derive(Debug, Serialize, Clone)]
pub struct HubAdmissionStage {
    pub name: String,
    pub enabled: bool,
    pub responsibilities: Vec<String>,
    pub queue_depth: u64,
    pub max_queue_depth: u64,
    pub recent_err_rates: BTreeMap<String, f64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AdmissionLogEvent {
    pub ts: u64,
    pub code: String,
    pub label_prefix: String,
    pub client_id_prefix: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct HubAdmissionLogResponse {
    pub ok: bool,
    pub events: Vec<AdmissionLogEvent>,
}

#[derive(Debug, Serialize)]
pub struct HubCapStatusResponse {
    pub ok: bool,
    pub auth_ref: String,
    pub hub_known: bool,
    pub currently_valid: bool,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HubRevocationList {
    pub ok: bool,
    pub revocations: Vec<HubRevocationEntry>,
}

#[derive(Debug, Serialize)]
pub struct HubRevocationEntry {
    pub kind: String,
    pub target: String,
    pub ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub active_now: bool,
}

#[derive(Debug, Serialize)]
pub struct HubPowChallengeDescriptor {
    pub ok: bool,
    pub challenge: String,
    pub difficulty: u8,
}

const HUB_KEY_VERSION: u8 = 1;

#[derive(Clone)]
struct HubIdentity {
    hub_id: HubId,
    hub_id_hex: String,
    public_key_hex: String,
}

#[derive(Deserialize, Serialize)]
struct HubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

async fn load_hub_identity(storage: &HubStorage) -> Result<HubIdentity> {
    let path = storage.hub_key_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking hub key at {}", path.display()))?
    {
        bail!(
            "hub data directory at {} is missing hub_key.cbor",
            storage.data_dir().display()
        );
    }

    let bytes = fs::read(&path)
        .await
        .with_context(|| format!("reading hub key material from {}", path.display()))?;
    let mut cursor = Cursor::new(bytes);
    let material: HubKeyMaterial =
        from_reader(&mut cursor).context("decoding hub key material from CBOR")?;

    if material.version != HUB_KEY_VERSION {
        bail!(
            "unsupported hub key version {}; expected {}",
            material.version,
            HUB_KEY_VERSION
        );
    }

    let public_key: [u8; 32] = material
        .public_key
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("hub public key must be 32 bytes"))?;
    let hub_id = HubId::derive(public_key)
        .map_err(|err| anyhow!("deriving hub identifier failed: {err}"))?;

    Ok(HubIdentity {
        hub_id,
        hub_id_hex: hex::encode(hub_id.as_ref()),
        public_key_hex: hex::encode(public_key),
    })
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
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".head.json"))
            {
                continue;
            }
            let loaded = if matches!(path.extension().and_then(|ext| ext.to_str()), Some("json")) {
                load_legacy_stream_state(&path).await?
            } else {
                load_stream_state_from_index(storage, &path).await?
            };
            let stream_name = loaded
                .state
                .messages
                .first()
                .map(|msg| msg.stream.clone())
                .or_else(|| {
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string())
                });
            if let Some(name) = stream_name {
                let runtime = StreamRuntime::new(loaded.state, loaded.proven)?;
                map.insert(name, runtime);
            }
        }
    }
    Ok(map)
}

fn collect_recent_dedup_entries(
    streams: &HashMap<String, StreamRuntime>,
    config: &DedupConfig,
) -> Result<Vec<DedupKey>> {
    let limit = config.bloom_capacity.max(config.lru_capacity);
    if limit == 0 {
        return Ok(Vec::new());
    }

    #[derive(Eq, PartialEq)]
    struct DedupCandidate {
        ts: u64,
        seq: u64,
        key: DedupKey,
    }

    impl Ord for DedupCandidate {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            (self.ts, self.seq).cmp(&(other.ts, other.seq))
        }
    }

    impl PartialOrd for DedupCandidate {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    let mut heap = std::collections::BinaryHeap::with_capacity(limit.saturating_add(1));

    for runtime in streams.values() {
        let len = runtime.state.messages.len();
        let start = len.saturating_sub(limit);
        for message in runtime.state.messages.iter().skip(start) {
            let leaf = leaf_hash_for(message)?;
            let candidate = DedupCandidate {
                ts: message.sent_at,
                seq: message.seq,
                key: DedupKey::new(message.stream.clone(), leaf),
            };
            heap.push(std::cmp::Reverse(candidate));
            if heap.len() > limit {
                heap.pop();
            }
        }
    }

    let mut entries: Vec<DedupCandidate> =
        heap.into_iter().map(|entry| entry.0).collect();
    entries.sort_by_key(|entry| (entry.ts, entry.seq));
    Ok(entries.into_iter().map(|entry| entry.key).collect())
}

async fn load_recent_dedup_cache(
    storage: &HubStorage,
    config: &DedupConfig,
) -> Result<Option<Vec<DedupKey>>> {
    let path = storage.recent_leaf_hashes_path();
    let data = match fs::read(&path).await {
        Ok(data) => data,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("reading recent dedup cache from {}", path.display()))
        }
    };
    let encoded: Vec<DedupCacheEntry> = match serde_json::from_slice(&data) {
        Ok(entries) => entries,
        Err(_) => return Ok(None),
    };
    let limit = config.bloom_capacity.max(config.lru_capacity);
    let mut keys = Vec::with_capacity(encoded.len());
    for entry in encoded {
        let leaf_hash = LeafHash::from_str(&entry.leaf_hash)
            .with_context(|| format!("parsing cached leaf hash {}", entry.leaf_hash))?;
        keys.push(DedupKey::new(entry.stream, leaf_hash));
    }
    if keys.len() > limit {
        keys.drain(0..keys.len().saturating_sub(limit));
    }
    Ok(Some(keys))
}

async fn persist_recent_dedup_cache(storage: &HubStorage, entries: &[DedupKey]) -> Result<()> {
    let path = storage.recent_leaf_hashes_path();
    let encoded: Vec<DedupCacheEntry> = entries.iter().map(DedupCacheEntry::from).collect();
    let data = serde_json::to_vec(&encoded)
        .with_context(|| format!("encoding recent dedup cache for {}", path.display()))?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing recent dedup cache to {}", path.display()))
}

fn leaf_hash_exists(runtime: &StreamRuntime, leaf_hash: &LeafHash) -> Result<bool> {
    Ok(runtime.has_leaf_hash(leaf_hash))
}

async fn rebuild_attachment_ref_counts(
    storage: &HubStorage,
    streams: &HashMap<String, StreamRuntime>,
) -> Result<HashMap<String, u64>> {
    let mut counts = HashMap::new();
    for runtime in streams.values() {
        for message in &runtime.state.messages {
            for attachment in &message.attachments {
                *counts.entry(attachment.digest.clone()).or_insert(0) += 1;
            }
        }
    }

    attachments::rewrite_all_refcounts(storage, &counts).await?;
    Ok(counts)
}

async fn load_attachment_ref_counts(
    storage: &HubStorage,
    streams: &HashMap<String, StreamRuntime>,
) -> Result<HashMap<String, u64>> {
    if let Some(counts) = attachments::load_refcounts(storage).await? {
        return Ok(counts);
    }

    rebuild_attachment_ref_counts(storage, streams).await
}

#[derive(Default)]
struct LoadedStreamState {
    state: HubStreamState,
    proven: Vec<StreamMessageWithProof>,
}

async fn load_legacy_stream_state(path: &Path) -> Result<LoadedStreamState> {
    let data = fs::read(path)
        .await
        .with_context(|| format!("reading stream state from {}", path.display()))?;
    let state: HubStreamState = serde_json::from_slice(&data)
        .with_context(|| format!("decoding stream state from {}", path.display()))?;
    let proven = build_proven_messages(&state.messages)?;
    Ok(LoadedStreamState { state, proven })
}

async fn load_stream_state_from_index(
    storage: &HubStorage,
    path: &Path,
) -> Result<LoadedStreamState> {
    let Some(mut reader) = stream_index::StreamIndexReader::open(path).await? else {
        return Ok(LoadedStreamState::default());
    };
    let mut next_entry = reader.next_entry().await?;
    if next_entry.is_none() {
        return Ok(LoadedStreamState::default());
    }

    let mut messages = Vec::new();
    let mut proven = Vec::new();
    let mut mmr = Mmr::new();
    let mut migrations = Vec::new();

    while let Some(entry) = next_entry {
        let bundle_path = stream_index::bundle_path(storage, &entry);
        let bundle = read_message_bundle(&bundle_path).await?;
        let StoredMessageBundle {
            message,
            receipt,
            proof,
        } = bundle;
        let leaf = leaf_hash_for(&message)?;
        let leaf_hex = hex::encode(leaf.as_bytes());
        if let (Some(receipt), Some(proof)) = (receipt, proof) {
            let (seq, root) = mmr.append(leaf);
            ensure!(
                seq == message.seq,
                "stored message seq {} diverges from mmr seq {} for {}",
                message.seq,
                seq,
                bundle_path.display()
            );
            ensure!(
                receipt.seq == message.seq,
                "receipt seq {} diverges from message seq {} for {}",
                receipt.seq,
                message.seq,
                bundle_path.display()
            );
            ensure!(
                receipt.leaf_hash == leaf_hex,
                "receipt leaf hash mismatch for {}",
                bundle_path.display()
            );
            let computed_root = hex::encode(root.as_bytes());
            ensure!(
                receipt.mmr_root == computed_root,
                "receipt mmr root {} mismatches computed {} for {}",
                receipt.mmr_root,
                computed_root,
                bundle_path.display()
            );
            proven.push(StreamMessageWithProof {
                message: message.clone(),
                receipt,
                proof,
            });
        } else {
            let (seq, root, proof) = mmr.append_with_proof(leaf);
            ensure!(
                seq == message.seq,
                "legacy message seq {} diverges from mmr seq {} for {}",
                message.seq,
                seq,
                bundle_path.display()
            );
            let receipt = StreamReceipt {
                seq,
                leaf_hash: leaf_hex,
                mmr_root: hex::encode(root.as_bytes()),
                hub_ts: message.sent_at,
            };
            let entry_with_proof = StreamMessageWithProof {
                message: message.clone(),
                receipt: receipt.clone(),
                proof: StreamProof::from(proof),
            };
            proven.push(entry_with_proof.clone());
            migrations.push(entry_with_proof);
        }
        messages.push(message);
        next_entry = reader.next_entry().await?;
    }

    for entry in &migrations {
        persist_message_bundle(storage, &entry.message.stream, entry.message.seq, entry).await?;
    }

    Ok(LoadedStreamState {
        state: HubStreamState { messages },
        proven,
    })
}

async fn read_message_bundle(path: &Path) -> Result<StoredMessageBundle> {
    let data = fs::read(path)
        .await
        .with_context(|| format!("reading message bundle from {}", path.display()))?;
    match serde_json::from_slice(&data) {
        Ok(bundle) => Ok(bundle),
        Err(parse_err) => {
            let legacy: StoredMessage = serde_json::from_slice(&data).with_context(|| {
                format!(
                    "decoding legacy message bundle from {} after error: {parse_err}",
                    path.display()
                )
            })?;
            Ok(StoredMessageBundle {
                message: legacy,
                receipt: None,
                proof: None,
            })
        }
    }
}

async fn read_proven_bundle(
    stream: &str,
    seq: u64,
    bundle_path: &Path,
) -> Result<StreamMessageWithProof> {
    let bundle = read_message_bundle(bundle_path).await?;
    let StoredMessageBundle {
        message,
        receipt,
        proof,
    } = bundle;
    let (receipt, proof) = match (receipt, proof) {
        (Some(receipt), Some(proof)) => (receipt, proof),
        _ => {
            bail!(
                "missing receipt or proof in bundle for {}#{} at {}",
                stream,
                seq,
                bundle_path.display()
            );
        }
    };
    Ok(StreamMessageWithProof {
        message,
        receipt,
        proof,
    })
}

fn build_proven_messages(messages: &[StoredMessage]) -> Result<Vec<StreamMessageWithProof>> {
    let mut mmr = Mmr::new();
    let mut proven = Vec::with_capacity(messages.len());
    for message in messages {
        let leaf = leaf_hash_for(message)?;
        let (seq, root, proof) = mmr.append_with_proof(leaf);
        ensure!(
            seq == message.seq,
            "stream message seq {} diverges from mmr seq {}",
            message.seq,
            seq
        );
        let receipt = StreamReceipt {
            seq,
            leaf_hash: hex::encode(leaf.as_bytes()),
            mmr_root: hex::encode(root.as_bytes()),
            hub_ts: message.sent_at,
        };
        proven.push(StreamMessageWithProof {
            message: message.clone(),
            receipt,
            proof: StreamProof::from(proof),
        });
    }
    Ok(proven)
}

async fn load_proven_messages_range(
    storage: &HubStorage,
    stream: &str,
    from: u64,
    to: u64,
) -> Result<Vec<StreamMessageWithProof>> {
    if from > to {
        return Ok(Vec::new());
    }
    if let Some(head) = stream_index::load_stream_index_head(storage, stream).await? {
        if from > head.last_seq {
            return Ok(Vec::new());
        }
        let upper = to.min(head.last_seq);
        let start = from.max(1);
        if start > upper {
            return Ok(Vec::new());
        }
        let expected = (upper - start + 1) as usize;
        let mut results = vec![None; expected];
        let mut join_set = tokio::task::JoinSet::new();
        const MAX_BUNDLE_READ_CONCURRENCY: usize = 32;
        let concurrency = MAX_BUNDLE_READ_CONCURRENCY.min(expected);
        let stream_name: Arc<str> = Arc::from(stream);

        for seq in start..=upper {
            let bundle_path = storage.message_bundle_path(stream, seq);
            let stream_name = Arc::clone(&stream_name);
            join_set.spawn(async move {
                let entry = read_proven_bundle(stream_name.as_ref(), seq, &bundle_path).await?;
                Ok::<_, anyhow::Error>((seq, entry))
            });
            if join_set.len() >= concurrency {
                if let Some(result) = join_set.join_next().await {
                    let (seq, entry) = result??;
                    let index = (seq - start) as usize;
                    results[index] = Some(entry);
                }
            }
        }

        while let Some(result) = join_set.join_next().await {
            let (seq, entry) = result??;
            let index = (seq - start) as usize;
            results[index] = Some(entry);
        }

        let mut proven = Vec::with_capacity(expected);
        for (offset, entry) in results.into_iter().enumerate() {
            let entry = entry.ok_or_else(|| {
                anyhow!(
                    "missing bundle result for {}#{}",
                    stream_name.as_ref(),
                    start + offset as u64
                )
            })?;
            proven.push(entry);
        }
        return Ok(proven);
    }

    let index_path = storage.stream_index_path(stream);
    let entries = stream_index::load_stream_index_range(&index_path, from, to).await?;
    let mut proven = Vec::with_capacity(entries.len());
    for entry in entries {
        let bundle_path = stream_index::bundle_path(storage, &entry);
        let entry = read_proven_bundle(stream, entry.seq, &bundle_path).await?;
        proven.push(entry);
    }
    Ok(proven)
}

async fn persist_stream_state(
    storage: &HubStorage,
    stream: &str,
    entry: &StreamIndexEntry,
) -> Result<()> {
    stream_index::append_stream_index(storage, stream, entry).await
}

async fn persist_message_bundle(
    storage: &HubStorage,
    stream: &str,
    seq: u64,
    entry: &StreamMessageWithProof,
) -> Result<()> {
    let path = storage.message_bundle_path(stream, seq);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring message directory {}", parent.display()))?;
    }
    let bundle = StoredMessageBundle {
        message: entry.message.clone(),
        receipt: Some(entry.receipt.clone()),
        proof: Some(entry.proof.clone()),
    };
    let data = serde_json::to_vec(&bundle)
        .with_context(|| format!("encoding message bundle for {stream}#{seq}"))?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing message bundle to {}", path.display()))
}

async fn append_receipt(storage: &HubStorage, entry: &StreamMessageWithProof) -> Result<()> {
    let receipt = ReceiptRecord {
        stream: entry.message.stream.clone(),
        seq: entry.message.seq,
        leaf_hash: entry.receipt.leaf_hash.clone(),
        mmr_root: entry.receipt.mmr_root.clone(),
        hub_ts: entry.receipt.hub_ts,
        proof: Some(entry.proof.clone()),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<StreamProof>,
}

async fn read_checkpoints(storage: &HubStorage) -> Result<Vec<Checkpoint>> {
    let path = storage.checkpoints_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking checkpoint log {}", path.display()))?
    {
        return Ok(Vec::new());
    }

    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading checkpoint log from {}", path.display()))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut cursor = Cursor::new(&data);
    let mut checkpoints = Vec::new();
    while (cursor.position() as usize) < data.len() {
        let offset = cursor.position();
        let checkpoint: Checkpoint = ciborium::de::from_reader(&mut cursor)
            .with_context(|| format!("decoding checkpoint at offset {}", offset))?;
        checkpoints.push(checkpoint);
    }

    Ok(checkpoints)
}

fn prepare_attachments_for_storage(
    storage: &HubStorage,
    stream: &str,
    attachments: &[AttachmentUpload],
    initial_bytes: usize,
) -> Result<PreparedAttachments> {
    if attachments.is_empty() {
        return Ok(PreparedAttachments {
            prepared: Vec::new(),
            stored: Vec::new(),
        });
    }

    let mut total_bytes = initial_bytes;
    let mut prepared = Vec::with_capacity(attachments.len());
    let mut stored = Vec::with_capacity(attachments.len());
    for (index, attachment) in attachments.iter().enumerate() {
        let data = BASE64_STANDARD
            .decode(&attachment.data)
            .with_context(|| format!("decoding attachment {} for stream {}", index, stream))?;
        let new_total = total_bytes.checked_add(data.len()).ok_or({
            CapabilityError::MessageTotalTooLarge {
                total_bytes: usize::MAX,
                limit: MAX_MSG_BYTES,
            }
        })?;
        if new_total > MAX_MSG_BYTES {
            return Err(CapabilityError::MessageTotalTooLarge {
                total_bytes: new_total,
                limit: MAX_MSG_BYTES,
            }
            .into());
        }
        total_bytes = new_total;
        let digest = sha2::Sha256::digest(&data);
        let digest_hex = hex::encode(digest);
        let file_name = format!("{digest_hex}.bin");
        let path = storage.attachments_dir().join(&file_name);
        let stored_attachment = StoredAttachment {
            name: attachment
                .name
                .clone()
                .unwrap_or_else(|| format!("attachment-{index}")),
            digest: digest_hex,
            size: data.len() as u64,
            stored_path: file_name,
        };
        prepared.push(PreparedAttachment {
            digest: stored_attachment.digest.clone(),
            path,
            data,
        });
        stored.push(stored_attachment);
    }

    Ok(PreparedAttachments { prepared, stored })
}

async fn persist_attachments(
    storage: &HubStorage,
    attachments: &[PreparedAttachment],
    ref_counts: &Arc<Mutex<HashMap<String, u64>>>,
) -> Result<()> {
    if attachments.is_empty() {
        return Ok(());
    }

    fs::create_dir_all(storage.attachments_dir())
        .await
        .with_context(|| {
            format!(
                "ensuring attachments directory {}",
                storage.attachments_dir().display()
            )
        })?;

    for attachment in attachments {
        let mut needs_write = true;
        match fs::metadata(&attachment.path).await {
            Ok(metadata) => {
                if metadata.len() == attachment.data.len() as u64 {
                    needs_write = false;
                } else {
                    bail!(
                        "existing attachment {} size mismatch: expected {} bytes, found {} bytes",
                        attachment.path.display(),
                        attachment.data.len(),
                        metadata.len()
                    );
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("checking attachment {}", attachment.path.display()));
            }
        }

        if needs_write {
            fs::write(&attachment.path, &attachment.data)
                .await
                .with_context(|| format!("writing attachment to {}", attachment.path.display()))?;
        }

        let mut counts = ref_counts.lock().await;
        let counter = counts.entry(attachment.digest.clone()).or_insert(0);
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("attachment refcount overflow for {}", attachment.digest))?;
        if let Err(err) = attachments::write_refcount(storage, &attachment.digest, *counter).await {
            *counter = counter.saturating_sub(1);
            return Err(err);
        }
    }

    Ok(())
}

fn check_client_usage(
    store: &mut CapabilityStore,
    admission: &AdmissionConfig,
    client_id: &str,
    stream: &str,
    now: u64,
) -> Result<(Option<ClientUsageUpdate>, bool), CapabilityError> {
    if admission.max_client_id_lifetime_sec.is_none()
        && admission.max_msgs_per_client_id_per_label.is_none()
    {
        return Ok((None, false));
    }

    let mut store_dirty = false;
    let entry = match store.client_usage.entry(client_id.to_string()) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(vacant) => {
            store_dirty = true;
            vacant.insert(ClientAdmissionState::new(now))
        }
    };

    if let Some(limit) = admission.max_client_id_lifetime_sec {
        if now.saturating_sub(entry.first_seen) >= limit {
            return Err(CapabilityError::ClientLifetimeExceeded {
                client_id: client_id.to_string(),
                lifetime: limit,
            });
        }
    }

    let current = entry.per_stream_counts.get(stream).copied().unwrap_or(0);

    if let Some(limit) = admission.max_msgs_per_client_id_per_label {
        if current >= limit {
            return Err(CapabilityError::ClientQuotaExceeded {
                client_id: client_id.to_string(),
                stream: stream.to_string(),
                limit,
            });
        }
    }

    Ok((
        Some(ClientUsageUpdate {
            client_id: client_id.to_string(),
            stream: stream.to_string(),
            first_seen: entry.first_seen,
        }),
        store_dirty,
    ))
}

fn apply_client_usage_update(
    store: &mut CapabilityStore,
    update: Option<ClientUsageUpdate>,
) -> Result<bool, CapabilityError> {
    let mut store_dirty = false;
    if let Some(ClientUsageUpdate {
        client_id,
        stream,
        first_seen,
    }) = update
    {
        store_dirty = true;
        let entry = store
            .client_usage
            .entry(client_id.clone())
            .or_insert_with(|| ClientAdmissionState::new(first_seen));
        let counter = entry.per_stream_counts.entry(stream.clone()).or_insert(0);
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| CapabilityError::ClientUsageOverflow {
                client_id: client_id.clone(),
                stream: stream.clone(),
            })?;
    }
    Ok(store_dirty)
}

fn enforce_capability(
    store: &mut CapabilityStore,
    auth_ref: &str,
    subject: &str,
    stream: &str,
    now: u64,
    now_ms: u64,
) -> Result<bool, CapabilityError> {
    if !store.records.contains_key(auth_ref) {
        return Err(CapabilityError::Unauthorized {
            auth_ref: auth_ref.to_string(),
        });
    }

    let mut store_dirty = false;
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
        store_dirty = true;
        record.bucket_state = record
            .rate
            .as_ref()
            .map(|rate| TokenBucketState::new(rate.burst, now_ms));
    }

    let stream_id =
        cap_stream_id_from_label(stream).map_err(|err| CapabilityError::StreamMismatch {
            auth_ref: auth_ref.to_string(),
            source: err,
        })?;
    let stream_hex = hex::encode(stream_id.as_ref());
    if !record.allows_stream(&stream_hex) {
        return Err(CapabilityError::StreamDenied {
            auth_ref: auth_ref.to_string(),
            stream: stream.to_string(),
        });
    }

    if let (Some(rate), Some(state)) = (&record.rate, record.bucket_state.as_mut()) {
        let previous_tokens = state.tokens;
        let previous_last_refill = state.last_refill;
        refill_bucket(state, rate, now_ms);
        if state.tokens != previous_tokens || state.last_refill != previous_last_refill {
            store_dirty = true;
        }
        if state.tokens == 0 {
            let retry_after = retry_after_seconds(rate, state, now_ms);
            return Err(CapabilityError::RateLimited {
                auth_ref: auth_ref.to_string(),
                retry_after,
            });
        }
        let tokens_before = state.tokens;
        state.tokens = state.tokens.saturating_sub(1);
        if state.tokens != tokens_before {
            store_dirty = true;
        }
    }

    let previous_uses = record.uses;
    let new_uses = record.uses.saturating_add(1);
    if new_uses != previous_uses {
        record.uses = new_uses;
        store_dirty = true;
    }
    Ok(store_dirty)
}

fn refill_bucket(state: &mut TokenBucketState, rate: &CapTokenRate, now_ms: u64) {
    if now_ms <= state.last_refill {
        return;
    }
    let elapsed = now_ms.saturating_sub(state.last_refill);
    if elapsed == 0 {
        return;
    }
    if rate.per_sec == 0 {
        return;
    }

    let gained = ((elapsed as u128) * (rate.per_sec as u128)) / 1_000;
    if gained == 0 {
        return;
    }

    let available_capacity = (rate.burst as u128).saturating_sub(state.tokens as u128);
    if available_capacity == 0 {
        state.last_refill = now_ms;
        return;
    }

    let added = gained.min(available_capacity);
    state.tokens = state.tokens.saturating_add(added as u64);

    let consumed = ((added * 1_000) / (rate.per_sec as u128)) as u64;
    state.last_refill = state.last_refill.saturating_add(consumed).min(now_ms);
}

fn retry_after_seconds(rate: &CapTokenRate, state: &TokenBucketState, now_ms: u64) -> u64 {
    if rate.per_sec == 0 {
        return 1;
    }

    let interval = div_ceil(1_000, rate.per_sec);
    let target = state.last_refill.saturating_add(interval);
    if target <= now_ms {
        return 1;
    }

    let wait_ms = target - now_ms;
    let wait_secs = wait_ms / 1_000;
    if wait_secs == 0 {
        1
    } else {
        wait_secs
    }
}

fn div_ceil(lhs: u64, rhs: u64) -> u64 {
    if rhs == 0 {
        return lhs;
    }
    let quotient = lhs / rhs;
    let remainder = lhs % rhs;
    if remainder == 0 {
        quotient
    } else {
        quotient.saturating_add(1)
    }
}

async fn update_capability_store(storage: &HubStorage, store: &CapabilityStore) -> Result<()> {
    let path = storage.capabilities_store_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring capability directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec(store).context("encoding capability store")?;
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
    let mut store: CapabilityStore = serde_json::from_slice(&data)
        .with_context(|| format!("parsing capability store from {}", path.display()))?;
    store.normalise_bucket_state();
    store.rebuild_stream_indexes();
    Ok(store)
}

async fn load_revocation_log(storage: &HubStorage) -> Result<Vec<RevocationRecord>> {
    let path = storage.revocations_store_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking revocation log {}", path.display()))?
    {
        return Ok(Vec::new());
    }
    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading revocation log from {}", path.display()))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let records = serde_json::from_slice(&data)
        .with_context(|| format!("parsing revocation log from {}", path.display()))?;
    Ok(records)
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

fn build_label_class_index(records: &[LabelClassRecord]) -> HashMap<Label, LabelClassRecord> {
    let mut index = HashMap::new();
    for record in records {
        index.insert(record.label, record.clone());
    }
    index
}

fn update_revocation_index(
    index: &mut HashMap<(RevocationKind, RevocationTarget), RevocationRecord>,
    record: &RevocationRecord,
) {
    match index.entry((record.kind, record.target)) {
        Entry::Vacant(entry) => {
            entry.insert(record.clone());
        }
        Entry::Occupied(mut entry) => {
            if record.ts >= entry.get().ts {
                entry.insert(record.clone());
            }
        }
    }
}

fn build_revocation_index(
    records: &[RevocationRecord],
) -> HashMap<(RevocationKind, RevocationTarget), RevocationRecord> {
    let mut index = HashMap::new();
    for record in records {
        update_revocation_index(&mut index, record);
    }
    index
}

fn build_revocation_order(records: &[RevocationRecord]) -> BTreeMap<u64, Vec<usize>> {
    let mut order = BTreeMap::new();
    for (index, record) in records.iter().enumerate() {
        update_revocation_order(&mut order, record.ts, index);
    }
    order
}

fn update_revocation_order(order: &mut BTreeMap<u64, Vec<usize>>, ts: u64, index: usize) {
    order.entry(ts).or_default().push(index);
}

fn build_schema_registry(records: &[SchemaDescriptor]) -> SchemaRegistry {
    let mut registry = SchemaRegistry::new();
    for (idx, descriptor) in records.iter().cloned().enumerate() {
        let stream_seq = (idx + 1) as u64;
        registry.upsert(descriptor, stream_seq);
    }
    registry
}

async fn persist_authority_records(
    storage: &HubStorage,
    records: &[AuthorityRecord],
) -> Result<()> {
    let path = storage.authority_store_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring authority directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(records).context("encoding authority records")?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing authority records to {}", path.display()))
}

async fn load_authority_records(storage: &HubStorage) -> Result<Vec<AuthorityRecord>> {
    let path = storage.authority_store_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking authority records {}", path.display()))?
    {
        return Ok(Vec::new());
    }
    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading authority records from {}", path.display()))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let records = serde_json::from_slice(&data)
        .with_context(|| format!("parsing authority records from {}", path.display()))?;
    Ok(records)
}

async fn persist_label_classes(storage: &HubStorage, records: &[LabelClassRecord]) -> Result<()> {
    let path = storage.label_class_store_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring label class directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(records).context("encoding label class records")?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing label class records to {}", path.display()))
}

async fn load_label_classes(storage: &HubStorage) -> Result<Vec<LabelClassRecord>> {
    let path = storage.label_class_store_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking label class records {}", path.display()))?
    {
        return Ok(Vec::new());
    }
    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading label class records from {}", path.display()))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let records = serde_json::from_slice(&data)
        .with_context(|| format!("parsing label class records from {}", path.display()))?;
    Ok(records)
}

fn pad_block_for_class(class: Option<&str>) -> u64 {
    match class {
        Some("wallet") => 1024,
        Some("log") | Some("metric") | Some("bulk") => 0,
        _ => 256,
    }
}

fn retention_policy_for_class(class: Option<&str>) -> &'static str {
    match class {
        Some("wallet") => "long-term",
        Some("log") | Some("metric") | Some("bulk") => "short-term",
        _ => "standard",
    }
}

fn rate_policy_for_class(class: Option<&str>) -> &'static str {
    match class {
        Some("admin") | Some("control") => "elevated",
        Some("bulk") => "throttled",
        _ => "rl0-default",
    }
}

async fn persist_schema_descriptors(
    storage: &HubStorage,
    records: &[SchemaDescriptor],
) -> Result<()> {
    let path = storage.schema_registry_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring schema registry directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(records).context("encoding schema descriptors")?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing schema descriptors to {}", path.display()))
}

async fn load_schema_descriptors(storage: &HubStorage) -> Result<Vec<SchemaDescriptor>> {
    let path = storage.schema_registry_path();
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking schema registry {}", path.display()))?
    {
        return Ok(Vec::new());
    }
    let data = fs::read(&path)
        .await
        .with_context(|| format!("reading schema descriptors from {}", path.display()))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let records = serde_json::from_slice(&data)
        .with_context(|| format!("parsing schema descriptors from {}", path.display()))?;
    Ok(records)
}

async fn persist_revocations(storage: &HubStorage, records: &[RevocationRecord]) -> Result<()> {
    let path = storage.revocations_store_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring revocation directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(records).context("encoding revocation log")?;
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing revocation log to {}", path.display()))
}

fn leaf_hash_for(message: &StoredMessage) -> Result<LeafHash> {
    let encoded = serde_json::to_vec(message).context("encoding message for leaf hash")?;
    let digest = sha2::Sha256::digest(&encoded);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(LeafHash::new(bytes))
}

fn current_unix_timestamp() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?;
    Ok(now.as_secs())
}

fn current_unix_timestamp_millis() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?;
    Ok(now.as_millis() as u64)
}

fn revocation_target_from_hex_str(value: &str) -> Result<RevocationTarget> {
    let bytes =
        hex::decode(value).with_context(|| format!("decoding revocation target {value}"))?;
    RevocationTarget::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "invalid revocation target length: expected {} bytes, found {}",
            err.expected(),
            err.actual()
        )
    })
}

fn revocation_kind_label(kind: RevocationKind) -> &'static str {
    match kind {
        RevocationKind::ClientId => "client-id",
        RevocationKind::AuthRef => "auth-ref",
        RevocationKind::CapToken => "cap-token",
    }
}

fn identifier_prefix(value: &str) -> String {
    const PREFIX_LEN: usize = 16;
    if value.len() <= PREFIX_LEN {
        return value.to_string();
    }
    format!("{}…", &value[..PREFIX_LEN])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::HubConfigOverrides;
    use anyhow::Context;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::net::SocketAddr;
    use std::path::Path;
    use tempfile::tempdir;
    use tokio::fs;
    use tokio::runtime::Runtime;
    use veen_core::cap_stream_id_from_label;
    use veen_core::federation::AuthorityPolicy;
    use veen_core::label::Label;
    use veen_core::meta::SchemaId;
    use veen_core::realm::RealmId;
    use veen_core::revocation::{RevocationKind, RevocationRecord, RevocationTarget};
    use veen_core::HubId;
    use veen_core::REVOCATION_TARGET_LEN;

    async fn write_test_hub_key(data_dir: &Path) -> Result<()> {
        let path = data_dir.join(crate::storage::HUB_KEY_FILE);
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
            created_at: current_unix_timestamp()?,
            public_key: ByteBuf::from(verifying.as_bytes().to_vec()),
            secret_key: ByteBuf::from(signing.to_bytes().to_vec()),
        };

        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&material, &mut encoded)
            .context("serialising test hub key material")?;
        fs::write(&path, encoded)
            .await
            .with_context(|| format!("writing hub key material to {}", path.display()))?;
        Ok(())
    }

    async fn init_pipeline_with_overrides(
        data_dir: &Path,
        overrides: HubConfigOverrides,
    ) -> HubPipeline {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = HubRuntimeConfig::from_sources(
            listen,
            data_dir.to_path_buf(),
            None,
            HubRole::Primary,
            overrides,
        )
        .await
        .unwrap();
        let storage = HubStorage::bootstrap(&config).await.unwrap();
        write_test_hub_key(storage.data_dir()).await.unwrap();
        HubPipeline::initialise(&config, &storage).await.unwrap()
    }

    async fn init_pipeline(data_dir: &Path) -> HubPipeline {
        init_pipeline_with_overrides(data_dir, HubConfigOverrides::default()).await
    }

    async fn allow_stream_for_hub(
        pipeline: &HubPipeline,
        label: &str,
        realm_name: &str,
    ) -> Result<()> {
        let stream_id = cap_stream_id_from_label(label).expect("stream id");
        let realm = RealmId::derive(realm_name);
        let record = AuthorityRecord {
            realm_id: realm,
            stream_id,
            primary_hub: pipeline.identity.hub_id,
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::SinglePrimary,
            ts: current_unix_timestamp()?,
            ttl: 600,
        };
        let payload = encode_envelope(schema_fed_authority(), record);
        pipeline.publish_authority(&payload).await.unwrap();
        Ok(())
    }

    fn encode_envelope<T: Serialize>(schema: [u8; 32], body: T) -> Vec<u8> {
        #[derive(Serialize)]
        struct WritableEnvelope<T> {
            #[serde(with = "serde_bytes")]
            schema: Vec<u8>,
            body: T,
            #[serde(with = "serde_bytes")]
            signature: Vec<u8>,
        }

        let envelope = WritableEnvelope {
            schema: schema.to_vec(),
            body,
            signature: vec![0u8; 64],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&envelope, &mut buf).unwrap();
        buf
    }

    #[test]
    fn kex_policy_descriptor_reflects_admission_overrides() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                max_client_id_lifetime_sec: Some(86_400),
                max_msgs_per_client_id_per_label: Some(5),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;

            {
                let mut guard = pipeline.inner.write().await;
                let expires_at = current_unix_timestamp()? + 600;
                guard.capabilities.records.insert(
                    "deadbeef".to_string(),
                    CapabilityRecord {
                        subject: "client".into(),
                        stream_ids: vec!["core/test".into()],
                        stream_id_set: ["core/test".to_string()].into_iter().collect(),
                        expires_at,
                        ttl: 600,
                        rate: None,
                        bucket_state: None,
                        uses: 0,
                        token_hash: Some("cafebabe".into()),
                    },
                );
            }

            let descriptor = pipeline.kex_policy_descriptor().await;
            assert_eq!(descriptor.max_client_id_lifetime_sec, Some(86_400));
            assert_eq!(descriptor.max_msgs_per_client_id_per_label, Some(5));
            assert_eq!(descriptor.default_cap_ttl_sec, Some(600));
            assert_eq!(descriptor.max_cap_ttl_sec, Some(600));
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn retry_after_seconds_has_floor_of_one_second() {
        let rate = CapTokenRate {
            burst: 1,
            per_sec: 1_000,
        };
        let state = TokenBucketState {
            tokens: 0,
            last_refill: 10_000,
        };
        let now_ms = 10_000;

        assert_eq!(retry_after_seconds(&rate, &state, now_ms), 1);
    }

    #[test]
    fn capability_store_rebuilds_stream_index() {
        let mut store = CapabilityStore {
            records: HashMap::from([(
                "deadbeef".to_string(),
                CapabilityRecord {
                    subject: "client".into(),
                    stream_ids: vec!["deadbeef".into()],
                    stream_id_set: HashSet::new(),
                    expires_at: 1,
                    ttl: 1,
                    rate: None,
                    bucket_state: None,
                    uses: 0,
                    token_hash: None,
                },
            )]),
            client_usage: HashMap::new(),
        };

        store.rebuild_stream_indexes();
        let record = store.records.get("deadbeef").expect("record exists");
        assert!(record.allows_stream("deadbeef"));
    }

    #[test]
    fn admission_log_filters_results() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;

            pipeline
                .record_admission_failure("core/test", "aa", "E.AUTH", "missing auth")
                .await?;
            pipeline
                .record_admission_failure("core/test", "bb", "E.CAP", "expired")
                .await?;

            let filtered = pipeline
                .admission_log(Some(1), Some(vec!["E.CAP".to_string()]))
                .await;
            assert_eq!(filtered.events.len(), 1);
            assert_eq!(filtered.events[0].code, "E.CAP");
            assert!(filtered.events[0].detail.contains("expired"));
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn revocation_list_respects_filters() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;
            let target = RevocationTarget::new([0x11; REVOCATION_TARGET_LEN]);
            let record = RevocationRecord {
                kind: RevocationKind::AuthRef,
                target,
                reason: Some("compromised".into()),
                ts: current_unix_timestamp()?,
                ttl: Some(60),
            };
            let payload = encode_envelope(schema_revocation(), record.clone());
            pipeline.publish_revocation(&payload).await.unwrap();

            let response = pipeline
                .revocation_list(Some(RevocationKind::AuthRef), None, true, None)
                .await?;
            assert_eq!(response.revocations.len(), 1);
            assert_eq!(response.revocations[0].kind, "auth-ref");
            assert_eq!(
                response.revocations[0].reason.as_deref(),
                Some("compromised")
            );
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn revocation_list_returns_latest_first_with_limit() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;
            let now = current_unix_timestamp()?;
            let targets = [
                RevocationTarget::new([0x01; REVOCATION_TARGET_LEN]),
                RevocationTarget::new([0x02; REVOCATION_TARGET_LEN]),
                RevocationTarget::new([0x03; REVOCATION_TARGET_LEN]),
            ];
            let records = [
                RevocationRecord {
                    kind: RevocationKind::AuthRef,
                    target: targets[0],
                    reason: None,
                    ts: now.saturating_sub(30),
                    ttl: None,
                },
                RevocationRecord {
                    kind: RevocationKind::AuthRef,
                    target: targets[1],
                    reason: None,
                    ts: now.saturating_sub(10),
                    ttl: None,
                },
                RevocationRecord {
                    kind: RevocationKind::AuthRef,
                    target: targets[2],
                    reason: None,
                    ts: now.saturating_sub(20),
                    ttl: None,
                },
            ];
            for record in &records {
                let payload = encode_envelope(schema_revocation(), record.clone());
                pipeline.publish_revocation(&payload).await.unwrap();
            }

            let response = pipeline.revocation_list(None, None, false, Some(2)).await?;
            assert_eq!(response.revocations.len(), 2);
            assert!(response.revocations[0].ts >= response.revocations[1].ts);
            assert_eq!(response.revocations[0].ts, records[1].ts);
            assert_eq!(response.revocations[1].ts, records[2].ts);
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn readiness_report_ok_for_fresh_state() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;

            let report = pipeline.readiness_report().await?;
            assert!(report.ok, "fresh pipeline must be ready");
            assert!(report.state_dir_accessible);
            assert!(report.indexes_initialised);
            assert!(report.details.is_empty());
            assert!(report.authority_view.ok);
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn readiness_report_detects_stale_authority() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;

            let realm = RealmId::derive("stale");
            let stream = realm.stream_fed_admin();
            let record = AuthorityRecord {
                realm_id: realm,
                stream_id: stream,
                primary_hub: HubId::new([0x01; 32]),
                replica_hubs: Vec::new(),
                policy: AuthorityPolicy::SinglePrimary,
                ts: 1,
                ttl: 1,
            };
            let payload = encode_envelope(schema_fed_authority(), record);
            pipeline.publish_authority(&payload).await.unwrap();

            let report = pipeline.readiness_report().await?;
            assert!(!report.ok, "stale authority view must fail readiness");
            assert!(!report.authority_view.ok);
            assert!(report
                .details
                .iter()
                .any(|detail| detail.contains("authority")));
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn readiness_report_detects_index_divergence() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            let stream = "core/readiness";
            allow_stream_for_hub(&pipeline, stream, "ready").await?;

            let request = SubmitRequest {
                stream: stream.to_string(),
                client_id: hex::encode([0x33; 32]),
                payload: json!({"ok": true}),
                attachments: None,
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };
            pipeline.submit(request).await.unwrap();

            {
                let mut guard = pipeline.inner.write().await;
                let runtime = guard.streams.get_mut(stream).expect("stream runtime");
                let mut dup = runtime
                    .state
                    .messages
                    .last()
                    .cloned()
                    .expect("message present");
                dup.seq += 1;
                let leaf = leaf_hash_for(&dup).expect("leaf hash");
                runtime.insert_message_with_leaf(dup, leaf);
            }

            let report = pipeline.readiness_report().await?;
            assert!(!report.ok, "divergent indexes must fail readiness");
            assert!(!report.indexes_initialised);
            assert!(report.details.iter().any(|detail| detail.contains(stream)));
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn publish_authority_persists_record() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;

            let realm = RealmId::derive("test-realm");
            let stream = realm.stream_fed_admin();
            let record = AuthorityRecord {
                realm_id: realm,
                stream_id: stream,
                primary_hub: HubId::new([0x11; 32]),
                replica_hubs: vec![HubId::new([0x22; 32])],
                policy: AuthorityPolicy::SinglePrimary,
                ts: 1,
                ttl: 600,
            };
            let payload = encode_envelope(schema_fed_authority(), record.clone());

            pipeline.publish_authority(&payload).await.unwrap();

            let guard = pipeline.inner.read().await;
            assert_eq!(guard.authority_records.len(), 1);
            assert_eq!(guard.authority_records[0], record);
            assert!(guard
                .authority_view
                .active_record_at(realm, stream, record.ts)
                .is_some());
        });
    }

    #[test]
    fn submit_rejects_when_hub_not_authorised() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;

            let stream_label = "core/main";
            let stream_id = cap_stream_id_from_label(stream_label).expect("stream id");
            let realm = RealmId::derive("authority-realm");
            let record = AuthorityRecord {
                realm_id: realm,
                stream_id,
                primary_hub: HubId::new([0xAA; 32]),
                replica_hubs: Vec::new(),
                policy: AuthorityPolicy::SinglePrimary,
                ts: current_unix_timestamp()?,
                ttl: 600,
            };
            let payload = encode_envelope(schema_fed_authority(), record);
            pipeline.publish_authority(&payload).await.unwrap();

            let request = SubmitRequest {
                stream: stream_label.to_string(),
                client_id: hex::encode([0x11; 32]),
                payload: serde_json::json!({"text": "unauthorised"}),
                attachments: None,
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };

            let err = pipeline
                .submit(request)
                .await
                .expect_err("submit should fail");
            let capability_err = err.downcast::<CapabilityError>().expect("capability error");
            match capability_err {
                CapabilityError::NotAuthorisedForStream { policy, .. } => {
                    assert_eq!(policy, "single-primary");
                }
                other => panic!("unexpected error: {other:?}"),
            }
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn submit_accepts_for_multi_primary_replica() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;

            let stream_label = "core/main";
            let stream_id = cap_stream_id_from_label(stream_label).expect("stream id");
            let realm = RealmId::derive("multi-realm");
            let record = AuthorityRecord {
                realm_id: realm,
                stream_id,
                primary_hub: HubId::new([0xAA; 32]),
                replica_hubs: vec![pipeline.identity.hub_id],
                policy: AuthorityPolicy::MultiPrimary,
                ts: current_unix_timestamp()?,
                ttl: 600,
            };
            let payload = encode_envelope(schema_fed_authority(), record);
            pipeline.publish_authority(&payload).await.unwrap();

            let request = SubmitRequest {
                stream: stream_label.to_string(),
                client_id: hex::encode([0x22; 32]),
                payload: serde_json::json!({"text": "multi-primary"}),
                attachments: None,
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };

            pipeline.submit(request).await.expect("submit to succeed");
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn submit_rejects_duplicate_leaf_hash() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            allow_stream_for_hub(&pipeline, "core/dup", "dup").await?;

            let request = SubmitRequest {
                stream: "core/dup".to_string(),
                client_id: hex::encode([0x33; 32]),
                payload: serde_json::json!({"text": "deduplicate"}),
                attachments: None,
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };

            pipeline.submit(request.clone()).await.unwrap();
            {
                let mut guard = pipeline.inner.write().await;
                let runtime = guard
                    .streams
                    .get_mut("core/dup")
                    .expect("stream runtime present");
                runtime.state.messages.clear();
                runtime.message_index.clear();
                runtime.leaf_index.clear();
                runtime.proven_messages.clear();
                runtime.mmr = Mmr::new();
            }
            let err = pipeline
                .submit(request)
                .await
                .expect_err("duplicate submit should fail");
            let submit_err = err.downcast::<SubmitError>().expect("submit error");
            match submit_err {
                SubmitError::Duplicate { leaf_hash } => {
                    assert!(!leaf_hash.is_empty());
                }
            }
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn duplicate_detector_is_seeded_from_persisted_messages() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides.clone()).await;
            allow_stream_for_hub(&pipeline, "core/dup-seed", "dup-seed").await?;

            let request = SubmitRequest {
                stream: "core/dup-seed".to_string(),
                client_id: hex::encode([0x44; 32]),
                payload: serde_json::json!({"text": "persisted"}),
                attachments: None,
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };

            pipeline.submit(request.clone()).await.unwrap();
            let authority_path = pipeline.storage.authority_store_path();
            pipeline.storage.flush().await.unwrap();
            drop(pipeline);

            let pid_path = temp.path().join(crate::storage::HUB_PID_FILE);
            if pid_path.exists() {
                fs::remove_file(&pid_path).await.unwrap();
            }
            if authority_path.exists() {
                fs::remove_file(&authority_path).await.unwrap();
            }

            let restarted = init_pipeline_with_overrides(temp.path(), overrides).await;
            {
                let mut guard = restarted.inner.write().await;
                let runtime = guard
                    .streams
                    .get_mut("core/dup-seed")
                    .expect("stream runtime present");
                runtime.state.messages.clear();
                runtime.message_index.clear();
                runtime.leaf_index.clear();
                runtime.proven_messages.clear();
                runtime.mmr = Mmr::new();
            }
            let err = restarted
                .submit(request)
                .await
                .expect_err("duplicate submit should fail after restart");
            assert!(err.downcast_ref::<SubmitError>().is_some());
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn publish_label_class_updates_index() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;

            let stream = RealmId::derive("realm").stream_label_class();
            let label = Label::derive([], stream, 0);
            let record = LabelClassRecord {
                label,
                class: "user".into(),
                sensitivity: Some("medium".into()),
                retention_hint: Some(86_400),
            };
            let payload = encode_envelope(schema_label_class(), record.clone());

            pipeline.publish_label_class(&payload).await.unwrap();

            let guard = pipeline.inner.read().await;
            assert_eq!(guard.label_class_records.len(), 1);
            assert_eq!(guard.label_class_index.get(&label), Some(&record));
        });
    }

    #[tokio::test]
    async fn label_class_descriptor_reports_defaults() -> Result<()> {
        let dir = tempdir()?;
        write_test_hub_key(dir.path()).await?;
        let pipeline = init_pipeline(dir.path()).await;
        let stream_id = cap_stream_id_from_label("chat/general")?;
        let label = Label::derive([], stream_id, 0);

        let descriptor = pipeline.label_class_descriptor(label).await;
        assert!(descriptor.class.is_none());
        assert_eq!(descriptor.pad_block_effective, 256);
        assert_eq!(descriptor.retention_policy, "standard");
        assert_eq!(descriptor.rate_policy, "rl0-default");

        Ok(())
    }

    #[tokio::test]
    async fn label_class_list_filters_by_class() -> Result<()> {
        let dir = tempdir()?;
        write_test_hub_key(dir.path()).await?;
        let pipeline = init_pipeline(dir.path()).await;
        let stream_id = cap_stream_id_from_label("chat/general")?;
        let label = Label::derive([], stream_id, 0);
        let record = LabelClassRecord {
            label,
            class: "user".to_string(),
            sensitivity: Some("medium".to_string()),
            retention_hint: Some(86_400),
        };
        let payload = encode_envelope(schema_label_class(), record);
        pipeline.publish_label_class(&payload).await?;

        let list = pipeline.label_class_list(Some("user".to_string())).await;
        assert_eq!(list.entries.len(), 1);
        let entry = &list.entries[0];
        assert_eq!(entry.class, "user");
        assert_eq!(entry.sensitivity.as_deref(), Some("medium"));
        assert_eq!(entry.retention_hint, Some(86_400));

        Ok(())
    }

    #[test]
    fn register_schema_descriptor_tracks_latest() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let pipeline = init_pipeline(temp.path()).await;

            let descriptor = SchemaDescriptor {
                schema_id: SchemaId::new([0xAA; 32]),
                name: "wallet.transfer".into(),
                version: "v1".into(),
                doc_url: Some("https://example.com".into()),
                owner: None,
                ts: 42,
            };
            let payload = encode_envelope(schema_meta_schema(), descriptor.clone());

            pipeline.register_schema_descriptor(&payload).await.unwrap();

            let guard = pipeline.inner.read().await;
            assert_eq!(guard.schema_descriptors.len(), 1);
            let stored = guard
                .schema_registry
                .get(&descriptor.schema_id)
                .expect("schema descriptor present");
            assert_eq!(stored, &descriptor);
        });
    }

    #[test]
    fn submit_rejects_payload_body_over_limit() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            allow_stream_for_hub(&pipeline, "core/limit-body", "limit-body").await?;

            let body = "x".repeat(MAX_BODY_BYTES + 1);
            let request = SubmitRequest {
                stream: "core/limit-body".to_string(),
                client_id: hex::encode([0xAB; 32]),
                payload: serde_json::json!({"blob": body}),
                attachments: None,
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };

            let err = pipeline
                .submit(request)
                .await
                .expect_err("submit should fail");
            let capability_err = err.downcast::<CapabilityError>().expect("capability error");
            match capability_err {
                CapabilityError::MessageBodyTooLarge { limit, .. } => {
                    assert_eq!(limit, MAX_BODY_BYTES);
                }
                other => panic!("unexpected error: {other:?}"),
            }
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn submit_rejects_attachment_count_over_limit() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            allow_stream_for_hub(&pipeline, "core/limit-attachments", "limit-attachments").await?;

            let attachment = AttachmentUpload {
                name: None,
                data: BASE64_STANDARD.encode([0u8; 1]),
            };
            let attachments = vec![attachment; MAX_ATTACHMENTS_PER_MSG + 1];

            let request = SubmitRequest {
                stream: "core/limit-attachments".to_string(),
                client_id: hex::encode([0xBC; 32]),
                payload: serde_json::json!({"ok": true}),
                attachments: Some(attachments),
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };

            let err = pipeline
                .submit(request)
                .await
                .expect_err("submit should fail");
            let capability_err = err.downcast::<CapabilityError>().expect("capability error");
            match capability_err {
                CapabilityError::AttachmentCountExceeded { limit, .. } => {
                    assert_eq!(limit, MAX_ATTACHMENTS_PER_MSG);
                }
                other => panic!("unexpected error: {other:?}"),
            }
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }

    #[test]
    fn submit_rejects_total_message_size_over_limit() -> Result<()> {
        let rt = Runtime::new()?;
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            allow_stream_for_hub(&pipeline, "core/limit-total", "limit-total").await?;

            // Body well below limit so that attachments trigger the overflow.
            let body = serde_json::json!({"text": "small"});
            let body_len = body.to_string().len();
            let attachment_bytes = MAX_MSG_BYTES - body_len + 1; // forces total > limit
            let attachment = AttachmentUpload {
                name: Some("large".into()),
                data: BASE64_STANDARD.encode(vec![0u8; attachment_bytes]),
            };

            let request = SubmitRequest {
                stream: "core/limit-total".to_string(),
                client_id: hex::encode([0xCD; 32]),
                payload: body,
                attachments: Some(vec![attachment]),
                auth_ref: None,
                expires_at: None,
                schema: None,
                idem: None,
                pow_cookie: None,
            };

            let err = pipeline
                .submit(request)
                .await
                .expect_err("submit should fail");
            let capability_err = err.downcast::<CapabilityError>().expect("capability error");
            match capability_err {
                CapabilityError::MessageTotalTooLarge { limit, .. } => {
                    assert_eq!(limit, MAX_MSG_BYTES);
                }
                other => panic!("unexpected error: {other:?}"),
            }
            Ok::<(), anyhow::Error>(())
        })?;
        Ok(())
    }
}
