use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ciborium::de::from_reader;
use hex;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::Value as JsonValue;
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::fs::OpenOptions;
use tokio::sync::Mutex;

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
    types::{AuthRef, ClientId, LeafHash, MmrNode, MmrRoot},
};
use veen_core::{
    cap_stream_id_from_label, cap_token_from_cbor, schema_fed_authority, schema_label_class,
    schema_meta_schema, AuthorityRecord, AuthorityView, CapTokenRate, Label, LabelClassRecord,
    LabelPolicy, PowCookie, RealmId, SchemaDescriptor, StreamId, StreamIdParseError,
    CAP_TOKEN_VERSION, MAX_ATTACHMENTS_PER_MSG, MAX_BODY_BYTES, MAX_MSG_BYTES,
};

use thiserror::Error;

use crate::config::{AdmissionConfig, FederationConfig, HubRole, HubRuntimeConfig};
use crate::observability::{HubObservability, ObservabilitySnapshot};
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
    identity: HubIdentity,
}

struct HubState {
    streams: HashMap<String, StreamRuntime>,
    capabilities: CapabilityStore,
    anchors: AnchorLog,
    revocations: RevocationView,
    revocation_log: Vec<RevocationRecord>,
    authority_records: Vec<AuthorityRecord>,
    authority_view: AuthorityView,
    label_class_records: Vec<LabelClassRecord>,
    label_class_index: HashMap<Label, LabelClassRecord>,
    schema_descriptors: Vec<SchemaDescriptor>,
    schema_registry: SchemaRegistry,
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
        let revocation_log = load_revocation_log(storage).await?;
        let mut revocations = RevocationView::new();
        revocations.extend(revocation_log.iter().cloned());
        let authority_records = load_authority_records(storage).await?;
        let mut authority_view = AuthorityView::new();
        authority_view.extend(authority_records.iter().cloned());
        let label_class_records = load_label_classes(storage).await?;
        let label_class_index = build_label_class_index(&label_class_records);
        let schema_descriptors = load_schema_descriptors(storage).await?;
        let schema_registry = build_schema_registry(&schema_descriptors);
        let identity = load_hub_identity(storage).await?;
        let state = HubState {
            streams,
            capabilities,
            anchors,
            revocations,
            revocation_log,
            authority_records,
            authority_view,
            label_class_records,
            label_class_index,
            schema_descriptors,
            schema_registry,
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
            identity,
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
        let submitted_at = current_unix_timestamp();
        let submitted_at_ms = current_unix_timestamp_millis();
        let client_id_value = ClientId::from_str(&client_id)
            .with_context(|| format!("parsing client_id {client_id} as hex-encoded identifier"))?;
        let client_target = RevocationTarget::from_slice(client_id_value.as_ref())
            .context("constructing client revocation target")?;
        let parsed_auth_ref = if let Some(ref auth_hex) = auth_ref {
            Some(AuthRef::from_str(auth_hex).with_context(|| {
                format!("parsing auth_ref {auth_hex} as hex-encoded identifier")
            })?)
        } else {
            None
        };
        let auth_target = parsed_auth_ref
            .as_ref()
            .map(|value| RevocationTarget::from_slice(value.as_ref()))
            .transpose()
            .context("constructing auth_ref revocation target")?;

        let mut guard = self.inner.lock().await;

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
                    .map(|primary| format!("; expected primary {}", hex::encode(primary.as_ref())))
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
            tracing::debug!(stream = %stream, allowed_hubs = %allowed.join(","), "accepting multi-primary stream");
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
            if let Err(err) = enforce_capability(
                &mut guard.capabilities,
                cap,
                &client_id,
                &stream,
                submitted_at,
                submitted_at_ms,
            ) {
                update_capability_store(&self.storage, &guard.capabilities).await?;
                return Err(anyhow::Error::new(err));
            }
        } else if self.admission.capability_gating_enabled {
            update_capability_store(&self.storage, &guard.capabilities).await?;
            return Err(anyhow::Error::new(CapabilityError::Unauthorized {
                auth_ref: "missing".to_string(),
            }));
        }

        if let Some((token_hash, target)) = token_revocation {
            if guard
                .revocations
                .is_revoked(RevocationKind::CapToken, target, submitted_at)
            {
                update_capability_store(&self.storage, &guard.capabilities).await?;
                return Err(anyhow::Error::new(CapabilityError::CapTokenRevoked {
                    token_hash,
                }));
            }
        }

        let usage_update = match check_client_usage(
            &mut guard.capabilities,
            &self.admission,
            &client_id,
            &stream,
            submitted_at,
        ) {
            Ok(update) => update,
            Err(err) => {
                update_capability_store(&self.storage, &guard.capabilities).await?;
                return Err(anyhow::Error::new(err));
            }
        };

        let stream_runtime = guard.streams.entry(stream.clone()).or_insert_with(|| {
            StreamRuntime::new(HubStreamState::default()).expect("empty stream state")
        });

        let seq = stream_runtime
            .state
            .messages
            .last()
            .map(|m| m.seq + 1)
            .unwrap_or(1);

        let stored_attachments =
            persist_attachments(&self.storage, &stream, &attachments, payload_json.len()).await?;

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

        let leaf = leaf_hash_for(&stored_message)?;
        let (_, mmr_root) = stream_runtime.mmr.append(leaf);
        stream_runtime.state.messages.push(stored_message.clone());

        persist_stream_state(&self.storage, &stream, &stream_runtime.state).await?;
        persist_message_bundle(&self.storage, &stream, seq, &stored_message).await?;
        append_receipt(&self.storage, &stream, seq, &leaf, &mmr_root, submitted_at).await?;

        if let Err(err) = apply_client_usage_update(&mut guard.capabilities, usage_update) {
            update_capability_store(&self.storage, &guard.capabilities).await?;
            return Err(anyhow::Error::new(err));
        }

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

        let mut guard = self.inner.lock().await;
        guard.revocations.insert(record.clone());
        guard.revocation_log.push(record);
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

        let mut guard = self.inner.lock().await;
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

        let mut guard = self.inner.lock().await;
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

        let mut guard = self.inner.lock().await;
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
        let guard = self.inner.lock().await;
        let runtime = guard
            .streams
            .get(stream)
            .ok_or_else(|| anyhow!("stream {stream} has no stored messages"))?;

        if !with_proof {
            let messages = runtime
                .state
                .messages
                .iter()
                .filter(|msg| msg.seq >= from)
                .cloned()
                .collect();
            return Ok(StreamResponse::Messages(messages));
        }

        let mut mmr = Mmr::new();
        let mut proven = Vec::new();
        for message in &runtime.state.messages {
            let leaf = leaf_hash_for(message)?;
            let (_, root, proof) = mmr.append_with_proof(leaf);
            if message.seq >= from {
                let receipt = StreamReceipt {
                    seq: message.seq,
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
        }

        Ok(StreamResponse::Proven(proven))
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
            bucket_state: token
                .allow
                .rate
                .as_ref()
                .map(|rate| TokenBucketState::new(rate.burst, current_unix_timestamp_millis())),
            uses: 0,
            token_hash: Some(hex::encode(cap_token_hash(token_bytes))),
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

    pub async fn profile_descriptor(&self) -> HubProfileDescriptor {
        let guard = self.inner.lock().await;
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
    ) -> HubRoleDescriptor {
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
            let guard = self.inner.lock().await;
            let now = current_unix_timestamp();
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

            HubRoleDescriptor {
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
            }
        } else {
            HubRoleDescriptor {
                ok: true,
                hub_id: self.identity.hub_id_hex.clone(),
                role,
                stream: None,
            }
        }
    }

    pub async fn anchor_log(&self) -> Result<AnchorLog> {
        let guard = self.inner.lock().await;
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

#[derive(Debug, Deserialize, Serialize)]
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

async fn persist_attachments(
    storage: &HubStorage,
    stream: &str,
    attachments: &[AttachmentUpload],
    initial_bytes: usize,
) -> Result<Vec<StoredAttachment>> {
    if attachments.is_empty() {
        return Ok(Vec::new());
    }

    let mut decoded = Vec::with_capacity(attachments.len());
    let mut total_bytes = initial_bytes;

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
        decoded.push((index, attachment.name.clone(), data));
    }

    fs::create_dir_all(storage.attachments_dir())
        .await
        .with_context(|| {
            format!(
                "ensuring attachments directory {}",
                storage.attachments_dir().display()
            )
        })?;

    let mut stored = Vec::with_capacity(decoded.len());
    for (index, name, data) in decoded {
        let digest = sha2::Sha256::digest(&data);
        let digest_hex = hex::encode(digest);
        let file_name = format!("{digest_hex}.bin");
        let path = storage.attachments_dir().join(&file_name);
        fs::write(&path, &data)
            .await
            .with_context(|| format!("writing attachment to {}", path.display()))?;
        stored.push(StoredAttachment {
            name: name
                .clone()
                .unwrap_or_else(|| format!("attachment-{index}")),
            digest: digest_hex,
            size: data.len() as u64,
            stored_path: path.to_string_lossy().into_owned(),
        });
    }

    Ok(stored)
}

fn check_client_usage(
    store: &mut CapabilityStore,
    admission: &AdmissionConfig,
    client_id: &str,
    stream: &str,
    now: u64,
) -> Result<Option<ClientUsageUpdate>, CapabilityError> {
    if admission.max_client_id_lifetime_sec.is_none()
        && admission.max_msgs_per_client_id_per_label.is_none()
    {
        return Ok(None);
    }

    let entry = store
        .client_usage
        .entry(client_id.to_string())
        .or_insert_with(|| ClientAdmissionState::new(now));

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

    Ok(Some(ClientUsageUpdate {
        client_id: client_id.to_string(),
        stream: stream.to_string(),
        first_seen: entry.first_seen,
    }))
}

fn apply_client_usage_update(
    store: &mut CapabilityStore,
    update: Option<ClientUsageUpdate>,
) -> Result<(), CapabilityError> {
    if let Some(ClientUsageUpdate {
        client_id,
        stream,
        first_seen,
    }) = update
    {
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
    Ok(())
}

fn enforce_capability(
    store: &mut CapabilityStore,
    auth_ref: &str,
    subject: &str,
    stream: &str,
    now: u64,
    now_ms: u64,
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
        refill_bucket(state, rate, now_ms);
        if state.tokens == 0 {
            let retry_after = retry_after_seconds(rate, state, now_ms);
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
    let mut store: CapabilityStore = serde_json::from_slice(&data)
        .with_context(|| format!("parsing capability store from {}", path.display()))?;
    store.normalise_bucket_state();
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

fn current_unix_timestamp() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH");
    now.as_secs()
}

fn current_unix_timestamp_millis() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH");
    now.as_millis() as u64
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HubConfigOverrides;
    use anyhow::Context;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::net::SocketAddr;
    use std::path::Path;
    use tempfile::tempdir;
    use tokio::fs;
    use tokio::runtime::Runtime;
    use veen_core::cap_stream_id_from_label;
    use veen_core::federation::AuthorityPolicy;
    use veen_core::meta::SchemaId;
    use veen_core::realm::RealmId;
    use veen_core::HubId;

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
            created_at: current_unix_timestamp(),
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

    async fn allow_stream_for_hub(pipeline: &HubPipeline, label: &str, realm_name: &str) {
        let stream_id = cap_stream_id_from_label(label).expect("stream id");
        let realm = RealmId::derive(realm_name);
        let record = AuthorityRecord {
            realm_id: realm,
            stream_id,
            primary_hub: pipeline.identity.hub_id,
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::SinglePrimary,
            ts: current_unix_timestamp(),
            ttl: 600,
        };
        let payload = encode_envelope(schema_fed_authority(), record);
        pipeline.publish_authority(&payload).await.unwrap();
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

            let guard = pipeline.inner.lock().await;
            assert_eq!(guard.authority_records.len(), 1);
            assert_eq!(guard.authority_records[0], record);
            assert!(guard
                .authority_view
                .active_record_at(realm, stream, record.ts)
                .is_some());
        });
    }

    #[test]
    fn submit_rejects_when_hub_not_authorised() {
        let rt = Runtime::new().unwrap();
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
                ts: current_unix_timestamp(),
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
        });
    }

    #[test]
    fn submit_accepts_for_multi_primary_replica() {
        let rt = Runtime::new().unwrap();
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
                ts: current_unix_timestamp(),
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
        });
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

            let guard = pipeline.inner.lock().await;
            assert_eq!(guard.label_class_records.len(), 1);
            assert_eq!(guard.label_class_index.get(&label), Some(&record));
        });
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

            let guard = pipeline.inner.lock().await;
            assert_eq!(guard.schema_descriptors.len(), 1);
            let stored = guard
                .schema_registry
                .get(&descriptor.schema_id)
                .expect("schema descriptor present");
            assert_eq!(stored, &descriptor);
        });
    }

    #[test]
    fn submit_rejects_payload_body_over_limit() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            allow_stream_for_hub(&pipeline, "core/limit-body", "limit-body").await;

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
        });
    }

    #[test]
    fn submit_rejects_attachment_count_over_limit() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            allow_stream_for_hub(&pipeline, "core/limit-attachments", "limit-attachments").await;

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
        });
    }

    #[test]
    fn submit_rejects_total_message_size_over_limit() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let temp = tempdir().unwrap();
            let overrides = HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..HubConfigOverrides::default()
            };
            let pipeline = init_pipeline_with_overrides(temp.path(), overrides).await;
            allow_stream_for_hub(&pipeline, "core/limit-total", "limit-total").await;

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
        });
    }
}
