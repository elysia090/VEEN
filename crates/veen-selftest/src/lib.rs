use std::{collections::HashSet, fmt};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, SeedableRng};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_bytes::ByteBuf;

use veen_core::{
    h, AttachmentRoot, ClientId, ClientObservationIndex, ClientUsage, ClientUsageConfig, Label,
    LeafHash, Mmr, MmrRoot, Msg, PayloadHeader, RealmId, REALM_ID_LEN,
};
use veen_overlays::meta::SchemaRegistry;
use veen_overlays::{
    ContextId, LabelClassRecord, SchemaDescriptor, SchemaId, SchemaOwner, TransferId,
    WalletDepositEvent, WalletId, WalletOpenEvent, WalletState, WalletTransferEvent,
    TRANSFER_ID_LEN, WALLET_ID_LEN,
};

pub mod metrics;
mod overlays;
mod perf;
mod process_harness;
mod query;
mod recorder;
mod suites;

use process_harness::{HardenedResult, IntegrationHarness, MetaOverlayResult};
use suites::common::{SampleData, SequenceHarness};

pub use metrics::{HistogramSnapshot, HubMetricsSnapshot};
pub use overlays::run_overlays;
pub use perf::{run_perf, PerfConfig, PerfMode, PerfSummary};
pub use query::run_query_overlays;
pub use recorder::run_recorder;

#[derive(Default, serde::Serialize)]
pub struct SelftestReport {
    entries: Vec<SelftestGoalReport>,
}

impl SelftestReport {
    pub fn add_entry(&mut self, entry: SelftestGoalReport) {
        self.entries.push(entry);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl fmt::Display for SelftestReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.entries.is_empty() {
            writeln!(f, "No self-test entries recorded.")?;
            return Ok(());
        }

        for (idx, entry) in self.entries.iter().enumerate() {
            writeln!(f, "Goal: {}", entry.goal)?;
            if !entry.environment.is_empty() {
                writeln!(f, "  Environment:")?;
                for env in &entry.environment {
                    writeln!(f, "    - {env}")?;
                }
            }
            if !entry.invariants.is_empty() {
                writeln!(f, "  Invariants:")?;
                for invariant in &entry.invariants {
                    writeln!(f, "    - {invariant}")?;
                }
            }
            if !entry.evidence.is_empty() {
                writeln!(f, "  Evidence:")?;
                for ev in &entry.evidence {
                    writeln!(f, "    - {ev}")?;
                }
            }
            if let Some(perf) = &entry.perf {
                writeln!(f, "  Performance:")?;
                writeln!(
                    f,
                    "    - throughput_rps={:.2} (requests={}, concurrency={}, mode={})",
                    perf.throughput_rps,
                    perf.workload.requests,
                    perf.workload.concurrency,
                    perf.workload.mode.as_str()
                )?;
                writeln!(
                    f,
                    "    - verify p95/p99 ms: {:.2}/{:.2}",
                    perf.verify_p95_ms, perf.verify_p99_ms
                )?;
                writeln!(
                    f,
                    "    - commit p95/p99 ms: {:.2}/{:.2}",
                    perf.commit_p95_ms, perf.commit_p99_ms
                )?;
                writeln!(
                    f,
                    "    - end-to-end p95/p99 ms: {:.2}/{:.2}",
                    perf.end_to_end_p95_ms, perf.end_to_end_p99_ms
                )?;
            }
            if idx + 1 < self.entries.len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}

#[derive(serde::Serialize)]
pub struct SelftestGoalReport {
    pub goal: String,
    pub environment: Vec<String>,
    pub invariants: Vec<String>,
    pub evidence: Vec<String>,
    pub perf: Option<PerfSummary>,
}

impl SelftestGoalReport {
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            goal: goal.into(),
            environment: Vec::new(),
            invariants: Vec::new(),
            evidence: Vec::new(),
            perf: None,
        }
    }
}

pub struct SelftestReporter<'a> {
    target: Option<&'a mut SelftestReport>,
    recorded: usize,
}

impl<'a> SelftestReporter<'a> {
    pub fn new(target: Option<&'a mut SelftestReport>) -> Self {
        Self {
            target,
            recorded: 0,
        }
    }

    pub fn disabled() -> Self {
        Self {
            target: None,
            recorded: 0,
        }
    }

    pub fn record(&mut self, entry: SelftestGoalReport) {
        self.recorded += 1;
        if let Some(report) = self.target.as_mut() {
            report.add_entry(entry);
        }
    }

    pub fn recorded(&self) -> usize {
        self.recorded
    }
}

/// Execute the core protocol self-test invariants described in the CLI goal.
pub async fn run_core(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let prereqs =
        process_harness::core_suite_prereqs().context("checking core suite prerequisites")?;
    if !prereqs.ready() {
        let missing = prereqs.missing.join("; ");
        let diagnostics = prereqs.diagnostics.join("; ");
        bail!(
            "core integration suite prerequisites missing: {missing}. diagnostics: {diagnostics}"
        );
    }

    let data = SampleData::generate()?;

    ensure!(data.msg.has_valid_version(), "unexpected message version");
    ensure!(
        data.msg.ct_hash_matches(),
        "ciphertext hash does not match payload bytes"
    );
    data.msg
        .verify_signature()
        .context("verifying client signature on message")?;

    let payload_att_root = data
        .payload_header
        .att_root
        .ok_or_else(|| anyhow!("payload header missing attachment root"))?;
    ensure!(
        payload_att_root == data.att_root,
        "attachment root must be recorded in payload header"
    );

    let recomputed_root =
        AttachmentRoot::from_ciphertexts(data.attachments.iter().map(Vec::as_slice))
            .ok_or_else(|| anyhow!("failed to recompute attachment root"))?;
    ensure!(
        recomputed_root == data.att_root,
        "attachment Merkle root mismatch during verification"
    );

    let mut tampered_first = data.attachments[0].clone();
    tampered_first[0] ^= 0xFF;
    let tampered_root = AttachmentRoot::from_ciphertexts([
        tampered_first.as_slice(),
        data.attachments[1].as_slice(),
    ]);
    ensure!(
        tampered_root != Some(data.att_root),
        "tampering with attachment ciphertext must change att_root"
    );

    ensure!(
        data.stream_seq == 1,
        "first message must yield stream sequence 1"
    );
    ensure!(
        data.receipt.has_valid_version(),
        "receipt version deviates from specification"
    );
    ensure!(
        data.receipt.leaf_hash == data.msg.leaf_hash(),
        "receipt leaf hash must match message leaf hash"
    );
    ensure!(
        data.receipt.mmr_root == data.mmr_root,
        "receipt must commit to the current MMR root"
    );

    data.receipt
        .verify_signature(&data.hub_public)
        .context("verifying hub receipt signature")?;

    process_harness::run_core_suite()
        .await
        .context("running process-level core integration suite")?;

    tracing::info!(
        label = %data.msg.label,
        stream_seq = data.stream_seq,
        mmr_root = %data.mmr_root,
        "core protocol self-test satisfied invariants",
    );

    let entry = SelftestGoalReport {
        goal: "SELFTEST.CORE".into(),
        environment: vec![
            format!("label={}", data.msg.label),
            format!("stream_seq={}", data.stream_seq),
        ],
        invariants: vec![
            "validated message signature and payload hash".into(),
            "validated attachment roots and tamper-detection".into(),
            "validated receipt signature and MMR sequencing".into(),
            "validated process harness core scenario".into(),
        ],
        evidence: vec![
            format!("hub_public={}", hex::encode(data.hub_public)),
            format!("mmr_root={}", hex::encode(data.mmr_root.as_bytes())),
            format!("att_root={}", hex::encode(data.att_root.as_bytes())),
        ],
        perf: None,
    };
    reporter.record(entry);
    ensure!(
        reporter.recorded() > 0,
        "core self-test did not record any entries"
    );

    Ok(())
}

/// Execute property-style checks over deterministic scenarios.
pub fn run_props(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    check_prev_ack_within_stream_bounds()?;
    check_client_sequence_uniqueness_and_increment()?;
    check_mmr_index_consistency_under_resync()?;
    check_cbor_determinism_suite()?;
    check_mmr_fold_invariance()?;
    check_attachment_root_stability()?;
    check_schema_registry_precedence()?;
    run_overlay_scenario()?;

    tracing::info!("property-based VEEN self-tests completed");
    let entry = SelftestGoalReport {
        goal: "SELFTEST.PROPS".into(),
        environment: vec!["harness=sequence+overlay".into()],
        invariants: vec![
            "prev_ack bounded by stream state".into(),
            "client sequence monotonicity".into(),
            "MMR index consistency".into(),
            "CBOR determinism".into(),
            "MMR folding invariance".into(),
            "attachment root determinism".into(),
            "schema registry precedence".into(),
        ],
        evidence: vec![
            "overlay wallet scenario executed".into(),
            "multiple deterministic harness passes".into(),
        ],
        perf: None,
    };
    reporter.record(entry);
    Ok(())
}

/// Execute basic fuzz-style checks by mutating valid artefacts.
pub fn run_fuzz(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let data = SampleData::generate()?;

    fuzz_truncated_cbor(&data.msg, "MSG")?;
    fuzz_truncated_cbor(&data.receipt, "RECEIPT")?;
    fuzz_signature_validations(&data)?;
    fuzz_nonce_uniqueness()?;

    tracing::info!("fuzz-style VEEN self-tests completed");
    let entry = SelftestGoalReport {
        goal: "SELFTEST.FUZZ".into(),
        environment: vec![format!("label={}", data.msg.label)],
        invariants: vec![
            "CBOR decoding rejects truncation".into(),
            "signature verification rejects tampering".into(),
            "nonce uniqueness preserved".into(),
        ],
        evidence: vec![
            format!("msg_ct_hash={}", hex::encode(data.msg.ct_hash.as_bytes())),
            format!(
                "receipt_root={}",
                hex::encode(data.receipt.mmr_root.as_bytes())
            ),
        ],
        perf: None,
    };
    reporter.record(entry);
    Ok(())
}

/// Run the complete self-test suite (core + props + fuzz).
pub async fn run_all(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    run_core(reporter).await?;
    run_props(reporter)?;
    run_fuzz(reporter)?;
    tracing::info!("all VEEN self-test suites completed successfully");
    Ok(())
}

/// Execute the federated overlay suite covering FED1/AUTH1 goals.
pub async fn run_federated(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    run_overlays(None, reporter)
        .await
        .context("running federated overlay scenarios")?;
    tracing::info!("federated VEEN self-tests completed");
    Ok(())
}

/// Placeholder for lifecycle and revocation (KEX1+) self-tests.
pub async fn run_kex1(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let mut harness = process_harness::IntegrationHarness::new()
        .await
        .context("initialising lifecycle harness")?;

    let restart = harness
        .run_restart_suite()
        .await
        .context("running restart lifecycle suite")?;
    let failstart = harness
        .run_failstart_suite()
        .await
        .context("running failstart lifecycle suite")?;
    let version_skew = harness
        .run_version_skew_suite()
        .await
        .context("running version-skew lifecycle suite")?;

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.LIFECYCLE.RESTART".into(),
        environment: vec![
            format!("stream={}", restart.stream),
            format!("seq_before_restart={}", restart.seq_before_restart),
        ],
        invariants: vec![
            "MMR root stable across graceful restart".into(),
            "stream proofs verify before and after restart".into(),
            "sequence continuity preserved after restart send".into(),
        ],
        evidence: vec![
            format!("mmr_before={}", restart.mmr_before),
            format!("mmr_after_restart={}", restart.mmr_after_restart),
            format!("mmr_after_new_message={}", restart.mmr_after_new_message),
            format!("seq_after_restart={}", restart.seq_after_restart),
        ],
        perf: None,
    });

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.LIFECYCLE.FAILSTART".into(),
        environment: vec![format!("config_path={}", failstart.config_path.display())],
        invariants: vec![
            "invalid configuration exits with CLI usage code".into(),
            "stderr describes configuration parse failure".into(),
        ],
        evidence: vec![
            format!("exit_code={}", failstart.exit_code),
            format!("stderr_excerpt={}", failstart.stderr_excerpt),
        ],
        perf: None,
    });

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.LIFECYCLE.VERSION_SKEW".into(),
        environment: vec![format!("stream={}", version_skew.stream)],
        invariants: vec![
            "legacy receipts and proofs validate under new binary".into(),
            "checkpoint_latest aligns with legacy upto_seq and root".into(),
            "replayed stream maintains legacy mmr_root".into(),
        ],
        evidence: vec![
            format!("legacy_root={}", version_skew.legacy_root),
            format!("replayed_root={}", version_skew.replayed_root),
            format!("last_seq={}", version_skew.last_seq),
            format!("checkpoint_path={}", version_skew.checkpoint_path.display()),
        ],
        perf: None,
    });

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.KEX1".into(),
        environment: vec!["suite=lifecycle".into()],
        invariants: vec![
            "hub restart, failstart, and version-skew lifecycle scenarios executed".into(),
        ],
        evidence: vec![
            format!("restart_stream={}", restart.stream),
            format!("failstart_exit_code={}", failstart.exit_code),
            format!("version_skew_stream={}", version_skew.stream),
            format!("checkpoint={}", version_skew.checkpoint_path.display()),
        ],
        perf: None,
    });

    tracing::info!("kex1+ lifecycle self-tests completed");
    Ok(())
}

/// Hardened profile (SH1+) self-tests covering PoW admission, rate limiting, and replica resync.
pub async fn run_hardened(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let harness = IntegrationHarness::new()
        .await
        .context("initialising hardened integration harness")?;
    let HardenedResult {
        pow_challenge,
        pow_difficulty,
        pow_forbidden_status,
        pow_accept_seq,
        pow_accept_root,
        rate_limit_status,
        replicated_seq,
    } = harness.run_hardened_flow().await?;

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.HARDENED".into(),
        environment: vec![
            format!("pow.difficulty={pow_difficulty}"),
            "suite=hardened".into(),
        ],
        invariants: vec![
            "pow-required submissions are rejected".into(),
            "valid pow cookies admit submissions".into(),
            "client quota enforces rate limits".into(),
            "replica resynchronises upto latest seq".into(),
        ],
        evidence: vec![
            format!("challenge={pow_challenge}"),
            format!("forbidden_status={pow_forbidden_status}"),
            format!("accepted_seq={pow_accept_seq}"),
            format!("accepted_root={pow_accept_root}"),
            format!("rate_limit_status={rate_limit_status}"),
            format!("replicated_seq={replicated_seq}"),
        ],
        perf: None,
    });

    tracing::info!("hardened self-tests completed successfully");
    Ok(())
}

/// Label and schema overlays (META0+) self-tests.
pub async fn run_meta(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let prereqs =
        process_harness::core_suite_prereqs().context("checking meta suite prerequisites")?;
    if !prereqs.ready() {
        let missing = prereqs.missing.join("; ");
        let diagnostics = prereqs.diagnostics.join("; ");
        bail!(
            "meta integration suite prerequisites missing: {missing}. diagnostics: {diagnostics}. \
            Ensure veen-hub/veen-cli binaries are available, the hub data directory is writable, \
            and META0+ schema registry endpoints are enabled."
        );
    }
    let harness = IntegrationHarness::new()
        .await
        .context("initialising meta integration harness")?;
    let MetaOverlayResult {
        schema_id_hex,
        descriptor_name,
        descriptor_version,
        registry_len,
    } = harness.run_meta_overlay().await?;

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.META".into(),
        environment: vec![format!("schema_id={schema_id_hex}"), "suite=meta".into()],
        invariants: vec![
            "schema registration succeeds via overlay".into(),
            "schema registry returns registered descriptor".into(),
        ],
        evidence: vec![
            format!("name={descriptor_name}"),
            format!("version={descriptor_version}"),
            format!("registry_len={registry_len}"),
        ],
        perf: None,
    });
    ensure!(
        reporter.recorded() > 0,
        "meta self-test did not record any entries"
    );

    tracing::info!("meta overlay self-tests completed successfully");
    Ok(())
}

/// Execute the v0.0.1+ aggregated suite.
pub async fn run_plus(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    run_core(reporter).await?;
    run_props(reporter)?;
    run_fuzz(reporter)?;
    run_federated(reporter).await?;
    run_recorder(reporter).await?;
    run_kex1(reporter).await?;
    run_hardened(reporter).await?;
    run_meta(reporter).await?;
    tracing::info!("plus self-test suite completed successfully");
    Ok(())
}

fn check_prev_ack_within_stream_bounds() -> Result<()> {
    let harness = SequenceHarness::new()?;
    let mut mmr = Mmr::new();
    let mut last_stream_seq = 0u64;

    for client_seq in 1..=12 {
        let prev_ack = if client_seq % 3 == 0 && last_stream_seq > 0 {
            last_stream_seq - 1
        } else {
            last_stream_seq
        };
        let (msg, receipt, stream_seq, _) = harness
            .make_message(&mut mmr, client_seq, prev_ack)
            .with_context(|| format!("building message {client_seq} for I6"))?;

        ensure!(
            msg.prev_ack <= last_stream_seq,
            "prev_ack must not exceed the last observed stream_seq",
        );
        ensure!(
            receipt.stream_seq == stream_seq,
            "receipt stream_seq must equal the position returned by the MMR",
        );

        last_stream_seq = stream_seq;
    }

    Ok(())
}

fn check_client_sequence_uniqueness_and_increment() -> Result<()> {
    let harness = SequenceHarness::new()?;
    let mut mmr = Mmr::new();
    let mut seen_pairs: HashSet<(ClientId, u64)> = HashSet::new();
    let mut expected_client_seq = 0u64;
    let mut last_stream_seq = 0u64;

    for _ in 0..8 {
        let next_seq = expected_client_seq + 1;
        let (msg, receipt, stream_seq, _) = harness
            .make_message(&mut mmr, next_seq, last_stream_seq)
            .with_context(|| format!("building message {next_seq} for I8/I9"))?;

        ensure!(
            msg.client_seq == expected_client_seq + 1,
            "client_seq must increment by exactly one per label",
        );
        ensure!(
            stream_seq == last_stream_seq + 1,
            "stream_seq must advance contiguously without gaps",
        );
        ensure!(
            receipt.stream_seq == stream_seq,
            "receipt stream_seq must align with append index",
        );
        ensure!(
            seen_pairs.insert((msg.client_id, msg.client_seq)),
            "duplicate (client_id, client_seq) pair detected",
        );

        expected_client_seq = msg.client_seq;
        last_stream_seq = stream_seq;
    }

    let duplicate_pair = (harness.client_id(), expected_client_seq);
    ensure!(
        !seen_pairs.insert(duplicate_pair),
        "duplicate (client_id, client_seq) must be rejected",
    );

    Ok(())
}

fn check_mmr_index_consistency_under_resync() -> Result<()> {
    let harness = SequenceHarness::new()?;
    let mut mmr = Mmr::new();
    let mut leaves = Vec::new();
    let mut last_stream_seq = 0u64;

    for client_seq in 1..=6 {
        let (msg, receipt, stream_seq, _) = harness
            .make_message(&mut mmr, client_seq, last_stream_seq)
            .with_context(|| format!("building message {client_seq} for I12"))?;
        ensure!(
            stream_seq == last_stream_seq + 1,
            "stream_seq must increase contiguously",
        );
        ensure!(
            receipt.stream_seq == stream_seq,
            "receipt stream_seq must equal the MMR leaf index",
        );
        leaves.push(msg.leaf_hash());
        last_stream_seq = stream_seq;
    }

    let mut rebuilt = Mmr::new();
    for (index, leaf) in leaves.iter().enumerate() {
        let (stream_seq, _) = rebuilt.append(*leaf);
        ensure!(
            stream_seq == (index as u64) + 1,
            "rebuilt MMR stream_seq must match stored leaf index",
        );
    }

    ensure!(
        rebuilt.root() == mmr.root(),
        "rebuilt MMR root must match live MMR root after resync",
    );

    Ok(())
}

fn check_cbor_determinism_suite() -> Result<()> {
    let harness = SequenceHarness::new()?;
    let mut mmr = Mmr::new();
    let (msg, receipt, _, _) = harness
        .make_message(&mut mmr, 1, 0)
        .context("building baseline message for CBOR determinism")?;

    assert_cbor_determinism(&msg, "MSG")?;
    assert_cbor_determinism(&receipt, "RECEIPT")?;

    let attachments = [
        b"deterministic attachment 1".to_vec(),
        b"deterministic attachment 2".to_vec(),
    ];
    let att_root = AttachmentRoot::from_ciphertexts(attachments.iter().map(Vec::as_slice))
        .ok_or_else(|| anyhow!("expected attachment root for determinism suite"))?;
    let payload_header = PayloadHeader {
        schema: SchemaId::from(veen_overlays::schema_wallet_transfer()),
        parent_id: Some(msg.leaf_hash()),
        att_root: Some(att_root),
        cap_ref: None,
        expires_at: Some(1_900_000_000),
    };
    assert_cbor_determinism(&payload_header, "PayloadHeader")?;

    let wallet_id = WalletId::new([0x11; WALLET_ID_LEN]);
    let realm_id = RealmId::new([0x22; REALM_ID_LEN]);
    let ctx_id = ContextId::new([0x33; 32]);
    let open_event = WalletOpenEvent {
        wallet_id,
        realm_id,
        ctx_id,
        currency: "USD".into(),
        created_at: 1_700_000_000,
    };
    assert_cbor_determinism(&open_event, "WalletOpenEvent")?;

    let transfer_id = TransferId::from([0x44; TRANSFER_ID_LEN]);
    let transfer_event = WalletTransferEvent {
        wallet_id,
        to_wallet_id: WalletId::new([0x55; WALLET_ID_LEN]),
        amount: 250,
        ts: 1_700_000_100,
        transfer_id,
        metadata: Some(Value::Map(vec![
            (Value::Text("count".into()), Value::Integer(2u64.into())),
            (
                Value::Text("note".into()),
                Value::Text("deterministic".into()),
            ),
        ])),
    };
    assert_cbor_determinism(&transfer_event, "WalletTransferEvent")?;

    let deposit_event = WalletDepositEvent {
        wallet_id,
        amount: 500,
        ts: 1_700_000_200,
        reference: Some(ByteBuf::from(b"deterministic-ref".as_slice())),
    };
    assert_cbor_determinism(&deposit_event, "WalletDepositEvent")?;

    let schema_owner = SchemaOwner::from_slice(harness.hub_public())
        .context("constructing schema owner for determinism")?;
    let descriptor = SchemaDescriptor {
        schema_id: SchemaId::from(veen_overlays::schema_wallet_transfer()),
        name: "wallet.transfer".into(),
        version: "v1".into(),
        doc_url: Some("https://example.com/wallet-transfer".into()),
        owner: Some(schema_owner),
        ts: 1_700_000_300,
    };
    assert_cbor_determinism(&descriptor, "SchemaDescriptor")?;

    let label_class = LabelClassRecord {
        label: *harness.label(),
        class: "selftest".into(),
        sensitivity: Some("medium".into()),
        retention_hint: Some(86_400),
    };
    assert_cbor_determinism(&label_class, "LabelClassRecord")?;

    Ok(())
}

fn assert_cbor_determinism<T>(value: &T, label: &str) -> Result<()>
where
    T: Serialize + DeserializeOwned + PartialEq,
{
    let mut baseline = Vec::new();
    ciborium::ser::into_writer(value, &mut baseline)
        .with_context(|| format!("serializing {label} baseline"))?;

    let view: Value = ciborium::de::from_reader(baseline.as_slice())
        .with_context(|| format!("decoding {label} baseline"))?;
    enforce_canonical_maps(&view, label)?;

    let roundtrip: T = ciborium::de::from_reader(baseline.as_slice())
        .with_context(|| format!("round-tripping {label} baseline"))?;
    ensure!(roundtrip == *value, "{label} round-trip mismatch");

    for iter in 0..3 {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(value, &mut buf)
            .with_context(|| format!("serializing {label} iteration {iter}"))?;
        ensure!(
            buf == baseline,
            "{label} serialization diverged on iteration {iter}",
        );
        let decoded: Value = ciborium::de::from_reader(buf.as_slice())
            .with_context(|| format!("decoding {label} iteration {iter}"))?;
        enforce_canonical_maps(&decoded, label)?;
    }

    Ok(())
}

fn enforce_canonical_maps(value: &Value, label: &str) -> Result<()> {
    match value {
        Value::Map(entries) => {
            let mut prev_key: Option<Vec<u8>> = None;
            let mut seen = HashSet::new();
            for (index, (key, val)) in entries.iter().enumerate() {
                let key_bytes = encode_value(key)
                    .with_context(|| format!("serializing {label} key {index}"))?;
                ensure!(
                    seen.insert(key_bytes.clone()),
                    "{label} contains duplicate CBOR map keys",
                );
                if let Some(prev) = prev_key {
                    ensure!(
                        prev <= key_bytes,
                        "{label} CBOR keys out of canonical order at index {index}",
                    );
                }
                prev_key = Some(key_bytes);
                enforce_canonical_maps(val, label)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                enforce_canonical_maps(item, label)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

fn fuzz_nonce_uniqueness() -> Result<()> {
    let harness = SequenceHarness::new()?;
    let mut rng = StdRng::seed_from_u64(0x5354_4655_5A5Au64);
    let mut seen_pairs = HashSet::new();
    let mut seen_nonces = HashSet::new();
    let mut last_stream_seq = 0u64;

    for client_seq in 1..=512 {
        let prev_ack = if last_stream_seq == 0 {
            0
        } else {
            rng.gen_range(0..=last_stream_seq)
        };
        ensure!(
            prev_ack <= last_stream_seq,
            "prev_ack fuzz input exceeded last observed stream sequence",
        );
        let pair = (prev_ack, client_seq);
        ensure!(
            seen_pairs.insert(pair),
            "duplicate (prev_ack, client_seq) pair generated during fuzz",
        );
        let nonce =
            Msg::derive_body_nonce(harness.label(), prev_ack, &harness.client_id(), client_seq);
        ensure!(
            seen_nonces.insert(nonce),
            "AEAD body nonce repeated for unique (prev_ack, client_seq) pair",
        );
        last_stream_seq += 1;
    }

    let duplicate_pair = (last_stream_seq, last_stream_seq);
    let nonce_first = Msg::derive_body_nonce(
        harness.label(),
        duplicate_pair.0,
        &harness.client_id(),
        duplicate_pair.1,
    );
    let nonce_second = Msg::derive_body_nonce(
        harness.label(),
        duplicate_pair.0,
        &harness.client_id(),
        duplicate_pair.1,
    );
    ensure!(
        nonce_first == nonce_second,
        "nonce derivation must be stable for identical parameters",
    );
    ensure!(
        !seen_nonces.insert(nonce_first),
        "duplicate nonce should not be accepted when parameters repeat",
    );

    Ok(())
}

fn check_mmr_fold_invariance() -> Result<()> {
    for len in 1..=6 {
        let leaves: Vec<LeafHash> = (0..len)
            .map(|idx| LeafHash::new([idx as u8 + 1; 32]))
            .collect();
        let reference_root =
            mmr_root_for(&leaves).ok_or_else(|| anyhow!("expected non-empty leaf set for MMR"))?;

        for split in 1..len {
            let mut mmr = Mmr::new();
            let (left, right) = leaves.split_at(split);
            for leaf in left.iter().chain(right.iter()) {
                mmr.append(*leaf);
            }
            ensure!(
                mmr.root() == Some(reference_root),
                "mmr root mismatch for len={len} split={split}"
            );
        }
    }

    Ok(())
}

fn mmr_root_for(leaves: &[LeafHash]) -> Option<MmrRoot> {
    let mut mmr = Mmr::new();
    for leaf in leaves {
        mmr.append(*leaf);
    }
    mmr.root()
}

fn check_attachment_root_stability() -> Result<()> {
    let ciphertexts: Vec<Vec<u8>> = (0..4).map(|idx| vec![idx as u8; (idx + 1) * 3]).collect();

    let baseline = AttachmentRoot::from_ciphertexts(ciphertexts.iter().map(Vec::as_slice))
        .ok_or_else(|| anyhow!("expected attachment root for baseline"))?;

    for _ in 0..3 {
        let recomputed = AttachmentRoot::from_ciphertexts(ciphertexts.iter().map(Vec::as_slice))
            .ok_or_else(|| anyhow!("expected attachment root while recomputing"))?;
        ensure!(
            recomputed == baseline,
            "attachment root must be deterministic"
        );
    }

    let mut tampered = ciphertexts.clone();
    tampered[2][0] ^= 0xAA;
    let tampered_root = AttachmentRoot::from_ciphertexts(tampered.iter().map(Vec::as_slice))
        .ok_or_else(|| anyhow!("expected attachment root for tampered set"))?;
    ensure!(
        tampered_root != baseline,
        "tampering must alter the attachment root"
    );

    Ok(())
}

fn check_schema_registry_precedence() -> Result<()> {
    let mut rng = OsRng;
    let owner_key = SigningKey::generate(&mut rng);
    let schema_id = SchemaId::from(veen_overlays::schema_wallet_transfer());
    let owner = SchemaOwner::from_slice(owner_key.verifying_key().as_bytes())
        .context("constructing schema owner")?;

    let descriptor_v1 = SchemaDescriptor {
        schema_id,
        name: "wallet.transfer".into(),
        version: "v1".into(),
        doc_url: None,
        owner: Some(owner),
        ts: 1_000,
    };
    let descriptor_v2 = SchemaDescriptor {
        ts: 2_000,
        version: "v2".into(),
        ..descriptor_v1.clone()
    };

    let mut registry = SchemaRegistry::new();
    registry.upsert(descriptor_v1.clone(), 1);
    registry.upsert(descriptor_v2.clone(), 2);
    let stored = registry
        .get(&schema_id)
        .ok_or_else(|| anyhow!("schema descriptor missing after updates"))?;
    ensure!(stored == &descriptor_v2, "newest descriptor must win");

    registry.upsert(descriptor_v1.clone(), 3);
    let stored_after = registry
        .get(&schema_id)
        .ok_or_else(|| anyhow!("schema descriptor missing after precedence check"))?;
    ensure!(
        stored_after == &descriptor_v2,
        "older descriptor must not replace a newer one"
    );

    Ok(())
}

fn run_overlay_scenario() -> Result<()> {
    let mut rng = OsRng;
    let realm = RealmId::derive("selftest-realm");
    let primary_principal = SigningKey::generate(&mut rng);
    let peer_principal = SigningKey::generate(&mut rng);

    let ctx_primary = ContextId::derive(primary_principal.verifying_key().as_bytes(), realm)
        .context("deriving primary context identifier")?;
    let ctx_peer = ContextId::derive(peer_principal.verifying_key().as_bytes(), realm)
        .context("deriving peer context identifier")?;

    let wallet_primary = WalletId::derive(realm, ctx_primary, "USD")
        .context("deriving primary wallet identifier")?;
    let wallet_peer =
        WalletId::derive(realm, ctx_peer, "USD").context("deriving peer wallet identifier")?;

    let open_primary = WalletOpenEvent {
        wallet_id: wallet_primary,
        realm_id: realm,
        ctx_id: ctx_primary,
        currency: "USD".into(),
        created_at: 100,
    };
    let open_peer = WalletOpenEvent {
        wallet_id: wallet_peer,
        realm_id: realm,
        ctx_id: ctx_peer,
        currency: "USD".into(),
        created_at: 110,
    };

    let mut wallet_state_primary = WalletState::new();
    wallet_state_primary
        .apply_open(&open_primary)
        .context("opening primary wallet")?;

    let mut wallet_state_peer = WalletState::new();
    wallet_state_peer
        .apply_open(&open_peer)
        .context("opening peer wallet")?;

    let deposit = WalletDepositEvent {
        wallet_id: wallet_primary,
        amount: 2_000,
        ts: 120,
        reference: None,
    };
    wallet_state_primary
        .apply_deposit(&deposit)
        .context("depositing funds into primary wallet")?;

    let transfer_msg_id = LeafHash::new(h(b"selftest/transfer"));
    let transfer_id =
        TransferId::derive(transfer_msg_id.as_bytes()).context("deriving transfer identifier")?;
    let transfer_event = WalletTransferEvent {
        wallet_id: wallet_primary,
        to_wallet_id: wallet_peer,
        amount: 500,
        ts: 130,
        transfer_id,
        metadata: None,
    };

    wallet_state_primary
        .apply_transfer(&transfer_event)
        .context("debited transfer from primary wallet")?;
    wallet_state_peer
        .apply_transfer(&transfer_event)
        .context("crediting transfer to peer wallet")?;

    ensure!(
        wallet_state_primary.balance() == 1_500,
        "primary wallet balance incorrect"
    );
    ensure!(
        wallet_state_peer.balance() == 500,
        "peer wallet balance incorrect"
    );
    ensure!(wallet_state_primary.exists(), "primary wallet should exist");
    ensure!(wallet_state_peer.exists(), "peer wallet should exist");

    let overlay_stream_id = realm.stream_schema_meta();
    let overlay_label = Label::derive(b"overlay-routing", overlay_stream_id, 0);

    let usage_config = ClientUsageConfig::new(60, 2);
    let mut usage = ClientUsage::new(1_000);
    usage
        .record_message(overlay_label)
        .context("recording first local message usage")?;
    ensure!(
        !usage.should_rotate(1_010, usage_config),
        "single message should not trigger rotation"
    );
    usage
        .record_message(overlay_label)
        .context("recording second local message usage")?;
    ensure!(
        usage.should_rotate(1_020, usage_config),
        "usage limits must request client key rotation"
    );

    let client_id = ClientId::from(*primary_principal.verifying_key().as_bytes());
    let mut observation = ClientObservationIndex::new(usage_config);
    let first_decision = observation
        .observe(client_id, overlay_label, 1_000)
        .context("observing first remote usage")?;
    ensure!(
        !first_decision.is_violation(),
        "first observation should not exceed remote bounds"
    );
    let second_decision = observation
        .observe(client_id, overlay_label, 1_001)
        .context("observing second remote usage")?;
    ensure!(
        second_decision.message_count_exceeded(),
        "second observation must signal rate violation"
    );

    let label_class = LabelClassRecord {
        label: Label::derive(b"overlay-label-class", realm.stream_label_class(), 0),
        class: "user".into(),
        sensitivity: Some("medium".into()),
        retention_hint: Some(86_400),
    };
    ensure!(label_class.has_retention_hint(), "retention hint expected");

    let schema_owner = SchemaOwner::from_slice(primary_principal.verifying_key().as_bytes())
        .context("constructing schema owner")?;
    let descriptor = SchemaDescriptor {
        schema_id: SchemaId::from(veen_overlays::schema_wallet_transfer()),
        name: "wallet.transfer.v1".into(),
        version: "v1".into(),
        doc_url: Some("https://example.com/wallet-transfer".into()),
        owner: Some(schema_owner),
        ts: 1_500,
    };

    let mut registry = SchemaRegistry::new();
    registry.upsert(descriptor.clone(), 7);
    let stored = registry
        .get(&descriptor.schema_id)
        .ok_or_else(|| anyhow!("schema descriptor was not registered"))?;
    ensure!(
        stored == &descriptor,
        "schema registry must retain latest descriptor"
    );

    tracing::info!(
        realm = %realm,
        primary_wallet = %wallet_primary,
        peer_wallet = %wallet_peer,
        "overlay self-test validated wallet, schema, and usage flows",
    );

    Ok(())
}

fn fuzz_truncated_cbor<T>(value: &T, label: &str) -> Result<()>
where
    T: Serialize + DeserializeOwned,
{
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)
        .with_context(|| format!("serializing {label} to CBOR"))?;

    for len in 0..buf.len() {
        let truncated = &buf[..len];
        let result: Result<T, _> = ciborium::de::from_reader(truncated);
        ensure!(
            result.is_err(),
            "truncated {label} payload of length {len} should fail to decode"
        );
    }

    Ok(())
}

fn fuzz_signature_validations(data: &SampleData) -> Result<()> {
    let mut tampered_msg = data.msg.clone();
    tampered_msg.ciphertext[0] ^= 0x55;
    ensure!(
        !tampered_msg.ct_hash_matches(),
        "tampering must break ciphertext hash"
    );
    ensure!(
        tampered_msg.verify_signature().is_err(),
        "tampering must break message signature"
    );

    let mut tampered_receipt = data.receipt.clone();
    tampered_receipt.hub_sig = veen_core::Signature64::new([0u8; 64]);
    ensure!(
        tampered_receipt.verify_signature(&data.hub_public).is_err(),
        "tampering must break receipt signature"
    );

    Ok(())
}
