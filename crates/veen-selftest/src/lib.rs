use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::Serialize;

use veen_core::meta::SchemaRegistry;
use veen_core::wire::message::MSG_VERSION;
use veen_core::wire::receipt::RECEIPT_VERSION;
use veen_core::{
    h, AttachmentRoot, ClientId, ClientObservationIndex, ClientUsage, ClientUsageConfig, Label,
    LabelClassRecord, LeafHash, Mmr, MmrRoot, Msg, PayloadHeader, Profile, Receipt,
    SchemaDescriptor, SchemaId, SchemaOwner, StreamId, TransferId, WalletDepositEvent, WalletId,
    WalletOpenEvent, WalletState, WalletTransferEvent,
};

struct SampleData {
    msg: Msg,
    receipt: Receipt,
    attachments: Vec<Vec<u8>>,
    att_root: AttachmentRoot,
    payload_header: PayloadHeader,
    hub_public: [u8; 32],
    mmr_root: MmrRoot,
    stream_seq: u64,
}

impl SampleData {
    fn generate() -> Result<Self> {
        let mut rng = OsRng;
        let client_signing = SigningKey::generate(&mut rng);
        let hub_signing = SigningKey::generate(&mut rng);

        let profile = Profile::default();
        let profile_id = profile
            .id()
            .context("computing canonical profile identifier")?;

        let stream_id = StreamId::from(h(b"selftest/core/stream"));
        let label = Label::derive(b"selftest-routing", stream_id, 0);
        let client_id = ClientId::from(*client_signing.verifying_key().as_bytes());

        let ciphertext = b"selftest ciphertext payload".repeat(4);
        let ct_hash = veen_core::CtHash::compute(&ciphertext);

        let mut msg = Msg {
            ver: MSG_VERSION,
            profile_id,
            label,
            client_id,
            client_seq: 1,
            prev_ack: 0,
            auth_ref: None,
            ct_hash,
            ciphertext,
            sig: veen_core::Signature64::new([0u8; 64]),
        };

        let msg_digest = msg
            .signing_tagged_hash()
            .context("computing message signing digest")?;
        let msg_signature = client_signing.sign(msg_digest.as_ref());
        msg.sig = veen_core::Signature64::from(msg_signature.to_bytes());

        let attachments: Vec<Vec<u8>> = vec![
            b"attachment ciphertext 1".to_vec(),
            b"attachment ciphertext 2".to_vec(),
        ];
        let att_root = AttachmentRoot::from_ciphertexts(attachments.iter().map(Vec::as_slice))
            .ok_or_else(|| anyhow!("expected non-empty attachment set"))?;

        let payload_header = PayloadHeader {
            schema: SchemaId::from(veen_core::schema_wallet_transfer()),
            parent_id: None,
            att_root: Some(att_root),
            cap_ref: None,
            expires_at: None,
        };

        let mut mmr = Mmr::new();
        let (stream_seq, mmr_root) = mmr.append(msg.leaf_hash());

        let mut receipt = Receipt {
            ver: RECEIPT_VERSION,
            label,
            stream_seq,
            leaf_hash: msg.leaf_hash(),
            mmr_root,
            hub_ts: 1_700_000_000,
            hub_sig: veen_core::Signature64::new([0u8; 64]),
        };

        let receipt_digest = receipt
            .signing_tagged_hash()
            .context("computing receipt signing digest")?;
        let receipt_signature = hub_signing.sign(receipt_digest.as_ref());
        receipt.hub_sig = veen_core::Signature64::from(receipt_signature.to_bytes());

        Ok(Self {
            msg,
            receipt,
            attachments,
            att_root,
            payload_header,
            hub_public: *hub_signing.verifying_key().as_bytes(),
            mmr_root,
            stream_seq,
        })
    }
}

/// Execute the core protocol self-test invariants described in the CLI goal.
pub fn run_core() -> Result<()> {
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

    tracing::info!(
        label = %data.msg.label,
        stream_seq = data.stream_seq,
        mmr_root = %data.mmr_root,
        "core protocol self-test satisfied invariants",
    );

    Ok(())
}

/// Execute property-style checks over deterministic scenarios.
pub fn run_props() -> Result<()> {
    check_mmr_fold_invariance()?;
    check_attachment_root_stability()?;
    check_schema_registry_precedence()?;
    run_overlay_scenario()?;

    tracing::info!("property-based VEEN self-tests completed");
    Ok(())
}

/// Execute basic fuzz-style checks by mutating valid artefacts.
pub fn run_fuzz() -> Result<()> {
    let data = SampleData::generate()?;

    fuzz_truncated_cbor(&data.msg, "MSG")?;
    fuzz_truncated_cbor(&data.receipt, "RECEIPT")?;
    fuzz_signature_validations(&data)?;

    tracing::info!("fuzz-style VEEN self-tests completed");
    Ok(())
}

/// Run the complete self-test suite (core + props + fuzz).
pub fn run_all() -> Result<()> {
    run_core()?;
    run_props()?;
    run_fuzz()?;
    tracing::info!("all VEEN self-test suites completed successfully");
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
    let schema_id = SchemaId::from(veen_core::schema_wallet_transfer());
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
    let realm = veen_core::RealmId::derive("selftest-realm");
    let primary_principal = SigningKey::generate(&mut rng);
    let peer_principal = SigningKey::generate(&mut rng);

    let ctx_primary =
        veen_core::ContextId::derive(primary_principal.verifying_key().as_bytes(), realm)
            .context("deriving primary context identifier")?;
    let ctx_peer = veen_core::ContextId::derive(peer_principal.verifying_key().as_bytes(), realm)
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
        schema_id: SchemaId::from(veen_core::schema_wallet_transfer()),
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
