use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tracing_subscriber::EnvFilter;

use veen_core::meta::SchemaRegistry;
use veen_core::wire::message::MSG_VERSION;
use veen_core::wire::receipt::RECEIPT_VERSION;
use veen_core::{
    h, AttachmentRoot, ClientId, ClientObservationIndex, ClientUsage, ClientUsageConfig, ContextId,
    Label, LabelClassRecord, LeafHash, Mmr, Msg, PayloadHeader, Profile, RealmId, Receipt,
    SchemaDescriptor, SchemaId, SchemaOwner, StreamId, TransferId, WalletDepositEvent, WalletId,
    WalletOpenEvent, WalletState, WalletTransferEvent,
};

#[derive(Parser)]
#[command(name = "veen-selftest", version, about = "Integration harness for VEEN", long_about = None)]
struct Cli {
    #[command(subcommand)]
    suite: Suite,
}

#[derive(Subcommand)]
enum Suite {
    /// Execute the core protocol acceptance tests.
    Core,
    /// Execute overlay scenarios layered on top of the core protocol.
    Overlays,
    /// Execute all suites.
    All,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.suite {
        Suite::Core => run_core().await,
        Suite::Overlays => run_overlays().await,
        Suite::All => run_all().await,
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}

async fn run_core() -> Result<()> {
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

    ensure!(msg.has_valid_version(), "unexpected message version");
    ensure!(
        msg.ct_hash_matches(),
        "ciphertext hash does not match payload bytes"
    );
    msg.verify_signature()
        .context("verifying client signature on message")?;

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
    ensure!(
        payload_header.att_root == Some(att_root),
        "attachment root must be recorded in payload header"
    );

    let recomputed_root = AttachmentRoot::from_ciphertexts(attachments.iter().map(Vec::as_slice))
        .ok_or_else(|| anyhow!("failed to recompute attachment root"))?;
    ensure!(
        recomputed_root == att_root,
        "attachment Merkle root mismatch during verification"
    );

    let mut tampered_first = attachments[0].clone();
    tampered_first[0] ^= 0xFF;
    let tampered_root = AttachmentRoot::from_ciphertexts(
        [tampered_first.as_slice(), attachments[1].as_slice()].into_iter(),
    );
    ensure!(
        tampered_root != Some(att_root),
        "tampering with attachment ciphertext must change att_root"
    );

    let mut mmr = Mmr::new();
    let (stream_seq, mmr_root) = mmr.append(msg.leaf_hash());
    ensure!(
        stream_seq == 1,
        "first message must yield stream sequence 1"
    );

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

    ensure!(
        receipt.has_valid_version(),
        "receipt version deviates from specification"
    );
    ensure!(
        receipt.leaf_hash == msg.leaf_hash(),
        "receipt leaf hash must match message leaf hash"
    );
    ensure!(
        receipt.mmr_root == mmr_root,
        "receipt must commit to the current MMR root"
    );

    receipt
        .verify_signature(hub_signing.verifying_key().as_bytes())
        .context("verifying hub receipt signature")?;

    tracing::info!(
        label = %label,
        stream_seq,
        mmr_root = %mmr_root,
        "core protocol self-test satisfied invariants"
    );

    Ok(())
}

async fn run_overlays() -> Result<()> {
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
    ensure!(
        wallet_state_primary.exists(),
        "primary wallet should exist after operations"
    );
    ensure!(
        wallet_state_peer.exists(),
        "peer wallet should exist after operations"
    );

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
    ensure!(
        label_class.has_retention_hint(),
        "retention hint expected for label class"
    );

    let schema_id = SchemaId::from(veen_core::schema_wallet_transfer());
    let schema_owner = SchemaOwner::from_slice(primary_principal.verifying_key().as_bytes())
        .context("constructing schema owner")?;
    let descriptor = SchemaDescriptor {
        schema_id,
        name: "wallet.transfer.v1".into(),
        version: "v1".into(),
        doc_url: Some("https://example.com/wallet-transfer".into()),
        owner: Some(schema_owner),
        ts: 1_500,
    };

    let mut registry = SchemaRegistry::new();
    registry.upsert(descriptor.clone(), 7);
    let stored = registry
        .get(&schema_id)
        .ok_or_else(|| anyhow!("schema descriptor was not registered"))?;
    ensure!(
        stored == &descriptor,
        "schema registry must retain latest descriptor"
    );

    tracing::info!(
        realm = %realm,
        primary_wallet = %wallet_primary,
        peer_wallet = %wallet_peer,
        "overlay self-test validated wallet, schema, and usage flows"
    );

    Ok(())
}

async fn run_all() -> Result<()> {
    run_core().await?;
    run_overlays().await?;
    tracing::info!("all VEEN self-test suites completed successfully");
    Ok(())
}
