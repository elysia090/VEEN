use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

use veen_core::{
    h, AttachmentRoot, ClientId, Label, Msg, PayloadHeader, Profile, ProfileId, Receipt, SchemaId,
    StreamId,
};

pub(crate) struct SampleData {
    pub(crate) msg: Msg,
    pub(crate) receipt: Receipt,
    pub(crate) attachments: Vec<Vec<u8>>,
    pub(crate) att_root: AttachmentRoot,
    pub(crate) payload_header: PayloadHeader,
    pub(crate) hub_public: [u8; 32],
    pub(crate) mmr_root: veen_core::MmrRoot,
    pub(crate) stream_seq: u64,
}

impl SampleData {
    pub(crate) fn generate() -> Result<Self> {
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
            ver: veen_core::wire::message::MSG_VERSION,
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

        let mut mmr = veen_core::Mmr::new();
        let (stream_seq, mmr_root) = mmr.append(msg.leaf_hash());

        let mut receipt = Receipt {
            ver: veen_core::wire::receipt::RECEIPT_VERSION,
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

pub(crate) struct SequenceHarness {
    client_signing: SigningKey,
    hub_signing: SigningKey,
    profile_id: ProfileId,
    label: Label,
    client_id: ClientId,
    hub_public: [u8; 32],
}

impl SequenceHarness {
    pub(crate) fn new() -> Result<Self> {
        let mut rng = OsRng;
        let client_signing = SigningKey::generate(&mut rng);
        let hub_signing = SigningKey::generate(&mut rng);

        let profile = Profile::default();
        let profile_id = profile
            .id()
            .context("computing canonical profile identifier for sequence harness")?;

        let stream_id = StreamId::from(h(b"selftest/core/sequence"));
        let label = Label::derive(b"selftest-seq", stream_id, 0);
        let client_id = ClientId::from(*client_signing.verifying_key().as_bytes());
        let hub_public = *hub_signing.verifying_key().as_bytes();

        Ok(Self {
            client_signing,
            hub_signing,
            profile_id,
            label,
            client_id,
            hub_public,
        })
    }

    pub(crate) fn make_message(
        &self,
        mmr: &mut veen_core::Mmr,
        client_seq: u64,
        prev_ack: u64,
    ) -> Result<(Msg, Receipt, u64, veen_core::MmrRoot)> {
        let ciphertext = format!("selftest-seq-{client_seq}-ack-{prev_ack}").into_bytes();
        let ct_hash = veen_core::CtHash::compute(&ciphertext);

        let mut msg = Msg {
            ver: veen_core::wire::message::MSG_VERSION,
            profile_id: self.profile_id,
            label: self.label,
            client_id: self.client_id,
            client_seq,
            prev_ack,
            auth_ref: None,
            ct_hash,
            ciphertext,
            sig: veen_core::Signature64::new([0u8; 64]),
        };

        let msg_digest = msg
            .signing_tagged_hash()
            .context("computing signing digest for harness message")?;
        let signature = self.client_signing.sign(msg_digest.as_ref());
        msg.sig = veen_core::Signature64::from(signature.to_bytes());

        let leaf = msg.leaf_hash();
        let (stream_seq, mmr_root) = mmr.append(leaf);

        let mut receipt = Receipt {
            ver: veen_core::wire::receipt::RECEIPT_VERSION,
            label: self.label,
            stream_seq,
            leaf_hash: msg.leaf_hash(),
            mmr_root,
            hub_ts: 1_800_000_000,
            hub_sig: veen_core::Signature64::new([0u8; 64]),
        };

        let receipt_digest = receipt
            .signing_tagged_hash()
            .context("computing signing digest for harness receipt")?;
        let hub_signature = self.hub_signing.sign(receipt_digest.as_ref());
        receipt.hub_sig = veen_core::Signature64::from(hub_signature.to_bytes());

        Ok((msg, receipt, stream_seq, mmr_root))
    }

    pub(crate) fn hub_public(&self) -> &[u8; 32] {
        &self.hub_public
    }

    pub(crate) fn label(&self) -> &Label {
        &self.label
    }

    pub(crate) fn client_id(&self) -> ClientId {
        self.client_id
    }
}
