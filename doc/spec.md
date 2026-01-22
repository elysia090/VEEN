# VEEN Specification (SSOT) — v0.0.1

This document is the single source of truth for VEEN v0.0.1. `doc/reference.md` is legacy, non-normative context only.

The v0.0.1 core is **fixed and immutable**. All optional features are expressed as **profiles/overlays within v0.0.1** and MUST NOT change core wire objects or invariants.

---

## 0. Design intent (normative)

VEEN is an **ephemeral, verifiable, reproducible network fabric**.

**Core principles (MUST):**
- **Ephemeral fabric:** Networks are disposable; hubs are replaceable processes. Logs and receipts are the durable truth.
- **Verifiability:** Every accepted message yields a signed RECEIPT and is committed into an authenticated log with compact proofs.
- **Reproducibility:** Any retained log prefix deterministically reproduces the same overlay state on any conforming implementation.
- **Determinism:** Admission decisions and folds are deterministic given the same log state and configured limits.
- **Portability:** The same data directory and keys define the fabric, independent of OS, runtime, or topology.
- **Minimal core:** Hubs order and prove; they do not interpret payload semantics.

**Primary outcomes (MUST be supported):**
- **Clone:** Copy a data directory and pinned keys to reproduce the same fabric.
- **Fork:** Retain a prefix and diverge; both forks remain verifiable.
- **Replay:** Recompute overlay state from logs or checkpoints without hidden state.
- **Interpret:** Apply new overlays to old logs without hub changes.

---

## 1. Scope, versioning, and compatibility

- **Version:** This specification defines **v0.0.1**. There is no v0.0.1+ or v0.0.1++ in the normative spec.
- **Immutability:** Wire encoding and invariants in v0.0.1 MUST NOT change.
- **Additions:** New functionality MUST be implemented as overlay schemas or operational tooling that do not alter core objects.
- **Compatibility:** Older logs remain valid and verifiable forever.

---

## 2. Terms and identifiers

- **Hub:** Orders and proves messages; does not interpret payload semantics.
- **StreamID:** Application-defined logical stream identifier (bstr(32)).
- **Label:** Physical routing identifier ordered by a Hub:
  `label = Ht("veen/label", routing_key || stream_id || u64be(epoch))`.
- **StreamSeq:** Monotonic sequence number per Label (1-based).
- **ClientID:** Ed25519 public key that verifies `MSG.sig`.
- **ClientSeq:** Monotonic sequence per `(label, client_id)`.
- **ProfileID:** Hash of profile parameters (`Ht("veen/profile", CBOR(profile))`).
- **CapToken:** Capability token for authorization and admission limits.
- **MsgID / leaf_hash:** `Ht("veen/leaf", label || profile_id || ct_hash || client_id || u64be(client_seq))`.

---

## 3. Global conventions (strict)

### 3.1 Deterministic CBOR
- Fixed field order as defined here.
- Minimal-length integers.
- Definite-length arrays and byte strings only.
- No tags, no floats.
- Unknown keys are rejected.

### 3.2 Cryptographic profile (minimum)
- Hash: SHA-256
- HKDF: HKDF-SHA256
- AEAD: XChaCha20-Poly1305 (payload body)
- Signature: Ed25519
- DH: X25519
- HPKE: RFC9180 base (X25519-HKDF-SHA256 + ChaCha20-Poly1305) for payload header

**ProfileID** MUST be computed as `Ht("veen/profile", CBOR(profile))` and carried in every MSG.

### 3.3 Performance contract (normative)
Every external API/CLI operation MUST be **O(1)** or **O(polylog n)**. Any linear scan or sequential replay on a hot path is non-compliant.

Required structures:
- Per-label head index
- Persistent secondary indices
- MMR peaks cache
- Chunk summaries + merge trees

No internal linearity may be observable by external callers.

### 3.4 Architecture boundaries
- **Core protocol:** wire objects, ordering, proofs. Depends only on crypto, CBOR, append-only storage.
- **Storage/index:** append-only log, MMR, indices. No overlay semantics.
- **Overlays:** pure folds over logs. No access to hub internals.
- **Operational tooling:** uses public APIs only.

---

## 4. Core wire specification (v0.0.1)

### 4.1 MSG (submit)
Fixed field order:
1. `ver` (uint=1)
2. `profile_id` (bstr32)
3. `label` (bstr32)
4. `client_id` (bstr32)
5. `client_seq` (uint, strictly +1)
6. `prev_ack` (uint)
7. `auth_ref` (bstr32, optional)
8. `ct_hash` (bstr32)
9. `ciphertext` (bstr)
10. `sig` (bstr64) = `Sig(client_id, Ht("veen/sig", CBOR(MSG without sig)))`

### 4.2 Ciphertext construction (normative)
1. `enc, ctx = HPKE.SealSetup(pkR)` (enc is 32 bytes).
2. `hpke_ct_hdr = HPKE.Seal(ctx, "", CBOR(payload_hdr))`.
3. `k_body = HPKE.Export(ctx, "veen/body-k", 32)`.
4. `nonce = Trunc_24(Ht("veen/nonce", label || u64be(prev_ack) || client_id || u64be(client_seq)))`.
5. `aead_ct_body = AEAD_Encrypt(k_body, nonce, "", body)`.
6. `hdr_len = u32be(len(hpke_ct_hdr))`.
7. `body_len = u32be(len(aead_ct_body))`.
8. `ciphertext = enc || hdr_len || body_len || hpke_ct_hdr || aead_ct_body`.
9. If `pad_block > 0`, right-pad with zeros to a multiple of `pad_block` (padding bytes are unauthenticated zeros).
10. `ct_hash = H(ciphertext)`.
11. `leaf_hash = Ht("veen/leaf", label || profile_id || ct_hash || client_id || u64be(client_seq))`.

### 4.3 RECEIPT (admission proof)
Fixed field order:
1. `ver` (uint=1)
2. `label` (bstr32)
3. `stream_seq` (uint)
4. `leaf_hash` (bstr32)
5. `mmr_root` (bstr32)
6. `hub_ts` (uint)
7. `hub_sig` (bstr64) = `Sig(hub_pk, Ht("veen/sig", CBOR(RECEIPT without hub_sig)))`

### 4.4 CHECKPOINT (log snapshot)
Fixed field order:
1. `ver` (uint=1)
2. `label_prev` (bstr32)
3. `label_curr` (bstr32)
4. `upto_seq` (uint)
5. `mmr_root` (bstr32)
6. `epoch` (uint)
7. `hub_sig` (bstr64)
8. `witness_sigs` ([bstr64], optional)

### 4.5 Payload header (encrypted)
CBOR(payload_hdr) fields:
1. `schema` (bstr32)
2. `parent_id` (bstr32, optional)
3. `att_root` (bstr32, optional)
4. `cap_ref` (bstr32, optional)
5. `expires_at` (uint, optional)

The hub never sees payload_hdr in plaintext.

### 4.6 Attachments
- Attachment `i` uses `k_att = HPKE.Export(ctx, "veen/att-k" || u64be(i), 32)`.
- Nonce `n_att = Trunc_24(Ht("veen/att-nonce", msg_id || u64be(i)))`.
- `coid = H(AEAD_Encrypt(k_att, n_att, "", attachment))`.
- `att_root` is a Merkle root over ordered `coid` values.

---

## 5. MMR and proofs

### 5.1 MMR update (per label)
- Append `leaf_hash` in stream order, update peaks.
- `mmr_root` is either the single peak or `Ht("veen/mmr-root", concat(peaks))`.

### 5.2 Inclusion proof
`mmr_proof` is a deterministic CBOR object containing the path and peaks.
Verification MUST reproduce the `mmr_root` recorded in a RECEIPT or CHECKPOINT.

---

## 6. Capability tokens (CapToken)

cap_token CBOR map:
```
{
  ver: 1,
  issuer_pk: bstr(32),
  subject_pk: bstr(32),
  allow: {
    stream_ids: [ bstr(32), ... ],
    ttl: uint,
    rate: { per_sec: uint, burst: uint }?
  },
  sig_chain: [ bstr(64), ... ]
}
```

Rules:
- `allow.stream_ids` MUST be non-empty.
- `auth_ref = Ht("veen/cap", CBOR(cap_token))`.
- `MSG.auth_ref` MUST equal `payload_hdr.cap_ref` if `cap_ref` is present.
- Hubs MUST verify all signatures in `sig_chain` and enforce TTL and rate limits.
- If a deployment cannot map `label -> stream_id`, it MUST document that hub-side stream scoping is disabled; clients MUST enforce scoping after decrypt.

---

## 7. Core invariants (MUST)

For any accepted (MSG, RECEIPT) pair:
- **I1:** `H(ciphertext) = ct_hash`.
- **I2:** `leaf_hash = Ht("veen/leaf", label || profile_id || ct_hash || client_id || u64be(client_seq))`.
- **I3:** `mmr_root` matches the MMR after appending `leaf_hash` at `stream_seq`.
- **I4:** `profile_id` is supported.
- **I5:** If `att_root` exists, it matches the ordered attachment Merkle root.
- **I6:** `prev_ack <=` last observed stream_seq for the label at admission.
- **I7:** Capability constraints (TTL, rate, revocation) are satisfied.
- **I8:** `(label, client_id, client_seq)` is unique across accepted MSG.
- **I9:** For each `(label, client_id)`, `client_seq` increases by exactly 1.
- **I10:** Deterministic CBOR rules are enforced.
- **I11:** Size limits (max msg/header/body/attachments) are enforced deterministically.
- **I12:** Epoch validity for labels (clock skew bounds) is enforced if epoching is enabled.

Any violation MUST be rejected with a deterministic error code.

---

## 8. Hub behavior (normative)

### 8.1 Admission pipeline (strict order)
1. **Prefilter:** size caps, optional stateless rejection (rate/PoW).
2. **Structural checks:** CBOR determinism, field sizes, ver/profile_id.
3. **Auth checks:** `MSG.sig`, CapToken validation, TTL/rate/revocation.
4. **Commit:** append to MMR, issue RECEIPT, persist log entries.

### 8.2 Errors
Return deterministic error codes:
- `E.FORMAT`, `E.SIZE`, `E.SIG`, `E.CAP`, `E.AUTH`, `E.RATE`, `E.SEQ`, `E.TIME`.

### 8.3 Disallowed behaviors
- Inspecting decrypted payload to make admission decisions.
- Linear scans or sequential replays on any external operation path.
- Hidden state that cannot be reconstructed from logs and checkpoints.

---

## 9. Client behavior (normative)

- **Submit:** build MSG, sign, send, verify RECEIPT, update `prev_ack` and local MMR.
- **Read:** request `stream` ranges with optional proofs; verify receipts and proofs.
- **Decrypt:** parse ciphertext, verify padding rules, decrypt payload_hdr and body.
- **Resync:** if receipts diverge, re-fetch checkpoints and rebuild local MMR and state.

---

## 10. Data plane API (minimal and strict)

The data plane is intentionally minimal and deterministic. All endpoints MUST satisfy the O(1)/polylog requirement.

### 10.1 Required operations
- **submit**: accept MSG, return RECEIPT or deterministic error.
- **stream**: range read by `(label, from_seq, to_seq)` with optional proofs.
- **receipt**: fetch RECEIPT by `(label, stream_seq)`.
- **proof**: fetch `mmr_proof` by `(label, stream_seq)`.
- **checkpoint**: create/fetch/verify CHECKPOINT at `(label, upto_seq)`.

### 10.2 Determinism requirements
- Range reads MUST be index-bounded and never scan unindexed history.
- Proof generation MUST be deterministic and reproducible.
- Stream replay order is strictly by `stream_seq`.

---

## 11. Overlay framework (v0.0.1)

Overlays are **pure folds over logs**. They MUST:
- Depend only on `(payload_hdr.schema, payload body bytes, stream order)`.
- Provide deterministic conflict resolution (e.g., LWW with stream_seq tie-breaker).
- Be replayable and interpretable without hub changes.

### 11.1 Required overlay properties
- **Deterministic fold:** `fold(range)` is associative and supports merge from summaries.
- **Explicit ordering:** if timestamps exist, order by `(timestamp, stream_seq, tie-breaker)`.
- **Deduplication:** define stable keys for replay/mirror deduplication.
- **No hidden state:** any derived state can be rebuilt from logs/checkpoints.

### 11.2 Canonical overlay classes (non-exhaustive)
- **Identity (ID):** subjects/devices/contexts/orgs/groups/handles as log-derived state.
- **Wallet:** balances/limits/freezes/adjustments are log folds, no hub-side balances.
- **Authorization/Revocation:** cap_token lifecycle and revocation logs.
- **Query:** structured queries over indexed fields; no full scans.
- **Products:** audit/evidence logging, air-gap bridges, anchoring, disaster recovery.

Overlays are optional but MUST NOT change core wire objects or invariants.

---

## 12. Operational requirements

- **OS portability:** Linux/WSL2/Docker/k8s/k3s with identical semantics.
- **Data portability:** hub data directory is a portable, auditable directory.
- **Observability:** admission latency, proof time, and fsync time are core metrics.
- **Disposability:** hubs can be destroyed and rebuilt from logs at any time.

---

## 13. Non-goals

- General-purpose compute or smart contracts
- Consensus protocols or blockchain semantics
- Deep packet inspection or payload routing

---

**Note:** `doc/reference.md` is preserved for historical context and does not alter this SSOT.
