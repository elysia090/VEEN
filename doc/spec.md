# VEEN Specification (SSOT)

This document is the single source of truth (SSOT) for VEEN. `doc/reference.md` is an archived legacy reference and is non-normative.

## 0. Purpose and scope

- **Purpose:** Integrate the VEEN core, overlays, operations, and product profiles in a structured, unambiguous specification.
- **Scope:** v0.0.1 core, v0.0.1+ / v0.0.1++ overlays, CLI/operations, and product profiles (SDR0/AGB0).
- **Invariant:** Every external API/CLI operation MUST be **O(1)** or **O(polylog n)**. Linear scans and sequential replays on hot paths are non-compliant.

## 1. Terms and naming (clarified and compatible)

- **Hub:** Relay node that admits, orders, and proves messages. It does not interpret payload semantics.
- **StreamID:** Application-defined logical stream identifier (32 bytes).
- **Label:** Physical stream identifier ordered by a Hub. `Label = Ht("veen/label", routing_key || StreamID || epoch)`.
- **StreamSeq:** Monotonic sequence per Label.
- **ClientID:** Ed25519 public key (verification key for `MSG.sig`).
- **ClientSeq:** Monotonic sequence per `(Label, ClientID)`.
- **ProfileID:** Hash of the cryptographic profile definition.
- **CapToken:** Capability token expressing authorization, TTL, and rate.

**Backward-compatibility rules (normative)**
- CLI: `veen` is canonical. `veen-cli` is an equivalent alias. `veen hub start` is canonical. Legacy `veen-hub run/start` are accepted aliases.
- Versioning: v0.0.1 is immutable core. v0.0.1+ and v0.0.1++ are additive only (no redefinition or overrides).

## 2. Global conventions

### 2.1 Encoding
- **CBOR must be deterministic:** fixed field order, minimal integers, fixed-length `bstr`, no tags, reject unknown keys.

### 2.2 Cryptographic profile (minimum requirements)
- Hash: SHA-256
- HKDF: HKDF-SHA256
- AEAD: XChaCha20-Poly1305 (payload)
- Signature: Ed25519
- DH: X25519
- HPKE: RFC9180 base (X25519-HKDF-SHA256 + ChaCha20-Poly1305)

**ProfileID** is computed as `Ht("veen/profile", CBOR(profile_params))`.

### 2.3 Performance invariants (O(1)/polylog n)
All external operations (submit, read, prove, query, inspect, revoke, wallet/ID, etc.) MUST be **O(1)** or **O(polylog n)**. Any O(n) or scan-based path is prohibited for the external surface.

- **Minimize sequential dependence:** folds MUST be associative `merge(S_left, S_right)` so that evaluation is tree-structured.
- **Range summaries:** store K-sized chunk summaries so `fold(range)` is **O(polylog n)**.
- **Head index:** O(1) access to the latest `(StreamSeq, leaf_hash, checkpoint_ref)` per Label.
- **No hidden linearity:** internal maintenance MAY be incremental, but any O(n) work MUST be amortized off the critical path and MUST NOT be observable in an external API/CLI.

### 2.4 Architecture boundaries and dependency minimization
- **Core protocol layer:** wire objects (MSG/RECEIPT/CHECKPOINT), ordering, and proofs. Depends only on crypto, CBOR, and append-only storage.
- **Storage/index layer:** append-only log, MMR, per-label indices, and checkpoint snapshots. No dependency on overlays or application schemas.
- **Overlay layer:** identity, wallet, query, products. Depends only on core proofs and indexed log access. No dependency on hub runtime internals.
- **Operational tooling layer:** CLI, bridge, self-test. Depends on public APIs only. No privileged coupling to implementation-specific storage.
- **No cross-layer leakage:** overlays must not reach into hub storage internals; core must not interpret overlay semantics.

## 3. Core wire specification (v0.0.1)

### 3.1 MSG (submit)
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

### 3.2 Ciphertext generation (normative)
- `payload_hdr` and `body` are protected with HPKE + AEAD.
- Nonce = `Trunc_24(Ht("veen/nonce", label || prev_ack || client_id || client_seq))`.

### 3.3 RECEIPT (admission proof)
- Hub-issued proof that a MSG was admitted. MUST include hub signature, `StreamSeq`, and MMR root.
- Third-party verification MUST be possible after admission.

### 3.4 CHECKPOINT (log snapshot)
- Includes `log_root`, per-stream `last_seq`, `hub_pk`, and `timestamp`.
- MUST be consistent with the MMR.

### 3.5 MMR and proofs
- MMR provides inclusion proofs in **O(polylog n)**.
- Proofs MUST be deterministic and reproducible.

## 4. Hub normative behavior

### 4.1 Admission path
- Validate `CapToken` (signature/expiry/rate/revocation)
- Enforce monotonic `client_seq`
- Assign `StreamSeq` for the target `label`
- Issue a RECEIPT after admission

### 4.2 Log/MMR
- Append-only in admission order
- Update MMR root at each admission

### 4.3 Errors
- Rejections return deterministic error codes (e.g., `E.AUTH`, `E.RATE`, `E.SEQ`, `E.TIME`, `E.FORMAT`).

## 5. Client behavior

- **Submit:** build MSG, sign, send, verify RECEIPT.
- **Read:** provide `stream(range)` and `stream(with_proof=1)`.
- **Verify:** independent verification using RECEIPT/PROOF/CHECKPOINT.

## 6. Overlays (v0.0.1+ / v0.0.1++)

### 6.1 Identity (ID)
- **Subjects/devices/contexts/orgs/groups/handles** are log-derived state.
- Sessions are verifiable via **device key + cap_token chain + ID log**.
- Revocation is deterministically evaluated from ID logs.

### 6.2 Wallet / paid operations
- **Balances/limits/freezes/adjustments** are derived solely from event folds.
- Hubs do not store balances; operational consistency is ensured by the overlay.

### 6.3 Query API overlay
- Provide **structured queries** over log-derived state.
- All searchable fields require **persistent indices**; full scans are forbidden.

### 6.4 Product overlays (SDR0 / AGB0)
- **SDR0:** audit/evidence logging with `record/*` streams, checkpoints, and replay API.
- **AGB0:** air-gap bridge via `export/*` → `import/*` unidirectional/bidirectional transfer.
- Both require **CapToken/Revocation/Checkpoint** governance.

### 6.5 Auxiliary overlays (operational)
- **KEX0:** key exchange/share log.
- **AUTH1:** authorization/revocation base log.
- **ANCHOR0:** external anchoring of audit roots.
- **DR0:** disaster recovery support log.
- **OBS0:** observability/operations metrics log.

## 7. CLI (operational API)

**Canonical primitives (necessary and sufficient)**

**Hub control**
- `veen hub start|stop|status` (legacy `veen-hub` accepted)

**Data plane**
- `veen send` (submit MSG)
- `veen stream` (range read)
- `veen receipt` (fetch/verify receipts)
- `veen proof` (fetch inclusion proofs)
- `veen checkpoint` (create/fetch/verify checkpoints)

**Authorization and policy**
- `veen cap issue|revoke|inspect` (CapToken lifecycle)
- `veen revocation list|check` (revocation view)

**Operations**
- `veen bridge` (or `veen-bridge`)
- `veen selftest` (or `veen-selftest`)
- `veen inspect` (local state and index health)

**CLI invariants**
- `--hub` accepts a URL or local hub data directory.
- If `--data-dir` is provided, it is authoritative for hub control commands.
- All CLI operations MUST uphold O(1)/O(polylog n) behavior.

## 8. Operations and deployment

- **OS:** Linux / WSL2 / Docker / k8s / k3s with identical semantics.
- **Data:** hub data directory is a plain, portable directory.
- **Observability:** admission latency, proof generation time, and fsync time are core metrics.
- **Availability:** hubs are disposable; logs are the sole source of truth.

## 9. Security model

- **Trust boundary:** client keys, hub public keys, signatures, and MMR roots.
- **Confidentiality:** payloads are AEAD/HPKE protected and opaque to the hub.
- **Integrity:** guaranteed by MSG signatures and hub signatures.
- **Revocation/rotation:** deterministically evaluated via overlays and CapTokens.

## 10. Evolution and compatibility

- Additive fields/errors are **backward compatible**.
- Reinterpreting existing logs to change semantics is forbidden.

## 11. Non-goals

- General-purpose compute or smart contracts
- Blockchain-style consensus
- Deep packet inspection or L7 routing

## 12. Required data structures (non-exhaustive)

- **MMR:** inclusion proofs in O(polylog n).
- **Persistent indices:** Label/StreamSeq/ClientSeq/Query fields.
- **Summaries:** chunk summaries + merge trees for fast folds.
- **Ordered sets:** y-fast tries, vEB trees, or rank/select bitsets for predecessor/successor queries.
- **Fenwick/segment trees:** polylog fold and range aggregation.
- **Caches:** TTL caches for CapToken/issuer/public keys.

---

**Note:** `doc/reference.md` preserves the legacy text for historical reference and does not affect this SSOT.
