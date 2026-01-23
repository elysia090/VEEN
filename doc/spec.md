# VEEN Specification (SSOT) — v0.0.1

This document is the single source of truth for VEEN v0.0.1. `doc/reference.md` is legacy, non-normative context only.

The v0.0.1 core is **fixed and immutable**. All optional features are expressed as **profiles/overlays within v0.0.1** and MUST NOT change core wire objects or invariants.

---

## 0. Design intent (normative)

VEEN is an **ephemeral, verifiable, reproducible network fabric**.
It targets the **intermediate space between CRUD, KV, and Queue**, while being **end-to-end encrypted** and **disposable** by design.

**Core principles (MUST):**
- **Ephemeral fabric:** Networks are disposable; hubs are replaceable processes. Logs and receipts are the durable truth.
- **Verifiability:** Every accepted message yields a signed RECEIPT and is committed into an authenticated log with compact proofs.
- **Reproducibility:** Any retained log prefix deterministically reproduces the same overlay state on any conforming implementation.
- **Determinism:** Admission decisions and folds are deterministic given the same log state and configured limits.
- **Portability:** The same data directory and keys define the fabric, independent of OS, runtime, or topology.
- **Minimal core:** Hubs order and prove; they do not interpret payload semantics.
- **Typed boundaries:** Types are carried in payload headers and enforced by overlays, never by hubs.
- **Engineering-first rigor:** The spec defines precise constraints, deterministic error handling, and measurable complexity bounds.

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
- **Overlay:** A pure, deterministic fold from logs to typed state, defined by `schema`.
- **Summary:** A compact associative digest of an overlay state used for merge or replay.
- **Epoch:** A routing epoch used to rotate labels without altering StreamID.

---

## 3. Global conventions (strict)

### 3.1 Deterministic CBOR
- Fixed field order as defined here.
- Minimal-length integers.
- Definite-length arrays, maps, and byte strings only.
- No tags, no floats.
- CBOR simple value `null` is allowed **only** as the sentinel for an explicitly optional field.
- Unknown keys are rejected for all CBOR maps defined in this spec.
- Wire objects are encoded as **CBOR arrays** unless explicitly defined as maps.
- Any CBOR map in this spec uses **unsigned integer keys** with ascending key order.

### 3.2 Cryptographic profile (minimum)
- Hash: SHA-256
- HKDF: HKDF-SHA256
- AEAD: XChaCha20-Poly1305 (payload body)
- Signature: Ed25519
- DH: X25519
- HPKE: RFC9180 base (X25519-HKDF-SHA256 + ChaCha20-Poly1305) for payload header

**ProfileID** MUST be computed as `Ht("veen/profile", CBOR(profile))` and carried in every MSG.

`profile` is a CBOR map with integer keys:
```
{
  1: aead,       // tstr
  2: kdf,        // tstr
  3: sig,        // tstr
  4: dh,         // tstr
  5: hpke_suite, // tstr
  6: epoch_sec,  // uint
  7: pad_block,  // uint
  8: mmr_hash    // tstr
}
```

Allowed values for v0.0.1:
- `aead`: `"xchacha20poly1305"`
- `kdf`: `"hkdf-sha256"`
- `sig`: `"ed25519"`
- `dh`: `"x25519"`
- `hpke_suite`: `"X25519-HKDF-SHA256-CHACHA20POLY1305"`
- `mmr_hash`: `"sha256"`

`epoch_sec` is an unsigned integer. Define `epoch = floor(unix_time_sec / epoch_sec)` if `epoch_sec > 0`, otherwise `epoch = 0`. For admission and label validity, the hub MUST use its assigned `hub_ts` as `unix_time_sec`.

`pad_block` is an unsigned integer encoded in the profile; there is no implicit default.

### 3.3 Notation and canonical hashes
- `H(x)` = SHA-256 over byte string `x`.
- `Ht(tag, x)` = `H(tag || 0x00 || x)` with `tag` as UTF-8 bytes and a single `0x00` separator.
- `u64be(n)`/`u32be(n)` = unsigned big-endian encodings.
- `Trunc_24(x)` = first 24 bytes of `x`.
- CBOR maps are encoded in key order (ascending by integer key).
- **Lexicographic byte order** compares byte strings by unsigned byte value from left to right; shorter prefixes sort before longer strings when all compared bytes are equal.

### 3.4 Performance contract (normative)
Every external API/CLI operation MUST be **O(1)** or **O(polylog n)** in **positioning, lookup, and verification**. Any linear scan or sequential replay on a hot path is non-compliant.
Returned output is necessarily **O(k)** in the number of records or bytes emitted and is excluded from the positioning/lookup bound.

Required structures:
- Per-label head index
- Persistent secondary indices
- MMR peaks cache
- Chunk summaries + merge trees

No internal linearity may be observable by external callers.

### 3.4.1 Algorithm and data-structure optimization (normative)
Implementations MUST employ the following algorithmic and storage strategies to meet the contract above. These requirements are not optional tuning; they are part of the wire-compatible performance behavior.

**Admission + append (O(1)):**
- Maintain a **per-label append cursor** storing `(stream_seq, mmr_peaks)` and the last `client_seq` per `(label, client_id)`.
- Enforce admission ordering with **constant-time checks** against these cursors; no replay or scan of historical records.
- Persist cursors in a **write-ahead journal** so recovery restores them without replaying the full log.

**Proofs + receipts (O(log n)):**
- Store MMR peaks in a **bounded-height array** keyed by label; updates are O(log n).
- Cache **latest inclusion paths** in a small LRU keyed by `(label, stream_seq)` to serve hot proof requests.
- Persist **peak snapshots** at fixed intervals so a proof can be reconstructed by O(log n) merges without scanning raw leaves.

**Query + inspection (O(polylog n)):**
- Every predicate MUST map to an **explicit index** (B-tree or LSM). Composite predicates MUST map to **composite keys**.
- Use **covering indices** for inspection views so results are served without fetching payloads.
- Maintain **time-bucketed partitions** (e.g., by day or epoch) with bounded fanout to guarantee polylog range scans.

**Retention + pruning (O(polylog n)):**
- Implement **tombstone indices** and **segment manifests** to delete or retain ranges without scanning live segments.
- Keep a **manifest tree** keyed by `(label, epoch, seq_range)` to verify completeness without reading segments.

**Determinism + bounds:**
- All caches MUST be **size-bounded and deterministic** with a canonical access order; the eviction policy MUST NOT alter externally observable results or complexity bounds. LRU with fixed caps is acceptable under a deterministic access order.
- Any probabilistic structure (e.g., Bloom filters) MUST be **supplemental only** and never the sole correctness path.

### 3.5 Deterministic limits and sizing
All size and time limits are **explicit, configuration-bound, and deterministic**. Implementations MUST define:
- Max message size, header size, body size, attachment count, and attachment size.
- Max log chunk size and checkpoint interval.
- Max rate and burst per CapToken.
- Max clock skew for epoch validity.
All limits MUST be enforced with deterministic error codes and MUST NOT depend on runtime state outside indexed metadata.

### 3.6 Architecture boundaries
- **Core protocol:** wire objects, ordering, proofs. Depends only on crypto, CBOR, append-only storage.
- **Storage/index:** append-only log, MMR, indices. No overlay semantics.
- **Overlays:** pure folds over logs. No access to hub internals.
- **Operational tooling:** uses public APIs only.

---

## 4. Core wire specification (v0.0.1)

### 4.1 MSG (submit)
CBOR array with fixed field order:
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

`auth_ref` is optional but appears mid-array; when absent it MUST be encoded as `null`.

### 4.2 Ciphertext construction (normative)
1. `enc, ctx = HPKE.SealSetup(pkR)` (enc is 32 bytes).
2. `auth_ref_or_zero = auth_ref if present, else 32 zero bytes`.
3. `aad = Ht("veen/aad", profile_id || label || client_id || u64be(client_seq) || u64be(prev_ack) || auth_ref_or_zero)`.
4. `hpke_ct_hdr = HPKE.Seal(ctx, aad, CBOR(payload_hdr))`.
5. `k_body = HPKE.Export(ctx, "veen/body-k", 32)`.
6. `nonce = Trunc_24(Ht("veen/nonce", label || u64be(prev_ack) || client_id || u64be(client_seq)))`.
7. `aead_ct_body = AEAD_Encrypt(k_body, nonce, aad, body)`.
8. `hdr_len = u32be(len(hpke_ct_hdr))`.
9. `body_len = u32be(len(aead_ct_body))`.
10. `ciphertext = enc || hdr_len || body_len || hpke_ct_hdr || aead_ct_body`.
11. If `pad_block > 0`, right-pad with zeros to a multiple of `pad_block` (padding bytes are unauthenticated zeros).
12. `ct_hash = H(ciphertext)`.
13. `leaf_hash = Ht("veen/leaf", label || profile_id || ct_hash || client_id || u64be(client_seq))`.

Receivers MUST parse ciphertext using `hdr_len`/`body_len` and:
- Reject if `ciphertext` is shorter than `enc || hdr_len || body_len || hpke_ct_hdr || aead_ct_body`.
- Reject if any trailing padding bytes are non-zero.
- Ignore trailing zero padding beyond the encoded lengths.

`pad_block` is a profile parameter and MUST be configured deterministically.

### 4.3 RECEIPT (admission proof)
CBOR array with fixed field order:
1. `ver` (uint=1)
2. `label` (bstr32)
3. `stream_seq` (uint)
4. `leaf_hash` (bstr32)
5. `mmr_root` (bstr32)
6. `hub_ts` (uint)
7. `hub_sig` (bstr64) = `Sig(hub_pk, Ht("veen/sig", CBOR(RECEIPT without hub_sig)))`

### 4.4 CHECKPOINT (log snapshot)
CBOR array with fixed field order:
1. `ver` (uint=1)
2. `label_prev` (bstr32)
3. `label_curr` (bstr32)
4. `upto_seq` (uint)
5. `mmr_root` (bstr32)
6. `epoch` (uint)
7. `hub_sig` (bstr64)
8. `witness_sigs` ([bstr64], optional)

`witness_sigs` is a trailing optional field. If absent, the CBOR array MUST be length 7 (trailing trim). `null` is not permitted for `witness_sigs`.

CHECKPOINTs MUST:
- Encode the log prefix up to `upto_seq` for `label_curr`.
- Allow deterministic reconstruction of MMR peaks and index cursors using the data directory’s peak snapshots and chunk summaries (CHECKPOINTs do not carry peaks).
- Be reproducible from the same log prefix and configuration.

### 4.5 Payload header (encrypted)
CBOR(payload_hdr) map with integer keys:
- `1`: `schema` (bstr32)
- `2`: `parent_id` (bstr32, optional)
- `3`: `att_root` (bstr32, optional)
- `4`: `cap_ref` (bstr32, optional)
- `5`: `expires_at` (uint, optional)

The hub never sees payload_hdr in plaintext.
Unknown keys are rejected. `schema` is required.
Optional fields are omitted when absent; `null` is not permitted in `payload_hdr`.
`expires_at` is overlay-only and MUST NOT affect hub admission.

### 4.6 Attachments
- Attachment `i` uses `k_att = HPKE.Export(ctx, "veen/att-k" || u64be(i), 32)`.
- Nonce `n_att = Trunc_24(Ht("veen/att-nonce", msg_id || u64be(i)))`.
- `coid = H(AEAD_Encrypt(k_att, n_att, "", attachment))`.
- Leaves are the ordered `coid` values (attachment index ascending).
- Internal nodes are `Ht("veen/att-node", left || right)`.
- Peaks are combined as `Ht("veen/att-root", concat(peaks))` with the same peak ordering and fold rules as section 5.1.
- `att_root` is the resulting root.

---

## 4.7 Typed payloads and schema rigor (normative)
- `schema` identifies a typed overlay definition, not a hub-level type.
- Overlays MUST provide a **total decoding function** from `(payload_hdr, body)` to a well-defined typed event or a deterministic error.
- Schema evolution MUST be handled by versioning in `schema` or within the encrypted body; hubs remain agnostic.
- Typed invariants (e.g., “must include primary key”) are enforced at overlay fold time, not at admission.

---

## 5. MMR and proofs

### 5.1 MMR update (per label)
- Append `leaf_hash` in stream order, update peaks.
- `mmr_root` is either the single peak or `Ht("veen/mmr-root", concat(peaks))`.
- `peaks` is an array of 32-byte hashes ordered by increasing height (left-to-right within the same height). `concat(peaks)` is the raw 32-byte concatenation in that order.

### 5.2 Inclusion proof
`mmr_proof` is a deterministic CBOR map with the following fixed keys (unsigned integer keys):
```
{
  1: ver,         // uint (MUST be 1)
  2: leaf_hash,   // bstr32
  3: path,        // [ { 1: dir, 2: sib }, ... ]
  4: peaks_after  // [ bstr32, ... ]
}
```
All maps in `mmr_proof` (including elements of `path`) use unsigned integer keys ordered exactly as listed for deterministic CBOR.
`path` entries are ordered from the leaf toward the peak (ascending height), and `dir` indicates whether `leaf_hash` was on the left (`0`) or right (`1`) at that step.
Verification MUST reproduce the `mmr_root` recorded in a RECEIPT or CHECKPOINT.

### 5.3 Proof compactness (normative)
- Proofs MUST be minimal with no redundant siblings.
- Peaks are ordered by increasing height.
- Any proof with unknown keys or invalid ordering is rejected.

---

## 6. Capability tokens (CapToken)

cap_token CBOR map with integer keys:
```
{
  1: ver,        // uint (MUST be 1)
  2: issuer_pk,  // bstr32
  3: subject_pk, // bstr32
  4: allow,      // map
  5: sig_chain   // [bstr64, ...]
}
```

`allow` is a CBOR map with integer keys:
```
{
  1: stream_ids, // [bstr32, ...]
  2: ttl,        // uint
  3: rate?       // map
}
```

`rate` is a CBOR map with integer keys:
```
{
  1: per_sec, // uint
  2: burst    // uint
}
```

Rules:
- `ver` MUST be `1`.
- `allow.stream_ids` MUST be non-empty.
- `allow.stream_ids` MUST be sorted in ascending lexicographic byte order with no duplicates; hubs MUST reject unsorted or duplicate entries.
- `allow.rate` is optional; if absent, key `3` MUST be omitted (null is not permitted).
- `auth_ref = Ht("veen/cap", CBOR(cap_token))`.
- `MSG.auth_ref` MUST equal `payload_hdr.cap_ref` if `cap_ref` is present (enforced by clients/overlays; hubs do not inspect encrypted payloads).
- `sig_chain` is ordered; each link is an Ed25519 signature over `Ht("veen/cap-link", CBOR(cap_token without sig_chain) || prev_sig)` where `prev_sig` is 64 zero bytes for the first link and the prior signature for subsequent links.
- All `sig_chain` links are verified with `issuer_pk`; v0.0.1 does not define delegation or per-link signer rotation. The chain represents issuer re-signing history, not delegated authority.
- Hubs MUST verify all signatures in `sig_chain` and enforce TTL and rate limits. TTL evaluation uses `hub_ts` at admission time; the hub MUST bind a stable `issued_at` to each `auth_ref` on first successful admission and enforce `hub_ts <= issued_at + ttl` for the lifetime of the admission record.
- `issued_at` is defined as the `hub_ts` in the RECEIPT for the first accepted MSG that uses the `auth_ref`. It MUST be reconstructable from logs/receipts; a hub MUST NOT depend on hidden state to determine `issued_at`. v0.0.1 MUST NOT use `/authorize` unless it produces a log-replayable receipt with a `hub_ts` that serves as `issued_at`.
- If a deployment cannot map `label -> stream_id`, it MUST document that hub-side stream scoping is disabled; clients MUST enforce scoping after decrypt.
- CapToken revocation MUST be modeled as an overlay stream and is enforced by clients/overlays in v0.0.1 (hubs do not enforce revocation).
- Unknown keys are rejected in `cap_token`, `allow`, and `rate`.

---

## 7. Core invariants (MUST)

For any accepted (MSG, RECEIPT) pair:
- **I1:** `H(ciphertext) = ct_hash`.
- **I2:** `leaf_hash = Ht("veen/leaf", label || profile_id || ct_hash || client_id || u64be(client_seq))`.
- **I3:** `mmr_root` matches the MMR after appending `leaf_hash` at `stream_seq`.
- **I4:** `profile_id` is supported.
- **I5:** If `att_root` exists, it matches the ordered attachment Merkle root.
- **I6:** `prev_ack <=` last observed stream_seq for the label at admission.
- **I7:** Capability constraints (TTL, rate) are satisfied.
- **I8:** `(label, client_id, client_seq)` is unique across accepted MSG.
- **I9:** For each `(label, client_id)`, `client_seq` increases by exactly 1.
- **I10:** Deterministic CBOR rules are enforced.
- **I11:** Size limits (max msg/header/body/attachments) are enforced deterministically.
- **I12:** Epoch validity for labels (clock skew bounds) is enforced if epoching is enabled.
- **I13:** Admission order and error codes are deterministic given the same log prefix and configuration.

Any violation MUST be rejected with a deterministic error code.

`prev_ack` is the client’s last verified `RECEIPT.stream_seq` for the label. Clients SHOULD advance it monotonically and MUST NOT decrease it for a given `(label, client_id)`; hubs MAY reject regressions as `E.SEQ`.

---

## 8. Hub behavior (normative)

### 8.1 Admission pipeline (strict order)
1. **Prefilter:** size caps, optional stateless rejection (e.g., proof-of-work validation). Any optional prefilter MUST be deterministic and MUST NOT depend on mutable hub state beyond the request itself.
2. **Structural checks:** CBOR determinism, field sizes, ver/profile_id.
3. **Auth checks:** `MSG.sig`, CapToken validation, TTL/rate.
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

The data plane is intentionally minimal and deterministic. All endpoints MUST satisfy the positioning/lookup O(1)/polylog requirement, with output cost proportional to returned data.

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
- **Typed totality:** decoding is total with explicit error states; no implicit coercions.

### 11.2 Canonical overlay classes (non-exhaustive)
- **Identity (ID):** subjects/devices/contexts/orgs/groups/handles as log-derived state.
- **Wallet:** balances/limits/freezes/adjustments are log folds, no hub-side balances.
- **Authorization/Revocation:** cap_token lifecycle and revocation logs.
- **Query:** structured queries over indexed fields; no full scans.
- **Products:** audit/evidence logging, air-gap bridges, anchoring, disaster recovery.

Overlays are optional but MUST NOT change core wire objects or invariants.

### 11.3 Overlay summaries and polylog merges (normative)
- Each overlay MUST define a **summary monoid** `(S, ⊕, e)` where:
  - `⊕` is associative and deterministic.
  - `e` is the identity summary.
- `fold(range)` MUST be computed via cached summaries in O(polylog n).
- Summary validity MUST be tied to a `(schema, label, upto_seq, mmr_root)` tuple.

### 11.4 CRUD/KV/Queue alignment (normative)
- **CRUD:** Enhanced by typed events; reads are derived views over ordered logs.
- **KV:** Keys map to overlay state with deterministic conflict rules (e.g., LWW).
- **Queue:** Stream order is authoritative; at-least-once delivery is ensured by receipts.
These behaviors are realized purely by overlays; hubs remain unchanged.

---

## 12. Operational requirements

- **OS portability:** Linux/WSL2/Docker/k8s/k3s with identical semantics.
- **Data portability:** hub data directory is a portable, auditable directory.
- **Observability:** admission latency, proof time, and fsync time are core metrics.
- **Disposability:** hubs can be destroyed and rebuilt from logs at any time.
- **Repairability:** corrupted indices MUST be rebuildable from logs/checkpoints only.
- **Key rotation:** supported via epoch-based labels without breaking verification.

---

## 13. Non-goals

- General-purpose compute or smart contracts
- Consensus protocols or blockchain semantics
- Deep packet inspection or payload routing

---

**Note:** `doc/reference.md` is preserved for historical context and does not alter this SSOT.
