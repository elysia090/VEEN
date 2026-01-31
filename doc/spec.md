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

**Design sophistication (SHOULD):**
- **Control/data plane separation:** Admission, ordering, and proofs remain in the hub; overlay semantics and
  policy live outside the hub, so operational changes do not mutate the core.
- **Failure-domain clarity:** Every durable artifact (log chunk, checkpoint, receipt, index snapshot) has an
  explicit producer and verifier so recovery is mechanical, not interpretive.
- **Capability-first authority:** All mutations flow through scoped CapTokens; ambient authority is forbidden.
- **Composable overlays:** Overlays are defined as pure folds with declared inputs/outputs, enabling safe
  composition and deterministic replays across profiles.
- **Observable determinism:** Every decision is derivable from log state + limits; telemetry may explain but
  never alter outcomes.

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
- **RoutingKey:** Hub-scoped label salt used in label derivation; a static, per-hub value derived from the
  hub identity (e.g., `routing_key = Ht("veen/routing_key", hub_id)`), fixed for the lifetime of a hub
  identity and its deployment data directory.
- **StreamSeq:** Monotonic sequence number per Label (1-based).
- **ClientID:** Ed25519 public key that verifies `MSG.sig`.
- **ClientSeq:** Monotonic sequence per `(label, client_id)`.
- **ProfileID:** Hash of profile parameters (`Ht("veen/profile", CBOR(profile))`).
- **CapToken:** Capability token for authorization and admission limits.
- **MsgID / leaf_hash:** `Ht("veen/leaf", label || profile_id || ct_hash || client_id || u64be(client_seq))`.
- **Overlay:** A pure, deterministic fold from logs to typed state, defined by `schema`.
- **Summary:** A compact associative digest of an overlay state used for merge or replay.
- **Epoch:** A routing epoch used to rotate labels without altering StreamID; derived from `epoch_sec` as
  defined in §3.2 and enforced with `max_epoch_skew_sec`.

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
v0.0.1 mandates conservative default maxima in §14, which deployments MAY lower but MUST NOT raise for
wire compatibility.

### 3.6 Architecture boundaries
- **Core protocol:** wire objects, ordering, proofs. Depends only on crypto, CBOR, append-only storage.
- **Storage/index:** append-only log, MMR, indices. No overlay semantics.
- **Overlays:** pure folds over logs. No access to hub internals.
- **Operational tooling:** uses public APIs only.

### 3.7 Crate boundaries (recommended workspace layout)
To keep the architecture boundaries enforceable in code, implementations SHOULD map them to **crate-level
dependency boundaries**. This section intentionally discards the current repo layout and defines a cleaner
logical separation that can be implemented as crates or as strict module boundaries. The dependency direction
is **one-way** from higher-level tooling to lower-level primitives; lower layers MUST NOT depend on higher
layers.

**Core primitives (no operational dependencies):**
- **`veen-core`**: wire objects, deterministic CBOR, cryptographic profiles, error codes, and proof types. It
  MUST NOT depend on hub orchestration, storage engines, overlays, or CLI code.

**Storage and indexing (no overlay semantics):**
- **`veen-storage`** (or an internal `storage` module if kept within `veen-hub`): append-only log abstraction,
  MMR maintenance, indices, checkpoints, and retention primitives. It MUST depend only on `veen-core` and
  storage backends. It MUST NOT implement overlay-specific shortcuts.

**Hub orchestration (protocol enforcement):**
- **`veen-hub`**: admission pipeline, receipt issuance, and API surface for submit/stream/proof/checkpoint. It
  depends on `veen-core` + `veen-storage` only. It MUST expose public APIs that are overlay-agnostic.

**Overlay execution (pure folds):**
- **`veen-overlays`** (or overlay-specific crates): schema definitions, deterministic fold logic, summaries, and
  validation. Overlays MUST depend only on public read/proof APIs from `veen-hub` or a stable read-only facade.

**Operational tooling (public APIs only):**
- **`veen-cli`**: user-facing commands; depends on public hub APIs and overlay APIs. It MUST NOT bypass them.
- **`veen-bridge`**: mirroring/replay tooling; depends on public hub read/write APIs and `veen-core` types only.
- **`veen-selftest`**: conformance and invariants; depends on public APIs and fixtures only.

**Boundary enforcement:**
- Cross-layer calls MUST go through explicit traits/interfaces defined in the lower layer.
- Any shared utility between layers MUST live in the lower layer (or `veen-core`) and be imported upward.
- No crate may rely on filesystem paths or storage details except `veen-storage`.

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

#### 4.4.1 Verification and label transition rules
Verifiers MUST recompute `mmr_root` for `label_curr` at `upto_seq` by reconstructing the MMR peaks for the
log prefix `[1, upto_seq]`. Reconstruction MUST use the persisted peak snapshots and chunk summaries:
1) locate the latest peak snapshot at or before `upto_seq`, 2) apply the indexed chunk summaries covering
`(snapshot_seq, upto_seq]` to merge leaves into the peak set, and 3) fold the resulting peaks in canonical
order to derive `mmr_root`. Any deviation from the MMR peak ordering or a mismatch between the computed
root and `mmr_root` in the CHECKPOINT MUST be rejected.

`label_prev` and `label_curr` define a deterministic label rotation boundary. A transition where
`label_prev != label_curr` implies a label rotation and MUST coincide with an epoch change as defined in
§3.2. Verifiers MUST validate that the checkpoint’s `epoch` matches the derived epoch for `label_curr` and
that `label_prev` equals the label derived from the immediately preceding epoch (using the same
`routing_key` and `stream_id`). A transition where `label_prev == label_curr` MUST mean no rotation and
the `epoch` MUST equal the label’s current epoch; otherwise the CHECKPOINT is invalid.

CHECKPOINTs MUST be rejected if:
- The `epoch` does not match the derived epoch for `label_curr`, or `label_prev` does not match the
  previous-epoch label when rotation is indicated.
- `upto_seq` is less than the last accepted checkpoint for the same `label_curr`, or does not align with
  the reconstructed prefix length from indexed chunks and peak snapshots.
- The reconstructed `mmr_root` at `upto_seq` does not equal the checkpoint’s `mmr_root`.

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
- Attachment count and per-attachment sizes are defined by the **encrypted body schema** for the selected `schema`; they are not encoded in `payload_hdr`.
- Attachment `i` uses `k_att = HPKE.Export(ctx, "veen/att-k" || u64be(i), 32)`.
- Nonce `n_att = Trunc_24(Ht("veen/att-nonce", msg_id || u64be(i)))`.
- `coid = H(AEAD_Encrypt(k_att, n_att, "", attachment))`.
- Leaves are the ordered `coid` values (attachment index ascending).
- Internal nodes are `Ht("veen/att-node", left || right)`.
- Peaks are combined as `Ht("veen/att-root", concat(peaks))` with the same peak ordering and fold rules as section 5.1.
- `att_root` is the resulting root.
- For zero attachments, `att_root = Ht("veen/att-root", "")` (the empty-peak root). If no attachments are present, `att_root` SHOULD be omitted from `payload_hdr`; if provided it MUST equal this empty root constant.
- Attachment sizes are authenticated by the encrypted body (AEAD) and the attachment AEADs themselves; `payload_hdr` does not carry sizes.
- Implementations MUST reject messages when the attachment list length or any declared attachment size in the decrypted body schema does not match the supplied attachment array, or when `att_root` does not match the computed root.

---

## 4.7 Typed payloads and schema rigor (normative)
- `schema` identifies a typed overlay definition, not a hub-level type.
- Overlays MUST provide a **total decoding function** from `(payload_hdr, body)` to a well-defined typed event or a deterministic error.
- Schema evolution MUST be handled by versioning in `schema` or within the encrypted body; hubs remain agnostic.
- Typed invariants (e.g., “must include primary key”) are enforced at overlay fold time, not at admission.

---

## 4.8 Log framing, chunking, and recovery artifacts (normative)
This section defines the **on-disk log framing and recovery artifacts** that bind the wire objects in §4 to
the operational requirements in §12. These rules are mandatory for deterministic recovery and reproducible
replay.

### 4.8.1 Log entry framing (per entry)
Each append to the hub log is a **paired record** consisting of a `MSG` (§4.1) and its corresponding
`RECEIPT` (§4.3). The pair is stored as a single framed log entry with the following fixed header:

1. `entry_ver` (u8 = 1)
2. `flags` (u8, bitfield; all unused bits MUST be zero)
3. `label` (bstr32)
4. `stream_seq` (u64be)
5. `msg_len` (u32be)
6. `receipt_len` (u32be)
7. `entry_hash` (bstr32) = `H("veen/entry" || msg_bytes || receipt_bytes)`

`msg_bytes` and `receipt_bytes` are the canonical CBOR encodings of `MSG` and `RECEIPT`. The log entry body
is `msg_bytes || receipt_bytes` in that order. Implementations MUST reject entries where:
- `msg_len` or `receipt_len` do not match the actual byte lengths.
- `entry_hash` does not match `msg_bytes || receipt_bytes`.
- `RECEIPT.label`/`stream_seq` do not match the header `label`/`stream_seq`.
- The `MSG` and `RECEIPT` violate invariants in §7.

The `entry_hash` is a durable integrity check for storage and is distinct from `ct_hash` and `leaf_hash`.
Entries are append-only and MUST NOT be rewritten in place.

### 4.8.2 Chunking rules
Logs are stored as **chunks** with deterministic rolling and alignment:
- Each chunk file contains a contiguous sequence of framed entries.
- Chunks MUST roll when either `max_chunk_bytes` would be exceeded by the next entry or
  `max_checkpoint_interval` entries have been appended since the last checkpoint (see §14.1).
- Each chunk boundary MUST align to the end of a framed entry; partial entries are forbidden.
- Chunk sizes MAY be smaller than `max_chunk_bytes` but MUST NOT exceed it.
- The rolling criteria and resulting chunk boundaries MUST be deterministic given the same log prefix and
  limit registry.

### 4.8.3 Checkpoint artifacts on disk
To satisfy §12 repairability and deterministic recovery, the data directory MUST include:

- **Chunk files:** `log/chunk-<label_hex>-<start_seq>-<end_seq>.log`
  - `label_hex` is the hex encoding of `label`.
  - `start_seq` and `end_seq` are inclusive, zero-padded decimal (width 20) for stable ordering.
- **Chunk summaries:** `log/chunk-<label_hex>-<start_seq>-<end_seq>.summary`
  - Contains `(label, start_seq, end_seq, mmr_root_end, entry_count, total_bytes, entry_hashes_root)`.
  - `entry_hashes_root` is the MMR root over `entry_hash` values for the chunk in entry order.
- **Peak snapshots:** `log/peaks-<label_hex>-<upto_seq>.cbor`
  - Contains the deterministic MMR peak array after `upto_seq` for `label`.
- **Checkpoint files:** `log/checkpoint-<label_hex>-<upto_seq>.cbor`
  - The CBOR encoding of `CHECKPOINT` (§4.4).
- **Checkpoint index:** `log/checkpoint-index-<label_hex>.cbor`
  - Summary map of `(upto_seq -> mmr_root, chunk_range, peaks_ref)`.

These artifacts MUST be sufficient to reconstruct the exact MMR state and append cursors without reading
any payload bytes beyond the logged entries. Filenames and index summaries MUST be derived solely from
log contents and limit registry values; no external mutable state is permitted.

### 4.8.4 Compression and deterministic decoding
v0.0.1 does not mandate compression. If compression is enabled by a deployment, it MUST satisfy:
- Compression applies **only** to chunk files; summaries, peaks, and checkpoints MUST remain uncompressed.
- The compression algorithm and parameters MUST be fixed in the limit registry and treated as part of the
  deterministic configuration.
- Decompression MUST be deterministic and byte-exact; any decoding error invalidates the entire chunk.
- Compression MUST NOT alter entry boundaries; the decoded byte stream MUST match the concatenated framed
  entries exactly.

If compression is disabled, chunk files are stored verbatim and decoded by direct framing.

---

## 5. MMR and proofs

### 5.1 MMR update (per label)
- Append `leaf_hash` in stream order, update peaks.
- Internal node hashes are `Ht("veen/mmr-node", left || right)` where `left` and `right` are 32-byte child hashes.
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

### 5.4 Proof verification (normative)
The verifier MUST treat `mmr_proof` as evidence that `leaf_hash` is included at a specific leaf position in
the per-label MMR, and MUST recompute the same `mmr_root` recorded in the corresponding RECEIPT or
CHECKPOINT. The procedure below applies to §5.2–§5.3 and is mandatory for deterministic validation.

**Required inputs:**
- `mmr_proof` (per §5.2).
- `expected_root`: the `mmr_root` from the RECEIPT or CHECKPOINT being verified.
- `stream_seq`: the 1-based stream sequence number for the entry being proved.
- `label` and `profile_id` (to recompute `leaf_hash` when validating a receipt/message pair).
- `ct_hash`, `client_id`, `client_seq` (from MSG/RECEIPT) to recompute `leaf_hash` as `Ht("veen/leaf", ...)`.

**Deriving `stream_seq` and leaf position:**
- For RECEIPT verification, `stream_seq` is the `RECEIPT.stream_seq` field and MUST match the caller’s
  referenced entry. For CHECKPOINT verification, `stream_seq` is the checkpoint’s `upto_seq`.
- The leaf position is the 0-based index `pos = stream_seq - 1`. Verifiers MUST reject `stream_seq = 0` or
  any `pos` that is inconsistent with `peaks_after` (see rejection conditions).
- If the verifier is validating a stream page (`/stream`), `stream_seq` MUST equal the last item’s
  `stream_seq` when `mmr_proof` is included (see §10.4.2).

**Verification algorithm (pseudocode):**
```
verify_mmr_proof(mmr_proof, expected_root, stream_seq, leaf_hash):
  require mmr_proof.ver == 1
  require stream_seq >= 1
  require mmr_proof.leaf_hash == leaf_hash

  acc = leaf_hash
  for step in mmr_proof.path:        # ordered leaf → peak
    require step.dir in {0,1}
    require len(step.sib) == 32
    if step.dir == 0:
      acc = Ht("veen/mmr-node", acc || step.sib)
    else:
      acc = Ht("veen/mmr-node", step.sib || acc)

  # acc is the peak hash for the leaf's tree.
  # peaks_after are in increasing height order and represent the full MMR after stream_seq.
  peaks = integrate_peak(acc, mmr_proof.peaks_after, stream_seq)
  computed_root = (len(peaks) == 1)
    ? peaks[0]
    : Ht("veen/mmr-root", concat(peaks))

  require computed_root == expected_root
```

`integrate_peak(acc, peaks_after, stream_seq)` MUST place `acc` at the correct height for the leaf’s
tree and validate that the remaining `peaks_after` are consistent with the implied MMR size. A conforming
implementation MUST derive the peak heights from `stream_seq` (i.e., the binary decomposition of
`stream_seq`) and MUST NOT accept `peaks_after` that cannot match those heights.

**Explicit rejection conditions (non-exhaustive):**
- Any unknown keys, out-of-order keys, or non-canonical CBOR in `mmr_proof` or its `path` entries.
- `ver != 1`, missing required fields, or wrong types/lengths (`leaf_hash`/`sib` not 32 bytes, `path` not an
  array, `peaks_after` not an array of bstr32).
- `stream_seq = 0`, or `stream_seq` inconsistent with the proof context (e.g., not the requested receipt
  sequence or not the last item in a `stream` page).
- Any `dir` value other than `0` or `1`.
- `mmr_proof.leaf_hash` mismatches the recomputed `leaf_hash` from the MSG/RECEIPT data.
- `path` ordering not strictly leaf-to-peak (ascending height) or any redundant sibling (violates §5.3).
- `peaks_after` ordering not strictly increasing height, duplicates, or peak count inconsistent with the
  expected MMR size derived from `stream_seq`.
- Final `computed_root` does not equal the `expected_root`.

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
- `issued_at` is defined as the `hub_ts` in the RECEIPT for the first accepted MSG that uses the `auth_ref`. It MUST be reconstructable from logs/receipts; a hub MUST NOT depend on hidden state to determine `issued_at`. v0.0.1 MUST NOT use `/tooling/authorize` unless it produces a log-replayable receipt with a `hub_ts` that serves as `issued_at`.
- If a deployment cannot map `label -> stream_id`, it MUST document that hub-side stream scoping is disabled; clients MUST enforce scoping after decrypt.
- CapToken revocation MUST be modeled as an overlay stream and is enforced by clients/overlays in v0.0.1 (hubs do not enforce revocation).
- Unknown keys are rejected in `cap_token`, `allow`, and `rate`.

### 6.1 CapToken minting, distribution, and auditability

- **Minting:** CapTokens are minted by an issuer holding `issuer_pk` and signing the `cap_token` to form the `sig_chain`.
  Minting MUST be deterministic given the issuance inputs (`subject_pk`, `allow`, and `ver`) and MUST NOT depend on hidden
  mutable state.
- **Distribution:** CapTokens are distributed out-of-band to the subject (e.g., over a secure control plane or provisioning
  channel). Hubs do not issue CapTokens in the data plane; they only verify `auth_ref` and the referenced CapToken.
- **Persistence:** Clients/overlays MUST persist CapTokens (or an exact CBOR re-encoding) and the derived `auth_ref` so they
  can re-submit `auth_ref` and reconstruct admission history. Hubs MUST persist a stable admission record keyed by
  `auth_ref` with `issued_at` to enforce TTL deterministically.
- **MSG binding:** MSGs carry only `auth_ref` (not the CapToken itself) once established; the CapToken MAY be supplied
  out-of-band or via a separate authorization path, but the hub MUST bind the `auth_ref` to a unique CapToken
  representation for its admission record.
- **Replayable issuance artifacts:** To satisfy the replayability requirement, any CapToken issuance path (including
  `/tooling/authorize`) MUST produce log-replayable artifacts that allow reconstruction of (a) the CapToken bytes,
  (b) the derived `auth_ref`, and (c) the `issued_at` bound by the hub. At minimum, the hub MUST emit a receipt-like record
  containing `hub_ts`, `auth_ref`, and a hash of the CapToken bytes, and MUST persist the CapToken bytes or a deterministic
  encoding that can be replayed to the same hash.
- **Operational constraints for `/tooling/authorize`:** If used, `/tooling/authorize` MUST be deterministic, MUST write to
  the same append-only log domain as MSG admission (or an equivalently replayable log), and MUST produce a receipt that
  anchors `issued_at`. Alternative issuance flows are permitted only if they generate the same replayable artifacts and
  allow the hub to reconstruct `issued_at` solely from logs and checkpoints.

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

**Required error response fields (admission):**
- `code` (canonical error code; see table below).
- `stage` (one of `prefilter`, `structural`, `auth`, `commit`).
- Optional stable `detail_enum` (implementation-defined, stable across releases).

Admission errors MUST use the error envelope in §10.6. The `stage` and optional `detail_enum` MUST be carried in
`detail` as `detail.stage` and `detail.detail_enum` respectively.

**Tie-breaking (deterministic):**
- **First-failure wins** by pipeline order in §8.1: `prefilter` → `structural` → `auth` → `commit`.
- Within a stage, checks MUST be evaluated in a deterministic order. The table below is the normative ordering for
  failures listed here; any additional optional checks MUST be inserted deterministically and documented.

**Admission error mapping (stage + validation failure → code):**

| Stage | Validation failure (ordered) | Code | Optional detail enum |
| --- | --- | --- | --- |
| prefilter | Size caps exceeded | `E.SIZE` | `SIZE_PREFILTER` |
| prefilter | Stateless policy reject (e.g., PoW missing/invalid) | `E.AUTH` | `PREFILTER_REJECT` |
| structural | Non-canonical/invalid CBOR, unknown fields | `E.FORMAT` | `CBOR_INVALID` |
| structural | Field length/size invalid | `E.SIZE` | `FIELD_SIZE` |
| structural | `ver` unsupported | `E.FORMAT` | `VERSION` |
| structural | `profile_id` unsupported | `E.FORMAT` | `PROFILE` |
| structural | `ct_hash` mismatch (`H(ciphertext) != ct_hash`) | `E.FORMAT` | `CT_HASH` |
| structural | `att_root` mismatch (if present) | `E.FORMAT` | `ATT_ROOT` |
| auth | `MSG.sig` invalid | `E.SIG` | `SIG_INVALID` |
| auth | CapToken missing/unknown | `E.CAP` | `CAP_MISSING` |
| auth | CapToken signature chain invalid | `E.CAP` | `CAP_INVALID` |
| auth | `auth_ref` binding invalid | `E.AUTH` | `AUTH_REF` |
| auth | CapToken TTL expired | `E.TIME` | `CAP_TTL` |
| auth | Rate limit exceeded | `E.RATE` | `CAP_RATE` |
| commit | `prev_ack` regression | `E.SEQ` | `PREV_ACK` |
| commit | Duplicate `(label, client_id, client_seq)` | `E.SEQ` | `DUPLICATE` |
| commit | `client_seq` not +1 | `E.SEQ` | `CLIENT_SEQ` |
| commit | Epoch skew invalid | `E.TIME` | `EPOCH` |

### 8.3 Disallowed behaviors
- Inspecting decrypted payload to make admission decisions.
- Linear scans or sequential replays on any external operation path.
- Hidden state that cannot be reconstructed from logs and checkpoints.

### 8.4 Hub identity, keys, and rotation
The hub public key `hub_pk` used to verify `RECEIPT.hub_sig` (§4.3) and `CHECKPOINT.hub_sig` is discovered and
anchored by one (or more) of the following deterministic mechanisms:
- **Data directory identity:** a hub identity record stored in the data directory (see required artifacts below),
  verified by a local trust root (e.g., OS trust store, provisioning secret, or explicit allow-list).
- **Out-of-band fingerprint:** a pinned fingerprint (e.g., `H(hub_pk)` or certificate fingerprint) configured by
  the client/operator.
- **Certificate binding:** a certificate chain that binds `hub_pk` to an identity, validated by a configured trust
  anchor (e.g., TLS PKI or a private CA).

Multiple hub keys MAY be allowed, but the hub MUST define a deterministic selection/validation rule set:
- Clients MUST accept only keys anchored by one of the configured mechanisms above.
- If multiple keys are valid, clients MUST select deterministically (e.g., by `valid_from` then lexicographic
  `hub_pk`), and MUST reject receipts/checkpoints signed by keys outside the active set.
- The hub MUST include a key identifier in its metadata artifacts so clients can map signatures to the correct key.

Rotation rules:
- The hub MAY rotate `hub_pk` by adding a new key to the active set with a `valid_from` (and optional `valid_until`)
  timestamp, while retaining previous keys in an archive set.
- Clients MUST treat a receipt or checkpoint as valid if its signature verifies under any key that was active at the
  corresponding `hub_ts` (for receipts) or `epoch` (for checkpoints).
- Old receipts MUST remain verifiable as long as the hub identity record and archived keys remain available.

Required metadata artifacts in the data directory (normative binding to logs/checkpoints):
- **hub-identity.json (or CBOR equivalent):** includes `hub_id`, list of `hub_keys` with `key_id`, `hub_pk`,
  `valid_from`, `valid_until` (optional), and the anchoring method used.
- **hub-identity.sig:** signature over the canonical encoding of `hub-identity.*` using the current `hub_pk`
  (or an offline root key if configured).
- **hub-key-map:** a deterministic mapping from `key_id` to `hub_pk` used by receipt/checkpoint verification.
- **checkpoint-binding:** a manifest that ties `checkpoint` files to `hub_id`, `key_id`, and the expected
  `mmr_root` for each `epoch`.

These artifacts MUST be sufficient to bind `hub_pk` to the log and checkpoint history without external mutable
state. Clients MUST reject hubs that cannot provide a complete, verifiable chain from the anchored identity to the
signatures in §4.3.

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

### 10.3 Transport, versioning, and content types
- **Transport:** v0.0.1 assumes HTTP/1.1 or HTTP/2 over TLS with request/response bodies encoded as CBOR.
- **Content-Type:** `application/cbor` for CBOR payloads; `application/json` is permitted for debugging but MUST
  be semantically equivalent to the CBOR shapes in this section.
- **Versioning:** the API version is fixed by the URL prefix (`/v1/...`). Servers MUST reject unknown major
  versions with `E.VERSION` and HTTP 400. Minor/patch changes are backward compatible and reflected in the
  `server_version` response field (see §10.4).

### 10.4 Request/response envelopes (CBOR + JSON)
All data plane requests are CBOR maps with unsigned integer keys. The JSON shape uses string keys with the
same names for readability. Unknown keys are rejected. Optional fields are omitted when absent; `null` is not
permitted unless explicitly stated. Unless noted, all integers are unsigned.

#### 10.4.1 submit
**Request (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: msg           // CBOR array, MSG as defined in §4.1
}
```
**JSON equivalent:**
```
{ "ver": 1, "msg": [ ... ] }
```
**Response (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: receipt,      // CBOR array, RECEIPT as defined in §4.3
  3: server_version // tstr, optional (e.g., "0.0.1")
}
```

#### 10.4.2 stream
**Request (CBOR map):**
```
{
  1: ver,              // uint (MUST be 1)
  2: label,            // bstr32
  3: from_seq,         // uint, inclusive lower bound
  4: to_seq,           // uint, inclusive upper bound, optional
  5: max_items,        // uint, optional (server-enforced upper bound)
  6: cursor,           // uint, optional (next stream_seq to read)
  7: with_receipts,    // bool, optional (default false)
  8: with_mmr_proof    // bool, optional (default false)
}
```
**JSON equivalent:**
```
{
  "ver": 1,
  "label": "<bstr32>",
  "from_seq": 0,
  "to_seq": 100,
  "max_items": 1000,
  "cursor": 42,
  "with_receipts": true,
  "with_mmr_proof": false
}
```
**Response (CBOR map):**
```
{
  1: ver,              // uint (MUST be 1)
  2: label,            // bstr32
  3: from_seq,         // uint (echoed effective lower bound)
  4: to_seq,           // uint (echoed effective upper bound if present)
  5: items,            // [ item, ... ]
  6: next_cursor,      // uint, optional (absent if no more data)
  7: mmr_proof,        // CBOR map per §5.2, optional
  8: server_version    // tstr, optional
}
```
Each `item` is a CBOR map:
```
{
  1: stream_seq,       // uint
  2: msg,              // CBOR array, MSG (§4.1)
  3: receipt           // CBOR array, RECEIPT (§4.3), optional
}
```
If `with_receipts` is false, `receipt` is omitted. If `with_mmr_proof` is true, `mmr_proof` is included once
for the whole page and proves inclusion for the last `stream_seq` in `items`.

#### 10.4.3 receipt
**Request (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: label,        // bstr32
  3: stream_seq    // uint
}
```
**Response (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: receipt,      // CBOR array, RECEIPT (§4.3)
  3: server_version // tstr, optional
}
```

#### 10.4.4 proof
**Request (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: label,        // bstr32
  3: stream_seq    // uint
}
```
**Response (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: mmr_proof,    // CBOR map per §5.2
  3: server_version // tstr, optional
}
```

#### 10.4.5 checkpoint
**Request (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: label,        // bstr32
  3: upto_seq      // uint
}
```
**Response (CBOR map):**
```
{
  1: ver,          // uint (MUST be 1)
  2: checkpoint,   // CBOR array, CHECKPOINT (§4.4)
  3: server_version // tstr, optional
}
```

### 10.5 Stream pagination semantics
- **Cursor vs. range:** `cursor` (if present) takes precedence over `from_seq` and represents the next
  `stream_seq` to read. Servers MUST set `next_cursor` to `last_stream_seq + 1` when more data is available.
- **Bounds:** `from_seq` and `to_seq` are inclusive bounds when `cursor` is absent. If `to_seq` is omitted, the
  server reads forward until `max_items` or the end of the stream.
- **Page size:** `max_items` is capped by the server’s configured maximum. Clients MUST handle truncation. A
  response with `items` length `< max_items` and no `next_cursor` indicates end of range.

### 10.6 Errors
Errors are CBOR maps with unsigned integer keys (JSON equivalents use the string names). The error envelope is:
```
{
  1: ver,         // uint (MUST be 1)
  2: code,        // tstr (canonical error code)
  3: message,     // tstr, human-readable
  4: detail,      // map, optional (machine-readable fields)
  5: retry_after, // uint seconds, optional
  6: request_id   // tstr, optional
}
```
Canonical code mapping (HTTP):
- `E.BAD_REQUEST` → 400 (malformed CBOR, unknown fields, invalid types)
- `E.UNAUTHORIZED` → 401 (missing/invalid auth)
- `E.FORBIDDEN` → 403 (capability denied)
- `E.NOT_FOUND` → 404 (unknown label/seq)
- `E.CONFLICT` → 409 (sequence regression, duplicate submit)
- `E.LIMIT` → 413 (exceeds size/limit registry)
- `E.UNAVAILABLE` → 503 (temporary load or maintenance)
- `E.VERSION` → 400 (unknown API version)

`detail` fields are machine-readable and MUST use stable keys such as `field`, `expected`, `actual`,
`max_allowed`, `label`, and `stream_seq`.

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
- **Routing key derivation and stability (normative):**
  - `routing_key` is **static per hub identity** and MUST NOT vary across restarts of the same hub data
    directory. It SHOULD be derived from the hub identity as `routing_key = Ht("veen/routing_key", hub_id)`.
  - If a deployment uses a different `hub_id` (new hub identity), it implicitly creates a new routing key
    and thus a new label space; this is a **deployment change**, not an epoch transition.
- **Epoch discovery (normative):**
  - Clients learn `epoch_sec` from the hub’s advertised cryptographic `profile` (see §3.2) and compute
    `epoch = floor(unix_time_sec / epoch_sec)` locally when `epoch_sec > 0`; otherwise `epoch = 0`.
  - The hub MUST expose its current `epoch` and `hub_ts` via a status/introspection API or receipt metadata
    so clients can align with the hub’s authoritative time base. Clients SHOULD prefer hub-provided values
    over local clocks when submitting messages.
- **Epoch acceptance and skew enforcement (normative):**
  - A hub MAY accept messages that target a limited window around its current epoch derived from `hub_ts`.
  - The hub MUST reject any message whose `epoch` is outside `current_epoch ± floor(max_epoch_skew_sec / epoch_sec)`
    when `epoch_sec > 0`; if `epoch_sec = 0`, only `epoch = 0` is valid.
  - When the hub’s `hub_ts` advances across an epoch boundary, it MUST begin accepting the new epoch while
    continuing to accept the previous epoch only within the skew window above.
- **In-flight messages at epoch boundaries (guidance):**
  - Clients SHOULD target the hub’s reported current epoch and MAY retry with the next epoch if a submit
    fails due to skew. Hubs SHOULD include the accepted `epoch` in receipts so clients can reconcile.
  - If message delivery spans the boundary, labels derived with the previous epoch remain valid only within
    the skew window; clients SHOULD plan for brief overlap and avoid long-lived batching across epochs.

---

## 13. Non-goals

- General-purpose compute or smart contracts
- Consensus protocols or blockchain semantics
- Deep packet inspection or payload routing

---

## 14. Protocol limits (normative)

v0.0.1 defines conservative upper bounds for acceptance and verification. Implementations MUST enforce
these maxima (or stricter limits) when processing client traffic.

- **Max serialized MSG size:** 1,048,576 bytes (1 MiB)
- **Max encrypted payload header size:** 16,384 bytes (16 KiB)
- **Max decrypted payload body size:** 1,048,320 bytes (1 MiB minus header envelope)
- **Max inclusion proof path length:** 64 sibling entries
- **Max CapToken signature chain length:** 8 signatures
- **Max attachments per MSG:** 1,024

### 14.1 Limit registry (normative)
Implementations MUST define a deterministic limit registry that is fixed for the lifetime of a hub
process. The registry MUST include, at minimum:

- `max_msg_bytes`
- `max_hdr_bytes`
- `max_body_bytes`
- `max_attachments_per_msg`
- `max_attachment_bytes`
- `max_chunk_bytes`
- `max_checkpoint_interval`
- `max_cap_rate_per_sec`
- `max_cap_rate_burst`
- `max_epoch_skew_sec`

The registry MUST be a deployment configuration artifact and MUST NOT be derived from runtime load,
available memory, or other mutable hub state. Deployments MAY lower any maximums from §14 but MUST NOT
raise them.

### 14.2 Derived sizing rules (normative)
To preserve deterministic admission behavior, hubs MUST apply the following derived sizing rules:

- `len(ciphertext) <= max_msg_bytes` and `len(MSG) <= max_msg_bytes` MUST both hold for acceptance.
- `hdr_len <= max_hdr_bytes` and `body_len <= max_body_bytes` are enforced from the ciphertext length
  fields before any decryption.
- If `pad_block > 0`, padding bytes count toward `max_msg_bytes` but do not reduce `max_body_bytes`.
- Attachment count and each attachment size are enforced against `max_attachments_per_msg` and
  `max_attachment_bytes` prior to computing `att_root`.

---

**Note:** `doc/reference.md` is preserved for historical context and does not alter this SSOT.
