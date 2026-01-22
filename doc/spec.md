# VEEN Specifications (SSOT)

This document consolidates all VEEN specification and operational documents into a single source of truth (SSOT).
Original spec files have been merged here and should no longer be referenced individually.

**SSOT policy**
- Update **only** this file for spec changes.
- Keep sections aligned to prevent drift across implementations.
- If any legacy text conflicts with the normalization rules below, the normalization rules take precedence.

## Normalization and conflict resolution

The documents consolidated here were authored at different times. To avoid implementation drift, the following
normalization rules are authoritative and resolve any conflicts across legacy sections:

- **Canonical CLI name:** `veen` is the primary CLI binary. References to `veen-cli` are legacy aliases of `veen`.
- **Hub runtime:** `veen hub start` is the canonical hub start command. Legacy `veen-hub run` or `veen-hub start`
  are accepted aliases with equivalent flags and behavior.
- **Companion binaries:** `veen-bridge` and `veen-selftest` may ship as separate binaries. If a unified `veen bridge`
  or `veen selftest` command exists, it MUST behave equivalently to the standalone binaries.
- **Path vs URL targets:** `--hub` accepts either an HTTP(S) URL or a local hub data directory path; `--data-dir`
  explicitly selects a local hub data directory when starting/stopping a hub.
- **Environment naming:** “WSL” and “WSL2” are treated as the same environment class.
- **Version layering:** v0.0.1 is the core spec; v0.0.1+ and v0.0.1++ are additive overlays and MUST NOT redefine
  or contradict v0.0.1 semantics.

## Spec refactoring & optimization addendum (SSOT)

This addendum resolves remaining ambiguities, removes effective duplication by declaring canonical sections, and
summarizes hot paths, critical paths, implementation risks, and dependencies for implementers and reviewers.

### Canonical section map (authoritative for conflicts)
- **Core wire objects and invariants:** `spec-1.txt` through `spec-4.txt` sections in this SSOT.
- **Overlay semantics:** `id-spec.txt`, `wallet-spec.txt`, `query-api-spec.txt`, plus any `spec-5.txt` overlays.
- **Operational CLI semantics:** `USAGE.md` and CLI goal documents consolidated below.
- **Rationale and philosophy:** `Design-Philosophy.txt`, `Whyuse.txt`, `CORE-GOALS.txt`, `OS-GOALS.txt`.

When a legacy section repeats or rephrases requirements, the first occurrence in the above canonical map is
authoritative; later repetitions are non-normative commentary unless explicitly marked as an update.

### Ambiguities resolved (normative)
- **Stream vs label:** `stream_id` is the logical stream identifier; `label` is the routing label derived from
  `label(stream_id, routing_key)` and MUST NOT be used as a stream identifier. If both appear, the stream identifier
  always determines fold order and state derivation.
- **Fold ordering with timestamps:** If a schema defines an explicit timestamp (`ts`, `updated_at`), use
  `(timestamp, stream_seq, tie-breaker)` for ordering. If not defined, use `(stream_seq, tie-breaker)` only.
  Timestamp fields are not required to be monotonic; they are only used to refine ordering.
- **Hub target selection:** `--hub` accepts either an HTTP(S) URL or a local hub data directory. If both `--hub`
  and `--data-dir` are supplied, `--data-dir` is authoritative for hub control commands.
- **Authentication identifiers:** `client_id` on MSG is always `device_pk`; `ctx_id` is never sent on wire and is
  derived by applications during authorization.
- **Cross-hub mirroring:** Mirror processes MUST preserve payload bytes and schema identifiers; any rewrite is a
  protocol violation and invalidates the fold.

### Duplication resolved (normative)
- **CLI binaries:** `veen` is canonical; `veen-cli` is an alias. References to `veen-hub` are legacy and resolve to
  `veen hub`.
- **Environment names:** “WSL” and “WSL2” are equivalent.
- **Version overlays:** v0.0.1+ and v0.0.1++ only add features; they MUST NOT relax or override v0.0.1 invariants.

### Hot paths (performance-sensitive)
- **Submit path:** `veen send` → hub admission (cap_token + PoW + rate) → log append → receipt signing.
- **Stream read path:** `veen stream`/`stream(with_proof=1)` → MMR proof generation → client verification.
- **Checkpoint path:** hub checkpoint creation → snapshot verification → mirror/bridge replay.

### Critical paths (correctness-sensitive)
- **Admission correctness:** cap_token signature chain validation, rate limiting, revocation lookups.
- **Deterministic folding:** schema-defined ordering + deterministic CBOR decoding + stable tie-breaker.
- **Integrity proofs:** MMR leaf/branch consistency; receipt and checkpoint signature verification.
- **Bridge/federation:** deduplication by stable ID and parent_id linkage preservation.

### Implementation risk register (hard parts)
- **Deterministic CBOR:** key order and canonical encoding MUST be enforced; unknown keys rejected.
- **Clock ambiguity:** timestamps may be skewed; rely on stream_seq for total order where needed.
- **State compaction:** compaction MUST preserve fold determinism and verifiable history when proofs are required.
- **Concurrency hazards:** avoid races between admission checks and log append; ensure atomicity for receipt issuance.
- **Backfill/replay:** replay order across hubs must be deterministic and consistent with bridge rules.

### Dependency inventory (non-exhaustive)
- **Crypto:** Ed25519, X25519, AEAD, hash function H, MMR implementation.
- **Encoding:** CBOR with deterministic map ordering and minimal integer encoding.
- **Storage:** append-only log, index for stream_seq, and snapshot/checkpoint storage.
- **Networking:** HTTP(S) and/or local FS hub access, streaming RPC layer.
- **Operational tooling:** CLI, bridge process, self-test harness, container/k8s manifests.

### Bottleneck elimination & optimization toolkit (normative guidance)
- **Admission hot path**
  - Pre-validate cap_token chains and cache issuer public keys with bounded TTL.
  - Deduplicate concurrent validation for the same auth_ref (single-flight).
  - Keep revocation lookups in memory with periodic snapshot refresh.
- **Append/log path**
  - Batch fsync operations (configurable) while preserving receipt correctness.
  - Use append-only segment files with bounded size for faster compaction.
  - Maintain a write-ahead buffer per label to reduce lock contention.
- **Proof generation**
  - Cache MMR peaks and recent branches per stream label.
  - Precompute checkpoints on a schedule and reuse during stream proofs.
- **Bridge/mirror path**
  - Apply idempotent deduplication before re-signing and publishing.
  - Use backpressure and bounded queues to avoid runaway memory usage.

### Spec optimization pipeline (normative guidance)
Implementations SHOULD apply the following ordered refinement steps when converting a spec surface into concrete
data structures. The order is intended to expose constant-time or polylog access paths early, and to re-normalize
derived structures so they can be indexed uniformly.

1. **ID-ify keys/state:** Compress coordinates/keys into dense IDs (coordinate compression, dictionary encoding,
   normalization) so they map to array indices.
2. **Fix the location in O(1) expected time:** Use hash maps, perfect hash tables, or cache-indexed tables to
   resolve “where” each ID lives.
3. **Precompute static parts:** Pre-derive tables, indices, and auxiliary arrays so queries become O(1) lookups.
4. **Create locality:** Use fixed-size blocks, micro/macro layouts, and bitset/SIMD-friendly packing to improve
   cache behavior and bounded fan-out.
5. **Decompose aggregation:** Model folds as monoids and implement with Fenwick trees, segment trees, sparse tables,
   or equivalent structures to ensure O(1)/O(polylog) queries.
6. **Reduce residual order dependence:** If strict ordering remains, convert to predecessor/successor queries using
   y-fast tries, vEB trees, or rank/select bitsets.
7. **Re-ID derived structures:** Assign IDs to nodes/blocks/clusters so the new structures are again array-indexed.
8. **Re-hash in the new ID space:** Rebuild hash tables and indexes in the normalized space; then repeat from step 2
   if additional derived layers emerge.

### Operational efficiency levers (actionable)
- **Cold start**
  - Keep a warm standby hub pointed at the same data directory for fast recovery.
  - Persist indexes; avoid rebuilding from raw logs when possible.
  - Maintain a per-stream index head sidecar that records the latest stream_seq and leaf_hash so range reads can bound work in O(1) without scanning the full index.
  - Avoid extra filesystem metadata probes in range reads; prefer direct bundle reads to cut constant-factor latency.
- **Observability**
  - Expose admission latency, proof generation time, and fsync durations as core metrics.
  - Track revocation hit rate and cache evictions for tuning.
- **Cost control**
  - Prune or archive old segments while retaining checkpoints and required proofs.
  - Use a separate storage tier for historical logs (bridge replay only).

### Bottleneck inventory (current known choke points)
- **Signature verification fan-out:** cap_token chains and receipt validation dominate CPU.
- **MMR proof fan-out:** large stream history drives proof generation cost.
- **I/O sync latency:** receipt issuance on fsync can be tail-latency sensitive.
- **Bridge replay storms:** cross-hub resync can saturate CPU and disk.

### Optimization priorities (recommended order)
1. **Admission caching** (keys, revocations, single-flight validation).
2. **MMR proof reuse** (checkpointing and branch caching).
3. **Append-path batching** (bounded fsync + segmented logs).
4. **Bridge throttling** (dedupe + backpressure).

### Complexity & non-sequential processing guarantees (normative update)
All implementations MUST guarantee that every externally visible operation defined by this specification
has a strict worst-case time complexity of **O(1)** or, at maximum, **O(polylog n)** with respect to the
total history size `n` (total events/messages per stream or per realm as applicable). Any design that
requires linear scans, linear rebuilds, or sequential dependency on the entire history is **non-compliant**.

**Definitions**
- `n` refers to the total number of events/messages relevant to the operation (per-stream for stream ops,
  per-realm for realm-wide ops, per-hub for hub-wide ops).
- **polylog n** means `O((log n)^k)` for a fixed constant `k`.

**Normative constraints**
- **No O(n) reads or writes:** All request paths (submit, stream read/proof, query, inspection, revocation,
  and wallet/identity overlays) MUST be bounded by O(1) or O(polylog n). Any fallback to linear scans is
  forbidden, even under cache miss or cold start.
- **No sequential dependency on full history:** Derived state MUST be computable via associative, deterministic
  reductions that support parallel or tree-based evaluation. A schema’s fold function MUST specify a
  merge/combine operation that allows `fold(range)` to be computed from subrange summaries without replaying
  every event in sequence.
- **Mandatory hierarchical summaries:** Implementations MUST maintain hierarchical checkpoints/snapshots and
  range summaries (e.g., segment trees, skip lists, or chunked accumulator tables) so that:
  - stream range proofs are O(polylog n),
  - range state reconstruction is O(polylog n),
  - the latest state is retrievable in O(1).
- **Index completeness:** All queryable fields and inspection endpoints MUST have explicit, persisted indexes
  with bounded fan-out (e.g., B-tree or LSM-tree indexes), eliminating any need for full scans.
- **Cold start bound:** Cold start and restart MUST be O(polylog n) by loading bounded summaries and indexes;
  replaying full logs is non-compliant except in offline recovery tooling that is not part of the operational
  spec surface.
- **Proof construction bound:** MMR or equivalent proof construction MUST be O(polylog n) with precomputed
  peaks/branches and bounded caches; rebuilding proofs by scanning history is non-compliant.

**Design requirements (implementation-agnostic)**
- **Per-label head index:** Maintain an O(1) head record per label/stream with (latest stream_seq, latest leaf_hash,
  and last checkpoint reference).
- **Chunked fold summaries:** Every K events, compute a deterministic summary object (schema-defined) so that
  any range fold can be computed by combining O(polylog n) summaries.
- **Deterministic tree shape:** Use a canonical tree partitioning of stream_seq (e.g., binary tree over ranges,
  fixed-size chunking with a balanced index) so that all nodes derive identical summaries from identical inputs.
- **Parallelizable evaluation:** Implementations SHOULD exploit parallelism across independent ranges or labels,
  but MUST remain deterministic regardless of concurrency.

These constraints are **normative** and supersede any legacy text that implies or permits linear-time scans,
full-log replays, or sequential-only folding in operational paths.

**Additional optimization requirements (normative)**
- **Amortization is insufficient:** Any bound MUST hold per request in the worst case; amortized O(1) or
  probabilistic bounds alone are non-compliant unless an explicit hard cap is enforced.
- **Bounded fan-out structures:** All index and summary structures MUST use bounded fan-out and MUST cap
  per-operation disk seeks and network round trips to O(polylog n).
- **Streaming-friendly proofs:** Proof generation MUST support streaming construction from precomputed
  summaries without materializing full paths in memory; memory usage MUST be O(polylog n).
- **Mergeable schema summaries:** Every schema that defines folding MUST define a summary type `S` and a
  deterministic merge function `merge(S_left, S_right) -> S` such that summaries compose without reprocessing
  individual events.
- **Deterministic concurrency:** If implementations parallelize folding/proof construction, they MUST ensure
  that the order of merges is canonical and that the output is byte-identical across executions.

## Source index (consolidated)

### Documents merged into this SSOT (original files removed)
- Design-Philosophy.txt
- Whyuse.txt
- USAGE.md
- CORE-GOALS.txt
- CLI-GOALS-1.txt
- CLI-GOALS-2.txt
- CLI-GOALS-3.txt
- OS-GOALS.txt

### Legacy sources already embedded below
- id-spec.txt
- products-spec-1.txt
- query-api-spec.txt
- spec-1.txt
- spec-2.txt
- spec-3.txt
- spec-4.txt
- spec-5.txt
- wallet-spec.txt


## id-spec.txt

VEEN Identity Layer (ID) v0.0.1
Principals, Realms, Context IDs, Orgs, and Bridging
(Overlay on VEEN v0.0.1, no wire-format changes)
	0.	Scope

This document defines the VEEN Identity Layer (ID) v0.0.1. ID is an overlay on VEEN v0.0.1 that provides:
	•	cryptographic principals and devices,
	•	realm-scoped pseudonymous account identifiers (context IDs),
	•	organizations, groups, and roles,
	•	handle and external-ID mapping,
	•	capability-based delegation and revocation,
	•	cross-hub and cross-realm identity bridging.

ID introduces only payload schemas and processing rules. It does not change VEEN core wire objects (MSG, RECEIPT, CHECKPOINT, cap_token) and does not alter VEEN invariants.

All identity semantics are carried as encrypted VEEN payloads and folded deterministically. Hubs remain blind to identity contents.
	1.	Notation and common rules

Ht(tag,x) = H(ascii(tag) || 0x00 || x) as in VEEN core.

Keys:
	•	principal_pk: Ed25519 public key (32 bytes) for a root identity (human or service).
	•	device_pk: Ed25519 public key (32 bytes) for a device.
	•	dh_pk: X25519 public key (32 bytes) for a device.

All payload bodies defined in this document are deterministic CBOR maps:
	•	exact key set and key order as listed per schema,
	•	minimal-length unsigned integers,
	•	definite-length byte strings and arrays,
	•	no floats,
	•	no CBOR tags,
	•	unknown keys MUST be rejected.

Events are folded per stream in a deterministic order:
	•	primarily by VEEN stream_seq,
	•	optionally refined by an explicit timestamp field (ts/updated_at) when defined,
	•	with a stable, implementation-defined tie-breaker if required (e.g. leaf_hash).

	2.	Identity model

ID separates the following layers:
	•	Principal: long-lived cryptographic root identity (principal_pk).
	•	Realm: identity scope for an application, tenant, or federation (realm_id).
	•	Context identity: realm-scoped pseudonymous account identifier (ctx_id).
	•	Devices: device_pk attached to a principal, used as authenticators.
	•	Organizations: org_id representing multi-account entities.
	•	Groups and roles: sets and labels over ctx_id for access control.
	•	Handles: human-readable identifiers mapped to ctx_id or org_id.
	•	External IDs: references to legacy IdPs or systems.

Applications SHOULD primarily interact with ctx_id and realm_id. Principals are used as cryptographic roots and are not necessarily exposed to applications.
	3.	Identifiers

3.1 Realm identifiers

A realm is a scope for context identities.

realm_id = Ht(“id/realm”, ascii(realm_name))

realm_name is an implementation-chosen UTF-8 string (e.g. “example-app”, “tenant-123”). Realm identifiers are 32-byte opaque values.

3.2 Principals

Each principal_pk defines a root identity. No derived identifier is required beyond principal_pk itself, but a stable reference can be defined if needed:

principal_id = Ht(“id/principal”, principal_pk)

principal_id is not required for protocol correctness and is informative.

3.3 Context identifiers (ctx_id)

For a principal_pk in a given realm_id:

ctx_id = Ht(“id/ctx”, principal_pk || realm_id)

Properties:
	•	ctx_id is 32 bytes.
	•	The same principal_pk yields different ctx_id for different realm_id.
	•	Within a realm_id, ctx_id is stable for the lifetime of principal_pk.
	•	No global user identifier is imposed; correlation across realms is optional and explicit.

Applications SHOULD treat ctx_id as the primary account identifier inside a realm.

3.4 Device identifiers

Each device keypair (device_sk, device_pk) and DH key (dh_sk, dh_pk) defines:

device_id = Ht(“id/device”, device_pk)

device_id is used only within identity payloads. On-wire VEEN MSG.client_id remains device_pk.

3.5 Organizations

An organization root key org_pk (Ed25519) defines:

org_id = Ht(“id/org”, org_pk)

org_id is stable for the lifetime of org_pk. For realm-scoped organizations, an additional scoped id MAY be used:

scoped_org_id = Ht(“id/org/realm”, org_id || realm_id)

When scoped_org_id is used, group and role bindings inside that realm MUST reference scoped_org_id, not bare org_id.

3.6 Groups

Groups are identified under an organization (scoped or not):

group_id = Ht(“id/group”, org_id || ascii(group_local_name))

group_local_name is a UTF-8 string chosen by the application and MUST be stable for the logical group’s lifetime.
	4.	Streams

4.1 Recommended identity streams

The following VEEN stream identifiers are RECOMMENDED:

stream_id_principal   = Ht(“id/stream/principal”, principal_pk)
stream_id_ctx         = Ht(“id/stream/ctx”, ctx_id || realm_id)
stream_id_org         = Ht(“id/stream/org”, org_id)
stream_id_handle_ns   = Ht(“id/stream/handle”, realm_id)

Implementations MAY merge multiple logical streams into one VEEN stream or split them further, as long as folding rules remain deterministic.

4.2 Labels

For each stream_id, labels are derived using VEEN’s label function from a routing_key and stream_id. Multiple labels MAY be used per stream_id (e.g. for sharding or epoching) if fold order is well defined.
	5.	Schemas

Schema identifiers (H is the VEEN-wide hash):

schema_principal      = H(“id.principal.v1”)
schema_device         = H(“id.device.v1”)
schema_ctx_profile    = H(“id.ctx.profile.v1”)
schema_org_profile    = H(“id.org.profile.v1”)
schema_group          = H(“id.group.v1”)
schema_role_binding   = H(“id.role.v1”)
schema_handle_map     = H(“id.handlemap.v1”)
schema_external_link  = H(“id.external.v1”)
schema_revocation     = H(“id.revoke.v1”)

Each schema is identified by setting payload_hdr.schema to the corresponding hash value. All payload_hdr and body data are AEAD-protected inside the VEEN ciphertext.
	6.	Principals and devices

6.1 Principal record

Schema: schema_principal
Stream: stream_id_principal

Body:

{
principal_pk: bstr(32),
created_at: uint,        // unix time seconds
info: map?               // optional, application-defined
}

Rules:
	•	principal_pk MUST match the public key used to derive stream_id_principal.
	•	Multiple principal records MAY exist; later records MAY override info but MUST NOT change principal_pk.

6.2 Device record

Schema: schema_device
Stream: stream_id_principal

Body:

{
principal_pk: bstr(32),
device_id: bstr(32),      // Ht(“id/device”, device_pk)
device_pk: bstr(32),      // Ed25519
dh_pk: bstr(32),          // X25519
label: text?,             // e.g. “phone”, “laptop”
created_at: uint,
expires_at: uint?,        // unix time seconds
flags: { disabled: bool? }?
}

Rules:
	•	principal_pk MUST equal the principal_pk of stream_id_principal.
	•	device_id MUST equal Ht(“id/device”, device_pk).
	•	Device is ACTIVE if:
	•	flags.disabled is absent or false, and
	•	expires_at is absent or now <= expires_at.
	•	Folding:
	•	For each device_id, events are ordered as in section 1.
	•	The last event determines flags and expiry.

ACTIVE devices are permitted authenticators for ctx_id derived from the same principal_pk, subject to delegation via cap_token.
	7.	Context accounts (per-realm identities)

7.1 Context profile

Schema: schema_ctx_profile
Stream: stream_id_ctx

Body:

{
ctx_id: bstr(32),
realm_id: bstr(32),
display_name: text?,
avatar_coid: bstr(32)?,   // content object ID for avatar
prefs: map?,
updated_at: uint          // unix time seconds
}

Rules:
	•	ctx_id MUST equal Ht(“id/ctx”, principal_pk || realm_id) for some principal_pk; the principal linkage may be implicit or explicit (via delegation).
	•	realm_id MUST match the stream’s realm_id.
	•	CRDT semantics:
	•	For each (ctx_id, realm_id), the context profile is an LWW-register.
	•	The winner is the record with maximum (updated_at, stream_seq).
	•	Conflicts with equal (updated_at, stream_seq) MUST be treated as equivalent or rejected as duplicates.

Applications SHOULD read ctx_profile via stream_id_ctx and MUST NOT assume uniqueness of display_name.
	8.	Organizations, groups, and roles

8.1 Organization profile

Schema: schema_org_profile
Stream: stream_id_org

Body:

{
org_id: bstr(32),
display_name: text?,
metadata: map?,
created_at: uint,
updated_at: uint
}

Rules:
	•	org_id MUST match the org_id used to derive stream_id_org.
	•	Organization profile is an LWW-register per org_id using (updated_at, stream_seq).

8.2 Group membership

Schema: schema_group
Stream: stream_id_org or a realm-scoped variant

Body:

{
org_id: bstr(32),
realm_id: bstr(32)?,
group_id: bstr(32),
name: text,
members_add: [ bstr(32) ]?,      // ctx_id list
members_remove: [ bstr(32) ]?,   // ctx_id list
updated_at: uint
}

CRDT semantics:
	•	Group membership is an OR-set per (org_id, group_id).
	•	For each ctx_id:
	•	membership is true if there exists at least one add event listing ctx_id that is not fully tombstoned by later remove events listing the same ctx_id.
	•	Group name:
	•	name is LWW per (org_id, group_id) using (updated_at, stream_seq).

8.3 Role binding

Schema: schema_role_binding
Stream: stream_id_org or a realm-scoped variant

Body:

{
org_id: bstr(32),
realm_id: bstr(32)?,
role: text,                   // e.g. “admin”, “editor”
targets_ctx: [ bstr(32) ]?,   // ctx_id list
targets_group: [ bstr(32) ]?, // group_id list
ts: uint
}

Semantics:
	•	Roles are additive by default:
	•	For each ctx_id, assigned roles are:
	•	roles mentioned in events where ctx_id is in targets_ctx, and
	•	roles applied to group_id where ctx_id is a member.
	•	Explicit role revocation MAY be modeled by:
	•	a role naming convention (e.g. “no-admin”), or
	•	a separate revocation schema (implementation-specific).
	•	ID v0.0.1 does not define negative roles or hierarchical roles; these are left to applications.

	9.	Delegation and authentication

9.1 Delegation via cap_token

Delegation uses VEEN cap_token unchanged.

Issuer: principal_pk (for account-level delegation) or org_pk (for org-level delegation).
Subject: device_pk or a service key.

cap_token:

{
ver: 1,
issuer_pk: bstr(32),
subject_pk: bstr(32),
allow: {
stream_ids: [ bstr(32) … ],
ttl: uint,
rate: { per_sec: uint, burst: uint }?
},
sig_chain: [ 64-byte signatures … ]
}

Rules:
	•	For principal-based delegation:
	•	issuer_pk MUST equal principal_pk.
	•	subject_pk MUST equal device_pk of an ACTIVE device.
	•	allow.stream_ids SHOULD include required identity and application streams (including stream_id_ctx for relevant realms).
	•	For org-based delegation:
	•	issuer_pk MUST equal org_pk.
	•	subject_pk MAY be principal_pk, device_pk, or a service key.
	•	ttl and rate MUST be enforced by admission logic according to OP0.3-style policies.

9.2 Authentication path for ctx_id

To authenticate a client as a ctx_id in a realm:
	1.	Client submits MSG with:
	•	client_id = device_pk,
	•	MSG.sig signed by device_sk,
	•	optional auth_ref referencing a cap_token.
	2.	Application obtains cap_token via auth_ref and verifies:
	•	sig_chain matches issuer_pk root (principal_pk or org_pk),
	•	subject_pk equals device_pk,
	•	allow.stream_ids includes the target application/identity streams,
	•	ttl and optional rate are satisfied.
	3.	If issuer_pk is principal_pk:
	•	Application computes ctx_id_expected = Ht(“id/ctx”, principal_pk || realm_id).
	•	Application binds this session to ctx_id_expected.
	4.	Additionally, application SHOULD check:
	•	device_pk is ACTIVE in schema_device for principal_pk,
	•	any required org/group/role bindings are present.

The application does not need to store passwords, session IDs, or bearer tokens; possession of device_sk and a valid cap_token chain is sufficient.
	10.	Handles and external IDs

10.1 Handle mapping

Schema: schema_handle_map
Stream: stream_id_handle_ns for a given realm_id

Body:

{
realm_id: bstr(32),
handle: text,                    // “@user”, “user@example.com”, etc.
target_type: text,               // “ctx” or “org”
target_id: bstr(32),             // ctx_id or org_id
ts: uint
}

Semantics:
	•	The handle namespace is per realm_id.
	•	For each (realm_id, handle), mapping is an LWW-register:
	•	winner is record with maximum (ts, stream_seq).
	•	Implementations MUST define:
	•	which handles are valid (syntax),
	•	whether and how handles can be reassigned,
	•	how to handle conflicts or squatting.

10.2 External ID link

Schema: schema_external_link
Stream: stream_id_ctx (recommended) or stream_id_org

Body:

{
realm_id: bstr(32),
ctx_id: bstr(32)?,
org_id: bstr(32)?,
provider: text,                  // “google”, “github”, “saml:corp”, etc.
external_sub: text,              // subject from external IdP or system
attributes: map?,                // optional mirrored claims
ts: uint
}

Semantics:
	•	At least one of ctx_id or org_id MUST be present.
	•	For each (provider, external_sub) there SHOULD be at most one active linkage across trusted streams.
	•	On external login:
	•	a gateway validates the external token,
	•	locates or creates ctx_id in the target realm,
	•	emits or updates an external_link binding external_sub to ctx_id.

ID v0.0.1 does not define global uniqueness or trust policies for providers; deployments MUST define which providers are trusted and how conflicts are resolved.
	11.	Revocation and rotation

11.1 Revocation record

Schema: schema_revocation
Stream: stream_id_principal or stream_id_org

Body:

{
principal_pk: bstr(32)?,
org_id: bstr(32)?,
device_id: bstr(32)?,
revoked_auth_ref: bstr(32)?,
realm_id: bstr(32)?,
ctx_id: bstr(32)?,
reason: text?,
ts: uint
}

Rules:
	•	At least one of device_id, revoked_auth_ref, ctx_id, org_id MUST be present.
	•	Revocation is advisory and MUST be enforced by:
	•	hubs (for admission) and/or
	•	applications (for authorization decisions).

Recommended enforcement:
	•	If revoked_auth_ref matches auth_ref, hubs SHOULD deny /submit for that auth_ref.
	•	If device_id is revoked, applications MUST treat the corresponding device as INACTIVE even if schema_device flags are not updated.
	•	If ctx_id is revoked in a realm, applications SHOULD treat that ctx_id as disabled for that realm.

11.2 Device rotation

To rotate a device:
	•	Generate new device_pk2 / dh_pk2.
	•	Create a schema_device event for device_pk2 (ACTIVE).
	•	Create a schema_revocation event for old device_id and/or old revoked_auth_ref.
	•	Optionally disable old device via a schema_device record with flags.disabled = true.

11.3 Principal and organization key rotation

Principal and org key rotation are advanced operations and are not fully standardized in ID v0.0.1. A deployment MAY define:
	•	a dedicated key-rotation schema, and
	•	rules mapping old principal_pk/org_pk to new ones.

Until such schema exists, principal_pk and org_pk SHOULD be treated as long-lived roots.
	12.	Bridging and federation

12.1 Cross-hub identity mirroring

Bridging uses the VEEN bridging overlay.

A bridge process:
	•	subscribes to identity streams on hub A (principal, ctx, org, handle, external_link, revocation) using stream(with_proof=1),
	•	for each MSG:
	•	preserves payload_hdr.schema and payload body byte-for-byte,
	•	sets parent_id of the mirrored MSG to the original msg_id,
	•	publishes a new MSG to hub B on the corresponding identity stream.

Semantics:
	•	Logical identity state is the union of events from all trusted hubs.
	•	Events are deduplicated using a stable identifier:
	•	for example, (payload hash, parent_id) or original msg_id.
	•	The fold order MUST be deterministic across hubs.

12.2 Realm-level federation

Realms support multiple federation patterns:
	•	Single realm for all applications in a deployment.
	•	Per-tenant realm for multi-tenant SaaS.
	•	Per-product realm for independent products sharing principals at a higher layer.

Root-level federation (e.g. a “meta realm”) that links multiple realms via external_link is permitted but not specified in detail by ID v0.0.1.
	13.	Privacy

ID v0.0.1 aims to minimise implicit correlation:
	•	ctx_id differs per realm by construction.
	•	Principals are not required to be exposed to applications.
	•	Identity payloads are encrypted; hubs do not see principal_pk, ctx_id, org_id, or handles in plaintext.
	•	Cross-realm correlation is opt-in via external_link or application-specific logic.

Deployments SHOULD:
	•	avoid using principal_pk as a global account identifier in plaintext,
	•	scope handles per realm_id,
	•	use external_link only for explicit federation or legacy integration.

	14.	Compliance levels

An implementation MAY claim:
	•	“ID v0.0.1 Core” if it implements:
	•	realm_id and ctx_id derivation,
	•	schema_ctx_profile,
	•	schema_device,
	•	delegation and authentication as in section 9.
	•	“ID v0.0.1 Orgs” if it additionally implements:
	•	schema_org_profile,
	•	schema_group,
	•	schema_role_binding.
	•	“ID v0.0.1 Handles” if it additionally implements:
	•	schema_handle_map,
	•	resolve-by-handle logic.
	•	“ID v0.0.1 External” if it additionally implements:
	•	schema_external_link and a gateway for at least one external provider.
	•	“ID v0.0.1 Bridge” if it additionally implements:
	•	cross-hub identity mirroring as in section 12.1.

	15.	Summary

ID v0.0.1 defines a minimal, coherent identity layer for VEEN:
	•	cryptographic principals and devices as roots,
	•	realm-scoped pseudonymous context IDs (ctx_id) as primary account identifiers,
	•	organizations, groups, and roles as CRDT overlays,
	•	handle and external-ID mapping as additional overlays,
	•	delegation via cap_token and event-driven revocation,
	•	bridging across hubs and realms without changing VEEN wire formats.


## products-spec-1.txt

Server Drive Recorder and Air-gap Bridge Product Specification
Version v0.0.2 (Products)
	0.	Scope

This document defines two product-grade profiles built on a VEEN-compatible deployment:
	1.	VEEN Server Drive Recorder (SDR0)
Continuous, tamper-evident recording and replay of selected events inside a trust domain.
	2.	VEEN Air-gap Bridge (AGB0)
Controlled, auditable, and optionally one-way transfer of events and proofs between two trust domains.

The goal of v0.0.2 is to turn the previous conceptual profiles into concrete products:
	•	with explicit SKUs,
	•	with concrete CLI and deployment expectations,
	•	with testable invariants,
	•	with minimal but sufficient threat model and operations model.

This specification assumes:
	•	VEEN core (hub, streams, receipts, checkpoints, MMR log) is available,
	•	0-series overlays (KEX0, AUTH1, ANCHOR0, DR0, OBS0) are present where referenced,
	•	VEEN CLI v0.0.1+ is available and self-tests are green.

	1.	Product line and SKUs

1.1. SKUs

SKU SDR0:
	•	Name: VEEN Server Drive Recorder
	•	Purpose: domain-internal forensic and operational evidence log
	•	Dependencies: VEEN hub, VEEN CLI, ANCHOR0 optional but recommended

SKU AGB0:
	•	Name: VEEN Air-gap Bridge
	•	Purpose: inter-domain evidence-carrying event transfer, optionally strictly one-way
	•	Dependencies: VEEN hub (both zones), VEEN CLI, ANCHOR0 recommended, DR0 optional

SKU SDR0+AGB0:
	•	Name: VEEN Recorder + Bridge bundle
	•	Purpose: combined deployment of SDR0 in both zones plus AGB0 between them

1.2. Minimal VEEN feature set required

All SKUs require at least:
	•	Ordered encrypted streams
	•	Message receipts with:
	•	stream id
	•	sequence number
	•	MMR root
	•	signatures (hub and sender)
	•	Checkpoint support:
	•	log root
	•	per-stream last sequence
	•	hub identity
	•	timestamp
	•	Capability tokens:
	•	stream-level access
	•	rate and TTL limits
	•	Revocation support (AUTH1):
	•	revocation records for client ids and cap tokens

	2.	Common terminology and types

2.1. Core terms

hub: VEEN-compatible message hub.
stream: named ordered sequence of messages in a hub.
event: application-level payload plus metadata emitted as one message to a stream.
receipt: verifiable record of a committed event.
checkpoint: compact snapshot of log state and stream positions.
trust domain: set of systems and operators sharing security policy and boundary.
zone: specific deployment region within or adjacent to a trust domain.
bridge: process that transfers events and proofs between hubs.

2.2. Stream namespaces (product-level)

SDR0 streams:
	•	Namespace: record/*
	•	record/app/*
	•	record/security/*
	•	record/infrastructure/*

AGB0 streams:
	•	Export: export/*
	•	Import: import/*
	•	Bridge audit: bridge/online/log, bridge/offline/log

2.3. Identity and capability roles

Shared patterns:
	•	recorder_producer:
	•	one identity per emitting service
	•	append-only to specific record/* streams
	•	recorder_admin:
	•	manage label_class, retention, checkpoint triggers
	•	read access across record/*
	•	bridge_online:
	•	read-only on export/* (Z1)
	•	optional read-only on specific record/* where export is derived
	•	bridge_offline:
	•	write-only on import/* (Z2)

No identity may simultaneously hold read access in one zone and write access in the opposite direction for the same logical bridge.
	3.	VEEN Server Drive Recorder (SDR0)

3.1. Product goal

Provide a deterministic and verifiable logging fabric that answers:
	•	“What happened, in which order, and who caused it?”
	•	“Up to which point is the log provably consistent?”
	•	“Which subset of events belongs to a given actor or time window?”

without introducing new cryptography.

3.2. Functional requirements

3.2.1. Event shape

Each recorder event MUST expose the following fields (payload or metadata):
	1.	subject_id       (stable actor id)
	2.	principal_id     (client public key id)
	3.	event_type       (string, application-defined)
	4.	event_time       (application-observed timestamp)
	5.	hub_commit_seq   (implicit from stream / receipt)
	6.	hub_commit_time  (hub-observed timestamp)
	7.	origin           (service/component identifier)
	8.	payload          (opaque structured content)

The hub MUST:
	•	sign committed messages,
	•	include them in an append-only log,
	•	provide inclusion proofs.

3.2.2. Stream configuration

For SDR0 compliance:
	•	All in-scope events MUST be written to record/* streams.
	•	Each application event type MUST map to exactly one recorder stream.
	•	record/* streams MUST have:
	•	retention_hint = long_term
	•	admission policy forbidding oversized payloads beyond configured bound
	•	renames and splits MUST be logged as explicit migration events in a dedicated management stream (e.g. record/infrastructure/changes).

3.2.3. Capability and isolation
	•	recorder_producer identities:
	•	capabilities limited to:
	•	append to specific record/* streams,
	•	no delete, no stream admin operations.
	•	recorder_admin identities:
	•	may manage label_class and retention policies,
	•	may read across record/* streams,
	•	MUST be distinct from any producer identity.

3.2.4. Checkpointing

Deployment MUST define:
	•	checkpoint frequency:
	•	by time (e.g. every 5 minutes) and/or
	•	by volume (e.g. every 10k events).
	•	checkpoint content MUST include:
	•	log_root (MMR root or equivalent)
	•	per-stream last sequence for all record/*
	•	hub_public key
	•	profile id identifying the SDR0 configuration
	•	creation timestamp

3.2.5. Replay API

Minimal replay interface:
	•	Replay by range:
	•	input: stream id, from_seq, to_seq (inclusive range [from_seq, to_seq], 1-based, from_seq <= to_seq)
	•	output: ordered events plus receipts
	•	Replay by time window:
	•	input: stream set, start_time, end_time
	•	output: events with hub_commit_time in [start_time, end_time]

Replay consumers MUST, at least for critical flows:
	•	verify hub identity against configured root-of-trust,
	•	verify selected inclusion proofs against log_root.

3.3. Non-functional requirements

3.3.1. Operational
	•	Checkpoint generation MUST be scriptable via CLI.
	•	Replay MUST be automatable (non-interactive CLI mode).
	•	Operators MUST have a documented runbook for:
	•	generating an ad-hoc checkpoint,
	•	validating the last checkpoint after incident,
	•	deriving a safe replay window.

3.3.2. Performance
	•	Recorder logging path MUST not require additional interactive network round-trips beyond normal VEEN submit path.
	•	Checkpoints MAY be generated asynchronously from the event ingestion path, provided consistency is preserved.

3.4. Invariants (SDR0)

Informal invariants:

I1. Order:
For any stream S and events e_i, e_j with i < j, any replay by sequence range on S MUST return e_i before e_j.

I2. Stability up to checkpoint:
Given checkpoint C with log_root R_C and per-stream last_seq_C(S), any event e in S with seq <= last_seq_C(S) is either:
	•	verifiable against R_C, or
	•	causes verification failure; silent omission is forbidden.

I3. Actor consistency:
For any principal_id P, the set of events recorded with principal_id = P corresponds to all uses of that VEEN client identity on recorder streams under the configured policies. Implementation MUST NOT multiplex multiple unrelated principals behind one VEEN client if that breaks auditability.

3.5. VEEN CLI mapping (SDR0)

A minimal SDR0 product MUST expose at least:
	•	Recorder event emission:
	•	via existing veen send with fixed schemas for record/*
	•	Recorder stream management:
	•	veen label-class set/list/show for record/*
	•	Checkpoints:
	•	veen hub checkpoint (or equivalent)
	•	veen hub anchor for external anchoring (recommended with ANCHOR0)
	•	Replay:
	•	veen stream … –with-proofs for record/* streams
	•	Self-test:
	•	veen selftest core
	•	SDR0-specific selftest scenario MAY be added as selftest recorder

AGCI (Acceptance-grade CI) MUST ensure:
	•	veen-core tests green,
	•	veen-hub tests green,
	•	goals_core_pipeline green,
	•	goals_audit_anchor green when ANCHOR0 is enabled.

	4.	VEEN Air-gap Bridge (AGB0)

4.1. Product goal

Provide a controlled and auditable path to move events (and their cryptographic evidence) from zone Z1 to zone Z2, preserving:
	•	directionality constraints,
	•	tamper-evident properties,
	•	traceable operational actions.

4.2. Topology and roles

Zones:
	•	Z1 (online zone):
	•	hub_online
	•	export/* streams
	•	optional record/* streams feeding export/*
	•	bridge/online/log audit stream
	•	Z2 (offline or higher-trust zone):
	•	hub_offline
	•	import/* streams
	•	bridge/offline/log audit stream

Bridge:
	•	AGB0 bridge process:
	•	runs in its own environment,
	•	has:
	•	read-only capabilities in Z1 (export/*),
	•	write-only capabilities in Z2 (import/*),
	•	has no shared private keys between hubs.

4.3. Directionality

AGB0 product MUST enforce:
	•	At capability level:
	•	bridge_online identities:
	•	read-only on export/*,
	•	MUST NOT have write access in Z1.
	•	bridge_offline identities:
	•	write-only on import/*,
	•	MUST NOT have read access in Z2 beyond import control scope.
	•	At network/physical level:
	•	Strict one-way option:
	•	transfer via removable media or one-way link,
	•	no route from Z2 back to Z1 under same operator control.

4.4. Export bundle format

Bundle B has:
	•	header:
	•	bundle_id (hash of bundle contents)
	•	source_hub_id
	•	source_profile_id (SDR0 or other)
	•	export_stream_id
	•	export_seq_from, export_seq_to
	•	export_time_from, export_time_to
	•	export_checkpoint:
	•	root
	•	per-stream last_seq
	•	timestamp
	•	hub_public
	•	events:
	•	ordered list of events in [export_seq_from, export_seq_to]
	•	for each:
	•	payload
	•	metadata (including subject_id, principal_id, event_type, times, origin)
	•	receipt or a reference to a bundled proof index
	•	proof:
	•	evidence that all events are consistent with export_checkpoint:
	•	minimal subset of MMR peaks, membership proofs, or aggregated structure

Bundle immutability:
	•	Any change to payload, metadata, or proof MUST change bundle_id.
	•	Import MUST fail if bundle_id or internal signatures do not verify.

4.5. Import procedure

For each bundle B:
	1.	Receive B via physical or network means.
	2.	Validate:
	•	source_hub_id against trusted list,
	•	export_checkpoint signature,
	•	bundle_proof against export_checkpoint,
	•	internal receipts.
	3.	Apply stream mapping:
	•	export/zoneX/foo -> import/zoneX/foo
	4.	For each event:
	•	create new event in import stream with:
	•	original payload and metadata,
	•	origin_receipt (or reference),
	•	import_time,
	•	bridge_id.
	5.	Commit events to hub_offline.
	6.	Optionally generate and anchor an import checkpoint.

Import MUST NOT:
	•	reuse source sequence numbers as hub_offline commit sequence,
	•	silently drop events on verification failure,
	•	modify payload content.

On any failure:
	•	record an audit entry in bridge/offline/log including:
	•	bundle_id,
	•	reason,
	•	position in bundle.

4.6. Bridge audit streams

bridge/online/log:
	•	records bundle creation:
	•	bundle_id, hash
	•	export_stream_id and seq range
	•	event count
	•	export_checkpoint id
	•	operator/automation id

bridge/offline/log:
	•	records imports:
	•	bundle_id
	•	target import streams and seq ranges
	•	event count
	•	verification_result (success/failure, error code)
	•	operator/automation id

4.7. Reconciliation and consistency

Given a chosen export checkpoint C1 in Z1:
	•	In Z1:
	•	compute exported ranges per export/* stream up to C1 from bundle headers.
	•	In Z2:
	•	compute imported ranges per import/* stream,
	•	track origin_receipt set.

AGB0 MUST offer a reconciliation tool or script that can:
	•	detect missing bundles,
	•	detect duplicate imports,
	•	detect partial imports,
	•	report them in a machine-readable format.

4.8. Invariants (AGB0)

Informal invariants:

J1. One-to-one origin mapping:
For any imported event in Z2, there exists exactly one origin_receipt in Z1, and reconciliation MUST be able to map between them.

J2. No silent loss in normal operation:
If bundle B is marked as successfully imported, then all events in B MUST have corresponding imported events, unless an explicit and logged exclusion policy is configured.

J3. Directionality:
For a strictly one-way Z1→Z2 bridge, there exists no identity and no network path that allows events originating in Z2 to directly influence any stream in hub_online under the same bridge operator’s control.

4.9. VEEN CLI mapping (AGB0)

AGB0 implementation SHOULD be expressed mainly as:
	•	Bundle exporter:
	•	veen bridge export or equivalent:
	•	pulls from export/* streams,
	•	builds bundle CBOR/JSON artifact,
	•	writes audit event to bridge/online/log.
	•	Bundle importer:
	•	veen bridge import or equivalent:
	•	verifies bundle,
	•	writes events to import/*,
	•	writes audit event to bridge/offline/log.
	•	Hubs and anchors:
	•	veen hub start/stop/status
	•	veen hub anchor /anchor endpoint for anchoring checkpoints.
	•	Self-test:
	•	goals_dr_cutover MUST be green when DR0 overlay is used.
	•	goals_k8s_disposable_mesh SHOULD be green for k8s deployments.
	•	AGB0-specific selftest MAY be added that:
	•	starts temporary hubs for Z1/Z2,
	•	exports synthetic events,
	•	imports them,
	•	runs reconciliation.

	5.	Combined product: SDR0+AGB0

5.1. Pattern

Recommended pattern:
	1.	Run SDR0 in both Z1 and Z2:
	•	record/* streams with long_term retention.
	2.	Select subset of record/* as export candidates:
	•	e.g. record/security/* and record/infrastructure/changes.
	3.	Configure AGB0 to:
	•	export from export/* (derived from record/* or mapped 1–1),
	•	import to import/* in Z2,
	•	log all bridge operations.
	4.	Use SDR0 replay in Z2 for analysis:
	•	import/* plus local record/*.
	5.	Optionally anchor:
	•	SDR0 checkpoints in both zones via ANCHOR0,
	•	AGB0 bundle ids and reconciliation results.

5.2. Shared invariants

K1. End-to-end trace:

For any critical event that originated in Z1 and is imported to Z2:
	•	there MUST exist:
	•	a chain:
	•	SDR0 event in record/* in Z1,
	•	inclusion in export bundle,
	•	audit record in bridge/online/log,
	•	audit record in bridge/offline/log,
	•	imported event in import/* in Z2,
	•	optional SDR0 event in record/* in Z2 that references the import.

K2. Bounded uncertainty window:

Given checkpoints C1 in Z1 and C2 in Z2 and a reconciliation run, the system MUST be able to:
	•	identify a closed region of time/sequence where log state is provably consistent across bridge operations,
	•	identify any gaps beyond that region.

	6.	Threat model and non-goals

6.1. In-scope threats
	•	Attempted log tampering at VEEN API level:
	•	removing or reordering events,
	•	injecting forged events not signed by valid keys.
	•	Attempted bundle tampering:
	•	modification of payload, receipts, or proofs after export.
	•	Misconfiguration of capabilities:
	•	accidentally granting write where only read is intended (AGB0),
	•	bypassing append-only policy for recorder streams.
	•	Bridge operation errors:
	•	partial imports,
	•	duplicated imports.

6.2. Out-of-scope threats
	•	OS-level compromise of hub hosts or bridge hosts:
	•	arbitrary root access on machines is treated as out-of-scope.
	•	Physical access to storage leading to complete data replacement without VEEN validation paths being used.
	•	Side-channel attacks on cryptographic primitives (reuse of VEEN’s crypto assumptions).

6.3. Expected mitigations
	•	Anchoring (ANCHOR0) to external services or ledgers is RECOMMENDED for:
	•	SDR0 checkpoints,
	•	AGB0 bundle ids,
	•	reconciliation reports.
	•	Strict identity and key management MUST be enforced by deployment processes and is not provided by the spec.

	7.	Implementation and test requirements for v0.0.2

To claim v0.0.2 product compliance:
	•	All existing VEEN test suites MUST be green:
	•	veen-core, veen-hub, veen-cli, veen-bridge, veen-selftest,
	•	goals_core_pipeline,
	•	goals_audit_anchor,
	•	goals_dr_cutover,
	•	goals_k8s_disposable_mesh (for k8s environments).
	•	At least one SDR0 integration selftest MUST exist that:
	•	emits events to record/*,
	•	generates and verifies checkpoints,
	•	replays with proofs.
	•	At least one AGB0 integration selftest MUST exist that:
	•	creates hubs for Z1/Z2,
	•	exports bundles,
	•	imports them,
	•	runs reconciliation,
	•	asserts invariants J1–J3.

This v0.0.2 spec is intentionally minimal at the product surface: UI, billing, and higher-level workflows may be added freely as long as the invariants and capabilities defined above remain satisfied.

## query-api-spec.txt

Query API Specification v0.0.1 (Tightened)
	0.	Scope

This document tightens the Query API on top of a VEEN deployment that already implements:
	•	Server Drive Recorder profile
	•	Air-gap Bridge profile

The Query API:
	1.	Treats queries and results as first-class recorder events.
	2.	Provides deterministic, verifiable digests for returned result sets.
	3.	Allows reconstruction and replay of queries across zones.

No new cryptography is introduced. The API is a structured way to:
	•	express queries,
	•	record them as events,
	•	produce and verify results.

	1.	Terminology

hub: VEEN-compatible message hub.
stream: named ordered stream of VEEN messages.
event: application-level payload plus metadata in a VEEN message.
receipt: cryptographically verifiable record of a committed VEEN message.
checkpoint: compact snapshot: log root + stream positions + metadata.
trust domain: set of systems under a shared security policy.
zone: concrete deployment region (e.g. online zone, offline zone).
query: structured request for a derived view of recorder events.
QueryDescriptor: canonical JSON representation of a query.
ResultRow: single row of a query result.
ResultDigest: compact summary and hash of a result set.
evidence: cryptographic material to verify that result rows match underlying events.
principal: VEEN client identity (key) that submits a query.
	2.	Namespaces and resources

2.1. Streams

The Query API uses the following recorder streams:
	1.	Query request stream
	•	Name: record/query/requests
	•	Direction: append-only
	•	Payload: normalized QueryDescriptor
	2.	Query result stream
	•	Name: record/query/results
	•	Direction: append-only
	•	Payload: ResultDigest
	3.	Optional query audit streams
	•	Name: record/query/audit/*
	•	Direction: append-only
	•	Payload: implementation-specific execution logs

All streams inherit the guarantees of the underlying Recorder profile: signed messages, inclusion in an append-only log, and MMR-based proofs.

2.2. Identifiers

The following identifiers are treated as opaque ASCII strings:

query_id: unique per query submission.
result_id: unique per query execution.
receipt_id: reference to a VEEN receipt for a source event.
hub_id: identifier of a VEEN hub instance.
profile_id: identifier of a hub profile or deployment configuration.

Constraints:
	•	query_id and result_id MUST be unique in the hub.
	•	Implementations MAY use UUIDv4 or cryptographic hashes; the format MUST be stable and documented.

	3.	Data types and encoding

3.1. JSON encoding

All API payloads and stored QueryDescriptor and ResultDigest objects use JSON with:
	1.	UTF-8 encoding.
	2.	No binary blobs; binary data must be hex or base64.
	3.	Deterministic canonicalization for hashing:
	•	object keys sorted lexicographically (byte order),
	•	no insignificant whitespace,
	•	numeric values encoded in minimal decimal form (no leading zeros, no unnecessary trailing zeros),
	•	strings encoded as UTF-8 with standard JSON escaping,
	•	arrays preserve order.

When this document refers to “canonical JSON” it means this encoding.

3.2. Timestamps

All timestamps are ISO-8601 UTC strings:
	•	Format: YYYY-MM-DDTHH:MM:SSZ
	•	Example: 2025-11-19T03:20:00Z

Sub-second precision MAY be added as fractional seconds, but MUST be consistent across implementation (e.g. always millisecond 3 decimal digits).
	4.	QueryDescriptor model

4.1. Shape

A QueryDescriptor is a JSON object:

{
“query_id”: “string”,
“version”: 1,
“scope”: [ “string”, … ],
“filter”: { … },
“projection”: [ “string”, … ],
“aggregate”: { … },   // optional
“evidence”: { … },
“meta”: { … }         // optional
}

4.2. Fields (required core)
	1.	query_id (string)
	•	Globally unique per submitted query.
	•	If not supplied by the client, the server MUST generate it and include it in the normalized descriptor.
	2.	version (integer)
	•	MUST be 1 for this specification.
	3.	scope (array of string)
	•	Non-empty array of stream names.
	•	Each entry SHOULD be a recorder stream (e.g. “record/app/http”).
	•	Implementations MUST reject unknown or unauthorized streams.
	4.	filter (object)
	•	Minimal required fields:
{
“subject_id”: “string or null”,           // optional
“event_type”: [“string”, …] or null,    // optional
“time”: {
“from”: “timestamp or null”,
“to”: “timestamp or null”
}
}
Semantics:
	•	subject_id: include only events with matching subject_id if present.
	•	event_type: include only events whose event_type is in the list.
	•	time.from / time.to: filter by hub_commit_time or event_time (implementation MUST document which).
If a field is omitted or null, it does not constrain the result.
	5.	projection (array of string)
	•	Non-empty.
	•	Each entry names a logical field or path. Minimal required fields:
	•	“subject_id”
	•	“principal_id”
	•	“event_time”
	•	“origin”
	•	“event_type”
	•	“payload.*” (implementation MAY support dotted paths)
	•	“receipt_id” (if available from storage)
If projection is [”*”], implementation MAY return a default field set.
	6.	evidence (object)
	•	Evidence policy:
{
“mode”: “none” | “spot” | “full”,
“sample_rate”: number  // required for “spot”
}
Constraints:
	•	mode “none”: sample_rate MUST be omitted or null.
	•	mode “spot”: sample_rate MUST be in (0, 1].
	•	mode “full”: sample_rate MUST be omitted or null.

4.3. Fields (optional extensions)
	1.	aggregate (object)
	•	Optional; if absent, the query is a row-level selection.
	•	Minimal structure:
{
“group_by”: [“field”, …],      // optional; empty or omitted = no grouping
“metrics”: [
“count”,
“min(event_time)”,
“max(event_time)”
]
}
	•	count MUST be supported; other metrics are implementation-defined.
	2.	meta (object)
	•	Free-form metadata. Recommended keys:
{
“requested_by”: “principal-id or human id”,
“requested_at”: “timestamp”,
“reason”: “string”
}

4.4. Normalization

On submission:
	1.	The server parses the client-supplied descriptor.
	2.	It fills defaults:
	•	set version = 1 if missing,
	•	generate query_id if missing,
	•	normalize filter, projection, evidence, meta to canonical JSON.
	3.	It validates:
	•	required fields are present,
	•	types are correct,
	•	references (streams, metrics, fields) are supported.

If validation fails, the API MUST return HTTP 400 with an error payload (see section 7.4).

The normalized QueryDescriptor is the one stored in record/query/requests.

4.5. Recording as VEEN event

The normalized QueryDescriptor MUST be embedded in a VEEN message:
	•	stream: record/query/requests
	•	body: canonical JSON of the descriptor
	•	recorder layer MUST populate:
	•	subject_id: the actor on whose behalf the query is run,
	•	principal_id: the VEEN client key id,
	•	event_type: “query.submitted” (or equivalent stable string),
	•	event_time: server receive time.

	5.	Result model

5.1. ResultRow

ResultRow is a logical row returned by the query engine. There is no fixed global schema; fields derive from projection and aggregate.

Constraints:
	1.	Each row MUST be representable as a JSON object.
	2.	For selection queries:
	•	it SHOULD include projected base fields (such as subject_id, event_time).
	3.	For aggregate queries:
	•	it SHOULD include group keys and metric values.
	4.	If projection includes “receipt_id”:
	•	each row MUST include a string “receipt_id” that refers to a VEEN receipt for the source event or a canonical derived identifier (implementation MUST document mapping).

Example (selection):

{
“subject_id”: “user:123”,
“event_time”: “2025-11-18T12:34:56Z”,
“origin”: “api-gateway-1”,
“path”: “/login”,
“status”: 401,
“receipt_id”: “rcpt-abc…”
}

Example (aggregate):

{
“subject_id”: “user:123”,
“origin”: “api-gateway-1”,
“count”: 23,
“first_seen”: “2025-11-18T00:10:00Z”,
“last_seen”: “2025-11-18T23:50:00Z”
}

5.2. ResultDigest

ResultDigest has this minimal structure:

{
“query_id”: “q-…”,
“result_id”: “r-…”,
“version”: 1,
“row_count”: 123,
“evidence_policy”: {
“mode”: “spot”,
“sample_rate”: 0.1
},
“rows_hash”: “hex”,
“evidence_hash”: “hex”,
“executed_at”: “timestamp”,
“hub_id”: “hub-…”,
“profile_id”: “profile-…”   // optional
}

Fields:
	•	query_id: MUST match the QueryDescriptor.
	•	result_id: unique; binds the fetchable result to this digest.
	•	version: MUST be 1.
	•	row_count: number of rows after aggregation.
	•	evidence_policy: normalized copy of evidence.
	•	rows_hash: SHA-256 (or stronger) of canonical JSON encoding of the rows array.
	•	evidence_hash: SHA-256 (or stronger) of canonical JSON encoding of evidence summary (see 6).
	•	executed_at: timestamp when the result set was fully materialized.
	•	hub_id: hub identity at execution time.
	•	profile_id: optional; identifies hub configuration profile.

5.3. Canonical rows_hash

To compute rows_hash:
	1.	Construct an array R of ResultRow objects in the order they will be returned to the client.
	2.	Encode R as canonical JSON (section 3.1).
	3.	Compute SHA-256 over the resulting bytes.
	4.	Encode as lowercase hex string.

rows_hash = hex(sha256(canonical_json(R)))

5.4. Canonical evidence_hash

The exact shape of evidence summary is implementation-defined but MUST be deterministic.

Minimal requirement:
	1.	For mode “none”:
	•	evidence_summary := { “mode”: “none” }
	2.	For mode “spot” or “full”:
	•	evidence_summary MUST include at least:
	•	query_id
	•	result_id
	•	mode
	•	sample_rate (for mode “spot”)
	•	a list of verified entries; each entry SHOULD contain:
	•	receipt_id
	•	mmr_root or equivalent
	•	hub_id

Example:

{
“query_id”: “q-…”,
“result_id”: “r-…”,
“mode”: “spot”,
“sample_rate”: 0.1,
“verified”: [
{
“receipt_id”: “rcpt-1”,
“mmr_root”: “hex”,
“hub_id”: “hub-…”
},
{
“receipt_id”: “rcpt-2”,
“mmr_root”: “hex”,
“hub_id”: “hub-…”
}
]
}

evidence_hash is then:

evidence_hash = hex(sha256(canonical_json(evidence_summary)))

5.5. Recording ResultDigest

ResultDigest MUST be embedded in a VEEN message:
	•	stream: record/query/results
	•	body: canonical JSON of the digest
	•	event_type: “query.result”
	•	subject_id: principal or service responsible for execution
	•	principal_id: execution engine identity

	6.	Evidence modes

6.1. Mode “none”
	•	Engine does not resolve receipts.
	•	Engine does not verify MMR or signatures.
	•	rows_hash MUST still be computed.
	•	evidence_summary is minimal; evidence_hash is deterministic.

Use cases:
	•	dashboards,
	•	low-criticality analytics.

6.2. Mode “spot”
	•	Engine must:
	1.	Materialize all ResultRow entries.
	2.	Select a deterministic subset using sample_rate.
	3.	For each sampled row, resolve receipt_id and verify:
	•	signature,
	•	MMR inclusion against a known root.
	4.	Construct evidence_summary with all sampled verifications.
	•	If any sampled verification fails:
	•	the query MUST fail (no successful result is returned).

6.3. Mode “full”
	•	Engine must:
	1.	For every ResultRow, resolve and verify receipts.
	2.	Fail the query if any verification fails.
	3.	Construct evidence_summary that allows recomputation or replay of verification.
	•	Mode “full” is intended for:
	•	forensic investigations,
	•	regulatory-grade reporting.

	7.	HTTP API

7.1. Authentication

All endpoints MUST be protected by:
	•	an authentication layer (e.g. bearer tokens, mTLS), and
	•	a mapping from authenticated principal to VEEN client identity.

Access control rules:
	•	Only authorized principals MAY submit queries.
	•	Access to scopes (streams) MUST be filtered by policy.
	•	Access to results MAY be restricted by:
	•	who submitted the query,
	•	tenant partition,
	•	query classification.

7.2. POST /api/query/submit

Request:
	•	Method: POST
	•	Path: /api/query/submit
	•	Headers:
	•	Content-Type: application/json
	•	Authorization: implementation-defined
	•	Body: JSON, partial or full QueryDescriptor (server can fill query_id and version).

Server behavior:
	1.	Authenticate and authorize.
	2.	Normalize and validate descriptor.
	3.	Emit VEEN event to record/query/requests.
	4.	Schedule execution.
	5.	Allocate result_id.

Response (accepted):

HTTP 202

{
“query_id”: “q-…”,
“result_id”: “r-…”,
“status”: “pending”
}

For small queries, server MAY synchronously execute and respond:

HTTP 200

{
“result_digest”: { … },
“rows”: [ … ]
}

7.3. GET /api/query/status/{result_id}

Optional.
	•	Method: GET
	•	Path: /api/query/status/{result_id}

Response:

HTTP 200

{
“query_id”: “q-…”,
“result_id”: “r-…”,
“status”: “pending” | “running” | “completed” | “failed”,
“error_code”: “string or null”,
“message”: “string or null”
}

7.4. GET /api/query/result/{result_id}

Request:
	•	Method: GET
	•	Path: /api/query/result/{result_id}

Query parameters (optional):
	•	offset: integer, default 0
	•	limit: integer, default 1000, upper bound implementation-defined

Response (completed, paginated):

HTTP 200

{
“result_digest”: { … },         // full digest
“rows”: [ ResultRow, … ],
“page”: {
“offset”: 0,
“limit”: 1000,
“total”: 1234,                  // optional; may be omitted for streaming backends
“has_more”: true | false
}
}

Offset and limit refer to row indices in the logical result set used when computing rows_hash. The server MUST ensure that:
	•	pagination does not change row ordering, and
	•	rows_hash remains the hash of the full ordered result set, not of a single page.

7.5. GET /api/query/descriptor/{query_id}

Optional but recommended for audit.
	•	Method: GET
	•	Path: /api/query/descriptor/{query_id}

Response:

{
“descriptor”: { QueryDescriptor },
“record_event”: {
“stream”: “record/query/requests”,
“seq”: integer,
“hub_id”: “hub-…”,
“receipt_id”: “rcpt-…”
}
}

7.6. Error model

Error responses MUST be JSON:

{
“error_code”: “string”,
“message”: “human readable”
}

Recommended error_code values:
	•	invalid_json
	•	invalid_query_descriptor
	•	unauthorized
	•	forbidden_scope
	•	query_not_found
	•	result_not_ready
	•	execution_failed
	•	internal_error

Mapping to HTTP status:
	•	400: invalid_json, invalid_query_descriptor
	•	401: unauthorized
	•	403: forbidden_scope
	•	404: query_not_found
	•	409: duplicate_query_id
	•	425 or 404 or 409 (implementation-defined): result_not_ready
	•	500: execution_failed, internal_error

	8.	Execution semantics

8.1. State machine (logical)

For each result_id:
	•	PENDING: descriptor accepted, not yet executed.
	•	RUNNING: query engine executing.
	•	COMPLETED: result_digest written to record/query/results and result rows materialized.
	•	FAILED: execution failed; no ResultDigest committed.

Transition rules:
	•	PENDING → RUNNING → COMPLETED
	•	PENDING → RUNNING → FAILED
	•	PENDING → FAILED (fast failure during planning or validation)

Once COMPLETED or FAILED, the state MUST be immutable.

8.2. Coupling with VEEN

A result is considered COMMITTED when:
	1.	ResultDigest event is successfully appended to record/query/results, and
	2.	The hub acknowledges the message and provides a receipt.

The API MAY return the result to the client after the local append but SHOULD expose the receipt or its hash via ResultDigest for later verification.
	9.	Cross-zone usage with Air-gap Bridge

9.1. Query in Z1, replay in Z2

Pattern:
	1.	In zone Z1:
	•	submit query, obtain QueryDescriptor and ResultDigest.
	•	optionally export underlying recorder events via Recorder + Bridge profile.
	2.	Export:
	•	export:
	•	QueryDescriptor event,
	•	ResultDigest event,
	•	the recorder events required by the query (or a superset).
	3.	In zone Z2:
	•	import recorder events.
	•	import QueryDescriptor and ResultDigest as recorder events.
	•	optionally re-run the query engine locally using the imported QueryDescriptor.
	•	compute local ResultDigest’.

If:
	•	QueryDescriptor’ equals QueryDescriptor, and
	•	ResultDigest’ matches ResultDigest on:
	•	query_id
	•	row_count
	•	rows_hash
	•	evidence_hash (for same evidence settings),

then Z2 can assert that:
	•	it observes a recorder history that matches Z1 for the queried scope, up to retention.

9.2. One-way bridge constraints
	•	Queries MAY be submitted separately in each zone.
	•	Query descriptors and digests MAY flow one-way with ordinary exported streams.
	•	No query-related control channel MUST be used to bypass one-way constraints.

	10.	Versioning and compatibility

10.1. Schema versions

This document fixes:
	•	QueryDescriptor.version = 1
	•	ResultDigest.version = 1

If a client supplies another version, the server MUST:
	•	either reject (HTTP 400, error_code = “unsupported_version”), or
	•	explicitly document a migration strategy.

10.2. HTTP API versioning

The bare paths in this document define v0.0.1 behavior. Implementations MAY expose:
	•	/api/v1/query/…

In that case they MUST document which descriptor/result versions the v1 API accepts and produces.

10.3. Backward-compatible extensions

The following are considered backward-compatible:
	•	adding new filter keys that can be safely ignored by older servers,
	•	adding new aggregate metrics that are rejected only if requested,
	•	adding fields to ResultRow and ResultDigest that clients may ignore.

Breaking changes MUST increment the schema version and, if exposed, the HTTP path version.

## spec-1.txt

Verifiable End-to-End Network (VEEN) v0.0.1 - Core plus Operational and Upper-Layer Profiles (wire format unchanged)
	0.	Scope

Endpoints hold semantics and cryptography; the hub provides ordering and reachability only. Accepted messages yield signed receipts and are committed into an append-only Merkle Mountain Range (MMR) with logarithmic inclusion proofs. Authority is carried by portable capability tokens. Transport is abstract (HTTP, QUIC, NATS, file). This document restates the immutable v0.0.1 core succinctly and adds operational and upper-layer profiles that do not modify the wire format. Sections 5 to 8 define the v0.0.1 wire objects and proof format. All later sections are additive and do not change bytes on the wire.
	1.	Notation

Byte concatenation is ||. u64be(n) is the 8-byte big-endian encoding of n. u32be(n) is the 4-byte big-endian encoding of n. Trunc_24(x) is the first 24 bytes of x. H is SHA-256. HKDF is HKDF-SHA256. AEAD (for message bodies and attachments) is XChaCha20-Poly1305 (24-byte nonce). Ed25519 is used for signatures; X25519 for Diffie-Hellman (DH). HPKE is RFC 9180 base mode: KEM X25519HKDF-SHA256, KDF HKDF-SHA256, AEAD ChaCha20-Poly1305 (12-byte nonce) for payload_hdr encapsulation only; exporter interface is used. Ht(tag, x) = H(ascii(tag) || 0x00 || x). Deterministic CBOR: maps with the exact field order listed in this document; minimal-length unsigned integers; definite-length arrays and byte strings only; no floats; no CBOR tags; fixed-length bstr fields are exact size; unknown keys are rejected.
	2.	Cryptographic profile

profile = {
aead: “xchacha20poly1305”,
kdf: “hkdf-sha256”,
sig: “ed25519”,
dh: “x25519”,
hpke_suite: “X25519-HKDF-SHA256-CHACHA20POLY1305”,
epoch_sec: 60,
pad_block: 0,
mmr_hash: “sha256”
}

profile_id = Ht(“veen/profile”, CBOR(profile))

Every MSG carries profile_id; receivers MAY reject unknown profile_id. Changing any field in profile changes profile_id. All participants in a deployment MUST agree on a single profile_id or an explicit set of supported profile_id values.
	3.	Keys and identities

Clients hold long-term keys id_sign (Ed25519) and id_dh (X25519). Prekeys are X25519 public keys signed by id_sign.

client_id in MSG is an Ed25519 public key that verifies MSG.sig. Clients SHOULD rotate client_id at least once per epoch when epoch_sec > 0, else after at most M messages (RECOMMENDED M = 256). Long-term identity, if needed, is referenced inside payload via cap_ref, never in plaintext MSG fields.

hub_pk is the hub Ed25519 public key and is distributed out of band. Clients and auditors SHOULD pin hub_pk (for example in application configuration or a trust store).
	4.	Streams and labels

stream_id is 32 bytes (for example, H(application name) or some other application-defined identifier).

Let epoch_sec be taken from profile. For a given Unix time t (seconds since Unix epoch):
	•	If epoch_sec > 0, define epoch E = floor(t / epoch_sec).
	•	If epoch_sec == 0, define E = 0.

Define:

label = Ht(“veen/label”, routing_key || stream_id || u64be(E))

where routing_key is a deployment-specific secret or pseudorandom value used to hide routing structure from the hub. The hub orders by label and does not learn stream_id or routing_key.

Receivers SHOULD accept labels where the embedded epoch E is in the inclusive range [E_local - CLOCK_SKEW_EPOCHS, E_local + CLOCK_SKEW_EPOCHS], where E_local is the receiver’s own computed epoch at acceptance time and CLOCK_SKEW_EPOCHS is a deployment parameter (see section 19). Messages with epochs outside this window SHOULD yield E.TIME.

Each label defines an independent, totally ordered stream at the hub. For a given label, the hub maintains a per-label sequence counter stream_seq (see sections 5 and 7).
	5.	Wire objects (immutable core)

The following CBOR objects define the v0.0.1 wire format. Map key order is fixed exactly as listed.

MSG fields (in order):
	•	ver: uint (MUST be 1)
	•	profile_id: bstr(32)
	•	label: bstr(32)
	•	client_id: bstr(32) (Ed25519 public key)
	•	client_seq: uint (per (label, client_id), strictly increasing by exactly 1; see invariants)
	•	prev_ack: uint
	•	auth_ref: bstr(32)? (optional)
	•	ct_hash: bstr(32)
	•	ciphertext: bstr
	•	sig: bstr(64) (Ed25519 signature over Ht(“veen/sig”, CBOR(MSG without sig)))

Ciphertext formation:
	1.	(enc, ctx) = HPKE.SealSetup(pkR) where pkR is the receiver HPKE public key (for example derived from a prekey). For the fixed profile, enc is 32 bytes (X25519 KEM output).
	2.	hpke_ct_hdr = HPKE.Seal(ctx, “”, CBOR(payload_hdr)).
	3.	k_body = HPKE.Export(ctx, “veen/body-k”, 32).
	4.	nonce = Trunc_24(Ht(“veen/nonce”, label || u64be(prev_ack) || client_id || u64be(client_seq))).
	5.	aead_ct_body = AEAD_Encrypt(k_body, nonce, “”, body).
	6.	hdr_len = u32be(len(hpke_ct_hdr)).
	7.	body_len = u32be(len(aead_ct_body)).
	8.	ciphertext = enc || hdr_len || body_len || hpke_ct_hdr || aead_ct_body.
	9.	If pad_block > 0, right-pad ciphertext with zero bytes so that len(ciphertext) is a multiple of pad_block. Receivers MUST treat padding bytes as unauthenticated zeros and MUST strip them after parsing hdr_len/body_len and before AEAD_Decrypt.
	10.	ct_hash = H(ciphertext). The hash covers the ciphertext including any right-padding bytes.
	11.	leaf_hash = Ht(“veen/leaf”, label || profile_id || ct_hash || client_id || u64be(client_seq)).
	12.	msg_id = leaf_hash.

RECEIPT fields (in order):
	•	ver: uint (MUST be 1)
	•	label: bstr(32)
	•	stream_seq: uint
	•	leaf_hash: bstr(32)
	•	mmr_root: bstr(32)
	•	hub_ts: uint (hub-local Unix time seconds at commit)
	•	hub_sig: bstr(64) (Ed25519 signature over Ht(“veen/sig”, CBOR(RECEIPT without hub_sig)))

CHECKPOINT fields (in order):
	•	ver: uint (MUST be 1)
	•	label_prev: bstr(32)
	•	label_curr: bstr(32)
	•	upto_seq: uint
	•	mmr_root: bstr(32)
	•	epoch: uint
	•	hub_sig: bstr(64)
	•	witness_sigs: [bstr(64)]? (optional)

For each label, stream_seq is defined as the number of accepted messages (leaves) for that label. The first accepted MSG under a label has stream_seq = 1, the second has stream_seq = 2, and so on. This stream_seq is the MMR leaf index used for that label (see section 7).
	6.	Payload header (encrypted, hub-blind)

CBOR(payload_hdr) is the first item inside the ciphertext and is AEAD-authenticated. payload_hdr is HPKE-encrypted as hpke_ct_hdr and is length-delimited by hdr_len (section 5); aead_ct_body is length-delimited by body_len. Fields (in order):
	•	schema: bstr(32) (application-defined schema identifier)
	•	parent_id: bstr(32)? (optional, parent msg_id)
	•	att_root: bstr(32)? (optional attachment Merkle root; see section 10)
	•	cap_ref: bstr(32)? (optional reference to a capability token; see section 11)
	•	expires_at: uint? (optional Unix time seconds for application-level expiry)

The hub never sees payload_hdr in plaintext.
	7.	Hub commitment (MMR)

For each label, the hub maintains an MMR state (seq, peaks) where seq is the number of accepted leaves (equal to stream_seq for the last accepted message) and peaks is the list of current peak hashes ordered by increasing tree size.

Append x (where x is leaf_hash for the new MSG):
	1.	seq += 1
	2.	Treat x as a leaf. While the least significant bit of seq is 0, fold:
node = Ht(“veen/mmr-node”, left || right)
where left and right are the last two consecutive subtrees. Replace them with node and shift to the next bit.
	3.	After all folds, peaks contains one hash per peak. Compute:
	•	If there is a single peak p, mmr_root = p.
	•	If there are multiple peaks [p1, …, pk] ordered by increasing tree size:
mmr_root = Ht(“veen/mmr-root”, p1 || … || pk).
	4.	Emit a RECEIPT with this mmr_root and stream_seq = seq.

By definition, for each RECEIPT, mmr_root is the MMR root that results from appending leaf_hash at position stream_seq under that label.
	8.	Inclusion proof

mmr_proof is a CBOR map:

{
ver: uint (MUST be 1),
leaf_hash: bstr(32),
path: [ { dir: 0|1, sib: bstr(32) }, … ],
peaks_after: [ bstr(32), … ]
}

Verification folds leaf_hash and path according to dir (0 for left, 1 for right) using Ht(“veen/mmr-node”, left || right) to reconstruct the relevant peak, and then folds peaks_after (ordered by increasing tree size, as in section 7) using Ht(“veen/mmr-root”, …) to yield mmr_root. The verifier checks that this mmr_root matches the mmr_root in some RECEIPT or CHECKPOINT.
	9.	Client algorithms

Send:
	1.	Build payload_hdr and attachments (if any), compute att_root if needed (section 10).
	2.	Form ciphertext and ct_hash as in section 5.
	3.	Construct MSG with fields set according to section 5; compute sig over Ht(“veen/sig”, CBOR(MSG without sig)).
	4.	Submit MSG via submit API (section 16).
	5.	On RECEIPT:
	•	Verify hub_sig using hub_pk.
	•	Check invariants I1..I12.
	•	Advance local MMR for this label to match mmr_root and stream_seq.
	•	Set prev_ack = stream_seq for subsequent MSG under the same label.
	•	Rekey per receipt s: rk_next = HKDF(rk, “veen/rk” || u64be(s)) and derive send/recv keys from rk_next.
	•	Refresh HPKE (new ctx, new enc) at least once per epoch and RECOMMENDED every M messages per (label, client_id), where M is implementation-defined (for example M = 256).

Receive:
	1.	Receive a pair (RECEIPT, MSG) from stream (section 16).
	2.	Verify hub_sig and invariants I1..I12.
	3.	Update local MMR for the label to match mmr_root and stream_seq, validating any provided mmr_proof if with_proof was requested.
	4.	Decrypt:
	•	Split ciphertext into enc (32 bytes), hdr_len (4 bytes), body_len (4 bytes), hpke_ct_hdr, and aead_ct_body as in section 5. Reject if ciphertext is shorter than 40 bytes, if hdr_len/body_len exceed MAX_HDR_BYTES/MAX_BODY_BYTES, or if the remaining ciphertext is shorter than hdr_len + body_len.
	•	After consuming hpke_ct_hdr and aead_ct_body, any remaining bytes are padding. If pad_block > 0, verify remaining bytes are all zero and strip them; if pad_block == 0, reject any remaining bytes as E.SIZE.
	•	Use HPKE.Open with enc to recover payload_hdr, and derive k_body via HPKE.Export(ctx, “veen/body-k”, 32). If ctx is not cached, reconstruct it via HPKE.SetupBaseR with enc and the receiver private key.
	•	Recompute nonce as in section 5.
	•	AEAD_Decrypt with k_body, nonce, and associated data “” to recover body.
	5.	Deliver decrypted payload to the application if all checks pass.
	6.	Accept epochs E in [E_local - CLOCK_SKEW_EPOCHS, E_local + CLOCK_SKEW_EPOCHS] for labels.

Failure to progress prev_ack across R attempts (RECOMMENDED R = 3) SHOULD trigger HPKE refresh and prekey fetch as per RESYNC0 (section 23).
	10.	Attachments

For attachment i (0-based index, contiguous starting at 0 and ascending by 1):
	1.	k_att = HPKE.Export(ctx, “veen/att-k” || u64be(i), 32).
	2.	n_att = Trunc_24(Ht(“veen/att-nonce”, msg_id || u64be(i))).
	3.	c = AEAD_Encrypt(k_att, n_att, “”, b) where b is the attachment plaintext.
	4.	coid = H(c).

att_root is a Merkle root over the ordered list of coids (sorted by attachment index i ascending) with:
	•	Internal node: Ht(“veen/att-node”, left || right)
	•	Root: Ht(“veen/att-root”, peak1 || …)

where peaks are ordered and combined similarly to section 7.

att_root is placed into payload_hdr.att_root. Verification requires recomputing the ordered coid list and the Merkle root and checking equality with att_root.
	11.	Capability tokens and admission

cap_token is a CBOR map:

{
ver: 1,
issuer_pk: bstr(32),
subject_pk: bstr(32),
allow: {
stream_ids: [ bstr(32), … ],
ttl: uint,
rate: { per_sec: uint, burst: uint }?
},
sig_chain: [ bstr(64), … ]
}

Each link in sig_chain is an Ed25519 signature over:

Ht(“veen/cap-link”, issuer_pk || subject_pk || CBOR(allow) || prev_link_hash)

where prev_link_hash is a 32-byte value:
	•	For the root link, prev_link_hash is 32 zero bytes.
	•	For each subsequent link, prev_link_hash is H(previous_signature).

auth_ref is defined as:

auth_ref = Ht(“veen/cap”, CBOR(cap_token))

auth_ref is placed into MSG.auth_ref when the client uses this cap_token.

cap_ref is defined as:

cap_ref = auth_ref

If payload_hdr.cap_ref is present, MSG.auth_ref MUST be present and MUST equal payload_hdr.cap_ref to bind the encrypted payload to the same capability used for admission.

Hubs MUST, at admission time, verify every signature in sig_chain back to the root (prev_link_hash = zeros). Any verification failure yields E.CAP. Hubs MAY cache validated cap_tokens keyed by auth_ref for performance.

Hubs MAY enforce admission via /authorize (section 16). A successful authorization installs an admission record keyed by auth_ref.

Stream scoping note: cap_token.allow.stream_ids refers to the stream_id inputs used to derive labels. Hub-side enforcement of allow.stream_ids requires a deployment-defined stream_id_for_label(label) mapping (for example by sharing routing_key with the hub or providing an out-of-band mapping service). If such a mapping is not available, hubs MUST document that they cannot enforce allow.stream_ids and MUST NOT claim OP0 admission gating for stream scoping; receivers SHOULD enforce stream scoping after decrypt by checking payload_hdr.cap_ref against the expected stream_id policy.
	12.	Invariants (MUST on accepted (RECEIPT, MSG))

For any accepted (MSG, RECEIPT) pair, hubs and clients MUST enforce:

I1. H(ciphertext) = ct_hash.

I2. leaf_hash = Ht(“veen/leaf”, label || profile_id || ct_hash || client_id || u64be(client_seq)).

I3. mmr_root equals the MMR root obtained by appending leaf_hash at position stream_seq in the label’s MMR, starting from an empty MMR at stream_seq = 0 and applying the procedure in section 7.

I4. profile_id is supported by both client and hub.

I5. If att_root exists in payload_hdr, it matches exactly the Merkle root of the ordered coid list for attachments, as defined in section 10.

I6. prev_ack <= last observed stream_seq for the label at the hub at the time of acceptance.

I7. Capability constraints via auth_ref (on the hub) and cap_ref (inside the payload) hold at acceptance. This includes:
	•	ttl not expired,
	•	allowed stream_ids containing the label’s stream_id, and
	•	rate limits not exceeded (see OP0.2 and OP0.3).
Hub enforcement covers auth_ref, ttl, rate limits, and any stream_id policy only if stream_id_for_label(label) is available. Receiver enforcement covers payload_hdr.cap_ref (if present) and any application-level stream_id policy.

I8. Within a label, (client_id, client_seq) is unique across all accepted MSG.

I9. For a fixed (label, client_id), client_seq increases by exactly 1 per accepted MSG under that label.

I10. CBOR determinism is respected for all VEEN wire objects:
	•	exact keys and order as listed in this document,
	•	minimal unsigned integers,
	•	exact bstr sizes where specified,
	•	no unknown keys.

I11. AEAD nonce uniqueness: For any fixed profile_id, label, client_id, and HPKE context (ctx) used to derive k_body, the pair (prev_ack, client_seq) used in MSG MUST NOT repeat across accepted messages. As a consequence, the nonce computed as Trunc_24(Ht(“veen/nonce”, label || u64be(prev_ack) || client_id || u64be(client_seq))) is unique per k_body and AEAD key, and AEAD_Encrypt is never invoked with the same (key, nonce) pair twice.

I12. MMR index consistency: For each label, stream_seq in RECEIPT is equal to the MMR leaf index of leaf_hash for that label (1-based). The label’s MMR seq counter and stream_seq MUST match and MUST be contiguous with no gaps.
	13.	Errors

Error codes are ASCII text at the CBOR layer:
	•	E.SIG    (signature failure, including hub_sig or MSG.sig)
	•	E.SIZE   (bounds violation, including MAX_* limits)
	•	E.SEQ    (sequence invariant violation, including I6, I8, I9, I12)
	•	E.CAP    (capability failure, including invalid sig_chain, expired ttl)
	•	E.AUTH   (missing or invalid authorization record)
	•	E.RATE   (rate limit exceeded)
	•	E.PROFILE (unsupported profile_id)
	•	E.DUP    (duplicate leaf or message)
	•	E.TIME   (epoch or time-related failure)

Response body is CBOR:

{ code: “E.*”, detail: text? }

Hubs MAY include additional structured fields in detail for diagnostics, but clients MUST treat them as informational only.
	14.	Security properties (informal)

	•	End-to-end confidentiality is provided by HPKE plus AEAD.
	•	Authenticity and integrity of MSG and RECEIPT are provided by Ed25519 signatures.
	•	Append-only properties for accepted messages are provided by MMR receipts and CHECKPOINTs.
	•	Public equivocation proofs are possible by presenting two RECEIPTs with identical (label, stream_seq) and different mmr_root or leaf_hash.
	•	Routing privacy is provided by pseudorandom labels and client_id rotation; the hub does not see stream_id or routing_key in plaintext.
	•	Cross-stream replay is prevented because leaf_hash binds ct_hash to (label, profile_id, client_id, client_seq).
	•	Nonce uniqueness for AEAD is guaranteed by I8, I9, and I11.
	•	Length-hiding is provided by pad_block; ciphertext length is padded and included in ct_hash.

	15.	Portability

Portable WORM (write-once read-many) set:
	•	identity_card(pub) (client public identity data)
	•	keystore.enc (encrypted key material)
	•	routing_secret (secret used to derive routing_key)
	•	receipts.cborseq (append-only CBOR Sequence of RECEIPT)
	•	checkpoints.cborseq (append-only CBOR Sequence of CHECKPOINT)
	•	payloads.cborseq (append-only CBOR Sequence of MSG payloads, if stored)
	•	sync_state = { last_stream_seq, last_mmr_root } per label
	•	cap_tokens (set of cap_token objects)
	•	optional attachments, addressed by coid

CBOR Sequence is as in RFC 8742.
	16.	API surface (transport-agnostic)

submit:
	•	Request: POST CBOR(MSG)
	•	Response: CBOR(RECEIPT)
	•	Errors: CBOR({ code: “E.*”, detail?: text })

stream:
	•	Request: GET with parameters label, from=stream_seq, with_proof=bool?
	•	Response: CBOR Sequence of items:
{ RECEIPT, MSG, mmr_proof? }

where mmr_proof is present only if with_proof=1.

checkpoint_latest:
	•	Request: GET label
	•	Response: CHECKPOINT

checkpoint_range:
	•	Request: GET epoch range [epoch_min, epoch_max]
	•	Response: CBOR Sequence of CHECKPOINT

authorize:
	•	Request: POST CBOR(cap_token)
	•	Response: { auth_ref: bstr(32), expires_at: uint }

report_equivocation:
	•	Request: POST two RECEIPT with identical (label, stream_seq) and differing leaf_hash or mmr_root
	•	Response: { ok: bool }

Implementations MUST treat all endpoints as transport-agnostic; mappings for HTTP, QUIC, and NATS are defined in section 30.
	17.	Complexity

Hub append per MSG:
	•	Time: amortized O(1).
	•	Memory: O(log N) per label for peaks.

Inclusion proofs:
	•	Proof size: O(log N).
	•	Verification: O(log N) hash operations.

Client hot paths (per accepted MSG):
	•	O(1) for local state updates, plus O(log N) if verifying proofs.
	•	Cryptographic operations: O(1) per MSG (HPKE, AEAD, Ed25519).

	18.	Interop discipline

All implementations that claim compliance MUST adhere to:
	•	Exact map key order as listed in this document.
	•	Unknown keys rejected in all VEEN maps.
	•	Minimal unsigned integers.
	•	Exact-size bstr for fixed-size fields (32, 64 bytes, etc).
	•	peaks in MMR and attachments Merkle root ordered by increasing tree size.
	•	Tag prefix “veen/” for all Ht domain separation tags.
	•	Padding bytes included in ct_hash; ciphertext is hashed after padding.
	•	Hubs sign RECEIPT after updating MMR.
	•	Clients verify hub_sig before attempting decryption.

	19.	Limits (defaults, configurable)

The following limits are defaults and MAY be tuned per deployment, but MUST be bounded:
	•	MAX_MSG_BYTES = 1_048_576
	•	MAX_BODY_BYTES = 1_048_320
	•	MAX_HDR_BYTES = 16_384
	•	MAX_PROOF_LEN = 64
	•	MAX_CAP_CHAIN = 8
	•	MAX_ATTACHMENTS_PER_MSG = 1024
	•	CLOCK_SKEW_EPOCHS = 1

Exceeding any bound yields E.SIZE. Implementations SHOULD document any deviations from these default values.
	20.	Conformance vectors

Test vectors and scenarios:
	•	A: single writer per label; basic append-only correctness.
	•	B: multi-writer with (client_id, client_seq) uniqueness and replay prevention.
	•	C: epoch roll and CHECKPOINT chaining correctness across time windows.
	•	D: capability admission via authorize, including sig_chain and rate limiting.

	21.	Operational Profile OP0 (normative, no wire changes)

OP0.1 Processing order (hub):

For each submit request:
	1.	Decode CBOR(MSG); on failure or truncation, return E.SIZE.
	2.	Check bounds (MAX_MSG_BYTES, MAX_HDR_BYTES, etc); on violation, return E.SIZE.
	3.	Verify MSG.sig; on failure, return E.SIG.
	4.	If admission is configured, authorize via auth_ref (section 11); otherwise skip:
	•	Missing admission record: E.AUTH.
	•	Capability failure: E.CAP.
	•	Rate overflow: E.RATE.
	5.	Append leaf_hash to the label’s MMR, update stream_seq and mmr_root, enforcing invariants I1..I12. On violation, return E.SEQ, E.DUP, or E.PROFILE as appropriate.
	6.	Sign RECEIPT (hub_sig).
	7.	Respond with RECEIPT.

On HTTP, hubs SHOULD map error codes as:
	•	E.SIZE -> 413 Payload Too Large
	•	E.RATE -> 429 Too Many Requests
	•	E.AUTH, E.CAP -> 403 Forbidden
	•	E.PROFILE, E.TIME -> 400 Bad Request
	•	E.SIG, E.SEQ, E.DUP -> 409 Conflict

OP0.2 Admission gating:

Hubs SHOULD require /authorize for write access. The authorization record keyed by auth_ref contains:
	•	allowed_stream_ids: set of stream_id values
	•	rate: { per_sec, burst }
	•	expiry: Unix time seconds
	•	subject_pk: expected subject public key

Missing record yields E.AUTH. Expired record yields E.CAP. Rate overflow yields E.RATE.

If the hub cannot derive stream_id from label (for example because routing_key is not shared with the hub), it MUST document that allowed_stream_ids are not enforced at admission time and MUST NOT represent itself as enforcing stream scoping under OP0.2.

OP0.3 Rate limiting RL0:

Token bucket per (auth_ref, label) and optionally per IP address. Each accepted MSG (i.e., each RECEIPT) consumes 1 token. Refill every 1 s by per_sec up to burst. Servers SHOULD emit Retry-After header (seconds) on E.RATE when using HTTP.

OP0.4 Worker pools:

Hubs SHOULD use separate worker pools for:
	•	verification: MSG.sig, cap_token signature chains, basic CBOR checks;
	•	commitment: MMR append, fsync, checkpointing.

Under sustained overload, hubs SHOULD apply back-pressure by returning 503 Service Unavailable when the verification queue exceeds a configured limit Qmax.

OP0.5 Storage:

Hubs SHOULD store:
	•	receipts.cborseq: append-only file of RECEIPT.
	•	payloads.cborseq: append-only file of MSG payloads, if retention for payloads is enabled.
	•	checkpoints.cborseq: append-only file of CHECKPOINT.

fsync policy: sync every N = 100 receipts or T = 100 ms, whichever comes first. Peaks SHOULD be checkpointed every K appends per label to allow fast restart.

OP0.6 Padding policy:

pad_block is in {0, 256, 1024}. Default:
	•	pad_block = 256 for messaging use cases.
	•	pad_block = 0 for bulk ingest where length-hiding is not required.

Padding bytes are zeros and are included in ct_hash.

OP0.7 Clock discipline:

hub_ts is informational and SHOULD reflect hub’s best-effort Unix time seconds. Acceptance windows use CLOCK_SKEW_EPOCHS as in section 4. Large drift relative to clients SHOULD cause E.TIME and SHOULD be surfaced via metrics and alerts.
	22.	Key Distribution Profile KEX0 (normative optional)

KEX0.1 Hub key pin:

Applications ship hub_pk out of band (configuration file, static bundle, etc). For hub key rotation, a rotation window W is defined. During W:
	•	CHECKPOINT objects carry witness_sigs from both old and new hub keys.
	•	Clients that pin hub_pk SHOULD accept CHECKPOINT only if both witness_sigs are present and valid.

After W, the old key is retired and CHECKPOINT no longer carries its signatures.

KEX0.2 Client identity rotation:

client_id rotates at least once per epoch. Key continuity (linking old and new client_id) is tracked locally and MUST NOT be exposed in plaintext MSG fields. Prekeys are signed by id_sign and MUST include expiry times. Hubs SHOULD reject expired prekeys or use them only for decryption of older messages.

KEX0.3 Revocation:

Hubs MAY blacklist client_id or auth_ref. Subsequent submit operations from blacklisted identities return E.CAP or E.AUTH. Blacklist entries SHOULD have expiry times or require manual clearing. Revocation state MAY be distributed via an out-of-band channel.
	23.	Resynchronization and Recovery RESYNC0

RESYNC0.1 Duplicate detection:

Hubs maintain a Bloom filter plus LRU cache of recent leaf_hash values for a configurable window Wdup. A repeat leaf_hash in this window yields E.DUP. The authoritative duplicate check remains the label’s accepted set defined by I8 and I12.

RESYNC0.2 Client resync:

Clients that lose connection or suspect divergence:
	1.	Reconnect with stream?from=last_stream_seq+1.
	2.	Verify hub_sig and invariants I1..I12 for each RECEIPT and MSG.
	3.	If mmr_root or proofs diverge from local state, request checkpoint_latest for the label, rebuild local peaks from CHECKPOINT, and then replay receipts from an earlier stream_seq as needed.

RESYNC0.3 Rekey:

If prev_ack fails to progress across R consecutive attempts for a given label (RECOMMENDED R = 3):
	•	Client refreshes HPKE ctx (new prekey, new HPKE key exchange).
	•	Client MAY fetch a fresh prekey set or update its own id_dh/id_sign.

RESYNC0.4 Durable state:

Clients SHOULD persist, per label:
	•	rk (current rekey material),
	•	current profile_id,
	•	last_stream_seq,
	•	last_mmr_root.

These values MUST be persisted atomically so that after a crash, resync uses a consistent snapshot.
	24.	RPC Overlay RPC0 (pure overlay, no wire changes)

RPC0.1 Request message:
	•	payload_hdr.schema = H(“rpc.v1”)
	•	payload body:
{
method: text,
args: CBOR,
timeout_ms: uint?,
reply_to: bstr(32)?
}

msg_id acts as the correlation id. Servers reply with parent_id = msg_id in the reply payload_hdr.

RPC0.2 Reply message:
	•	payload_hdr.schema = H(“rpc.res.v1”)
	•	payload body:
{
ok: bool,
result: CBOR?,
error: { code: text, detail: text? }?
}

If ok = true, result MUST be present and error MUST be absent. If ok = false, error MUST be present.

RPC0.3 Idempotency:

Clients MAY set body.idem: uint64 as an idempotency key. Servers MUST treat (method, client_id, idem) as an idempotency key, ensuring that duplicate requests with the same tuple have the same effect and return the same logical result.

RPC0.4 Timeouts and retries:

Clients SHOULD use application-level timeouts and exponential backoff when retrying. Duplicate requests are harmless due to E.DUP and idempotency keys.
	25.	CRDT Overlay CRDT0 (pure overlay)

CRDT0.1 LWW-Register:
	•	schema = H(“crdt.lww.v1”)
	•	body:
{ key: bytes, ts: uint64, value: bytes }

Total order by (ts, stream_seq) breaks ties. Application clocks are optional. Last writer wins based on this total order.

CRDT0.2 OR-Set:
	•	schema = H(“crdt.orset.v1”)
	•	add operation body: { id: bstr(32), elem: bytes }
	•	remove operation body: { tomb: [ bstr(32), … ] }

Concurrency is resolved by element presence: an element is present if there exists an add id that is not listed in any tomb set in the prefix considered.

CRDT0.3 Counter G-Counter:
	•	schema = H(“crdt.gcnt.v1”)
	•	body: { shard: bstr(32), delta: uint64 }

Reduction is sum of deltas per shard. Snapshots are deterministic folds of receipts up to upto_seq in CHECKPOINT.

CRDT0.4 Provenance:

att_root commits any large element payloads. Verification requires recomputing the coid set from attachment ciphertexts and checking att_root.
	26.	Anchoring and Bridging ANCHOR0 (pure overlay)

ANCHOR0.1 External anchor interface:
	•	anchor_publish(root: bstr(32), epoch: uint, ts: uint, nonce: bytes) -> anchor_ref: bytes
	•	anchor_verify(root: bstr(32), anchor_ref: bytes) -> bool

Implementations map these operations to a ledger or anchoring system of choice (public blockchain, internal audit log, etc).

ANCHOR0.2 Policy:

Hubs SHOULD anchor mmr_root at a fixed cadence, for example:
	•	every K receipts per label, or
	•	every T minutes per deployment.

anchor_ref MUST be stored alongside CHECKPOINT so that auditors can recover the binding from mmr_root to external ledger.

ANCHOR0.3 Cross-hub mirroring:

A bridge process subscribes to stream(with_proof=1) on hub A and submits those MSG to hub B under label’ with a distinct routing_key’. RECEIPTs from B include a new leaf_hash and mmr_root. Provenance is preserved by embedding parent_id = original msg_id in the mirrored payload_hdr.
	27.	Observability OBS0

OBS0.1 Metrics (names and units):
	•	veen_submit_ok_total (counter)
	•	veen_submit_err_total{code} (counter)
	•	veen_verify_latency_ms (histogram)
	•	veen_commit_latency_ms (histogram)
	•	veen_end_to_end_latency_ms (histogram)
	•	veen_queue_depth (gauge)
	•	veen_rate_limited_total (counter)
	•	veen_checkpoint_interval (histogram)
	•	veen_anchor_fail_total (counter)

OBS0.2 Logs:

Structured JSON per submit with fields:
	•	label
	•	client_id_prefix (for example first 8 hex chars)
	•	stream_seq
	•	leaf_hash_prefix
	•	code? (error code if any)
	•	bytes_in
	•	bytes_out
	•	verify_ms
	•	commit_ms

OBS0.3 Health:

/healthz returns:

{
ok: bool,
profile_id: bstr(32),
peaks_count: uint,
last_stream_seq: uint,
last_mmr_root: bstr(32)
}
	28.	Compliance and Retention COMP0

COMP0.1 Retention:
	•	receipts.cborseq retained for Rr days.
	•	payloads.cborseq retained for Rp days if payload retention is enabled.
	•	checkpoints.cborseq retained indefinitely or as long as needed for audit plus external anchoring.

File rotation MAY be by size or time. An index sidecar per rotated file stores:

{ offset: uint64, stream_seq: uint64 }

to allow random access.

COMP0.2 Encryption at rest:
	•	keystore.enc MAY be sealed with OS KMS or hardware security modules.
	•	payloads and receipts MAY be whole-file AEAD-encrypted at rest. This is orthogonal to the on-wire protocol and MUST NOT change wire formats.

COMP0.3 Access:

Read-only export endpoints:
	•	stream?with_proof=1 for auditors.

These endpoints SHOULD be rate-limited and MAY require signed URLs or mutual TLS.
	29.	Security Hardening SH0

SH0.1 Prefilter:

During overload, hubs MAY require a stateless cookie (QUIC-token-like) or proof-of-work salt before performing signature verification. Failure to provide such a cookie yields HTTP 403 or 429 depending on deployment policy.

SH0.2 Constant-time checks:
	•	Ed25519 verify MUST be constant-time.
	•	String/bytes comparisons on auth_ref MUST use constant-time equality to avoid timing leaks.

SH0.3 TLS:

When using TLS, hubs MUST:
	•	use modern AEAD cipher suites,
	•	disable TLS-level compression.

SH0.4 Bounds first:

All size and bounds checks MUST be performed before performing costly signature or HPKE work, to avoid waste under attack or abuse.
	30.	Deployment Reference DR0

HTTP:
	•	Content-Type application/cbor for all POST bodies.
	•	stream endpoint returns Content-Type application/cbor-seq.

QUIC:
	•	Map endpoints 1:1 with HTTP-like semantics over QUIC streams.
	•	Use TLS as in SH0.3.

NATS:
	•	Subjects:
	•	submit.<label_hex> for MSG submissions.
	•	Replies carry RECEIPT as CBOR in the reply payload.

	31.	Test Suite TS0

TS0.1 Unit tests:
	•	Conformance vectors A to D for basic flows.
	•	CBOR determinism for MSG, RECEIPT, CHECKPOINT, mmr_proof, cap_token.
	•	Nonce uniqueness for AEAD under repeated sends.

TS0.2 Property tests:
	•	MMR associativity and idempotence of append operations.
	•	Proof minimality for mmr_proof.
	•	Duplicate rejection according to I8 and I12.

TS0.3 Fuzz tests:
	•	Malformed CBOR maps (unknown keys, overlong integers, indefinite lengths).
	•	Truncated ciphertext, receipts, and checkpoints.

TS0.4 Interop tests:
	•	Cross-implementation exchange of vectors A to D.
	•	Byte-for-byte equality on MSG and RECEIPT encodings.
	•	Identical mmr_root for identical sequences of leaf_hash values.

	32.	Reference state machines (informative)

Hub RX:
	•	Idle
-> DecodeOK? else E.SIZE
-> BoundsOK? else E.SIZE
-> SigOK? else E.SIG
-> Authorized? else E.AUTH / E.CAP / E.RATE
-> Commit (MMR append, invariants I1..I12) else E.SEQ / E.DUP / E.PROFILE
-> Sign RECEIPT
-> Respond.

Client TX:
	•	Build MSG
-> HPKE / AEAD
-> Sign
-> Submit
-> ReceiptOK? else retry with backoff or resync
-> Verify + Advance local MMR
-> Done.

Client RX:
	•	ReceiptOK? else drop
-> Verify root / proof
-> Decrypt
-> Deliver to application.

	33.	Compatibility

All OP0, KEX0, RESYNC0, RPC0, CRDT0, ANCHOR0, OBS0, COMP0, SH0, DR0, and TS0 clauses are additive and do not change the v0.0.1 wire format defined in sections 5 to 8. Implementations MAY claim:
	•	“VEEN v0.0.1 Core”
	•	“VEEN v0.0.1 Core + OP0”
	•	“VEEN v0.0.1 Core + OP0 + RPC0 + CRDT0”
	•	or similar, depending on which profiles are implemented.

An implementation that implements only Core MUST still obey all invariants I1..I12 and the CBOR and MMR rules in sections 5 to 8.
	34.	Summary

This document consolidates the VEEN v0.0.1 core with a fixed wire format and specifies operational edges (admission, rate limiting, rotation, recovery) plus portable overlays for RPC, CRDTs, external anchoring, observability, compliance, and hardening. A compliant “Core + OP0” hub and client can be deployed for end-to-end encrypted, verifiable messaging and audit logging immediately; overlays can be enabled incrementally without re-encoding messages or changing bytes on the wire.

## spec-2.txt

VEEN v0.0.1+ — Federated and Hardened Addendum
Wire-compatible overlays on VEEN v0.0.1 Core (sections 5–8 unchanged)
	0.	Status and relationship to VEEN v0.0.1

This document defines VEEN v0.0.1+ as a set of normative, wire-compatible overlays on top of the VEEN v0.0.1 core specification.

Constraints:
	•	No new fields are added to MSG, RECEIPT, CHECKPOINT, mmr_proof, or cap_token.
	•	Sections 5–8 of the v0.0.1 spec are unchanged and remain the single source of truth for wire objects and proofs.
	•	All additions in this document are:
	•	operational constraints on hub/client behavior, or
	•	encrypted payload-layer schemas (overlay messages).

Profiles introduced:
	•	FED1: Federated hubs and authority records
	•	AUTH1: Label authority and single-primary discipline
	•	KEX1+: Strengthened key and capability lifecycle
	•	SH1+: Extended hardening and admission pipeline
	•	LCLASS0: Label classification overlay
	•	META0+: Schema registry and discovery overlay

VEEN v0.0.1+ means:
	•	VEEN v0.0.1 Core + OP0 + KEX0 + RESYNC0 (as in the base document)
	•	plus one or more of FED1, AUTH1, KEX1+, SH1+, LCLASS0, META0+ as described here.

	1.	Additional notation and assumptions

1.1 General

This document reuses all notation from v0.0.1:
	•	Ht(tag, x), HPKE, Ed25519, X25519, etc.
	•	label, stream_id, epoch, profile_id, leaf_hash, msg_id.

New derived identifiers:
	•	hub_id: 32-byte identifier derived from hub_pk.
	•	realm_id: 32-byte realm identifier (if an ID overlay is in use).
	•	admin streams: fixed stream_id values used for control overlays.

1.2 hub_id

For any hub public key hub_pk (Ed25519):

hub_id = Ht(“veen/hub-id”, hub_pk)

Properties:
	•	hub_id is bstr(32).
	•	hub_id is stable for the lifetime of hub_pk.
	•	hub_id never appears in MSG/RECEIPT/CHECKPOINT; it is derived from hub_pk when needed.

Multiple hubs MAY share the same hub_pk and hub_id if they are logically the same authority (for example multiple replicas of a single hub process).

1.3 Realm and admin streams

If a deployment uses realms, it MUST define:
	•	realm_id: bstr(32), unique per logical realm.

Admin streams for a given realm_id:
	•	stream_fed_admin = Ht(“veen/admin”, realm_id)
	•	stream_revocation = Ht(“veen/revocation”, realm_id)
	•	stream_label_class = Ht(“veen/label-class”, realm_id)
	•	stream_schema_meta = Ht(“veen/meta-schema”, realm_id)

Deployments without realms MAY fix a single global realm_id and reuse these definitions.
	2.	FED1 — Federated hubs and authority records

2.1 Federation domain

A federation domain is a set of hubs that process VEEN traffic for overlapping sets of labels and realms. This addendum does not define automatic discovery; hubs learn about each other and about federation membership out of band or via administrative streams.

2.2 Authority record schema

Schema identifier:

schema_fed_authority = H(“veen.fed.authority.v1”)

Payload body (CBOR, fixed key order):

{
realm_id:    bstr(32),        // realm this record applies to
stream_id:   bstr(32),        // stream_id within the realm
primary_hub: bstr(32),        // hub_id of primary
replica_hubs: [ bstr(32) ],   // zero or more hub_id values
policy:      text,            // “single-primary” | “multi-primary”
ts:          uint,            // issued_at, Unix time seconds
ttl:         uint             // validity duration in seconds
}

Semantics:
	•	For a given pair (realm_id, stream_id), at most one authority record is considered active at time T:
	•	active if ts <= T < ts + ttl
	•	inactive otherwise
	•	If multiple active records exist due to misconfiguration, hubs MUST apply a deterministic tie-breaking rule, for example:
	•	sort records by (ts ascending, primary_hub ascending)
	•	choose the first

2.3 Publication

Authority records MUST be published as VEEN MSG on the admin stream for that realm:
	•	label for stream_fed_admin is computed in the same way as any other label (section 4 of v0.0.1).
	•	authority updates are end-to-end encrypted and audited like any other payload.

Recommendations:
	•	Only a small, well-defined set of principals (for example realm administrators) SHOULD be allowed to emit veen.fed.authority.v1 messages.
	•	These principals SHOULD be identified via cap_token and org-level id_sign keys.

2.4 Authority view at a hub

Each hub maintains an in-memory view:

authority_view[(realm_id, stream_id)] = {
primary_hub: bstr(32),
replica_hubs: [bstr(32)],
policy: text,            // “single-primary” | “multi-primary”
ts: uint,
ttl: uint
}

Construction:
	•	For each veen.fed.authority.v1 payload on stream_fed_admin:
	•	verify payload_sig and hub_sig as normal,
	•	apply the tie-breaking rules in 2.2 to keep only the active record with highest precedence.

If a realm_id/stream_id has no entry in authority_view, its authority is “unspecified” (see AUTH1).
	3.	AUTH1 — Label authority and single-primary discipline

3.1 Label to (realm_id, stream_id) mapping

This addendum assumes that each label corresponds to a (realm_id, stream_id) pair according to deployment rules. Typical options:
	•	stream_id is known to the application and Ht(“veen/label”, routing_key || stream_id || u64be(E)) is used to derive label.
	•	realm_id is fixed per hub or per application partition.

AUTH1 requires that hub operators document and implement a deterministic function:

stream_id_for_label(label) -> stream_id

and, when realms are used:

realm_id_for_label(label) -> realm_id

These functions are not encoded on the wire and are deployment-specific.

3.2 Label authority record

For each label L, a hub may derive a label_authority view:

label_authority(L) = {
realm_id:    bstr(32)?,
stream_id:   bstr(32),
primary_hub: bstr(32)?,
policy:      text        // “single-primary” | “multi-primary” | “unspecified”
}

Computation:
	•	stream_id = stream_id_for_label(L).
	•	realm_id = realm_id_for_label(L) if defined.
	•	Look up authority_view[(realm_id, stream_id)]:
	•	If an entry exists, set primary_hub, policy accordingly.
	•	If none exists, set policy = “unspecified” and primary_hub = null.

3.3 Admission rule under AUTH1

A hub implementing AUTH1 MUST enforce the following at the start of the submit pipeline (after basic syntactic checks but before MMR commit):

Given a MSG with label L:
	1.	Compute label_authority(L).
	2.	If policy == “single-primary” and primary_hub is defined:
	•	If hub_id != primary_hub:
	•	MUST reject the MSG.
	•	MUST return E.AUTH or E.CAP.
	•	SHOULD include a human-readable detail indicating “not primary for label”.
	3.	If policy == “multi-primary”:
	•	MAY accept the MSG, but SHOULD record that this label is multi-primary for operational monitoring.
	4.	If policy == “unspecified”:
	•	MAY accept the MSG according to local policy, which MUST be documented (for example default to single-primary at local hub_id, or default to multi-primary).

3.4 Equivocation classification (AUTH1)

Equivocation in v0.0.1 is defined as two RECEIPTs with identical (label, stream_seq) and differing leaf_hash or mmr_root.

Under AUTH1:
	•	If label_authority(L).policy == “single-primary”, and an equivocation is proven for label L:
	•	This indicates either:
	•	a compromised or misbehaving primary_hub, or
	•	an incorrect authority configuration.
	•	Hubs and auditors SHOULD:
	•	log the event with high severity,
	•	anchor the equivocation evidence via ANCHOR0,
	•	trigger operational responses (rotation of hub_pk, removal or isolation of the offending hub).

The report_equivocation API in v0.0.1 remains unchanged; AUTH1 only clarifies how to interpret equivocations relative to authority rules.
	4.	KEX1+ — Key and capability lifecycle

KEX1+ strengthens the lifecycle guarantees for client_id and cap_token without changing cap_token encoding.

4.1 Client key usage bounds

Deployments MUST configure the following parameters (per domain, per realm, or globally):
	•	max_client_id_lifetime_sec (recommended <= 86400)
	•	max_msgs_per_client_id_per_label (recommended <= 2^16)

Clients that claim KEX1+ compliance MUST:
	•	track, for each client_id:
	•	created_at (Unix time seconds),
	•	sent_msgs_per_label[label] (message count per label).

They MUST rotate client_id (and corresponding prekeys) when:
	•	now - created_at >= max_client_id_lifetime_sec, OR
	•	sent_msgs_per_label[label] >= max_msgs_per_client_id_per_label for any label.

Hubs that claim KEX1+ compliance SHOULD:
	•	track, for each (label, client_id), the observed messages and an approximate created_at.
	•	reject MSG for which:
	•	now - observed_created_at > max_client_id_lifetime_sec, OR
	•	observed_msg_count_per_label[label, client_id] >= max_msgs_per_client_id_per_label,

by returning E.CAP or E.AUTH.

4.2 Capability ttl semantics

cap_token.allow.ttl in v0.0.1 is interpreted as a validity duration. To apply a strict upper bound, KEX1+ introduces issued_at.

Deployments MUST define one of the following:
	•	cap_token carries an explicit issued_at: uint field in its CBOR body, OR
	•	issued_at is taken as the hub’s hub_ts at the time of authorize.

KEX1+ rule:
	•	A cap_token is valid at time now if and only if:
now <= issued_at + ttl

Hubs MUST NOT:
	•	install or keep an admission record for auth_ref beyond this bound.
	•	accept MSG referencing auth_ref after expiry.

Failure MUST yield E.CAP or E.AUTH.

Clients SHOULD:
	•	refresh their capabilities sufficiently in advance of ttl expiry and update MSG.auth_ref accordingly.

4.3 Revocation overlay

Schema identifier:

schema_revocation = H(“veen.revocation.v1”)

Payload body:

{
kind:   text,      // “client-id” | “auth-ref” | “cap-token”
target: bstr(32),  // client_id, auth_ref, or H(CBOR(cap_token))
reason: text?,
ts:     uint,      // revocation time
ttl:    uint?      // optional revocation duration
}

Semantics:
	•	kind = “client-id”:
	•	client_id identified by target is revoked.
	•	kind = “auth-ref”:
	•	auth_ref identified by target is revoked.
	•	kind = “cap-token”:
	•	the cap_token whose H(CBOR(cap_token)) equals target is revoked.

Revocation interval:
	•	If ttl is absent: revocation applies for [ts, +∞).
	•	If ttl is present: revocation applies for [ts, ts+ttl).

Operational rules for hubs implementing KEX1+:
	•	Maintain an in-memory revocation view constructed by folding veen.revocation.v1 payloads from stream_revocation.
	•	At admission time for submit:
	•	If kind == “client-id” and MSG.client_id matches target, and current_time ∈ [ts, ts+ttl or +∞), reject with E.CAP or E.AUTH.
	•	If kind == “auth-ref” and MSG.auth_ref matches target, and current_time ∈ [ts, ts+ttl or +∞), reject with E.CAP or E.AUTH.
	•	If kind == “cap-token”, and auth_ref used in MSG was derived from the revoked cap_token, treat it as invalid and reject with E.CAP or E.AUTH.

Revocation records are never removed from the log; expiry only controls operational enforcement, not history.

4.4 Interaction with RESYNC0

Clients that resync after being offline SHOULD:
	•	re-fetch revocation events up to current time.
	•	re-evaluate whether their client_id or auth_ref has been revoked.
	•	discard local keys and tokens that are now invalid.

Hubs SHOULD ensure that revocation streams are anchored and auditable to avoid silent deletion.
	5.	SH1+ — Extended hardening and admission pipeline

5.1 Admission stages

A hub implementing SH1+ SHOULD process submit requests through the following ordered stages:

Stage 0: Stateless prefilter
	•	Perform:
	•	size checks at the transport layer (for example reject if Content-Length > MAX_MSG_BYTES).
	•	basic IP/subnet allow/deny filtering if configured.
	•	optional verification of a stateless token or proof-of-work cookie.
	•	If checks fail, drop the request or return an HTTP error (for example 403 or 429) without attempting CBOR decoding.

Stage 1: Structural checks
	•	Decode CBOR(MSG).
	•	Enforce:
	•	MAX_MSG_BYTES,
	•	expected type and size for ver, profile_id, label, client_id, ct_hash, sig,
	•	CBOR determinism for MSG (no unknown keys, correct order, minimal integers).
	•	If decoding or structural checks fail, return E.SIZE.

Stage 2: Cryptographic and authorization checks
	•	Verify MSG.sig.
	•	Enforce:
	•	profile_id support (I4).
	•	capability admission via auth_ref and cap_token (I7), including:
	•	ttl checks from KEX1+,
	•	revocation checks from KEX1+,
	•	rate limiting (OP0.3).
	•	Reject with:
	•	E.SIG for signature failure,
	•	E.CAP / E.AUTH for capability or admission failures,
	•	E.RATE for rate limit overflow.

Stage 3: Commit
	•	Enforce invariants I1..I3, I5–I12 from v0.0.1.
	•	Append leaf_hash to the MMR for this label and update stream_seq and mmr_root.
	•	Sign RECEIPT and persist RECEIPT and optional payloads/checkpoints.
	•	Return RECEIPT on success.

Under sustained load, hubs MAY place independent concurrency or queue limits on each stage to avoid starvation and collapse.

5.2 Proof-of-work cookie (optional)

Proof-of-work cookies are used as an optional prefilter at Stage 0. They are not part of MSG.

Schema identifier:

schema_pow_cookie = H(“veen.pow.cookie.v1”)

Payload body:

{
challenge:   bstr,
nonce:       uint64,
difficulty:  uint8
}

Validation:
	•	Compute v = Ht(“veen/pow”, challenge || u64be(nonce)).
	•	v is interpreted as a 256-bit integer; a cookie is valid for given difficulty d if the first d bits of v are zero.

Usage:
	•	Hubs MAY require clients to attach a valid pow_cookie (for example via a separate RPC overlay or transport header) for certain classes of connections or under suspicious load.
	•	The mapping from submit requests to pow_cookie (per-IP, per-auth_ref, or per-client_id) is deployment-specific.

Difficulty policy:
	•	Hubs SHOULD choose difficulty dynamically based on observed load, such that legitimate clients can still submit messages with acceptable latency.

5.3 Bounds-first behavior

SH1+ requires that:
	•	All size and structural checks (MAX_MSG_BYTES, MAX_HDR_BYTES, MAX_ATTACHMENTS_PER_MSG, etc.) be performed before any Ed25519 or HPKE operation.
	•	This reduces the per-request cost under malformed-input attacks.

	6.	LCLASS0 — Label classification overlay

LCLASS0 lets deployments associate hints with labels without exposing payloads.

6.1 Schema

Schema identifier:

schema_label_class = H(“veen.label.class.v1”)

Payload body:

{
label:          bstr(32),
class:          text,          // for example “user” | “wallet” | “log” | “admin”
sensitivity:    text?,         // for example “low” | “medium” | “high”
retention_hint: uint?          // advisory retention in seconds
}

Published via:
	•	The reference implementation accepts signed label-class records via the hub’s `/label-class` endpoint and stores them as hub state.
	•	`stream_label_class` remains reserved for future stream-backed replication of label classifications.

6.2 Operational use

Hubs MAY use label classification as follows:
	•	Padding selection:
	•	For class “user” or “wallet”, choose pad_block from {256, 1024}.
	•	For class “log” or “metric”, pad_block = 0 MAY be used.
	•	Rate limiting:
	•	For class “admin” or “control”, allow higher rate/burst.
	•	For class “user”, use default RL0 parameters.
	•	For class “bulk”, apply tighter throughput limits.
	•	Retention:
	•	retention_hint MAY be used to select default retention windows in COMP0 (subject to policy and regulatory requirements).

These effects are advisory; failure to define or apply label classifications does not invalidate VEEN correctness.
	7.	META0+ — Schema registry and discovery overlay

META0+ provides a registry of schemas used on a VEEN fabric.

7.1 Schema descriptor

Schema identifier:

schema_meta_schema = H(“veen.meta.schema.v1”)

Payload body:

{
schema_id: bstr(32),
name:      text,
version:   text,        // for example “v1”, “v0.0.1”
doc_url:   text?,       // optional documentation URL or identifier
owner:     bstr(32)?,   // optional principal or org public key
ts:        uint         // registration time
}

Semantics:
	•	schema_id MUST match the 32-byte value used in payload_hdr.schema when that schema is used.
	•	name SHOULD be a concise identifier (for example “rpc.v1”, “wallet.transfer.v1”).
	•	version is application-defined; it does not affect semantics at the VEEN layer.
	•	owner identifies the controlling organization or principal if present.

Descriptive records are carried on:
	•	stream_schema_meta for the relevant realm or deployment.

7.2 Tooling and interop

Implementations MAY:
	•	subscribe to schema meta streams to build a mapping:
schema_id -> { name, version, owner, doc_url }
	•	use this mapping to:
	•	generate documentation,
	•	validate which schemas are used in which realms,
	•	perform static analysis or compliance checks.

META0+ does not change application semantics; it only improves discoverability and introspection.
	8.	Profile claims and compliance levels

An implementation MAY claim one of the following VEEN v0.0.1+ profiles:
	•	“VEEN v0.0.1+ Core”:
	•	v0.0.1 Core + OP0 + KEX0 + RESYNC0.
	•	No requirements from FED1, AUTH1, KEX1+, SH1+, LCLASS0, META0+.
	•	“VEEN v0.0.1+ Federated”:
	•	“Core” plus full compliance with FED1 and AUTH1.
	•	“VEEN v0.0.1+ Hardened”:
	•	“Federated” plus full compliance with KEX1+ and SH1+.
	•	“VEEN v0.0.1+ Federated + Hardened + Meta”:
	•	“Hardened” plus LCLASS0 and META0+.

Profile claims are not encoded on the wire; they are for documentation, configuration, and interop testing.
	9.	Security and operational impact

VEEN v0.0.1+ preserves all security properties of VEEN v0.0.1 (section 14 of the base spec) and adds:
	•	explicit single-primary discipline per (realm_id, stream_id) to avoid unintended multi-primary conflicts;
	•	bounded lifetimes and explicit revocation for client keys and capabilities;
	•	structured admission pipeline to handle adversarial traffic;
	•	classification and metadata overlays to steer operational policy without revealing payload contents.

The wire format remains unchanged; deployments can incrementally adopt these profiles without re-encoding messages or altering existing on-disk logs.

## spec-3.txt

Title
Extended Operation Profiles for VEEN v0.0.1 Core
	0.	Scope

This document defines nine higher level operation profiles on top of the VEEN v0.0.1 core. Each profile is expressed as one or more payload schemas and behavioral rules. No change is made to the VEEN wire format defined by the MSG, RECEIPT, CHECKPOINT, and mmr_proof objects. All profiles use the existing fields profile_id, label, client_id, client_seq, prev_ack, auth_ref, ct_hash, ciphertext, and sig.

All structures below are CBOR maps with deterministic encoding as required by VEEN v0.0.1. The keys listed are text keys unless otherwise specified. Ordering of keys in CBOR maps follows the order in each definition.
	1.	Common Conventions

1.1 Operation identifiers

operation_id: bstr(32) is defined as Ht(“veen/operation-id”, msg_id) where msg_id is the MSG leaf_hash. Application level references between messages MAY use operation_id instead of raw msg_id.

parent_operation_id: bstr(32)? is an optional reference in payload bodies that points to another operation_id to express dependence or causality.

1.2 Account identifiers and amounts

account_id: bstr(32) is an opaque identifier for an account, wallet, or logical state holder. It MUST be derived or mapped deterministically from application level identity but its internal structure is not constrained by this document.

amount: uint or int is a non negative or signed integer amount in the smallest currency or unit for the application. currency_code: text MAY be used to distinguish units (for example “JPY”, “USD”, “credits”, “points”) but VEEN does not interpret this field.

1.3 Capability linkage

When a profile requires authorization, MSG.auth_ref MUST reference a capability token that includes all required rights for the operation. Some profiles also allow cap_ref in payload_hdr to point to the specific capability used inside the encrypted header.

1.4 Schema identifiers

payload_hdr.schema MUST be a 32 byte hash value. For each profile a symbolic name is given and the concrete schema identifier is defined as

schema_id = H(“veen/schema:” || ascii_name)

where ascii_name is an ASCII string such as “paid.operation.v1”. Implementation MAY precompute these constants.
	2.	Paid Operation

2.1 Purpose

Paid Operation couples an application operation and its payment into a single atomic event committed to the stream log. Either both the business operation and the wallet update are accepted and logged, or neither is accepted.

2.2 Schema

payload_hdr.schema = H(“veen/schema:paid.operation.v1”)

Encrypted payload body:

{
“operation_type”: text,
“operation_args”: any,
“payer_account”: bstr(32),
“payee_account”: bstr(32),
“amount”: uint,
“currency_code”: text,
“operation_reference”: bstr(32)?,
“parent_operation_id”: bstr(32)?,
“ttl_seconds”: uint?,
“metadata”: any?
}

operation_type: application specific name of the business operation (for example “translate”, “store_file”, “api_call”).

operation_args: CBOR subtree with arguments for the business operation.

payer_account and payee_account: logical accounts affected by the payment.

amount and currency_code: payment amount. If currency_code is absent the deployment MUST define a single default unit.

operation_reference: optional external reference such as invoice id or order id.

parent_operation_id: optional link to an earlier operation that this paid operation responds to.

ttl_seconds: optional maximum time that the hub SHOULD accept the operation after msg creation time.

metadata: optional application specific structure.

2.3 Ledger behavior

The hub does not maintain balances. A wallet service, which is an application reading from the stream, MUST implement the following:
	•	Interpret each Paid Operation as a transfer of amount from payer_account to payee_account.
	•	Apply these transfers in stream order (stream_seq ascending).
	•	Reject any Paid Operation that would cause a negative balance if the domain forbids negative balances.

To provide atomicity from the client perspective:
	•	The client submits a Paid Operation MSG.
	•	If the MSG is accepted and a RECEIPT is returned, the combined event (operation and payment) is considered committed.
	•	If E.CAP, E.AUTH, E.RATE, E.SEQ, or other error is returned, the client MUST treat the whole Paid Operation as not executed.

2.4 Capability requirements

The capability token referenced by auth_ref SHOULD include:
	•	write permission to the relevant label or stream_id,
	•	permission to debit payer_account up to some total amount and rate,
	•	optional permission to credit payee_account.

The exact representation is application specific but MUST be deterministically interpretable by the wallet and authorization components.

2.5 Invariants

In addition to VEEN core invariants, implementations SHOULD enforce:

P1. A Paid Operation is only processed by the wallet service once per (label, stream_seq).

P2. If any application level side effect (such as remote procedure call) is performed for this operation_type, it MUST either be completely idempotent or keyed by operation_id so that replays do not create extra effects.
	3.	Access Grant

3.1 Purpose

Access Grant turns access control changes into explicit, logged operations rather than implicit database mutations.

3.2 Schema

There are two payload schemas: access.grant.v1 and access.revoke.v1.

Grant payload:

payload_hdr.schema = H(“veen/schema:access.grant.v1”)

body:

{
“subject_identity”: bstr(32),
“subject_label”: text?,
“allowed_stream_ids”: [ bstr(32) ],
“expiry_time”: uint,
“maximum_rate_per_second”: uint?,
“maximum_burst”: uint?,
“maximum_amount”: uint?,
“currency_code”: text?,
“reason”: text?,
“parent_operation_id”: bstr(32)?
}

Revoke payload:

payload_hdr.schema = H(“veen/schema:access.revoke.v1”)

body:

{
“subject_identity”: bstr(32),
“target_capability_reference”: bstr(32)?,
“reason”: text?,
“parent_operation_id”: bstr(32)?
}

subject_identity: public key or account identifier that will receive or lose permissions.

subject_label: human readable label for logging and display.

allowed_stream_ids: set of stream identifiers to which the subject may write.

expiry_time: Unix time when this access grant becomes invalid.

maximum_rate_per_second and maximum_burst: admission limits for messages.

maximum_amount and currency_code: optional bound for paid operations.

target_capability_reference: auth_ref of the capability that is being revoked. If absent, all capabilities for subject_identity in this domain MAY be revoked.

3.3 Capability token mapping

On receiving an Access Grant message the hub side admission subsystem SHOULD derive a capability token that:
	•	sets issuer_pk to the granting identity,
	•	sets subject_pk or subject identity to subject_identity,
	•	sets allow.stream_ids, allow.ttl, and allow.rate from the payload fields.

auth_ref for this capability MUST be Ht(“veen/cap”, CBOR(cap_token)) as in VEEN core.

Access Revoke MUST delete the corresponding admission record for target_capability_reference or all records related to subject_identity as configured.

3.4 Invariants

A1. The issuer of the Access Grant or Access Revoke MUST have a capability that authorizes modifying permissions. This constraint is domain specific but SHOULD be enforced by hub policy.

A2. Admission decisions MUST be derived entirely from current sets of Access Grant and Access Revoke messages plus any bootstrapped capabilities.
	4.	Delegated Execution

4.1 Purpose

Delegated Execution encodes that an action was performed by an agent using authority delegated through one or more steps.

4.2 Schema

payload_hdr.schema = H(“veen/schema:delegated.execution.v1”)

body:

{
“principal_identity”: bstr(32),
“agent_identity”: bstr(32),
“delegation_chain”: [ bstr(32) ],
“operation_schema”: bstr(32),
“operation_body”: any,
“parent_operation_id”: bstr(32)?,
“metadata”: any?
}

principal_identity: identity of the original authority holder.

agent_identity: identity that actually originated this MSG (usually the same as client_id but may be a stable account id).

delegation_chain: ordered list of capability references (auth_ref or cap_ref values) that form the delegation path from principal to agent.

operation_schema: schema id of the embedded application operation.

operation_body: payload body of the embedded operation (for example a remote procedure call or a wallet update) encoded as CBOR.

4.3 Processing model

A Delegated Execution consumer MUST:
	•	Verify all capability signatures for each capability reference in delegation_chain.
	•	Verify that the subject in the first capability matches principal_identity.
	•	Verify that the subject in the last capability matches agent_identity or client_id.
	•	Verify that each capability in the chain allows delegation to the next subject.
	•	Process operation_body as if it were a direct operation, with the effective authority of principal_identity.

The hub MAY optionally enforce these checks at admission time for higher assurance domains.

4.4 Invariants

D1. delegation_chain MUST be non empty.

D2. If any capability in delegation_chain fails validation, the operation MUST NOT be applied.

D3. Logs MUST retain the full delegation_chain so that later analysis can reconstruct responsibility.
	5.	Multi Party Agreement

5.1 Purpose

Multi Party Agreement records contracts or policy agreements involving multiple parties, with explicit agreement messages from each party.

5.2 Schema

Agreement definition:

payload_hdr.schema = H(“veen/schema:agreement.definition.v1”)

body:

{
“agreement_id”: bstr(32),
“version”: uint,
“terms_hash”: bstr(32),
“terms_attachment_root”: bstr(32)?,
“parties”: [ bstr(32) ],
“effective_time”: uint?,
“expiry_time”: uint?,
“metadata”: any?
}

Agreement confirmation:

payload_hdr.schema = H(“veen/schema:agreement.confirmation.v1”)

body:

{
“agreement_id”: bstr(32),
“version”: uint,
“party_identity”: bstr(32),
“decision”: text,
“decision_time”: uint?,
“parent_operation_id”: bstr(32)?,
“metadata”: any?
}

5.3 Semantics

agreement_id: stable identifier for the agreement.

version: version number, monotonically increasing for the same agreement_id.

terms_hash: hash of the canonical agreement text or binary.

terms_attachment_root: Merkle root of the full terms when stored as attachments.

parties: list of identities expected to confirm.

decision: text such as “accept”, “reject”, “withdraw”.

A deployment defines a policy such as:
	•	an agreement (agreement_id, version) is active when all parties have decision “accept” for that pair;
	•	a new version supersedes an older version when a majority or all parties confirm.

Consumers can derive which version was active at any stream_seq or time by scanning Agreement Definition and Agreement Confirmation messages.

5.4 Invariants

M1. For a given (agreement_id, version, party_identity) there MUST be at most one latest Confirmation with decision “accept” or “reject”. Earlier conflicting decisions MUST be treated as superseded by later stream order.

M2. Agreement Definition messages SHOULD be rare and stable; confirmation messages are the primary dynamic events.
	6.	Data Publication

6.1 Purpose

Data Publication binds a content item or bundle to a point in the log.

6.2 Schema

payload_hdr.schema = H(“veen/schema:data.publication.v1”)

body:

{
“publication_id”: bstr(32),
“publisher_identity”: bstr(32),
“content_root”: bstr(32),
“content_class”: text,
“version”: text,
“labels”: [ text ]?,
“source_uri”: text?,
“metadata”: any?
}

publication_id: stable identifier for the logical object (for example model name, dataset name).

publisher_identity: identity that publishes the content.

content_root: Merkle root over either inline attachments or external content hashes. The Merkle construction MUST be defined per deployment. A simple tree using Ht(“veen/content-node”, left||right) and Ht(“veen/content-root”, concat(peaks)) is RECOMMENDED.

content_class: functional class, for example “model”, “dataset”, “configuration”, “binary”.

version: semantically meaningful version identifier such as “v1.2.0” or “2025-11-13T12:00Z”.

labels, source_uri, metadata: optional search and descriptive fields.

6.3 Semantics

To verify that an artifact matches a publication:
	•	Recompute content_root from the candidate data or its hashes.
	•	Fetch the Data Publication message and check that content_root matches.
	•	Verify the RECEIPT and optional anchor.

6.4 Invariants

P1. For a given publication_id and version there MUST be at most one Data Publication message in the domain.

P2. Consumers MAY choose a survivorship rule for multiple versions (for example pick highest version or latest in stream order).
	7.	State Snapshot

7.1 Purpose

State Snapshot defines how to derive a consistent state from a stream of operations at a given point.

7.2 Snapshot checkpoint schema

payload_hdr.schema = H(“veen/schema:state.checkpoint.v1”)

body:

{
“state_id”: bstr(32),
“upto_stream_seq”: uint,
“mmr_root”: bstr(32),
“state_hash”: bstr(32),
“state_class”: text,
“metadata”: any?
}

state_id: identifier for the logical state, for example an account_id or configuration key.

upto_stream_seq: inclusive stream sequence number up to which operations are considered.

mmr_root: root value from CHECKPOINT or RECEIPT at upto_stream_seq.

state_hash: hash of the fully folded state after applying all relevant operations up to upto_stream_seq.

state_class: description such as “wallet.ledger”, “counter.map”, “configuration.map”.

7.3 Folding rules

Each application MUST define a deterministic folding function for its state_class.

Examples:
	•	For a wallet ledger, fold by summing credit and debit operations for each account_id.
	•	For a grow only counter map, fold by summing deltas per key.
	•	For a last writer wins map, fold by taking the value with the highest timestamp, with stream_seq as tie breaker.

The folding function MUST be pure and MUST produce the same state_hash for any correct implementation reading the same log prefix.

7.4 Verification procedure

To verify a State Snapshot:
	•	Fetch all RECEIPT and MSG pairs for the label up to upto_stream_seq.
	•	Filter messages relevant to state_id.
	•	Apply the state_class folding function in stream order.
	•	Compute Ht(“veen/state-” || state_class, serialized_state) and check equality with state_hash.
	•	Verify that the mmr_root matches the root recorded in the checkpoint or receipt at upto_stream_seq.

7.5 Invariants

S1. For a given state_id and upto_stream_seq there SHOULD be at most one checkpoint. If multiple checkpoints exist, consumers MAY prefer the latest one in stream order.

S2. A consumer MUST treat any snapshot with mismatched mmr_root or state_hash as invalid.
	8.	Recovery Procedure

8.1 Purpose

Recovery Procedure structures identity and wallet recovery as multi stage, logged actions.

8.2 Schemas

Recovery request:

payload_hdr.schema = H(“veen/schema:recovery.request.v1”)

body:

{
“target_identity”: bstr(32),
“requested_new_identity”: bstr(32),
“reason”: text?,
“request_time”: uint?,
“metadata”: any?
}

Recovery approval:

payload_hdr.schema = H(“veen/schema:recovery.approval.v1”)

body:

{
“target_identity”: bstr(32),
“requested_new_identity”: bstr(32),
“approver_identity”: bstr(32),
“policy_group_id”: bstr(32)?,
“decision”: text,
“decision_time”: uint?,
“parent_operation_id”: bstr(32)?,
“metadata”: any?
}

Recovery execution:

payload_hdr.schema = H(“veen/schema:recovery.execution.v1”)

body:

{
“target_identity”: bstr(32),
“new_identity”: bstr(32),
“applied_time”: uint?,
“approval_references”: [ bstr(32) ],
“metadata”: any?
}

8.3 Policy

A domain defines recovery policies such as:
	•	For each target_identity there is a set of guardian identities.
	•	A threshold number of approvals with decision “approve” and matching requested_new_identity is required.
	•	Approvals must be later than the request and earlier than the execution.

A wallet or identity service reads the log and:
	•	Tracks open Recovery Request messages.
	•	Aggregates approvals by target_identity and requested_new_identity.
	•	When a Recovery Execution appears with sufficient valid approvals, remaps the identity in its local state from target_identity to new_identity.

8.4 Invariants

R1. Recovery Execution MUST reference only approvals that exist in the log before its own stream_seq.

R2. If any referenced approval has decision other than “approve” or has mismatched target_identity or requested_new_identity, the execution MUST be rejected.

R3. A domain MAY enforce that only certain identities (for example administrators) can send Recovery Execution messages.
	9.	Query Audit Log

9.1 Purpose

Query Audit Log makes read operations on sensitive resources visible as first class events.

9.2 Schema

payload_hdr.schema = H(“veen/schema:query.audit.v1”)

body:

{
“requester_identity”: bstr(32),
“resource_identifier”: text,
“resource_class”: text,
“query_parameters”: any?,
“purpose_code”: text?,
“result_digest”: bstr(32)?,
“request_time”: uint?,
“metadata”: any?
}

resource_identifier: logical path or identifier for the resource (for example “patient:1234:lab-results”).

resource_class: high level class such as “personal-data”, “financial-record”, “system-log”.

query_parameters: filters, projection, or other parameters.

purpose_code: short code expressing why the query was made (for example “treatment”, “billing”, “debug”).

result_digest: optional hash of the returned data or a canonical digest. If present, it MUST be derived in a deterministic documented way.

9.3 Processing

A data access service SHOULD:
	•	Before or after serving a query, emit a Query Audit message with the appropriate fields.
	•	Use the same label structure consistently so that auditors can subscribe to all query logs for a domain.

Auditors can then reconstruct who accessed what and when by scanning the stream.

9.4 Invariants

Q1. For heavily regulated resources the domain MAY require that every successful data access produces a corresponding Query Audit message; absence of such a message is treated as a policy violation.
	10.	Federation Synchronization

10.1 Purpose

Federation Synchronization defines how messages and their proofs are mirrored across hubs.

10.2 Mirror payload

payload_hdr.schema = H(“veen/schema:federation.mirror.v1”)

body:

{
“source_hub_identifier”: text,
“source_label”: bstr(32),
“source_stream_seq”: uint,
“source_leaf_hash”: bstr(32),
“source_receipt_root”: bstr(32),
“target_label”: bstr(32),
“mirror_time”: uint?,
“metadata”: any?
}

source_hub_identifier: textual identifier or address of the origin hub.

source_label, source_stream_seq, source_leaf_hash, source_receipt_root: values from the source RECEIPT.

target_label: label under which the mirrored messages are stored in the target hub.

mirror_time: time when mirroring occurred.

10.3 Mirroring process

A mirror component runs the following loop:
	•	Subscribe to stream(with_proof=1) on the source hub for a set of labels.
	•	For each source (RECEIPT, MSG, mmr_proof):
	•	Validate hub_sig, invariants, and mmr_proof.
	•	Construct a mirror MSG whose payload is federation.mirror.v1 and whose parent_id in payload_hdr references the original msg_id.
	•	Submit the mirror MSG to the target hub under target_label.
	•	The target hub treats the mirrored MSG as a normal message and includes it in its own MMR and receipts.

10.4 Consistency checks

A consumer that wants to check synchronization between two hubs:
	•	Reads federation.mirror.v1 messages from the target hub.
	•	For each such message, fetches the referenced RECEIPT from the source hub using source_hub_identifier and source_label.
	•	Verifies that source_receipt_root, source_leaf_hash, and source_stream_seq match the source RECEIPT.
	•	Optionally verifies anchors on both sides.

10.5 Invariants

F1. A mirror MUST NOT send a federation.mirror.v1 message for a source message it has not fully validated.

F2. For a given source (source_hub_identifier, source_label, source_stream_seq) there SHOULD be at most one mirror record for a given target_label.
	11.	Integration Summary

All nine operation families share the following properties:
	•	They are defined only by payload_hdr.schema and encrypted payload fields.
	•	They reuse VEEN core invariants and data structures including MSG, RECEIPT, CHECKPOINT, MMR, and capability tokens.
	•	They can be implemented incrementally: a deployment MAY support only a subset and still remain fully compatible at the transport level.

A reference implementation SHOULD:
	•	Provide type safe structures and encoders for each schema.
	•	Provide validators for each profile that enforce the listed invariants.
	•	Provide client side helpers to construct these payloads, link them to capabilities, and submit them through the existing CLI and APIs.


## spec-4.txt

VEEN v0.0.1++ — Kubernetes-Native Profile (Tightened)
	0.	Purpose

This document refines the VEEN v0.0.1 Kubernetes-native profile to an implementation-grade level.

The goal is to make a “VEEN network” a portable, disposable unit that can be:
	•	created by applying a small set of Kubernetes manifests
	•	destroyed by deleting a namespace
	•	self-tested via standard Jobs
	•	wired into other workloads using stable Service endpoints

Protocol semantics (wire, overlay, identity, capability, revocation, wallet) are unchanged.
Only deployment, lifecycle, and operational invariants are specified more tightly.
	1.	Scope and non-goals

1.1 In scope
	•	Mapping VEEN authority and tenant hubs to Kubernetes resources.
	•	Mapping VEEN bridges to Kubernetes resources.
	•	Packaging VEEN CLI and self-tests as Jobs.
	•	Naming, labels, annotations, and minimal RBAC.
	•	Health probes, readiness conditions, and metrics exposure.
	•	Storage layout for hub state and attachments in a cluster.

1.2 Out of scope
	•	Cluster provisioning (nodes, CNI, ingress controllers).
	•	TLS termination and identity at the Kubernetes ingress layer.
	•	Multi-cluster mesh or global control planes.
	•	Any protocol-level change to VEEN messages or schemas.

	2.	Logical model of a VEEN network in Kubernetes

2.1 Definitions
	•	VEEN universe
	•	A set of hubs that share the same authority hub and schema universe.
	•	Authority hub
	•	The root of trust for schemas, label classes, authorities, and revocation streams.
	•	Tenant hub
	•	Hub instance bound to a tenant, environment, or application.
	•	VEEN network (Kubernetes sense)
	•	A namespace plus all VEEN objects inside it that share a single tenant hub and its bridge connections.

2.2 Mapping
	•	One VEEN universe per cluster (in v0.0.1++).
	•	Exactly one authority hub per VEEN universe.
	•	Zero or more tenant hubs, each in its own namespace.
	•	Zero or more bridges linking authority → tenant and tenant ↔ tenant.

	3.	Resource naming, labels, and annotations

3.1 Namespaces

Namespace patterns:
	•	Authority namespace
	•	Name: veen-system
	•	Tenant namespaces
	•	Name: veen-tenant-<tenant-id>
	•	<tenant-id> SHOULD be a short, DNS-safe identifier:
	•	lowercase letters, digits, hyphen
	•	for example acme-prod, team1-dev

3.2 Labels

Every VEEN-managed Pod, Deployment, StatefulSet, Job, and Service MUST include:
	•	app.kubernetes.io/part-of=veen
	•	app.kubernetes.io/component=hub|bridge|cli|selftest
	•	veen.io/role=authority|tenant|bridge|selftest
	•	veen.io/universe-id=<universe-id>
	•	A short identifier like default, stage-1.
	•	veen.io/tenant-id=<tenant-id>
	•	Present only for tenant hubs, bridges tied to a tenant, and per-tenant selftests.

3.3 Annotations

Recommended annotations:
	•	veen.io/profile=authority|tenant|bridge|cli|selftest
	•	veen.io/version=<semantic-version>
	•	Matches image tag or protocol version.
	•	veen.io/config-hash=<opaque-hash>
	•	Optional: hash of main config to make drift detection easier.

	4.	Authority hub specification

4.1 Resource set

Authority hub MUST be represented by:
	•	StatefulSet: veen-authority-hub
	•	Service: veen-authority
	•	ConfigMap: veen-authority-config
	•	Secret: veen-authority-keys
	•	PersistentVolumeClaim: veen-authority-data

All in namespace veen-system.

4.2 StatefulSet behaviour
	•	Replicas: 1
	•	Pod template:
	•	Container image:
	•	veen-hub:<version>
	•	Command:
	•	veen-hub
	•	Arguments:
	•	--profile=authority
	•	--config=/etc/veen/hub.yaml
	•	--data-dir=/var/lib/veen
	•	Environment variables (minimum):
	•	VEEN_ROLE=authority
	•	VEEN_UNIVERSE_ID=<universe-id>
	•	VEEN_LOG_LEVEL=info (default)
	•	Volume mounts:
	•	veen-config → /etc/veen (read-only)
	•	veen-keys → /etc/veen/keys (read-only)
	•	veen-data → /var/lib/veen (read-write PVC)

4.3 Authority hub config

ConfigMap veen-authority-config MUST provide:
	•	Hub listening address and port.
	•	Any local retention parameters for authority streams.
	•	A stable authority identifier.

The config file MUST be resolved relative to:
	•	/etc/veen/hub.yaml

Authority hub MUST not re-generate its identity at startup; it MUST always use keys from veen-authority-keys.

4.4 PVC behaviour
	•	PVC veen-authority-data MUST be bound to storage with:
	•	ReadWriteOnce access mode.
	•	Capacity sufficient for authority metadata and revocation history.
	•	StatefulSet MUST not mount emptyDir for /var/lib/veen.

Deleting the StatefulSet MUST NOT delete the PVC by default; PVC lifecycle is managed explicitly.
	5.	Tenant hub specification

5.1 Resource set

For each tenant namespace veen-tenant-<tenant-id>:
	•	Deployment: veen-hub
	•	Service: veen-hub
	•	ConfigMap: veen-hub-config
	•	Secret: veen-hub-keys
	•	Optional PVC: veen-hub-data (if persistence is desired)

5.2 Tenant hub Deployment
	•	Replicas: 1 (v0.0.1++ does not define multi-replica hubs).
	•	Pod template:
	•	Image: veen-hub:<version>
	•	Command:
	•	veen-hub
	•	Arguments:
	•	--profile=tenant
	•	--config=/etc/veen/hub.yaml
	•	--data-dir=/var/lib/veen
	•	Env:
	•	VEEN_ROLE=tenant
	•	VEEN_TENANT_ID=<tenant-id>
	•	VEEN_UNIVERSE_ID=<universe-id>
	•	Volumes:
	•	ConfigMap veen-hub-config → /etc/veen (read-only).
	•	Secret veen-hub-keys → /etc/veen/keys (read-only).
	•	One of:
	•	emptyDir volume veen-data → /var/lib/veen (disposable).
	•	PVC veen-hub-data → /var/lib/veen (persistent).

5.3 Tenant hub config

ConfigMap veen-hub-config MUST encode:
	•	authority_url
	•	URL of the authority hub Service:
	•	http://veen-authority.veen-system.svc.cluster.local:8080
	•	hub_profile
	•	tenant
	•	retention
	•	Optional: retention hints for non-critical streams.
	•	Any per-tenant policy parameters (for example, WAL size, attachment limits).

5.4 Tenant hub lifetime
	•	Creating the namespace and applying the manifests MUST be sufficient to bring the hub to a ready state.
	•	Deleting the namespace MUST remove:
	•	Deployment
	•	Service
	•	ConfigMap
	•	Secrets
	•	All emptyDir volumes
	•	If a PVC exists, its deletion policy SHOULD be explicit:
	•	For fully disposable tenants: PVC created in the same namespace and removed with it.
	•	For “archived tenants”: PVC may be in another namespace or bound to a static volume; this is outside v0.0.1++.

	6.	Bridge specification

6.1 Resource set

Bridge processes MAY be long-running or one-off.

Per universe or per tenant, the following resources are typical:
	•	Deployment or Job: veen-bridge-<name>
	•	ConfigMap: veen-bridge-<name>-config
	•	Secret: veen-bridge-<name>-keys (optional)

6.2 Bridge container behaviour

Container image:
	•	veen-bridge:<version>

Command:
	•	veen-bridge

Arguments:
	•	--source-url=<hub-url>
	•	--target-url=<hub-url>
	•	--streams=<selector>
	•	For example core/*, wallet/*, or a specific stream id.

Environment:
	•	VEEN_ROLE=bridge
	•	Optionally VEEN_TENANT_ID when bound to a single tenant.

6.3 Bridge placement
	•	Authority→tenant bridges MAY run in:
	•	veen-system namespace, or
	•	the corresponding tenant namespace.
	•	Tenant↔tenant bridges SHOULD run in one of the tenant namespaces or in veen-system, but MUST be associated with tenants via labels and annotations.

6.4 Idempotency

Bridge implementation MUST ensure:
	•	Applying the same configuration twice MUST NOT create duplicate messages.
	•	Replaying from a checkpoint MUST NOT break message ordering or proofs.

	7.	CLI and Job usage

7.1 CLI container

Image:
	•	veen-cli:<version>

Command/args (examples):
	•	veen-cli keygen --out /work/client
	•	veen-cli cap issue --issuer /work/admin --subject /work/client --stream core/quota --ttl 600 --rate 100,100 --out /work/cap.cbor
	•	veen-cli stream --hub http://veen-hub:8080 --client /work/client --stream core/main --from 0

The CLI image MUST contain:
	•	veen-cli binary
	•	Optionally helper scripts for common operations

7.2 CLI Job pattern

Typical one-off workflow in a tenant namespace:
	•	Job name: veen-cli-<action>
	•	Pod container:
	•	Image: veen-cli:<version>
	•	Volume work as emptyDir for intermediate files.
	•	Secrets with keystores mounted read-only under /secrets.
	•	Command that:
	•	copies keystores from Secrets to /work
	•	runs veen-cli with /work paths
	•	writes any output artifacts into /work or logs.

7.3 External CLI

When cluster exposes a hub via Ingress:
	•	External operator MAY run veen-cli locally using:
	•	--hub pointing at the Ingress URL.
	•	In this case, keystores are managed locally and never enter the cluster.

	8.	Self-test integration

8.1 Core self-test Job per tenant

Each tenant namespace MUST provide a standard Job:
	•	Name: veen-selftest-core
	•	Container image: veen-selftest:<version>
	•	Command:
	•	veen-selftest core --hub http://veen-hub:8080
	•	Env:
	•	VEEN_ROLE=selftest
	•	VEEN_TENANT_ID=<tenant-id>
	•	Volumes:
	•	emptyDir for working directory
	•	Secrets containing any pre-generated test keys

The Job MUST exit with:
	•	code 0 when all invariants are satisfied
	•	non-zero code when any invariant fails

8.2 Authority self-test

In veen-system:
	•	Job: veen-selftest-authority
	•	Command:
	•	veen-selftest authority --hub http://veen-authority:8080

8.3 When to run self-tests

Self-tests SHOULD be run:
	•	immediately after deploying a new VEEN version in the cluster
	•	after changing authority config
	•	periodically via a CronJob for early detection of drift

	9.	Security, RBAC, and network policy

9.1 Minimal RBAC roles

A veen-operator ClusterRole SHOULD be defined with permissions to:
	•	Namespaces:
	•	get, list, create, delete for namespaces matching veen-*
	•	In VEEN namespaces:
	•	Deployments, StatefulSets, Jobs, Pods, Services, ConfigMaps, Secrets:
	•	get, list, watch, create, update, delete

Application roles in tenant namespaces MUST NOT have permission to:
	•	modify veen-hub Deployment
	•	modify veen-hub-config ConfigMap
	•	modify veen-hub-keys Secret

9.2 NetworkPolicy

For each tenant namespace:
	•	A NetworkPolicy SHOULD restrict inbound traffic to veen-hub Pods to:
	•	Pods with label veen.io/role=bridge
	•	Pods with label veen.io/role=selftest
	•	Application Pods explicitly allowed via label selectors.

Authority namespace SHOULD have similar NetworkPolicy restricting access to:
	•	authority hub
	•	any authority-level bridge or admin workloads

9.3 Secret handling
	•	Hub key Secrets MUST be created once and only referenced by Pods.
	•	Self-test and CLI Jobs MUST mount Secrets as read-only.
	•	Jobs MAY generate temporary keys into emptyDir volumes but MUST NOT write back into Secrets.

	10.	Health, readiness, and metrics

10.1 Health endpoints

Each hub MUST expose:
	•	/healthz
	•	returns success if process is alive
	•	MUST NOT perform expensive checks
	•	/readyz
	•	returns success when:
	•	local state directory is accessible
	•	required indexes are initialized
	•	authority hub (for tenants) is reachable or has a fresh view

Kubernetes Probes:
	•	LivenessProbe:
	•	HTTP GET /healthz.
	•	ReadinessProbe:
	•	HTTP GET /readyz.

10.2 Metrics

Each hub SHOULD expose:
	•	/metrics endpoint with counters and histograms including:
	•	message append count per stream
	•	append latency distribution
	•	checkpoint creation rate
	•	capability validation success/failure counts
	•	revocation view update lag
	•	WAL/attachment store usage metrics (bytes, count)

10.3 Logging

All VEEN containers MUST log to stdout/stderr with structured fields:
	•	ts (timestamp)
	•	level (info, warn, error)
	•	component (hub, bridge, cli, selftest)
	•	role (authority, tenant, bridge, selftest)
	•	Optional:
	•	tenant_id
	•	stream_id
	•	client_id
	•	operation

	11.	End-to-end lifecycle flows

11.1 Creating a new tenant network

Sequence:
	1.	Create namespace veen-tenant-<tenant-id>.
	2.	Create veen-hub-keys Secret with tenant hub key material.
	3.	Create veen-hub-config ConfigMap pointing at authority hub.
	4.	Create veen-hub Deployment and veen-hub Service.
	5.	Optionally create bridge Deployment or Job to sync authority streams.
	6.	Run veen-selftest-core Job and verify completion.

Completion condition:
	•	veen-hub Pod Ready
	•	self-test Job succeeded

11.2 Destroying a tenant network

Sequence:
	1.	Delete namespace veen-tenant-<tenant-id>.

Outcome:
	•	All tenant hub state is removed (including emptyDir volumes).
	•	Any per-tenant PVCs are removed if they were in the namespace.

11.3 Upgrading VEEN version

Per universe:
	1.	Update image tags in:
	•	veen-authority-hub StatefulSet
	•	veen-hub Deployments (all tenants)
	•	veen-bridge Deployments or Jobs
	•	veen-cli and veen-selftest Jobs
	2.	Apply updated manifests.
	3.	Wait for:
	•	authority hub pod Ready
	•	tenant hub pods Ready
	4.	Run:
	•	veen-selftest-authority in veen-system
	•	veen-selftest-core in each tenant namespace (or a representative subset)

11.4 Rotating hub keys

To rotate a tenant hub’s keys:
	1.	Generate new keys via CLI Job or external CLI.
	2.	Create a new Secret veen-hub-keys-next with new keys.
	3.	Update veen-hub Deployment to mount veen-hub-keys-next instead of current.
	4.	Apply Deployment and wait for pod restart and readiness.
	5.	Optionally revoke old keys at authority level using veen-cli revoke publish.

	12.	Profile constraints and compatibility

12.1 Protocol compatibility
	•	v0.0.1++ is strictly an operational profile.
	•	All VEEN binary formats (wire messages, proofs, identities, wallet state) remain as in v0.0.1.
	•	Any implementation claiming v0.0.1++ compatibility MUST:
	•	pass existing v0.0.1 tests
	•	pass self-tests when deployed under Kubernetes according to this profile

12.2 Structural invariants

The following invariants MUST hold:
	•	Exactly one veen-authority-hub StatefulSet in veen-system.
	•	Exactly one veen-authority Service in veen-system.
	•	At most one veen-hub Deployment per tenant namespace.
	•	Each hub Pod has a unique veen.io/universe-id and role.
	•	Self-test Jobs MUST be able to reach the hub Service via its internal DNS name.
	•	Deleting a tenant namespace MUST NOT affect the authority hub or other tenants.

	13.	Implementation notes (non-normative)

	•	This profile is compatible with both full Kubernetes and k3s as long as:
	•	StatefulSet, Deployment, Service, ConfigMap, Secret, Job are supported.
	•	Operators are free to use Helm, Kustomize, or plain manifests as long as the resulting resources obey this spec.
	•	Higher-level constructs such as CRDs (VEENTenant, VEENUniverse) can wrap this profile but MUST not weaken its invariants.

## spec-5.txt

Discovery Overlay and Connect Application Specification v0.0.1
Plain ASCII, English only. Pure overlay on VEEN v0.0.1; no wire changes.
	0.	Purpose and scope

This document defines a discovery overlay and a connect application that run on top of VEEN v0.0.1. The goal is to let clients:
	•	discover hubs, overlays, and application services available on a VEEN fabric;
	•	query by capability (for example “RPC service implementing method X in region Y”);
	•	obtain connection hints (stream_ids, schemas, capability endpoints) without changing VEEN core.

All semantics are expressed as deterministic folds over discovery streams using normal VEEN messages, RPC0, and optional CRDT0. The wire format (MSG, RECEIPT, CHECKPOINT, cap_token) is unchanged.
	1.	Status

	•	v0.0.1 is an informative but implementation-grade overlay specification.
	•	It is safe to deploy in conjunction with VEEN v0.0.1 Core + OP0 + RPC0.
	•	All behavior is additive; no VEEN core change is required.

	2.	Terms

discovery overlay:
A set of schemas and folding rules used to publish and query descriptors about:
- hubs and their profiles;
- overlays and their streams;
- application services and their RPC endpoints.

discovery hub:
A hub whose operators choose to host one or more discovery streams. Any normal hub MAY act as a discovery hub by dedicating labels to discovery streams.

descriptor:
A CBOR payload describing a hub, overlay, or application (service). Descriptors are log-derived; the overlay never mutates in-place state.

connect application:
A client-side and optional server-side component that:
- issues discovery queries via RPC0;
- folds discovery streams locally;
- proposes connection plans (which hub, which label, which schema) to higher layers.
	3.	High-level design

The discovery overlay introduces:
	•	one or more well-known discovery stream_ids (for example:
	•	disc.hubs.v1
	•	disc.services.v1
	•	disc.overlays.v1 )
	•	a small set of schemas:
	•	disc.hub.advertise.v1
	•	disc.hub.retire.v1
	•	disc.service.advertise.v1
	•	disc.service.retire.v1
	•	disc.overlay.advertise.v1
	•	disc.overlay.retire.v1
	•	an RPC interface:
	•	disc.query.v1
	•	disc.query.res.v1

Hubs and service operators publish descriptors to the discovery streams. Clients and the connect application:
	•	either pull the logs directly via stream() and fold them locally; or
	•	call disc.query.v1 over RPC0 against a discovery hub that has already folded the logs.

	4.	Object model

4.1 Hub descriptor

A hub descriptor describes a hub as a possible point of attachment. It is expressed as:

schema: H(“disc.hub.advertise.v1”)

body:
{
hub_id: bstr(32),      // matches VEEN hub_id
hub_pk: bstr(32),      // Ed25519 public key
profile_id: bstr(32),  // VEEN profile_id supported
region: text,          // operator-chosen, for example “ap-northeast-1”
tags: [ text, … ],   // “public”, “private”, “test”, etc.
endpoints: [           // transport-specific hints
{
kind: text,        // “http”, “https”, “quic”, “nats”
url: text          // for example “https://hub.example.com”
},
…
],
overlays: [ bstr(32), … ], // overlay identifiers this hub participates in
ttl_sec: uint,         // recommended lifetime of this advertisement
version: text          // operator-defined hub software version
}

A retirement record is:

schema: H(“disc.hub.retire.v1”)

body:
{
hub_id: bstr(32),
reason: text?
}

4.2 Overlay descriptor

Describes an overlay that can be used on the fabric.

schema: H(“disc.overlay.advertise.v1”)

body:
{
overlay_id: bstr(32),        // stable identifier for the overlay
name: text,                  // for example “rpc”, “crdt”, “wallet”
version: text,               // overlay version string
schemas: [ bstr(32), … ],  // schema identifiers used by this overlay
docs_url: text?,             // optional documentation URL
tags: [ text, … ],         // for example “stable”, “experimental”
ttl_sec: uint
}

Retirement:

schema: H(“disc.overlay.retire.v1”)

body:
{
overlay_id: bstr(32),
reason: text?
}

4.3 Service descriptor

Describes an application service. A service is a logical RPC endpoint, not tied to a single hub.

schema: H(“disc.service.advertise.v1”)

body:
{
service_id: bstr(32),       // 32-byte stable ID for the service
name: text,                 // human-readable name
overlay_id: bstr(32),       // overlay used, for example RPC overlay id
methods: [ text, … ],     // for RPC: list of supported methods
stream_ids: [ bstr(32), … ], // VEEN stream_ids this service reads/writes
regions: [ text, … ],     // preferred regions
required_caps: [ text, … ], // logical capability names, for example “read”, “write”
auth_policy: {
mode: text,               // “cap_token”, “mtls”, “none”, “other”
details: CBOR?            // overlay-specific
}?,
operator: {
org: text?,
contact: text?
}?,
tags: [ text, … ],        // “public”, “beta”, “internal”
ttl_sec: uint
}

Retirement:

schema: H(“disc.service.retire.v1”)

body:
{
service_id: bstr(32),
reason: text?
}
	5.	Discovery streams

5.1 Stream allocation

Operators choose stable stream_ids for discovery. A common pattern is:
	•	stream_id_disc_hubs    = H(“disc.hubs.v1”)
	•	stream_id_disc_services = H(“disc.services.v1”)
	•	stream_id_disc_overlays = H(“disc.overlays.v1”)

Discovery hubs advertise that they host these stream_ids in their hub descriptor.

Each discovery stream is just a normal VEEN label derived from stream_id and routing_key. Hubs do not treat these labels specially at the core layer.

5.2 Folding rules (discovery overlay state)

The discovery overlay maintains three key maps per fabric:

Hubs[label]:
key: hub_id
value: latest Hub descriptor where hub_id matches, and which is not retired and not expired.

Overlays[label]:
key: overlay_id
value: latest Overlay descriptor where overlay_id matches, not retired, not expired.

Services[label]:
key: service_id
value: latest Service descriptor where service_id matches, not retired, not expired.

Folding is defined as:
	•	Events are processed in log order (stream_seq, plus RECEIPT order if needed).
	•	For an advertise record:
	•	Insert or replace the entry keyed by hub_id / overlay_id / service_id with the payload.
	•	Compute expiry as payload.hub_ts + ttl_sec if hub_ts is available or payload.expires_at inside the body if specified; expired entries are ignored by queries.
	•	For a retire record:
	•	Mark the corresponding entry as retired; retired entries are not returned in queries.

State is always derived from the retained log prefix. Implementations MUST NOT maintain hidden mutable state outside derived maps.
	6.	Query interface (disc.query)

6.1 Schema

Queries are expressed via RPC0 as:

Request:

schema: H(“disc.query.v1”)

body:
{
kind: text,       // “hub”, “service”, “overlay”
filter: CBOR,     // filter object, structure depends on kind
limit: uint?,     // maximum number of results
offset: uint?     // optional pagination offset
}

Kinds and filters:

kind = “hub”
filter = {
region: text?,           // exact match
tags_any: [ text, … ]?,// at least one tag
overlay_id: bstr(32)?    // hubs that advertise this overlay
}

kind = “service”
filter = {
name_prefix: text?,      // name starts with prefix
method: text?,           // services exposing this method
overlay_id: bstr(32)?,   // overlay id
region: text?,           // desired region
tags_any: [ text, … ]?
}

kind = “overlay”
filter = {
name_prefix: text?,
schema: bstr(32)?,       // overlays that include this schema
tags_any: [ text, … ]?
}

Response:

schema: H(“disc.query.res.v1”)

body:
{
ok: bool,
results: [ CBOR ],   // array of descriptors, shape depends on kind
more: bool,          // true if more results may exist beyond limit+offset
error: { code: text, detail: text? }?
}

If ok = true, error MUST be absent. If ok = false, results SHOULD be empty.

6.2 Implementation of queries

A discovery hub offering RPC-based discovery:
	•	folds the discovery streams into in-memory maps Hubs, Overlays, Services;
	•	answers disc.query.v1 requests by filtering those maps deterministically;
	•	enforces a maximum limit Lmax to bound resource usage.

Connect applications MAY bypass disc.query.v1 and instead:
	•	call stream() on discovery streams;
	•	fold the descriptors locally with the same rules;
	•	run equivalent filters in-process.

	7.	Connect application behavior

The connect application is an overlay consumer that helps a client establish a working configuration to use a service. It operates in four phases:

7.1 Phase 1: hub selection

Input:
	•	User’s constraints (region, latency, tags)
	•	Optional existing pin of hub_pk

Steps:
	1.	Issue disc.query.v1 with kind = “hub” and appropriate filter.
	2.	Collect candidate hub descriptors.
	3.	Apply selection strategy:
	•	prefer region match;
	•	prefer hubs that advertise required overlays;
	•	exclude hubs whose profile_id is not supported by the client.
	4.	Return one or more candidate hubs with:
	•	endpoints;
	•	hub_pk;
	•	profile_id.

7.2 Phase 2: overlay and service selection

For a chosen hub and its fabric:
	1.	Query overlays:
	•	disc.query.v1, kind = “overlay”, filter with schema or name.
	2.	For each target overlay (for example RPC or CRDT), verify:
	•	the schemas match what the client’s overlay implementation expects.
	3.	Query services:
	•	disc.query.v1, kind = “service”, filter with:
	•	overlay_id;
	•	method (for RPC) or tag.
	4.	Return candidate services with:
	•	service_id;
	•	stream_ids to use;
	•	methods available;
	•	required_caps and auth_policy.

7.3 Phase 3: capability planning

For a selected service:
	1.	Read required_caps and auth_policy.
	2.	If auth_policy.mode == “cap_token”:
	•	determine which administrative or wallet overlay needs to issue the cap_token;
	•	either:
	•	call an issuance RPC on an admin service; or
	•	request an out-of-band cap_token from an operator.
	3.	Once a cap_token is obtained:
	•	POST it to /authorize on the chosen hub;
	•	receive auth_ref and expires_at.
	4.	Cache:
	•	service_id;
	•	hub endpoint;
	•	label / stream_ids;
	•	auth_ref and expiry.

7.4 Phase 4: bind to service

Given a selected service and auth_ref:
	1.	For RPC-based services:
	•	use the advertised stream_ids as:
	•	request label(s) for sending RPC requests;
	•	reply label(s) for receiving RPC responses.
	•	send RPC0 messages with:
	•	payload_hdr.schema = H(“rpc.v1”)
	•	body.method chosen from descriptor.methods
	•	include auth_ref in MSG.auth_ref if admission control is active.
	2.	For CRDT-based or other overlays:
	•	interpret stream_ids and schemas exactly as described in the overlay’s documentation;
	•	configure local fold logic.

The connect application MUST NOT bypass VEEN invariants or modify core behavior. It only automates selection and configuration.
	8.	Security model

8.1 Trust boundaries
	•	Discovery payloads are opaque to VEEN core; all trust is at the overlay level.
	•	Clients MUST treat discovery results as hints, not authoritative security statements.
	•	Before sending any confidential payloads, clients MUST:
	•	pin hub_pk out-of-band or via an explicit trust decision;
	•	verify RECEIPT signatures and invariants I1..I12.

8.2 Integrity of discovery data
	•	Discovery descriptors are authenticated by VEEN end-to-end properties:
	•	MSG.sig from the publisher;
	•	RECEIPT hub_sig from the discovery hub.
	•	Clients SHOULD pin:
	•	the publisher’s identity (for example operator org key) for critical services;
	•	expected overlay_ids and schemas.

8.3 Capability and exposure control
	•	Publishing a service descriptor does not grant write access. Actual access control is still via cap_token and /authorize.
	•	Operators MAY use tags and regions to distinguish:
	•	internal only services;
	•	public beta endpoints;
	•	production endpoints.

The connect application SHOULD respect these tags when proposing candidates.
	9.	Deployment patterns

Pattern A: central discovery hub
	•	One or a few hubs host the discovery streams.
	•	All other hubs and services publish discovery descriptors there.
	•	Clients contact these hubs for discovery, then connect directly to service hubs.

Pattern B: per-realm discovery
	•	Each realm or organization runs its own discovery streams and hubs.
	•	Cross-realm bridges mirror (subset) discovery descriptors using ANCHOR0/bridge mechanisms.
	•	Clients fold local realm discovery logs and optionally subscribe to remote ones.

Pattern C: client-only folding
	•	Discovery streams are public and readable via stream(with_proof=1).
	•	Connect applications fold discovery logs locally without an RPC query API.

	10.	Non-goals

The discovery overlay does not intend to:
	•	replace general-purpose service mesh discovery protocols;
	•	perform load balancing or health checking at runtime;
	•	override local policy decisions about which hubs or services are trusted;
	•	enforce any specific economic or billing model.

It is a minimal, log-derived directory of what exists and how to reach it over VEEN.
	11.	Summary

Discovery Overlay and Connect Application v0.0.1:
	•	define schemas and folding rules to advertise hubs, overlays, and services;
	•	provide a simple RPC query interface for filtered lookups;
	•	describe a connect application that selects hubs and services, obtains capabilities, and binds to overlays;
	•	keep all changes strictly at the overlay level, leaving VEEN core unchanged.

With this overlay in place, hubs and overlays become discoverable resources on the same fabric, and clients can programmatically “ask the network” which applications are available and how to connect to them, without any new core wire objects or error codes.

## wallet-spec.txt

VEEN Wallet Layer (WAL) v0.0.1 (tightened)
Account-Based Transfer Overlay with Bridging
Overlay on VEEN Core v0.0.1 and VEEN ID v0.0.1
Plain ASCII, no wire-format changes
	0.	Scope and dependencies

This document defines the VEEN Wallet Layer (WAL) v0.0.1 as an account-based transfer overlay on top of:
	•	VEEN Core v0.0.1: MSG, RECEIPT, CHECKPOINT, cap_token, MMR, labels, invariants.
	•	VEEN Identity Layer (ID) v0.0.1: principals, devices, realms, context IDs (ctx_id), organizations (org_id), delegation.

WAL adds:
	•	wallet identifiers scoped by realm, owner, and currency
	•	deposit, withdraw, transfer, adjust, limit, freeze, unfreeze events
	•	deterministic balance folding per wallet
	•	bridging rules for cross-hub replication

WAL does not:
	•	change VEEN MSG, RECEIPT, CHECKPOINT, cap_token, or any VEEN invariant
	•	define external settlement, FX, or pricing semantics
	•	define fraud detection policies

All WAL semantics are carried as encrypted VEEN payloads. Hubs remain blind to WAL contents.
	1.	Notation and basic rules

Ht(tag,x) = H(ascii(tag) || 0x00 || x) where H is SHA-256, as in VEEN Core.

CBOR rules for WAL payload bodies:
	•	map keys as ASCII text
	•	exact key set and key order as defined per schema
	•	minimal-length unsigned integers (major type 0)
	•	signed integers (for delta) use minimal-length negative or positive encoding
	•	definite-length byte strings and arrays only
	•	no floats
	•	no CBOR tags
	•	unknown keys MUST cause rejection

Amounts:
	•	amount fields are uint representing the smallest currency unit (for example cents).
	•	WAL v0.0.1 does not define decimal or fractional representation beyond integers.

Event ordering for folding:
	•	primary order is VEEN stream_seq on the wallet stream
	•	if multiple labels per stream are used, implementations MUST fold according to the hub-defined logical order for that stream_id and MUST treat that order as total
	•	tie-breaking beyond stream_seq MUST be stable and deterministic (for example leaf_hash lexical order) but SHOULD not occur if invariants are respected

	2.	Identity and wallet identifiers

2.1 Owner identity

WAL assumes owners are represented by VEEN ID-layer context identities within a realm:
	•	ctx_id: bstr(32) as in ID v0.0.1
	•	realm_id: bstr(32) as in ID v0.0.1

A wallet belongs logically to (realm_id, ctx_id).

2.2 Currency

currency_code: ASCII string, for example:
	•	“USD”, “JPY”, “EUR”
	•	“POINTS1”, “MILES”, “CREDITS”

WAL does not define or restrict the registry of valid currency_code values. Deployments MUST define:
	•	allowed codes
	•	external settlement semantics (for example, mapping to bank accounts or tokens)

2.3 Wallet identifier

For given (realm_id, ctx_id, currency_code), WAL defines:

wallet_id = Ht(“wallet/id”, realm_id || ctx_id || ascii(currency_code))

Properties:
	•	wallet_id is bstr(32)
	•	deterministic and stable for the lifetime of (realm_id, ctx_id, currency_code)
	•	unique per (realm_id, ctx_id, currency_code) within a deployment

	3.	Streams and schemas

3.1 Wallet stream

Each wallet_id SHOULD have a unique VEEN stream:

stream_id_wallet = Ht(“wallet/stream”, wallet_id)

All events that mutate or constrain that wallet MUST be sent on stream_id_wallet, except for system-wide indices or reports, which MAY be sent elsewhere but do not affect wallet folding.

Deployments MAY choose alternative stream layouts (such as multiple wallets per stream) but then MUST preserve deterministic folding for each wallet_id.

3.2 Schemas

Schema identifiers:
	•	schema_wallet_open     = H(“wallet.open.v1”)
	•	schema_wallet_close    = H(“wallet.close.v1”)
	•	schema_wallet_deposit  = H(“wallet.deposit.v1”)
	•	schema_wallet_withdraw = H(“wallet.withdraw.v1”)
	•	schema_wallet_transfer = H(“wallet.transfer.v1”)
	•	schema_wallet_adjust   = H(“wallet.adjust.v1”)
	•	schema_wallet_limit    = H(“wallet.limit.v1”)
	•	schema_wallet_freeze   = H(“wallet.freeze.v1”)
	•	schema_wallet_unfreeze = H(“wallet.unfreeze.v1”)

All schemas are carried via payload_hdr.schema and are AEAD-protected.
	4.	Wallet state model

For each wallet_id, WAL defines the following logical state snapshot:
	•	exists: bool
	•	closed: bool
	•	balance: uint (MUST be >= 0 at all times)
	•	frozen: bool
	•	daily_limit: uint? (optional, per-day outgoing limit)
	•	pending_daily_spent: uint (outgoing amount in the current limit window)
	•	last_limit_reset_ts: uint (unix time seconds; 0 means unset)

Implementations MAY maintain additional derived state (such as total_in, total_out, last_activity_ts) without affecting WAL correctness.
	5.	Events

5.1 Wallet open

Schema: wallet.open.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
realm_id: bstr(32),
ctx_id: bstr(32),
currency: text,
created_at: uint
}

Constraints:
	•	wallet_id MUST equal Ht(“wallet/id”, realm_id || ctx_id || ascii(currency)).
	•	created_at is unix time seconds.

Folding:
	•	If exists is false:
	•	exists = true
	•	closed = false
	•	balance = 0
	•	frozen = false
	•	daily_limit = null
	•	pending_daily_spent = 0
	•	last_limit_reset_ts = created_at
	•	If exists is true:
	•	implementations MAY treat this as a no-op or as a soft metadata refresh
	•	WAL v0.0.1 does not define conflict resolution for divergent open events; producers SHOULD ensure that each wallet_id has at most one open event with consistent fields.

5.2 Wallet close

Schema: wallet.close.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
ts: uint
}

Folding:
	•	If exists is false, event is ignored for state.
	•	If exists is true, closed is set to true.
	•	WAL v0.0.1 does not require balance = 0 at close. Deployments SHOULD enforce balance constraints at the producer level (for example, require that a closure only occurs when balance is 0).

5.3 Deposit

Schema: wallet.deposit.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
amount: uint,
ts: uint,
ref: bstr?       // optional external reference
}

Folding:
	•	Precondition: exists == true and closed == false. If not, producers MUST NOT emit deposits.
	•	On folding:
balance = balance + amount

ref is an opaque external reference (for example bank transaction ID). WAL does not interpret it.

WAL does not specify who is authorized to emit deposit events. This is governed by cap_token and application policy.

5.4 Withdraw

Schema: wallet.withdraw.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
amount: uint,
ts: uint,
ref: bstr?
}

Folding:
	•	Precondition: exists == true, closed == false, frozen == false.
	•	Limit handling:
If daily_limit is not null:
	•	If needs_reset(last_limit_reset_ts, ts) is true:
	•	pending_daily_spent = 0
	•	last_limit_reset_ts = ts
	•	If pending_daily_spent + amount > daily_limit:
	•	producers MUST NOT emit such an event as “accepted”
	•	verifiers MUST treat this as a policy violation
	•	Overdraft prevention:
	•	If balance < amount:
	•	producers MUST NOT emit such an event as “accepted”
	•	verifiers MUST treat this as a policy violation
	•	On accepted event, folding:
balance = balance - amount
if daily_limit is not null:
pending_daily_spent = pending_daily_spent + amount

5.5 Transfer

WAL standardizes a symmetric, two-sided transfer using one authoritative event and one derived credit. To keep per-wallet folding local and O(1), WAL chooses Option B (explicit credit) as normative.

Schema: wallet.transfer.v1
Stream: stream_id_wallet (source wallet)

Body:

{
wallet_id: bstr(32),            // source wallet id
to_wallet_id: bstr(32),
amount: uint,
ts: uint,
transfer_id: bstr(32),
metadata: map?                  // optional
}

transfer_id MUST be globally unique within the WAL deployment. A recommended canonical value:

transfer_id = Ht(“wallet/xfer”, msg_id)

where msg_id is the VEEN leaf_hash of this MSG.

Source wallet folding:
	•	Precondition: same as withdraw:
	•	exists == true
	•	closed == false
	•	frozen == false
	•	Limit handling exactly as in withdraw.
	•	Overdraft prevention exactly as in withdraw.
	•	On accepted event:
balance = balance - amount
if daily_limit not null:
pending_daily_spent = pending_daily_spent + amount

Destination wallet credit:

Destination wallets MUST treat a transfer from another wallet as an incoming credit. WAL defines a derived credit event that MUST be equivalent to a deposit under a specific reference.

For destination wallet_id_dest:
	•	Either:
	•	the same MSG is mirrored into the destination wallet stream via application logic, or
	•	the destination state machine consumes wallet.transfer.v1 events via an index

In both cases, destination folding:
	•	For a wallet.transfer.v1 event where to_wallet_id == wallet_id_dest:
balance = balance + amount

The destination balance MUST NOT apply daily_limit or pending_daily_spent changes for incoming transfers.

Duplicate transfer_id:
	•	Implementations MUST treat multiple occurrences of the same transfer_id as the same logical transfer when folding balances, to avoid double credit or double debit.
	•	A simple rule:
	•	maintain a per-wallet set of seen transfer_id for source-side debits and destination-side credits (in memory or as a derived index)
	•	if transfer_id already processed for that wallet and direction, ignore additional copies for balance folding

5.6 Adjust

Schema: wallet.adjust.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
delta: int,      // CBOR signed integer
ts: uint,
reason: text,
ref: bstr?
}

Semantics:
	•	adjust is an administrative correction operation.
	•	Applications MUST treat adjust as high-privilege and SHOULD restrict it to institutional principals (org_pk) via cap_token.

Folding:
	•	Let new_balance = balance + delta.
	•	If new_balance < 0:
	•	producers MUST NOT emit such an event as accepted
	•	verifiers MUST treat as policy violation
	•	Else:
balance = new_balance

Adjust does not affect pending_daily_spent nor last_limit_reset_ts. If deployments want to reset limits after adjustments, they MUST emit a separate wallet.limit.v1 event.

5.7 Limit

Schema: wallet.limit.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
daily_limit: uint?,   // null clears the limit
ts: uint
}

Folding:
	•	If daily_limit is null:
daily_limit = null
	•	Else:
daily_limit = provided value

If last_limit_reset_ts == 0, implementations MAY set last_limit_reset_ts = ts on first limit definition.

needs_reset(last_limit_reset_ts, ts_now) MUST be defined consistently per deployment. A simple canonical choice:
	•	define day = floor(ts / 86400)
	•	needs_reset returns true when day(ts_now) != day(last_limit_reset_ts)

5.8 Freeze

Schema: wallet.freeze.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
ts: uint,
reason: text?
}

Folding:
	•	frozen = true

5.9 Unfreeze

Schema: wallet.unfreeze.v1
Stream: stream_id_wallet

Body:

{
wallet_id: bstr(32),
ts: uint,
reason: text?
}

Folding:
	•	frozen = false

	6.	Reference folding algorithm

For each wallet_id, implementations MUST derive state by folding all WAL events in stream order. The following pseudocode is normative:

state0:
exists = false
closed = false
balance = 0
frozen = false
daily_limit = null
pending_daily_spent = 0
last_limit_reset_ts = 0

for each event e in stream order:
match e.schema:

wallet.open.v1:
  if not exists:
    exists = true
    closed = false
    balance = 0
    frozen = false
    daily_limit = null
    pending_daily_spent = 0
    last_limit_reset_ts = e.created_at

wallet.close.v1:
  if exists:
    closed = true

wallet.limit.v1:
  if e.daily_limit is null:
    daily_limit = null
  else:
    daily_limit = e.daily_limit
    if last_limit_reset_ts == 0:
      last_limit_reset_ts = e.ts

wallet.freeze.v1:
  if exists:
    frozen = true

wallet.unfreeze.v1:
  if exists:
    frozen = false

wallet.deposit.v1:
  if exists and not closed:
    balance += e.amount

wallet.withdraw.v1:
  if exists and not closed and not frozen:
    if daily_limit not null:
      if needs_reset(last_limit_reset_ts, e.ts):
        pending_daily_spent = 0
        last_limit_reset_ts = e.ts
      pending_daily_spent += e.amount
    balance -= e.amount

wallet.transfer.v1:
  if exists and not closed:
    if e.wallet_id == wallet_id:
      if not frozen:
        if daily_limit not null:
          if needs_reset(last_limit_reset_ts, e.ts):
            pending_daily_spent = 0
            last_limit_reset_ts = e.ts
          pending_daily_spent += e.amount
        balance -= e.amount
    else if e.to_wallet_id == wallet_id:
      balance += e.amount

wallet.adjust.v1:
  if exists and not closed:
    balance = balance + e.delta

Implementations MUST additionally enforce that balance never becomes negative at runtime. The above algorithm assumes upstream validation has ensured this.
	7.	Double-spend and idempotency

VEEN Core guarantees:
	•	uniqueness of (client_id, client_seq) per label
	•	strict increment of client_seq per client_id per label
	•	MMR-committed, append-only RECEIPTs

WAL builds on this with:
	•	per-wallet overdraft checks (balance >= amount before debit)
	•	per-wallet daily_limit checks
	•	globally unique transfer_id for transfers

Applications SHOULD:
	•	treat a second attempt at the same withdraw or transfer (for example due to retries) as a duplicate if:
	•	it reuses the same transfer_id or ref, or
	•	it has the same msg_id
	•	reject or ignore duplicates when recomputing balances
	•	rely on VEEN invariants to ensure accepted MSG are not duplicated by the hub

No blockchain-style consensus is required; VEEN ordering plus local invariants are sufficient.
	8.	Authorization via cap_token

WAL depends on VEEN cap_token for admission control.

Typical patterns:
	•	End-user wallets:
	•	issuer_pk = principal_pk of user
	•	subject_pk = device_pk of user device
	•	allow.stream_ids includes the wallet streams for that user
	•	ttl is relatively short
	•	rate is tuned for human usage
	•	Institutional wallets (for example issuer, settlement):
	•	issuer_pk = org_pk
	•	subject_pk = service key
	•	allow.stream_ids includes system wallets and indexes
	•	ttl may be longer
	•	rate may be higher

For safety, deployments SHOULD:
	•	never grant deposit, adjust, freeze, unfreeze, or limit capabilities directly to end-user devices for institutional wallets
	•	require that these operations are emitted by institution-controlled services with separate keys
	•	implement additional business rules outside WAL for KYC and risk checks

	9.	Multisignature and approvals (informative)

Multisignature policies can be layered on WAL without protocol modifications:
	•	A transfer is proposed as an application-level object.
	•	Approvers sign a hash of core fields:
approval_hash = Ht(“wallet/approval”, wallet_id || to_wallet_id || u64be(amount) || ts || transfer_id)
	•	Signatures are collected as an array of Ed25519 signatures in metadata or a separate overlay schema.
	•	Once policy is satisfied (for example m-of-n), a single wallet.transfer.v1 event is emitted with MSG.sig by a designated execution key.

Hub and WAL folding logic remain unchanged. All multisig semantics live at the application level, and are fully auditable within the VEEN log.
	10.	Attachments and metadata

WAL events MAY include:
	•	metadata: CBOR map (for example narrative, category, tags, external references)
	•	att_root: reference to VEEN attachments if large payloads (such as invoices) are attached

Attach semantics:
	•	WAL folding (balance, limits, freeze) MUST not depend on metadata or attachments.
	•	Validation of attachments (for example verifying a Merkle tree) is optional and application-specific.

	11.	Bridging (WALBR0)

11.1 Scope

WALBR0 defines bridging rules for replicating wallet events between hubs. Bridging is implemented as an application using VEEN ANCHOR and BRIDGE overlays. No WAL payloads or schemas change.

11.2 Authoritative hub and replicas

Deployments SHOULD choose an authoritative hub (or small set) per wallet_id or per realm. Authoritative hubs:
	•	accept wallet-mutating events (open, deposit, withdraw, transfer, adjust, limit, freeze, unfreeze)
	•	commit them to their MMR and issue RECEIPTs

Replica hubs:
	•	receive bridged copies of these events
	•	fold state for read or local analytics
	•	SHOULD NOT originate new wallet-mutating events for the same wallet_id unless explicitly configured for multi-primary behavior

11.3 Bridging procedure

A bridge component:
	•	subscribes on hub A to relevant wallet streams (via stream with with_proof=1)
	•	for each MSG m_A and RECEIPT_A:
	•	verifies RECEIPT_A and mmr_proof if present
	•	constructs a new MSG m_B with:
	•	payload_hdr.schema = payload_hdr.schema from m_A
	•	payload body = payload body from m_A (byte-for-byte)
	•	payload_hdr.parent_id = msg_id of m_A
	•	client_id and label chosen per hub B policy
	•	MSG.sig created by bridge’s client key
	•	submits m_B to hub B and obtains RECEIPT_B

Wallet state on hub B is computed by folding WAL events from both locally-originated and bridged MSG.

11.4 Bridged idempotency

To avoid counting the same transfer or adjustment twice across hubs, implementations MUST:
	•	treat parent_id as the canonical identity of bridged events
	•	maintain a per-hub or per-deployment index of seen parent_id for WAL schemas
	•	ignore duplicates of the same parent_id when folding wallet balances

If both hubs might originate WAL events for the same wallet_id, deployments MUST define additional conflict-resolution mechanisms. WALBR0 assumes single-authority per wallet_id for simplicity.

11.5 Cross-currency or cross-realm bridging

WALBR0 does not alter wallet_id or currency_code during bridging. If different hubs are used for different jurisdictions or currencies:
	•	a bridge MAY translate wallet_id and currency_code to a different representation, but then the resulting events are outside WAL v0.0.1 canonical semantics
	•	such transformations MUST be documented and are deployment-specific

	12.	Audit and compliance

WAL on VEEN yields:
	•	full, append-only logs for all wallet operations (receipts.cborseq and payloads.cborseq)
	•	cryptographically committed and signed MMR roots
	•	optional external anchoring of roots for time-stamping

An auditor can:
	•	re-fold all wallets from raw WAL events
	•	verify that every balance is consistent with the event log
	•	prove that specific events existed at or before specific checkpoints or external anchors

WAL v0.0.1 deliberately keeps all monetary semantics in a single, verifiable log. No hidden side channels or out-of-band balance changes are assumed.
	13.	Error reporting

Transport-level errors use VEEN error codes (E.SIG, E.SIZE, E.SEQ, E.CAP, E.AUTH, E.RATE, E.PROFILE, E.DUP, E.TIME).

Application-level WAL errors SHOULD be returned as structured payloads (for example over an RPC overlay):

Examples:
	•	WAL.INSUFFICIENT_FUNDS
	•	WAL.FROZEN
	•	WAL.CLOSED
	•	WAL.DAILY_LIMIT_EXCEEDED
	•	WAL.INVALID_CURRENCY
	•	WAL.UNAUTHORIZED_OPERATION

WAL does not standardize these codes. Deployments SHOULD:
	•	define a stable set of error codes
	•	ensure these are logged via WAL or auxiliary streams for auditability

	14.	Conformance levels

An implementation MAY claim the following conformance sets:
	•	“WAL v0.0.1 Core”:
	•	implements wallet_id derivation
	•	supports wallet.open.v1, wallet.deposit.v1, wallet.withdraw.v1, wallet.transfer.v1
	•	folds balances correctly for single-hub deployments
	•	“WAL v0.0.1 Limits”:
	•	“Core” plus wallet.limit.v1 and daily limit folding
	•	“WAL v0.0.1 Control”:
	•	“Limits” plus wallet.freeze.v1, wallet.unfreeze.v1, wallet.adjust.v1
	•	“WAL v0.0.1 Bridge”:
	•	“Control” plus WALBR0 bridging with parent_id based deduplication

	15.	Security considerations

WAL inherits VEEN security properties:
	•	E2E confidentiality via HPKE + AEAD
	•	sender authenticity via Ed25519 MSG.sig
	•	hub-origin authenticity via hub_sig on RECEIPTs and CHECKPOINTs
	•	append-only, publicly verifiable logs via MMR and optional anchoring

WAL-specific considerations:
	•	balance must never go negative; this is enforced by application logic on top of WAL semantics
	•	adjust and deposit SHOULD be tightly restricted by cap_token and policy
	•	large or high-risk transactions SHOULD be subject to additional review (for example multisig, approvals schema)
	•	caps on daily_limit SHOULD be used to bound damage from key compromise

Key rotation and revocation MUST follow VEEN ID and cap_token practices, with particular care for:
	•	devices that can emit wallet-mutating events
	•	institutional service keys that can perform adjust, deposit, freeze, unfreeze

	16.	Summary

WAL v0.0.1 defines a compact, deterministic, account-based wallet overlay for VEEN:
	•	each wallet is bound to (realm_id, ctx_id, currency_code) via wallet_id
	•	balances are computed by folding a stable set of event types
	•	all semantics are encoded as end-to-end encrypted messages, not hub-visible state
	•	bridging replicates events across hubs without any change in payload
	•	auditability, non-repudiation, and portability are inherited from VEEN


## Consolidated operational and guidance documents


## CORE-GOALS.txt

⸻

0. Top-Level Structure

You have three main entrypoints from WSL:
	•	veen-hub – hub process (core + overlays)
	•	veen-cli – client / admin / test driver
	•	veen-selftest – orchestration for integration + unit/property/fuzz tests

Top-level test goals

From WSL, all of these must succeed:

veen-selftest core        # v0.0.1 core (wire, crypto, MMR, invariants, RPC/CRDT/ANCHOR/OBS/COMP/SH0/DR0/TS0)
veen-selftest overlays    # v0.0.1+ overlays (FED1, AUTH1, KEX1+, SH1+, LCLASS0, META0+)
veen-selftest all         # runs both suites end-to-end

If veen-selftest all is green on WSL, the implementation is considered complete.

⸻

1. Core Integration GOALs (VEEN v0.0.1)

1.1 Core E2E messaging + receipts + verification

GOAL: From WSL, you can spin up a single hub and do full E2E:
	•	Generate keys for a client.
	•	Send an encrypted MSG to a stream.
	•	Receive the MSG and decrypt it.
	•	Verify the RECEIPT and MMR root against the local view.

Key flows:

# Start hub
veen-hub run \
  --listen 127.0.0.1:8080 \
  --data-dir ~/.veen/hub-core

# Create a client
veen-cli keygen --out ~/.veen/client1

# Send a message
veen-cli send \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream core/main \
  --body '{"text":"hello-veens"}' \
  --dump-raw msg.cbor receipt.cbor

# Stream + decrypt
veen-cli stream \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream core/main \
  --from 1

# Verify RECEIPT + MMR
veen-cli verify-receipt --receipt receipt.cbor --stream core/main

Acceptance:
	•	MSG ciphertext is opaque to the hub (no plaintext in hub logs).
	•	verify-receipt confirms I1–I3 and MMR root for that label.
	•	Deterministic CBOR: re-encoding the same struct yields identical bytes.

⸻

1.2 Attachments (section 10)

GOAL: Attachments are encrypted, committed via att_root, and verifiable.

Flow:

veen-cli send-with-attachment \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream core/att \
  --file ./big.bin \
  --dump-raw msg_att.cbor receipt_att.cbor

veen-cli verify-attachment \
  --msg msg_att.cbor \
  --file ./big.bin

Acceptance:
	•	verify-attachment recomputes coid and att_root and matches payload_hdr.att_root.
	•	Any mutation of attachment bytes or att_root leads to rejection or verification failure.

⸻

1.3 Capabilities + admission + error codes (sections 11, 13, 21)

GOAL: Permissioned writes with rate limiting and correct E.* codes.

Flow:

# Admin identity
veen-cli keygen --out ~/.veen/admin

# Issue cap_token
veen-cli cap issue \
  --issuer ~/.veen/admin \
  --subject ~/.veen/client1.pub \
  --stream core/capped \
  --ttl 600 \
  --rate "5/s,10" \
  --out cap_client1.cbor

# Authorize on hub
veen-cli cap authorize \
  --hub http://127.0.0.1:8080 \
  --cap cap_client1.cbor

Tests:
	1.	Write without cap → E.AUTH / HTTP 403
	2.	Write with valid cap → success + RECEIPT
	3.	Exceed rate → E.RATE / HTTP 429
	4.	Use expired cap → E.CAP
	5.	Unknown profile_id, profile mismatch, etc. → E.PROFILE / HTTP 400
	6.	Dup (client_id, client_seq) → E.SEQ or E.DUP / HTTP 409

All via veen-selftest core subtests.

⸻

1.4 RESYNC + durable client state (RESYNC0)

GOAL: Client can lose its local state and fully reconstruct it from hub.

Flow:

# Load a stream with messages
veen-cli bench send \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream core/resync \
  --count 1000

# Destroy local client state
rm -rf ~/.veen/state/client1/*

# Resync from hub
veen-cli resync \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream core/resync

# Verify local state vs hub
veen-cli verify-state \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream core/resync

Acceptance:
	•	verify-state confirms last_stream_seq and last_mmr_root match the hub.
	•	RESYNC uses stream?from= and CHECKPOINT correctly; no holes, no divergences.

⸻

1.5 RPC overlay (RPC0)

GOAL: Request/response RPC over VEEN works end-to-end.

Flow:

veen-cli rpc call \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream rpc/main \
  --method "add" \
  --args '{"a":1,"b":2}' \
  --timeout-ms 5000

Acceptance:
	•	Request uses schema = H("rpc.v1"), reply uses schema = H("rpc.res.v1").
	•	Replies carry parent_id = request.msg_id.
	•	ok:true => result present; ok:false => error present.
	•	Idempotency: repeated (method, client_id, idem) yields the same result and no duplicate side-effects.

⸻

1.6 CRDT overlay (CRDT0)

GOAL: LWW, OR-Set, and G-Counter semantics hold when replayed via VEEN logs.

Examples:
	•	LWW register:

veen-cli crdt-lww set \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream crdt/main \
  --key foo \
  --value "A" \
  --ts 1

veen-cli crdt-lww set \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream crdt/main \
  --key foo \
  --value "B" \
  --ts 2

veen-cli crdt-lww get \
  --hub http://127.0.0.1:8080 \
  --stream crdt/main \
  --key foo
# => "B"

	•	OR-Set, G-Counter have analogous flows.

Acceptance:
	•	Snapshots up to upto_seq are deterministic and match the CRDT spec.
	•	Replaying from CHECKPOINT + receipts yields the same CRDT state.

⸻

1.7 Anchoring (ANCHOR0)

GOAL: Hub anchors MMR roots externally and auditors can verify the binding.

Flow:
	•	Start hub with anchoring backend configured (file or dummy ledger).
	•	Let hub run until it emits CHECKPOINTs with anchor_ref.
	•	From WSL:

veen-cli verify-anchor \
  --checkpoint checkpoint.cbor

Acceptance:
	•	verify-anchor confirms mmr_root → anchor_ref → external backend is consistent.
	•	Anchor cadence (K receipts or T minutes) is respected.

⸻

1.8 Observability / Compliance / Hardening (OBS0, COMP0, SH0, DR0)

GOAL: Core operational edges exist and behave as specified.

Checks:
	•	/healthz returns {ok, profile_id, peaks_count, last_stream_seq, last_mmr_root}.
	•	Metrics include veen_submit_ok_total, veen_submit_err_total{code}, latency histograms, etc.
	•	Logs are structured JSON per submit (label, client_id_prefix, stream_seq, leaf_hash_prefix, code?, bytes_in, bytes_out, verify_ms, commit_ms).
	•	Retention and file rotation work (receipts.cborseq, payloads.cborseq, checkpoints.cborseq + index sidecars).
	•	TLS uses AEAD suites and no compression; bounds checks happen before expensive crypto.

All covered by veen-selftest core via combined integration + small unit/property tests.

⸻

2. Overlay Integration GOALs (VEEN v0.0.1+)

These are the “+” features: FED1, AUTH1, KEX1+, SH1+, LCLASS0, META0+.

2.1 Federation & single-primary discipline (FED1 + AUTH1)

GOAL: Primary/replica/bridge topology with single writer per label.

Flow (from WSL):

# primary hub
veen-hub run \
  --role primary \
  --listen 127.0.0.1:8080 \
  --data-dir ~/.veen/hub-primary

# replica hub
veen-hub run \
  --role replica \
  --listen 127.0.0.1:8081 \
  --data-dir ~/.veen/hub-replica

# bridge primary -> replica
veen-bridge run \
  --from http://127.0.0.1:8080 \
  --to   http://127.0.0.1:8081

Set authority:

PRIMARY_ID=$(veen-cli hub-id --hub http://127.0.0.1:8080)
REPLICA_ID=$(veen-cli hub-id --hub http://127.0.0.1:8081)

veen-cli authority set \
  --realm default \
  --stream fed/chat \
  --primary-hub $PRIMARY_ID \
  --replica-hub $REPLICA_ID

Tests:
	1.	Send to primary → success.
	2.	Send directly to replica → E.AUTH/E.CAP (not primary for label).
	3.	Stream from replica → primary’s events appear via bridge.
	4.	On both hubs, veen-cli audit --stream fed/chat shows identical mmr_root and stream_seq.

All run by veen-selftest overlays --subset fed-auth.

⸻

2.2 Key/identity lifecycle and revocation (KEX1+)

GOAL: Enforce client_id lifetime, per-client msg caps, and revocation.

Flow:
	•	Start hub with:
	•	max_client_id_lifetime_sec
	•	max_msgs_per_client_id_per_label
	•	Use veen-cli to:
	1.	Hit the message cap for a client_id → next send fails with E.CAP/E.AUTH.
	2.	Wait (or simulate) client_id lifetime expiry → sends fail.
	3.	Revoke client-id, auth-ref, cap-token via:

veen-cli revoke \
  --hub http://127.0.0.1:8080 \
  --kind client-id|auth-ref|cap-token \
  --target <value>



Acceptance:
	•	All three revocation kinds take effect immediately for new writes.
	•	Revocation state is carried in the log and can be audited.

⸻

2.3 Hardening pipeline (SH1+)

GOAL: Full Stage0–Stage3 admission pipeline behaves correctly under normal and adversarial load.

Checks (driven by veen-selftest overlays --subset sh1):
	•	Oversized payloads fail at Stage0 (length checks) with E.SIZE / HTTP 413.
	•	Malformed CBOR / unknown keys fail at Stage1 with E.SIZE.
	•	Bad signatures fail at Stage2 with E.SIG / HTTP 409.
	•	Unauthorized / over-rate traffic fails at Stage2 with E.AUTH/E.CAP/E.RATE.
	•	Invariant violations fail at Stage3 with E.SEQ/E.DUP/E.PROFILE.
	•	Optional PoW / stateless cookie: requests without a valid cookie are blocked during overload; valid cookie passes.

Bounds-first is enforced: crypto is not invoked for obvious garbage.

⸻

2.4 Label classification (LCLASS0)

GOAL: Label classes influence padding, rate, and retention without exposing payload contents.

Flow:

# Set label classes as admin
veen-cli label-class set \
  --stream chat/user \
  --class user \
  --sensitivity medium \
  --retention-hint 86400

veen-cli label-class set \
  --stream wallet/main \
  --class wallet \
  --sensitivity high \
  --retention-hint 2592000

veen-cli label-class set \
  --stream log/ingest \
  --class log \
  --sensitivity low \
  --retention-hint 86400

# Inspect classification view
veen-cli label-class show \
  --hub http://127.0.0.1:8080 \
  --label HEX32 \
  --json

veen-cli label-class list \
  --hub http://127.0.0.1:8080 \
  --class user

Tests:
	•	Short payloads to each label must result in different ciphertext lengths per configured pad_block (e.g. 256 vs 1024 vs 0).
	•	Rate-limit and retention policies follow the label class configuration.
	•	All of this happens without hub ever seeing decrypted payloads.
	•	veen-cli label-class show/list reflect the hub’s classification view in text and JSON output.

⸻

2.5 Schema metadata (META0+)

GOAL: Schema registry maps schema_id to human-readable metadata and coordinates overlays (RPC, wallet, CRDT, etc.).

Flow:

# Register a schema
SCHEMA_ID=$(veen-cli schema-id "wallet.transfer.v1")

veen-cli schema register \
  --realm default \
  --schema-id $SCHEMA_ID \
  --name "wallet.transfer.v1" \
  --version "v1" \
  --doc-url "https://example.com/wallet-transfer" \
  --owner ~/.veen/admin.pub

# Use schema in a wallet-like message
veen-cli wallet transfer \
  --hub http://127.0.0.1:8080 \
  --client ~/.veen/client1 \
  --stream wallet/main \
  --to "user2" \
  --amount "100"

Acceptance:
	•	veen-cli schema list shows the registered schema.
	•	Messages that use this schema_id can be introspected by tooling (debug/CLI) even though the hub sees only ciphertext.
	•	Unregistered/unknown schemas are still transmitted, but tooling can report them as “unknown schema”.

⸻

2.6 Combined overlay scenario

GOAL: All overlays cooperate correctly in one integrated run.

Scenario (driven by veen-selftest overlays-full):
	•	Primary + replica + bridge.
	•	Label classes configured.
	•	Schema metadata registered for some RPC/CRDT/wallet messages.
	•	cap_token issued, authorized, then revoked.
	•	High RPS traffic to mixed labels (wallet, chat, log, admin) under SH1.
	•	Clients RESYNC after state loss.
	•	primary and replica remain consistent (mmr_root, CHECKPOINT, anchor).
	•	No hub crashes, correct E.* codes everywhere, and health/metrics/logs stay consistent.

If this full scenario passes from WSL, the overlay feature set is considered complete.

⸻

3. Final Acceptance: What “DONE” Means

VEEN v0.0.1+ implementation is “DONE” when:
	1.	From WSL, you can:
	•	Start hubs (single, primary/replica),
	•	Run clients and admin flows via veen-cli,
	•	Exercise all core and overlay behaviours as above.
	2.	veen-selftest core passes:
	•	Core wire format, crypto, MMR, invariants, RPC, CRDT, anchoring, observability, compliance, hardening, deployment mappings.
	3.	veen-selftest overlays passes:
	•	Federation (FED1), authority discipline (AUTH1), key/cap lifecycle and revocation (KEX1+), hardening pipeline (SH1+), label classification (LCLASS0), and schema metadata (META0+).
	4.	veen-selftest all is green on your WSL environment without manual intervention.

At that point you can say, in a very literal sense:

“From WSL, I can operate a full VEEN v0.0.1+ fabric – core + overlays – and verify every property the spec claims, via integration tests.”


## CLI-GOALS-1.txt

VEEN CLI v0.0.1 Operational Goal Specification (Tightened)
Plain ASCII, English only. No overlays beyond v0.0.1 (OP0, KEX0, RESYNC0, RPC0, CRDT0, ANCHOR0, OBS0, COMP0, SH0, DR0, TS0).
	0.	Scope

This document defines the required capabilities of the VEEN command line interface (CLI) for VEEN v0.0.1.

The CLI must be sufficient to:
	•	start, stop, and inspect a v0.0.1 hub
	•	manage client identities and hub keys
	•	send and receive VEEN messages
	•	handle attachments
	•	use capability tokens and admission
	•	resynchronize and verify client state
	•	use RPC0 and CRDT0 overlays
	•	manage external anchoring
	•	inspect observability, compliance, and hardening behavior
	•	run the v0.0.1 self test suite

If every requirement below is met, v0.0.1 is considered operationally complete from the CLI.
	1.	CLI process model

1.1 Binary
	•	Single binary: veen

1.2 Roles

The CLI supports these roles with no additional binaries:
	•	hub operator
	•	client user
	•	administrator
	•	auditor
	•	application developer (RPC/CRDT)

1.3 General rules
	•	Commands are deterministic given the same filesystem and environment variables.
	•	Non-zero exit code on error; 0 on success.
	•	Machine-readable outputs use JSON or CBOR on stdout when explicitly requested.
	•	Human-facing defaults are single-line or short multi-line text.

	2.	Hub control

2.1 Start hub

Command shape:

veen hub start 
–listen 0.0.0.0:8080 
–data-dir /path/to/data 
[–config /path/to/config.toml] 
[–profile-id hex32] 
[–foreground] 
[–log-level info|debug|warn|error]

Requirements:
	•	Starts a hub implementing:
	•	v0.0.1 core wire objects (MSG, RECEIPT, CHECKPOINT, mmr_proof)
	•	OP0 (operational profile)
	•	KEX0 (hub key pin and rotation)
	•	RESYNC0
	•	RPC0
	•	CRDT0
	•	ANCHOR0
	•	OBS0
	•	COMP0
	•	SH0
	•	DR0
	•	TS0
	•	Creates or reuses the directory tree under data-dir:
	•	data-dir/receipts.cborseq
	•	data-dir/payloads.cborseq (if enabled)
	•	data-dir/checkpoints.cborseq
	•	data-dir/anchors/…
	•	data-dir/state/…
	•	Listens on the specified address for:
	•	POST /submit
	•	GET  /stream
	•	GET  /checkpoint_latest
	•	GET  /checkpoint_range
	•	POST /authorize
	•	POST /report_equivocation
	•	GET  /healthz
	•	GET  /metrics

2.2 Stop hub

Command:

veen hub stop 
–data-dir /path/to/data

Requirements:
	•	Locates the running hub associated with data-dir (PID file or similar).
	•	Requests graceful shutdown.
	•	Waits until:
	•	receipts.cborseq is flushed
	•	checkpoints.cborseq is flushed
	•	current peaks are checkpointed
	•	anchoring queue is drained or cleanly persisted

2.3 Hub status

Command:

veen hub status 
–hub http://host:port

Output:
	•	role: string (for v0.0.1 minimal: “standalone”; federation role is out of scope here)
	•	profile_id: hex32
	•	peaks_count: uint
	•	last_stream_seq: uint (for a requested label or all labels)
	•	uptime_sec: uint
	•	data_dir: path (if reported)

	3.	Hub keys (KEX0 subset)

3.1 Show hub public key

Command:

veen hub key 
–hub http://host:port

Output:
	•	hub_pk: hex32 (Ed25519 public key)
	•	profile_id: hex32
	•	may include a hash identifier: H(hub_pk || profile_id)

3.2 Hub key rotation (admin view)

Actual rotation mechanism is out of scope for CLI v0.0.1; however the CLI MUST:
	•	be able to fetch CHECKPOINTs with witness_sigs (old and new hub keys) and:
	•	verify that both signatures are valid during rotation window.

Command:

veen hub verify-rotation 
–checkpoint checkpoint.cbor 
–old-key old_hub_pk.hex 
–new-key new_hub_pk.hex
	4.	Client identity and key management

4.1 Generate client identity

Command:

veen keygen 
–out /path/to/client

Requirements:
	•	Generate id_sign (Ed25519 private key).
	•	Generate id_dh (X25519 private key).
	•	Generate initial HPKE prekeys signed by id_sign.
	•	Create:
	•	/path/to/client/keystore.enc
	•	/path/to/client/identity_card.pub
	•	/path/to/client/state.json or equivalent
	•	identity_card.pub contains the public portion (id_sign public, id_dh public, metadata).

4.2 Show client identity

Command:

veen id show 
–client /path/to/client

Output:
	•	client_id: hex32 (current Ed25519 public key used as MSG.client_id)
	•	id_sign_public: hex32
	•	id_dh_public: hex32
	•	profile_id (if pinned)
	•	local state summary (last_stream_seq per label, last_mmr_root per label)

4.3 Rotate client_id (KEX0)

Command:

veen id rotate 
–client /path/to/client

Requirements:
	•	Generate a new Ed25519 keypair used for client_id.
	•	Generate new prekeys signed by id_sign.
	•	Store local linkage metadata in client state only.
	•	Do not emit any wire-visible linkage identifier.

	5.	Message send and receive

5.1 Send MSG

Minimal command:

veen send 
–hub http://host:port 
–client /path/to/client 
–stream stream/name 
–body ‘{“k”:“v”}’

Parameters:
	•	–stream: logical stream name, mapped to stream_id via H(stream/name).
	•	–body: JSON string, encoded as CBOR for payload body.
	•	Optional:
	•	–schema hex32 (if the caller wants a specific payload_hdr.schema)
	•	–expires-at unix_timestamp
	•	–cap cap.cbor (to use a capability token)
	•	–no-store-body (do not store payloads.cborseq locally)

Mandatory behavior:
	•	Load client keys and local state for this label (stream + epoch).
	•	Compute label based on routing_secret, stream_id, and epoch.
	•	Build payload_hdr with:
	•	schema (explicit or default)
	•	parent_id (if provided via option)
	•	att_root (provided or omitted)
	•	cap_ref (if using cap inside payload)
	•	expires_at (if provided)
	•	Run HPKE.SealSetup and HPKE.Seal for payload_hdr.
	•	Derive k_body via HPKE.Export.
	•	Compute nonce from (label, prev_ack, client_id, client_seq).
	•	AEAD encrypt body with k_body and nonce.
	•	Apply padding if pad_block > 0 from the profile.
	•	Compute ct_hash = H(ciphertext).
	•	Compute leaf_hash and msg_id.
	•	Construct MSG map in correct field order.
	•	Sign MSG.sig = Ed25519(Ht(“veen/sig”, CBOR(MSG without sig))).
	•	POST MSG to /submit.
	•	Receive RECEIPT or error.

Postconditions if RECEIPT is returned:
	•	Verify hub_sig.
	•	Verify I1..I12 for (MSG, RECEIPT).
	•	Update local MMR state for the label (stream_seq, peaks, mmr_root).
	•	Update prev_ack to the new stream_seq.

5.2 Receive MSG via stream

Command:

veen stream 
–hub http://host:port 
–client /path/to/client 
–stream stream/name 
[–from N] 
[–with-proof]

Behavior:
	•	Map stream to label as in send.
	•	GET /stream?label=…&from=N&with_proof=(0|1).
	•	For each {RECEIPT, MSG, mmr_proof?} triple:
	•	Verify hub_sig.
	•	Verify invariants I1..I12.
	•	If with_proof, verify mmr_proof against RECEIPT.mmr_root.
	•	Update local MMR state.
	•	Decrypt MSG for this client:
	•	Reconstruct HPKE ctx or re-open as needed.
	•	Recompute nonce.
	•	AEAD decrypt.
	•	Output:
	•	stream_seq
	•	msg_id (leaf_hash)
	•	payload_hdr fields
	•	body (as JSON if possible)

	6.	Attachments

6.1 Send with attachments

Command:

veen send 
–hub http://host:port 
–client /path/to/client 
–stream stream/att 
–body ‘{“k”:“v”}’ 
–attach ./file1.bin 
–attach ./file2.bin

Behavior:
	•	For each attachment i:
	•	Derive k_att = HPKE.Export(ctx, “veen/att-k” || u64be(i)).
	•	Derive n_att from msg_id and i.
	•	Encrypt attachment bytes b to ciphertext c.
	•	Compute coid = H(c).
	•	Compute att_root as Merkle root over coids according to spec.
	•	Place att_root into payload_hdr.att_root.
	•	Optionally store encrypted attachments locally keyed by coid.

6.2 Verify attachments

Command:

veen attachment verify 
–msg msg.cbor 
–file ./file1.bin 
–index i

Requirements:
	•	Recompute coid for attachment i.
	•	Recompute att_root from all coids.
	•	Verify equality with payload_hdr.att_root.
	•	Exit 0 if matched, non-zero if mismatched.

	7.	Capability tokens and admission

7.1 Issue cap_token

Command:

veen cap issue 
–issuer /path/to/issuer 
–subject /path/to/subject.pub 
–stream stream/name 
–ttl SECONDS 
[–rate “PER_SEC,BURST”] 
–out cap.cbor

Behavior:
	•	Build cap_token:
	•	ver = 1
	•	issuer_pk = issuer public key
	•	subject_pk = subject public key
	•	allow.stream_ids = [ stream_id ]
	•	allow.ttl = ttl
	•	allow.rate = optional rate map
	•	sig_chain = signatures as per Ht(“veen/cap-link”, …)
	•	Write CBOR to cap.cbor.

7.2 Authorize with hub

Command:

veen cap authorize 
–hub http://host:port 
–cap cap.cbor

Behavior:
	•	POST cap_token to /authorize.
	•	On success, read {auth_ref, expires_at}.
	•	Display auth_ref as hex32.
	•	Optionally cache mapping cap.cbor -> auth_ref for later sends.

7.3 Use cap in send

Command:

veen send 
–hub http://host:port 
–client /path/to/client 
–cap cap.cbor 
–stream stream/name 
–body ‘{“k”:“v”}’

Behavior:
	•	Compute auth_ref from cap.cbor if not cached.
	•	Set MSG.auth_ref = auth_ref.
	•	All other behavior as in basic send.

	8.	Errors and limits

8.1 Display errors

Any command that calls the hub must:
	•	If HTTP success:
	•	parse CBOR(RECEIPT) and continue.
	•	If HTTP error:
	•	parse CBOR({code, detail?}) if present.
	•	print code and optional detail.
	•	exit non-zero.

8.2 Explain error codes

Command:

veen explain-error E.CODE

Behavior:
	•	Print a one-line description of:
	•	E.SIG
	•	E.SIZE
	•	E.SEQ
	•	E.CAP
	•	E.AUTH
	•	E.RATE
	•	E.PROFILE
	•	E.DUP
	•	E.TIME

	9.	Client state, resync, and durable storage (RESYNC0)

9.1 Local state layout

For each client directory, the CLI and client library must maintain:
	•	state.json:
	•	profile_id
	•	hub pins (optional)
	•	per-label:
	•	last_stream_seq
	•	last_mmr_root (hex32)
	•	prev_ack for send
	•	MMR peaks per label (separate file or encoded in state.json)
	•	rekey material rk per label or per profile

9.2 Resync stream

Command:

veen resync 
–hub http://host:port 
–client /path/to/client 
–stream stream/name

Behavior:
	•	Load local state snapshot for label.
	•	Query hub via stream?from=last_stream_seq+1 with with_proof=1.
	•	For each new element:
	•	verify RECEIPT, mmr_proof, and invariants
	•	update local MMR, last_stream_seq, last_mmr_root
	•	If any divergence is detected (roots mismatch or proofs fail):
	•	fetch checkpoint_latest for the label
	•	rebuild local peaks from CHECKPOINT
	•	replay receipts from appropriate earlier stream_seq
	•	Persist updated state atomically (state + peaks).

9.3 Verify state

Command:

veen verify-state 
–hub http://host:port 
–client /path/to/client 
–stream stream/name

Behavior:
	•	Fetch checkpoint_latest and stream summary from hub.
	•	Compare local last_stream_seq and last_mmr_root with hub.
	•	Report:
	•	consistent: yes/no
	•	mismatch at stream_seq k if discovered.

	10.	RPC overlay (RPC0)

10.1 RPC request

Command:

veen rpc call 
–hub http://host:port 
–client /path/to/client 
–stream rpc/main 
–method method_name 
–args ‘{“k”:“v”}’ 
[–timeout-ms 5000] 
[–idem 12345]

Behavior:
	•	Build payload_hdr.schema = H(“rpc.v1”).
	•	Body:
	•	method: text
	•	args: CBOR from JSON
	•	timeout_ms: if provided
	•	reply_to: optional bstr(32); default is implicit correlation via msg_id.
	•	idem: optional u64 if provided.
	•	Send as MSG on stream rpc/main.
	•	Wait for a reply MSG with:
	•	payload_hdr.schema = H(“rpc.res.v1”)
	•	parent_id = request.msg_id
	•	Decrypt reply and output:
	•	on ok=true: print result as JSON.
	•	on ok=false: print error.code and error.detail.

Timeout handling:
	•	If no reply by timeout-ms:
	•	exit non-zero with a timeout indication.
	•	RPC semantics remain idempotent due to idem key.

	11.	CRDT overlay (CRDT0)

11.1 LWW register

Commands:

veen crdt lww set 
–hub http://host:port 
–client /path/to/client 
–stream crdt/main 
–key key_name 
–value “value” 
[–ts 123]

veen crdt lww get 
–hub http://host:port 
–client /path/to/client 
–stream crdt/main 
–key key_name

Behavior:
	•	set:
	•	schema = H(“crdt.lww.v1”)
	•	body = {key: bytes, ts: u64 (supplied or from local clock), value: bytes}
	•	get:
	•	fetch all relevant CRDT messages up to last_stream_seq via stream
	•	fold them into CRDT state
	•	apply tie-breaking by (ts, stream_seq)
	•	print final value or “unset” if none.

11.2 OR-set

Commands:

veen crdt orset add 
–hub http://host:port 
–client /path/to/client 
–stream crdt/main 
–elem “value”

veen crdt orset remove 
–hub http://host:port 
–client /path/to/client 
–stream crdt/main 
–elem “value”

veen crdt orset list 
–hub http://host:port 
–client /path/to/client 
–stream crdt/main

Behavior:
	•	add:
	•	schema = H(“crdt.orset.v1”)
	•	body = {id: random 32 bytes, elem: bytes}
	•	remove:
	•	schema = H(“crdt.orset.v1”)
	•	body = {tomb: [ids for elem to be removed]}
	•	list:
	•	reconstruct add / remove history via receipts
	•	output the current set of elements.

11.3 G-counter

Commands:

veen crdt counter add 
–hub http://host:port 
–client /path/to/client 
–stream crdt/main 
–delta 5

veen crdt counter get 
–hub http://host:port 
–client /path/to/client 
–stream crdt/main

Behavior:
	•	add:
	•	schema = H(“crdt.gcnt.v1”)
	•	body = {shard: client_id, delta: u64}
	•	get:
	•	sum deltas across shards up to last_stream_seq
	•	print total as integer.

	12.	Anchoring (ANCHOR0)

12.1 Publish anchor (hub-side behavior, CLI as controller)

Command:

veen anchor publish 
–hub http://host:port 
–stream stream/name 
[–epoch E] 
[–ts T] 
[–nonce hex…]

Behavior:
	•	Ask hub (if supported) to publish mmr_root to its configured anchoring backend for the label.
	•	Receive anchor_ref and print it.

12.2 Verify anchor

Command:

veen anchor verify 
–checkpoint checkpoint.cbor

Behavior:
	•	Read checkpoint:
	•	mmr_root
	•	anchor_ref (if present)
	•	Query configured anchor backend to verify that anchor_ref binds to mmr_root.
	•	Exit 0 on success, non-zero on mismatch.

	13.	Observability (OBS0) and compliance (COMP0)

13.1 Health

Command:

veen hub health 
–hub http://host:port

Behavior:
	•	GET /healthz.
	•	Print JSON:
	•	ok: bool
	•	profile_id: hex32
	•	peaks_count: uint
	•	last_stream_seq: uint
	•	last_mmr_root: hex32

13.2 Metrics

Command:

veen hub metrics 
–hub http://host:port 
[–raw]

Behavior:
	•	GET /metrics.
	•	If –raw: print raw metrics text.
	•	Else: print summarized counters and histograms:
	•	submit_ok_total
	•	submit_err_total by code
	•	verify_latency_ms summary
	•	commit_latency_ms summary
	•	end_to_end_latency_ms summary

13.3 Retention inspection

Command:

veen retention show 
–data-dir /path/to/data

Behavior:
	•	Report configured retention for:
	•	receipts.cborseq
	•	payloads.cborseq
	•	checkpoints.cborseq
	•	Show current on-disk files and their rotation boundaries.

	14.	Security hardening (SH0)

14.1 Bounds-first confirmation

No separate user command is required; instead, CLI self tests (section 15) must include:
	•	sending oversized payloads
	•	malformed CBOR
	•	ensuring hub responds with E.SIZE before any heavy work

14.2 TLS introspection

Command:

veen hub tls-info 
–hub https://host:port

Behavior:
	•	Show TLS version and cipher suite in use.
	•	Confirm AEAD and no compression if possible.

	15.	Test suite (TS0)

15.1 Core tests

Command:

veen selftest core

Behavior:
	•	Start a temporary hub on random port with a fresh data-dir.
	•	Run:
	•	basic send/receive
	•	attachment round trip
	•	cap_token issue/authorize/use
	•	sequence errors
	•	profile mismatch
	•	time window errors
	•	duplicate detection
	•	RESYNC0 flows
	•	RPC0 basic calls
	•	CRDT0 basic operations
	•	ANCHOR0 dummy backend checks
	•	Kill hub and clean up data-dir.

15.2 Property and fuzz tests

Command:

veen selftest props

Behavior:
	•	Run:
	•	MMR associativity tests
	•	mmr_proof minimality checks
	•	duplicate rejection
	•	CBOR determinism for all wire types

Command:

veen selftest fuzz

Behavior:
	•	Generate malformed CBOR and truncated inputs for:
	•	MSG
	•	RECEIPT
	•	CHECKPOINT
	•	mmr_proof
	•	Verify hub returns E.SIZE or E.SIG as appropriate and does not crash.

15.3 Full test suite

Command:

veen selftest all

Behavior:
	•	Equivalent to:
	•	veen selftest core
	•	veen selftest props
	•	veen selftest fuzz
	•	Exit non-zero if any subtest fails.

	16.	Success criteria for VEEN CLI v0.0.1

The CLI is considered v0.0.1-complete when:
	1.	A hub can be started with a single veen hub start command on a fresh machine and handles all v0.0.1 endpoints.
	2.	A client identity can be created with a single veen keygen command with no additional tools.
	3.	From only the CLI and the running hub, a user can:
	•	send and receive end-to-end encrypted messages
	•	send and verify attachments
	•	issue and use capability tokens
	•	resynchronize and verify client state
	•	perform RPC0 calls
	•	operate CRDT0 objects (LWW, OR-set, G-counter)
	•	read health and metrics
	•	inspect and verify anchors
	4.	All invariants I1..I12 are enforced and can be observed via CLI-driven checks.
	5.	veen selftest all exits with status 0 in a clean environment.


## CLI-GOALS-2.txt

VEEN CLI v0.0.1+ Operational Goal Specification (Tightened)
Plain ASCII, English only. Additive to VEEN CLI v0.0.1. No wire changes.
	0.	Scope

This document extends the VEEN CLI v0.0.1 Operational Goal Specification for deployments that implement VEEN v0.0.1+ overlays:
	•	FED1: Federated hubs and authority records
	•	AUTH1: Label authority and single-primary discipline
	•	KEX1+: Strengthened key and capability lifecycle
	•	SH1+: Extended hardening and admission pipeline
	•	LCLASS0: Label classification overlay
	•	META0+: Schema registry and discovery overlay

All v0.0.1 core CLI goals remain mandatory. v0.0.1+ goals are additional, not replacements.
A CLI implementation that satisfies both documents is “VEEN CLI v0.0.1+-complete”.
	1.	Global CLI conventions for v0.0.1+

1.1 Global flags

Every v0.0.1+ command MUST accept:
	•	–json : emit machine-readable JSON to stdout only, no extra text
	•	–quiet : suppress informational text and progress, print errors only
	•	–timeout-ms N : upper bound on HTTP / RPC round-trip per hub interaction

If both –json and –quiet are provided, –json governs output formatting, and errors MUST be JSON objects with fields:
	•	ok: false
	•	code: string
	•	detail: string?

1.2 Exit codes

The following exit codes are reserved:
	•	0   : success; all required checks passed
	•	1   : CLI usage error (missing flags, invalid combinations)
	•	2   : network or transport failure (hub not reachable, TLS error)
	•	3   : protocol error (malformed hub response)
	•	4   : hub-level logical error (E.* from hub or policy violation)
	•	5   : selftest failure (at least one test case failed)

Commands MAY use additional non-zero codes for finer-grained scripting but MUST treat 0 vs non-zero as success vs failure.

1.3 Determinism

For all v0.0.1+ commands:
	•	Given the same:
	•	CLI version
	•	command line arguments
	•	environment variables
	•	local filesystem tree
	•	hub state
	•	The observable outputs (stdout, stderr, exit code) MUST be bitwise identical.

Randomness (for ids, nonces) is allowed only when explicitly specified; selftests MUST control randomness via fixed seeds or explicit parameters.
	2.	Hub profile and role introspection

2.1 Hub feature profile

Command:

veen hub profile
–hub http://host:port
[–json]

Requirements:
	•	Perform a single request to obtain a v0.0.1+ capability descriptor. Mechanism is implementation-defined (HTTP endpoint, RPC schema, or admin label), but MUST be documented.
	•	On success, emit:

Human-readable (default):

version: veen-0.0.1+
profile_id: HEX32
hub_id: HEX32
features:
core: true|false
fed1: true|false
auth1: true|false
kex1_plus: true|false
sh1_plus: true|false
lclass0: true|false
meta0_plus: true|false

JSON (–json):

{
“ok”: true,
“version”: “veen-0.0.1+”,
“profile_id”: “HEX32”,
“hub_id”: “HEX32”,
“features”: {
“core”: true,
“fed1”: true,
“auth1”: true,
“kex1_plus”: true,
“sh1_plus”: true,
“lclass0”: true,
“meta0_plus”: true
}
}

Errors:
	•	If hub does not support profile introspection: exit 4 with code “E.PROFILE” in JSON or text.

2.2 Hub role for realm/stream

Command:

veen hub role
–hub http://host:port
[–realm HEX32]
[–stream STREAM_NAME]
[–json]

Definitions:
	•	stream_id = deterministic mapping from STREAM_NAME to bstr(32); same mapping as used by veen send.
	•	realm_id:
	•	if –realm provided: parsed from HEX32
	•	else: hub default realm (implementation-defined but must be documented)

Behavior:
	•	With no –stream:
	•	Print a coarse hub role summary, such as:
	•	role: “standalone”
	•	or role: “federated-primary”, “federated-replica”, “observer”
	•	With –stream:
	•	Compute stream_id and associated label mapping (same as send).
	•	Ask hub for label_authority(label) under AUTH1.
	•	Emit:

Human-readable:

hub_id: HEX32
role: “standalone” | “federated-primary” | “federated-replica” | “observer”
realm_id: HEX32 or “unspecified”
stream_id: HEX32
label: HEX32
policy: single-primary|multi-primary|unspecified
primary_hub: HEX32 or “none”
local_is_primary: true|false

JSON:

{
“ok”: true,
“hub_id”: “HEX32”,
“role”: “observer”,
“stream”: {
  “realm_id”: “HEX32” or null,
  “stream_id”: “HEX32”,
  “label”: “HEX32”,
  “policy”: “single-primary|multi-primary|unspecified”,
  “primary_hub”: “HEX32” or null,
  “local_is_primary”: true|false
}
}

If –stream is omitted, JSON output includes only ok, hub_id, and role (no stream object).

Constraints:
	•	If AUTH1 is not enabled on the hub:
	•	Exit 4 with code “E.PROFILE” (text or JSON).
	•	CLI MUST NOT guess policy locally; it MUST use hub view or fail explicitly.

	3.	Federation and authority management (FED1, AUTH1)

3.1 Publish authority record

Command:

veen fed authority publish
–hub http://host:port
–realm HEX32
–stream STREAM_NAME
–primary-hub HUB_ID_HEX32
[–replica-hub HUB_ID_HEX32 …]
–policy single-primary|multi-primary
–ttl SECONDS
[–ts UNIX_TIME]
–admin /path/to/admin-client
[–json]

Preconditions:
	•	admin client directory exists and is a valid VEEN client identity.
	•	Admin client has a capability that authorizes writing veen.fed.authority.v1 to the admin stream for given realm.

Behavior:
	•	Compute:
	•	realm_id from –realm
	•	stream_id from STREAM_NAME mapping
	•	Build veen.fed.authority.v1 body:
{
realm_id: bstr(32),
stream_id: bstr(32),
primary_hub: bstr(32),
replica_hubs: [bstr(32)…],
policy: text,
ts: uint (UNIX_TIME or now),
ttl: uint
}
	•	Send as MSG using admin client on stream_fed_admin (derived from realm_id).
	•	Verify RECEIPT locally (hub_sig, invariants).
	•	Optionally refresh authority view (see 3.2).

Postconditions:
	•	On success, print the active record chosen by the hub (after tie-breaking).
	•	On failure due to capability or policy, propagate code (E.AUTH, E.CAP, etc).

3.2 Show authority record for realm/stream

Command:

veen fed authority show
–hub http://host:port
–realm HEX32
–stream STREAM_NAME
[–json]

Behavior:
	•	Compute realm_id and stream_id.
	•	Query hub for its authority_view[(realm_id, stream_id)] (folded from veen.fed.authority.v1 stream).
	•	Emit:

Human-readable:

realm_id: HEX32
stream_id: HEX32
primary_hub: HEX32 or “none”
replica_hubs: [HEX32,…] or []
policy: single-primary|multi-primary|unspecified
ts: uint
ttl: uint
expires_at: uint
active_now: true|false

JSON with the same fields.

Edge cases:
	•	If no record exists, CLI prints policy: “unspecified” and active_now: false and exits 0.
	•	In this case, primary_hub = “none” (null in JSON), replica_hubs = [], ts = 0, ttl = 0, and expires_at = 0 (null in JSON).

3.3 Label authority by label

Command:

veen label authority
–hub http://host:port
–label HEX32
[–json]

Behavior:
	•	Request label_authority(L) from hub for label = HEX32.
	•	Emit:
label: HEX32
realm_id: HEX32 or “unspecified”
stream_id: HEX32
policy: single-primary|multi-primary|unspecified
primary_hub: HEX32 or “none”
local_hub_id: HEX32
locally_authorized: true|false

JSON includes the same fields plus replica_hubs: [HEX32,…] (possibly empty).

Use case:
	•	Diagnose “not primary for label” rejections and misconfigured federation.

	4.	Key and capability lifecycle (KEX1+)

4.1 Hub key and capability policy

Command:

veen hub kex-policy
–hub http://host:port
[–json]

Behavior:
	•	Query KEX1+ policy summary:
max_client_id_lifetime_sec: uint
max_msgs_per_client_id_per_label: uint
default_cap_ttl_sec: uint
max_cap_ttl_sec: uint
revocation_stream: stream name or label description
rotation_window_sec: uint (for hub key rotation) or 0 if not used
	•	CLI MUST treat absence of values as “unspecified” and show them as null in JSON.

4.2 Client identity usage summary

Command:

veen id usage
–client /path/to/client
[–hub http://host:port]
[–json]

Behavior:
	•	Read local state for the client (per-label send metadata).
	•	Optionally, if –hub provided, fetch KEX1+ policy and apply thresholds.

Output per label:

label: HEX32
stream: logical name if known, else “-”
client_id: HEX32
created_at: uint or 0 if unknown
msgs_sent: uint
approx_lifetime_sec: uint or 0 if unknown
exceeds_msg_bound: true|false (if policy known)
exceeds_lifetime_bound: true|false (if policy known)
rotation_recommended: true|false

Exit behavior:
	•	Exit code 0 even if rotation is recommended; the command is informational only.

4.3 Capability validity and hub view

Command:

veen cap status
–hub http://host:port
–cap cap.cbor
[–json]

Behavior:
	•	Load cap_token from cap.cbor.
	•	Compute auth_ref = Ht(“veen/cap”, CBOR(cap_token)).
	•	Derive local validity window:
	•	issued_at:
	•	if explicit field inside cap_token: use it
	•	else: unknown
	•	ttl from cap_token.allow.ttl
	•	Query hub via an inspection RPC or admin endpoint:
request: auth_ref
response fields:
known: bool
currently_valid: bool
revoked: bool
expiry: uint? (hub view)
revocation_kind: “client-id”|“auth-ref”|“cap-token”|null
revocation_ts: uint?
reason: text?

Compose output:

Human:

auth_ref: HEX32
locally_within_ttl: true|false|“unknown”
hub_known: true|false
hub_currently_valid: true|false
revoked: true|false
revocation_kind: …
expires_at: uint or “unknown”
reason: text?

JSON includes all fields plus an “ok”: true flag.

4.4 Publish revocation record

Command:

veen cap revoke
–hub http://host:port
–admin /path/to/admin-client
–kind client-id|auth-ref|cap-token
–target HEX32
[–reason TEXT]
[–ttl SECONDS]
[–json]

Behavior:
	•	Build veen.revocation.v1:
{
kind: text,
target: bstr(32),
reason: text?,
ts: now,
ttl: uint?
}
	•	Send via admin client on stream_revocation.
	•	Verify RECEIPT and invariants.
	•	Print:
kind, target, ts, ttl, active_now: bool

4.5 List revocations

Command:

veen cap revocations
–hub http://host:port
[–kind client-id|auth-ref|cap-token]
[–since UNIX_TIME]
[–active-only]
[–limit N]
[–json]

Behavior:
	•	Read revocation stream up to configured limit (or N).
	•	Fold to current active window at local “now”.
	•	Filter by:
	•	kind (if provided)
	•	ts >= since (if provided)
	•	active_now (if –active-only)
	•	Emit a table or JSON list of:
kind, target, ts, ttl, active_now, reason

	5.	Admission pipeline inspection (SH1+)

5.1 Admission stages overview

Command:

veen hub admission
–hub http://host:port
[–json]

Behavior:
	•	Query hub admission configuration and runtime metrics.
	•	Emit per stage:
stage:
name: text (“stage0-prefilter” etc)
enabled: bool
responsibilities: [text]
queue_depth: uint
max_queue_depth: uint
recent_err_rates:
E.SIZE: float?
E.SIG: float?
E.AUTH: float?
E.CAP: float?
E.RATE: float?

JSON uses arrays and objects with the same fields.

5.2 Proof-of-work challenge and solver

Command:

veen pow request
–hub http://host:port
[–difficulty D]
[–json]

Behavior:
	•	Ask the hub (or PoW endpoint) for:
	•	challenge: bytes
	•	difficulty: uint8 (recommended difficulty)
	•	Emit:

Human:

challenge: HEX
difficulty: D

JSON:

{ “ok”: true, “challenge”: “HEX”, “difficulty”: D }

Command:

veen pow solve
–challenge HEX
–difficulty D
[–max-iterations N]
[–json]

Behavior:
	•	Iterate nonce from 0 upward (or within a bounded range if –max-iterations is supplied).
	•	For each nonce:
v = Ht(“veen/pow”, challenge || u64be(nonce))
Check that the first D bits of v are zero.
	•	On success:
	•	Print nonce (decimal and hex) and v (optional) in human mode.
	•	JSON:
{ “ok”: true, “nonce”: NONCE, “nonce_hex”: “HEX”, “hash_prefix_ok”: true }
	•	If no solution within bound: exit 4 with an error message.

5.3 Using PoW with send

All send-like commands (veen send, veen rpc call, etc.) MUST accept optional PoW parameters:
	•	–pow-challenge HEX
	•	–pow-nonce NONCE
	•	–pow-difficulty D

Transport binding of PoW cookie is deployment-specific. CLI MUST:
	•	Attach these parameters exactly as hub expects (e.g., header, RPC field, or side-channel).
	•	Not alter MSG encoding, RECEIPT handling, or VEEN invariants.

5.4 Admission-log sampling

Command:

veen hub admission-log
–hub http://host:port
[–limit N]
[–codes CODE1,CODE2,…]
[–json]

Behavior:
	•	Fetch a recent window of failed admission events via:
	•	a dedicated observability RPC, or
	•	a VEEN audit stream filtered by E.* codes.
	•	Display per event:
ts: uint
code: “E.*”
label_prefix: first 8 hex chars
client_id_prefix: first 8 hex chars
detail: short text

Use case: confirm that AUTH1, KEX1+, SH1+ policies are actually enforced and that failures are visible.
	6.	Label classification overlay (LCLASS0)

6.1 Set label classification

Command:

veen label-class set
–hub http://host:port
–label HEX32 | –stream STREAM
–class TEXT
[–sensitivity low|medium|high]
[–retention-hint SECONDS]
–signer /path/to/admin-client
[–json]

Behavior:
	•	Build veen.label.class.v1:
{
label: bstr(32),
class: text,
sensitivity: text?,
retention_hint: uint?
}
	•	Publish a signed label classification to the hub.
	•	Optionally re-query hub for effective classification and print it.

6.2 Show label classification

Command:

veen label-class show
–hub http://host:port
–label HEX32 | –stream STREAM
[–json]

Behavior:
	•	Query hub classification view for the label.
	•	Emit:
label: HEX32
class: TEXT or “unset”
sensitivity: TEXT or “none”
retention_hint: uint or 0
pad_block_effective: uint
retention_policy: TEXT
rate_policy: TEXT
	•	CLI MUST treat hub values as authoritative; no local heuristics.
	•	Default output is human-readable text; use “–json” for machine-readable descriptors.

6.3 List label classifications

Command:

veen label-class list
–hub http://host:port
[–class TEXT]
[–json]

Behavior:
	•	Query all known label classifications in the deployment.
	•	Filter by class if provided.
	•	Print a compact table or JSON array of:
label, class, sensitivity, retention_hint
	•	“–json” returns the descriptor entries as an array for automation.

	7.	Schema registry overlay (META0+)

7.1 Register schema descriptor

Command:

veen schema register
–hub http://host:port
–realm HEX32
–name TEXT
–version TEXT
[–doc-url TEXT]
[–owner HEX32]
[–schema-id HEX32]
–admin /path/to/admin-client
[–json]

Behavior:
	•	schema_id selection:
	•	if –schema-id provided: parse HEX32.
	•	else: schema_id = H(“veen/schema:” || name) or equivalent documented rule.
	•	Build veen.meta.schema.v1:
{
schema_id: bstr(32),
name: text,
version: text,
doc_url: text?,
owner: bstr(32)?,
ts: now
}
	•	Publish on stream_schema_meta via admin client.
	•	Verify RECEIPT.
	•	Emit the registered descriptor (including schema_id).

7.2 Show schema descriptor

Command:

veen schema show
–hub http://host:port
–schema-id HEX32
[–json]

Behavior:
	•	Lookup schema_id in hub registry.
	•	Emit:
schema_id: HEX32
name: TEXT
version: TEXT
doc_url: TEXT or “none”
owner: HEX32 or “none”
ts: uint
used_labels: [HEX32,…]?   (optional summary)
used_count: uint?           (approximate)

If schema_id is unknown, exit 4 with code “E.SEQ” or “E.PROFILE”.

7.3 List schemas

Command:

veen schema list
–hub http://host:port
[–realm HEX32]
[–name-prefix TEXT]
[–owner HEX32]
[–json]

Behavior:
	•	List schema descriptors matching filters.
	•	Provide at least:
schema_id, name, version, owner, ts

7.4 Schema usage inspection (optional but recommended)

Command:

veen schema usage
–hub http://host:port
–schema-id HEX32
[–stream STREAM_NAME]
[–since UNIX_TIME]
[–limit N]
[–json]

Behavior:
	•	Optionally implemented to scan recent messages and show where a schema is used (labels, counts).
	•	Pure overlay; no wire changes.

	8.	Extended self tests for v0.0.1+

8.1 Federated behavior (FED1, AUTH1)

Command:

veen selftest federated
[–json]

Behavior:
	•	Start two temporary hubs (hubA, hubB) with shared realm and distinct hub_ids.
	•	Run the following deterministic sequence:
	•	Publish authority record pointing primary_hub = hubA for test stream S.
	•	Confirm via:
	•	veen fed authority show
	•	veen hub role –stream S
	•	Using a client:
	•	Send MSG for S to hubA: MUST succeed.
	•	Send MSG for S to hubB: MUST fail with E.AUTH or E.CAP.
	•	Switch primary_hub to hubB in a new authority record (higher ts).
	•	Confirm authority view flips.
	•	Repeat send tests with reversed roles.
	•	If any check fails, exit 5 and report failing step.

8.2 Lifecycle and revocation (KEX1+)

Command:

veen selftest kex1
[–json]

Behavior:
	•	Start a hub with KEX1+ enabled and tight bounds for test (e.g. max_msgs_per_client_id_per_label = 3).
	•	Generate a client and capability.
	•	Test:
	•	Send up to the bound: all succeed.
	•	One additional send: hub MUST reject with E.CAP/E.AUTH; CLI verifies.
	•	Issue a short-ttl capability; after expiry, confirm rejection.
	•	Publish revocations for:
	•	client-id
	•	auth-ref
	•	Confirm that subsequent sends with revoked identity or capability fail.
	•	Collect all steps in a JSON summary when –json is provided.

8.3 Hardening behavior (SH1+)

Command:

veen selftest hardened
[–json]

Behavior:
	•	Against a hub with SH1+ enabled:
	•	Send oversized MSG:
	•	Ensure E.SIZE is returned; hub remains responsive.
	•	Send malformed CBOR:
	•	Ensure E.SIZE or equivalent structural error, no crash.
	•	If PoW is configured:
	•	Call veen pow request, then veen pow solve for a small difficulty.
	•	Send a batch of MSG with valid PoW: majority MUST succeed.
	•	Send similar batch without PoW: hub SHOULD throttle or reject with policy-specific errors.
	•	Selftest reports whether bounds-first behavior holds (size check before Ed25519/HPKE).

8.4 Label and schema overlays (LCLASS0, META0+)

Command:

veen selftest meta
[–json]

Behavior:
	•	Start ephemeral hub with all meta overlays enabled.
	•	For a test label:
	•	Use veen label-class set to define a class and retention hint.
	•	Confirm via label-class show and hub metrics that the policy is recognized.
	•	For a test schema:
	•	Use veen schema register to register “test.operation.v1”.
	•	Send a MSG with payload_hdr.schema equal to that id.
	•	Confirm via schema show and schema list that the schema appears and has non-zero usage.

8.5 Aggregated v0.0.1+ test suite

Command:

veen selftest plus
[–json]

Behavior:
	•	Equivalent to:
	•	veen selftest core
	•	veen selftest props
	•	veen selftest fuzz
	•	veen selftest federated
	•	veen selftest kex1
	•	veen selftest hardened
	•	veen selftest meta
	•	Exit 0 only if all subtests succeed.

	9.	v0.0.1+ completeness criteria

The VEEN CLI is v0.0.1+-complete if and only if:
	1.	All VEEN CLI v0.0.1 success criteria are met.
	2.	Every command specified in this document is implemented with:
	•	deterministic behavior
	•	correct use of VEEN wire types
	•	no modification of MSG, RECEIPT, CHECKPOINT, mmr_proof, or cap_token encodings
	3.	A hub’s v0.0.1+ behavior (FED1, AUTH1, KEX1+, SH1+, LCLASS0, META0+) can be:
	•	configured and inspected using CLI only, and
	•	validated end-to-end via veen selftest plus.
	4.	For any label in a federated deployment:
	•	Its authority, classification, schemas, and lifecycle policies can be recovered and inspected using only VEEN logs and CLI tooling, without any external state.


## CLI-GOALS-3.txt

VEEN CLI v0.0.1++ Operational Goal Specification (Tightened)
Plain ASCII, English only. Additive to VEEN CLI v0.0.1 and v0.0.1+. No wire changes.
	0.	Scope and invariants

0.1 Purpose

This document refines the operational goals for the VEEN CLI when:
	•	Hubs are deployed as disposable, Kubernetes-native workloads.
	•	Extended operation profiles on top of VEEN v0.0.1 Core are in use:
	•	Paid Operation
	•	Access Grant / Revoke
	•	Delegated Execution
	•	Multi Party Agreement
	•	Data Publication
	•	State Snapshot
	•	Recovery Procedure
	•	Query Audit Log
	•	Federation Synchronization

0.2 Non-goals
	•	No change to VEEN wire objects: MSG, RECEIPT, CHECKPOINT, mmr_proof, cap_token.
	•	No new fields on the wire; all additions are in CLI behavior, Kubernetes manifests, and payload bodies.

0.3 Determinism and reproducibility

The CLI MUST satisfy:
	•	Given the same inputs (flags, files, environment variables, cluster state) it produces:
	•	identical manifests for kube render,
	•	identical payloads for op commands,
	•	identical JSON outputs for inspection commands (ignoring ordering in purely diagnostic text).
	•	All destructive operations (delete, purge, restore) MUST require an explicit flag and MUST be idempotent:
	•	a second invocation on an already-deleted resource MUST exit with success and a clear note.

0.4 Compliance levels

The CLI MAY expose a self-reported level:
	•	“veen-cli v0.0.1”
	•	“veen-cli v0.0.1+”
	•	“veen-cli v0.0.1++”

A v0.0.1++ implementation MUST satisfy all v0.0.1 and v0.0.1+ requirements plus every MUST and required command in this document.
	1.	CLI surface overview

1.1 Top-level command groups

The v0.0.1++ CLI binary “veen” MUST expose at least these groups:
	•	hub        (existing)
	•	keygen     (existing)
	•	id         (existing)
	•	send       (existing)
	•	stream     (existing)
	•	cap        (existing)
	•	resync     (existing)
	•	crdt       (existing)
	•	rpc        (existing)
	•	anchor     (existing)
	•	selftest   (existing)

New for v0.0.1++:
	•	kube       Kubernetes integration
	•	env        environments, tenants, realms
	•	op         extended operation profiles
	•	wallet     folding of Paid Operation into ledgers
	•	agreement  folding of agreements
	•	snapshot   state snapshots
	•	recovery   account and identity recovery views
	•	audit      query audits and policy checks
	•	federate   federation and mirroring helpers

1.2 Global conventions
	•	All commands accept “–help” and print a short, single-screen usage description.
	•	All commands accept “–json” when they produce structured output; “–json” MUST result in valid JSON printed to stdout with no extra text.
	•	Non-zero exit codes MUST be used for:
	•	input validation errors,
	•	hub errors (E.*),
	•	Kubernetes API errors,
	•	policy violations in verify and audit commands.

	2.	Kubernetes-native deployment (kube)

2.1 Naming and labels

The CLI MUST define a deterministic naming scheme:
	•	Deployment/StatefulSet name: “veen-hub-NAME”
	•	Service name: “veen-hub-NAME”
	•	ConfigMap name: “veen-hub-NAME-config”
	•	Secret name for hub private keys: “veen-hub-NAME-keys” (unless overridden)
	•	Label “app=veen-hub” and “veen.hub.name=NAME” applied to all hub pods.

These names MUST be derived solely from:
	•	“–namespace”
	•	“–name”

and MUST be stable across invocations.

2.2 kube render

Command:

veen kube render
–cluster-context CONTEXT
–namespace NAMESPACE
–name NAME
–image IMAGE
–data-pvc PVC_NAME
[–replicas N]
[–resources-cpu REQUEST,LIMIT]
[–resources-mem REQUEST,LIMIT]
[–profile-id HEX32]
[–config /path/to/hub-config.toml]
[–env-file /path/to/env]
[–pod-annotations /path/to/annotations.json]
[–json]

Behavior:
	•	Does not contact the cluster.
	•	Reads local files (config, env, annotations) if given.
	•	Produces a fixed ordered list of objects:
	•	Namespace (if not suppressed)
	•	ServiceAccount
	•	Role
	•	RoleBinding
	•	ConfigMap(s)
	•	Secret template (without private keys)
	•	Deployment or StatefulSet
	•	Service

Constraints:
	•	resource requests and limits:
	•	“–resources-cpu” is “request,limit”, for example “500m,1”.
	•	“–resources-mem” is “request,limit”, for example “512Mi,1Gi”.
	•	Missing limit means “request,request”.
	•	The container command MUST be equivalent to:
veen hub start 
–listen 0.0.0.0:8080 
–data-dir /var/lib/veen 
–config /etc/veen/hub-config.toml 
–profile-id HEX32_FROM_CONFIG_OR_FLAG
	•	Readiness and liveness:
	•	Readiness probe: HTTP GET /healthz on port 8080, success on “ok: true”.
	•	Liveness probe: HTTP GET /healthz with a higher failure threshold.
	•	These probe definitions MUST be present in rendered pods.
	•	Security:
	•	runAsNonRoot: true
	•	readOnlyRootFilesystem: true
	•	allowPrivilegeEscalation: false

If “–json” is provided, the CLI MUST output a JSON array of objects with “apiVersion”, “kind”, “metadata”, “spec”.

2.3 kube apply

Command:

veen kube apply
–cluster-context CONTEXT
–file MANIFESTS.(yaml|json)
[–wait-seconds T]

Behavior:
	•	Apply given manifests to the target cluster and namespace using Kubernetes API.
	•	If “–wait-seconds T” is set:
	•	Poll pod conditions of “veen-hub-NAME” until:
	•	ready replicas equal desired replicas, or
	•	timeout T seconds.
	•	On success, print:
	•	effective namespace
	•	hub service DNS name:
	•	“veen-hub-NAME.NAMESPACE.svc.cluster.local:8080”

If the manifests refer to a namespace that does not exist, the CLI MUST create it or report a clear error, depending on presence of Namespace objects in the file.

2.4 kube delete

Command:

veen kube delete
–cluster-context CONTEXT
–namespace NAMESPACE
–name NAME
[–purge-pvcs]

Behavior:
	•	Delete Deployment/StatefulSet and Service for “veen-hub-NAME”.
	•	Always delete Role and RoleBinding owned by that hub.
	•	If “–purge-pvcs” is set, also delete PVC “PVC_NAME” from kube render.
	•	If resources are already gone, exit 0 and print “already deleted”.

2.5 kube status

Command:

veen kube status
–cluster-context CONTEXT
–namespace NAMESPACE
–name NAME
[–json]

Behavior:
	•	Read Kubernetes Deployment/StatefulSet status.
	•	If hub pods are reachable, query each pod “/healthz”.
	•	Output at least:
	•	deployment_name
	•	namespace
	•	desired_replicas
	•	ready_replicas
	•	pod list with name, phase, restarts
	•	health per pod: “ok” or last error

With “–json”, output a JSON object; field names MUST be stable.

2.6 kube logs

Command:

veen kube logs
–cluster-context CONTEXT
–namespace NAMESPACE
–name NAME
[–pod POD]
[–follow]
[–since DURATION]

Behavior:
	•	If “–pod” omitted:
	•	pick all pods with label “veen.hub.name=NAME” and stream logs of each sequentially.
	•	“–since” is a duration like “1h”, “10m”, default “1h”.
	•	“–follow” keeps the connection open and continues streaming until user interrupts.

The CLI MUST pass logs from Kubernetes unchanged (no reformatting).

2.7 kube backup and restore

Command:

veen kube backup
–cluster-context CONTEXT
–namespace NAMESPACE
–name NAME
–snapshot-name SNAPNAME
–target-uri URI

Behavior:
	•	Contact hub via Service HTTP endpoint.
	•	Invoke hub backup RPC /admin/backup (deployment specific but CLI spec assumes existence).
	•	Backup metadata MUST include:
	•	hub profile_id
	•	last_stream_seq per label
	•	last_mmr_root per label
	•	timestamps
	•	Backup payload MUST be stored at URI; URI is implementation-specific but has to be a single string.

Command:

veen kube restore
–cluster-context CONTEXT
–namespace NAMESPACE
–name NAME
–snapshot-name SNAPNAME
–source-uri URI

Behavior:
	•	Ensure hub is not running or scaled to zero.
	•	Recreate data-dir from snapshot.
	•	Restart hub.
	•	After restart, CLI MUST call “veen hub status –hub SERVICE_URL” and verify restored last_stream_seq and mmr_root against snapshot metadata; mismatch MUST cause non-zero exit.

	3.	Disposable jobs as clients (kube job)

3.1 General job structure

All “veen kube job” commands MUST:
	•	Create a Kubernetes Job with:
	•	single container running the same veen binary
	•	environment variables taken from:
	•	“–env-file”
	•	Secrets config (for keys and caps)
	•	a volume for client state (either emptyDir or PVC if specified)
	•	The Job container MUST exit as soon as the requested CLI command terminates.

3.2 kube job send

Command:

veen kube job send
–cluster-context CONTEXT
–namespace NAMESPACE
–hub-service HUB_SERVICE_DNS
–client-secret SECRET_NAME
–stream STREAM_NAME
–body ‘{“k”:“v”}’
[–cap-secret CAP_SECRET_NAME]
[–profile-id HEX32]
[–timeout-ms N]
[–image IMAGE]

Behavior:
	•	Construct Job name “veen-job-send-”.
	•	Mount SECRET_NAME into the pod at “/var/lib/veen-client”:
	•	keystore.enc
	•	identity_card.pub
	•	state.json if present
	•	If CAP_SECRET_NAME is given, mount capability token CBOR at a fixed path.
	•	Container command MUST be equivalent to:
veen send 
–hub http://HUB_SERVICE_DNS 
–client /var/lib/veen-client 
–stream STREAM_NAME 
–body ‘{“k”:“v”}’ 
[–cap /var/lib/veen-cap/cap.cbor] 
[–profile-id HEX32] 
[–timeout-ms N]
	•	CLI waits for Job completion. Job status:
	•	success: print RECEIPT summary (stream_seq, msg_id).
	•	failure: print CLI stderr from the Job.

The mapping from Job completion to CLI exit code MUST be:
	•	Job succeeded: CLI exit 0.
	•	Job failed: CLI exit non-zero.

3.3 kube job stream

Command:

veen kube job stream
–cluster-context CONTEXT
–namespace NAMESPACE
–hub-service HUB_SERVICE_DNS
–client-secret SECRET_NAME
–stream STREAM_NAME
[–from N]
[–with-proof]
[–image IMAGE]

Behavior:
	•	Similar structure to kube job send but invokes “veen stream”.
	•	Job prints decrypted messages to stdout.

	4.	Environments, tenants, and realms (env)

4.1 Environment descriptor format

Command:

veen env init
–root ROOT_DIR
–name ENV_NAME
–cluster-context CONTEXT
–namespace NAMESPACE
[–description TEXT]

Behavior:
	•	Create directory ROOT_DIR if missing.
	•	Write file ROOT_DIR/ENV_NAME.env.json with JSON schema:
{
“version”: 1,
“name”: “ENV_NAME”,
“cluster_context”: “CONTEXT”,
“namespace”: “NAMESPACE”,
“description”: “TEXT or empty”,
“hubs”: {},
“tenants”: {}
}

4.2 Env add-hub

Command:

veen env add-hub
–env ROOT_DIR/ENV_NAME.env.json
–hub-name NAME
–service-url URL
–profile-id HEX32
[–realm HEX32]

Behavior:
	•	Load env JSON.
	•	Insert or update:
env[“hubs”][NAME] = {
“service_url”: URL,
“profile_id”: HEX32,
“realm_id”: HEX32 or null
}
	•	Save back to file atomically.

4.3 Env add-tenant

Command:

veen env add-tenant
–env ROOT_DIR/ENV_NAME.env.json
–tenant-id TENANT_ID
–stream-prefix PREFIX
[–label-class user|wallet|log|admin|bulk]

Behavior:
	•	Insert or update:
env[“tenants”][TENANT_ID] = {
“stream_prefix”: PREFIX,
“label_class”: CLASS if provided else “user”
}

4.4 Env show

Command:

veen env show
–env ROOT_DIR/ENV_NAME.env.json
[–json]

Behavior:
	•	Without “–json”:
	•	print a human-readable summary of hubs and tenants.
	•	With “–json”:
	•	reprint the env JSON verbatim.

Other commands MAY accept:
	•	“–env PATH” and “–hub-name NAME” instead of “–hub URL”.
	•	In that case, the CLI MUST resolve the hub URL and profile_id from the env descriptor.

	5.	Operation profile authoring (op)

5.1 Schema resolution

The CLI MUST support named schemas:
	•	paid.operation.v1
	•	access.grant.v1
	•	access.revoke.v1
	•	delegated.execution.v1
	•	agreement.definition.v1
	•	agreement.confirmation.v1
	•	data.publication.v1
	•	state.checkpoint.v1
	•	recovery.request.v1
	•	recovery.approval.v1
	•	recovery.execution.v1
	•	query.audit.v1
	•	federation.mirror.v1

Mapping:
	•	schema_id = SHA-256(“veen/schema:” || ascii_name)
	•	ascii_name is exactly the name above.

The CLI MUST compute this mapping deterministically and MAY also consult a schema registry (META0+) when present.

5.2 op send generic

Command:

veen op send
–hub URL
–client CLIENT_DIR
–stream STREAM_NAME
–schema-name SCHEMA_NAME
–body-json JSON_STRING
[–cap CAP_FILE]
[–expires-at UNIX_TIME]
[–parent-id HEX32]
[–json]

Behavior:
	•	Compute schema_id from SCHEMA_NAME.
	•	Parse JSON_STRING into a CBOR body.
	•	Perform minimal validation:
	•	All fields required by the schema MUST be present and of correct basic type (text, uint, bstr, array).
	•	Call “veen send” internally with:
	•	payload_hdr.schema = schema_id
	•	body = CBOR(body)

With “–json”, output:

{
“stream_seq”: N,
“msg_id”: “HEX32”,
“operation_id”: “HEX32”,
“schema_name”: “SCHEMA_NAME”
}

5.3 op paid

Command:

veen op paid
–hub URL
–client CLIENT_DIR
–stream STREAM_NAME
–op-type OP_TYPE
–payer HEX32
–payee HEX32
–amount UINT
–currency-code TEXT
[–op-args-json JSON]
[–ttl-seconds UINT]
[–op-ref HEX32]
[–parent-op HEX32]
[–cap CAP_FILE]
[–json]

Behavior:
	•	Build body:
{
“operation_type”: OP_TYPE,
“operation_args”: JSON or null,
“payer_account”: payer bstr,
“payee_account”: payee bstr,
“amount”: amount,
“currency_code”: TEXT,
“operation_reference”: op-ref or null,
“parent_operation_id”: parent-op or null,
“ttl_seconds”: ttl or null,
“metadata”: null
}
	•	Use payload_hdr.schema = schema_id for paid.operation.v1.
	•	Use “veen send” under the hood.
	•	Print RECEIPT and “operation_id = Ht(“veen/operation-id”, msg_id)” as HEX32.

5.4 op access-grant and op access-revoke

Commands:

veen op access-grant
–hub URL
–admin ADMIN_CLIENT_DIR
–subject-identity HEX32
–stream STREAM_NAME
–expiry-time UNIX_TIME
[–allowed-stream STREAM_ID_HEX] (repeatable)
[–max-rate-per-second UINT]
[–max-burst UINT]
[–max-amount UINT]
[–currency-code TEXT]
[–reason TEXT]

Behavior:
	•	If “–allowed-stream” is absent:
	•	default to stream_id derived from STREAM_NAME.
	•	Construct access.grant.v1 payload with given fields.

veen op access-revoke
–hub URL
–admin ADMIN_CLIENT_DIR
–subject-identity HEX32
[–target-cap-ref HEX32]
[–reason TEXT]

Behavior:
	•	Construct access.revoke.v1 payload.

5.5 op delegated

Command:

veen op delegated
–hub URL
–client CLIENT_DIR
–stream STREAM_NAME
–principal HEX32
–agent HEX32
–delegation-cap HEX32,…
–operation-schema-id HEX32
–operation-body-json JSON
[–parent-op HEX32]

Behavior:
	•	Parse delegation-cap as array of bstr(32).
	•	Parse operation-body-json into CBOR.
	•	Construct delegated.execution.v1 payload with fields:
	•	principal_identity
	•	agent_identity
	•	delegation_chain
	•	operation_schema
	•	operation_body
	•	parent_operation_id (optional)
	•	metadata null

	6.	Folding and state views

6.1 wallet ledger

Command:

veen wallet ledger
–hub URL
–stream STREAM_NAME
[–upto-stream-seq N]
[–since-stream-seq M]
[–account HEX32]
[–json]

Folding rules:
	•	Scan messages on STREAM_NAME between M (default 1) and N (default current tip).
	•	Filter paid.operation.v1 payloads.
	•	For each payload:
	•	debit payer_account by amount
	•	credit payee_account by amount
	•	Maintain a map account_id -> signed integer balance.

Output:
	•	If “–account” given:
	•	single balance for that account.
	•	Else:
	•	list of accounts and balances.

With “–json”, output:

{
“stream”: “…”,
“from”: M,
“upto”: N,
“balances”: {
“HEX32_ACCOUNT_1”: BAL1,
“HEX32_ACCOUNT_2”: BAL2
}
}

6.2 agreement status

Command:

veen agreement status
–hub URL
–stream STREAM_NAME
–agreement-id HEX32
[–version UINT]
[–json]

Folding rules:
	•	Extract agreement.definition.v1 and agreement.confirmation.v1 messages.
	•	Track:
	•	definition by (agreement_id, version)
	•	confirmations by (agreement_id, version, party_identity)

For each party, use last confirmation in stream order.

Output:
	•	active: boolean (all parties accepted, not expired, effective_time passed)
	•	parties: list with identity, last decision, decision time.

6.3 snapshot verify

Command:

veen snapshot verify
–hub URL
–stream STREAM_NAME
–state-id HEX32
–upto-stream-seq N
–state-class CLASS_NAME
[–json]

Behavior:
	•	Find state.checkpoint.v1 for (state_id, upto_stream_seq).
	•	Replay operations on STREAM_NAME that affect state_id up to N.
	•	Folding is defined per CLASS_NAME and MUST be deterministic.
	•	Compare computed state_hash to checkpoint.state_hash.
	•	Compare checkpoint.mmr_root to hub CHECKPOINT mmr_root at upto_seq.

Output:
	•	consistent: true or false
	•	if false, indicate first mismatch.

6.4 recovery timeline

Command:

veen recovery timeline
–hub URL
–stream STREAM_NAME
–target-identity HEX32
[–json]

Behavior:
	•	Extract recovery.request.v1, recovery.approval.v1, recovery.execution.v1 for target_identity.
	•	Show chronological list with:
	•	type: request / approval / execution
	•	msg_id
	•	requested_new_identity / new_identity
	•	approver_identity
	•	decision
	•	stream_seq

	7.	Federation synchronization (federate)

7.1 mirror-plan

Command:

veen federate mirror-plan
–source-hub URL_SRC
–target-hub URL_DST
–stream STREAM_NAME
[–label-map-file LABEL_MAP_JSON]
[–json]

Behavior:
	•	Fetch basic stream metadata from source and target:
	•	current last_stream_seq
	•	last_mmr_root
	•	Determine target label:
	•	if label-map-file provided, use mapping.
	•	else, default to same STREAM_NAME mapping.

Output:
	•	Plan object describing:
	•	source stream
	•	target stream
	•	start and end sequence numbers (initially 1 to src_last_stream_seq)
	•	approximate message count and size.

7.2 mirror-run

Command:

veen federate mirror-run
–source-hub URL_SRC
–target-hub URL_DST
–stream STREAM_NAME
[–from-stream-seq M]
[–to-stream-seq N]
[–json]

Behavior:
	•	Subscribe to “stream” on source hub for given range with with_proof=1.
	•	For each (RECEIPT, MSG, mmr_proof):
	•	verify proof and invariants.
	•	send a federation.mirror.v1 operation to target-hub under a configured mirror stream.
	•	Report:
	•	mirrored_count
	•	first_stream_seq
	•	last_stream_seq
	•	number of verification failures.

	8.	Audit and compliance (audit)

8.1 audit queries

Command:

veen audit queries
–hub URL
–stream STREAM_NAME
[–resource-prefix TEXT]
[–since UNIX_TIME]
[–json]

Behavior:
	•	Filter query.audit.v1 messages by resource_identifier prefix and time.
	•	Output rows:
	•	requester_identity
	•	resource_identifier
	•	resource_class
	•	purpose_code
	•	request_time

8.2 audit summary

Command:

veen audit summary
–hub URL
[–env ENV_FILE]
[–json]

Behavior:
	•	Optionally use ENV_FILE for known streams and tenants.
	•	For each labeled stream:
	•	list schemas seen (using META0+ or static names).
	•	list whether query.audit.v1 is present for streams labeled as “sensitive”.
	•	list presence of access.grant / access.revoke for authorization surfaces.

8.3 audit enforce-check

Command:

veen audit enforce-check
–hub URL
–policy-file POLICY_JSON
[–json]

Policy file minimal schema:

{
“version”: 1,
“rules”: [
{
“type”: “require_audit”,
“stream”: “STREAM_NAME”,
“resource_class”: “personal-data”
},
{
“type”: “require_recovery_threshold”,
“target_identity_prefix”: “HEX”,
“min_approvals”: 2
}
]
}

Behavior:
	•	Interpret simple rules:
	•	require_audit:
	•	if query.audit.v1 never appears for that stream and resource_class, report violation.
	•	require_recovery_threshold:
	•	if any recovery.execution.v1 is executed with fewer approvals than min_approvals, report violation.

Output:
	•	violations: list of strings or structured descriptions.
	•	exit non-zero if any violations found.

	9.	End-to-end scenarios

9.1 Wallet-backed paid operation from zero

A v0.0.1++ CLI MUST support the following minimal sequence, with no manual editing of manifests:
	1.	Initialize environment:
	•	veen env init
	•	veen env add-hub (after deployment)
	2.	Deploy hub:
	•	veen kube render | veen kube apply
	3.	Generate admin and user identities:
	•	veen keygen –out admin
	•	veen keygen –out user
	4.	Grant access:
	•	veen op access-grant –admin admin … –subject-identity USER_PUB
	5.	Perform paid operation:
	•	veen op paid –client user …
	6.	Inspect ledger:
	•	veen wallet ledger

Each step MUST have a bounded number of flags and not require any additional tools beyond “veen” and Kubernetes access.

9.2 Recovery and rekey

From only:
	•	hub logs and data-dir snapshot,
	•	an environment descriptor,
	•	and a backup of recovery guardians’ keys,

operator MUST be able to:
	•	reconstruct identity and ledger state:
	•	veen snapshot verify
	•	veen wallet ledger
	•	execute a recovery:
	•	veen op recovery-request
	•	veen op recovery-approval (multiple guardians)
	•	veen op recovery-execution
	•	confirm that new identity is applied:
	•	veen recovery timeline
	•	veen wallet ledger for new identity

	10.	v0.0.1++ completeness

The CLI is v0.0.1++-complete if:
	1.	It passes all v0.0.1 and v0.0.1+ selftests.
	2.	It can deploy a VEEN hub on Kubernetes and perform an end-to-end paid operation and ledger inspection using only CLI commands described here.
	3.	It can mirror a stream between two hubs and verify mirrored receipts and proofs.
	4.	It can reconstruct wallet, agreement, snapshot, and recovery state from VEEN logs using folding commands in this spec.
	5.	An automated “veen selftest plus-plus” (name implementation-defined) can:
	•	start temporary hubs on Kubernetes or locally,
	•	exercise kube, op, wallet, agreement, snapshot, recovery, audit, federate flows,
	•	and exit 0 when all invariants hold.


## OS-GOALS.txt

VEEN v0.0.1 OS-GOALS
Host Operating System Operational Goal Specification (Tightened)
Plain ASCII, English only. No overlays beyond v0.0.1 (OP0, KEX0, RESYNC0, RPC0, CRDT0, ANCHOR0, OBS0, COMP0, SH0, DR0, TS0).
	0.	Purpose and scope

OS-GOALS defines what must hold at the host operating system level for VEEN v0.0.1 to be considered operationally complete on a Unix-like platform, with Ubuntu 22.04 and 24.04 (including WSL2) as the reference environment.

It constrains:
	•	how VEEN is built and installed on the OS
	•	how processes are started, stopped, and supervised
	•	how persistent data and logs are placed on disk
	•	how CLI, hub, bridge, and selftest binaries interact with the OS
	•	how a clean system can be driven from “no VEEN” to “fully functioning VEEN deployment” using only documented commands

If every numbered requirement in this document is satisfied on the reference OS, VEEN v0.0.1 meets OS-GOALS.
	1.	Target operating systems

OS1.1 Reference distributions

VEEN MUST fully support:
	•	Ubuntu 22.04 LTS amd64 (native, systemd managed)
	•	Ubuntu 24.04 LTS amd64 (native, systemd managed)
	•	WSL2 Ubuntu 22.04 / 24.04 under Windows 10 or 11 (systemd may be absent or disabled)

OS1.2 Single source tree

The same git repository and Cargo workspace MUST:
	•	build on all reference distributions without source modifications
	•	not depend on OS-specific feature flags for protocol correctness
	•	only use OS-specific conditional compilation for optional integrations (for example, systemd units, TLS key paths)

	2.	Dependency model

OS2.1 Minimal system packages

On a clean reference system, the following sequence MUST be sufficient to install all system-level dependencies required to build and run VEEN:
	•	sudo apt update
	•	sudo apt install -y build-essential pkg-config libssl-dev curl ca-certificates

No additional mandatory system libraries beyond the standard OpenSSL, pthreads, and libc are allowed for core functionality.

OS2.2 Rust toolchain

VEEN MUST build and run on stable Rust, installed as:
	•	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	•	source "$HOME/.cargo/env"

The minimum Rust version MUST be documented in the repository (for example, in a rust-toolchain.toml or README) and MUST be a stable channel release.

OS2.3 No external services

VEEN core tests and selftest MUST NOT require:
	•	external databases
	•	external message brokers
	•	external key management services

Loopback HTTP ports and the local filesystem are the only mandatory external resources.
	3.	Source layout and build

OS3.1 Repository layout

The repository root MUST contain:
	•	a Cargo workspace with member crates including:
	•	veen-core
	•	veen-hub
	•	veen-bridge
	•	veen-cli
	•	veen-selftest
	•	documentation for build and runtime expectations in a text file (for example, README)

OS3.2 Build command

From the repository root:
	•	cargo build --release

MUST:
	•	complete with exit status 0 on all reference OS variants
	•	produce at least:
	•	target/release/veen (single CLI/hub binary) or
	•	documented binaries where one binary is the canonical CLI front-end and one is the hub
	•	not require environment variables beyond those documented (for example, no hidden dependency on PATH hacks)

OS3.3 Test command

From the repository root:
	•	cargo test --all

MUST:
	•	complete with exit status 0 on all reference OS variants
	•	run unit tests for all core protocol components
	•	not hang indefinitely or require manual interaction

	4.	Installation pattern on native Ubuntu

OS4.1 Standard install prefix

VEEN MUST support installation into a conventional Unix layout:
	•	binaries under /usr/local/bin or /usr/bin
	•	configuration under /etc/veen
	•	persistent data under /var/lib/veen
	•	logs under /var/log/veen (if not journald-only)

The repository MUST document:
	•	a simple manual install path using cp or install
	•	an optional package manager recipe (for example, deb build) may be provided but is not mandatory for OS-GOALS

OS4.2 Binary deployment

A minimal manual install sequence MUST be sufficient:
	•	sudo cp target/release/veen /usr/local/bin/veen
	•	sudo chmod 0755 /usr/local/bin/veen
	•	veen --help returns usage information and exit code 0

OS4.3 Configuration files

If configuration files are required for the hub, they MUST:
	•	reside under /etc/veen (for example, /etc/veen/veen.toml)
	•	be optional with sane defaults when absent
	•	have a documented example configuration

	5.	Runtime processes and supervision

5.1 Process roles

The OS MUST be able to host at least the following VEEN process roles:
	•	hub process
	•	bridge process (optional)
	•	CLI invocations from user shells
	•	selftest processes that start ephemeral hubs

5.2 Hub as a foreground process

The hub MUST support foreground operation for development and debugging:
	•	veen hub start --listen 127.0.0.1:8080 --data-dir /var/lib/veen --foreground

This MUST:
	•	keep the hub in the foreground
	•	log status and errors to stderr or stdout
	•	exit with non-zero code on fatal error

5.3 Hub as a background systemd service (native Ubuntu)

On native Ubuntu with systemd, a unit file of the form:
	•	ExecStart=/usr/local/bin/veen hub start --listen 0.0.0.0:8080 --data-dir /var/lib/veen --config /etc/veen/veen.toml

MUST work such that:
	•	sudo systemctl start veen-hub launches the hub
	•	sudo systemctl status veen-hub shows the hub as active
	•	sudo systemctl stop veen-hub stops the hub gracefully

The hub MUST respond to SIGTERM by:
	•	flushing receipt and checkpoint files
	•	flushing log buffers
	•	closing network listeners
	•	exiting with code 0 on normal shutdown

5.4 WSL2 environment

In a WSL2 Ubuntu instance with no systemd:
	•	the hub MUST still be startable as a foreground process
	•	a simple background pattern such as:
	•	nohup veen hub start --listen 0.0.0.0:8080 --data-dir ~/veen-data > ~/veen-hub.log 2>&1 &
MUST be valid and stable

No systemd-specific assumptions may be required for correctness.
	6.	Filesystem layout and permissions

OS6.1 Ownership model

On native Ubuntu:
	•	/var/lib/veen MUST be owned by a dedicated system user (for example, veen)
	•	the hub process SHOULD run as this user, not as root, except for port binding or container contexts
	•	the CLI may run as any user to manage client identities under that user’s home directory

On WSL2, running as the default user is acceptable but MUST still respect per-user client directories.

OS6.2 Data directory contents

The hub MUST create or reuse the following under its data directory:
	•	receipts.cborseq
	•	checkpoints.cborseq
	•	state/ (internal state)
	•	anchors/ (if anchoring is enabled)
	•	optional:
	•	payloads.cborseq if payload storage at the hub is enabled by configuration

These files and directories MUST:
	•	be created with permissions that prevent other unrelated users from modifying them (for example, 0700 directories, 0600 files, owned by the hub user)
	•	be usable across hub restarts without manual repair

OS6.3 Client filesystem layout

Each client identity MUST reside under a user-specific directory, for example:
	•	$HOME/.local/share/veen/client-main
	•	or a user-specified path

Each client directory MUST contain:
	•	keystore.enc (encrypted private keys)
	•	identity_card.pub (public identity)
	•	state.json (or equivalent state file)
	•	optional:
	•	additional state files such as MMR peaks

File permissions MUST restrict access to the owning user (for example, 0700 directory, 0600 files).
	7.	Networking and ports

OS7.1 Binding addresses

On the reference OS, the hub MUST be able to bind to:
	•	127.0.0.1:PORT for local-only testing
	•	0.0.0.0:PORT for serving remote clients on the host network

The CLI MUST accept hubs specified as:
	•	http://127.0.0.1:8080
	•	http://hostname:8080

OS7.2 Port reuse and restart

The hub MUST:
	•	properly close its listening sockets on shutdown
	•	allow immediate restart on the same address/port pair without manual socket cleanup

OS7.3 TLS endpoints (optional)

If TLS is enabled (for example, https://hostname:8443), the OS-level integration MUST:
	•	use the host’s certificate store or files under /etc/veen/tls or similar
	•	not require OS-specific hacks beyond documented configuration

	8.	CLI behavior on the OS

OS8.1 Path and invocation

After installation, the following MUST be valid on the reference OS:
	•	veen --help
	•	veen hub --help
	•	veen keygen --help
	•	veen send --help
	•	veen stream --help
	•	veen selftest core
	•	veen selftest all

All of these MUST:
	•	exit with status 0 when just printing help
	•	not require environment variables beyond PATH and HOME

OS8.2 Deterministic behavior

Given the same:
	•	hub data directory
	•	client directories and files
	•	VEEN binary version
	•	OS-level environment variables (for example, TZ)

CLI commands MUST produce:
	•	the same wire messages
	•	the same receipts and mmr_root values

apart from values that depend on wall-clock time and OS randomness where the specification allows it.

OS8.3 Error reporting

Any CLI command contacting the hub MUST:
	•	decode hub responses as CBOR
	•	if an error response is returned, print:
	•	the error code (for example, E.SIZE, E.SIG)
	•	optional detail text if present
	•	exit with a non-zero exit code

	9.	Logging and observability integration

OS9.1 Hub logs

On native Ubuntu:
	•	when run under systemd, hub logs MUST be visible via journalctl -u veen-hub
	•	when run in foreground, logs MUST go to stderr or stdout

Log output SHOULD:
	•	be structured as text or JSON lines
	•	contain timestamps and severity levels

OS9.2 Metrics endpoint

The hub MUST expose:
	•	GET /metrics on its HTTP port

The CLI command:
	•	veen hub metrics --hub http://127.0.0.1:8080

MUST:
	•	fetch this endpoint
	•	print raw output with --raw
	•	otherwise, summarize key counters and histograms

OS9.3 Health endpoint

The hub MUST expose:
	•	GET /healthz

The CLI command:
	•	veen hub health --hub http://127.0.0.1:8080

MUST:
	•	fetch /healthz
	•	map the response to a simple JSON or text summary

	10.	Security and OS-level hardening

OS10.1 Non-root operation

On native Ubuntu, VEEN MUST:
	•	be able to run the hub process as a non-root user for ports above 1024
	•	not require CAP_NET_ADMIN or similar privileged capabilities for normal operation

Running as root for port 80 or 443 MAY be supported but MUST NOT be required.

OS10.2 File permissions

Installation docs MUST specify:
	•	recommended permissions for /var/lib/veen
	•	recommended permissions for client directories under $HOME/.local/share/veen

The VEEN binaries MUST:
	•	not weaken these permissions automatically
	•	fail with a clear error message if they cannot create or access their required paths

OS10.3 Resource limits

VEEN MUST behave gracefully under OS resource limits such as:
	•	process file descriptor limits
	•	open file limits
	•	CPU time quotas (in containers)

The selftest suite SHOULD include at least one check that:
	•	the hub returns E.SIZE or a similar bound-related error when payload sizes exceed configured limits
	•	the hub does not crash or spin indefinitely under such stress

	11.	WSL2 specifics

OS11.1 Filesystem behavior

On WSL2, VEEN MUST:
	•	tolerate NTFS-backed filesystem semantics (no assumptions about fsync performance beyond basic durability)
	•	not rely on Linux-specific filesystem features (extended attributes, special file types) for correctness

OS11.2 Time and clocks

On WSL2, VEEN MUST:
	•	rely on wall-clock time only for epoch-based label derivation and expiry handling
	•	tolerate small clock skews without breaking protocol invariants beyond what CLOCK_SKEW_EPOCHS allows

	12.	End-to-end OS-level workflows

OS12.1 Local developer workflow

On a clean reference OS, the following end-to-end sequence MUST be valid and documented:
	1.	Install toolchain and clone repository.
	2.	Build VEEN.
	3.	Start a hub in foreground or via systemd.
	4.	Generate a client identity.
	5.	Send a message on core/main.
	6.	Stream messages on core/main.
	7.	Verify at least one attachment.
	8.	Issue a capability token and authorize it.
	9.	Send a capability-gated message.
	10.	Run veen resync and veen verify-state.
	11.	Run veen selftest core.
	12.	Run veen selftest all.

All steps MUST complete without OS-level surprises beyond normal firewall or port conflict issues.

OS12.2 Minimal production workflow

On native Ubuntu, documentation MUST describe a minimal production deployment pattern:
	•	create a system user for VEEN
	•	create /var/lib/veen and /etc/veen
	•	copy the veen binary into /usr/local/bin
	•	set up a systemd unit for the hub
	•	start the hub using systemd
	•	manage client identities from application hosts or users

	13.	Selftest integration with OS

OS13.1 Selftest independence

veen selftest core and veen selftest all MUST:
	•	start temporary hubs on random loopback ports
	•	create temporary data and client directories under /tmp or $TMPDIR
	•	clean up these directories and processes on success or failure
	•	not interfere with any existing hub that uses /var/lib/veen

OS13.2 Exit codes
	•	veen selftest core MUST exit 0 if all core goals are satisfied
	•	veen selftest all MUST exit 0 if all goals and properties pass
	•	non-zero exit codes MUST indicate failure and be accompanied by log lines describing which step failed

	14.	OS-GOALS success criteria

VEEN v0.0.1 meets OS-GOALS when all of the following are true on the reference operating systems:

G14.1 Build and test
	•	cargo build --release succeeds
	•	cargo test --all succeeds
	•	the veen binary (or equivalent documented binaries) is usable from the shell

G14.2 Process lifecycle
	•	the hub can be run in foreground on Ubuntu and WSL2
	•	the hub can be managed by systemd on native Ubuntu
	•	shutdown sequences preserve data durability

G14.3 Filesystem and permissions
	•	hub and client directories are created with safe permissions
	•	all required paths are created automatically or with documented manual steps
	•	restarts do not require manual repair of on-disk state

G14.4 Networking
	•	hubs can bind and listen on loopback and host interfaces
	•	CLI commands can reach hubs using HTTP URLs
	•	port reuse works after hub restart

G14.5 CLI capabilities

From a clean OS, using only VEEN and documented commands, an operator can:
	•	start a hub
	•	generate and inspect identities
	•	send and receive messages
	•	use attachments
	•	use capability tokens, rate limits, and revocations
	•	resynchronize and verify client state
	•	execute RPC and CRDT operations
	•	inspect health and metrics
	•	run selftest suites

G14.6 Stability and hardening
	•	malformed inputs produce controlled errors, not crashes
	•	large payloads are handled within configured bounds
	•	repeated selftest runs do not leak processes or files

When all G14.x conditions hold on Ubuntu 22.04 and 24.04 (native and WSL2) with only the documented prerequisites, VEEN v0.0.1 is OS-GOALS complete.


## Design-Philosophy.txt

VEEN Design Philosophy v0.0.1 (Ephemeral Fabric Tightened)
Plain ASCII, English only
	0.	Purpose and scope

This document pinpoints the design philosophy of VEEN v0.0.1 as an operating model for an “ephemeral, verifiable, reproducible network fabric”.

Motto:

Treat networks as ephemeral as pods.
A network should be disposable, verifiable, and reproducible.
A network you can clone, fork, replay, and interpret.

VEEN interprets this as:
	•	networks are infrastructure with pod-like lifetimes;
	•	hubs are disposable execution containers;
	•	logs and receipts are the durable truth;
	•	overlays (identity, wallet, RPC, CRDT, operations) are deterministic folds over logs;
	•	deployment is OS-agnostic: Linux, WSL2, Docker, k8s, k3s.

The goal is to keep these principles stable while implementations, overlays, and tooling evolve.
	1.	Primary objectives

1.1 Ephemeral fabric
	•	A “network” is treated like a pod:
	•	it can be created, scaled, drained, and destroyed without configuration debt;
	•	lifetimes are short and repeatable;
	•	the cheapest response to damage is replacement, not manual surgery.
	•	The long-lived artefacts are logs, keys, and anchor state, not hub processes, static configs, or mutable databases.

1.2 Disposability
	•	Hubs are explicitly disposable:
	•	a hub can be killed, upgraded, or moved without changing semantics of any label;
	•	a hub can be replaced by another binary using the same data directory;
	•	multiple hubs can serve the same fabric as long as they respect the core invariants.
	•	Network topologies, pod layouts, and node assignments are allowed to change frequently; logs remain authoritative.
	•	Operational guidelines should default to:
	•	“replace the hub” rather than “repair the hub”;
	•	“replay from logs” rather than “fix state in place”.

1.3 Verifiability
	•	Every accepted message is committed into an authenticated log:
	•	leaf_hash and msg_id bind ciphertext to label, profile, and client_seq;
	•	MMR roots and CHECKPOINT objects provide compact inclusion proofs;
	•	RECEIPT and CHECKPOINT carry hub signatures;
	•	anchors optionally bind MMR roots to external ledgers or trust systems.
	•	Any statement about “what happened” must be reconstructible and checkable from retained logs and proofs, without trusting a live hub, a particular database, or a specific cluster topology.

1.4 Reproducibility
	•	For any retained log prefix, folding overlays over that prefix must:
	•	produce identical state on any conforming implementation;
	•	allow state to be recomputed from scratch without hidden side channels;
	•	allow a new hub or client to join by replaying logs only.
	•	Reproducibility is preferred over mutable databases:
	•	operational state is derived, not stored ad hoc;
	•	divergence between stored state and log-derived state is treated as an error to surface, not a normal condition to tolerate.
	•	Cloneability and replayability are design requirements:
	•	copying a data directory must be sufficient to reconstruct the same fabric instance;
	•	replaying the same event sequence must yield the same overlay state.

1.5 Invariance
	•	A small set of wire objects and invariants is fixed:
	•	MSG, RECEIPT, CHECKPOINT, mmr_proof, cap_token;
	•	invariants I1..I12 over their relationships.
	•	The following must not change the meaning of these objects:
	•	OS or kernel version;
	•	container runtime (bare metal, Docker, containerd, etc.);
	•	hub process layout or topology;
	•	which overlays are in use, or how many hubs participate in the fabric.

1.6 Determinism
	•	For any finite event prefix L on a label:
	•	fold(L) is a deterministic function for every overlay;
	•	any conforming implementation produces identical overlay state from L.
	•	All non-determinism is either:
	•	forbidden, or
	•	explicitly localized and documented (for example:
	•	time in TTL checks,
	•	day-boundary limit windows,
	•	tie-breaking using stream_seq).
	•	Admission and error behavior for a given MSG under v0.0.1 are deterministic given:
	•	current log state;
	•	configured limits and profiles.
	•	Determinism is what makes “replay” and “interpret” meaningful operations rather than approximations.

1.7 Portability
	•	The same repository and binary must:
	•	run on Ubuntu 22.04 and 24.04 (native, systemd);
	•	run on WSL2 Ubuntu;
	•	run in containers under Docker, k8s, and k3s;
	•	expose identical wire semantics and log behavior.
	•	A “VEEN fabric instance” is defined by:
	•	its logs (receipts.cborseq, payloads.cborseq, checkpoints.cborseq, anchors);
	•	not by OS, container runtime, process layout, or cluster design.

1.8 Minimality
	•	Hubs:
	•	accept, verify, commit, stream, and anchor;
	•	expose health and metrics;
	•	do not interpret payload schemas.
	•	Overlays:
	•	define schemas and folding rules;
	•	are pure clients of the log model;
	•	do not require hub modifications.
	•	The core remains small enough that:
	•	audits are feasible and bounded;
	•	alternative hub implementations remain practical;
	•	cloning, forking, and replay are implementable without hidden dependencies.

1.9 Clone, fork, replay, interpret

VEEN is designed so that a network can be:
	•	Cloned:
	•	copying a fabric data directory and pinned keys is sufficient to stand up an equivalent fabric instance;
	•	cloned instances can be brought up in isolated environments for testing, audit, or simulation.
	•	Forked:
	•	retaining a log prefix and then diverging event streams allows independent evolution from a common history;
	•	forks are explicit at the fabric or label level and do not require bespoke migration paths.
	•	Replayed:
	•	overlay state is reconstructed by replaying events from zero or from a checkpoint;
	•	replay is deterministic and yields identical results for the same inputs.
	•	Interpreted:
	•	new overlays can be applied to existing logs to derive new views of the same history;
	•	no hub changes are required to interpret old logs with new overlays.

These four operations are core design targets, not side effects.
	2.	Network-as-container model

2.1 Fabric instance

A VEEN fabric instance is:
	•	a set of labels and their event logs;
	•	a set of MMR roots and checkpoints;
	•	optional anchors and bridge relationships;
	•	optional overlay-specific state reconstructed from logs.

This is analogous to:
	•	a container image plus its volume contents:
	•	logs are the durable “data volume”;
	•	hubs are disposable “container processes” that:
	•	bind logs to TCP ports and endpoints;
	•	enforce admission and invariants;
	•	interact with anchoring backends.

Cloning or snapshotting a fabric is equivalent to copying container volumes and pinned config.

2.2 Hubs as disposable nodes
	•	A hub process is started with a data directory, profile, and listen address.
	•	A hub can be:
	•	killed and restarted without semantic loss for any label whose logs are intact;
	•	replaced by a newer binary using the same data directory;
	•	replicated under supervision (systemd, k8s Deployments, k3s) with identical behavior for the same traffic and logs.
	•	Hubs are expected to be:
	•	short-lived compared to fabric lifetime;
	•	rotated often for upgrades, hardening, and topology changes.
	•	Operational guidance:
	•	“drain and replace a hub” should be routine, not exceptional.

2.3 Clients as portable endpoints
	•	A client identity (keys and state) is stored under a user-controlled path or volume.
	•	A client can:
	•	connect to any conforming hub in the fabric;
	•	resync and verify its state using /stream and CHECKPOINT endpoints;
	•	detect divergence and recover via RESYNC flows.
	•	Client correctness depends only on:
	•	retained logs;
	•	trust in pinned hub keys and profiles;
	•	never on hub-local mutable databases or in-memory caches.

	3.	Wire and invariants

3.1 Fixed wire objects
	•	MSG:
	•	carries ver, profile_id, label, client_id, client_seq, prev_ack, auth_ref, ct_hash, ciphertext, sig.
	•	RECEIPT:
	•	carries ver, label, stream_seq, leaf_hash, mmr_root, hub_ts, hub_sig.
	•	CHECKPOINT:
	•	commits label_prev, label_curr, upto_seq, mmr_root, epoch, hub_sig, optional witness_sigs.
	•	cap_token:
	•	carries issuer_pk, subject_pk, allow, sig_chain.

These objects, together with MMR structure and invariants, define what can be cloned, forked, and replayed.

3.2 Hub responsibilities

The hub must:
	•	validate:
	•	signatures (MSG.sig, hub_sig, cap_token signatures when used);
	•	sizes and limits;
	•	sequence and uniqueness invariants;
	•	profile compatibility;
	•	maintain per-label MMR state and emit RECEIPTs;
	•	emit CHECKPOINT objects and optional anchors.

The hub must not:
	•	branch on payload_hdr.schema contents for core behavior;
	•	use decrypted body for admission or ordering decisions;
	•	embed overlay-specific semantics into core wire handling.

3.3 Version stability
	•	Within v0.0.1:
	•	wire encoding is frozen;
	•	hub behavior for valid and invalid messages is frozen.
	•	Overlays may evolve by defining new schemas and folding rules without:
	•	changing MSG, RECEIPT, CHECKPOINT, mmr_proof, cap_token structure;
	•	requiring hub code changes;
	•	invalidating existing logs.

	4.	Logs as single source of truth

4.1 Append-only model
	•	The authoritative record for a label consists of:
	•	receipts.cborseq (sequence of RECEIPT, optionally paired with MSG payloads for retention);
	•	checkpoints.cborseq;
	•	optional anchors that bind mmr_root values externally.
	•	Hubs may rotate on-disk files and apply retention, but:
	•	any retained prefix must remain internally consistent and re-foldable;
	•	truncation must not silently create inconsistent prefixes;
	•	policies for retention and compaction must be documented and auditable.

4.2 Folding semantics
	•	For each overlay:
	•	state(label, upto_seq) = fold(events up to upto_seq on relevant streams).
	•	Folding rules must:
	•	depend only on:
	•	stream order (stream_seq as primary tie-breaker);
	•	payload_hdr.schema;
	•	payload body bytes;
	•	optional timestamps inside the payload body;
	•	not depend on:
	•	which hub accepted the message;
	•	sender IP or connection metadata;
	•	OS, hardware, or container runtime.
	•	Re-running fold on the same retained prefix must exactly reproduce prior overlay state, enabling replay and offline audit.

4.3 Cross-hub consistency
	•	Bridging and mirroring must preserve:
	•	payload bytes;
	•	payload_hdr.schema;
	•	a deterministic parent_id link back to original msg_id when mirroring.
	•	Overlay implementations must:
	•	treat local and bridged events under the same folding rules;
	•	document deduplication keys (for example (source_hub, label, stream_seq) or parent_id);
	•	ensure that clones and forks of fabrics that include bridged events remain foldable without ambiguity.

	5.	Overlay design constraints

5.1 Pure overlay

An overlay (identity, wallet, RPC, CRDT, operations) must:
	•	be defined only in terms of:
	•	schema identifiers in payload_hdr.schema;
	•	deterministic CBOR payload bodies;
	•	per-stream folding rules over logs;
	•	not require:
	•	hub-specific endpoints beyond VEEN core;
	•	schema-aware logic in hub;
	•	non-deterministic external state during folding.

5.2 Conflict handling

Overlays must specify:
	•	update rules:
	•	last-writer-wins when multiple updates can apply to the same key;
	•	OR-set or grow-only counter semantics when sets or counters are used;
	•	deduplication rules when duplicate events are possible (for example due to replay or mirroring);
	•	explicit tie-breakers:
	•	timestamps plus stream_seq;
	•	stream_seq alone;
	•	leaf_hash only if needed.

Any ambiguity must be resolved by documented rules. Different implementations must not diverge under the same event prefix, otherwise “interpret” ceases to be well-defined.

5.3 Compatibility
	•	Adding an overlay must not:
	•	change how MSG are accepted or ordered by the hub;
	•	require schema-specific error handling in core paths;
	•	invalidate or reinterpret older logs.
	•	Overlays must be strictly additive with respect to the core:
	•	new overlays can always be applied to old logs;
	•	old overlays continue to fold correctly when new overlays are introduced.

	6.	Identity overlay role

6.1 Identity as log-derived state
	•	Principals, devices, realms, contexts, organizations, groups, and handles:
	•	exist only as derived state from identity streams;
	•	are folded from identity messages and revocation messages.
	•	Hubs:
	•	are unaware of identity details beyond public keys and cap_token structures;
	•	are not required to understand realms, organizations, or group semantics.

6.2 Sessions and context binding
	•	Application frontends bind sessions to context identifiers using:
	•	device keys;
	•	capability chains;
	•	identity overlay logs.
	•	This binding must be:
	•	reconstructible from logs;
	•	verifiable offline;
	•	independent of hub internals.
	•	Identity overlays must remain foldable on cloned, forked, and replayed fabrics.

	7.	Wallet and paid operation overlay role

7.1 Balances and transfers from logs
	•	A wallet is defined by:
	•	wallet_id (for example realm, context, currency, account);
	•	its event stream of wallet operations and paid operations.
	•	Balances, limits, freezes, and adjustments are derived entirely by folding events:
	•	debit and credit operations;
	•	policy and configuration events;
	•	revocations and closures.

7.2 No hub-side balances
	•	Hubs do not:
	•	store balances;
	•	enforce wallet-specific rules;
	•	distinguish financial messages from other payloads.
	•	Wallet services and auditors:
	•	recompute balances from logs;
	•	detect overdrafts or violations using the same folding rules;
	•	can operate on cloned or forked fabric snapshots for what-if analysis.

	8.	OS and container integration

8.1 Execution environment
	•	VEEN must run as:
	•	a normal Unix process on Linux and WSL2;
	•	a container entrypoint in Docker, k8s, and k3s;
	•	the same veen binary with the same CLI surface.
	•	No mandatory external persistent systems:
	•	no required RDBMS;
	•	no required message broker;
	•	no required external KMS.
	•	Integrations with databases, KMS, or queues are permitted as overlays or sidecars, not as core dependencies.

8.2 Data and logs
	•	Hub data directories:
	•	are plain directories, mountable as volumes;
	•	contain receipts, payloads, checkpoints, anchor metadata, and state files;
	•	can be attached to containers or bare-metal processes interchangeably.
	•	Clients:
	•	store identity and state under user paths or mounted volumes;
	•	must be able to move between machines without changing semantics, as long as keys and state are preserved.

8.3 Supervision and lifecycle
	•	Hub lifecycle is managed by:
	•	systemd units on bare metal and WSL2;
	•	Deployments or StatefulSets on k8s and k3s;
	•	equivalent constructs on other orchestrators.
	•	Shutdown must:
	•	flush receipts and checkpoints to disk at documented durability guarantees;
	•	close listeners cleanly;
	•	permit immediate restart on the same data directory and port.
	•	Operational practices should treat hub restarts and redeployments as normal background noise, not rare events.

	9.	Security model

9.1 Trust boundaries
	•	Clients trust:
	•	their own keys and keystore;
	•	pinned hub public keys and profiles;
	•	log ordering and hub signatures as enforced by core invariants.
	•	Hubs are trusted to:
	•	enforce admission via cap_token and rate limiting;
	•	maintain MMR consistency and signatures;
	•	respect configured limits.
	•	Hubs are not trusted with:
	•	plaintext application payloads;
	•	overlay semantics or policy decisions beyond admission.

9.2 Confidentiality and integrity
	•	Confidentiality:
	•	payloads are protected by AEAD using per-label keys derived from HPKE contexts;
	•	hub does not see decrypted payload_hdr or body.
	•	Integrity:
	•	client-level via MSG.sig over the canonical MSG encoding (without sig);
	•	hub-level via hub_sig over RECEIPT and CHECKPOINT;
	•	log-level via MMR roots and inclusion proofs plus optional external anchoring.
	•	These properties must hold across clones, forks, and replays of the fabric.

9.3 Revocation and rotation
	•	Revocation is represented as overlay events and cap_token lifecycle:
	•	device or client identity revocations;
	•	capability and auth_ref revocations.
	•	Hubs and applications:
	•	read the same revocation events;
	•	enforce consistent decisions for new messages.
	•	Key rotation:
	•	is performed without changing wire semantics;
	•	is recorded via CHECKPOINT witness signatures and overlay events;
	•	must remain verifiable when logs are cloned, forked, or replayed.

	10.	Evolution and versioning

10.1 Core evolution
	•	VEEN v0.0.1:
	•	fixes wire objects, invariants, and error behavior.
	•	Future core versions may:
	•	add new fields or error codes;
	•	define new invariants;
	•	provide explicit upgrade paths.
	•	Core evolution must not:
	•	silently reinterpret v0.0.1 logs;
	•	break deterministic folding for pre-existing schemas;
	•	invalidate the ability to clone, fork, replay, and interpret v0.0.1 fabrics.

10.2 Overlay evolution
	•	New overlays are added by:
	•	defining new schema identifiers;
	•	defining folding rules and invariants for those schemas;
	•	documenting interaction with existing overlays.
	•	Existing overlays may:
	•	evolve via versioned schemas (for example “id.ctx.profile.v2”);
	•	introduce new fields while keeping old behavior well-defined.
	•	Overlay evolution must:
	•	be replayable from combined logs;
	•	specify precedence and tie-breaking between versions;
	•	preserve interpretability of past events.

	11.	Non-goals

VEEN does not aim to be:
	•	a general-purpose compute or function execution platform;
	•	a consensus or blockchain system;
	•	a deep packet inspection or routing engine;
	•	a replacement for every existing authentication or identity standard;
	•	a full-featured API gateway or service mesh.

VEEN aims to be:
	•	a minimal, deterministic fabric for:
	•	encrypted event transport;
	•	verifiable logging;
	•	overlay-defined state;
	•	a network layer that is:
	•	as ephemeral as pods in deployment;
	•	as auditable as a ledger in history;
	•	cloneable, forkable, replayable, and re-interpretable in operation.

	12.	Summary axis

The design axis that must not drift is:
	•	Fix a minimal wire and log core with strong invariants.
	•	Treat logs, receipts, and checkpoints as the single durable truth.
	•	Make hubs disposable containers that attach logs to networks and enforce invariants.
	•	Keep all higher-level semantics (identity, wallet, RPC, CRDT, operations) as deterministic folds over logs.
	•	Require OS and container independence: Linux, WSL2, Docker, k8s, and k3s all yield identical semantics for the same logs.
	•	Ensure that any conforming implementation supports:
	•	cloning fabrics by copying data;
	•	forking fabrics by splitting histories;
	•	replaying fabrics by folding logs;
	•	interpreting fabrics by adding overlays.

As long as these properties hold, networks can be treated as ephemeral as pods: disposable in deployment, verifiable in audit, reproducible under replay, and interpretable under new overlays.


## USAGE.md

# VEEN Usage Compendium

This is the “first hour” guide for the VEEN CLI and its companion binaries (`veen`, `veen-hub`, `veen-selftest`, `veen-bridge`). Follow the sections in order the first time you use VEEN, then dip back in as a reference for common tasks.

**Who is this for?**
- **First-time users:** start at “Before you begin”, then follow the Local developer quickstart exactly once end-to-end.
- **Returning operators:** skip straight to the command blocks you need; each block is self-contained.

**Reading tips**
- Commands written with `target/release/` assume you built locally. Drop the prefix when using packaged binaries or when already inside Docker/Kubernetes.
- Replace placeholders like `<PROFILE_ID>` with your own values. Flags in backticks are literal.
- Use temporary paths such as `/tmp/veen-hub` for experiments; for long-lived hubs see “Manual installation” for persistent directories.
- Output precedence: explicit output flags (for example `--json` on a subcommand) win over global defaults, and `--json` overrides `--quiet`. When `--quiet` is set without JSON output enabled, successful command output is suppressed (errors still print).
- If something fails, re-run with `--verbose` to see detailed logs. Most first-run issues relate to filesystem permissions on the chosen data directory.

**Fast navigation**
- [1. Before you begin](#1-before-you-begin)
- [2. Build and sanity-check](#2-build-and-sanity-check)
- [3. Local developer quickstart](#3-local-developer-quickstart)
- [4. Additional flows](#4-additional-flows)
- [5. Running with containers](#5-running-with-containers)
- [6. Environment descriptors (`veen env`)](#6-environment-descriptors-veen-env)
- [7. Kubernetes workflows (`veen kube`)](#7-kubernetes-workflows-veen-kube)
- [8. Verification and tests](#8-verification-and-tests)
- [9. Common helper tools](#9-common-helper-tools)
- [10. Further reading](#10-further-reading)

## 1. Before you begin

### Supported platforms and packages
- Target OS: Ubuntu 22.04/24.04 (including WSL2). macOS works if you swap `apt` commands for Homebrew equivalents.
- Required packages: `build-essential pkg-config libssl-dev curl ca-certificates`
- Recommended extras: `jq` for inspecting JSON outputs and `just` for developer shortcuts

Install everything in one go on Ubuntu:

```shell
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl ca-certificates
sudo apt install -y jq just # optional, but useful for debugging
```

### Rust toolchain
Use the pinned stable toolchain declared in `rust-toolchain.toml` so your build matches CI and the Docker image:

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo --version # verify Rust is available
```

If your shell cannot find `cargo`, ensure `~/.cargo/bin` is present on your `PATH` (rerun `source "$HOME/.cargo/env"`).

## 2. Build and sanity-check

### Build the workspace

```shell
cargo build --release
```

`cargo` will fetch dependencies on first run. Supply `CARGO_NET_OFFLINE=true` for an air-gapped build **only** when you already have a populated Cargo cache. If the build fails with linker errors, ensure `libssl-dev` is installed and re-run the command.

#### Quick sanity check
- List the installed binaries and confirm they respond:
  ```shell
  ls target/release/veen*
  target/release/veen --help | head -n 5
  target/release/veen version
  ```
- Expected result: a version string like `veen x.y.z (git <hash>)` and four binaries present. Missing files usually mean the build aborted; re-run `cargo build --release` and read the first error in the log.

You should now have four binaries under `target/release/`:
- `veen` – CLI used across all workflows
- `veen-hub` – hub runtime binary (invoked via `veen hub`)
- `veen-selftest` – self-test harness
- `veen-bridge` – log replication helper

### Manual installation

```shell
sudo install -m 0755 target/release/veen /usr/local/bin/veen
sudo install -m 0755 target/release/veen-hub /usr/local/bin/veen-hub
sudo install -m 0755 target/release/veen-selftest /usr/local/bin/veen-selftest
sudo install -m 0755 target/release/veen-bridge /usr/local/bin/veen-bridge
```

When packaging for production hosts, prefer copying the four binaries into `/usr/local/bin` as a single step using your configuration manager (Ansible, Chef, etc.). The binaries are dynamically linked to glibc and OpenSSL, so ensure the target hosts provide those libraries.

Recommended directories:

```shell
sudo install -d -m 0750 /var/lib/veen
sudo install -d -m 0755 /etc/veen
sudo install -d -m 0750 /var/log/veen
```

`/var/lib/veen` should be writable by the service account that runs the hub. `/etc/veen` can hold static configuration such as `hub-config.toml` and TLS material if you supply `--tls-cert`/`--tls-key`. Logs default to stderr; set `RUST_LOG` or `VEEN_LOG_LEVEL` to adjust verbosity.

## 3. Local developer quickstart

Complete these steps in order the first time you run VEEN. Create a disposable workspace (e.g. `/tmp/veen-hub` and `/tmp/veen-client`) so you can delete everything afterwards.

1. **Start a hub in the foreground**
   ```shell
   target/release/veen hub start \
     --listen 127.0.0.1:37411 \
     --data-dir /tmp/veen-hub \
     --foreground
   ```
   Stop with `Ctrl+C`. `--data-dir` accepts a local path or a `file://` URI. When not running in the foreground, the hub detaches and writes its PID under `<data-dir>/hub.pid` for `hub stop` to consume. On first start you should see the listen address, profile identifier, and log path printed to the terminal. If you see “address already in use”, change `--listen` to a free port.

2. **Generate a client identity**
   ```shell
   target/release/veen keygen --out /tmp/veen-client
   ```

   The command creates `identity_card.pub` (public key material), `keystore.enc`
   (private key material), and `state.json` (client ack/rotation state). Keep
   `keystore.enc` outside version control and back it up securely.

3. **Send a message**
   ```shell
   target/release/veen send \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   ```
   Expected result: the terminal prints the committed sequence number and the hub writes a JSON bundle under the data directory. Add `--cap <PATH>` to attach a capability token or `--attach <FILE>` to bundle binary payloads; each flag may be repeated. Errors such as `unable to open hub` usually mean the path after `--hub` is wrong or the hub from step 1 has stopped.

4. **Stream messages**
   ```shell
   target/release/veen stream \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --from 0
   ```
   Displays message bodies, attachment metadata, and received sequence numbers. ACK state is maintained client-side.

   Add `--with-proof` to request cryptographic proofs for each record or `--follow` to keep streaming new messages.

5. **Inspect hub status and keys**
   ```shell
   target/release/veen hub status --hub /tmp/veen-hub
   target/release/veen hub key --hub /tmp/veen-hub
   ```
   `hub status` reports the listen address, current state root, and whether PoW is enabled. `hub key` prints the hub's signing key and profile identifier.

6. **Stop a background hub**
   ```shell
   target/release/veen hub stop --data-dir /tmp/veen-hub
   ```
   This sends a shutdown signal to the backgrounded hub and waits for a clean exit. `hub stop` is only available on Unix-like hosts; on Windows, terminate the background process manually.

7. **Clean up**

   Remove temporary state when you are done exploring:
   ```shell
   rm -rf /tmp/veen-hub /tmp/veen-client
   ```
   Re-run the steps above any time you want a fresh sandbox. When in doubt, delete the temporary directories and repeat steps 1–4 to return to a known-good state.

## 4. Additional flows

### Viewing schema descriptors
- Inspect a registered schema:
  ```shell
  target/release/veen schema show \
    --hub http://127.0.0.1:37411 \
    --schema-id <HEX32> \
    --json
  ```
  Shows the identifier, name, version, and usage. Use `--json` for machine-readable output.

### Proof-of-Work (PoW)
If a hub demands PoW, supply the parameters on `veen send` or `veen rpc call`:
- `--pow-difficulty <BITS>`: Solve and attach a cookie of the given difficulty. When no challenge is supplied a random one is generated locally.
- `--pow-challenge <HEX>`: Reuse a hub-issued challenge or provide your own.
- `--pow-nonce <NONCE>`: Send a pre-computed cookie alongside the matching difficulty and challenge.

Enable PoW requirements on the hub with `veen hub start --pow-difficulty`.

Include `--pow-max-time <SECONDS>` to cap the time spent solving. All PoW parameters are echoed back in verbose logs to aid debugging.

### Snapshot verification
Verify that a stream state matches a checkpoint:
```shell
veen snapshot verify \
  --hub https://hub.example \
  --stream my/ledger \
  --state-class wallet.ledger \
  --state-id deadbeef... \
  --upto-stream-seq 42
```
Prints the state hash and MMR root, highlighting the first mismatch when present. Use `--json` for structured output.

For local debug you can point `--hub` at a filesystem path (e.g. `/tmp/veen-hub`) instead of HTTP(S). Combine with `--expected-root <HEX>` to assert a specific Merkle root during CI.

## 5. Running with containers

Docker packaging persists hub data in a named volume.

Prerequisites:
- Docker Engine 24+ and Docker Compose Plugin v2.2+ installed on the host.
- Ports `37411` (default) or your chosen `HUB_PORT` must be free.
- The current working directory should be the repo root (so Compose can build or locate the binary).

1. **Build and start**
   ```shell
   docker compose up --build -d
   ```
   Listens on `0.0.0.0:37411` with `restart: unless-stopped`.

   Override the exposed port with `HUB_PORT=<PORT> docker compose up -d` if you need to avoid clashes. Compose injects the hub binary built from the local workspace by default; set `HUB_IMAGE` to pull a prebuilt image instead.

2. **Health and logs**
   ```shell
   docker compose logs -f hub
   docker compose ps
   ```
   A container healthcheck runs `veen hub health` internally.

   Use `docker compose exec hub veen hub status --hub /var/lib/veen` to confirm the in-container data directory and profile ID.

3. **Use the CLI inside the container**
   Keep client material on the shared volume:
   ```shell
   docker compose run --rm hub veen keygen --out /var/lib/veen/clients/alice
   docker compose exec hub veen send \
     --hub /var/lib/veen \
     --client /var/lib/veen/clients/alice \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   docker compose exec hub veen stream \
     --hub /var/lib/veen \
     --client /var/lib/veen/clients/alice \
     --stream core/main \
     --from 0
   ```
   Stop with `docker compose down` (add `--volumes` to remove the persisted log).

### Overriding environment variables
Set `VEEN_LISTEN`, `VEEN_LOG_LEVEL`, `VEEN_PROFILE_ID`, `VEEN_CONFIG_PATH`, etc. in `docker-compose.yml` or via `docker compose run -e` to control listen addresses or config paths.

For TLS, mount cert/key pairs into the container and reference them with `VEEN_TLS_CERT`/`VEEN_TLS_KEY`. Logging verbosity can be increased with `VEEN_LOG_LEVEL=debug` to mirror the `--verbose` flag of the CLI.

## 6. Environment descriptors (`veen env`)

Environment files (`*.env.json`) capture cluster context, namespace, and hub metadata for reuse across commands.

1. **Initialise**
   ```shell
   veen env init \
     --root ~/.config/veen \
     --name demo \
     --cluster-context kind-demo \
     --namespace veen-tenant-demo \
     --description "demo tenant"
   ```
   `--root` must be an existing directory; VEEN will create the `.env.json` file within it. The description is optional but helps distinguish similar clusters.

2. **Register hubs and tenants**
   ```shell
   veen env add-hub \
     --env ~/.config/veen/demo.env.json \
     --hub-name primary \
     --service-url https://hub.demo.internal:8443 \
     --profile-id <PROFILE_ID>
   veen env add-tenant \
     --env ~/.config/veen/demo.env.json \
     --tenant-id demo \
     --stream-prefix core \
     --label-class wallet
   ```
   Use `veen env add-cap` to register capabilities or `veen env add-client` when distributing pre-generated client identities to operators.

3. **Inspect**
   ```shell
   veen env show --env ~/.config/veen/demo.env.json
   veen env show --env ~/.config/veen/demo.env.json --json
   ```
   `--json` output includes embedded hub profile IDs, service URLs, and tenant stream prefixes for consumption by automation.

Subsequent CLI calls can use `--env ~/.config/veen/demo.env.json --hub-name primary` to resolve service URLs and profile IDs automatically. When both `--env` and explicit flags are supplied, the explicit flags win.

## 7. Kubernetes workflows (`veen kube`)

Follows `doc/CLI-GOALS-3.txt` to render and apply Namespace/ServiceAccount/RBAC/ConfigMap/Secret/Deployment/Service resources. All subcommands support `--json`.

- **Render manifests**
  ```shell
  target/release/veen kube render \
    --cluster-context kind-veens \
    --namespace veen-tenants \
    --name alpha \
    --image veen-hub:latest \
    --data-pvc veen-alpha-data \
    --config hub-config.toml \
    --env-file hub.env \
    --pod-annotations pod-annotations.json > hub.yaml
  ```

- **Apply**
  ```shell
  target/release/veen kube apply --cluster-context kind-veens --file hub.yaml --wait-seconds 180
  ```

- **Logs and status**
  - `veen kube logs --cluster-context ... --namespace ... --name alpha --follow`
  - `veen kube status --cluster-context ... --namespace ... --name alpha --json`

- **Delete**
  ```shell
  veen kube delete --cluster-context kind-veens --namespace veen-tenants --name alpha --purge-pvcs
  ```

### Disposable Jobs for client workflows
Run `veen send` / `veen stream` inside short-lived Jobs that mount Secrets containing clients/capabilities.

- Send example:
  ```shell
  veen kube job send \
    --cluster-context prod-admin \
    --namespace veen-tenants \
    --hub-service veen-hub-alpha.veen-tenants.svc.cluster.local:8080 \
    --client-secret tenant-a-client \
    --cap-secret tenant-a-cap \
    --stream core/main \
    --body '{"k":"v"}' \
    --state-pvc veen-tenant-a-client-pvc
  ```

- Stream with proofs:
  ```shell
  veen kube job stream \
    --cluster-context prod-admin \
    --namespace veen-tenants \
    --hub-service veen-hub-alpha.veen-tenants.svc.cluster.local:8080 \
    --client-secret tenant-a-client \
    --stream core/main \
    --from 0 \
    --with-proof \
    --image registry.example.com/ops/veen-cli:v1
  ```

Jobs mount Secrets to `/var/lib/veen-client` (and `/var/lib/veen-cap`), stream pod logs in real time, and optionally persist ACK state via `--state-pvc`.

## 8. Verification and tests

- Run all unit tests: `cargo test --workspace`
- Self-test harness: `target/release/veen selftest core` / `props` / `fuzz` / `all`
- Overlay suites: `target/release/veen selftest federated` / `kex1` / `hardened` / `meta`

Temporary directories under `/tmp` are removed automatically on success or failure.

## 9. Common helper tools

- `Justfile` commands: `just ci` (fmt + clippy + test), `just fmt`, `just cli -- --help`
- Performance: `just perf -- "--requests 512 --concurrency 64"` (add `--mode http` for HTTP latency)

## 10. Further reading

- Protocol/overlay specs (SSOT): `doc/spec.md`
- CLI/OS goals: `doc/CLI-GOALS-1.txt`–`CLI-GOALS-3.txt`, `doc/OS-GOALS.txt`
- Design rationale: `doc/Design-Philosophy.txt`


## Whyuse.txt

Why use VEEN v0.0.1
Plain ASCII, English only
	0.	Purpose

This document explains why an organization should deploy VEEN as part of its production stack. It focuses on concrete, operational value: what becomes easier, safer, or cheaper once event traffic passes through VEEN’s ephemeral, verifiable fabric.

VEEN’s core claim can be stated as:

A network should be something you can clone, fork, replay, and interpret.

If your current messaging and network infrastructure cannot be cloned, cannot be replayed from a single source of truth, and cannot be interpreted offline in a deterministic way, VEEN gives you capabilities you do not currently have.
	1.	Operational value: safer networks by default

1.1 A single place where “what happened” is unambiguous

In most systems today:
	•	messages pass through multiple brokers, gateways, and services;
	•	each component keeps its own partial logs;
	•	reconstructing an incident requires correlating multiple data sources with different schemas and retention policies.

VEEN enforces one simple rule: every accepted message becomes part of an authenticated log for its label, with receipts, MMR roots, and optional checkpoints.

This means that:
	•	“Did this message happen?” has a cryptographic yes/no answer.
	•	“In what order did these events occur?” is determined by stream order and MMR proofs, not by scattered timestamps.
	•	“What state should the system be in?” can be recomputed by folding overlays over logs, without trusting ad hoc databases.

Adoption value: incident response, security reviews, and audits become fundamentally easier because there is a single, authoritative event history rooted in signed receipts.

1.2 Disposable hubs instead of fragile snowflake clusters

Traditional message brokers and API gateways become “pets”:
	•	upgrades are risky;
	•	topology drift breaks invariants;
	•	failover requires careful choreography.

VEEN treats hubs as disposable containers:
	•	they can be killed and restarted without semantic loss;
	•	they can be replaced by newer binaries on the same log directories;
	•	multiple hubs can serve the same fabric, as long as they respect invariants.

Operational value:
	•	upgrades are reduced to “roll out new hub image, point it at the same data directory, observe metrics”;
	•	capacity planning is about logs and I/O, not about preserving hidden broker state;
	•	running on bare metal, WSL2, Docker, k8s, or k3s is a deployment choice, not a semantic change.

1.3 Built-in disaster recovery semantics

Because VEEN treats logs as the single truth and hubs as disposable, DR becomes a first-class capability:
	•	a second region or cluster can mirror logs via bridge;
	•	a cutover scenario is a matter of moving clients and overlays to fold over mirrored logs;
	•	DR tests can be automated as self-tests that spin hubs, replay logs, and verify that invariants hold.

This is very different from trying to replicate an entire message broker, its database, and all consumers’ state. VEEN’s design makes “can we bring this network back from logs alone?” an answerable question.
	2.	Security and compliance value

2.1 Strong integrity without a blockchain

Many teams want tamper-evident logs but do not want to operate or integrate a blockchain.

VEEN offers:
	•	AEAD protection and end-to-end integrity for payloads;
	•	MMR-based authenticated logs with leaf-level inclusion proofs;
	•	hub signatures on receipts and checkpoints;
	•	optional external anchoring for roots.

This gives:
	•	demonstrable proof that events were not retroactively edited or deleted, within a retention policy;
	•	the ability to present short, verifiable evidence to auditors and regulators without exposing full internal infrastructure;
	•	a way to separate “who can see plaintext” from “who can verify integrity”.

In short, VEEN gives most of the audit and non-repudiation benefits people expect from ledger systems, but with the performance and operational model of an event fabric, not a global consensus chain.

2.2 Capability-based, rate-limited admission

Admission and rate limiting are expressed via cap_token and revocation overlays, not hard-coded per-service logic.

Benefits:
	•	access policies can be changed by publishing events, leaving a signed record of policy history;
	•	rate limits are enforced at the network fabric layer with cryptographic structure, instead of being reimplemented in every microservice;
	•	revocation decisions are reproducible from logs: “why was this request denied?” can be traced back to specific revocation and quota events.

This is particularly useful in environments where multiple teams or tenants share infrastructure and where auditability of access control is a requirement.
	3.	Developer and architecture value

3.1 Overlays let you add semantics after the fact

Today, changing semantics of a running network often requires:
	•	redeploying services;
	•	applying database migrations;
	•	coordinating new headers, message shapes, and routing rules.

In VEEN:
	•	the core wire format is fixed and minimal;
	•	overlays interpret logs as identity, wallets, CRDT state, RPC endpoints, or operational metrics;
	•	new overlays can be added to existing logs without touching hubs.

This yields:
	•	the ability to “retrofit” semantics to historical data (for example, compute new analytics, derive new counters, or define new forms of identity from existing traffic);
	•	the ability to introduce new application concerns, such as billing or cross-region CRDTs, as overlays instead of as invasive code changes across the fleet.

Put plainly: once traffic goes through VEEN, you regain the option to reinterpret that traffic later, without redeploying the world.

3.2 Stepwise migration from legacy systems

VEEN is explicitly designed so that teams can start with:
	•	mirroring events from existing brokers and APIs into a VEEN label;
	•	doing nothing else.

At this stage, VEEN is “just” a better audit log and DR substrate.

Then, gradually:
	•	a subset of traffic is sent directly through VEEN;
	•	overlays are added to derive identity, quotas, and financial state;
	•	existing services begin to read from VEEN streams instead of legacy brokers;
	•	legacy components can be retired one by one.

At no point is a big-bang migration required. VEEN fits into brownfield environments.

3.3 Treating the network as a testable, spec-aligned component

Because VEEN comes with:
	•	a precise specification for MSG, RECEIPT, CHECKPOINT, and invariants;
	•	self-tests that spin up hubs, send messages, resync, and verify invariants;
	•	test coverage for identity, wallet, revocation, and proof behavior,

you can treat the network fabric as a unit you can test in CI:
	•	“does our network obey its own spec?” becomes a machine-checkable question;
	•	regression in network semantics is caught at the level of invariants, not after outages;
	•	multiple implementations or forks can be validated against the same behavioral tests.

This is very different from most ad hoc event pipelines, where behavior is distributed and emergent.
	4.	Integration and platform value

4.1 OS and platform agnostic fabric

With VEEN, a single set of logs can be:
	•	served by a hub running on a developer’s laptop under WSL2;
	•	later attached to a hub running in Docker or k8s in staging;
	•	finally mounted into a k3s or bare-metal cluster in production.

Semantics remain identical.

This decouples:
	•	“where do we run this?” from “what does it mean when a message is accepted?”;
	•	infra decisions from protocol design.

It also makes it easier to support hybrid:
	•	on-prem components;
	•	cloud components;
	•	regulated environments that demand specific OS or hypervisor configurations.

4.2 Multi-tenant and multi-realm by construction

Because identity and realms are derived from overlay state, VEEN is naturally suited for:
	•	multi-tenant SaaS;
	•	internal platforms with multiple business units;
	•	regulated scenarios where one fabric must enforce strong separation between orgs.

The same core can:
	•	serve multiple realms, each with its own authorities and hubs;
	•	enforce admission via cap_token chains specific to each realm;
	•	expose only aggregated or filtered views to certain users or services.

You get a multi-tenant-ready network substrate without having to bolt on tenancy after the fact.
	5.	Economic value

5.1 Reduced cost of outages and investigations

Outages and security incidents are expensive mainly because:
	•	systems are opaque;
	•	reconstructing state takes time;
	•	root cause analysis is uncertain.

VEEN lowers these costs by:
	•	making “what happened” reconstructible from logs alone;
	•	making “what should state be now?” a deterministic fold;
	•	avoiding silent drift between databases, caches, and logs.

Even if VEEN does not replace your primary brokers immediately, using it as a parallel fabric for critical traffic acts as an insurance policy against opacity and state drift.

5.2 Cheaper evolution and compliance

As regulations change, many organizations are forced to:
	•	redesign logging;
	•	retrofit audit capabilities;
	•	revalidate access and revocation behavior.

With VEEN:
	•	log structure and proofs already exist;
	•	admission policies are expressed as overlay events;
	•	new compliance requirements can often be met by adding overlays or anchoring strategies, not by reengineering infrastructure.

The long-term cost of regulatory adaptation is lowered, and future-proofing is improved.
	6.	When VEEN makes the most sense

VEEN is most valuable when at least one of the following is true:
	•	you operate multiple services and want a coherent, verifiable event history across them;
	•	you need strong, demonstrable auditability without running a blockchain;
	•	you are planning or running multi-region and DR setups, and want deterministic recovery;
	•	you expect to evolve semantics (billing, identity, quotas, CRDT state) over years without constantly migrating databases and brokers;
	•	you want to treat your network as something you can clone, fork, replay, and interpret, not as a fragile, permanently live structure.

If your environment is simple (a single monolith, a single database, minimal compliance), VEEN may be overkill.
If your environment is complex, multi-service, multi-tenant, or regulated, VEEN’s value compounds as complexity grows.
	7.	Summary

You should use VEEN when you want your network fabric to behave like:
	•	a reproducible, testable component with a written spec;
	•	a tamper-evident event ledger without the cost of global consensus;
	•	an ephemeral deployment surface (hubs) over a durable truth (logs);
	•	an integration spine where higher-level semantics are overlays, not hard-coded wiring.

In practical terms: VEEN lets you turn your network into something you can clone, fork, replay, and interpret, while keeping hubs disposable and overlays programmable. That combination is rare, and it directly translates into lower risk, clearer audits, safer evolution, and simpler disaster recovery.
