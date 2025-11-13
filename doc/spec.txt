Verifiable End-to-End Network (VEEN) v0.0.1 — Core plus Operational and Upper-Layer Profiles (wire format unchanged)
	0.	Scope
Endpoints hold semantics and cryptography; the hub provides ordering and reachability only. Accepted messages yield signed receipts and are committed into an append-only MMR with logarithmic inclusion proofs. Authority is carried by portable capability tokens. Transport is abstract (HTTP, QUIC, NATS, file). This document restates the immutable v0.0.1 core succinctly and adds operational and upper-layer profiles that do not modify the wire format.
	1.	Notation
Byte concatenation is ||. u64be(n) is the 8-byte big-endian encoding of n. H is SHA-256. HKDF is HKDF-SHA256. AEAD is XChaCha20-Poly1305 (24-byte nonce). Ed25519 for signatures; X25519 for DH. HPKE is RFC 9180 base mode: KEM X25519HKDF-SHA256, KDF HKDF-SHA256, AEAD ChaCha20-Poly1305, exporter used. Ht(tag,x)=H(ascii(tag)||0x00||x). Deterministic CBOR: maps with the exact field order listed; minimal-length unsigned integers; definite-length arrays/byte strings only; no floats, no CBOR tags; fixed-length bstr are exact size; unknown keys rejected.
	2.	Cryptographic profile
profile = { aead:“xchacha20poly1305”, kdf:“hkdf-sha256”, sig:“ed25519”, dh:“x25519”, hpke_suite:“X25519-HKDF-SHA256-CHACHA20POLY1305”, epoch_sec:60, pad_block:0, mmr_hash:“sha256” }
profile_id = Ht(“veen/profile”, CBOR(profile))
Every MSG carries profile_id; receivers MAY reject unknown profile_id. Changing any field changes profile_id.
	3.	Keys and identities
Clients hold id_sign (Ed25519) and id_dh (X25519). Prekeys are X25519 pubkeys signed by id_sign. client_id in MSG is an Ed25519 public key verifying MSG.sig; rotate at least per epoch when epoch_sec>0, else after at most M messages (RECOMMENDED M=256). Long-term identity, if needed, is referenced inside payload via cap_ref, never in plaintext fields. hub_pk is distributed out of band and SHOULD be pinned.
	4.	Streams and labels
stream_id is 32 bytes (e.g., H(app name)). For epoch E=floor(unix_time/epoch_sec) when epoch_sec>0 else 0,
label = Ht(“veen/label”, routing_key || stream_id || u64be(E))
Hub orders by label and learns neither stream_id nor routing_key. Receivers SHOULD accept E−1..E+1 when epoch_sec>0.
	5.	Wire objects (immutable core)
MSG fields (in order): ver=1, profile_id:32, label:32, client_id:32, client_seq:uint (strict +1 per client_id per label), prev_ack:uint, auth_ref?:32, ct_hash:32, ciphertext:bstr, sig:64 over Ht(“veen/sig”, CBOR(MSG without sig)).
Ciphertext formation: (enc,ctx)=HPKE.SealSetup(pkR); hpke_ct_hdr=HPKE.Seal(ctx,””,CBOR(payload_hdr)); k_body=HPKE.Export(ctx,“veen/body-k”,32); nonce=Trunc_24(Ht(“veen/nonce”, label||u64be(prev_ack)||client_id||u64be(client_seq))); aead_ct_body=AEAD_Encrypt(k_body,nonce,””,body); ciphertext=enc||hpke_ct_hdr||aead_ct_body; if pad_block>0, right-pad with zero bytes before ct_hash; ct_hash=H(ciphertext). leaf_hash=Ht(“veen/leaf”, label||profile_id||ct_hash||client_id||u64be(client_seq)); msg_id=leaf_hash.
RECEIPT fields: ver=1, label:32, stream_seq:uint, leaf_hash:32, mmr_root:32, hub_ts:uint, hub_sig:64 over Ht(“veen/sig”, CBOR(RECEIPT without hub_sig)).
CHECKPOINT fields: ver=1, label_prev:32, label_curr:32, upto_seq:uint, mmr_root:32, epoch:uint, hub_sig:64, witness_sigs?:[64].
	6.	Payload header (encrypted, hub-blind)
CBOR(payload_hdr) first inside ciphertext and AEAD-authenticated. Fields: schema:32, parent_id?:32, att_root?:32, cap_ref?:32, expires_at?:uint.
	7.	Hub commitment (MMR)
Per label maintain (seq,peaks). Append x: seq+=1; fold with Ht(“veen/mmr-node”,left||right) along trailing zeros; mmr_root=Ht(“veen/mmr-root”, peaks[0]||…||peaks[k−1]) or the single peak form; emit RECEIPT.
	8.	Inclusion proof
mmr_proof CBOR {ver:1, leaf_hash:32, path:[{dir:0|1, sib:32}…], peaks_after:[32…]}. Verification folds to mmr_root.
	9.	Client algorithms
Send: build payload_hdr/att_root; form ciphertext and ct_hash; sign MSG; submit; on RECEIPT verify hub_sig, check invariants I1..I10, advance local MMR, set prev_ack=stream_seq; rekey per receipt s: rk_next=HKDF(rk,“veen/rk”||u64be(s)); derive send/recv; refresh HPKE at least once per epoch or every M messages. Receive: verify hub_sig; check invariants; update local MMR; decrypt; deliver; accept E−1..E+1.
	10.	Attachments
For attachment i: k_att=HPKE.Export(ctx,“veen/att-k”||u64be(i),32); n_att=Trunc_24(Ht(“veen/att-nonce”, msg_id||u64be(i))); c=AEAD_Encrypt(k_att,n_att,””,b); coid=H(c); att_root is Merkle root with Ht(“veen/att-node”,left||right) and Ht(“veen/att-root”,peak1||…).
	11.	Capability tokens and admission
cap_token CBOR {ver:1, issuer_pk:32, subject_pk:32, allow:{stream_ids:[32], ttl:uint, rate?:{per_sec:uint, burst:uint}}, sig_chain:[64…]}. Each link signs Ht(“veen/cap-link”, issuer_pk||subject_pk||CBOR(allow)||prev_link_hash), prev=32 zero bytes at root. auth_ref=Ht(“veen/cap”, CBOR(cap_token)). Hub MAY enforce admission via /authorize.
	12.	Invariants (MUST on accepted (RECEIPT,MSG))
I1 H(ciphertext)=ct_hash
I2 leaf_hash=Ht(“veen/leaf”, label||profile_id||ct_hash||client_id||u64be(client_seq))
I3 mmr_root equals MMR append at stream_seq
I4 profile_id supported
I5 if att_root exists, it matches the set of coids
I6 prev_ack <= last observed stream_seq
I7 capability constraints via auth_ref/cap_ref hold at acceptance
I8 within a label, (client_id,client_seq) unique
I9 client_seq increases by exactly 1 per client_id per label
I10 CBOR determinism: exact keys, order, minimal integers, exact bstr sizes
	13.	Errors
E.SIG, E.SIZE, E.SEQ, E.CAP, E.AUTH, E.RATE, E.PROFILE, E.DUP, E.TIME. Response body CBOR {code:“E.*”, detail?:text}.
	14.	Security properties (informal)
E2E confidentiality by HPKE+AEAD; authenticity/integrity by Ed25519; append-only by MMR receipts; public equivocation proofs; routing privacy by pseudorandom labels and client_id rotation; cross-stream replay prevented by leaf binding to label/profile_id; nonce uniqueness by construction; length-hiding via pad_block.
	15.	Portability
Portable WORM set: identity_card(pub), keystore.enc, routing_secret, receipts.cborseq, checkpoints.cborseq, payloads.cborseq, sync_state={last_stream_seq,last_mmr_root}, cap_tokens, optional attachments by coid. CBOR Sequence per RFC 8742.
	16.	API surface (transport-agnostic)
submit: POST CBOR(MSG)->CBOR(RECEIPT)
stream: GET label, from=stream_seq[, with_proof=bool]->CBOR Sequence of {RECEIPT,MSG,optional mmr_proof}
checkpoint_latest: GET label->CHECKPOINT
checkpoint_range: GET epoch range->sequence of CHECKPOINT
authorize: POST CBOR(cap_token)->{auth_ref:32, expires_at:uint}
report_equivocation: POST two RECEIPTs with identical (label,stream_seq)->ok
	17.	Complexity
Hub append amortized O(1) time and O(log N) memory; proofs O(log N); client hot paths O(1).
	18.	Interop discipline
Exact map order; unknown keys rejected; minimal unsigned ints; exact-size bstr; peaks ordered by increasing tree size; tag prefix “veen/”; pad included in ct_hash; hubs sign after MMR update; clients verify hub_sig before decryption.
	19.	Limits (defaults, configurable)
MAX_MSG_BYTES=1_048_576; MAX_BODY_BYTES=1_048_320; MAX_HDR_BYTES=16_384; MAX_PROOF_LEN=64; MAX_CAP_CHAIN=8; MAX_ATTACHMENTS_PER_MSG=1024; CLOCK_SKEW_EPOCHS=1. Exceeding yields E.SIZE.
	20.	Conformance vectors
A: single writer; B: multi-writer uniqueness/replay; C: epoch roll and checkpoint chaining; D: capability admission.
	21.	Operational Profile OP0 (normative, no wire changes)
OP0.1 Processing order (hub): decode CBOR -> bounds -> verify MSG.sig -> authorize via auth_ref (if configured) -> MMR append -> sign RECEIPT -> respond. On HTTP map E.SIZE->413, E.RATE->429, E.AUTH/E.CAP->403, E.PROFILE/E.TIME->400, E.SIG/E.SEQ/E.DUP->409.
OP0.2 Admission gating: hubs SHOULD require /authorize for write access. Authorization record keyed by auth_ref contains {allowed_stream_ids, rate:{per_sec,burst}, expiry, subject_pk}. Missing record yields E.AUTH; expired yields E.CAP; rate overflow yields E.RATE.
OP0.3 Rate limiting RL0: token bucket per (auth_ref, label) and optionally per IP. Each receipt consumes 1 token. Refill every 1s by per_sec up to burst. Servers SHOULD emit Retry-After in seconds on E.RATE.
OP0.4 Worker pools: split verification pool (Ed25519) and commitment pool (MMR). Back-pressure by 503 when verification queue > Qmax.
OP0.5 Storage: append-only files receipts.cborseq, payloads.cborseq, checkpoints.cborseq with fsync policy: sync every N=100 receipts or T=100ms, whichever first. Peaks checkpointed every K appends.
OP0.6 Padding policy: pad_block∈{0,256,1024}. Default 256 for messaging; 0 for bulk ingest. Padding bytes are zeros; included in ct_hash.
OP0.7 Clock discipline: hub_ts is informational; acceptance window uses CLOCK_SKEW_EPOCHS; large drift should be surfaced via E.TIME and metrics.
	22.	Key Distribution Profile KEX0 (normative optional)
KEX0.1 Hub key pin: applications ship hub_pk out of band. Rotation window W: during W, CHECKPOINTs carry witness_sigs by old and new hub keys. After W, old key retired.
KEX0.2 Client identity rotation: client_id rotates at least per epoch; key continuity is local only and never exposed in plaintext. Prekeys are signed by id_sign; include expiry.
KEX0.3 Revocation: hubs MAY blacklist client_id or auth_ref; subsequent submits return E.CAP or E.AUTH. Blacklist entries expire or require manual clear.
	23.	Resynchronization and Recovery RESYNC0
RESYNC0.1 Duplicate detection: hubs keep a Bloom+LRU of recent leaf_hash for E.DUP with window Wdup configurable; authoritative check remains the label’s accepted set.
RESYNC0.2 Client resync: clients reconnect with stream?from=last_stream_seq+1; verify hub_sig and inclusion proofs if present; on divergence, request checkpoint_latest and rebuild local peaks.
RESYNC0.3 Rekey: failure to progress prev_ack across R attempts triggers HPKE refresh and prekey fetch.
RESYNC0.4 Durable state: clients persist {rk,current profile_id,last_stream_seq,last_mmr_root}.
	24.	RPC Overlay RPC0 (pure overlay, no wire changes)
RPC0.1 Request message: payload_hdr.schema=H(“rpc.v1”); payload body {method:text, args:CBOR, timeout_ms:uint?, reply_to?:bstr(32)}. msg_id acts as correlation id; servers reply with parent_id=msg_id.
RPC0.2 Reply message: payload_hdr.schema=H(“rpc.res.v1”); body {ok:bool, result?:CBOR, error?:{code:text, detail?:text}}.
RPC0.3 Idempotency: clients MAY set body.idem:u64; servers MUST treat (client_id, idem) as idempotency key per method.
RPC0.4 Timeouts and retries: retry with exponential backoff; duplicates are harmless due to E.DUP and idempotency key.
	25.	CRDT Overlay CRDT0 (pure overlay)
CRDT0.1 LWW-Register: schema=H(“crdt.lww.v1”); body {key:bytes, ts:u64, value:bytes}. Total order by stream_seq breaks ties; app clocks optional.
CRDT0.2 OR-Set: schema=H(“crdt.orset.v1”); add {id:32, elem:bytes}; remove {tomb:[32…]}. Concurrency resolved by presence of add id not tombstoned.
CRDT0.3 Counter G-Counter: schema=H(“crdt.gcnt.v1”); body {shard:client_id, delta:u64}. Reduction is sum per shard. Snapshots are deterministic folds of receipts up to upto_seq.
CRDT0.4 Provenance: att_root commits any large element payloads; verification requires recomputing coid set.
	26.	Anchoring and Bridging ANCHOR0 (pure overlay)
ANCHOR0.1 External anchor interface: anchor_publish(root:32, epoch:uint, ts:uint, nonce:bytes)->anchor_ref:bytes; anchor_verify(root,anchor_ref)->bool. Implementations map to a ledger of choice.
ANCHOR0.2 Policy: hubs SHOULD anchor mmr_root at fixed cadence (e.g., every K receipts or every T minutes). Store anchor_ref alongside CHECKPOINT.
ANCHOR0.3 Cross-hub mirroring: a bridge process subscribes to stream(with_proof=1) on hub A and submits those MSG to hub B under label’ with a distinct routing_key’. Receipts from B include new leaf_hash; provenance is preserved by embedding parent_id=original msg_id.
	27.	Observability OBS0
OBS0.1 Metrics (names and units): veen_submit_ok_total, veen_submit_err_total{code}; veen_verify_latency_ms, veen_commit_latency_ms, veen_end_to_end_latency_ms; veen_queue_depth; veen_rate_limited_total; veen_checkpoint_interval; veen_anchor_fail_total.
OBS0.2 Logs: structured JSON per submit with fields {label, client_id_prefix, stream_seq, leaf_hash_prefix, code?, bytes_in, bytes_out, verify_ms, commit_ms}.
OBS0.3 Health: /healthz returns {ok:bool, profile_id, peaks_count, last_stream_seq, last_mmr_root}.
	28.	Compliance and Retention COMP0
COMP0.1 Retention: receipts.cborseq retained for Rr days; payloads.cborseq for Rp; checkpoints.cborseq forever or anchored. Rotation by size or time, with index sidecar {offset,stream_seq}.
COMP0.2 Encryption at rest: keystore.enc MAY be sealed with OS KMS; payloads/receipts MAY be whole-file AEAD; not visible to the hub protocol.
COMP0.3 Access: read-only export endpoints stream?with_proof=1 for auditors; rate-limited and signed URLs or mTLS.
	29.	Security Hardening SH0
SH0.1 Prefilter: optional stateless cookie (QUIC-token-like) or proof-of-work salt before signature verification during overload.
SH0.2 Constant-time checks: Ed25519 verify MUST be constant-time; string/bytes compares on auth_ref MUST use constant-time equality.
SH0.3 TLS: modern cipher suites; enforce AEAD; disable compression.
SH0.4 Bounds first: all size checks before signature or HPKE work.
	30.	Deployment Reference DR0
HTTP content-type application/cbor for all posts; stream returns application/cbor-seq. QUIC maps endpoints 1:1. NATS: subject submit.<label_hex>; replies carry RECEIPT as CBOR.
	31.	Test Suite TS0
TS0.1 Unit: vectors A–D; CBOR determinism; nonce uniqueness; E.* mappings. TS0.2 Property: MMR associativity; proof minimality; duplicate rejection. TS0.3 Fuzz: malformed CBOR maps (unknown keys, overlong ints). TS0.4 Interop: cross-implementation exchange of A–D with byte-for-byte equality on MSG/RECEIPT and identical mmr_root.
	32.	Reference state machines (informative)
Hub RX: Idle -> DecodeOK? else E.SIZE -> BoundsOK? else E.SIZE -> SigOK? else E.SIG -> Authorized? else E.AUTH/E.CAP/E.RATE -> Commit -> Sign -> Respond.
Client TX: Build -> HPKE/AEAD -> Sign -> Submit -> ReceiptOK? retry/backoff else -> Verify+Advance -> Done.
Client RX: ReceiptOK? else drop -> Verify root/proof -> Decrypt -> Deliver.
	33.	Compatibility
All OP0/KEX0/RESYNC0/RPC0/CRDT0/ANCHOR0/OBS0/COMP0/SH0/DR0/TS0 clauses are additive and do not change the v0.0.1 wire format (sections 5–8). Implementations MAY claim “VEEN v0.0.1 Core + OP0” or “VEEN v0.0.1 Core + OP0 + RPC0 + CRDT0”, etc.
	34.	Summary
This consolidation keeps v0.0.1 bytes on the wire intact and specifies the missing operational edges (admission, rate, rotation, recovery), plus portable overlays for RPC, CRDT, and external anchoring. A compliant “Core + OP0” hub and client can be deployed immediately for E2E-encrypted, verifiable messaging and audit logging; overlays can be enabled incrementally without re-encoding messages.
