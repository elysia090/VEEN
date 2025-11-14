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

