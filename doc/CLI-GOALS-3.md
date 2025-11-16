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
