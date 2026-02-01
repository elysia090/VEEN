# VEEN

Verifiable End-to-End Network (VEEN) is a Rust implementation of a privacy-
preserving messaging fabric with cryptographically enforced delivery
semantics. It enables auditable messaging streams, capability-based
authorization, and deterministic overlay schemas suitable for regulated and
multi-tenant environments. This repository hosts the full reference workspace,
including the core protocol primitives, the disposable hub runtime, and the CLI
used to drive end-to-end workflows.

### Key capabilities

- Cryptographic accountability for message delivery via receipts, checkpoints,
  and Merkle Mountain Range proofs.
- Disposable hubs that can be run locally, inside containers, or under
  Kubernetes with reproducible manifests.
- A single CLI (`veen`) that covers hub lifecycle management, client identity
  provisioning, overlay control (RPC, CRDT, wallet, schema), and self-testing.
- Deterministic schema and capability tooling to keep tenants, overlays, and
  ledger state auditable.

## Table of contents

- [Architecture overview](#architecture-overview)
- [Project status](#project-status)
- [Positioning and common use cases](#positioning-and-common-use-cases)
- [Security and audit properties](#security-and-audit-properties)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build the workspace](#build-the-workspace)
  - [Local developer quickstart](#local-developer-quickstart)
- [Comprehensive usage guide](#comprehensive-usage-guide)
- [Manual installation](#manual-installation)
- [Development workflow](#development-workflow)
- [Testing and verification](#testing-and-verification)
- [Further reading](#further-reading)

## Architecture overview

The workspace is organised as a set of crates that each focus on an aspect of
the VEEN protocol stack:

- [`crates/veen-core`](crates/veen-core) – deterministic primitives for
  identifiers, signatures, Merkle Mountain Range handling, capability tokens,
  and overlay schemas.
- [`crates/veen-hub`](crates/veen-hub) – disposable hub runtime responsible for
  accepting messages, committing receipts, emitting checkpoints, and serving
  HTTP APIs.
- [`crates/veen-cli`](crates/veen-cli) – produces the `veen` binary that drives
  hub lifecycle operations, client identity management, messaging flows,
  overlay control, and the self-test orchestration commands.
- [`crates/veen-selftest`](crates/veen-selftest) – houses automated acceptance
  checks and the goals executed by `veen selftest`.
- [`crates/veen-bridge`](crates/veen-bridge) – utilities for log replication
  scenarios and integration adapters.
- [`Justfile`](Justfile) – convenience recipes for formatting, linting, and
  running common developer commands.

### Reference specifications

The current release targets the v0.0.1 protocol suite described in the SSOT
specification document [`doc/spec.md`](doc/spec.md). Operational goals are
captured in [`doc/CLI-GOALS-1.txt`](doc/CLI-GOALS-1.txt) through
[`doc/CLI-GOALS-3.txt`](doc/CLI-GOALS-3.txt) and
[`doc/OS-GOALS.txt`](doc/OS-GOALS.txt). Compatibility and minimum supported
toolchain versions are pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

## Purpose and guaranteed properties

Use VEEN when you need a messaging surface that is cryptographically auditable
end-to-end, not merely log-based or broker-trusted. The stack is designed for
multi-tenant overlays where regulators or counterparties must reproduce state
independently. The implementation guarantees:

- **Deterministic reconstruction** – every overlay operation, schema change,
  and capability grant is encoded with deterministic identifiers so state can be
  replayed from receipts and checkpoints without access to the original hubs.
- **Cryptographic delivery proof** – messages are signed, folded into Merkle
  Mountain Ranges, and acknowledged with verifiable receipts, allowing third
  parties to assert that specific content was delivered (or detect its
  absence) without trusting operators.
- **Scoped blast radius** – disposable hubs, per-tenant namespaces, and
  capability-bound authorization keep failures or key compromises isolated to
  the affected overlay, while keeping audit evidence portable.
- **Reproducible deployment** – pinned toolchains, container images, and
  Kubernetes manifests ensure operators can attest to the exact bits running in
  production when presenting compliance evidence.

### Deduplication scope

The hub runtime performs message deduplication per stream. Submissions are
rejected as duplicates only when the same stream has already committed an
identical leaf hash. The runtime keys its deduplication cache on the tuple of
`(stream, leaf_hash)` so identical payloads in different streams are evaluated
independently.

### Stream index recovery behavior

Stream index files are append-only JSONL logs. On load, the hub tolerates
partial writes: a trailing line without a newline delimiter is ignored to avoid
ingesting half-written records. If a newline-delimited entry in the middle of
the file is malformed (invalid UTF-8 or JSON), the hub logs a warning and skips
that line while continuing to load the remaining entries.

## Project status

The v0.0.1 protocol release focuses on verifiable message delivery and overlay
support. Experimental features and incubating overlays are added behind feature
flags or scoped subcommands in the CLI. See [`doc/Design-Philosophy.txt`](doc/Design-Philosophy.txt)
for the guiding principles that shape stability decisions.

## Positioning and common use cases

- Serves as a verifiable alternative to ad-hoc queues or REST/RPC links when
  regulators and auditors need proofs of delivery rather than best-effort logs
  from brokers (Kafka/SQS/NATS) or application servers.
- Fits multi-tenant overlays where each stream must retain cryptographic
  provenance without sharing secrets across tenants, replacing bespoke
  message-wrapping layers.
- Provides a deterministic control surface for Kubernetes and containerised
  deployments so operators can reconstruct overlay state without relying on
  mutable control planes.
- Useful for compliance-sensitive workflows such as ledger replication,
  regulated data exchange between business units, and cross-organisation
  settlement and reporting flows.

## Security and audit properties

- **Provenance and integrity** – every message is signed by the sender, folded
  into a Merkle Mountain Range, and acknowledged with receipts and checkpoints
  so auditors can replay and independently verify the stream history.
- **Capability-based authorization** – access to overlays, streams, and schema
  operations is mediated by capabilities with deterministic identifiers and
  expiry/issuer metadata rather than mutable ACLs.
- **Tenant isolation** – hubs keep per-tenant namespaces and overlay schemas
  deterministic, making cross-tenant access visible in receipts while avoiding
  shared secrets across tenants.
- **Tamper evidence** – snapshot verification and state checkpoints expose any
  divergence between on-disk state and signed history, allowing third parties to
  detect manipulation without trusting hub operators.
- **Operational safeguards** – optional proof-of-work challenges, TLS support,
  and reproducible deployments (including Kubernetes manifests) reduce replay
  abuse, enforce transport security, and keep runtime configurations auditable.

## Getting started

### Prerequisites

The reference environment is Ubuntu 22.04/24.04 (including WSL2). Install the
system packages required for Rust builds:

```shell
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl ca-certificates
```

Install the stable Rust toolchain (the minimum supported version is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml)):

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Build the workspace

From the repository root, build the entire workspace in release mode:

```shell
cargo build --release
```

The build produces the following binaries under `target/release/`:

- `veen` – combined CLI for hub lifecycle, messaging, overlays, and self tests
- `veen-hub` – hub runtime (the `veen hub` subcommand delegates to this crate)
- `veen-selftest` – standalone test runner used by CI and by `veen selftest`
- `veen-bridge` – log replication helper used in extended scenarios

The `veen` CLI supports feature flags to trim heavy dependencies when you only
need a subset of commands:

- `hub` – enables hub lifecycle and tooling subcommands (and the runtime client
  types they rely on).
- `selftest` – enables the `veen selftest` command suite.
- `kube` – enables Kubernetes manifest rendering (`veen kube`).

By default all features are enabled. For a lighter client-only build, disable
defaults and add back the features you need, for example:

```shell
cargo build -p veen-cli --release --no-default-features --features hub
```

### Local developer quickstart

Use the commands below to spin up a disposable hub, generate credentials, and
exchange messages locally:

1. **Start a hub in the foreground**
   ```shell
   target/release/veen hub start \
     --listen 127.0.0.1:37411 \
     --data-dir /tmp/veen-hub \
     --foreground
   ```
   Leave this terminal running. Logs include the generated hub identifier and
   listen address. Use `Ctrl+C` to stop the hub when finished. Hub references
   passed to other commands accept either local data directories
   (`/tmp/veen-hub`, optionally prefixed with `file://`) or HTTP(S) endpoints
   when talking to a remote service.
2. **Generate a client identity** in a second terminal
   ```shell
   target/release/veen keygen --out /tmp/veen-client
   ```
3. **Send a message** to the hub
   ```shell
   target/release/veen send \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   ```
   The CLI persists a JSON message bundle under the hub data directory and
   prints the committed sequence number.
4. **Stream messages**
   ```shell
   target/release/veen stream \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --from 0
   ```
   Output includes the body, attachment metadata (if any), and the
   observed sequence numbers. Acknowledgement state is tracked in the client
   directory.
5. **Inspect hub status and keys**
   ```shell
   target/release/veen hub status --hub /tmp/veen-hub
   target/release/veen hub key --hub /tmp/veen-hub
   ```
6. **Stop the hub gracefully**
   - If you started the hub with `--foreground`, press `Ctrl+C`.
   - If you started it in the background (omit `--foreground`), run:
     ```shell
     target/release/veen hub stop --data-dir /tmp/veen-hub
     ```
     `hub stop` is only available on Unix-like hosts; on Windows, terminate the
     background process manually.

The same CLI also covers capability issuance/authorization, attachment
verification, resynchronisation, overlay management (RPC, CRDT, wallet,
revocation, schema), and TLS inspection. Run `veen --help` for the complete
command tree.

### Inspecting schema descriptors

The schema overlay exposes a lightweight registry served by hubs with the
META0+ feature flag enabled. After registering a descriptor with
`veen schema register`, use `veen schema show` to look up the authoritative
record and verify how the schema is being used:

```shell
target/release/veen schema show \
  --hub http://127.0.0.1:37411 \
  --schema-id <HEX32> \
  --json
```

The CLI renders the canonical identifier, name, version, documentation URL,
owner, publication timestamp, and any usage statistics (labels seen,
approximate counts, and last-seen timestamps). Supplying `--json` produces a
structured object that mirrors the hub response for automation pipelines.

### Handling proof-of-work challenges

Hubs may request a proof-of-work (PoW) cookie before accepting a submission.
The CLI exposes matching switches on `veen send` and `veen rpc call`:

- `--pow-difficulty <BITS>` – solve or supply a cookie that meets the given
  difficulty. When no other PoW options are supplied a random challenge is
  generated and solved locally.
- `--pow-challenge <HEX>` – reuse a hub-issued challenge (hex encoded) or
  provide your own when solving manually.
- `--pow-nonce <NONCE>` – send a pre-computed cookie. Combine this with the
  matching difficulty and challenge captured from the hub.

This flow allows operators to either have the CLI solve a PoW automatically or
to reuse a nonce received out-of-band from another system. Hub operators can
enforce PoW on the service side with `veen hub start --pow-difficulty` (or
`veen-hub run --pow-difficulty` when driving the runtime directly).

### Containerised deployment

This repository ships with Docker packaging that exposes the hub runtime via
`docker compose`. The compose definition now lives in
[`docker/docker-compose.yml`](docker/docker-compose.yml) so the repository
root stays focused on the Rust workspace. The image builds the audited binaries,
runs the hub as an unprivileged user, and persists receipts, payloads,
checkpoints, and state in a named volume so the event history remains available
for inspection.

1. **Build and start the hub**
   ```shell
   docker compose -f docker/docker-compose.yml up --build -d
   ```
   The service listens on `0.0.0.0:37411` by default, exports an HTTP health
   endpoint, and is configured with `restart: unless-stopped`.
2. **Check health or tail logs**
   ```shell
   docker compose -f docker/docker-compose.yml logs -f hub
   docker compose -f docker/docker-compose.yml ps
   ```
   A built-in healthcheck uses `veen hub health` against the container-local
   endpoint to confirm readiness.
3. **Run CLI workflows inside the container**
   Use the shared volume to keep client identities, receipts, and audit
   artefacts alongside the hub data:
   ```shell
   docker compose -f docker/docker-compose.yml run --rm hub veen keygen --out /var/lib/veen/clients/alice
   docker compose -f docker/docker-compose.yml exec hub veen send \
     --hub /var/lib/veen \
     --client /var/lib/veen/clients/alice \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   docker compose -f docker/docker-compose.yml exec hub veen stream \
     --hub /var/lib/veen \
     --client /var/lib/veen/clients/alice \
     --stream core/main \
     --from 0
  ```
  Shut the hub down with `docker compose -f docker/docker-compose.yml down`
  (add `--volumes` to remove the persisted audit log).

### Environment descriptors

`veen env` creates small JSON descriptors (`*.env.json`) that capture the
cluster context, namespace, and hub metadata for a deployment. This keeps hub
service URLs and profile identifiers in one place and allows other commands to
reuse them with `--env PATH --hub-name NAME` instead of pasting raw URLs.

1. **Initialise an environment** (creates `ROOT/demo.env.json`):
   ```shell
   veen env init \
     --root ~/.config/veen \
     --name demo \
     --cluster-context kind-demo \
     --namespace veen-tenant-demo \
     --description "demo tenant"
   ```
2. **Record hub endpoints and tenants** inside the descriptor:
   ```shell
   veen env add-hub \
     --env ~/.config/veen/demo.env.json \
     --hub-name primary \
     --service-url https://hub.demo.internal:8443 \
     --profile-id abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd
   veen env add-tenant \
     --env ~/.config/veen/demo.env.json \
     --tenant-id demo \
     --stream-prefix core \
     --label-class wallet
   ```
3. **Inspect the descriptor** with a human readable summary or the raw JSON:
   ```shell
   veen env show --env ~/.config/veen/demo.env.json
   veen env show --env ~/.config/veen/demo.env.json --json
   ```

Any CLI command that previously required `--hub URL` now accepts
`--env ~/.config/veen/demo.env.json --hub-name primary`; the CLI resolves the
service URL and profile identifier from the descriptor before connecting. This
makes it easy to reuse the same environment definition across `kube`, `op`, and
audit flows without duplicating connection details.

### Kubernetes workflows

`veen kube` renders deterministic manifests and applies them directly through
the Kubernetes API. The subcommands follow
[`doc/CLI-GOALS-3.txt`](doc/CLI-GOALS-3.txt) (Namespace/ServiceAccount/RBAC/
ConfigMap/Secret/Deployment/Service) and accept `--json` when structured output
is preferred.

- **Render manifests** referencing local configuration, environment overrides,
  and annotations:
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
- **Apply** the generated resources without invoking `kubectl`:
  ```shell
  target/release/veen kube apply --cluster-context kind-veens --file hub.yaml --wait-seconds 180
  ```
  The CLI prints the effective namespace and `veen-hub-NAMESPACE` DNS entry
  after waiting for ready replicas.
- **Dispatch disposable jobs** for ad-hoc messaging tasks inside the cluster
  (using mounted client and capability material, see
  [Disposable Jobs for client workflows](#disposable-jobs-for-client-workflows)):
  ```shell
  target/release/veen kube job send \
    --cluster-context kind-veens \
    --namespace veen-tenants \
    --hub-service veen-hub-alpha \
    --client-secret my-client-secret \
    --cap-secret my-cap-secret \
    --label core/main \
    --body '{"text":"hello-veens"}'
  target/release/veen kube job stream \
    --cluster-context kind-veens \
    --namespace veen-tenants \
    --hub-service veen-hub-alpha \
    --client-secret my-client-secret \
    --cap-secret my-cap-secret \
    --label core/main \
    --from 0
  ```
  Jobs use the same deterministic naming as deployments, mount secrets for
  client/cap state, and inherit the hub service DNS entry.
- **Operate deployed hubs** using the shared naming scheme:
  - `veen kube delete --cluster-context kind-veens --namespace veen-tenants --name alpha --purge-pvcs`
    removes the Deployment, Service, Role, RoleBinding, ServiceAccount, and PVCs
    (printing `already deleted` when nothing remains).
  - `veen kube status ... --json` reports desired/ready replicas, per-pod
    details, and `/healthz` probe results.
  - `veen kube logs` streams logs for all labelled pods or a single pod with
    `--since` and `--follow` filters.
  - `veen kube backup`/`veen kube restore` talk to the hub admin endpoints to
    persist snapshots to `file://` URIs, scale the deployment down, restore the
    data directory, and scale back up.

These commands keep hub manifests reproducible and remove the need for bespoke
shell wrappers when managing Kubernetes-native deployments. The rendered
manifests listen on port `8080` inside the cluster by default, matching the
probe and service configuration emitted by the CLI.

### Snapshot verification

The CLI can fold a stream's durable state and compare it to
`state.checkpoint.v1` messages to ensure the ledger has not been tampered with.
Use `veen snapshot verify` with the stream identifier, state metadata, and the
target sequence number from the checkpoint:

```shell
veen snapshot verify \
  --hub https://hub.example \
  --stream my/ledger \
  --state-class wallet.ledger \
  --state-id deadbeef... \
  --upto-stream-seq 42
```

The command prints the state hash, the MMR root for the requested prefix, and a
`consistent` flag in text or JSON (`--json`). When the computed values diverge
from the checkpoint, the output highlights the first mismatch so operators know
whether the ledger contents or the stream history failed verification.

Environment variables such as `VEEN_LISTEN`, `VEEN_LOG_LEVEL`, or
`VEEN_PROFILE_ID` can be overridden in `docker/docker-compose.yml` (or via
`docker compose run -e`) to adjust listening addresses, logging verbosity, or
profile identifiers. To supply a custom hub configuration file, mount it into
the container and set `VEEN_CONFIG_PATH` to the path inside the container.

#### Disposable Jobs for client workflows

The `veen kube job send` and `veen kube job stream` commands run the CLI inside
short-lived Kubernetes Jobs so operators can reuse Secrets that already hold
client identities. Each Job creates a single Pod that:

- mounts a client Secret specified via `--client-secret` (the Secret must
  contain `keystore.enc`, `identity_card.pub`, and optionally `state.json`)
- optionally mounts a capability Secret supplied with `--cap-secret` that holds
  a `cap.cbor` blob
- copies those files into `/var/lib/veen-client` (and `/var/lib/veen-cap` when a
  capability is present) so the container has a writable working directory
- runs the requested `veen send` or `veen stream` invocation inside the
  container image (defaults to `veen-cli:latest`, override with `--image`)
- streams pod logs back to the CLI until the Job succeeds or fails; the CLI
  exit code matches the Job completion state.

Persisting acknowledgement state between runs is supported by providing a PVC
name with `--state-pvc`. When omitted the CLI uses an `emptyDir` so state is
discarded with the Job. Arbitrary environment variables can be injected via
`--env-file` for cases where the CLI needs HTTP proxies or tracing tweaks.

Example: submit a message using a client Secret and a capability token secret:

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

Streaming messages with proofs uses the matching Job subcommand:

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

The CLI watches the Job status, relays pod logs (so payloads and
receipt summaries appear immediately), and returns a non-zero exit code when the
Job fails to complete successfully.

## Comprehensive usage guide

For an end-to-end catalogue of VEEN workflows—including container/Kubernetes
operations, PoW handling, snapshot verification, environment descriptors, and
commonly used helper commands—see [`doc/USAGE.md`](doc/USAGE.md).

## Manual installation

Install the binaries into a traditional Unix layout after building:

```shell
cargo build --release
sudo install -m 0755 target/release/veen /usr/local/bin/veen
sudo install -m 0755 target/release/veen-hub /usr/local/bin/veen-hub
sudo install -m 0755 target/release/veen-selftest /usr/local/bin/veen-selftest
sudo install -m 0755 target/release/veen-bridge /usr/local/bin/veen-bridge
```

Provision directories with safe permissions for persistent hub state and
configuration:

```shell
sudo install -d -m 0750 /var/lib/veen
sudo install -d -m 0755 /etc/veen
sudo install -d -m 0750 /var/log/veen
```

With the binaries on `PATH`, `veen --help` prints the full CLI surface and
exits with status 0, as required by OS-GOALS.

## Development workflow

Use the [`Justfile`](Justfile) to run common development tasks:

```shell
just ci            # fmt + clippy + cargo test --workspace
just fmt           # format the workspace in-place
just cli -- --help # run the veen binary directly from cargo
```

The workspace adheres to standard Rust tooling conventions. Formatting is
enforced by `rustfmt`, linting by `clippy`, and integration tests are executed
via `cargo test`.

The disposable performance harness can be launched with:

```shell
just perf -- "--requests 512 --concurrency 64"
```
By default it exercises an in-process hub; pass `--mode http` to measure
end-to-end HTTP request latencies.

## Testing and verification

- Run the Rust unit tests for the entire workspace:
  ```shell
  cargo test --workspace
  ```
- Execute the core self-test suite (starts disposable hubs on random ports):
  ```shell
  target/release/veen selftest core
  ```
- Run property-based checks directly:
  ```shell
  target/release/veen selftest props
  ```
- Exercise the wire-level fuzz tests:
  ```shell
  target/release/veen selftest fuzz
  ```
- Execute the aggregated core battery (core + props + fuzz):
  ```shell
  target/release/veen selftest all
  ```
- Exercise the v0.0.1+ overlay suites individually:
  ```shell
  target/release/veen selftest federated
  target/release/veen selftest kex1
  target/release/veen selftest hardened
  target/release/veen selftest meta
  ```
- Run the aggregated "plus" flow (core battery + overlays + lifecycle + meta):
  ```shell
  target/release/veen selftest plus
  ```

The self-test harness leaves temporary directories under `/tmp` and removes
them automatically on success or failure.

## Further reading

- [`doc/CLI-GOALS-1.txt`](doc/CLI-GOALS-1.txt),
  [`doc/CLI-GOALS-2.txt`](doc/CLI-GOALS-2.txt), and
  [`doc/CLI-GOALS-3.txt`](doc/CLI-GOALS-3.txt) – operational contract for the CLI
- [`doc/OS-GOALS.txt`](doc/OS-GOALS.txt) – host operating system expectations
- [`doc/Design-Philosophy.txt`](doc/Design-Philosophy.txt) – guiding principles
- [`doc/spec.md`](doc/spec.md) – SSOT for protocol and overlay specifications.
