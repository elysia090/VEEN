# VEEN

Verifiable End-to-End Network (VEEN) is a Rust implementation of a privacy-
preserving messaging fabric with cryptographically enforced delivery
semantics. This repository contains the full reference workspace, including the
core protocol primitives, the disposable hub runtime, and the CLI used to drive
end-to-end workflows.

The current release targets the v0.0.1 protocol suite described in
[`doc/spec-1.txt`](doc/spec-1.txt) through [`doc/spec-3.txt`](doc/spec-3.txt),
along with the operational requirements recorded in
[`doc/CLI-GOALS.txt`](doc/CLI-GOALS.txt) and
[`doc/OS-GOALS.txt`](doc/OS-GOALS.txt).

## Table of contents

- [Architecture overview](#architecture-overview)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build the workspace](#build-the-workspace)
  - [Local developer quickstart](#local-developer-quickstart)
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
   listen address. Use `Ctrl+C` to stop the hub when finished.
2. **Generate a client identity** in a second terminal
   ```shell
   target/release/veen keygen --out /tmp/veen-client
   ```
3. **Send an encrypted message** to the hub
   ```shell
   target/release/veen send \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   ```
   The CLI persists a JSON message bundle under the hub data directory and
   prints the committed sequence number.
4. **Stream and decrypt messages**
   ```shell
   target/release/veen stream \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --from 0
   ```
   Output includes the decrypted body, attachment metadata (if any), and the
   observed sequence numbers. Acknowledgement state is tracked in the client
   directory.
5. **Inspect hub status and keys**
   ```shell
   target/release/veen hub status --hub /tmp/veen-hub
   target/release/veen hub key --hub /tmp/veen-hub
   ```
6. **Stop the hub gracefully** when running in the background without
   `--foreground`
   ```shell
   target/release/veen hub stop --data-dir /tmp/veen-hub
   ```

The same CLI also covers capability issuance/authorisation, attachment
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
to reuse a nonce received out-of-band from another system.

### Containerised deployment

The repository ships with a Docker packaging that exposes the hub runtime via
`docker compose`. The image builds the audited binaries, runs the hub as an
unprivileged user, and persists receipts, payloads, checkpoints, and state in a
named volume so the event history remains available for inspection.

1. **Build and start the hub**
   ```shell
   docker compose up --build -d
   ```
   The service listens on `0.0.0.0:37411` by default, exports an HTTP health
   endpoint, and is configured with `restart: unless-stopped`.
2. **Check health or tail logs**
   ```shell
   docker compose logs -f hub
   docker compose ps
   ```
   A built-in healthcheck uses `veen hub health` against the container-local
   endpoint to confirm readiness.
3. **Run CLI workflows inside the container**
   Use the shared volume to keep client identities, receipts, and audit
   artefacts alongside the hub data:
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
   Shut the hub down with `docker compose down` (add `--volumes` to remove the
   persisted audit log).

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
shell wrappers when managing Kubernetes-native deployments.

Environment variables such as `VEEN_LISTEN`, `VEEN_LOG_LEVEL`, or
`VEEN_PROFILE_ID` can be overridden in `docker-compose.yml` (or via
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

The CLI watches the Job status, relays pod logs (so decrypted payloads and
receipt summaries appear immediately), and returns a non-zero exit code when the
Job fails to complete successfully.

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
just ci            # fmt + clippy + cargo test --all
just fmt           # format the workspace in-place
just cli -- --help # run the veen binary directly from cargo
```

The workspace adheres to standard Rust tooling conventions. Formatting is
enforced by `rustfmt`, linting by `clippy`, and integration tests are executed
via `cargo test`.

## Testing and verification

- Run the Rust unit tests for the entire workspace:
  ```shell
  cargo test --all
  ```
- Execute the core self-test suite (starts disposable hubs on random ports):
  ```shell
  target/release/veen selftest core
  ```
- Execute the full battery (core + overlays + fuzz/property checks):
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
- Run the aggregated "plus" flow (core + overlays + lifecycle + meta):
  ```shell
  target/release/veen selftest plus
  ```

The self-test harness leaves temporary directories under `/tmp` and removes
them automatically on success or failure.

## Further reading

- [`doc/CLI-GOALS.txt`](doc/CLI-GOALS.txt) – operational contract for the CLI
- [`doc/OS-GOALS.txt`](doc/OS-GOALS.txt) – host operating system expectations
- [`doc/Design-Philosophy.txt`](doc/Design-Philosophy.txt) – guiding principles
- [`doc/wallet-spec.txt`](doc/wallet-spec.txt) and related documents describing
  the overlay schemas layered on top of the VEEN core wire objects.
