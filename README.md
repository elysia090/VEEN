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

Environment variables such as `VEEN_LISTEN`, `VEEN_LOG_LEVEL`, or
`VEEN_PROFILE_ID` can be overridden in `docker-compose.yml` (or via
`docker compose run -e`) to adjust listening addresses, logging verbosity, or
profile identifiers. To supply a custom hub configuration file, mount it into
the container and set `VEEN_CONFIG_PATH` to the path inside the container.

### Kubernetes-native hub workflows

Use the `veen kube` command group to keep hub deployments reproducible on
Kubernetes:

1. **Render deterministic manifests** for a namespace and logical hub name.
   Output defaults to YAML and can be switched to JSON with `--json`.
   ```shell
   veen kube render \
     --cluster-context production \
     --namespace veen-prod \
     --name alpha \
     --image ghcr.io/veen/hub:latest \
     --data-pvc veen-hub-alpha-data \
     --config ./hub-config.toml \
     --resources-cpu 500m,1 \
     --resources-mem 512Mi,1Gi \
     > hub-alpha.yaml
   ```
2. **Apply manifests and wait for readiness** via the Kubernetes API. The CLI
   prints the namespace and service DNS name once the rollout completes.
   ```shell
   veen kube apply --cluster-context production --file hub-alpha.yaml --wait-seconds 120
   ```
3. **Inspect status or stream logs**. `veen kube status` queries the
   Deployment/StatefulSet and pod `/healthz` probes, while `veen kube logs`
   streams one or all pods with `--follow` and the `--since` window.
   ```shell
   veen kube status --cluster-context production --namespace veen-prod --name alpha --json
   veen kube logs --cluster-context production --namespace veen-prod --name alpha --since 30m
   ```
4. **Back up and restore state** through the in-cluster Service endpoint.
   Backups call `/admin/backup` and emit the profile identifier plus the latest
   stream/mmr roots. Restores replay `/admin/restore` and verify the reported
   observability data after the hub becomes healthy.
   ```shell
   veen kube backup \
     --cluster-context production \
     --namespace veen-prod \
     --name alpha \
     --snapshot-name nightly-2024-08-30 \
     --target-uri s3://backups/veen/alpha

   veen kube restore \
     --cluster-context production \
     --namespace veen-prod \
     --name alpha \
     --snapshot-name nightly-2024-08-30 \
     --source-uri s3://backups/veen/alpha
   ```
5. **Delete workloads** with `veen kube delete --purge-pvcs` when recycling a
   hub. The command is idempotent and reports whether resources already
   disappeared.

Every manifest emitted by the renderer carries the `app=veen-hub` and
`veen.hub.name=<NAME>` labels so selectors remain consistent across the
`render`, `apply`, `status`, `logs`, `backup`, and `restore` workflows.

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
