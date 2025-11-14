# VEEN

This repository hosts the Rust workspace for the Verifiable End-to-End Network
(VEEN) reference implementation.  It implements the v0.0.1 protocol suite
captured in [`doc/spec-1.txt`](doc/spec-1.txt) through
[`doc/spec-3.txt`](doc/spec-3.txt) together with the operational expectations in
[`doc/CLI-GOALS.txt`](doc/CLI-GOALS.txt) and [`doc/OS-GOALS.txt`](doc/OS-GOALS.txt).

## Workspace layout

- [`crates/veen-core`](crates/veen-core) contains deterministic primitives for
  identifiers, signatures, Merkle Mountain Range handling, capability tokens,
  and overlay schemas.
- [`crates/veen-hub`](crates/veen-hub) provides the disposable hub runtime that
  accepts messages, commits receipts, emits checkpoints, and serves HTTP APIs.
- [`crates/veen-cli`](crates/veen-cli) builds the single `veen` binary that
  drives hub lifecycle, client identity management, messaging flows, overlays,
  and the self-test orchestration commands.
- [`crates/veen-selftest`](crates/veen-selftest) packages end-to-end goals used
  by `veen selftest` and automated acceptance checks.
- [`crates/veen-bridge`](crates/veen-bridge) contains helper utilities for log
  replication scenarios.
- [`Justfile`](Justfile) offers convenience wrappers for formatting, linting,
  and running the workspace binaries.

## Prerequisites

The reference environment is Ubuntu 22.04/24.04 (including WSL2).  Install the
system packages required for Rust builds:

```shell
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl ca-certificates
```

Install the stable Rust toolchain (minimum version is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml)):

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## Building

From the repository root build the entire workspace:

```shell
cargo build --release
```

The command produces the following binaries under `target/release/`:

- `veen` – combined CLI for hub lifecycle, messaging, overlays, and self tests
- `veen-hub` – hub runtime (the `veen hub` subcommand delegates to this crate)
- `veen-selftest` – standalone test runner used by CI and by `veen selftest`
- `veen-bridge` – log replication helper used in extended scenarios

The `Justfile` mirrors common tasks:

```shell
just ci       # fmt + clippy + cargo test --all
just fmt      # format the workspace in-place
just cli -- --help  # run the veen binary directly from cargo
```

## Manual installation

To install the binaries into a traditional Unix layout:

```shell
cargo build --release
sudo install -m 0755 target/release/veen /usr/local/bin/veen
sudo install -m 0755 target/release/veen-hub /usr/local/bin/veen-hub
sudo install -m 0755 target/release/veen-selftest /usr/local/bin/veen-selftest
sudo install -m 0755 target/release/veen-bridge /usr/local/bin/veen-bridge
```

Create the standard directories with safe permissions:

```shell
sudo install -d -m 0750 /var/lib/veen
sudo install -d -m 0755 /etc/veen
sudo install -d -m 0750 /var/log/veen
```

With the binaries on `PATH`, `veen --help` prints the full CLI surface and
exits with status 0 as required by OS-GOALS.

## Local developer quickstart

1. **Build the workspace** (if not already built):
   ```shell
   cargo build --release
   ```
2. **Start a hub in the foreground**:
   ```shell
   target/release/veen hub start \
     --listen 127.0.0.1:37411 \
     --data-dir /tmp/veen-hub \
     --foreground
   ```
   Leave this terminal running.  Logs include the generated hub identifier and
   the listen address.  Use `Ctrl+C` to stop the hub when finished.
3. **Generate a client identity** in a second terminal:
   ```shell
   target/release/veen keygen --out /tmp/veen-client
   ```
4. **Send an encrypted message** to the hub:
   ```shell
   target/release/veen send \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   ```
   The CLI persists a JSON message bundle under the hub data directory and
   prints the committed sequence number.
5. **Stream and decrypt messages**:
   ```shell
   target/release/veen stream \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --from 0
   ```
   Streaming output includes the decrypted body, attachment metadata (if any),
   and the observed sequence numbers.  The command tracks acknowledgement state
   in the client directory.
6. **Inspect hub status and keys**:
   ```shell
   target/release/veen hub status --hub /tmp/veen-hub
   target/release/veen hub key --hub /tmp/veen-hub
   ```
7. **Stop the hub gracefully** (from another terminal) if you started it in the
   background without `--foreground`:
   ```shell
   target/release/veen hub stop --data-dir /tmp/veen-hub
   ```

The same CLI handles capability issuance/authorisation, attachment verification,
resynchronisation, overlay management (RPC, CRDT, wallet, revocation, schema),
and TLS inspection.  See `veen --help` for the full command tree.

## Self tests and verification

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

The self-test harness leaves temporary directories under `/tmp` and removes
them automatically on success or failure.

## Further reading

- [`doc/CLI-GOALS.txt`](doc/CLI-GOALS.txt) – operational contract for the CLI
- [`doc/OS-GOALS.txt`](doc/OS-GOALS.txt) – host operating system expectations
- [`doc/Design-Philosophy.txt`](doc/Design-Philosophy.txt) – guiding principles
- [`doc/wallet-spec.txt`](doc/wallet-spec.txt) and related documents cover the
  overlay schemas layered on top of the VEEN core wire objects.
