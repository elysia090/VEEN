# VEEN Usage Compendium

This is the “first hour” guide for the VEEN CLI and its companion binaries (`veen`, `veen-hub`, `veen-selftest`, `veen-bridge`). Follow the sections in order the first time you use VEEN, then dip back in as a reference for common tasks.

**Who is this for?**
- **First-time users:** start at “Before you begin”, then follow the Local developer quickstart exactly once end-to-end.
- **Returning operators:** skip straight to the command blocks you need; each block is self-contained.

**Reading tips**
- Commands written with `target/release/` assume you built locally. Drop the prefix when using packaged binaries or when already inside Docker/Kubernetes.
- Replace placeholders like `<PROFILE_ID>` with your own values. Flags in backticks are literal.
- Use temporary paths such as `/tmp/veen-hub` for experiments; for long-lived hubs see “Manual installation” for persistent directories.
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

When packaging for production hosts, prefer copying the four binaries into `/usr/local/bin` as a single step using your configuration manager (Ansible, Chef, etc.). All binaries are static and require no extra runtime dependencies beyond glibc and OpenSSL.

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

   The command creates `client.json` (public key material) and `client.secret.json` (private key). Keep the secret file outside version control and back it up securely.

3. **Send an encrypted message**
   ```shell
   target/release/veen send \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   ```
   Expected result: the terminal prints the committed sequence number and the hub writes a JSON bundle under the data directory. Add `--cap <PATH>` to attach a capability token or `--attachment <FILE>` to bundle binary payloads; each flag may be repeated. Errors such as `unable to open hub` usually mean the path after `--hub` is wrong or the hub from step 1 has stopped.

4. **Stream and decrypt messages**
   ```shell
   target/release/veen stream \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --from 0
   ```
   Displays decrypted bodies, attachment metadata, and received sequence numbers. ACK state is maintained client-side.

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
   This sends a shutdown signal to the backgrounded hub and waits for a clean exit.

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

- Protocol/overlay specs: `doc/spec-1.txt`–`spec-5.txt`, `doc/wallet-spec.txt`, `doc/products-spec-1.txt`
- CLI/OS goals: `doc/CLI-GOALS-1.txt`–`CLI-GOALS-3.txt`, `doc/OS-GOALS.txt`
- Design rationale: `doc/Design-Philosophy.txt`
