# VEEN Usage Compendium

This guide collects end-to-end workflows for the VEEN binaries (`veen`, `veen-hub`, `veen-selftest`, `veen-bridge`). It keeps the commands in one place so operators can move between local development, containerised deployments, and Kubernetes without changing tooling.

## 1. Prerequisites and build

### Required packages
- Target OS: Ubuntu 22.04/24.04 (including WSL2)
- Dependencies: `build-essential pkg-config libssl-dev curl ca-certificates`

```shell
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl ca-certificates
```

### Rust toolchain
Use the pinned stable toolchain declared in `rust-toolchain.toml`:

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Build the workspace

```shell
cargo build --release
```

Outputs under `target/release/`:
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

Recommended directories:

```shell
sudo install -d -m 0750 /var/lib/veen
sudo install -d -m 0755 /etc/veen
sudo install -d -m 0750 /var/log/veen
```

## 2. Local developer quickstart

1. **Start a hub in the foreground**
   ```shell
   target/release/veen hub start \
     --listen 127.0.0.1:37411 \
     --data-dir /tmp/veen-hub \
     --foreground
   ```
   Stop with `Ctrl+C`. `--data-dir` accepts a local path or a `file://` URI.

2. **Generate a client identity**
   ```shell
   target/release/veen keygen --out /tmp/veen-client
   ```

3. **Send an encrypted message**
   ```shell
   target/release/veen send \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --body '{"text":"hello-veens"}'
   ```
   Prints the committed sequence number and stores a JSON bundle under the hub data dir.

4. **Stream and decrypt messages**
   ```shell
   target/release/veen stream \
     --hub /tmp/veen-hub \
     --client /tmp/veen-client \
     --stream core/main \
     --from 0
   ```
   Displays decrypted bodies, attachment metadata, and received sequence numbers. ACK state is maintained client-side.

5. **Inspect hub status and keys**
   ```shell
   target/release/veen hub status --hub /tmp/veen-hub
   target/release/veen hub key --hub /tmp/veen-hub
   ```

6. **Stop a background hub**
   ```shell
   target/release/veen hub stop --data-dir /tmp/veen-hub
   ```

## 3. Additional flows

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

## 4. Running with containers

Docker packaging persists hub data in a named volume.

1. **Build and start**
   ```shell
   docker compose up --build -d
   ```
   Listens on `0.0.0.0:37411` with `restart: unless-stopped`.

2. **Health and logs**
   ```shell
   docker compose logs -f hub
   docker compose ps
   ```
   A container healthcheck runs `veen hub health` internally.

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

## 5. Environment descriptors (`veen env`)

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

3. **Inspect**
   ```shell
   veen env show --env ~/.config/veen/demo.env.json
   veen env show --env ~/.config/veen/demo.env.json --json
   ```

Subsequent CLI calls can use `--env ~/.config/veen/demo.env.json --hub-name primary` to resolve service URLs and profile IDs automatically.

## 6. Kubernetes workflows (`veen kube`)

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

## 7. Verification and tests

- Run all unit tests: `cargo test --workspace`
- Self-test harness: `target/release/veen selftest core` / `props` / `fuzz` / `all`
- Overlay suites: `target/release/veen selftest federated` / `kex1` / `hardened` / `meta`

Temporary directories under `/tmp` are removed automatically on success or failure.

## 8. Common helper tools

- `Justfile` commands: `just ci` (fmt + clippy + test), `just fmt`, `just cli -- --help`
- Performance: `just perf -- "--requests 512 --concurrency 64"` (add `--mode http` for HTTP latency)

## 9. Further reading

- Protocol/overlay specs: `doc/spec-1.txt`–`spec-5.txt`, `doc/wallet-spec.txt`, `doc/products-spec-1.txt`
- CLI/OS goals: `doc/CLI-GOALS-1.txt`–`CLI-GOALS-3.txt`, `doc/OS-GOALS.txt`
- Design rationale: `doc/Design-Philosophy.txt`
