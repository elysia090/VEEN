use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ciborium::{de::from_reader, ser::into_writer};
use ed25519_dalek::{Signer, SigningKey};

use anyhow::{anyhow, bail, ensure, Context, Result};
use rand::rngs::OsRng;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::Digest;
use tempfile::TempDir;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{self, AsyncRead, AsyncWriteExt};
use tokio::process::{Child, Command as TokioCommand};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::warn;

use veen_core::label::Label;
use veen_core::wire::checkpoint::{Checkpoint, CHECKPOINT_VERSION};
use veen_core::wire::mmr::Mmr;
use veen_core::wire::types::{LeafHash, MmrRoot, Signature64};
use veen_hub::pipeline::{HubStreamState, StoredMessage, StreamMessageWithProof};
use veen_hub::storage::HUB_PID_FILE;

const HUB_HEALTH_MAX_ATTEMPTS: usize = 120;
const HUB_HEALTH_RETRY_DELAY_MS: u64 = 250;
const REPLICATION_MAX_ATTEMPTS: usize = 120;
const REPLICATION_RETRY_DELAY_MS: u64 = 250;
const HUB_KEY_VERSION: u8 = 1;

#[derive(Clone)]
struct BinaryPaths {
    hub: PathBuf,
    cli: PathBuf,
    bridge: PathBuf,
}

impl BinaryPaths {
    fn discover() -> Result<Self> {
        let exe = std::env::current_exe().context("locating current executable")?;
        let mut dir = exe
            .parent()
            .ok_or_else(|| anyhow!("selftest binary has no parent directory"))?
            .to_path_buf();
        if dir.ends_with("deps") {
            dir.pop();
        }
        let hub = dir.join(format!("veen-hub{}", std::env::consts::EXE_SUFFIX));
        let cli = dir.join(format!("veen{}", std::env::consts::EXE_SUFFIX));
        let bridge = dir.join(format!("veen-bridge{}", std::env::consts::EXE_SUFFIX));
        ensure_binary(&hub, "veen-hub", "veen-hub")?;
        ensure_binary(&cli, "veen-cli", "veen")?;
        ensure_binary(&bridge, "veen-bridge", "veen-bridge")?;
        if !hub.exists() {
            bail!("expected hub binary at {}", hub.display());
        }
        if !cli.exists() {
            bail!("expected cli binary at {}", cli.display());
        }
        if !bridge.exists() {
            bail!("expected bridge binary at {}", bridge.display());
        }
        Ok(Self { hub, cli, bridge })
    }
}

fn ensure_binary(path: &Path, crate_name: &str, bin_name: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg(crate_name)
        .arg("--bin")
        .arg(bin_name)
        .status()
        .with_context(|| format!("building {crate_name} binary"))?;
    if !status.success() {
        bail!("cargo build --bin {crate_name} failed with status {status}");
    }
    Ok(())
}

struct ManagedProcess {
    name: String,
    child: Child,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
    stdout_task: Option<JoinHandle<Result<()>>>,
    stderr_task: Option<JoinHandle<Result<()>>>,
}

impl ManagedProcess {
    async fn terminate(mut self) -> Result<()> {
        let mut forced = false;
        if self.child.try_wait()?.is_none() {
            self.child.start_kill()?;
            forced = true;
        }
        let status = self.child.wait().await.context("awaiting process exit")?;
        if let Some(task) = self.stdout_task.take() {
            task.await
                .context("joining stdout task")?
                .context("propagating stdout task error")?;
        }
        if let Some(task) = self.stderr_task.take() {
            task.await
                .context("joining stderr task")?
                .context("propagating stderr task error")?;
        }
        if !status.success() && !forced {
            bail!(
                "process {} exited with status {status:?}; see {} and {}",
                self.name,
                self.stdout_log.display(),
                self.stderr_log.display()
            );
        }
        Ok(())
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

pub struct IntegrationHarness {
    bins: BinaryPaths,
    scratch: TempDir,
    logs_dir: PathBuf,
    http: Client,
}

impl IntegrationHarness {
    pub async fn new() -> Result<Self> {
        let bins = BinaryPaths::discover()?;
        let scratch = TempDir::new().context("creating integration harness tempdir")?;
        let logs_dir = scratch.path().join("logs");
        fs::create_dir_all(&logs_dir)
            .await
            .context("creating harness log directory")?;
        Ok(Self {
            bins,
            scratch,
            logs_dir,
            http: Client::new(),
        })
    }

    pub fn base_dir(&self) -> &Path {
        self.scratch.path()
    }

    pub async fn run_core_suite(&mut self) -> Result<()> {
        let hub = self
            .spawn_hub("core-hub", HubRole::Primary, &[])
            .await
            .context("spawning primary hub process")?;

        self.wait_for_health(hub.listen).await?;

        let hub_url = format!("http://{}", hub.listen);
        let client_dir = self.base_dir().join("client-core");
        let admin_dir = self.base_dir().join("admin-core");
        fs::create_dir_all(&client_dir)
            .await
            .context("creating client directory")?;
        fs::create_dir_all(&admin_dir)
            .await
            .context("creating admin directory")?;

        self.run_cli_success(
            vec![
                OsString::from("keygen"),
                OsString::from("--out"),
                client_dir.as_os_str().to_os_string(),
            ],
            "generating client identity",
        )
        .await?;

        self.run_cli_success(
            vec![
                OsString::from("keygen"),
                OsString::from("--out"),
                admin_dir.as_os_str().to_os_string(),
            ],
            "generating admin identity",
        )
        .await?;

        let send_output = self
            .run_cli_success(
                vec![
                    OsString::from("send"),
                    OsString::from("--hub"),
                    OsString::from(&hub_url),
                    OsString::from("--client"),
                    client_dir.as_os_str().to_os_string(),
                    OsString::from("--stream"),
                    OsString::from("core/main"),
                    OsString::from("--body"),
                    OsString::from(r#"{"text":"hello-veens"}"#),
                ],
                "sending integration message",
            )
            .await?;
        let _seq = parse_send_sequence(&send_output.stdout)?;

        let stream_output = self
            .run_cli_success(
                vec![
                    OsString::from("stream"),
                    OsString::from("--hub"),
                    OsString::from(&hub_url),
                    OsString::from("--client"),
                    client_dir.as_os_str().to_os_string(),
                    OsString::from("--stream"),
                    OsString::from("core/main"),
                    OsString::from("--from"),
                    OsString::from("0"),
                ],
                "streaming integration message",
            )
            .await?;
        ensure_contains(
            &stream_output.stdout,
            "seq: 1",
            "stream output includes sequence 1",
        )?;

        let verify_state = self
            .run_cli_success(
                vec![
                    OsString::from("verify-state"),
                    OsString::from("--hub"),
                    hub.data_dir.as_os_str().to_os_string(),
                    OsString::from("--client"),
                    client_dir.as_os_str().to_os_string(),
                    OsString::from("--stream"),
                    OsString::from("core/main"),
                ],
                "verifying hub/client state",
            )
            .await?;
        ensure_contains(
            &verify_state.stdout,
            "state verified",
            "verify-state confirms synchronisation",
        )?;

        // Attachment flow
        let attachment_path = self.base_dir().join("attachment.bin");
        fs::write(&attachment_path, b"attachment-bytes")
            .await
            .context("writing attachment test file")?;

        let send_attachment = self
            .run_cli_success(
                vec![
                    OsString::from("send"),
                    OsString::from("--hub"),
                    OsString::from(&hub_url),
                    OsString::from("--client"),
                    client_dir.as_os_str().to_os_string(),
                    OsString::from("--stream"),
                    OsString::from("core/att"),
                    OsString::from("--body"),
                    OsString::from(r#"{"text":"attachment"}"#),
                    OsString::from("--attach"),
                    attachment_path.as_os_str().to_os_string(),
                ],
                "sending attachment message",
            )
            .await?;
        let att_seq = parse_send_sequence(&send_attachment.stdout)?;
        let bundle_path = message_bundle_path(&hub.data_dir, "core/att", att_seq);
        self.run_cli_success(
            vec![
                OsString::from("attachment"),
                OsString::from("verify"),
                OsString::from("--msg"),
                bundle_path.as_os_str().to_os_string(),
                OsString::from("--file"),
                attachment_path.as_os_str().to_os_string(),
                OsString::from("--index"),
                OsString::from("0"),
            ],
            "verifying attachment bundle",
        )
        .await?;

        // Capability flow
        let cap_path = self.base_dir().join("cap.cbor");
        self.run_cli_success(
            vec![
                OsString::from("cap"),
                OsString::from("issue"),
                OsString::from("--issuer"),
                admin_dir.as_os_str().to_os_string(),
                OsString::from("--subject"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("core/capped"),
                OsString::from("--ttl"),
                OsString::from("600"),
                OsString::from("--out"),
                cap_path.as_os_str().to_os_string(),
            ],
            "issuing capability token",
        )
        .await?;

        let unauthorized = self
            .run_cli(vec![
                OsString::from("send"),
                OsString::from("--hub"),
                OsString::from(&hub_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("core/capped"),
                OsString::from("--body"),
                OsString::from(r#"{"text":"denied"}"#),
                OsString::from("--cap"),
                cap_path.as_os_str().to_os_string(),
            ])
            .await?;
        if unauthorized.status.success() {
            bail!("unauthorised send unexpectedly succeeded");
        }

        self.run_cli_success(
            vec![
                OsString::from("cap"),
                OsString::from("authorize"),
                OsString::from("--hub"),
                OsString::from(&hub_url),
                OsString::from("--cap"),
                cap_path.as_os_str().to_os_string(),
            ],
            "authorising capability with hub",
        )
        .await?;

        self.run_cli_success(
            vec![
                OsString::from("send"),
                OsString::from("--hub"),
                OsString::from(&hub_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("core/capped"),
                OsString::from("--body"),
                OsString::from(r#"{"text":"authorised"}"#),
                OsString::from("--cap"),
                cap_path.as_os_str().to_os_string(),
            ],
            "sending authorised capability message",
        )
        .await?;

        // Resync flow: ensure multiple messages then resync client state
        self.run_cli_success(
            vec![
                OsString::from("send"),
                OsString::from("--hub"),
                OsString::from(&hub_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("core/resync"),
                OsString::from("--body"),
                OsString::from(r#"{"text":"resync-a"}"#),
            ],
            "seeding resync stream",
        )
        .await?;
        self.run_cli_success(
            vec![
                OsString::from("send"),
                OsString::from("--hub"),
                OsString::from(&hub_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("core/resync"),
                OsString::from("--body"),
                OsString::from(r#"{"text":"resync-b"}"#),
            ],
            "seeding second resync message",
        )
        .await?;

        self.run_cli_success(
            vec![
                OsString::from("resync"),
                OsString::from("--hub"),
                OsString::from(&hub_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("core/resync"),
            ],
            "resynchronising client state",
        )
        .await?;

        self.run_mmr_drift_recovery(&hub, &hub_url, &client_dir)
            .await
            .context("executing checkpoint recovery scenario")?;

        // Explain error codes to ensure table is wired
        let explain = self
            .run_cli_success(
                vec![OsString::from("explain-error"), OsString::from("E.AUTH")],
                "explaining error code",
            )
            .await?;
        ensure_contains(&explain.stdout, "E.AUTH", "explain-error emits description")?;

        // Health + metrics diagnostics
        let _ = self.fetch_metrics(&hub_url).await?;
        self.fetch_health(&hub_url).await?;

        hub.handle.terminate().await?;
        Ok(())
    }

    pub async fn run_federation_suite(&mut self) -> Result<()> {
        let primary = self
            .spawn_hub("overlay-primary", HubRole::Primary, &[])
            .await
            .context("spawning primary hub")?;
        let replica_target = format!("http://{}", primary.listen);
        let replica = self
            .spawn_hub(
                "overlay-replica",
                HubRole::Replica,
                std::slice::from_ref(&replica_target),
            )
            .await
            .context("spawning replica hub")?;

        self.wait_for_health(primary.listen).await?;
        self.wait_for_health(replica.listen).await?;

        let primary_url = format!("http://{}", primary.listen);
        let replica_url = format!("http://{}", replica.listen);

        let bridge = self
            .spawn_bridge("fed-bridge", &primary_url, &replica_url)
            .await
            .context("spawning federation bridge")?;

        // Generate client and send message to primary
        let client_dir = self.base_dir().join("fed-client");
        fs::create_dir_all(&client_dir)
            .await
            .context("creating federation client dir")?;
        self.run_cli_success(
            vec![
                OsString::from("keygen"),
                OsString::from("--out"),
                client_dir.as_os_str().to_os_string(),
            ],
            "generating federation client identity",
        )
        .await?;

        self.run_cli_success(
            vec![
                OsString::from("send"),
                OsString::from("--hub"),
                OsString::from(&primary_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("fed/chat"),
                OsString::from("--body"),
                OsString::from(r#"{"text":"primary"}"#),
            ],
            "sending primary federation message",
        )
        .await?;

        // Sending directly to replica should fail (AUTH)
        let replica_attempt = self
            .run_cli(vec![
                OsString::from("send"),
                OsString::from("--hub"),
                OsString::from(&replica_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from("fed/chat"),
                OsString::from("--body"),
                OsString::from(r#"{"text":"replica"}"#),
            ])
            .await?;
        if replica_attempt.status.success() {
            bail!("replica accepted write despite replica role");
        }

        self.wait_for_replication(&replica_url).await?;
        self.verify_federated_mmr(&primary_url, &replica_url)
            .await?;

        bridge.handle.terminate().await?;
        primary.handle.terminate().await?;
        replica.handle.terminate().await?;
        Ok(())
    }

    async fn run_mmr_drift_recovery(
        &mut self,
        primary: &HubProcess,
        primary_url: &str,
        client_dir: &Path,
    ) -> Result<()> {
        const STREAM: &str = "core/drift-long";
        const INITIAL_MESSAGES: usize = 4;
        const FORK_MESSAGES: usize = 6;
        const PRIMARY_MESSAGES_AFTER: usize = 20;

        for idx in 0..INITIAL_MESSAGES {
            let body = format!(r#"{{\"text\":\"drift-initial-{idx}\"}}"#);
            self.send_test_message(primary_url, client_dir, STREAM, &body)
                .await
                .with_context(|| format!("sending initial drift message {idx}"))?;
        }

        let fork_dir = self.base_dir().join("fork-hub");
        if fs::try_exists(&fork_dir)
            .await
            .with_context(|| format!("checking fork directory {}", fork_dir.display()))?
        {
            fs::remove_dir_all(&fork_dir)
                .await
                .with_context(|| format!("clearing prior fork directory {}", fork_dir.display()))?;
        }
        copy_dir_recursive(&primary.data_dir, &fork_dir)
            .await
            .context("copying primary hub state for forked hub")?;

        let fork_pid_path = fork_dir.join(HUB_PID_FILE);
        if fs::try_exists(&fork_pid_path)
            .await
            .with_context(|| format!("checking fork PID file {}", fork_pid_path.display()))?
        {
            fs::remove_file(&fork_pid_path)
                .await
                .with_context(|| format!("removing fork PID file {}", fork_pid_path.display()))?;
        }

        let fork = self
            .spawn_hub("fork-hub", HubRole::Primary, &[])
            .await
            .context("spawning forked hub process")?;
        let fork_url = format!("http://{}", fork.listen);
        self.wait_for_health(fork.listen)
            .await
            .context("awaiting fork hub health")?;

        for idx in INITIAL_MESSAGES..(INITIAL_MESSAGES + FORK_MESSAGES) {
            let body = format!(r#"{{\"text\":\"fork-divergent-{idx}\"}}"#);
            self.send_test_message(&fork_url, client_dir, STREAM, &body)
                .await
                .with_context(|| format!("sending divergent message {idx} to fork"))?;
        }

        for idx in INITIAL_MESSAGES..(INITIAL_MESSAGES + PRIMARY_MESSAGES_AFTER) {
            let body = format!(r#"{{\"text\":\"primary-divergent-{idx}\"}}"#);
            self.send_test_message(primary_url, client_dir, STREAM, &body)
                .await
                .with_context(|| format!("sending divergent message {idx} to primary"))?;
        }

        fork.handle
            .terminate()
            .await
            .context("terminating forked hub after divergence")?;

        let fork_root_before = compute_stream_mmr_root(&fork_dir, STREAM)
            .await
            .context("computing forked hub MMR root prior to recovery")?;
        let fork_root_before = fork_root_before
            .map(|root| hex::encode(root.as_bytes()))
            .unwrap_or_default();

        let primary_metrics = self
            .fetch_metrics(primary_url)
            .await
            .context("fetching metrics for primary hub during drift scenario")?;
        let primary_root_hex = extract_mmr_root(&primary_metrics, STREAM)
            .context("primary hub missing MMR root for drift stream")?;
        ensure!(
            fork_root_before != primary_root_hex,
            "forked hub should diverge from primary before recovery"
        );

        let remote_messages = self
            .fetch_stream_with_proofs(primary_url, STREAM)
            .await
            .context("streaming primary messages with proofs")?;
        ensure!(
            !remote_messages.is_empty(),
            "primary hub must provide messages for drift recovery"
        );

        let mut recovery_mmr = Mmr::new();
        for remote in &remote_messages {
            let leaf = message_leaf_hash(&remote.message)
                .context("computing leaf hash for streamed message")?;
            let (seq, root) = recovery_mmr.append(leaf);
            ensure!(
                seq == remote.message.seq,
                "stream {} sequence mismatch while rebuilding MMR",
                STREAM
            );

            let receipt_root = parse_mmr_root_hex(&remote.receipt.mmr_root)
                .context("decoding receipt mmr_root during recovery")?;
            ensure!(
                root == receipt_root,
                "replayed receipt root does not match reconstructed MMR"
            );

            let proof = remote
                .proof
                .clone()
                .try_into_mmr()
                .context("decoding remote MMR proof")?;
            ensure!(
                proof.verify(&receipt_root),
                "remote proof failed verification during recovery replay"
            );
        }

        let final_root = recovery_mmr
            .root()
            .context("reconstructed MMR missing root after replay")?;
        let final_root_hex = hex::encode(final_root.as_bytes());
        ensure!(
            final_root_hex == primary_root_hex,
            "replayed receipts did not converge to primary MMR root"
        );

        let checkpoint =
            create_checkpoint_for_stream(&primary.data_dir, STREAM, recovery_mmr.seq(), final_root)
                .await
                .context("creating checkpoint for drift recovery")?;
        append_checkpoint(&primary.data_dir, &checkpoint)
            .await
            .context("appending drift recovery checkpoint")?;

        let fetched_checkpoint = self
            .fetch_latest_checkpoint(primary_url)
            .await
            .context("fetching latest checkpoint after publication")?;
        ensure!(
            fetched_checkpoint.mmr_root == checkpoint.mmr_root,
            "checkpoint endpoint returned unexpected MMR root"
        );
        ensure!(
            fetched_checkpoint.upto_seq == checkpoint.upto_seq,
            "checkpoint endpoint returned unexpected upto_seq"
        );

        persist_recovered_stream_state(
            &fork_dir,
            STREAM,
            remote_messages.iter().map(|m| m.message.clone()),
        )
        .await
        .context("persisting recovered stream state to fork directory")?;

        let fork_root_after = compute_stream_mmr_root(&fork_dir, STREAM)
            .await
            .context("computing forked hub MMR root after recovery")?
            .map(|root| hex::encode(root.as_bytes()))
            .unwrap_or_default();
        ensure!(
            fork_root_after == final_root_hex,
            "forked hub state did not converge to checkpoint root"
        );

        Ok(())
    }

    async fn run_cli_success(&self, args: Vec<OsString>, context: &str) -> Result<CommandOutput> {
        let output = self.run_cli(args).await?;
        if !output.status.success() {
            bail!(
                "cli command failed while {context}: status {:?}\nstdout:{}\nstderr:{}",
                output.status,
                output.stdout,
                output.stderr
            );
        }
        Ok(output)
    }

    async fn send_test_message(
        &self,
        hub_url: &str,
        client_dir: &Path,
        stream: &str,
        body: &str,
    ) -> Result<()> {
        self.run_cli_success(
            vec![
                OsString::from("send"),
                OsString::from("--hub"),
                OsString::from(hub_url),
                OsString::from("--client"),
                client_dir.as_os_str().to_os_string(),
                OsString::from("--stream"),
                OsString::from(stream),
                OsString::from("--body"),
                OsString::from(body),
            ],
            "sending drift scenario message",
        )
        .await?;
        Ok(())
    }

    async fn fetch_stream_with_proofs(
        &self,
        hub_url: &str,
        stream: &str,
    ) -> Result<Vec<StreamMessageWithProof>> {
        let response = self
            .http
            .get(format!("{hub_url}/stream"))
            .query(&[("stream", stream), ("with_proof", "true")])
            .send()
            .await
            .with_context(|| format!("streaming {stream} from {hub_url}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "stream endpoint {} returned {} while fetching {}",
                hub_url,
                status,
                stream
            );
        }
        let messages = response
            .json::<Vec<StreamMessageWithProof>>()
            .await
            .context("decoding streamed messages with proofs")?;
        Ok(messages)
    }

    async fn fetch_latest_checkpoint(&self, hub_url: &str) -> Result<Checkpoint> {
        let response = self
            .http
            .get(format!("{hub_url}/checkpoint_latest"))
            .send()
            .await
            .with_context(|| format!("fetching checkpoint_latest from {hub_url}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!("checkpoint_latest {} returned status {}", hub_url, status);
        }
        let bytes = response
            .bytes()
            .await
            .context("reading checkpoint response body")?;
        let checkpoint: Checkpoint =
            from_reader(bytes.as_ref()).context("decoding checkpoint CBOR payload")?;
        Ok(checkpoint)
    }

    async fn run_cli(&self, args: Vec<OsString>) -> Result<CommandOutput> {
        let mut command = TokioCommand::new(&self.bins.cli);
        command.args(args.iter());
        let output = command
            .output()
            .await
            .context("executing veen-cli command")?;
        Ok(CommandOutput::from(output))
    }

    async fn spawn_hub(
        &self,
        name: &str,
        role: HubRole,
        replica_targets: &[String],
    ) -> Result<HubProcess> {
        let listen = next_listen_addr()?;
        let data_dir = self.base_dir().join(name);
        fs::create_dir_all(&data_dir)
            .await
            .with_context(|| format!("creating hub data dir {}", data_dir.display()))?;

        ensure_hub_key_material(&data_dir)
            .await
            .with_context(|| format!("ensuring hub key material in {}", data_dir.display()))?;

        let mut args = vec![
            OsString::from("run"),
            OsString::from("--listen"),
            OsString::from(listen.to_string()),
            OsString::from("--data-dir"),
            data_dir.as_os_str().to_os_string(),
            OsString::from("--disable-capability-gating"),
        ];
        if role == HubRole::Replica {
            args.push(OsString::from("--role"));
            args.push(OsString::from("replica"));
            for target in replica_targets {
                args.push(OsString::from("--replica-target"));
                args.push(OsString::from(target));
            }
        }
        let handle = self
            .spawn_process(name, &self.bins.hub, args)
            .await
            .context("spawning hub process")?;

        Ok(HubProcess {
            handle,
            listen,
            data_dir,
        })
    }

    async fn spawn_bridge(
        &self,
        name: &str,
        primary: &str,
        replica: &str,
    ) -> Result<BridgeProcess> {
        let args = vec![
            OsString::from("run"),
            OsString::from("--from"),
            OsString::from(primary),
            OsString::from("--to"),
            OsString::from(replica),
            OsString::from("--poll-interval-ms"),
            OsString::from("100"),
            OsString::from("--stream"),
            OsString::from("fed/chat"),
        ];
        let handle = self
            .spawn_process(name, &self.bins.bridge, args)
            .await
            .context("spawning bridge process")?;
        Ok(BridgeProcess { handle })
    }

    async fn spawn_process(
        &self,
        name: &str,
        program: &Path,
        args: Vec<OsString>,
    ) -> Result<ManagedProcess> {
        let stdout_log = self.logs_dir.join(format!("{name}.stdout.log"));
        let stderr_log = self.logs_dir.join(format!("{name}.stderr.log"));
        let mut command = TokioCommand::new(program);
        command.args(args.iter());
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
        command.kill_on_drop(true);
        let mut child = command
            .spawn()
            .with_context(|| format!("spawning process {} using {}", name, program.display()))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("{name} missing stdout pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("{name} missing stderr pipe"))?;

        let stdout_file = File::create(&stdout_log)
            .await
            .with_context(|| format!("creating stdout log {}", stdout_log.display()))?;
        let stderr_file = File::create(&stderr_log)
            .await
            .with_context(|| format!("creating stderr log {}", stderr_log.display()))?;

        let stdout_task = tokio::spawn(pipe_output(stdout, stdout_file));
        let stderr_task = tokio::spawn(pipe_output(stderr, stderr_file));

        Ok(ManagedProcess {
            name: name.to_string(),
            child,
            stdout_log,
            stderr_log,
            stdout_task: Some(stdout_task),
            stderr_task: Some(stderr_task),
        })
    }

    async fn wait_for_health(&self, listen: SocketAddr) -> Result<()> {
        let url = format!("http://{listen}/healthz");
        for attempt in 0..HUB_HEALTH_MAX_ATTEMPTS {
            match self.http.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    warn!("hub health attempt {} returned {}", attempt, resp.status());
                }
                Err(err) => {
                    warn!("hub health attempt {} failed: {}", attempt, err);
                }
            }
            sleep(Duration::from_millis(HUB_HEALTH_RETRY_DELAY_MS)).await;
        }
        bail!("hub at {url} did not become healthy within timeout");
    }

    async fn wait_for_replication(&self, replica_url: &str) -> Result<()> {
        for attempt in 0..REPLICATION_MAX_ATTEMPTS {
            let response = self
                .http
                .post(format!("{replica_url}/resync"))
                .json(&serde_json::json!({ "stream": "fed/chat" }))
                .send()
                .await;
            match response {
                Ok(resp) if resp.status().is_success() => {
                    let state: serde_json::Value =
                        resp.json().await.context("decoding replica resync state")?;
                    if state
                        .get("messages")
                        .and_then(|v| v.as_array())
                        .map(|msgs| !msgs.is_empty())
                        .unwrap_or(false)
                    {
                        return Ok(());
                    }
                }
                Ok(resp) if resp.status().as_u16() == 404 => {
                    // Replica has not seen stream yet, keep waiting.
                }
                Ok(resp) => {
                    warn!(
                        "replica resync attempt {} returned {}",
                        attempt,
                        resp.status()
                    );
                }
                Err(err) => {
                    warn!("replica resync attempt {} failed: {}", attempt, err);
                }
            }
            sleep(Duration::from_millis(REPLICATION_RETRY_DELAY_MS)).await;
        }
        bail!("replica did not observe federated message within timeout");
    }

    async fn verify_federated_mmr(&self, primary: &str, replica: &str) -> Result<()> {
        let primary_metrics = self.fetch_metrics(primary).await?;
        let replica_metrics = self.fetch_metrics(replica).await?;
        let primary_root = extract_mmr_root(&primary_metrics, "fed/chat")
            .context("primary hub missing MMR root for fed/chat")?;
        let replica_root = extract_mmr_root(&replica_metrics, "fed/chat")
            .context("replica hub missing MMR root for fed/chat")?;
        if primary_root != replica_root {
            bail!(
                "primary and replica MMR roots diverged: primary={} replica={}",
                primary_root,
                replica_root
            );
        }
        Ok(())
    }

    async fn fetch_metrics(&self, base: &str) -> Result<serde_json::Value> {
        let response = self
            .http
            .get(format!("{base}/metrics"))
            .send()
            .await
            .context("fetching hub metrics")?;
        let status = response.status();
        if !status.is_success() {
            bail!("metrics endpoint {} returned {}", base, status);
        }
        let body = response.text().await.context("decoding metrics body")?;
        let metrics: serde_json::Value =
            serde_json::from_str(&body).context("parsing metrics payload as JSON")?;
        ensure!(
            metrics.get("submit_ok_total").is_some(),
            "metrics response missing submit_ok_total"
        );
        ensure!(
            metrics.get("submit_err_total").is_some(),
            "metrics response missing submit_err_total"
        );
        Ok(metrics)
    }

    async fn fetch_health(&self, base: &str) -> Result<()> {
        let response = self
            .http
            .get(format!("{base}/healthz"))
            .send()
            .await
            .context("fetching hub healthz")?;
        let status = response.status();
        if !status.is_success() {
            bail!("health endpoint {} returned {}", base, status);
        }
        Ok(())
    }
}

pub struct HubProcess {
    handle: ManagedProcess,
    listen: SocketAddr,
    data_dir: PathBuf,
}

pub struct BridgeProcess {
    handle: ManagedProcess,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HubRole {
    Primary,
    Replica,
}

struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

impl CommandOutput {
    fn from(output: std::process::Output) -> Self {
        Self {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

async fn pipe_output<R>(mut reader: R, mut writer: File) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    io::copy(&mut reader, &mut writer)
        .await
        .context("copying process output")?;
    writer.flush().await.context("flushing process log")?;
    Ok(())
}

fn next_listen_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("binding ephemeral port")?;
    let addr = listener.local_addr().context("reading socket address")?;
    drop(listener);
    Ok(addr)
}

fn parse_send_sequence(output: &str) -> Result<u64> {
    for line in output.lines() {
        if let Some(pos) = line.find("seq=") {
            let rest = &line[pos + 4..];
            if let Some(end) = rest.find(' ') {
                let seq: u64 = rest[..end]
                    .parse()
                    .context("parsing sequence from send output")?;
                return Ok(seq);
            }
        }
    }
    bail!("send command output did not include sequence: {output}");
}

fn message_bundle_path(data_dir: &Path, stream: &str, seq: u64) -> PathBuf {
    data_dir
        .join("state")
        .join("messages")
        .join(format!("{}-{seq:08}.json", stream_storage_name(stream)))
}

fn stream_storage_name(stream: &str) -> String {
    let mut safe = String::with_capacity(stream.len());
    for ch in stream.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            safe.push(ch);
        } else if ch.is_whitespace() {
            safe.push('_');
        } else {
            safe.push('-');
        }
    }
    if safe.is_empty() {
        safe.push_str("stream");
    }
    let digest = sha2::Sha256::digest(stream.as_bytes());
    let suffix = hex::encode(&digest[..8]);
    format!("{safe}-{suffix}")
}

async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        fs::create_dir_all(&to)
            .await
            .with_context(|| format!("creating directory {}", to.display()))?;
        let mut entries = fs::read_dir(&from)
            .await
            .with_context(|| format!("reading directory {}", from.display()))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .context("advancing directory iterator")?
        {
            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("reading metadata for {}", entry.path().display()))?;
            let target = to.join(entry.file_name());
            if file_type.is_dir() {
                stack.push((entry.path(), target));
            } else if file_type.is_file() {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).await.with_context(|| {
                        format!("ensuring parent directory {}", parent.display())
                    })?;
                }
                fs::copy(entry.path(), &target).await.with_context(|| {
                    format!("copying {} to {}", entry.path().display(), target.display())
                })?;
            }
        }
    }
    Ok(())
}

async fn clear_stream_messages(dir: &Path, stream: &str) -> Result<()> {
    if !fs::try_exists(dir)
        .await
        .with_context(|| format!("checking messages directory {}", dir.display()))?
    {
        return Ok(());
    }
    let mut entries = fs::read_dir(dir)
        .await
        .with_context(|| format!("reading messages directory {}", dir.display()))?;
    let prefix = format!("{}-", stream_storage_name(stream));
    while let Some(entry) = entries
        .next_entry()
        .await
        .context("advancing messages directory iterator")?
    {
        let path = entry.path();
        if entry
            .file_type()
            .await
            .with_context(|| format!("checking file type for {}", path.display()))?
            .is_file()
            && entry.file_name().to_string_lossy().starts_with(&prefix)
        {
            fs::remove_file(&path)
                .await
                .with_context(|| format!("removing stale bundle {}", path.display()))?;
        }
    }
    Ok(())
}

async fn ensure_hub_key_material(data_dir: &Path) -> Result<()> {
    let key_path = data_dir.join("hub_key.cbor");
    if fs::try_exists(&key_path)
        .await
        .with_context(|| format!("checking hub key at {}", key_path.display()))?
    {
        return Ok(());
    }

    let created_at = current_unix_timestamp()?;
    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();

    let material = HubKeyMaterial {
        version: HUB_KEY_VERSION,
        created_at,
        public_key: ByteBuf::from(verifying.to_bytes().to_vec()),
        secret_key: ByteBuf::from(signing.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    into_writer(&material, &mut encoded).context("encoding hub key material")?;
    fs::write(&key_path, encoded)
        .await
        .with_context(|| format!("writing hub key to {}", key_path.display()))?;
    Ok(())
}

fn current_unix_timestamp() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?;
    Ok(duration.as_secs())
}

fn ensure_contains(haystack: &str, needle: &str, context: &str) -> Result<()> {
    if !haystack.contains(needle) {
        bail!("expected {context}; missing `{needle}` in `{haystack}`");
    }
    Ok(())
}

fn extract_mmr_root(metrics: &serde_json::Value, stream: &str) -> Option<String> {
    metrics
        .get("mmr_roots")
        .and_then(|roots| roots.get(stream))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

async fn persist_recovered_stream_state<I>(data_dir: &Path, stream: &str, messages: I) -> Result<()>
where
    I: IntoIterator<Item = StoredMessage>,
{
    let collected: Vec<StoredMessage> = messages.into_iter().collect();
    let state = HubStreamState {
        messages: collected.clone(),
    };
    let state_path = data_dir
        .join("state")
        .join("streams")
        .join(format!("{}.json", stream_storage_name(stream)));
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring stream directory {}", parent.display()))?;
    }
    let encoded = serde_json::to_vec_pretty(&state)
        .with_context(|| format!("encoding recovered state for stream {}", stream))?;
    fs::write(&state_path, encoded)
        .await
        .with_context(|| format!("writing recovered state to {}", state_path.display()))?;

    let messages_dir = data_dir.join("state").join("messages");
    clear_stream_messages(&messages_dir, stream).await?;
    for message in &state.messages {
        let bundle_path = message_bundle_path(data_dir, stream, message.seq);
        if let Some(parent) = bundle_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("ensuring message directory {}", parent.display()))?;
        }
        let encoded = serde_json::to_vec_pretty(message).with_context(|| {
            format!(
                "encoding message bundle for {stream}#{seq}",
                seq = message.seq
            )
        })?;
        fs::write(&bundle_path, encoded)
            .await
            .with_context(|| format!("writing message bundle to {}", bundle_path.display()))?;
    }
    Ok(())
}

fn message_leaf_hash(message: &StoredMessage) -> Result<LeafHash> {
    let encoded =
        serde_json::to_vec(message).context("encoding message for leaf hash computation")?;
    let digest = sha2::Sha256::digest(&encoded);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(LeafHash::new(bytes))
}

fn parse_mmr_root_hex(value: &str) -> Result<MmrRoot> {
    let bytes = hex::decode(value).with_context(|| format!("decoding mmr_root {}", value))?;
    MmrRoot::from_slice(&bytes).with_context(|| format!("parsing mmr_root {}", value))
}

async fn append_checkpoint(data_dir: &Path, checkpoint: &Checkpoint) -> Result<()> {
    let path = data_dir.join("checkpoints.cborseq");
    let mut encoded = Vec::new();
    into_writer(checkpoint, &mut encoded).context("encoding checkpoint to CBOR")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("opening checkpoint log {}", path.display()))?;
    file.write_all(&encoded)
        .await
        .context("appending checkpoint to log")?;
    file.flush().await.context("flushing checkpoint log")?;
    Ok(())
}

async fn create_checkpoint_for_stream(
    data_dir: &Path,
    stream: &str,
    upto_seq: u64,
    root: MmrRoot,
) -> Result<Checkpoint> {
    let key_path = data_dir.join("hub_key.cbor");
    let key_bytes = fs::read(&key_path)
        .await
        .with_context(|| format!("reading hub key from {}", key_path.display()))?;
    let material: HubKeyMaterial =
        from_reader(key_bytes.as_slice()).context("decoding hub key material")?;
    ensure!(
        material.version == HUB_KEY_VERSION,
        "unsupported hub key version {}",
        material.version
    );
    ensure!(
        material.public_key.len() == 32,
        "hub public key must be 32 bytes"
    );
    ensure!(
        material.secret_key.len() == 32,
        "hub secret key must be 32 bytes"
    );
    let mut secret = [0u8; 32];
    secret.copy_from_slice(material.secret_key.as_ref());
    let signing = SigningKey::from_bytes(&secret);

    let label_bytes = sha2::Sha256::digest(stream.as_bytes());
    let label = Label::from_slice(&label_bytes)
        .context("constructing checkpoint label from stream hash")?;

    let mut checkpoint = Checkpoint {
        ver: CHECKPOINT_VERSION,
        label_prev: label,
        label_curr: label,
        upto_seq,
        mmr_root: root,
        epoch: upto_seq,
        hub_sig: Signature64::from([0u8; 64]),
        witness_sigs: None,
    };
    let digest = checkpoint
        .signing_tagged_hash()
        .context("computing checkpoint signing digest")?;
    let signature = signing.sign(&digest);
    checkpoint.hub_sig = Signature64::from(signature.to_bytes());
    Ok(checkpoint)
}

#[derive(Serialize, Deserialize)]
struct HubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

async fn compute_stream_mmr_root(data_dir: &Path, stream: &str) -> Result<Option<MmrRoot>> {
    let state_path = data_dir
        .join("state")
        .join("streams")
        .join(format!("{}.json", stream_storage_name(stream)));
    if !fs::try_exists(&state_path)
        .await
        .with_context(|| format!("checking state file {}", state_path.display()))?
    {
        return Ok(None);
    }
    let data = fs::read(&state_path)
        .await
        .with_context(|| format!("reading stream state from {}", state_path.display()))?;
    let state: HubStreamState = serde_json::from_slice(&data)
        .with_context(|| format!("decoding stream state from {}", state_path.display()))?;
    if state.messages.is_empty() {
        return Ok(None);
    }
    let mut mmr = Mmr::new();
    for message in &state.messages {
        let leaf = message_leaf_hash(message)?;
        let (seq, _) = mmr.append(leaf);
        ensure!(
            seq == message.seq,
            "stream {stream} sequence mismatch while recomputing MMR"
        );
    }
    Ok(mmr.root())
}

pub async fn run_core_suite() -> Result<()> {
    let mut harness = IntegrationHarness::new().await?;
    harness.run_core_suite().await
}

pub async fn run_overlay_suite() -> Result<()> {
    let mut harness = IntegrationHarness::new().await?;
    harness.run_federation_suite().await
}
