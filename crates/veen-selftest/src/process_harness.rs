use std::collections::HashSet;
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ciborium::{de::from_reader, ser::into_writer};
use ed25519_dalek::{Signer, SigningKey};

use anyhow::{anyhow, bail, ensure, Context, Result};
use rand::rngs::OsRng;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{self, AsyncRead, AsyncWriteExt};
use tokio::process::{Child, Command as TokioCommand};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::warn;

use veen_core::label::Label;
use veen_core::wire::checkpoint::{Checkpoint, CHECKPOINT_VERSION};
use veen_core::wire::message::MSG_VERSION;
use veen_core::wire::mmr::Mmr;
use veen_core::wire::types::{ClientId, CtHash, LeafHash, MmrRoot, Signature64};
use veen_core::{
    cap_stream_id_from_label, h, ht, Msg, Profile, CIPHERTEXT_LEN_PREFIX, HPKE_ENC_LEN,
    MAX_MSG_BYTES,
};
use veen_hub::pipeline::{HubStreamState, StoredMessage, StreamMessageWithProof, SubmitRequest};
use veen_hub::pipeline::{PowCookieEnvelope, SubmitResponse};
use veen_hub::storage::{CHECKPOINTS_FILE, HUB_PID_FILE};
use veen_overlays::{schema_meta_schema, PowCookie, SchemaDescriptor, SchemaId, SchemaOwner};

#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;

const HUB_HEALTH_MAX_ATTEMPTS: usize = 120;
const HUB_HEALTH_RETRY_DELAY_MS: u64 = 250;
#[allow(dead_code)]
const REPLICATION_MAX_ATTEMPTS: usize = 120;
#[allow(dead_code)]
const REPLICATION_RETRY_DELAY_MS: u64 = 250;
const ADMIN_SIGNING_DOMAIN: &str = "veen/admin";
const HUB_KEY_VERSION: u8 = 1;

#[derive(Clone)]
#[allow(dead_code)]
struct BinaryPaths {
    hub: PathBuf,
    cli: PathBuf,
    bridge: PathBuf,
}

pub struct RestartResult {
    pub stream: String,
    pub seq_before_restart: u64,
    pub seq_after_restart: u64,
    pub mmr_before: String,
    pub mmr_after_restart: String,
    pub mmr_after_new_message: String,
}

pub struct FailstartResult {
    pub exit_code: i32,
    pub stderr_excerpt: String,
    pub config_path: PathBuf,
}

pub struct VersionSkewResult {
    pub stream: String,
    pub legacy_root: String,
    pub replayed_root: String,
    pub last_seq: u64,
    pub checkpoint_path: PathBuf,
}

pub struct RecorderCaptureResult {
    pub stream: String,
    pub total_events: usize,
    pub mmr_root: String,
    pub checkpoint_root: String,
    pub checkpoint_path: PathBuf,
    pub sampled_seqs: Vec<u64>,
}

pub struct RecorderRecoveryResult {
    pub stream: String,
    pub checkpoint_root: String,
    pub replay_from_seq: u64,
    pub validated_seqs: Vec<u64>,
}

struct RecorderEvent {
    subject_id: String,
    principal_id: String,
    event_type: String,
    event_time: u64,
}

pub struct HardenedResult {
    pub pow_challenge: String,
    pub pow_difficulty: u8,
    pub pow_forbidden_status: reqwest::StatusCode,
    pub pow_accept_seq: u64,
    pub pow_accept_root: String,
    pub rate_limit_status: reqwest::StatusCode,
    pub replicated_seq: u64,
}

pub struct MetaOverlayResult {
    pub schema_id_hex: String,
    pub descriptor_name: String,
    pub descriptor_version: String,
    pub registry_len: usize,
}

pub struct CoreSuitePrereqs {
    pub missing: Vec<String>,
    pub diagnostics: Vec<String>,
}

impl CoreSuitePrereqs {
    pub fn ready(&self) -> bool {
        self.missing.is_empty()
    }
}

#[derive(Deserialize)]
struct PowChallengeResponse {
    pub ok: bool,
    pub challenge: String,
    pub difficulty: u8,
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

pub fn core_suite_prereqs() -> Result<CoreSuitePrereqs> {
    let mut diagnostics = Vec::new();
    let mut missing = Vec::new();

    match BinaryPaths::discover() {
        Ok(bins) => {
            diagnostics.push(format!("hub_binary={}", bins.hub.display()));
            diagnostics.push(format!("cli_binary={}", bins.cli.display()));
            diagnostics.push(format!("bridge_binary={}", bins.bridge.display()));
        }
        Err(err) => {
            missing.push(format!("required binaries unavailable: {err}"));
        }
    }

    match TempDir::new() {
        Ok(temp) => {
            diagnostics.push(format!("scratch_dir={}", temp.path().display()));
        }
        Err(err) => {
            missing.push(format!("unable to create scratch directory: {err}"));
        }
    }

    Ok(CoreSuitePrereqs {
        missing,
        diagnostics,
    })
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
        let status = self.wait_for_exit().await?;
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

    async fn wait_for_exit(&mut self) -> Result<std::process::ExitStatus> {
        let status = self.child.wait().await.context("awaiting process exit")?;
        self.join_output_tasks().await?;
        Ok(status)
    }

    async fn join_output_tasks(&mut self) -> Result<()> {
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
        Ok(())
    }

    #[cfg(unix)]
    async fn signal_and_wait(mut self, signal: Signal) -> Result<std::process::ExitStatus> {
        let pid = self
            .child
            .id()
            .ok_or_else(|| anyhow!("process {} missing PID", self.name))?;
        kill(Pid::from_raw(pid as i32), signal)
            .with_context(|| format!("sending {signal:?} to {}", self.name))?;
        self.wait_for_exit().await
    }

    #[cfg(not(unix))]
    async fn signal_and_wait(self, _signal: i32) -> Result<std::process::ExitStatus> {
        bail!("signal-driven termination unsupported on this platform");
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

    pub(crate) fn http_client(&self) -> &Client {
        &self.http
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

    pub async fn run_restart_suite(&mut self) -> Result<RestartResult> {
        const STREAM: &str = "lifecycle/restart";

        let hub = self
            .spawn_hub("restart-hub", HubRole::Primary, &[])
            .await
            .context("spawning lifecycle hub")?;
        self.wait_for_health(hub.listen)
            .await
            .context("waiting for lifecycle hub health")?;

        let hub_url = format!("http://{}", hub.listen);
        let client_dir = self.base_dir().join("restart-client");
        fs::create_dir_all(&client_dir)
            .await
            .context("creating lifecycle client directory")?;
        self.run_cli_success(
            vec![
                OsString::from("keygen"),
                OsString::from("--out"),
                client_dir.as_os_str().to_os_string(),
            ],
            "creating lifecycle client identity",
        )
        .await?;

        for idx in 0..3 {
            let body = format!(r#"{{\"text\":\"before-restart-{idx}\"}}"#);
            self.send_test_message(&hub_url, &client_dir, STREAM, &body)
                .await
                .with_context(|| format!("sending lifecycle message {idx}"))?;
        }

        let messages_before = self
            .fetch_stream_with_proofs(&hub_url, STREAM)
            .await
            .context("fetching lifecycle stream before restart")?;
        ensure!(
            !messages_before.is_empty(),
            "lifecycle stream missing messages before restart",
        );
        let seq_before_restart = messages_before
            .last()
            .map(|msg| msg.message.seq)
            .unwrap_or_default();

        let metrics_before = self.fetch_metrics(&hub_url).await?;
        let mmr_before = extract_mmr_root(&metrics_before, STREAM)
            .context("lifecycle stream missing mmr_root before restart")?;
        let mmr_before_root = parse_mmr_root_hex(&mmr_before)?;
        verify_stream_proofs(&messages_before, &mmr_before_root)?;

        let hub_dir = hub.data_dir.clone();
        let hub_name = hub.name.clone();
        self.stop_hub_gracefully(hub)
            .await
            .context("gracefully stopping lifecycle hub")?;

        let restarted = self
            .spawn_hub_at_dir(&hub_name, hub_dir, HubRole::Primary, &[])
            .await
            .context("restarting lifecycle hub")?;
        self.wait_for_health(restarted.listen)
            .await
            .context("waiting for restarted hub health")?;
        let restart_url = format!("http://{}", restarted.listen);

        let metrics_after = self.fetch_metrics(&restart_url).await?;
        let mmr_after_restart = extract_mmr_root(&metrics_after, STREAM)
            .context("lifecycle stream missing mmr_root after restart")?;
        ensure!(
            mmr_after_restart == mmr_before,
            "mmr_root changed across hub restart",
        );
        let mmr_after_root = parse_mmr_root_hex(&mmr_after_restart)?;

        let messages_after = self
            .fetch_stream_with_proofs(&restart_url, STREAM)
            .await
            .context("streaming lifecycle data after restart")?;
        ensure!(
            messages_after
                .last()
                .map(|msg| msg.message.seq)
                .unwrap_or_default()
                == seq_before_restart,
            "restart changed last observed sequence",
        );
        verify_stream_proofs(&messages_after, &mmr_after_root)?;

        self.send_test_message(
            &restart_url,
            &client_dir,
            STREAM,
            r#"{"text":"after-restart"}"#,
        )
        .await
        .context("sending lifecycle message after restart")?;
        let messages_final = self
            .fetch_stream_with_proofs(&restart_url, STREAM)
            .await
            .context("streaming lifecycle data after new message")?;
        let seq_after_restart = messages_final
            .last()
            .map(|msg| msg.message.seq)
            .unwrap_or_default();
        ensure!(
            seq_after_restart == seq_before_restart + 1,
            "sequence continuity failed after restart",
        );

        let metrics_final = self.fetch_metrics(&restart_url).await?;
        let mmr_after_new_message = extract_mmr_root(&metrics_final, STREAM)
            .context("lifecycle stream missing mmr_root after new message")?;
        let mmr_after_new_message_root = parse_mmr_root_hex(&mmr_after_new_message)?;
        verify_stream_proofs(&messages_final, &mmr_after_new_message_root)?;

        self.stop_hub_gracefully(restarted)
            .await
            .context("stopping restarted hub")?;

        Ok(RestartResult {
            stream: STREAM.to_string(),
            seq_before_restart,
            seq_after_restart,
            mmr_before,
            mmr_after_restart,
            mmr_after_new_message,
        })
    }

    pub async fn run_failstart_suite(&self) -> Result<FailstartResult> {
        let data_dir = self.base_dir().join("failstart-hub");
        fs::create_dir_all(&data_dir)
            .await
            .context("creating failstart data directory")?;
        let config_path = self.base_dir().join("invalid-hub-config.toml");
        fs::write(&config_path, "invalid = [this is not valid toml]")
            .await
            .context("writing invalid hub configuration")?;

        let listen = next_listen_addr()?;
        let output = TokioCommand::new(&self.bins.hub)
            .arg("run")
            .arg("--listen")
            .arg(listen.to_string())
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("--config")
            .arg(&config_path)
            .output()
            .await
            .context("executing hub with invalid configuration")?;

        let exit_code = output.status.code().unwrap_or_default();
        ensure!(
            exit_code == 1,
            "expected usage exit code 1 for invalid configuration (CLI-GOALS), got {exit_code}",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            stderr.contains("parsing hub configuration"),
            "hub stderr did not describe configuration failure",
        );
        let excerpt = stderr.lines().take(4).collect::<Vec<&str>>().join("\n");

        Ok(FailstartResult {
            exit_code,
            stderr_excerpt: excerpt,
            config_path,
        })
    }

    pub async fn run_version_skew_suite(&mut self) -> Result<VersionSkewResult> {
        const STREAM: &str = "lifecycle/version-skew";
        let legacy_hub = self
            .spawn_hub("version-skew-legacy", HubRole::Primary, &[])
            .await
            .context("spawning legacy hub for version skew scenario")?;
        self.wait_for_health(legacy_hub.listen)
            .await
            .context("waiting for legacy hub health")?;

        let client_dir = self.base_dir().join("version-skew-client");
        fs::create_dir_all(&client_dir)
            .await
            .context("creating version skew client dir")?;
        self.run_cli_success(
            vec![
                OsString::from("keygen"),
                OsString::from("--out"),
                client_dir.as_os_str().to_os_string(),
            ],
            "creating version skew client",
        )
        .await?;

        let legacy_url = format!("http://{}", legacy_hub.listen);
        for idx in 0..5 {
            let body = format!(r#"{{\"text\":\"legacy-{idx}\"}}"#);
            self.send_test_message(&legacy_url, &client_dir, STREAM, &body)
                .await
                .with_context(|| format!("sending legacy message {idx}"))?;
        }

        let legacy_messages = self
            .fetch_stream_with_proofs(&legacy_url, STREAM)
            .await
            .context("streaming legacy messages")?;
        ensure!(
            !legacy_messages.is_empty(),
            "expected legacy hub to emit messages",
        );
        let last_seq = legacy_messages
            .last()
            .map(|msg| msg.message.seq)
            .unwrap_or_default();
        let legacy_metrics = self.fetch_metrics(&legacy_url).await?;
        let legacy_root_hex = extract_mmr_root(&legacy_metrics, STREAM)
            .context("legacy hub missing mmr_root for version skew stream")?;
        let legacy_root = parse_mmr_root_hex(&legacy_root_hex)?;
        verify_stream_proofs(&legacy_messages, &legacy_root)?;

        let checkpoint =
            create_checkpoint_for_stream(&legacy_hub.data_dir, STREAM, last_seq, legacy_root)
                .await
                .context("creating legacy checkpoint")?;
        append_checkpoint(&legacy_hub.data_dir, &checkpoint)
            .await
            .context("appending legacy checkpoint")?;

        self.stop_hub_gracefully(legacy_hub)
            .await
            .context("stopping legacy hub for version skew scenario")?;

        let replay_dir = self.base_dir().join("version-skew-replay");
        if fs::try_exists(&replay_dir)
            .await
            .with_context(|| format!("checking replay directory {}", replay_dir.display()))?
        {
            fs::remove_dir_all(&replay_dir)
                .await
                .with_context(|| format!("clearing replay directory {}", replay_dir.display()))?;
        }
        fs::create_dir_all(&replay_dir)
            .await
            .context("creating replay directory")?;

        let hub_key_src = self
            .base_dir()
            .join("version-skew-legacy")
            .join("hub_key.cbor");
        let hub_key_dst = replay_dir.join("hub_key.cbor");
        fs::copy(&hub_key_src, &hub_key_dst)
            .await
            .with_context(|| format!("copying hub key from {}", hub_key_src.display()))?;

        persist_recovered_stream_state(
            &replay_dir,
            STREAM,
            legacy_messages.iter().map(|msg| msg.message.clone()),
        )
        .await
        .context("persisting replayed stream state")?;

        let checkpoints_src = self
            .base_dir()
            .join("version-skew-legacy")
            .join("checkpoints.cborseq");
        if fs::try_exists(&checkpoints_src)
            .await
            .with_context(|| format!("checking checkpoint log {}", checkpoints_src.display()))?
        {
            fs::copy(&checkpoints_src, replay_dir.join("checkpoints.cborseq"))
                .await
                .context("copying legacy checkpoint log")?;
        }

        let replay_hub = self
            .spawn_hub_at_dir(
                "version-skew-new",
                replay_dir.clone(),
                HubRole::Primary,
                &[],
            )
            .await
            .context("starting replay hub with legacy artefacts")?;
        self.wait_for_health(replay_hub.listen)
            .await
            .context("waiting for replay hub health")?;
        let replay_url = format!("http://{}", replay_hub.listen);

        let replay_metrics = self.fetch_metrics(&replay_url).await?;
        let replay_root_hex =
            extract_mmr_root(&replay_metrics, STREAM).context("replay hub missing mmr_root")?;
        ensure!(
            replay_root_hex == legacy_root_hex,
            "replay hub diverged from legacy mmr_root",
        );
        let replay_root = parse_mmr_root_hex(&replay_root_hex)?;
        let replay_messages = self
            .fetch_stream_with_proofs(&replay_url, STREAM)
            .await
            .context("streaming replay hub messages")?;
        verify_stream_proofs(&replay_messages, &replay_root)?;

        let replay_checkpoint = self
            .fetch_latest_checkpoint(&replay_url)
            .await
            .context("fetching replay checkpoint")?;
        ensure!(
            replay_checkpoint.mmr_root == checkpoint.mmr_root,
            "replay hub checkpoint root mismatch",
        );
        ensure!(
            replay_checkpoint.upto_seq == checkpoint.upto_seq,
            "replay hub checkpoint sequence mismatch",
        );

        self.stop_hub_gracefully(replay_hub)
            .await
            .context("stopping replay hub")?;

        Ok(VersionSkewResult {
            stream: STREAM.to_string(),
            legacy_root: legacy_root_hex,
            replayed_root: replay_root_hex,
            last_seq,
            checkpoint_path: replay_dir.join("checkpoints.cborseq"),
        })
    }

    pub async fn run_recorder_suite(
        &mut self,
    ) -> Result<(RecorderCaptureResult, RecorderRecoveryResult)> {
        const STREAM: &str = "record/app/http";

        let hub = self
            .spawn_hub("recorder-hub", HubRole::Primary, &[])
            .await
            .context("spawning recorder hub")?;
        self.wait_for_health(hub.listen)
            .await
            .context("waiting for recorder hub health")?;

        let hub_url = format!("http://{}", hub.listen);
        let client_dir = self.base_dir().join("recorder-client");
        fs::create_dir_all(&client_dir)
            .await
            .context("creating recorder client directory")?;
        self.run_cli_success(
            vec![
                OsString::from("keygen"),
                OsString::from("--out"),
                client_dir.as_os_str().to_os_string(),
            ],
            "creating recorder client identity",
        )
        .await?;

        let cli_events = vec![
            (
                "cli-login",
                json!({
                    "subject_id": "user-123",
                    "principal_id": "principal-cli-1",
                    "event_type": "login",
                    "event_time": current_unix_timestamp()? - 1,
                }),
            ),
            (
                "cli-download",
                json!({
                    "subject_id": "user-123",
                    "principal_id": "principal-cli-1",
                    "event_type": "download",
                    "event_time": current_unix_timestamp()?,
                }),
            ),
        ];

        for (label, body) in &cli_events {
            let body_text = serde_json::to_string(body)
                .with_context(|| format!("serialising CLI event body {label}"))?;
            self.send_test_message(&hub_url, &client_dir, STREAM, &body_text)
                .await
                .with_context(|| format!("sending recorder CLI event {label}"))?;
        }

        let http_payload = json!({
            "subject_id": "server-01",
            "principal_id": "principal-http",
            "event_type": "health_check",
            "event_time": current_unix_timestamp()? + 1,
        });
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let submit_request = build_submit_request(STREAM, &signing_key, 1, 0, http_payload, None)?;
        self.http
            .post(format!("{hub_url}/submit"))
            .json(&submit_request)
            .send()
            .await
            .context("submitting HTTP recorder event")?
            .error_for_status()
            .context("hub rejected HTTP recorder submission")?;

        let messages = self
            .fetch_stream_with_proofs(&hub_url, STREAM)
            .await
            .context("fetching recorder stream with proofs")?;
        ensure!(!messages.is_empty(), "recorder stream emitted no messages");
        ensure!(
            messages.len() > cli_events.len(),
            "recorder stream missing expected messages"
        );

        let mut event_types = HashSet::new();
        let mut principals = HashSet::new();
        for entry in &messages {
            let event = parse_recorder_event(entry).context("parsing recorded event fields")?;
            validate_recorder_event(&event, entry).context("validating recorded event fields")?;
            event_types.insert(event.event_type);
            principals.insert(event.principal_id);
        }

        let expected_events = ["login", "download", "health_check"];
        for event in expected_events {
            ensure!(
                event_types.contains(event),
                "recorder missing expected event_type {event}"
            );
        }
        let expected_principals = ["principal-cli-1", "principal-http"];
        for principal in expected_principals {
            ensure!(
                principals.contains(principal),
                "recorder missing expected principal_id {principal}"
            );
        }

        let metrics = self.fetch_metrics(&hub_url).await?;
        let mmr_root_hex = extract_mmr_root(&metrics, STREAM)
            .context("recorder hub missing mmr_root for record/app/http")?;
        let mmr_root = parse_mmr_root_hex(&mmr_root_hex)?;

        let last_seq = messages
            .last()
            .map(|msg| msg.message.seq)
            .unwrap_or_default();
        let checkpoint = create_checkpoint_for_stream(&hub.data_dir, STREAM, last_seq, mmr_root)
            .await
            .context("creating recorder checkpoint")?;
        append_checkpoint(&hub.data_dir, &checkpoint)
            .await
            .context("appending recorder checkpoint")?;

        verify_stream_proofs(&messages, &checkpoint.mmr_root)
            .context("verifying proofs against checkpoint root")?;

        let sample: Vec<StreamMessageWithProof> = messages.iter().take(2).cloned().collect();

        #[cfg(unix)]
        let _ = hub
            .handle
            .signal_and_wait(Signal::SIGKILL)
            .await
            .context("killing recorder hub after checkpointing")?;
        #[cfg(not(unix))]
        let _ = hub.handle.terminate().await?;

        let pid_path = hub.data_dir.join(HUB_PID_FILE);
        if fs::try_exists(&pid_path)
            .await
            .with_context(|| format!("checking PID file {}", pid_path.display()))?
        {
            fs::remove_file(&pid_path)
                .await
                .with_context(|| format!("removing stale PID file {}", pid_path.display()))?;
        }

        let restarted = self
            .spawn_hub_at_dir(
                "recorder-hub-restart",
                hub.data_dir.clone(),
                HubRole::Primary,
                &[],
            )
            .await
            .context("restarting recorder hub")?;
        self.wait_for_health(restarted.listen)
            .await
            .context("waiting for recorder hub restart health")?;

        let restart_url = format!("http://{}", restarted.listen);
        let replay_checkpoint = self
            .fetch_latest_checkpoint(&restart_url)
            .await
            .context("fetching replay checkpoint")?;
        ensure!(
            replay_checkpoint.mmr_root == checkpoint.mmr_root,
            "restarted hub returned different checkpoint root",
        );
        ensure!(
            replay_checkpoint.upto_seq == checkpoint.upto_seq,
            "restarted hub returned different upto_seq",
        );

        let replay_messages = self
            .fetch_stream_with_proofs(&restart_url, STREAM)
            .await
            .context("streaming recorder events after restart")?;
        ensure!(
            replay_messages.len() == messages.len(),
            "restarted hub returned different message count",
        );

        let recovery_sample: Vec<StreamMessageWithProof> =
            replay_messages.iter().take(2).cloned().collect();
        verify_stream_proofs(&recovery_sample, &replay_checkpoint.mmr_root)
            .context("verifying recorder proofs after restart")?;

        self.stop_hub_gracefully(restarted)
            .await
            .context("stopping recorder hub after recovery")?;

        let capture = RecorderCaptureResult {
            stream: STREAM.to_string(),
            total_events: messages.len(),
            mmr_root: mmr_root_hex,
            checkpoint_root: hex::encode(checkpoint.mmr_root.as_bytes()),
            checkpoint_path: hub.data_dir.join(CHECKPOINTS_FILE),
            sampled_seqs: sample.into_iter().map(|msg| msg.message.seq).collect(),
        };

        let recovery = RecorderRecoveryResult {
            stream: STREAM.to_string(),
            checkpoint_root: hex::encode(replay_checkpoint.mmr_root.as_bytes()),
            replay_from_seq: replay_checkpoint.upto_seq + 1,
            validated_seqs: recovery_sample
                .into_iter()
                .map(|msg| msg.message.seq)
                .collect(),
        };

        Ok((capture, recovery))
    }

    pub async fn run_hardened_flow(&self) -> Result<HardenedResult> {
        let pow_difficulty = 5u8;
        let hub = self
            .spawn_hub_with_admission(
                "hardened-hub",
                HubRole::Primary,
                &[],
                Some(pow_difficulty),
                Some(1),
            )
            .await
            .context("spawning hardened hub process")?;
        self.wait_for_health(hub.listen).await?;

        let hub_base = format!("http://{}", hub.listen);
        let submit_endpoint = format!("{hub_base}/submit");

        let client_dir = self.base_dir().join("hardened-client");
        fs::create_dir_all(&client_dir)
            .await
            .context("creating hardened client directory")?;
        self.run_cli_success(
            vec![
                OsString::from("keygen"),
                OsString::from("--out"),
                client_dir.as_os_str().to_os_string(),
            ],
            "generating hardened flow client",
        )
        .await?;

        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let forbidden = self
            .http
            .post(&submit_endpoint)
            .json(&build_submit_request(
                "hardened/pow",
                &signing_key,
                1,
                0,
                json!({ "msg": "missing pow" }),
                None,
            )?)
            .send()
            .await
            .context("submitting hardened message without pow")?;

        let pow_descriptor: PowChallengeResponse = self
            .http
            .get(format!(
                "{hub_base}/tooling/pow_request?difficulty={pow_difficulty}"
            ))
            .send()
            .await
            .context("requesting pow challenge")?
            .error_for_status()
            .context("pow challenge returned error status")?
            .json()
            .await
            .context("decoding pow challenge")?;

        ensure!(pow_descriptor.ok, "hub returned unsuccessful pow challenge");

        let challenge_bytes =
            hex::decode(&pow_descriptor.challenge).context("decoding pow challenge hex")?;
        let solved_cookie = solve_pow_cookie_with_limit(
            challenge_bytes,
            pow_descriptor.difficulty,
            Some(250_000u64),
        )
        .context("solving pow challenge")?;
        let pow_envelope = PowCookieEnvelope::from_cookie(&solved_cookie);

        let accepted: SubmitResponse = self
            .http
            .post(&submit_endpoint)
            .json(&build_submit_request(
                "hardened/pow",
                &signing_key,
                2,
                0,
                json!({ "msg": "with pow" }),
                Some(pow_envelope.clone()),
            )?)
            .send()
            .await
            .context("submitting hardened message with pow")?
            .error_for_status()
            .context("pow submission rejected")?
            .json()
            .await
            .context("decoding pow submission response")?;

        let rate_limited = self
            .http
            .post(&submit_endpoint)
            .json(&build_submit_request(
                "hardened/pow",
                &signing_key,
                3,
                0,
                json!({ "msg": "quota" }),
                Some(pow_envelope),
            )?)
            .send()
            .await
            .context("submitting hardened rate-limit probe")?;

        let replica = self
            .spawn_hub(
                "hardened-replica",
                HubRole::Replica,
                std::slice::from_ref(&hub_base),
            )
            .await
            .context("spawning hardened replica")?;
        self.wait_for_health(replica.listen).await?;
        let replica_base = format!("http://{}", replica.listen);
        let replicated_checkpoint = self
            .wait_for_checkpoint(&replica_base, accepted.seq)
            .await
            .context("waiting for hardened replica to resync")?;

        self.stop_hub_gracefully(hub).await?;
        self.stop_hub_gracefully(replica).await?;

        Ok(HardenedResult {
            pow_challenge: pow_descriptor.challenge,
            pow_difficulty: pow_descriptor.difficulty,
            pow_forbidden_status: forbidden.status(),
            pow_accept_seq: accepted.seq,
            pow_accept_root: accepted.mmr_root,
            rate_limit_status: rate_limited.status(),
            replicated_seq: replicated_checkpoint.upto_seq,
        })
    }

    pub async fn run_meta_overlay(&self) -> Result<MetaOverlayResult> {
        let hub = self
            .spawn_hub("meta-hub", HubRole::Primary, &[])
            .await
            .context("spawning meta overlay hub")?;
        self.wait_for_health(hub.listen).await?;

        let hub_base = format!("http://{}", hub.listen);

        let signing_key = SigningKey::generate(&mut OsRng);
        let schema_id = SchemaId::from(h(b"selftest/meta/schema"));
        let descriptor = SchemaDescriptor {
            schema_id,
            name: "selftest-meta".to_string(),
            version: "0.0.1".to_string(),
            doc_url: Some("https://example.invalid/meta".to_string()),
            owner: Some(SchemaOwner::from(*signing_key.verifying_key().as_bytes())),
            ts: current_unix_timestamp_millis(),
        };

        let payload = encode_signed_envelope(schema_meta_schema(), &descriptor, &signing_key)
            .context("encoding schema register payload")?;
        let register_response = self
            .http
            .post(format!("{hub_base}/schema"))
            .header("content-type", "application/cbor")
            .body(payload)
            .send()
            .await
            .context("registering schema via overlay")?;
        meta_overlay_response_or_bail(register_response, "schema register").await?;

        let registry_response = self
            .http
            .get(format!("{hub_base}/schema"))
            .send()
            .await
            .context("fetching schema registry")?;
        let registry: Vec<SchemaDescriptor> =
            meta_overlay_response_or_bail(registry_response, "schema registry list")
                .await?
                .json()
                .await
                .context("decoding schema registry")?;
        let fetched_response = self
            .http
            .get(format!(
                "{hub_base}/schema/{}",
                hex::encode(schema_id.as_bytes())
            ))
            .send()
            .await
            .context("fetching schema descriptor")?;
        let fetched: SchemaDescriptor =
            meta_overlay_response_or_bail(fetched_response, "schema registry entry fetch")
                .await?
                .json()
                .await
                .context("decoding schema descriptor")?;

        ensure!(
            fetched.schema_id == descriptor.schema_id
                && fetched.name == descriptor.name
                && fetched.version == descriptor.version,
            "fetched schema descriptor mismatch"
        );

        self.stop_hub_gracefully(hub).await?;

        Ok(MetaOverlayResult {
            schema_id_hex: hex::encode(schema_id.as_bytes()),
            descriptor_name: descriptor.name,
            descriptor_version: descriptor.version,
            registry_len: registry.len(),
        })
    }

    #[allow(dead_code)]
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

    pub(crate) async fn run_cli_success(
        &self,
        args: Vec<OsString>,
        context: &str,
    ) -> Result<CommandOutput> {
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

    pub(crate) async fn send_test_message(
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

    pub(crate) async fn fetch_stream_with_proofs(
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
            .get(format!("{hub_url}/tooling/checkpoint_latest"))
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

    async fn wait_for_checkpoint(&self, hub_url: &str, expected_seq: u64) -> Result<Checkpoint> {
        for _ in 0..HUB_HEALTH_MAX_ATTEMPTS {
            let checkpoint = self.fetch_latest_checkpoint(hub_url).await?;
            if checkpoint.upto_seq >= expected_seq {
                return Ok(checkpoint);
            }
            sleep(Duration::from_millis(HUB_HEALTH_RETRY_DELAY_MS)).await;
        }
        bail!("replica did not reach upto_seq {expected_seq}");
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

    async fn spawn_hub_with_admission(
        &self,
        name: &str,
        role: HubRole,
        replica_targets: &[String],
        pow_difficulty: Option<u8>,
        max_msgs_per_client_id_per_label: Option<u64>,
    ) -> Result<HubProcess> {
        let data_dir = self.base_dir().join(name);
        let listen = next_listen_addr()?;
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
            OsString::from("--enable-tooling"),
        ];

        if let Some(difficulty) = pow_difficulty {
            args.push(OsString::from("--pow-difficulty"));
            args.push(OsString::from(difficulty.to_string()));
        }

        if let Some(limit) = max_msgs_per_client_id_per_label {
            args.push(OsString::from("--max-msgs-per-client-id-per-label"));
            args.push(OsString::from(limit.to_string()));
        }

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
            name: name.to_string(),
            handle,
            listen,
            data_dir,
        })
    }

    pub(crate) async fn spawn_hub(
        &self,
        name: &str,
        role: HubRole,
        replica_targets: &[String],
    ) -> Result<HubProcess> {
        let data_dir = self.base_dir().join(name);
        self.spawn_hub_at_dir(name, data_dir, role, replica_targets)
            .await
    }

    async fn spawn_hub_at_dir(
        &self,
        name: &str,
        data_dir: PathBuf,
        role: HubRole,
        replica_targets: &[String],
    ) -> Result<HubProcess> {
        let listen = next_listen_addr()?;
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
            OsString::from("--enable-tooling"),
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
            name: name.to_string(),
            handle,
            listen,
            data_dir,
        })
    }

    #[allow(dead_code)]
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

    async fn stop_hub_gracefully(&self, hub: HubProcess) -> Result<()> {
        #[cfg(unix)]
        {
            let stdout_log = hub.handle.stdout_log.clone();
            let stderr_log = hub.handle.stderr_log.clone();
            let status = hub
                .handle
                .signal_and_wait(Signal::SIGINT)
                .await
                .with_context(|| format!("sending SIGINT to {}", hub.name))?;
            if !status.success() {
                let stdout = fs::read_to_string(&stdout_log)
                    .await
                    .unwrap_or_else(|_| "<unavailable>".into());
                let stderr = fs::read_to_string(&stderr_log)
                    .await
                    .unwrap_or_else(|_| "<unavailable>".into());
                bail!(
                    "hub {} did not exit cleanly with SIGINT: status {status:?}\nstdout:{}\nstderr:{}",
                    hub.name,
                    stdout,
                    stderr
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = hub;
            bail!("graceful hub shutdown is unsupported on this platform");
        }
    }

    pub(crate) async fn wait_for_health(&self, listen: SocketAddr) -> Result<()> {
        let url = format!("http://{listen}/tooling/healthz");
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

    #[allow(dead_code)]
    async fn wait_for_replication(&self, replica_url: &str) -> Result<()> {
        for attempt in 0..REPLICATION_MAX_ATTEMPTS {
            let response = self
                .http
                .post(format!("{replica_url}/tooling/resync"))
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

    #[allow(dead_code)]
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
            .get(format!("{base}/tooling/metrics"))
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
            .get(format!("{base}/tooling/healthz"))
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
    name: String,
    handle: ManagedProcess,
    listen: SocketAddr,
    data_dir: PathBuf,
}

impl HubProcess {
    pub(crate) fn listen_addr(&self) -> SocketAddr {
        self.listen
    }
}

#[allow(dead_code)]
pub struct BridgeProcess {
    handle: ManagedProcess,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HubRole {
    Primary,
    Replica,
}

pub(crate) struct CommandOutput {
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

fn validate_recorder_event(event: &RecorderEvent, entry: &StreamMessageWithProof) -> Result<()> {
    ensure!(!event.subject_id.is_empty(), "subject_id must not be empty");
    ensure!(
        !event.principal_id.is_empty() && !entry.message.client_id.is_empty(),
        "principal identifier fields must be present"
    );
    ensure!(!event.event_type.is_empty(), "event_type must not be empty");
    ensure!(event.event_time > 0, "event_time must be positive");

    Ok(())
}

fn parse_recorder_event(entry: &StreamMessageWithProof) -> Result<RecorderEvent> {
    let body_text = entry
        .message
        .body
        .as_deref()
        .ok_or_else(|| anyhow!("recorder message missing body"))?;
    let body: serde_json::Value =
        serde_json::from_str(body_text).context("decoding recorder body as JSON")?;

    let subject_id = body
        .get("subject_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("recorder body missing subject_id"))?;
    let principal_id = body
        .get("principal_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("recorder body missing principal_id"))?;
    let event_type = body
        .get("event_type")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("recorder body missing event_type"))?;
    let event_time = body
        .get("event_time")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| anyhow!("recorder body missing numeric event_time"))?;

    Ok(RecorderEvent {
        subject_id: subject_id.to_string(),
        principal_id: principal_id.to_string(),
        event_type: event_type.to_string(),
        event_time,
    })
}

fn build_submit_request(
    stream: &str,
    signing_key: &SigningKey,
    client_seq: u64,
    prev_ack: u64,
    payload: serde_json::Value,
    pow_cookie: Option<PowCookieEnvelope>,
) -> Result<SubmitRequest> {
    let payload_bytes = serde_json::to_vec(&payload).context("encoding submit payload")?;
    let msg = encode_submit_msg(stream, signing_key, client_seq, prev_ack, &payload_bytes)?;
    Ok(SubmitRequest {
        stream: stream.to_string(),
        client_id: hex::encode(signing_key.verifying_key().as_bytes()),
        msg,
        attachments: None,
        auth_ref: None,
        idem: None,
        pow_cookie,
    })
}

fn encode_submit_msg(
    stream: &str,
    signing_key: &SigningKey,
    client_seq: u64,
    prev_ack: u64,
    payload: &[u8],
) -> Result<String> {
    let label = derive_label_for_stream(stream)?;
    let profile_id = Profile::default()
        .id()
        .context("computing profile id for submit msg")?;
    let client_id = ClientId::from(*signing_key.verifying_key().as_bytes());
    let ciphertext = build_ciphertext_envelope(&[], payload, 256)?;
    if ciphertext.len() > MAX_MSG_BYTES {
        bail!(
            "submit ciphertext size {} exceeds max_msg_bytes {}",
            ciphertext.len(),
            MAX_MSG_BYTES
        );
    }
    let ct_hash = CtHash::compute(&ciphertext);
    let mut msg = Msg {
        ver: MSG_VERSION,
        profile_id,
        label,
        client_id,
        client_seq,
        prev_ack,
        auth_ref: None,
        ct_hash,
        ciphertext,
        sig: Signature64::new([0u8; 64]),
    };
    let digest = msg
        .signing_tagged_hash()
        .context("computing submit msg signing digest")?;
    let signature = signing_key.sign(digest.as_ref());
    msg.sig = Signature64::from(signature.to_bytes());
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&msg, &mut encoded).context("encoding submit msg")?;
    Ok(BASE64_STANDARD.encode(encoded))
}

fn derive_label_for_stream(stream: &str) -> Result<Label> {
    let stream_id = cap_stream_id_from_label(stream)
        .with_context(|| format!("deriving stream identifier for {}", stream))?;
    Ok(Label::derive([], stream_id, 0))
}

fn build_ciphertext_envelope(header: &[u8], body: &[u8], pad_block: u64) -> Result<Vec<u8>> {
    if header.len() > u32::MAX as usize || body.len() > u32::MAX as usize {
        bail!("ciphertext lengths overflow u32");
    }
    let mut ciphertext =
        Vec::with_capacity(HPKE_ENC_LEN + CIPHERTEXT_LEN_PREFIX + header.len() + body.len());
    ciphertext.extend_from_slice(&[0u8; HPKE_ENC_LEN]);
    ciphertext.extend_from_slice(&(header.len() as u32).to_be_bytes());
    ciphertext.extend_from_slice(&(body.len() as u32).to_be_bytes());
    ciphertext.extend_from_slice(header);
    ciphertext.extend_from_slice(body);
    if pad_block > 0 {
        let pad_block = usize::try_from(pad_block)
            .map_err(|_| anyhow!("invalid pad_block size {pad_block}"))?;
        if pad_block == 0 {
            bail!("pad_block must be non-zero when enabled");
        }
        let remainder = ciphertext.len() % pad_block;
        if remainder != 0 {
            let padding = pad_block - remainder;
            ciphertext.extend(std::iter::repeat_n(0u8, padding));
        }
    }
    Ok(ciphertext)
}

fn message_leaf_hash(message: &StoredMessage) -> Result<LeafHash> {
    if let Some(leaf) = wire_leaf_hash(message)? {
        return Ok(leaf);
    }
    let encoded =
        serde_json::to_vec(message).context("encoding message for leaf hash computation")?;
    let digest = sha2::Sha256::digest(&encoded);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(LeafHash::new(bytes))
}

fn wire_leaf_hash(message: &StoredMessage) -> Result<Option<LeafHash>> {
    let Some(label_hex) = message.label.as_ref() else {
        return Ok(None);
    };
    let Some(profile_hex) = message.profile_id.as_ref() else {
        return Ok(None);
    };
    let Some(ct_hash_hex) = message.ct_hash.as_ref() else {
        return Ok(None);
    };
    let Some(client_seq) = message.client_seq else {
        return Ok(None);
    };

    let label_bytes =
        hex::decode(label_hex).with_context(|| format!("decoding label {}", label_hex))?;
    let profile_bytes =
        hex::decode(profile_hex).with_context(|| format!("decoding profile_id {}", profile_hex))?;
    let ct_hash_bytes =
        hex::decode(ct_hash_hex).with_context(|| format!("decoding ct_hash {}", ct_hash_hex))?;

    let label = Label::from_slice(&label_bytes).context("parsing label from stored message")?;
    let profile_id = veen_core::ProfileId::from_slice(&profile_bytes)
        .context("parsing profile_id from stored message")?;
    let ct_hash =
        CtHash::from_slice(&ct_hash_bytes).context("parsing ct_hash from stored message")?;
    let client_id =
        ClientId::from_str(&message.client_id).context("parsing client_id from stored message")?;

    Ok(Some(LeafHash::derive(
        &label,
        &profile_id,
        &ct_hash,
        &client_id,
        client_seq,
    )))
}

fn parse_mmr_root_hex(value: &str) -> Result<MmrRoot> {
    let bytes = hex::decode(value).with_context(|| format!("decoding mmr_root {}", value))?;
    MmrRoot::from_slice(&bytes).with_context(|| format!("parsing mmr_root {}", value))
}

fn verify_stream_proofs(
    messages: &[StreamMessageWithProof],
    expected_root: &MmrRoot,
) -> Result<()> {
    for entry in messages {
        let proof = entry
            .proof
            .clone()
            .try_into_mmr()
            .context("decoding stream proof")?;
        ensure!(
            proof.leaf_hash == message_leaf_hash(&entry.message)?,
            "proof leaf hash mismatch for seq {}",
            entry.message.seq,
        );
        ensure!(
            proof.verify(expected_root),
            "proof verification failed for seq {}",
            entry.message.seq,
        );
    }
    Ok(())
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

#[derive(Serialize)]
struct SignedEnvelope<T>
where
    T: Serialize + Clone,
{
    #[serde(with = "serde_bytes")]
    schema: ByteBuf,
    body: T,
    #[serde(with = "serde_bytes")]
    signature: ByteBuf,
}

fn encode_signed_envelope<T>(
    schema: [u8; 32],
    body: &T,
    signing_key: &SigningKey,
) -> Result<Vec<u8>>
where
    T: Serialize + Clone,
{
    let mut body_bytes = Vec::new();
    ciborium::ser::into_writer(body, &mut body_bytes)
        .map_err(|err| anyhow!("failed to encode payload body to CBOR: {err}"))?;

    let mut signing_input = Vec::with_capacity(schema.len() + body_bytes.len());
    signing_input.extend_from_slice(&schema);
    signing_input.extend_from_slice(&body_bytes);
    let digest = ht(ADMIN_SIGNING_DOMAIN, &signing_input);

    let signature = signing_key.sign(digest.as_ref());
    let envelope = SignedEnvelope {
        schema: ByteBuf::from(schema.to_vec()),
        body: body.clone(),
        signature: ByteBuf::from(signature.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut encoded)
        .map_err(|err| anyhow!("failed to encode signed envelope: {err}"))?;
    Ok(encoded)
}

fn solve_pow_cookie_with_limit(
    challenge: Vec<u8>,
    difficulty: u8,
    max_iterations: Option<u64>,
) -> Result<PowCookie> {
    let limit = max_iterations.unwrap_or(u64::MAX);
    for nonce in 0..limit {
        let mut hasher = Sha256::new();
        hasher.update(&challenge);
        hasher.update(nonce.to_le_bytes());
        let digest = hasher.finalize();
        if digest
            .iter()
            .take((difficulty / 8) as usize)
            .all(|b| *b == 0)
        {
            let remaining = difficulty % 8;
            if remaining == 0
                || (digest
                    .get((difficulty / 8) as usize)
                    .map(|byte| byte.leading_zeros() >= remaining as u32)
                    .unwrap_or(false))
            {
                return Ok(PowCookie {
                    challenge,
                    nonce,
                    difficulty,
                });
            }
        }
    }

    bail!("unable to satisfy pow difficulty {difficulty} within iteration budget");
}

fn current_unix_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

async fn meta_overlay_response_or_bail(
    response: reqwest::Response,
    action: &str,
) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let mut message = format!("meta overlay {action} failed with status {status}");
    if !body.trim().is_empty() {
        message.push_str(&format!(": {body}"));
    }
    if matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED | StatusCode::BAD_REQUEST
    ) {
        message.push_str(
            ". META0+ overlay tests require a hub that exposes the schema registry endpoints \
            (/schema and /schema/<id>), has a writable data directory for registry persistence, \
            and is built/configured with META0+ support. If you are using a custom hub config, \
            verify it is loaded and does not disable schema registry features.",
        );
    }
    bail!(message);
}

pub async fn run_core_suite() -> Result<()> {
    let mut harness = IntegrationHarness::new().await?;
    harness.run_core_suite().await
}

#[allow(dead_code)]
pub async fn run_overlay_suite() -> Result<()> {
    let mut harness = IntegrationHarness::new().await?;
    harness.run_federation_suite().await
}
