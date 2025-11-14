use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use reqwest::Client;
use sha2::Digest;
use tempfile::TempDir;
use tokio::fs::{self, File};
use tokio::io::{self, AsyncRead, AsyncWriteExt};
use tokio::process::{Child, Command as TokioCommand};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::warn;

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
        let cli = dir.join(format!("veen-cli{}", std::env::consts::EXE_SUFFIX));
        let bridge = dir.join(format!("veen-bridge{}", std::env::consts::EXE_SUFFIX));
        ensure_binary(&hub, "veen-hub")?;
        ensure_binary(&cli, "veen-cli")?;
        ensure_binary(&bridge, "veen-bridge")?;
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

fn ensure_binary(path: &Path, crate_name: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    let status = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg(crate_name)
        .arg("--bin")
        .arg(crate_name)
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

        // Explain error codes to ensure table is wired
        let explain = self
            .run_cli_success(
                vec![OsString::from("explain-error"), OsString::from("E.AUTH")],
                "explaining error code",
            )
            .await?;
        ensure_contains(&explain.stdout, "E.AUTH", "explain-error emits description")?;

        // Health + metrics diagnostics
        self.fetch_metrics(&hub_url).await?;
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
                &[replica_target.clone()],
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

        let mut args = vec![
            OsString::from("run"),
            OsString::from("--listen"),
            OsString::from(listen.to_string()),
            OsString::from("--data-dir"),
            data_dir.as_os_str().to_os_string(),
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
        for attempt in 0..40 {
            match self.http.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    warn!("hub health attempt {} returned {}", attempt, resp.status());
                }
                Err(err) => {
                    warn!("hub health attempt {} failed: {}", attempt, err);
                }
            }
            sleep(Duration::from_millis(250)).await;
        }
        bail!("hub at {url} did not become healthy within timeout");
    }

    async fn wait_for_replication(&self, replica_url: &str) -> Result<()> {
        for attempt in 0..40 {
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
            sleep(Duration::from_millis(250)).await;
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

    async fn fetch_metrics(&self, base: &str) -> Result<String> {
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
        Ok(body)
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

fn ensure_contains(haystack: &str, needle: &str, context: &str) -> Result<()> {
    if !haystack.contains(needle) {
        bail!("expected {context}; missing `{needle}` in `{haystack}`");
    }
    Ok(())
}

fn extract_mmr_root(metrics: &str, stream: &str) -> Option<String> {
    metrics
        .lines()
        .find(|line| line.contains("veen_mmr_root{") && line.contains(stream))
        .and_then(|line| line.split_whitespace().last())
        .map(|value| value.trim().to_string())
}

pub async fn run_core_suite() -> Result<()> {
    let mut harness = IntegrationHarness::new().await?;
    harness.run_core_suite().await
}

pub async fn run_overlay_suite() -> Result<()> {
    let mut harness = IntegrationHarness::new().await?;
    harness.run_federation_suite().await
}
