use super::*;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use clap::Parser;
use ed25519_dalek::{Signature, Verifier};
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request as HyperRequest, Response as HyperResponse, Server, StatusCode};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;
use tokio::time::sleep;
use veen_core::wire::types::{MmrRoot, Signature64};
use veen_hub::runtime::HubRuntime;
use veen_hub::runtime::{HubConfigOverrides, HubRole, HubRuntimeConfig};

fn dummy_receipt(stream_seq: u64) -> Receipt {
    Receipt {
        ver: 1,
        label: Label::from_slice(&[0u8; 32]).expect("label bytes"),
        stream_seq,
        leaf_hash: LeafHash::new([0u8; 32]),
        mmr_root: MmrRoot::new([0u8; 32]),
        hub_ts: 0,
        hub_sig: Signature64::new([0u8; 64]),
    }
}

#[test]
fn parse_label_map_entries_parses_pairs() -> anyhow::Result<()> {
    let entries = vec!["alpha=beta".to_string(), "foo = bar/baz".to_string()];
    let map = super::parse_label_map_entries(&entries)?;
    assert_eq!(map.get("alpha").cloned(), Some("beta".to_string()));
    assert_eq!(map.get("foo").cloned(), Some("bar/baz".to_string()));
    Ok(())
}

#[test]
fn parse_label_map_entries_rejects_duplicates() {
    let entries = vec!["alpha=one".to_string(), "alpha=two".to_string()];
    let err = super::parse_label_map_entries(&entries).unwrap_err();
    assert!(err.to_string().contains("duplicate --label-map entry"));
}

#[test]
fn args_request_json_output_detects_flag() {
    let args = vec![
        OsString::from("veen"),
        OsString::from("--json"),
        OsString::from("hub"),
    ];
    assert!(super::args_request_json_output(&args));

    let no_flag = vec![OsString::from("veen"), OsString::from("hub")];
    assert!(!super::args_request_json_output(&no_flag));
}

#[test]
fn help_command_parses_subcommand_path() {
    let cli = Cli::parse_from(["veen", "help", "hub", "tls-info"]);

    match cli.command {
        Command::Help(args) => {
            assert_eq!(
                args.command,
                vec!["hub".to_string(), "tls-info".to_string()]
            );
        }
        _ => panic!("unexpected command parsed"),
    }
}

#[test]
fn try_fast_path_does_not_intercept_help() {
    let top_level_help = vec![OsString::from("veen"), OsString::from("--help")];
    assert_eq!(super::try_fast_path(&top_level_help), None);

    let help_command = vec![OsString::from("veen"), OsString::from("help")];
    assert_eq!(super::try_fast_path(&help_command), None);
}

#[test]
fn operation_command_accepts_op_alias() {
    let cli = Cli::parse_from([
        "veen",
        "op",
        "paid",
        "--client",
        "/tmp/veen-client",
        "--stream",
        "wallet/main",
        "--op-type",
        "transfer",
        "--payer",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "--payee",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "--amount",
        "10",
        "--currency-code",
        "JPY",
    ]);

    match cli.command {
        Command::Operation(OperationCommand::Paid(_)) => {}
        _ => panic!("expected `op paid` alias to map to operation paid"),
    }
}

#[test]
fn hub_name_requires_env_descriptor() {
    let result = Cli::try_parse_from([
        "veen",
        "stream",
        "--hub-name",
        "primary",
        "--client",
        "/tmp/veen-client",
        "--stream",
        "demo/main",
    ]);
    let err = match result {
        Ok(_) => panic!("expected --hub-name without --env to fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("--env"));
}

#[test]
fn env_descriptor_requires_hub_name() {
    let result = Cli::try_parse_from([
        "veen",
        "stream",
        "--env",
        "/tmp/demo.env.json",
        "--client",
        "/tmp/veen-client",
        "--stream",
        "demo/main",
    ]);
    let err = match result {
        Ok(_) => panic!("expected --env without --hub-name to fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("--hub-name"));
}

#[test]
fn send_pow_inputs_require_difficulty() {
    let result = Cli::try_parse_from([
        "veen",
        "send",
        "--client",
        "/tmp/veen-client",
        "--stream",
        "demo/main",
        "--body",
        "hello",
        "--pow-challenge",
        "deadbeef",
    ]);
    let err = match result {
        Ok(_) => panic!("expected --pow-challenge without --pow-difficulty to fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("--pow-difficulty"));
}
#[test]
fn hub_tls_info_is_nested_under_hub_command() {
    let cli = Cli::parse_from(["veen", "hub", "tls-info", "--hub", "http://localhost:8080"]);

    match cli.command {
        Command::Hub(HubCommand::TlsInfo(args)) => {
            assert_eq!(args.hub.hub, Some("http://localhost:8080".to_string()));
        }
        _ => panic!("unexpected command parsed"),
    }
}

#[test]
fn hub_start_accepts_pow_difficulty() {
    let cli = Cli::parse_from([
        "veen",
        "hub",
        "start",
        "--listen",
        "127.0.0.1:8080",
        "--data-dir",
        "/tmp/veen",
        "--pow-difficulty",
        "6",
    ]);

    match cli.command {
        Command::Hub(HubCommand::Start(args)) => {
            assert_eq!(args.pow_difficulty, Some(6));
        }
        _ => panic!("unexpected command parsed"),
    }
}

#[test]
fn hub_start_rejects_zero_pow_difficulty() {
    let err = super::hub_start_overrides("profile", Some(0), false).unwrap_err();
    assert!(err
        .to_string()
        .contains("pow-difficulty must be greater than zero"));
}

#[test]
fn hub_state_ready_requires_expected_pid() {
    let mut state = HubRuntimeState::new(Path::new("/tmp/veen"));
    state.running = true;
    state.hub_id = Some("hub-1".to_string());
    state.listen = Some("127.0.0.1:8080".to_string());
    state.pid = Some(42);

    assert!(super::hub_state_ready_for_pid(&state, 42));
    assert!(!super::hub_state_ready_for_pid(&state, 7));

    state.hub_id = None;
    assert!(!super::hub_state_ready_for_pid(&state, 42));
}

#[tokio::test]
async fn reconcile_hub_state_marks_running_without_pid_as_stopped() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let mut state = HubRuntimeState::new(dir.path());
    state.running = true;
    state.started_at = Some(1);
    save_hub_state(dir.path(), &state).await?;

    let reconciled = super::reconcile_hub_state_with_process(dir.path(), state).await?;
    assert!(!reconciled.running);
    assert!(reconciled.pid.is_none());
    assert!(reconciled.stopped_at.is_some());

    Ok(())
}

#[tokio::test]
async fn read_pid_file_cleans_up_invalid_contents() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let pid_path = dir.path().join(HUB_PID_FILE);
    tokio::fs::write(&pid_path, "not-a-number").await?;

    let pid = read_pid_file(dir.path()).await?;
    assert!(pid.is_none());
    assert!(!tokio::fs::try_exists(&pid_path).await?);

    Ok(())
}

fn spawn_short_sleep_process() -> anyhow::Result<std::process::Child> {
    #[cfg(windows)]
    {
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Start-Sleep -Milliseconds 900"])
            .spawn()
            .context("spawning short-lived helper process on Windows")
    }

    #[cfg(not(windows))]
    {
        std::process::Command::new("sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .context("spawning short-lived helper process on unix")
    }
}

#[tokio::test]
async fn wait_for_hub_ready_rejects_stale_pid_state() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let mut state = HubRuntimeState::new(dir.path());
    state.running = true;
    state.hub_id = Some("hub-stale".to_string());
    state.listen = Some("127.0.0.1:39001".to_string());
    state.pid = Some(9999);
    save_hub_state(dir.path(), &state).await?;

    let mut child = spawn_short_sleep_process()?;
    let child_pid = child.id();

    let err = super::wait_for_hub_ready(dir.path(), child_pid, &mut child)
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("exited before reporting ready state"));

    Ok(())
}
#[test]
fn retention_value_parser_supports_seconds_and_indefinite() {
    assert_eq!(
        "600".parse::<RetentionValue>().unwrap(),
        RetentionValue::Seconds(600)
    );
    assert_eq!(
        "indefinite".parse::<RetentionValue>().unwrap(),
        RetentionValue::Indefinite
    );
    assert!("ten".parse::<RetentionValue>().is_err());
}

async fn write_test_hub_key(data_dir: &Path) -> anyhow::Result<()> {
    let path = data_dir.join(HUB_KEY_FILE);
    if tokio::fs::try_exists(&path)
        .await
        .with_context(|| format!("checking hub key at {}", path.display()))?
    {
        return Ok(());
    }

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let created_at = current_unix_timestamp()?;
    let material = HubKeyMaterial {
        version: HUB_KEY_VERSION,
        created_at,
        public_key: ByteBuf::from(verifying_key.to_bytes().to_vec()),
        secret_key: ByteBuf::from(signing_key.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&material, &mut encoded)
        .context("serialising test hub key material")?;
    tokio::fs::write(&path, encoded)
        .await
        .with_context(|| format!("writing hub key material to {}", path.display()))?;
    Ok(())
}

#[tokio::test]
async fn env_descriptor_round_trip() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("alpha.env.json");
    let descriptor = EnvDescriptor {
        version: ENV_DESCRIPTOR_VERSION,
        name: "alpha".to_string(),
        cluster_context: "kind-test".to_string(),
        namespace: "veen".to_string(),
        description: Some("test".to_string()),
        hubs: BTreeMap::new(),
        tenants: BTreeMap::new(),
    };
    write_env_descriptor(&path, &descriptor).await?;
    let loaded = read_env_descriptor(&path).await?;
    assert_eq!(loaded.name, "alpha");
    assert_eq!(loaded.cluster_context, "kind-test");
    Ok(())
}

#[tokio::test]
async fn env_descriptor_mutations_persist() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let root = dir.path().join("env");
    let init_args = EnvInitArgs {
        root: root.clone(),
        name: "demo".to_string(),
        cluster_context: "kind-demo".to_string(),
        namespace: "veen-demo".to_string(),
        description: None,
    };
    handle_env_init(init_args).await?;
    let env_path = root.join("demo.env.json");

    let add_hub = EnvAddHubArgs {
        env: env_path.clone(),
        hub_name: "primary".to_string(),
        service_url: "http://hub.demo".to_string(),
        profile_id: "a".repeat(64),
        realm: Some("b".repeat(64)),
    };
    handle_env_add_hub(add_hub).await?;

    let add_tenant = EnvAddTenantArgs {
        env: env_path.clone(),
        tenant_id: "tenant-a".to_string(),
        stream_prefix: "app".to_string(),
        label_class: Some(EnvTenantLabelClass::Wallet),
    };
    handle_env_add_tenant(add_tenant).await?;

    let descriptor = read_env_descriptor(&env_path).await?;
    let hub = descriptor.hubs.get("primary").expect("hub recorded");
    assert_eq!(hub.service_url, "http://hub.demo");
    assert_eq!(hub.profile_id, "a".repeat(64));
    let tenant = descriptor.tenants.get("tenant-a").expect("tenant recorded");
    assert_eq!(tenant.label_class, "wallet");
    assert_eq!(tenant.stream_prefix, "app");
    Ok(())
}

#[tokio::test]
async fn env_descriptor_validation_detects_empty_namespace() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("broken.env.json");
    let invalid = json!({
        "version": ENV_DESCRIPTOR_VERSION,
        "name": "broken",
        "cluster_context": "ctx",
        "namespace": "",
        "hubs": {},
        "tenants": {}
    });
    tokio::fs::write(&path, serde_json::to_vec_pretty(&invalid)?).await?;
    let err = read_env_descriptor(&path)
        .await
        .expect_err("expected namespace validation failure");
    assert!(err.to_string().contains("namespace"));
    Ok(())
}

#[tokio::test]
async fn retention_set_updates_requested_values() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let args = RetentionSetArgs {
        data_dir: dir.path().to_path_buf(),
        receipts: Some(RetentionValue::Seconds(3600)),
        payloads: Some(RetentionValue::Indefinite),
        checkpoints: None,
    };

    super::handle_retention_set(args).await?;

    let retention_path = dir.path().join(STATE_DIR).join(RETENTION_CONFIG_FILE);
    let stored: Value = read_json_file(&retention_path).await?;
    assert_eq!(stored.get("receipts"), Some(&json!(3600u64)));
    assert_eq!(stored.get("payloads"), Some(&json!("indefinite")));
    assert!(stored.get("checkpoints").is_none());
    Ok(())
}

#[test]
fn kube_render_arguments_parse() {
    let cli = Cli::try_parse_from([
        "veen",
        "kube",
        "render",
        "--cluster-context",
        "kind-test",
        "--namespace",
        "veen",
        "--name",
        "alpha",
        "--image",
        "hub:latest",
        "--data-pvc",
        "alpha-pvc",
        "--replicas",
        "2",
    ])
    .expect("cli parse");
    match cli.command {
        Command::Kube(crate::kube::KubeCommand::Render(args)) => {
            assert_eq!(args.namespace.as_deref(), Some("veen"));
            assert_eq!(args.name, "alpha");
            assert_eq!(args.replicas, 2);
        }
        _ => panic!("expected kube render command"),
    }
}

async fn spawn_cbor_capture_server(
    path: &'static str,
) -> anyhow::Result<(String, mpsc::Receiver<Vec<u8>>, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr: SocketAddr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(1);
    let service = make_service_fn(move |_| {
        let tx = tx.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |mut req: HyperRequest<Body>| {
                let tx = tx.clone();
                async move {
                    assert_eq!(req.uri().path(), path);
                    let body = to_bytes(req.body_mut())
                        .await
                        .context("capture server failed to read request body")
                        .map_err(|err| ProtocolError::new(err.to_string()))?
                        .to_vec();
                    tx.send(body)
                        .await
                        .context("capture server failed to forward request body")
                        .map_err(|err| ProtocolError::new(err.to_string()))?;
                    Ok::<_, anyhow::Error>(
                        HyperResponse::builder()
                            .status(StatusCode::OK)
                            .body(Body::from("null"))
                            .unwrap(),
                    )
                }
            }))
        }
    });
    let server = Server::from_tcp(listener)?.serve(service);
    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("capture server error: {err}");
        }
    });
    Ok((format!("http://{}", addr), rx, handle))
}

async fn spawn_submit_capture_server(
    response: RemoteSubmitResponse,
) -> anyhow::Result<(String, mpsc::Receiver<Vec<u8>>, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr: SocketAddr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(1);
    let response = Arc::new(response);
    let service = make_service_fn(move |_| {
        let tx = tx.clone();
        let response = Arc::clone(&response);
        async move {
            Ok::<_, Infallible>(service_fn(move |mut req: HyperRequest<Body>| {
                let tx = tx.clone();
                let response = Arc::clone(&response);
                async move {
                    assert_eq!(req.method(), Method::POST);
                    assert_eq!(req.uri().path(), "/v1/submit");
                    let body = to_bytes(req.body_mut())
                        .await
                        .context("submit capture server failed to read request body")
                        .map_err(|err| ProtocolError::new(err.to_string()))?
                        .to_vec();
                    tx.send(body)
                        .await
                        .context("submit capture server failed to forward request body")
                        .map_err(|err| ProtocolError::new(err.to_string()))?;
                    let response = RemoteSubmitResponse {
                        ver: DATA_PLANE_VERSION,
                        receipt: response.receipt.clone(),
                        server_version: response.server_version.clone(),
                    };
                    let mut cbor = Vec::new();
                    ciborium::ser::into_writer(&response, &mut cbor).unwrap();
                    Ok::<_, anyhow::Error>(
                        HyperResponse::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", "application/cbor")
                            .body(Body::from(cbor))
                            .unwrap(),
                    )
                }
            }))
        }
    });
    let server = Server::from_tcp(listener)?.serve(service);
    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("capture server error: {err}");
        }
    });
    Ok((format!("http://{}", addr), rx, handle))
}

struct DecodedSubmitRequest {
    pow_cookie: Option<PowCookieEnvelope>,
}

fn decode_submit_request_cbor(body: &[u8]) -> anyhow::Result<DecodedSubmitRequest> {
    let mut cursor = Cursor::new(body);
    let map: BTreeMap<u64, CborValue> = ciborium::de::from_reader(&mut cursor)?;
    let pow_cookie = match map.get(&8) {
        Some(value) => Some(decode_cbor_value(value)?),
        None => None,
    };
    Ok(DecodedSubmitRequest { pow_cookie })
}

fn decode_cbor_value<T: DeserializeOwned>(value: &CborValue) -> anyhow::Result<T> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded)?;
    let mut cursor = Cursor::new(encoded);
    Ok(ciborium::de::from_reader(&mut cursor)?)
}

async fn spawn_fixed_response_server(
    path: &'static str,
    body: Vec<u8>,
) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr: SocketAddr = listener.local_addr()?;
    let body = Arc::new(body);
    let service = make_service_fn(move |_| {
        let body = body.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: HyperRequest<Body>| {
                let body = body.clone();
                async move {
                    assert_eq!(req.uri().path(), path);
                    Ok::<_, Infallible>(
                        HyperResponse::builder()
                            .status(StatusCode::OK)
                            .body(Body::from(body.as_ref().clone()))
                            .unwrap(),
                    )
                }
            }))
        }
    });
    let server = Server::from_tcp(listener)?.serve(service);
    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("fixed response server error: {err}");
        }
    });
    Ok((format!("http://{}", addr), handle))
}

fn verify_envelope_signature<T>(
    envelope: &SignedEnvelope<T>,
    schema: [u8; 32],
    signing_key: &SigningKey,
) -> anyhow::Result<()>
where
    T: Serialize,
{
    let verifying_key = signing_key.verifying_key();
    let mut body_bytes = Vec::new();
    ciborium::ser::into_writer(&envelope.body, &mut body_bytes)?;
    let mut signing_input = Vec::with_capacity(schema.len() + body_bytes.len());
    signing_input.extend_from_slice(&schema);
    signing_input.extend_from_slice(&body_bytes);
    let digest = ht(ADMIN_SIGNING_DOMAIN, &signing_input);
    let signature_bytes: [u8; 64] = envelope
        .signature
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("invalid signature length"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(digest.as_ref(), &signature)
        .map_err(|err| anyhow!("signature verification failed: {err}"))?;
    Ok(())
}

#[test]
fn json_output_enabled_uses_global_flag() {
    let global_json = GlobalOptions {
        json: true,
        quiet: false,
        verbose: false,
        timeout_ms: None,
    };
    assert!(super::json_output_enabled_with(false, &global_json));

    let global_text = GlobalOptions {
        json: false,
        quiet: false,
        verbose: false,
        timeout_ms: None,
    };
    assert!(super::json_output_enabled_with(true, &global_text));
    assert!(!super::json_output_enabled_with(false, &global_text));

    let global_quiet = GlobalOptions {
        json: false,
        quiet: true,
        verbose: false,
        timeout_ms: None,
    };
    assert!(super::json_output_enabled_with(true, &global_quiet));
    assert!(!super::json_output_enabled_with(false, &global_quiet));
}

#[test]
fn remote_health_json_includes_expected_fields() -> anyhow::Result<()> {
    let mut submit_err_total = BTreeMap::new();
    submit_err_total.insert("E.HUB".to_string(), 2);
    let mut last_stream_seq = BTreeMap::new();
    last_stream_seq.insert("core/main".to_string(), 5);
    let mut mmr_roots = BTreeMap::new();
    mmr_roots.insert("core/main".to_string(), "abcd".to_string());

    let health = RemoteHealthStatus {
        ok: true,
        uptime: Duration::from_secs(42),
        submit_ok_total: 7,
        submit_err_total,
        last_stream_seq,
        mmr_roots,
        peaks_count: 9,
        profile_id: Some("deadbeef".to_string()),
        hub_id: Some("hub-01".to_string()),
        hub_public_key: None,
        role: "standalone".to_string(),
        data_dir: "/tmp/veen".to_string(),
    };

    let rendered = super::render_remote_health_json(&health)?;
    assert_eq!(rendered["ok"], json!(true));
    assert_eq!(rendered["uptime_sec"], json!(42));
    assert_eq!(rendered["profile_id"], json!("deadbeef"));
    assert_eq!(rendered["hub_id"], json!("hub-01"));
    assert!(rendered["hub_pk"].is_null());
    assert_eq!(rendered["submit_ok_total"], json!(7));
    assert_eq!(rendered["submit_err_total"]["E.HUB"], json!(2));
    assert_eq!(rendered["last_stream_seq"]["core/main"], json!(5));
    assert_eq!(rendered["mmr_roots"]["core/main"], json!("abcd"));
    assert_eq!(rendered["data_dir"], json!("/tmp/veen"));

    Ok(())
}

#[test]
fn local_health_json_tracks_runtime_state() {
    let mut state = HubRuntimeState::new(Path::new("/var/lib/veen"));
    state.running = true;
    state.started_at = Some(10);
    state.profile_id = Some("abcd".to_string());
    state.hub_id = Some("hub-1".to_string());
    state.peaks_count = 11;
    state.metrics.submit_ok_total = 3;
    state
        .metrics
        .submit_err_total
        .insert("E.HUB".to_string(), 1);
    state.last_stream_seq.insert("core/main".to_string(), 4);

    let rendered = super::render_local_health_json(&state, 20);
    assert_eq!(rendered["ok"], json!(true));
    assert_eq!(rendered["uptime_sec"], json!(10));
    assert_eq!(rendered["peaks_count"], json!(11));
    assert_eq!(rendered["profile_id"], json!("abcd"));
    assert_eq!(rendered["hub_id"], json!("hub-1"));
    assert_eq!(rendered["submit_ok_total"], json!(3));
    assert_eq!(rendered["submit_err_total"]["E.HUB"], json!(1));
    assert_eq!(rendered["last_stream_seq"]["core/main"], json!(4));
    assert_eq!(rendered["data_dir"], json!("/var/lib/veen"));
    assert!(rendered["hub_pk"].is_null());
}

#[test]
fn hub_profile_output_matches_cli_goals() -> anyhow::Result<()> {
    let features = RemoteHubProfileFeatures {
        core: true,
        fed1: true,
        auth1: true,
        kex1_plus: true,
        sh1_plus: false,
        lclass0: false,
        meta0_plus: true,
    };

    let text =
        super::format_hub_profile_output(true, "veen-0.0.1+", "abcd", "hub-0001", &features, false);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "version: veen-0.0.1+");
    assert_eq!(lines[1], "profile_id: abcd");
    assert_eq!(lines[2], "hub_id: hub-0001");
    assert_eq!(lines[3], "features:");
    assert_eq!(lines[4], "  core: true");
    assert_eq!(lines[5], "  fed1: true");
    assert_eq!(lines[6], "  auth1: true");
    assert_eq!(lines[7], "  kex1_plus: true");
    assert_eq!(lines[8], "  sh1_plus: false");
    assert_eq!(lines[9], "  lclass0: false");
    assert_eq!(lines[10], "  meta0_plus: true");

    let json =
        super::format_hub_profile_output(true, "veen-0.0.1+", "abcd", "hub-0001", &features, true);
    let value: Value = serde_json::from_str(&json)
        .context("hub profile JSON output should be valid")
        .map_err(|err| ProtocolError::new(err.to_string()))?;
    assert_eq!(value["version"], "veen-0.0.1+");
    assert_eq!(value["profile_id"], "abcd");
    assert_eq!(value["hub_id"], "hub-0001");
    assert_eq!(value["features"]["core"], Value::Bool(true));
    assert_eq!(value["features"]["sh1_plus"], Value::Bool(false));
    Ok(())
}

#[test]
fn hub_role_output_matches_cli_goals() -> anyhow::Result<()> {
    let stream = RemoteHubRoleStream {
        realm_id: Some("aaaa".to_string()),
        stream_id: "bbbb".to_string(),
        label: "fed/chat".to_string(),
        policy: "single-primary".to_string(),
        primary_hub: Some("hub-primary".to_string()),
        local_is_primary: true,
    };

    let text = super::format_hub_role_output(
        true,
        "hub-primary",
        "federated-primary",
        Some(&stream),
        false,
    );
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "hub_id: hub-primary");
    assert_eq!(lines[1], "role: federated-primary");
    assert_eq!(lines[2], "realm_id: aaaa");
    assert_eq!(lines[3], "stream_id: bbbb");
    assert_eq!(lines[4], "label: fed/chat");
    assert_eq!(lines[5], "policy: single-primary");
    assert_eq!(lines[6], "primary_hub: hub-primary");
    assert_eq!(lines[7], "local_is_primary: true");

    let stream_without_defaults = RemoteHubRoleStream {
        realm_id: None,
        stream_id: "cccc".to_string(),
        label: "fed/alt".to_string(),
        policy: "multi-primary".to_string(),
        primary_hub: None,
        local_is_primary: false,
    };
    let json = super::format_hub_role_output(
        true,
        "hub-observer",
        "observer",
        Some(&stream_without_defaults),
        true,
    );
    let value: Value = serde_json::from_str(&json)
        .context("hub role JSON output should be valid")
        .map_err(|err| ProtocolError::new(err.to_string()))?;
    assert_eq!(value["hub_id"], "hub-observer");
    assert_eq!(value["role"], "observer");
    assert_eq!(value["stream"]["realm_id"], Value::Null);
    assert_eq!(value["stream"]["primary_hub"], Value::Null);
    assert_eq!(value["stream"]["local_is_primary"], Value::Bool(false));
    Ok(())
}

#[test]
fn authority_record_output_matches_cli_goals() {
    let descriptor = RemoteAuthorityRecordDescriptor {
        ok: true,
        realm_id: "aaaa".to_string(),
        stream_id: "bbbb".to_string(),
        primary_hub: Some("hub-primary".to_string()),
        replica_hubs: vec!["hub-replica-1".to_string(), "hub-replica-2".to_string()],
        policy: "single-primary".to_string(),
        ts: 1,
        ttl: 60,
        expires_at: Some(61),
        active_now: true,
    };

    let text = super::format_authority_record_output(&descriptor, false);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "realm_id: aaaa");
    assert_eq!(lines[1], "stream_id: bbbb");
    assert_eq!(lines[2], "primary_hub: hub-primary");
    assert_eq!(lines[3], "replica_hubs: [hub-replica-1,hub-replica-2]");
    assert_eq!(lines[4], "policy: single-primary");
    assert_eq!(lines[5], "ts: 1");
    assert_eq!(lines[6], "ttl: 60");
    assert_eq!(lines[7], "expires_at: 61");
    assert_eq!(lines[8], "active_now: true");
}

#[test]
fn authority_record_json_output_matches_cli_goals() -> anyhow::Result<()> {
    let descriptor = RemoteAuthorityRecordDescriptor {
        ok: true,
        realm_id: "ffff".to_string(),
        stream_id: "eeee".to_string(),
        primary_hub: None,
        replica_hubs: Vec::new(),
        policy: "unspecified".to_string(),
        ts: 99,
        ttl: 0,
        expires_at: None,
        active_now: false,
    };

    let json = super::format_authority_record_output(&descriptor, true);
    let value: Value = serde_json::from_str(&json)
        .context("authority record JSON output should be valid")
        .map_err(|err| ProtocolError::new(err.to_string()))?;
    assert_eq!(value["realm_id"], "ffff");
    assert_eq!(value["stream_id"], "eeee");
    assert_eq!(value["primary_hub"], Value::Null);
    assert_eq!(value["replica_hubs"], json!([]));
    assert_eq!(value["policy"], "unspecified");
    assert_eq!(value["ts"], 99);
    assert_eq!(value["ttl"], 0);
    assert_eq!(value["expires_at"], Value::Null);
    assert_eq!(value["active_now"], Value::Bool(false));
    Ok(())
}

#[test]
fn schema_show_text_output_matches_cli_goals() {
    let descriptor = RemoteSchemaDescriptorEntry {
        schema_id: "abcd".to_string(),
        name: "test.operation.v1".to_string(),
        version: "1".to_string(),
        doc_url: Some("https://schemas/test".to_string()),
        owner: Some("0123".to_string()),
        ts: 123,
        created_at: Some(100),
        updated_at: Some(120),
    };
    let usage = RemoteSchemaUsage {
        used_labels: vec!["core/example".to_string(), "core/audit".to_string()],
        used_count: Some(7),
        first_used_ts: Some(101),
        last_used_ts: Some(125),
    };

    let text = super::format_schema_descriptor_output(&descriptor, Some(&usage), false);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "schema_id: abcd");
    assert_eq!(lines[1], "name: test.operation.v1");
    assert_eq!(lines[2], "version: 1");
    assert_eq!(lines[3], "doc_url: https://schemas/test");
    assert_eq!(lines[4], "owner: 0123");
    assert_eq!(lines[5], "ts: 123");
    assert_eq!(lines[6], "created_at: 100");
    assert_eq!(lines[7], "updated_at: 120");
    assert_eq!(lines[8], "used_labels: [core/example,core/audit]");
    assert_eq!(lines[9], "used_count: 7");
    assert_eq!(lines[10], "first_used_ts: 101");
    assert_eq!(lines[11], "last_used_ts: 125");
}

#[test]
fn schema_show_json_output_matches_cli_goals() -> anyhow::Result<()> {
    let descriptor = RemoteSchemaDescriptorEntry {
        schema_id: "a1b2".to_string(),
        name: "audit.record.v1".to_string(),
        version: "1".to_string(),
        doc_url: None,
        owner: None,
        ts: 42,
        created_at: None,
        updated_at: None,
    };
    let usage = RemoteSchemaUsage {
        used_labels: vec!["core/main".to_string()],
        used_count: Some(1),
        first_used_ts: Some(10),
        last_used_ts: Some(20),
    };

    let json = super::format_schema_descriptor_output(&descriptor, Some(&usage), true);
    let value: Value = serde_json::from_str(&json)
        .context("schema descriptor JSON output should be valid")
        .map_err(|err| ProtocolError::new(err.to_string()))?;
    assert_eq!(value["schema_id"], "a1b2");
    assert_eq!(value["name"], "audit.record.v1");
    assert_eq!(value["doc_url"], Value::Null);
    assert_eq!(value["owner"], Value::Null);
    assert_eq!(value["usage"]["used_labels"], json!(["core/main"]));
    assert_eq!(value["usage"]["used_count"], 1);
    assert_eq!(value["usage"]["first_used_ts"], 10);
    assert_eq!(value["usage"]["last_used_ts"], 20);
    Ok(())
}

#[test]
fn label_authority_output_matches_cli_goals() -> anyhow::Result<()> {
    let descriptor = RemoteLabelAuthorityDescriptor {
        ok: true,
        label: "fed/chat".to_string(),
        realm_id: None,
        stream_id: "bbbb".to_string(),
        policy: "single-primary".to_string(),
        primary_hub: None,
        replica_hubs: vec!["hub-replica".to_string()],
        local_hub_id: "hub-local".to_string(),
        local_is_authorized: true,
    };

    let json = super::format_label_authority_output(&descriptor, true);
    let value: Value = serde_json::from_str(&json)
        .context("label authority JSON output should be valid")
        .map_err(|err| ProtocolError::new(err.to_string()))?;
    assert_eq!(value["label"], "fed/chat");
    assert_eq!(value["realm_id"], Value::Null);
    assert_eq!(value["stream_id"], "bbbb");
    assert_eq!(value["primary_hub"], Value::Null);
    assert_eq!(value["replica_hubs"], json!(["hub-replica"]));
    assert_eq!(value["locally_authorized"], Value::Bool(true));
    Ok(())
}

#[test]
fn label_authority_text_output_matches_cli_goals() {
    let descriptor = RemoteLabelAuthorityDescriptor {
        ok: true,
        label: "fed/debug".to_string(),
        realm_id: Some("bbbb".to_string()),
        stream_id: "cccc".to_string(),
        policy: "single-primary".to_string(),
        primary_hub: Some("hub-primary".to_string()),
        replica_hubs: vec![],
        local_hub_id: "hub-local".to_string(),
        local_is_authorized: false,
    };

    let text = super::format_label_authority_output(&descriptor, false);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "label: fed/debug");
    assert_eq!(lines[1], "realm_id: bbbb");
    assert_eq!(lines[2], "stream_id: cccc");
    assert_eq!(lines[3], "policy: single-primary");
    assert_eq!(lines[4], "primary_hub: hub-primary");
    assert_eq!(lines[5], "local_hub_id: hub-local");
    assert_eq!(lines[6], "locally_authorized: false");
}

#[tokio::test]
async fn http_send_stream_and_resync() -> anyhow::Result<()> {
    let hub_dir = tempdir()?;
    let client_dir = tempdir()?;

    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let listen: SocketAddr = socket.local_addr()?;
    drop(socket);
    let mut config = HubRuntimeConfig::from_sources(
        listen,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            capability_gating_enabled: Some(false),
            tooling_enabled: Some(true),
            ..Default::default()
        },
    )
    .await?;
    config.tooling_enabled = true;
    write_test_hub_key(hub_dir.path()).await?;
    let runtime = HubRuntime::start(config).await?;
    let hub_url = format!("http://{}", runtime.listen_addr());

    sleep(Duration::from_millis(50)).await;

    handle_keygen(KeygenArgs {
        out: client_dir.path().to_path_buf(),
    })
    .await?;

    handle_send(SendArgs {
        hub: HubLocatorArgs::from_url(hub_url.clone()),
        client: client_dir.path().to_path_buf(),
        stream: "test".to_string(),
        body: json!({ "msg": "hello" }).to_string(),
        schema: None,
        expires_at: None,
        cap: None,
        parent: None,
        attach: Vec::new(),
        no_store_body: false,
        pow_difficulty: None,
        pow_challenge: None,
        pow_nonce: None,
    })
    .await?;

    handle_stream(StreamArgs {
        hub: HubLocatorArgs::from_url(hub_url.clone()),
        client: client_dir.path().to_path_buf(),
        stream: "test".to_string(),
        from: 0,
        to: None,
        with_proof: false,
    })
    .await?;

    handle_resync(ResyncArgs {
        hub: HubLocatorArgs::from_url(hub_url),
        client: client_dir.path().to_path_buf(),
        stream: "test".to_string(),
    })
    .await?;

    let state_path = client_dir.path().join("state.json");
    let state: ClientStateFile = read_json_file(&state_path).await?;
    let seq = state
        .labels
        .get("test")
        .map(|label| label.last_stream_seq)
        .unwrap_or(0);
    assert_eq!(seq, 1);

    runtime.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn send_remote_auto_solves_pow_cookie() -> anyhow::Result<()> {
    let client_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: client_dir.path().to_path_buf(),
    })
    .await?;

    let response = RemoteSubmitResponse {
        ver: DATA_PLANE_VERSION,
        receipt: dummy_receipt(1),
        server_version: None,
    };
    let (url, mut body_rx, server) = spawn_submit_capture_server(response).await?;

    let challenge_hex = "0abc".to_string();
    handle_send(SendArgs {
        hub: HubLocatorArgs::from_url(url.to_string()),
        client: client_dir.path().to_path_buf(),
        stream: "pow".to_string(),
        body: json!({ "msg": "pow" }).to_string(),
        schema: None,
        expires_at: None,
        cap: None,
        parent: None,
        attach: Vec::new(),
        no_store_body: false,
        pow_difficulty: Some(4),
        pow_challenge: Some(challenge_hex.clone()),
        pow_nonce: None,
    })
    .await?;

    let body = body_rx.recv().await.expect("payload captured");
    server.abort();

    let request = decode_submit_request_cbor(&body)?;
    let cookie = request.pow_cookie.expect("pow cookie present");
    assert_eq!(cookie.difficulty, 4);
    let pow_cookie = cookie.into_pow_cookie();
    assert!(pow_cookie.meets_difficulty());
    assert_eq!(hex::encode(pow_cookie.challenge), challenge_hex);

    Ok(())
}

#[tokio::test]
async fn send_remote_accepts_user_supplied_pow_cookie() -> anyhow::Result<()> {
    let client_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: client_dir.path().to_path_buf(),
    })
    .await?;

    let response = RemoteSubmitResponse {
        ver: DATA_PLANE_VERSION,
        receipt: dummy_receipt(7),
        server_version: None,
    };
    let (url, mut body_rx, server) = spawn_submit_capture_server(response).await?;

    let challenge_bytes = vec![0x55u8; 16];
    let challenge_hex = hex::encode(&challenge_bytes);
    let solved = super::solve_pow_cookie(challenge_bytes.clone(), 5)?;

    handle_send(SendArgs {
        hub: HubLocatorArgs::from_url(url.to_string()),
        client: client_dir.path().to_path_buf(),
        stream: "pow".to_string(),
        body: json!({ "msg": "provided" }).to_string(),
        schema: None,
        expires_at: None,
        cap: None,
        parent: None,
        attach: Vec::new(),
        no_store_body: false,
        pow_difficulty: Some(solved.difficulty),
        pow_challenge: Some(challenge_hex.clone()),
        pow_nonce: Some(solved.nonce),
    })
    .await?;

    let body = body_rx.recv().await.expect("payload captured");
    server.abort();

    let request = decode_submit_request_cbor(&body)?;
    let cookie = request.pow_cookie.expect("pow cookie present");
    let pow_cookie = cookie.into_pow_cookie();
    assert_eq!(pow_cookie.difficulty, solved.difficulty);
    assert_eq!(pow_cookie.nonce, solved.nonce);
    assert_eq!(pow_cookie.challenge, challenge_bytes);

    Ok(())
}

#[tokio::test]
async fn send_remote_rejects_nonce_without_challenge() -> anyhow::Result<()> {
    let client_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: client_dir.path().to_path_buf(),
    })
    .await?;

    let url = Url::parse("http://localhost")?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);

    let args = SendArgs {
        hub: HubLocatorArgs::from_url("http://localhost".to_string()),
        client: client_dir.path().to_path_buf(),
        stream: "pow".to_string(),
        body: json!({ "msg": "pow" }).to_string(),
        schema: None,
        expires_at: None,
        cap: None,
        parent: None,
        attach: Vec::new(),
        no_store_body: false,
        pow_difficulty: Some(3),
        pow_challenge: None,
        pow_nonce: Some(42),
    };

    let err = super::send_message_remote(client, args)
        .await
        .expect_err("missing challenge should error");
    assert!(err
        .to_string()
        .contains("--pow-nonce requires --pow-challenge"));

    Ok(())
}

#[tokio::test]
async fn stream_with_proofs_detects_tampering() -> anyhow::Result<()> {
    let hub_dir = tempdir()?;
    let client_dir = tempdir()?;

    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let listen: SocketAddr = socket.local_addr()?;
    drop(socket);
    let mut config = HubRuntimeConfig::from_sources(
        listen,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            capability_gating_enabled: Some(false),
            tooling_enabled: Some(true),
            ..Default::default()
        },
    )
    .await?;
    config.tooling_enabled = true;
    write_test_hub_key(hub_dir.path()).await?;
    let runtime = HubRuntime::start(config).await?;
    let hub_url = format!("http://{}", runtime.listen_addr());

    sleep(Duration::from_millis(50)).await;

    handle_keygen(KeygenArgs {
        out: client_dir.path().to_path_buf(),
    })
    .await?;

    handle_send(SendArgs {
        hub: HubLocatorArgs::from_url(hub_url.clone()),
        client: client_dir.path().to_path_buf(),
        stream: "proofs".to_string(),
        body: json!({ "msg": "hello" }).to_string(),
        schema: None,
        expires_at: None,
        cap: None,
        parent: None,
        attach: Vec::new(),
        no_store_body: false,
        pow_difficulty: None,
        pow_challenge: None,
        pow_nonce: None,
    })
    .await?;

    handle_stream(StreamArgs {
        hub: HubLocatorArgs::from_url(hub_url.clone()),
        client: client_dir.path().to_path_buf(),
        stream: "proofs".to_string(),
        from: 0,
        to: None,
        with_proof: true,
    })
    .await?;

    let response = runtime
        .pipeline()
        .stream("proofs", 0, None, true, true)
        .await?;
    assert_eq!(response.items.len(), 1);
    let original = response.items.into_iter().next().expect("message");
    let proof_wire = response
        .mmr_proof
        .ok_or_else(|| anyhow!("missing mmr proof"))?;
    let proof = proof_wire.clone();

    let mut tampered_receipt = original.receipt.ok_or_else(|| anyhow!("missing receipt"))?;
    let mut root_bytes = tampered_receipt.mmr_root.as_bytes().to_vec();
    root_bytes[0] ^= 0xFF;
    tampered_receipt.mmr_root =
        MmrRoot::from_slice(&root_bytes).context("rebuilding tampered MMR root")?;

    let err = validate_stream_proof_wire(&original.msg, &tampered_receipt, &proof)
        .expect_err("tampered proof fails");
    assert!(err.to_string().contains("mmr proof verification failed"));

    runtime.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn http_checkpoint_fetch() -> anyhow::Result<()> {
    let hub_dir = tempdir()?;

    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let listen: SocketAddr = socket.local_addr()?;
    drop(socket);
    let mut config = HubRuntimeConfig::from_sources(
        listen,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            capability_gating_enabled: Some(false),
            tooling_enabled: Some(true),
            ..Default::default()
        },
    )
    .await?;
    config.tooling_enabled = true;
    write_test_hub_key(hub_dir.path()).await?;
    let runtime = HubRuntime::start(config).await?;
    let hub_url = format!("http://{}", runtime.listen_addr());

    sleep(Duration::from_millis(50)).await;

    let checkpoint1 = Checkpoint {
        ver: CHECKPOINT_VERSION,
        label_prev: Label::from([0x11; 32]),
        label_curr: Label::from([0x22; 32]),
        upto_seq: 5,
        mmr_root: MmrRoot::new([0x33; 32]),
        epoch: 1,
        hub_sig: Signature64::new([0x44; 64]),
        witness_sigs: None,
    };
    let checkpoint2 = Checkpoint {
        ver: CHECKPOINT_VERSION,
        label_prev: Label::from([0x55; 32]),
        label_curr: Label::from([0x66; 32]),
        upto_seq: 9,
        mmr_root: MmrRoot::new([0x77; 32]),
        epoch: 2,
        hub_sig: Signature64::new([0x88; 64]),
        witness_sigs: Some(vec![Signature64::new([0x99; 64])]),
    };

    let mut encoded = Vec::new();
    into_writer(&checkpoint1, &mut encoded)?;
    into_writer(&checkpoint2, &mut encoded)?;
    fs::write(hub_dir.path().join(CHECKPOINTS_FILE), &encoded).await?;

    sleep(Duration::from_millis(50)).await;

    let latest = handle_hub_checkpoint_latest(HubCheckpointLatestArgs {
        hub: HubLocatorArgs::from_url(hub_url.clone()),
    })
    .await?;
    assert_eq!(latest, checkpoint2);

    let range = handle_hub_checkpoint_range(HubCheckpointRangeArgs {
        hub: HubLocatorArgs::from_url(hub_url.clone()),
        from_epoch: Some(1),
        to_epoch: Some(3),
    })
    .await?;
    assert_eq!(range, vec![checkpoint1.clone(), checkpoint2.clone()]);

    runtime.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn write_json_file_creates_parent_directories() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let path = temp.path().join("nested").join("dir").join("config.json");
    let payload = json!({ "hello": "world" });

    write_json_file(&path, &payload).await?;
    let roundtrip: Value = read_json_file(&path).await?;

    assert_eq!(roundtrip, payload);
    Ok(())
}

#[tokio::test]
async fn write_cbor_file_creates_parent_directories() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let path = temp.path().join("nested").join("dir").join("payload.cbor");
    let mut payload = BTreeMap::new();
    payload.insert(String::from("value"), 42u32);

    write_cbor_file(&path, &payload).await?;
    let roundtrip: BTreeMap<String, u32> = read_cbor_file(&path).await?;

    assert_eq!(roundtrip, payload);
    Ok(())
}

#[tokio::test]
async fn authority_set_produces_signed_payload() -> anyhow::Result<()> {
    let signer_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: signer_dir.path().to_path_buf(),
    })
    .await?;

    let realm_id = RealmId::derive("default");
    let realm_hex = hex::encode(realm_id.as_ref());
    let primary_hex = hex::encode([0x11u8; HUB_ID_LEN]);
    let replica_hex = hex::encode([0x22u8; HUB_ID_LEN]);
    let stream_name = "fed/chat".to_string();
    let stream_id = cap_stream_id_from_label(&stream_name)?;
    let stream_hex = hex::encode(stream_id.as_ref());

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr: SocketAddr = listener.local_addr()?;
    let (tx, mut body_rx) = mpsc::channel(1);
    let response_realm = realm_hex.clone();
    let response_stream = stream_hex.clone();
    let response_primary = primary_hex.clone();
    let response_replica = replica_hex.clone();
    let service = make_service_fn(move |_| {
        let tx = tx.clone();
        let response_realm = response_realm.clone();
        let response_stream = response_stream.clone();
        let response_primary = response_primary.clone();
        let response_replica = response_replica.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |mut req: HyperRequest<Body>| {
                let tx = tx.clone();
                let response_realm = response_realm.clone();
                let response_stream = response_stream.clone();
                let response_primary = response_primary.clone();
                let response_replica = response_replica.clone();
                async move {
                    match (req.method(), req.uri().path()) {
                        (&Method::POST, "/authority") => {
                            let body = to_bytes(req.body_mut())
                                .await
                                .context("authority test server failed to read body")
                                .map_err(|err| ProtocolError::new(err.to_string()))?
                                .to_vec();
                            tx.send(body)
                                .await
                                .context("authority test server failed to forward body")
                                .map_err(|err| ProtocolError::new(err.to_string()))?;
                            Ok::<_, anyhow::Error>(
                                HyperResponse::builder()
                                    .status(StatusCode::OK)
                                    .body(Body::from("null"))
                                    .unwrap(),
                            )
                        }
                        (&Method::GET, "/authority_view") => {
                            let payload = json!({
                                "ok": true,
                                "realm_id": response_realm,
                                "stream_id": response_stream,
                                "primary_hub": response_primary,
                                "replica_hubs": [response_replica],
                                "policy": "single-primary",
                                "ts": 1_234_567u64,
                                "ttl": 3_600u64,
                                "expires_at": 1_238_167u64,
                                "active_now": true,
                            });
                            let body = serde_json::to_string(&payload).unwrap();
                            Ok::<_, anyhow::Error>(
                                HyperResponse::builder()
                                    .status(StatusCode::OK)
                                    .body(Body::from(body))
                                    .unwrap(),
                            )
                        }
                        _ => Ok::<_, anyhow::Error>(
                            HyperResponse::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::empty())
                                .unwrap(),
                        ),
                    }
                }
            }))
        }
    });
    let server = Server::from_tcp(listener)?.serve(service);
    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("authority test server error: {err}");
        }
    });

    let url = format!("http://{}", addr);
    let url = Url::parse(&url)?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);
    let args = FedAuthorityPublishArgs {
        hub: HubLocatorArgs::from_url(url.to_string()),
        signer: signer_dir.path().to_path_buf(),
        realm: realm_hex,
        stream: stream_name,
        policy: AuthorityPolicyValue::SinglePrimary,
        primary_hub: primary_hex.clone(),
        replica_hubs: vec![replica_hex.clone()],
        ttl: Some(3_600),
        ts: Some(1_234_567),
        json: false,
    };

    handle_fed_authority_publish_remote(client, args).await?;
    let body = body_rx.recv().await.expect("payload captured");
    handle.abort();

    let envelope: SignedEnvelope<AuthorityRecord> = from_reader(body.as_slice())?;
    assert_eq!(envelope.schema.as_ref(), schema_fed_authority().as_slice());
    assert_eq!(envelope.body.primary_hub, parse_hub_id_hex(&primary_hex)?);
    assert_eq!(envelope.body.replica_hubs.len(), 1);
    assert_eq!(
        envelope.body.replica_hubs[0],
        parse_hub_id_hex(&replica_hex)?
    );
    assert_eq!(envelope.body.policy, AuthorityPolicy::SinglePrimary);
    assert_eq!(envelope.body.ttl, 3_600);
    assert_eq!(envelope.body.ts, 1_234_567);

    let keystore = signer_dir.path().join("keystore.enc");
    let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
    let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    verify_envelope_signature(&envelope, schema_fed_authority(), &signing_key)?;

    Ok(())
}

#[tokio::test]
async fn label_class_set_produces_signed_payload() -> anyhow::Result<()> {
    let signer_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: signer_dir.path().to_path_buf(),
    })
    .await?;

    let (url, mut body_rx, server) = spawn_cbor_capture_server("/label-class").await?;
    let url = Url::parse(&url)?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);
    let args = LabelClassSetArgs {
        hub: HubLocatorArgs::from_url(url.to_string()),
        signer: signer_dir.path().to_path_buf(),
        label_hex: None,
        stream: Some("chat/general".to_string()),
        class: "user".to_string(),
        sensitivity: Some("medium".to_string()),
        retention_hint: Some(86_400),
    };

    handle_label_class_set_remote(client, args).await?;
    let body = body_rx.recv().await.expect("payload captured");
    server.abort();

    let envelope: SignedEnvelope<LabelClassRecord> = from_reader(body.as_slice())?;
    assert_eq!(envelope.schema.as_ref(), schema_label_class().as_slice());
    assert_eq!(envelope.body.class, "user");
    assert_eq!(envelope.body.sensitivity.as_deref(), Some("medium"));
    assert_eq!(envelope.body.retention_hint, Some(86_400));
    let stream_id = cap_stream_id_from_label("chat/general")?;
    let expected_label = Label::derive([], stream_id, 0);
    assert_eq!(envelope.body.label, expected_label);

    let keystore = signer_dir.path().join("keystore.enc");
    let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
    let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    verify_envelope_signature(&envelope, schema_label_class(), &signing_key)?;

    Ok(())
}

#[tokio::test]
async fn label_class_show_fetches_descriptor() -> anyhow::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    let expected_label = hex::encode([0x11u8; 32]);
    let expected_path = format!("/label-class/{expected_label}");
    let (path_tx, mut path_rx) = mpsc::channel(1);
    let response_label = expected_label.clone();
    let expected_path_for_server = expected_path.clone();
    let handle = tokio::spawn(async move {
        let service = make_service_fn(move |_| {
            let expected_path = expected_path_for_server.clone();
            let path_tx = path_tx.clone();
            let response_label = response_label.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: HyperRequest<Body>| {
                    let expected_path = expected_path.clone();
                    let path_tx = path_tx.clone();
                    let response_label = response_label.clone();
                    async move {
                        if req.method() == Method::GET && req.uri().path() == expected_path {
                            path_tx.send(req.uri().path().to_string()).await.ok();
                            let body = serde_json::to_string(&json!({
                                "ok": true,
                                "label": response_label,
                                "class": "user",
                                "sensitivity": "medium",
                                "retention_hint": 86_400u64,
                                "pad_block_effective": 256u64,
                                "retention_policy": "standard",
                                "rate_policy": "rl0-default",
                            }))
                            .unwrap();
                            return Ok::<_, Infallible>(
                                HyperResponse::builder()
                                    .status(StatusCode::OK)
                                    .body(Body::from(body))
                                    .unwrap(),
                            );
                        }
                        Ok::<_, Infallible>(
                            HyperResponse::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }
                }))
            }
        });
        if let Err(err) = Server::from_tcp(listener)?.serve(service).await {
            eprintln!("label-class show test server error: {err}");
        }
        Ok::<_, anyhow::Error>(())
    });

    let url = format!("http://{addr}");
    handle_label_class_show(LabelClassShowArgs {
        hub: HubLocatorArgs::from_url(url),
        label_hex: Some(expected_label.clone()),
        stream: None,
        json: true,
    })
    .await?;
    let requested_path = path_rx.recv().await.expect("path observed");
    assert_eq!(requested_path, expected_path);
    handle.abort();
    Ok(())
}

#[tokio::test]
async fn label_class_list_fetches_entries() -> anyhow::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    let expected_query = "class=user".to_string();
    let (query_tx, mut query_rx) = mpsc::channel(1);
    let expected_query_for_server = expected_query.clone();
    let handle = tokio::spawn(async move {
        let service = make_service_fn(move |_| {
            let expected_query = expected_query_for_server.clone();
            let query_tx = query_tx.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: HyperRequest<Body>| {
                    let expected_query = expected_query.clone();
                    let query_tx = query_tx.clone();
                    async move {
                        if req.method() == Method::GET
                            && req.uri().path() == "/label-class"
                            && req.uri().query() == Some(expected_query.as_str())
                        {
                            query_tx
                                .send(req.uri().query().unwrap().to_string())
                                .await
                                .ok();
                            let body = serde_json::to_string(&json!({
                                "ok": true,
                                "entries": [{
                                    "label": hex::encode([0x33u8; 32]),
                                    "class": "user",
                                    "sensitivity": "medium",
                                    "retention_hint": 86_400u64,
                                }],
                            }))
                            .unwrap();
                            return Ok::<_, Infallible>(
                                HyperResponse::builder()
                                    .status(StatusCode::OK)
                                    .body(Body::from(body))
                                    .unwrap(),
                            );
                        }
                        Ok::<_, Infallible>(
                            HyperResponse::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }
                }))
            }
        });
        if let Err(err) = Server::from_tcp(listener)?.serve(service).await {
            eprintln!("label-class list test server error: {err}");
        }
        Ok::<_, anyhow::Error>(())
    });

    let url = format!("http://{addr}");
    handle_label_class_list(LabelClassListArgs {
        hub: HubLocatorArgs::from_url(url),
        class: Some("user".to_string()),
        json: true,
    })
    .await?;
    let observed = query_rx.recv().await.expect("query observed");
    assert_eq!(observed, expected_query);
    handle.abort();
    Ok(())
}

#[tokio::test]
async fn schema_register_produces_signed_payload() -> anyhow::Result<()> {
    let signer_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: signer_dir.path().to_path_buf(),
    })
    .await?;

    let (url, mut body_rx, server) = spawn_cbor_capture_server("/schema").await?;
    let url = Url::parse(&url)?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);
    let schema_id_hex = hex::encode([0xAAu8; SCHEMA_ID_LEN]);
    let args = SchemaRegisterArgs {
        hub: HubLocatorArgs::from_url(url.to_string()),
        signer: signer_dir.path().to_path_buf(),
        schema_id: schema_id_hex.clone(),
        name: "wallet.transfer.v1".to_string(),
        version: "v1".to_string(),
        doc_url: Some("https://example.com".to_string()),
        owner: None,
        ts: Some(99),
    };

    handle_schema_register_remote(client, args).await?;
    let body = body_rx.recv().await.expect("payload captured");
    server.abort();

    let envelope: SignedEnvelope<SchemaDescriptor> = from_reader(body.as_slice())?;
    assert_eq!(envelope.schema.as_ref(), schema_meta_schema().as_slice());
    assert_eq!(
        hex::encode(envelope.body.schema_id.as_bytes()),
        schema_id_hex
    );
    assert_eq!(envelope.body.name, "wallet.transfer.v1");
    assert_eq!(envelope.body.version, "v1");
    assert_eq!(
        envelope.body.doc_url.as_deref(),
        Some("https://example.com")
    );
    assert_eq!(envelope.body.owner, None);
    assert_eq!(envelope.body.ts, 99);

    let keystore = signer_dir.path().join("keystore.enc");
    let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
    let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    verify_envelope_signature(&envelope, schema_meta_schema(), &signing_key)?;

    Ok(())
}

#[tokio::test]
async fn wallet_transfer_produces_signed_payload() -> anyhow::Result<()> {
    let signer_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: signer_dir.path().to_path_buf(),
    })
    .await?;

    let (url, mut body_rx, server) = spawn_cbor_capture_server("/wallet/transfer").await?;
    let url = Url::parse(&url)?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);
    let wallet_hex = hex::encode([0x55u8; WALLET_ID_LEN]);
    let to_wallet_hex = hex::encode([0x66u8; WALLET_ID_LEN]);
    let args = WalletTransferArgs {
        hub: HubLocatorArgs::from_url(url.to_string()),
        signer: signer_dir.path().to_path_buf(),
        wallet_id: wallet_hex.clone(),
        to_wallet_id: to_wallet_hex.clone(),
        amount: 123,
        ts: Some(777),
        transfer_id: None,
        metadata: Some("{\"note\":\"hello\"}".to_string()),
    };

    handle_wallet_transfer_remote(client, args).await?;
    let body = body_rx.recv().await.expect("payload captured");
    server.abort();

    let envelope: SignedEnvelope<WalletTransferEvent> = from_reader(body.as_slice())?;
    assert_eq!(hex::encode(envelope.body.wallet_id.as_bytes()), wallet_hex);
    assert_eq!(
        hex::encode(envelope.body.to_wallet_id.as_bytes()),
        to_wallet_hex
    );
    assert_eq!(envelope.body.amount, 123);
    assert_eq!(envelope.body.ts, 777);
    assert!(matches!(envelope.body.metadata, Some(CborValue::Map(_))));

    let keystore = signer_dir.path().join("keystore.enc");
    let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
    let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    verify_envelope_signature(&envelope, schema_wallet_transfer(), &signing_key)?;

    Ok(())
}

#[tokio::test]
async fn operation_id_helper_matches_manual_hash() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let path = temp.path().join("message.json");
    let message = StoredMessage {
        stream: "core/example".to_string(),
        seq: 5,
        sent_at: 1_700_000_000,
        client_id: hex::encode([0xAAu8; 32]),
        ver: None,
        profile_id: None,
        label: None,
        client_seq: None,
        prev_ack: None,
        ct_hash: None,
        ciphertext: None,
        sig: None,
        schema: Some("schema-id".to_string()),
        expires_at: Some(1_700_000_600),
        parent: None,
        body: Some("{\"key\":\"value\"}".to_string()),
        body_digest: None,
        attachments: Vec::new(),
        auth_ref: None,
        idem: None,
    };

    write_json_file(&path, &message).await?;

    let expected_leaf = compute_message_leaf_hash(&message)?;
    let expected = OperationId::from_leaf_hash(&expected_leaf);

    let computed = operation_id_from_bundle(&path).await?;
    assert_eq!(computed.as_bytes(), expected.as_bytes());

    Ok(())
}

#[test]
fn snapshot_wallet_fold_computes_balance() -> anyhow::Result<()> {
    let account = AccountId::from_slice(&[0x33u8; ACCOUNT_ID_LEN])?;
    let peer = AccountId::from_slice(&[0x44u8; ACCOUNT_ID_LEN])?;
    let messages = vec![
        test_paid_message(1, &account, &peer, 50)?,
        test_paid_message(2, &peer, &account, 20)?,
    ];

    let summary = fold_wallet_ledger_snapshot(&messages, 2, &account)?;
    assert_eq!(summary.account_id, hex::encode(account.as_bytes()));
    assert_eq!(summary.balance, -30);

    let summary_one = fold_wallet_ledger_snapshot(&messages, 1, &account)?;
    assert_eq!(summary_one.balance, -50);
    Ok(())
}

#[test]
fn snapshot_prefix_mmr_matches_manual_fold() -> anyhow::Result<()> {
    let mut messages = Vec::new();
    for seq in 1..=3 {
        messages.push(test_plain_message(seq));
    }

    let mut manual = Mmr::new();
    let mut expected = None;
    for message in &messages {
        let leaf = compute_message_leaf_hash(message)?;
        let (_, root) = manual
            .append(leaf)
            .context("appending leaf for manual MMR root")?;
        expected = Some(root);
    }

    let computed = compute_stream_prefix_mmr_root(&messages, 3)?;
    assert_eq!(
        computed.as_bytes(),
        expected.expect("manual root").as_bytes()
    );
    Ok(())
}

fn test_paid_message(
    seq: u64,
    payer: &AccountId,
    payee: &AccountId,
    amount: u64,
) -> anyhow::Result<StoredMessage> {
    let payload = PaidOperation {
        operation_type: "transfer".to_string(),
        operation_args: CborValue::Null,
        payer_account: *payer,
        payee_account: *payee,
        amount,
        currency_code: Some("USD".to_string()),
        operation_reference: None,
        parent_operation_id: None,
        ttl_seconds: None,
        metadata: None,
    };
    let body = serde_json::to_string(&payload)?;
    Ok(StoredMessage {
        stream: "wallet/demo".to_string(),
        seq,
        sent_at: 1_700_000_000 + seq,
        client_id: "client".to_string(),
        ver: None,
        profile_id: None,
        label: None,
        client_seq: None,
        prev_ack: None,
        ct_hash: None,
        ciphertext: None,
        sig: None,
        schema: Some(hex::encode(schema_paid_operation())),
        expires_at: None,
        parent: None,
        body: Some(body),
        body_digest: None,
        attachments: Vec::new(),
        auth_ref: None,
        idem: None,
    })
}

fn test_plain_message(seq: u64) -> StoredMessage {
    StoredMessage {
        stream: "wallet/demo".to_string(),
        seq,
        sent_at: 1_700_000_000 + seq,
        client_id: format!("client-{seq}"),
        ver: None,
        profile_id: None,
        label: None,
        client_seq: None,
        prev_ack: None,
        ct_hash: None,
        ciphertext: None,
        sig: None,
        schema: Some("test.schema".to_string()),
        expires_at: None,
        parent: None,
        body: Some(format!("{{\"seq\":{seq}}}")),
        body_digest: None,
        attachments: Vec::new(),
        auth_ref: None,
        idem: None,
    }
}

#[tokio::test]
async fn revoke_publish_produces_signed_payload() -> anyhow::Result<()> {
    let signer_dir = tempdir()?;
    handle_keygen(KeygenArgs {
        out: signer_dir.path().to_path_buf(),
    })
    .await?;

    let (url, mut body_rx, server) = spawn_cbor_capture_server("/revoke").await?;
    let url = Url::parse(&url)?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);
    let target_hex = hex::encode([0x77u8; REVOCATION_TARGET_LEN]);
    let args = RevokePublishArgs {
        hub: HubLocatorArgs::from_url(url.to_string()),
        signer: signer_dir.path().to_path_buf(),
        kind: RevocationKindValue::ClientId,
        target: target_hex.clone(),
        reason: Some("compromised".to_string()),
        ttl: Some(1_000),
        ts: Some(55),
    };

    handle_revoke_publish_remote(client, args).await?;
    let body = body_rx.recv().await.expect("payload captured");
    server.abort();

    let envelope: SignedEnvelope<RevocationRecord> = from_reader(body.as_slice())?;
    assert_eq!(envelope.schema.as_ref(), schema_revocation().as_slice());
    assert_eq!(envelope.body.kind, RevocationKind::ClientId);
    assert_eq!(hex::encode(envelope.body.target.as_bytes()), target_hex);
    assert_eq!(envelope.body.reason.as_deref(), Some("compromised"));
    assert_eq!(envelope.body.ttl, Some(1_000));
    assert_eq!(envelope.body.ts, 55);

    let keystore = signer_dir.path().join("keystore.enc");
    let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
    let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    verify_envelope_signature(&envelope, schema_revocation(), &signing_key)?;

    Ok(())
}

#[test]
fn schema_identifier_matches_hash() {
    let expected = h(b"wallet.transfer.v1");
    assert_eq!(compute_schema_identifier("wallet.transfer.v1"), expected);
}

#[tokio::test]
async fn schema_list_fetches_descriptors() -> anyhow::Result<()> {
    let schema_id_bytes = [0x12; SCHEMA_ID_LEN];
    let descriptor = SchemaDescriptor {
        schema_id: SchemaId::from(schema_id_bytes),
        name: "example".to_string(),
        version: "1".to_string(),
        doc_url: Some("https://schemas".to_string()),
        owner: None,
        ts: 42,
    };
    let body_bytes = serde_json::to_vec(&vec![descriptor.clone()])?;
    let (url, server) = spawn_fixed_response_server("/schema", body_bytes).await?;
    let url = Url::parse(&url)?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);
    let fetched = fetch_schema_descriptors(&client).await?;
    server.abort();
    assert_eq!(fetched, vec![descriptor]);
    Ok(())
}

#[tokio::test]
async fn schema_show_fetches_descriptor() -> anyhow::Result<()> {
    let schema_hex = hex::encode([0x42u8; SCHEMA_ID_LEN]);
    let response = RemoteSchemaRegistryEntry {
        ok: true,
        descriptor: Some(RemoteSchemaDescriptorEntry {
            schema_id: schema_hex.clone(),
            name: "test.operation.v1".to_string(),
            version: "1".to_string(),
            doc_url: Some("https://schemas/test".to_string()),
            owner: Some("abcd".to_string()),
            ts: 55,
            created_at: Some(50),
            updated_at: Some(55),
        }),
        usage: Some(RemoteSchemaUsage {
            used_labels: vec!["core/example".to_string()],
            used_count: Some(3),
            first_used_ts: Some(51),
            last_used_ts: Some(55),
        }),
    };
    let body_bytes = serde_json::to_vec(&response)?;
    let path = Box::leak(format!("/schema/{schema_hex}").into_boxed_str());
    let (url, server) = spawn_fixed_response_server(path, body_bytes).await?;
    let url = Url::parse(&url)?;
    let client = HubHttpClient::new(url.clone(), build_http_client_for_url(&url)?);
    let fetched = fetch_schema_registry_entry(&client, &schema_hex).await?;
    server.abort();
    assert_eq!(fetched, response);
    Ok(())
}

#[test]
fn operation_schema_helper_matches_fixture() -> anyhow::Result<()> {
    let fixture_path = test_fixture_path("op_schema_ids.json");
    let data = std::fs::read(&fixture_path)?;
    let fixtures: BTreeMap<String, String> = serde_json::from_slice(&data)?;

    for (name, expected_hex) in fixtures {
        let derived = resolve_operation_schema(&name)?;
        assert_eq!(expected_hex, hex::encode(derived), "schema {name}");
    }

    Ok(())
}

#[test]
fn paid_operation_payload_matches_fixture() -> anyhow::Result<()> {
    let args = sample_paid_operation_args();
    let payload = build_paid_operation_payload(&args)?;
    let fixture_path = test_fixture_path("op_paid_payload_hex.txt");
    let expected_hex = std::fs::read_to_string(&fixture_path)?.trim().to_string();
    let actual_hex = hex::encode(&payload.cbor_body);

    assert!(
        !expected_hex.is_empty(),
        "populate {} with paid operation fixture hex: {}",
        fixture_path.display(),
        actual_hex
    );
    assert_eq!(expected_hex, actual_hex, "paid operation payload changed");

    Ok(())
}

fn test_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

fn sample_paid_operation_args() -> OperationPaidArgs {
    OperationPaidArgs {
        hub: HubLocatorArgs {
            hub: None,
            env: None,
            hub_name: None,
        },
        client: PathBuf::from("client.pem"),
        stream: "tenant/core".to_string(),
        operation_type: "ledger.transfer.v1".to_string(),
        payer: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
        payee: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100".to_string(),
        amount: 1_000_000,
        currency_code: "USD".to_string(),
        operation_args: Some(
            "{\"memo\":\"test payment\",\"tags\":[\"priority\",\"external\"]}".to_string(),
        ),
        ttl_seconds: Some(3_600),
        operation_reference: Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        ),
        parent_operation: Some(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        ),
        cap: None,
        json: false,
    }
}
