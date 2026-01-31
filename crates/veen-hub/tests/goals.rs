use std::collections::BTreeMap;
use std::io::Cursor;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::header::RETRY_AFTER;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::fs;

use veen_core::cap_token_from_cbor;
use veen_hub::pipeline::{
    AnchorRequest, AttachmentUpload, AuthorizeResponse, PowCookieEnvelope, SubmitRequest,
};
use veen_hub::runtime::HubRuntime;
use veen_hub::runtime::{HubConfigOverrides, HubRole, HubRuntimeConfig};
use veen_overlays::PowCookie;
mod support;
use support::{
    client_id_hex, decode_submit_response_cbor, encode_submit_msg, encode_submit_request_cbor,
    read_signing_key,
};

#[derive(Debug, Deserialize)]
struct MetricsResponse {
    submit_err_total: BTreeMap<String, u64>,
}

const HUB_KEY_VERSION: u8 = 1;
const RATE_LIMIT_TTL_SEC: u64 = 2;

async fn submit_cbor(
    http: &Client,
    endpoint: &str,
    request: &SubmitRequest,
) -> Result<veen_hub::pipeline::SubmitResponse> {
    let body = encode_submit_request_cbor(request)?;
    let response = http
        .post(endpoint)
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .context("submitting CBOR request")?
        .error_for_status()
        .context("submit endpoint returned error")?
        .bytes()
        .await
        .context("reading submit response")?;
    decode_submit_response_cbor(&response)
}
const RATE_LIMIT_EXPIRY_SLEEP_SEC: u64 = 2;
const CLIENT_LIFETIME_SEC: u64 = 2;
const CLIENT_LIFETIME_EXPIRY_SLEEP_SEC: u64 = 2;

#[derive(Serialize)]
struct TestHubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

async fn ensure_hub_key(data_dir: &Path) -> Result<()> {
    let path = data_dir.join("hub_key.cbor");
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking hub key at {}", path.display()))?
    {
        return Ok(());
    }

    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    let material = TestHubKeyMaterial {
        version: HUB_KEY_VERSION,
        created_at,
        public_key: ByteBuf::from(verifying.to_bytes().to_vec()),
        secret_key: ByteBuf::from(signing.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    into_writer(&material, &mut encoded).context("encoding hub key material")?;
    fs::write(&path, encoded)
        .await
        .with_context(|| format!("writing hub key material to {}", path.display()))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_core_pipeline() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub temp directory")?;
    let hub_data_path = hub_dir.path().to_path_buf();
    let mut cli_streams = Vec::new();
    let client_dir = hub_dir.path().join("client");

    run_cli(["keygen", "--out", client_dir.to_str().unwrap()])
        .context("generating client identity")?;

    let listen_addr = next_listen_addr()?;
    let config = HubRuntimeConfig::from_sources(
        listen_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            tooling_enabled: Some(true),
            capability_gating_enabled: Some(false),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    ensure_hub_key(hub_dir.path()).await?;
    let runtime = HubRuntime::start(config).await?;

    let client_signing = read_signing_key(&client_dir)?;
    let client_id = client_id_hex(&client_signing);

    let http = Client::builder().no_proxy().build()?;
    let submit_endpoint = format!("http://{}/v1/submit", runtime.listen_addr());

    let msg = encode_submit_msg(
        "core/main",
        &client_signing,
        1,
        0,
        None,
        &serde_json::to_vec(&serde_json::json!({ "text": "hello-veens" }))?,
    )?;
    let _main_response = submit_cbor(
        &http,
        &submit_endpoint,
        &SubmitRequest {
            stream: "core/main".to_string(),
            client_id: client_id.clone(),
            msg,
            attachments: None,
            auth_ref: None,
            idem: None,
            pow_cookie: None,
        },
    )
    .await
    .context("submitting core message")?;

    cli_streams.push("core/main".to_string());
    run_cli([
        "stream",
        "--hub",
        hub_dir.path().to_str().unwrap(),
        "--client",
        client_dir.to_str().unwrap(),
        "--stream",
        "core/main",
        "--from",
        "0",
    ])
    .context("streaming messages via CLI")?;

    // Attachments
    let attachment_path = hub_dir.path().join("attachment.bin");
    std::fs::write(&attachment_path, b"attachment-bytes")
        .context("writing attachment test file")?;
    let attachment_data = BASE64_ENGINE.encode(std::fs::read(&attachment_path)?);

    let msg = encode_submit_msg(
        "core/att",
        &client_signing,
        1,
        0,
        None,
        &serde_json::to_vec(&serde_json::json!({ "text": "attachment" }))?,
    )?;
    let attachment_response = submit_cbor(
        &http,
        &submit_endpoint,
        &SubmitRequest {
            stream: "core/att".to_string(),
            client_id: client_id.clone(),
            msg,
            attachments: Some(vec![AttachmentUpload {
                name: Some("file.bin".into()),
                data: attachment_data,
            }]),
            auth_ref: None,
            idem: None,
            pow_cookie: None,
        },
    )
    .await
    .context("submitting attachment message")?;

    let attachment_bundle_path = message_bundle_path(
        hub_dir.path(),
        "core/att",
        attachment_response.receipt.stream_seq,
    );
    run_cli([
        "attachment",
        "verify",
        "--msg",
        attachment_bundle_path.to_str().unwrap(),
        "--file",
        attachment_path.to_str().unwrap(),
        "--index",
        "0",
    ])
    .context("verifying attachment via CLI")?;
    cli_streams.push("core/att".to_string());

    // Capability issuance via CLI, authorization via HTTP.
    let admin_dir = hub_dir.path().join("admin");
    run_cli(["keygen", "--out", admin_dir.to_str().unwrap()])
        .context("generating admin identity")?;

    let cap_file = hub_dir.path().join("cap.cbor");
    cli_streams.push("core/capped".to_string());
    let rate_limit_ttl = RATE_LIMIT_TTL_SEC.to_string();
    run_cli([
        "cap",
        "issue",
        "--issuer",
        admin_dir.to_str().unwrap(),
        "--subject",
        client_dir.to_str().unwrap(),
        "--stream",
        "core/capped",
        "--ttl",
        &rate_limit_ttl,
        "--rate",
        "1,1",
        "--out",
        cap_file.to_str().unwrap(),
    ])
    .context("issuing capability via CLI")?;

    let cap_bytes = std::fs::read(&cap_file).context("reading capability artefact")?;
    let cap_token = cap_token_from_cbor(&cap_bytes).context("decoding issued capability")?;
    cap_token
        .verify()
        .map_err(|err| anyhow::anyhow!("issued capability failed verification: {err}"))?;
    let expected_auth_ref = hex::encode(cap_token.auth_ref()?.as_ref());

    let mut tampered = cap_bytes.clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 0x01;
    }
    let tampered_response = http
        .post(format!(
            "http://{}/tooling/authorize",
            runtime.listen_addr()
        ))
        .header("Content-Type", "application/cbor")
        .body(tampered)
        .send()
        .await
        .context("authorizing tampered capability")?;
    assert!(tampered_response.status().is_client_error());

    let authorize_response_bytes = http
        .post(format!(
            "http://{}/tooling/authorize",
            runtime.listen_addr()
        ))
        .header("Content-Type", "application/cbor")
        .body(cap_bytes.clone())
        .send()
        .await
        .context("authorizing capability")?
        .error_for_status()
        .context("authorize endpoint returned error")?
        .bytes()
        .await
        .context("reading authorize response body")?;
    let authorize_response: AuthorizeResponse =
        from_reader(&mut Cursor::new(authorize_response_bytes.as_ref()))
            .context("decoding authorize response")?;

    assert_eq!(
        hex::encode(authorize_response.auth_ref.as_ref()),
        expected_auth_ref
    );
    let auth_ref_hex = hex::encode(authorize_response.auth_ref.as_ref());

    let mut rng = OsRng;
    let unauthorized_signing = SigningKey::generate(&mut rng);
    let unauthorized_request = make_submit_request(
        "core/capped",
        &unauthorized_signing,
        1,
        0,
        serde_json::json!({"text":"denied"}),
        None,
        Some(auth_ref_hex.clone()),
        None,
        None,
    )?;
    let unauthorized = http
        .post(&submit_endpoint)
        .header("Content-Type", "application/cbor")
        .body(encode_submit_request_cbor(&unauthorized_request)?)
        .send()
        .await
        .context("submitting unauthorized message")?;
    assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);
    let unauthorized_body = unauthorized
        .text()
        .await
        .context("reading unauthorized response body")?;
    assert!(
        unauthorized_body.contains("E.AUTH") || unauthorized_body.contains("E.CAP"),
        "expected capability rejection to return E.AUTH or E.CAP, got: {unauthorized_body}"
    );

    let authorized_request = make_submit_request(
        "core/capped",
        &client_signing,
        1,
        0,
        serde_json::json!({"text":"authorized"}),
        None,
        Some(auth_ref_hex.clone()),
        None,
        None,
    )?;
    let _authorized = submit_cbor(&http, &submit_endpoint, &authorized_request)
        .await
        .context("submitting authorized message")?;

    let rate_request = make_submit_request(
        "core/capped",
        &client_signing,
        2,
        0,
        serde_json::json!({"text":"rate-limited"}),
        None,
        Some(auth_ref_hex.clone()),
        None,
        None,
    )?;
    let rate_limited = http
        .post(&submit_endpoint)
        .header("Content-Type", "application/cbor")
        .body(encode_submit_request_cbor(&rate_request)?)
        .send()
        .await
        .context("submitting rate-limited message")?;
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = rate_limited
        .headers()
        .get(RETRY_AFTER)
        .context("missing retry-after header on rate limit")?
        .to_str()
        .context("retry-after header not valid UTF-8")?
        .to_string();
    assert!(!retry_after.is_empty());
    let rate_body = rate_limited
        .text()
        .await
        .context("reading rate limit response body")?;
    assert!(
        rate_body.contains("E.RATE"),
        "expected rate limit error code in body: {rate_body}"
    );

    let retry_after_secs: u64 = retry_after
        .parse()
        .context("parsing retry-after header as integer")?;
    tokio::time::sleep(Duration::from_secs(retry_after_secs.max(1))).await;

    let rate_recovered_request = make_submit_request(
        "core/capped",
        &client_signing,
        3,
        0,
        serde_json::json!({"text":"rate-recovered"}),
        None,
        Some(auth_ref_hex.clone()),
        None,
        None,
    )?;
    let _rate_recovered = submit_cbor(&http, &submit_endpoint, &rate_recovered_request)
        .await
        .context("submitting message after rate token refill")?;

    tokio::time::sleep(Duration::from_secs(RATE_LIMIT_EXPIRY_SLEEP_SEC)).await;

    let ttl_request = make_submit_request(
        "core/capped",
        &client_signing,
        4,
        0,
        serde_json::json!({"text":"ttl-expired"}),
        None,
        Some(auth_ref_hex.clone()),
        None,
        None,
    )?;
    let ttl_expired = http
        .post(&submit_endpoint)
        .header("Content-Type", "application/cbor")
        .body(encode_submit_request_cbor(&ttl_request)?)
        .send()
        .await
        .context("submitting message after capability ttl expiry")?;
    assert_eq!(ttl_expired.status(), StatusCode::BAD_REQUEST);
    let ttl_body = ttl_expired
        .text()
        .await
        .context("reading ttl expiry response body")?;
    assert!(
        ttl_body.contains("E.TIME"),
        "expected ttl expiry to return E.TIME, got: {ttl_body}"
    );

    let reauthorized_bytes = http
        .post(format!(
            "http://{}/tooling/authorize",
            runtime.listen_addr()
        ))
        .header("Content-Type", "application/cbor")
        .body(cap_bytes.clone())
        .send()
        .await
        .context("reauthorizing capability after ttl expiry")?
        .error_for_status()
        .context("reauthorize endpoint returned error after ttl expiry")?
        .bytes()
        .await
        .context("reading reauthorize response body")?;
    let reauthorized: AuthorizeResponse =
        from_reader(&mut Cursor::new(reauthorized_bytes.as_ref()))
            .context("decoding reauthorize response")?;
    assert_eq!(hex::encode(reauthorized.auth_ref.as_ref()), auth_ref_hex);

    let ttl_recovered_request = make_submit_request(
        "core/capped",
        &client_signing,
        5,
        0,
        serde_json::json!({"text":"ttl-recovered"}),
        None,
        Some(auth_ref_hex.clone()),
        None,
        None,
    )?;
    let _ttl_recovered = submit_cbor(&http, &submit_endpoint, &ttl_recovered_request)
        .await
        .context("submitting message after capability reauthorization")?;

    let metrics: MetricsResponse = http
        .get(format!("http://{}/tooling/metrics", runtime.listen_addr()))
        .send()
        .await
        .context("fetching metrics")?
        .error_for_status()
        .context("metrics endpoint error")?
        .json()
        .await
        .context("decoding metrics response")?;
    let auth_errors = metrics.submit_err_total.get("E.AUTH").copied().unwrap_or(0);
    let time_errors = metrics.submit_err_total.get("E.TIME").copied().unwrap_or(0);
    assert!(
        auth_errors >= 1,
        "expected at least one E.AUTH error (subject mismatch), got {auth_errors}"
    );
    assert!(
        time_errors >= 1,
        "expected at least one E.TIME error (ttl expiry), got {time_errors}"
    );
    let rate_errors = metrics.submit_err_total.get("E.RATE").copied().unwrap_or(0);
    assert!(
        rate_errors >= 1,
        "expected at least one E.RATE error recorded, got {rate_errors}"
    );

    // Anchor log via HTTP
    http.post(format!("http://{}/tooling/anchor", runtime.listen_addr()))
        .json(&AnchorRequest {
            stream: "core/main".into(),
            mmr_root: "mmr-root".into(),
            backend: Some("file".into()),
        })
        .send()
        .await
        .context("submitting anchor request")?
        .error_for_status()
        .context("anchor endpoint returned error")?;

    // Health endpoint
    http.get(format!("http://{}/tooling/healthz", runtime.listen_addr()))
        .send()
        .await
        .context("fetching healthz")?
        .error_for_status()
        .context("healthz endpoint error")?;

    run_cli(["selftest", "core"]).context("running selftest core suite")?;

    println!(
        "goal: CORE.PIPELINE\n  hub.data: {}\n  cli.streams: {}\n  attachments.bundle: {}\n  cap.auth_ref: {}\n  metrics: E.AUTH={}, E.TIME={}, E.RATE={}",
        hub_data_path.display(),
        cli_streams.join(","),
        attachment_bundle_path.display(),
        auth_ref_hex,
        auth_errors,
        time_errors,
        rate_errors
    );

    runtime.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_pow_prefilter_enforced() -> Result<()> {
    let hub_dir = TempDir::new().context("creating pow hub temp directory")?;
    let client_dir = hub_dir.path().join("client");

    run_cli(["keygen", "--out", client_dir.to_str().unwrap()])
        .context("generating client identity for pow test")?;

    let listen_addr = next_listen_addr()?;
    let config = HubRuntimeConfig::from_sources(
        listen_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            tooling_enabled: Some(true),
            capability_gating_enabled: Some(false),
            pow_difficulty: Some(10),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    ensure_hub_key(hub_dir.path()).await?;
    let runtime = HubRuntime::start(config).await?;

    let client_signing = read_signing_key(&client_dir)?;
    let http = Client::builder().no_proxy().build()?;
    let submit_endpoint = format!("http://{}/v1/submit", runtime.listen_addr());
    let pow_stream = "core/pow";

    let forbidden_request = make_submit_request(
        pow_stream,
        &client_signing,
        1,
        0,
        serde_json::json!({ "text": "pow" }),
        None,
        None,
        None,
        None,
    )?;
    let forbidden = http
        .post(&submit_endpoint)
        .header("Content-Type", "application/cbor")
        .body(encode_submit_request_cbor(&forbidden_request)?)
        .send()
        .await
        .context("submitting message without pow cookie")?;
    let forbidden_status = forbidden.status();
    assert_eq!(forbidden_status, StatusCode::FORBIDDEN);

    let pow_challenge = vec![0x42; 16];
    let pow_difficulty = 10;
    let pow_envelope = solve_pow_for_tests(pow_challenge.clone(), pow_difficulty);

    let success_request = make_submit_request(
        pow_stream,
        &client_signing,
        2,
        0,
        serde_json::json!({ "text": "pow" }),
        None,
        None,
        Some(pow_envelope),
        None,
    )?;
    let success = submit_cbor(&http, &submit_endpoint, &success_request)
        .await
        .context("submitting message with pow cookie")?;

    println!(
        "goal: POW.PREFILTER\n  stream: {}\n  pow.challenge: {}\n  pow.difficulty: {}\n  forbidden.status: {}\n  submit.seq: {}\n  submit.mmr: {}\n  pow.cookie: accepted",
        pow_stream,
        hex::encode(pow_challenge),
        pow_difficulty,
        forbidden_status,
        success.receipt.stream_seq,
        hex::encode(success.receipt.mmr_root.as_bytes()),
    );

    runtime.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_capability_gating_persists() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub temp directory")?;
    let client_dir = hub_dir.path().join("client");
    let admin_dir = hub_dir.path().join("admin");
    let cap_file = hub_dir.path().join("cap.cbor");

    run_cli(["keygen", "--out", client_dir.to_str().unwrap()])
        .context("generating client identity")?;
    run_cli(["keygen", "--out", admin_dir.to_str().unwrap()])
        .context("generating admin identity")?;
    let client_signing = read_signing_key(&client_dir)?;

    run_cli([
        "cap",
        "issue",
        "--issuer",
        admin_dir.to_str().unwrap(),
        "--subject",
        client_dir.to_str().unwrap(),
        "--stream",
        "core/capped",
        "--ttl",
        "600",
        "--rate",
        "1,1",
        "--out",
        cap_file.to_str().unwrap(),
    ])
    .context("issuing capability via CLI")?;

    let listen_addr = next_listen_addr()?;
    let config = HubRuntimeConfig::from_sources(
        listen_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            tooling_enabled: Some(true),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    ensure_hub_key(hub_dir.path()).await?;
    let runtime = HubRuntime::start(config).await?;
    let base_url = format!("http://{}", runtime.listen_addr());

    let cap_bytes = std::fs::read(&cap_file).context("reading capability artefact")?;
    let cap_token = cap_token_from_cbor(&cap_bytes).context("decoding issued capability")?;
    cap_token
        .verify()
        .map_err(|err| anyhow::anyhow!("issued capability failed verification: {err}"))?;
    let http = Client::builder().no_proxy().build()?;
    let authorize_response_bytes = http
        .post(format!("{base_url}/tooling/authorize"))
        .header("Content-Type", "application/cbor")
        .body(cap_bytes.clone())
        .send()
        .await
        .context("authorizing capability")?
        .error_for_status()
        .context("authorize endpoint returned error")?
        .bytes()
        .await
        .context("reading authorize response body")?;
    let authorize_response: AuthorizeResponse =
        from_reader(&mut Cursor::new(authorize_response_bytes.as_ref()))
            .context("decoding authorize response")?;
    let auth_ref_hex = hex::encode(authorize_response.auth_ref.as_ref());

    let capability_store_path = hub_dir
        .path()
        .join("state")
        .join("capabilities")
        .join("authorized_caps.json");

    runtime.shutdown().await?;

    let stored_caps = std::fs::read_to_string(&capability_store_path).with_context(|| {
        format!(
            "reading capability store from {}",
            capability_store_path.display()
        )
    })?;
    let capability_store_survived = stored_caps.contains(&auth_ref_hex);
    assert!(
        capability_store_survived,
        "capability store missing authorised record"
    );

    let restart_addr = next_listen_addr()?;
    let restart_config = HubRuntimeConfig::from_sources(
        restart_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            tooling_enabled: Some(true),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    ensure_hub_key(hub_dir.path()).await?;
    let restart_runtime = HubRuntime::start(restart_config).await?;
    let submit_endpoint = format!("http://{}/v1/submit", restart_runtime.listen_addr());

    let authorized_request = make_submit_request(
        "core/capped",
        &client_signing,
        1,
        0,
        serde_json::json!({ "text": "authorized" }),
        None,
        Some(auth_ref_hex.clone()),
        None,
        None,
    )?;
    let authorized = submit_cbor(&http, &submit_endpoint, &authorized_request)
        .await
        .context("submitting authorized message after restart")?;
    assert_eq!(authorized.receipt.stream_seq, 1);

    let missing_auth_request = make_submit_request(
        "core/capped",
        &client_signing,
        2,
        0,
        serde_json::json!({ "text": "unauthorized" }),
        None,
        None,
        None,
        None,
    )?;
    let missing_auth = http
        .post(&submit_endpoint)
        .header("Content-Type", "application/cbor")
        .body(encode_submit_request_cbor(&missing_auth_request)?)
        .send()
        .await
        .context("submitting message without auth_ref")?;
    assert_eq!(missing_auth.status(), StatusCode::FORBIDDEN);
    let missing_body = missing_auth
        .text()
        .await
        .context("reading missing auth_ref response body")?;
    assert!(
        missing_body.contains("E.CAP"),
        "expected E.CAP error code in response: {missing_body}"
    );

    let restart_metrics: MetricsResponse = http
        .get(format!(
            "http://{}/tooling/metrics",
            restart_runtime.listen_addr()
        ))
        .send()
        .await
        .context("fetching restart hub metrics")?
        .error_for_status()
        .context("metrics endpoint error after restart")?
        .json()
        .await
        .context("decoding restart metrics response")?;
    let auth_errors = restart_metrics
        .submit_err_total
        .get("E.CAP")
        .copied()
        .unwrap_or(0);
    assert!(
        auth_errors >= 1,
        "expected at least one E.CAP error recorded for missing auth_ref, got {auth_errors}"
    );

    println!(
        "goal: CAP.PERSISTENCE\n  hub.path: {}\n  cap.file: {}\n  auth_ref: {}\n  capability.store: {}\n  restart.addr: {}\n  submit.seq: {}\n  metrics.E.CAP: {}",
        hub_dir.path().display(),
        cap_file.display(),
        auth_ref_hex,
        if capability_store_survived { "persisted" } else { "missing" },
        restart_runtime.listen_addr(),
        authorized.receipt.stream_seq,
        auth_errors,
    );

    restart_runtime.shutdown().await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_admission_bounds() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub temp directory")?;
    let admin_dir = hub_dir.path().join("admin");
    let client_a_dir = hub_dir.path().join("client-a");
    let client_b_dir = hub_dir.path().join("client-b");
    let cap_a_file = hub_dir.path().join("cap-a.cbor");
    let cap_b_file = hub_dir.path().join("cap-b.cbor");

    for dir in [&admin_dir, &client_a_dir, &client_b_dir] {
        run_cli(["keygen", "--out", dir.to_str().unwrap()])
            .with_context(|| format!("generating identity in {}", dir.display()))?;
    }

    run_cli([
        "cap",
        "issue",
        "--issuer",
        admin_dir.to_str().unwrap(),
        "--subject",
        client_a_dir.to_str().unwrap(),
        "--stream",
        "core/quota",
        "--ttl",
        "600",
        "--rate",
        "100,100",
        "--out",
        cap_a_file.to_str().unwrap(),
    ])
    .context("issuing capability for client A")?;

    run_cli([
        "cap",
        "issue",
        "--issuer",
        admin_dir.to_str().unwrap(),
        "--subject",
        client_b_dir.to_str().unwrap(),
        "--stream",
        "core/lifetime",
        "--ttl",
        "600",
        "--rate",
        "100,100",
        "--out",
        cap_b_file.to_str().unwrap(),
    ])
    .context("issuing capability for client B")?;

    let listen_addr = next_listen_addr()?;
    let stream_quota = "core/quota";
    let stream_lifetime = "core/lifetime";
    let config = HubRuntimeConfig::from_sources(
        listen_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            tooling_enabled: Some(true),
            capability_gating_enabled: Some(true),
            max_client_id_lifetime_sec: Some(CLIENT_LIFETIME_SEC),
            max_msgs_per_client_id_per_label: Some(2),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    ensure_hub_key(hub_dir.path()).await?;
    let runtime = HubRuntime::start(config).await?;
    let hub_url = format!("http://{}", runtime.listen_addr());
    let submit_endpoint = format!("{hub_url}/v1/submit");
    let http = Client::builder().no_proxy().build()?;

    let cap_quota_bytes =
        std::fs::read(&cap_a_file).context("reading client A quota capability")?;
    let cap_quota_token =
        cap_token_from_cbor(&cap_quota_bytes).context("decoding client A quota capability")?;
    cap_quota_token
        .verify()
        .map_err(|err| anyhow::anyhow!("client A capability verification failed: {err}"))?;
    let auth_quota_bytes = http
        .post(format!("{hub_url}/tooling/authorize"))
        .header("Content-Type", "application/cbor")
        .body(cap_quota_bytes.clone())
        .send()
        .await
        .context("authorizing client A quota capability")?
        .error_for_status()
        .context("authorize endpoint rejected client A quota capability")?
        .bytes()
        .await
        .context("reading authorize response for client A quota capability")?;
    let auth_quota: AuthorizeResponse = from_reader(&mut Cursor::new(auth_quota_bytes.as_ref()))
        .context("decoding authorize response for client A quota capability")?;

    let auth_ref_quota = hex::encode(auth_quota.auth_ref.as_ref());
    let client_a_signing = read_signing_key(&client_a_dir)?;

    let mut quota_seqs = Vec::new();
    for index in 0..2 {
        let quota_request = make_submit_request(
            stream_quota,
            &client_a_signing,
            index + 1,
            0,
            serde_json::json!({ "msg": index }),
            None,
            Some(auth_ref_quota.clone()),
            None,
            None,
        )?;
        let quota_response = submit_cbor(&http, &submit_endpoint, &quota_request)
            .await
            .with_context(|| format!("submitting quota message {index}"))?;
        quota_seqs.push(quota_response.receipt.stream_seq);
    }

    let quota_fail_request = make_submit_request(
        stream_quota,
        &client_a_signing,
        3,
        0,
        serde_json::json!({ "msg": "over" }),
        None,
        Some(auth_ref_quota.clone()),
        None,
        None,
    )?;
    let quota_fail = http
        .post(&submit_endpoint)
        .header("Content-Type", "application/cbor")
        .body(encode_submit_request_cbor(&quota_fail_request)?)
        .send()
        .await
        .context("submitting over-quota message")?;
    let quota_fail_status = quota_fail.status();
    assert_eq!(quota_fail_status, StatusCode::FORBIDDEN);
    let quota_body = quota_fail
        .text()
        .await
        .context("reading quota failure body")?;
    let quota_error_code = quota_body.contains("E.AUTH");
    assert!(
        quota_error_code,
        "expected quota failure to return E.AUTH, got: {quota_body}"
    );

    let cap_b_bytes = std::fs::read(&cap_b_file).context("reading client B capability")?;
    let cap_b_token = cap_token_from_cbor(&cap_b_bytes).context("decoding client B capability")?;
    cap_b_token
        .verify()
        .map_err(|err| anyhow::anyhow!("client B capability verification failed: {err}"))?;
    let auth_b_bytes = http
        .post(format!("{hub_url}/tooling/authorize"))
        .header("Content-Type", "application/cbor")
        .body(cap_b_bytes.clone())
        .send()
        .await
        .context("authorizing client B capability")?
        .error_for_status()
        .context("authorize endpoint rejected client B capability")?
        .bytes()
        .await
        .context("reading authorize response for client B")?;
    let auth_b: AuthorizeResponse = from_reader(&mut Cursor::new(auth_b_bytes.as_ref()))
        .context("decoding authorize response for client B")?;
    let auth_ref_b = hex::encode(auth_b.auth_ref.as_ref());
    let client_b_signing = read_signing_key(&client_b_dir)?;

    let lifetime_initial_request = make_submit_request(
        stream_lifetime,
        &client_b_signing,
        1,
        0,
        serde_json::json!({ "msg": "first" }),
        None,
        Some(auth_ref_b.clone()),
        None,
        None,
    )?;
    let lifetime_initial = submit_cbor(&http, &submit_endpoint, &lifetime_initial_request)
        .await
        .context("submitting initial lifetime message")?;

    tokio::time::sleep(Duration::from_secs(CLIENT_LIFETIME_EXPIRY_SLEEP_SEC)).await;

    let lifetime_fail_request = make_submit_request(
        stream_lifetime,
        &client_b_signing,
        2,
        0,
        serde_json::json!({ "msg": "expired" }),
        None,
        Some(auth_ref_b.clone()),
        None,
        None,
    )?;
    let lifetime_fail = http
        .post(&submit_endpoint)
        .header("Content-Type", "application/cbor")
        .body(encode_submit_request_cbor(&lifetime_fail_request)?)
        .send()
        .await
        .context("submitting lifetime-expired message")?;
    let lifetime_fail_status = lifetime_fail.status();
    assert_eq!(lifetime_fail_status, StatusCode::BAD_REQUEST);
    let lifetime_body = lifetime_fail
        .text()
        .await
        .context("reading lifetime failure body")?;
    let lifetime_error_code = lifetime_body.contains("E.TIME");
    assert!(
        lifetime_error_code,
        "expected lifetime enforcement to return E.TIME, got: {lifetime_body}"
    );

    println!(
        "goal: ADMISSION.BOUNDS\n  hub.url: {hub_url}\n  streams: [{stream_quota}, {stream_lifetime}]\n  auth_ref.quota: {auth_ref_quota}\n  auth_ref.lifetime: {auth_ref_b}\n  quota.seqs: {:?}\n  quota.forbidden.status: {}\n  quota.error.E.AUTH: {}\n  lifetime.initial.seq: {}\n  lifetime.expiry.status: {}\n  lifetime.error.E.TIME: {}\n  lifetime.limit.sec: {}",
        quota_seqs,
        quota_fail_status,
        quota_error_code,
        lifetime_initial.receipt.stream_seq,
        lifetime_fail_status,
        lifetime_error_code,
        3,
    );

    runtime.shutdown().await?;
    Ok(())
}

fn next_listen_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding ephemeral port")?;
    let port = listener
        .local_addr()
        .context("retrieving listener address")?
        .port();
    drop(listener);
    Ok(SocketAddr::from(([127, 0, 0, 1], port)))
}

fn run_cli<I, S>(args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let status = StdCommand::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("veen-cli")
        .arg("--")
        .args(args)
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
        .status()
        .context("executing veen command")?;
    if !status.success() {
        bail!("veen command failed with status {status}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn make_submit_request(
    stream: &str,
    client_signing: &SigningKey,
    client_seq: u64,
    prev_ack: u64,
    payload: serde_json::Value,
    attachments: Option<Vec<AttachmentUpload>>,
    auth_ref: Option<String>,
    pow_cookie: Option<PowCookieEnvelope>,
    idem: Option<u64>,
) -> Result<SubmitRequest> {
    let payload_bytes = serde_json::to_vec(&payload).context("encoding payload for submit msg")?;
    let msg = encode_submit_msg(
        stream,
        client_signing,
        client_seq,
        prev_ack,
        auth_ref.as_deref(),
        &payload_bytes,
    )?;
    Ok(SubmitRequest {
        stream: stream.to_string(),
        client_id: client_id_hex(client_signing),
        msg,
        attachments,
        auth_ref,
        idem,
        pow_cookie,
    })
}

fn solve_pow_for_tests(challenge: Vec<u8>, difficulty: u8) -> PowCookieEnvelope {
    let mut cookie = PowCookie {
        challenge,
        nonce: 0,
        difficulty,
    };

    loop {
        if cookie.meets_difficulty() {
            return PowCookieEnvelope::from_cookie(&cookie);
        }
        if cookie.nonce == u64::MAX {
            panic!("unable to solve proof-of-work for tests");
        }
        cookie.nonce = cookie.nonce.checked_add(1).expect("nonce overflow");
    }
}

fn message_bundle_path(hub_dir: &Path, stream: &str, seq: u64) -> PathBuf {
    let name = stream_storage_name(stream);
    hub_dir
        .join("state")
        .join("messages")
        .join(format!("{name}-{seq:08}.json"))
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
    let digest = Sha256::digest(stream.as_bytes());
    let suffix = hex::encode(&digest[..8]);
    format!("{safe}-{suffix}")
}
