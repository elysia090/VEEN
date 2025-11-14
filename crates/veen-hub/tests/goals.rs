use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use ciborium::de::from_reader;
use reqwest::header::RETRY_AFTER;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use veen_core::{cap_token_from_cbor, revocation::cap_token_hash};
use veen_hub::config::{HubConfigOverrides, HubRole, HubRuntimeConfig};
use veen_hub::pipeline::{
    AnchorRequest, AttachmentUpload, AuthorizeResponse, SubmitRequest, SubmitResponse,
};
use veen_hub::runtime::HubRuntime;

#[derive(Debug, Deserialize)]
struct MetricsResponse {
    submit_err_total: BTreeMap<String, u64>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_core_pipeline() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub temp directory")?;
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
            capability_gating_enabled: Some(false),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    let runtime = HubRuntime::start(config).await?;

    let client_id = read_client_id(&client_dir.join("identity_card.pub"))?;

    let http = Client::new();
    let submit_endpoint = format!("http://{}/submit", runtime.listen_addr());

    let _main_response: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/main".to_string(),
            client_id: client_id.clone(),
            payload: serde_json::json!({ "text": "hello-veens" }),
            attachments: None,
            auth_ref: None,
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting core message")?
        .error_for_status()
        .context("submit endpoint returned error")?
        .json()
        .await
        .context("parsing submit response")?;

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

    let attachment_response: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/att".to_string(),
            client_id: client_id.clone(),
            payload: serde_json::json!({ "text": "attachment" }),
            attachments: Some(vec![AttachmentUpload {
                name: Some("file.bin".into()),
                data: attachment_data,
            }]),
            auth_ref: None,
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting attachment message")?
        .error_for_status()
        .context("attachment submit returned error")?
        .json()
        .await
        .context("parsing attachment submit response")?;

    let bundle_path = message_bundle_path(hub_dir.path(), "core/att", attachment_response.seq);
    run_cli([
        "attachment",
        "verify",
        "--msg",
        bundle_path.to_str().unwrap(),
        "--file",
        attachment_path.to_str().unwrap(),
        "--index",
        "0",
    ])
    .context("verifying attachment via CLI")?;

    // Capability issuance via CLI, authorization via HTTP.
    let admin_dir = hub_dir.path().join("admin");
    run_cli(["keygen", "--out", admin_dir.to_str().unwrap()])
        .context("generating admin identity")?;

    let cap_file = hub_dir.path().join("cap.cbor");
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
        "4",
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
        .post(format!("http://{}/authorize", runtime.listen_addr()))
        .header("Content-Type", "application/cbor")
        .body(tampered)
        .send()
        .await
        .context("authorizing tampered capability")?;
    assert!(tampered_response.status().is_client_error());

    let authorize_response: AuthorizeResponse = http
        .post(format!("http://{}/authorize", runtime.listen_addr()))
        .header("Content-Type", "application/cbor")
        .body(cap_bytes.clone())
        .send()
        .await
        .context("authorizing capability")?
        .error_for_status()
        .context("authorize endpoint returned error")?
        .json()
        .await
        .context("decoding authorize response")?;

    assert_eq!(authorize_response.auth_ref, expected_auth_ref);
    let auth_ref_hex = authorize_response.auth_ref.clone();

    let mut mismatched_subject = cap_token.subject_pk.as_ref().to_vec();
    if let Some(first) = mismatched_subject.first_mut() {
        *first ^= 0xFF;
    }
    let invalid_client_id = hex::encode(mismatched_subject);

    let unauthorized = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: invalid_client_id,
            payload: serde_json::json!({"text":"denied"}),
            attachments: None,
            auth_ref: Some(auth_ref_hex.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
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

    let _authorized: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: hex::encode(cap_token.subject_pk.as_ref()),
            payload: serde_json::json!({"text":"authorized"}),
            attachments: None,
            auth_ref: Some(auth_ref_hex.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting authorized message")?
        .error_for_status()
        .context("authorized submit returned error")?
        .json()
        .await
        .context("parsing authorized submit response")?;

    let rate_limited = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: hex::encode(cap_token.subject_pk.as_ref()),
            payload: serde_json::json!({"text":"rate-limited"}),
            attachments: None,
            auth_ref: Some(auth_ref_hex.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
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

    let _rate_recovered: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: hex::encode(cap_token.subject_pk.as_ref()),
            payload: serde_json::json!({"text":"rate-recovered"}),
            attachments: None,
            auth_ref: Some(auth_ref_hex.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting message after rate token refill")?
        .error_for_status()
        .context("rate limit persisted after retry-after interval")?
        .json()
        .await
        .context("parsing rate recovery response")?;

    tokio::time::sleep(Duration::from_secs(5)).await;

    let ttl_expired = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: hex::encode(cap_token.subject_pk.as_ref()),
            payload: serde_json::json!({"text":"ttl-expired"}),
            attachments: None,
            auth_ref: Some(auth_ref_hex.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting message after capability ttl expiry")?;
    assert_eq!(ttl_expired.status(), StatusCode::FORBIDDEN);
    let ttl_body = ttl_expired
        .text()
        .await
        .context("reading ttl expiry response body")?;
    assert!(
        ttl_body.contains("E.CAP"),
        "expected ttl expiry to return E.CAP, got: {ttl_body}"
    );

    let reauthorized: AuthorizeResponse = http
        .post(format!("http://{}/authorize", runtime.listen_addr()))
        .header("Content-Type", "application/cbor")
        .body(cap_bytes.clone())
        .send()
        .await
        .context("reauthorizing capability after ttl expiry")?
        .error_for_status()
        .context("reauthorize endpoint returned error after ttl expiry")?
        .json()
        .await
        .context("decoding reauthorize response")?;
    assert_eq!(reauthorized.auth_ref, auth_ref_hex);

    let _ttl_recovered: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: hex::encode(cap_token.subject_pk.as_ref()),
            payload: serde_json::json!({"text":"ttl-recovered"}),
            attachments: None,
            auth_ref: Some(auth_ref_hex.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting message after capability reauthorization")?
        .error_for_status()
        .context("submission after reauthorization returned error")?
        .json()
        .await
        .context("parsing capability recovery response")?;

    let metrics: MetricsResponse = http
        .get(format!("http://{}/metrics", runtime.listen_addr()))
        .send()
        .await
        .context("fetching metrics")?
        .error_for_status()
        .context("metrics endpoint error")?
        .json()
        .await
        .context("decoding metrics response")?;
    let cap_errors = metrics.submit_err_total.get("E.CAP").copied().unwrap_or(0);
    assert!(
        cap_errors >= 2,
        "expected at least two E.CAP errors (subject mismatch + ttl expiry), got {cap_errors}"
    );
    let rate_errors = metrics.submit_err_total.get("E.RATE").copied().unwrap_or(0);
    assert!(
        rate_errors >= 1,
        "expected at least one E.RATE error recorded, got {rate_errors}"
    );

    // Anchor log via HTTP
    http.post(format!("http://{}/anchor", runtime.listen_addr()))
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
    http.get(format!("http://{}/healthz", runtime.listen_addr()))
        .send()
        .await
        .context("fetching healthz")?
        .error_for_status()
        .context("healthz endpoint error")?;

    run_cli(["selftest", "core"]).context("running selftest core suite")?;

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
        HubConfigOverrides::default(),
    )
    .await?;
    let runtime = HubRuntime::start(config).await?;
    let base_url = format!("http://{}", runtime.listen_addr());

    let cap_bytes = std::fs::read(&cap_file).context("reading capability artefact")?;
    let cap_token = cap_token_from_cbor(&cap_bytes).context("decoding issued capability")?;
    cap_token
        .verify()
        .map_err(|err| anyhow::anyhow!("issued capability failed verification: {err}"))?;
    let subject_client_id = hex::encode(cap_token.subject_pk.as_ref());

    let http = Client::new();
    let authorize_response: AuthorizeResponse = http
        .post(format!("{base_url}/authorize"))
        .header("Content-Type", "application/cbor")
        .body(cap_bytes.clone())
        .send()
        .await
        .context("authorizing capability")?
        .error_for_status()
        .context("authorize endpoint returned error")?
        .json()
        .await
        .context("decoding authorize response")?;
    let auth_ref_hex = authorize_response.auth_ref.clone();

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
    assert!(
        stored_caps.contains(&auth_ref_hex),
        "capability store missing authorised record"
    );

    let restart_addr = next_listen_addr()?;
    let restart_config = HubRuntimeConfig::from_sources(
        restart_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides::default(),
    )
    .await?;
    let restart_runtime = HubRuntime::start(restart_config).await?;
    let submit_endpoint = format!("http://{}/submit", restart_runtime.listen_addr());

    let authorized: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: subject_client_id.clone(),
            payload: serde_json::json!({ "text": "authorized" }),
            attachments: None,
            auth_ref: Some(auth_ref_hex.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting authorized message after restart")?
        .error_for_status()
        .context("authorized submit after restart returned error")?
        .json()
        .await
        .context("parsing authorized submit response")?;
    assert_eq!(authorized.stream, "core/capped");

    let missing_auth = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/capped".to_string(),
            client_id: subject_client_id,
            payload: serde_json::json!({ "text": "unauthorized" }),
            attachments: None,
            auth_ref: None,
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting message without auth_ref")?;
    assert_eq!(missing_auth.status(), StatusCode::FORBIDDEN);
    let missing_body = missing_auth
        .text()
        .await
        .context("reading missing auth_ref response body")?;
    assert!(
        missing_body.contains("E.AUTH"),
        "expected E.AUTH error code in response: {missing_body}"
    );

    let restart_metrics: MetricsResponse = http
        .get(format!("http://{}/metrics", restart_runtime.listen_addr()))
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
        .get("E.AUTH")
        .copied()
        .unwrap_or(0);
    assert!(
        auth_errors >= 1,
        "expected at least one E.AUTH error recorded for missing auth_ref, got {auth_errors}"
    );

    restart_runtime.shutdown().await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn goals_revocation_and_admission_bounds() -> Result<()> {
    let hub_dir = TempDir::new().context("creating hub temp directory")?;
    let admin_dir = hub_dir.path().join("admin");
    let client_a_dir = hub_dir.path().join("client-a");
    let client_revoke_dir = hub_dir.path().join("client-revoke");
    let client_b_dir = hub_dir.path().join("client-b");
    let cap_a_file = hub_dir.path().join("cap-a.cbor");
    let cap_revoke_file = hub_dir.path().join("cap-revoke.cbor");
    let cap_b_file = hub_dir.path().join("cap-b.cbor");

    for dir in [&admin_dir, &client_a_dir, &client_revoke_dir, &client_b_dir] {
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
        client_revoke_dir.to_str().unwrap(),
        "--stream",
        "core/revoke",
        "--ttl",
        "600",
        "--rate",
        "100,100",
        "--out",
        cap_revoke_file.to_str().unwrap(),
    ])
    .context("issuing revocation stream capability")?;

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
    let config = HubRuntimeConfig::from_sources(
        listen_addr,
        hub_dir.path().to_path_buf(),
        None,
        HubRole::Primary,
        HubConfigOverrides {
            capability_gating_enabled: Some(true),
            max_client_id_lifetime_sec: Some(3),
            max_msgs_per_client_id_per_label: Some(2),
            ..HubConfigOverrides::default()
        },
    )
    .await?;
    let runtime = HubRuntime::start(config).await?;
    let hub_url = format!("http://{}", runtime.listen_addr());
    let submit_endpoint = format!("{hub_url}/submit");
    let http = Client::new();

    let cap_quota_bytes =
        std::fs::read(&cap_a_file).context("reading client A quota capability")?;
    let cap_quota_token =
        cap_token_from_cbor(&cap_quota_bytes).context("decoding client A quota capability")?;
    cap_quota_token
        .verify()
        .map_err(|err| anyhow::anyhow!("client A capability verification failed: {err}"))?;
    let auth_quota: AuthorizeResponse = http
        .post(format!("{hub_url}/authorize"))
        .header("Content-Type", "application/cbor")
        .body(cap_quota_bytes.clone())
        .send()
        .await
        .context("authorizing client A quota capability")?
        .error_for_status()
        .context("authorize endpoint rejected client A quota capability")?
        .json()
        .await
        .context("decoding authorize response for client A quota capability")?;

    let cap_revoke_bytes =
        std::fs::read(&cap_revoke_file).context("reading client revoke capability")?;
    let cap_revoke_token =
        cap_token_from_cbor(&cap_revoke_bytes).context("decoding client revoke capability")?;
    cap_revoke_token
        .verify()
        .map_err(|err| anyhow::anyhow!("client revoke capability verification failed: {err}"))?;
    let auth_revoke: AuthorizeResponse = http
        .post(format!("{hub_url}/authorize"))
        .header("Content-Type", "application/cbor")
        .body(cap_revoke_bytes.clone())
        .send()
        .await
        .context("authorizing client revoke capability")?
        .error_for_status()
        .context("authorize endpoint rejected client revoke capability")?
        .json()
        .await
        .context("decoding authorize response for client revoke capability")?;

    let auth_ref_quota = auth_quota.auth_ref.clone();
    let auth_ref_revoke = auth_revoke.auth_ref.clone();
    let client_a_id = read_client_id(&client_a_dir.join("identity_card.pub"))?;
    let client_revoke_id = read_client_id(&client_revoke_dir.join("identity_card.pub"))?;
    let token_hash_revoke = hex::encode(cap_token_hash(&cap_revoke_bytes));

    for index in 0..2 {
        let _: SubmitResponse = http
            .post(&submit_endpoint)
            .json(&SubmitRequest {
                stream: "core/quota".to_string(),
                client_id: client_a_id.clone(),
                payload: serde_json::json!({ "msg": index }),
                attachments: None,
                auth_ref: Some(auth_ref_quota.clone()),
                expires_at: None,
                schema: None,
                idem: None,
            })
            .send()
            .await
            .with_context(|| format!("submitting quota message {index}"))?
            .error_for_status()
            .context("quota submission returned error")?
            .json()
            .await
            .context("decoding quota submit response")?;
    }

    let quota_fail = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/quota".to_string(),
            client_id: client_a_id.clone(),
            payload: serde_json::json!({ "msg": "over" }),
            attachments: None,
            auth_ref: Some(auth_ref_quota.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting over-quota message")?;
    assert_eq!(quota_fail.status(), StatusCode::FORBIDDEN);
    let quota_body = quota_fail
        .text()
        .await
        .context("reading quota failure body")?;
    assert!(
        quota_body.contains("E.AUTH"),
        "expected quota failure to return E.AUTH, got: {quota_body}"
    );

    run_cli([
        "revoke",
        "publish",
        "--hub",
        &hub_url,
        "--signer",
        admin_dir.to_str().unwrap(),
        "--kind",
        "client-id",
        "--target",
        &client_revoke_id,
        "--ttl",
        "1",
    ])
    .context("publishing client-id revocation")?;

    let revoked = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/revoke".to_string(),
            client_id: client_revoke_id.clone(),
            payload: serde_json::json!({ "msg": "revoked" }),
            attachments: None,
            auth_ref: Some(auth_ref_revoke.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting message during revocation TTL")?;
    assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
    let revoked_body = revoked
        .text()
        .await
        .context("reading revocation failure body")?;
    assert!(
        revoked_body.contains("E.AUTH"),
        "expected client-id revocation to return E.AUTH, got: {revoked_body}"
    );

    tokio::time::sleep(Duration::from_secs(2)).await;

    let post_ttl = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/revoke".to_string(),
            client_id: client_revoke_id.clone(),
            payload: serde_json::json!({ "msg": "restored" }),
            attachments: None,
            auth_ref: Some(auth_ref_revoke.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting message after revocation TTL")?;
    if !post_ttl.status().is_success() {
        let status = post_ttl.status();
        let body = post_ttl
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_string());
        panic!("post-TTL submission returned {status}: {body}");
    }
    let _: SubmitResponse = post_ttl
        .json()
        .await
        .context("decoding post-TTL submit response")?;

    run_cli([
        "revoke",
        "publish",
        "--hub",
        &hub_url,
        "--signer",
        admin_dir.to_str().unwrap(),
        "--kind",
        "cap-token",
        "--target",
        &token_hash_revoke,
    ])
    .context("publishing capability token revocation")?;

    let cap_revoked = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/revoke".to_string(),
            client_id: client_revoke_id.clone(),
            payload: serde_json::json!({ "msg": "cap revoked" }),
            attachments: None,
            auth_ref: Some(auth_ref_revoke.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting message after cap-token revocation")?;
    assert_eq!(cap_revoked.status(), StatusCode::FORBIDDEN);
    let cap_body = cap_revoked
        .text()
        .await
        .context("reading cap-token revocation body")?;
    assert!(
        cap_body.contains("E.CAP"),
        "expected cap-token revocation to return E.CAP, got: {cap_body}"
    );

    let cap_b_bytes = std::fs::read(&cap_b_file).context("reading client B capability")?;
    let cap_b_token = cap_token_from_cbor(&cap_b_bytes).context("decoding client B capability")?;
    cap_b_token
        .verify()
        .map_err(|err| anyhow::anyhow!("client B capability verification failed: {err}"))?;
    let auth_b: AuthorizeResponse = http
        .post(format!("{hub_url}/authorize"))
        .header("Content-Type", "application/cbor")
        .body(cap_b_bytes.clone())
        .send()
        .await
        .context("authorizing client B capability")?
        .error_for_status()
        .context("authorize endpoint rejected client B capability")?
        .json()
        .await
        .context("decoding authorize response for client B")?;
    let auth_ref_b = auth_b.auth_ref.clone();
    let client_b_id = read_client_id(&client_b_dir.join("identity_card.pub"))?;

    let _: SubmitResponse = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/lifetime".to_string(),
            client_id: client_b_id.clone(),
            payload: serde_json::json!({ "msg": "first" }),
            attachments: None,
            auth_ref: Some(auth_ref_b.clone()),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting initial lifetime message")?
        .error_for_status()
        .context("initial lifetime submission returned error")?
        .json()
        .await
        .context("decoding initial lifetime submit response")?;

    tokio::time::sleep(Duration::from_secs(4)).await;

    let lifetime_fail = http
        .post(&submit_endpoint)
        .json(&SubmitRequest {
            stream: "core/lifetime".to_string(),
            client_id: client_b_id,
            payload: serde_json::json!({ "msg": "expired" }),
            attachments: None,
            auth_ref: Some(auth_ref_b),
            expires_at: None,
            schema: None,
            idem: None,
        })
        .send()
        .await
        .context("submitting lifetime-expired message")?;
    assert_eq!(lifetime_fail.status(), StatusCode::FORBIDDEN);
    let lifetime_body = lifetime_fail
        .text()
        .await
        .context("reading lifetime failure body")?;
    assert!(
        lifetime_body.contains("E.AUTH"),
        "expected lifetime enforcement to return E.AUTH, got: {lifetime_body}"
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
        .status()
        .context("executing veen-cli command")?;
    if !status.success() {
        bail!("veen-cli command failed with status {status}");
    }
    Ok(())
}

fn read_client_id(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let bundle: ClientPublicBundle = from_reader(file).context("decoding client identity card")?;
    Ok(hex::encode(bundle.client_id))
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

#[derive(Deserialize)]
struct ClientPublicBundle {
    #[serde(with = "serde_bytes")]
    client_id: ByteBuf,
}
