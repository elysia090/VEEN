use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Client, Url};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use sha2::{Digest, Sha256};
use veen_core::label::Label;
use veen_core::profile::ProfileId;
use veen_core::wire::mmr::Mmr;
use veen_core::wire::types::{ClientId, CtHash, LeafHash};
use veen_hub::pipeline::{
    BridgeIngestRequest, BridgeIngestResponse, HubStreamState, StoredMessage, StreamResponse,
};

const DATA_PLANE_VERSION: u64 = 1;

#[derive(Clone, Debug)]
pub struct EndpointConfig {
    pub base_url: Url,
    pub bearer_token: Option<String>,
}

impl EndpointConfig {
    pub fn new(base_url: Url, bearer_token: Option<String>) -> Self {
        Self {
            base_url,
            bearer_token,
        }
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.bearer_token {
            request.bearer_auth(token)
        } else {
            request
        }
    }
}

#[derive(Clone, Debug)]
pub struct BridgeConfig {
    pub primary: EndpointConfig,
    pub replica: EndpointConfig,
    pub poll_interval: Duration,
    pub initial_streams: Vec<String>,
}

impl BridgeConfig {
    pub fn with_streams(mut self, streams: Vec<String>) -> Self {
        self.initial_streams = streams;
        self
    }
}

#[derive(Default, Clone)]
struct StreamState {
    mmr: Mmr,
    next_seq: u64,
}

struct StreamRequestCbor<'a> {
    stream: &'a str,
    from: u64,
}

impl Serialize for StreamRequestCbor<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry(&1u64, &DATA_PLANE_VERSION)?;
        map.serialize_entry(&2u64, &self.stream)?;
        map.serialize_entry(&3u64, &self.from)?;
        map.serialize_entry(&7u64, &false)?;
        map.serialize_entry(&8u64, &false)?;
        map.end()
    }
}

pub async fn run_bridge(config: BridgeConfig, shutdown: CancellationToken) -> Result<()> {
    let client = Client::builder()
        .build()
        .context("initialising HTTP client for bridge")?;

    let mut bridge = BridgeRuntime::new(client, config);
    bridge.initialise().await?;

    info!("bridge initialised; starting replication loop");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("bridge shutdown requested; exiting replication loop");
                break;
            }
            result = bridge.replicate_once() => {
                if let Err(err) = result {
                    warn!(error = ?err, "bridge replication iteration failed");
                }
                sleep(bridge.config.poll_interval).await;
            }
        }
    }

    Ok(())
}

struct BridgeRuntime {
    client: Client,
    config: BridgeConfig,
    streams: HashMap<String, StreamState>,
}

impl BridgeRuntime {
    fn new(client: Client, config: BridgeConfig) -> Self {
        Self {
            client,
            config,
            streams: HashMap::new(),
        }
    }

    async fn initialise(&mut self) -> Result<()> {
        let mut to_bootstrap = Vec::new();
        if self.config.initial_streams.is_empty() {
            to_bootstrap.extend(self.refresh_streams_from_primary().await?);
        } else {
            for stream in &self.config.initial_streams {
                if self.streams.entry(stream.clone()).or_default().next_seq == 0 {
                    to_bootstrap.push(stream.clone());
                }
            }
        }

        for stream in to_bootstrap {
            self.bootstrap_replica_state(&stream).await?;
        }

        Ok(())
    }

    async fn refresh_streams_from_primary(&mut self) -> Result<Vec<String>> {
        let metrics = self.fetch_metrics().await?;
        let mut new_streams = Vec::new();
        for stream in metrics.last_stream_seq.keys() {
            if self.streams.entry(stream.clone()).or_default().next_seq == 0 {
                new_streams.push(stream.clone());
            }
        }
        Ok(new_streams)
    }

    async fn replicate_once(&mut self) -> Result<()> {
        if self.streams.is_empty() {
            let new_streams = self.refresh_streams_from_primary().await?;
            for stream in new_streams {
                self.bootstrap_replica_state(&stream).await?;
            }
        }

        let streams: Vec<String> = self.streams.keys().cloned().collect();
        for stream in streams {
            let state = self.streams.entry(stream.clone()).or_default();
            let next_seq = state.next_seq;
            let messages = self.fetch_primary_stream(&stream, next_seq).await?;

            if messages.is_empty() {
                continue;
            }

            for message in messages {
                self.apply_message(&stream, message).await?;
            }
        }

        // Discover new streams that may have been created during replication.
        let new_streams = self.refresh_streams_from_primary().await?;
        for stream in new_streams {
            self.bootstrap_replica_state(&stream).await?;
        }

        Ok(())
    }

    async fn bootstrap_replica_state(&mut self, stream: &str) -> Result<()> {
        let replica_state = self.fetch_replica_state(stream).await?;
        let mut mmr = Mmr::new();
        let mut next_seq = 1;
        for message in replica_state.messages {
            let leaf = leaf_hash_for(&message)?;
            let (seq, _) = mmr
                .append(leaf)
                .with_context(|| format!("appending leaf to replica MMR for stream {stream}"))?;
            if seq != message.seq {
                bail!(
                    "replica stream {} has inconsistent sequence numbers",
                    stream
                );
            }
            next_seq = seq.saturating_add(1);
        }
        let entry = self.streams.entry(stream.to_string()).or_default();
        entry.mmr = mmr;
        entry.next_seq = next_seq;
        Ok(())
    }

    async fn apply_message(&mut self, stream: &str, message: StoredMessage) -> Result<()> {
        let entry = self.streams.entry(stream.to_string()).or_default();

        if message.seq != entry.next_seq {
            bail!(
                "primary sequence mismatch for stream {}: expected {}, saw {}",
                stream,
                entry.next_seq,
                message.seq
            );
        }

        let leaf = leaf_hash_for(&message)?;
        let mut preview_mmr = entry.mmr.clone();
        let (_, mmr_root) = preview_mmr
            .append(leaf)
            .with_context(|| format!("previewing MMR root for stream {stream}"))?;
        let expected_root_hex = hex::encode(mmr_root.as_bytes());

        let request = BridgeIngestRequest {
            message: message.clone(),
            expected_mmr_root: expected_root_hex.clone(),
        };

        let response = self.send_bridge_request(&request).await?;

        if response.stream != message.stream {
            bail!(
                "bridge response stream mismatch: expected {}, got {}",
                message.stream,
                response.stream
            );
        }

        if response.seq != message.seq {
            bail!(
                "bridge response sequence mismatch: expected {}, got {}",
                message.seq,
                response.seq
            );
        }

        if response.mmr_root != expected_root_hex {
            bail!(
                "bridge mmr root mismatch: expected {}, got {}",
                expected_root_hex,
                response.mmr_root
            );
        }

        debug!(
            stream = %stream,
            seq = message.seq,
            mmr_root = %expected_root_hex,
            "bridged message applied"
        );

        let state = self.streams.get_mut(stream).with_context(|| {
            format!("stream state missing after bridge request for stream {stream}")
        })?;
        state.mmr = preview_mmr;
        state.next_seq = state.next_seq.saturating_add(1);
        Ok(())
    }

    async fn fetch_primary_stream(&self, stream: &str, from: u64) -> Result<Vec<StoredMessage>> {
        let mut url = self.config.primary.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow!("primary hub URL is not base"))?
            .extend(&["v1", "stream"]);

        let request_body = StreamRequestCbor { stream, from };
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&request_body, &mut encoded)
            .context("encoding stream request")?;

        let request = self
            .client
            .post(url)
            .header("Content-Type", "application/cbor")
            .body(encoded);
        let request = self.config.primary.apply_auth(request);
        let response = request
            .send()
            .await
            .with_context(|| format!("fetching primary stream {stream}"))?;

        if !response.status().is_success() {
            bail!(
                "primary stream request failed for {} with status {}",
                stream,
                response.status()
            );
        }

        let bytes = response
            .bytes()
            .await
            .context("reading primary stream payload")?;
        let mut cursor = std::io::Cursor::new(bytes);
        let response: StreamResponse =
            ciborium::de::from_reader(&mut cursor).context("decoding primary stream payload")?;
        if response.ver != DATA_PLANE_VERSION {
            bail!(
                "primary stream response version {} unsupported",
                response.ver
            );
        }
        Ok(response
            .items
            .into_iter()
            .map(|item| StoredMessage::from_wire(stream, item.stream_seq, 0, &item.msg))
            .collect())
    }

    async fn fetch_replica_state(&self, stream: &str) -> Result<HubStreamState> {
        let mut url = self.config.replica.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow!("replica hub URL is not base"))?
            .extend(&["tooling", "resync"]);

        let request = self.client.post(url).json(&ResyncBody {
            stream: stream.to_string(),
        });
        let request = self.config.replica.apply_auth(request);
        let response = request
            .send()
            .await
            .with_context(|| format!("fetching replica state for {stream}"))?;

        if response.status().is_success() {
            let state = response
                .json::<HubStreamState>()
                .await
                .context("decoding replica stream state")?;
            Ok(state)
        } else if response.status().as_u16() == 404 {
            Ok(HubStreamState::default())
        } else {
            bail!(
                "replica resync request failed for {} with status {}",
                stream,
                response.status()
            );
        }
    }

    async fn fetch_metrics(&self) -> Result<MetricsSnapshot> {
        let mut url = self.config.primary.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow!("primary hub URL is not base"))?
            .extend(&["tooling", "metrics"]);
        let request = self.client.get(url);
        let request = self.config.primary.apply_auth(request);
        let response = request.send().await.context("fetching hub metrics")?;
        if !response.status().is_success() {
            bail!(
                "primary metrics request failed with status {}",
                response.status()
            );
        }
        let metrics = response
            .json::<MetricsSnapshot>()
            .await
            .context("decoding metrics payload")?;
        Ok(metrics)
    }

    async fn send_bridge_request(
        &self,
        request: &BridgeIngestRequest,
    ) -> Result<BridgeIngestResponse> {
        let mut url = self.config.replica.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow!("replica hub URL is not base"))?
            .extend(&["tooling", "bridge"]);

        let req = self.client.post(url).json(request);
        let req = self.config.replica.apply_auth(req);

        let response = req.send().await.context("sending bridge ingest request")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("bridge ingest failed with status {}: {}", status, body);
        }

        let parsed = response
            .json::<BridgeIngestResponse>()
            .await
            .context("decoding bridge ingest response")?;
        Ok(parsed)
    }
}

#[derive(Debug, Deserialize)]
struct MetricsSnapshot {
    #[serde(default)]
    last_stream_seq: HashMap<String, u64>,
}

#[derive(Debug, Serialize)]
struct ResyncBody {
    stream: String,
}

fn leaf_hash_for(message: &StoredMessage) -> Result<LeafHash> {
    let label_hex = message.label.as_ref();
    let profile_hex = message.profile_id.as_ref();
    let ct_hash_hex = message.ct_hash.as_ref();
    let client_seq = message.client_seq;

    if let (Some(label_hex), Some(profile_hex), Some(ct_hash_hex), Some(client_seq)) =
        (label_hex, profile_hex, ct_hash_hex, client_seq)
    {
        let label =
            Label::from_str(label_hex).with_context(|| format!("parsing label {label_hex}"))?;
        let profile_id = ProfileId::from_str(profile_hex)
            .with_context(|| format!("parsing profile_id {profile_hex}"))?;
        let ct_hash = CtHash::from_str(ct_hash_hex)
            .with_context(|| format!("parsing ct_hash {ct_hash_hex}"))?;
        let client_id = ClientId::from_str(&message.client_id)
            .with_context(|| format!("parsing client_id {}", message.client_id))?;
        return Ok(LeafHash::derive(
            &label,
            &profile_id,
            &ct_hash,
            &client_id,
            client_seq,
        ));
    }

    let encoded = serde_json::to_vec(message).context("encoding message for leaf hash")?;
    let digest = Sha256::digest(&encoded);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(LeafHash::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use httpmock::prelude::*;
    use serde_json::json;
    use veen_core::wire::types::Signature64;
    use veen_core::wire::Msg;
    use veen_hub::pipeline::StreamResponseItem;

    fn sample_msg(stream: &str, seq: u64) -> Msg {
        let label =
            Label::from_slice(Sha256::digest(stream.as_bytes()).as_slice()).expect("label bytes");
        let profile_id =
            ProfileId::from_slice(Sha256::digest(b"bridge-profile").as_slice()).expect("profile");
        let client_id = ClientId::from([0x11; 32]);
        let ciphertext = vec![0u8; 16];
        let ct_hash = CtHash::compute(&ciphertext);
        Msg {
            ver: 1,
            profile_id,
            label,
            client_id,
            client_seq: seq,
            prev_ack: seq.saturating_sub(1),
            auth_ref: None,
            ct_hash,
            ciphertext,
            sig: Signature64::from([0u8; 64]),
        }
    }

    fn sample_message(stream: &str, seq: u64) -> StoredMessage {
        let msg = sample_msg(stream, seq);
        StoredMessage::from_wire(stream, seq, 0, &msg)
    }

    fn encode_stream_response(stream: &str, items: Vec<(u64, Msg)>) -> Vec<u8> {
        let from_seq = items.first().map(|(seq, _)| *seq).unwrap_or(0);
        let response = StreamResponse {
            ver: DATA_PLANE_VERSION,
            stream: stream.to_string(),
            from_seq,
            to_seq: None,
            items: items
                .into_iter()
                .map(|(stream_seq, msg)| StreamResponseItem {
                    stream_seq,
                    msg,
                    receipt: None,
                })
                .collect(),
            next_cursor: None,
            mmr_proof: None,
            server_version: None,
        };
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&response, &mut encoded).expect("encoding stream response");
        encoded
    }

    async fn start_bridge_runtime(
        primary: &MockServer,
        replica: &MockServer,
        config: BridgeConfig,
    ) -> Result<BridgeRuntime> {
        let client = Client::builder().no_proxy().build()?;
        let mut runtime = BridgeRuntime::new(client, config);

        let _replica_resync_mock = replica
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/tooling/resync")
                    .json_body(json!({ "stream": "test/stream" }));
                then.status(404);
            })
            .await;

        let _primary_metrics_mock = primary
            .mock_async(|when, then| {
                when.method(GET).path("/tooling/metrics");
                then.status(200)
                    .json_body(json!({ "last_stream_seq": { "test/stream": 1 } }));
            })
            .await;

        runtime.initialise().await?;
        Ok(runtime)
    }

    #[tokio::test]
    async fn replicate_applies_message_and_tracks_mmr() -> Result<()> {
        let primary = MockServer::start_async().await;
        let replica = MockServer::start_async().await;
        let stream = "test/stream";
        let message = sample_message(stream, 1);
        let wire_msg = sample_msg(stream, 1);

        let leaf = leaf_hash_for(&message)?;
        let mut mmr = Mmr::new();
        let (_, root) = mmr.append(leaf).context("building expected MMR root")?;
        let expected_root_hex = hex::encode(root.as_bytes());

        let config = BridgeConfig {
            primary: EndpointConfig::new(primary.base_url().parse()?, None),
            replica: EndpointConfig::new(replica.base_url().parse()?, None),
            poll_interval: Duration::from_millis(10),
            initial_streams: vec![stream.to_string()],
        };

        let mut runtime = start_bridge_runtime(&primary, &replica, config).await?;

        let stream_body = encode_stream_response(stream, vec![(1, wire_msg.clone())]);
        primary
            .mock_async(move |when, then| {
                when.method(POST).path("/v1/stream");
                then.status(200)
                    .header("Content-Type", "application/cbor")
                    .body(stream_body.clone());
            })
            .await;

        let expected_root_request = expected_root_hex.clone();
        let expected_root_response = expected_root_hex.clone();
        let bridge_mock = replica
            .mock_async(move |when, then| {
                when.method(POST).path("/tooling/bridge").json_body(json!({
                    "message": sample_message(stream, 1),
                    "expected_mmr_root": expected_root_request,
                }));
                then.status(200).json_body(json!({
                    "stream": stream,
                    "seq": 1,
                    "mmr_root": expected_root_response,
                }));
            })
            .await;

        runtime.replicate_once().await?;

        bridge_mock.assert_hits_async(1).await;

        let state = runtime
            .streams
            .get(stream)
            .ok_or_else(|| anyhow!("expected stream state to exist"))?;
        ensure!(state.next_seq == 2, "next sequence did not advance");

        Ok(())
    }

    #[tokio::test]
    async fn initialise_discovers_streams_via_metrics() -> Result<()> {
        let primary = MockServer::start_async().await;
        let replica = MockServer::start_async().await;
        let stream = "dynamic/stream";
        let message = sample_message(stream, 1);
        let wire_msg = sample_msg(stream, 1);

        let leaf = leaf_hash_for(&message)?;
        let mut mmr = Mmr::new();
        let (_, root) = mmr.append(leaf).context("building expected MMR root")?;
        let expected_root_hex = hex::encode(root.as_bytes());

        let config = BridgeConfig {
            primary: EndpointConfig::new(primary.base_url().parse()?, None),
            replica: EndpointConfig::new(replica.base_url().parse()?, None),
            poll_interval: Duration::from_millis(10),
            initial_streams: Vec::new(),
        };

        let _replica_resync_mock = replica
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/tooling/resync")
                    .json_body(json!({ "stream": "dynamic/stream" }));
                then.status(404);
            })
            .await;

        let _primary_metrics_mock = primary
            .mock_async(|when, then| {
                when.method(GET).path("/tooling/metrics");
                then.status(200)
                    .json_body(json!({ "last_stream_seq": { "dynamic/stream": 1 } }));
            })
            .await;

        let mut runtime = BridgeRuntime::new(Client::builder().no_proxy().build()?, config);
        runtime.initialise().await?;

        let stream_body = encode_stream_response(stream, vec![(1, wire_msg.clone())]);
        primary
            .mock_async(move |when, then| {
                when.method(POST).path("/v1/stream");
                then.status(200)
                    .header("Content-Type", "application/cbor")
                    .body(stream_body.clone());
            })
            .await;

        let expected_root_request = expected_root_hex.clone();
        let expected_root_response = expected_root_hex.clone();
        let bridge_mock = replica
            .mock_async(move |when, then| {
                when.method(POST).path("/tooling/bridge").json_body(json!({
                    "message": sample_message(stream, 1),
                    "expected_mmr_root": expected_root_request,
                }));
                then.status(200).json_body(json!({
                    "stream": stream,
                    "seq": 1,
                    "mmr_root": expected_root_response,
                }));
            })
            .await;

        runtime.replicate_once().await?;
        bridge_mock.assert_hits_async(1).await;

        ensure!(
            runtime.streams.contains_key(stream),
            "stream was not tracked"
        );

        Ok(())
    }
}
