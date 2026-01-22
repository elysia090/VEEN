use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::warn;

use super::HubStorage;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamIndexEntry {
    pub seq: u64,
    pub leaf_hash: String,
    pub bundle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamIndexHead {
    pub last_seq: u64,
    pub last_leaf_hash: String,
}

pub async fn append_stream_index(
    storage: &HubStorage,
    stream: &str,
    entry: &StreamIndexEntry,
) -> Result<()> {
    let path = storage.stream_index_path(stream);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring stream index directory {}", parent.display()))?;
    }

    let mut encoded = serde_json::to_vec(entry).context("serialising stream index entry")?;
    encoded.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("opening stream index {} for append", path.display()))?;

    file.write_all(&encoded)
        .await
        .with_context(|| format!("appending stream index record for {stream}"))?;

    write_stream_index_head(storage, stream, entry).await?;

    Ok(())
}

pub async fn load_stream_index(path: &Path) -> Result<Vec<StreamIndexEntry>> {
    if !fs::try_exists(path)
        .await
        .with_context(|| format!("checking stream index {}", path.display()))?
    {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let file = File::open(path)
        .await
        .with_context(|| format!("opening stream index {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    let mut line_number = 0usize;
    loop {
        buffer.clear();
        let bytes_read = reader
            .read_until(b'\n', &mut buffer)
            .await
            .with_context(|| format!("reading stream index {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        if !buffer.ends_with(b"\n") {
            break;
        }
        line_number += 1;
        buffer.pop();
        if buffer.last() == Some(&b'\r') {
            buffer.pop();
        }
        if buffer.is_empty() {
            continue;
        }
        match serde_json::from_slice::<StreamIndexEntry>(&buffer) {
            Ok(entry) => entries.push(entry),
            Err(error) => {
                if let Err(utf8_error) = std::str::from_utf8(&buffer) {
                    warn!(
                        "Skipping stream index line {} in {} due to invalid UTF-8: {}",
                        line_number,
                        path.display(),
                        utf8_error
                    );
                } else {
                    warn!(
                        "Skipping stream index line {} in {} due to invalid JSON: {}",
                        line_number,
                        path.display(),
                        error
                    );
                }
            }
        }
    }

    Ok(entries)
}

pub async fn load_stream_index_head(
    storage: &HubStorage,
    stream: &str,
) -> Result<Option<StreamIndexHead>> {
    let path = storage.stream_index_head_path(stream);
    let data = match fs::read(&path).await {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("reading stream index head {}", path.display()))
        }
    };
    let head = serde_json::from_slice(&data)
        .with_context(|| format!("decoding stream index head {}", path.display()))?;
    Ok(Some(head))
}

async fn write_stream_index_head(
    storage: &HubStorage,
    stream: &str,
    entry: &StreamIndexEntry,
) -> Result<()> {
    let head = StreamIndexHead {
        last_seq: entry.seq,
        last_leaf_hash: entry.leaf_hash.clone(),
    };
    let data = serde_json::to_vec(&head).context("serialising stream index head")?;
    let path = storage.stream_index_head_path(stream);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring stream head directory {}", parent.display()))?;
    }
    fs::write(&path, data)
        .await
        .with_context(|| format!("writing stream index head {}", path.display()))
}

pub fn bundle_path(storage: &HubStorage, entry: &StreamIndexEntry) -> PathBuf {
    let bundle_path = Path::new(&entry.bundle);
    if bundle_path.is_absolute() {
        bundle_path.to_path_buf()
    } else {
        storage.messages_dir().join(bundle_path)
    }
}
