use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::HubStorage;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamIndexEntry {
    pub seq: u64,
    pub leaf_hash: String,
    pub bundle: String,
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
    let mut lines = BufReader::new(file).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .with_context(|| format!("reading stream index {}", path.display()))?
    {
        if line.is_empty() {
            continue;
        }
        let entry: StreamIndexEntry = serde_json::from_str(&line)
            .with_context(|| format!("decoding stream index entry from {}", path.display()))?;
        entries.push(entry);
    }

    Ok(entries)
}

pub fn bundle_path(storage: &HubStorage, entry: &StreamIndexEntry) -> PathBuf {
    let bundle_path = Path::new(&entry.bundle);
    if bundle_path.is_absolute() {
        bundle_path.to_path_buf()
    } else {
        storage.messages_dir().join(bundle_path)
    }
}
