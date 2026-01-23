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

pub struct StreamIndexReader {
    reader: BufReader<File>,
    buffer: Vec<u8>,
    line_number: usize,
    path: PathBuf,
}

impl StreamIndexReader {
    pub async fn open(path: &Path) -> Result<Option<Self>> {
        if !fs::try_exists(path)
            .await
            .with_context(|| format!("checking stream index {}", path.display()))?
        {
            return Ok(None);
        }

        let file = File::open(path)
            .await
            .with_context(|| format!("opening stream index {}", path.display()))?;
        Ok(Some(Self {
            reader: BufReader::new(file),
            buffer: Vec::new(),
            line_number: 0,
            path: path.to_path_buf(),
        }))
    }

    pub async fn next_entry(&mut self) -> Result<Option<StreamIndexEntry>> {
        loop {
            self.buffer.clear();
            let bytes_read = self
                .reader
                .read_until(b'\n', &mut self.buffer)
                .await
                .with_context(|| format!("reading stream index {}", self.path.display()))?;
            if bytes_read == 0 {
                return Ok(None);
            }
            if !self.buffer.ends_with(b"\n") {
                return Ok(None);
            }
            self.line_number += 1;
            self.buffer.pop();
            if self.buffer.last() == Some(&b'\r') {
                self.buffer.pop();
            }
            if self.buffer.is_empty() {
                continue;
            }

            match serde_json::from_slice::<StreamIndexEntry>(&self.buffer) {
                Ok(entry) => return Ok(Some(entry)),
                Err(error) => self.warn_invalid_line(error),
            }
        }
    }

    fn warn_invalid_line(&self, error: serde_json::Error) {
        if let Err(utf8_error) = std::str::from_utf8(&self.buffer) {
            warn!(
                "Skipping stream index line {} in {} due to invalid UTF-8: {}",
                self.line_number,
                self.path.display(),
                utf8_error
            );
        } else {
            warn!(
                "Skipping stream index line {} in {} due to invalid JSON: {}",
                self.line_number,
                self.path.display(),
                error
            );
        }
    }
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
    let Some(mut reader) = StreamIndexReader::open(path).await? else {
        return Ok(Vec::new());
    };

    let mut entries = Vec::new();
    while let Some(entry) = reader.next_entry().await? {
        entries.push(entry);
    }
    Ok(entries)
}

pub async fn load_stream_index_range(
    path: &Path,
    from: u64,
    to: u64,
) -> Result<Vec<StreamIndexEntry>> {
    if from > to {
        return Ok(Vec::new());
    }

    let Some(mut reader) = StreamIndexReader::open(path).await? else {
        return Ok(Vec::new());
    };

    let expected = (to - from).saturating_add(1);
    let mut entries = Vec::with_capacity(expected as usize);
    while let Some(entry) = reader.next_entry().await? {
        if entry.seq < from {
            continue;
        }
        if entry.seq > to {
            // Stream indexes are append-only in sequence order, so we can stop early once
            // we pass the requested upper bound.
            break;
        }
        entries.push(entry);
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
