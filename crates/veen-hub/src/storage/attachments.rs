use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;

use super::HubStorage;

pub async fn load_refcounts(storage: &HubStorage) -> Result<Option<HashMap<String, u64>>> {
    let refs_dir = storage.attachment_refs_dir();
    if !fs::try_exists(&refs_dir)
        .await
        .with_context(|| format!("checking attachment ref index {}", refs_dir.display()))?
    {
        return Ok(None);
    }

    let mut counts = HashMap::new();
    let mut entries = fs::read_dir(&refs_dir)
        .await
        .with_context(|| format!("listing attachment ref index {}", refs_dir.display()))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .context("reading attachment ref index entry")?
    {
        if !entry
            .file_type()
            .await
            .context("checking attachment ref entry type")?
            .is_file()
        {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("ref") {
            continue;
        }
        let digest = match path.file_stem().and_then(|stem| stem.to_str()) {
            Some(digest) => digest.to_string(),
            None => continue,
        };
        let raw = fs::read_to_string(&path)
            .await
            .with_context(|| format!("reading attachment ref {}", path.display()))?;
        let value = raw
            .trim()
            .parse::<u64>()
            .with_context(|| format!("parsing attachment ref {}", path.display()))?;
        counts.insert(digest, value);
    }

    Ok(Some(counts))
}

pub async fn rewrite_all_refcounts(
    storage: &HubStorage,
    counts: &HashMap<String, u64>,
) -> Result<()> {
    let refs_dir = storage.attachment_refs_dir();
    fs::create_dir_all(&refs_dir).await.with_context(|| {
        format!(
            "ensuring attachment ref index directory {}",
            refs_dir.display()
        )
    })?;

    let mut entries = fs::read_dir(&refs_dir)
        .await
        .with_context(|| format!("listing attachment ref index {}", refs_dir.display()))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .context("reading attachment ref index entry")?
    {
        fs::remove_file(entry.path())
            .await
            .with_context(|| format!("clearing attachment ref entry {}", entry.path().display()))?;
    }

    for (digest, count) in counts {
        if *count == 0 {
            continue;
        }
        let path = storage.attachment_ref_path(digest);
        write_refcount_file(&path, *count).await?;
    }

    Ok(())
}

pub async fn write_refcount(storage: &HubStorage, digest: &str, count: u64) -> Result<()> {
    let path = storage.attachment_ref_path(digest);
    let refs_dir = storage.attachment_refs_dir();
    fs::create_dir_all(&refs_dir).await.with_context(|| {
        format!(
            "ensuring attachment ref index directory {}",
            refs_dir.display()
        )
    })?;

    if count == 0 {
        if fs::try_exists(&path)
            .await
            .with_context(|| format!("checking attachment ref {}", path.display()))?
        {
            fs::remove_file(&path)
                .await
                .with_context(|| format!("removing attachment ref {}", path.display()))?;
        }
        return Ok(());
    }

    write_refcount_file(&path, count).await?;
    Ok(())
}

pub async fn read_refcount(storage: &HubStorage, digest: &str) -> Result<Option<u64>> {
    let path = storage.attachment_ref_path(digest);
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking attachment ref {}", path.display()))?
    {
        return Ok(None);
    }

    let raw = fs::read_to_string(&path)
        .await
        .with_context(|| format!("reading attachment ref {}", path.display()))?;
    let value = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("parsing attachment ref {}", path.display()))?;
    Ok(Some(value))
}

async fn write_refcount_file(path: &Path, count: u64) -> Result<()> {
    fs::write(path, count.to_string())
        .await
        .with_context(|| format!("writing attachment ref {}", path.display()))?;
    Ok(())
}
