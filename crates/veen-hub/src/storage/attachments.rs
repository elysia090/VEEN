use std::collections::HashMap;

use anyhow::{Context, Result};
use tokio::fs;

use super::HubStorage;

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
        write_refcount(storage, digest, *count).await?;
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

    fs::write(&path, count.to_string())
        .await
        .with_context(|| format!("writing attachment ref {}", path.display()))?;
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
