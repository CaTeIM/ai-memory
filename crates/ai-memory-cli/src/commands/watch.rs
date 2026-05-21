//! `ai-memory watch` — foreground watcher loop.
//!
//! In v1 this is a standalone command; in M2 the watcher folds into
//! `ai-memory serve` alongside the MCP transport.

use ai_memory_store::Store;
use ai_memory_wiki::{WatcherHandle, Wiki};
use anyhow::{Context, Result};

use crate::cli::WatchArgs;
use crate::config::Config;

/// Run the `watch` subcommand.
///
/// # Errors
/// Returns an error if the store cannot be opened or the watcher
/// cannot install its filesystem hooks.
pub async fn run(config: &Config, args: WatchArgs) -> Result<()> {
    let store = Store::open(&config.data_dir)
        .with_context(|| format!("opening store at {}", config.data_dir.display()))?;
    let ws = store
        .writer
        .get_or_create_workspace(args.workspace.clone())
        .await?;
    let proj = store
        .writer
        .get_or_create_project(ws, args.project.clone(), None)
        .await?;

    let wiki = Wiki::new(&config.data_dir, store.writer.clone())?;
    let handle = WatcherHandle::start(wiki.clone(), ws, proj)?;
    tracing::info!(
        root = %wiki.root().display(),
        workspace = %args.workspace,
        project = %args.project,
        "watching wiki (Ctrl-C to stop)"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down watcher");
    handle.shutdown().await;
    Ok(())
}
