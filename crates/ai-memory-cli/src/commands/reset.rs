//! `ai-memory reset --confirm` — wipe wiki/, db/, raw/ contents.
//!
//! Refuses to run while another `ai-memory` process is alive (lesson from
//! basic-memory #765, where a zombie process holding the old SQLite
//! inode caused phantom search results after a reset).

use anyhow::{Result, bail};
use std::ffi::OsStr;
use sysinfo::System;

use crate::cli::ResetArgs;
use crate::config::Config;

const SUBDIRS: &[&str] = &["wiki", "db", "raw"];
const BIN_NAME: &str = "ai-memory";

/// Run the `reset` subcommand.
///
/// # Errors
/// Returns an error if another `ai-memory` process is running, if
/// `--confirm` was not provided, or if a directory cannot be removed.
pub fn run(config: &Config, args: ResetArgs) -> Result<()> {
    let siblings = sibling_processes();
    if !siblings.is_empty() {
        let pids: Vec<u32> = siblings.iter().map(|p| p.as_u32()).collect();
        bail!(
            "refusing to reset: {} other ai-memory process(es) running (pids: {:?}). \
             Stop them first, then re-run.",
            pids.len(),
            pids,
        );
    }

    if !args.confirm {
        for sub in SUBDIRS {
            let path = config.data_dir.join(sub);
            if path.exists() {
                println!("would remove {}", path.display());
            }
        }
        println!("(dry-run; pass --confirm to wipe)");
        return Ok(());
    }

    for sub in SUBDIRS {
        let path = config.data_dir.join(sub);
        if !path.exists() {
            continue;
        }
        std::fs::remove_dir_all(&path)?;
        std::fs::create_dir_all(&path)?;
        tracing::info!(path = %path.display(), "reset");
    }
    tracing::info!("reset complete");
    Ok(())
}

fn sibling_processes() -> Vec<sysinfo::Pid> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let me = sysinfo::Pid::from_u32(std::process::id());
    let bin_os: &OsStr = OsStr::new(BIN_NAME);
    sys.processes_by_exact_name(bin_os)
        // On Linux, sysinfo lists tokio worker threads alongside the main
        // process under the same comm name. thread_kind() == None means
        // we're looking at the process leader, not one of its threads.
        .filter(|p| p.thread_kind().is_none())
        .map(sysinfo::Process::pid)
        .filter(|pid| *pid != me)
        .collect()
}
