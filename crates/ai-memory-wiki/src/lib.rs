//! Wiki filesystem layer.
//!
//! Owns the markdown-on-disk source of truth: atomic writes, frontmatter
//! parsing/emission, and write-through to the [`ai_memory_store`] writer
//! actor so the SQLite index never diverges from the file. The watcher +
//! git layer arrive in M1-D and M5.

mod atomic;
mod error;
mod markdown;
mod watcher;
mod wiki;

pub use error::{WikiError, WikiResult};
pub use markdown::{Markdown, derive_title, emit, parse};
pub use watcher::{DEBOUNCE_WINDOW, RECONCILE_INTERVAL, WatcherHandle};
pub use wiki::{Wiki, WritePageRequest};
