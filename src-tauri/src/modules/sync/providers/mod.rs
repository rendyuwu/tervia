//! The backends that sit behind `SyncProvider` in
//! `src-tauri/src/modules/sync/provider.rs`.
//!
//! One per file, each reachable only through `build` in that module, so adding
//! a backend is a new file here plus one arm there and touches nothing else.
//! `src-tauri/src/modules/sync/providers/sigv4.rs` is shared signing rather
//! than a backend of its own: any other service speaking the same signature
//! scheme would use it without a second copy.

pub mod s3;
pub mod sigv4;
pub mod webdav;
