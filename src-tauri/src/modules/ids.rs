//! Single source of truth for the app's bundle identifier and the
//! per-user data paths derived from it without an `AppHandle`.
//!
//! [`BUNDLE_ID`] MUST match the `identifier` field in `tauri.conf.json`
//! (and the `.dev` override in `tauri.dev.conf.json`). Tauri 2's
//! `app_data_dir` returns `<dirs::data_dir()>/<identifier>` on every desktop
//! platform, so the no-`AppHandle` callers here (the CLI surfaces and the
//! pty daemon, which boot before Tauri builds an `AppHandle`) reproduce the
//! same path. Debug builds use the `.dev` suffix so `pnpm tauri dev` reads
//! and writes a separate data dir from an installed release.

use std::path::PathBuf;

/// Bundle id from `tauri.conf.json`. Keep in sync with the `identifier`
/// field there. Debug builds switch to the `.dev` suffix so dev runs land
/// in a separate data dir from installed releases.
#[cfg(debug_assertions)]
pub const BUNDLE_ID: &str = "dev.rendy.tervia.dev";
#[cfg(not(debug_assertions))]
pub const BUNDLE_ID: &str = "dev.rendy.tervia";

/// Per-user app-data directory: `<dirs::data_dir()>/<BUNDLE_ID>`. `None`
/// only when the OS data dir cannot be resolved (very rare). Does NOT create
/// the directory.
pub fn app_data_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join(BUNDLE_ID))
}
