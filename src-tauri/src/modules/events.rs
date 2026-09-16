//! Names of Tauri events the Rust process EMITS to the webview.
//!
//! Mirror of the `IPC_EVENTS` constants in `src/lib/ipc.ts`. A typo on either
//! side just makes the listener never fire (silent), so both sides reference a
//! single named constant instead of a bare string literal.

/// Rust -> Settings webview: focus a settings tab (payload: tab id string).
pub const SETTINGS_TAB: &str = "tervia:settings-tab";

/// Rust -> main window: open a path passed to the `tervia` CLI (single-instance forward).
pub const OPEN_CLI_TARGET: &str = "tervia:open-cli-target";

/// Rust -> main window: the `tervia --update` shim asks the UI to start updating.
pub const TRIGGER_UPDATE: &str = "tervia:trigger-update";

/// Rust -> main window: the window regained focus, which is when the sync
/// scheduler may pull.
///
/// A SIGNAL, not a command: the rate limit lives on the frontend beside the
/// debounce, because both of them measure the same thing and splitting them
/// across the IPC boundary would put half the policy where the other half
/// cannot see it. Emitted only for the `main` label - see the window event
/// handler in `src-tauri/src/lib.rs` for why only one webview may apply.
pub const SYNC_FOCUSED: &str = "tervia:sync-focused";
