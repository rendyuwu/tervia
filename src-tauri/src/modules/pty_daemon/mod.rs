// Sidecar PTY daemon — owns the lifecycle of every interactive shell so
// they survive the GUI window closing. Same binary as the GUI; the
// daemon mode is selected by the `--pty-daemon` flag short-circuited
// before Tauri boots (mirrors `cli::handle_version_help_and_exit`).
//
// Process model:
//   `TerviaApp` (GUI)  <—local socket—>  `TerviaApp --pty-daemon`
//
// Lifecycle goals:
//   • GUI close       → daemon survives, sessions persist
//   • GUI reopen      → reconnect + Attach(session_id) to resume
//   • PC restart      → daemon dies with kernel, sessions lost (intended)
//   • Daemon crash    → sessions lost, GUI falls back to fresh spawn
//
// File map, grouped by the layer each module belongs to. The three groups are
// also the three that landed together, in this order — the wire first, then
// the end that serves it, then the end that dials it:
//
//   the wire, spoken by both ends:
//     protocol.rs   — wire messages (ClientMsg / DaemonMsg)
//     transport.rs  — length-prefixed JSON framing over local sockets
//     paths.rs      — per-user socket path / pipe name
//
//   daemon side:
//     server.rs     — daemon-side accept loop, session store, scrollback
//
//   GUI side:
//     client.rs     — GUI-side connect_or_spawn + event proxy
//     spawn.rs      — detached child spawn (POSIX setsid / Win DETACHED)

pub mod client;
pub mod paths;
pub mod protocol;
pub mod server;
pub mod spawn;
pub mod transport;

/// Argv flag selecting daemon mode. Mirrors the conventions of
/// `cli::handle_version_help_and_exit`.
pub const DAEMON_FLAG: &str = "--pty-daemon";

/// Detect the daemon flag without consuming argv. Cheap; called once per
/// `lib::run()` invocation alongside the other CLI short-circuits.
pub fn args_request_daemon() -> bool {
    std::env::args().skip(1).any(|a| a == DAEMON_FLAG)
}

/// Pre-Tauri CLI short-circuit: if invoked with `--pty-daemon`, run the
/// daemon server forever and `process::exit`. Returns immediately when the
/// flag is absent. Matches the calling convention of
/// `cli::handle_version_help_and_exit` so it slots into `lib::run()`'s
/// dispatch chain.
pub fn handle_pty_daemon_command_and_exit() {
    if !args_request_daemon() {
        return;
    }
    server::run_forever();
}
