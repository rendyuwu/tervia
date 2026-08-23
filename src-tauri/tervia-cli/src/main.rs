//! Console-subsystem entry point shipped as `tervia.exe` next to the GUI
//! binary `TerviaApp.exe` on Windows. PATHEXT finds this binary first when
//! the user types `tervia` (the GUI binary intentionally has a non-matching
//! name so it stays off the shell's resolution path).
//!
//! Why it exists: TerviaApp.exe is `windows_subsystem = "windows"` (set in
//! `main.rs`). PowerShell - the default Windows 11 shell - does NOT
//! synchronously wait for GUI-subsystem children. The next prompt is drawn
//! immediately after spawn, and any output the GUI binary later emits via
//! `AttachConsole(ATTACH_PARENT_PROCESS)` lands on top of that already-drawn
//! prompt. Cursor ends up mid-line; the user has to press Enter to recover.
//!
//! This stub fixes the wait semantics at the kernel level: PowerShell sees
//! a console-subsystem child and waits for it the same way it waits for
//! `git.exe` or `node.exe`. Inside, we dispatch:
//!
//!   `--help` / `--version`         → print inline, no spawn (fast - no
//!                                     Tauri runtime boot for a 20-line
//!                                     string).
//!   `--update`                    → spawn TerviaApp.exe synchronously with
//!                                     `Stdio::inherit` so output streams
//!                                     to the shell in real time and the
//!                                     stub's exit code mirrors the child's.
//!   anything else (no args, paths) → spawn TerviaApp.exe DETACHED with
//!                                     null stdio so the shell prompt
//!                                     returns immediately.
//!
//! macOS / Linux ship without a subsystem split - there `tervia` resolves
//! directly to the GUI binary which inherits stdio natively. This stub is
//! built on every platform for `cargo check` parity but only the NSIS
//! installer bundles `tervia.exe`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rest = &args[1..];

    // --help / --version: handle natively. Reuses `tervia_lib::cli::help_text`
    // so the text never drifts from the GUI binary's `--help` output.
    if rest.iter().any(|a| matches!(a.as_str(), "--help" | "-h")) {
        println!("{}", tervia_lib::modules::cli::help_text());
        return;
    }
    if rest
        .iter()
        .any(|a| matches!(a.as_str(), "--version" | "-v" | "-V"))
    {
        // Print "tervia <ver>" - the literal binary name the user invoked.
        // `env!("CARGO_PKG_NAME")` would render as "tervia-cli" (this launcher
        // package's Cargo name) which would confuse anyone tracking down a
        // version string; the user typed `tervia`, the answer says `tervia`.
        // Version comes from the GUI crate so both --version paths agree.
        println!("tervia {}", tervia_lib::VERSION);
        return;
    }

    let Some(gui_exe) = resolve_gui_exe() else {
        eprintln!(
            "tervia: could not locate TerviaApp.exe next to the launcher. \
             Reinstall Tervia if this persists."
        );
        std::process::exit(2);
    };

    if is_cli_invocation(rest) {
        // Synchronous: stdio passes straight through so output streams to
        // the shell in real time. GUI binary inherits the console handles
        // and calls `AttachConsole(ATTACH_PARENT_PROCESS)` to make
        // Win32 console APIs (used by dialoguer) work. PowerShell waits on
        // *this* stub (console subsystem) - proper synchronisation.
        match Command::new(&gui_exe)
            .args(rest)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
        {
            Ok(status) => std::process::exit(status.code().unwrap_or(0)),
            Err(e) => {
                eprintln!("tervia: failed to spawn TerviaApp.exe: {e}");
                std::process::exit(2);
            }
        }
    }

    // GUI launch (`tervia`, `tervia .`, `tervia <path>`). Detach so the shell
    // prompt returns immediately - the GUI lives its own life from here.
    // Errors are intentionally swallowed: if the GUI fails to start the
    // user sees nothing in their shell (matches `start "" TerviaApp.exe`
    // behaviour). Errors will surface in the Windows Event Log if needed.
    spawn_detached(&gui_exe, rest);
}

/// Resolve the GUI binary path as a sibling of this binary. Returns `None`
/// when the file is missing (corrupted install).
fn resolve_gui_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(if cfg!(target_os = "windows") {
        "TerviaApp.exe"
    } else {
        "TerviaApp"
    });
    candidate.exists().then_some(candidate)
}

/// Argv shapes that require the GUI binary to print to the user's terminal
/// (rather than open a window). Mirrors the routing in `lib::run`'s
/// `handle_*_and_exit` short-circuits.
fn is_cli_invocation(rest: &[String]) -> bool {
    rest.iter().any(|a| matches!(a.as_str(), "--update" | "-u"))
}

#[cfg(target_os = "windows")]
fn spawn_detached(gui_exe: &Path, args: &[String]) {
    use std::os::windows::process::CommandExt;
    // DETACHED_PROCESS: child has no console of its own.
    // CREATE_NEW_PROCESS_GROUP: Ctrl+C handler in our stub does not
    // propagate to the detached GUI (it would already have its own input
    // path via the webview anyway).
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    let _ = Command::new(gui_exe)
        .args(args)
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(not(target_os = "windows"))]
fn spawn_detached(gui_exe: &Path, args: &[String]) {
    // Non-Windows: nothing fancy - POSIX shells background the child via
    // job control if invoked with `&`. This binary is not shipped on
    // mac/Linux anyway (only Windows needs the subsystem split fix);
    // we keep the function for `cargo check` parity.
    let _ = Command::new(gui_exe).args(args).spawn();
}
