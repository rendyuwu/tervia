<div align="center">
  <img src="tervia.png" width="120" height="120" alt="Tervia" />
  <h1>Tervia</h1>
  <p><em>A desktop client for remote machines.</em></p>
  <p><strong>SSH, port forwarding, and file transfer in one window. Nothing else.</strong></p>

  <p>
    <img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="license" />
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="platform" />
    <img src="https://img.shields.io/badge/runtime-no%20Electron-brightgreen" alt="no Electron" />
    <img src="https://img.shields.io/badge/telemetry-none-blue" alt="no telemetry" />
    <img src="https://img.shields.io/badge/status-pre--release-orange" alt="pre-release" />
  </p>
</div>

---

## What is Tervia?

Tervia keeps your remote machines in one place: a saved connection opens a
shell, forwards a port, or browses the remote filesystem without you assembling
a command line for it. Built on Tauri 2, so a Rust core owns every OS resource
and the UI is a single webview — no Node runtime, no bundled Chromium, and a
resident footprint closer to a terminal than to an IDE.

**No telemetry.** Passwords and private keys go to the OS keychain, never to
disk in plaintext. The connection backup is encrypted with a passphrase you
choose, and the server side of the planned sync only ever sees ciphertext.

## Features

| Feature              | Status  | What it does                                                                                                                                                                  |
| -------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SSH**              | Shipped | Terminal sessions to saved hosts over `russh`. Password, private key, or the local ssh-agent. Host-key pinning with a trust-on-first-use prompt, and chained jump hosts.      |
| **Port forwarding**  | Shipped | `ssh -L` style local forwards, bound to loopback only. Several forwards share one refcounted session.                                                                         |
| **SFTP**             | Shipped | Remote file tree, drag-and-drop transfer, open a remote file straight into the editor.                                                                                        |
| **Encrypted backup** | Shipped | Export every saved connection — including the secrets pulled back out of the keychain — as one passphrase-encrypted file, and import it on another machine.                   |
| **Local workspace**  | Shipped | Native PTY terminals (zsh / bash / fish / pwsh) on xterm.js + WebGL, split panes, tab groups, a CodeMirror editor, and a file explorer with git decorations. Fully themeable. |
| **RDP**              | Planned | Remote desktop, alongside SSH in the same connection list.                                                                                                                    |
| **Sync**             | Planned | End-to-end encrypted sync of your saved machines across devices. Private keys stay opt-in.                                                                                    |

## Install

There is no published release yet — Tervia is pre-1.0 and the version series
starts at `0.1.0`. Build from source for now; see below.

## CLI

```bash
tervia [PATH]     # open a folder or file in Tervia
tervia .          # open the current directory
tervia --help | --version | --update
```

If Tervia is already running the request forwards to that window, rather than
opening a second one. On macOS and the Linux AppImage the `tervia` command is
not on `PATH` by default: **Settings → General → Install `tervia` command in
PATH** writes a shim to `~/.local/bin/tervia`. The Windows installer does this
for you.

## Build from source

Prereqs: Rust stable ([rustup](https://rustup.rs)), Node 20.19+ / 22.12+ with
[pnpm](https://pnpm.io), and
[Tauri's platform prereqs](https://tauri.app/start/prerequisites/).

```bash
pnpm install
pnpm tauri:dev     # dev, against an isolated data dir
pnpm tauri build   # production bundle
```

Pre-PR checks (full list in [CONTRIBUTING.md](CONTRIBUTING.md)):

```bash
pnpm exec tsc --noEmit && pnpm lint:imports && pnpm format:check
cd src-tauri && cargo clippy && cargo fmt && cargo test
```

## Architecture

A React 19 webview (`src/`) talks to a Rust backend (`src-tauri/`) through
`invoke()` and streaming `Channel`s. See **[ARCHITECTURE.md](ARCHITECTURE.md)**
for the design, then [TERVIA.md](TERVIA.md) for the per-module reference.

## Notes per platform

- **Windows**: SmartScreen warns on first launch (unsigned); click _More info >
  Run anyway_. Shell priority: `pwsh.exe`, `powershell.exe`, `cmd.exe`.
- **Linux**: on `EGL_BAD_PARAMETER` or a blank window, set
  `WEBKIT_DISABLE_DMABUF_RENDERER=1`. AppImage needs FUSE (otherwise
  `--appimage-extract-and-run`, or use the `.deb` / `.rpm`).
- **macOS**: minimum 10.15. Unsigned builds may trip Gatekeeper; drag to
  `/Applications`, run `xattr -cr /Applications/Tervia.app` once, then open
  from Finder.

## Credits

Tervia is a fork of **[TEDI](https://github.com/IlhamriSKY/TEDI)** at `v0.4.22`
by [IlhamriSKY](https://github.com/IlhamriSKY), which is itself a fork of
**[Terax](https://github.com/crynta/terax-ai)** by
[Crynta](https://github.com/crynta). The Tauri/Rust backend, the xterm.js
terminal and the CodeMirror editor come from Terax; the SSH, SFTP, port
forwarding and encrypted-backup work that Tervia is built around comes from
TEDI. Both are Apache-2.0. If Tervia is useful to you, please star
[TEDI](https://github.com/IlhamriSKY/TEDI) and
[Terax](https://github.com/crynta/terax-ai) too.

Tervia removes what it does not need — the AI agent, the extension system, the
in-app browser, the API client and the SQL explorer are all gone — so it is not
a drop-in replacement for either upstream, and it is maintained independently
rather than upstreamed. Files modified from TEDI are marked as such by this
notice and by the repository's git history, which is intact back to the fork
point.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for required
attribution.
