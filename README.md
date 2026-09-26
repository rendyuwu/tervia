<div align="center">
  <img src="tervia.png" width="120" height="120" alt="Tervia" />
  <h1>Tervia</h1>
  <p><em>A desktop client for remote machines.</em></p>
  <p>
    <img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="license" />
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="platform" />
  </p>
</div>

SSH, RDP, port forwarding and SFTP for your saved machines, in one window.
Tauri 2: a Rust backend and one webview, no Electron. No telemetry.

## Features

**Hosts**

- SSH and RDP hosts in one list: nested groups, tags, icon and colour, last connected, search.
- Vault: identities and keys shared by many hosts. Generates Ed25519, ECDSA P-256 and RSA-4096 keys.
- Connect from the Hosts page, the header quick connect, or `#` in the Command Palette.
- Import from `~/.ssh/config` and PuTTY `.reg` exports.

**SSH**

- Auth: password, private key (with passphrase), ssh-agent, OpenSSH certificate, hardware key through ssh-agent.
- Host keys pinned by SHA-256 on first connect (trust prompt). The Known Hosts page lists and revokes pins.
- Jump host chains.
- One session per host, shared by its terminal tabs, forwards and RDP tunnels.

**Port forwarding**

- Local (`-L`), remote (`-R`) and dynamic SOCKS5 (`-D`) rules. Local listeners bind `127.0.0.1` only.
- Start a rule by hand, with the host's terminal (`-L` only), or when Tervia starts (retries with backoff).
- A `localhost:PORT` URL printed in a remote shell is forwarded automatically.

**SFTP**

- Remote file tree: drop files to upload, open and save remote text files in the editor, create, rename, delete.
- Branch name of remote repos in the Workspaces panel.

**RDP**

- TLS and CredSSP (NTLM). Server certificate pinned on first connect.
- Resolution follows the pane, or a fixed size. Clipboard text and images, both ways.
- Direct, or tunnelled through a saved SSH host.

**Backup and sync**

- Encrypted backup: hosts, groups, vault, forward rules and their secrets in one passphrase-sealed `.tervia-backup` file.
- End-to-end encrypted sync over S3-compatible storage or WebDAV. Off by default. Private key bodies sync only if you opt in.

**Local workspace**

- Terminals on xterm.js (WebGL). Shell integration for zsh, bash, fish and PowerShell. Local sessions survive closing the window.
- Split panes, tabs, saved workspaces, pop-out windows.
- CodeMirror 6 editor: vim mode, format on save, Markdown preview.
- File explorer: go to file, search and replace in files, git decorations.
- Shows the status of AI agent CLIs (Claude Code, Codex, Gemini, ...) running in a terminal, plus a board of them.
- Themes, rebindable shortcuts, Command Palette (`Mod+Shift+P`, `@` for files).

Secrets are stored per platform: macOS Keychain, a DPAPI-encrypted file on
Windows, a plaintext mode-0600 file on Linux. What does not work yet:
[KNOWN-LIMITS.md](KNOWN-LIMITS.md).

## Install

Download from [Releases](https://github.com/rendyuwu/tervia/releases):

| OS      | Files                                  |
| ------- | -------------------------------------- |
| macOS   | `.dmg` (Apple silicon, Intel), 10.15+  |
| Linux   | `.AppImage`, `.deb`, `.rpm`            |
| Windows | `-setup.exe` (per-user NSIS installer) |

Tervia checks for signed updates every 6 hours and installs only when you say so.

Builds are not code-signed:

- **macOS**: drag to `/Applications`, run `xattr -cr /Applications/Tervia.app` once.
- **Windows**: SmartScreen warns on first launch. Click _More info > Run anyway_.
- **Linux**: AppImage needs FUSE (or run it with `--appimage-extract-and-run`). Blank window or `EGL_BAD_PARAMETER`: set `WEBKIT_DISABLE_DMABUF_RENDERER=1`.

## CLI

```bash
tervia [PATH]                       # open a folder or file
tervia --help | --version | --update
```

A running Tervia receives the request; no second window opens. `tervia` on
`PATH`: the Windows installer and the `.deb`/`.rpm` add it. On macOS and the
AppImage use **Settings > General > Install `tervia` command in PATH**
(writes `~/.local/bin/tervia`).

## Build from source

Needs Rust stable, Node 20.19+ with pnpm, and
[Tauri's prerequisites](https://tauri.app/start/prerequisites/).

```bash
pnpm install
pnpm tauri:dev     # dev build, separate data dir
pnpm tauri build   # installers
```

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Code map:
[ARCHITECTURE.md](ARCHITECTURE.md).

## Credits

Fork of [TEDI](https://github.com/IlhamriSKY/TEDI) `v0.4.22` by
[IlhamriSKY](https://github.com/IlhamriSKY), itself a fork of
[Terax](https://github.com/crynta/terax-ai) by
[Crynta](https://github.com/crynta), both Apache-2.0. Terax gave the Tauri
backend, terminal and editor; TEDI gave SSH, SFTP, port forwarding and the
encrypted backup. Tervia drops TEDI's AI agent, extension system, in-app
browser, Source Control panel and task scheduler, and is maintained
independently. Git history is intact back to both.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
