# Changelog

The latest release only. Every earlier version:
[GitHub Releases](https://github.com/rendyuwu/tervia/releases). Versions:
[SemVer](https://semver.org/); before `1.0` a minor bump may break things.

## [0.1.0] - Unreleased

First release. Forked from [TEDI](https://github.com/IlhamriSKY/TEDI) v0.4.22,
itself forked from [Terax](https://github.com/crynta/terax-ai) v0.5.9. Earlier
history: their changelogs and `git log`.

### Added

**Hosts and vault**

- One host list for SSH and RDP: nested groups, tags, icon and colour, last connected.
- Vault: identities and keys shared by many hosts. A group can set a default identity for new hosts.
- Key editor: generate Ed25519, ECDSA P-256 or RSA-4096. OpenSSH certificate and hardware (ssh-agent) key kinds.
- Connect from the Hosts page, the header quick connect, or `#` in the Command Palette.
- Import from `~/.ssh/config` and PuTTY `.reg` exports.
- Vault page finds keychain entries no record uses and deletes them.

**SSH**

- Auth: password, private key, ssh-agent, OpenSSH certificate, hardware key.
- SHA-256 host-key pinning with a first-connect trust prompt. Known Hosts page lists and revokes SSH and RDP pins.
- Jump host chains.
- One session per host, shared by terminal tabs, forwards and RDP tunnels.

**Port forwarding**

- `-L`, `-R` and SOCKS5 `-D` rules on the Port Forwarding page.
- Start by hand, with the host's terminal (`-L` only), or at app launch with retry backoff.
- A `localhost:PORT` URL printed by a remote shell gets a local forward.

**SFTP**

- Remote file tree: upload by drop (files, up to 256 MiB), open and save text files (up to 16 MiB), create, rename, delete.

**RDP**

- TLS and CredSSP (NTLM), certificate pinning, RemoteFX and bitmap graphics.
- Resize to fit the pane (Display Control), or a fixed size.
- Clipboard text and images, direction set per host.
- Tunnel through a saved SSH host. Up to 8 sessions.

**Backup and sync**

- `.tervia-backup` (format v3): hosts, groups, vault, forward rules and secrets, sealed with PBKDF2-HMAC-SHA256 (600,000 rounds) and AES-256-GCM.
- End-to-end encrypted sync over S3-compatible storage or WebDAV. Per-record AES-256-GCM, last writer wins, 90-day tombstones. Off by default; key bodies opt-in.

**Workspace**

- Local terminals on xterm.js (WebGL). Shell integration for zsh, bash, fish and PowerShell. PTYs survive closing the window.
- Split panes, tabs, saved workspaces, pop-out windows.
- CodeMirror 6 editor: vim mode, format on save (Prettier or an external formatter), Markdown preview.
- File explorer: go to file, search and replace in files, git decorations.
- Status of AI agent CLIs (Claude Code, Codex, Gemini, ...) in a terminal, and a board of them.
- Themes (import and export `.tervia` files), rebindable shortcuts, Command Palette.
- CLI: `tervia [PATH]`, `--help`, `--version`, `--update`.
- Signed updates, checked every 6 hours, installed on request.

### Changed (vs TEDI v0.4.22)

- `Ctrl+]` / `Ctrl+[` move pane focus even when a terminal or RDP pane has focus. Rebind `pane.focusNext` / `pane.focusPrev` to give them back to the shell.

### Removed (vs TEDI v0.4.22)

- AI agent: providers, MCP, sub-agents, autocomplete, AI diff tab. Detecting agent CLIs in a terminal stays.
- Extension system and the `ext` CLI subcommand.
- In-app browser.
- Source Control panel. Explorer git decorations stay.
- Task scheduler.
- `theme` CLI subcommand and headless `--update`. `--update` now opens the window.
