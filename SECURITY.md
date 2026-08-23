# Security

Tervia runs shells, reads and writes files, holds SSH credentials, and dials
remote hosts on your behalf, so security bugs matter. If you find one, please
tell us before posting it publicly.

## Reporting

Use
**[GitHub Security Advisories](https://github.com/rendyuwu/tervia/security/advisories/new)**
to file a private report. Include:

- What the issue is and what it lets an attacker do
- Steps to reproduce (a small PoC is great)
- Version, OS, arch

You'll usually hear back within a few days. Once it's fixed, we'll credit you in
the release notes, unless you'd rather stay anonymous.

Please **don't** open a public GitHub issue for security reports.

## Supported versions

Until `1.0.0`, only the latest minor gets security fixes.

## What's in scope

- The Rust backend in `src-tauri/` (PTY, FS, SSH, IPC, keychain, plugins)
- The frontend in `src/`, anywhere untrusted input lands: terminal output,
  remote file content, an imported connection backup, a host's key material
- The update feed and the signatures on release artifacts

## What's not

- Bugs in upstream deps (Tauri, `russh`, xterm.js, CodeMirror). Report those
  upstream; we'll ship the fix once it's released.
- Anything that needs an already-compromised machine or a local attacker with
  shell access

## What we do to keep things safe

- **SSH secrets live in the OS keychain** via `keyring`. Not on disk, not in
  `localStorage`, not in logs. An `agent`-auth connection never sees the
  private key at all — the local ssh-agent signs each handshake.
- **Host keys are pinned.** An unknown host raises a trust-on-first-use prompt;
  a changed key fails the connection. The port-forward path refuses a
  connection with no pinned key outright, because nothing there can show that
  prompt.
- **Port forwards bind loopback only.** A forward is never exposed on the LAN.
- **The connection backup is encrypted in the Rust process** —
  PBKDF2-HMAC-SHA256 into AES-256-GCM, a fresh salt and nonce per seal. A wrong
  passphrase and a corrupted file both fail closed on the GCM tag.
- **No telemetry.** Tervia only talks to the network when you ask it to, plus
  the update check.
- **Updates are signed.** The updater verifies a minisign signature against the
  public key baked into the build before it installs anything. It does not
  install without you starting it.
- **No Node in the renderer.** The frontend only reaches the host through
  allow-listed Tauri commands.

## What we can't promise

- Tervia runs whatever you tell it to run, locally and remotely, with your
  permissions. That's the point of a terminal.
- A remote host you connect to sees whatever you type into it, and its output
  is rendered in your terminal. Connect to hosts you trust.
- An imported connection backup is only as trustworthy as wherever you got it
  from. The parser re-validates every field for exactly this reason, but the
  hosts inside it are still hosts someone else chose.
