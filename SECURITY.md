# Security

## Reporting

File a private report through
**[GitHub Security Advisories](https://github.com/rendyuwu/tervia/security/advisories/new)**.
Do not open a public issue. Include what it lets an attacker do, steps to
reproduce, and version, OS, arch. Fixed reports are credited in the release
notes unless you ask otherwise.

Until `1.0.0`, only the latest minor gets security fixes.

## Scope

- In: the Rust backend (`src-tauri/`), the frontend wherever untrusted input lands (terminal output, remote files, RDP data, imported backups and configs, sync objects), the update feed and release signatures.
- Out: bugs in upstream dependencies (Tauri, `russh`, IronRDP, xterm.js, CodeMirror), report those upstream. Attacks that need an already-compromised machine or local shell access.

## What Tervia does

- **Secrets stay out of the store files.** macOS: Keychain. Windows: a DPAPI-encrypted file. Linux: a plaintext file with mode 0600. With ssh-agent auth the private key never enters Tervia.
- **Host keys and RDP certificates are pinned** (SHA-256). First connect asks before a password or key is used; a changed key fails the connection.
- **Local listeners bind `127.0.0.1`** (`-L`, `-D`). A `-R` rule listens on the server, at the address the rule names.
- **Backups are sealed in Rust**: PBKDF2-HMAC-SHA256 (600,000 rounds) into AES-256-GCM, fresh salt and nonce per file. A wrong passphrase or a corrupt file fails on the GCM tag.
- **Sync is end-to-end encrypted.** The storage provider sees ciphertext and opaque object names. Private key bodies are uploaded only if you opt in.
- **Updates are signed** (minisign, key built into the app) and install only when you start them.
- **No telemetry.** Network traffic is what you ask for, plus the update check.
- **The webview reaches the OS only through registered Tauri commands.**

## What Tervia cannot promise

- It runs what you tell it to, locally and remotely, with your permissions.
- A remote host sees what you type and controls what your terminal renders. Connect to hosts you trust.
- An imported backup, `ssh_config` or PuTTY export is only as trustworthy as its source. Every field is re-validated, but the hosts in it were chosen by someone else.
