# TERVIA.md

Dense map of the Tervia codebase for AI assistants and contributors: what the
project is, where everything lives, the conventions, and the patterns. This
file is also preloaded as workspace-root agent memory, so the most important
facts are front-loaded. For the design rationale see
[ARCHITECTURE.md](ARCHITECTURE.md); for build/PR rules see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Project

**Tervia**: a lightweight, cross-platform desktop client for remote machines.
SSH terminal sessions to saved hosts, `ssh -L` port forwarding, and SFTP
browsing, wrapped in a workspace shell that also does local terminals, a
CodeMirror editor, a file explorer, split panes and tabs. Forked from
[TEDI v0.4.22](https://github.com/IlhamriSKY/TEDI), itself forked from
[Crynta/Terax](https://github.com/crynta/terax-ai); both upstreams are
Apache-2.0 (see [NOTICE](NOTICE)).

|                  |                                                                                 |
| ---------------- | ------------------------------------------------------------------------------- |
| Version          | 0.1.0                                                                           |
| Repo / site      | `github.com/rendyuwu/tervia` / `https://tervia.rendy.dev`                       |
| Stack            | Tauri 2 + Rust (`portable-pty`, `russh`) <-> React 19 + TS + xterm.js (WebGL)   |
| Editor / UI      | CodeMirror 6, shadcn/ui (`radix-luma` / `mist`, lucide icons), Tailwind v4      |
| Bundle id        | `dev.rendy.tervia` (dev profile: `dev.rendy.tervia.dev`)                        |
| Crates           | `tervia` / lib `tervia_lib`; GUI binary `TerviaApp`                             |
| Keychain service | `tervia-hosts` (a host's own secrets), `tervia-vault` (shared identities, keys) |
| Package manager  | pnpm                                                                            |
| Platforms        | macOS, Linux, Windows                                                           |
| Frontend check   | `pnpm exec tsc --noEmit`, `pnpm run lint:imports`                               |
| Rust check       | `cd src-tauri && cargo check && cargo clippy`                                   |
| Behaviour checks | `pnpm run verify` (all `scripts/*-verify.ts`), `pnpm run verify ssh`            |
| Build            | `pnpm tauri build`                                                              |
| Dev              | `pnpm tauri:dev` (isolated `.dev` data dir) or `pnpm tauri dev` (see gotcha)    |
| Auto-updater     | Enabled: signed updates via GitHub Releases, 6 h poll                           |

**Persisted state** (all under the bundle id's app-data dir, via
`tauri-plugin-store`): `tervia-settings.json`, `tervia-workspaces.json`,
`tervia-hosts.json`, `tervia-vault.json`, `tervia-cli-agents.json`. The two old
`tervia-ssh-connections.json` / `tervia-rdp-connections.json` files are no
longer read; they are deliberately left on disk (there is no migration) and
`hosts/legacyPurge.ts` clears the keychain accounts they named.
Rust -> webview events are `tervia:`-prefixed;
intra-frontend store-change events are `tervia://`. Export formats:
`.tervia-backup` (fully encrypted SSH + RDP connection backup, JSON kind
`tervia-connections`, format v2) and `.tervia` (theme,
`$schema: "tervia-theme"`). The v1 `.tervia-ssh` backup (kind
`tervia-ssh-connections`, SSH only, plaintext inventory) is still read.

**Not built yet.** End-to-end encrypted sync of saved machines and keys is
planned, not present. The `.tervia-backup` passphrase-encrypted export is the
current answer to moving connections between machines, and it is a manual file,
not sync.

## Mental model

Six invariants (rationale in
[ARCHITECTURE.md](ARCHITECTURE.md#2-design-principles)):

1. **Two processes.** Frontend (`src/`, React webview) owns UI; backend
   (`src-tauri/`, Rust) owns every OS resource. The webview reaches the OS only
   via `invoke("cmd", args)`; streaming output returns over a Tauri `Channel`.
   Every command is registered in `src-tauri/src/lib.rs` (`invoke_handler`, 91
   commands) which is the whole backend API index.
2. **Three webviews.** The main window, a separate Settings window
   (`src/settings/`), and per-pane float windows (`src/float/`). They share
   state via `tauri-plugin-store` and Tauri events, not React.
   `src/settings/` is the Settings UI; `src/modules/settings/` is the state
   layer.
3. **Modules are self-contained.** Import only through the `@/*` alias, never a
   relative path across modules (enforced by `scripts/check-imports.mjs`).
4. **Tabs never unmount.** Inactive tabs are hidden in `panes/PaneStack.tsx`
   with `pointer-events-none invisible`, so PTYs and SSH sessions keep
   streaming.
5. **Secrets live only in the OS keychain / DPAPI / a 0600 file** (`secrets_*`
   commands, services `tervia-hosts` and `tervia-vault`). Never in the settings
   store, the workspace store, or `localStorage`. The stores hold metadata plus
   `has*` presence flags, so listing a hundred hosts costs no `secrets_get`.
   This makes secrets no _safer_ - on Linux a private key is in a mode-0600 JSON
   file either way, and the SSH connect path still round-trips plaintext through
   the webview on every connect and every ProxyJump hop
   ([#11](https://github.com/rendyuwu/tervia/issues/11)). What a vault binding
   buys is fewer copies of one secret.
6. **App.tsx coordinates, it does not implement.** It owns cross-module wiring;
   feature logic lives in `src/modules/<area>/` and the per-concern hooks in
   `src/app/hooks/`.

## Project structure

```
src-tauri/                      Backend (Rust)
  src/lib.rs                    invoke_handler (all 91 commands) + boot + CLI dispatch
  src/main.rs                   thin shim
  src/modules/
    ssh/{mod,session,sftp}.rs             russh sessions, ProxyJump, -L forwards, SFTP,
                                          ssh_key_inspect
    rdp/{mod,session,frame,tls}.rs        ironrdp sessions, certificate pinning, frames
    pty/{mod,session,shell_init,job,path_probe}.rs + scripts/   interactive PTYs
    pty_daemon/{mod,protocol,transport,paths,server,client,spawn}.rs   sidecar
    fs/{mod,tree,file,mutate,search,grep,atomic}.rs
    shell/{mod,session,background,ringbuffer}.rs
    git/{mod,commands}.rs       git status / branch / log backend
    backup.rs secrets.rs format.rs net.rs clipboard.rs
    cli.rs cli_paint.rs events.rs ids.rs lockext.rs appimage.rs
  tervia-cli/                   Windows console-subsystem `tervia.exe` (separate crate)
  capabilities/                 plugin API allowlist for the webviews

src/                            Frontend (React webview), alias @/* -> src/*
  main.tsx                      main-window entry -> app/App
  app/App.tsx                   top-level coordinator (~800 lines; wiring, not features)
  app/{components,hooks,lib}/   App-owned chrome, per-concern hooks, shortcut handlers
  settings/                     Settings UI (SEPARATE webview, entry settings/main.tsx)
  float/                        Floating pane window (SEPARATE webview, float.html)
  components/ui/                shadcn (generated; don't hand-edit)
  components/markdown/          markdown + code-block + mermaid renderers
  components/{BrandIcon,CliAgentIcon,LeafIcon,WindowControls,...}.tsx
  lib/                          shared helpers (cn, path, fonts, ipc, projectUrl, ...)
  styles/                       globals.css, shadcn-tailwind.css, theme tokens
  modules/                      19 modules:
    hosts/     vault/       ssh/        rdp/        terminal/
    panes/     tabs/        workspaces/ editor/     explorer/
    header/    statusbar/   rightPanel/ settings/   shortcuts/
    commandPalette/  theme/  updater/   scm/
```

## Backend (`src-tauri/src/modules/`)

| Module         | Key commands / role                                                                                                                                                                                                                                                                       |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ssh/`         | The product. `ssh_open/write/resize/close/attach/list_sessions`, `ssh_confirm_host_key`, `ssh_agent_keys`, `ssh_forward_open`, `ssh_git_status`, `ssh_git`, `ssh_sftp_*` (see below), `ssh_key_inspect`.                                                                                  |
| `rdp/`         | `rdp_open/input/close/attach/list_sessions/snapshot`, `rdp_confirm_cert`. Certificate pinning mirrors SSH's host-key flow; the password arrives as a keychain **reference**, never a value.                                                                                               |
| `pty/`         | `pty_open/attach/write/resize/close/list_sessions/kill_all`, `terminal_probe_path`. Two backends: daemon (default) falls back to in-process.                                                                                                                                              |
| `pty_daemon/`  | Sidecar owning PTYs across GUI restarts (`--pty-daemon` flag, no Tauri commands).                                                                                                                                                                                                         |
| `fs/`          | `fs_read_dir/read_file/read_file_portion/canonicalize/write_file/create_file/create_dir/rename/copy/delete/search/grep/glob/grep_replace/replace_in_file`, `list_subdirs`.                                                                                                                |
| `shell/`       | `shell_run_command`, `shell_session_*`, `shell_bg_*`. One-shot and background commands, distinct from interactive PTYs.                                                                                                                                                                   |
| `git/`         | `git_status/ignored/file_head/file_at/run/diff_full/log/commit_detail`. `git_run` is held to an allowlist of subcommands (`check_args`).                                                                                                                                                  |
| `backup.rs`    | `backup_seal_payload` / `backup_open_payload` / `backup_apply_secrets` / `backup_release`, plus `backup_open` for v1 reads: PBKDF2-HMAC-SHA256 + AES-256-GCM over the connection export. Lives host-side because `crypto.subtle` needs a secure context and the app origin is plain http. |
| `secrets.rs`   | `secrets_get/set/delete/get_all`. macOS Keychain; Windows DPAPI file (Credential Manager's 2560-byte blob cap is too small for an RSA key, with CredMan reads kept as a fallback); Linux 0600 file (no Secret Service daemon can be assumed for AppImage/deb/rpm).                        |
| `format.rs`    | `fmt_run_external` direct-spawn external formatter (15 s default timeout, 8 MiB cap).                                                                                                                                                                                                     |
| `net.rs`       | `http_ping`, `port_is_open`, `http_stream`, `http_abort`. SSRF guard blocks metadata / link-local addresses, re-applied on every redirect hop.                                                                                                                                            |
| `clipboard.rs` | `clipboard_read_text`: paste reads run host-side via arboard because WebKitGTK rejects `navigator.clipboard.readText()` under Tauri's default webview flags. Writes stay on the webview API.                                                                                              |
| `cli.rs`       | `cli_initial_target`, `cli_classify_path`, `cli_take_initial_update_request`, `cli_install_path_shim`, plus the pre-Tauri `--version` / `--help` / `--update` dispatch and the macOS `RunEvent::Opened` handler.                                                                          |
| `ids.rs`       | `BUNDLE_ID` and the no-`AppHandle` data-dir derivation used by the CLI and the daemon.                                                                                                                                                                                                    |
| `lockext.rs`   | `lock_or_recover`: poison-safe `Mutex` acquisition for detached pump threads, where a poison panic would silently kill an output stream.                                                                                                                                                  |
| `appimage.rs`  | Strips the AppImage runtime's `LD_LIBRARY_PATH` from spawned children so a system `git`/`php` links against the distro's libraries, not the bundle's.                                                                                                                                     |

`lib.rs` also registers `open_settings_window` and `open_float_window`.

Wired Tauri plugins (`lib.rs` `.plugin(...)` + `capabilities/{default,desktop}.json`):
`process`, `single-instance` (desktop, release builds only), `updater`,
`window-state`, `autostart`, `store`, `os`, `log`, `opener`, `dialog`.

### SSH (`ssh/`)

`russh` 0.60 + `russh-sftp`, all sessions driven on one shared 2-worker tokio
runtime (`ssh_runtime()`); the Tauri commands hop onto it and back.

- **Auth**: local ssh-agent (named pipe / Pageant / `SSH_AUTH_SOCK`; the private
  key never reaches Tervia, only signatures), a PEM private key with optional
  passphrase, or a password. `SshOpenInput.use_agent` takes precedence.
- **Host keys**: SHA-256 fingerprint pinning, trust-on-first-use. A new host
  raises a `HostKeyPrompt` event that pauses the handshake _before any
  credential is sent_; `ssh_confirm_host_key(prompt_id, accept)` resumes or
  aborts it. Later connects pass `expected_fingerprint` and a mismatch fails the
  handshake as a possible MITM. Re-trusting a rotated key means clearing the
  saved fingerprint (`clearFingerprint`).
- **Algorithms**: `HOST_KEY_ALGOS` is russh's default set minus bare `ssh-rsa`
  (SHA-1). KEX / ciphers / MACs stay at russh defaults. Pinning the list freezes
  the posture across russh bumps.
- **ProxyJump**: `SshOpenInput.jumps` is an ordered hop list in _connect_ order
  (publicly reachable entry host first). The chain is walked and its per-hop
  secrets read on the frontend; the backend just dials them in sequence and
  echoes each hop's `connectionId` back in `JumpConnected` so the right row gets
  its fingerprint pinned.
- **Port forwarding**: `ssh_forward_open` binds `127.0.0.1:local_port` and
  tunnels to the given remote host and port as resolved from the server, over
  the live session (so a jump chain applies for free). A `local_port` of 0
  picks a free port and returns it.
  There is deliberately **no close command**: forwards are declared on the saved
  connection and re-opened per connect, so session teardown is their whole
  lifecycle.
- **Mirroring**: `ssh_attach` adds a second event sink to a live session and
  replays its ring; `ssh_list_sessions` enumerates them. Neither has a frontend
  caller today.
- **Remote git**: `ssh_git_status` / `ssh_git` run git over an exec channel,
  reusing the local porcelain parsers. Every remote-supplied value is
  `shell_quote`d (OSC 7 cwd is attacker-controlled if the host is compromised),
  and `last_line()` discards `~/.bashrc` chatter that sshd's login shell
  prepends to every capture.
- **SFTP** (`sftp.rs`): `ssh_sftp_*` (`home`, `read_dir`, `read_file`,
  `write_file`, `upload`, `create_file`, `create_dir`, `rename`, `delete`),
  opened as a fresh subsystem channel on the existing russh `Handle`.
  `SftpEntry` mirrors the local `fs::DirEntry` shape so
  the explorer renders remote and local trees with one component. Everything is
  bounded by the remote user's unix permissions; a denial surfaces in-tree.

### PTY shell integration

Init scripts in `pty/scripts/` bootstrap shells to emit **OSC 7** (cwd) and
**OSC 133 A/B/C/D** (prompt/command/output/exit boundaries), parsed in
`terminal/lib/osc-handlers.ts` (no prompt re-parsing). Two Tervia-private codes
ride along: **OSC 8888** opens a file in an editor tab (the `tervia_open` shell
function, alias `tp`) and **OSC 8889** spawns a tab; **OSC 9** carries progress.
Every spawned shell gets `TERVIA_TERMINAL=1`.

Unix: zsh (`ZDOTDIR`, with the user's own preserved as `TERVIA_USER_ZDOTDIR`),
bash (`--rcfile`), fish (`--init-command`). Windows: pwsh 7+, falling back to
powershell 5.1, then `cmd.exe` with no integration. Generated rc files live
under `~/.cache/tervia/shell-integration/` and are rewritten atomically only
when their content changes. `pty/shell_init.rs` is split into `#[cfg(unix)]` /
`#[cfg(windows)]` arms; keep new platform code in the right arm.

### PTY daemon (persistence)

PTYs survive a window close; a PC restart or daemon crash clears sessions and
the GUI respawns fresh (out of scope by design). Protocol: length-prefixed
JSON, version-gated via `Hello` (`PROTOCOL_VERSION = 1`); push events
(`Data`/`Exit`) carry no `req_id`. Socket: Unix
`$XDG_RUNTIME_DIR/tervia-ptyd.sock` (falling back to
`$TMPDIR/tervia-ptyd-<USER>.sock`), Windows
`tervia-ptyd-<fnv1a(USERNAME)>` named pipe. Scrollback: per-session ring capped
at 1 MiB (trimmed lazily with 256 KiB of slack so a log flood is not one
memmove per write), replayed as a single `AttachOk { scrollback_b64 }`.

Restore: each terminal leaf carries `ptyId?`, persisted by
`workspaces/serialize.ts`; `attachSession` calls `reattachPty` and falls back to
`openPty` at the saved cwd on an unknown uuid. A blank-reattach repaint watchdog
(`pty-lifecycle.ts`) nudges a resize if an alive reattach nets to a blank
viewport. Idle 24 h self-shutdown (`TERVIA_PTYD_IDLE_SECS` overrides). Logs at
`<data_dir>/<BUNDLE_ID>/logs/tervia-ptyd.log` (`TERVIA_PTYD_LOG=debug`).

### Windows PTY gotchas

- **`SPAWN_LOCK`** (`pty/session.rs`): a `Mutex` gating ConPTY lifecycle. Held
  by `spawn()` across `openpty + spawn_command` and by `drop_session()` across
  the `Arc<Session>` drop, so `ClosePseudoConsole` cannot race a sibling's
  openpty (which corrupts the fresh console and leaves the pane blank). It gates
  lifecycle, not IO. Do not remove without testing fast tab spam and workspace
  restore with 3+ panes.
- **Job Objects** (`pty/job.rs`): each ConPTY child joins a per-session Job with
  `KILL_ON_JOB_CLOSE`, so the kernel kills the whole subtree (e.g. `npm run dev`
  inside pwsh) when the Job handle drops. `portable-pty::killer.kill()` only
  kills the immediate child.
- **Cwd normalization** (`pty/shell_init.rs`): the frontend's canonical path is
  forward-slash, so `apply_common` rewrites the cwd to backslashes under
  `#[cfg(windows)]` before handing it to ConPTY. User-configured extra PATH
  entries get the same treatment in `assemble_path`.

macOS/Linux rely on `Drop for Session -> killer.kill()`.

## Frontend (`src/modules/`, 19 modules)

| Module            | Role                                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `hosts/`          | The saved-machine store (`tervia-hosts.json`): one `Host` union for SSH and RDP, groups, jump-chain resolution, the one-shot legacy secret purge. Every integrity rule lives here, not in a dialog (below).  |
| `vault/`          | Shared credentials nothing owns: `VaultIdentity` / `VaultKey` in `tervia-vault.json`, and `resolve.ts`, the one place a credential binding becomes something the connect path can use (below).               |
| `ssh/`            | Connection manager, host-key dialog, SFTP explorer, encrypted backup, route pill (below).                                                                                                                    |
| `rdp/`            | RDP pane and menu, the frame decoder, scancode mapping, and `dial.ts` (a tunnelled dial target with an idempotent `release()`).                                                                              |
| `terminal/`       | One mounted xterm per leaf via `useTerminalSession`; pty-bridge and ssh-session backends behind one Session; OSC handlers; AI CLI detection; write metering; WebGL.                                          |
| `panes/`          | Split-pane orchestration via `react-resizable-panels` (`PaneStack`, `PaneTreeView`) plus the float-window host and its event protocol.                                                                       |
| `tabs/`           | Source of truth: `useTabs` (tab list + active id), `useWorkspaceCwd`, the `+` menu and the Agent spawn dialog.                                                                                               |
| `workspaces/`     | Workspace persistence + switching (`store.ts`, `serialize.ts`) and the Workspaces panel / board.                                                                                                             |
| `editor/`         | CodeMirror 6 (`EditorPane`), language modes, format-on-save, vim mode, minimap, prebuilt themes. Reads/writes remote files over SFTP when the leaf is SSH-bound.                                             |
| `explorer/`       | File tree (Catppuccin icons), fuzzy search, project-wide grep + replace, keyboard nav, inline rename, git decorations.                                                                                       |
| `header/`         | Top bar, inline search (`SearchInline` adapts terminal vs editor), the SSH and RDP menus, custom `WindowControls` (Linux/Windows).                                                                           |
| `statusbar/`      | Bottom bar, cwd breadcrumb (SFTP-aware on an SSH pane), zoom, updater pill, `SshRoutePill`.                                                                                                                  |
| `rightPanel/`     | Which sidebar sections are docked to the right column (`files`, `workspaces`) and their persisted placement.                                                                                                 |
| `shortcuts/`      | Keymap catalog + `useGlobalShortcuts`; handlers wired in `app/lib/shortcutHandlers.ts` by id. Use `metaKey \|\| ctrlKey`.                                                                                    |
| `commandPalette/` | Ctrl+Shift+P palette over the shared `commandRegistry`, which every `useGlobalShortcuts` caller populates so component-owned commands run too.                                                               |
| `settings/`       | Settings store (`store.ts` via `tauri-plugin-store`), preferences, theme presets, terminal palette, window opener.                                                                                           |
| `theme/`          | `ThemeProvider`: applies theme / brand colour / opacity / fonts and keeps them in sync with the settings store across windows.                                                                               |
| `updater/`        | In-app updater UI on `tauri-plugin-updater`; 6 h poll, listens for `tervia:trigger-update`.                                                                                                                  |
| `scm/`            | Library only, no UI: `api.ts` wraps the `git_*` and `ssh_git*` commands, `branch.ts` the branch name, `types.ts` the payloads. Consumed by the explorer's git decorations and the Workspaces branch display. |

### Saved machines (`src/modules/hosts/`)

- `store.ts` owns the saved-machine list (`tervia-hosts.json`, keys `hosts` /
  `groups` / `legacySecretsPurged`). One record per machine, discriminated on
  `protocol`, so grouping and vault binding are built once instead of twice. It
  holds metadata and `has*` flags only; a host's own secrets go to the keychain
  under service `tervia-hosts`, account `<id>::<field>`. `agent` mode stores
  nothing at all. Every mutation goes through one serialized `enqueueWrite`
  chain, because a chained connect fires `markConnected` once per hop
  near-simultaneously and a lost write would revert a host to a TOFU prompt.
- **Every integrity rule lives in this layer, never in a dialog**, because a
  dialog is never the only writer - an import, a duplicate, a palette entry and
  the next window would each have to remember it. Three cost something specific
  when forgotten: `assertBindingOwner` on every upsert (a spread-copied host
  authenticates with the SOURCE's secrets, silently); a jump or tunnel target
  must be an SSH host and the whole chain must not loop (checked at the write
  _and_ at the connect, because neither covers a row an import put there); and no
  account outlives the record naming it, which is why `upsertHost` releases what
  the new record can no longer name **after** the record is on disk, and
  `deleteHost` clears the host's accounts plus every row that pointed at it.
- `types.ts` is the `Host` union (`SshHost | RdpHost`) plus the per-protocol
  keychain field lists, so a caller that has to enumerate a host's accounts
  cannot miss one. There is no `forwards` field: a forward rule is its own record.
- `jumps.ts`: `jumpChain` is the pure walk (shared with the write guard),
  `resolveJumpHops` puts a credential on each hop and reverses into the backend's
  connect order. Cycle detection is seeded by the target's own id, and
  `MAX_JUMP_HOPS` is 16 - `backupFile.ts` duplicates that number and the two have
  to agree, because an over-long chain is refused by the store, not truncated.
- `duplicateHost` copies the source's secrets for **both** protocols and
  deliberately **not** the pinned server key (a copy exists to be pointed
  elsewhere, and carrying the key over reads as a MITM on the next connect, so
  `pins` and the flat fingerprint field both go). The secrets never pass through
  JS: `copyHostSecrets` calls `secrets_copy`, which reads and writes in-process,
  which is what lets an RDP password travel at all - the copy's `has*` flags
  describe what that command actually found, because this layer never reads a
  secret back to correct them. A vault-bound source owns no accounts, so its
  binding is **shared** rather than duplicated. It rewrites the binding's
  `hostId` and runs read-and-write inside one queue entry.
- `legacyPurge.ts` clears the accounts the two OLD connection stores left on
  `tervia-ssh` and `tervia-rdp`, once, and is the only thing that can: there is no
  `secrets_list`, so an account nothing references is unreachable rather than
  untidy. It therefore imports nothing from `ssh/` or `rdp/` and reads the old
  store files directly, so it still works after those modules are gone.
- `useHosts()` / `useHostGroups()` are the subscribed reads, one per collection
  rather than per surface: the store broadcasts on every commit, so a rename in
  the Settings webview reaches the tab strip without either side knowing about the
  other. `adapters.ts` is the injected IO port that lets the store layer run under
  plain node in `scripts/hosts-store-verify.ts`.
- Both stores sit behind `createRecoveredStore` (`src/lib/recoveredStore.ts`):
  `tauri-plugin-store` saves with a plain `fs::write`, so a power cut can leave a
  zero-byte or nul-filled file. It recovers from a `.bak`, then snapshots on every
  commit, and hands back one notice for the UI to show once.

### The vault (`src/modules/vault/`)

- `store.ts` owns `tervia-vault.json`: a `VaultIdentity` is "who I log in as", a
  `VaultKey` is a private key stored once and shared by every identity using it.
  Secrets go to service `tervia-vault`. A delete is **refused** while something
  still references the record (`VaultInUseError` names the holders) rather than
  cascading, and `identityHostRefs` is the host store's answer to "who uses this".
- `resolve.ts` is the **one** place a binding becomes something the connect path
  can use, and the two protocols get deliberately different shapes.
  `resolveRdpAuth` returns a keychain **reference** (`{service, account}`), which
  is what keeps an RDP password out of the webview by construction;
  `resolveSshAuth` returns values, because `openSsh` takes values -
  [#11](https://github.com/rendyuwu/tervia/issues/11), pre-existing and not fixed
  here. `sshCredentialValues(authMode, secrets)` is the mode-to-wire mapping
  inside it: the same switch used to be spelled out at four call sites and a
  missed one connected with no credentials at all. Empty values become `undefined`
  so the backend's "no credentials" guard fires instead of an empty password.
- `types.ts` holds the binding union both stores use, and `assertBindingOwner`.
  An inline binding carries its own `hostId`, which removes the resolve-time
  mismatch and moves it to write time - which is why the host store must call that
  assertion on every upsert.
- Key metadata comes from `ssh_key_inspect(pem, passphrase?)`, wrapped in
  `ssh/bridge.ts`: type, comment, fingerprint and public half, all readable from
  an **encrypted** OpenSSH key because that container keeps the public part in the
  clear. It reports `parsed: false` rather than an error when only the passphrase
  is missing, so a key editor can prompt instead of showing a failure.

### SSH (`src/modules/ssh/`)

- `tunnel.ts` opens headless forwards for callers that want a TCP tunnel rather
  than a terminal. It refuses a connection with no pinned server key, because a
  first connect needs a human and nothing here can show the dialog.
- `backup.ts` / `backupFile.ts` export and import `.tervia-backup` (format v2):
  one sealed blob over the whole inventory and every credential, so the file leaks
  no hostnames. Credentials never enter the webview on this path — the export
  sends keychain references to `backup_seal_payload`, and the import gets
  metadata back from `backup_open_payload` while `backup_apply_secrets` writes
  the secrets from Rust. v1 `.tervia-ssh` files still import, and that path is
  the one exception: their sealed block is the credential map itself.
  `SshBackupDialog` and `SshMenu` are the UI for both protocols; `RdpMenu`
  deliberately has no second copy.
- An import is a **trust boundary**, and `backupFile.ts` is where every field is
  re-checked. Two of its passes exist because the alternative is destructive
  rather than merely wrong: the store releases every account a new record can no
  longer NAME, so a row that arrives bound to a vault identity (owning none) or
  on the other protocol (owning fewer) would delete the saved host's secrets with
  nothing copied first. A vault binding is never applied - the row keeps whatever
  this machine already had, or lands as a blank inline host - and a protocol flip
  is refused. Records are written **before** the credentials so every account
  belongs to a host that is already in the store, and one refused row is counted
  in `ImportResult` rather than abandoning the rest of the file.
- `status.ts` models the per-leaf handshake state including per-hop progress;
  `SshRoutePill` renders the chain in the status bar. `hostKeyPrompt.ts` queues
  first-connect confirmations and pins the fingerprint at the moment of trust.
- `SshFileExplorer` + `useSshFileTree` / `useSshNav` / `useSshFileDrop` are the
  remote tree, reusing `explorer`'s `FileTreeNode`.

Terminal-side connect logic lives in `terminal/lib/ssh-session.ts`: banner,
per-hop status, reconnect with a 1s/3s/7s backoff, a DECRST mode reset so a
dropped `vim`/`htop` cannot leak mouse-tracking escapes into the new shell, and
the `-L` auto-forward that rewrites a remote `http://localhost:PORT`
announcement to the local end of the tunnel (`terminal/lib/forwardUrl.ts`).

### Tabs, panes and leaves

`tabs/lib/tabTypes.ts`: `Tab = PaneTab`. The alias survives because the app
talks about `Tab` everywhere and the layer used to carry other kinds. A
`PaneTab` (`kind: "pane"`) holds a split tree whose leaves
(`terminal/lib/panes.ts`) are one of three `leafKind`s:

- `terminal` - local PTY, or a remote shell when `sshConnectionId` is set (`cwd`
  is then ignored). Carries `ptyId`/`savedPtyId` for daemon reattach,
  `terminalOrdinal` for the tab chip, `terminalThemeId` for a per-pane palette,
  and `activeTool` for the AI CLI badge.
- `editor` - a file, local or remote. `sshConnectionId` is the _stable_ half of
  a remote editor's identity and is persisted; `sshSessionId` is the live russh
  session and is not.
- `board` - the kanban of the workspace's terminals grouped by what their AI CLI
  is doing. Stateless: rebuilt from the live tab tree every render.
- `rdp` - one RDP session on a canvas. Holds a reference to a saved host, never a
  copy of its fields, so it carries no secret and no host-shaped state.
- `page` - the Hosts page, and only Hosts (`page: TabPageKind`). Stateless like
  `board`. See "Pages: tabs vs rail views" below.

`customTitle` is declared on every leaf kind so the tab strip's Rename works
anywhere. Any leaf can be popped into a floating OS window (`panes/floatHost.ts`
-> `open_float_window` -> `float.html`), which mirrors over Tauri events rather
than sharing React state.

#### What may be closed (`tabs/lib/closable.ts`)

Two invariants, one predicate, and every close path asks it. They are separate
reasons that share a gate:

1. **A page leaf is permanent.** Hosts is the workspace's entry point and holds
   no session that closing would end, so it is refused regardless of what else is
   open - not merely when it happens to be the last thing left.
2. **The last entry is permanent.** Closing the only thing on screen would leave
   an empty window.

`leafCloseRefusal` / `tabCloseRefusal` are the whole rule. Three paths consult
them - the tab-strip X (`TabBar` builds its closable set from the predicate), the
pane-header X (`PaneStack` passes it into `PaneTreeView`), and `Ctrl+Shift+X` /
`Ctrl+W` (both funnel through `useTabActions`' `requestCloseLeaf` / `handleClose`)

- and `useTabs`' `closePaneByLeaf` / `closeTab` re-check at the mutation, so a
  caller that never asked cannot route around it. A refusal is **not rendered**
  rather than rendered dead: neither X appears on a leaf the rule refuses, which is
  what lets the chord no-op silently without telling the user two different things.
  There is deliberately no confirmation dialog for either case.

The predicate names exactly one leaf kind, `page`. Every other kind - terminal,
editor, board, **rdp** - is answered by the last-entry rule alone, which is what
"one predicate" means. `Ctrl+Shift+X` used to carry its own
`activeLeafKind === "terminal"` test in front of it and so silently dropped the
chord on an RDP pane both X buttons closed happily; that test is gone, the chord
asks only `requestCloseLeaf`, and the catalogue entry says **"Close focused
pane"** in the **Panes** group (the id stays `terminal.close`, because a user's
rebinding is stored under it). With no kind test the chord can now reach the
Hosts page leaf, where it is refused as permanent - and both X buttons are absent
there, so its silence still never contradicts a visible affordance.

The one thing a close chord refuses that the X buttons do not: **while a rail
view covers the tab area, `Ctrl+W` and `Ctrl+Shift+X` do nothing.** The X names
the tab it closes and is on screen; a chord names "the active tab", which is
exactly what the view has taken off screen, and a close cannot show its own
result the way a new tab or a split can. That refusal lives on the chord
(`app/lib/shortcutHandlers.ts`), deliberately NOT at the mutation, because
`closeTab` / `closePaneByLeaf` are shared with the strip X, which must keep
leaving the user in the view.

**And the second question, in the same module: may a legal close happen
_silently_?** `leafCloseConfirmReason` / `tabCloseConfirmReason` answer
`"unsaved"` (an editor leaf with unsaved edits), `"running"` (a terminal leaf
with a foreground command) or `null`, and unsaved wins when a tab is both -
discarding an edit cannot be undone, killing a process can be redone. Both are
asked **after** the refusal, never before: prompting for a close that is then
refused is worse than the silent no-op it replaces.

They live beside the refusals because the confirmation was left in exactly the
state the refusal was in - one copy per path, disagreeing.
`handleClose` asked about unsaved work and a running process; `requestCloseLeaf`
asked only about the process, in so many words ("Editor leaves always close
without a prompt"). So a single-pane tab holding a **dirty editor** prompted from
the pane-header X and `Ctrl+W`, and was discarded without a word by
`Ctrl+Shift+X`, by the tab-strip leaf X and by that same header X on a split.
Removing the chord's leaf-kind test is only what made it reportable - it let the
chord reach an editor for the first time - and the fix is at the funnel for that
reason: guarding the chord would have left the other two paths losing buffers.
The tab-level answer also stopped being read off `tab.dirty`, which
`syncPaneMirror` mirrors from the **active** leaf alone, so a split whose unsaved
editor was not the pane you were looking at closed in silence.

Checked by `scripts/tab-close-verify.ts`, whose third assertion - an ordinary leaf
beside another entry IS closable - is what stops a predicate hardwired to `false`
from passing, plus an RDP section, a source-text check that no path re-decides in
front of the arbiter, and the confirmation half - behavioural, including the
negative ("a **saved** editor still closes silently", which is what stops "confirm
everything" passing) and the source-text check that both close paths route
through it. The `editorLeaf` fixture takes `dirty` as a parameter; hardcoding it
`false` is how the whole suite ran past the one input this rule turns on.

#### Pages: tabs vs rail views (`tabs/lib/pages.ts`)

The rail has three pages, and the tab strip is for connections, so only **Hosts**
is a tab - leftmost. Vault and Port Forwarding are **views** shown over the tab
area (`app/components/RailViewArea.tsx`): the strip stays visible above them, and
clicking any tab or the lit rail button again comes back. Rail-view activation is
deliberately not persisted; a relaunch comes up on the tabs.

Which view is up lives in **`useTabs`, in the same state object as `activeId`**
(`tabs/lib/tabView.ts`), not beside it and not in App. The pair carries an
invariant that two `useState`s cannot express - _a tab cannot become active while
a view is still covering it_ - and as App state it was every caller's job to
clear: nine of the eleven routes into the tab area did not, so Ctrl+T, Ctrl+Tab,
Ctrl+1..9, header quick-connect, a file click, a workspace switch and an OSC-8889
open all activated a tab behind the view and looked like they had done nothing.
So there is one write instead: `focusTabView` is the only way `activeId` moves,
and it leaves the view unconditionally - including when the id does not change,
because Ctrl+1 on the tab the Vault is covering is exactly that case. The two
close paths use `rehomeTabView` instead, which deliberately keeps the view:
closing a tab in the strip is not a request to leave the Vault. `setActiveId` is
typed `(id: number)`, so the functional updater a removal used to write - which
read identically to a focus - is a type error.

The bad state is unrepresentable rather than checked for. `PageKind` still names
all three (the rail, `PAGE_LABELS` and `PAGE_ICONS` are indexed by it), but
`PageLeafState.page` is `TabPageKind` (`= "hosts"`, declared beside the leaf in
`terminal/lib/panes.ts`, re-exported from `tabs/lib/pages.ts`), so a Vault or
Port-Forwarding **leaf** is a compile error. The two page-leaf constructors -
`useAuxTabs.openPageTab` and the restore path in `workspaces/serialize.ts` - take
that type too.

`SavedPageLeaf.page` stays wide, because old snapshots must still be readable.
Restore therefore **migrates**: a saved page leaf that is not the tab page is
dropped, its tab goes with it if that empties it, and a workspace emptied that way
falls back to Hosts (`restoreSavedTabs`). The predicate is
`isUnrestorablePageLeaf`, and it asks `!isTabPageKind` rather than naming the two
rail views - so a page value **this build does not recognise** (a newer build's
page, a hand-edited file) is dropped too. Rewriting it into Hosts, which the
enumerating version fell through to, minted a _second_ Hosts tab, and a page leaf
is permanent, so neither could then be closed.

Dropping a leaf or a tab shifts every later one, so restore **re-bases** both
saved focus indices onto the survivors rather than clamping the raw index:
`restoredActiveTabIndex` for tabs, `restoredActiveLeafIndex` for the active pane
inside one - the mirror of `tabToSaved`'s `kept.findIndex` on the way out. A clamp
lands on the wrong entry whenever a drop sat _before_ the saved index, which is
not a rounding error: `[Hosts, Vault, termA, termB]` saved on termA came back on
termB. Getting the helper right was not enough - two of the three cold-restore
callers never called it - so **`restoreWorkspaceEntry` returns the tabs and the
id to focus from one call**, and the workspace switch, the workspace close and the
startup hydrate all take it.

**The funnel was scoped to the wrong enumeration once already.** "Every route
that ACTIVATES A TAB" cannot cover a mutation that rearranges the tab already
active, so `Ctrl+D`, the header's Rotate split and its drag-reorder all reshaped
panes behind the view - `Ctrl+D` being the worst, since it mints a shell with no
visible effect at all. The rule is now enumerated from the **state write**: every
`useTabs` / `useAuxTabs` callback whose body reshapes a pane tree or moves the
focused leaf shows the tabs. One is deliberately exempt and says so -
`setSplitSizes`, which persists the ratio a divider drag just produced: it changes
no membership and no focus, so there is nothing for showing the tabs to reveal,
and it is _echoed_ (`onLayoutChanged` fires on any relayout the panel library
performs), so clearing the view from it would let a stray echo close the Vault.
The exemption deliberately does **not** rest on the divider being unreachable
under a view; `movePaneLeafToEdge` gave that argument up, because an
unreachability claim is only as good as the enumeration of affordances behind it.

**And "what counts as a pane-tree write" is derived, not transcribed.** It was
seven function names hardcoded into a regex, out of the twenty-one `useTabs`
imports from `panes.ts` - so `buildPaneTree` and `cloneLeafState` were in the
file, in use, and invisible to it. Every name a swept file imports from `panes.ts`
must now appear in exactly one of three classified lists (reshapes a tree / writes
a leaf field / reads only), so the next import fails the check by name. The leaf-
field writers are exempt as a class and for a reason: an OSC 7 cwd, a PTY id or an
editor going dirty changes what a pane _says_, not which panes exist or which is
focused, and they are driven by the session rather than by the user - a background
terminal printing a prompt must not pull anyone out of the Vault.

`useTabs` also stopped being the only place the rule lives: the two **closing**
chords refuse instead of clearing, on the chord itself. See "What may be closed"
above for why the strip X must keep the opposite behaviour.

Checked by `scripts/rail-views-verify.ts`, which asserts the narrowing (and
`setActiveId`'s signature) at compile time, the migration and the two re-basings
at runtime **through their consumers**, and - source-text, because the state lives
in a hook this suite cannot render - that every `activeId` write and every
pane-tree write in `useTabs` **and `useAuxTabs`** goes through the funnel or is
named as an exemption, that nothing else writes the view, and that the two closing
chords carry the refusal while the constructive ones do not. The scan reads any
top-level `const` / `function`, not only `const x = useCallback(`, because that
shape is a convention rather than a rule; and every key `useTabs` returns must be
a declaration one of the two swept files owns, which is the check that would have
caught `useAuxTabs`' three openers arriving by destructuring and being swept by
nothing.

#### Who owns the keyboard (`shortcuts/lib/keyboardOwner.ts`)

A focused terminal owns every bare-Ctrl control code and every bare-Alt meta
sequence, and a focused RDP pane owns the same; App's `isDisabled` gate lets them
fall through instead of firing an app chord. That is a claim about **focus**, and
it was answered with `activeLeafKind(activeTab)`, which is a claim about which
leaf is active **in the tab** - so the gate was wrong in both directions. With
the caret in the tab strip the terminal was still "active", so `Ctrl+W` closed no
tab anywhere; with a rail view up the terminal was invisible and still "active",
so `Ctrl+T` / `Ctrl+]` / `Ctrl+[` were swallowed by a surface nobody could see.

So the gate asks the DOM: `ownsRawKeyboard(focusTargetOf(e))` walks up from the
keydown's own target to `[data-terminal-leaf-id]` or `[data-rdp-leaf-id]` -
markers both panes already render for the file-drop hit-test and for focus. It
also requires `railView === null`, because a covered surface does not own the
keyboard by definition and that should not depend on whether the browser blurs a
`visibility: hidden` subtree. `pane.splitRight` keeps its documented exemption
(Ctrl+D always fires, taking `^D` from the shell).

The deciding half is a pure predicate over anything with `closest`, so
`scripts/keybindings-terminal-verify.ts` runs it without a DOM - both directions,
plus a read-back of `TerminalPane` / `RdpPane` proving every marker the selector
names is actually rendered. A selector that matches nothing would turn the gate
permanently off, silently.

#### The modal gate, and its one exemption (`shortcuts/lib/modalRegistry.ts`)

No catalogued chord fires while a `Dialog`/`AlertDialog` is open: a background
action must not run out from under a modal the user is mid-edit in. Registration
is at the two shared primitives, so every dialog built on them is covered.

The registry is a **stack**, not a count. A count already handled the easy half
(a confirm closing over a form must not un-suppress the form), but it could not
answer _which_ modal is on top - and that is the question the single exemption
needs. `commandPalette.open` was exempt by the chord's identity, which is true of
the palette closing itself and false of it **opening over the host editor**. The
exemption now names the modal the chord may act on, and applies only while that
modal is topmost: the palette registers as `COMMAND_PALETTE_MODAL` (threaded
through `Dialog`'s `modalName`), so its chord closes it, is suppressed over any
other dialog, and is suppressed again the moment a confirm stacks on top of it.
Checked by `scripts/modal-shortcut-verify.ts`, behaviourally for the stack and by
source text for the wiring.

### AI CLI support (terminal-side only)

Tervia ships no AI of its own, but it knows about third-party agent CLIs running
inside a terminal. `terminal/lib/aiCliDetector.ts` classifies the running tool
(`AiCliKind`: claude, codex, opencode, copilot, pi, aider, gemini, grok,
amazon-q, cody, goose, cursor, ollama) and tracks a four-state badge:
`idle`, `working`, `blocking`, `done`. `done` is held as a breathing badge
until the user focuses or types in that terminal, so a finished turn stays
visible across many panes.

`cliAgents.ts` owns the pickable agent list (`tervia-cli-agents.json`; built-in
commands are overridable and custom entries allowed). The tab strip's
`+ -> Agent...` picker spawns up to `MAX_AGENT_SPAWN = 6` panes in one go, and
Settings -> General -> "Terminal AI agents" edits the list. `agentTodos.ts`
reads Claude Code's own session log to decorate the board; it is best-effort
and silent on failure because those are undocumented internals.

## Formatters (format on save)

Two pipelines under one prefs schema (`editor/lib/formatters/`). `builtin`
(`prettier.ts`): lazy-imports Prettier 3 standalone plus only the plugins a
parser needs; project config layers bundled defaults, then `.editorconfig`, then
`.prettierrc` / `.prettierrc.json` / `.prettierrc.json5` /
`package.json#prettier` walked up from the file. `external` (`external.ts` ->
`fmt_run_external`): direct spawn, `${file}` temp-file mode or stdin mode,
`cwd = dir(file)`, presets for 30+ tools in `presets.ts`. Resolution:
`languageFromPath` -> the language's configured formatter -> the shipped default
for that language (Prettier for the web languages, the external preset for the
rest) -> dispatch. Failures toast and fall through to a plain save; formatting
never blocks persistence. Not supported in builtin mode:
`.prettierrc.{js,cjs,mjs,yaml,yml}` (use `external` with `prettier
--stdin-filepath ${file}`).

## Conventions and patterns

- **Icons**: `lucide-react`, imported by name rather than resolved at runtime.
  Brand marks: `components/BrandIcon.tsx`; agent marks:
  `components/CliAgentIcon.tsx`; file/folder glyphs: the Catppuccin set,
  dynamically imported by `explorer/lib/iconResolver.ts`.
- **Styling**: Tailwind v4 (`@theme` blocks in `src/styles/globals.css` and
  `shadcn-tailwind.css`, no `tailwind.config.*`); `cn()` from `@/lib/utils`.
  shadcn/ui components are generated, not hand-edited.
- **Imports**: always `@/...`, never relative across modules.
- **Paths**: split with `pathSegments` / `basename` from `@/lib/path`, which
  handle both separators; the canonical frontend form is forward-slash. OSC 7
  arrives forward-slash after `parseOsc7` strips the `/C:` drive prefix.
- **Terminal input**: send `\r` (CR) for Enter, not `\n` (PowerShell needs CR).
- **Cross-platform**: HOME/cache/data via the `dirs` crate, never raw env vars.
- **Window styling**: macOS native traffic lights via Overlay title bar; Linux +
  Windows are borderless with React `WindowControls`. Windows adds
  `apply_windows_frame_fixes` (main window only) for maximize-clamp and
  minimize, `disable_windows_corner_rounding` for square DWM corners, and
  `disable_browser_accelerator_keys` so WebView2 does not eat Ctrl+W / Ctrl+R.
  macOS rebuilds the app menu without "Close Window" so Cmd+W closes a tab.
- **Docs and prose**: avoid em-dashes; use commas, colons, or parentheses.
- **Comments cite only what a clone can reach.** The whole test is whether a
  reader holding nothing but the clone can open the thing you named. A comment
  may reference a file `git ls-files` returns, a symbol, or a path inside the
  repo. It may also reference something outside the tree that the clone still
  gets you to: an **upstream** project's public tracker (`xterm.js #4054`,
  `IronRDP issue #1251`) or a **pinned** dependency's own source, both of which
  a reader reaches through the lockfile. Name that project when you cite it - a
  bare `#1251` fails the test even though `IronRDP issue #1251` passes. It may
  not reference this project's own planning or handoff documents, a row id from
  one of them, a bare `issues/nn` path (this repository's tracker is not in the
  tree, so that reads as a directory and there is no such directory), a section
  number of a document that is not checked in, a `/tmp` path, a date, or a
  commit hash: to anyone cloning the repository those name something that does
  not exist, which is worse than no citation because it looks checkable. State
  the fact in the comment; provenance belongs in the commit message, which is
  in git and reachable with `git log -S` or `--grep`. The tell when writing
  one is a backtick around a filename `git ls-files` would not return.
- **An accepted state lives in [KNOWN-LIMITS.md](KNOWN-LIMITS.md), not in a
  planning document.** Behaviour that was weighed and kept on purpose, and a
  deferral whose trigger has not fired yet, both belong somewhere a reader
  holding only the clone can reach - which is the same test as the bullet
  above, applied to the thing the citation rule stops you from pointing at. An
  entry is three parts and no more: what is accepted, which file and symbol
  carries it, and the named condition that would change the answer ("a
  component test runner existing in this repository", not "later"). A comment
  may cite that file BY NAME, and the symbol an entry names should point back
  at it, so whoever edits that symbol next finds out there is an entry to
  retire.

## Development workflow

- **Checks before commit**: `pnpm exec tsc --noEmit`, `pnpm run lint:imports`,
  and in `src-tauri` `cargo check && cargo clippy` (clippy is `-D warnings` in
  CI). Rust tests: `cargo test`. CI runs those plus `pnpm build` and a bundle
  matrix; it does **not** run `pnpm run verify` or `cargo fmt --check`, so run
  those locally (`pnpm run fmt:rust`, `pnpm run lint:rust`).
- **`scripts/*-verify.ts`** are standalone `tsx` behaviour checks (the host store
  and its guards, credential resolution, the legacy purge, SSH routing, backup
  round-trip, forward URLs, host keys, workspace serialization, terminal resize,
  theming, ...). `pnpm run verify <substring>` runs a subset; the whole suite is
  ~15 s and `verify-all.mjs` globs the directory, so a new `*-verify.ts` is picked
  up with no registration. Modules meant to be exercised here stay free of
  xterm/Tauri imports at module scope so plain node can load them; a store layer
  does it by taking its IO as an injected port instead.
- **Dev profiles**: `pnpm tauri:dev` uses `tauri.dev.conf.json` (identifier
  `dev.rendy.tervia.dev`), so workspaces, stores, the PTY socket and logs all
  land in the `.dev` data dir and cannot stomp an installed release. Prefer it.
  With plain `pnpm tauri dev` the two halves disagree: `ids::BUNDLE_ID` is
  `.dev`-suffixed in _any_ debug build (so the daemon logs and the Rust-side
  settings read for the terminal's extra PATH go to the `.dev` dir) while
  `tauri-plugin-store` follows the config identifier and writes to the release
  dir. The daemon also outlives the dev GUI; set `TERVIA_PTYD_IDLE_SECS=60` when
  iterating on daemon code.
- **`tervia` CLI** (`cli.rs`): `tervia .` / `tervia <path>` opens a folder or
  file in the running window (single-instance forward, `tervia:open-cli-target`
  event). `--version` / `--help` print and exit before Tauri boots; `--update`
  is captured at startup, the GUI boots, and the frontend drains it via
  `cli_take_initial_update_request` to run the in-app updater. On Windows the
  user-facing `tervia.exe` is the console-subsystem launcher in `tervia-cli/`
  (the GUI binary is `TerviaApp.exe`, so PATHEXT resolves the shim first), and
  the GUI binary calls `AttachConsole` when it is reached directly. A PATH shim
  (`~/.local/bin/tervia`, marked `# tervia-cli-shim v1`) is installed from
  Settings and self-heals on launch; on AppImage it points at `$APPIMAGE`, not
  the temp mount.
- **Release**: tag push triggers `.github/workflows/release.yml`, which builds
  signed updates (`TAURI_SIGNING_PRIVATE_KEY*` secrets) and a draft GitHub
  Release. Updater endpoint is that repo's `latest.json`.

## Gotchas worth knowing

- `tauri.conf.json` sets `"removeUnusedCommands": true`. A command with no
  frontend `invoke` call site can be stripped from a release build. Today
  `http_stream`, `http_abort`, `shell_bg_spawn_direct`, `ssh_list_sessions` and
  `ssh_attach` have no caller in `src/`. `secrets_get_all` does now, through
  `vault/adapters.ts`: it is the one-round-trip batch read a host's three SSH
  accounts go through. Note it is `(service, accounts[])`, one service per call,
  so a batch spanning host-owned and vault-owned secrets is two calls.
- The plugin store writes non-atomically, so `shell_init.rs` retries its
  `tervia-settings.json` read a couple of times before giving up; a spawn can
  otherwise land between the truncate and the rewrite.
- `git_run` and `ssh_git` share `check_args`, an allowlist of subcommands plus a
  NUL-byte guard. Remote arguments are additionally single-quoted, because a
  remote OSC 7 cwd is attacker-controlled when the host is compromised.
- The Settings window is denylisted from `tauri-plugin-window-state`, and
  `VISIBLE` is stripped from the restored state flags so the main window can
  call `show()` after first paint instead of flashing a transparent shadow.
- `capabilities/*.json` still list a `debug` window; there is no `debug.html`
  and no code creating one.
