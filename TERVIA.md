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

|                  |                                                                               |
| ---------------- | ----------------------------------------------------------------------------- |
| Version          | 0.1.0                                                                         |
| Repo / site      | `github.com/rendyuwu/tervia` / `https://tervia.rendy.dev`                     |
| Stack            | Tauri 2 + Rust (`portable-pty`, `russh`) <-> React 19 + TS + xterm.js (WebGL) |
| Editor / UI      | CodeMirror 6, shadcn/ui (`radix-luma` / `mist`, lucide icons), Tailwind v4    |
| Bundle id        | `dev.rendy.tervia` (dev profile: `dev.rendy.tervia.dev`)                      |
| Crates           | `tervia` / lib `tervia_lib`; GUI binary `TerviaApp`                           |
| Keychain service | `tervia-ssh` (SSH secrets)                                                    |
| Package manager  | pnpm                                                                          |
| Platforms        | macOS, Linux, Windows                                                         |
| Frontend check   | `pnpm exec tsc --noEmit`, `pnpm run lint:imports`                             |
| Rust check       | `cd src-tauri && cargo check && cargo clippy`                                 |
| Behaviour checks | `pnpm run verify` (all `scripts/*-verify.ts`), `pnpm run verify ssh`          |
| Build            | `pnpm tauri build`                                                            |
| Dev              | `pnpm tauri:dev` (isolated `.dev` data dir) or `pnpm tauri dev` (see gotcha)  |
| Auto-updater     | Enabled: signed updates via GitHub Releases, 6 h poll                         |

**Persisted state** (all under the bundle id's app-data dir, via
`tauri-plugin-store`): `tervia-settings.json`, `tervia-workspaces.json`,
`tervia-ssh-connections.json`, `tervia-cli-agents.json`. Rust -> webview events
are `tervia:`-prefixed; intra-frontend store-change events are `tervia://`.
Export formats: `.tervia-ssh` (encrypted connection backup, JSON kind
`tervia-ssh-connections`) and `.tervia` (theme, `$schema: "tervia-theme"`).

**Not built yet.** RDP sessions and end-to-end encrypted sync of saved machines
and keys are planned, not present. Nothing in the tree implements either; the
`.tervia-ssh` passphrase-encrypted export is the current answer to moving
connections between machines, and it is a manual file, not sync.

## Mental model

Six invariants (rationale in
[ARCHITECTURE.md](ARCHITECTURE.md#2-design-principles)):

1. **Two processes.** Frontend (`src/`, React webview) owns UI; backend
   (`src-tauri/`, Rust) owns every OS resource. The webview reaches the OS only
   via `invoke("cmd", args)`; streaming output returns over a Tauri `Channel`.
   Every command is registered in `src-tauri/src/lib.rs` (`invoke_handler`, 80
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
   commands, service `tervia-ssh`). Never in the settings store, the workspace
   store, or `localStorage`.
6. **App.tsx coordinates, it does not implement.** It owns cross-module wiring;
   feature logic lives in `src/modules/<area>/` and the per-concern hooks in
   `src/app/hooks/`.

## Project structure

```
src-tauri/                      Backend (Rust)
  src/lib.rs                    invoke_handler (all 80 commands) + boot + CLI dispatch
  src/main.rs                   thin shim
  src/modules/
    ssh/{mod,session,sftp}.rs             russh sessions, ProxyJump, -L forwards, SFTP
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
  modules/                      16 modules:
    ssh/       terminal/    panes/      tabs/       workspaces/
    editor/    explorer/    header/     statusbar/  rightPanel/
    settings/  shortcuts/   commandPalette/  theme/  updater/  scm/
```

## Backend (`src-tauri/src/modules/`)

| Module         | Key commands / role                                                                                                                                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ssh/`         | The product. `ssh_open/write/resize/close/attach/list_sessions`, `ssh_confirm_host_key`, `ssh_agent_keys`, `ssh_forward_open`, `ssh_git_status`, `ssh_git`, `ssh_sftp_*` (see below).                                                                              |
| `pty/`         | `pty_open/attach/write/resize/close/list_sessions/kill_all`, `terminal_probe_path`. Two backends: daemon (default) falls back to in-process.                                                                                                                       |
| `pty_daemon/`  | Sidecar owning PTYs across GUI restarts (`--pty-daemon` flag, no Tauri commands).                                                                                                                                                                                  |
| `fs/`          | `fs_read_dir/read_file/read_file_portion/canonicalize/write_file/create_file/create_dir/rename/copy/delete/search/grep/glob/grep_replace/replace_in_file`, `list_subdirs`.                                                                                         |
| `shell/`       | `shell_run_command`, `shell_session_*`, `shell_bg_*`. One-shot and background commands, distinct from interactive PTYs.                                                                                                                                            |
| `git/`         | `git_status/ignored/file_head/file_at/run/diff_full/log/commit_detail`. `git_run` is held to an allowlist of subcommands (`check_args`).                                                                                                                           |
| `backup.rs`    | `backup_seal` / `backup_open`: PBKDF2-HMAC-SHA256 + AES-256-GCM over the SSH connection export. Lives host-side because `crypto.subtle` needs a secure context and the app origin is plain http.                                                                   |
| `secrets.rs`   | `secrets_get/set/delete/get_all`. macOS Keychain; Windows DPAPI file (Credential Manager's 2560-byte blob cap is too small for an RSA key, with CredMan reads kept as a fallback); Linux 0600 file (no Secret Service daemon can be assumed for AppImage/deb/rpm). |
| `format.rs`    | `fmt_run_external` direct-spawn external formatter (15 s default timeout, 8 MiB cap).                                                                                                                                                                              |
| `net.rs`       | `http_ping`, `port_is_open`, `http_stream`, `http_abort`. SSRF guard blocks metadata / link-local addresses, re-applied on every redirect hop.                                                                                                                     |
| `clipboard.rs` | `clipboard_read_text`: paste reads run host-side via arboard because WebKitGTK rejects `navigator.clipboard.readText()` under Tauri's default webview flags. Writes stay on the webview API.                                                                       |
| `cli.rs`       | `cli_initial_target`, `cli_classify_path`, `cli_take_initial_update_request`, `cli_install_path_shim`, plus the pre-Tauri `--version` / `--help` / `--update` dispatch and the macOS `RunEvent::Opened` handler.                                                   |
| `ids.rs`       | `BUNDLE_ID` and the no-`AppHandle` data-dir derivation used by the CLI and the daemon.                                                                                                                                                                             |
| `lockext.rs`   | `lock_or_recover`: poison-safe `Mutex` acquisition for detached pump threads, where a poison panic would silently kill an output stream.                                                                                                                           |
| `appimage.rs`  | Strips the AppImage runtime's `LD_LIBRARY_PATH` from spawned children so a system `git`/`php` links against the distro's libraries, not the bundle's.                                                                                                              |

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

## Frontend (`src/modules/`, 16 modules)

| Module            | Role                                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ssh/`            | Connection manager, host-key dialog, SFTP explorer, encrypted backup, route pill (below).                                                                                                                    |
| `terminal/`       | One mounted xterm per leaf via `useTerminalSession`; pty-bridge and ssh-session backends behind one Session; OSC handlers; AI CLI detection; write metering; WebGL.                                          |
| `panes/`          | Split-pane orchestration via `react-resizable-panels` (`PaneStack`, `PaneTreeView`) plus the float-window host and its event protocol.                                                                       |
| `tabs/`           | Source of truth: `useTabs` (tab list + active id), `useWorkspaceCwd`, the `+` menu and the Agent spawn dialog.                                                                                               |
| `workspaces/`     | Workspace persistence + switching (`store.ts`, `serialize.ts`) and the Workspaces panel / board.                                                                                                             |
| `editor/`         | CodeMirror 6 (`EditorPane`), language modes, format-on-save, vim mode, minimap, prebuilt themes. Reads/writes remote files over SFTP when the leaf is SSH-bound.                                             |
| `explorer/`       | File tree (Catppuccin icons), fuzzy search, project-wide grep + replace, keyboard nav, inline rename, git decorations.                                                                                       |
| `header/`         | Top bar, inline search (`SearchInline` adapts terminal vs editor), the SSH menu, custom `WindowControls` (Linux/Windows).                                                                                    |
| `statusbar/`      | Bottom bar, cwd breadcrumb (SFTP-aware on an SSH pane), zoom, updater pill, `SshRoutePill`.                                                                                                                  |
| `rightPanel/`     | Which sidebar sections are docked to the right column (`files`, `workspaces`) and their persisted placement.                                                                                                 |
| `shortcuts/`      | Keymap catalog + `useGlobalShortcuts`; handlers wired in `app/lib/shortcutHandlers.ts` by id. Use `metaKey \|\| ctrlKey`.                                                                                    |
| `commandPalette/` | Ctrl+Shift+P palette over the shared `commandRegistry`, which every `useGlobalShortcuts` caller populates so component-owned commands run too.                                                               |
| `settings/`       | Settings store (`store.ts` via `tauri-plugin-store`), preferences, theme presets, terminal palette, window opener.                                                                                           |
| `theme/`          | `ThemeProvider`: applies theme / brand colour / opacity / fonts and keeps them in sync with the settings store across windows.                                                                               |
| `updater/`        | In-app updater UI on `tauri-plugin-updater`; 6 h poll, listens for `tervia:trigger-update`.                                                                                                                  |
| `scm/`            | Library only, no UI: `api.ts` wraps the `git_*` and `ssh_git*` commands, `branch.ts` the branch name, `types.ts` the payloads. Consumed by the explorer's git decorations and the Workspaces branch display. |

### SSH (`src/modules/ssh/`)

- `connections.ts` is the store of saved hosts (`tervia-ssh-connections.json`).
  It holds metadata and `has*` flags only; password, private key and key
  passphrase go to the keychain under service `tervia-ssh`, account
  `<id>::<field>`. `agent` mode stores nothing at all. Every mutation goes
  through one serialized `enqueueWrite` chain, because a chained connect fires
  `markConnected` once per hop near-simultaneously and a lost write would revert
  a host to a TOFU prompt.
- `authFields(authMode, secrets)` is the **one** mode-to-wire mapping. It exists
  because the same switch used to be spelled out at four call sites and a missed
  one connected with no credentials at all. Empty values become `undefined` so
  the backend's "no credentials" guard fires instead of an empty password.
- `resolveJumpHops` walks `proxyJumpId` transitively into the backend's connect
  order, with cycle detection seeded by the target's own id and a 16-hop cap. A
  deleted jump host throws rather than silently dropping a tunnel;
  `deleteConnection` cascade-clears any row pointing at the deleted id.
- `duplicateConnection` copies credentials but deliberately **not** the pinned
  fingerprint: a copy exists to be pointed elsewhere, and carrying the key over
  would read as a MITM on the next connect.
- `tunnel.ts` opens headless forwards for callers that want a TCP tunnel rather
  than a terminal. It refuses a connection with no pinned server key, because a
  first connect needs a human and nothing here can show the dialog.
- `backup.ts` / `backupFile.ts` export and import `.tervia-ssh`, sealed by
  `backup_seal`. `SshBackupDialog` and `SshMenu` are the UI.
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

`customTitle` is declared on every leaf kind so the tab strip's Rename works
anywhere. Any leaf can be popped into a floating OS window (`panes/floatHost.ts`
-> `open_float_window` -> `float.html`), which mirrors over Tauri events rather
than sharing React state.

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

## Development workflow

- **Checks before commit**: `pnpm exec tsc --noEmit`, `pnpm run lint:imports`,
  and in `src-tauri` `cargo check && cargo clippy` (clippy is `-D warnings` in
  CI). Rust tests: `cargo test`. CI runs those plus `pnpm build` and a bundle
  matrix; it does **not** run `pnpm run verify` or `cargo fmt --check`, so run
  those locally (`pnpm run fmt:rust`, `pnpm run lint:rust`).
- **`scripts/*-verify.ts`** are standalone `tsx` behaviour checks (SSH routing,
  backup round-trip, forward URLs, host keys, workspace serialization, terminal
  resize, theming, ...). `pnpm run verify <substring>` runs a subset; the whole
  suite is ~15 s. Modules meant to be exercised here stay free of xterm/Tauri
  imports at module scope so plain node can load them.
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
  `secrets_get_all`, `http_stream`, `http_abort`, `shell_bg_spawn_direct`,
  `ssh_list_sessions` and `ssh_attach` have no caller in `src/`. The
  `.tervia-ssh` export does not use `secrets_get_all`; it reads each
  connection's secrets individually through `getConnectionSecrets`.
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
